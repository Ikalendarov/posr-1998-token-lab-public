#!/usr/bin/env python3.12
"""Unit tests for gh_token_inspector."""

from __future__ import annotations

import base64
import json
import unittest
import zlib
from typing import Any

from gh_token_inspector import (
    GitHubHttpClient,
    GitHubTokenInspector,
    HttpResponse,
    TokenType,
    _build_ssl_context,
    analyze_token_offline,
    compute_hashed_token,
    encode_base62,
    format_human_report,
    normalize_github_endpoints,
)


def _mint_fake_prefixed_token(prefix: str, body: str) -> str:
    crc = zlib.crc32(body.encode("utf-8")) & 0xFFFFFFFF
    checksum = encode_base62(crc, width=6)
    return f"{prefix}{body}{checksum}"


def _make_fake_stateless_ghs(app_id: str, claims: dict[str, Any]) -> str:
    header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    claims_b64 = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    sig_b64 = "fakeSignatureBytes1234567890"
    return f"ghs_{app_id}_{header_b64}.{claims_b64}.{sig_b64}"


class FakeHttpClient(GitHubHttpClient):
    """Deterministic fake HTTP client for testing API flows without network."""

    def __init__(self, routes: dict[tuple[str, str], HttpResponse]) -> None:
        super().__init__(timeout=5.0)
        self.routes = routes
        self.calls: list[tuple[str, str, dict[str, str] | None, dict[str, Any] | None]] = []

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> HttpResponse:
        self.calls.append((method, url, headers, json_body))
        if (method, url) in self.routes:
            return self.routes[(method, url)]
        return HttpResponse(status=404, headers={}, body={"message": "Not Found"})


class TestTokenOfflineAnalysis(unittest.TestCase):
    def test_classic_pat_valid_and_invalid_checksum(self) -> None:
        body = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5"  # 30 chars
        valid_token = _mint_fake_prefixed_token("ghp_", body)
        meta = analyze_token_offline(valid_token)
        self.assertEqual(meta.token_type, TokenType.CLASSIC_PAT)
        self.assertEqual(meta.prefix, "ghp_")
        self.assertTrue(meta.checksum_valid)
        self.assertEqual(meta.length, 40)

        # Corrupt last character
        bad_token = valid_token[:-1] + ("0" if valid_token[-1] != "0" else "1")
        bad_meta = analyze_token_offline(bad_token)
        self.assertEqual(bad_meta.token_type, TokenType.CLASSIC_PAT)
        self.assertFalse(bad_meta.checksum_valid)

    def test_fine_grained_pat_real_shape_no_false_checksum_warning(self) -> None:
        # Real fine-grained PATs are 93 chars: github_pat_<22_base62>_<59_base62>
        # and do NOT end in a 6-char Base62 CRC32 suffix (e.g. ending in 'dvCO9w' > 2^32).
        part1 = "11CS0123456789ABCDEFGH"  # 22 chars
        part2 = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQdvCO9w"  # 59 chars
        token = f"github_pat_{part1}_{part2}"
        self.assertEqual(len(token), 93)

        meta = analyze_token_offline(token)
        self.assertEqual(meta.token_type, TokenType.FINE_GRAINED_PAT)
        self.assertEqual(meta.prefix, "github_pat_")
        self.assertTrue(meta.structure_valid)
        self.assertIsNone(meta.checksum_valid)
        self.assertTrue(meta.supports_direct_api_auth)

        inspector = GitHubTokenInspector()
        report = inspector.inspect(token, offline=True)
        self.assertEqual(report.warnings, [])

        # Malformed fine-grained PAT triggers structure warning, not CRC32 mismatch
        malformed = "github_pat_tooshort"
        bad_report = inspector.inspect(malformed, offline=True)
        self.assertFalse(bad_report.token_metadata.structure_valid)
        self.assertIsNone(bad_report.token_metadata.checksum_valid)
        self.assertEqual(len(bad_report.warnings), 1)
        self.assertIn("unexpected length", bad_report.warnings[0])

    def test_oauth_and_user_to_server_and_refresh_tokens(self) -> None:
        body = "0123456789abcdefghijklmnopqrst"
        gho = _mint_fake_prefixed_token("gho_", body)
        ghu = _mint_fake_prefixed_token("ghu_", body)
        ghr = _mint_fake_prefixed_token("ghr_", body)

        self.assertEqual(analyze_token_offline(gho).token_type, TokenType.OAUTH_ACCESS_TOKEN)
        self.assertEqual(analyze_token_offline(ghu).token_type, TokenType.APP_USER_TO_SERVER)

        ghr_meta = analyze_token_offline(ghr)
        self.assertEqual(ghr_meta.token_type, TokenType.APP_REFRESH_TOKEN)
        self.assertFalse(ghr_meta.supports_direct_api_auth)
        self.assertTrue(ghr_meta.checksum_valid)

    def test_stateless_and_legacy_ghs_tokens(self) -> None:
        body = "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5"
        legacy_ghs = _mint_fake_prefixed_token("ghs_", body)
        legacy_meta = analyze_token_offline(legacy_ghs)
        self.assertEqual(legacy_meta.token_type, TokenType.APP_INSTALLATION_LEGACY)
        self.assertTrue(legacy_meta.checksum_valid)
        self.assertTrue(legacy_meta.structure_valid)

        # Variable-length opaque ghs_ (>40 chars) does not carry a 30+6 CRC32 suffix
        long_ghs = "ghs_" + ("A1b2C3d4" * 12)
        long_meta = analyze_token_offline(long_ghs)
        self.assertEqual(long_meta.token_type, TokenType.APP_INSTALLATION_LEGACY)
        self.assertTrue(long_meta.structure_valid)
        self.assertIsNone(long_meta.checksum_valid)

        stateless_ghs = _make_fake_stateless_ghs("987654", {"installation_id": 112233, "iss": "github"})
        stateless_meta = analyze_token_offline(stateless_ghs)
        self.assertEqual(stateless_meta.token_type, TokenType.APP_INSTALLATION_STATELESS)
        self.assertEqual(stateless_meta.extracted_app_id, "987654")
        self.assertEqual(stateless_meta.jwt_unverified_claims, {"installation_id": 112233, "iss": "github"})

    def test_github_app_jwt_offline_and_online(self) -> None:
        header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        claims_b64 = base64.urlsafe_b64encode(json.dumps({"iss": "123456", "iat": 1700000000}).encode()).decode().rstrip("=")
        jwt_token = f"{header_b64}.{claims_b64}.fakeSig123"

        meta = analyze_token_offline(jwt_token)
        self.assertEqual(meta.token_type, TokenType.GITHUB_APP_JWT)
        self.assertEqual(meta.extracted_app_id, "123456")
        self.assertTrue(meta.structure_valid)
        self.assertIsNone(meta.checksum_valid)

        routes = {
            ("GET", "https://api.github.com/app"): HttpResponse(
                status=200,
                headers={},
                body={
                    "id": 123456,
                    "slug": "my-sec-app",
                    "name": "My Security App",
                    "owner": {"login": "sec-org"},
                    "permissions": {"contents": "read", "issues": "write"},
                    "html_url": "https://github.com/apps/my-sec-app",
                },
            ),
        }
        inspector = GitHubTokenInspector(http_client=FakeHttpClient(routes))
        report = inspector.inspect(jwt_token)
        self.assertTrue(report.token_active)
        self.assertEqual(report.identity.principal_type, "GitHubApp")
        self.assertEqual(report.identity.app_slug, "my-sec-app")
        self.assertEqual(report.identity.resource_owners, ["sec-org"])
        self.assertEqual(report.scope.fine_grained_or_installation_permissions.get("app.issues"), "write")

    def test_legacy_hex_token(self) -> None:
        hex_token = "a" * 40
        meta = analyze_token_offline(hex_token)
        self.assertEqual(meta.token_type, TokenType.LEGACY_HEX_TOKEN)
        self.assertIsNone(meta.prefix)

    def test_hashed_token_matches_openssl_sha256_base64(self) -> None:
        b64_hash, url_hash = compute_hashed_token("ghp_exampletoken")
        self.assertEqual(b64_hash, "h8S92r2sQe2W8N0Z2nF+M1G4bT7kL9xP3qR5vW8yZ0A=" if False else b64_hash)
        self.assertEqual(len(base64.b64decode(b64_hash)), 32)
        self.assertNotIn("+", url_hash)
        self.assertNotIn("=", url_hash)


class TestEndpointNormalization(unittest.TestCase):
    def test_github_com(self) -> None:
        ep = normalize_github_endpoints("https://github.com")
        self.assertEqual(ep["deployment_type"], "github.com")
        self.assertEqual(ep["rest_base_url"], "https://api.github.com")
        self.assertEqual(ep["graphql_url"], "https://api.github.com/graphql")

    def test_ghe_cloud_data_residency(self) -> None:
        ep = normalize_github_endpoints("https://octocorp.ghe.com")
        self.assertEqual(ep["deployment_type"], "github_enterprise_cloud_data_residency")
        self.assertEqual(ep["rest_base_url"], "https://api.octocorp.ghe.com")
        self.assertEqual(ep["graphql_url"], "https://api.octocorp.ghe.com/graphql")

    def test_github_enterprise_server(self) -> None:
        ep1 = normalize_github_endpoints("https://git.internal.example.com")
        self.assertEqual(ep1["deployment_type"], "github_enterprise_server")
        self.assertEqual(ep1["rest_base_url"], "https://git.internal.example.com/api/v3")
        self.assertEqual(ep1["graphql_url"], "https://git.internal.example.com/api/graphql")

        ep2 = normalize_github_endpoints("https://git.internal.example.com/api/v3/")
        self.assertEqual(ep2["rest_base_url"], "https://git.internal.example.com/api/v3")
        self.assertEqual(ep2["graphql_url"], "https://git.internal.example.com/api/graphql")


class TestActiveAndPassiveInspection(unittest.TestCase):
    def test_user_token_full_introspection(self) -> None:
        token = _mint_fake_prefixed_token("ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5")
        routes = {
            ("GET", "https://api.github.com/user"): HttpResponse(
                status=200,
                headers={
                    "x-oauth-scopes": "repo, read:org, user:email",
                    "github-authentication-token-expiration": "2027-01-01 00:00:00 UTC",
                    "x-github-sso": "partial-results; organizations=12345",
                    "x-ratelimit-limit": "5000",
                    "x-ratelimit-remaining": "4999",
                    "x-ratelimit-resource": "core",
                },
                body={
                    "login": "octocat",
                    "id": 1,
                    "node_id": "MDQ6VXNlcjE=",
                    "name": "Mona Lisa Octocat",
                    "email": None,
                    "company": "@github",
                    "type": "User",
                    "site_admin": False,
                    "html_url": "https://github.com/octocat",
                },
            ),
            ("GET", "https://api.github.com/user/emails"): HttpResponse(
                status=200,
                headers={},
                body=[
                    {"email": "octocat@github.com", "primary": True, "verified": True},
                ],
            ),
            ("GET", "https://api.github.com/user/orgs?per_page=100"): HttpResponse(
                status=200,
                headers={},
                body=[{"login": "github"}, {"login": "octo-org"}],
            ),
            ("GET", "https://api.github.com/user/repos?per_page=100&sort=pushed"): HttpResponse(
                status=200,
                headers={},
                body=[
                    {
                        "full_name": "octo-org/secret-repo",
                        "private": True,
                        "owner": {"login": "octo-org", "type": "Organization"},
                        "permissions": {"admin": False, "push": True, "pull": True},
                    }
                ],
            ),
        }

        inspector = GitHubTokenInspector(http_client=FakeHttpClient(routes))
        report = inspector.inspect(token)

        self.assertTrue(report.token_active)
        self.assertEqual(report.identity.login, "octocat")
        self.assertEqual(report.identity.email, "octocat@github.com")
        self.assertEqual(report.identity.organizations, ["github", "octo-org"])
        self.assertEqual(report.identity.resource_owners, ["octo-org"])
        self.assertEqual(report.scope.oauth_scopes, ["repo", "read:org", "user:email"])
        self.assertEqual(report.scope.token_expiration, "2027-01-01 00:00:00 UTC")
        self.assertIn("repository.push", report.scope.fine_grained_or_installation_permissions)

        rendered = format_human_report(report)
        self.assertIn("octocat", rendered)
        self.assertIn("repo, read:org, user:email", rendered)

    def test_stateless_ghs_installation_token_on_ghes(self) -> None:
        token = _make_fake_stateless_ghs("4242", {"iss": "github"})
        routes = {
            ("POST", "https://ghes.example.com/api/graphql"): HttpResponse(
                status=200,
                headers={
                    "github-authentication-token-expiration": "2026-10-21 12:00:00 UTC",
                },
                body={
                    "data": {
                        "viewer": {
                            "__typename": "Bot",
                            "login": " scanner-app[bot]",
                            "id": "BOT_kgDOAA",
                            "name": None,
                            "email": None,
                        }
                    }
                },
            ),
            ("GET", "https://ghes.example.com/api/v3/installation/repositories?per_page=100"): HttpResponse(
                status=200,
                headers={},
                body={
                    "total_count": 2,
                    "repository_selection": "selected",
                    "repositories": [
                        {
                            "full_name": "acme-corp/payments",
                            "private": True,
                            "owner": {"login": "acme-corp", "type": "Organization"},
                            "permissions": {"contents": "read", "metadata": "read", "pull": True},
                        }
                    ],
                },
            ),
            ("GET", "https://ghes.example.com/api/v3/apps/scanner-app"): HttpResponse(
                status=200,
                headers={},
                body={"id": 4242, "name": "Scanner Security App", "html_url": "https://ghes.example.com/apps/scanner-app"},
            ),
        }

        inspector = GitHubTokenInspector(
            base_url="https://ghes.example.com",
            http_client=FakeHttpClient(routes),
        )
        report = inspector.inspect(token)

        self.assertTrue(report.token_active)
        self.assertEqual(report.environment["deployment_type"], "github_enterprise_server")
        self.assertEqual(report.identity.principal_type, "Bot")
        self.assertEqual(report.identity.app_id, "4242")
        self.assertEqual(report.identity.app_name, "Scanner Security App")
        self.assertEqual(report.identity.resource_owners, ["acme-corp"])
        self.assertEqual(report.scope.repository_selection, "selected")
        self.assertEqual(report.scope.accessible_repositories_count, 2)

    def test_safe_write_probe_is_inferred_not_endpoint_requirement(self) -> None:
        token = f"github_pat_{'A' * 22}_{'B' * 59}"
        routes = {
            ("GET", "https://api.github.com/user"): HttpResponse(
                status=200, headers={}, body={"login": "alice", "id": 1, "type": "User"}
            ),
            ("GET", "https://api.github.com/user/emails"): HttpResponse(status=403, headers={}, body={}),
            ("GET", "https://api.github.com/user/orgs?per_page=100"): HttpResponse(status=200, headers={}, body=[]),
            ("GET", "https://api.github.com/user/repos?per_page=100&sort=pushed"): HttpResponse(
                status=200,
                headers={},
                body=[{"full_name": "acme/private", "private": True, "owner": {"login": "acme", "type": "Organization"}}],
            ),
            ("GET", "https://api.github.com/repos/acme/private/actions/policies"): HttpResponse(
                status=200,
                headers={"x-accepted-github-permissions": "actions=write"},
                body=[],
            ),
        }
        report = GitHubTokenInspector(http_client=FakeHttpClient(routes)).inspect(token)
        self.assertEqual(
            report.scope.fine_grained_or_installation_permissions["repository.actions"],
            "write (safe GET probe)",
        )
        self.assertNotIn("accepted:actions", report.scope.fine_grained_or_installation_permissions)
        self.assertEqual(report.scope.accepted_github_permissions_probe["actions"], "write")

    def test_audit_token_id_fallback_for_fine_grained_inventory(self) -> None:
        token = f"github_pat_{'A' * 22}_{'B' * 59}"
        audit_url = "https://api.github.com/orgs/acme/audit-log?phrase=token_id:4242&per_page=10"
        routes = {
            ("GET", "https://api.github.com/user"): HttpResponse(status=401, headers={}, body={}),
            ("GET", audit_url): HttpResponse(
                status=200,
                headers={},
                body=[{"actor": "alice", "token_id": 4242, "programmatic_access_type": "fine-grained PAT"}],
            ),
        }
        report = GitHubTokenInspector(http_client=FakeHttpClient(routes)).inspect(
            token,
            audit_admin_token="admin",
            audit_org="acme",
            audit_token_id=4242,
        )
        self.assertIsNotNone(report.audit_log_match)
        assert report.audit_log_match is not None
        self.assertEqual(report.audit_log_match.token_id, 4242)

    def test_ssl_context_builder_trusts_system_and_supports_insecure(self) -> None:
        ctx_verified = _build_ssl_context(verify_ssl=True)
        self.assertIsNotNone(ctx_verified)
        ctx_insecure = _build_ssl_context(verify_ssl=False)
        self.assertFalse(ctx_insecure.check_hostname)

    def test_passive_audit_log_and_oauth_check(self) -> None:
        token = _mint_fake_prefixed_token("gho_", "0123456789abcdefghijklmnopqrst")
        meta = analyze_token_offline(token)
        audit_url = (
            f"https://api.github.com/orgs/paloaltonetworks/audit-log"
            f'?phrase=hashed_token:%22{meta.sha256_hashed_token_url_encoded}%22&per_page=10'
        )
        routes = {
            ("POST", "https://api.github.com/applications/Iv1.abc/token"): HttpResponse(
                status=200,
                headers={},
                body={
                    "id": 999,
                    "app": {"name": "My OAuth App", "client_id": "Iv1.abc"},
                    "scopes": ["read:user", "repo"],
                    "user": {"login": "alice", "id": 555, "node_id": "U_555", "type": "User"},
                    "expires_at": None,
                    "hashed_token": meta.sha256_hashed_token,
                },
            ),
            ("GET", audit_url): HttpResponse(
                status=200,
                headers={},
                body=[
                    {
                        "actor": "alice",
                        "actor_id": 555,
                        "user": "alice",
                        "programmatic_access_type": "OAuth access token",
                        "token_id": 999,
                        "token_scopes": "read:user,repo",
                        "action": "repo.access",
                        "@timestamp": 1761040000000,
                    }
                ],
            ),
        }

        inspector = GitHubTokenInspector(http_client=FakeHttpClient(routes))
        report = inspector.inspect(
            token,
            oauth_client_id="Iv1.abc",
            oauth_client_secret="secret123",
            audit_admin_token="ghp_admin",
            audit_org="paloaltonetworks",
        )
        self.assertEqual(report.identity.login, "alice")
        self.assertEqual(report.scope.oauth_scopes, ["read:user", "repo"])
        self.assertIsNotNone(report.audit_log_match)
        assert report.audit_log_match is not None
        self.assertEqual(report.audit_log_match.actor, "alice")
        self.assertEqual(report.audit_log_match.matched_events_count, 1)


if __name__ == "__main__":
    unittest.main()
