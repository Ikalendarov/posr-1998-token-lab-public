#!/usr/bin/env python3.12
"""
GitHub Token Inspector (Python 3.12+)

Inspects any supported GitHub authentication token to determine:
1. Token type, format, offline CRC32 Base62 checksum validity, and SHA-256 audit hash.
2. Attached identity (User, Bot/Installation, Organization/Resource Owner).
3. Granted scopes / fine-grained permissions / accessible repositories & organizations.
4. Supports GitHub.com, GitHub Enterprise Cloud (Data Residency *.ghe.com),
   and GitHub Enterprise Server (GHES /api/v3).
5. Supports active self-introspection, OAuth App token check, and passive Audit Log lookup.
"""

from __future__ import annotations

import argparse
import base64
import functools
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
GITHUB_API_VERSION = "2022-11-28"


class TokenType(StrEnum):
    CLASSIC_PAT = "personal_access_token_classic"
    FINE_GRAINED_PAT = "personal_access_token_fine_grained"
    OAUTH_ACCESS_TOKEN = "oauth_app_access_token"
    APP_USER_TO_SERVER = "github_app_user_to_server_token"
    APP_INSTALLATION_LEGACY = "github_app_installation_token_legacy"
    APP_INSTALLATION_STATELESS = "github_app_installation_token_stateless"
    APP_REFRESH_TOKEN = "github_app_refresh_token"
    GITHUB_APP_JWT = "github_app_jwt"
    LEGACY_HEX_TOKEN = "legacy_hex_token"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class TokenMetadata:
    token_type: TokenType
    prefix: str | None
    description: str
    owner_kind: str
    default_lifespan: str
    supports_direct_api_auth: bool
    length: int
    masked_token: str
    sha256_hashed_token: str
    sha256_hashed_token_url_encoded: str
    structure_valid: bool | None = None
    checksum_expected: str | None = None
    checksum_actual: str | None = None
    checksum_valid: bool | None = None
    extracted_app_id: str | None = None
    jwt_unverified_header: dict[str, Any] | None = None
    jwt_unverified_claims: dict[str, Any] | None = None


@dataclass(slots=True)
class IdentityInfo:
    principal_type: str | None = None  # "User", "Bot", "Organization", "AppInstallation", "GitHubApp"
    login: str | None = None
    user_id: int | str | None = None
    node_id: str | None = None
    name: str | None = None
    email: str | None = None
    emails: list[dict[str, Any]] = field(default_factory=list)
    company: str | None = None
    site_admin: bool | None = None
    two_factor_authentication: bool | None = None
    created_at: str | None = None
    app_id: str | int | None = None
    app_slug: str | None = None
    app_name: str | None = None
    client_id: str | None = None
    resource_owners: list[str] = field(default_factory=list)
    organizations: list[str] = field(default_factory=list)
    profile_url: str | None = None
    detection_source: str | None = None


@dataclass(slots=True)
class ScopeInfo:
    inferred_resource_owner: str | None = None
    resource_owner_confidence: str | None = None
    oauth_scopes: list[str] = field(default_factory=list)
    accepted_oauth_scopes_probe: list[str] = field(default_factory=list)
    accepted_github_permissions_probe: dict[str, str] = field(default_factory=dict)
    fine_grained_or_installation_permissions: dict[str, str] = field(default_factory=dict)
    repository_selection: str | None = None
    accessible_repositories_count: int | None = None
    accessible_repositories_sample: list[dict[str, Any]] = field(default_factory=list)
    effective_access_state: str | None = None
    permission_evidence: list[dict[str, Any]] = field(default_factory=list)
    unresolved_probes: list[dict[str, Any]] = field(default_factory=list)
    token_expiration: str | None = None
    sso_status: str | None = None
    rate_limit_resource: str | None = None
    rate_limit_limit: int | None = None
    rate_limit_remaining: int | None = None


@dataclass(slots=True)
class AuditLogMatch:
    actor: str | None = None
    actor_id: int | str | None = None
    user: str | None = None
    programmatic_access_type: str | None = None
    token_id: int | str | None = None
    token_scopes: str | None = None
    last_action: str | None = None
    last_timestamp: int | str | None = None
    org_or_enterprise: str | None = None
    matched_events_count: int = 0


@dataclass(slots=True)
class InspectionReport:
    environment: dict[str, str]
    token_metadata: TokenMetadata
    token_active: bool | None = None
    identity: IdentityInfo = field(default_factory=IdentityInfo)
    scope: ScopeInfo = field(default_factory=ScopeInfo)
    oauth_app_check: dict[str, Any] | None = None
    audit_log_match: AuditLogMatch | None = None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def encode_base62(num: int, width: int = 6) -> str:
    """Encode an unsigned integer into Base62 padded with leading zeros."""
    if num == 0:
        return "0".zfill(width)
    chars: list[str] = []
    while num > 0:
        num, rem = divmod(num, 62)
        chars.append(BASE62_ALPHABET[rem])
    return "".join(reversed(chars)).zfill(width)


def verify_token_checksum(payload: str, checksum_str: str) -> tuple[bool, str]:
    """Compute CRC32 of payload and compare with 6-character Base62 checksum."""
    crc = zlib.crc32(payload.encode("utf-8")) & 0xFFFFFFFF
    expected = encode_base62(crc, width=6)
    return (expected == checksum_str), expected


def compute_hashed_token(token: str) -> tuple[str, str]:
    """
    Compute the Base64-encoded SHA-256 digest used in GitHub Audit Logs (`hashed_token`),
    along with its URL-encoded form for REST API queries.
    """
    digest = hashlib.sha256(token.encode("utf-8")).digest()
    b64 = base64.b64encode(digest).decode("ascii")
    return b64, urllib.parse.quote(b64, safe="")


def mask_token(token: str) -> str:
    """Mask a token safely for display while preserving prefix and last 4 characters."""
    if len(token) <= 12:
        return "***"
    if token.startswith("github_pat_"):
        return f"github_pat_{token[11:15]}...{token[-4:]}"
    if token.startswith("ghs_") and token.count("_") >= 2 and "." in token:
        parts = token.split("_", 2)
        return f"ghs_{parts[1]}_{parts[2][:6]}...{token[-4:]}"
    if "_" in token[:5]:
        prefix = token[:4]
        return f"{prefix}{token[4:8]}...{token[-4:]}"
    return f"{token[:4]}...{token[-4:]}"


def _decode_jwt_segment_unverified(segment: str) -> dict[str, Any] | None:
    """Best-effort decode of a Base64URL JWT JSON segment without signature validation."""
    try:
        padded = segment + "=" * (-len(segment) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        parsed = json.loads(raw.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def analyze_token_offline(token: str) -> TokenMetadata:
    """
    Classify a GitHub token offline, validate its structure and CRC32 checksum
    (for classic 40-char gh*_ tokens), extract embedded App IDs (for 2026 stateless
    ghs_ tokens and GitHub App JWTs), and compute its SHA-256 audit hash.
    """
    clean_token = token.strip()
    hashed, hashed_url = compute_hashed_token(clean_token)
    masked = mask_token(clean_token)
    length = len(clean_token)

    # 1. Stateless 2026 GitHub App Installation token: ghs_<APPID>_<JWT>
    stateless_match = re.match(
        r"^ghs_([A-Za-z0-9]+)_([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$",
        clean_token,
    )
    if stateless_match:
        app_id, jwt_str = stateless_match.groups()
        jwt_parts = jwt_str.split(".")
        jwt_header = _decode_jwt_segment_unverified(jwt_parts[0])
        jwt_claims = _decode_jwt_segment_unverified(jwt_parts[1])
        return TokenMetadata(
            token_type=TokenType.APP_INSTALLATION_STATELESS,
            prefix="ghs_",
            description="GitHub App installation access token (stateless JWT format, or Actions GITHUB_TOKEN)",
            owner_kind="GitHub App installation / Workflow run (not a human user)",
            default_lifespan="1 hour (or duration of GitHub Actions job)",
            supports_direct_api_auth=True,
            length=length,
            masked_token=masked,
            sha256_hashed_token=hashed,
            sha256_hashed_token_url_encoded=hashed_url,
            structure_valid=True,
            extracted_app_id=app_id,
            jwt_unverified_header=jwt_header,
            jwt_unverified_claims=jwt_claims,
        )

    # 2. Fine-grained Personal Access Token: github_pat_<22_chars>_<59_chars> (93 chars total)
    # Note: Fine-grained PATs do NOT use the 2021 classic 6-char Base62 CRC32 suffix;
    # their trailing characters are part of the Base62-encoded token payload.
    if clean_token.startswith("github_pat_"):
        body = clean_token[len("github_pat_") :]
        structure_valid = bool(re.fullmatch(r"[A-Za-z0-9]{22}_[A-Za-z0-9]{59}", body))
        return TokenMetadata(
            token_type=TokenType.FINE_GRAINED_PAT,
            prefix="github_pat_",
            description="Fine-grained Personal Access Token (scoped to a single user or organization resource owner)",
            owner_kind="User account",
            default_lifespan="Configurable (up to 1 year, or no expiration if allowed by policy)",
            supports_direct_api_auth=True,
            length=length,
            masked_token=masked,
            sha256_hashed_token=hashed,
            sha256_hashed_token_url_encoded=hashed_url,
            structure_valid=structure_valid,
            checksum_expected=None,
            checksum_actual=None,
            checksum_valid=None,
        )

    # 3. Standard 4-character prefixed tokens: ghp_, gho_, ghu_, ghs_, ghr_
    # Only the 40-char classic format (<4-char prefix><30-char Base62 entropy><6-char Base62 CRC32>)
    # carries the trailing 6-character CRC32 checksum. Longer opaque ghs_ tokens pass without CRC check.
    prefix_map: dict[str, tuple[TokenType, str, str, str, bool]] = {
        "ghp_": (
            TokenType.CLASSIC_PAT,
            "Personal Access Token (classic)",
            "User account",
            "Long-lived (until revoked, or auto-revoked after 1 year unused)",
            True,
        ),
        "gho_": (
            TokenType.OAUTH_ACCESS_TOKEN,
            "OAuth App access token",
            "User account (acting through an OAuth App)",
            "Long-lived (until revoked, or auto-revoked after 1 year unused)",
            True,
        ),
        "ghu_": (
            TokenType.APP_USER_TO_SERVER,
            "GitHub App user-to-server access token",
            "User account (acting through a GitHub App)",
            "Short-lived (8 hours by default)",
            True,
        ),
        "ghs_": (
            TokenType.APP_INSTALLATION_LEGACY,
            "GitHub App server-to-server installation access token (or Actions GITHUB_TOKEN)",
            "GitHub App installation / Workflow run (not a human user)",
            "Short-lived (1 hour, or duration of GitHub Actions job)",
            True,
        ),
        "ghr_": (
            TokenType.APP_REFRESH_TOKEN,
            "GitHub App refresh token",
            "User account (used to refresh a GitHub App user-to-server token)",
            "6 months",
            False,
        ),
    }

    for prefix, (ttype, desc, owner_kind, lifespan, can_auth) in prefix_map.items():
        if clean_token.startswith(prefix):
            rest = clean_token[len(prefix) :]
            checksum_valid: bool | None = None
            expected_crc: str | None = None
            actual_crc: str | None = None
            structure_valid: bool | None = None

            if len(rest) == 36 and re.fullmatch(r"[A-Za-z0-9]{36}", rest):
                structure_valid = True
                payload = rest[:30]
                actual_crc = rest[30:]
                checksum_valid, expected_crc = verify_token_checksum(payload, actual_crc)
            elif prefix == "ghs_" and len(rest) > 36 and re.fullmatch(r"[A-Za-z0-9_]+", rest):
                # Variable-length opaque ghs_ token (no 30+6 CRC32 suffix)
                structure_valid = True
            else:
                structure_valid = False

            return TokenMetadata(
                token_type=ttype,
                prefix=prefix,
                description=desc,
                owner_kind=owner_kind,
                default_lifespan=lifespan,
                supports_direct_api_auth=can_auth,
                length=length,
                masked_token=masked,
                sha256_hashed_token=hashed,
                sha256_hashed_token_url_encoded=hashed_url,
                structure_valid=structure_valid,
                checksum_expected=expected_crc,
                checksum_actual=actual_crc,
                checksum_valid=checksum_valid,
            )

    # 4. Bare GitHub App JWT: eyJ<header>.eyJ<claims>.<signature>
    jwt_match = re.match(r"^(eyJ[A-Za-z0-9_-]+)\.(eyJ[A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$", clean_token)
    if jwt_match:
        h_seg, c_seg, _ = jwt_match.groups()
        jwt_header = _decode_jwt_segment_unverified(h_seg)
        jwt_claims = _decode_jwt_segment_unverified(c_seg)
        iss = str(jwt_claims["iss"]) if isinstance(jwt_claims, dict) and jwt_claims.get("iss") is not None else None
        return TokenMetadata(
            token_type=TokenType.GITHUB_APP_JWT,
            prefix=None,
            description="GitHub App JSON Web Token (JWT used to authenticate as a GitHub App via GET /app)",
            owner_kind="GitHub App (integration itself)",
            default_lifespan="Short-lived (up to 10 minutes)",
            supports_direct_api_auth=True,
            length=length,
            masked_token=masked,
            sha256_hashed_token=hashed,
            sha256_hashed_token_url_encoded=hashed_url,
            structure_valid=True,
            extracted_app_id=iss,
            jwt_unverified_header=jwt_header,
            jwt_unverified_claims=jwt_claims,
        )

    # 5. Legacy 40-char hexadecimal token (pre-April 2021)
    if re.fullmatch(r"[a-fA-F0-9]{40}", clean_token):
        return TokenMetadata(
            token_type=TokenType.LEGACY_HEX_TOKEN,
            prefix=None,
            description="Legacy 40-character hexadecimal OAuth / Personal Access Token (pre-April 2021 format)",
            owner_kind="User account",
            default_lifespan="Long-lived (until revoked)",
            supports_direct_api_auth=True,
            length=length,
            masked_token=masked,
            sha256_hashed_token=hashed,
            sha256_hashed_token_url_encoded=hashed_url,
            structure_valid=True,
        )

    # 6. Unknown format
    return TokenMetadata(
        token_type=TokenType.UNKNOWN,
        prefix=None,
        description="Unrecognized token format (attempting generic GitHub API introspection)",
        owner_kind="Unknown",
        default_lifespan="Unknown",
        supports_direct_api_auth=True,
        length=length,
        masked_token=masked,
        sha256_hashed_token=hashed,
        sha256_hashed_token_url_encoded=hashed_url,
        structure_valid=False,
    )


def normalize_github_endpoints(base_url: str) -> dict[str, str]:
    """
    Normalize any GitHub URL into REST API and GraphQL endpoints for:
    - Regular GitHub.com (https://api.github.com, https://github.com)
    - GitHub Enterprise Cloud with Data Residency (https://<sub.ghe.com>, https://api.<sub.ghe.com>)
    - GitHub Enterprise Server (https://<ghes-host>, https://<ghes-host>/api/v3)
    """
    raw = (base_url or "https://api.github.com").strip().rstrip("/")
    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"

    parsed = urllib.parse.urlparse(raw)
    host = parsed.netloc.lower()
    scheme = parsed.scheme
    path = parsed.path.rstrip("/")

    # Case 1: Regular GitHub.com
    if host in ("github.com", "www.github.com", "api.github.com"):
        return {
            "deployment_type": "github.com",
            "rest_base_url": "https://api.github.com",
            "graphql_url": "https://api.github.com/graphql",
        }

    # Case 2: GitHub Enterprise Cloud with Data Residency (*.ghe.com)
    if host.endswith(".ghe.com"):
        api_host = host if host.startswith("api.") else f"api.{host}"
        return {
            "deployment_type": "github_enterprise_cloud_data_residency",
            "rest_base_url": f"{scheme}://{api_host}",
            "graphql_url": f"{scheme}://{api_host}/graphql",
        }

    # Case 3: GitHub Enterprise Server (GHES)
    # Strip trailing /api/v3 or /api/graphql if caller passed it directly
    base_root = f"{scheme}://{parsed.netloc}"
    if path.endswith("/api/v3"):
        prefix_path = path[: -len("/api/v3")]
    elif path.endswith("/api/graphql"):
        prefix_path = path[: -len("/api/graphql")]
    elif path.endswith("/api"):
        prefix_path = path[: -len("/api")]
    else:
        prefix_path = path

    return {
        "deployment_type": "github_enterprise_server",
        "rest_base_url": f"{base_root}{prefix_path}/api/v3",
        "graphql_url": f"{base_root}{prefix_path}/api/graphql",
    }


@dataclass(slots=True)
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: Any


@functools.lru_cache(maxsize=4)
def _build_ssl_context(ca_bundle: str | None = None, verify_ssl: bool = True) -> ssl.SSLContext:
    """
    Build an SSLContext that trusts:
    1. Standard system / certifi CA bundle (ssl.create_default_context)
    2. Explicit --ca-bundle or CA environment variables (GITHUB_CA_BUNDLE, SSL_CERT_FILE,
       REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, GIT_SSL_CAINFO, NODE_EXTRA_CA_CERTS)
    3. System /etc/ssl/cert.pem if present
    4. macOS System & Login Keychains (essential when behind corporate TLS inspection
       proxies such as Palo Alto Networks GlobalProtect on standalone Python builds)
    """
    if not verify_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    ctx = ssl.create_default_context()

    candidate_files: list[str] = []
    if ca_bundle:
        candidate_files.append(ca_bundle)
    for env_var in (
        "GITHUB_CA_BUNDLE",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "NODE_EXTRA_CA_CERTS",
    ):
        val = os.environ.get(env_var)
        if val:
            candidate_files.append(val)
    if os.path.isfile("/private/etc/ssl/cert.pem"):
        candidate_files.append("/private/etc/ssl/cert.pem")
    elif os.path.isfile("/etc/ssl/cert.pem"):
        candidate_files.append("/etc/ssl/cert.pem")

    for cafile in dict.fromkeys(candidate_files):
        if os.path.isfile(cafile):
            try:
                ctx.load_verify_locations(cafile=cafile)
            except ssl.SSLError:
                pass

    if sys.platform == "darwin":
        keychains = [
            "/Library/Keychains/System.keychain",
            "/System/Library/Keychains/SystemRootCertificates.keychain",
        ]
        existing_kcs = [kc for kc in keychains if os.path.exists(kc)]
        for cmd in (
            ["/usr/bin/security", "find-certificate", "-a", "-p", *existing_kcs],
            ["/usr/bin/security", "find-certificate", "-a", "-p"],
        ):
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5.0, check=False)
                if res.returncode == 0 and "-----BEGIN CERTIFICATE-----" in res.stdout:
                    ctx.load_verify_locations(cadata=res.stdout)
            except Exception:
                pass

    return ctx


class GitHubHttpClient:
    """Lightweight HTTP client using Python 3.12 stdlib urllib.request."""

    def __init__(
        self,
        timeout: float = 15.0,
        ca_bundle: str | None = None,
        verify_ssl: bool = True,
    ) -> None:
        self.timeout = timeout
        self.ca_bundle = ca_bundle
        self.verify_ssl = verify_ssl
        self._ssl_context: ssl.SSLContext | None = None

    def _get_ssl_context(self) -> ssl.SSLContext:
        if self._ssl_context is None:
            self._ssl_context = _build_ssl_context(self.ca_bundle, self.verify_ssl)
        return self._ssl_context

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> HttpResponse:
        req_headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "github-token-inspector/1.0 (Python 3.12)",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        if headers:
            req_headers.update(headers)

        data: bytes | None = None
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")

        req = urllib.request.Request(url=url, data=data, headers=req_headers, method=method)
        ssl_ctx = self._get_ssl_context() if url.lower().startswith("https://") else None
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ssl_ctx) as resp:
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                raw_bytes = resp.read()
                parsed_body = self._parse_body(raw_bytes)
                return HttpResponse(status=resp.status, headers=resp_headers, body=parsed_body)
        except urllib.error.HTTPError as err:
            resp_headers = {k.lower(): v for k, v in err.headers.items()} if err.headers else {}
            raw_bytes = err.read() if err.fp else b""
            parsed_body = self._parse_body(raw_bytes)
            return HttpResponse(status=err.code, headers=resp_headers, body=parsed_body)

    @staticmethod
    def _parse_body(raw_bytes: bytes) -> Any:
        if not raw_bytes:
            return None
        text = raw_bytes.decode("utf-8", errors="replace")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text


class GitHubTokenInspector:
    """Main orchestrator for offline + active + passive GitHub token inspection."""

    def __init__(
        self,
        base_url: str = "https://api.github.com",
        http_client: GitHubHttpClient | None = None,
    ) -> None:
        self.endpoints = normalize_github_endpoints(base_url)
        self.http = http_client or GitHubHttpClient()

    def inspect(
        self,
        token: str,
        *,
        offline: bool = False,
        oauth_client_id: str | None = None,
        oauth_client_secret: str | None = None,
        audit_admin_token: str | None = None,
        audit_org: str | None = None,
        audit_enterprise: str | None = None,
        audit_token_id: str | int | None = None,
        candidate_repositories: list[str] | None = None,
    ) -> InspectionReport:
        clean_token = token.strip()
        meta = analyze_token_offline(clean_token)
        report = InspectionReport(
            environment=self.endpoints,
            token_metadata=meta,
        )

        if meta.checksum_valid is False:
            report.warnings.append(
                f"Offline CRC32 checksum mismatch: expected '{meta.checksum_expected}', "
                f"found '{meta.checksum_actual}'. The token may be corrupted or fake."
            )
        elif meta.structure_valid is False and meta.token_type != TokenType.UNKNOWN:
            report.warnings.append(
                f"Token with prefix '{meta.prefix}' has an unexpected length ({meta.length}) "
                "or character structure for its type."
            )

        if meta.extracted_app_id:
            report.identity.app_id = meta.extracted_app_id

        if offline:
            return report

        # Active self-introspection using the token itself
        if not meta.supports_direct_api_auth:
            report.warnings.append(
                f"Token type '{meta.token_type}' ({meta.prefix}) is a refresh token and cannot "
                "authenticate direct REST API requests without exchanging it via the GitHub App."
            )
        else:
            try:
                self._introspect_active_token(clean_token, report)
            except urllib.error.URLError as exc:
                report.errors.append(f"Network error contacting GitHub API: {exc}")
            except Exception as exc:
                report.errors.append(f"Unexpected error during active introspection: {exc}")

        if candidate_repositories:
            self._probe_candidate_repositories(
                clean_token, candidate_repositories, report
            )

        # Optional: OAuth App / GitHub App Owner Token Check (POST /applications/{client_id}/token)
        if oauth_client_id and oauth_client_secret:
            try:
                self._check_via_oauth_application(
                    clean_token, oauth_client_id, oauth_client_secret, report
                )
            except Exception as exc:
                report.errors.append(f"OAuth application check failed: {exc}")

        # Optional: Passive Audit Log lookup using an Admin token
        if audit_admin_token and (audit_org or audit_enterprise):
            try:
                self._lookup_audit_log(
                    meta.sha256_hashed_token_url_encoded,
                    audit_admin_token.strip(),
                    audit_org=audit_org,
                    audit_enterprise=audit_enterprise,
                    audit_token_id=audit_token_id,
                    report=report,
                )
            except Exception as exc:
                report.errors.append(f"Audit log search failed: {exc}")

        return report

    def _auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def _populate_headers_metadata(
        self,
        headers: dict[str, str],
        scope: ScopeInfo,
        identity: IdentityInfo | None = None,
    ) -> None:
        if "x-oauth-scopes" in headers:
            raw_scopes = headers["x-oauth-scopes"]
            parsed_scopes = [s.strip() for s in raw_scopes.split(",") if s.strip()]
            if parsed_scopes:
                scope.oauth_scopes = parsed_scopes
        if "x-accepted-oauth-scopes" in headers:
            raw_acc = headers["x-accepted-oauth-scopes"]
            for s in (x.strip() for x in raw_acc.split(",") if x.strip()):
                if s not in scope.accepted_oauth_scopes_probe:
                    scope.accepted_oauth_scopes_probe.append(s)
        if "x-accepted-github-permissions" in headers:
            raw_perms = headers["x-accepted-github-permissions"]
            for item in (x.strip() for x in raw_perms.split(",") if x.strip()):
                if "=" in item:
                    k, v = item.split("=", 1)
                    scope.accepted_github_permissions_probe[k.strip()] = v.strip()
        if "github-authentication-token-expiration" in headers:
            scope.token_expiration = headers["github-authentication-token-expiration"].strip()
        if "x-github-sso" in headers:
            scope.sso_status = headers["x-github-sso"].strip()
        if "x-oauth-client-id" in headers and identity is not None:
            client_id = headers["x-oauth-client-id"].strip()
            if client_id:
                identity.client_id = client_id
        if "x-ratelimit-resource" in headers:
            scope.rate_limit_resource = headers["x-ratelimit-resource"].strip()
        if "x-ratelimit-limit" in headers and headers["x-ratelimit-limit"].isdigit():
            scope.rate_limit_limit = int(headers["x-ratelimit-limit"])
        if "x-ratelimit-remaining" in headers and headers["x-ratelimit-remaining"].isdigit():
            scope.rate_limit_remaining = int(headers["x-ratelimit-remaining"])

    def _introspect_active_token(self, token: str, report: InspectionReport) -> None:
        meta = report.token_metadata
        rest_base = self.endpoints["rest_base_url"]

        # Route bare GitHub App JWTs directly to GET /app
        if meta.token_type == TokenType.GITHUB_APP_JWT:
            self._introspect_github_app_jwt(token, report)
            return

        # Route installation tokens directly to installation/GraphQL flow,
        # or try /user first for user tokens.
        is_installation_type = meta.token_type in (
            TokenType.APP_INSTALLATION_LEGACY,
            TokenType.APP_INSTALLATION_STATELESS,
        )

        if not is_installation_type:
            user_resp = self.http.request(
                "GET", f"{rest_base}/user", headers=self._auth_headers(token)
            )
            self._populate_headers_metadata(user_resp.headers, report.scope, report.identity)

            if user_resp.status == 200 and isinstance(user_resp.body, dict):
                report.token_active = True
                body = user_resp.body
                report.identity.principal_type = body.get("type") or "User"
                report.identity.login = body.get("login")
                report.identity.user_id = body.get("id")
                report.identity.node_id = body.get("node_id")
                report.identity.name = body.get("name")
                report.identity.email = body.get("email")
                report.identity.company = body.get("company")
                report.identity.site_admin = body.get("site_admin")
                report.identity.two_factor_authentication = body.get("two_factor_authentication")
                report.identity.created_at = body.get("created_at")
                report.identity.profile_url = body.get("html_url")
                report.identity.detection_source = "GET /user"

                self._enrich_user_token(token, report)
                return

            if user_resp.status == 401:
                report.token_active = False
                msg = (
                    user_resp.body.get("message")
                    if isinstance(user_resp.body, dict)
                    else str(user_resp.body)
                )
                report.errors.append(f"Token rejected (401 Unauthorized): {msg}")
                return

            # A 403 on GET /user can happen for an installation token without standard prefix
            # or a restricted token. Fall through to GraphQL + installation check.

        # Installation token or restricted token flow
        self._introspect_installation_or_graphql(token, report)

    def _introspect_github_app_jwt(self, token: str, report: InspectionReport) -> None:
        rest_base = self.endpoints["rest_base_url"]
        app_resp = self.http.request("GET", f"{rest_base}/app", headers=self._auth_headers(token))
        self._populate_headers_metadata(app_resp.headers, report.scope, report.identity)
        if app_resp.status == 200 and isinstance(app_resp.body, dict):
            body = app_resp.body
            report.token_active = True
            report.identity.principal_type = "GitHubApp"
            report.identity.app_id = body.get("id") or report.identity.app_id
            report.identity.app_slug = body.get("slug")
            report.identity.app_name = body.get("name")
            report.identity.login = body.get("slug") or body.get("name")
            report.identity.user_id = body.get("id")
            report.identity.node_id = body.get("node_id")
            report.identity.created_at = body.get("created_at")
            report.identity.profile_url = body.get("html_url")
            report.identity.detection_source = "GET /app"
            owner = body.get("owner")
            if isinstance(owner, dict) and owner.get("login"):
                report.identity.resource_owners = [owner["login"]]
            perms = body.get("permissions")
            if isinstance(perms, dict):
                for k, v in perms.items():
                    if v:
                        report.scope.fine_grained_or_installation_permissions[f"app.{k}"] = str(v)
        elif app_resp.status == 401:
            report.token_active = False
            msg = (
                app_resp.body.get("message")
                if isinstance(app_resp.body, dict)
                else str(app_resp.body)
            )
            report.errors.append(f"GitHub App JWT rejected (401 Unauthorized): {msg}")
        else:
            report.warnings.append(f"GET /app returned HTTP {app_resp.status}: {app_resp.body}")

    def _enrich_user_token(self, token: str, report: InspectionReport) -> None:
        rest_base = self.endpoints["rest_base_url"]
        headers = self._auth_headers(token)
        meta = report.token_metadata

        # 1. Fetch verified emails if 'user' or 'user:email' scope/permission is granted
        emails_resp = self.http.request("GET", f"{rest_base}/user/emails", headers=headers)
        self._populate_headers_metadata(emails_resp.headers, report.scope, report.identity)
        if emails_resp.status == 200 and isinstance(emails_resp.body, list):
            report.identity.emails = [
                {
                    "email": e.get("email"),
                    "primary": e.get("primary"),
                    "verified": e.get("verified"),
                }
                for e in emails_resp.body
                if isinstance(e, dict)
            ]
            if not report.identity.email:
                primary = next(
                    (e["email"] for e in report.identity.emails if e.get("primary")),
                    None,
                )
                if primary:
                    report.identity.email = primary

        # 2. Fetch organizations the token can see
        orgs_resp = self.http.request("GET", f"{rest_base}/user/orgs?per_page=100", headers=headers)
        self._populate_headers_metadata(orgs_resp.headers, report.scope, report.identity)
        if orgs_resp.status == 200 and isinstance(orgs_resp.body, list):
            report.identity.organizations = [
                o.get("login") for o in orgs_resp.body if isinstance(o, dict) and o.get("login")
            ]

        # 3. Fetch accessible repositories to discover resource owners and effective repo permissions
        repos_resp = self.http.request(
            "GET",
            f"{rest_base}/user/repos?per_page=100&sort=pushed",
            headers=headers,
        )
        self._populate_headers_metadata(repos_resp.headers, report.scope, report.identity)
        if repos_resp.status == 200 and isinstance(repos_resp.body, list):
            private_repos = [
                repo for repo in repos_resp.body
                if isinstance(repo, dict) and repo.get("private") is True
            ]
            self._extract_repo_scope_and_owners(private_repos, report)
            if private_repos:
                report.scope.effective_access_state = "CONFIRMED_PRIVATE_RESOURCE_ACCESS"
            elif meta.token_type == TokenType.FINE_GRAINED_PAT:
                report.scope.effective_access_state = "PUBLIC_ONLY_OR_BLOCKED"
                report.warnings.append(
                    "No private repository was reachable. Fine-grained PATs always read public "
                    "repositories, so public results do not prove configured resource scope. "
                    "The token may be public-only, pending approval, SSO/policy blocked, or have no private selection."
                )

        # 4. Fine-grained PATs do not expose their complete grant to their holder.
        #    Safe GET probes instead test high-value capabilities. A successful private-resource
        #    request is evidence of at least read. Some documented GET routes require WRITE,
        #    which allows read-only probing of high-impact write grants.
        if meta.token_type in (
            TokenType.FINE_GRAINED_PAT,
            TokenType.APP_USER_TO_SERVER,
            TokenType.UNKNOWN,
        ):
            self._probe_fine_grained_capabilities(token, report)

        # 5. For ghu_ (GitHub App user-to-server) tokens, query GET /user/installations
        #    to discover the exact GitHub App, installation permissions, and resource owners.
        if meta.token_type == TokenType.APP_USER_TO_SERVER:
            inst_resp = self.http.request(
                "GET", f"{rest_base}/user/installations?per_page=25", headers=headers
            )
            self._populate_headers_metadata(inst_resp.headers, report.scope, report.identity)
            if inst_resp.status == 200 and isinstance(inst_resp.body, dict):
                installations = inst_resp.body.get("installations") or []
                if isinstance(installations, list):
                    for inst in installations:
                        if not isinstance(inst, dict):
                            continue
                        if not report.identity.app_id and inst.get("app_id"):
                            report.identity.app_id = inst.get("app_id")
                        if not report.identity.app_slug and inst.get("app_slug"):
                            report.identity.app_slug = str(inst.get("app_slug")).strip()
                        if not report.scope.repository_selection and inst.get("repository_selection"):
                            report.scope.repository_selection = inst.get("repository_selection")
                        acct_login = (inst.get("account") or {}).get("login")
                        if acct_login and acct_login not in report.identity.resource_owners:
                            report.identity.resource_owners.append(acct_login)
                        perms = inst.get("permissions")
                        if isinstance(perms, dict):
                            for perm_name, level in perms.items():
                                if level:
                                    report.scope.fine_grained_or_installation_permissions[
                                        f"installation.{perm_name}"
                                    ] = str(level)

    def _introspect_installation_or_graphql(self, token: str, report: InspectionReport) -> None:
        rest_base = self.endpoints["rest_base_url"]
        graphql_url = self.endpoints["graphql_url"]
        headers = self._auth_headers(token)

        # 1. Try GraphQL viewer query (works for both user tokens and ghs_ installation tokens)
        gql_query = {
            "query": "query { viewer { __typename login id name email } }"
        }
        gql_resp = self.http.request("POST", graphql_url, headers=headers, json_body=gql_query)
        self._populate_headers_metadata(gql_resp.headers, report.scope, report.identity)

        if gql_resp.status == 401:
            report.token_active = False
            msg = (
                gql_resp.body.get("message")
                if isinstance(gql_resp.body, dict)
                else str(gql_resp.body)
            )
            report.errors.append(f"Token rejected (401 Unauthorized): {msg}")
            return

        if gql_resp.status == 200 and isinstance(gql_resp.body, dict):
            viewer = (gql_resp.body.get("data") or {}).get("viewer")
            if isinstance(viewer, dict):
                report.token_active = True
                raw_login = viewer.get("login")
                login = raw_login.strip() if isinstance(raw_login, str) else raw_login
                report.identity.login = login
                report.identity.node_id = viewer.get("id")
                report.identity.name = viewer.get("name")
                report.identity.email = viewer.get("email")
                if isinstance(login, str) and login.endswith("[bot]"):
                    report.identity.principal_type = "Bot"
                    report.identity.app_slug = login[: -len("[bot]")].strip()
                else:
                    report.identity.principal_type = viewer.get("__typename") or "User"
                report.identity.detection_source = "POST /graphql (viewer)"

        # 2. Query GET /installation/repositories (standard for ghs_ installation tokens)
        inst_resp = self.http.request(
            "GET", f"{rest_base}/installation/repositories?per_page=100", headers=headers
        )
        self._populate_headers_metadata(inst_resp.headers, report.scope, report.identity)

        if inst_resp.status == 200 and isinstance(inst_resp.body, dict):
            report.token_active = True
            if not report.identity.principal_type:
                report.identity.principal_type = "AppInstallation"
            report.scope.repository_selection = inst_resp.body.get("repository_selection")
            report.scope.accessible_repositories_count = inst_resp.body.get("total_count")
            repos = inst_resp.body.get("repositories") or []
            if isinstance(repos, list):
                self._extract_repo_scope_and_owners(repos, report)
            if not report.identity.detection_source:
                report.identity.detection_source = "GET /installation/repositories"
        elif inst_resp.status == 401 and not report.token_active:
            report.token_active = False
            msg = (
                inst_resp.body.get("message")
                if isinstance(inst_resp.body, dict)
                else str(inst_resp.body)
            )
            report.errors.append(f"Token rejected (401 Unauthorized): {msg}")
            return

        # X-Accepted-GitHub-Permissions says what an endpoint requires, not what the
        # supplied token has. Test grants separately and label the result as inferred.
        self._probe_fine_grained_capabilities(token, report)

        # 3. If we have an app_slug (from viewer login `<slug>[bot]`), look up public App details
        if report.identity.app_slug and report.identity.app_slug != "github-actions":
            encoded_slug = urllib.parse.quote(report.identity.app_slug.strip(), safe="")
            app_resp = self.http.request(
                "GET", f"{rest_base}/apps/{encoded_slug}", headers=headers
            )
            if app_resp.status == 200 and isinstance(app_resp.body, dict):
                report.identity.app_id = report.identity.app_id or app_resp.body.get("id")
                report.identity.app_name = app_resp.body.get("name")
                report.identity.profile_url = report.identity.profile_url or app_resp.body.get("html_url")
        elif report.identity.app_slug == "github-actions":
            report.identity.app_name = "GitHub Actions"

    def _probe_fine_grained_capabilities(self, token: str, report: InspectionReport) -> None:
        """Infer effective fine-grained grants with read-only requests only."""
        rest_base = self.endpoints["rest_base_url"]
        headers = self._auth_headers(token)
        repos = report.scope.accessible_repositories_sample
        orgs = report.identity.resource_owners or report.identity.organizations
        repo = next((r.get("full_name") for r in repos if r.get("private") and r.get("full_name")), None)
        if repo is None:
            repo = next((r.get("full_name") for r in repos if r.get("full_name")), None)

        # These GET endpoints require the named permission according to GitHub's
        # fine-grained permission reference. No state is changed by the probes.
        # They are intentionally incomplete; absence is not proof of denial.
        probes: list[tuple[str, str]] = []
        if repo:
            quoted_repo = "/".join(urllib.parse.quote(p, safe="") for p in str(repo).split("/", 1))
            probes.extend(
                [
                    ("repository.actions", f"{rest_base}/repos/{quoted_repo}/actions/policies"),
                    ("repository.administration", f"{rest_base}/repos/{quoted_repo}/code-quality/setup"),
                    ("repository.secret_scanning", f"{rest_base}/repos/{quoted_repo}/secret-scanning/custom-patterns"),
                    ("repository.attestations", f"{rest_base}/repos/{quoted_repo}/attestations"),
                    ("repository.code_scanning_alerts", f"{rest_base}/repos/{quoted_repo}/code-scanning/alerts?per_page=1"),
                    ("repository.codespaces", f"{rest_base}/repos/{quoted_repo}/codespaces?per_page=1"),
                    ("repository.codespaces_metadata", f"{rest_base}/repos/{quoted_repo}/codespaces/new"),
                    ("repository.commit_statuses", f"{rest_base}/repos/{quoted_repo}/commits/HEAD/status"),
                    ("repository.contents", f"{rest_base}/repos/{quoted_repo}/contents/.github/workflows"),
                    ("repository.deployments", f"{rest_base}/repos/{quoted_repo}/deployments?per_page=1"),
                    ("repository.environments", f"{rest_base}/repos/{quoted_repo}/environments?per_page=1"),
                    ("repository.issues", f"{rest_base}/repos/{quoted_repo}/issues?per_page=1"),
                    ("repository.metadata", f"{rest_base}/repos/{quoted_repo}"),
                    ("repository.contents", f"{rest_base}/repos/{quoted_repo}/branches?per_page=1"),
                    ("repository.pull_requests", f"{rest_base}/repos/{quoted_repo}/pulls?per_page=1"),
                    ("repository.security_events", f"{rest_base}/repos/{quoted_repo}/secret-scanning/alerts?per_page=1"),
                    ("repository.workflows", f"{rest_base}/repos/{quoted_repo}/actions/workflows?per_page=1"),
                ]
            )
        if orgs:
            org = urllib.parse.quote(str(orgs[0]), safe="")
            probes.extend(
                [
                    ("organization.administration", f"{rest_base}/orgs/{org}/actions/policies"),
                    ("organization.actions", f"{rest_base}/orgs/{org}/actions/artifacts?per_page=1"),
                    ("organization.members", f"{rest_base}/orgs/{org}/members?per_page=1"),
                    ("organization.secrets", f"{rest_base}/orgs/{org}/actions/secrets?per_page=1"),
                ]
            )

        for permission, url in probes:
            resp = self.http.request("GET", url, headers=headers)
            self._populate_headers_metadata(resp.headers, report.scope, report.identity)
            if resp.status == 200:
                accepted = resp.headers.get("x-accepted-github-permissions", "")
                level = self._required_permission_level(accepted) or "granted"
                report.scope.fine_grained_or_installation_permissions[permission] = (
                    f"{level} (safe GET probe)"
                )
                report.scope.permission_evidence.append(
                    {"permission": permission, "level": level, "status": "EFFECTIVE", "method": "safe_get", "url": url}
                )
            elif resp.status in (403, 404):
                report.scope.unresolved_probes.append(
                    {"permission": permission, "status": "UNKNOWN_OR_BLOCKED", "http_status": resp.status, "url": url}
                )

    @staticmethod
    def _required_permission_level(accepted_permissions: str) -> str | None:
        levels: list[str] = []
        for item in (x.strip() for x in accepted_permissions.split(",") if x.strip()):
            if "=" in item:
                levels.append(item.split("=", 1)[1].strip())
        for level in ("admin", "write", "read"):
            if level in levels:
                return level
        return levels[0] if levels else None

    def _extract_repo_scope_and_owners(
        self, repos: list[Any], report: InspectionReport
    ) -> None:
        owners_seen: list[str] = list(report.identity.resource_owners)
        orgs_seen: list[str] = list(report.identity.organizations)
        aggregated_perms: dict[str, str] = dict(report.scope.fine_grained_or_installation_permissions)
        sample: list[dict[str, Any]] = []

        for repo in repos:
            if not isinstance(repo, dict):
                continue
            owner = repo.get("owner")
            if isinstance(owner, dict):
                owner_login = owner.get("login")
                if owner_login and owner_login not in owners_seen:
                    owners_seen.append(owner_login)
                if owner.get("type") == "Organization" and owner_login and owner_login not in orgs_seen:
                    orgs_seen.append(owner_login)

            perms = repo.get("permissions")
            if isinstance(perms, dict) and report.token_metadata.token_type in (
                TokenType.CLASSIC_PAT,
                TokenType.OAUTH_ACCESS_TOKEN,
                TokenType.LEGACY_HEX_TOKEN,
            ):
                for perm_name, granted in perms.items():
                    if granted:
                        aggregated_perms[f"repository.{perm_name}"] = (
                            str(granted) if not isinstance(granted, bool) else "granted"
                        )

            if len(sample) < 10:
                sample.append(
                    {
                        "full_name": repo.get("full_name"),
                        "private": repo.get("private"),
                        "permissions": perms,
                    }
                )

        report.identity.resource_owners = owners_seen
        report.identity.organizations = orgs_seen
        report.scope.fine_grained_or_installation_permissions = aggregated_perms
        report.scope.accessible_repositories_sample = sample
        if report.scope.accessible_repositories_count is None:
            report.scope.accessible_repositories_count = len(repos)

    def _probe_candidate_repositories(
        self, token: str, candidate_repositories: list[str], report: InspectionReport
    ) -> None:
        """Try externally discovered private repo candidates without mutating them."""
        rest_base = self.endpoints["rest_base_url"]
        headers = self._auth_headers(token)
        confirmed: list[dict[str, Any]] = []
        for candidate in dict.fromkeys(candidate_repositories):
            if "/" not in candidate:
                continue
            owner, repo = candidate.split("/", 1)
            quoted = f"{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(repo, safe='')}"
            resp = self.http.request("GET", f"{rest_base}/repos/{quoted}", headers=headers)
            self._populate_headers_metadata(resp.headers, report.scope, report.identity)
            if resp.status == 200 and isinstance(resp.body, dict) and resp.body.get("private") is True:
                confirmed.append(resp.body)
            elif resp.status in (403, 404):
                report.scope.unresolved_probes.append(
                    {"resource": candidate, "status": "UNKNOWN_OR_BLOCKED", "http_status": resp.status}
                )
        if confirmed:
            self._extract_repo_scope_and_owners(confirmed, report)
            report.scope.effective_access_state = "CONFIRMED_PRIVATE_RESOURCE_ACCESS"
            owners = sorted(
                {
                    str((repo.get("owner") or {}).get("login"))
                    for repo in confirmed
                    if isinstance(repo.get("owner"), dict) and (repo.get("owner") or {}).get("login")
                }
            )
            if len(owners) == 1:
                report.scope.inferred_resource_owner = owners[0]
                report.scope.resource_owner_confidence = "CONFIRMED_TARGETABLE"

    def _check_via_oauth_application(
        self,
        token: str,
        client_id: str,
        client_secret: str,
        report: InspectionReport,
    ) -> None:
        """
        Inspect a gho_ or ghu_ token via POST /applications/{client_id}/token using
        the OAuth/GitHub App's client_id and client_secret.
        """
        rest_base = self.endpoints["rest_base_url"]
        basic_creds = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
        resp = self.http.request(
            "POST",
            f"{rest_base}/applications/{urllib.parse.quote(client_id)}/token",
            headers={"Authorization": f"Basic {basic_creds}"},
            json_body={"access_token": token},
        )
        if resp.status == 200 and isinstance(resp.body, dict):
            body = resp.body
            report.token_active = True
            report.oauth_app_check = {
                "id": body.get("id"),
                "app": body.get("app"),
                "scopes": body.get("scopes"),
                "created_at": body.get("created_at"),
                "updated_at": body.get("updated_at"),
                "expires_at": body.get("expires_at"),
                "hashed_token": body.get("hashed_token"),
            }
            app_info = body.get("app")
            if isinstance(app_info, dict):
                report.identity.app_name = report.identity.app_name or app_info.get("name")
                report.identity.client_id = report.identity.client_id or app_info.get("client_id")
            user = body.get("user")
            if isinstance(user, dict) and not report.identity.login:
                report.identity.login = user.get("login")
                report.identity.user_id = user.get("id")
                report.identity.node_id = user.get("node_id")
                report.identity.principal_type = user.get("type") or "User"
                report.identity.detection_source = "POST /applications/{client_id}/token"
            if isinstance(body.get("scopes"), list) and not report.scope.oauth_scopes:
                report.scope.oauth_scopes = [str(s) for s in body["scopes"]]
            if body.get("expires_at") and not report.scope.token_expiration:
                report.scope.token_expiration = str(body["expires_at"])
        else:
            report.warnings.append(
                f"OAuth App token check returned HTTP {resp.status}: {resp.body}"
            )

    def _lookup_audit_log(
        self,
        url_encoded_hashed_token: str,
        admin_token: str,
        *,
        audit_org: str | None,
        audit_enterprise: str | None,
        report: InspectionReport,
        audit_token_id: str | int | None = None,
    ) -> None:
        """
        Passively search the GitHub Org or Enterprise Audit Log for `hashed_token:"<HASH>"`
        without authenticating with the target token itself.
        """
        rest_base = self.endpoints["rest_base_url"]
        if audit_enterprise:
            scope_path = f"enterprises/{urllib.parse.quote(audit_enterprise)}"
            target_label = f"enterprise:{audit_enterprise}"
        else:
            assert audit_org is not None
            scope_path = f"orgs/{urllib.parse.quote(audit_org)}"
            target_label = f"org:{audit_org}"

        qualifier = (
            f"token_id:{urllib.parse.quote(str(audit_token_id), safe='')}"
            if audit_token_id is not None
            else f"hashed_token:%22{url_encoded_hashed_token}%22"
        )
        url = f"{rest_base}/{scope_path}/audit-log?phrase={qualifier}&per_page=10"
        resp = self.http.request("GET", url, headers=self._auth_headers(admin_token))
        if resp.status == 200 and isinstance(resp.body, list):
            if not resp.body:
                report.audit_log_match = AuditLogMatch(
                    org_or_enterprise=target_label,
                    matched_events_count=0,
                )
                return
            first = resp.body[0] if isinstance(resp.body[0], dict) else {}
            report.audit_log_match = AuditLogMatch(
                actor=first.get("actor"),
                actor_id=first.get("actor_id"),
                user=first.get("user"),
                programmatic_access_type=first.get("programmatic_access_type"),
                token_id=first.get("token_id"),
                token_scopes=first.get("token_scopes"),
                last_action=first.get("action"),
                last_timestamp=first.get("@timestamp") or first.get("created_at"),
                org_or_enterprise=target_label,
                matched_events_count=len(resp.body),
            )
            if not report.identity.login and first.get("actor"):
                report.identity.login = first.get("actor")
                report.identity.user_id = first.get("actor_id")
                report.identity.detection_source = f"Audit Log ({target_label})"
        else:
            report.warnings.append(
                f"Audit log query on {target_label} returned HTTP {resp.status}: {resp.body}"
            )


def format_human_report(report: InspectionReport) -> str:
    """Render a clean, readable CLI summary of the inspection report."""
    meta = report.token_metadata
    ident = report.identity
    scope = report.scope

    lines: list[str] = [
        "=" * 72,
        "GITHUB TOKEN INSPECTION REPORT",
        "=" * 72,
        "",
        "[1] Environment",
        f"  Deployment Type : {report.environment['deployment_type']}",
        f"  REST Base URL   : {report.environment['rest_base_url']}",
        f"  GraphQL URL     : {report.environment['graphql_url']}",
        "",
        "[2] Token Format & Offline Metadata",
        f"  Masked Token    : {meta.masked_token} (length: {meta.length})",
        f"  Token Type      : {meta.token_type}",
        f"  Prefix          : {meta.prefix or 'None'}",
        f"  Description     : {meta.description}",
        f"  Expected Owner  : {meta.owner_kind}",
        f"  Typical Lifespan: {meta.default_lifespan}",
    ]
    if meta.structure_valid is not None:
        lines.append(f"  Structure Check : {'VALID' if meta.structure_valid else 'INVALID'}")
    if meta.checksum_valid is not None:
        status_str = "VALID" if meta.checksum_valid else f"INVALID (expected {meta.checksum_expected})"
        lines.append(f"  CRC32 Checksum  : {status_str}")
    else:
        lines.append("  CRC32 Checksum  : Not applicable (only 40-char classic gh*_ tokens use a 6-char CRC32 suffix)")
    if meta.extracted_app_id:
        lines.append(f"  Embedded App ID : {meta.extracted_app_id}")
    lines.extend(
        [
            f"  Audit SHA-256   : {meta.sha256_hashed_token}",
            f"  Audit Query     : hashed_token:\"{meta.sha256_hashed_token}\"",
            "",
            "[3] Attached Identity",
            f"  Token Active    : {report.token_active if report.token_active is not None else 'Not checked (offline/unsupported)'}",
            f"  Principal Type  : {ident.principal_type or 'Unknown'}",
            f"  Login / Actor   : {ident.login or 'Unknown'}",
            f"  User / Bot ID   : {ident.user_id if ident.user_id is not None else (ident.node_id or 'Unknown')}",
        ]
    )
    if ident.name:
        lines.append(f"  Display Name    : {ident.name}")
    if ident.email:
        lines.append(f"  Primary Email   : {ident.email}")
    if ident.company:
        lines.append(f"  Company         : {ident.company}")
    if ident.site_admin is not None:
        lines.append(f"  Site Admin      : {ident.site_admin}")
    if ident.app_id or ident.app_slug or ident.app_name or ident.client_id:
        lines.append(
            f"  GitHub App/OAuth: name={ident.app_name or 'N/A'}, slug={ident.app_slug or 'N/A'}, "
            f"id={ident.app_id or 'N/A'}, client_id={ident.client_id or 'N/A'}"
        )
    if ident.organizations:
        lines.append(f"  Organizations   : {', '.join(ident.organizations)}")
    if ident.resource_owners:
        lines.append(f"  Resource Owners : {', '.join(ident.resource_owners)}")
    if ident.detection_source:
        lines.append(f"  Detected Via    : {ident.detection_source}")

    lines.extend(
        [
            "",
            "[4] Scopes, Permissions & Expiration",
            f"  OAuth Scopes    : {', '.join(scope.oauth_scopes) if scope.oauth_scopes else 'None / Not applicable (fine-grained or installation token)'}",
            f"  Expiration      : {scope.token_expiration or 'None / Non-expiring or not reported'}",
        ]
    )
    if scope.sso_status:
        lines.append(f"  SAML SSO Header : {scope.sso_status}")
    if scope.repository_selection:
        lines.append(f"  Repo Selection  : {scope.repository_selection}")
    if scope.accessible_repositories_count is not None:
        lines.append(f"  Accessible Repos: {scope.accessible_repositories_count}")
    if scope.fine_grained_or_installation_permissions:
        perms_str = ", ".join(
            f"{k}={v}" for k, v in sorted(scope.fine_grained_or_installation_permissions.items())
        )
        lines.append(f"  Inferred Perms  : {perms_str}")
    if scope.accessible_repositories_sample:
        repo_names = [
            f"{r['full_name']} ({'private' if r.get('private') else 'public'})"
            for r in scope.accessible_repositories_sample
            for _ in [0]
            if r.get("full_name")
        ]
        lines.append(f"  Repo Sample     : {', '.join(repo_names[:5])}")
    if scope.rate_limit_limit is not None:
        lines.append(
            f"  Rate Limit      : {scope.rate_limit_remaining}/{scope.rate_limit_limit} (resource: {scope.rate_limit_resource or 'core'})"
        )

    if report.audit_log_match:
        am = report.audit_log_match
        lines.extend(
            [
                "",
                "[5] Passive Audit Log Lookup",
                f"  Target Scope    : {am.org_or_enterprise}",
                f"  Matched Events  : {am.matched_events_count}",
                f"  Actor           : {am.actor or 'None'} (ID: {am.actor_id or 'N/A'})",
                f"  Access Type     : {am.programmatic_access_type or 'N/A'}",
                f"  Token ID        : {am.token_id or 'N/A'}",
                f"  Token Scopes    : {am.token_scopes or 'N/A'}",
                f"  Last Action     : {am.last_action or 'N/A'} at {am.last_timestamp or 'N/A'}",
            ]
        )

    if report.warnings:
        lines.append("")
        lines.append("[!] Warnings")
        for w in report.warnings:
            lines.append(f"  - {w}")

    if report.errors:
        lines.append("")
        lines.append("[X] Errors")
        for e in report.errors:
            lines.append(f"  - {e}")

    lines.append("=" * 72)
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gh_token_inspector",
        description=(
            "Inspect a GitHub token to identify its type, checksum validity, "
            "attached identity, and scopes across GitHub.com and GitHub Enterprise."
        ),
    )
    parser.add_argument(
        "token",
        nargs="?",
        help="GitHub token to inspect (or set GITHUB_TOKEN_TO_INSPECT env var, or pass '-' to read from stdin).",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("GITHUB_BASE_URL", "https://api.github.com"),
        help=(
            "GitHub base URL. Supports https://api.github.com (default), "
            "https://<subdomain>.ghe.com (GHEC Data Residency), or "
            "https://<ghes-host>/api/v3 (GitHub Enterprise Server)."
        ),
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Perform only offline prefix, checksum, JWT App ID, and SHA-256 audit hash analysis (no network calls).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output the full inspection report as JSON.",
    )
    parser.add_argument(
        "--client-id",
        default=os.environ.get("GITHUB_OAUTH_CLIENT_ID"),
        help="Optional OAuth/GitHub App client_id to check gho_/ghu_ tokens via POST /applications/{client_id}/token.",
    )
    parser.add_argument(
        "--client-secret",
        default=os.environ.get("GITHUB_OAUTH_CLIENT_SECRET"),
        help="Optional OAuth/GitHub App client_secret for POST /applications/{client_id}/token.",
    )
    parser.add_argument(
        "--audit-token",
        default=os.environ.get("GITHUB_AUDIT_ADMIN_TOKEN"),
        help="Optional admin token to passively search Org/Enterprise audit logs by hashed_token.",
    )
    parser.add_argument(
        "--org",
        default=os.environ.get("GITHUB_AUDIT_ORG"),
        help="Organization name for passive audit log search (requires --audit-token).",
    )
    parser.add_argument(
        "--enterprise",
        default=os.environ.get("GITHUB_AUDIT_ENTERPRISE"),
        help="Enterprise slug for passive audit log search (requires --audit-token).",
    )
    parser.add_argument(
        "--audit-token-id",
        default=os.environ.get("GITHUB_AUDIT_TOKEN_ID"),
        help="Optional token_id from enterprise credential inventory; searches audit events when hashed_token is unavailable (notably fine-grained PATs).",
    )
    parser.add_argument(
        "--ca-bundle",
        default=os.environ.get("GITHUB_CA_BUNDLE"),
        help="Optional path to a custom CA certificate bundle (.pem) for TLS verification.",
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (for self-signed GitHub Enterprise Server instances).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="HTTP request timeout in seconds (default: 15.0).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    raw_token = args.token
    if raw_token == "-":
        raw_token = sys.stdin.read().strip()
    elif not raw_token:
        raw_token = os.environ.get("GITHUB_TOKEN_TO_INSPECT", "").strip()

    if not raw_token:
        parser.error(
            "A GitHub token must be provided via positional argument, '-' (stdin), "
            "or the GITHUB_TOKEN_TO_INSPECT environment variable."
        )

    inspector = GitHubTokenInspector(
        base_url=args.base_url,
        http_client=GitHubHttpClient(
            timeout=args.timeout,
            ca_bundle=args.ca_bundle,
            verify_ssl=not args.insecure,
        ),
    )
    report = inspector.inspect(
        raw_token,
        offline=args.offline,
        oauth_client_id=args.client_id,
        oauth_client_secret=args.client_secret,
        audit_admin_token=args.audit_token,
        audit_org=args.org,
        audit_enterprise=args.enterprise,
        audit_token_id=args.audit_token_id,
    )

    if args.json_output:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(format_human_report(report))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
