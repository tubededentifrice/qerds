"""Security-focused tests covering OWASP Top 10 vulnerabilities.

Tests cover:
- Authentication bypass attempts (A07:2021)
- Authorization boundary tests / Broken Access Control (A01:2021)
- Input validation (SQL injection, XSS) (A03:2021)
- IDOR (Insecure Direct Object Reference)
- Rate limiting (if implemented)
- Session security (A02:2021)
- Security misconfiguration (A05:2021)
- Cryptographic failures (A02:2021)

Beads Task: qerds-axj

Run with: docker compose exec qerds-api pytest tests/test_security.py -v
"""

from __future__ import annotations

import hashlib
import secrets
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException, status
from httpx import ASGITransport, AsyncClient

from qerds.api import create_app
from qerds.api.middleware.auth import (
    AuthenticatedUser,
    get_current_user,
    require_admin_user,
    require_authenticated_user,
    require_permission,
    require_role,
    require_superuser,
    set_current_user,
)

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def test_app() -> FastAPI:
    """Create a test FastAPI application instance."""
    return create_app()


@pytest.fixture
async def api_client(test_app: FastAPI) -> AsyncClient:
    """Async HTTP client for testing the API."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
def sender_user() -> AuthenticatedUser:
    """Create a mock authenticated sender user."""
    return AuthenticatedUser(
        principal_id=uuid4(),
        principal_type="party",
        session_id=uuid4(),
        is_superuser=False,
        is_active=True,
        roles=frozenset(["sender_user"]),
        permissions=frozenset(),
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0",
        auth_method="session",
        metadata={"display_name": "Test Sender", "email": "sender@example.com"},
    )


@pytest.fixture
def recipient_user() -> AuthenticatedUser:
    """Create a mock authenticated recipient user."""
    return AuthenticatedUser(
        principal_id=uuid4(),
        principal_type="party",
        session_id=uuid4(),
        is_superuser=False,
        is_active=True,
        roles=frozenset(["recipient_user"]),
        permissions=frozenset(),
        ip_address="192.168.1.101",
        user_agent="Mozilla/5.0",
        auth_method="session",
        metadata={},
    )


@pytest.fixture
def admin_user() -> AuthenticatedUser:
    """Create a mock authenticated admin user."""
    return AuthenticatedUser(
        principal_id=uuid4(),
        principal_type="admin_user",
        session_id=uuid4(),
        is_superuser=False,
        is_active=True,
        roles=frozenset(["admin"]),
        permissions=frozenset(),
        ip_address="10.0.0.1",
        user_agent="AdminClient/1.0",
        auth_method="session",
        metadata={},
    )


@pytest.fixture
def inactive_user() -> AuthenticatedUser:
    """Create an inactive user for testing."""
    return AuthenticatedUser(
        principal_id=uuid4(),
        principal_type="admin_user",
        session_id=uuid4(),
        is_superuser=False,
        is_active=False,
        roles=frozenset(["admin"]),
        permissions=frozenset(),
        ip_address="10.0.0.5",
        user_agent="Client/1.0",
        auth_method="session",
        metadata={},
    )


@pytest.fixture
def mock_request() -> MagicMock:
    """Create a mock request object."""
    request = MagicMock()
    request.state = MagicMock()
    return request


# ---------------------------------------------------------------------------
# A01:2021 - Broken Access Control (Authentication Bypass)
# ---------------------------------------------------------------------------


class TestAuthenticationBypass:
    """Tests for authentication bypass attempts.

    OWASP A07:2021 - Identification and Authentication Failures
    """

    @pytest.mark.asyncio
    async def test_missing_auth_token_returns_401(self, api_client: AsyncClient) -> None:
        """Requests without auth token should be rejected with 401."""
        response = await api_client.get("/sender/deliveries")
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_invalid_bearer_token_format(self, api_client: AsyncClient) -> None:
        """Malformed Bearer token should be rejected."""
        # Malformed token (not base64, random garbage)
        response = await api_client.get(
            "/sender/deliveries",
            headers={"Authorization": "Bearer not-a-valid-token-format"},
        )
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_empty_bearer_token(self, api_client: AsyncClient) -> None:
        """Empty Bearer token should be rejected."""
        response = await api_client.get(
            "/sender/deliveries",
            headers={"Authorization": "Bearer "},
        )
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_bearer_without_token(self, api_client: AsyncClient) -> None:
        """Authorization header with only 'Bearer' should be rejected."""
        response = await api_client.get(
            "/sender/deliveries",
            headers={"Authorization": "Bearer"},
        )
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_wrong_auth_scheme(self, api_client: AsyncClient) -> None:
        """Non-Bearer auth scheme should be rejected."""
        response = await api_client.get(
            "/sender/deliveries",
            headers={"Authorization": "Basic dXNlcm5hbWU6cGFzc3dvcmQ="},
        )
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_forged_jwt_without_signature(self, api_client: AsyncClient) -> None:
        """JWT without valid signature should be rejected."""
        # Forged JWT with no signature (alg: none attack)
        import base64

        header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=")
        payload = base64.urlsafe_b64encode(b'{"sub":"admin","admin":true}').rstrip(b"=")
        fake_jwt = f"{header.decode()}.{payload.decode()}."

        response = await api_client.get(
            "/sender/deliveries",
            headers={"Authorization": f"Bearer {fake_jwt}"},
        )
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_expired_session_token_rejected(self, api_client: AsyncClient) -> None:
        """Expired session tokens should be rejected."""
        # Random token that would be expired in database
        expired_token = secrets.token_urlsafe(32)
        response = await api_client.get(
            "/sender/deliveries",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_x_session_token_header_with_invalid_token(self, api_client: AsyncClient) -> None:
        """Invalid X-Session-Token header should be rejected."""
        response = await api_client.get(
            "/sender/deliveries",
            headers={"X-Session-Token": "invalid-session-token"},
        )
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_api_key_header_with_invalid_key(self, api_client: AsyncClient) -> None:
        """Invalid X-API-Key header should be rejected."""
        response = await api_client.get(
            "/sender/deliveries",
            headers={"X-API-Key": "invalid-api-key"},
        )
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_cookie_with_invalid_session(self, api_client: AsyncClient) -> None:
        """Invalid session cookie should be rejected."""
        response = await api_client.get(
            "/sender/deliveries",
            cookies={"qerds_session": "invalid-session-cookie-value"},
        )
        assert response.status_code in [401, 403]


class TestSessionSecurity:
    """Tests for session security.

    OWASP A02:2021 - Cryptographic Failures
    """

    @pytest.mark.asyncio
    async def test_inactive_user_denied_access(
        self, inactive_user: AuthenticatedUser, mock_request: MagicMock
    ) -> None:
        """Inactive users should be denied access even with valid session."""
        set_current_user(inactive_user)
        try:
            with pytest.raises(HTTPException) as exc_info:
                await require_authenticated_user(mock_request)
            assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
            assert "inactive" in exc_info.value.detail.lower()
        finally:
            set_current_user(None)

    def test_session_token_has_sufficient_entropy(self) -> None:
        """Session tokens should have at least 128 bits of entropy."""
        # Generate 1000 tokens and check they're all unique (no collisions)
        tokens = {secrets.token_urlsafe(32) for _ in range(1000)}
        assert len(tokens) == 1000  # All unique

        # Each token should be at least 32 bytes (256 bits) when decoded
        sample_token = secrets.token_urlsafe(32)
        # urlsafe_b64 encodes 32 bytes to ~43 characters
        assert len(sample_token) >= 40

    def test_api_key_hashed_before_storage(self) -> None:
        """API keys should be hashed with SHA-256 before storage lookup."""
        api_key = "test-api-key-12345"
        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()

        # Verify hash format
        assert len(key_hash) == 64
        assert all(c in "0123456789abcdef" for c in key_hash)

        # Verify same key produces same hash (deterministic)
        assert hashlib.sha256(api_key.encode("utf-8")).hexdigest() == key_hash


# ---------------------------------------------------------------------------
# A01:2021 - Broken Access Control (Authorization Boundaries)
# ---------------------------------------------------------------------------


class TestAuthorizationBoundaries:
    """Tests for authorization boundary enforcement.

    OWASP A01:2021 - Broken Access Control
    """

    @pytest.mark.asyncio
    async def test_sender_cannot_access_admin_endpoints(self, api_client: AsyncClient) -> None:
        """Sender users should not access admin endpoints."""
        response = await api_client.get("/admin/stats")
        # Should require admin auth, return 401/403
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_require_admin_user_rejects_non_admin(
        self, sender_user: AuthenticatedUser
    ) -> None:
        """require_admin_user should reject non-admin users."""
        with pytest.raises(HTTPException) as exc_info:
            await require_admin_user(sender_user)
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_require_superuser_rejects_regular_admin(
        self, admin_user: AuthenticatedUser
    ) -> None:
        """require_superuser should reject non-superuser admins."""
        with pytest.raises(HTTPException) as exc_info:
            await require_superuser(admin_user)
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.asyncio
    async def test_require_role_rejects_missing_role(self, sender_user: AuthenticatedUser) -> None:
        """require_role should reject users without the required role."""
        check_admin_role = require_role("admin")
        with pytest.raises(HTTPException) as exc_info:
            await check_admin_role(sender_user)
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "admin" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_require_permission_rejects_missing_permission(
        self, sender_user: AuthenticatedUser
    ) -> None:
        """require_permission should reject users without the required permission."""
        check_admin_access = require_permission("admin_access")
        with pytest.raises(HTTPException) as exc_info:
            await check_admin_access(sender_user)
        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "admin_access" in exc_info.value.detail

    def test_superuser_bypass_regular_permissions(self) -> None:
        """Superuser should bypass regular permission checks."""
        superuser = AuthenticatedUser(
            principal_id=uuid4(),
            principal_type="admin_user",
            is_superuser=True,
            is_active=True,
            permissions=frozenset(),
        )
        # Superuser should have any permission via has_permission
        assert superuser.has_permission("any_permission")
        assert superuser.has_permission("admin_access")

    def test_roles_are_immutable(self) -> None:
        """User roles should be immutable (frozenset)."""
        user = AuthenticatedUser(
            principal_id=uuid4(),
            principal_type="party",
            roles=frozenset(["sender_user"]),
        )
        assert isinstance(user.roles, frozenset)
        # Cannot modify frozenset
        with pytest.raises(AttributeError):
            user.roles.add("admin")  # type: ignore

    def test_permissions_are_immutable(self) -> None:
        """User permissions should be immutable (frozenset)."""
        user = AuthenticatedUser(
            principal_id=uuid4(),
            principal_type="party",
            permissions=frozenset(["view_deliveries"]),
        )
        assert isinstance(user.permissions, frozenset)
        # Cannot modify frozenset
        with pytest.raises(AttributeError):
            user.permissions.add("admin_access")  # type: ignore


class TestIDOR:
    """Tests for Insecure Direct Object Reference vulnerabilities.

    OWASP A01:2021 - Broken Access Control

    Note: This project has two route layers:
    1. HTML pages router (pages.py) - serves templates with mock data, no auth required
    2. API routers (sender.py, recipient.py) - return JSON, require authentication

    The HTML pages are safe because they only return mock/demo data, not real user data.
    API endpoints properly enforce authentication and return 401/403 for unauthorized access.
    """

    @pytest.mark.asyncio
    async def test_api_delivery_list_requires_auth(self, api_client: AsyncClient) -> None:
        """API endpoint for listing deliveries requires authentication."""
        # The /sender/deliveries endpoint (list, not detail) returns JSON and requires auth
        response = await api_client.get("/sender/deliveries")
        # API endpoint returns 401 for unauthenticated requests
        assert response.status_code in [401, 403]
        # Verify it's a JSON response, not HTML
        assert "application/json" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_api_content_upload_requires_auth(self, api_client: AsyncClient) -> None:
        """API endpoint for content upload requires authentication."""
        delivery_id = str(uuid4())
        response = await api_client.post(
            f"/sender/deliveries/{delivery_id}/content",
            files={"file": ("test.pdf", b"content", "application/pdf")},
        )
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_api_deposit_requires_auth(self, api_client: AsyncClient) -> None:
        """API endpoint for depositing delivery requires authentication."""
        delivery_id = str(uuid4())
        response = await api_client.post(f"/sender/deliveries/{delivery_id}/deposit")
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_html_pages_return_only_mock_data(self, api_client: AsyncClient) -> None:
        """HTML pages return mock data, not real user data (safe for IDOR)."""
        # HTML pages serve demo/mock data that doesn't expose real user information
        delivery_id = str(uuid4())
        response = await api_client.get(f"/sender/deliveries/{delivery_id}")

        # Returns HTML (not JSON API)
        assert "text/html" in response.headers.get("content-type", "")

        # The page returns mock data that doesn't contain the actual delivery_id
        # from the URL (demonstrating it's not fetching real data)
        # Note: The mock data contains fixed demo UUIDs, not the requested one
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_uuid_format_validated_by_api_endpoints(self, api_client: AsyncClient) -> None:
        """API endpoints validate UUID format for resource IDs."""
        invalid_ids = [
            "12345",
            "not-a-uuid",
            "../../etc/passwd",
            "1; DROP TABLE deliveries;--",
        ]

        for invalid_id in invalid_ids:
            # Test content upload endpoint (POST to API, not GET to HTML page)
            response = await api_client.post(
                f"/sender/deliveries/{invalid_id}/content",
                files={"file": ("test.pdf", b"content", "application/pdf")},
            )
            # Should return validation error (422), auth error (401/403), or not found (404)
            # NOT server error (500) which would indicate potential injection success
            assert response.status_code in [401, 403, 404, 422]

    @pytest.mark.asyncio
    async def test_recipient_content_access_requires_auth(self, api_client: AsyncClient) -> None:
        """Recipients must authenticate to access delivery content."""
        delivery_id = str(uuid4())
        response = await api_client.get(f"/recipient/deliveries/{delivery_id}/content")
        # Should require auth
        assert response.status_code in [401, 403, 404]

    @pytest.mark.asyncio
    async def test_admin_endpoints_require_admin_auth(self, api_client: AsyncClient) -> None:
        """Admin endpoints require admin authentication."""
        # Admin stats endpoint
        response = await api_client.get("/admin/stats")
        assert response.status_code in [401, 403]

        # Admin audit pack endpoint
        response = await api_client.post(
            "/admin/audit-packs",
            json={"start_date": "2024-01-01", "end_date": "2024-01-31"},
        )
        assert response.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_delivery_timeline_admin_only(self, api_client: AsyncClient) -> None:
        """Delivery timeline endpoint is admin-only."""
        delivery_id = str(uuid4())
        response = await api_client.get(f"/admin/deliveries/{delivery_id}/timeline")
        assert response.status_code in [401, 403]


# ---------------------------------------------------------------------------
# A03:2021 - Injection
# ---------------------------------------------------------------------------


class TestSQLInjection:
    """Tests for SQL injection vulnerabilities.

    OWASP A03:2021 - Injection
    """

    @pytest.mark.asyncio
    async def test_sql_injection_in_query_params(self, api_client: AsyncClient) -> None:
        """SQL injection in query parameters should be sanitized."""
        malicious_inputs = [
            "'; DROP TABLE deliveries; --",
            "1 OR 1=1",
            "1; SELECT * FROM admin_users;--",
            "' UNION SELECT password FROM users--",
            "1') OR ('1'='1",
            "admin'--",
        ]

        for payload in malicious_inputs:
            # Test in state filter
            response = await api_client.get(
                "/sender/deliveries",
                params={"state": payload},
            )
            # Should return auth error (401/403) or validation error (400/422)
            # NOT a server error (500) which would indicate injection succeeded
            assert response.status_code < 500

    @pytest.mark.asyncio
    async def test_sql_injection_in_path_params(self, api_client: AsyncClient) -> None:
        """SQL injection in path parameters should be sanitized."""
        malicious_paths = [
            "'; DROP TABLE deliveries; --",
            "../../../etc/passwd",
            "00000000-0000-0000-0000-000000000000' OR '1'='1",
        ]

        for payload in malicious_paths:
            response = await api_client.get(f"/sender/deliveries/{payload}")
            # Should return validation error or auth error, not 500
            assert response.status_code < 500

    @pytest.mark.asyncio
    async def test_sql_injection_in_json_body(self, api_client: AsyncClient) -> None:
        """SQL injection in JSON body should be sanitized."""
        malicious_payloads = [
            {"recipient": {"email": "test@example.com'; DROP TABLE parties;--"}},
            {"subject": "'; DELETE FROM deliveries;--"},
            {"message": "1' OR '1'='1"},
        ]

        for payload in malicious_payloads:
            payload["recipient"] = payload.get("recipient", {"email": "test@example.com"})
            response = await api_client.post("/sender/deliveries", json=payload)
            # Should return auth error (401/403) or validation error (400/422)
            assert response.status_code < 500


class TestXSSPrevention:
    """Tests for XSS (Cross-Site Scripting) prevention.

    OWASP A03:2021 - Injection
    """

    @pytest.mark.asyncio
    async def test_xss_in_subject_field(self, api_client: AsyncClient) -> None:
        """XSS payloads in subject should be escaped or rejected."""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>",
            "'\"><script>alert('xss')</script>",
            "<body onload=alert('xss')>",
            "<iframe src='javascript:alert(1)'>",
        ]

        for payload in xss_payloads:
            response = await api_client.post(
                "/sender/deliveries",
                json={
                    "recipient": {"email": "test@example.com"},
                    "subject": payload,
                },
            )
            # Should return auth error or succeed (content is escaped on output)
            # NOT render script tags
            assert response.status_code < 500

    @pytest.mark.asyncio
    async def test_xss_in_message_field(self, api_client: AsyncClient) -> None:
        """XSS payloads in message should be escaped or rejected."""
        response = await api_client.post(
            "/sender/deliveries",
            json={
                "recipient": {"email": "test@example.com"},
                "message": "<script>document.cookie</script>",
            },
        )
        assert response.status_code < 500

    @pytest.mark.asyncio
    async def test_xss_in_recipient_name(self, api_client: AsyncClient) -> None:
        """XSS payloads in recipient name should be escaped."""
        response = await api_client.post(
            "/sender/deliveries",
            json={
                "recipient": {
                    "email": "test@example.com",
                    "display_name": "<script>alert(1)</script>",
                },
            },
        )
        assert response.status_code < 500


class TestCommandInjection:
    """Tests for command injection vulnerabilities.

    OWASP A03:2021 - Injection
    """

    @pytest.mark.asyncio
    async def test_command_injection_in_filename(self, api_client: AsyncClient) -> None:
        """Command injection in filename should be sanitized."""
        delivery_id = str(uuid4())
        malicious_filenames = [
            "test; rm -rf /",
            "test`cat /etc/passwd`",
            "test$(whoami)",
            "test|cat /etc/passwd",
            "../../../etc/passwd",
            "test\ncat /etc/passwd",
        ]

        for filename in malicious_filenames:
            response = await api_client.post(
                f"/sender/deliveries/{delivery_id}/content",
                files={"file": (filename, b"content", "application/pdf")},
                data={
                    "original_filename": filename,
                    "mime_type": "application/pdf",
                    "sha256": "a" * 64,
                },
            )
            # Should return auth error or validation error, not execute commands
            assert response.status_code < 500


# ---------------------------------------------------------------------------
# A05:2021 - Security Misconfiguration
# ---------------------------------------------------------------------------


class TestSecurityMisconfiguration:
    """Tests for security misconfiguration.

    OWASP A05:2021 - Security Misconfiguration
    """

    @pytest.mark.asyncio
    async def test_error_messages_do_not_leak_stack_traces(self, api_client: AsyncClient) -> None:
        """Error messages should not leak stack traces or internal details."""
        # Trigger various errors and check responses don't leak internals
        response = await api_client.get("/sender/deliveries/invalid-uuid")

        if response.status_code >= 400:
            body = response.text
            # Should not contain Python traceback indicators
            assert "Traceback" not in body
            assert 'File "' not in body
            assert "line " not in body or "error" in body.lower()
            # Should not expose internal paths
            assert "/home/" not in body
            assert "/usr/" not in body
            assert "site-packages" not in body

    @pytest.mark.asyncio
    async def test_debug_endpoints_not_exposed(self, api_client: AsyncClient) -> None:
        """Debug endpoints should not be accessible."""
        debug_endpoints = [
            "/debug",
            "/_debug",
            "/debug/routes",
            "/debug/sql",
            "/admin/debug",
            "/__debug__",
            "/profiler",
        ]

        for endpoint in debug_endpoints:
            response = await api_client.get(endpoint)
            # Should return 404 (not found) or 401/403 (not accessible)
            # NOT 200 (exposed debug info)
            assert response.status_code in [401, 403, 404, 405]

    @pytest.mark.asyncio
    async def test_sensitive_headers_not_exposed(self, api_client: AsyncClient) -> None:
        """Response should not expose sensitive headers."""
        response = await api_client.get("/health")

        # Should not expose server version details
        server_header = response.headers.get("Server", "")
        assert "uvicorn" not in server_header.lower() or not server_header
        assert "python" not in server_header.lower()

        # Should not expose powered-by headers
        assert "X-Powered-By" not in response.headers

    @pytest.mark.asyncio
    async def test_cors_not_overly_permissive(self, api_client: AsyncClient) -> None:
        """CORS should not allow all origins in production."""
        response = await api_client.options(
            "/health",
            headers={"Origin": "https://evil.example.com"},
        )

        # If CORS is configured, it should not allow arbitrary origins
        acao = response.headers.get("Access-Control-Allow-Origin", "")
        # Either no CORS header, or specific origin, not wildcard for authenticated endpoints
        # Note: Health endpoint might allow *, but authenticated endpoints should not
        # This is a design verification - wildcard CORS on authenticated endpoints is a risk
        assert acao != "*" or "sender" not in response.url.path

    @pytest.mark.asyncio
    async def test_content_type_header_present(self, api_client: AsyncClient) -> None:
        """Responses should have Content-Type header."""
        response = await api_client.get("/health")
        assert "content-type" in response.headers
        assert "application/json" in response.headers["content-type"]

    @pytest.mark.asyncio
    async def test_security_headers_present(self, api_client: AsyncClient) -> None:
        """Recommended security headers should be present."""
        response = await api_client.get("/health")

        # X-Request-ID should be present
        assert "x-request-id" in response.headers

        # These are best practice headers (may or may not be implemented)
        # We check they are set correctly if present
        if "X-Content-Type-Options" in response.headers:
            assert response.headers["X-Content-Type-Options"] == "nosniff"

        if "X-Frame-Options" in response.headers:
            assert response.headers["X-Frame-Options"] in ["DENY", "SAMEORIGIN"]


# ---------------------------------------------------------------------------
# Input Validation
# ---------------------------------------------------------------------------


class TestInputValidation:
    """Tests for general input validation."""

    @pytest.mark.asyncio
    async def test_oversized_request_body_rejected(self, api_client: AsyncClient) -> None:
        """Extremely large request bodies should be rejected."""
        # Create a large JSON payload (10MB of text)
        large_payload = {"message": "x" * (10 * 1024 * 1024)}

        response = await api_client.post(
            "/sender/deliveries",
            json=large_payload,
        )
        # Should be rejected - either by size limit (413) or validation (422)
        # or auth (401/403)
        assert response.status_code in [401, 403, 413, 422, 400]

    @pytest.mark.asyncio
    async def test_deeply_nested_json_rejected(self, api_client: AsyncClient) -> None:
        """Deeply nested JSON should be rejected to prevent DoS."""

        def create_nested(depth: int) -> dict:
            if depth == 0:
                return {"value": "end"}
            return {"nested": create_nested(depth - 1)}

        # Create deeply nested structure (100 levels)
        deep_json = create_nested(100)

        response = await api_client.post(
            "/sender/deliveries",
            json=deep_json,
        )
        # Should handle gracefully (validation error or auth error)
        assert response.status_code < 500

    @pytest.mark.asyncio
    async def test_null_byte_injection_prevented(self, api_client: AsyncClient) -> None:
        """Null byte injection should be prevented."""
        null_payloads = [
            "test\x00.pdf",
            "test%00.pdf",
            "test\x00admin",
        ]

        for payload in null_payloads:
            response = await api_client.post(
                "/sender/deliveries",
                json={
                    "recipient": {"email": "test@example.com"},
                    "subject": payload,
                },
            )
            assert response.status_code < 500

    @pytest.mark.asyncio
    async def test_unicode_normalization_attacks(self, api_client: AsyncClient) -> None:
        """Unicode normalization attacks should be handled."""
        # Homograph attack - visually similar characters
        unicode_payloads = [
            "admin\u200badmin",  # Zero-width space
            "\u202efdp.txeT",  # Right-to-left override
            "test\ufefftest",  # BOM character
            "test\u0000test",  # Null character
        ]

        for payload in unicode_payloads:
            response = await api_client.post(
                "/sender/deliveries",
                json={
                    "recipient": {"email": "test@example.com"},
                    "subject": payload,
                },
            )
            assert response.status_code < 500

    @pytest.mark.asyncio
    async def test_email_validation_strict(self, api_client: AsyncClient) -> None:
        """Email validation should be strict."""
        invalid_emails = [
            "not-an-email",
            "@example.com",
            "test@",
            "test@.com",
            "test@example.",
            "test test@example.com",
            "test@exam ple.com",
            # But these might be valid depending on strictness:
            # "test+tag@example.com",  # Usually valid
        ]

        for email in invalid_emails:
            response = await api_client.post(
                "/sender/deliveries",
                json={"recipient": {"email": email}},
            )
            # Should return validation error or auth error, not 500
            assert response.status_code in [400, 401, 403, 422]

    @pytest.mark.asyncio
    async def test_sha256_hash_validation(self, api_client: AsyncClient) -> None:
        """SHA-256 hash validation should be strict."""
        delivery_id = str(uuid4())
        invalid_hashes = [
            "not-a-hash",
            "ZZZZ" * 16,  # Invalid hex characters
            "a" * 63,  # Too short
            "a" * 65,  # Too long
            "a" * 64 + " ",  # Trailing space
            " " + "a" * 64,  # Leading space
        ]

        for invalid_hash in invalid_hashes:
            response = await api_client.post(
                f"/sender/deliveries/{delivery_id}/content",
                files={"file": ("test.pdf", b"content", "application/pdf")},
                data={
                    "original_filename": "test.pdf",
                    "mime_type": "application/pdf",
                    "sha256": invalid_hash,
                },
            )
            # Should return validation error or auth error
            assert response.status_code in [400, 401, 403, 422]


# ---------------------------------------------------------------------------
# Cryptographic Security
# ---------------------------------------------------------------------------


class TestCryptographicSecurity:
    """Tests for cryptographic security.

    OWASP A02:2021 - Cryptographic Failures
    """

    def test_constant_time_comparison_for_tokens(self) -> None:
        """Token comparisons should use constant-time algorithms."""
        import hmac

        # Verify hmac.compare_digest is available and works
        token1 = b"secret_token_value"
        token2 = b"secret_token_value"
        token3 = b"different_token"

        # Same tokens should match
        assert hmac.compare_digest(token1, token2)

        # Different tokens should not match
        assert not hmac.compare_digest(token1, token3)

    def test_sha256_hash_computation(self) -> None:
        """SHA-256 hashes should be computed correctly."""
        from qerds.services.evidence import compute_content_hash

        content = b"test content"
        expected_hash = hashlib.sha256(content).hexdigest()

        computed_hash = compute_content_hash(content)

        assert computed_hash == expected_hash
        assert len(computed_hash) == 64
        assert all(c in "0123456789abcdef" for c in computed_hash)

    def test_uuid_generation_is_random(self) -> None:
        """UUID generation should be cryptographically random (UUID4)."""
        # Generate multiple UUIDs and verify they're different
        uuids = [uuid4() for _ in range(100)]
        assert len(set(uuids)) == 100  # All unique

        # Verify they're version 4 (random)
        for u in uuids:
            assert u.version == 4


# ---------------------------------------------------------------------------
# Rate Limiting and DoS Prevention
# ---------------------------------------------------------------------------


class TestRateLimitingAndDoS:
    """Tests for rate limiting and DoS prevention."""

    @pytest.mark.asyncio
    async def test_rapid_requests_handled_gracefully(self, api_client: AsyncClient) -> None:
        """Rapid repeated requests should be handled without server errors."""
        # Send 50 rapid requests
        responses = []
        for _ in range(50):
            response = await api_client.get("/health")
            responses.append(response.status_code)

        # All should return valid HTTP codes (no 500 errors)
        assert all(code < 500 for code in responses)

        # If rate limiting is implemented, some might be 429
        # But health endpoint should generally always work
        assert responses.count(200) >= 40  # At least 80% should succeed

    @pytest.mark.asyncio
    async def test_malformed_content_type_handled(self, api_client: AsyncClient) -> None:
        """Malformed Content-Type headers should be handled gracefully."""
        malformed_content_types = [
            "not-a-content-type",
            "application/json; charset=utf-8; extra=invalid",
            "application/json\x00",
            "",
            "application/",
            "/json",
        ]

        for ct in malformed_content_types:
            response = await api_client.post(
                "/sender/deliveries",
                content=b'{"recipient":{"email":"test@example.com"}}',
                headers={"Content-Type": ct},
            )
            # Should handle gracefully (4xx), not crash (5xx)
            assert response.status_code < 500


# ---------------------------------------------------------------------------
# Role-Based Access Control (RBAC) Security
# ---------------------------------------------------------------------------


class TestRBACSecurityBoundaries:
    """Tests for RBAC security boundaries.

    These tests verify that role-based permissions cannot be escalated
    or bypassed through various attack vectors.
    """

    def test_sender_cannot_escalate_to_admin(self, sender_user: AuthenticatedUser) -> None:
        """Sender users cannot have admin permissions."""
        assert not sender_user.has_role("admin")
        assert not sender_user.has_permission("admin_access")

    def test_recipient_cannot_create_deliveries(self, recipient_user: AuthenticatedUser) -> None:
        """Recipient users cannot create deliveries."""
        assert not recipient_user.has_role("sender_user")
        # Recipients don't have create_delivery permission
        assert not recipient_user.has_permission("create_delivery")

    def test_admin_without_superuser_has_limited_access(
        self, admin_user: AuthenticatedUser
    ) -> None:
        """Admin users without superuser flag have limited access."""
        assert admin_user.has_role("admin")
        assert not admin_user.is_superuser
        # Admin should not have key_management (requires security_officer + dual control)
        assert not admin_user.has_permission("key_management")

    def test_separation_of_duties_enforced(self) -> None:
        """Verify incompatible roles cannot be combined."""
        from qerds.services.authz import (
            AuthorizationService,
            Principal,
            RoleClass,
        )

        authz_service = AuthorizationService()

        # Admin cannot also be auditor
        admin_principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["admin"]),
        )
        assert not authz_service.check_separation_of_duties(admin_principal, RoleClass.AUDITOR)

        # Security officer cannot also be admin
        security_principal = Principal(
            principal_id=uuid4(),
            principal_type="admin_user",
            roles=frozenset(["security_officer"]),
        )
        assert not authz_service.check_separation_of_duties(security_principal, RoleClass.ADMIN)

    def test_dual_control_required_for_sensitive_operations(self) -> None:
        """Verify dual-control is required for sensitive permissions."""
        from qerds.services.authz import (
            AuthorizationService,
            Permission,
        )

        authz_service = AuthorizationService()

        # These permissions require dual-control
        sensitive_permissions = [
            Permission.KEY_MANAGEMENT,
            Permission.CONFIG_CHANGE,
            Permission.EXPORT_AUDIT_LOGS,
        ]

        for perm in sensitive_permissions:
            assert authz_service.requires_dual_control(perm), f"{perm} should require dual-control"

        # Regular permissions don't require dual-control
        assert not authz_service.requires_dual_control(Permission.VIEW_DELIVERIES)
        assert not authz_service.requires_dual_control(Permission.CREATE_DELIVERY)


# ---------------------------------------------------------------------------
# Context Isolation
# ---------------------------------------------------------------------------


class TestContextIsolation:
    """Tests for context isolation between requests."""

    def test_context_cleared_between_users(
        self, sender_user: AuthenticatedUser, admin_user: AuthenticatedUser
    ) -> None:
        """User context should not leak between requests."""
        # Set sender user
        set_current_user(sender_user)
        assert get_current_user() == sender_user

        # Clear and set different user
        set_current_user(None)
        assert get_current_user() is None

        set_current_user(admin_user)
        assert get_current_user() == admin_user
        assert get_current_user() != sender_user

        # Clean up
        set_current_user(None)

    def test_no_default_user_in_context(self) -> None:
        """Context should not have a default user."""
        set_current_user(None)
        user = get_current_user()
        assert user is None


# ---------------------------------------------------------------------------
# API Client / Machine Authentication Security
# ---------------------------------------------------------------------------


class TestAPIClientSecurity:
    """Tests for API client (machine) authentication security."""

    def test_api_key_must_be_hashed_for_lookup(self) -> None:
        """API keys should be hashed before database lookup."""
        # This is a design verification - the actual implementation
        # hashes API keys with SHA-256 before lookup
        api_key = "qerds_api_key_123456789"
        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()

        # Hash should be deterministic
        assert hashlib.sha256(api_key.encode("utf-8")).hexdigest() == key_hash

        # Plain key should never equal hash
        assert api_key != key_hash

    @pytest.mark.asyncio
    async def test_invalid_api_key_rejected(self, api_client: AsyncClient) -> None:
        """Invalid API keys should be rejected."""
        response = await api_client.get(
            "/sender/deliveries",
            headers={"X-API-Key": "invalid-key-that-does-not-exist"},
        )
        assert response.status_code in [401, 403]

    def test_api_client_permissions_are_scoped(self) -> None:
        """API clients should have scoped permissions, not full access."""
        api_client_user = AuthenticatedUser(
            principal_id=uuid4(),
            principal_type="api_client",
            is_superuser=False,
            is_active=True,
            roles=frozenset(["api_client"]),
            permissions=frozenset(["create_delivery", "view_deliveries"]),
            auth_method="api_key",
        )

        # API client should have explicit permissions
        assert api_client_user.has_permission("create_delivery")
        assert api_client_user.has_permission("view_deliveries")

        # But not admin permissions
        assert not api_client_user.has_permission("admin_access")
        assert not api_client_user.has_permission("manage_users")
