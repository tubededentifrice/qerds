"""Tests for QERDS API application structure.

Tests cover:
- App factory (create_app)
- Namespace routers and health endpoints
- Request ID middleware
- Error handling middleware
- OpenAPI documentation endpoints
"""

import uuid

import pytest
from fastapi import FastAPI
from httpx import AsyncClient

from qerds.api import create_app
from qerds.api.middleware.errors import (
    APIError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ValidationAPIError,
    build_error_response,
)
from qerds.api.middleware.request_id import REQUEST_ID_HEADER, get_request_id


class TestAppFactory:
    """Tests for the create_app factory function."""

    def test_create_app_returns_fastapi_instance(self):
        """Test that create_app returns a FastAPI application."""
        app = create_app()
        assert isinstance(app, FastAPI)

    def test_create_app_sets_title(self):
        """Test that the app has correct title."""
        app = create_app()
        assert app.title == "QERDS API"

    def test_create_app_sets_version(self):
        """Test that the app has a version."""
        app = create_app()
        assert app.version == "0.1.0"

    def test_create_app_docs_url(self):
        """Test that docs URL is configured."""
        app = create_app()
        assert app.docs_url == "/api/docs"

    def test_create_app_redoc_url(self):
        """Test that redoc URL is configured."""
        app = create_app()
        assert app.redoc_url == "/api/redoc"

    def test_create_app_openapi_url(self):
        """Test that OpenAPI URL is configured."""
        app = create_app()
        assert app.openapi_url == "/api/openapi.json"

    def test_create_app_stores_settings_in_state(self):
        """Test that settings are stored in app state."""
        app = create_app()
        # Settings is None when not provided
        assert hasattr(app.state, "settings")


class TestHealthEndpoints:
    """Tests for health check endpoints across all namespaces."""

    @pytest.mark.asyncio
    async def test_root_health(self, api_client: AsyncClient):
        """Test the root health endpoint."""
        response = await api_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_sender_health(self, api_client: AsyncClient):
        """Test the sender namespace health endpoint."""
        response = await api_client.get("/sender/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["namespace"] == "sender"

    @pytest.mark.asyncio
    async def test_recipient_health(self, api_client: AsyncClient):
        """Test the recipient namespace health endpoint."""
        response = await api_client.get("/recipient/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["namespace"] == "recipient"

    @pytest.mark.asyncio
    async def test_verify_health(self, api_client: AsyncClient):
        """Test the verify namespace health endpoint."""
        response = await api_client.get("/verify/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["namespace"] == "verify"

    @pytest.mark.asyncio
    async def test_admin_health(self, api_client: AsyncClient):
        """Test the admin namespace health endpoint."""
        response = await api_client.get("/admin/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["namespace"] == "admin"


class TestRequestIDMiddleware:
    """Tests for the X-Request-ID middleware."""

    @pytest.mark.asyncio
    async def test_response_includes_request_id_header(self, api_client: AsyncClient):
        """Test that responses include X-Request-ID header."""
        response = await api_client.get("/health")
        assert REQUEST_ID_HEADER in response.headers
        # Should be a valid UUID
        request_id = response.headers[REQUEST_ID_HEADER]
        uuid.UUID(request_id)  # Raises if invalid

    @pytest.mark.asyncio
    async def test_provided_request_id_is_preserved(self, api_client: AsyncClient):
        """Test that a client-provided X-Request-ID is preserved."""
        custom_id = "custom-request-id-12345"
        response = await api_client.get("/health", headers={REQUEST_ID_HEADER: custom_id})
        assert response.headers[REQUEST_ID_HEADER] == custom_id

    @pytest.mark.asyncio
    async def test_generated_request_id_is_uuid(self, api_client: AsyncClient):
        """Test that generated request IDs are valid UUIDs."""
        response = await api_client.get("/health")
        request_id = response.headers[REQUEST_ID_HEADER]
        # Should not raise ValueError
        parsed = uuid.UUID(request_id)
        assert str(parsed) == request_id

    @pytest.mark.asyncio
    async def test_different_requests_get_different_ids(self, api_client: AsyncClient):
        """Test that different requests get different IDs."""
        response1 = await api_client.get("/health")
        response2 = await api_client.get("/health")
        id1 = response1.headers[REQUEST_ID_HEADER]
        id2 = response2.headers[REQUEST_ID_HEADER]
        assert id1 != id2


class TestErrorResponses:
    """Tests for error response middleware and helpers."""

    def test_build_error_response_basic(self):
        """Test basic error response building."""
        response = build_error_response(
            error="test_error",
            message="Test message",
            status_code=400,
        )
        assert response.status_code == 400
        # Parse the body (JSONResponse stores as bytes)
        import json

        body = json.loads(response.body.decode())
        assert body["error"] == "test_error"
        assert body["message"] == "Test message"

    def test_build_error_response_with_detail(self):
        """Test error response with additional detail."""
        response = build_error_response(
            error="validation_error",
            message="Validation failed",
            status_code=422,
            detail={"field": "email", "reason": "invalid format"},
        )
        import json

        body = json.loads(response.body.decode())
        assert body["detail"]["field"] == "email"
        assert body["detail"]["reason"] == "invalid format"

    def test_api_error_exception(self):
        """Test APIError exception structure."""
        error = APIError(
            error="custom_error",
            message="Something went wrong",
            status_code=418,
            detail={"tea": "pot"},
        )
        assert error.error == "custom_error"
        assert error.message == "Something went wrong"
        assert error.status_code == 418
        assert error.detail == {"tea": "pot"}

    def test_not_found_error(self):
        """Test NotFoundError exception."""
        error = NotFoundError(resource="delivery", identifier="abc123")
        assert error.error == "not_found"
        assert error.status_code == 404
        assert "delivery" in error.message
        assert "abc123" in error.message

    def test_validation_api_error(self):
        """Test ValidationAPIError exception."""
        error = ValidationAPIError(
            message="Invalid email format",
            detail={"field": "email"},
        )
        assert error.error == "validation_error"
        assert error.status_code == 400

    def test_authorization_error(self):
        """Test AuthorizationError exception."""
        error = AuthorizationError(message="Access denied")
        assert error.error == "forbidden"
        assert error.status_code == 403

    def test_authentication_error(self):
        """Test AuthenticationError exception."""
        error = AuthenticationError()
        assert error.error == "unauthorized"
        assert error.status_code == 401
        assert "Authentication required" in error.message


class TestOpenAPIDocumentation:
    """Tests for OpenAPI documentation endpoints."""

    @pytest.mark.asyncio
    async def test_openapi_json_available(self, api_client: AsyncClient):
        """Test that OpenAPI JSON spec is available."""
        response = await api_client.get("/api/openapi.json")
        assert response.status_code == 200
        data = response.json()
        assert "openapi" in data
        assert "info" in data
        assert data["info"]["title"] == "QERDS API"

    @pytest.mark.asyncio
    async def test_openapi_includes_all_namespaces(self, api_client: AsyncClient):
        """Test that OpenAPI spec includes all namespace paths."""
        response = await api_client.get("/api/openapi.json")
        data = response.json()
        paths = data.get("paths", {})

        # Check that all namespace health endpoints are documented
        assert "/sender/health" in paths
        assert "/recipient/health" in paths
        assert "/verify/health" in paths
        assert "/admin/health" in paths

    @pytest.mark.asyncio
    async def test_openapi_includes_namespace_tags_in_paths(self, api_client: AsyncClient):
        """Test that OpenAPI spec includes namespace tags in path operations."""
        response = await api_client.get("/api/openapi.json")
        data = response.json()
        paths = data.get("paths", {})

        # Verify that namespace endpoints have correct tags
        # Each namespace router specifies its tag in the APIRouter definition
        sender_health = paths.get("/sender/health", {}).get("get", {})
        assert "sender" in sender_health.get("tags", [])

        recipient_health = paths.get("/recipient/health", {}).get("get", {})
        assert "recipient" in recipient_health.get("tags", [])

        verify_health = paths.get("/verify/health", {}).get("get", {})
        assert "verify" in verify_health.get("tags", [])

        admin_health = paths.get("/admin/health", {}).get("get", {})
        assert "admin" in admin_health.get("tags", [])

    @pytest.mark.asyncio
    async def test_docs_endpoint_available(self, api_client: AsyncClient):
        """Test that Swagger UI docs endpoint is accessible."""
        response = await api_client.get("/api/docs")
        # Swagger UI returns HTML
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_redoc_endpoint_available(self, api_client: AsyncClient):
        """Test that ReDoc endpoint is accessible."""
        response = await api_client.get("/api/redoc")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")


class TestNotFoundHandling:
    """Tests for 404 handling on unknown routes."""

    @pytest.mark.asyncio
    async def test_unknown_route_returns_404(self, api_client: AsyncClient):
        """Test that unknown routes return 404."""
        response = await api_client.get("/unknown/endpoint")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_unknown_namespace_returns_404(self, api_client: AsyncClient):
        """Test that unknown namespace prefixes return 404."""
        response = await api_client.get("/invalid/health")
        assert response.status_code == 404


class TestRequestIdContextVar:
    """Tests for request ID context variable functionality."""

    def test_get_request_id_returns_none_outside_request(self):
        """Test that get_request_id returns None when not in request context."""
        # Outside of a request, should return None (the default)
        result = get_request_id()
        assert result is None
