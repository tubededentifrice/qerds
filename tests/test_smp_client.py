"""Tests for SMP client (BDXR/Peppol service metadata).

Covers: REQ-C04 (interoperability profile), EN 319 522-4-3 (SMP metadata)

Test Categories:
1. SMPConfig - configuration handling
2. URL Building - BDXR URL patterns
3. SMPClient - HTTP client behavior and error handling
4. Service metadata CRUD operations

Note: These tests use mocked HTTP responses to verify client behavior
without requiring a running phoss SMP instance.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch
from urllib.parse import quote

import httpx
import pytest

from qerds.services.smp_client import (
    PARTICIPANT_ID_SCHEME,
    ParticipantMetadata,
    ServiceEndpoint,
    SMPAuthError,
    SMPClient,
    SMPConfig,
    SMPConnectionError,
    SMPError,
    SMPNotFoundError,
)


def _make_response(
    status_code: int, text: str = "", json_data: dict | None = None
) -> httpx.Response:
    """Create an httpx.Response with a request object for raise_for_status()."""
    request = httpx.Request("GET", "http://test")
    if json_data is not None:
        text = json.dumps(json_data)
    return httpx.Response(status_code, text=text, request=request)


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def smp_config() -> SMPConfig:
    """Create a test SMP configuration."""
    return SMPConfig(
        base_url="http://localhost:8280",
        username="smp-admin",
        password="smp_admin_dev",
        timeout=10.0,
    )


@pytest.fixture
def sample_participant_id() -> str:
    """Sample participant ID for tests."""
    return "0088:1234567890123"


@pytest.fixture
def sample_document_type_id() -> str:
    """Sample document type ID for tests."""
    # Standard UBL 2.1 Invoice document type identifier
    return (
        "busdox-docid-qns::urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##UBL-2.1"
    )


@pytest.fixture
def sample_service_group_xml() -> str:
    """Sample service group XML for tests."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<ServiceGroup xmlns="http://docs.oasis-open.org/bdxr/ns/SMP/2016/05">
    <ParticipantIdentifier scheme="iso6523-actorid-upis">0088:1234567890123</ParticipantIdentifier>
    <ServiceMetadataReferenceCollection/>
</ServiceGroup>"""


@pytest.fixture
def sample_service_metadata_xml() -> str:
    """Sample service metadata XML for tests."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<ServiceMetadata xmlns="http://docs.oasis-open.org/bdxr/ns/SMP/2016/05">
    <ServiceInformation>
        <ProcessList>
            <Process>
                <ProcessIdentifier>urn:fdc:peppol.eu:2017:poacc:billing:01:1.0</ProcessIdentifier>
                <ServiceEndpointList>
                    <Endpoint transportProfile="peppol-transport-as4-v2_0">
                        <EndpointURI>https://example.com/as4</EndpointURI>
                    </Endpoint>
                </ServiceEndpointList>
            </Process>
        </ProcessList>
    </ServiceInformation>
</ServiceMetadata>"""


# =============================================================================
# TEST CLASS: SMPConfig
# =============================================================================


class TestSMPConfig:
    """Tests for SMP configuration dataclass."""

    def test_config_creation(self):
        """Verify config can be created with required fields."""
        config = SMPConfig(base_url="http://localhost:8280")
        assert config.base_url == "http://localhost:8280"
        assert config.username is None
        assert config.password is None
        assert config.timeout == 30.0  # default

    def test_config_with_auth(self, smp_config: SMPConfig):
        """Verify config includes authentication credentials."""
        assert smp_config.username == "smp-admin"
        assert smp_config.password == "smp_admin_dev"

    def test_config_from_env(self):
        """Verify config can be created from environment variables."""
        with patch.dict(
            "os.environ",
            {
                "SMP_BASE_URL": "http://test-smp:8080",
                "SMP_USERNAME": "test-user",
                "SMP_PASSWORD": "test-pass",
                "SMP_TIMEOUT": "60",
            },
        ):
            config = SMPConfig.from_env()
            assert config.base_url == "http://test-smp:8080"
            assert config.username == "test-user"
            assert config.password == "test-pass"
            assert config.timeout == 60.0

    def test_config_from_env_defaults(self):
        """Verify config uses defaults when env vars not set."""
        with patch.dict("os.environ", {}, clear=True):
            config = SMPConfig.from_env()
            assert config.base_url == "http://smp:8080"
            assert config.username is None
            assert config.password is None
            assert config.timeout == 30.0


# =============================================================================
# TEST CLASS: URL Building (BDXR Compliance)
# =============================================================================


class TestURLBuilding:
    """Tests for BDXR-compliant URL construction."""

    def test_participant_url_format(self, smp_config: SMPConfig, sample_participant_id: str):
        """Verify participant URL follows BDXR format: /{scheme}::{id}."""
        client = SMPClient(smp_config)
        url = client._participant_url(sample_participant_id)

        # BDXR format requires scheme::id, URL-encoded
        expected_encoded = quote(f"{PARTICIPANT_ID_SCHEME}::{sample_participant_id}", safe="")
        assert url == f"/{expected_encoded}"

    def test_participant_id_scheme(self):
        """Verify the participant ID scheme is iso6523-actorid-upis (BDXR standard)."""
        assert PARTICIPANT_ID_SCHEME == "iso6523-actorid-upis"

    def test_service_url_format(
        self,
        smp_config: SMPConfig,
        sample_participant_id: str,
        sample_document_type_id: str,
    ):
        """Verify service URL follows BDXR format: /{participant}/services/{doctype}."""
        client = SMPClient(smp_config)
        url = client._service_url(sample_participant_id, sample_document_type_id)

        # URL should contain participant path + /services/ + encoded doctype
        assert "/services/" in url
        encoded_doctype = quote(sample_document_type_id, safe="")
        assert url.endswith(f"/services/{encoded_doctype}")

    def test_url_encoding_preserves_colons_in_participant(self, smp_config: SMPConfig):
        """Verify colons in participant ID are properly URL-encoded."""
        client = SMPClient(smp_config)
        url = client._participant_url("0088:test:123")

        # Colons should be encoded as %3A in the URL
        assert "%3A" in url


# =============================================================================
# TEST CLASS: SMPClient Context Manager
# =============================================================================


class TestSMPClientContextManager:
    """Tests for async context manager behavior."""

    @pytest.mark.asyncio
    async def test_context_manager_creates_client(self, smp_config: SMPConfig):
        """Verify context manager creates HTTP client on enter."""
        client = SMPClient(smp_config)
        assert client._client is None

        async with client:
            assert client._client is not None
            assert isinstance(client._client, httpx.AsyncClient)

    @pytest.mark.asyncio
    async def test_context_manager_closes_client(self, smp_config: SMPConfig):
        """Verify context manager closes HTTP client on exit."""
        client = SMPClient(smp_config)

        async with client:
            pass

        assert client._client is None

    @pytest.mark.asyncio
    async def test_get_client_raises_outside_context(self, smp_config: SMPConfig):
        """Verify _get_client raises error when not in context."""
        client = SMPClient(smp_config)

        with pytest.raises(RuntimeError, match="must be used as async context manager"):
            client._get_client()


# =============================================================================
# TEST CLASS: Health Check
# =============================================================================


class TestHealthCheck:
    """Tests for SMP health check functionality."""

    @pytest.mark.asyncio
    async def test_health_check_success(self, smp_config: SMPConfig):
        """Verify health check returns status on success."""
        mock_response = _make_response(
            200,
            json_data={"smp.status": "OK", "smp.sql.db.connection-possible": True},
        )

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response

            async with SMPClient(smp_config) as client:
                result = await client.health_check()

            assert result["smp.status"] == "OK"
            mock_get.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_connection_error(self, smp_config: SMPConfig):
        """Verify health check raises SMPConnectionError on connection failure."""
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.ConnectError("Connection refused")

            async with SMPClient(smp_config) as client:
                with pytest.raises(SMPConnectionError, match="Cannot connect to SMP"):
                    await client.health_check()


# =============================================================================
# TEST CLASS: Participant Operations (Read)
# =============================================================================


class TestParticipantReadOperations:
    """Tests for reading participant metadata."""

    @pytest.mark.asyncio
    async def test_get_participant_success(
        self,
        smp_config: SMPConfig,
        sample_participant_id: str,
        sample_service_group_xml: str,
    ):
        """Verify get_participant returns XML on success."""
        mock_response = _make_response(200, text=sample_service_group_xml)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response

            async with SMPClient(smp_config) as client:
                result = await client.get_participant(sample_participant_id)

            assert "ServiceGroup" in result
            assert sample_participant_id in result

    @pytest.mark.asyncio
    async def test_get_participant_not_found(
        self, smp_config: SMPConfig, sample_participant_id: str
    ):
        """Verify get_participant raises SMPNotFoundError on 404."""
        mock_response = _make_response(404)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response

            async with SMPClient(smp_config) as client:
                with pytest.raises(SMPNotFoundError, match="Participant not found"):
                    await client.get_participant(sample_participant_id)

    @pytest.mark.asyncio
    async def test_get_participant_connection_error(
        self, smp_config: SMPConfig, sample_participant_id: str
    ):
        """Verify get_participant raises SMPConnectionError on connection failure."""
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.ConnectError("Connection refused")

            async with SMPClient(smp_config) as client:
                with pytest.raises(SMPConnectionError):
                    await client.get_participant(sample_participant_id)


# =============================================================================
# TEST CLASS: Service Metadata Operations (Read)
# =============================================================================


class TestServiceMetadataReadOperations:
    """Tests for reading service metadata."""

    @pytest.mark.asyncio
    async def test_get_service_metadata_success(
        self,
        smp_config: SMPConfig,
        sample_participant_id: str,
        sample_document_type_id: str,
        sample_service_metadata_xml: str,
    ):
        """Verify get_service_metadata returns XML on success."""
        mock_response = _make_response(200, text=sample_service_metadata_xml)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response

            async with SMPClient(smp_config) as client:
                result = await client.get_service_metadata(
                    sample_participant_id, sample_document_type_id
                )

            assert "ServiceMetadata" in result
            assert "Endpoint" in result

    @pytest.mark.asyncio
    async def test_get_service_metadata_not_found(
        self,
        smp_config: SMPConfig,
        sample_participant_id: str,
        sample_document_type_id: str,
    ):
        """Verify get_service_metadata raises SMPNotFoundError on 404."""
        mock_response = _make_response(404)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response

            async with SMPClient(smp_config) as client:
                with pytest.raises(SMPNotFoundError, match="Service metadata not found"):
                    await client.get_service_metadata(
                        sample_participant_id, sample_document_type_id
                    )


# =============================================================================
# TEST CLASS: Service Group Write Operations
# =============================================================================


class TestServiceGroupWriteOperations:
    """Tests for writing service group metadata."""

    @pytest.mark.asyncio
    async def test_put_service_group_success(
        self,
        smp_config: SMPConfig,
        sample_participant_id: str,
        sample_service_group_xml: str,
    ):
        """Verify put_service_group succeeds with authentication."""
        mock_response = _make_response(200)

        with patch("httpx.AsyncClient.put", new_callable=AsyncMock) as mock_put:
            mock_put.return_value = mock_response

            async with SMPClient(smp_config) as client:
                await client.put_service_group(sample_participant_id, sample_service_group_xml)

            mock_put.assert_called_once()

    @pytest.mark.asyncio
    async def test_put_service_group_auth_error_401(
        self,
        smp_config: SMPConfig,
        sample_participant_id: str,
        sample_service_group_xml: str,
    ):
        """Verify put_service_group raises SMPAuthError on 401."""
        mock_response = _make_response(401)

        with patch("httpx.AsyncClient.put", new_callable=AsyncMock) as mock_put:
            mock_put.return_value = mock_response

            async with SMPClient(smp_config) as client:
                with pytest.raises(SMPAuthError, match="authentication failed"):
                    await client.put_service_group(sample_participant_id, sample_service_group_xml)

    @pytest.mark.asyncio
    async def test_put_service_group_auth_error_403(
        self,
        smp_config: SMPConfig,
        sample_participant_id: str,
        sample_service_group_xml: str,
    ):
        """Verify put_service_group raises SMPAuthError on 403."""
        mock_response = _make_response(403)

        with patch("httpx.AsyncClient.put", new_callable=AsyncMock) as mock_put:
            mock_put.return_value = mock_response

            async with SMPClient(smp_config) as client:
                with pytest.raises(SMPAuthError, match="authorization denied"):
                    await client.put_service_group(sample_participant_id, sample_service_group_xml)

    @pytest.mark.asyncio
    async def test_delete_service_group_success(
        self, smp_config: SMPConfig, sample_participant_id: str
    ):
        """Verify delete_service_group succeeds with authentication."""
        mock_response = _make_response(200)

        with patch("httpx.AsyncClient.delete", new_callable=AsyncMock) as mock_delete:
            mock_delete.return_value = mock_response

            async with SMPClient(smp_config) as client:
                await client.delete_service_group(sample_participant_id)

            mock_delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_service_group_not_found(
        self, smp_config: SMPConfig, sample_participant_id: str
    ):
        """Verify delete_service_group raises SMPNotFoundError on 404."""
        mock_response = _make_response(404)

        with patch("httpx.AsyncClient.delete", new_callable=AsyncMock) as mock_delete:
            mock_delete.return_value = mock_response

            async with SMPClient(smp_config) as client:
                with pytest.raises(SMPNotFoundError, match="Participant not found"):
                    await client.delete_service_group(sample_participant_id)


# =============================================================================
# TEST CLASS: Service Metadata Write Operations
# =============================================================================


class TestServiceMetadataWriteOperations:
    """Tests for writing service metadata."""

    @pytest.mark.asyncio
    async def test_put_service_metadata_success(
        self,
        smp_config: SMPConfig,
        sample_participant_id: str,
        sample_document_type_id: str,
        sample_service_metadata_xml: str,
    ):
        """Verify put_service_metadata succeeds with authentication."""
        mock_response = _make_response(200)

        with patch("httpx.AsyncClient.put", new_callable=AsyncMock) as mock_put:
            mock_put.return_value = mock_response

            async with SMPClient(smp_config) as client:
                await client.put_service_metadata(
                    sample_participant_id,
                    sample_document_type_id,
                    sample_service_metadata_xml,
                )

            mock_put.assert_called_once()

    @pytest.mark.asyncio
    async def test_put_service_metadata_auth_error(
        self,
        smp_config: SMPConfig,
        sample_participant_id: str,
        sample_document_type_id: str,
        sample_service_metadata_xml: str,
    ):
        """Verify put_service_metadata raises SMPAuthError on auth failure."""
        mock_response = _make_response(401)

        with patch("httpx.AsyncClient.put", new_callable=AsyncMock) as mock_put:
            mock_put.return_value = mock_response

            async with SMPClient(smp_config) as client:
                with pytest.raises(SMPAuthError):
                    await client.put_service_metadata(
                        sample_participant_id,
                        sample_document_type_id,
                        sample_service_metadata_xml,
                    )

    @pytest.mark.asyncio
    async def test_delete_service_metadata_success(
        self,
        smp_config: SMPConfig,
        sample_participant_id: str,
        sample_document_type_id: str,
    ):
        """Verify delete_service_metadata succeeds with authentication."""
        mock_response = _make_response(200)

        with patch("httpx.AsyncClient.delete", new_callable=AsyncMock) as mock_delete:
            mock_delete.return_value = mock_response

            async with SMPClient(smp_config) as client:
                await client.delete_service_metadata(sample_participant_id, sample_document_type_id)

            mock_delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_service_metadata_not_found(
        self,
        smp_config: SMPConfig,
        sample_participant_id: str,
        sample_document_type_id: str,
    ):
        """Verify delete_service_metadata raises SMPNotFoundError on 404."""
        mock_response = _make_response(404)

        with patch("httpx.AsyncClient.delete", new_callable=AsyncMock) as mock_delete:
            mock_delete.return_value = mock_response

            async with SMPClient(smp_config) as client:
                with pytest.raises(SMPNotFoundError, match="Service metadata not found"):
                    await client.delete_service_metadata(
                        sample_participant_id, sample_document_type_id
                    )


# =============================================================================
# TEST CLASS: Data Models
# =============================================================================


class TestDataModels:
    """Tests for SMP data model classes."""

    def test_service_endpoint_creation(self):
        """Verify ServiceEndpoint can be created with all fields."""
        endpoint = ServiceEndpoint(
            endpoint_url="https://example.com/as4",
            transport_profile="peppol-transport-as4-v2_0",
            certificate="MIIBIjANBgkqhki...",
            service_description="Test AS4 endpoint",
        )

        assert endpoint.endpoint_url == "https://example.com/as4"
        assert endpoint.transport_profile == "peppol-transport-as4-v2_0"
        assert endpoint.certificate is not None
        assert endpoint.service_description is not None

    def test_service_endpoint_optional_fields(self):
        """Verify ServiceEndpoint works with only required fields."""
        endpoint = ServiceEndpoint(
            endpoint_url="https://example.com/as4",
            transport_profile="peppol-transport-as4-v2_0",
        )

        assert endpoint.certificate is None
        assert endpoint.service_description is None

    def test_participant_metadata_creation(self):
        """Verify ParticipantMetadata can be created with endpoints."""
        endpoints = [
            ServiceEndpoint(
                endpoint_url="https://example.com/as4",
                transport_profile="peppol-transport-as4-v2_0",
            )
        ]

        metadata = ParticipantMetadata(
            participant_id="0088:1234567890123",
            endpoints=endpoints,
            raw_xml="<ServiceGroup>...</ServiceGroup>",
        )

        assert metadata.participant_id == "0088:1234567890123"
        assert len(metadata.endpoints) == 1
        assert metadata.raw_xml is not None

    def test_service_endpoint_is_frozen(self):
        """Verify ServiceEndpoint is immutable (frozen dataclass)."""
        endpoint = ServiceEndpoint(
            endpoint_url="https://example.com/as4",
            transport_profile="peppol-transport-as4-v2_0",
        )

        with pytest.raises(AttributeError):
            endpoint.endpoint_url = "https://other.com/as4"  # type: ignore

    def test_participant_metadata_is_frozen(self):
        """Verify ParticipantMetadata is immutable (frozen dataclass)."""
        metadata = ParticipantMetadata(
            participant_id="0088:1234567890123",
            endpoints=[],
        )

        with pytest.raises(AttributeError):
            metadata.participant_id = "0088:9999999999999"  # type: ignore


# =============================================================================
# TEST CLASS: Exception Hierarchy
# =============================================================================


class TestExceptionHierarchy:
    """Tests for SMP exception classes."""

    def test_smp_error_is_base(self):
        """Verify SMPError is the base exception class."""
        assert issubclass(SMPConnectionError, SMPError)
        assert issubclass(SMPNotFoundError, SMPError)
        assert issubclass(SMPAuthError, SMPError)

    def test_exceptions_can_carry_message(self):
        """Verify exceptions can carry a message."""
        error = SMPConnectionError("Cannot connect to SMP at localhost:8280")
        assert "localhost:8280" in str(error)

        error = SMPNotFoundError("Participant not found: 0088:1234")
        assert "0088:1234" in str(error)

        error = SMPAuthError("Authentication failed")
        assert "Authentication" in str(error)
