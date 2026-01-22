"""SMP (Service Metadata Publisher) client for phoss SMP integration.

This module provides a client for interacting with phoss SMP to:
- Publish service metadata for QERDS endpoints
- Query participant metadata for routing decisions
- Manage certificates and endpoint information

Reference: https://github.com/phax/phoss-smp/wiki
ETSI EN 319 522: REQ-C04 (interoperability profile)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)

# BDXR participant ID scheme
PARTICIPANT_ID_SCHEME = "iso6523-actorid-upis"

# Default timeout for SMP API requests (seconds)
DEFAULT_TIMEOUT = 30.0


@dataclass(frozen=True)
class SMPConfig:
    """Configuration for SMP client."""

    base_url: str
    username: str | None = None
    password: str | None = None
    timeout: float = DEFAULT_TIMEOUT

    @classmethod
    def from_env(cls) -> SMPConfig:
        """Create config from environment variables."""
        import os

        return cls(
            base_url=os.environ.get("SMP_BASE_URL", "http://smp:8080"),
            username=os.environ.get("SMP_USERNAME"),
            password=os.environ.get("SMP_PASSWORD"),
            timeout=float(os.environ.get("SMP_TIMEOUT", DEFAULT_TIMEOUT)),
        )


@dataclass(frozen=True)
class ServiceEndpoint:
    """Service endpoint information for SMP metadata."""

    endpoint_url: str
    transport_profile: str
    certificate: str | None = None
    service_description: str | None = None


@dataclass(frozen=True)
class ParticipantMetadata:
    """Participant metadata from SMP lookup."""

    participant_id: str
    endpoints: list[ServiceEndpoint]
    raw_xml: str | None = None


class SMPError(Exception):
    """Base exception for SMP client errors."""

    pass


class SMPConnectionError(SMPError):
    """Failed to connect to SMP."""

    pass


class SMPNotFoundError(SMPError):
    """Participant or service metadata not found."""

    pass


class SMPAuthError(SMPError):
    """Authentication failed for SMP management API."""

    pass


class SMPClient:
    """Client for phoss SMP REST API.

    Supports both read operations (unauthenticated) and write operations
    (authenticated with basic auth).

    Example usage:
        config = SMPConfig(
            base_url="http://localhost:8280",
            username="smp-admin",
            password="smp_admin_dev",
        )
        client = SMPClient(config)

        # Query participant metadata
        metadata = await client.get_participant("0088:1234567890123")

        # Publish service metadata (requires auth)
        await client.put_service_group("0088:1234567890123", service_group_xml)
    """

    def __init__(self, config: SMPConfig) -> None:
        """Initialize SMP client with configuration."""
        self._config = config
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> SMPClient:
        """Enter async context manager."""
        self._client = httpx.AsyncClient(
            base_url=self._config.base_url,
            timeout=self._config.timeout,
            auth=(
                httpx.BasicAuth(self._config.username, self._config.password)
                if self._config.username and self._config.password
                else None
            ),
        )
        return self

    async def __aexit__(self, *args: object) -> None:
        """Exit async context manager."""
        if self._client:
            await self._client.aclose()
            self._client = None

    def _get_client(self) -> httpx.AsyncClient:
        """Get the HTTP client, raising if not in context."""
        if self._client is None:
            msg = "SMPClient must be used as async context manager"
            raise RuntimeError(msg)
        return self._client

    def _participant_url(self, participant_id: str) -> str:
        """Build URL for participant identifier.

        BDXR format: /{scheme}::{id}
        Example: /iso6523-actorid-upis::0088:1234567890123
        """
        # URL-encode the participant ID (colons are significant)
        encoded_id = quote(f"{PARTICIPANT_ID_SCHEME}::{participant_id}", safe="")
        return f"/{encoded_id}"

    def _service_url(self, participant_id: str, document_type_id: str) -> str:
        """Build URL for service metadata.

        BDXR format: /{participant}/services/{doctype}
        """
        encoded_doctype = quote(document_type_id, safe="")
        return f"{self._participant_url(participant_id)}/services/{encoded_doctype}"

    async def health_check(self) -> dict[str, object]:
        """Check SMP health status.

        Returns:
            Status dictionary from /status endpoint.

        Raises:
            SMPConnectionError: If SMP is unreachable.
        """
        client = self._get_client()
        try:
            response = await client.get("/status")
            response.raise_for_status()
            return response.json()
        except httpx.ConnectError as e:
            raise SMPConnectionError(f"Cannot connect to SMP at {self._config.base_url}") from e
        except httpx.HTTPStatusError as e:
            raise SMPError(f"SMP health check failed: {e.response.status_code}") from e

    async def get_participant(self, participant_id: str) -> str:
        """Get service group for a participant.

        Args:
            participant_id: Participant identifier (e.g., "0088:1234567890123")

        Returns:
            XML string of service group metadata.

        Raises:
            SMPNotFoundError: Participant not found.
            SMPConnectionError: Cannot connect to SMP.
        """
        client = self._get_client()
        url = self._participant_url(participant_id)

        try:
            response = await client.get(url, headers={"Accept": "application/xml"})
            if response.status_code == 404:
                raise SMPNotFoundError(f"Participant not found: {participant_id}")
            response.raise_for_status()
            return response.text
        except httpx.ConnectError as e:
            raise SMPConnectionError(f"Cannot connect to SMP: {e}") from e
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise SMPNotFoundError(f"Participant not found: {participant_id}") from e
            raise SMPError(f"SMP request failed: {e.response.status_code}") from e

    async def get_service_metadata(self, participant_id: str, document_type_id: str) -> str:
        """Get service metadata for a participant and document type.

        Args:
            participant_id: Participant identifier.
            document_type_id: Document type identifier.

        Returns:
            XML string of service metadata.

        Raises:
            SMPNotFoundError: Service metadata not found.
            SMPConnectionError: Cannot connect to SMP.
        """
        client = self._get_client()
        url = self._service_url(participant_id, document_type_id)

        try:
            response = await client.get(url, headers={"Accept": "application/xml"})
            if response.status_code == 404:
                raise SMPNotFoundError(
                    f"Service metadata not found: {participant_id}/{document_type_id}"
                )
            response.raise_for_status()
            return response.text
        except httpx.ConnectError as e:
            raise SMPConnectionError(f"Cannot connect to SMP: {e}") from e
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise SMPNotFoundError(
                    f"Service metadata not found: {participant_id}/{document_type_id}"
                ) from e
            raise SMPError(f"SMP request failed: {e.response.status_code}") from e

    async def put_service_group(self, participant_id: str, service_group_xml: str) -> None:
        """Create or update service group for a participant.

        Requires authentication.

        Args:
            participant_id: Participant identifier.
            service_group_xml: Service group XML document.

        Raises:
            SMPAuthError: Authentication failed.
            SMPError: Request failed.
        """
        client = self._get_client()
        url = self._participant_url(participant_id)

        try:
            response = await client.put(
                url,
                content=service_group_xml,
                headers={"Content-Type": "application/xml"},
            )
            if response.status_code == 401:
                raise SMPAuthError("SMP authentication failed")
            if response.status_code == 403:
                raise SMPAuthError("SMP authorization denied")
            response.raise_for_status()
            logger.info("Published service group for participant %s", participant_id)
        except httpx.ConnectError as e:
            raise SMPConnectionError(f"Cannot connect to SMP: {e}") from e
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (401, 403):
                raise SMPAuthError("SMP authentication/authorization failed") from e
            raise SMPError(f"SMP request failed: {e.response.status_code}") from e

    async def put_service_metadata(
        self,
        participant_id: str,
        document_type_id: str,
        service_metadata_xml: str,
    ) -> None:
        """Create or update service metadata for a participant.

        Requires authentication.

        Args:
            participant_id: Participant identifier.
            document_type_id: Document type identifier.
            service_metadata_xml: Service metadata XML document.

        Raises:
            SMPAuthError: Authentication failed.
            SMPError: Request failed.
        """
        client = self._get_client()
        url = self._service_url(participant_id, document_type_id)

        try:
            response = await client.put(
                url,
                content=service_metadata_xml,
                headers={"Content-Type": "application/xml"},
            )
            if response.status_code == 401:
                raise SMPAuthError("SMP authentication failed")
            if response.status_code == 403:
                raise SMPAuthError("SMP authorization denied")
            response.raise_for_status()
            logger.info(
                "Published service metadata for %s/%s",
                participant_id,
                document_type_id,
            )
        except httpx.ConnectError as e:
            raise SMPConnectionError(f"Cannot connect to SMP: {e}") from e
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (401, 403):
                raise SMPAuthError("SMP authentication/authorization failed") from e
            raise SMPError(f"SMP request failed: {e.response.status_code}") from e

    async def delete_service_group(self, participant_id: str) -> None:
        """Delete service group for a participant.

        Requires authentication.

        Args:
            participant_id: Participant identifier.

        Raises:
            SMPAuthError: Authentication failed.
            SMPNotFoundError: Participant not found.
            SMPError: Request failed.
        """
        client = self._get_client()
        url = self._participant_url(participant_id)

        try:
            response = await client.delete(url)
            if response.status_code == 401:
                raise SMPAuthError("SMP authentication failed")
            if response.status_code == 403:
                raise SMPAuthError("SMP authorization denied")
            if response.status_code == 404:
                raise SMPNotFoundError(f"Participant not found: {participant_id}")
            response.raise_for_status()
            logger.info("Deleted service group for participant %s", participant_id)
        except httpx.ConnectError as e:
            raise SMPConnectionError(f"Cannot connect to SMP: {e}") from e
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (401, 403):
                raise SMPAuthError("SMP authentication/authorization failed") from e
            if e.response.status_code == 404:
                raise SMPNotFoundError(f"Participant not found: {participant_id}") from e
            raise SMPError(f"SMP request failed: {e.response.status_code}") from e

    async def delete_service_metadata(self, participant_id: str, document_type_id: str) -> None:
        """Delete service metadata for a participant.

        Requires authentication.

        Args:
            participant_id: Participant identifier.
            document_type_id: Document type identifier.

        Raises:
            SMPAuthError: Authentication failed.
            SMPNotFoundError: Service metadata not found.
            SMPError: Request failed.
        """
        client = self._get_client()
        url = self._service_url(participant_id, document_type_id)

        try:
            response = await client.delete(url)
            if response.status_code == 401:
                raise SMPAuthError("SMP authentication failed")
            if response.status_code == 403:
                raise SMPAuthError("SMP authorization denied")
            if response.status_code == 404:
                raise SMPNotFoundError(
                    f"Service metadata not found: {participant_id}/{document_type_id}"
                )
            response.raise_for_status()
            logger.info(
                "Deleted service metadata for %s/%s",
                participant_id,
                document_type_id,
            )
        except httpx.ConnectError as e:
            raise SMPConnectionError(f"Cannot connect to SMP: {e}") from e
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (401, 403):
                raise SMPAuthError("SMP authentication/authorization failed") from e
            if e.response.status_code == 404:
                raise SMPNotFoundError(
                    f"Service metadata not found: {participant_id}/{document_type_id}"
                ) from e
            raise SMPError(f"SMP request failed: {e.response.status_code}") from e
