"""Pytest configuration and shared fixtures.

All tests must run in Docker for reproducibility.
Use `docker compose exec qerds-api pytest` to run tests.

Environment variables for test database:
    TEST_DATABASE_URL: PostgreSQL connection URL (asyncpg)
    TEST_S3_ENDPOINT: MinIO/S3 endpoint URL
    TEST_S3_ACCESS_KEY: S3 access key
    TEST_S3_SECRET_KEY: S3 secret key
"""

import asyncio
import os
from collections.abc import AsyncGenerator, Generator

import pytest
from httpx import ASGITransport, AsyncClient

from qerds.api import create_app


# ---------------------------------------------------------------------------
# Event loop fixture for async tests (session-scoped for efficiency)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# Database configuration fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def database_url() -> str:
    """Get test database URL from environment or use default.

    Default assumes test compose stack is running on localhost:5433.
    """
    return os.environ.get(
        "TEST_DATABASE_URL",
        "postgresql+psycopg://qerds:qerds_dev_password@localhost:5433/qerds_test",
    )


@pytest.fixture(scope="session")
def sync_database_url() -> str:
    """Get synchronous test database URL for Alembic/schema operations."""
    return os.environ.get(
        "TEST_DATABASE_URL_SYNC",
        "postgresql://qerds:qerds_dev_password@localhost:5433/qerds_test",
    )


# ---------------------------------------------------------------------------
# S3/MinIO fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def s3_endpoint() -> str:
    """Get test S3 endpoint from environment or use default."""
    return os.environ.get("TEST_S3_ENDPOINT", "http://localhost:9002")


@pytest.fixture(scope="session")
def s3_credentials() -> dict[str, str]:
    """Get test S3 credentials from environment or use defaults."""
    return {
        "aws_access_key_id": os.environ.get("TEST_S3_ACCESS_KEY", "qerds_minio"),
        "aws_secret_access_key": os.environ.get("TEST_S3_SECRET_KEY", "qerds_minio_secret"),
    }


@pytest.fixture
def s3_client(s3_endpoint: str, s3_credentials: dict[str, str]):
    """Create MinIO/S3 client for tests.

    Returns a boto3 S3 client configured for the test MinIO instance.
    """
    import boto3

    return boto3.client(
        "s3",
        endpoint_url=s3_endpoint,
        aws_access_key_id=s3_credentials["aws_access_key_id"],
        aws_secret_access_key=s3_credentials["aws_secret_access_key"],
    )


# ---------------------------------------------------------------------------
# API client fixture (in-process testing via ASGI transport)
# ---------------------------------------------------------------------------
@pytest.fixture
def test_app():
    """Create a test FastAPI application instance.

    Uses the app factory to create a fresh application for testing.
    """
    return create_app()


@pytest.fixture
async def api_client(test_app) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client for testing the API.

    Uses httpx with ASGI transport for in-process testing.
    """
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


# ---------------------------------------------------------------------------
# Test user/party fixtures (data builders for common test entities)
# ---------------------------------------------------------------------------
@pytest.fixture
def sender_party() -> dict:
    """Create a test sender party.

    Returns a dict representing a natural person sender for delivery tests.
    """
    return {
        "party_id": "550e8400-e29b-41d4-a716-446655440001",
        "party_type": "natural_person",
        "given_name": "Jean",
        "family_name": "Dupont",
        "email": "jean.dupont@example.com",
    }


@pytest.fixture
def recipient_party() -> dict:
    """Create a test recipient party.

    Returns a dict representing a natural person recipient for delivery tests.
    """
    return {
        "party_id": "550e8400-e29b-41d4-a716-446655440002",
        "party_type": "natural_person",
        "given_name": "Marie",
        "family_name": "Martin",
        "email": "marie.martin@example.com",
    }


@pytest.fixture
def corporate_sender() -> dict:
    """Create a test corporate sender (legal person).

    Returns a dict representing a legal entity sender for business delivery tests.
    """
    return {
        "party_id": "550e8400-e29b-41d4-a716-446655440010",
        "party_type": "legal_person",
        "organization_name": "ACME Corporation",
        "organization_id": "SIREN:123456789",
        "email": "registered@acme.example.com",
    }


@pytest.fixture
def admin_user() -> dict:
    """Create a test admin user.

    Returns a dict representing an admin user for administrative endpoint tests.
    """
    return {
        "admin_user_id": "550e8400-e29b-41d4-a716-446655440003",
        "username": "admin",
        "roles": ["admin"],
    }


@pytest.fixture
def operator_user() -> dict:
    """Create a test operator user.

    Returns a dict representing an operator user with limited administrative access.
    """
    return {
        "admin_user_id": "550e8400-e29b-41d4-a716-446655440004",
        "username": "operator",
        "roles": ["operator"],
    }
