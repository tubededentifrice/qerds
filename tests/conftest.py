"""Pytest configuration and shared fixtures.

All tests must run in Docker for reproducibility.
Use `docker compose exec qerds-api pytest` to run tests.
"""

from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient

from qerds.api.main import app


@pytest.fixture
async def api_client() -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client for testing the API.

    Uses httpx with ASGI transport for in-process testing.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
