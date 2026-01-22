"""QERDS Trust service entry point.

Internal service for signing, sealing, and timestamping operations.
Per specs/implementation/45-trust-services.md, this service:
- Provides provider attestation (seal/signature) over evidence payloads
- Creates RFC 3161-style timestamp tokens
- Manages key lifecycle with ceremony evidence

IMPORTANT: This service should only be accessible on the internal network.
All calls must be authenticated via mTLS in production (stub for dev).
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI

from qerds.api.routers.trust import (
    initialize_trust_router,
    shutdown_trust_router,
)
from qerds.api.routers.trust import (
    router as trust_router,
)
from qerds.services.trust import QualificationMode

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler.

    Initializes the trust service on startup and cleans up on shutdown.
    """
    # Determine mode from environment
    mode_str = os.environ.get("QERDS_TRUST_MODE", "non_qualified")
    mode = QualificationMode(mode_str)

    # Get configuration from environment
    key_storage = os.environ.get("QERDS_TRUST_KEY_STORAGE", "/keys")
    key_password_str = os.environ.get("QERDS_TRUST_KEY_PASSWORD", "")
    key_password = key_password_str.encode("utf-8") if key_password_str else None
    org_name = os.environ.get("QERDS_TRUST_ORG_NAME", "QERDS Development")
    country = os.environ.get("QERDS_TRUST_COUNTRY", "FR")
    policy_id = os.environ.get("QERDS_TRUST_POLICY_ID", "dev-policy-v1")

    logger.info(
        "Starting trust service: mode=%s, key_storage=%s",
        mode.value,
        key_storage,
    )

    await initialize_trust_router(
        mode=mode,
        key_storage_path=key_storage,
        key_password=key_password,
        organization_name=org_name,
        country=country,
        policy_snapshot_id=policy_id,
    )

    yield

    logger.info("Shutting down trust service")
    await shutdown_trust_router()


app = FastAPI(
    title="QERDS Trust Service",
    description=(
        "Internal signing and timestamping service.\n\n"
        "**WARNING**: This service is NOT for public exposure. "
        "All calls must be authenticated via mTLS in production.\n\n"
        "Supports two modes:\n"
        "- `non_qualified`: Software keys for development (labeled as non-qualified)\n"
        "- `qualified`: HSM keys via PKCS#11 (not yet implemented)\n\n"
        "See specs/implementation/45-trust-services.md for details."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Include the trust router
app.include_router(trust_router)


@app.get("/", include_in_schema=False)
async def root() -> dict[str, str]:
    """Root endpoint with service info."""
    return {
        "service": "qerds-trust",
        "version": "0.1.0",
        "docs": "/docs",
    }


def run() -> None:
    """Run the trust service using uvicorn.

    IMPORTANT: This service should only be accessible on the internal network.
    It must NOT be exposed to the public internet.

    Configuration via environment variables:
        QERDS_TRUST_MODE: non_qualified or qualified
        QERDS_TRUST_KEY_STORAGE: Path for key storage
        QERDS_TRUST_KEY_PASSWORD: Password for key encryption
        QERDS_TRUST_ORG_NAME: Organization name for certificates
        QERDS_TRUST_COUNTRY: Country code for certificates
        QERDS_TRUST_POLICY_ID: Policy snapshot identifier
    """
    import uvicorn

    # Bind to localhost only by default for security
    # In production, this should be on an internal network interface
    host = os.environ.get("QERDS_TRUST_HOST", "127.0.0.1")
    port = int(os.environ.get("QERDS_TRUST_PORT", "8001"))

    uvicorn.run(
        "qerds.trust.main:app",
        host=host,
        port=port,
        reload=False,
    )


if __name__ == "__main__":
    run()
