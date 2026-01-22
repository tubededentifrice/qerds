"""QERDS Trust service entry point."""

import logging

from fastapi import FastAPI

logger = logging.getLogger(__name__)

app = FastAPI(
    title="QERDS Trust Service",
    description="Internal signing and timestamping service (NOT exposed to internet)",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint for container orchestration."""
    return {"status": "healthy", "mode": "non_qualified"}


def run() -> None:
    """Run the trust service using uvicorn.

    IMPORTANT: This service should only be accessible on the internal network.
    It must NOT be exposed to the public internet.
    """
    import uvicorn

    # Bind to localhost only by default for security
    # In production, this should be on an internal network interface
    uvicorn.run(
        "qerds.trust.main:app",
        host="127.0.0.1",
        port=8001,
        reload=False,
    )


if __name__ == "__main__":
    run()
