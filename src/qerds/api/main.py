"""QERDS API service entry point."""

import logging

from fastapi import FastAPI

logger = logging.getLogger(__name__)

app = FastAPI(
    title="QERDS API",
    description="Qualified Electronic Registered Delivery Service API",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint for container orchestration."""
    return {"status": "healthy"}


def run() -> None:
    """Run the API server using uvicorn."""
    import uvicorn

    uvicorn.run(
        "qerds.api.main:app",
        host="0.0.0.0",  # noqa: S104 - Binding to all interfaces is intentional for containers
        port=8000,
        reload=False,
    )


if __name__ == "__main__":
    run()
