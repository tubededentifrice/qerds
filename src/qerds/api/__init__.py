"""QERDS API service.

FastAPI application providing:
- Sender/recipient/admin/verifier HTTP API
- Delivery lifecycle state machine enforcement
- Evidence creation orchestration
- Authorization, audit logging, and export endpoints
- Jinja2 template rendering for HTML pages
- Static file serving (CSS, JS, fonts)

This module provides the app factory pattern for creating configured
FastAPI instances suitable for testing and production deployment.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from qerds.api.middleware import ErrorHandlerMiddleware, RequestIDMiddleware
from qerds.api.routers import (
    admin_router,
    as4_router,
    auth_router,
    consent_router,
    pickup_router,
    recipient_router,
    sender_router,
    verify_router,
)
from qerds.api.routers.pages import router as pages_router
from qerds.api.templates import get_templates

if TYPE_CHECKING:
    from qerds.core.config import Settings

# Static files directory (src/qerds/static/)
STATIC_DIR = Path(__file__).parent.parent / "static"

logger = logging.getLogger(__name__)

# Application metadata
API_TITLE = "QERDS API"
API_DESCRIPTION = """
Qualified Electronic Registered Delivery Service API.

## Namespaces

- **/pickup/** - Recipient pickup portal with auth wall (REQ-E02, REQ-F03)
- **/sender/** - Sender operations (authenticated)
- **/recipient/** - Recipient portal API (authenticated)
- **/consent/** - Consumer consent management (REQ-F06)
- **/verify/** - Third-party verification (token-gated)
- **/admin/** - Operational/admin endpoints (admin auth)

## Documentation

- OpenAPI spec: `/api/openapi.json`
- Swagger UI: `/api/docs`
- ReDoc: `/api/redoc`
"""


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create and configure a FastAPI application instance.

    This factory function creates a fully configured FastAPI app with:
    - API namespace routers mounted at appropriate prefixes
    - HTML page routes for the frontend
    - Static file serving (CSS, JS, fonts)
    - Jinja2 template configuration
    - Request ID middleware for distributed tracing
    - Error handling middleware for consistent JSON responses
    - CORS middleware (configurable via settings)
    - OpenAPI documentation at /api/docs and /api/redoc

    Args:
        settings: Optional Settings instance. If not provided, uses
            default development settings. Pass explicit settings for
            testing or production configuration.

    Returns:
        Configured FastAPI application ready to serve requests.

    Example:
        # Basic usage
        app = create_app()

        # With custom settings
        from qerds.core.config import Settings
        settings = Settings(environment="production", ...)
        app = create_app(settings)

        # For testing
        test_settings = Settings(environment="dev", debug=True)
        app = create_app(test_settings)
    """
    # Determine version from settings or default
    version = "0.1.0"
    if settings:
        version = settings.app_version

    app = FastAPI(
        title=API_TITLE,
        description=API_DESCRIPTION,
        version=version,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # Store settings in app state for access in routes
    app.state.settings = settings

    # Configure Jinja2 templates
    app.state.templates = get_templates()

    # Mount static files (CSS, JS, fonts)
    _mount_static_files(app)

    # Add middleware (order matters - first added is outermost)
    _add_middleware(app, settings)

    # Include routers
    _include_routers(app)

    # Add root health endpoint
    @app.get("/health", tags=["health"])
    async def health_check() -> dict[str, str]:
        """Health check endpoint for container orchestration.

        Returns:
            Status dictionary indicating the service is healthy.
        """
        return {"status": "healthy"}

    logger.info("QERDS API application created (version=%s)", version)

    return app


def _add_middleware(app: FastAPI, settings: Settings | None) -> None:
    """Add middleware to the application.

    Args:
        app: The FastAPI application instance.
        settings: Optional settings for middleware configuration.
    """
    # Request ID middleware - adds X-Request-ID to all responses
    app.add_middleware(RequestIDMiddleware)

    # Error handler middleware - converts exceptions to JSON responses
    app.add_middleware(ErrorHandlerMiddleware)

    # CORS middleware - configure based on environment
    # In development, allow localhost origins; in production, restrict appropriately
    allowed_origins = ["http://localhost:3000", "http://localhost:8000"]
    if settings and settings.is_production:
        # In production, should be configured via settings
        # For now, use restrictive defaults
        allowed_origins = []

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
    )


def _mount_static_files(app: FastAPI) -> None:
    """Mount static file directories.

    Static files are served from src/qerds/static/ at /static/
    This includes CSS, JS, and self-hosted fonts (no external CDN).

    Args:
        app: The FastAPI application instance.
    """
    if not STATIC_DIR.exists():
        logger.warning("Static files directory not found: %s", STATIC_DIR)
        return

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    logger.info("Static files mounted from %s", STATIC_DIR)


def _include_routers(app: FastAPI) -> None:
    """Include API namespace routers.

    Args:
        app: The FastAPI application instance.
    """
    # HTML page routes (no prefix - serve at root for user-facing pages)
    app.include_router(pages_router)

    # Browser-facing routers (HTML/redirect-based, no /api prefix)
    # - auth_router: OAuth/OIDC flows with browser redirects
    # - pickup_router: Authentication-gated pickup portal with HTML templates
    app.include_router(auth_router)
    app.include_router(pickup_router)

    # JSON API namespace routers (prefixed with /api to avoid conflicts with HTML pages)
    # This follows the standard pattern:
    #   - /api/sender/... for JSON API endpoints
    #   - /sender/... for HTML page routes
    app.include_router(sender_router, prefix="/api")
    app.include_router(recipient_router, prefix="/api")
    app.include_router(consent_router, prefix="/api")
    app.include_router(verify_router, prefix="/api")
    app.include_router(admin_router, prefix="/api")
    app.include_router(as4_router, prefix="/api")  # Domibus AS4 webhook callbacks (REQ-C04)
