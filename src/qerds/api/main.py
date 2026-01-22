"""QERDS API service entry point.

This module provides the application instance for ASGI servers (uvicorn)
and a run() function for direct execution.

The app is created using the factory pattern from qerds.api.create_app().
"""

import logging

from qerds.api import create_app

logger = logging.getLogger(__name__)

# Create the application instance for ASGI servers
# This is what uvicorn references: qerds.api.main:app
app = create_app()


def run() -> None:
    """Run the API server using uvicorn.

    This function is called by the qerds-api console script
    defined in pyproject.toml.
    """
    import uvicorn

    from qerds.core.config import Settings

    # Load settings from environment
    try:
        settings = Settings()
        host = settings.api_host
        port = settings.api_port
    except Exception:
        # Fall back to defaults if settings can't be loaded
        logger.warning("Could not load settings, using defaults")
        host = "127.0.0.1"
        port = 8000

    logger.info("Starting QERDS API on %s:%d", host, port)

    uvicorn.run(
        "qerds.api.main:app",
        host=host,
        port=port,
        reload=False,
    )


if __name__ == "__main__":
    run()
