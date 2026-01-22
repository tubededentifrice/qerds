"""Singleton settings accessor for QERDS configuration.

This module provides a cached accessor for the application settings,
ensuring consistent configuration across all services.

Usage:
    from qerds.core.settings import get_settings

    settings = get_settings()
    if settings.is_qualified:
        # Use qualified evidence handling
        ...

The settings are loaded once and cached. To reload settings (e.g., in tests),
use clear_settings_cache().
"""

from __future__ import annotations

import logging
from functools import lru_cache

from pydantic import ValidationError

from qerds.core.config import (
    ConfigValidationError,
    Settings,
    validate_settings,
)

logger = logging.getLogger(__name__)

# Module-level cache for settings instance
_settings_cache: Settings | None = None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Get the cached application settings.

    Settings are loaded from environment variables on first call and
    cached for subsequent calls. This ensures consistent configuration
    across the application lifecycle.

    Returns:
        Validated Settings instance.

    Raises:
        ConfigValidationError: If settings validation fails.
        SystemExit: If settings cannot be loaded (fail-fast behavior).
    """
    global _settings_cache

    if _settings_cache is not None:
        return _settings_cache

    try:
        logger.info("Loading application settings from environment")
        settings = Settings()  # type: ignore[call-arg]
        validate_settings(settings)
        _settings_cache = settings

        # Log startup configuration (non-sensitive)
        logger.info(
            "Configuration loaded: environment=%s, claim_state=%s, "
            "crypto_version=%s, policy_hash=%s",
            settings.environment.value,
            settings.claim_state.value,
            settings.crypto.config_version,
            settings.get_policy_hash()[:16] + "...",
        )

        return settings

    except ValidationError as e:
        # Pydantic validation failed - provide helpful error message
        error_messages = []
        for error in e.errors():
            loc = ".".join(str(x) for x in error["loc"])
            msg = error["msg"]
            error_messages.append(f"  - {loc}: {msg}")

        logger.critical(
            "Configuration validation failed:\n%s",
            "\n".join(error_messages),
        )
        raise SystemExit(1) from e

    except ConfigValidationError as e:
        # Custom validation failed
        logger.critical(
            "Configuration validation failed: %s (field: %s)",
            e.message,
            e.field or "unknown",
        )
        raise SystemExit(1) from e

    except Exception as e:
        # Unexpected error during configuration loading
        logger.critical(
            "Failed to load configuration: %s",
            str(e),
        )
        raise SystemExit(1) from e


def clear_settings_cache() -> None:
    """Clear the settings cache.

    Use this function in tests to reset settings between test cases,
    or when configuration needs to be reloaded.

    Example:
        def test_something():
            clear_settings_cache()
            os.environ["QERDS_ENVIRONMENT"] = "staging"
            settings = get_settings()
            ...
    """
    global _settings_cache
    _settings_cache = None
    get_settings.cache_clear()
    logger.debug("Settings cache cleared")


def get_settings_safe() -> Settings | None:
    """Get settings without raising exceptions.

    Unlike get_settings(), this function returns None if settings
    cannot be loaded. Useful for graceful degradation or optional
    configuration checks.

    Returns:
        Settings instance if available, None otherwise.
    """
    try:
        return get_settings()
    except SystemExit:
        return None


def require_qualified() -> None:
    """Assert that the service is in qualified mode.

    Use this as a guard at the start of functions that should only
    run in qualified mode.

    Raises:
        RuntimeError: If not in qualified mode.

    Example:
        def create_qualified_seal(data: bytes) -> bytes:
            require_qualified()
            # Only runs if claim_state is qualified
            ...
    """
    settings = get_settings()
    if not settings.is_qualified:
        msg = (
            "This operation requires qualified mode. "
            f"Current claim_state: {settings.claim_state.value}"
        )
        raise RuntimeError(msg)


def require_production() -> None:
    """Assert that the service is in production environment.

    Raises:
        RuntimeError: If not in production environment.
    """
    settings = get_settings()
    if not settings.is_production:
        msg = (
            "This operation requires production environment. "
            f"Current environment: {settings.environment.value}"
        )
        raise RuntimeError(msg)


def log_config_change(component: str, change_description: str) -> None:
    """Log a configuration change for audit purposes.

    Per REQ-H05 (change management), configuration changes should be
    traceable. This function logs changes in a structured format.

    Args:
        component: Component or setting that changed.
        change_description: Human-readable description of the change.
    """
    settings = get_settings()
    logger.info(
        "CONFIG_CHANGE: component=%s, description=%s, policy_hash=%s",
        component,
        change_description,
        settings.get_policy_hash()[:16],
    )
