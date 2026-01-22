"""QERDS Core module.

Shared components used across all services:
- Configuration management
- Logging setup
- Common models and types
- Utility functions
"""

from qerds.core.config import (
    ClaimState,
    ConfigValidationError,
    CryptoSettings,
    DatabaseSettings,
    Environment,
    OIDCSettings,
    S3Settings,
    Settings,
    SMTPSettings,
    TrustSettings,
)
from qerds.core.settings import (
    clear_settings_cache,
    get_settings,
    get_settings_safe,
    log_config_change,
    require_production,
    require_qualified,
)

__all__ = [
    "ClaimState",
    "ConfigValidationError",
    "CryptoSettings",
    "DatabaseSettings",
    "Environment",
    "OIDCSettings",
    "S3Settings",
    "SMTPSettings",
    "Settings",
    "TrustSettings",
    "clear_settings_cache",
    "get_settings",
    "get_settings_safe",
    "log_config_change",
    "require_production",
    "require_qualified",
]
