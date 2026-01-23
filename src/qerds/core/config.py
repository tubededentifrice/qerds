"""Configuration management for QERDS services.

This module provides centralized configuration using Pydantic Settings,
supporting environment-based configuration (dev, staging, production) and
claim_state tracking for qualified/non_qualified modes per REQ-G01, REQ-G02.

All configuration is loaded from environment variables with the QERDS_ prefix.
Nested settings use double underscore as delimiter (e.g., QERDS_DATABASE__URL).

Example:
    export QERDS_ENVIRONMENT=dev
    export QERDS_DATABASE__URL=postgresql://user:pass@localhost/qerds
"""

from __future__ import annotations

import hashlib
import json
import logging
from enum import Enum
from functools import cached_property
from typing import Annotated, Any, Self

from pydantic import (
    Field,
    PostgresDsn,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class ClaimState(str, Enum):
    """Qualification claim state for the service.

    Per REQ-G01 and REQ-G02, the system must clearly distinguish between
    qualified and non-qualified operation modes. This affects:
    - Evidence sealing (qualified vs non-qualified signatures/timestamps)
    - UI/UX claims about compliance
    - Audit trail labeling
    """

    QUALIFIED = "qualified"
    NON_QUALIFIED = "non_qualified"


class Environment(str, Enum):
    """Deployment environment.

    Affects default behaviors and validation strictness.
    Production environment has additional constraints.
    """

    DEV = "dev"
    STAGING = "staging"
    PRODUCTION = "production"


class DatabaseSettings(BaseSettings):
    """PostgreSQL database connection settings.

    The database stores core state, evidence indexing, and audit metadata.
    Per CLAUDE.md, PostgreSQL is required (no SQLite).
    """

    model_config = SettingsConfigDict(
        env_prefix="QERDS_DATABASE__",
        extra="ignore",
    )

    url: PostgresDsn = Field(
        description="PostgreSQL connection URL (postgresql://user:pass@host:port/dbname)"
    )
    pool_size: Annotated[int, Field(ge=1, le=100)] = Field(
        default=5,
        description="Connection pool size for database connections",
    )
    max_overflow: Annotated[int, Field(ge=0, le=100)] = Field(
        default=10,
        description="Maximum overflow connections beyond pool_size",
    )
    pool_timeout: Annotated[int, Field(ge=1, le=300)] = Field(
        default=30,
        description="Seconds to wait for a connection from the pool",
    )
    echo: bool = Field(
        default=False,
        description="Enable SQL query logging (dev only)",
    )


class S3Settings(BaseSettings):
    """S3-compatible object storage settings.

    Used for content blobs and evidence bundles.
    In development, MinIO provides S3-compatible storage.
    """

    model_config = SettingsConfigDict(
        env_prefix="QERDS_S3__",
        extra="ignore",
    )

    endpoint: str = Field(
        default="http://localhost:9000",
        description="S3-compatible endpoint URL",
    )
    access_key: SecretStr = Field(
        description="Access key for S3 authentication",
    )
    secret_key: SecretStr = Field(
        description="Secret key for S3 authentication",
    )
    bucket: str = Field(
        default="qerds-evidence",
        description="Default bucket for evidence storage",
    )
    region: str = Field(
        default="us-east-1",
        description="S3 region (use us-east-1 for MinIO)",
    )
    secure: bool = Field(
        default=False,
        description="Use HTTPS for S3 connections (True for production)",
    )

    @field_validator("bucket")
    @classmethod
    def validate_bucket_name(cls, v: str) -> str:
        """Validate S3 bucket naming rules."""
        if not v:
            msg = "Bucket name cannot be empty"
            raise ValueError(msg)
        if len(v) < 3 or len(v) > 63:
            msg = "Bucket name must be 3-63 characters"
            raise ValueError(msg)
        return v


class SMTPSettings(BaseSettings):
    """SMTP settings for email notifications.

    Per CLAUDE.md, Mailpit is used for development email testing.
    Production should use a proper SMTP server with TLS.
    """

    model_config = SettingsConfigDict(
        env_prefix="QERDS_SMTP__",
        extra="ignore",
    )

    host: str = Field(
        default="localhost",
        description="SMTP server hostname",
    )
    port: Annotated[int, Field(ge=1, le=65535)] = Field(
        default=1025,
        description="SMTP server port (1025 is Mailpit default)",
    )
    username: str | None = Field(
        default=None,
        description="SMTP authentication username (optional for dev)",
    )
    password: SecretStr | None = Field(
        default=None,
        description="SMTP authentication password (optional for dev)",
    )
    use_tls: bool = Field(
        default=False,
        description="Enable STARTTLS (required for production)",
    )
    use_ssl: bool = Field(
        default=False,
        description="Enable implicit TLS/SSL",
    )
    from_address: str = Field(
        default="noreply@qerds.local",
        description="Default sender email address",
    )
    from_name: str = Field(
        default="QERDS",
        description="Default sender display name",
    )
    timeout: Annotated[int, Field(ge=1, le=120)] = Field(
        default=30,
        description="SMTP connection timeout in seconds",
    )


class OIDCSettings(BaseSettings):
    """OpenID Connect settings for identity provider integration.

    Used for FranceConnect+ integration per REQ-B03 (sender/addressee identification)
    and REQ-B05 (sender identity verification).
    """

    model_config = SettingsConfigDict(
        env_prefix="QERDS_OIDC__",
        extra="ignore",
    )

    enabled: bool = Field(
        default=False,
        description="Enable OIDC authentication",
    )
    client_id: str = Field(
        default="",
        description="OIDC client identifier",
    )
    client_secret: SecretStr = Field(
        default=SecretStr(""),
        description="OIDC client secret",
    )
    discovery_url: str = Field(
        default="",
        description="OIDC discovery endpoint (/.well-known/openid-configuration)",
    )
    redirect_uri: str = Field(
        default="",
        description="OAuth2 callback URL",
    )
    scopes: list[str] = Field(
        default=["openid", "profile", "email"],
        description="OIDC scopes to request",
    )
    # FranceConnect+ specific
    acr_values: str = Field(
        default="eidas2",
        description="Authentication Context Class Reference (eidas2 for high assurance)",
    )


class TrustSettings(BaseSettings):
    """Trust service settings for signing and timestamping.

    Controls the qualification mode affecting key handling and evidence sealing.
    Per REQ-G02, non-qualified mode must be clearly labeled.
    """

    model_config = SettingsConfigDict(
        env_prefix="QERDS_TRUST__",
        extra="ignore",
    )

    service_url: str = Field(
        default="http://localhost:8080",
        description="Trust service endpoint URL",
    )
    mode: ClaimState = Field(
        default=ClaimState.NON_QUALIFIED,
        description="Trust service qualification mode",
    )
    timeout: Annotated[int, Field(ge=1, le=120)] = Field(
        default=30,
        description="Trust service request timeout in seconds",
    )
    # Non-qualified mode key storage (for development only)
    key_storage_path: str = Field(
        default="/keys",
        description="Path for non-qualified key storage (dev only)",
    )


class RetentionSettings(BaseSettings):
    """Retention policy settings for CPCE/LRE compliance (REQ-F05, REQ-H02).

    The French CPCE requires minimum 1-year retention for LRE delivery proofs.
    These settings define the floor values that cannot be overridden by
    per-artifact policies.
    """

    model_config = SettingsConfigDict(
        env_prefix="QERDS_RETENTION__",
        extra="ignore",
    )

    # CPCE requires 1 year minimum for LRE proofs (REQ-F05)
    lre_proof_retention_days: Annotated[int, Field(ge=365)] = Field(
        default=365,
        description="Minimum retention days for LRE delivery proofs (CPCE minimum: 365)",
    )
    # Audit logs should be kept longer for compliance audits
    audit_log_retention_days: Annotated[int, Field(ge=365)] = Field(
        default=1825,
        description="Retention days for audit logs (default: 5 years)",
    )
    # Content objects can have shorter retention after delivery completes
    content_object_retention_days: Annotated[int, Field(ge=30)] = Field(
        default=90,
        description="Retention days for content objects after delivery",
    )

    @field_validator("lre_proof_retention_days")
    @classmethod
    def validate_lre_minimum(cls, v: int) -> int:
        """Ensure LRE proof retention meets CPCE minimum of 365 days."""
        if v < 365:
            msg = (
                "LRE proof retention must be at least 365 days per CPCE requirements. "
                f"Got: {v} days."
            )
            raise ValueError(msg)
        return v


class CryptoSettings(BaseSettings):
    """Cryptographic algorithm configuration.

    Per REQ-D03, cryptographic mechanisms must follow state-of-the-art
    guidance (e.g., ENISA agreed mechanisms). This config is versioned
    for audit traceability per REQ-A04.
    """

    model_config = SettingsConfigDict(
        env_prefix="QERDS_CRYPTO__",
        extra="ignore",
    )

    config_version: str = Field(
        default="2026.1",
        description="Crypto configuration version for audit trail",
    )
    hash_algorithm: str = Field(
        default="sha256",
        description="Hash algorithm for content digests",
    )
    signature_algorithm: str = Field(
        default="ECDSA-P384",
        description="Digital signature algorithm (ECDSA-P384 per ENISA recommendations)",
    )
    encryption_algorithm: str = Field(
        default="AES-256-GCM",
        description="Symmetric encryption algorithm for content",
    )
    key_derivation_algorithm: str = Field(
        default="HKDF-SHA256",
        description="Key derivation function",
    )
    # Minimum key sizes for validation
    min_rsa_key_bits: int = Field(
        default=3072,
        description="Minimum RSA key size in bits",
    )
    min_ec_key_bits: int = Field(
        default=256,
        description="Minimum EC key size in bits",
    )

    @field_validator("hash_algorithm")
    @classmethod
    def validate_hash_algorithm(cls, v: str) -> str:
        """Ensure hash algorithm is acceptable."""
        allowed = {"sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"}
        if v.lower() not in allowed:
            msg = f"Hash algorithm must be one of: {', '.join(sorted(allowed))}"
            raise ValueError(msg)
        return v.lower()


class Settings(BaseSettings):
    """Main QERDS configuration container.

    Loads all configuration from environment variables with QERDS_ prefix.
    Nested settings use double underscore delimiter.

    Example environment variables:
        QERDS_ENVIRONMENT=production
        QERDS_CLAIM_STATE=qualified
        QERDS_DATABASE__URL=postgresql://user:pass@host/db
        QERDS_S3__ENDPOINT=https://s3.example.com
    """

    model_config = SettingsConfigDict(
        env_prefix="QERDS_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        validate_default=True,
    )

    # Core settings
    environment: Environment = Field(
        default=Environment.DEV,
        description="Deployment environment (dev, staging, production)",
    )
    claim_state: ClaimState = Field(
        default=ClaimState.NON_QUALIFIED,
        description="Qualification claim state (per REQ-G01, REQ-G02)",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode (never in production)",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )

    # Service-specific settings
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    s3: S3Settings = Field(default_factory=S3Settings)
    smtp: SMTPSettings = Field(default_factory=SMTPSettings)
    oidc: OIDCSettings = Field(default_factory=OIDCSettings)
    trust: TrustSettings = Field(default_factory=TrustSettings)
    crypto: CryptoSettings = Field(default_factory=CryptoSettings)
    retention: RetentionSettings = Field(default_factory=RetentionSettings)

    # API settings
    api_host: str = Field(
        default="127.0.0.1",
        description="API server bind address",
    )
    api_port: Annotated[int, Field(ge=1, le=65535)] = Field(
        default=8000,
        description="API server port",
    )

    # Application metadata
    app_name: str = Field(
        default="QERDS",
        description="Application name for logging and UI",
    )
    app_version: str = Field(
        default="0.1.0",
        description="Application version",
    )

    @model_validator(mode="after")
    def validate_production_constraints(self) -> Self:
        """Enforce production environment constraints.

        Per REQ-G01, production environment must not run in non-qualified mode
        to prevent accidental compliance claims.
        """
        if self.environment == Environment.PRODUCTION:
            # Production must be qualified to prevent accidental non-qualified claims
            if self.claim_state == ClaimState.NON_QUALIFIED:
                msg = (
                    "Production environment requires claim_state=qualified. "
                    "Set QERDS_CLAIM_STATE=qualified or use a non-production environment."
                )
                raise ValueError(msg)
            # Debug must be disabled in production
            if self.debug:
                msg = "Debug mode is not allowed in production environment"
                raise ValueError(msg)
            # SMTP should use TLS in production
            if not self.smtp.use_tls and not self.smtp.use_ssl:
                logger.warning(
                    "SMTP is configured without TLS in production. "
                    "This is insecure and may violate compliance requirements."
                )
            # S3 should use HTTPS in production
            if not self.s3.secure:
                logger.warning(
                    "S3 is configured without HTTPS in production. "
                    "This is insecure and may violate compliance requirements."
                )
        return self

    @model_validator(mode="after")
    def sync_trust_mode_with_claim_state(self) -> Self:
        """Ensure trust service mode matches overall claim state."""
        if self.trust.mode != self.claim_state:
            logger.warning(
                "Trust service mode (%s) differs from claim_state (%s). "
                "Aligning trust mode to claim_state.",
                self.trust.mode.value,
                self.claim_state.value,
            )
            self.trust.mode = self.claim_state
        return self

    @cached_property
    def is_qualified(self) -> bool:
        """Check if the service is in qualified mode.

        Use this property to gate qualified-only features.
        """
        return self.claim_state == ClaimState.QUALIFIED

    @cached_property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == Environment.DEV

    @cached_property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == Environment.PRODUCTION

    def get_policy_snapshot(self) -> dict[str, Any]:
        """Generate a policy snapshot for audit purposes.

        Per REQ-H05 (change management), configuration changes should be
        traceable. This method produces a snapshot suitable for logging.

        Returns:
            Dictionary containing non-sensitive configuration values.
        """
        return {
            "environment": self.environment.value,
            "claim_state": self.claim_state.value,
            "crypto": {
                "config_version": self.crypto.config_version,
                "hash_algorithm": self.crypto.hash_algorithm,
                "signature_algorithm": self.crypto.signature_algorithm,
                "encryption_algorithm": self.crypto.encryption_algorithm,
            },
            "trust": {
                "mode": self.trust.mode.value,
            },
            "oidc": {
                "enabled": self.oidc.enabled,
                "scopes": self.oidc.scopes,
            },
            "api": {
                "host": self.api_host,
                "port": self.api_port,
            },
            "app_version": self.app_version,
        }

    def get_policy_hash(self) -> str:
        """Compute a hash of the policy snapshot.

        Useful for detecting configuration changes between deployments.

        Returns:
            SHA-256 hex digest of the policy snapshot.
        """
        snapshot = self.get_policy_snapshot()
        # Sort keys for deterministic serialization
        snapshot_json = json.dumps(snapshot, sort_keys=True)
        return hashlib.sha256(snapshot_json.encode()).hexdigest()


class ConfigValidationError(Exception):
    """Raised when configuration validation fails.

    This exception should cause fast failure at startup to prevent
    running with invalid configuration.
    """

    def __init__(self, message: str, field: str | None = None) -> None:
        """Initialize with error details.

        Args:
            message: Human-readable error description.
            field: Optional field name that failed validation.
        """
        self.message = message
        self.field = field
        super().__init__(message)


def validate_settings(settings: Settings) -> None:
    """Perform additional runtime validation of settings.

    This function performs validations that cannot be expressed
    declaratively in Pydantic models.

    Args:
        settings: Settings instance to validate.

    Raises:
        ConfigValidationError: If validation fails.
    """
    # Validate database URL is set
    if not settings.database.url:
        raise ConfigValidationError(
            "Database URL is required. Set QERDS_DATABASE__URL.",
            field="database.url",
        )

    # Validate S3 credentials are set
    if not settings.s3.access_key.get_secret_value():
        raise ConfigValidationError(
            "S3 access key is required. Set QERDS_S3__ACCESS_KEY.",
            field="s3.access_key",
        )
    if not settings.s3.secret_key.get_secret_value():
        raise ConfigValidationError(
            "S3 secret key is required. Set QERDS_S3__SECRET_KEY.",
            field="s3.secret_key",
        )

    # Validate OIDC settings if enabled
    if settings.oidc.enabled:
        if not settings.oidc.client_id:
            raise ConfigValidationError(
                "OIDC client_id is required when OIDC is enabled.",
                field="oidc.client_id",
            )
        if not settings.oidc.discovery_url:
            raise ConfigValidationError(
                "OIDC discovery_url is required when OIDC is enabled.",
                field="oidc.discovery_url",
            )

    # Log policy snapshot for audit trail
    logger.info(
        "Configuration validated. Policy hash: %s",
        settings.get_policy_hash(),
    )
