"""Tests for configuration management system.

Tests cover:
- Loading configuration from environment variables
- Validation of invalid configuration
- Production environment constraints
- Settings singleton behavior
- Policy snapshot generation
"""

import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from qerds.core.config import (
    ClaimState,
    ConfigValidationError,
    CryptoSettings,
    DatabaseSettings,
    Environment,
    OIDCSettings,
    RetentionSettings,
    S3Settings,
    Settings,
    SMTPSettings,
    TrustSettings,
    validate_settings,
)
from qerds.core.settings import (
    clear_settings_cache,
    get_settings,
    require_production,
    require_qualified,
)


# Fixtures for test environment setup
@pytest.fixture(autouse=True)
def clean_settings_cache():
    """Clear settings cache before and after each test."""
    clear_settings_cache()
    yield
    clear_settings_cache()


@pytest.fixture
def minimal_env():
    """Provide minimal valid environment variables."""
    return {
        "QERDS_DATABASE__URL": "postgresql://user:pass@localhost:5432/qerds",
        "QERDS_S3__ACCESS_KEY": "test_access_key",
        "QERDS_S3__SECRET_KEY": "test_secret_key",
    }


@pytest.fixture
def production_env(minimal_env):
    """Provide production environment variables."""
    return {
        **minimal_env,
        "QERDS_ENVIRONMENT": "production",
        "QERDS_CLAIM_STATE": "qualified",
        "QERDS_DEBUG": "false",
    }


class TestEnvironmentEnum:
    """Tests for Environment enum."""

    def test_environment_values(self):
        """Test that all expected environment values exist."""
        assert Environment.DEV.value == "dev"
        assert Environment.STAGING.value == "staging"
        assert Environment.PRODUCTION.value == "production"

    def test_environment_from_string(self):
        """Test creating Environment from string value."""
        assert Environment("dev") == Environment.DEV
        assert Environment("staging") == Environment.STAGING
        assert Environment("production") == Environment.PRODUCTION


class TestClaimStateEnum:
    """Tests for ClaimState enum."""

    def test_claim_state_values(self):
        """Test that all expected claim state values exist."""
        assert ClaimState.QUALIFIED.value == "qualified"
        assert ClaimState.NON_QUALIFIED.value == "non_qualified"

    def test_claim_state_from_string(self):
        """Test creating ClaimState from string value."""
        assert ClaimState("qualified") == ClaimState.QUALIFIED
        assert ClaimState("non_qualified") == ClaimState.NON_QUALIFIED


class TestDatabaseSettings:
    """Tests for DatabaseSettings."""

    def test_database_settings_from_env(self):
        """Test loading database settings from environment."""
        with patch.dict(
            os.environ,
            {
                "QERDS_DATABASE__URL": "postgresql://user:pass@localhost:5432/testdb",
                "QERDS_DATABASE__POOL_SIZE": "10",
                "QERDS_DATABASE__MAX_OVERFLOW": "20",
            },
            clear=False,
        ):
            settings = DatabaseSettings()
            assert str(settings.url) == "postgresql://user:pass@localhost:5432/testdb"
            assert settings.pool_size == 10
            assert settings.max_overflow == 20

    def test_database_settings_defaults(self):
        """Test database settings default values."""
        with patch.dict(
            os.environ,
            {"QERDS_DATABASE__URL": "postgresql://user:pass@localhost:5432/db"},
            clear=False,
        ):
            settings = DatabaseSettings()
            assert settings.pool_size == 5
            assert settings.max_overflow == 10
            assert settings.pool_timeout == 30
            assert settings.echo is False

    def test_database_invalid_url(self):
        """Test that invalid database URL raises validation error."""
        with (
            patch.dict(
                os.environ,
                {"QERDS_DATABASE__URL": "not-a-valid-url"},
                clear=False,
            ),
            pytest.raises(ValidationError),
        ):
            DatabaseSettings()


class TestS3Settings:
    """Tests for S3Settings."""

    def test_s3_settings_from_env(self):
        """Test loading S3 settings from environment."""
        with patch.dict(
            os.environ,
            {
                "QERDS_S3__ENDPOINT": "https://s3.example.com",
                "QERDS_S3__ACCESS_KEY": "my_access_key",
                "QERDS_S3__SECRET_KEY": "my_secret_key",
                "QERDS_S3__BUCKET": "my-bucket",
                "QERDS_S3__SECURE": "true",
            },
            clear=False,
        ):
            settings = S3Settings()
            assert settings.endpoint == "https://s3.example.com"
            assert settings.access_key.get_secret_value() == "my_access_key"
            assert settings.secret_key.get_secret_value() == "my_secret_key"
            assert settings.bucket == "my-bucket"
            assert settings.secure is True

    def test_s3_settings_defaults(self):
        """Test S3 settings default values."""
        with patch.dict(
            os.environ,
            {
                "QERDS_S3__ACCESS_KEY": "key",
                "QERDS_S3__SECRET_KEY": "secret",
            },
            clear=False,
        ):
            settings = S3Settings()
            assert settings.endpoint == "http://localhost:9000"
            assert settings.bucket == "qerds-evidence"
            assert settings.region == "us-east-1"
            assert settings.secure is False

    def test_s3_invalid_bucket_name_empty(self):
        """Test that empty bucket name is rejected."""
        with patch.dict(
            os.environ,
            {
                "QERDS_S3__ACCESS_KEY": "key",
                "QERDS_S3__SECRET_KEY": "secret",
                "QERDS_S3__BUCKET": "",
            },
            clear=False,
        ):
            with pytest.raises(ValidationError) as exc_info:
                S3Settings()
            assert "Bucket name cannot be empty" in str(exc_info.value)

    def test_s3_invalid_bucket_name_too_short(self):
        """Test that bucket name too short is rejected."""
        with patch.dict(
            os.environ,
            {
                "QERDS_S3__ACCESS_KEY": "key",
                "QERDS_S3__SECRET_KEY": "secret",
                "QERDS_S3__BUCKET": "ab",
            },
            clear=False,
        ):
            with pytest.raises(ValidationError) as exc_info:
                S3Settings()
            assert "3-63 characters" in str(exc_info.value)


class TestSMTPSettings:
    """Tests for SMTPSettings."""

    def test_smtp_settings_defaults(self):
        """Test SMTP settings default values (Mailpit dev defaults)."""
        settings = SMTPSettings()
        assert settings.host == "localhost"
        assert settings.port == 1025
        assert settings.username is None
        assert settings.password is None
        assert settings.use_tls is False
        assert settings.from_address == "noreply@qerds.local"

    def test_smtp_settings_from_env(self):
        """Test loading SMTP settings from environment."""
        with patch.dict(
            os.environ,
            {
                "QERDS_SMTP__HOST": "smtp.example.com",
                "QERDS_SMTP__PORT": "587",
                "QERDS_SMTP__USERNAME": "user",
                "QERDS_SMTP__PASSWORD": "pass",
                "QERDS_SMTP__USE_TLS": "true",
                "QERDS_SMTP__FROM_ADDRESS": "noreply@example.com",
            },
            clear=False,
        ):
            settings = SMTPSettings()
            assert settings.host == "smtp.example.com"
            assert settings.port == 587
            assert settings.username == "user"
            assert settings.password.get_secret_value() == "pass"
            assert settings.use_tls is True


class TestOIDCSettings:
    """Tests for OIDCSettings."""

    def test_oidc_settings_defaults(self):
        """Test OIDC settings defaults (disabled by default)."""
        settings = OIDCSettings()
        assert settings.enabled is False
        assert settings.client_id == ""
        assert settings.scopes == ["openid", "profile", "email"]
        assert settings.acr_values == "eidas2"

    def test_oidc_settings_from_env(self):
        """Test loading OIDC settings from environment."""
        with patch.dict(
            os.environ,
            {
                "QERDS_OIDC__ENABLED": "true",
                "QERDS_OIDC__CLIENT_ID": "my-client",
                "QERDS_OIDC__CLIENT_SECRET": "my-secret",
                "QERDS_OIDC__DISCOVERY_URL": "https://fc.example.com/.well-known/openid-configuration",
            },
            clear=False,
        ):
            settings = OIDCSettings()
            assert settings.enabled is True
            assert settings.client_id == "my-client"
            assert settings.client_secret.get_secret_value() == "my-secret"


class TestTrustSettings:
    """Tests for TrustSettings."""

    def test_trust_settings_defaults(self):
        """Test trust settings defaults (non-qualified mode)."""
        settings = TrustSettings()
        assert settings.service_url == "http://localhost:8080"
        assert settings.mode == ClaimState.NON_QUALIFIED
        assert settings.timeout == 30

    def test_trust_settings_qualified_mode(self):
        """Test trust settings in qualified mode."""
        with patch.dict(
            os.environ,
            {"QERDS_TRUST__MODE": "qualified"},
            clear=False,
        ):
            settings = TrustSettings()
            assert settings.mode == ClaimState.QUALIFIED


class TestCryptoSettings:
    """Tests for CryptoSettings."""

    def test_crypto_settings_defaults(self):
        """Test crypto settings default values."""
        settings = CryptoSettings()
        assert settings.config_version == "2026.1"
        assert settings.hash_algorithm == "sha256"
        assert settings.signature_algorithm == "ECDSA-P384"  # ENISA recommended, matches trust.py
        assert settings.encryption_algorithm == "AES-256-GCM"

    def test_crypto_settings_valid_hash_algorithms(self):
        """Test that valid hash algorithms are accepted."""
        valid_algorithms = ["sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"]
        for algo in valid_algorithms:
            with patch.dict(
                os.environ,
                {"QERDS_CRYPTO__HASH_ALGORITHM": algo},
                clear=False,
            ):
                settings = CryptoSettings()
                assert settings.hash_algorithm == algo.lower()

    def test_crypto_settings_invalid_hash_algorithm(self):
        """Test that invalid hash algorithm is rejected."""
        with patch.dict(
            os.environ,
            {"QERDS_CRYPTO__HASH_ALGORITHM": "md5"},
            clear=False,
        ):
            with pytest.raises(ValidationError) as exc_info:
                CryptoSettings()
            assert "Hash algorithm must be one of" in str(exc_info.value)


class TestMainSettings:
    """Tests for main Settings class."""

    def test_settings_from_env(self, minimal_env):
        """Test loading main settings from environment."""
        with patch.dict(os.environ, minimal_env, clear=False):
            settings = Settings()
            assert settings.environment == Environment.DEV
            assert settings.claim_state == ClaimState.NON_QUALIFIED
            assert settings.debug is False

    def test_settings_is_qualified_property(self, minimal_env):
        """Test is_qualified property."""
        with patch.dict(os.environ, minimal_env, clear=False):
            settings = Settings()
            assert settings.is_qualified is False

        with patch.dict(
            os.environ,
            {**minimal_env, "QERDS_CLAIM_STATE": "qualified"},
            clear=False,
        ):
            settings = Settings()
            assert settings.is_qualified is True

    def test_settings_is_development_property(self, minimal_env):
        """Test is_development property."""
        with patch.dict(os.environ, minimal_env, clear=False):
            settings = Settings()
            assert settings.is_development is True

        with patch.dict(
            os.environ,
            {**minimal_env, "QERDS_ENVIRONMENT": "staging"},
            clear=False,
        ):
            settings = Settings()
            assert settings.is_development is False

    def test_settings_is_production_property(self, minimal_env):
        """Test is_production property."""
        with patch.dict(os.environ, minimal_env, clear=False):
            settings = Settings()
            assert settings.is_production is False

    def test_settings_is_production_property_true(self, production_env):
        """Test is_production property when in production."""
        with patch.dict(os.environ, production_env, clear=False):
            settings = Settings()
            assert settings.is_production is True


class TestProductionConstraints:
    """Tests for production environment constraints."""

    def test_production_requires_qualified(self, minimal_env):
        """Test that production environment requires qualified claim state."""
        with patch.dict(
            os.environ,
            {
                **minimal_env,
                "QERDS_ENVIRONMENT": "production",
                "QERDS_CLAIM_STATE": "non_qualified",
            },
            clear=False,
        ):
            with pytest.raises(ValidationError) as exc_info:
                Settings()
            assert "Production environment requires claim_state=qualified" in str(exc_info.value)

    def test_production_disallows_debug(self, minimal_env):
        """Test that production environment disallows debug mode."""
        with patch.dict(
            os.environ,
            {
                **minimal_env,
                "QERDS_ENVIRONMENT": "production",
                "QERDS_CLAIM_STATE": "qualified",
                "QERDS_DEBUG": "true",
            },
            clear=False,
        ):
            with pytest.raises(ValidationError) as exc_info:
                Settings()
            assert "Debug mode is not allowed in production" in str(exc_info.value)

    def test_production_valid_config(self, production_env):
        """Test that valid production config loads successfully."""
        with patch.dict(os.environ, production_env, clear=False):
            settings = Settings()
            assert settings.environment == Environment.PRODUCTION
            assert settings.claim_state == ClaimState.QUALIFIED
            assert settings.debug is False


class TestTrustModeSync:
    """Tests for trust mode synchronization with claim state."""

    def test_trust_mode_syncs_with_claim_state(self, minimal_env):
        """Test that trust mode is synchronized with overall claim state."""
        with patch.dict(
            os.environ,
            {
                **minimal_env,
                "QERDS_CLAIM_STATE": "non_qualified",
                "QERDS_TRUST__MODE": "qualified",
            },
            clear=False,
        ):
            settings = Settings()
            # Trust mode should be aligned to claim_state
            assert settings.trust.mode == ClaimState.NON_QUALIFIED


class TestPolicySnapshot:
    """Tests for policy snapshot generation."""

    def test_get_policy_snapshot(self, minimal_env):
        """Test generating policy snapshot."""
        with patch.dict(os.environ, minimal_env, clear=False):
            settings = Settings()
            snapshot = settings.get_policy_snapshot()

            assert "environment" in snapshot
            assert "claim_state" in snapshot
            assert "crypto" in snapshot
            assert "trust" in snapshot
            assert "app_version" in snapshot

            assert snapshot["environment"] == "dev"
            assert snapshot["claim_state"] == "non_qualified"

    def test_get_policy_hash(self, minimal_env):
        """Test generating policy hash."""
        with patch.dict(os.environ, minimal_env, clear=False):
            settings = Settings()
            hash1 = settings.get_policy_hash()

            # Hash should be consistent
            hash2 = settings.get_policy_hash()
            assert hash1 == hash2

            # Hash should be 64 hex characters (SHA-256)
            assert len(hash1) == 64
            assert all(c in "0123456789abcdef" for c in hash1)

    def test_policy_hash_changes_with_config(self, minimal_env):
        """Test that policy hash changes when config changes."""
        with patch.dict(os.environ, minimal_env, clear=False):
            settings1 = Settings()
            hash1 = settings1.get_policy_hash()

        with patch.dict(
            os.environ,
            {**minimal_env, "QERDS_CRYPTO__CONFIG_VERSION": "2026.2"},
            clear=False,
        ):
            settings2 = Settings()
            hash2 = settings2.get_policy_hash()

        assert hash1 != hash2


class TestValidateSettings:
    """Tests for validate_settings function."""

    def test_validate_missing_s3_access_key(self, minimal_env):
        """Test validation fails when S3 access key is empty."""
        with patch.dict(
            os.environ,
            {**minimal_env, "QERDS_S3__ACCESS_KEY": ""},
            clear=False,
        ):
            settings = Settings()
            with pytest.raises(ConfigValidationError) as exc_info:
                validate_settings(settings)
            assert "S3 access key is required" in str(exc_info.value)

    def test_validate_missing_s3_secret_key(self, minimal_env):
        """Test validation fails when S3 secret key is empty."""
        with patch.dict(
            os.environ,
            {**minimal_env, "QERDS_S3__SECRET_KEY": ""},
            clear=False,
        ):
            settings = Settings()
            with pytest.raises(ConfigValidationError) as exc_info:
                validate_settings(settings)
            assert "S3 secret key is required" in str(exc_info.value)

    def test_validate_oidc_enabled_without_client_id(self, minimal_env):
        """Test validation fails when OIDC is enabled without client_id."""
        with patch.dict(
            os.environ,
            {
                **minimal_env,
                "QERDS_OIDC__ENABLED": "true",
                "QERDS_OIDC__CLIENT_ID": "",
            },
            clear=False,
        ):
            settings = Settings()
            with pytest.raises(ConfigValidationError) as exc_info:
                validate_settings(settings)
            assert "OIDC client_id is required" in str(exc_info.value)

    def test_validate_oidc_enabled_without_discovery_url(self, minimal_env):
        """Test validation fails when OIDC is enabled without discovery_url."""
        with patch.dict(
            os.environ,
            {
                **minimal_env,
                "QERDS_OIDC__ENABLED": "true",
                "QERDS_OIDC__CLIENT_ID": "my-client",
                "QERDS_OIDC__DISCOVERY_URL": "",
            },
            clear=False,
        ):
            settings = Settings()
            with pytest.raises(ConfigValidationError) as exc_info:
                validate_settings(settings)
            assert "OIDC discovery_url is required" in str(exc_info.value)


class TestSettingsSingleton:
    """Tests for settings singleton accessor."""

    def test_get_settings_caches_result(self, minimal_env):
        """Test that get_settings returns cached instance."""
        with patch.dict(os.environ, minimal_env, clear=False):
            settings1 = get_settings()
            settings2 = get_settings()
            assert settings1 is settings2

    def test_clear_settings_cache(self, minimal_env):
        """Test that clear_settings_cache resets the cache."""
        with patch.dict(os.environ, minimal_env, clear=False):
            settings1 = get_settings()
            clear_settings_cache()

        with patch.dict(
            os.environ,
            {**minimal_env, "QERDS_APP_NAME": "Test App"},
            clear=False,
        ):
            settings2 = get_settings()
            # Different instances after cache clear
            assert settings1 is not settings2


class TestRequireQualified:
    """Tests for require_qualified guard."""

    def test_require_qualified_raises_in_non_qualified_mode(self, minimal_env):
        """Test that require_qualified raises in non-qualified mode."""
        with patch.dict(os.environ, minimal_env, clear=False):
            with pytest.raises(RuntimeError) as exc_info:
                require_qualified()
            assert "requires qualified mode" in str(exc_info.value)

    def test_require_qualified_passes_in_qualified_mode(self, minimal_env):
        """Test that require_qualified passes in qualified mode."""
        with patch.dict(
            os.environ,
            {**minimal_env, "QERDS_CLAIM_STATE": "qualified"},
            clear=False,
        ):
            # Should not raise
            require_qualified()


class TestRequireProduction:
    """Tests for require_production guard."""

    def test_require_production_raises_in_dev_mode(self, minimal_env):
        """Test that require_production raises in dev mode."""
        with patch.dict(os.environ, minimal_env, clear=False):
            with pytest.raises(RuntimeError) as exc_info:
                require_production()
            assert "requires production environment" in str(exc_info.value)

    def test_require_production_passes_in_production(self, production_env):
        """Test that require_production passes in production."""
        with patch.dict(os.environ, production_env, clear=False):
            # Should not raise
            require_production()


class TestRetentionSettings:
    """Tests for RetentionSettings (REQ-F05, REQ-H02)."""

    def test_retention_settings_defaults(self):
        """Test retention settings default values meet CPCE requirements."""
        settings = RetentionSettings()
        # CPCE requires 365 days minimum for LRE proofs
        assert settings.lre_proof_retention_days >= 365
        assert settings.lre_proof_retention_days == 365  # Default is minimum
        # Audit logs should have longer retention
        assert settings.audit_log_retention_days == 1825  # 5 years
        # Content objects can have shorter retention
        assert settings.content_object_retention_days == 90

    def test_retention_settings_from_env(self):
        """Test loading retention settings from environment."""
        with patch.dict(
            os.environ,
            {
                "QERDS_RETENTION__LRE_PROOF_RETENTION_DAYS": "400",
                "QERDS_RETENTION__AUDIT_LOG_RETENTION_DAYS": "2555",
                "QERDS_RETENTION__CONTENT_OBJECT_RETENTION_DAYS": "60",
            },
            clear=False,
        ):
            settings = RetentionSettings()
            assert settings.lre_proof_retention_days == 400
            assert settings.audit_log_retention_days == 2555
            assert settings.content_object_retention_days == 60

    def test_retention_lre_proof_below_cpce_minimum_rejected(self):
        """Test that LRE proof retention below 365 days is rejected."""
        with patch.dict(
            os.environ,
            {"QERDS_RETENTION__LRE_PROOF_RETENTION_DAYS": "364"},
            clear=False,
        ):
            with pytest.raises(ValidationError) as exc_info:
                RetentionSettings()
            # The error should mention the CPCE minimum
            assert "365" in str(exc_info.value) or "greater than or equal" in str(exc_info.value)

    def test_retention_lre_proof_exactly_365_accepted(self):
        """Test that LRE proof retention of exactly 365 days is accepted."""
        with patch.dict(
            os.environ,
            {"QERDS_RETENTION__LRE_PROOF_RETENTION_DAYS": "365"},
            clear=False,
        ):
            settings = RetentionSettings()
            assert settings.lre_proof_retention_days == 365

    def test_retention_settings_in_main_settings(self, minimal_env):
        """Test that retention settings are included in main Settings."""
        with patch.dict(os.environ, minimal_env, clear=False):
            settings = Settings()
            assert hasattr(settings, "retention")
            assert isinstance(settings.retention, RetentionSettings)
            assert settings.retention.lre_proof_retention_days >= 365
