"""Tests for qualification service guardrails.

Tests cover:
- QualificationService mode detection and state management
- Localized labels and warnings for different languages
- Context generation for templates
- Assertion helpers for fail-closed paths
- Evidence metadata generation
- Factory function
- "No false qualified claims" guardrail verification

Per REQ-A01, REQ-G01, REQ-G02: The system must not claim "qualified" status
unless explicitly configured, and non-qualified mode must be clearly labeled.
"""

import os
from unittest.mock import patch

import pytest

from qerds.core.config import ClaimState, Settings
from qerds.services.qualification import (
    QualificationContext,
    QualificationError,
    QualificationService,
    create_qualification_service,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def minimal_env():
    """Provide minimal valid environment variables for Settings."""
    return {
        "QERDS_DATABASE__URL": "postgresql://user:pass@localhost:5432/qerds",
        "QERDS_S3__ACCESS_KEY": "test_access_key",
        "QERDS_S3__SECRET_KEY": "test_secret_key",
    }


@pytest.fixture
def non_qualified_settings(minimal_env):
    """Create Settings instance in non-qualified mode (default)."""
    with patch.dict(os.environ, minimal_env, clear=False):
        return Settings(
            claim_state=ClaimState.NON_QUALIFIED,
        )


@pytest.fixture
def qualified_settings(minimal_env):
    """Create Settings instance in qualified mode."""
    with patch.dict(os.environ, minimal_env, clear=False):
        return Settings(
            claim_state=ClaimState.QUALIFIED,
        )


@pytest.fixture
def non_qualified_service(non_qualified_settings):
    """Create QualificationService in non-qualified mode."""
    return QualificationService(non_qualified_settings)


@pytest.fixture
def qualified_service(qualified_settings):
    """Create QualificationService in qualified mode."""
    return QualificationService(qualified_settings)


# ---------------------------------------------------------------------------
# QualificationService Tests
# ---------------------------------------------------------------------------
class TestQualificationServiceBasics:
    """Basic tests for QualificationService functionality."""

    def test_init_with_non_qualified_settings(self, non_qualified_service):
        """Test service initializes correctly with non-qualified settings."""
        assert non_qualified_service.get_current_mode() == ClaimState.NON_QUALIFIED
        assert not non_qualified_service.is_qualified()

    def test_init_with_qualified_settings(self, qualified_service):
        """Test service initializes correctly with qualified settings."""
        assert qualified_service.get_current_mode() == ClaimState.QUALIFIED
        assert qualified_service.is_qualified()

    def test_get_current_mode_non_qualified(self, non_qualified_service):
        """Test get_current_mode returns NON_QUALIFIED."""
        assert non_qualified_service.get_current_mode() == ClaimState.NON_QUALIFIED
        assert non_qualified_service.get_current_mode().value == "non_qualified"

    def test_get_current_mode_qualified(self, qualified_service):
        """Test get_current_mode returns QUALIFIED."""
        assert qualified_service.get_current_mode() == ClaimState.QUALIFIED
        assert qualified_service.get_current_mode().value == "qualified"

    def test_is_qualified_returns_false_for_non_qualified(self, non_qualified_service):
        """Test is_qualified returns False in non-qualified mode."""
        assert non_qualified_service.is_qualified() is False

    def test_is_qualified_returns_true_for_qualified(self, qualified_service):
        """Test is_qualified returns True in qualified mode."""
        assert qualified_service.is_qualified() is True


class TestQualificationServiceLabels:
    """Tests for localized label generation."""

    def test_get_mode_label_non_qualified_french(self, non_qualified_service):
        """Test mode label in French for non-qualified mode."""
        label = non_qualified_service.get_mode_label("fr")
        # Should indicate non-qualified status
        assert "developpement" in label.lower() or "non qualifie" in label.lower()

    def test_get_mode_label_non_qualified_english(self, non_qualified_service):
        """Test mode label in English for non-qualified mode."""
        label = non_qualified_service.get_mode_label("en")
        # Should indicate non-qualified/development status
        assert "development" in label.lower() or "not qualified" in label.lower()

    def test_get_mode_label_qualified_french(self, qualified_service):
        """Test mode label in French for qualified mode."""
        label = qualified_service.get_mode_label("fr")
        # Should indicate qualified status
        assert "qualifie" in label.lower()

    def test_get_mode_label_qualified_english(self, qualified_service):
        """Test mode label in English for qualified mode."""
        label = qualified_service.get_mode_label("en")
        # Should indicate qualified status
        assert "qualified" in label.lower()

    def test_get_mode_label_defaults_to_french(self, non_qualified_service):
        """Test that mode label defaults to French."""
        label_default = non_qualified_service.get_mode_label()
        label_fr = non_qualified_service.get_mode_label("fr")
        assert label_default == label_fr


class TestQualificationServiceWarnings:
    """Tests for warning message generation."""

    def test_get_mode_warning_non_qualified_french(self, non_qualified_service):
        """Test warning message in French for non-qualified mode."""
        warning = non_qualified_service.get_mode_warning("fr")
        # Should warn about non-qualification and legal value
        assert warning != ""
        assert "qualifie" in warning.lower() or "juridique" in warning.lower()

    def test_get_mode_warning_non_qualified_english(self, non_qualified_service):
        """Test warning message in English for non-qualified mode."""
        warning = non_qualified_service.get_mode_warning("en")
        # Should warn about non-qualification and legal value
        assert warning != ""
        assert "qualified" in warning.lower() or "legal" in warning.lower()

    def test_get_mode_warning_qualified_returns_empty(self, qualified_service):
        """Test that qualified mode returns empty warning."""
        warning_fr = qualified_service.get_mode_warning("fr")
        warning_en = qualified_service.get_mode_warning("en")
        assert warning_fr == ""
        assert warning_en == ""

    def test_get_mode_warning_defaults_to_french(self, non_qualified_service):
        """Test that warning defaults to French."""
        warning_default = non_qualified_service.get_mode_warning()
        warning_fr = non_qualified_service.get_mode_warning("fr")
        assert warning_default == warning_fr


class TestQualificationServiceBadge:
    """Tests for badge text generation."""

    def test_get_badge_text_non_qualified(self, non_qualified_service):
        """Test badge text for non-qualified mode."""
        badge = non_qualified_service.get_badge_text("en")
        # Should be short text indicating dev mode
        assert badge != ""
        assert len(badge) < 50  # Badge should be short

    def test_get_badge_text_qualified(self, qualified_service):
        """Test badge text for qualified mode."""
        badge = qualified_service.get_badge_text("en")
        # Should indicate qualified
        assert "qualified" in badge.lower()


class TestQualificationServiceCssClass:
    """Tests for CSS class generation."""

    def test_get_css_class_non_qualified(self, non_qualified_service):
        """Test CSS class for non-qualified mode."""
        css_class = non_qualified_service.get_css_class()
        assert css_class == "dev"

    def test_get_css_class_qualified(self, qualified_service):
        """Test CSS class for qualified mode."""
        css_class = qualified_service.get_css_class()
        assert css_class == "qualified"


class TestQualificationServiceContext:
    """Tests for QualificationContext generation."""

    def test_get_context_non_qualified(self, non_qualified_service):
        """Test context generation for non-qualified mode."""
        context = non_qualified_service.get_context("en")

        assert isinstance(context, QualificationContext)
        assert context.mode == ClaimState.NON_QUALIFIED
        assert context.is_qualified is False
        assert context.css_class == "dev"
        assert context.warning != ""
        assert context.label != ""
        assert context.badge_text != ""

    def test_get_context_qualified(self, qualified_service):
        """Test context generation for qualified mode."""
        context = qualified_service.get_context("en")

        assert isinstance(context, QualificationContext)
        assert context.mode == ClaimState.QUALIFIED
        assert context.is_qualified is True
        assert context.css_class == "qualified"
        assert context.warning == ""
        assert context.label != ""
        assert context.badge_text != ""

    def test_get_context_defaults_to_french(self, non_qualified_service):
        """Test that context defaults to French."""
        context_default = non_qualified_service.get_context()
        context_fr = non_qualified_service.get_context("fr")

        assert context_default.label == context_fr.label
        assert context_default.warning == context_fr.warning


class TestQualificationContextDataclass:
    """Tests for QualificationContext dataclass."""

    def test_context_is_immutable(self, qualified_service):
        """Test that QualificationContext is immutable (frozen)."""
        context = qualified_service.get_context()
        with pytest.raises(AttributeError):
            context.mode = ClaimState.NON_QUALIFIED

    def test_context_to_dict(self, non_qualified_service):
        """Test context serialization to dictionary."""
        context = non_qualified_service.get_context("en")
        data = context.to_dict()

        assert isinstance(data, dict)
        assert data["mode"] == "non_qualified"
        assert data["is_qualified"] is False
        assert data["css_class"] == "dev"
        assert "label" in data
        assert "warning" in data
        assert "badge_text" in data

    def test_context_to_evidence_metadata(self, non_qualified_service):
        """Test evidence metadata generation."""
        context = non_qualified_service.get_context("en")
        metadata = context.to_evidence_metadata()

        assert isinstance(metadata, dict)
        assert metadata["qualification_label"] == "non_qualified"

    def test_context_to_evidence_metadata_qualified(self, qualified_service):
        """Test evidence metadata generation for qualified mode."""
        context = qualified_service.get_context()
        metadata = context.to_evidence_metadata()

        assert metadata["qualification_label"] == "qualified"


class TestQualificationServiceAssertion:
    """Tests for fail-closed assertion functionality."""

    def test_assert_qualified_raises_in_non_qualified_mode(self, non_qualified_service):
        """Test that assert_qualified raises QualificationError in non-qualified mode."""
        with pytest.raises(QualificationError):
            non_qualified_service.assert_qualified()

    def test_assert_qualified_raises_with_operation_name(self, non_qualified_service):
        """Test that assert_qualified includes operation name in error."""
        with pytest.raises(QualificationError) as exc_info:
            non_qualified_service.assert_qualified("generate_qualified_evidence")

        assert exc_info.value.operation == "generate_qualified_evidence"
        assert "generate_qualified_evidence" in str(exc_info.value)

    def test_assert_qualified_passes_in_qualified_mode(self, qualified_service):
        """Test that assert_qualified does not raise in qualified mode."""
        # Should not raise any exception
        qualified_service.assert_qualified()
        qualified_service.assert_qualified("any_operation")

    def test_assert_qualified_logs_warning(self, non_qualified_service):
        """Test that failed assertion logs a warning."""
        with (
            patch("qerds.services.qualification.logger") as mock_logger,
            pytest.raises(QualificationError),
        ):
            non_qualified_service.assert_qualified("test_op")
            mock_logger.warning.assert_called_once()


class TestQualificationServiceEvidenceMetadata:
    """Tests for evidence metadata generation."""

    def test_get_evidence_metadata_non_qualified(self, non_qualified_service):
        """Test evidence metadata for non-qualified mode."""
        metadata = non_qualified_service.get_evidence_metadata()

        assert isinstance(metadata, dict)
        assert metadata["qualification_label"] == "non_qualified"

    def test_get_evidence_metadata_qualified(self, qualified_service):
        """Test evidence metadata for qualified mode."""
        metadata = qualified_service.get_evidence_metadata()

        assert isinstance(metadata, dict)
        assert metadata["qualification_label"] == "qualified"


class TestQualificationServiceWarningVisibility:
    """Tests for warning visibility checks."""

    def test_should_show_warning_non_qualified(self, non_qualified_service):
        """Test that warning should be shown in non-qualified mode."""
        assert non_qualified_service.should_show_warning() is True

    def test_should_show_warning_qualified(self, qualified_service):
        """Test that warning should not be shown in qualified mode."""
        assert qualified_service.should_show_warning() is False


class TestQualificationError:
    """Tests for QualificationError exception."""

    def test_error_without_operation(self):
        """Test error message without operation name."""
        error = QualificationError()
        assert error.operation is None
        assert "non-qualified" in str(error).lower() or "development" in str(error).lower()

    def test_error_with_operation(self):
        """Test error message with operation name."""
        error = QualificationError("sign_document")
        assert error.operation == "sign_document"
        assert "sign_document" in str(error)

    def test_error_is_exception(self):
        """Test that QualificationError is an Exception."""
        error = QualificationError()
        assert isinstance(error, Exception)


class TestCreateQualificationService:
    """Tests for factory function."""

    def test_create_qualification_service(self, non_qualified_settings):
        """Test factory function creates service correctly."""
        service = create_qualification_service(non_qualified_settings)

        assert isinstance(service, QualificationService)
        assert service.get_current_mode() == ClaimState.NON_QUALIFIED


# ---------------------------------------------------------------------------
# "No False Qualified Claims" Guardrail Tests
# ---------------------------------------------------------------------------
class TestNoFalseQualifiedClaims:
    """Tests verifying the guardrail that prevents false qualified claims.

    These tests ensure that:
    1. Non-qualified mode always renders clear warnings
    2. The word "qualified" never appears without proper qualification
    3. Switching modes only changes labels/presentation, not behavior
    4. Evidence artifacts are always properly labeled
    """

    def test_non_qualified_never_claims_qualified_in_label(self, non_qualified_service):
        """Verify non-qualified mode label never claims to be qualified."""
        for lang in ["fr", "en"]:
            label = non_qualified_service.get_mode_label(lang)
            # The label should NOT contain "qualified" without "not" or "non"
            # or should explicitly say "development"
            label_lower = label.lower()
            if "qualified" in label_lower:
                # If "qualified" appears, it must be preceded by "not" or "non"
                assert "not qualified" in label_lower or "non qualifie" in label_lower

    def test_non_qualified_always_has_warning(self, non_qualified_service):
        """Verify non-qualified mode always produces a warning."""
        for lang in ["fr", "en"]:
            warning = non_qualified_service.get_mode_warning(lang)
            assert warning != "", f"Warning must not be empty for lang={lang}"
            assert len(warning) > 10, "Warning must be a substantial message"

    def test_non_qualified_evidence_metadata_labeled(self, non_qualified_service):
        """Verify non-qualified evidence is labeled as non_qualified."""
        metadata = non_qualified_service.get_evidence_metadata()
        assert metadata["qualification_label"] == "non_qualified"
        # Must NOT be "qualified"
        assert metadata["qualification_label"] != "qualified"

    def test_qualified_evidence_metadata_labeled(self, qualified_service):
        """Verify qualified evidence is labeled as qualified."""
        metadata = qualified_service.get_evidence_metadata()
        assert metadata["qualification_label"] == "qualified"

    def test_context_qualified_flag_matches_mode(self, non_qualified_service, qualified_service):
        """Verify is_qualified flag in context matches actual mode."""
        non_qual_ctx = non_qualified_service.get_context()
        qual_ctx = qualified_service.get_context()

        assert non_qual_ctx.is_qualified is False
        assert qual_ctx.is_qualified is True

    def test_switching_mode_changes_presentation_only(self, minimal_env):
        """Verify that mode switch changes labels but core API is consistent."""
        with patch.dict(os.environ, minimal_env, clear=False):
            # Create both services
            nq_settings = Settings(claim_state=ClaimState.NON_QUALIFIED)
            q_settings = Settings(claim_state=ClaimState.QUALIFIED)

            nq_service = QualificationService(nq_settings)
            q_service = QualificationService(q_settings)

            # Both should have the same methods available
            assert hasattr(nq_service, "get_context")
            assert hasattr(q_service, "get_context")
            assert hasattr(nq_service, "get_mode_label")
            assert hasattr(q_service, "get_mode_label")

            # Labels should be different
            assert nq_service.get_mode_label("en") != q_service.get_mode_label("en")

            # CSS classes should be different
            assert nq_service.get_css_class() != q_service.get_css_class()

    def test_serialized_context_never_lies_about_qualification(self, non_qualified_service):
        """Verify serialized context always truthfully reports qualification status."""
        context_dict = non_qualified_service.get_context().to_dict()

        # The is_qualified field must be False
        assert context_dict["is_qualified"] is False
        # The mode field must be non_qualified
        assert context_dict["mode"] == "non_qualified"

    def test_qualified_mode_can_claim_qualified(self, qualified_service):
        """Verify that qualified mode CAN claim qualified status."""
        context = qualified_service.get_context("en")

        # Should be able to claim qualified
        assert context.is_qualified is True
        assert "qualified" in context.label.lower()
        # Warning should be empty
        assert context.warning == ""


class TestIntegrationWithSettings:
    """Integration tests verifying QualificationService works with Settings."""

    def test_service_reflects_settings_claim_state(self, minimal_env):
        """Test that service accurately reflects settings claim_state."""
        with patch.dict(os.environ, minimal_env, clear=False):
            for claim_state in [ClaimState.QUALIFIED, ClaimState.NON_QUALIFIED]:
                settings = Settings(claim_state=claim_state)
                service = QualificationService(settings)

                assert service.get_current_mode() == claim_state
                assert service.is_qualified() == (claim_state == ClaimState.QUALIFIED)

    def test_default_settings_are_non_qualified(self, minimal_env):
        """Test that default settings produce non-qualified mode (safe default)."""
        with patch.dict(os.environ, minimal_env, clear=False):
            # Don't explicitly set claim_state - use default
            settings = Settings()
            service = QualificationService(settings)

            # Default should be non-qualified (safe default per compliance guardrail)
            assert service.is_qualified() is False
            assert service.get_current_mode() == ClaimState.NON_QUALIFIED
