"""Tests for qualified mode enforcement and fail-closed behavior.

Covers: REQ-A01, REQ-B04, REQ-D04, REQ-G02

These tests verify:
- Prerequisite checking for qualified mode operations
- Fail-closed behavior when prerequisites are not met
- Evidence labeling (qualified vs non_qualified)
- Mode switching and its effects on operations
- No silent fallback paths in qualified mode
"""

import os
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from qerds.core.config import ClaimState, Settings
from qerds.services.qualified_mode import (
    PrerequisiteCheckResult,
    PrerequisiteStatus,
    PrerequisiteType,
    QualifiedModeEnforcer,
    QualifiedModeNotReadyError,
    QualifiedModePrerequisites,
    create_qualified_mode_enforcer,
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
        return Settings(claim_state=ClaimState.NON_QUALIFIED)


@pytest.fixture
def qualified_settings(minimal_env):
    """Create Settings instance in qualified mode."""
    with patch.dict(os.environ, minimal_env, clear=False):
        return Settings(claim_state=ClaimState.QUALIFIED)


@pytest.fixture
def mock_hsm_connector():
    """Create a mock HSM connector that reports connected."""
    mock = MagicMock()
    mock.is_connected.return_value = True
    mock.has_signing_key.return_value = True
    mock.get_certificate_validity.return_value = {"valid": True}
    return mock


@pytest.fixture
def mock_disconnected_hsm():
    """Create a mock HSM connector that reports disconnected."""
    mock = MagicMock()
    mock.is_connected.return_value = False
    return mock


@pytest.fixture
def mock_time_verifier():
    """Create a mock time source verifier."""
    mock = MagicMock()
    mock.verify.return_value = True
    return mock


@pytest.fixture
def fully_configured_qualified_settings(minimal_env):
    """Create Settings instance in qualified mode with all qualified-mode fields.

    This fixture creates a settings object that has all the fields needed for
    qualified mode prerequisite checks (TSA URL, dossier ID, etc.) by using
    a MagicMock.
    """
    with patch.dict(os.environ, minimal_env, clear=False):
        settings = Settings(claim_state=ClaimState.QUALIFIED)
        # Create a mock that delegates to real settings but adds extra attrs
        mock_settings = MagicMock()
        mock_settings.claim_state = settings.claim_state
        mock_settings.trust = settings.trust
        mock_settings.qualified_tsa_url = "https://tsa.example.com"
        mock_settings.qualification_dossier_id = "dossier-123"
        mock_settings.trusted_list_reference = "EU-TL-001"
        return mock_settings


# ---------------------------------------------------------------------------
# PrerequisiteCheckResult Tests
# ---------------------------------------------------------------------------


class TestPrerequisiteCheckResult:
    """Tests for PrerequisiteCheckResult dataclass."""

    def test_create_satisfied_result(self):
        """Test creating a satisfied prerequisite result."""
        result = PrerequisiteCheckResult(
            prerequisite=PrerequisiteType.HSM_AVAILABLE,
            status=PrerequisiteStatus.SATISFIED,
            message="HSM connected via PKCS#11",
        )

        assert result.is_satisfied()
        assert result.prerequisite == PrerequisiteType.HSM_AVAILABLE
        assert result.status == PrerequisiteStatus.SATISFIED

    def test_create_unsatisfied_result(self):
        """Test creating an unsatisfied prerequisite result."""
        result = PrerequisiteCheckResult(
            prerequisite=PrerequisiteType.QUALIFIED_TSA,
            status=PrerequisiteStatus.NOT_SATISFIED,
            message="TSA not configured",
            details={"reason": "no_tsa_url"},
        )

        assert not result.is_satisfied()
        assert result.details["reason"] == "no_tsa_url"

    def test_result_is_immutable(self):
        """Test that PrerequisiteCheckResult is immutable."""
        result = PrerequisiteCheckResult(
            prerequisite=PrerequisiteType.HSM_AVAILABLE,
            status=PrerequisiteStatus.SATISFIED,
            message="OK",
        )
        with pytest.raises(AttributeError):
            result.status = PrerequisiteStatus.NOT_SATISFIED

    def test_result_to_dict(self):
        """Test serialization to dictionary."""
        result = PrerequisiteCheckResult(
            prerequisite=PrerequisiteType.HSM_AVAILABLE,
            status=PrerequisiteStatus.SATISFIED,
            message="HSM connected",
            details={"hsm_id": "test-hsm"},
        )

        data = result.to_dict()

        assert data["prerequisite"] == "hsm_available"
        assert data["status"] == "satisfied"
        assert data["message"] == "HSM connected"
        assert data["details"]["hsm_id"] == "test-hsm"
        assert "checked_at" in data


# ---------------------------------------------------------------------------
# QualifiedModePrerequisites Tests
# ---------------------------------------------------------------------------


class TestQualifiedModePrerequisites:
    """Tests for QualifiedModePrerequisites dataclass."""

    def test_all_satisfied_when_all_pass(self):
        """Test all_satisfied is True when all prerequisites pass."""
        results = (
            PrerequisiteCheckResult(
                prerequisite=PrerequisiteType.HSM_AVAILABLE,
                status=PrerequisiteStatus.SATISFIED,
                message="OK",
            ),
            PrerequisiteCheckResult(
                prerequisite=PrerequisiteType.QUALIFIED_TSA,
                status=PrerequisiteStatus.SATISFIED,
                message="OK",
            ),
        )

        prereqs = QualifiedModePrerequisites(
            results=results,
            all_satisfied=True,
            checked_at=datetime.now(UTC),
            qualification_basis_ref="dossier-123",
        )

        assert prereqs.all_satisfied
        assert len(prereqs.get_unsatisfied()) == 0
        assert prereqs.qualification_basis_ref == "dossier-123"

    def test_all_satisfied_false_when_any_fail(self):
        """Test all_satisfied is False when any prerequisite fails."""
        results = (
            PrerequisiteCheckResult(
                prerequisite=PrerequisiteType.HSM_AVAILABLE,
                status=PrerequisiteStatus.SATISFIED,
                message="OK",
            ),
            PrerequisiteCheckResult(
                prerequisite=PrerequisiteType.QUALIFIED_TSA,
                status=PrerequisiteStatus.NOT_SATISFIED,
                message="Not configured",
            ),
        )

        prereqs = QualifiedModePrerequisites(
            results=results,
            all_satisfied=False,
            checked_at=datetime.now(UTC),
        )

        assert not prereqs.all_satisfied
        assert len(prereqs.get_unsatisfied()) == 1
        assert prereqs.get_unsatisfied()[0].prerequisite == PrerequisiteType.QUALIFIED_TSA

    def test_get_failure_summary(self):
        """Test failure summary generation."""
        results = (
            PrerequisiteCheckResult(
                prerequisite=PrerequisiteType.HSM_AVAILABLE,
                status=PrerequisiteStatus.NOT_SATISFIED,
                message="HSM not connected",
            ),
            PrerequisiteCheckResult(
                prerequisite=PrerequisiteType.QUALIFIED_TSA,
                status=PrerequisiteStatus.NOT_SATISFIED,
                message="TSA not configured",
            ),
        )

        prereqs = QualifiedModePrerequisites(
            results=results,
            all_satisfied=False,
            checked_at=datetime.now(UTC),
        )

        summary = prereqs.get_failure_summary()

        assert "2 failures" in summary
        assert "hsm_available" in summary
        assert "qualified_tsa" in summary

    def test_get_failure_summary_empty_when_satisfied(self):
        """Test failure summary is empty when all satisfied."""
        results = (
            PrerequisiteCheckResult(
                prerequisite=PrerequisiteType.HSM_AVAILABLE,
                status=PrerequisiteStatus.SATISFIED,
                message="OK",
            ),
        )

        prereqs = QualifiedModePrerequisites(
            results=results,
            all_satisfied=True,
            checked_at=datetime.now(UTC),
        )

        assert prereqs.get_failure_summary() == ""

    def test_to_dict(self):
        """Test serialization to dictionary."""
        results = (
            PrerequisiteCheckResult(
                prerequisite=PrerequisiteType.HSM_AVAILABLE,
                status=PrerequisiteStatus.SATISFIED,
                message="OK",
            ),
        )

        prereqs = QualifiedModePrerequisites(
            results=results,
            all_satisfied=True,
            checked_at=datetime.now(UTC),
            qualification_basis_ref="ref-123",
        )

        data = prereqs.to_dict()

        assert data["all_satisfied"] is True
        assert data["qualification_basis_ref"] == "ref-123"
        assert len(data["results"]) == 1


# ---------------------------------------------------------------------------
# QualifiedModeNotReadyError Tests
# ---------------------------------------------------------------------------


class TestQualifiedModeNotReadyError:
    """Tests for QualifiedModeNotReadyError exception."""

    def test_error_contains_operation_name(self):
        """Test that error message includes operation name."""
        results = (
            PrerequisiteCheckResult(
                prerequisite=PrerequisiteType.HSM_AVAILABLE,
                status=PrerequisiteStatus.NOT_SATISFIED,
                message="HSM not connected",
            ),
        )

        prereqs = QualifiedModePrerequisites(
            results=results,
            all_satisfied=False,
            checked_at=datetime.now(UTC),
        )

        error = QualifiedModeNotReadyError("seal", prereqs)

        assert "seal" in str(error)
        assert "hsm_available" in str(error)
        assert "REQ-B04" in str(error)

    def test_error_to_dict(self):
        """Test error serialization for API responses."""
        results = (
            PrerequisiteCheckResult(
                prerequisite=PrerequisiteType.HSM_AVAILABLE,
                status=PrerequisiteStatus.NOT_SATISFIED,
                message="HSM not connected",
            ),
        )

        prereqs = QualifiedModePrerequisites(
            results=results,
            all_satisfied=False,
            checked_at=datetime.now(UTC),
        )

        error = QualifiedModeNotReadyError("timestamp", prereqs)
        data = error.to_dict()

        assert data["error"] == "qualified_mode_not_ready"
        assert data["operation"] == "timestamp"
        assert "prerequisites" in data


# ---------------------------------------------------------------------------
# QualifiedModeEnforcer Tests - Non-Qualified Mode
# ---------------------------------------------------------------------------


class TestQualifiedModeEnforcerNonQualified:
    """Tests for QualifiedModeEnforcer in non-qualified mode."""

    def test_is_qualified_mode_false_in_non_qualified(self, non_qualified_settings):
        """Test that is_qualified_mode returns False in non-qualified mode."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)
        assert enforcer.is_qualified_mode is False

    def test_check_prerequisites_returns_results(self, non_qualified_settings):
        """Test that check_prerequisites returns prerequisite results."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)
        prereqs = enforcer.check_prerequisites()

        assert isinstance(prereqs, QualifiedModePrerequisites)
        assert len(prereqs.results) > 0
        assert prereqs.checked_at is not None

    def test_enforce_does_not_raise_in_non_qualified(self, non_qualified_settings):
        """Test that enforce_prerequisites does not raise in non-qualified mode.

        Even if prerequisites are not met, non-qualified mode allows operations
        to proceed (they are just labeled as non-qualified).
        """
        enforcer = QualifiedModeEnforcer(non_qualified_settings)

        # Should not raise, even without HSM
        prereqs = enforcer.enforce_prerequisites("seal")

        assert isinstance(prereqs, QualifiedModePrerequisites)

    def test_get_qualification_label_non_qualified(self, non_qualified_settings):
        """Test that qualification label is non_qualified in non-qualified mode."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)

        label = enforcer.get_qualification_label()

        assert label == "non_qualified"

    def test_get_qualification_basis_ref_none_in_non_qualified(self, non_qualified_settings):
        """Test that qualification_basis_ref is None in non-qualified mode."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)

        ref = enforcer.get_qualification_basis_ref()

        assert ref is None


# ---------------------------------------------------------------------------
# QualifiedModeEnforcer Tests - Qualified Mode
# ---------------------------------------------------------------------------


class TestQualifiedModeEnforcerQualified:
    """Tests for QualifiedModeEnforcer in qualified mode."""

    def test_is_qualified_mode_true_in_qualified(self, qualified_settings):
        """Test that is_qualified_mode returns True in qualified mode."""
        enforcer = QualifiedModeEnforcer(qualified_settings)
        assert enforcer.is_qualified_mode is True

    def test_enforce_raises_without_prerequisites(self, qualified_settings):
        """Test that enforce_prerequisites raises when prerequisites not met.

        This is the fail-closed behavior per REQ-B04.
        """
        enforcer = QualifiedModeEnforcer(qualified_settings)

        with pytest.raises(QualifiedModeNotReadyError) as exc_info:
            enforcer.enforce_prerequisites("seal")

        assert exc_info.value.operation == "seal"
        assert len(exc_info.value.prerequisites.get_unsatisfied()) > 0

    def test_enforce_raises_for_timestamp_without_prerequisites(self, qualified_settings):
        """Test fail-closed for timestamp operation."""
        enforcer = QualifiedModeEnforcer(qualified_settings)

        with pytest.raises(QualifiedModeNotReadyError) as exc_info:
            enforcer.enforce_prerequisites("timestamp")

        assert "timestamp" in str(exc_info.value)

    def test_enforce_passes_with_all_prerequisites(
        self, fully_configured_qualified_settings, mock_hsm_connector, mock_time_verifier
    ):
        """Test that enforcement passes when all prerequisites are met."""
        enforcer = QualifiedModeEnforcer(
            fully_configured_qualified_settings,
            hsm_connector=mock_hsm_connector,
            time_source_verifier=mock_time_verifier,
        )

        # Should not raise
        prereqs = enforcer.enforce_prerequisites("seal")

        assert prereqs.all_satisfied

    def test_get_qualification_label_qualified_when_all_satisfied(
        self, fully_configured_qualified_settings, mock_hsm_connector, mock_time_verifier
    ):
        """Test that label is 'qualified' when all prerequisites met."""
        enforcer = QualifiedModeEnforcer(
            fully_configured_qualified_settings,
            hsm_connector=mock_hsm_connector,
            time_source_verifier=mock_time_verifier,
        )

        label = enforcer.get_qualification_label()

        assert label == "qualified"

    def test_get_qualification_label_non_qualified_when_prereqs_not_met(self, qualified_settings):
        """Test that label is 'non_qualified' when prerequisites not met.

        Even in qualified mode, if prerequisites fail, we conservatively
        label as non_qualified (should not normally happen due to enforcement).
        """
        enforcer = QualifiedModeEnforcer(qualified_settings)

        label = enforcer.get_qualification_label()

        # Without HSM, should return non_qualified
        assert label == "non_qualified"


# ---------------------------------------------------------------------------
# Prerequisite Check Tests
# ---------------------------------------------------------------------------


class TestHSMPrerequisiteCheck:
    """Tests for HSM availability prerequisite check."""

    def test_hsm_not_satisfied_without_connector(self, non_qualified_settings):
        """Test HSM check fails without connector."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)
        prereqs = enforcer.check_prerequisites()

        hsm_result = next(
            r for r in prereqs.results if r.prerequisite == PrerequisiteType.HSM_AVAILABLE
        )

        assert not hsm_result.is_satisfied()
        assert "not configured" in hsm_result.message.lower()

    def test_hsm_satisfied_with_connected_hsm(self, non_qualified_settings, mock_hsm_connector):
        """Test HSM check passes with connected HSM."""
        enforcer = QualifiedModeEnforcer(
            non_qualified_settings,
            hsm_connector=mock_hsm_connector,
        )
        prereqs = enforcer.check_prerequisites()

        hsm_result = next(
            r for r in prereqs.results if r.prerequisite == PrerequisiteType.HSM_AVAILABLE
        )

        assert hsm_result.is_satisfied()

    def test_hsm_not_satisfied_when_disconnected(
        self, non_qualified_settings, mock_disconnected_hsm
    ):
        """Test HSM check fails when HSM is disconnected."""
        enforcer = QualifiedModeEnforcer(
            non_qualified_settings,
            hsm_connector=mock_disconnected_hsm,
        )
        prereqs = enforcer.check_prerequisites()

        hsm_result = next(
            r for r in prereqs.results if r.prerequisite == PrerequisiteType.HSM_AVAILABLE
        )

        assert not hsm_result.is_satisfied()


class TestTSAPrerequisiteCheck:
    """Tests for TSA availability prerequisite check."""

    def test_tsa_not_satisfied_without_url(self, non_qualified_settings):
        """Test TSA check fails without URL configured."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)
        prereqs = enforcer.check_prerequisites()

        tsa_result = next(
            r for r in prereqs.results if r.prerequisite == PrerequisiteType.QUALIFIED_TSA
        )

        assert not tsa_result.is_satisfied()

    def test_tsa_satisfied_with_url(self, non_qualified_settings):
        """Test TSA check passes with URL configured."""
        # Use mock to add the qualified_tsa_url attribute
        mock_settings = MagicMock()
        mock_settings.claim_state = non_qualified_settings.claim_state
        mock_settings.trust = non_qualified_settings.trust
        mock_settings.qualified_tsa_url = "https://tsa.example.com"

        enforcer = QualifiedModeEnforcer(mock_settings)
        prereqs = enforcer.check_prerequisites()

        tsa_result = next(
            r for r in prereqs.results if r.prerequisite == PrerequisiteType.QUALIFIED_TSA
        )

        assert tsa_result.is_satisfied()


class TestPolicyPrerequisiteCheck:
    """Tests for policy/dossier configuration prerequisite check."""

    def test_policy_not_satisfied_without_dossier(self, non_qualified_settings):
        """Test policy check fails without dossier configured."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)
        prereqs = enforcer.check_prerequisites()

        policy_result = next(
            r for r in prereqs.results if r.prerequisite == PrerequisiteType.POLICY_CONFIGURED
        )

        assert not policy_result.is_satisfied()

    def test_policy_satisfied_with_dossier(self, non_qualified_settings):
        """Test policy check passes with dossier configured."""
        # Use mock to add the qualification_dossier_id attribute
        mock_settings = MagicMock()
        mock_settings.claim_state = non_qualified_settings.claim_state
        mock_settings.trust = non_qualified_settings.trust
        mock_settings.qualification_dossier_id = "dossier-123"

        enforcer = QualifiedModeEnforcer(mock_settings)
        prereqs = enforcer.check_prerequisites()

        policy_result = next(
            r for r in prereqs.results if r.prerequisite == PrerequisiteType.POLICY_CONFIGURED
        )

        assert policy_result.is_satisfied()


# ---------------------------------------------------------------------------
# Caching Tests
# ---------------------------------------------------------------------------


class TestPrerequisiteCheckCaching:
    """Tests for prerequisite check result caching."""

    def test_results_are_cached(self, non_qualified_settings, mock_hsm_connector):
        """Test that check results are cached."""
        enforcer = QualifiedModeEnforcer(
            non_qualified_settings,
            hsm_connector=mock_hsm_connector,
        )

        prereqs1 = enforcer.check_prerequisites()
        prereqs2 = enforcer.check_prerequisites()

        # Should be same object (cached)
        assert prereqs1 is prereqs2

    def test_force_recheck_bypasses_cache(self, non_qualified_settings, mock_hsm_connector):
        """Test that force_recheck bypasses the cache."""
        enforcer = QualifiedModeEnforcer(
            non_qualified_settings,
            hsm_connector=mock_hsm_connector,
        )

        prereqs1 = enforcer.check_prerequisites()
        prereqs2 = enforcer.check_prerequisites(force_recheck=True)

        # Should be different objects (not cached)
        assert prereqs1 is not prereqs2

    def test_invalidate_cache(self, non_qualified_settings, mock_hsm_connector):
        """Test cache invalidation."""
        enforcer = QualifiedModeEnforcer(
            non_qualified_settings,
            hsm_connector=mock_hsm_connector,
        )

        prereqs1 = enforcer.check_prerequisites()
        enforcer.invalidate_cache()
        prereqs2 = enforcer.check_prerequisites()

        # Should be different objects after invalidation
        assert prereqs1 is not prereqs2


# ---------------------------------------------------------------------------
# Factory Function Tests
# ---------------------------------------------------------------------------


class TestCreateQualifiedModeEnforcer:
    """Tests for factory function."""

    def test_create_enforcer_basic(self, non_qualified_settings):
        """Test creating enforcer with factory function."""
        enforcer = create_qualified_mode_enforcer(non_qualified_settings)

        assert isinstance(enforcer, QualifiedModeEnforcer)

    def test_create_enforcer_with_hsm(self, non_qualified_settings, mock_hsm_connector):
        """Test creating enforcer with HSM connector."""
        enforcer = create_qualified_mode_enforcer(
            non_qualified_settings,
            hsm_connector=mock_hsm_connector,
        )

        prereqs = enforcer.check_prerequisites()
        hsm_result = next(
            r for r in prereqs.results if r.prerequisite == PrerequisiteType.HSM_AVAILABLE
        )

        assert hsm_result.is_satisfied()


# ---------------------------------------------------------------------------
# Fail-Closed Behavior Tests (REQ-B04)
# ---------------------------------------------------------------------------


class TestFailClosedBehavior:
    """Tests verifying fail-closed behavior per REQ-B04.

    These tests ensure that qualified mode operations fail when
    prerequisites are not met, with no silent fallback paths.
    """

    def test_seal_operation_fails_closed_without_hsm(self, qualified_settings):
        """Test that seal fails closed without HSM in qualified mode."""
        enforcer = QualifiedModeEnforcer(qualified_settings)

        with pytest.raises(QualifiedModeNotReadyError) as exc_info:
            enforcer.enforce_prerequisites("seal")

        # Verify error contains useful information
        assert exc_info.value.operation == "seal"
        assert "REQ-B04" in str(exc_info.value)

    def test_timestamp_operation_fails_closed_without_tsa(self, qualified_settings):
        """Test that timestamp fails closed without TSA in qualified mode."""
        enforcer = QualifiedModeEnforcer(qualified_settings)

        with pytest.raises(QualifiedModeNotReadyError) as exc_info:
            enforcer.enforce_prerequisites("timestamp")

        unsatisfied = exc_info.value.prerequisites.get_unsatisfied()
        prereq_types = [r.prerequisite for r in unsatisfied]

        # Should include TSA as unsatisfied
        assert PrerequisiteType.QUALIFIED_TSA in prereq_types

    def test_no_fallback_to_software_keys(self, qualified_settings):
        """Test that qualified mode does not fall back to software keys.

        Per REQ-D04, qualified mode must use HSM with no software fallback.
        """
        enforcer = QualifiedModeEnforcer(qualified_settings)

        with pytest.raises(QualifiedModeNotReadyError):
            enforcer.enforce_prerequisites("seal")

        # Verify qualification label is not 'qualified' without HSM
        label = enforcer.get_qualification_label()
        assert label == "non_qualified"

    def test_multiple_missing_prerequisites_all_reported(self, qualified_settings):
        """Test that all missing prerequisites are reported."""
        enforcer = QualifiedModeEnforcer(qualified_settings)

        with pytest.raises(QualifiedModeNotReadyError) as exc_info:
            enforcer.enforce_prerequisites("seal")

        unsatisfied = exc_info.value.prerequisites.get_unsatisfied()

        # Should report multiple missing prerequisites
        assert len(unsatisfied) > 1

    def test_operations_proceed_in_non_qualified_mode(self, non_qualified_settings):
        """Test that operations proceed in non-qualified mode (with labeling)."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)

        # Should not raise, even without any prerequisites
        _ = enforcer.enforce_prerequisites("seal")

        # But should be labeled as non-qualified
        assert enforcer.get_qualification_label() == "non_qualified"


# ---------------------------------------------------------------------------
# Evidence Labeling Tests (REQ-G02)
# ---------------------------------------------------------------------------


class TestEvidenceLabeling:
    """Tests for evidence labeling per REQ-G02.

    Per REQ-G02, non-qualified mode outputs must be clearly labeled
    as non_qualified to prevent misrepresentation.
    """

    def test_non_qualified_label_in_non_qualified_mode(self, non_qualified_settings):
        """Test that non-qualified mode produces non_qualified label."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)

        label = enforcer.get_qualification_label()

        assert label == "non_qualified"

    def test_no_basis_ref_in_non_qualified_mode(self, non_qualified_settings):
        """Test that non-qualified mode has no basis reference."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)

        ref = enforcer.get_qualification_basis_ref()

        assert ref is None

    def test_qualified_label_requires_all_prerequisites(
        self, fully_configured_qualified_settings, mock_hsm_connector, mock_time_verifier
    ):
        """Test that 'qualified' label requires all prerequisites satisfied."""
        enforcer = QualifiedModeEnforcer(
            fully_configured_qualified_settings,
            hsm_connector=mock_hsm_connector,
            time_source_verifier=mock_time_verifier,
        )

        label = enforcer.get_qualification_label()

        assert label == "qualified"

    def test_basis_ref_present_when_qualified(
        self, fully_configured_qualified_settings, mock_hsm_connector, mock_time_verifier
    ):
        """Test that qualification_basis_ref is present when qualified."""
        enforcer = QualifiedModeEnforcer(
            fully_configured_qualified_settings,
            hsm_connector=mock_hsm_connector,
            time_source_verifier=mock_time_verifier,
        )

        ref = enforcer.get_qualification_basis_ref()

        assert ref == "dossier-123"


# ---------------------------------------------------------------------------
# Mode Switching Tests
# ---------------------------------------------------------------------------


class TestModeSwitching:
    """Tests for behavior changes when switching modes."""

    def test_same_api_in_both_modes(self, non_qualified_settings, qualified_settings):
        """Test that the API is consistent in both modes."""
        nq_enforcer = QualifiedModeEnforcer(non_qualified_settings)
        q_enforcer = QualifiedModeEnforcer(qualified_settings)

        # Both should have same methods
        assert hasattr(nq_enforcer, "check_prerequisites")
        assert hasattr(q_enforcer, "check_prerequisites")
        assert hasattr(nq_enforcer, "enforce_prerequisites")
        assert hasattr(q_enforcer, "enforce_prerequisites")
        assert hasattr(nq_enforcer, "get_qualification_label")
        assert hasattr(q_enforcer, "get_qualification_label")

    def test_different_enforcement_behavior(self, non_qualified_settings, qualified_settings):
        """Test that enforcement behavior differs by mode."""
        nq_enforcer = QualifiedModeEnforcer(non_qualified_settings)
        q_enforcer = QualifiedModeEnforcer(qualified_settings)

        # Non-qualified should not raise
        nq_prereqs = nq_enforcer.enforce_prerequisites("seal")
        assert isinstance(nq_prereqs, QualifiedModePrerequisites)

        # Qualified should raise without prerequisites
        with pytest.raises(QualifiedModeNotReadyError):
            q_enforcer.enforce_prerequisites("seal")

    def test_labels_differ_by_mode(self, non_qualified_settings, qualified_settings):
        """Test that labels are appropriate for each mode."""
        nq_enforcer = QualifiedModeEnforcer(non_qualified_settings)

        # Non-qualified always produces non_qualified label
        assert nq_enforcer.get_qualification_label() == "non_qualified"

        # Qualified without prerequisites also produces non_qualified
        q_enforcer = QualifiedModeEnforcer(qualified_settings)
        assert q_enforcer.get_qualification_label() == "non_qualified"


# ---------------------------------------------------------------------------
# TrustService Integration Tests
# ---------------------------------------------------------------------------


class TestTrustServiceIntegration:
    """Tests for QualifiedModeEnforcer integration with TrustService."""

    @pytest.fixture
    def temp_key_dir(self, tmp_path):
        """Create a temporary directory for key storage."""
        key_dir = tmp_path / "keys"
        key_dir.mkdir()
        return key_dir

    @pytest.fixture
    def trust_config(self, temp_key_dir):
        """Create a TrustServiceConfig for testing."""
        from qerds.services.trust import QualificationMode, TrustServiceConfig

        return TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
        )

    @pytest.fixture
    async def trust_service_with_enforcer(self, trust_config, non_qualified_settings):
        """Create TrustService with QualifiedModeEnforcer."""
        from qerds.services.trust import TrustService

        enforcer = QualifiedModeEnforcer(non_qualified_settings)
        service = TrustService(trust_config, qualified_mode_enforcer=enforcer)
        await service.initialize()
        return service

    @pytest.fixture
    async def trust_service_without_enforcer(self, trust_config):
        """Create TrustService without QualifiedModeEnforcer."""
        from qerds.services.trust import TrustService

        service = TrustService(trust_config)
        await service.initialize()
        return service

    async def test_seal_with_enforcer_succeeds(self, trust_service_with_enforcer):
        """Test seal operation succeeds with enforcer in non-qualified mode."""
        data = b"test data for sealing"
        sealed = await trust_service_with_enforcer.seal(data)

        assert sealed is not None
        assert sealed.qualification_label.value == "non_qualified"

    async def test_seal_without_enforcer_succeeds(self, trust_service_without_enforcer):
        """Test seal operation succeeds without enforcer."""
        data = b"test data for sealing"
        sealed = await trust_service_without_enforcer.seal(data)

        assert sealed is not None
        assert sealed.qualification_label.value == "non_qualified"

    async def test_timestamp_with_enforcer_succeeds(self, trust_service_with_enforcer):
        """Test timestamp operation succeeds with enforcer in non-qualified mode."""
        data = b"test data for timestamping"
        token = await trust_service_with_enforcer.timestamp(data)

        assert token is not None
        assert token.qualification_label.value == "non_qualified"

    async def test_enforcer_called_on_seal(self, trust_config, non_qualified_settings):
        """Test that enforcer.enforce_prerequisites is called on seal."""
        from unittest.mock import MagicMock

        from qerds.services.trust import TrustService

        mock_enforcer = MagicMock()
        mock_enforcer.enforce_prerequisites.return_value = MagicMock()

        service = TrustService(trust_config, qualified_mode_enforcer=mock_enforcer)
        await service.initialize()

        await service.seal(b"test data")

        mock_enforcer.enforce_prerequisites.assert_called_once_with("seal")

    async def test_enforcer_called_on_timestamp(self, trust_config, non_qualified_settings):
        """Test that enforcer.enforce_prerequisites is called on timestamp."""
        from unittest.mock import MagicMock

        from qerds.services.trust import TrustService

        mock_enforcer = MagicMock()
        mock_enforcer.enforce_prerequisites.return_value = MagicMock()

        service = TrustService(trust_config, qualified_mode_enforcer=mock_enforcer)
        await service.initialize()

        await service.timestamp(b"test data")

        mock_enforcer.enforce_prerequisites.assert_called_once_with("timestamp")
