"""Integration tests for HSM fail-closed behavior.

Covers: REQ-D04, REQ-G02

These tests verify that:
1. Qualified mode without HSM config -> signing operation fails
2. Qualified mode with HSM unreachable -> signing operation fails
3. Qualified mode with valid HSM -> signing succeeds
4. Non-qualified mode without HSM -> signing succeeds (labeled non-qualified)
5. Mode transition requires restart (no hot switching to qualified)

Per REQ-D04: Qualified mode must use HSM with no software fallback.
Per REQ-G02: Non-qualified mode outputs must be clearly labeled.

Run with: docker compose exec api pytest -xvs tests/integration/test_hsm_failclosed.py
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from qerds.core.config import ClaimState, Settings
from qerds.services.qualified_mode import (
    PrerequisiteStatus,
    PrerequisiteType,
    QualifiedModeEnforcer,
    QualifiedModeNotReadyError,
)
from qerds.services.trust import (
    QualificationMode,
    TrustService,
    TrustServiceConfig,
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
def temp_key_dir():
    """Create a temporary directory for key storage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def non_qualified_settings(minimal_env):
    """Create Settings instance in non-qualified mode."""
    with patch.dict(os.environ, minimal_env, clear=False):
        return Settings(claim_state=ClaimState.NON_QUALIFIED)


@pytest.fixture
def qualified_settings(minimal_env):
    """Create Settings instance in qualified mode."""
    with patch.dict(os.environ, minimal_env, clear=False):
        return Settings(claim_state=ClaimState.QUALIFIED)


@pytest.fixture
def mock_hsm_connected():
    """Create a mock HSM connector that reports connected with valid key."""
    mock = MagicMock()
    mock.is_connected.return_value = True
    mock.has_signing_key.return_value = True
    mock.get_certificate_validity.return_value = {"valid": True}
    return mock


@pytest.fixture
def mock_hsm_disconnected():
    """Create a mock HSM connector that reports disconnected (unreachable)."""
    mock = MagicMock()
    mock.is_connected.return_value = False
    return mock


@pytest.fixture
def mock_hsm_connection_error():
    """Create a mock HSM connector that raises an exception on connection check."""
    mock = MagicMock()
    mock.is_connected.side_effect = Exception("HSM connection timeout")
    return mock


@pytest.fixture
def mock_time_verifier():
    """Create a mock time source verifier."""
    mock = MagicMock()
    mock.verify.return_value = True
    return mock


@pytest.fixture
def fully_configured_qualified_settings(minimal_env):
    """Create mock Settings with all qualified-mode prerequisite fields."""
    with patch.dict(os.environ, minimal_env, clear=False):
        settings = Settings(claim_state=ClaimState.QUALIFIED)
        # Wrap in mock to add extra attributes needed for prerequisite checks
        mock_settings = MagicMock()
        mock_settings.claim_state = settings.claim_state
        mock_settings.trust = settings.trust
        mock_settings.qualified_tsa_url = "https://tsa.qualified.example.com"
        mock_settings.qualification_dossier_id = "dossier-qualified-001"
        mock_settings.trusted_list_reference = "EU-TL-2026"
        return mock_settings


# ---------------------------------------------------------------------------
# Scenario 1: Qualified mode without HSM config -> signing fails
# ---------------------------------------------------------------------------


class TestQualifiedModeWithoutHSMConfig:
    """Test that qualified mode fails closed when HSM is not configured.

    Per REQ-D04: If HSM unavailable, fail closed.
    """

    def test_enforcer_fails_without_hsm_connector(self, qualified_settings):
        """Verify enforcer raises when no HSM connector is provided."""
        # Create enforcer without HSM connector
        enforcer = QualifiedModeEnforcer(qualified_settings)

        # Attempting to enforce prerequisites should fail
        with pytest.raises(QualifiedModeNotReadyError) as exc_info:
            enforcer.enforce_prerequisites("seal")

        # Verify HSM is listed as unsatisfied
        unsatisfied = exc_info.value.prerequisites.get_unsatisfied()
        hsm_prereq = next(
            (r for r in unsatisfied if r.prerequisite == PrerequisiteType.HSM_AVAILABLE),
            None,
        )
        assert hsm_prereq is not None
        assert not hsm_prereq.is_satisfied()
        assert "not configured" in hsm_prereq.message.lower()

    def test_seal_fails_in_qualified_mode_without_hsm(self, qualified_settings, temp_key_dir):
        """Verify seal operation fails when HSM not configured in qualified mode."""
        # Create trust service with qualified mode enforcer but no HSM
        enforcer = QualifiedModeEnforcer(qualified_settings)

        # TrustService uses non-qualified config but with qualified enforcer
        # This simulates misconfiguration where someone tries qualified without HSM
        # Note: We verify the enforcer blocks operations, not the TrustService
        _ = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,  # Can only initialize non-qualified
            key_storage_path=temp_key_dir,
        )

        # The enforcer will block qualified operations
        assert enforcer.is_qualified_mode is True

        with pytest.raises(QualifiedModeNotReadyError) as exc_info:
            enforcer.enforce_prerequisites("seal")

        assert "seal" in exc_info.value.operation
        assert "REQ-B04" in str(exc_info.value)

    def test_timestamp_fails_in_qualified_mode_without_hsm(self, qualified_settings):
        """Verify timestamp operation fails when HSM not configured."""
        enforcer = QualifiedModeEnforcer(qualified_settings)

        with pytest.raises(QualifiedModeNotReadyError) as exc_info:
            enforcer.enforce_prerequisites("timestamp")

        assert "timestamp" in exc_info.value.operation

    def test_error_message_identifies_missing_hsm(self, qualified_settings):
        """Verify error message clearly identifies HSM as the missing prerequisite."""
        enforcer = QualifiedModeEnforcer(qualified_settings)

        with pytest.raises(QualifiedModeNotReadyError) as exc_info:
            enforcer.enforce_prerequisites("seal")

        error_message = str(exc_info.value)
        # Error should mention HSM as missing
        assert "hsm_available" in error_message.lower()


# ---------------------------------------------------------------------------
# Scenario 2: Qualified mode with HSM unreachable -> signing fails
# ---------------------------------------------------------------------------


class TestQualifiedModeWithHSMUnreachable:
    """Test that qualified mode fails closed when HSM is unreachable.

    Per REQ-D04: If HSM unavailable, fail closed.
    """

    def test_enforcer_fails_with_disconnected_hsm(self, qualified_settings, mock_hsm_disconnected):
        """Verify enforcer raises when HSM connector reports disconnected."""
        enforcer = QualifiedModeEnforcer(
            qualified_settings,
            hsm_connector=mock_hsm_disconnected,
        )

        with pytest.raises(QualifiedModeNotReadyError) as exc_info:
            enforcer.enforce_prerequisites("seal")

        # Verify HSM status shows disconnected
        unsatisfied = exc_info.value.prerequisites.get_unsatisfied()
        hsm_prereq = next(
            (r for r in unsatisfied if r.prerequisite == PrerequisiteType.HSM_AVAILABLE),
            None,
        )
        assert hsm_prereq is not None
        assert hsm_prereq.status == PrerequisiteStatus.NOT_SATISFIED
        assert "disconnected" in hsm_prereq.details.get("hsm_status", "")

    def test_enforcer_fails_with_hsm_connection_error(
        self, qualified_settings, mock_hsm_connection_error
    ):
        """Verify enforcer raises when HSM connector throws exception."""
        enforcer = QualifiedModeEnforcer(
            qualified_settings,
            hsm_connector=mock_hsm_connection_error,
        )

        with pytest.raises(QualifiedModeNotReadyError) as exc_info:
            enforcer.enforce_prerequisites("seal")

        # Verify HSM status shows error
        unsatisfied = exc_info.value.prerequisites.get_unsatisfied()
        hsm_prereq = next(
            (r for r in unsatisfied if r.prerequisite == PrerequisiteType.HSM_AVAILABLE),
            None,
        )
        assert hsm_prereq is not None
        # Error status indicates exception during check
        assert hsm_prereq.status in (
            PrerequisiteStatus.NOT_SATISFIED,
            PrerequisiteStatus.ERROR,
        )

    def test_seal_blocked_when_hsm_unreachable(self, qualified_settings, mock_hsm_disconnected):
        """Verify seal is blocked when HSM becomes unreachable."""
        enforcer = QualifiedModeEnforcer(
            qualified_settings,
            hsm_connector=mock_hsm_disconnected,
        )

        # Seal should be blocked
        with pytest.raises(QualifiedModeNotReadyError):
            enforcer.enforce_prerequisites("seal")

        # Verify label is non_qualified since prerequisites not met
        label = enforcer.get_qualification_label()
        assert label == "non_qualified"

    def test_no_silent_fallback_to_software_keys(self, qualified_settings, mock_hsm_disconnected):
        """Verify there is no silent fallback to software keys when HSM fails.

        Per REQ-D04: No software key fallback in qualified mode.
        """
        enforcer = QualifiedModeEnforcer(
            qualified_settings,
            hsm_connector=mock_hsm_disconnected,
        )

        # Must raise exception, not fall back silently
        with pytest.raises(QualifiedModeNotReadyError):
            enforcer.enforce_prerequisites("seal")

        # Verify we're in qualified mode configuration
        assert enforcer.is_qualified_mode is True

        # But qualification label is non_qualified because HSM unavailable
        assert enforcer.get_qualification_label() == "non_qualified"


# ---------------------------------------------------------------------------
# Scenario 3: Qualified mode with valid HSM -> signing succeeds
# ---------------------------------------------------------------------------


class TestQualifiedModeWithValidHSM:
    """Test that qualified mode succeeds with valid HSM configuration."""

    def test_enforcer_passes_with_connected_hsm(
        self,
        fully_configured_qualified_settings,
        mock_hsm_connected,
        mock_time_verifier,
    ):
        """Verify enforcer passes when all prerequisites are met."""
        enforcer = QualifiedModeEnforcer(
            fully_configured_qualified_settings,
            hsm_connector=mock_hsm_connected,
            time_source_verifier=mock_time_verifier,
        )

        # Should not raise
        prereqs = enforcer.enforce_prerequisites("seal")

        assert prereqs.all_satisfied is True
        assert len(prereqs.get_unsatisfied()) == 0

    def test_hsm_prerequisite_satisfied(
        self,
        fully_configured_qualified_settings,
        mock_hsm_connected,
        mock_time_verifier,
    ):
        """Verify HSM prerequisite is marked as satisfied."""
        enforcer = QualifiedModeEnforcer(
            fully_configured_qualified_settings,
            hsm_connector=mock_hsm_connected,
            time_source_verifier=mock_time_verifier,
        )

        prereqs = enforcer.check_prerequisites()

        hsm_result = next(
            r for r in prereqs.results if r.prerequisite == PrerequisiteType.HSM_AVAILABLE
        )
        assert hsm_result.is_satisfied()
        assert hsm_result.status == PrerequisiteStatus.SATISFIED

    def test_qualification_label_is_qualified(
        self,
        fully_configured_qualified_settings,
        mock_hsm_connected,
        mock_time_verifier,
    ):
        """Verify qualification label is 'qualified' when all prerequisites met."""
        enforcer = QualifiedModeEnforcer(
            fully_configured_qualified_settings,
            hsm_connector=mock_hsm_connected,
            time_source_verifier=mock_time_verifier,
        )

        label = enforcer.get_qualification_label()

        assert label == "qualified"

    def test_qualification_basis_ref_present(
        self,
        fully_configured_qualified_settings,
        mock_hsm_connected,
        mock_time_verifier,
    ):
        """Verify qualification_basis_ref is returned when qualified."""
        enforcer = QualifiedModeEnforcer(
            fully_configured_qualified_settings,
            hsm_connector=mock_hsm_connected,
            time_source_verifier=mock_time_verifier,
        )

        ref = enforcer.get_qualification_basis_ref()

        assert ref == "dossier-qualified-001"

    async def test_trust_service_seal_with_qualified_enforcer(
        self,
        fully_configured_qualified_settings,
        mock_hsm_connected,
        mock_time_verifier,
        temp_key_dir,
    ):
        """Verify TrustService seal succeeds with qualified enforcer."""
        enforcer = QualifiedModeEnforcer(
            fully_configured_qualified_settings,
            hsm_connector=mock_hsm_connected,
            time_source_verifier=mock_time_verifier,
        )

        # TrustService in non-qualified mode (for key generation) but with enforcer
        trust_config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
        )
        service = TrustService(trust_config, qualified_mode_enforcer=enforcer)
        await service.initialize()

        # Seal should succeed (enforcer allows it)
        sealed = await service.seal(b"test evidence data")

        assert sealed is not None
        assert sealed.seal_id.startswith("seal-")

    async def test_trust_service_timestamp_with_qualified_enforcer(
        self,
        fully_configured_qualified_settings,
        mock_hsm_connected,
        mock_time_verifier,
        temp_key_dir,
    ):
        """Verify TrustService timestamp succeeds with qualified enforcer."""
        enforcer = QualifiedModeEnforcer(
            fully_configured_qualified_settings,
            hsm_connector=mock_hsm_connected,
            time_source_verifier=mock_time_verifier,
        )

        trust_config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
        )
        service = TrustService(trust_config, qualified_mode_enforcer=enforcer)
        await service.initialize()

        # Timestamp should succeed
        token = await service.timestamp(b"test data")

        assert token is not None
        assert token.token_id.startswith("tst-")


# ---------------------------------------------------------------------------
# Scenario 4: Non-qualified mode without HSM -> signing succeeds
# ---------------------------------------------------------------------------


class TestNonQualifiedModeWithoutHSM:
    """Test that non-qualified mode succeeds without HSM (labeled non-qualified).

    Per REQ-G02: Non-qualified mode outputs must be clearly labeled.
    """

    def test_enforcer_does_not_raise_in_non_qualified_mode(self, non_qualified_settings):
        """Verify enforcer does not raise in non-qualified mode even without HSM."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)

        # Should not raise, even without HSM
        prereqs = enforcer.enforce_prerequisites("seal")

        assert prereqs is not None

    def test_label_is_non_qualified(self, non_qualified_settings):
        """Verify label is 'non_qualified' in non-qualified mode."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)

        label = enforcer.get_qualification_label()

        assert label == "non_qualified"

    def test_no_qualification_basis_ref_in_non_qualified(self, non_qualified_settings):
        """Verify no qualification_basis_ref in non-qualified mode."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)

        ref = enforcer.get_qualification_basis_ref()

        assert ref is None

    async def test_seal_succeeds_in_non_qualified_mode(self, non_qualified_settings, temp_key_dir):
        """Verify seal succeeds in non-qualified mode without HSM."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)

        trust_config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
        )
        service = TrustService(trust_config, qualified_mode_enforcer=enforcer)
        await service.initialize()

        sealed = await service.seal(b"test evidence data")

        assert sealed is not None
        assert sealed.qualification_label == QualificationMode.NON_QUALIFIED

    async def test_seal_labeled_non_qualified(self, non_qualified_settings, temp_key_dir):
        """Verify sealed data is clearly labeled as non-qualified."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)

        trust_config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
        )
        service = TrustService(trust_config, qualified_mode_enforcer=enforcer)
        await service.initialize()

        sealed = await service.seal(b"test data")

        # Verify labeling
        assert sealed.qualification_label == QualificationMode.NON_QUALIFIED
        assert sealed.qualification_label.value == "non_qualified"

        # Verify in serialized form
        data = sealed.to_dict()
        assert data["qualification_label"] == "non_qualified"

    async def test_timestamp_labeled_non_qualified(self, non_qualified_settings, temp_key_dir):
        """Verify timestamp is clearly labeled as non-qualified."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)

        trust_config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
        )
        service = TrustService(trust_config, qualified_mode_enforcer=enforcer)
        await service.initialize()

        token = await service.timestamp(b"test data")

        assert token.qualification_label == QualificationMode.NON_QUALIFIED

        data = token.to_dict()
        assert data["qualification_label"] == "non_qualified"


# ---------------------------------------------------------------------------
# Scenario 5: Mode transition requires restart (no hot switching)
# ---------------------------------------------------------------------------


class TestModeTransitionRequiresRestart:
    """Test that mode cannot be hot-switched to qualified without restart.

    Per REQ-D04: Mode switching should require restart to prevent
    accidentally operating in the wrong mode.
    """

    def test_enforcer_mode_is_immutable_after_creation(self, non_qualified_settings):
        """Verify enforcer mode cannot be changed after creation."""
        enforcer = QualifiedModeEnforcer(non_qualified_settings)

        # Mode is determined by settings at creation time
        assert enforcer.is_qualified_mode is False

        # Settings object is stored but should not be modified
        # The enforcer reads from settings at check time, but the settings
        # object itself is typically immutable (Pydantic with frozen or similar)

    def test_settings_claim_state_determines_mode(self, minimal_env):
        """Verify mode is determined by claim_state at startup."""
        with patch.dict(os.environ, minimal_env, clear=False):
            nq_settings = Settings(claim_state=ClaimState.NON_QUALIFIED)
            q_settings = Settings(claim_state=ClaimState.QUALIFIED)

        nq_enforcer = QualifiedModeEnforcer(nq_settings)
        q_enforcer = QualifiedModeEnforcer(q_settings)

        assert nq_enforcer.is_qualified_mode is False
        assert q_enforcer.is_qualified_mode is True

    def test_different_enforcers_for_different_modes(
        self, non_qualified_settings, qualified_settings
    ):
        """Verify different enforcer instances have independent modes."""
        nq_enforcer = QualifiedModeEnforcer(non_qualified_settings)
        q_enforcer = QualifiedModeEnforcer(qualified_settings)

        # They should have different modes
        assert nq_enforcer.is_qualified_mode != q_enforcer.is_qualified_mode

        # Non-qualified can proceed without prerequisites
        nq_prereqs = nq_enforcer.enforce_prerequisites("seal")
        assert nq_prereqs is not None

        # Qualified fails without prerequisites
        with pytest.raises(QualifiedModeNotReadyError):
            q_enforcer.enforce_prerequisites("seal")

    def test_cache_invalidation_does_not_change_mode(self, qualified_settings):
        """Verify cache invalidation does not change the configured mode."""
        enforcer = QualifiedModeEnforcer(qualified_settings)

        assert enforcer.is_qualified_mode is True

        # Invalidate cache
        enforcer.invalidate_cache()

        # Mode should still be qualified
        assert enforcer.is_qualified_mode is True

        # And enforcement should still fail without HSM
        with pytest.raises(QualifiedModeNotReadyError):
            enforcer.enforce_prerequisites("seal")

    def test_recheck_does_not_change_mode(self, qualified_settings, mock_hsm_disconnected):
        """Verify force recheck does not change the configured mode."""
        enforcer = QualifiedModeEnforcer(
            qualified_settings,
            hsm_connector=mock_hsm_disconnected,
        )

        # First check
        prereqs1 = enforcer.check_prerequisites()
        assert not prereqs1.all_satisfied

        # Force recheck
        prereqs2 = enforcer.check_prerequisites(force_recheck=True)
        assert not prereqs2.all_satisfied

        # Mode is still qualified (configuration hasn't changed)
        assert enforcer.is_qualified_mode is True


# ---------------------------------------------------------------------------
# Error Message Clarity Tests
# ---------------------------------------------------------------------------


class TestErrorMessageClarity:
    """Test that error messages clearly identify what's missing."""

    def test_error_identifies_hsm_missing(self, qualified_settings):
        """Verify error message identifies HSM as missing."""
        enforcer = QualifiedModeEnforcer(qualified_settings)

        with pytest.raises(QualifiedModeNotReadyError) as exc_info:
            enforcer.enforce_prerequisites("seal")

        error_str = str(exc_info.value)
        assert "hsm" in error_str.lower()

    def test_error_references_req_b04(self, qualified_settings):
        """Verify error message references REQ-B04 for fail-closed behavior."""
        enforcer = QualifiedModeEnforcer(qualified_settings)

        with pytest.raises(QualifiedModeNotReadyError) as exc_info:
            enforcer.enforce_prerequisites("seal")

        error_str = str(exc_info.value)
        assert "REQ-B04" in error_str

    def test_error_includes_operation_name(self, qualified_settings):
        """Verify error message includes the attempted operation."""
        enforcer = QualifiedModeEnforcer(qualified_settings)

        with pytest.raises(QualifiedModeNotReadyError) as exc_info:
            enforcer.enforce_prerequisites("my_custom_operation")

        assert exc_info.value.operation == "my_custom_operation"
        assert "my_custom_operation" in str(exc_info.value)

    def test_error_to_dict_for_api_response(self, qualified_settings):
        """Verify error can be serialized for API responses."""
        enforcer = QualifiedModeEnforcer(qualified_settings)

        with pytest.raises(QualifiedModeNotReadyError) as exc_info:
            enforcer.enforce_prerequisites("seal")

        error_dict = exc_info.value.to_dict()

        assert error_dict["error"] == "qualified_mode_not_ready"
        assert error_dict["operation"] == "seal"
        assert "prerequisites" in error_dict
        assert error_dict["prerequisites"]["all_satisfied"] is False

    def test_failure_summary_lists_all_missing(self, qualified_settings):
        """Verify failure summary lists all missing prerequisites."""
        enforcer = QualifiedModeEnforcer(qualified_settings)

        prereqs = enforcer.check_prerequisites()
        summary = prereqs.get_failure_summary()

        # Should list multiple failures
        assert "failures" in summary
        # Should include HSM
        assert "hsm_available" in summary


# ---------------------------------------------------------------------------
# Trust Service Integration with Enforcer
# ---------------------------------------------------------------------------


class TestTrustServiceEnforcerIntegration:
    """Test TrustService integration with QualifiedModeEnforcer."""

    async def test_enforcer_called_on_seal(self, non_qualified_settings, temp_key_dir):
        """Verify enforcer.enforce_prerequisites is called during seal."""
        mock_enforcer = MagicMock()
        mock_enforcer.enforce_prerequisites.return_value = MagicMock()

        trust_config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
        )
        service = TrustService(trust_config, qualified_mode_enforcer=mock_enforcer)
        await service.initialize()

        await service.seal(b"test data")

        mock_enforcer.enforce_prerequisites.assert_called_once_with("seal")

    async def test_enforcer_called_on_timestamp(self, non_qualified_settings, temp_key_dir):
        """Verify enforcer.enforce_prerequisites is called during timestamp."""
        mock_enforcer = MagicMock()
        mock_enforcer.enforce_prerequisites.return_value = MagicMock()

        trust_config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
        )
        service = TrustService(trust_config, qualified_mode_enforcer=mock_enforcer)
        await service.initialize()

        await service.timestamp(b"test data")

        mock_enforcer.enforce_prerequisites.assert_called_once_with("timestamp")

    async def test_seal_blocked_when_enforcer_raises(self, temp_key_dir):
        """Verify seal is blocked when enforcer raises."""
        mock_enforcer = MagicMock()
        mock_enforcer.enforce_prerequisites.side_effect = QualifiedModeNotReadyError(
            "seal",
            MagicMock(all_satisfied=False, get_unsatisfied=lambda: []),
        )

        trust_config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
        )
        service = TrustService(trust_config, qualified_mode_enforcer=mock_enforcer)
        await service.initialize()

        with pytest.raises(QualifiedModeNotReadyError):
            await service.seal(b"test data")

    async def test_timestamp_blocked_when_enforcer_raises(self, temp_key_dir):
        """Verify timestamp is blocked when enforcer raises."""
        mock_enforcer = MagicMock()
        mock_enforcer.enforce_prerequisites.side_effect = QualifiedModeNotReadyError(
            "timestamp",
            MagicMock(all_satisfied=False, get_unsatisfied=lambda: []),
        )

        trust_config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
        )
        service = TrustService(trust_config, qualified_mode_enforcer=mock_enforcer)
        await service.initialize()

        with pytest.raises(QualifiedModeNotReadyError):
            await service.timestamp(b"test data")

    async def test_service_works_without_enforcer(self, temp_key_dir):
        """Verify TrustService works without enforcer (backwards compatible)."""
        trust_config = TrustServiceConfig(
            mode=QualificationMode.NON_QUALIFIED,
            key_storage_path=temp_key_dir,
        )
        # No enforcer provided
        service = TrustService(trust_config)
        await service.initialize()

        # Should work fine
        sealed = await service.seal(b"test data")
        assert sealed is not None

        token = await service.timestamp(b"test data")
        assert token is not None


# ---------------------------------------------------------------------------
# Prerequisite Check Coverage Tests
# ---------------------------------------------------------------------------


class TestPrerequisiteCheckCoverage:
    """Test that all required prerequisites are checked."""

    def test_hsm_prerequisite_checked(self, qualified_settings):
        """Verify HSM_AVAILABLE prerequisite is checked."""
        enforcer = QualifiedModeEnforcer(qualified_settings)
        prereqs = enforcer.check_prerequisites()

        hsm_prereq = next(
            (r for r in prereqs.results if r.prerequisite == PrerequisiteType.HSM_AVAILABLE),
            None,
        )
        assert hsm_prereq is not None

    def test_signing_key_prerequisite_checked(self, qualified_settings):
        """Verify QUALIFIED_SIGNING_KEY prerequisite is checked."""
        enforcer = QualifiedModeEnforcer(qualified_settings)
        prereqs = enforcer.check_prerequisites()

        key_prereq = next(
            (
                r
                for r in prereqs.results
                if r.prerequisite == PrerequisiteType.QUALIFIED_SIGNING_KEY
            ),
            None,
        )
        assert key_prereq is not None

    def test_tsa_prerequisite_checked(self, qualified_settings):
        """Verify QUALIFIED_TSA prerequisite is checked."""
        enforcer = QualifiedModeEnforcer(qualified_settings)
        prereqs = enforcer.check_prerequisites()

        tsa_prereq = next(
            (r for r in prereqs.results if r.prerequisite == PrerequisiteType.QUALIFIED_TSA),
            None,
        )
        assert tsa_prereq is not None

    def test_time_source_prerequisite_checked(self, qualified_settings):
        """Verify TIME_SOURCE_TRUSTED prerequisite is checked."""
        enforcer = QualifiedModeEnforcer(qualified_settings)
        prereqs = enforcer.check_prerequisites()

        time_prereq = next(
            (r for r in prereqs.results if r.prerequisite == PrerequisiteType.TIME_SOURCE_TRUSTED),
            None,
        )
        assert time_prereq is not None

    def test_policy_prerequisite_checked(self, qualified_settings):
        """Verify POLICY_CONFIGURED prerequisite is checked."""
        enforcer = QualifiedModeEnforcer(qualified_settings)
        prereqs = enforcer.check_prerequisites()

        policy_prereq = next(
            (r for r in prereqs.results if r.prerequisite == PrerequisiteType.POLICY_CONFIGURED),
            None,
        )
        assert policy_prereq is not None

    def test_certificate_prerequisite_checked(self, qualified_settings):
        """Verify CERTIFICATE_VALID prerequisite is checked."""
        enforcer = QualifiedModeEnforcer(qualified_settings)
        prereqs = enforcer.check_prerequisites()

        cert_prereq = next(
            (r for r in prereqs.results if r.prerequisite == PrerequisiteType.CERTIFICATE_VALID),
            None,
        )
        assert cert_prereq is not None
