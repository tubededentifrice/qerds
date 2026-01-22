"""Tests for the email notification service.

Covers: REQ-F02 (notification content), REQ-F03 (pre-acceptance redaction)

Tests verify:
- Emails are sent correctly via SMTP
- Templates comply with CPCE (no sender info)
- Magic link generation and verification
- Evidence metadata generation
- Error handling (bounce detection placeholder)
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from qerds.services.email import (
    TEMPLATE_VERSION,
    BounceType,
    DeliveryStatus,
    EmailDeliveryError,
    EmailNotificationService,
    NotificationChannel,
    NotificationResult,
    NotificationStatus,
    set_token_secret,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_smtp_settings() -> MagicMock:
    """Create mock SMTP settings for testing."""
    settings = MagicMock()
    settings.host = "localhost"
    settings.port = 1025
    settings.username = None
    settings.password = None
    settings.use_tls = False
    settings.use_ssl = False
    settings.from_address = "noreply@qerds.test"
    settings.from_name = "QERDS Test"
    settings.timeout = 30
    return settings


@pytest.fixture
def mock_session() -> MagicMock:
    """Create mock async database session."""
    return MagicMock()


@pytest.fixture
def email_service(
    mock_session: MagicMock, mock_smtp_settings: MagicMock
) -> EmailNotificationService:
    """Create email service instance for testing."""
    return EmailNotificationService(
        session=mock_session,
        smtp_settings=mock_smtp_settings,
        base_url="https://qerds.test",
        provider_name="QERDS Test",
    )


@pytest.fixture
def sample_delivery_id() -> uuid.UUID:
    """Create a sample delivery UUID."""
    return uuid.UUID("12345678-1234-5678-1234-567812345678")


@pytest.fixture
def sample_recipient_email() -> str:
    """Create a sample recipient email."""
    return "recipient@example.com"


@pytest.fixture
def sample_deadline() -> datetime:
    """Create a sample deadline timestamp."""
    return datetime(2026, 2, 6, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Token Generation and Verification Tests
# ---------------------------------------------------------------------------


class TestTokenGeneration:
    """Tests for magic link token generation and verification."""

    def test_generate_magic_link_creates_valid_url(
        self,
        email_service: EmailNotificationService,
        sample_delivery_id: uuid.UUID,
        sample_recipient_email: str,
    ) -> None:
        """Magic link should contain base URL and token parameters."""
        magic_link = email_service.generate_magic_link(sample_delivery_id, sample_recipient_email)

        assert magic_link.startswith("https://qerds.test/pickup?")
        assert "token=" in magic_link
        assert "ref=QERDS-" in magic_link

    def test_generate_claim_token_is_deterministic_format(
        self,
        email_service: EmailNotificationService,
        sample_delivery_id: uuid.UUID,
        sample_recipient_email: str,
    ) -> None:
        """Token should have format: nonce.signature."""
        token = email_service._generate_claim_token(sample_delivery_id, sample_recipient_email)

        parts = token.split(".")
        assert len(parts) == 2
        # Nonce is base64 url-safe (16 bytes -> ~22 chars)
        assert len(parts[0]) >= 16
        # Signature is truncated hex (32 chars)
        assert len(parts[1]) == 32

    def test_verify_claim_token_valid(
        self,
        email_service: EmailNotificationService,
        sample_delivery_id: uuid.UUID,
        sample_recipient_email: str,
    ) -> None:
        """Valid token should verify successfully."""
        token = email_service._generate_claim_token(sample_delivery_id, sample_recipient_email)

        is_valid = email_service.verify_claim_token(
            token, sample_delivery_id, sample_recipient_email
        )

        assert is_valid is True

    def test_verify_claim_token_invalid_delivery_id(
        self,
        email_service: EmailNotificationService,
        sample_delivery_id: uuid.UUID,
        sample_recipient_email: str,
    ) -> None:
        """Token should not verify with wrong delivery ID."""
        token = email_service._generate_claim_token(sample_delivery_id, sample_recipient_email)
        wrong_delivery_id = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

        is_valid = email_service.verify_claim_token(
            token, wrong_delivery_id, sample_recipient_email
        )

        assert is_valid is False

    def test_verify_claim_token_invalid_email(
        self,
        email_service: EmailNotificationService,
        sample_delivery_id: uuid.UUID,
        sample_recipient_email: str,
    ) -> None:
        """Token should not verify with wrong email."""
        token = email_service._generate_claim_token(sample_delivery_id, sample_recipient_email)
        wrong_email = "wrong@example.com"

        is_valid = email_service.verify_claim_token(token, sample_delivery_id, wrong_email)

        assert is_valid is False

    def test_verify_claim_token_malformed(
        self,
        email_service: EmailNotificationService,
        sample_delivery_id: uuid.UUID,
        sample_recipient_email: str,
    ) -> None:
        """Malformed token should not verify."""
        malformed_tokens = [
            "not_a_valid_token",
            "missing.too.many.parts",
            "",
            "nonce.",
            ".signature",
        ]

        for token in malformed_tokens:
            is_valid = email_service.verify_claim_token(
                token, sample_delivery_id, sample_recipient_email
            )
            assert is_valid is False, f"Token '{token}' should not verify"

    def test_set_token_secret_validates_length(self) -> None:
        """Token secret must be exactly 32 bytes."""
        with pytest.raises(ValueError, match="32 bytes"):
            set_token_secret(b"too_short")

        with pytest.raises(ValueError, match="32 bytes"):
            set_token_secret(b"this_secret_is_way_too_long_for_the_requirement")

    def test_set_token_secret_accepts_valid_length(self) -> None:
        """Token secret should accept 32-byte value."""
        valid_secret = b"0123456789abcdef0123456789abcdef"
        set_token_secret(valid_secret)
        # Should not raise


# ---------------------------------------------------------------------------
# Email Sending Tests
# ---------------------------------------------------------------------------


class TestSendDeliveryNotification:
    """Tests for send_delivery_notification method."""

    @patch("qerds.services.email.EmailNotificationService._send_email")
    async def test_send_notification_success(
        self,
        mock_send: MagicMock,
        email_service: EmailNotificationService,
        sample_delivery_id: uuid.UUID,
        sample_recipient_email: str,
    ) -> None:
        """Successful notification should return success result."""
        mock_send.return_value = "<test-message-id@qerds.test>"

        result = await email_service.send_delivery_notification(
            delivery_id=sample_delivery_id,
            recipient_email=sample_recipient_email,
            lang="fr",
        )

        assert result.success is True
        assert result.status == NotificationStatus.SENT
        assert result.message_id == "<test-message-id@qerds.test>"
        assert result.template_version == TEMPLATE_VERSION
        assert result.error is None
        assert result.sent_at is not None

    @patch("qerds.services.email.EmailNotificationService._send_email")
    async def test_send_notification_failure(
        self,
        mock_send: MagicMock,
        email_service: EmailNotificationService,
        sample_delivery_id: uuid.UUID,
        sample_recipient_email: str,
    ) -> None:
        """Failed notification should return failure result with error."""
        mock_send.side_effect = EmailDeliveryError("SMTP connection failed")

        result = await email_service.send_delivery_notification(
            delivery_id=sample_delivery_id,
            recipient_email=sample_recipient_email,
            lang="fr",
        )

        assert result.success is False
        assert result.status == NotificationStatus.FAILED
        assert result.message_id is None
        assert "SMTP connection failed" in result.error
        assert result.sent_at is None

    @patch("qerds.services.email.EmailNotificationService._send_email")
    async def test_send_notification_hashes_recipient(
        self,
        mock_send: MagicMock,
        email_service: EmailNotificationService,
        sample_delivery_id: uuid.UUID,
        sample_recipient_email: str,
    ) -> None:
        """Recipient email should be hashed for evidence."""
        mock_send.return_value = "<test@qerds.test>"

        result = await email_service.send_delivery_notification(
            delivery_id=sample_delivery_id,
            recipient_email=sample_recipient_email,
            lang="fr",
        )

        # Hash should match SHA-256 of lowercased email
        expected_hash = hashlib.sha256(sample_recipient_email.lower().encode()).hexdigest()
        assert result.recipient_hash == expected_hash

    @patch("qerds.services.email.EmailNotificationService._send_email")
    async def test_send_notification_english_template(
        self,
        mock_send: MagicMock,
        email_service: EmailNotificationService,
        sample_delivery_id: uuid.UUID,
        sample_recipient_email: str,
    ) -> None:
        """English notification should use English template."""
        mock_send.return_value = "<test@qerds.test>"

        result = await email_service.send_delivery_notification(
            delivery_id=sample_delivery_id,
            recipient_email=sample_recipient_email,
            lang="en",
        )

        assert result.success is True
        # Verify _send_email was called (template rendering worked)
        mock_send.assert_called_once()


class TestSendReminder:
    """Tests for send_reminder method."""

    @patch("qerds.services.email.EmailNotificationService._send_email")
    async def test_send_reminder_success(
        self,
        mock_send: MagicMock,
        email_service: EmailNotificationService,
        sample_delivery_id: uuid.UUID,
        sample_recipient_email: str,
    ) -> None:
        """Successful reminder should return success result."""
        mock_send.return_value = "<reminder@qerds.test>"

        result = await email_service.send_reminder(
            delivery_id=sample_delivery_id,
            recipient_email=sample_recipient_email,
            lang="fr",
            days_remaining=5,
        )

        assert result.success is True
        assert result.status == NotificationStatus.SENT
        assert result.message_id == "<reminder@qerds.test>"

    @patch("qerds.services.email.EmailNotificationService._send_email")
    async def test_send_reminder_with_urgency(
        self,
        mock_send: MagicMock,
        email_service: EmailNotificationService,
        sample_delivery_id: uuid.UUID,
        sample_recipient_email: str,
    ) -> None:
        """Reminder with 1 day remaining should work."""
        mock_send.return_value = "<urgent@qerds.test>"

        result = await email_service.send_reminder(
            delivery_id=sample_delivery_id,
            recipient_email=sample_recipient_email,
            lang="fr",
            days_remaining=1,
        )

        assert result.success is True


# ---------------------------------------------------------------------------
# Template Rendering Tests
# ---------------------------------------------------------------------------


class TestTemplateRendering:
    """Tests for email template rendering."""

    def test_render_notification_template_french(
        self,
        email_service: EmailNotificationService,
        sample_deadline: datetime,
    ) -> None:
        """French notification template should render correctly."""
        subject, html, text = email_service._render_notification_template(
            lang="fr",
            delivery_ref="QERDS-12345678",
            deadline=sample_deadline,
            magic_link="https://qerds.test/pickup?token=test",
        )

        # Subject should be in French
        assert "Lettre recommandee electronique" in subject
        assert "QERDS-12345678" in subject

        # HTML should contain required elements
        assert "QERDS Test" in html  # Provider name
        assert "QERDS-12345678" in html  # Reference
        assert "https://qerds.test/pickup?token=test" in html  # Magic link
        assert "06/02/2026" in html  # Formatted deadline (dd/mm/yyyy)

        # Text should contain required elements
        assert "QERDS-12345678" in text
        assert "https://qerds.test/pickup?token=test" in text

    def test_render_notification_template_english(
        self,
        email_service: EmailNotificationService,
        sample_deadline: datetime,
    ) -> None:
        """English notification template should render correctly."""
        subject, html, _text = email_service._render_notification_template(
            lang="en",
            delivery_ref="QERDS-12345678",
            deadline=sample_deadline,
            magic_link="https://qerds.test/pickup?token=test",
        )

        # Subject should be in English
        assert "Electronic registered delivery" in subject
        assert "QERDS-12345678" in subject

        # HTML should contain English text
        assert "Hello," in html
        assert "2026-02-06" in html  # English date format

    def test_render_reminder_template_french(
        self,
        email_service: EmailNotificationService,
        sample_deadline: datetime,
    ) -> None:
        """French reminder template should render correctly."""
        subject, html, _text = email_service._render_reminder_template(
            lang="fr",
            delivery_ref="QERDS-12345678",
            deadline=sample_deadline,
            days_remaining=5,
            magic_link="https://qerds.test/pickup?token=test",
        )

        # Subject should indicate reminder
        assert "RAPPEL" in subject
        assert "5 jours restants" in subject

        # HTML should show urgency
        assert "5 jour" in html  # days remaining
        assert "RAPPEL" in html

    def test_notification_does_not_contain_sender_info(
        self,
        email_service: EmailNotificationService,
        sample_deadline: datetime,
    ) -> None:
        """Per REQ-F03, notification should NOT contain sender identity."""
        subject, html, text = email_service._render_notification_template(
            lang="fr",
            delivery_ref="QERDS-12345678",
            deadline=sample_deadline,
            magic_link="https://qerds.test/pickup?token=test",
        )

        # These strings should NOT appear (sample sender info)
        forbidden_strings = [
            "Jean Dupont",  # Sender name
            "expediteur@example.com",  # Sender email
            "ACME Corporation",  # Sender company
        ]

        for forbidden in forbidden_strings:
            assert forbidden not in html, f"Sender info '{forbidden}' found in HTML"
            assert forbidden not in text, f"Sender info '{forbidden}' found in text"
            assert forbidden not in subject, f"Sender info '{forbidden}' found in subject"

    def test_notification_contains_required_cpce_elements(
        self,
        email_service: EmailNotificationService,
        sample_deadline: datetime,
    ) -> None:
        """Per REQ-F02, notification MUST contain specific elements."""
        _subject, html, _text = email_service._render_notification_template(
            lang="fr",
            delivery_ref="QERDS-12345678",
            deadline=sample_deadline,
            magic_link="https://qerds.test/pickup?token=test",
        )

        # Provider identity
        assert "QERDS Test" in html

        # Delivery reference
        assert "QERDS-12345678" in html

        # Legal nature mention
        assert "Lettre Recommandee Electronique" in html or "LRE" in html

        # Deadline information
        assert "2026" in html  # Year in deadline


# ---------------------------------------------------------------------------
# Helper Method Tests
# ---------------------------------------------------------------------------


class TestHelperMethods:
    """Tests for helper methods."""

    def test_hash_email_is_consistent(self, email_service: EmailNotificationService) -> None:
        """Email hashing should be consistent and case-insensitive."""
        hash1 = email_service._hash_email("Test@Example.COM")
        hash2 = email_service._hash_email("test@example.com")
        hash3 = email_service._hash_email("  TEST@EXAMPLE.COM  ")

        assert hash1 == hash2
        assert hash2 == hash3
        assert len(hash1) == 64  # SHA-256 hex

    def test_format_delivery_ref(self, email_service: EmailNotificationService) -> None:
        """Delivery reference should be formatted consistently."""
        delivery_id = uuid.UUID("12345678-1234-5678-1234-567812345678")

        ref = email_service._format_delivery_ref(delivery_id)

        assert ref == "QERDS-12345678"
        assert ref.startswith("QERDS-")
        assert len(ref) == 14  # QERDS- + 8 chars

    def test_format_date_french(self, email_service: EmailNotificationService) -> None:
        """French date format should be dd/mm/yyyy a HH:MM."""
        dt = datetime(2026, 2, 6, 14, 30, 0, tzinfo=UTC)

        formatted = email_service._format_date(dt, "fr")

        assert formatted == "06/02/2026 a 14:30"

    def test_format_date_english(self, email_service: EmailNotificationService) -> None:
        """English date format should be yyyy-mm-dd at HH:MM."""
        dt = datetime(2026, 2, 6, 14, 30, 0, tzinfo=UTC)

        formatted = email_service._format_date(dt, "en")

        assert formatted == "2026-02-06 at 14:30"

    def test_get_subject_notification_french(self, email_service: EmailNotificationService) -> None:
        """French notification subject should be properly formatted."""
        subject = email_service._get_subject("fr", "notification", "QERDS-12345678")

        assert "[QERDS]" in subject
        assert "Lettre recommandee electronique" in subject
        assert "QERDS-12345678" in subject

    def test_get_subject_reminder_with_days(self, email_service: EmailNotificationService) -> None:
        """Reminder subject should include days remaining."""
        subject = email_service._get_subject("fr", "reminder", "QERDS-12345678", days_remaining=3)

        assert "[RAPPEL]" in subject
        assert "3 jours restants" in subject
        assert "QERDS-12345678" in subject


# ---------------------------------------------------------------------------
# Evidence Metadata Tests
# ---------------------------------------------------------------------------


class TestEvidenceMetadata:
    """Tests for evidence metadata generation."""

    def test_get_evidence_metadata_success(self, email_service: EmailNotificationService) -> None:
        """Evidence metadata should contain required fields for EVT_NOTIFICATION_SENT."""
        result = NotificationResult(
            success=True,
            message_id="<test@qerds.test>",
            status=NotificationStatus.SENT,
            recipient_hash="abc123" * 10 + "abcd",
            template_version="2026.1.0",
            error=None,
            sent_at=datetime(2026, 1, 22, 12, 0, 0, tzinfo=UTC),
        )

        metadata = email_service.get_evidence_metadata(result)

        assert metadata["channel"] == "email"
        assert metadata["template_version"] == "2026.1.0"
        assert metadata["recipient_hash"] == "abc123" * 10 + "abcd"
        assert metadata["status"] == "sent"
        assert metadata["sent_at"] == "2026-01-22T12:00:00+00:00"
        assert metadata["error"] is None
        # Message ID should be hashed, not raw
        assert metadata["message_id_hash"] is not None
        assert metadata["message_id_hash"] != "<test@qerds.test>"

    def test_get_evidence_metadata_failure(self, email_service: EmailNotificationService) -> None:
        """Evidence metadata should include error for failed notifications."""
        result = NotificationResult(
            success=False,
            message_id=None,
            status=NotificationStatus.FAILED,
            recipient_hash="abc123" * 10 + "abcd",
            template_version="2026.1.0",
            error="SMTP connection refused",
            sent_at=None,
        )

        metadata = email_service.get_evidence_metadata(result)

        assert metadata["status"] == "failed"
        assert metadata["error"] == "SMTP connection refused"
        assert metadata["sent_at"] is None
        assert metadata["message_id_hash"] is None


# ---------------------------------------------------------------------------
# Delivery Status Tests
# ---------------------------------------------------------------------------


class TestDeliveryStatus:
    """Tests for delivery status checking."""

    def test_check_delivery_status_placeholder(
        self,
        email_service: EmailNotificationService,
    ) -> None:
        """Delivery status check should return pending (placeholder)."""
        status = email_service.check_delivery_status("<test@qerds.test>")

        assert isinstance(status, DeliveryStatus)
        assert status.message_id == "<test@qerds.test>"
        assert status.status == NotificationStatus.PENDING
        assert status.bounce_type is None
        assert status.checked_at is not None


# ---------------------------------------------------------------------------
# SMTP Integration Tests (with mocking)
# ---------------------------------------------------------------------------


class TestSMTPIntegration:
    """Tests for SMTP sending functionality."""

    @patch("qerds.services.email.smtplib.SMTP")
    def test_send_email_plain_smtp(
        self,
        mock_smtp_class: MagicMock,
        email_service: EmailNotificationService,
    ) -> None:
        """Plain SMTP should work without TLS."""
        mock_smtp = MagicMock()
        mock_smtp_class.return_value = mock_smtp

        message_id = email_service._send_email(
            to_email="test@example.com",
            subject="Test Subject",
            html_body="<p>HTML body</p>",
            text_body="Text body",
        )

        # SMTP should be created with correct parameters
        mock_smtp_class.assert_called_once_with(
            "localhost",
            1025,
            timeout=30,
        )

        # No STARTTLS since use_tls is False
        mock_smtp.starttls.assert_not_called()

        # Email should be sent
        mock_smtp.sendmail.assert_called_once()
        mock_smtp.quit.assert_called_once()

        # Message ID should be returned
        assert message_id.startswith("<")
        assert message_id.endswith("@qerds.test>")

    @patch("qerds.services.email.smtplib.SMTP")
    def test_send_email_with_starttls(
        self,
        mock_smtp_class: MagicMock,
        mock_session: MagicMock,
        mock_smtp_settings: MagicMock,
    ) -> None:
        """SMTP with STARTTLS should call starttls()."""
        mock_smtp_settings.use_tls = True
        mock_smtp = MagicMock()
        mock_smtp_class.return_value = mock_smtp

        service = EmailNotificationService(
            session=mock_session,
            smtp_settings=mock_smtp_settings,
            base_url="https://qerds.test",
        )

        service._send_email(
            to_email="test@example.com",
            subject="Test",
            html_body="<p>HTML</p>",
            text_body="Text",
        )

        # STARTTLS should be called
        mock_smtp.starttls.assert_called_once()

    @patch("qerds.services.email.smtplib.SMTP_SSL")
    def test_send_email_with_ssl(
        self,
        mock_smtp_ssl_class: MagicMock,
        mock_session: MagicMock,
        mock_smtp_settings: MagicMock,
    ) -> None:
        """SMTP with SSL should use SMTP_SSL."""
        mock_smtp_settings.use_ssl = True
        mock_smtp = MagicMock()
        mock_smtp_ssl_class.return_value = mock_smtp

        service = EmailNotificationService(
            session=mock_session,
            smtp_settings=mock_smtp_settings,
            base_url="https://qerds.test",
        )

        service._send_email(
            to_email="test@example.com",
            subject="Test",
            html_body="<p>HTML</p>",
            text_body="Text",
        )

        # SMTP_SSL should be used
        mock_smtp_ssl_class.assert_called_once()

    @patch("qerds.services.email.smtplib.SMTP")
    def test_send_email_with_auth(
        self,
        mock_smtp_class: MagicMock,
        mock_session: MagicMock,
        mock_smtp_settings: MagicMock,
    ) -> None:
        """SMTP with credentials should authenticate."""
        mock_smtp_settings.username = "user"
        mock_smtp_settings.password = MagicMock()
        mock_smtp_settings.password.get_secret_value.return_value = "secret"

        mock_smtp = MagicMock()
        mock_smtp_class.return_value = mock_smtp

        service = EmailNotificationService(
            session=mock_session,
            smtp_settings=mock_smtp_settings,
            base_url="https://qerds.test",
        )

        service._send_email(
            to_email="test@example.com",
            subject="Test",
            html_body="<p>HTML</p>",
            text_body="Text",
        )

        # Login should be called with credentials
        mock_smtp.login.assert_called_once_with("user", "secret")

    @patch("qerds.services.email.smtplib.SMTP")
    def test_send_email_smtp_error(
        self,
        mock_smtp_class: MagicMock,
        email_service: EmailNotificationService,
    ) -> None:
        """SMTP error should raise EmailDeliveryError."""
        import smtplib

        mock_smtp = MagicMock()
        mock_smtp.sendmail.side_effect = smtplib.SMTPException("Connection refused")
        mock_smtp_class.return_value = mock_smtp

        with pytest.raises(EmailDeliveryError, match="SMTP error"):
            email_service._send_email(
                to_email="test@example.com",
                subject="Test",
                html_body="<p>HTML</p>",
                text_body="Text",
            )

    @patch("qerds.services.email.smtplib.SMTP")
    def test_send_email_connection_error(
        self,
        mock_smtp_class: MagicMock,
        email_service: EmailNotificationService,
    ) -> None:
        """Connection error should raise EmailDeliveryError."""
        mock_smtp_class.side_effect = OSError("Network unreachable")

        with pytest.raises(EmailDeliveryError, match="Connection error"):
            email_service._send_email(
                to_email="test@example.com",
                subject="Test",
                html_body="<p>HTML</p>",
                text_body="Text",
            )


# ---------------------------------------------------------------------------
# Data Classes Tests
# ---------------------------------------------------------------------------


class TestDataClasses:
    """Tests for data class definitions."""

    def test_notification_result_frozen(self) -> None:
        """NotificationResult should be immutable."""
        result = NotificationResult(
            success=True,
            message_id="<test>",
            status=NotificationStatus.SENT,
            recipient_hash="abc",
            template_version="1.0",
            error=None,
            sent_at=datetime.now(UTC),
        )

        with pytest.raises(AttributeError):
            result.success = False  # type: ignore

    def test_delivery_status_frozen(self) -> None:
        """DeliveryStatus should be immutable."""
        status = DeliveryStatus(
            message_id="<test>",
            status=NotificationStatus.SENT,
            bounce_type=None,
            bounce_reason=None,
            checked_at=datetime.now(UTC),
        )

        with pytest.raises(AttributeError):
            status.status = NotificationStatus.FAILED  # type: ignore

    def test_notification_channel_values(self) -> None:
        """NotificationChannel enum should have expected values."""
        assert NotificationChannel.EMAIL.value == "email"

    def test_notification_status_values(self) -> None:
        """NotificationStatus enum should have expected values."""
        assert NotificationStatus.SENT.value == "sent"
        assert NotificationStatus.FAILED.value == "failed"
        assert NotificationStatus.BOUNCED.value == "bounced"
        assert NotificationStatus.PENDING.value == "pending"

    def test_bounce_type_values(self) -> None:
        """BounceType enum should have expected values."""
        assert BounceType.HARD.value == "hard"
        assert BounceType.SOFT.value == "soft"
        assert BounceType.SPAM.value == "spam"
