"""Tests for recipient pickup portal HTML views (REQ-F03).

Covers:
- Pickup portal template structure
- CSS class patterns
- i18n translation keys
- Router helper functions

Note: Full integration tests for pickup views require database access
and should be run via Docker (docker compose exec qerds-api pytest).
"""

from __future__ import annotations

from qerds.api.templates import TEMPLATES_DIR


# ---------------------------------------------------------------------------
# Template Structure Tests
# ---------------------------------------------------------------------------
class TestPickupTemplateStructure:
    """Tests for pickup template file structure."""

    def test_pickup_template_exists(self) -> None:
        """Verify pickup.html template exists."""
        assert (TEMPLATES_DIR / "recipient" / "pickup.html").exists()

    def test_pickup_template_extends_base(self) -> None:
        """Verify pickup.html extends base template."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        assert '{% extends "base.html" %}' in content

    def test_pickup_template_has_title_block(self) -> None:
        """Verify pickup.html sets the title block."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        assert "{% block title %}" in content

    def test_pickup_template_has_main_block(self) -> None:
        """Verify pickup.html has main content block."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        assert "{% block main %}" in content

    def test_pickup_template_has_scripts_block(self) -> None:
        """Verify pickup.html has scripts block for countdown JS."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        assert "{% block scripts %}" in content


# ---------------------------------------------------------------------------
# Template Content Tests (REQ-F03 Compliance)
# ---------------------------------------------------------------------------
class TestPickupTemplateContent:
    """Tests for pickup template content requirements."""

    def test_pickup_has_hero_section(self) -> None:
        """Verify pickup template has hero section."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        assert "pickup-hero" in content

    def test_pickup_has_card_structure(self) -> None:
        """Verify pickup template has card structure."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        assert "pickup-card" in content
        assert "pickup-card-header" in content
        assert "pickup-card-body" in content
        assert "pickup-card-footer" in content

    def test_pickup_has_delivery_info_list(self) -> None:
        """Verify pickup template has delivery info section."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        assert "delivery-info-list" in content

    def test_pickup_has_sender_redacted_section(self) -> None:
        """Verify pickup template hides sender identity (REQ-F03)."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        assert "redacted-info" in content
        # Should reference sender_hidden translation key
        assert "sender_hidden" in content

    def test_pickup_has_deadline_countdown(self) -> None:
        """Verify pickup template has deadline countdown element."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        assert "deadline-countdown" in content
        # Should have data attribute for JavaScript
        assert "data-deadline" in content

    def test_pickup_has_auth_wall_for_unauthenticated(self) -> None:
        """Verify pickup template shows auth wall when not authenticated."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        assert "{% if not user %}" in content
        # Should link to pickup auth endpoint
        assert "/auth" in content

    def test_pickup_has_accept_refuse_buttons(self) -> None:
        """Verify pickup template has accept/refuse buttons for authenticated users."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        assert "accept" in content.lower()
        assert "refuse" in content.lower()
        # Should have form actions for accept/refuse
        assert "/accept" in content
        assert "/refuse" in content

    def test_pickup_has_notice_section(self) -> None:
        """Verify pickup template has important notice section."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        assert "pickup-notice" in content

    def test_pickup_has_compliance_note(self) -> None:
        """Verify pickup template references eIDAS compliance."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        assert "eidas_compliance_note" in content

    def test_pickup_has_content_metadata_display(self) -> None:
        """Verify pickup template displays content metadata."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        # Should show attachment info
        assert "attachment" in content.lower() or "content_objects" in content


# ---------------------------------------------------------------------------
# JavaScript Tests
# ---------------------------------------------------------------------------
class TestPickupJavaScript:
    """Tests for pickup page JavaScript functionality."""

    def test_pickup_has_countdown_function(self) -> None:
        """Verify pickup template has countdown JavaScript."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        assert "updateCountdown" in content

    def test_pickup_has_form_submission_handling(self) -> None:
        """Verify pickup template has form submission handling."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        # Should handle form submission with loading states
        assert "pickup-action-form" in content
        assert "addEventListener" in content


# ---------------------------------------------------------------------------
# i18n Tests
# ---------------------------------------------------------------------------
class TestPickupI18nKeys:
    """Tests for pickup template i18n keys."""

    def test_pickup_uses_i18n_function(self) -> None:
        """Verify pickup template uses _() translation function."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        assert "{{ _(" in content

    def test_pickup_has_required_translation_keys(self) -> None:
        """Verify pickup template uses expected translation keys."""
        template_path = TEMPLATES_DIR / "recipient" / "pickup.html"
        content = template_path.read_text()
        # Check for key pickup-related translation keys
        expected_keys = [
            "pickup.title",
            "pickup.received_title",
            "delivery.sender",
            "delivery.subject",
            "delivery.attachment",
        ]
        for key in expected_keys:
            assert key in content, f"Missing translation key: {key}"


# ---------------------------------------------------------------------------
# Router Helper Function Tests
# ---------------------------------------------------------------------------
class TestPickupRouterHelpers:
    """Tests for pickup router helper functions."""

    def test_format_file_size_bytes(self) -> None:
        """Test file size formatting for bytes."""
        from qerds.api.routers.pickup import _format_file_size

        assert _format_file_size(500) == "500 o"

    def test_format_file_size_kilobytes(self) -> None:
        """Test file size formatting for kilobytes."""
        from qerds.api.routers.pickup import _format_file_size

        result = _format_file_size(2048)
        assert "Ko" in result
        assert "2.0" in result

    def test_format_file_size_megabytes(self) -> None:
        """Test file size formatting for megabytes."""
        from qerds.api.routers.pickup import _format_file_size

        result = _format_file_size(1048576)  # 1 MB
        assert "Mo" in result
        assert "1.00" in result

    def test_format_file_size_large_megabytes(self) -> None:
        """Test file size formatting for larger files."""
        from qerds.api.routers.pickup import _format_file_size

        result = _format_file_size(5242880)  # 5 MB
        assert "Mo" in result
        assert "5.00" in result

    def test_format_file_size_zero(self) -> None:
        """Test file size formatting for zero bytes."""
        from qerds.api.routers.pickup import _format_file_size

        assert _format_file_size(0) == "0 o"
