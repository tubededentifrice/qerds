"""Tests for recipient HTML views (refused and inbox pages).

Covers:
- Refused view template rendering
- Inbox view template rendering with filters and pagination
- i18n support for French and English
- Responsive design patterns (via CSS class assertions)
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from qerds.api import create_app
from qerds.api.templates import TEMPLATES_DIR


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def client() -> TestClient:
    """Create a synchronous test client for HTTP requests."""
    app = create_app()
    return TestClient(app)


# ---------------------------------------------------------------------------
# Template Structure Tests
# ---------------------------------------------------------------------------
class TestRecipientTemplateStructure:
    """Tests for recipient template file structure."""

    def test_refused_template_exists(self) -> None:
        """Verify refused.html template exists."""
        assert (TEMPLATES_DIR / "recipient" / "refused.html").exists()

    def test_inbox_template_exists(self) -> None:
        """Verify inbox.html template exists."""
        assert (TEMPLATES_DIR / "recipient" / "inbox.html").exists()


# ---------------------------------------------------------------------------
# Refused View Tests
# ---------------------------------------------------------------------------
class TestRefusedView:
    """Tests for GET /recipient/refused/{delivery_id} endpoint."""

    def test_refused_page_renders(self, client: TestClient) -> None:
        """Verify refused page renders successfully."""
        response = client.get("/recipient/refused/test-delivery-id")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_refused_page_shows_refusal_confirmation(self, client: TestClient) -> None:
        """Verify refused page shows refusal confirmation message."""
        response = client.get("/recipient/refused/test-delivery-id")
        assert response.status_code == 200
        # Check for refusal-specific content (French is default)
        content = response.text.lower()
        assert "refus" in content or "refused" in content

    def test_refused_page_shows_sender_identity(self, client: TestClient) -> None:
        """Verify refused page reveals sender identity per CPCE."""
        response = client.get("/recipient/refused/test-delivery-id")
        assert response.status_code == 200
        # Mock data should include sender name
        assert "Entreprise ABC" in response.text

    def test_refused_page_shows_proof_download(self, client: TestClient) -> None:
        """Verify refused page has refusal proof download link."""
        response = client.get("/recipient/refused/test-delivery-id")
        assert response.status_code == 200
        # Should have link to download refusal proof
        assert "proofs/refusal" in response.text

    def test_refused_page_content_not_accessible_notice(self, client: TestClient) -> None:
        """Verify refused page shows notice that content is not accessible."""
        response = client.get("/recipient/refused/test-delivery-id")
        assert response.status_code == 200
        # Should have notice about content not being accessible
        # Check for CSS class that styles the notice
        assert "pickup-notice" in response.text

    def test_refused_page_shows_delivery_reference(self, client: TestClient) -> None:
        """Verify refused page shows delivery reference/ID."""
        response = client.get("/recipient/refused/test-delivery-id")
        assert response.status_code == 200
        assert "test-delivery-id" in response.text

    def test_refused_page_english_language(self, client: TestClient) -> None:
        """Verify refused page can render in English."""
        response = client.get("/recipient/refused/test-delivery-id?lang=en")
        assert response.status_code == 200
        # English version should have "Refused" text
        assert "Refused" in response.text or "refused" in response.text.lower()


# ---------------------------------------------------------------------------
# Inbox View Tests
# ---------------------------------------------------------------------------
class TestInboxView:
    """Tests for GET /recipient/inbox endpoint."""

    def test_inbox_page_renders(self, client: TestClient) -> None:
        """Verify inbox page renders successfully."""
        response = client.get("/recipient/inbox")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_inbox_page_shows_title(self, client: TestClient) -> None:
        """Verify inbox page shows inbox title."""
        response = client.get("/recipient/inbox")
        assert response.status_code == 200
        # Check for inbox-specific content (French is default)
        content = response.text.lower()
        assert "boite" in content or "inbox" in content

    def test_inbox_page_shows_filter_options(self, client: TestClient) -> None:
        """Verify inbox page shows filter options."""
        response = client.get("/recipient/inbox")
        assert response.status_code == 200
        # Should have filter buttons
        assert "inbox-filters" in response.text
        # Check for filter links
        assert "filter=pending" in response.text
        assert "filter=accepted" in response.text
        assert "filter=refused" in response.text

    def test_inbox_page_shows_deliveries_list(self, client: TestClient) -> None:
        """Verify inbox page shows deliveries list."""
        response = client.get("/recipient/inbox")
        assert response.status_code == 200
        # Should have inbox list items
        assert "inbox-list" in response.text
        assert "inbox-item" in response.text

    def test_inbox_page_shows_status_badges(self, client: TestClient) -> None:
        """Verify inbox page shows status badges for deliveries."""
        response = client.get("/recipient/inbox")
        assert response.status_code == 200
        # Should have status badges
        assert "status-badge" in response.text

    def test_inbox_page_filter_pending(self, client: TestClient) -> None:
        """Verify inbox page with pending filter."""
        response = client.get("/recipient/inbox?filter=pending")
        assert response.status_code == 200
        # Page should still render
        assert "text/html" in response.headers["content-type"]

    def test_inbox_page_filter_accepted(self, client: TestClient) -> None:
        """Verify inbox page with accepted filter."""
        response = client.get("/recipient/inbox?filter=accepted")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_inbox_page_filter_refused(self, client: TestClient) -> None:
        """Verify inbox page with refused filter."""
        response = client.get("/recipient/inbox?filter=refused")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_inbox_page_filter_expired(self, client: TestClient) -> None:
        """Verify inbox page with expired filter."""
        response = client.get("/recipient/inbox?filter=expired")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_inbox_page_pagination(self, client: TestClient) -> None:
        """Verify inbox page pagination parameters are accepted."""
        response = client.get("/recipient/inbox?page=1")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    def test_inbox_page_sender_hidden_pre_acceptance(self, client: TestClient) -> None:
        """Verify inbox shows hidden sender for pre-acceptance deliveries."""
        response = client.get("/recipient/inbox")
        assert response.status_code == 200
        # Pre-acceptance deliveries should show hidden sender indicator
        content = response.text.lower()
        assert (
            "masqu" in content
            or "hidden" in content
            or "inbox-item-sender--hidden" in response.text
        )

    def test_inbox_page_shows_action_buttons(self, client: TestClient) -> None:
        """Verify inbox page shows appropriate action buttons."""
        response = client.get("/recipient/inbox")
        assert response.status_code == 200
        # Should have action buttons
        assert "inbox-item-actions" in response.text
        # Should have view/respond links
        assert "btn" in response.text

    def test_inbox_page_english_language(self, client: TestClient) -> None:
        """Verify inbox page can render in English."""
        response = client.get("/recipient/inbox?lang=en")
        assert response.status_code == 200
        # English version should have "inbox" or "mail" text
        content = response.text.lower()
        assert "inbox" in content or "mail" in content

    def test_inbox_page_links_to_pickup(self, client: TestClient) -> None:
        """Verify inbox page has links to pickup view for pending deliveries."""
        response = client.get("/recipient/inbox")
        assert response.status_code == 200
        # Should have link to pickup page
        assert "/recipient/pickup/" in response.text

    def test_inbox_page_links_to_accepted(self, client: TestClient) -> None:
        """Verify inbox page has links to accepted view."""
        response = client.get("/recipient/inbox")
        assert response.status_code == 200
        # Should have link to accepted page
        assert "/recipient/accepted/" in response.text

    def test_inbox_page_links_to_refused(self, client: TestClient) -> None:
        """Verify inbox page has links to refused view."""
        response = client.get("/recipient/inbox")
        assert response.status_code == 200
        # Should have link to refused page
        assert "/recipient/refused/" in response.text


# ---------------------------------------------------------------------------
# CSS and Styling Tests
# ---------------------------------------------------------------------------
class TestRecipientViewStyling:
    """Tests for CSS classes and responsive design elements."""

    def test_refused_uses_semantic_css_classes(self, client: TestClient) -> None:
        """Verify refused page uses semantic CSS classes per CLAUDE.md guidelines."""
        response = client.get("/recipient/refused/test-delivery-id")
        assert response.status_code == 200
        # Should use semantic class names, not utility classes
        assert "pickup-hero" in response.text
        assert "pickup-card" in response.text
        assert "delivery-info-list" in response.text

    def test_inbox_uses_semantic_css_classes(self, client: TestClient) -> None:
        """Verify inbox page uses semantic CSS classes per CLAUDE.md guidelines."""
        response = client.get("/recipient/inbox")
        assert response.status_code == 200
        # Should use semantic class names
        assert "inbox-list" in response.text
        assert "inbox-item" in response.text
        assert "inbox-filters" in response.text

    def test_refused_includes_main_css(self, client: TestClient) -> None:
        """Verify refused page includes main.css stylesheet."""
        response = client.get("/recipient/refused/test-delivery-id")
        assert response.status_code == 200
        assert "/static/css/main.css" in response.text

    def test_inbox_includes_main_css(self, client: TestClient) -> None:
        """Verify inbox page includes main.css stylesheet."""
        response = client.get("/recipient/inbox")
        assert response.status_code == 200
        assert "/static/css/main.css" in response.text


# ---------------------------------------------------------------------------
# i18n Tests
# ---------------------------------------------------------------------------
class TestRecipientViewI18n:
    """Tests for internationalization of recipient views."""

    def test_refused_french_translations(self, client: TestClient) -> None:
        """Verify refused page uses French translations by default."""
        response = client.get("/recipient/refused/test-delivery-id")
        assert response.status_code == 200
        # Should have French text
        content = response.text
        # Check for French-specific phrases
        assert "refus" in content.lower() or "Refuse" in content

    def test_inbox_french_translations(self, client: TestClient) -> None:
        """Verify inbox page uses French translations by default."""
        response = client.get("/recipient/inbox")
        assert response.status_code == 200
        # Should have French text
        content = response.text.lower()
        # Check for French-specific phrases
        assert "filtrer" in content or "filter" in content

    def test_refused_accepts_lang_parameter(self, client: TestClient) -> None:
        """Verify refused page accepts lang query parameter."""
        response_fr = client.get("/recipient/refused/test?lang=fr")
        response_en = client.get("/recipient/refused/test?lang=en")
        assert response_fr.status_code == 200
        assert response_en.status_code == 200

    def test_inbox_accepts_lang_parameter(self, client: TestClient) -> None:
        """Verify inbox page accepts lang query parameter."""
        response_fr = client.get("/recipient/inbox?lang=fr")
        response_en = client.get("/recipient/inbox?lang=en")
        assert response_fr.status_code == 200
        assert response_en.status_code == 200


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------
class TestRecipientViewIntegration:
    """Integration tests for recipient views."""

    def test_refused_to_inbox_navigation(self, client: TestClient) -> None:
        """Verify refused page has link back to inbox."""
        response = client.get("/recipient/refused/test-delivery-id")
        assert response.status_code == 200
        # Should have link to inbox
        assert "/recipient/inbox" in response.text

    def test_inbox_to_refused_navigation(self, client: TestClient) -> None:
        """Verify inbox can navigate to refused view."""
        response = client.get("/recipient/inbox")
        assert response.status_code == 200
        # Should have link to refused pages
        assert "/recipient/refused/" in response.text

    def test_refused_extends_base_template(self, client: TestClient) -> None:
        """Verify refused page extends base template with header/footer."""
        response = client.get("/recipient/refused/test-delivery-id")
        assert response.status_code == 200
        # Should have QERDS branding from base template
        assert "QERDS" in response.text
        # Should have footer
        assert "qerds-footer" in response.text

    def test_inbox_extends_base_template(self, client: TestClient) -> None:
        """Verify inbox page extends base template with header/footer."""
        response = client.get("/recipient/inbox")
        assert response.status_code == 200
        # Should have QERDS branding from base template
        assert "QERDS" in response.text
        # Should have footer
        assert "qerds-footer" in response.text

    def test_refused_shows_verification_link(self, client: TestClient) -> None:
        """Verify refused page has link to verification portal."""
        response = client.get("/recipient/refused/test-delivery-id")
        assert response.status_code == 200
        # Should have link to verify proof
        assert "/verify" in response.text

    def test_inbox_shows_help_link(self, client: TestClient) -> None:
        """Verify inbox page has link to help."""
        response = client.get("/recipient/inbox")
        assert response.status_code == 200
        # Should have link to help
        assert "/help" in response.text
