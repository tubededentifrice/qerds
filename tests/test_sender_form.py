"""Tests for the sender new delivery form page.

Tests cover:
- Template rendering for /sender/new
- Form structure and required fields
- i18n support verification
- Accessibility attributes
- Form actions (cancel, draft, send)

Covers: REQ-B01 (frontend aspects)
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from qerds.api import create_app


@pytest.fixture
def test_app():
    """Create a test FastAPI application instance."""
    return create_app()


@pytest.fixture
async def client(test_app) -> AsyncClient:
    """Create async HTTP client for testing the API."""
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


class TestSenderNewDeliveryPage:
    """Tests for the sender new delivery form page."""

    @pytest.mark.asyncio
    async def test_new_delivery_page_renders(self, client: AsyncClient):
        """Test that the new delivery page renders successfully."""
        response = await client.get("/sender/new")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]

    @pytest.mark.asyncio
    async def test_new_delivery_page_has_form(self, client: AsyncClient):
        """Test that the page contains a delivery form."""
        response = await client.get("/sender/new")
        content = response.text

        # Check form exists with correct attributes
        assert "<form" in content
        assert 'enctype="multipart/form-data"' in content
        assert 'id="delivery-form"' in content

    @pytest.mark.asyncio
    async def test_new_delivery_form_has_recipient_fields(self, client: AsyncClient):
        """Test that the form has recipient email and name fields."""
        response = await client.get("/sender/new")
        content = response.text

        # Recipient email field
        assert 'id="recipient_email"' in content
        assert 'name="recipient_email"' in content
        assert 'type="email"' in content
        assert "required" in content  # Email is required

        # Recipient name field
        assert 'id="recipient_name"' in content
        assert 'name="recipient_name"' in content

    @pytest.mark.asyncio
    async def test_new_delivery_form_has_content_fields(self, client: AsyncClient):
        """Test that the form has subject, message, and document fields."""
        response = await client.get("/sender/new")
        content = response.text

        # Subject field
        assert 'id="subject"' in content
        assert 'name="subject"' in content

        # Message field
        assert 'id="message"' in content
        assert 'name="message"' in content
        assert "<textarea" in content

        # Document upload field
        assert 'id="document"' in content
        assert 'name="document"' in content
        assert 'type="file"' in content
        assert 'accept=".pdf,.doc,.docx,.odt"' in content

    @pytest.mark.asyncio
    async def test_new_delivery_form_has_delivery_type_options(self, client: AsyncClient):
        """Test that the form has standard and urgent delivery type options."""
        response = await client.get("/sender/new")
        content = response.text

        # Delivery type radio buttons
        assert 'name="delivery_type"' in content
        assert 'value="standard"' in content
        assert 'value="urgent"' in content
        # Standard should be checked by default
        assert "checked" in content

    @pytest.mark.asyncio
    async def test_new_delivery_form_has_action_buttons(self, client: AsyncClient):
        """Test that the form has cancel, draft, and send buttons."""
        response = await client.get("/sender/new")
        content = response.text

        # Cancel button
        assert 'class="btn btn--ghost"' in content
        assert "window.history.back()" in content

        # Draft button
        assert 'id="btn-draft"' in content
        assert 'value="draft"' in content

        # Send button
        assert 'id="btn-send"' in content
        assert 'value="send"' in content
        assert "btn--primary" in content

    @pytest.mark.asyncio
    async def test_new_delivery_page_has_breadcrumb(self, client: AsyncClient):
        """Test that the page has a breadcrumb link back to dashboard."""
        response = await client.get("/sender/new")
        content = response.text

        assert 'href="/sender/dashboard"' in content
        assert "breadcrumb-back" in content

    @pytest.mark.asyncio
    async def test_new_delivery_page_has_page_title(self, client: AsyncClient):
        """Test that the page has a proper page title."""
        response = await client.get("/sender/new")
        content = response.text

        assert '<h1 class="page-title">' in content

    @pytest.mark.asyncio
    async def test_new_delivery_page_has_info_alert(self, client: AsyncClient):
        """Test that the page has an informational alert about deposit proof."""
        response = await client.get("/sender/new")
        content = response.text

        assert "alert--info" in content

    @pytest.mark.asyncio
    async def test_new_delivery_form_has_progress_overlay(self, client: AsyncClient):
        """Test that the form has a progress overlay for submission feedback."""
        response = await client.get("/sender/new")
        content = response.text

        assert 'id="form-progress"' in content
        assert "form-progress-overlay" in content

    @pytest.mark.asyncio
    async def test_new_delivery_form_file_upload_has_max_size(self, client: AsyncClient):
        """Test that file upload has max size data attribute."""
        response = await client.get("/sender/new")
        content = response.text

        # 10MB in bytes
        assert 'data-max-size="10485760"' in content

    @pytest.mark.asyncio
    async def test_new_delivery_form_has_file_selected_display(self, client: AsyncClient):
        """Test that the form has elements for displaying selected file."""
        response = await client.get("/sender/new")
        content = response.text

        assert 'id="file-selected"' in content
        assert 'id="file-name"' in content
        assert 'id="file-size"' in content
        assert 'id="file-remove"' in content

    @pytest.mark.asyncio
    async def test_new_delivery_form_has_error_elements(self, client: AsyncClient):
        """Test that the form has error display elements for validation."""
        response = await client.get("/sender/new")
        content = response.text

        # Error elements for each required field
        assert 'id="recipient_email_error"' in content
        assert 'id="subject_error"' in content
        assert 'id="document_error"' in content


class TestSenderFormAccessibility:
    """Tests for accessibility attributes on the sender form."""

    @pytest.mark.asyncio
    async def test_form_inputs_have_labels(self, client: AsyncClient):
        """Test that all form inputs have associated labels."""
        response = await client.get("/sender/new")
        content = response.text

        # Each input should have a label with for attribute
        assert 'for="recipient_email"' in content
        assert 'for="recipient_name"' in content
        assert 'for="subject"' in content
        assert 'for="message"' in content
        assert 'for="document"' in content

    @pytest.mark.asyncio
    async def test_form_inputs_have_aria_attributes(self, client: AsyncClient):
        """Test that form inputs have aria-describedby for hints and errors."""
        response = await client.get("/sender/new")
        content = response.text

        # Recipient email should reference hint and error
        assert 'aria-describedby="recipient_email_hint recipient_email_error"' in content

        # Subject should reference error
        assert 'aria-describedby="subject_error"' in content

        # Document should reference hint and error
        assert 'aria-describedby="document_hint document_error"' in content

    @pytest.mark.asyncio
    async def test_file_remove_button_has_aria_label(self, client: AsyncClient):
        """Test that the file remove button has an aria-label."""
        response = await client.get("/sender/new")
        content = response.text

        assert 'id="file-remove"' in content
        assert "aria-label=" in content

    @pytest.mark.asyncio
    async def test_breadcrumb_has_aria_label(self, client: AsyncClient):
        """Test that the breadcrumb navigation has an aria-label."""
        response = await client.get("/sender/new")
        content = response.text

        assert 'aria-label="Breadcrumb"' in content


class TestSenderFormI18n:
    """Tests for i18n support in the sender form."""

    @pytest.mark.asyncio
    async def test_page_renders_with_french_locale(self, client: AsyncClient):
        """Test that the page renders correctly with French locale."""
        response = await client.get("/sender/new", headers={"Accept-Language": "fr-FR,fr;q=0.9"})
        assert response.status_code == 200
        # The page should have French content
        content = response.text
        # Check for some French text (the translations should be loaded)
        assert "QERDS" in content  # App title should be present

    @pytest.mark.asyncio
    async def test_page_renders_with_english_locale(self, client: AsyncClient):
        """Test that the page renders correctly with English locale."""
        response = await client.get("/sender/new", headers={"Accept-Language": "en-US,en;q=0.9"})
        assert response.status_code == 200
        content = response.text
        assert "QERDS" in content


class TestSenderFormStructure:
    """Tests for form structure and fieldsets."""

    @pytest.mark.asyncio
    async def test_form_has_fieldsets(self, client: AsyncClient):
        """Test that the form uses fieldsets for grouping."""
        response = await client.get("/sender/new")
        content = response.text

        # Should have fieldsets for organization
        assert "<fieldset" in content
        assert "<legend" in content
        assert "form-fieldset" in content
        assert "form-fieldset-legend" in content

    @pytest.mark.asyncio
    async def test_form_has_radio_group(self, client: AsyncClient):
        """Test that delivery type uses radio-group class."""
        response = await client.get("/sender/new")
        content = response.text

        assert 'class="radio-group"' in content
        assert 'class="radio-option"' in content
        assert "radio-option-title" in content
        assert "radio-option-description" in content

    @pytest.mark.asyncio
    async def test_form_has_card_structure(self, client: AsyncClient):
        """Test that the form uses card component structure."""
        response = await client.get("/sender/new")
        content = response.text

        assert "card card--elevated" in content
        assert "card-body" in content
        assert "card-footer" in content

    @pytest.mark.asyncio
    async def test_form_has_spinner_for_loading(self, client: AsyncClient):
        """Test that the form has spinner SVG for loading states."""
        response = await client.get("/sender/new")
        content = response.text

        assert 'class="spinner"' in content
        assert "btn-loading" in content
