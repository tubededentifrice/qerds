"""Tests for sender dashboard and related views.

Tests cover:
- GET /sender/dashboard - dashboard page rendering
- Dashboard stats display
- Delivery cards rendering
- Empty state when no deliveries
- Quick actions section
- i18n support
- Responsive design elements
"""

import pytest
from httpx import AsyncClient


class TestSenderDashboardPage:
    """Tests for the sender dashboard view."""

    @pytest.mark.asyncio
    async def test_dashboard_returns_200(self, api_client: AsyncClient):
        """Test that dashboard page returns 200 OK."""
        response = await api_client.get("/sender/dashboard")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_dashboard_returns_html(self, api_client: AsyncClient):
        """Test that dashboard page returns HTML content."""
        response = await api_client.get("/sender/dashboard")
        assert "text/html" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_dashboard_contains_title(self, api_client: AsyncClient):
        """Test that dashboard page contains proper title."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        # French by default
        assert "Tableau de bord" in content

    @pytest.mark.asyncio
    async def test_dashboard_contains_page_header(self, api_client: AsyncClient):
        """Test that dashboard has page header with title and description."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "page-header" in content
        assert "page-title" in content
        assert "page-description" in content


class TestSenderDashboardStats:
    """Tests for the dashboard statistics section."""

    @pytest.mark.asyncio
    async def test_dashboard_contains_stats_grid(self, api_client: AsyncClient):
        """Test that dashboard contains stats grid section."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "stats-grid" in content

    @pytest.mark.asyncio
    async def test_dashboard_shows_this_month_stat(self, api_client: AsyncClient):
        """Test that dashboard shows 'this month' statistic."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        # French label
        assert "Envois ce mois" in content or "stats_this_month" in content
        assert "stat-value" in content

    @pytest.mark.asyncio
    async def test_dashboard_shows_pending_stat(self, api_client: AsyncClient):
        """Test that dashboard shows pending deliveries stat."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "En attente" in content or "stats_pending" in content

    @pytest.mark.asyncio
    async def test_dashboard_shows_accepted_stat(self, api_client: AsyncClient):
        """Test that dashboard shows accepted deliveries stat."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        # French label (with accented e for Acceptes)
        assert "Accept" in content

    @pytest.mark.asyncio
    async def test_dashboard_shows_refused_expired_stat(self, api_client: AsyncClient):
        """Test that dashboard shows refused/expired deliveries stat."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        # French label
        assert "Refus" in content or "Neglig" in content


class TestSenderDashboardDeliveries:
    """Tests for the recent deliveries section."""

    @pytest.mark.asyncio
    async def test_dashboard_contains_deliveries_section(self, api_client: AsyncClient):
        """Test that dashboard contains recent deliveries section."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "recent-deliveries-title" in content

    @pytest.mark.asyncio
    async def test_dashboard_uses_deliveries_grid(self, api_client: AsyncClient):
        """Test that dashboard uses semantic deliveries-grid class."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        # Should use the semantic class, not inline styles
        assert "deliveries-grid" in content

    @pytest.mark.asyncio
    async def test_dashboard_uses_section_header(self, api_client: AsyncClient):
        """Test that dashboard uses semantic section-header class."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "section-header" in content
        assert "section-title" in content

    @pytest.mark.asyncio
    async def test_dashboard_contains_delivery_cards(self, api_client: AsyncClient):
        """Test that dashboard contains delivery card components."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        # Mock data provides deliveries, so cards should be present
        assert "delivery-card" in content

    @pytest.mark.asyncio
    async def test_dashboard_delivery_card_has_subject(self, api_client: AsyncClient):
        """Test that delivery cards show subject."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "delivery-subject" in content

    @pytest.mark.asyncio
    async def test_dashboard_delivery_card_has_recipient(self, api_client: AsyncClient):
        """Test that delivery cards show recipient email."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "delivery-recipient" in content

    @pytest.mark.asyncio
    async def test_dashboard_delivery_card_has_status_badge(self, api_client: AsyncClient):
        """Test that delivery cards include status badge."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "status-badge" in content

    @pytest.mark.asyncio
    async def test_dashboard_contains_view_all_link(self, api_client: AsyncClient):
        """Test that dashboard contains 'view all' link to history."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "/sender/history" in content
        assert "Voir tout" in content or "view_all" in content


class TestSenderDashboardQuickActions:
    """Tests for the quick actions section."""

    @pytest.mark.asyncio
    async def test_dashboard_contains_quick_actions(self, api_client: AsyncClient):
        """Test that dashboard contains quick actions section."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "quick-actions-title" in content

    @pytest.mark.asyncio
    async def test_dashboard_uses_quick_actions_class(self, api_client: AsyncClient):
        """Test that quick actions uses semantic CSS class."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "quick-actions" in content

    @pytest.mark.asyncio
    async def test_dashboard_contains_new_delivery_action(self, api_client: AsyncClient):
        """Test that quick actions includes new delivery link."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "/sender/new" in content

    @pytest.mark.asyncio
    async def test_dashboard_contains_drafts_action(self, api_client: AsyncClient):
        """Test that quick actions includes drafts link."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "/sender/drafts" in content
        assert "Brouillons" in content or "drafts" in content.lower()

    @pytest.mark.asyncio
    async def test_dashboard_contains_proofs_action(self, api_client: AsyncClient):
        """Test that quick actions includes proofs download link."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "/sender/proofs" in content

    @pytest.mark.asyncio
    async def test_dashboard_contains_help_action(self, api_client: AsyncClient):
        """Test that quick actions includes help link."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "/help" in content
        assert "Aide" in content or "help" in content.lower()


class TestSenderDashboardNavigation:
    """Tests for navigation elements on dashboard."""

    @pytest.mark.asyncio
    async def test_dashboard_has_new_delivery_button(self, api_client: AsyncClient):
        """Test that dashboard has prominent new delivery button."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        # Primary button in page header
        assert "btn--primary" in content
        assert "/sender/new" in content

    @pytest.mark.asyncio
    async def test_dashboard_nav_highlights_current_page(self, api_client: AsyncClient):
        """Test that navigation highlights dashboard as active page."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        # Dashboard nav link should have active class
        assert 'class="nav-link active"' in content or "nav-link active" in content


class TestSenderDashboardI18n:
    """Tests for dashboard internationalization."""

    @pytest.mark.asyncio
    async def test_dashboard_french_by_default(self, api_client: AsyncClient):
        """Test that dashboard renders in French by default."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        # French content
        assert "Tableau de bord" in content
        assert "Nouvel envoi" in content

    @pytest.mark.asyncio
    async def test_dashboard_english_with_lang_param(self, api_client: AsyncClient):
        """Test that dashboard renders in English when requested."""
        response = await api_client.get("/sender/dashboard?lang=en")
        content = response.text
        # English content
        assert "Dashboard" in content

    @pytest.mark.asyncio
    async def test_dashboard_respects_accept_language_header(self, api_client: AsyncClient):
        """Test that dashboard respects Accept-Language header."""
        response = await api_client.get(
            "/sender/dashboard",
            headers={"Accept-Language": "en-US,en;q=0.9"},
        )
        content = response.text
        assert "Dashboard" in content


class TestSenderDashboardAccessibility:
    """Tests for accessibility features on dashboard."""

    @pytest.mark.asyncio
    async def test_dashboard_has_main_heading(self, api_client: AsyncClient):
        """Test that dashboard has h1 heading."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "<h1" in content

    @pytest.mark.asyncio
    async def test_dashboard_sections_have_aria_labels(self, api_client: AsyncClient):
        """Test that major sections have aria labels."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        # Stats section has aria-label
        assert "aria-label=" in content or "aria-labelledby=" in content

    @pytest.mark.asyncio
    async def test_dashboard_quick_actions_has_sr_only_title(self, api_client: AsyncClient):
        """Test that quick actions has screen-reader-only title."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "sr-only" in content


class TestSenderDashboardDevMode:
    """Tests for development mode behavior on dashboard."""

    @pytest.mark.asyncio
    async def test_dashboard_shows_dev_banner_by_default(self, api_client: AsyncClient):
        """Test that dev mode banner shows by default."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        # Dev banner should appear in non-qualified mode
        assert "dev-banner" in content or "Mode d" in content


class TestSenderDashboardStructure:
    """Tests for dashboard HTML structure and CSS classes."""

    @pytest.mark.asyncio
    async def test_dashboard_uses_container(self, api_client: AsyncClient):
        """Test that dashboard content is in container."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert 'class="container"' in content

    @pytest.mark.asyncio
    async def test_dashboard_uses_card_component(self, api_client: AsyncClient):
        """Test that dashboard uses card component for quick actions."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert 'class="card"' in content

    @pytest.mark.asyncio
    async def test_dashboard_uses_stat_cards(self, api_client: AsyncClient):
        """Test that dashboard uses stat-card class."""
        response = await api_client.get("/sender/dashboard")
        content = response.text
        assert "stat-card" in content

    @pytest.mark.asyncio
    async def test_dashboard_no_inline_styles_for_grid(self, api_client: AsyncClient):
        """Test that grid layout uses CSS classes, not inline styles.

        The deliveries grid should use the 'deliveries-grid' class
        instead of inline style declarations.
        """
        response = await api_client.get("/sender/dashboard")
        content = response.text
        # Should use class, not inline grid style
        assert "deliveries-grid" in content
        # Should NOT have inline grid style on the deliveries container
        # The template should not have 'style="display: grid;' for the deliveries
        assert 'style="display: grid; grid-template-columns' not in content
