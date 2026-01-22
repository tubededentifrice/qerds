"""Tests for sender history and delivery detail views.

Tests cover:
- GET /sender/history - history page rendering
- History filtering by status, date range, search
- History pagination
- History sorting
- GET /sender/deliveries/{delivery_id} - detail page rendering
- Detail page timeline display
- Detail page proofs section
- Detail page actions
- i18n support for both views
"""

import pytest
from httpx import AsyncClient


class TestSenderHistoryPage:
    """Tests for the sender history view."""

    @pytest.mark.asyncio
    async def test_history_returns_200(self, api_client: AsyncClient):
        """Test that history page returns 200 OK."""
        response = await api_client.get("/sender/history")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_history_returns_html(self, api_client: AsyncClient):
        """Test that history page returns HTML content."""
        response = await api_client.get("/sender/history")
        assert "text/html" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_history_contains_title(self, api_client: AsyncClient):
        """Test that history page contains proper title."""
        response = await api_client.get("/sender/history")
        content = response.text
        # French by default
        assert "Historique" in content

    @pytest.mark.asyncio
    async def test_history_contains_page_header(self, api_client: AsyncClient):
        """Test that history has page header with title and description."""
        response = await api_client.get("/sender/history")
        content = response.text
        assert "page-header" in content
        assert "page-title" in content
        assert "page-description" in content

    @pytest.mark.asyncio
    async def test_history_contains_new_delivery_button(self, api_client: AsyncClient):
        """Test that history has new delivery button in header."""
        response = await api_client.get("/sender/history")
        content = response.text
        assert "/sender/new" in content
        assert "btn--primary" in content


class TestSenderHistoryFilters:
    """Tests for the history page filtering functionality."""

    @pytest.mark.asyncio
    async def test_history_contains_filters_section(self, api_client: AsyncClient):
        """Test that history page contains filters section."""
        response = await api_client.get("/sender/history")
        content = response.text
        assert "history-filters" in content

    @pytest.mark.asyncio
    async def test_history_contains_search_input(self, api_client: AsyncClient):
        """Test that history page has search input."""
        response = await api_client.get("/sender/history")
        content = response.text
        assert "history-search" in content
        assert 'type="search"' in content

    @pytest.mark.asyncio
    async def test_history_contains_status_filter(self, api_client: AsyncClient):
        """Test that history page has status filter dropdown."""
        response = await api_client.get("/sender/history")
        content = response.text
        assert 'name="status"' in content
        assert "filter-status" in content

    @pytest.mark.asyncio
    async def test_history_contains_date_filter(self, api_client: AsyncClient):
        """Test that history page has date range filter."""
        response = await api_client.get("/sender/history")
        content = response.text
        assert 'name="date_range"' in content

    @pytest.mark.asyncio
    async def test_history_contains_sort_options(self, api_client: AsyncClient):
        """Test that history page has sort options."""
        response = await api_client.get("/sender/history")
        content = response.text
        assert 'name="sort"' in content
        assert "date_desc" in content
        assert "date_asc" in content

    @pytest.mark.asyncio
    async def test_history_filter_apply_button(self, api_client: AsyncClient):
        """Test that history page has filter apply button."""
        response = await api_client.get("/sender/history")
        content = response.text
        assert 'type="submit"' in content

    @pytest.mark.asyncio
    async def test_history_filter_clear_link(self, api_client: AsyncClient):
        """Test that history page has filter clear/reset link."""
        response = await api_client.get("/sender/history")
        content = response.text
        # Clear filters links back to history without params
        assert "history-filter-actions" in content


class TestSenderHistoryFilterFunctionality:
    """Tests for actual filter functionality."""

    @pytest.mark.asyncio
    async def test_history_status_filter_pending(self, api_client: AsyncClient):
        """Test filtering by pending status."""
        response = await api_client.get("/sender/history?status=pending")
        assert response.status_code == 200
        content = response.text
        # Should show deliveries in pending states
        assert "history-item" in content or "history-list" in content

    @pytest.mark.asyncio
    async def test_history_status_filter_completed(self, api_client: AsyncClient):
        """Test filtering by completed status."""
        response = await api_client.get("/sender/history?status=completed")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_history_status_filter_expired(self, api_client: AsyncClient):
        """Test filtering by expired status."""
        response = await api_client.get("/sender/history?status=expired")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_history_date_filter_today(self, api_client: AsyncClient):
        """Test filtering by today's date."""
        response = await api_client.get("/sender/history?date_range=today")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_history_date_filter_week(self, api_client: AsyncClient):
        """Test filtering by this week."""
        response = await api_client.get("/sender/history?date_range=week")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_history_date_filter_month(self, api_client: AsyncClient):
        """Test filtering by this month."""
        response = await api_client.get("/sender/history?date_range=month")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_history_search_query(self, api_client: AsyncClient):
        """Test search query parameter."""
        response = await api_client.get("/sender/history?q=test")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_history_sort_date_asc(self, api_client: AsyncClient):
        """Test sorting by date ascending."""
        response = await api_client.get("/sender/history?sort=date_asc")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_history_sort_status(self, api_client: AsyncClient):
        """Test sorting by status."""
        response = await api_client.get("/sender/history?sort=status")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_history_combined_filters(self, api_client: AsyncClient):
        """Test combining multiple filters."""
        response = await api_client.get(
            "/sender/history?status=pending&date_range=week&sort=date_asc"
        )
        assert response.status_code == 200


class TestSenderHistoryList:
    """Tests for the history list display."""

    @pytest.mark.asyncio
    async def test_history_contains_list_section(self, api_client: AsyncClient):
        """Test that history page contains list section."""
        response = await api_client.get("/sender/history")
        content = response.text
        assert "history-list" in content

    @pytest.mark.asyncio
    async def test_history_list_items(self, api_client: AsyncClient):
        """Test that history page shows delivery items."""
        response = await api_client.get("/sender/history")
        content = response.text
        # Mock data provides deliveries
        assert "history-item" in content

    @pytest.mark.asyncio
    async def test_history_item_has_link(self, api_client: AsyncClient):
        """Test that history items link to detail page."""
        response = await api_client.get("/sender/history")
        content = response.text
        assert "history-item-link" in content
        assert "/sender/deliveries/" in content

    @pytest.mark.asyncio
    async def test_history_item_shows_subject(self, api_client: AsyncClient):
        """Test that history items display subject."""
        response = await api_client.get("/sender/history")
        content = response.text
        assert "history-item-subject" in content

    @pytest.mark.asyncio
    async def test_history_item_shows_recipient(self, api_client: AsyncClient):
        """Test that history items display recipient email."""
        response = await api_client.get("/sender/history")
        content = response.text
        assert "history-item-recipient" in content

    @pytest.mark.asyncio
    async def test_history_item_shows_status(self, api_client: AsyncClient):
        """Test that history items include status badge."""
        response = await api_client.get("/sender/history")
        content = response.text
        assert "status-badge" in content

    @pytest.mark.asyncio
    async def test_history_shows_results_count(self, api_client: AsyncClient):
        """Test that history shows results count."""
        response = await api_client.get("/sender/history")
        content = response.text
        assert "history-results-count" in content


class TestSenderHistoryPagination:
    """Tests for history pagination."""

    @pytest.mark.asyncio
    async def test_history_pagination_section(self, api_client: AsyncClient):
        """Test that history page has pagination section when needed."""
        response = await api_client.get("/sender/history")
        content = response.text
        # Pagination shown when total_pages > 1
        assert "history-pagination" in content

    @pytest.mark.asyncio
    async def test_history_pagination_with_page_param(self, api_client: AsyncClient):
        """Test pagination with page parameter."""
        response = await api_client.get("/sender/history?page=1")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_history_pagination_page_2(self, api_client: AsyncClient):
        """Test accessing page 2."""
        response = await api_client.get("/sender/history?page=2")
        assert response.status_code == 200


class TestSenderHistoryI18n:
    """Tests for history page internationalization."""

    @pytest.mark.asyncio
    async def test_history_french_by_default(self, api_client: AsyncClient):
        """Test that history renders in French by default."""
        response = await api_client.get("/sender/history")
        content = response.text
        assert "Historique des envois" in content

    @pytest.mark.asyncio
    async def test_history_english_with_lang_param(self, api_client: AsyncClient):
        """Test that history renders in English when requested."""
        response = await api_client.get("/sender/history?lang=en")
        content = response.text
        assert "Delivery History" in content

    @pytest.mark.asyncio
    async def test_history_respects_accept_language_header(self, api_client: AsyncClient):
        """Test that history respects Accept-Language header."""
        response = await api_client.get(
            "/sender/history",
            headers={"Accept-Language": "en-US,en;q=0.9"},
        )
        content = response.text
        assert "Delivery History" in content


class TestSenderHistoryNavigation:
    """Tests for navigation elements on history page."""

    @pytest.mark.asyncio
    async def test_history_nav_highlights_current_page(self, api_client: AsyncClient):
        """Test that navigation highlights history as active page."""
        response = await api_client.get("/sender/history")
        content = response.text
        # The history link should be active
        assert "/sender/history" in content


class TestSenderDeliveryDetailPage:
    """Tests for the delivery detail view."""

    @pytest.mark.asyncio
    async def test_detail_returns_200(self, api_client: AsyncClient):
        """Test that detail page returns 200 OK."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_detail_returns_html(self, api_client: AsyncClient):
        """Test that detail page returns HTML content."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        assert "text/html" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_detail_contains_title(self, api_client: AsyncClient):
        """Test that detail page contains proper title."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        # French by default, showing delivery detail title
        assert "detail" in content.lower() or "envoi" in content.lower()

    @pytest.mark.asyncio
    async def test_detail_contains_back_link(self, api_client: AsyncClient):
        """Test that detail has back to history link."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        assert "/sender/history" in content
        assert "breadcrumb-back" in content

    @pytest.mark.asyncio
    async def test_detail_contains_status_badge(self, api_client: AsyncClient):
        """Test that detail page shows delivery status."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        assert "status-badge" in content


class TestSenderDeliveryDetailInfo:
    """Tests for the detail page information sections."""

    @pytest.mark.asyncio
    async def test_detail_contains_delivery_info(self, api_client: AsyncClient):
        """Test that detail shows delivery information section."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        assert "detail-info-list" in content

    @pytest.mark.asyncio
    async def test_detail_shows_delivery_id(self, api_client: AsyncClient):
        """Test that detail shows delivery ID."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        assert "test-delivery-id" in content

    @pytest.mark.asyncio
    async def test_detail_shows_recipient_info(self, api_client: AsyncClient):
        """Test that detail shows recipient information."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        assert "recipient-info-title" in content

    @pytest.mark.asyncio
    async def test_detail_shows_content_info(self, api_client: AsyncClient):
        """Test that detail shows content information."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        assert "content-info-title" in content


class TestSenderDeliveryDetailTimeline:
    """Tests for the detail page timeline section."""

    @pytest.mark.asyncio
    async def test_detail_contains_timeline(self, api_client: AsyncClient):
        """Test that detail page has timeline section."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        assert "timeline-title" in content
        assert "detail-timeline" in content

    @pytest.mark.asyncio
    async def test_detail_timeline_has_items(self, api_client: AsyncClient):
        """Test that timeline shows event items."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        assert "detail-timeline-item" in content

    @pytest.mark.asyncio
    async def test_detail_timeline_shows_event_titles(self, api_client: AsyncClient):
        """Test that timeline items have titles."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        assert "detail-timeline-title" in content

    @pytest.mark.asyncio
    async def test_detail_timeline_shows_timestamps(self, api_client: AsyncClient):
        """Test that timeline items show timestamps."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        assert "detail-timeline-time" in content


class TestSenderDeliveryDetailProofs:
    """Tests for the detail page proofs section."""

    @pytest.mark.asyncio
    async def test_detail_contains_proofs_section(self, api_client: AsyncClient):
        """Test that detail page has proofs section."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        assert "proofs-title" in content

    @pytest.mark.asyncio
    async def test_detail_shows_available_proofs(self, api_client: AsyncClient):
        """Test that proofs section shows available proofs."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        # Mock data provides proofs
        assert "detail-proofs-list" in content or "detail-proofs-empty" in content

    @pytest.mark.asyncio
    async def test_detail_proofs_have_download_links(self, api_client: AsyncClient):
        """Test that proofs have download action."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        # Should have download link when proofs are available
        assert "detail-proof-actions" in content or "detail-proofs-empty" in content


class TestSenderDeliveryDetailActions:
    """Tests for the detail page actions section."""

    @pytest.mark.asyncio
    async def test_detail_contains_actions_section(self, api_client: AsyncClient):
        """Test that detail page has actions section."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        assert "actions-title" in content
        assert "detail-actions" in content


class TestSenderDeliveryDetailI18n:
    """Tests for detail page internationalization."""

    @pytest.mark.asyncio
    async def test_detail_french_by_default(self, api_client: AsyncClient):
        """Test that detail renders in French by default."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        # French labels
        assert "Chronologie" in content or "timeline" in content.lower()

    @pytest.mark.asyncio
    async def test_detail_english_with_lang_param(self, api_client: AsyncClient):
        """Test that detail renders in English when requested."""
        response = await api_client.get("/sender/deliveries/test-delivery-id?lang=en")
        content = response.text
        assert "Timeline" in content


class TestSenderDeliveryDetailResponsive:
    """Tests for detail page responsive design."""

    @pytest.mark.asyncio
    async def test_detail_uses_grid_layout(self, api_client: AsyncClient):
        """Test that detail page uses grid layout."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        assert "detail-grid" in content

    @pytest.mark.asyncio
    async def test_detail_has_sidebar(self, api_client: AsyncClient):
        """Test that detail page has sidebar."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        assert "detail-sidebar" in content

    @pytest.mark.asyncio
    async def test_detail_has_main_content(self, api_client: AsyncClient):
        """Test that detail page has main content area."""
        response = await api_client.get("/sender/deliveries/test-delivery-id")
        content = response.text
        assert "detail-main" in content
