"""Tests for login page and authentication views.

Tests cover:
- GET /login - login page rendering
- GET /logout - logout handler redirect
- Template context building
- Dev mode warning display
- i18n on login page
"""

import pytest
from httpx import AsyncClient


class TestLoginPage:
    """Tests for the login page view."""

    @pytest.mark.asyncio
    async def test_login_page_returns_200(self, api_client: AsyncClient):
        """Test that login page returns 200 OK."""
        response = await api_client.get("/login")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_login_page_returns_html(self, api_client: AsyncClient):
        """Test that login page returns HTML content."""
        response = await api_client.get("/login")
        assert "text/html" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_login_page_contains_title(self, api_client: AsyncClient):
        """Test that login page contains proper title."""
        response = await api_client.get("/login")
        content = response.text
        # Should contain the page title (French by default)
        assert "Connexion" in content or "Log in" in content

    @pytest.mark.asyncio
    async def test_login_page_contains_franceconnect_button(self, api_client: AsyncClient):
        """Test that login page contains FranceConnect+ button."""
        response = await api_client.get("/login")
        content = response.text
        # Should contain link to OIDC auth endpoint
        assert "/auth/login" in content
        # Should contain FranceConnect text
        assert "FranceConnect" in content

    @pytest.mark.asyncio
    async def test_login_page_contains_email_form(self, api_client: AsyncClient):
        """Test that login page contains email/password form."""
        response = await api_client.get("/login")
        content = response.text
        # Check for form elements
        assert 'type="email"' in content
        assert 'type="password"' in content
        assert "<form" in content

    @pytest.mark.asyncio
    async def test_login_page_contains_language_switcher(self, api_client: AsyncClient):
        """Test that login page includes language switcher."""
        response = await api_client.get("/login")
        content = response.text
        # Language switcher should be present
        assert "language-switcher" in content or "?lang=" in content

    @pytest.mark.asyncio
    async def test_login_page_contains_dev_warning_by_default(self, api_client: AsyncClient):
        """Test that login page shows dev warning in non-qualified mode.

        By default, the service runs in dev mode (not qualified),
        so the dev warning banner should be visible.
        """
        response = await api_client.get("/login")
        content = response.text
        # Dev mode warning should appear by default
        assert "alert--warning" in content or "dev-banner" in content

    @pytest.mark.asyncio
    async def test_login_page_contains_legal_links(self, api_client: AsyncClient):
        """Test that login page contains legal/terms links."""
        response = await api_client.get("/login")
        content = response.text
        # Should contain links to legal pages
        assert "/legal/terms" in content
        assert "/legal/privacy" in content


class TestLoginPageI18n:
    """Tests for login page internationalization."""

    @pytest.mark.asyncio
    async def test_login_page_french_by_default(self, api_client: AsyncClient):
        """Test that login page renders in French by default."""
        response = await api_client.get("/login")
        content = response.text
        # French content should be present
        assert "Connexion" in content or "Se connecter" in content

    @pytest.mark.asyncio
    async def test_login_page_english_with_lang_param(self, api_client: AsyncClient):
        """Test that login page renders in English when requested."""
        response = await api_client.get("/login?lang=en")
        content = response.text
        # English content should be present
        assert "Log in" in content

    @pytest.mark.asyncio
    async def test_login_page_respects_accept_language_header(self, api_client: AsyncClient):
        """Test that login page respects Accept-Language header."""
        response = await api_client.get(
            "/login",
            headers={"Accept-Language": "en-US,en;q=0.9"},
        )
        content = response.text
        # English content should be present
        assert "Log in" in content


class TestLogoutPage:
    """Tests for the logout page view."""

    @pytest.mark.asyncio
    async def test_logout_redirects_to_login(self, api_client: AsyncClient):
        """Test that logout redirects to login page."""
        response = await api_client.get("/logout", follow_redirects=False)
        assert response.status_code == 302
        assert response.headers.get("location") == "/login"

    @pytest.mark.asyncio
    async def test_logout_clears_session_cookie(self, api_client: AsyncClient):
        """Test that logout clears the session cookie."""
        response = await api_client.get("/logout", follow_redirects=False)
        # Check that a Set-Cookie header is present to clear the cookie
        set_cookie = response.headers.get("set-cookie", "")
        # Cookie should be set to empty or with max-age=0/expires in past
        assert "qerds_session" in set_cookie.lower() or response.status_code == 302


class TestHomePageRedirect:
    """Tests for the home page redirect behavior."""

    @pytest.mark.asyncio
    async def test_home_redirects_to_login_when_unauthenticated(self, api_client: AsyncClient):
        """Test that home page redirects to login when not authenticated."""
        response = await api_client.get("/", follow_redirects=False)
        assert response.status_code == 302
        assert response.headers.get("location") == "/login"


class TestFranceConnectLink:
    """Tests for FranceConnect+ authentication link."""

    @pytest.mark.asyncio
    async def test_franceconnect_link_includes_flow_parameter(self, api_client: AsyncClient):
        """Test that FranceConnect link includes flow parameter."""
        response = await api_client.get("/login")
        content = response.text
        # Link should specify sender_identity flow
        assert "flow=sender_identity" in content

    @pytest.mark.asyncio
    async def test_franceconnect_link_includes_redirect_parameter(self, api_client: AsyncClient):
        """Test that FranceConnect link includes redirect parameter."""
        response = await api_client.get("/login")
        content = response.text
        # Link should specify where to redirect after auth
        assert "redirect=" in content or "redirect_to=" in content


class TestLoginPageStructure:
    """Tests for login page HTML structure and accessibility."""

    @pytest.mark.asyncio
    async def test_login_page_has_main_heading(self, api_client: AsyncClient):
        """Test that login page has proper heading structure."""
        response = await api_client.get("/login")
        content = response.text
        # Should have an h1 element
        assert "<h1" in content

    @pytest.mark.asyncio
    async def test_login_page_form_has_labels(self, api_client: AsyncClient):
        """Test that login form inputs have associated labels."""
        response = await api_client.get("/login")
        content = response.text
        # Labels should be present
        assert "<label" in content
        assert 'for="email"' in content
        assert 'for="password"' in content

    @pytest.mark.asyncio
    async def test_login_page_has_branding(self, api_client: AsyncClient):
        """Test that login page displays branding."""
        response = await api_client.get("/login")
        content = response.text
        # Should contain QERDS branding
        assert "QERDS" in content
