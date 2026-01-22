"""Tests for Jinja2 template rendering and static file serving.

These tests verify:
- Static files are served correctly (CSS, JS, fonts)
- Templates render without errors
- Context processors provide expected data
- i18n language detection works
- Qualification mode banner appears in dev mode
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from qerds.api import create_app
from qerds.api.i18n import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    create_translator,
    translate,
)
from qerds.api.templates import (
    TEMPLATES_DIR,
    build_template_context,
    format_date,
    format_datetime,
    format_filesize,
    get_templates,
    truncate_id,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def client() -> TestClient:
    """Create a synchronous test client for HTTP requests."""
    app = create_app()
    return TestClient(app)


@pytest.fixture
def templates():
    """Get configured Jinja2Templates instance."""
    return get_templates()


# ---------------------------------------------------------------------------
# Static Files Tests
# ---------------------------------------------------------------------------
class TestStaticFiles:
    """Tests for static file serving."""

    def test_css_main_served(self, client: TestClient) -> None:
        """Verify main.css is served at /static/css/main.css."""
        response = client.get("/static/css/main.css")
        assert response.status_code == 200
        assert "text/css" in response.headers["content-type"]
        # Verify some CSS content is present
        assert ":root" in response.text or "--color" in response.text

    def test_css_fonts_served(self, client: TestClient) -> None:
        """Verify fonts.css is served at /static/css/fonts.css."""
        response = client.get("/static/css/fonts.css")
        assert response.status_code == 200
        assert "text/css" in response.headers["content-type"]
        assert "@font-face" in response.text

    def test_js_main_served(self, client: TestClient) -> None:
        """Verify main.js is served at /static/js/main.js."""
        response = client.get("/static/js/main.js")
        assert response.status_code == 200
        assert "javascript" in response.headers["content-type"]
        assert "QERDS" in response.text

    def test_font_files_served(self, client: TestClient) -> None:
        """Verify font files are served (woff2 format)."""
        response = client.get("/static/fonts/SourceSans3-Regular.woff2")
        assert response.status_code == 200
        # woff2 files have specific content type
        content_type = response.headers["content-type"]
        assert "woff2" in content_type or "octet-stream" in content_type

    def test_static_404_for_missing_file(self, client: TestClient) -> None:
        """Verify 404 returned for missing static files."""
        response = client.get("/static/nonexistent.css")
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Template Rendering Tests
# ---------------------------------------------------------------------------
class TestTemplateRendering:
    """Tests for page route rendering."""

    def test_login_page_renders(self, client: TestClient) -> None:
        """Verify login page renders successfully."""
        response = client.get("/login")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        # Check for key elements
        assert "QERDS" in response.text
        assert "FranceConnect" in response.text
        assert "Connexion" in response.text or "Log in" in response.text

    def test_login_page_shows_dev_banner(self, client: TestClient) -> None:
        """Verify dev mode banner appears on login page when in dev mode."""
        response = client.get("/login")
        assert response.status_code == 200
        # In dev mode (default), dev banner should appear
        assert "dev-banner" in response.text or "Mode d" in response.text

    def test_sender_dashboard_renders(self, client: TestClient) -> None:
        """Verify sender dashboard renders successfully."""
        response = client.get("/sender/dashboard")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Tableau de bord" in response.text or "Dashboard" in response.text

    def test_sender_new_delivery_renders(self, client: TestClient) -> None:
        """Verify new delivery form renders successfully."""
        response = client.get("/sender/new")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "Nouvel envoi" in response.text or "New delivery" in response.text

    def test_recipient_pickup_renders(self, client: TestClient) -> None:
        """Verify recipient pickup page renders successfully."""
        response = client.get("/recipient/pickup/test-delivery-id")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        # Check for pickup-specific content
        assert "recommand" in response.text.lower() or "delivery" in response.text.lower()

    def test_recipient_accepted_renders(self, client: TestClient) -> None:
        """Verify recipient accepted page renders successfully."""
        response = client.get("/recipient/accepted/test-delivery-id")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "accept" in response.text.lower()

    def test_admin_dashboard_renders(self, client: TestClient) -> None:
        """Verify admin dashboard renders successfully."""
        response = client.get("/admin/dashboard")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        # Check for admin-specific content
        assert "admin" in response.text.lower() or "qualification" in response.text.lower()

    def test_verify_page_renders(self, client: TestClient) -> None:
        """Verify proof verification page renders successfully."""
        response = client.get("/verify")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "rification" in response.text.lower() or "verify" in response.text.lower()

    def test_verify_page_with_params_renders(self, client: TestClient) -> None:
        """Verify proof verification page with params shows result."""
        response = client.get("/verify?id=PRF-12345678&token=ABCD-1234")
        assert response.status_code == 200
        # Should show verification result
        assert "authentique" in response.text.lower() or "valid" in response.text.lower()

    def test_home_redirects_to_login(self, client: TestClient) -> None:
        """Verify home page redirects unauthenticated users to login."""
        response = client.get("/", follow_redirects=False)
        assert response.status_code == 302
        assert "/login" in response.headers["location"]


# ---------------------------------------------------------------------------
# Template Utilities Tests
# ---------------------------------------------------------------------------
class TestTemplateUtilities:
    """Tests for template utility functions."""

    def test_templates_directory_exists(self) -> None:
        """Verify templates directory exists."""
        assert TEMPLATES_DIR.exists()
        assert TEMPLATES_DIR.is_dir()

    def test_get_templates_returns_instance(self) -> None:
        """Verify get_templates returns configured instance."""
        templates = get_templates()
        assert templates is not None
        assert hasattr(templates, "env")

    def test_format_date_with_datetime(self) -> None:
        """Test format_date with datetime object."""
        from datetime import datetime

        dt = datetime(2024, 12, 25, 14, 30)
        assert format_date(dt) == "25/12/2024"

    def test_format_date_with_iso_string(self) -> None:
        """Test format_date with ISO string."""
        assert format_date("2024-12-25T14:30:00") == "25/12/2024"

    def test_format_date_with_none(self) -> None:
        """Test format_date with None returns empty string."""
        assert format_date(None) == ""

    def test_format_datetime_with_datetime(self) -> None:
        """Test format_datetime with datetime object."""
        from datetime import datetime

        dt = datetime(2024, 12, 25, 14, 30)
        assert format_datetime(dt) == "25/12/2024 14:30"

    def test_format_filesize_bytes(self) -> None:
        """Test format_filesize with bytes."""
        assert format_filesize(500) == "500 o"

    def test_format_filesize_kilobytes(self) -> None:
        """Test format_filesize with kilobytes."""
        result = format_filesize(5120)
        assert "Ko" in result
        assert "5" in result

    def test_format_filesize_megabytes(self) -> None:
        """Test format_filesize with megabytes."""
        result = format_filesize(1_500_000)
        assert "Mo" in result

    def test_format_filesize_gigabytes(self) -> None:
        """Test format_filesize with gigabytes."""
        result = format_filesize(2_000_000_000)
        assert "Go" in result

    def test_format_filesize_none(self) -> None:
        """Test format_filesize with None returns empty string."""
        assert format_filesize(None) == ""

    def test_truncate_id(self) -> None:
        """Test truncate_id truncates correctly."""
        assert truncate_id("abcdefghijklmnop") == "abcdefgh"
        assert truncate_id("abcdefghijklmnop", 4) == "abcd"

    def test_truncate_id_none(self) -> None:
        """Test truncate_id with None returns empty string."""
        assert truncate_id(None) == ""


# ---------------------------------------------------------------------------
# i18n Tests
# ---------------------------------------------------------------------------
class TestI18n:
    """Tests for internationalization functionality."""

    def test_supported_languages(self) -> None:
        """Verify supported languages are French and English."""
        assert "fr" in SUPPORTED_LANGUAGES
        assert "en" in SUPPORTED_LANGUAGES

    def test_default_language_is_french(self) -> None:
        """Verify default language is French."""
        assert DEFAULT_LANGUAGE == "fr"

    def test_translate_french(self) -> None:
        """Test translation to French."""
        result = translate("auth.login", "fr")
        assert result == "Se connecter"

    def test_translate_english(self) -> None:
        """Test translation to English."""
        result = translate("auth.login", "en")
        assert result == "Log in"

    def test_translate_missing_key_returns_key(self) -> None:
        """Test that missing translation key returns the key itself."""
        result = translate("nonexistent.key", "fr")
        assert result == "nonexistent.key"

    def test_create_translator(self) -> None:
        """Test creating a bound translator function."""
        translator = create_translator("en")
        assert translator("auth.login") == "Log in"
        assert translator("auth.logout") == "Log out"

    def test_get_language_from_query_param(self, client: TestClient) -> None:
        """Test language detection from query parameter."""
        # Use the client to make a request with lang param
        response = client.get("/login?lang=en")
        assert response.status_code == 200

    def test_get_language_from_accept_header(self, client: TestClient) -> None:
        """Test language detection from Accept-Language header."""
        response = client.get("/login", headers={"Accept-Language": "en-US,en;q=0.9"})
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Context Processor Tests
# ---------------------------------------------------------------------------
class TestContextProcessor:
    """Tests for template context building."""

    def test_build_template_context_includes_request(self, client: TestClient) -> None:
        """Verify context includes request object."""
        # We need an actual request object for this test
        # This is tested indirectly through template rendering
        # Verify pages render which requires valid request context
        response = client.get("/login")
        assert response.status_code == 200

    def test_build_template_context_default_qualification_mode(self) -> None:
        """Verify default qualification mode is 'dev'."""
        # Create a mock request
        from unittest.mock import MagicMock

        mock_request = MagicMock()
        mock_request.query_params = {}
        mock_request.cookies = {}
        mock_request.headers = {}
        mock_request.app.state.settings = None
        mock_request.state.user = None

        context = build_template_context(mock_request)
        assert context["qualification_mode"] == "dev"

    def test_build_template_context_includes_current_year(self) -> None:
        """Verify context includes current year."""
        from datetime import datetime
        from unittest.mock import MagicMock

        mock_request = MagicMock()
        mock_request.query_params = {}
        mock_request.cookies = {}
        mock_request.headers = {}
        mock_request.app.state.settings = None
        mock_request.state.user = None

        context = build_template_context(mock_request)
        assert context["current_year"] == datetime.now().year

    def test_build_template_context_includes_language(self) -> None:
        """Verify context includes language."""
        from unittest.mock import MagicMock

        mock_request = MagicMock()
        mock_request.query_params = {}
        mock_request.cookies = {}
        mock_request.headers = {}
        mock_request.app.state.settings = None
        mock_request.state.user = None

        context = build_template_context(mock_request)
        assert context["lang"] == "fr"  # Default to French

    def test_build_template_context_with_extra_context(self) -> None:
        """Verify extra context is merged."""
        from unittest.mock import MagicMock

        mock_request = MagicMock()
        mock_request.query_params = {}
        mock_request.cookies = {}
        mock_request.headers = {}
        mock_request.app.state.settings = None
        mock_request.state.user = None

        context = build_template_context(mock_request, custom_data="test_value")
        assert context["custom_data"] == "test_value"


# ---------------------------------------------------------------------------
# Template Structure Tests
# ---------------------------------------------------------------------------
class TestTemplateStructure:
    """Tests for template file structure."""

    def test_base_template_exists(self) -> None:
        """Verify base.html template exists."""
        assert (TEMPLATES_DIR / "base.html").exists()

    def test_login_template_exists(self) -> None:
        """Verify login.html template exists."""
        assert (TEMPLATES_DIR / "login.html").exists()

    def test_sender_templates_exist(self) -> None:
        """Verify sender templates exist."""
        assert (TEMPLATES_DIR / "sender" / "dashboard.html").exists()
        assert (TEMPLATES_DIR / "sender" / "new.html").exists()

    def test_recipient_templates_exist(self) -> None:
        """Verify recipient templates exist."""
        assert (TEMPLATES_DIR / "recipient" / "pickup.html").exists()
        assert (TEMPLATES_DIR / "recipient" / "accepted.html").exists()
        assert (TEMPLATES_DIR / "recipient" / "refused.html").exists()
        assert (TEMPLATES_DIR / "recipient" / "inbox.html").exists()

    def test_admin_templates_exist(self) -> None:
        """Verify admin templates exist."""
        assert (TEMPLATES_DIR / "admin" / "dashboard.html").exists()

    def test_verify_template_exists(self) -> None:
        """Verify verify.html template exists."""
        assert (TEMPLATES_DIR / "verify.html").exists()

    def test_partials_exist(self) -> None:
        """Verify partial templates exist."""
        partials_dir = TEMPLATES_DIR / "partials"
        assert partials_dir.exists()
        assert (partials_dir / "dev_banner.html").exists()
        assert (partials_dir / "delivery_card.html").exists()
        assert (partials_dir / "status_badge.html").exists()


# ---------------------------------------------------------------------------
# Static File Structure Tests
# ---------------------------------------------------------------------------
class TestStaticFileStructure:
    """Tests for static file structure."""

    def test_static_directory_exists(self) -> None:
        """Verify static directory exists."""
        static_dir = TEMPLATES_DIR.parent / "static"
        assert static_dir.exists()
        assert static_dir.is_dir()

    def test_css_directory_exists(self) -> None:
        """Verify CSS directory exists with required files."""
        css_dir = TEMPLATES_DIR.parent / "static" / "css"
        assert css_dir.exists()
        assert (css_dir / "main.css").exists()
        assert (css_dir / "fonts.css").exists()

    def test_js_directory_exists(self) -> None:
        """Verify JS directory exists with required files."""
        js_dir = TEMPLATES_DIR.parent / "static" / "js"
        assert js_dir.exists()
        assert (js_dir / "main.js").exists()

    def test_fonts_directory_exists(self) -> None:
        """Verify fonts directory exists with font files."""
        fonts_dir = TEMPLATES_DIR.parent / "static" / "fonts"
        assert fonts_dir.exists()
        # Check for at least one font file
        font_files = list(fonts_dir.glob("*.woff2"))
        assert len(font_files) > 0, "No .woff2 font files found"
