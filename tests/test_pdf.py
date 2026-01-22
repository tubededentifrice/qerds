"""Tests for PDF generation service.

Tests cover:
- PDF generation from templates
- PDF generation from raw HTML
- Template context handling
- Qualification mode rendering
- Error handling (template not found, render failures)
- Output validation (valid PDF format)
- Styling application
"""

from datetime import datetime
from pathlib import Path

import pytest

from qerds.services.pdf import (
    PDFGenerationError,
    PDFGenerator,
    PDFResult,
    TemplateNotFoundError,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def pdf_generator() -> PDFGenerator:
    """Create a PDFGenerator with default settings."""
    return PDFGenerator()


@pytest.fixture
def qualified_generator() -> PDFGenerator:
    """Create a PDFGenerator in qualified mode."""
    return PDFGenerator(qualification_mode="qualified")


@pytest.fixture
def sample_delivery_context() -> dict:
    """Sample context for delivery proof templates."""
    return {
        "delivery_id": "del-abc123-xyz789",
        "deposit_timestamp": "2026-01-22T10:30:00Z",
        "status": "Deposee",
        "status_class": "success",
        "sender_name": "Jean Dupont",
        "sender_email": "jean.dupont@example.com",
        "recipient_name": "Marie Martin",
        "recipient_email": "marie.martin@example.com",
        "content_info": {
            "subject": "Contrat de vente",
            "document_count": 2,
            "total_size": "1.5 Mo",
        },
        "content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "seal_timestamp": "2026-01-22T10:30:05Z",
        "seal_id": "seal-2026012210300500-abc123",
    }


@pytest.fixture
def temp_template_dir(tmp_path: Path) -> Path:
    """Create a temporary template directory with test templates."""
    template_dir = tmp_path / "templates"
    template_dir.mkdir()

    # Create a simple test template
    simple_template = template_dir / "simple.html"
    simple_template.write_text("""
<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<h1>{{ title }}</h1>
<p>Generated at: {{ generated_at }}</p>
<p>Mode: {{ qualification_mode }}</p>
</body>
</html>
""")

    # Create a template with date formatting
    date_template = template_dir / "with_dates.html"
    date_template.write_text("""
<!DOCTYPE html>
<html>
<head><title>Dates</title></head>
<body>
<p>Datetime: {{ timestamp|format_datetime }}</p>
<p>Date: {{ date_only|format_date }}</p>
</body>
</html>
""")

    return template_dir


# ---------------------------------------------------------------------------
# PDFResult Tests
# ---------------------------------------------------------------------------
class TestPDFResult:
    """Tests for PDFResult dataclass."""

    def test_pdf_result_creation(self):
        """Test creating a PDFResult instance."""
        result = PDFResult(
            content=b"%PDF-1.4...",
            page_count=3,
            template_name="test.html",
            generated_at="2026-01-22T10:00:00Z",
        )

        assert result.content == b"%PDF-1.4..."
        assert result.page_count == 3
        assert result.template_name == "test.html"
        assert result.generated_at == "2026-01-22T10:00:00Z"

    def test_pdf_result_is_frozen(self):
        """Test that PDFResult is immutable."""
        result = PDFResult(
            content=b"test",
            page_count=1,
            template_name="test.html",
            generated_at="2026-01-22T10:00:00Z",
        )

        with pytest.raises(AttributeError):
            result.page_count = 5


# ---------------------------------------------------------------------------
# Exception Tests
# ---------------------------------------------------------------------------
class TestPDFExceptions:
    """Tests for PDF generation exceptions."""

    def test_pdf_generation_error_attributes(self):
        """Test PDFGenerationError has context attributes."""
        cause = ValueError("Underlying error")
        error = PDFGenerationError(
            "Test error",
            template_name="test.html",
            cause=cause,
        )

        assert error.message == "Test error"
        assert error.template_name == "test.html"
        assert error.cause is cause
        assert str(error) == "Test error"

    def test_template_not_found_error(self):
        """Test TemplateNotFoundError is a PDFGenerationError."""
        error = TemplateNotFoundError(
            "Template missing",
            template_name="missing.html",
        )

        assert isinstance(error, PDFGenerationError)
        assert error.template_name == "missing.html"


# ---------------------------------------------------------------------------
# PDFGenerator Initialization Tests
# ---------------------------------------------------------------------------
class TestPDFGeneratorInit:
    """Tests for PDFGenerator initialization."""

    def test_default_initialization(self, pdf_generator: PDFGenerator):
        """Test generator initializes with defaults."""
        assert pdf_generator.qualification_mode == "non_qualified"
        assert pdf_generator.template_dir.exists()

    def test_qualified_mode_initialization(self, qualified_generator: PDFGenerator):
        """Test generator initializes in qualified mode."""
        assert qualified_generator.qualification_mode == "qualified"

    def test_custom_template_dir(self, temp_template_dir: Path):
        """Test generator with custom template directory."""
        generator = PDFGenerator(template_dir=temp_template_dir)
        assert generator.template_dir == temp_template_dir

    def test_get_available_templates(self, temp_template_dir: Path):
        """Test listing available templates."""
        generator = PDFGenerator(template_dir=temp_template_dir)
        templates = generator.get_available_templates()

        assert "simple.html" in templates
        assert "with_dates.html" in templates


# ---------------------------------------------------------------------------
# PDF Generation Tests
# ---------------------------------------------------------------------------
class TestPDFGeneration:
    """Tests for PDF generation functionality."""

    def test_render_proof_basic(self, temp_template_dir: Path):
        """Test basic PDF rendering from template."""
        generator = PDFGenerator(template_dir=temp_template_dir)

        result = generator.render_proof(
            template_name="simple.html",
            context={"title": "Test Document"},
        )

        assert isinstance(result, PDFResult)
        assert result.page_count >= 1
        assert result.template_name == "simple.html"
        assert len(result.content) > 0
        # PDF files start with %PDF
        assert result.content.startswith(b"%PDF")

    def test_render_proof_with_full_context(
        self,
        pdf_generator: PDFGenerator,
        sample_delivery_context: dict,
    ):
        """Test PDF rendering with full delivery context."""
        result = pdf_generator.render_proof(
            template_name="proof_placeholder.html",
            context=sample_delivery_context,
        )

        assert isinstance(result, PDFResult)
        assert result.content.startswith(b"%PDF")
        assert result.page_count >= 1

    def test_render_proof_qualified_mode(
        self,
        qualified_generator: PDFGenerator,
        sample_delivery_context: dict,
    ):
        """Test PDF rendering in qualified mode."""
        result = qualified_generator.render_proof(
            template_name="proof_placeholder.html",
            context=sample_delivery_context,
        )

        assert result.content.startswith(b"%PDF")
        # In qualified mode, the PDF should contain qualified text
        # (Note: We can't easily check PDF content without parsing)

    def test_render_proof_includes_base_context(self, temp_template_dir: Path):
        """Test that base context is merged with provided context."""
        generator = PDFGenerator(
            template_dir=temp_template_dir,
            qualification_mode="non_qualified",
        )

        result = generator.render_proof(
            template_name="simple.html",
            context={"title": "Custom Title"},
        )

        # Result should have generated_at timestamp
        assert result.generated_at is not None
        assert "T" in result.generated_at  # ISO format

    def test_render_proof_template_not_found(self, pdf_generator: PDFGenerator):
        """Test error when template does not exist."""
        with pytest.raises(TemplateNotFoundError) as exc_info:
            pdf_generator.render_proof(
                template_name="nonexistent_template.html",
                context={},
            )

        assert exc_info.value.template_name == "nonexistent_template.html"

    def test_render_html_string(self, pdf_generator: PDFGenerator):
        """Test PDF generation from raw HTML string."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Raw HTML Test</title></head>
        <body><h1>Test Content</h1></body>
        </html>
        """

        result = pdf_generator.render_html_string(html)

        assert result.content.startswith(b"%PDF")
        assert result.template_name == "<inline>"
        assert result.page_count >= 1

    def test_render_html_string_without_css(self, pdf_generator: PDFGenerator):
        """Test PDF generation without applying CSS."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>No CSS Test</title></head>
        <body><p>Plain content</p></body>
        </html>
        """

        result = pdf_generator.render_html_string(html, include_css=False)

        assert result.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Date Formatting Tests
# ---------------------------------------------------------------------------
class TestDateFormatting:
    """Tests for date formatting filters."""

    def test_format_datetime_filter(self, temp_template_dir: Path):
        """Test datetime formatting in templates."""
        generator = PDFGenerator(template_dir=temp_template_dir)

        result = generator.render_proof(
            template_name="with_dates.html",
            context={
                "timestamp": "2026-01-22T14:30:00Z",
                "date_only": "2026-06-15T00:00:00Z",
            },
        )

        # PDF generated successfully
        assert result.content.startswith(b"%PDF")

    def test_format_datetime_with_datetime_object(self):
        """Test formatting datetime objects directly."""
        # Test the static method directly
        dt = datetime(2026, 3, 15, 9, 45, 0)
        formatted = PDFGenerator._format_datetime(dt)

        assert "15" in formatted
        assert "mars" in formatted
        assert "2026" in formatted
        assert "9h45" in formatted

    def test_format_date_with_datetime_object(self):
        """Test formatting date only."""
        dt = datetime(2026, 12, 25, 0, 0, 0)
        formatted = PDFGenerator._format_date(dt)

        assert "25" in formatted
        assert "decembre" in formatted
        assert "2026" in formatted
        assert "h" not in formatted  # No time component

    def test_format_datetime_invalid_string(self):
        """Test formatting handles invalid date strings gracefully."""
        invalid = "not-a-date"
        result = PDFGenerator._format_datetime(invalid)
        assert result == invalid  # Returns original on failure


# ---------------------------------------------------------------------------
# PDF Validity Tests
# ---------------------------------------------------------------------------
class TestPDFValidity:
    """Tests for PDF output validity."""

    def test_pdf_starts_with_header(self, pdf_generator: PDFGenerator):
        """Test generated PDF has valid header."""
        result = pdf_generator.render_proof(
            template_name="proof_placeholder.html",
            context={"delivery_id": "test-123"},
        )

        # PDF/A files start with %PDF-
        assert result.content[:5] == b"%PDF-"

    def test_pdf_ends_with_eof(self, pdf_generator: PDFGenerator):
        """Test generated PDF has EOF marker."""
        result = pdf_generator.render_proof(
            template_name="proof_placeholder.html",
            context={"delivery_id": "test-123"},
        )

        # PDF files end with %%EOF
        assert b"%%EOF" in result.content[-32:]

    def test_pdf_has_reasonable_size(self, pdf_generator: PDFGenerator):
        """Test generated PDF has reasonable size (not empty or huge)."""
        result = pdf_generator.render_proof(
            template_name="proof_placeholder.html",
            context={"delivery_id": "test-123"},
        )

        # Minimum reasonable PDF size is around 1KB
        assert len(result.content) > 1000
        # Maximum reasonable size for a simple document is 500KB
        assert len(result.content) < 500_000

    def test_pdf_can_be_saved_to_file(
        self,
        pdf_generator: PDFGenerator,
        tmp_path: Path,
    ):
        """Test that generated PDF can be saved and read back."""
        result = pdf_generator.render_proof(
            template_name="proof_placeholder.html",
            context={"delivery_id": "file-test"},
        )

        output_file = tmp_path / "test_output.pdf"
        output_file.write_bytes(result.content)

        # Read back and verify
        read_content = output_file.read_bytes()
        assert read_content == result.content
        assert read_content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Edge Case Tests
# ---------------------------------------------------------------------------
class TestEdgeCases:
    """Tests for edge cases and special scenarios."""

    def test_empty_context(self, temp_template_dir: Path):
        """Test rendering with empty context (uses base context only)."""
        generator = PDFGenerator(template_dir=temp_template_dir)

        result = generator.render_proof(
            template_name="simple.html",
            context={},
        )

        assert result.content.startswith(b"%PDF")

    def test_none_context(self, temp_template_dir: Path):
        """Test rendering with None context."""
        generator = PDFGenerator(template_dir=temp_template_dir)

        result = generator.render_proof(
            template_name="simple.html",
            context=None,
        )

        assert result.content.startswith(b"%PDF")

    def test_unicode_content(self, pdf_generator: PDFGenerator):
        """Test rendering with unicode characters."""
        result = pdf_generator.render_proof(
            template_name="proof_placeholder.html",
            context={
                "delivery_id": "unicode-test",
                "sender_name": "Jean-Pierre Lefevre",
                "recipient_name": "Francoise Carre",
            },
        )

        assert result.content.startswith(b"%PDF")

    def test_special_characters_in_content(self, pdf_generator: PDFGenerator):
        """Test rendering with special characters that need escaping."""
        result = pdf_generator.render_proof(
            template_name="proof_placeholder.html",
            context={
                "delivery_id": "special-chars",
                "sender_name": "<script>alert('test')</script>",
                "content_info": {
                    "subject": "Test & verification <important>",
                },
            },
        )

        # Should still generate valid PDF (Jinja2 autoescaping)
        assert result.content.startswith(b"%PDF")

    def test_long_content(self, pdf_generator: PDFGenerator):
        """Test rendering with long content that spans multiple pages."""
        long_subject = "A" * 1000  # Very long subject

        result = pdf_generator.render_proof(
            template_name="proof_placeholder.html",
            context={
                "delivery_id": "long-content",
                "content_info": {
                    "subject": long_subject,
                },
            },
        )

        assert result.content.startswith(b"%PDF")
        # May span multiple pages
        assert result.page_count >= 1


# ---------------------------------------------------------------------------
# Styling Tests
# ---------------------------------------------------------------------------
class TestStyling:
    """Tests for CSS styling application."""

    def test_custom_css_file(self, temp_template_dir: Path):
        """Test using a custom CSS file."""
        # Create custom CSS
        css_file = temp_template_dir / "custom.css"
        css_file.write_text("""
            body { font-family: sans-serif; }
            h1 { color: red; }
        """)

        generator = PDFGenerator(
            template_dir=temp_template_dir,
            css_path=css_file,
        )

        result = generator.render_proof(
            template_name="simple.html",
            context={"title": "Styled"},
        )

        assert result.content.startswith(b"%PDF")

    def test_missing_css_file_handled(self, temp_template_dir: Path):
        """Test that missing CSS file is handled gracefully."""
        generator = PDFGenerator(
            template_dir=temp_template_dir,
            css_path=temp_template_dir / "nonexistent.css",
        )

        # Should still work, just without custom CSS
        result = generator.render_proof(
            template_name="simple.html",
            context={"title": "No CSS"},
        )

        assert result.content.startswith(b"%PDF")
