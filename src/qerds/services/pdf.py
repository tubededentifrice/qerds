"""PDF generation service using WeasyPrint.

This module provides PDF generation for human-readable proof documents,
including delivery proofs, receipt confirmations, and verification reports.

WeasyPrint is used for its excellent CSS support and ability to embed fonts,
ensuring consistent rendering across environments. PDFs are generated from
Jinja2 HTML templates with PDF-specific styling.

Example:
    from qerds.services.pdf import PDFGenerator

    generator = PDFGenerator()

    # Render a proof document
    pdf_bytes = generator.render_proof(
        template_name="proof_of_delivery.html",
        context={
            "delivery_id": "abc123",
            "sender_name": "Jean Dupont",
            "recipient_name": "Marie Martin",
            "timestamp": "2026-01-22T10:30:00Z",
        }
    )
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import CSS, HTML

logger = logging.getLogger(__name__)

# Default template directory relative to this module
DEFAULT_TEMPLATE_DIR = Path(__file__).parent.parent / "templates" / "pdf"

# Default CSS for PDF rendering
DEFAULT_CSS_PATH = DEFAULT_TEMPLATE_DIR / "styles.css"


@dataclass(frozen=True)
class PDFResult:
    """Result of a PDF generation operation.

    Attributes:
        content: The generated PDF as bytes.
        page_count: Number of pages in the generated PDF.
        template_name: Name of the template used.
        generated_at: Timestamp of generation (ISO 8601).
    """

    content: bytes
    page_count: int
    template_name: str
    generated_at: str


class PDFGenerationError(Exception):
    """Raised when PDF generation fails.

    Attributes:
        message: Human-readable error description.
        template_name: The template that failed to render.
        cause: The underlying exception, if any.
    """

    def __init__(
        self,
        message: str,
        *,
        template_name: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        """Initialize PDF generation error.

        Args:
            message: Error description.
            template_name: Template that failed (if applicable).
            cause: Underlying exception.
        """
        self.message = message
        self.template_name = template_name
        self.cause = cause
        super().__init__(message)


class TemplateNotFoundError(PDFGenerationError):
    """Raised when a requested template does not exist."""


class PDFGenerator:
    """PDF generation service using WeasyPrint and Jinja2 templates.

    This service renders HTML templates to PDF format with consistent styling
    suitable for official proof documents. It supports:
    - French government-inspired styling
    - A4 page format with proper margins
    - Embedded fonts for consistent rendering
    - Qualification status visualization (qualified vs non-qualified)

    The generator is designed to be reusable - create one instance and call
    render methods multiple times.
    """

    def __init__(
        self,
        template_dir: Path | str | None = None,
        css_path: Path | str | None = None,
        *,
        qualification_mode: str = "non_qualified",
        base_url: str | None = None,
    ) -> None:
        """Initialize the PDF generator.

        Args:
            template_dir: Directory containing PDF templates. Defaults to
                the built-in templates/pdf directory.
            css_path: Path to the PDF stylesheet. Defaults to the built-in
                styles.css.
            qualification_mode: Either "qualified" or "non_qualified".
                Controls the seal visualization and compliance badges.
            base_url: Base URL for resolving relative URLs in templates
                (e.g., for images). If None, uses template_dir.
        """
        self._template_dir = Path(template_dir) if template_dir else DEFAULT_TEMPLATE_DIR
        self._css_path = Path(css_path) if css_path else DEFAULT_CSS_PATH
        self._qualification_mode = qualification_mode
        self._base_url = base_url or f"file://{self._template_dir}/"

        # Initialize Jinja2 environment with autoescape for HTML
        self._env = Environment(
            loader=FileSystemLoader(str(self._template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

        # Add custom filters for template rendering
        self._env.filters["format_datetime"] = self._format_datetime
        self._env.filters["format_date"] = self._format_date

        # Pre-load CSS if it exists
        self._css: CSS | None = None
        if self._css_path.exists():
            self._css = CSS(filename=str(self._css_path))

        logger.debug(
            "Initialized PDFGenerator: template_dir=%s, qualification_mode=%s",
            self._template_dir,
            self._qualification_mode,
        )

    @staticmethod
    def _format_datetime(value: str | datetime) -> str:
        """Format a datetime value for display in French locale.

        Args:
            value: ISO 8601 datetime string or datetime object.

        Returns:
            Formatted date string (e.g., "22 janvier 2026 a 10h30").
        """
        if isinstance(value, str):
            try:
                dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return value
        else:
            dt = value

        # French month names
        months = [
            "janvier",
            "fevrier",
            "mars",
            "avril",
            "mai",
            "juin",
            "juillet",
            "aout",
            "septembre",
            "octobre",
            "novembre",
            "decembre",
        ]
        month_name = months[dt.month - 1]

        return f"{dt.day} {month_name} {dt.year} a {dt.hour}h{dt.minute:02d}"

    @staticmethod
    def _format_date(value: str | datetime) -> str:
        """Format a date value for display in French locale.

        Args:
            value: ISO 8601 date string or datetime object.

        Returns:
            Formatted date string (e.g., "22 janvier 2026").
        """
        if isinstance(value, str):
            try:
                dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return value
        else:
            dt = value

        months = [
            "janvier",
            "fevrier",
            "mars",
            "avril",
            "mai",
            "juin",
            "juillet",
            "aout",
            "septembre",
            "octobre",
            "novembre",
            "decembre",
        ]
        month_name = months[dt.month - 1]

        return f"{dt.day} {month_name} {dt.year}"

    def _get_base_context(self) -> dict[str, Any]:
        """Build the base context available to all templates.

        Returns:
            Dictionary with common template variables.
        """
        return {
            "qualification_mode": self._qualification_mode,
            "is_qualified": self._qualification_mode == "qualified",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "generator_version": "1.0.0",
        }

    def render_proof(
        self,
        template_name: str,
        context: dict[str, Any] | None = None,
    ) -> PDFResult:
        """Render a proof document to PDF.

        This is the primary method for generating proof PDFs. It renders
        the specified template with the given context and returns the
        PDF bytes along with metadata.

        Args:
            template_name: Name of the template file in the templates/pdf
                directory (e.g., "proof_of_delivery.html").
            context: Template variables to pass to the template. Will be
                merged with base context (qualification_mode, etc.).

        Returns:
            PDFResult containing the PDF bytes and metadata.

        Raises:
            TemplateNotFoundError: If the template does not exist.
            PDFGenerationError: If rendering fails.
        """
        # Merge context with base context
        full_context = self._get_base_context()
        if context:
            full_context.update(context)

        try:
            # Load and render template
            template = self._env.get_template(template_name)
            html_content = template.render(**full_context)
        except Exception as e:
            if "not found" in str(e).lower() or "TemplateNotFound" in type(e).__name__:
                raise TemplateNotFoundError(
                    f"Template not found: {template_name}",
                    template_name=template_name,
                ) from e
            raise PDFGenerationError(
                f"Failed to render template: {e}",
                template_name=template_name,
                cause=e,
            ) from e

        try:
            # Generate PDF from HTML
            html_doc = HTML(
                string=html_content,
                base_url=self._base_url,
            )

            # Render with optional CSS
            stylesheets = [self._css] if self._css else None
            pdf_document = html_doc.render(stylesheets=stylesheets)
            pdf_bytes = pdf_document.write_pdf()

            logger.debug(
                "Generated PDF from template=%s, pages=%d, bytes=%d",
                template_name,
                len(pdf_document.pages),
                len(pdf_bytes),
            )

            return PDFResult(
                content=pdf_bytes,
                page_count=len(pdf_document.pages),
                template_name=template_name,
                generated_at=full_context["generated_at"],
            )

        except Exception as e:
            raise PDFGenerationError(
                f"Failed to generate PDF: {e}",
                template_name=template_name,
                cause=e,
            ) from e

    def render_html_string(
        self,
        html_content: str,
        *,
        include_css: bool = True,
    ) -> PDFResult:
        """Render arbitrary HTML string to PDF.

        This method is useful for generating PDFs from dynamically
        constructed HTML rather than templates.

        Args:
            html_content: Complete HTML document string.
            include_css: Whether to apply the default PDF stylesheet.

        Returns:
            PDFResult containing the PDF bytes and metadata.

        Raises:
            PDFGenerationError: If rendering fails.
        """
        try:
            html_doc = HTML(
                string=html_content,
                base_url=self._base_url,
            )

            stylesheets = [self._css] if (include_css and self._css) else None
            pdf_document = html_doc.render(stylesheets=stylesheets)
            pdf_bytes = pdf_document.write_pdf()

            return PDFResult(
                content=pdf_bytes,
                page_count=len(pdf_document.pages),
                template_name="<inline>",
                generated_at=datetime.utcnow().isoformat() + "Z",
            )

        except Exception as e:
            raise PDFGenerationError(
                f"Failed to generate PDF from HTML string: {e}",
                cause=e,
            ) from e

    def generate_acceptance_proof(
        self,
        evidence_data: dict[str, Any],
    ) -> PDFResult:
        """Generate a Preuve d'Acceptation (Proof of Acceptance) PDF.

        This method generates a proof of acceptance document for when a recipient
        accepts a registered electronic delivery. It is triggered by the EVT_ACCEPTED
        event and includes all required CPCE/LRE information.

        The generated PDF includes:
        - Delivery reference and timestamps
        - Sender identity and address
        - Recipient identity (revealed post-acceptance per CPCE)
        - Content hash/digest
        - Provider electronic seal
        - Timestamp authority information
        - Verification instructions

        Args:
            evidence_data: Dictionary containing acceptance evidence data.
                Required keys:
                    - delivery_id: Unique delivery identifier
                    - acceptance_timestamp: ISO 8601 timestamp of acceptance
                Optional keys:
                    - deposit_timestamp: ISO 8601 timestamp of deposit
                    - sender_name: Sender's name
                    - sender_email: Sender's email address
                    - sender_organization: Sender's organization
                    - sender_address: Sender's postal address
                    - recipient_name: Recipient's name
                    - recipient_email: Recipient's email address
                    - recipient_organization: Recipient's organization
                    - recipient_address: Recipient's postal address
                    - content_info: Dict with subject, document_count, total_size
                    - content_hash: SHA-256 hash of content
                    - hash_algorithm: Algorithm used for content hash (default: SHA-256)
                    - seal_id: Provider seal identifier
                    - signature_algorithm: Signature algorithm (default: Ed25519)
                    - provider_name: Provider name (default: QERDS)
                    - timestamp_authority: Dict with name, policy_oid, serial_number
                    - proof_id: Unique proof identifier
                    - verification_url: URL for verification

        Returns:
            PDFResult containing the generated PDF bytes and metadata.

        Raises:
            PDFGenerationError: If PDF generation fails.

        Example:
            >>> generator = PDFGenerator()
            >>> result = generator.generate_acceptance_proof({
            ...     "delivery_id": "del-abc123",
            ...     "acceptance_timestamp": "2026-01-22T14:30:00Z",
            ...     "sender_name": "Jean Dupont",
            ...     "recipient_name": "Marie Martin",
            ...     "content_hash": "e3b0c44...",
            ... })
            >>> result.content.startswith(b"%PDF")
            True
        """
        # Validate required fields
        if "delivery_id" not in evidence_data:
            raise PDFGenerationError(
                "Missing required field: delivery_id",
                template_name="proof_acceptance.html",
            )
        if "acceptance_timestamp" not in evidence_data:
            raise PDFGenerationError(
                "Missing required field: acceptance_timestamp",
                template_name="proof_acceptance.html",
            )

        logger.info(
            "Generating acceptance proof PDF for delivery_id=%s",
            evidence_data.get("delivery_id"),
        )

        return self.render_proof(
            template_name="proof_acceptance.html",
            context=evidence_data,
        )

    def get_available_templates(self) -> list[str]:
        """List available PDF templates.

        Returns:
            List of template filenames in the templates directory.
        """
        if not self._template_dir.exists():
            return []

        return [f.name for f in self._template_dir.iterdir() if f.is_file() and f.suffix == ".html"]

    @property
    def qualification_mode(self) -> str:
        """Get the current qualification mode."""
        return self._qualification_mode

    @property
    def template_dir(self) -> Path:
        """Get the template directory path."""
        return self._template_dir
