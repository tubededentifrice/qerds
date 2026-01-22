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

    def get_available_templates(self) -> list[str]:
        """List available PDF templates.

        Returns:
            List of template filenames in the templates directory.
        """
        if not self._template_dir.exists():
            return []

        return [f.name for f in self._template_dir.iterdir() if f.is_file() and f.suffix == ".html"]

    def generate_deposit_proof(
        self,
        *,
        delivery_id: str,
        deposit_timestamp: str | datetime,
        sender_name: str,
        recipient_name: str,
        recipient_email: str,
        content_hash: str,
        subject: str | None = None,
        sender_email: str | None = None,
        sender_address: str | None = None,
        sender_organization: str | None = None,
        recipient_organization: str | None = None,
        content_info: dict[str, Any] | None = None,
        seal_id: str | None = None,
        seal_timestamp: str | datetime | None = None,
        signature_algorithm: str = "Ed25519",
        tsa_info: dict[str, str] | None = None,
        proof_id: str | None = None,
        verification_url: str | None = None,
    ) -> PDFResult:
        """Generate a Preuve de Depot (Proof of Deposit) PDF.

        Generates the proof of deposit document per CPCE/LRE requirements,
        emitted at EVT_DEPOSITED event. Covers REQ-B01, REQ-F01, REQ-F07.

        The generated PDF contains:
        - Provider header with qualification status
        - Document title: "Preuve de Depot"
        - Delivery reference (ID) and deposit timestamp
        - Sender identity and address
        - Recipient identity and email
        - Subject line (if provided)
        - Content hash/digest for integrity verification
        - Provider seal visualization
        - Timestamp authority information
        - Verification instructions with proof ID and URL
        - Qualification label (qualified/non-qualified)

        Args:
            delivery_id: Unique delivery reference identifier.
            deposit_timestamp: Timestamp when the deposit occurred (ISO 8601 or datetime).
            sender_name: Full name of the sender.
            recipient_name: Full name of the recipient.
            recipient_email: Email address of the recipient.
            content_hash: SHA-256 hash of the delivered content.
            subject: Subject line of the delivery (optional).
            sender_email: Email address of the sender (optional).
            sender_address: Physical address of the sender (optional).
            sender_organization: Organization name of the sender (optional).
            recipient_organization: Organization name of the recipient (optional).
            content_info: Additional content metadata (document_count, total_size).
            seal_id: Provider seal identifier (optional).
            seal_timestamp: Timestamp of the seal (optional, defaults to deposit_timestamp).
            signature_algorithm: Algorithm used for seal signature (default: Ed25519).
            tsa_info: Timestamp authority information dict with keys:
                name, policy_oid, token_id (all optional).
            proof_id: Unique identifier for this proof document (optional).
            verification_url: URL for verifying this proof (optional).

        Returns:
            PDFResult containing the PDF bytes and metadata.

        Raises:
            TemplateNotFoundError: If the deposit template is missing.
            PDFGenerationError: If PDF rendering fails.

        Example:
            result = generator.generate_deposit_proof(
                delivery_id="del-abc123-xyz789",
                deposit_timestamp="2026-01-22T10:30:00Z",
                sender_name="Jean Dupont",
                recipient_name="Marie Martin",
                recipient_email="marie.martin@example.com",
                content_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                subject="Contrat de vente",
                proof_id="PRF-2026-0122-ABC123",
                verification_url="https://verify.qerds.example.com",
            )
        """
        context: dict[str, Any] = {
            "delivery_id": delivery_id,
            "deposit_timestamp": deposit_timestamp,
            "sender_name": sender_name,
            "recipient_name": recipient_name,
            "recipient_email": recipient_email,
            "content_hash": content_hash,
            "signature_algorithm": signature_algorithm,
        }

        # Add optional fields only if provided
        if subject:
            context["subject"] = subject
        if sender_email:
            context["sender_email"] = sender_email
        if sender_address:
            context["sender_address"] = sender_address
        if sender_organization:
            context["sender_organization"] = sender_organization
        if recipient_organization:
            context["recipient_organization"] = recipient_organization
        if content_info:
            context["content_info"] = content_info
        if seal_id:
            context["seal_id"] = seal_id
        if seal_timestamp:
            context["seal_timestamp"] = seal_timestamp
        if tsa_info:
            context["tsa_info"] = tsa_info
        if proof_id:
            context["proof_id"] = proof_id
        if verification_url:
            context["verification_url"] = verification_url

        logger.debug(
            "Generating deposit proof PDF for delivery_id=%s",
            delivery_id,
        )

        return self.render_proof(template_name="deposit.html", context=context)

    @property
    def qualification_mode(self) -> str:
        """Get the current qualification mode."""
        return self._qualification_mode

    @property
    def template_dir(self) -> Path:
        """Get the template directory path."""
        return self._template_dir
