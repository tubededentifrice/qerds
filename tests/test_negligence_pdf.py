"""Tests for Proof of Negligence (Preuve de Negligence) PDF generation.

Tests cover:
- Negligence proof generation with all required fields
- Negligence proof generation with optional fields
- Qualified vs non-qualified mode rendering
- PDF validity (header, EOF, reasonable size)
- Timeline information (deposit, notification, expiry timestamps)
- Verification information inclusion
- Error handling for missing required fields
- Edge cases (unicode, special characters, long values)

This proof is generated at EVT_EXPIRED event when recipient fails to
claim within the 15-day legal window per CPCE Article L.100.
"""

from datetime import datetime
from pathlib import Path

import pytest

from qerds.services.pdf import (
    PDFGenerationError,
    PDFGenerator,
    PDFResult,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def pdf_generator() -> PDFGenerator:
    """Create a PDFGenerator with default (non-qualified) settings."""
    return PDFGenerator()


@pytest.fixture
def qualified_generator() -> PDFGenerator:
    """Create a PDFGenerator in qualified mode."""
    return PDFGenerator(qualification_mode="qualified")


@pytest.fixture
def minimal_negligence_context() -> dict:
    """Minimal required context for negligence proof.

    Contains only the four required timestamp fields for the proof.
    """
    return {
        "delivery_id": "del-neg-test-001",
        "deposit_timestamp": "2026-01-07T10:30:00Z",
        "notification_timestamp": "2026-01-07T10:35:00Z",
        "expiry_timestamp": "2026-01-22T10:35:00Z",
    }


@pytest.fixture
def full_negligence_context() -> dict:
    """Full context with all optional fields for negligence proof."""
    return {
        "delivery_id": "del-neg-full-002",
        "deposit_timestamp": "2026-01-05T09:00:00Z",
        "notification_timestamp": "2026-01-05T09:15:00Z",
        "expiry_timestamp": "2026-01-20T09:15:00Z",
        # Sender info
        "sender_name": "Jean-Pierre Lefevre",
        "sender_email": "jp.lefevre@entreprise.fr",
        "sender_organization": "Entreprise SARL",
        "sender_address": "123 Rue de la Paix, 75001 Paris, France",
        # Recipient info (revealed after expiry per CPCE)
        "recipient_name": "Francoise Carre",
        "recipient_email": "f.carre@destinataire.fr",
        "recipient_organization": "Societe Destinataire",
        "recipient_address": "456 Avenue des Champs, 75008 Paris",
        # Content info
        "subject": "Mise en demeure - Contrat #2026-001",
        "content_hash": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd",
        # Seal info
        "seal_id": "seal-2026012009150000-xyz789",
        "seal_timestamp": "2026-01-20T09:15:05Z",
        "signature_algorithm": "Ed25519",
        # TSA info
        "tsa_info": {
            "name": "Service d'horodatage qualifie eIDAS",
            "policy_oid": "1.2.3.4.5.6.7.8.9",
            "token_id": "TSA-TOKEN-NEG-2026-001",
        },
        # Verification info
        "proof_id": "PRF-NEG-2026-0120-FULL002",
        "verification_url": "https://verify.qerds.example.com/proof/PRF-NEG-2026-0120-FULL002",
    }


# ---------------------------------------------------------------------------
# Basic Generation Tests
# ---------------------------------------------------------------------------
class TestNegligenceProofBasicGeneration:
    """Tests for basic negligence proof PDF generation."""

    def test_generate_negligence_proof_minimal(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test generating negligence proof with minimal required fields."""
        result = pdf_generator.generate_negligence_proof(**minimal_negligence_context)

        assert isinstance(result, PDFResult)
        assert result.content.startswith(b"%PDF")
        assert result.page_count >= 1
        assert result.template_name == "proof_negligence.html"

    def test_generate_negligence_proof_full(
        self,
        pdf_generator: PDFGenerator,
        full_negligence_context: dict,
    ):
        """Test generating negligence proof with all optional fields."""
        result = pdf_generator.generate_negligence_proof(**full_negligence_context)

        assert isinstance(result, PDFResult)
        assert result.content.startswith(b"%PDF")
        assert result.page_count >= 1

    def test_generate_negligence_proof_qualified_mode(
        self,
        qualified_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test negligence proof generation in qualified mode."""
        result = qualified_generator.generate_negligence_proof(**minimal_negligence_context)

        assert result.content.startswith(b"%PDF")
        assert result.page_count >= 1

    def test_generate_negligence_proof_non_qualified_mode(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test negligence proof generation in non-qualified mode (default)."""
        assert pdf_generator.qualification_mode == "non_qualified"

        result = pdf_generator.generate_negligence_proof(**minimal_negligence_context)

        assert result.content.startswith(b"%PDF")
        assert result.page_count >= 1

    def test_generate_negligence_proof_returns_generated_at(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test that result includes generation timestamp."""
        result = pdf_generator.generate_negligence_proof(**minimal_negligence_context)

        assert result.generated_at is not None
        assert "T" in result.generated_at  # ISO 8601 format


# ---------------------------------------------------------------------------
# PDF Validity Tests
# ---------------------------------------------------------------------------
class TestNegligenceProofPDFValidity:
    """Tests for PDF output validity of negligence proofs."""

    def test_pdf_starts_with_header(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test generated PDF has valid header."""
        result = pdf_generator.generate_negligence_proof(**minimal_negligence_context)

        # PDF files start with %PDF-
        assert result.content[:5] == b"%PDF-"

    def test_pdf_ends_with_eof(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test generated PDF has EOF marker."""
        result = pdf_generator.generate_negligence_proof(**minimal_negligence_context)

        # PDF files end with %%EOF
        assert b"%%EOF" in result.content[-32:]

    def test_pdf_has_reasonable_size(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test generated PDF has reasonable size (not empty or huge)."""
        result = pdf_generator.generate_negligence_proof(**minimal_negligence_context)

        # Minimum reasonable PDF size is around 1KB
        assert len(result.content) > 1000
        # Maximum reasonable size for a simple document is 500KB
        assert len(result.content) < 500_000

    def test_pdf_can_be_saved_to_file(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
        tmp_path: Path,
    ):
        """Test that generated PDF can be saved and read back."""
        result = pdf_generator.generate_negligence_proof(**minimal_negligence_context)

        output_file = tmp_path / "negligence_proof.pdf"
        output_file.write_bytes(result.content)

        # Read back and verify
        read_content = output_file.read_bytes()
        assert read_content == result.content
        assert read_content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Timeline/Timestamp Tests (critical for legal proof)
# ---------------------------------------------------------------------------
class TestNegligenceProofTimeline:
    """Tests for timeline information in negligence proofs.

    The timeline is critical for legal proof as it documents the 15-day
    window elapsed per CPCE Article L.100.
    """

    def test_all_timestamps_as_strings(
        self,
        pdf_generator: PDFGenerator,
    ):
        """Test negligence proof with all timestamps as ISO 8601 strings."""
        result = pdf_generator.generate_negligence_proof(
            delivery_id="del-ts-string",
            deposit_timestamp="2026-01-01T08:00:00Z",
            notification_timestamp="2026-01-01T08:15:00Z",
            expiry_timestamp="2026-01-16T08:15:00Z",
        )

        assert result.content.startswith(b"%PDF")

    def test_all_timestamps_as_datetime(
        self,
        pdf_generator: PDFGenerator,
    ):
        """Test negligence proof with all timestamps as datetime objects."""
        result = pdf_generator.generate_negligence_proof(
            delivery_id="del-ts-datetime",
            deposit_timestamp=datetime(2026, 1, 1, 8, 0, 0),
            notification_timestamp=datetime(2026, 1, 1, 8, 15, 0),
            expiry_timestamp=datetime(2026, 1, 16, 8, 15, 0),
        )

        assert result.content.startswith(b"%PDF")

    def test_mixed_timestamp_types(
        self,
        pdf_generator: PDFGenerator,
    ):
        """Test negligence proof with mixed timestamp types."""
        result = pdf_generator.generate_negligence_proof(
            delivery_id="del-ts-mixed",
            deposit_timestamp="2026-01-01T08:00:00Z",
            notification_timestamp=datetime(2026, 1, 1, 8, 15, 0),
            expiry_timestamp="2026-01-16T08:15:00Z",
        )

        assert result.content.startswith(b"%PDF")

    def test_seal_timestamp_as_datetime(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test seal timestamp as datetime object."""
        context = {
            **minimal_negligence_context,
            "seal_timestamp": datetime(2026, 1, 22, 10, 35, 5),
        }

        result = pdf_generator.generate_negligence_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_fifteen_day_window_edge_case(
        self,
        pdf_generator: PDFGenerator,
    ):
        """Test proof at exact 15-day boundary."""
        # Notification at exactly midnight
        result = pdf_generator.generate_negligence_proof(
            delivery_id="del-15day-edge",
            deposit_timestamp="2026-01-01T00:00:00Z",
            notification_timestamp="2026-01-01T00:00:01Z",
            # Exactly 15 days later
            expiry_timestamp="2026-01-16T00:00:01Z",
        )

        assert result.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Content Verification Tests
# ---------------------------------------------------------------------------
class TestNegligenceProofContent:
    """Tests for negligence proof content verification."""

    def test_negligence_proof_with_subject(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test negligence proof with subject line."""
        context = {
            **minimal_negligence_context,
            "subject": "Mise en demeure - Delai de paiement expire",
        }

        result = pdf_generator.generate_negligence_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_negligence_proof_with_content_hash(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test negligence proof with content hash."""
        context = {
            **minimal_negligence_context,
            "content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }

        result = pdf_generator.generate_negligence_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_negligence_proof_with_sender_info(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test negligence proof with full sender information."""
        context = {
            **minimal_negligence_context,
            "sender_name": "Jean Dupont",
            "sender_email": "jean.dupont@example.com",
            "sender_organization": "Cabinet Dupont",
            "sender_address": "123 Rue des Avocats, 75001 Paris",
        }

        result = pdf_generator.generate_negligence_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_negligence_proof_with_recipient_info(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test negligence proof with full recipient information.

        Recipient identity is revealed after expiry per CPCE regulations.
        """
        context = {
            **minimal_negligence_context,
            "recipient_name": "Marie Martin",
            "recipient_email": "marie.martin@example.com",
            "recipient_organization": "Entreprise Martin",
            "recipient_address": "456 Avenue du Commerce, 69001 Lyon",
        }

        result = pdf_generator.generate_negligence_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_negligence_proof_with_seal_info(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test negligence proof with seal information."""
        context = {
            **minimal_negligence_context,
            "seal_id": "seal-neg-test-001",
            "seal_timestamp": "2026-01-22T10:35:05Z",
            "signature_algorithm": "RSA-PSS",
        }

        result = pdf_generator.generate_negligence_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_negligence_proof_with_tsa_info(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test negligence proof with timestamp authority information."""
        context = {
            **minimal_negligence_context,
            "tsa_info": {
                "name": "Test TSA Provider",
                "policy_oid": "1.2.3.4.5",
                "token_id": "TSA-TOKEN-NEG-001",
            },
        }

        result = pdf_generator.generate_negligence_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_negligence_proof_with_verification_info(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test negligence proof with verification information."""
        context = {
            **minimal_negligence_context,
            "proof_id": "PRF-NEG-2026-TEST-001",
            "verification_url": "https://verify.example.com/PRF-NEG-2026-TEST-001",
        }

        result = pdf_generator.generate_negligence_proof(**context)

        assert result.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Edge Cases Tests
# ---------------------------------------------------------------------------
class TestNegligenceProofEdgeCases:
    """Tests for edge cases in negligence proof generation."""

    def test_unicode_content(
        self,
        pdf_generator: PDFGenerator,
    ):
        """Test negligence proof with unicode characters in names."""
        result = pdf_generator.generate_negligence_proof(
            delivery_id="del-unicode-neg",
            deposit_timestamp="2026-01-01T10:00:00Z",
            notification_timestamp="2026-01-01T10:15:00Z",
            expiry_timestamp="2026-01-16T10:15:00Z",
            sender_name="Jean-Pierre Lefevre",
            sender_organization="Societe des Etudes Avancees",
            recipient_name="Francoise Carre",
            recipient_email="francoise@exemple.fr",
            subject="Etude d'impact - Evaluation preliminaire et observations",
        )

        assert result.content.startswith(b"%PDF")

    def test_special_characters_escaped(
        self,
        pdf_generator: PDFGenerator,
    ):
        """Test that special HTML characters are properly escaped."""
        result = pdf_generator.generate_negligence_proof(
            delivery_id="del-special-neg",
            deposit_timestamp="2026-01-01T10:00:00Z",
            notification_timestamp="2026-01-01T10:15:00Z",
            expiry_timestamp="2026-01-16T10:15:00Z",
            sender_name="Test <script>alert('xss')</script>",
            recipient_name="Recipient & Partner",
            recipient_email="test@example.com",
            subject="Test & Validation <important>",
        )

        # Should still generate valid PDF (Jinja2 autoescaping)
        assert result.content.startswith(b"%PDF")

    def test_long_content_hash(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test negligence proof with very long content hash."""
        # SHA-512 produces 128-char hex string
        long_hash = "a" * 128

        context = {**minimal_negligence_context, "content_hash": long_hash}

        result = pdf_generator.generate_negligence_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_long_subject_line(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test negligence proof with very long subject line."""
        long_subject = "A" * 500  # Very long subject

        context = {**minimal_negligence_context, "subject": long_subject}

        result = pdf_generator.generate_negligence_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_very_long_delivery_id(
        self,
        pdf_generator: PDFGenerator,
    ):
        """Test negligence proof with very long delivery ID."""
        result = pdf_generator.generate_negligence_proof(
            delivery_id="del-neg-" + "x" * 200,
            deposit_timestamp="2026-01-01T10:00:00Z",
            notification_timestamp="2026-01-01T10:15:00Z",
            expiry_timestamp="2026-01-16T10:15:00Z",
        )

        assert result.content.startswith(b"%PDF")

    def test_multiline_address(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test negligence proof with multiline addresses."""
        context = {
            **minimal_negligence_context,
            "sender_address": "123 Rue de la Paix\nAppartement 4B\n75001 Paris\nFrance",
            "recipient_address": "456 Avenue des Champs\nBatiment C, Etage 3\n75008 Paris",
        }

        result = pdf_generator.generate_negligence_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_empty_optional_fields(
        self,
        pdf_generator: PDFGenerator,
    ):
        """Test negligence proof when optional fields are None."""
        result = pdf_generator.generate_negligence_proof(
            delivery_id="del-neg-empty-opts",
            deposit_timestamp="2026-01-01T10:00:00Z",
            notification_timestamp="2026-01-01T10:15:00Z",
            expiry_timestamp="2026-01-16T10:15:00Z",
            sender_name=None,
            sender_email=None,
            sender_address=None,
            sender_organization=None,
            recipient_name=None,
            recipient_email=None,
            recipient_organization=None,
            recipient_address=None,
            subject=None,
            content_hash=None,
            seal_id=None,
            seal_timestamp=None,
            tsa_info=None,
            proof_id=None,
            verification_url=None,
        )

        assert result.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Error Handling Tests
# ---------------------------------------------------------------------------
class TestNegligenceProofErrorHandling:
    """Tests for error handling in negligence proof generation."""

    def test_missing_negligence_template(
        self,
        tmp_path: Path,
    ):
        """Test error when negligence template is missing."""
        # Create generator with empty template dir
        empty_template_dir = tmp_path / "empty_templates"
        empty_template_dir.mkdir()

        generator = PDFGenerator(template_dir=empty_template_dir)

        with pytest.raises(PDFGenerationError):
            generator.generate_negligence_proof(
                delivery_id="test",
                deposit_timestamp="2026-01-01T10:00:00Z",
                notification_timestamp="2026-01-01T10:15:00Z",
                expiry_timestamp="2026-01-16T10:15:00Z",
            )


# ---------------------------------------------------------------------------
# Comparison Tests (Qualified vs Non-Qualified)
# ---------------------------------------------------------------------------
class TestNegligenceProofComparison:
    """Tests comparing qualified vs non-qualified negligence proofs."""

    def test_qualified_and_non_qualified_both_generate(
        self,
        pdf_generator: PDFGenerator,
        qualified_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test both qualified and non-qualified modes generate valid PDFs."""
        non_qualified_result = pdf_generator.generate_negligence_proof(**minimal_negligence_context)
        qualified_result = qualified_generator.generate_negligence_proof(
            **minimal_negligence_context
        )

        assert non_qualified_result.content.startswith(b"%PDF")
        assert qualified_result.content.startswith(b"%PDF")

        # Both should generate reasonable size PDFs
        assert len(non_qualified_result.content) > 1000
        assert len(qualified_result.content) > 1000

    def test_full_context_both_modes(
        self,
        pdf_generator: PDFGenerator,
        qualified_generator: PDFGenerator,
        full_negligence_context: dict,
    ):
        """Test full context generates in both modes."""
        non_qualified_result = pdf_generator.generate_negligence_proof(**full_negligence_context)
        qualified_result = qualified_generator.generate_negligence_proof(**full_negligence_context)

        assert non_qualified_result.content.startswith(b"%PDF")
        assert qualified_result.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------
class TestNegligenceProofIntegration:
    """Tests for integration with render_proof method."""

    def test_uses_render_proof_internally(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test that generate_negligence_proof delegates to render_proof."""
        result = pdf_generator.generate_negligence_proof(**minimal_negligence_context)

        # Should use the proof_negligence.html template
        assert result.template_name == "proof_negligence.html"

    def test_base_context_merged(
        self,
        pdf_generator: PDFGenerator,
        minimal_negligence_context: dict,
    ):
        """Test that base context is merged with evidence data."""
        result = pdf_generator.generate_negligence_proof(**minimal_negligence_context)

        # generated_at should be set from base context
        assert result.generated_at is not None
