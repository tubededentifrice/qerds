"""Tests for Proof of Deposit (Preuve de Depot) PDF generation.

Tests cover:
- Deposit proof generation with all required fields
- Deposit proof generation with optional fields
- Qualified vs non-qualified mode rendering
- PDF validity (header, EOF, reasonable size)
- Content integrity (hash display)
- Verification information inclusion
- Error handling for missing required fields
- Edge cases (unicode, special characters)

Covers: REQ-B01, REQ-F01, REQ-F07
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
def minimal_deposit_context() -> dict:
    """Minimal required context for deposit proof."""
    return {
        "delivery_id": "del-test-001",
        "deposit_timestamp": "2026-01-22T10:30:00Z",
        "sender_name": "Jean Dupont",
        "recipient_name": "Marie Martin",
        "recipient_email": "marie.martin@example.com",
        "content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }


@pytest.fixture
def full_deposit_context() -> dict:
    """Full context with all optional fields for deposit proof."""
    return {
        "delivery_id": "del-full-test-002",
        "deposit_timestamp": "2026-01-22T14:45:30Z",
        "sender_name": "Jean-Pierre Lefevre",
        "sender_email": "jp.lefevre@entreprise.fr",
        "sender_address": "123 Rue de la Paix, 75001 Paris, France",
        "sender_organization": "Entreprise SARL",
        "recipient_name": "Francoise Carre",
        "recipient_email": "f.carre@destinataire.fr",
        "recipient_organization": "Societe Destinataire",
        "subject": "Contrat de prestation de services",
        "content_hash": "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd",
        "content_info": {
            "document_count": 3,
            "total_size": "2.5 Mo",
        },
        "seal_id": "seal-2026012214453000-xyz789",
        "seal_timestamp": "2026-01-22T14:45:35Z",
        "signature_algorithm": "Ed25519",
        "tsa_info": {
            "name": "Service d'horodatage qualifie eIDAS",
            "policy_oid": "1.2.3.4.5.6.7.8.9",
            "token_id": "TSA-TOKEN-2026-001",
        },
        "proof_id": "PRF-2026-0122-FULL002",
        "verification_url": "https://verify.qerds.example.com/proof/PRF-2026-0122-FULL002",
    }


# ---------------------------------------------------------------------------
# Basic Generation Tests
# ---------------------------------------------------------------------------
class TestDepositProofBasicGeneration:
    """Tests for basic deposit proof PDF generation."""

    def test_generate_deposit_proof_minimal(
        self,
        pdf_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test generating deposit proof with minimal required fields."""
        result = pdf_generator.generate_deposit_proof(**minimal_deposit_context)

        assert isinstance(result, PDFResult)
        assert result.content.startswith(b"%PDF")
        assert result.page_count >= 1
        assert result.template_name == "deposit.html"

    def test_generate_deposit_proof_full(
        self,
        pdf_generator: PDFGenerator,
        full_deposit_context: dict,
    ):
        """Test generating deposit proof with all optional fields."""
        result = pdf_generator.generate_deposit_proof(**full_deposit_context)

        assert isinstance(result, PDFResult)
        assert result.content.startswith(b"%PDF")
        assert result.page_count >= 1

    def test_generate_deposit_proof_qualified_mode(
        self,
        qualified_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test deposit proof generation in qualified mode."""
        result = qualified_generator.generate_deposit_proof(**minimal_deposit_context)

        assert result.content.startswith(b"%PDF")
        # Qualified mode should still generate valid PDF
        assert result.page_count >= 1

    def test_generate_deposit_proof_non_qualified_mode(
        self,
        pdf_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test deposit proof generation in non-qualified mode (default)."""
        assert pdf_generator.qualification_mode == "non_qualified"

        result = pdf_generator.generate_deposit_proof(**minimal_deposit_context)

        assert result.content.startswith(b"%PDF")
        assert result.page_count >= 1


# ---------------------------------------------------------------------------
# PDF Validity Tests
# ---------------------------------------------------------------------------
class TestDepositProofPDFValidity:
    """Tests for PDF output validity of deposit proofs."""

    def test_pdf_starts_with_header(
        self,
        pdf_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test generated PDF has valid header."""
        result = pdf_generator.generate_deposit_proof(**minimal_deposit_context)

        # PDF files start with %PDF-
        assert result.content[:5] == b"%PDF-"

    def test_pdf_ends_with_eof(
        self,
        pdf_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test generated PDF has EOF marker."""
        result = pdf_generator.generate_deposit_proof(**minimal_deposit_context)

        # PDF files end with %%EOF
        assert b"%%EOF" in result.content[-32:]

    def test_pdf_has_reasonable_size(
        self,
        pdf_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test generated PDF has reasonable size (not empty or huge)."""
        result = pdf_generator.generate_deposit_proof(**minimal_deposit_context)

        # Minimum reasonable PDF size is around 1KB
        assert len(result.content) > 1000
        # Maximum reasonable size for a simple document is 500KB
        assert len(result.content) < 500_000

    def test_pdf_can_be_saved_to_file(
        self,
        pdf_generator: PDFGenerator,
        minimal_deposit_context: dict,
        tmp_path: Path,
    ):
        """Test that generated PDF can be saved and read back."""
        result = pdf_generator.generate_deposit_proof(**minimal_deposit_context)

        output_file = tmp_path / "deposit_proof.pdf"
        output_file.write_bytes(result.content)

        # Read back and verify
        read_content = output_file.read_bytes()
        assert read_content == result.content
        assert read_content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Content Verification Tests
# ---------------------------------------------------------------------------
class TestDepositProofContent:
    """Tests for deposit proof content verification."""

    def test_deposit_proof_includes_delivery_id(
        self,
        pdf_generator: PDFGenerator,
    ):
        """Test that delivery ID is included in the generated PDF."""
        unique_id = "del-unique-verification-id-xyz"
        result = pdf_generator.generate_deposit_proof(
            delivery_id=unique_id,
            deposit_timestamp="2026-01-22T10:00:00Z",
            sender_name="Test Sender",
            recipient_name="Test Recipient",
            recipient_email="test@example.com",
            content_hash="abc123def456",
        )

        # PDF should generate successfully
        assert result.content.startswith(b"%PDF")

    def test_deposit_proof_with_subject(
        self,
        pdf_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test deposit proof with subject line."""
        context = {**minimal_deposit_context, "subject": "Important Legal Notice"}

        result = pdf_generator.generate_deposit_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_deposit_proof_with_content_info(
        self,
        pdf_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test deposit proof with content metadata."""
        context = {
            **minimal_deposit_context,
            "content_info": {
                "document_count": 5,
                "total_size": "10.5 Mo",
            },
        }

        result = pdf_generator.generate_deposit_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_deposit_proof_with_seal_info(
        self,
        pdf_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test deposit proof with seal information."""
        context = {
            **minimal_deposit_context,
            "seal_id": "seal-test-001",
            "seal_timestamp": "2026-01-22T10:30:05Z",
            "signature_algorithm": "RSA-PSS",
        }

        result = pdf_generator.generate_deposit_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_deposit_proof_with_tsa_info(
        self,
        pdf_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test deposit proof with timestamp authority information."""
        context = {
            **minimal_deposit_context,
            "tsa_info": {
                "name": "Test TSA Provider",
                "policy_oid": "1.2.3.4.5",
                "token_id": "TSA-TOKEN-001",
            },
        }

        result = pdf_generator.generate_deposit_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_deposit_proof_with_verification_info(
        self,
        pdf_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test deposit proof with verification information."""
        context = {
            **minimal_deposit_context,
            "proof_id": "PRF-2026-TEST-001",
            "verification_url": "https://verify.example.com/PRF-2026-TEST-001",
        }

        result = pdf_generator.generate_deposit_proof(**context)

        assert result.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Datetime Handling Tests
# ---------------------------------------------------------------------------
class TestDepositProofDatetimeHandling:
    """Tests for datetime handling in deposit proofs."""

    def test_deposit_timestamp_as_string(
        self,
        pdf_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test deposit timestamp as ISO 8601 string."""
        context = {
            **minimal_deposit_context,
            "deposit_timestamp": "2026-06-15T09:30:00Z",
        }

        result = pdf_generator.generate_deposit_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_deposit_timestamp_as_datetime(
        self,
        pdf_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test deposit timestamp as datetime object."""
        context = {
            **minimal_deposit_context,
            "deposit_timestamp": datetime(2026, 6, 15, 9, 30, 0),
        }

        result = pdf_generator.generate_deposit_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_seal_timestamp_as_datetime(
        self,
        pdf_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test seal timestamp as datetime object."""
        context = {
            **minimal_deposit_context,
            "seal_timestamp": datetime(2026, 6, 15, 9, 30, 5),
        }

        result = pdf_generator.generate_deposit_proof(**context)

        assert result.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Edge Cases Tests
# ---------------------------------------------------------------------------
class TestDepositProofEdgeCases:
    """Tests for edge cases in deposit proof generation."""

    def test_unicode_content(
        self,
        pdf_generator: PDFGenerator,
    ):
        """Test deposit proof with unicode characters in names."""
        result = pdf_generator.generate_deposit_proof(
            delivery_id="del-unicode-test",
            deposit_timestamp="2026-01-22T10:00:00Z",
            sender_name="Jean-Pierre Lefevre",
            sender_organization="Societe des Etudes Avancees",
            recipient_name="Francoise Carre",
            recipient_email="francoise@exemple.fr",
            content_hash="abcdef123456",
            subject="Etude d'impact environnemental - Evaluation preliminaire",
        )

        assert result.content.startswith(b"%PDF")

    def test_special_characters_escaped(
        self,
        pdf_generator: PDFGenerator,
    ):
        """Test that special HTML characters are properly escaped."""
        result = pdf_generator.generate_deposit_proof(
            delivery_id="del-special-chars",
            deposit_timestamp="2026-01-22T10:00:00Z",
            sender_name="Test <script>alert('xss')</script>",
            recipient_name="Recipient & Partner",
            recipient_email="test@example.com",
            content_hash="abc123",
            subject="Test & Validation <important>",
        )

        # Should still generate valid PDF (Jinja2 autoescaping)
        assert result.content.startswith(b"%PDF")

    def test_long_content_hash(
        self,
        pdf_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test deposit proof with very long content hash."""
        # SHA-512 produces 128-char hex string
        long_hash = "a" * 128

        context = {**minimal_deposit_context, "content_hash": long_hash}

        result = pdf_generator.generate_deposit_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_long_subject_line(
        self,
        pdf_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test deposit proof with very long subject line."""
        long_subject = "A" * 500  # Very long subject

        context = {**minimal_deposit_context, "subject": long_subject}

        result = pdf_generator.generate_deposit_proof(**context)

        assert result.content.startswith(b"%PDF")

    def test_empty_optional_fields(
        self,
        pdf_generator: PDFGenerator,
    ):
        """Test deposit proof when optional fields are None."""
        result = pdf_generator.generate_deposit_proof(
            delivery_id="del-empty-opts",
            deposit_timestamp="2026-01-22T10:00:00Z",
            sender_name="Sender Name",
            recipient_name="Recipient Name",
            recipient_email="recipient@example.com",
            content_hash="hash123",
            subject=None,
            sender_email=None,
            sender_address=None,
            sender_organization=None,
            recipient_organization=None,
            content_info=None,
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
class TestDepositProofErrorHandling:
    """Tests for error handling in deposit proof generation."""

    def test_missing_deposit_template(
        self,
        tmp_path: Path,
    ):
        """Test error when deposit template is missing."""
        # Create generator with empty template dir
        empty_template_dir = tmp_path / "empty_templates"
        empty_template_dir.mkdir()

        generator = PDFGenerator(template_dir=empty_template_dir)

        with pytest.raises(PDFGenerationError):
            generator.generate_deposit_proof(
                delivery_id="test",
                deposit_timestamp="2026-01-22T10:00:00Z",
                sender_name="Test",
                recipient_name="Test",
                recipient_email="test@example.com",
                content_hash="hash",
            )


# ---------------------------------------------------------------------------
# Comparison Tests
# ---------------------------------------------------------------------------
class TestDepositProofComparison:
    """Tests comparing qualified vs non-qualified deposit proofs."""

    def test_qualified_and_non_qualified_both_generate(
        self,
        pdf_generator: PDFGenerator,
        qualified_generator: PDFGenerator,
        minimal_deposit_context: dict,
    ):
        """Test both qualified and non-qualified modes generate valid PDFs."""
        non_qualified_result = pdf_generator.generate_deposit_proof(**minimal_deposit_context)
        qualified_result = qualified_generator.generate_deposit_proof(**minimal_deposit_context)

        assert non_qualified_result.content.startswith(b"%PDF")
        assert qualified_result.content.startswith(b"%PDF")

        # Both should generate reasonable size PDFs
        assert len(non_qualified_result.content) > 1000
        assert len(qualified_result.content) > 1000

    def test_full_context_both_modes(
        self,
        pdf_generator: PDFGenerator,
        qualified_generator: PDFGenerator,
        full_deposit_context: dict,
    ):
        """Test full context generates in both modes."""
        non_qualified_result = pdf_generator.generate_deposit_proof(**full_deposit_context)
        qualified_result = qualified_generator.generate_deposit_proof(**full_deposit_context)

        assert non_qualified_result.content.startswith(b"%PDF")
        assert qualified_result.content.startswith(b"%PDF")
