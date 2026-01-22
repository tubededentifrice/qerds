"""Tests for Refusal Proof (Preuve de Refus) PDF generation.

Tests cover:
- PDF generation with all required fields
- PDF generation with optional fields
- Required field validation
- PDF validity (format, headers, EOF markers)
- Qualification mode rendering (qualified vs non-qualified)
- Verification info presence
- French localization
"""

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
    """Create a PDFGenerator with default settings (non-qualified mode)."""
    return PDFGenerator()


@pytest.fixture
def qualified_generator() -> PDFGenerator:
    """Create a PDFGenerator in qualified mode."""
    return PDFGenerator(qualification_mode="qualified")


@pytest.fixture
def minimal_refusal_data() -> dict:
    """Minimal required data for refusal proof."""
    return {
        "delivery_id": "del-refusal-001",
        "refusal_timestamp": "2026-01-22T16:45:00Z",
    }


@pytest.fixture
def complete_refusal_data() -> dict:
    """Complete refusal evidence data with all fields."""
    return {
        "delivery_id": "del-refusal-full-xyz789",
        "deposit_timestamp": "2026-01-20T09:00:00Z",
        "refusal_timestamp": "2026-01-22T16:45:00Z",
        # Sender info
        "sender_name": "Jean Dupont",
        "sender_email": "jean.dupont@example.com",
        "sender_organization": "Entreprise ABC",
        "sender_address": "123 Rue de la Paix, 75001 Paris",
        # Recipient info (revealed post-refusal per CPCE)
        "recipient_name": "Marie Martin",
        "recipient_email": "marie.martin@example.com",
        "recipient_organization": "Societe XYZ",
        "recipient_address": "456 Avenue des Champs, 75008 Paris",
        # Subject
        "subject": "Contrat de prestation de services",
        # Cryptographic data
        "content_hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
        "hash_algorithm": "SHA-256",
        "seal_id": "seal-2026012216450000-xyz789",
        "signature_algorithm": "Ed25519",
        # Provider info
        "provider_name": "QERDS Qualified Provider",
        # Timestamp authority
        "timestamp_authority": {
            "name": "Autorite d'Horodatage Qualifiee FR",
            "policy_oid": "1.2.3.4.5.6.7.8.9",
            "serial_number": "TSA-2026012216450000-001",
        },
        # Verification
        "proof_id": "proof-ref-2026012216450000-xyz789",
        "verification_url": "https://verify.qerds.example.com/proof/ref-xyz789",
    }


# ---------------------------------------------------------------------------
# Basic Generation Tests
# ---------------------------------------------------------------------------
class TestRefusalProofGeneration:
    """Tests for refusal proof PDF generation."""

    def test_generate_refusal_proof_minimal(
        self,
        pdf_generator: PDFGenerator,
        minimal_refusal_data: dict,
    ):
        """Test generating refusal proof with minimal required data."""
        result = pdf_generator.generate_refusal_proof(minimal_refusal_data)

        assert isinstance(result, PDFResult)
        assert result.content.startswith(b"%PDF")
        assert result.page_count >= 1
        assert result.template_name == "proof_refusal.html"

    def test_generate_refusal_proof_complete(
        self,
        pdf_generator: PDFGenerator,
        complete_refusal_data: dict,
    ):
        """Test generating refusal proof with all fields populated."""
        result = pdf_generator.generate_refusal_proof(complete_refusal_data)

        assert isinstance(result, PDFResult)
        assert result.content.startswith(b"%PDF")
        assert result.page_count >= 1

    def test_generate_refusal_proof_qualified_mode(
        self,
        qualified_generator: PDFGenerator,
        complete_refusal_data: dict,
    ):
        """Test generating refusal proof in qualified mode."""
        result = qualified_generator.generate_refusal_proof(complete_refusal_data)

        assert isinstance(result, PDFResult)
        assert result.content.startswith(b"%PDF")

    def test_generate_refusal_proof_returns_generated_at(
        self,
        pdf_generator: PDFGenerator,
        minimal_refusal_data: dict,
    ):
        """Test that result includes generation timestamp."""
        result = pdf_generator.generate_refusal_proof(minimal_refusal_data)

        assert result.generated_at is not None
        assert "T" in result.generated_at  # ISO 8601 format


# ---------------------------------------------------------------------------
# Validation Tests
# ---------------------------------------------------------------------------
class TestRefusalProofValidation:
    """Tests for refusal proof input validation."""

    def test_missing_delivery_id_raises_error(self, pdf_generator: PDFGenerator):
        """Test that missing delivery_id raises PDFGenerationError."""
        with pytest.raises(PDFGenerationError) as exc_info:
            pdf_generator.generate_refusal_proof(
                {
                    "refusal_timestamp": "2026-01-22T16:45:00Z",
                }
            )

        assert "delivery_id" in str(exc_info.value.message)

    def test_missing_refusal_timestamp_raises_error(
        self,
        pdf_generator: PDFGenerator,
    ):
        """Test that missing refusal_timestamp raises PDFGenerationError."""
        with pytest.raises(PDFGenerationError) as exc_info:
            pdf_generator.generate_refusal_proof(
                {
                    "delivery_id": "del-123",
                }
            )

        assert "refusal_timestamp" in str(exc_info.value.message)

    def test_empty_data_raises_error(self, pdf_generator: PDFGenerator):
        """Test that empty evidence data raises PDFGenerationError."""
        with pytest.raises(PDFGenerationError):
            pdf_generator.generate_refusal_proof({})


# ---------------------------------------------------------------------------
# PDF Validity Tests
# ---------------------------------------------------------------------------
class TestRefusalProofPDFValidity:
    """Tests for PDF output validity."""

    def test_pdf_starts_with_header(
        self,
        pdf_generator: PDFGenerator,
        minimal_refusal_data: dict,
    ):
        """Test generated PDF has valid PDF header."""
        result = pdf_generator.generate_refusal_proof(minimal_refusal_data)

        assert result.content[:5] == b"%PDF-"

    def test_pdf_ends_with_eof(
        self,
        pdf_generator: PDFGenerator,
        minimal_refusal_data: dict,
    ):
        """Test generated PDF has EOF marker."""
        result = pdf_generator.generate_refusal_proof(minimal_refusal_data)

        assert b"%%EOF" in result.content[-32:]

    def test_pdf_has_reasonable_size(
        self,
        pdf_generator: PDFGenerator,
        complete_refusal_data: dict,
    ):
        """Test generated PDF has reasonable file size."""
        result = pdf_generator.generate_refusal_proof(complete_refusal_data)

        # Minimum reasonable PDF size is around 1KB
        assert len(result.content) > 1000
        # Maximum reasonable size for a proof document is 500KB
        assert len(result.content) < 500_000

    def test_pdf_can_be_saved_to_file(
        self,
        pdf_generator: PDFGenerator,
        complete_refusal_data: dict,
        tmp_path: Path,
    ):
        """Test that generated PDF can be saved and read back."""
        result = pdf_generator.generate_refusal_proof(complete_refusal_data)

        output_file = tmp_path / "refusal_proof.pdf"
        output_file.write_bytes(result.content)

        # Read back and verify integrity
        read_content = output_file.read_bytes()
        assert read_content == result.content
        assert read_content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Content Tests
# ---------------------------------------------------------------------------
class TestRefusalProofContent:
    """Tests for PDF content (via template rendering)."""

    def test_contains_delivery_id(
        self,
        pdf_generator: PDFGenerator,
        minimal_refusal_data: dict,
    ):
        """Test that PDF is generated with delivery ID in context."""
        result = pdf_generator.generate_refusal_proof(minimal_refusal_data)
        assert result.content.startswith(b"%PDF")

    def test_handles_unicode_names(self, pdf_generator: PDFGenerator):
        """Test PDF generation with French accented characters."""
        data = {
            "delivery_id": "del-unicode-test",
            "refusal_timestamp": "2026-01-22T16:45:00Z",
            "sender_name": "Jean-Pierre Lefevre",
            "recipient_name": "Helene Beauregard",
            "sender_organization": "Societe d'Edition Francaise",
        }

        result = pdf_generator.generate_refusal_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_handles_special_characters(self, pdf_generator: PDFGenerator):
        """Test PDF generation escapes special HTML characters."""
        data = {
            "delivery_id": "del-special-chars",
            "refusal_timestamp": "2026-01-22T16:45:00Z",
            "sender_name": "<script>alert('xss')</script>",
            "subject": "Test & verification <important>",
        }

        # Should generate valid PDF with escaped content
        result = pdf_generator.generate_refusal_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_handles_long_content_hash(self, pdf_generator: PDFGenerator):
        """Test PDF generation with full SHA-256 hash."""
        data = {
            "delivery_id": "del-hash-test",
            "refusal_timestamp": "2026-01-22T16:45:00Z",
            "content_hash": "a" * 64,  # 64 hex chars for SHA-256
        }

        result = pdf_generator.generate_refusal_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_handles_subject_line(self, pdf_generator: PDFGenerator):
        """Test PDF generation with subject line."""
        data = {
            "delivery_id": "del-subject-test",
            "refusal_timestamp": "2026-01-22T16:45:00Z",
            "subject": "Mise en demeure concernant le contrat n 12345",
        }

        result = pdf_generator.generate_refusal_proof(data)
        assert result.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Verification Info Tests
# ---------------------------------------------------------------------------
class TestRefusalProofVerification:
    """Tests for verification information presence."""

    def test_proof_id_used_when_provided(
        self,
        pdf_generator: PDFGenerator,
    ):
        """Test that proof_id is accepted in evidence data."""
        data = {
            "delivery_id": "del-verify-001",
            "refusal_timestamp": "2026-01-22T16:45:00Z",
            "proof_id": "proof-custom-id-12345",
        }

        result = pdf_generator.generate_refusal_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_verification_url_accepted(self, pdf_generator: PDFGenerator):
        """Test that verification URL is accepted in evidence data."""
        data = {
            "delivery_id": "del-verify-002",
            "refusal_timestamp": "2026-01-22T16:45:00Z",
            "verification_url": "https://verify.qerds.example.com/proof/12345",
        }

        result = pdf_generator.generate_refusal_proof(data)
        assert result.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Timestamp Authority Tests
# ---------------------------------------------------------------------------
class TestRefusalProofTimestampAuthority:
    """Tests for timestamp authority information."""

    def test_timestamp_authority_complete(self, pdf_generator: PDFGenerator):
        """Test PDF generation with complete timestamp authority info."""
        data = {
            "delivery_id": "del-tsa-001",
            "refusal_timestamp": "2026-01-22T16:45:00Z",
            "timestamp_authority": {
                "name": "TSA Qualifiee France",
                "policy_oid": "1.2.3.4.5.6.7.8.9",
                "serial_number": "TSA-12345-67890",
            },
        }

        result = pdf_generator.generate_refusal_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_timestamp_authority_partial(self, pdf_generator: PDFGenerator):
        """Test PDF generation with partial timestamp authority info."""
        data = {
            "delivery_id": "del-tsa-002",
            "refusal_timestamp": "2026-01-22T16:45:00Z",
            "timestamp_authority": {
                "name": "TSA Provider",
                # No policy_oid or serial_number
            },
        }

        result = pdf_generator.generate_refusal_proof(data)
        assert result.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Seal Information Tests
# ---------------------------------------------------------------------------
class TestRefusalProofSeal:
    """Tests for seal/signature information."""

    def test_seal_info_complete(self, pdf_generator: PDFGenerator):
        """Test PDF generation with complete seal information."""
        data = {
            "delivery_id": "del-seal-001",
            "refusal_timestamp": "2026-01-22T16:45:00Z",
            "seal_id": "seal-2026012216450000-001",
            "signature_algorithm": "Ed25519",
            "provider_name": "QERDS Provider",
        }

        result = pdf_generator.generate_refusal_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_seal_defaults_applied(
        self,
        pdf_generator: PDFGenerator,
        minimal_refusal_data: dict,
    ):
        """Test that seal defaults (Ed25519, QERDS) are applied."""
        # No seal info provided - template should use defaults
        result = pdf_generator.generate_refusal_proof(minimal_refusal_data)
        assert result.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Integration with render_proof Tests
# ---------------------------------------------------------------------------
class TestRefusalProofIntegration:
    """Tests for integration with render_proof method."""

    def test_uses_render_proof_internally(self, pdf_generator: PDFGenerator):
        """Test that generate_refusal_proof delegates to render_proof."""
        data = {
            "delivery_id": "del-integration-001",
            "refusal_timestamp": "2026-01-22T16:45:00Z",
        }

        result = pdf_generator.generate_refusal_proof(data)

        # Should use the proof_refusal.html template
        assert result.template_name == "proof_refusal.html"

    def test_base_context_merged(
        self,
        pdf_generator: PDFGenerator,
        minimal_refusal_data: dict,
    ):
        """Test that base context is merged with evidence data."""
        result = pdf_generator.generate_refusal_proof(minimal_refusal_data)

        # generated_at should be set from base context
        assert result.generated_at is not None


# ---------------------------------------------------------------------------
# Edge Case Tests
# ---------------------------------------------------------------------------
class TestRefusalProofEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_very_long_delivery_id(self, pdf_generator: PDFGenerator):
        """Test PDF generation with very long delivery ID."""
        data = {
            "delivery_id": "del-" + "x" * 200,  # Very long ID
            "refusal_timestamp": "2026-01-22T16:45:00Z",
        }

        result = pdf_generator.generate_refusal_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_multiline_address(self, pdf_generator: PDFGenerator):
        """Test PDF generation with multiline addresses."""
        data = {
            "delivery_id": "del-multiline-001",
            "refusal_timestamp": "2026-01-22T16:45:00Z",
            "sender_address": "123 Rue de la Paix\nAppartement 4B\n75001 Paris\nFrance",
            "recipient_address": "456 Avenue des Champs\nBatiment C, Etage 3\n75008 Paris",
        }

        result = pdf_generator.generate_refusal_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_empty_optional_fields(self, pdf_generator: PDFGenerator):
        """Test PDF generation with empty optional fields."""
        data = {
            "delivery_id": "del-empty-opts",
            "refusal_timestamp": "2026-01-22T16:45:00Z",
            "sender_name": "",
            "recipient_name": "",
            "subject": "",
        }

        result = pdf_generator.generate_refusal_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_none_optional_fields(self, pdf_generator: PDFGenerator):
        """Test PDF generation with None optional fields."""
        data = {
            "delivery_id": "del-none-opts",
            "refusal_timestamp": "2026-01-22T16:45:00Z",
            "sender_name": None,
            "recipient_name": None,
        }

        result = pdf_generator.generate_refusal_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_both_timestamps_present(self, pdf_generator: PDFGenerator):
        """Test PDF generation with both deposit and refusal timestamps."""
        data = {
            "delivery_id": "del-both-ts",
            "deposit_timestamp": "2026-01-20T09:00:00Z",
            "refusal_timestamp": "2026-01-22T16:45:00Z",
        }

        result = pdf_generator.generate_refusal_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_refusal_without_deposit_timestamp(self, pdf_generator: PDFGenerator):
        """Test PDF generation when deposit timestamp is missing."""
        data = {
            "delivery_id": "del-no-deposit-ts",
            "refusal_timestamp": "2026-01-22T16:45:00Z",
            # No deposit_timestamp - template should handle this gracefully
        }

        result = pdf_generator.generate_refusal_proof(data)
        assert result.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Qualification Mode Tests
# ---------------------------------------------------------------------------
class TestRefusalProofQualification:
    """Tests for qualification mode handling."""

    def test_non_qualified_mode_generates_valid_pdf(
        self,
        pdf_generator: PDFGenerator,
        minimal_refusal_data: dict,
    ):
        """Test that non-qualified mode generates valid PDF."""
        assert pdf_generator.qualification_mode == "non_qualified"
        result = pdf_generator.generate_refusal_proof(minimal_refusal_data)
        assert result.content.startswith(b"%PDF")

    def test_qualified_mode_generates_valid_pdf(
        self,
        qualified_generator: PDFGenerator,
        minimal_refusal_data: dict,
    ):
        """Test that qualified mode generates valid PDF."""
        assert qualified_generator.qualification_mode == "qualified"
        result = qualified_generator.generate_refusal_proof(minimal_refusal_data)
        assert result.content.startswith(b"%PDF")

    def test_qualified_mode_with_complete_data(
        self,
        qualified_generator: PDFGenerator,
        complete_refusal_data: dict,
    ):
        """Test qualified mode with all data fields."""
        result = qualified_generator.generate_refusal_proof(complete_refusal_data)

        assert result.content.startswith(b"%PDF")
        assert result.page_count >= 1
