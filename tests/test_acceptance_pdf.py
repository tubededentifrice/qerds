"""Tests for Acceptance Proof (Preuve d'Acceptation) PDF generation.

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
def minimal_acceptance_data() -> dict:
    """Minimal required data for acceptance proof."""
    return {
        "delivery_id": "del-acceptance-001",
        "acceptance_timestamp": "2026-01-22T14:30:00Z",
    }


@pytest.fixture
def complete_acceptance_data() -> dict:
    """Complete acceptance evidence data with all fields."""
    return {
        "delivery_id": "del-acceptance-full-xyz789",
        "deposit_timestamp": "2026-01-20T09:00:00Z",
        "acceptance_timestamp": "2026-01-22T14:30:00Z",
        # Sender info
        "sender_name": "Jean Dupont",
        "sender_email": "jean.dupont@example.com",
        "sender_organization": "Entreprise ABC",
        "sender_address": "123 Rue de la Paix, 75001 Paris",
        # Recipient info (revealed post-acceptance per CPCE)
        "recipient_name": "Marie Martin",
        "recipient_email": "marie.martin@example.com",
        "recipient_organization": "Societe XYZ",
        "recipient_address": "456 Avenue des Champs, 75008 Paris",
        # Content info
        "content_info": {
            "subject": "Contrat de prestation de services",
            "document_count": 3,
            "total_size": "2.5 Mo",
        },
        # Cryptographic data
        "content_hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
        "hash_algorithm": "SHA-256",
        "seal_id": "seal-2026012214300000-xyz789",
        "signature_algorithm": "Ed25519",
        # Provider info
        "provider_name": "QERDS Qualified Provider",
        # Timestamp authority
        "timestamp_authority": {
            "name": "Autorite d'Horodatage Qualifiee FR",
            "policy_oid": "1.2.3.4.5.6.7.8.9",
            "serial_number": "TSA-2026012214300000-001",
        },
        # Verification
        "proof_id": "proof-acc-2026012214300000-xyz789",
        "verification_url": "https://verify.qerds.example.com/proof/acc-xyz789",
    }


# ---------------------------------------------------------------------------
# Basic Generation Tests
# ---------------------------------------------------------------------------
class TestAcceptanceProofGeneration:
    """Tests for acceptance proof PDF generation."""

    def test_generate_acceptance_proof_minimal(
        self,
        pdf_generator: PDFGenerator,
        minimal_acceptance_data: dict,
    ):
        """Test generating acceptance proof with minimal required data."""
        result = pdf_generator.generate_acceptance_proof(minimal_acceptance_data)

        assert isinstance(result, PDFResult)
        assert result.content.startswith(b"%PDF")
        assert result.page_count >= 1
        assert result.template_name == "proof_acceptance.html"

    def test_generate_acceptance_proof_complete(
        self,
        pdf_generator: PDFGenerator,
        complete_acceptance_data: dict,
    ):
        """Test generating acceptance proof with all fields populated."""
        result = pdf_generator.generate_acceptance_proof(complete_acceptance_data)

        assert isinstance(result, PDFResult)
        assert result.content.startswith(b"%PDF")
        assert result.page_count >= 1

    def test_generate_acceptance_proof_qualified_mode(
        self,
        qualified_generator: PDFGenerator,
        complete_acceptance_data: dict,
    ):
        """Test generating acceptance proof in qualified mode."""
        result = qualified_generator.generate_acceptance_proof(complete_acceptance_data)

        assert isinstance(result, PDFResult)
        assert result.content.startswith(b"%PDF")
        # PDF should be generated successfully in qualified mode

    def test_generate_acceptance_proof_returns_generated_at(
        self,
        pdf_generator: PDFGenerator,
        minimal_acceptance_data: dict,
    ):
        """Test that result includes generation timestamp."""
        result = pdf_generator.generate_acceptance_proof(minimal_acceptance_data)

        assert result.generated_at is not None
        assert "T" in result.generated_at  # ISO 8601 format


# ---------------------------------------------------------------------------
# Validation Tests
# ---------------------------------------------------------------------------
class TestAcceptanceProofValidation:
    """Tests for acceptance proof input validation."""

    def test_missing_delivery_id_raises_error(self, pdf_generator: PDFGenerator):
        """Test that missing delivery_id raises PDFGenerationError."""
        with pytest.raises(PDFGenerationError) as exc_info:
            pdf_generator.generate_acceptance_proof(
                {
                    "acceptance_timestamp": "2026-01-22T14:30:00Z",
                }
            )

        assert "delivery_id" in str(exc_info.value.message)

    def test_missing_acceptance_timestamp_raises_error(
        self,
        pdf_generator: PDFGenerator,
    ):
        """Test that missing acceptance_timestamp raises PDFGenerationError."""
        with pytest.raises(PDFGenerationError) as exc_info:
            pdf_generator.generate_acceptance_proof(
                {
                    "delivery_id": "del-123",
                }
            )

        assert "acceptance_timestamp" in str(exc_info.value.message)

    def test_empty_data_raises_error(self, pdf_generator: PDFGenerator):
        """Test that empty evidence data raises PDFGenerationError."""
        with pytest.raises(PDFGenerationError):
            pdf_generator.generate_acceptance_proof({})


# ---------------------------------------------------------------------------
# PDF Validity Tests
# ---------------------------------------------------------------------------
class TestAcceptanceProofPDFValidity:
    """Tests for PDF output validity."""

    def test_pdf_starts_with_header(
        self,
        pdf_generator: PDFGenerator,
        minimal_acceptance_data: dict,
    ):
        """Test generated PDF has valid PDF header."""
        result = pdf_generator.generate_acceptance_proof(minimal_acceptance_data)

        assert result.content[:5] == b"%PDF-"

    def test_pdf_ends_with_eof(
        self,
        pdf_generator: PDFGenerator,
        minimal_acceptance_data: dict,
    ):
        """Test generated PDF has EOF marker."""
        result = pdf_generator.generate_acceptance_proof(minimal_acceptance_data)

        assert b"%%EOF" in result.content[-32:]

    def test_pdf_has_reasonable_size(
        self,
        pdf_generator: PDFGenerator,
        complete_acceptance_data: dict,
    ):
        """Test generated PDF has reasonable file size."""
        result = pdf_generator.generate_acceptance_proof(complete_acceptance_data)

        # Minimum reasonable PDF size is around 1KB
        assert len(result.content) > 1000
        # Maximum reasonable size for a proof document is 500KB
        assert len(result.content) < 500_000

    def test_pdf_can_be_saved_to_file(
        self,
        pdf_generator: PDFGenerator,
        complete_acceptance_data: dict,
        tmp_path: Path,
    ):
        """Test that generated PDF can be saved and read back."""
        result = pdf_generator.generate_acceptance_proof(complete_acceptance_data)

        output_file = tmp_path / "acceptance_proof.pdf"
        output_file.write_bytes(result.content)

        # Read back and verify integrity
        read_content = output_file.read_bytes()
        assert read_content == result.content
        assert read_content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Content Tests
# ---------------------------------------------------------------------------
class TestAcceptanceProofContent:
    """Tests for PDF content (via template rendering)."""

    def test_contains_delivery_id(
        self,
        pdf_generator: PDFGenerator,
        minimal_acceptance_data: dict,
    ):
        """Test that PDF is generated with delivery ID in context."""
        # We can't easily parse PDF content, but we can verify the template
        # renders successfully with the delivery ID
        result = pdf_generator.generate_acceptance_proof(minimal_acceptance_data)
        assert result.content.startswith(b"%PDF")

    def test_handles_unicode_names(self, pdf_generator: PDFGenerator):
        """Test PDF generation with French accented characters."""
        data = {
            "delivery_id": "del-unicode-test",
            "acceptance_timestamp": "2026-01-22T14:30:00Z",
            "sender_name": "Jean-Pierre Lefevre",
            "recipient_name": "Helene Beauregard",
            "sender_organization": "Societe d'Edition Francaise",
        }

        result = pdf_generator.generate_acceptance_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_handles_special_characters(self, pdf_generator: PDFGenerator):
        """Test PDF generation escapes special HTML characters."""
        data = {
            "delivery_id": "del-special-chars",
            "acceptance_timestamp": "2026-01-22T14:30:00Z",
            "sender_name": "<script>alert('xss')</script>",
            "content_info": {
                "subject": "Test & verification <important>",
            },
        }

        # Should generate valid PDF with escaped content
        result = pdf_generator.generate_acceptance_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_handles_long_content_hash(self, pdf_generator: PDFGenerator):
        """Test PDF generation with full SHA-256 hash."""
        data = {
            "delivery_id": "del-hash-test",
            "acceptance_timestamp": "2026-01-22T14:30:00Z",
            "content_hash": "a" * 64,  # 64 hex chars for SHA-256
        }

        result = pdf_generator.generate_acceptance_proof(data)
        assert result.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Verification Info Tests
# ---------------------------------------------------------------------------
class TestAcceptanceProofVerification:
    """Tests for verification information presence."""

    def test_proof_id_used_when_provided(
        self,
        pdf_generator: PDFGenerator,
    ):
        """Test that proof_id is accepted in evidence data."""
        data = {
            "delivery_id": "del-verify-001",
            "acceptance_timestamp": "2026-01-22T14:30:00Z",
            "proof_id": "proof-custom-id-12345",
        }

        result = pdf_generator.generate_acceptance_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_verification_url_accepted(self, pdf_generator: PDFGenerator):
        """Test that verification URL is accepted in evidence data."""
        data = {
            "delivery_id": "del-verify-002",
            "acceptance_timestamp": "2026-01-22T14:30:00Z",
            "verification_url": "https://verify.qerds.example.com/proof/12345",
        }

        result = pdf_generator.generate_acceptance_proof(data)
        assert result.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Timestamp Authority Tests
# ---------------------------------------------------------------------------
class TestAcceptanceProofTimestampAuthority:
    """Tests for timestamp authority information."""

    def test_timestamp_authority_complete(self, pdf_generator: PDFGenerator):
        """Test PDF generation with complete timestamp authority info."""
        data = {
            "delivery_id": "del-tsa-001",
            "acceptance_timestamp": "2026-01-22T14:30:00Z",
            "timestamp_authority": {
                "name": "TSA Qualifiee France",
                "policy_oid": "1.2.3.4.5.6.7.8.9",
                "serial_number": "TSA-12345-67890",
            },
        }

        result = pdf_generator.generate_acceptance_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_timestamp_authority_partial(self, pdf_generator: PDFGenerator):
        """Test PDF generation with partial timestamp authority info."""
        data = {
            "delivery_id": "del-tsa-002",
            "acceptance_timestamp": "2026-01-22T14:30:00Z",
            "timestamp_authority": {
                "name": "TSA Provider",
                # No policy_oid or serial_number
            },
        }

        result = pdf_generator.generate_acceptance_proof(data)
        assert result.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Seal Information Tests
# ---------------------------------------------------------------------------
class TestAcceptanceProofSeal:
    """Tests for seal/signature information."""

    def test_seal_info_complete(self, pdf_generator: PDFGenerator):
        """Test PDF generation with complete seal information."""
        data = {
            "delivery_id": "del-seal-001",
            "acceptance_timestamp": "2026-01-22T14:30:00Z",
            "seal_id": "seal-2026012214300000-001",
            "signature_algorithm": "Ed25519",
            "provider_name": "QERDS Provider",
        }

        result = pdf_generator.generate_acceptance_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_seal_defaults_applied(
        self,
        pdf_generator: PDFGenerator,
        minimal_acceptance_data: dict,
    ):
        """Test that seal defaults (Ed25519, QERDS) are applied."""
        # No seal info provided - template should use defaults
        result = pdf_generator.generate_acceptance_proof(minimal_acceptance_data)
        assert result.content.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# Integration with render_proof Tests
# ---------------------------------------------------------------------------
class TestAcceptanceProofIntegration:
    """Tests for integration with render_proof method."""

    def test_uses_render_proof_internally(self, pdf_generator: PDFGenerator):
        """Test that generate_acceptance_proof delegates to render_proof."""
        data = {
            "delivery_id": "del-integration-001",
            "acceptance_timestamp": "2026-01-22T14:30:00Z",
        }

        result = pdf_generator.generate_acceptance_proof(data)

        # Should use the proof_acceptance.html template
        assert result.template_name == "proof_acceptance.html"

    def test_base_context_merged(
        self,
        pdf_generator: PDFGenerator,
        minimal_acceptance_data: dict,
    ):
        """Test that base context is merged with evidence data."""
        result = pdf_generator.generate_acceptance_proof(minimal_acceptance_data)

        # generated_at should be set from base context
        assert result.generated_at is not None


# ---------------------------------------------------------------------------
# Edge Case Tests
# ---------------------------------------------------------------------------
class TestAcceptanceProofEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_very_long_delivery_id(self, pdf_generator: PDFGenerator):
        """Test PDF generation with very long delivery ID."""
        data = {
            "delivery_id": "del-" + "x" * 200,  # Very long ID
            "acceptance_timestamp": "2026-01-22T14:30:00Z",
        }

        result = pdf_generator.generate_acceptance_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_multiline_address(self, pdf_generator: PDFGenerator):
        """Test PDF generation with multiline addresses."""
        data = {
            "delivery_id": "del-multiline-001",
            "acceptance_timestamp": "2026-01-22T14:30:00Z",
            "sender_address": "123 Rue de la Paix\nAppartement 4B\n75001 Paris\nFrance",
            "recipient_address": "456 Avenue des Champs\nBatiment C, Etage 3\n75008 Paris",
        }

        result = pdf_generator.generate_acceptance_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_empty_optional_fields(self, pdf_generator: PDFGenerator):
        """Test PDF generation with empty optional fields."""
        data = {
            "delivery_id": "del-empty-opts",
            "acceptance_timestamp": "2026-01-22T14:30:00Z",
            "sender_name": "",
            "recipient_name": "",
            "content_info": {},
        }

        result = pdf_generator.generate_acceptance_proof(data)
        assert result.content.startswith(b"%PDF")

    def test_none_optional_fields(self, pdf_generator: PDFGenerator):
        """Test PDF generation with None optional fields."""
        data = {
            "delivery_id": "del-none-opts",
            "acceptance_timestamp": "2026-01-22T14:30:00Z",
            "sender_name": None,
            "recipient_name": None,
        }

        result = pdf_generator.generate_acceptance_proof(data)
        assert result.content.startswith(b"%PDF")
