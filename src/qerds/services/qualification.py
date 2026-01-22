"""Qualification service for claim state guardrails.

Covers: REQ-A01, REQ-G01, REQ-G02

This module provides centralized qualification state management to ensure
the platform cannot be misrepresented as a qualified service unless the
operator has explicitly configured qualified mode with proper trust anchors.

Key responsibilities:
- Single source of truth for qualification mode
- Localized labels and warnings for UI display
- Assertion helpers for fail-closed code paths
- Evidence metadata generation for qualification labeling

Per REQ-G01, the system must avoid the word "qualified" unless properly configured.
Per REQ-G02, non-qualified mode must be clearly labeled in all outputs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from qerds.api.i18n import translate
from qerds.core.config import ClaimState

if TYPE_CHECKING:
    from qerds.core.config import Settings

logger = logging.getLogger(__name__)


class QualificationError(Exception):
    """Raised when a qualified-only operation is attempted in non-qualified mode."""

    def __init__(self, operation: str | None = None) -> None:
        """Initialize with optional operation name.

        Args:
            operation: Name of the operation that requires qualification.
        """
        self.operation = operation
        if operation:
            msg = (
                f"Operation '{operation}' requires qualified mode. "
                "The service is currently in non-qualified/development mode."
            )
        else:
            msg = (
                "This operation requires qualified mode. "
                "The service is currently in non-qualified/development mode."
            )
        super().__init__(msg)


@dataclass(frozen=True, slots=True)
class QualificationContext:
    """Qualification context for templates and evidence generation.

    This immutable dataclass provides all qualification-related information
    needed for UI rendering and evidence artifact labeling.

    Attributes:
        mode: The claim state (qualified or non_qualified).
        is_qualified: True if in qualified mode.
        label: Localized display label for the mode.
        warning: Localized warning message (empty if qualified).
        css_class: CSS class for styling (e.g., "qualified" or "dev").
        badge_text: Short badge text for UI display.
    """

    mode: ClaimState
    is_qualified: bool
    label: str
    warning: str
    css_class: str
    badge_text: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for template context or JSON serialization."""
        return {
            "mode": self.mode.value,
            "is_qualified": self.is_qualified,
            "label": self.label,
            "warning": self.warning,
            "css_class": self.css_class,
            "badge_text": self.badge_text,
        }

    def to_evidence_metadata(self) -> dict[str, str]:
        """Generate metadata for evidence artifact labeling.

        Returns:
            Dictionary with qualification_label field for evidence objects.
        """
        return {
            "qualification_label": self.mode.value,
        }


class QualificationService:
    """Service for managing and querying qualification state.

    This service provides a consistent interface for checking qualification
    mode and generating appropriate labels/warnings. It acts as the single
    source of truth for qualification state across the application.

    All UI components and evidence generators should use this service
    rather than directly checking configuration settings.

    Example:
        service = QualificationService(settings)

        # Check mode
        if service.is_qualified():
            # Qualified-only logic
            pass

        # Get context for templates
        context = service.get_context("fr")

        # Fail-closed assertion
        service.assert_qualified("sign_evidence")  # Raises if not qualified
    """

    def __init__(self, settings: Settings) -> None:
        """Initialize the qualification service.

        Args:
            settings: Application settings containing claim_state.
        """
        self._settings = settings
        logger.debug(
            "QualificationService initialized with claim_state=%s",
            settings.claim_state.value,
        )

    def get_current_mode(self) -> ClaimState:
        """Get the current qualification mode.

        Returns:
            The current ClaimState (QUALIFIED or NON_QUALIFIED).
        """
        return self._settings.claim_state

    def is_qualified(self) -> bool:
        """Check if the service is in qualified mode.

        Returns:
            True if claim_state is QUALIFIED, False otherwise.
        """
        return self._settings.claim_state == ClaimState.QUALIFIED

    def get_mode_label(self, lang: str = "fr") -> str:
        """Get the localized display label for the current mode.

        Args:
            lang: Two-letter language code (fr, en).

        Returns:
            Localized label string (e.g., "Service Qualifie eIDAS" or "Mode developpement").
        """
        if self.is_qualified():
            return translate("qualification.qualified", lang)
        return translate("qualification.dev_not_qualified", lang)

    def get_mode_warning(self, lang: str = "fr") -> str:
        """Get the localized warning message for non-qualified mode.

        Args:
            lang: Two-letter language code (fr, en).

        Returns:
            Localized warning string, or empty string if qualified.
        """
        if self.is_qualified():
            return ""
        return translate("qualification.dev_warning_eidas", lang)

    def get_badge_text(self, lang: str = "fr") -> str:
        """Get short badge text for UI display.

        Args:
            lang: Two-letter language code (fr, en).

        Returns:
            Short localized badge text.
        """
        if self.is_qualified():
            return translate("qualification.qualified", lang)
        return translate("qualification.dev", lang)

    def get_css_class(self) -> str:
        """Get the CSS class for qualification mode styling.

        Returns:
            CSS class name: "qualified" or "dev".
        """
        return "qualified" if self.is_qualified() else "dev"

    def get_context(self, lang: str = "fr") -> QualificationContext:
        """Get complete qualification context for templates.

        This method returns all qualification-related information needed
        for rendering UI components with proper mode indicators.

        Args:
            lang: Two-letter language code (fr, en).

        Returns:
            QualificationContext with all mode-related information.
        """
        return QualificationContext(
            mode=self.get_current_mode(),
            is_qualified=self.is_qualified(),
            label=self.get_mode_label(lang),
            warning=self.get_mode_warning(lang),
            css_class=self.get_css_class(),
            badge_text=self.get_badge_text(lang),
        )

    def assert_qualified(self, operation: str | None = None) -> None:
        """Assert that the service is in qualified mode.

        Use this method in code paths that must fail-closed if the service
        is not in qualified mode. This provides explicit guardrails against
        accidentally performing qualified-only operations in dev mode.

        Args:
            operation: Optional name of the operation for error messages.

        Raises:
            QualificationError: If the service is not in qualified mode.

        Example:
            # Fail if not qualified - prevents accidental qualified claims
            service.assert_qualified("generate_qualified_evidence")
            # ... proceed with qualified-only operation
        """
        if not self.is_qualified():
            logger.warning(
                "Qualification assertion failed for operation: %s (mode=%s)",
                operation or "unspecified",
                self._settings.claim_state.value,
            )
            raise QualificationError(operation)

    def get_evidence_metadata(self) -> dict[str, str]:
        """Get metadata for evidence artifact labeling.

        Returns dictionary containing qualification_label to be included
        in all generated evidence objects per REQ-G02.

        Returns:
            Dictionary with qualification metadata.
        """
        return {"qualification_label": self._settings.claim_state.value}

    def should_show_warning(self) -> bool:
        """Check if a non-qualified warning should be displayed.

        Returns:
            True if in non-qualified mode and warning should be shown.
        """
        return not self.is_qualified()


def create_qualification_service(settings: Settings) -> QualificationService:
    """Factory function to create a QualificationService.

    Args:
        settings: Application settings.

    Returns:
        Configured QualificationService instance.
    """
    return QualificationService(settings)
