"""Jinja2 template configuration for QERDS frontend.

This module provides:
- Jinja2 environment configuration
- Template context processors for common data (user, qualification_mode, etc.)
- i18n infrastructure preparation (French + English per SPEC-J01, SPEC-J02)

Templates are rendered server-side following the SSR-first approach
per the frontend development skill guidelines.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi.templating import Jinja2Templates

from qerds.api.i18n import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    create_translator,
    get_available_languages,
    get_language,
    get_language_context,
    get_status_label,
    translate,
)

if TYPE_CHECKING:
    from starlette.requests import Request

    from qerds.core.config import Settings

logger = logging.getLogger(__name__)

# Resolve the templates directory relative to this file
# Templates are in src/qerds/templates/
TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


def get_templates() -> Jinja2Templates:
    """Create and configure the Jinja2 templates instance.

    Returns:
        Configured Jinja2Templates instance.

    Raises:
        RuntimeError: If the templates directory does not exist.
    """
    if not TEMPLATES_DIR.exists():
        msg = f"Templates directory not found: {TEMPLATES_DIR}"
        raise RuntimeError(msg)

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    # Add custom filters and globals to the environment
    _configure_jinja_environment(templates)

    logger.info("Jinja2 templates configured from %s", TEMPLATES_DIR)
    return templates


def _configure_jinja_environment(templates: Jinja2Templates) -> None:
    """Configure the Jinja2 environment with filters and globals.

    Args:
        templates: The Jinja2Templates instance to configure.
    """
    env = templates.env

    # Add custom filters
    env.filters["format_date"] = format_date
    env.filters["format_datetime"] = format_datetime
    env.filters["format_filesize"] = format_filesize
    env.filters["truncate_id"] = truncate_id

    # Add global functions
    env.globals["current_year"] = lambda: datetime.now().year
    env.globals["supported_languages"] = list(SUPPORTED_LANGUAGES)
    env.globals["default_language"] = DEFAULT_LANGUAGE

    # Add i18n translation function
    # The '_' function is available in templates: {{ _("auth.login") }}
    env.globals["_"] = translate

    # Add language helper functions for templates
    env.globals["get_available_languages"] = get_available_languages
    env.globals["get_language_context"] = get_language_context
    env.globals["get_status_label"] = get_status_label


def format_date(value: datetime | str | None, format_str: str = "%d/%m/%Y") -> str:
    """Format a date for display.

    Args:
        value: The datetime object or ISO string to format.
        format_str: The strftime format string.

    Returns:
        Formatted date string or empty string if value is None.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime(format_str)


def format_datetime(value: datetime | str | None, format_str: str = "%d/%m/%Y %H:%M") -> str:
    """Format a datetime for display.

    Args:
        value: The datetime object or ISO string to format.
        format_str: The strftime format string.

    Returns:
        Formatted datetime string or empty string if value is None.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime(format_str)


def format_filesize(size_bytes: int | None) -> str:
    """Format a file size in bytes to a human-readable string.

    Args:
        size_bytes: Size in bytes.

    Returns:
        Human-readable size string (e.g., "1.2 Mo").
    """
    if size_bytes is None:
        return ""

    # Use French units (Mo, Ko, Go)
    if size_bytes < 1024:
        return f"{size_bytes} o"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} Ko"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} Mo"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} Go"


def truncate_id(value: str | None, length: int = 8) -> str:
    """Truncate an ID for display.

    Args:
        value: The ID string to truncate.
        length: Maximum length.

    Returns:
        Truncated ID or empty string if value is None.
    """
    if value is None:
        return ""
    return value[:length]


def get_language_from_request(request: Request) -> str:
    """Extract the preferred language from the request.

    This is a convenience wrapper around qerds.api.i18n.get_language.

    Args:
        request: The Starlette request object.

    Returns:
        Two-letter language code (fr or en).
    """
    return get_language(request)


def build_template_context(
    request: Request,
    settings: Settings | None = None,
    **extra_context: Any,
) -> dict[str, Any]:
    """Build the template context with common data.

    This function provides the base context for all templates, including:
    - request: The Starlette request object (required by Jinja2Templates)
    - user: The authenticated user (if any)
    - qualification_mode: 'dev' or 'qualified' for UI display
    - current_year: For footer copyright
    - lang: Current language code
    - active_page: For navigation highlighting

    Args:
        request: The Starlette request object.
        settings: Optional Settings instance for qualification mode.
        **extra_context: Additional context variables to include.

    Returns:
        Dictionary suitable for passing to TemplateResponse.
    """
    # Get user from request state if available (set by auth middleware)
    user = getattr(request.state, "user", None)

    # Determine qualification mode from settings
    # Default to 'dev' if no settings provided (safe default per compliance guardrail)
    if settings is not None:
        qualification_mode = "qualified" if settings.is_qualified else "dev"
    else:
        # Try to get settings from app state
        app_settings = getattr(request.app.state, "settings", None)
        if app_settings is not None:
            qualification_mode = "qualified" if app_settings.is_qualified else "dev"
        else:
            qualification_mode = "dev"

    # Get language preference
    lang = get_language_from_request(request)

    # Create language-specific translator function
    translator = create_translator(lang)

    # Get language context and available languages for switcher
    lang_context = get_language_context(lang)
    available_languages = get_available_languages()

    # Build base context
    context: dict[str, Any] = {
        "request": request,
        "user": user,
        "qualification_mode": qualification_mode,
        "current_year": datetime.now().year,
        "lang": lang,
        "lang_context": lang_context,
        "available_languages": available_languages,
        "_": translator,  # Language-specific translator
        "active_page": extra_context.pop("active_page", None),
    }

    # Merge extra context
    context.update(extra_context)

    return context
