"""Internationalization (i18n) infrastructure for QERDS.

This module provides multi-language support per:
- SPEC-J01: French language support (primary)
- SPEC-J02: English language support (secondary)

Features:
- Language detection from Accept-Language header
- Language preference cookie
- URL parameter override (?lang=xx)
- JSON-based translations loaded from locales/ directory
- Nested key access (e.g., "nav.dashboard")
- Fallback to key name if translation is missing
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from starlette.requests import Request

logger = logging.getLogger(__name__)

# Supported languages per SPEC-J01, SPEC-J02
SUPPORTED_LANGUAGES = ("fr", "en")
DEFAULT_LANGUAGE = "fr"

# Path to locale files
LOCALES_DIR = Path(__file__).parent.parent / "locales"

# Cache for loaded translations
_translations_cache: dict[str, dict[str, Any]] = {}


def _load_translations(lang: str) -> dict[str, Any]:
    """Load translations from JSON file for a language.

    Args:
        lang: Two-letter language code.

    Returns:
        Translation dictionary with nested structure.
    """
    if lang in _translations_cache:
        return _translations_cache[lang]

    locale_file = LOCALES_DIR / f"{lang}.json"
    if not locale_file.exists():
        logger.warning("Locale file not found: %s", locale_file)
        return {}

    try:
        with locale_file.open("r", encoding="utf-8") as f:
            translations = json.load(f)
            _translations_cache[lang] = translations
            return translations
    except (json.JSONDecodeError, OSError) as e:
        logger.error("Failed to load locale file %s: %s", locale_file, e)
        return {}


def _get_nested_value(data: dict[str, Any], key: str) -> str | None:
    """Get a value from a nested dictionary using dot notation.

    Args:
        data: The dictionary to search.
        key: Dot-separated key (e.g., "nav.dashboard").

    Returns:
        The value if found, None otherwise.
    """
    parts = key.split(".")
    current = data
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    # Only return if we got a string value, not a nested dict
    return current if isinstance(current, str) else None


def _flatten_translations(data: dict[str, Any], prefix: str = "") -> dict[str, str]:
    """Flatten a nested translation dictionary to dot-notation keys.

    Args:
        data: Nested translation dictionary.
        prefix: Current key prefix for recursion.

    Returns:
        Flat dictionary with dot-notation keys.
    """
    result: dict[str, str] = {}
    for key, value in data.items():
        # Skip metadata keys
        if key.startswith("_"):
            continue
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            result.update(_flatten_translations(value, full_key))
        elif isinstance(value, str):
            result[full_key] = value
    return result


def reload_translations() -> None:
    """Clear the translation cache, forcing a reload on next access.

    Useful for development or after updating locale files.
    """
    _translations_cache.clear()


def get_all_translation_keys(lang: str = DEFAULT_LANGUAGE) -> set[str]:
    """Get all available translation keys for a language.

    Args:
        lang: Two-letter language code.

    Returns:
        Set of all translation keys in dot notation.
    """
    translations = _load_translations(lang)
    flat = _flatten_translations(translations)
    return set(flat.keys())


@dataclass
class LanguageContext:
    """Language context for template rendering.

    Attributes:
        code: Two-letter language code (fr, en).
        name: Display name in the language (native).
        name_english: Display name in English.
        is_rtl: Whether the language is right-to-left.
    """

    code: str
    name: str
    name_english: str
    is_rtl: bool = False


# Language metadata (not translations, just language info)
LANGUAGE_INFO: dict[str, LanguageContext] = {
    "fr": LanguageContext(
        code="fr",
        name="Francais",
        name_english="French",
        is_rtl=False,
    ),
    "en": LanguageContext(
        code="en",
        name="English",
        name_english="English",
        is_rtl=False,
    ),
}


def get_language(request: Request) -> str:
    """Determine the preferred language from the request.

    Priority order:
    1. Query parameter: ?lang=xx
    2. Cookie: lang=xx
    3. Accept-Language header
    4. Default language (French)

    Args:
        request: The Starlette request object.

    Returns:
        Two-letter language code.
    """
    # Check query parameter
    lang = request.query_params.get("lang")
    if lang in SUPPORTED_LANGUAGES:
        return lang

    # Check cookie
    lang = request.cookies.get("lang")
    if lang in SUPPORTED_LANGUAGES:
        return lang

    # Check Accept-Language header
    accept_lang = request.headers.get("Accept-Language", "")
    for lang_part in accept_lang.split(","):
        # Parse: "fr-FR;q=0.9" -> "fr"
        lang_code = lang_part.split(";")[0].strip()
        lang_code = lang_code.split("-")[0].lower()
        if lang_code in SUPPORTED_LANGUAGES:
            return lang_code

    return DEFAULT_LANGUAGE


def get_language_context(lang: str) -> LanguageContext:
    """Get the language context for a language code.

    Args:
        lang: Two-letter language code.

    Returns:
        LanguageContext with language metadata.
    """
    return LANGUAGE_INFO.get(lang, LANGUAGE_INFO[DEFAULT_LANGUAGE])


def get_available_languages() -> list[LanguageContext]:
    """Get list of all available languages.

    Returns:
        List of LanguageContext objects for each supported language.
    """
    return [LANGUAGE_INFO[lang] for lang in SUPPORTED_LANGUAGES]


def translate(key: str, lang: str = DEFAULT_LANGUAGE, **kwargs: Any) -> str:
    """Translate a key to the specified language.

    Supports string interpolation with keyword arguments.

    Args:
        key: Translation key in dot notation (e.g., "nav.dashboard").
        lang: Target language code.
        **kwargs: Variables to interpolate into the translation.

    Returns:
        Translated string, or the key itself if not found.

    Example:
        >>> translate("nav.dashboard", "fr")
        "Tableau de bord"
        >>> translate("greeting", "en", name="John")
        "Hello, John!"
    """
    # Load translations for the requested language
    translations = _load_translations(lang)
    value = _get_nested_value(translations, key)

    # Fallback to default language if not found
    if value is None and lang != DEFAULT_LANGUAGE:
        translations = _load_translations(DEFAULT_LANGUAGE)
        value = _get_nested_value(translations, key)

    # If still not found, return the key
    if value is None:
        logger.debug("Missing translation for key '%s' in language '%s'", key, lang)
        return key

    # Interpolate variables if any provided
    if kwargs:
        try:
            return value.format(**kwargs)
        except KeyError as e:
            logger.warning("Missing interpolation variable %s for key '%s'", e, key)
            return value

    return value


def create_translator(lang: str) -> Callable[[str], str]:
    """Create a translation function bound to a specific language.

    This is useful for passing to templates as a callable (the _ function).

    Args:
        lang: Target language code.

    Returns:
        Function that translates keys to the specified language.

    Example:
        >>> _ = create_translator("fr")
        >>> _("nav.dashboard")
        "Tableau de bord"
    """

    def _translate(key: str, **kwargs: Any) -> str:
        return translate(key, lang, **kwargs)

    return _translate


def get_status_label(status: str, lang: str = DEFAULT_LANGUAGE) -> str:
    """Get the translated label for a delivery status.

    Args:
        status: Status code (draft, deposited, notified, etc.).
        lang: Target language code.

    Returns:
        Translated status label.
    """
    return translate(f"status.{status}", lang)


def get_error_message(error_code: str, lang: str = DEFAULT_LANGUAGE) -> str:
    """Get the translated error message for an error code.

    Args:
        error_code: Error code (not_found, unauthorized, etc.).
        lang: Target language code.

    Returns:
        Translated error message.
    """
    return translate(f"errors.{error_code}", lang)


# Pre-load translations at module load time for faster first access
def _preload_translations() -> None:
    """Pre-load translations for all supported languages."""
    for lang in SUPPORTED_LANGUAGES:
        _load_translations(lang)


# Preload on import
_preload_translations()
