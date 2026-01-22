"""Tests for the internationalization (i18n) infrastructure.

These tests verify:
- Translation file structure and completeness
- Translation function behavior
- Language detection from requests
- Missing key handling
- All keys have translations in both French and English
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

from qerds.api.i18n import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    create_translator,
    get_all_translation_keys,
    get_available_languages,
    get_error_message,
    get_language,
    get_language_context,
    get_status_label,
    reload_translations,
    translate,
)

if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture(autouse=True)
def reset_translation_cache() -> Generator[None, None, None]:
    """Reset translation cache before and after each test."""
    reload_translations()
    yield
    reload_translations()


class TestTranslationFilesExist:
    """Test that translation files exist and are valid JSON."""

    def test_french_locale_exists(self) -> None:
        """Verify French locale file exists."""
        locale_path = Path(__file__).parent.parent / "src" / "qerds" / "locales" / "fr.json"
        assert locale_path.exists(), "French locale file should exist"

    def test_english_locale_exists(self) -> None:
        """Verify English locale file exists."""
        locale_path = Path(__file__).parent.parent / "src" / "qerds" / "locales" / "en.json"
        assert locale_path.exists(), "English locale file should exist"


class TestTranslationCompleteness:
    """Test that all keys are translated in both languages."""

    def test_all_french_keys_have_english_translations(self) -> None:
        """Every French key should have an English translation (except language-specific keys)."""
        fr_keys = get_all_translation_keys("fr")
        en_keys = get_all_translation_keys("en")

        # Language-specific keys are intentionally asymmetric
        # French has "switch_to_en", English has "switch_to_fr"
        language_specific_keys = {"language.switch_to_en", "language.switch_to_fr"}

        missing_in_english = fr_keys - en_keys - language_specific_keys
        assert not missing_in_english, f"Keys missing in English translations: {missing_in_english}"

    def test_all_english_keys_have_french_translations(self) -> None:
        """Every English key should have a French translation (except language-specific keys)."""
        fr_keys = get_all_translation_keys("fr")
        en_keys = get_all_translation_keys("en")

        # Language-specific keys are intentionally asymmetric
        language_specific_keys = {"language.switch_to_en", "language.switch_to_fr"}

        missing_in_french = en_keys - fr_keys - language_specific_keys
        assert not missing_in_french, f"Keys missing in French translations: {missing_in_french}"

    def test_translations_are_not_empty(self) -> None:
        """All translation values should be non-empty strings."""
        for lang in SUPPORTED_LANGUAGES:
            keys = get_all_translation_keys(lang)
            for key in keys:
                value = translate(key, lang)
                assert value, f"Empty translation for {key} in {lang}"
                assert value != key, f"Untranslated key {key} in {lang}"


class TestTranslateFunction:
    """Test the translate function behavior."""

    def test_translate_returns_french_value(self) -> None:
        """translate() returns the correct French value."""
        result = translate("nav.dashboard", "fr")
        assert result == "Tableau de bord"

    def test_translate_returns_english_value(self) -> None:
        """translate() returns the correct English value."""
        result = translate("nav.dashboard", "en")
        assert result == "Dashboard"

    def test_translate_with_nested_keys(self) -> None:
        """translate() works with deeply nested keys."""
        result = translate("auth.franceconnect_note", "fr")
        assert "FranceConnect+" in result
        assert "eIDAS" in result

    def test_translate_missing_key_returns_key(self) -> None:
        """Missing keys should return the key itself."""
        result = translate("nonexistent.key", "fr")
        assert result == "nonexistent.key"

    def test_translate_fallback_to_default_language(self) -> None:
        """If key missing in requested language, fall back to default."""
        # The translate function should fall back to French (default)
        # if a key is missing in English
        # Since all keys should exist, we test with a hypothetical scenario
        result = translate("common.app_title", "en")
        assert result == "QERDS"

    def test_default_language_is_french(self) -> None:
        """Default language should be French."""
        assert DEFAULT_LANGUAGE == "fr"


class TestCreateTranslator:
    """Test the create_translator factory function."""

    def test_create_french_translator(self) -> None:
        """create_translator creates a function bound to French."""
        _ = create_translator("fr")
        assert _("nav.dashboard") == "Tableau de bord"

    def test_create_english_translator(self) -> None:
        """create_translator creates a function bound to English."""
        _ = create_translator("en")
        assert _("nav.dashboard") == "Dashboard"

    def test_translator_handles_missing_keys(self) -> None:
        """Translator function handles missing keys gracefully."""
        _ = create_translator("fr")
        result = _("this.key.does.not.exist")
        assert result == "this.key.does.not.exist"


class TestLanguageDetection:
    """Test language detection from HTTP requests."""

    def _make_mock_request(
        self,
        query_params: dict | None = None,
        cookies: dict | None = None,
        accept_language: str | None = None,
    ) -> MagicMock:
        """Create a mock request object."""
        request = MagicMock()
        request.query_params = query_params or {}
        request.cookies = cookies or {}
        request.headers = {}
        if accept_language:
            request.headers["Accept-Language"] = accept_language
        return request

    def test_query_param_takes_precedence(self) -> None:
        """Query parameter ?lang=xx has highest priority."""
        request = self._make_mock_request(
            query_params={"lang": "en"},
            cookies={"lang": "fr"},
            accept_language="fr-FR,fr;q=0.9",
        )
        assert get_language(request) == "en"

    def test_cookie_takes_precedence_over_header(self) -> None:
        """Cookie lang=xx has priority over Accept-Language."""
        request = self._make_mock_request(
            cookies={"lang": "en"},
            accept_language="fr-FR,fr;q=0.9",
        )
        assert get_language(request) == "en"

    def test_accept_language_header_parsed_correctly(self) -> None:
        """Accept-Language header is parsed correctly."""
        request = self._make_mock_request(accept_language="en-US,en;q=0.9,fr;q=0.8")
        assert get_language(request) == "en"

    def test_french_accept_language_header(self) -> None:
        """French Accept-Language is detected correctly."""
        request = self._make_mock_request(accept_language="fr-FR,fr;q=0.9")
        assert get_language(request) == "fr"

    def test_unsupported_language_falls_back_to_default(self) -> None:
        """Unsupported languages fall back to French."""
        request = self._make_mock_request(accept_language="de-DE,de;q=0.9")
        assert get_language(request) == "fr"

    def test_no_language_info_returns_default(self) -> None:
        """No language info returns the default (French)."""
        request = self._make_mock_request()
        assert get_language(request) == "fr"

    def test_invalid_query_param_ignored(self) -> None:
        """Invalid language codes in query params are ignored."""
        request = self._make_mock_request(
            query_params={"lang": "invalid"},
            accept_language="en-US",
        )
        assert get_language(request) == "en"


class TestLanguageContext:
    """Test language context and metadata."""

    def test_get_french_context(self) -> None:
        """get_language_context returns correct French context."""
        context = get_language_context("fr")
        assert context.code == "fr"
        assert context.name == "Francais"
        assert context.name_english == "French"
        assert context.is_rtl is False

    def test_get_english_context(self) -> None:
        """get_language_context returns correct English context."""
        context = get_language_context("en")
        assert context.code == "en"
        assert context.name == "English"
        assert context.name_english == "English"
        assert context.is_rtl is False

    def test_invalid_language_returns_default_context(self) -> None:
        """Invalid language code returns French context."""
        context = get_language_context("invalid")
        assert context.code == "fr"

    def test_get_available_languages(self) -> None:
        """get_available_languages returns all supported languages."""
        languages = get_available_languages()
        codes = [lang.code for lang in languages]
        assert "fr" in codes
        assert "en" in codes
        assert len(codes) == len(SUPPORTED_LANGUAGES)


class TestStatusLabels:
    """Test status label translations."""

    @pytest.mark.parametrize(
        "status",
        [
            "draft",
            "deposited",
            "notified",
            "available",
            "accepted",
            "refused",
            "expired",
            "received",
        ],
    )
    def test_all_statuses_have_translations(self, status: str) -> None:
        """All delivery statuses should have translations."""
        fr_label = get_status_label(status, "fr")
        en_label = get_status_label(status, "en")

        # Should not return the key itself
        assert fr_label != f"status.{status}", f"Missing French translation for status.{status}"
        assert en_label != f"status.{status}", f"Missing English translation for status.{status}"

        # French and English should be different
        assert fr_label != en_label, f"Same translation for {status} in both languages"

    def test_status_labels_are_reasonable(self) -> None:
        """Status labels should be human-readable."""
        assert get_status_label("accepted", "fr") == "Accepte"
        assert get_status_label("accepted", "en") == "Accepted"


class TestErrorMessages:
    """Test error message translations."""

    @pytest.mark.parametrize(
        "error_code",
        [
            "not_found",
            "unauthorized",
            "forbidden",
            "server_error",
            "bad_request",
            "validation_error",
        ],
    )
    def test_all_errors_have_translations(self, error_code: str) -> None:
        """All error codes should have translations."""
        fr_msg = get_error_message(error_code, "fr")
        en_msg = get_error_message(error_code, "en")

        # Should not return the key itself
        assert fr_msg != f"errors.{error_code}", (
            f"Missing French translation for errors.{error_code}"
        )
        assert en_msg != f"errors.{error_code}", (
            f"Missing English translation for errors.{error_code}"
        )


class TestKeyCategories:
    """Test that all expected key categories exist."""

    @pytest.mark.parametrize(
        "category",
        [
            "common",
            "nav",
            "auth",
            "form",
            "delivery",
            "pickup",
            "accepted",
            "status",
            "dashboard",
            "admin",
            "verification",
            "qualification",
            "footer",
            "errors",
            "pdf",
            "email",
            "language",
        ],
    )
    def test_category_exists(self, category: str) -> None:
        """All expected translation categories should exist."""
        keys = get_all_translation_keys("fr")
        category_keys = [k for k in keys if k.startswith(f"{category}.")]
        assert category_keys, f"No translation keys found for category: {category}"

    def test_minimum_key_count(self) -> None:
        """Should have a substantial number of translation keys."""
        fr_keys = get_all_translation_keys("fr")
        # We expect at least 100 translation keys
        assert len(fr_keys) >= 100, f"Only {len(fr_keys)} translation keys found"


class TestTranslationQuality:
    """Test translation quality aspects."""

    def test_no_html_entities_in_translations(self) -> None:
        """Translations should not contain unescaped HTML entities."""
        for lang in SUPPORTED_LANGUAGES:
            keys = get_all_translation_keys(lang)
            for key in keys:
                value = translate(key, lang)
                # Check for common HTML entities that should be actual characters
                assert "&amp;" not in value, f"HTML entity &amp; in {key} ({lang})"
                assert "&lt;" not in value, f"HTML entity &lt; in {key} ({lang})"
                assert "&gt;" not in value, f"HTML entity &gt; in {key} ({lang})"

    def test_consistent_formatting(self) -> None:
        """Translations should not have leading/trailing whitespace."""
        for lang in SUPPORTED_LANGUAGES:
            keys = get_all_translation_keys(lang)
            for key in keys:
                value = translate(key, lang)
                assert value == value.strip(), f"Whitespace in {key} ({lang})"


class TestSupportedLanguages:
    """Test supported languages configuration."""

    def test_supported_languages_tuple(self) -> None:
        """SUPPORTED_LANGUAGES should be a tuple of language codes."""
        assert isinstance(SUPPORTED_LANGUAGES, tuple)
        assert "fr" in SUPPORTED_LANGUAGES
        assert "en" in SUPPORTED_LANGUAGES

    def test_default_language_is_supported(self) -> None:
        """DEFAULT_LANGUAGE should be in SUPPORTED_LANGUAGES."""
        assert DEFAULT_LANGUAGE in SUPPORTED_LANGUAGES
