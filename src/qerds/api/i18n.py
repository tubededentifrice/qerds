"""Internationalization (i18n) infrastructure for QERDS.

This module provides the foundation for multi-language support per:
- SPEC-J01: French language support (primary)
- SPEC-J02: English language support (secondary)

Currently, French is hardcoded in templates. This module prepares
the infrastructure for future translation integration using:
- Language detection from Accept-Language header
- Language preference cookie
- URL parameter override (?lang=xx)

Future implementation will use gettext or similar for string externalization.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.requests import Request

# Supported languages per SPEC-J01, SPEC-J02
SUPPORTED_LANGUAGES = ("fr", "en")
DEFAULT_LANGUAGE = "fr"

# Common UI strings placeholder - to be populated with actual translations
# This structure prepares for gettext (.po/.mo) or JSON-based translations
TRANSLATIONS: dict[str, dict[str, str]] = {
    "fr": {
        # Common
        "app.title": "QERDS",
        "app.tagline": "Lettre Recommandee Electronique Qualifiee",
        "nav.dashboard": "Tableau de bord",
        "nav.new_delivery": "Nouvel envoi",
        "nav.history": "Historique",
        "nav.audit": "Audit",
        "nav.config": "Configuration",
        # Auth
        "auth.login": "Se connecter",
        "auth.logout": "Deconnexion",
        "auth.login_title": "Connexion a votre espace",
        "auth.franceconnect": "Se connecter avec FranceConnect+",
        "auth.franceconnect_note": (
            "FranceConnect+ garantit une identification de niveau eleve (eIDAS Substantiel)"
        ),
        # Forms
        "form.email": "Adresse e-mail",
        "form.password": "Mot de passe",
        "form.required": "Champ obligatoire",
        "form.submit": "Envoyer",
        "form.cancel": "Annuler",
        "form.save_draft": "Enregistrer brouillon",
        # Delivery status
        "status.draft": "Brouillon",
        "status.deposited": "Depose",
        "status.notified": "Notifie",
        "status.available": "Disponible",
        "status.accepted": "Accepte",
        "status.refused": "Refuse",
        "status.expired": "Neglige",
        "status.received": "Recu",
        # Qualification
        "qualification.qualified": "Service Qualifie eIDAS",
        "qualification.dev": "Mode developpement",
        "qualification.dev_warning": (
            "Ce service n'est pas qualifie. Les preuves generees n'ont pas de valeur juridique."
        ),
        # Errors
        "error.not_found": "Page non trouvee",
        "error.unauthorized": "Acces non autorise",
        "error.server": "Erreur serveur",
    },
    "en": {
        # Common
        "app.title": "QERDS",
        "app.tagline": "Qualified Electronic Registered Delivery Service",
        "nav.dashboard": "Dashboard",
        "nav.new_delivery": "New delivery",
        "nav.history": "History",
        "nav.audit": "Audit",
        "nav.config": "Configuration",
        # Auth
        "auth.login": "Log in",
        "auth.logout": "Log out",
        "auth.login_title": "Log in to your account",
        "auth.franceconnect": "Log in with FranceConnect+",
        "auth.franceconnect_note": (
            "FranceConnect+ guarantees high-level identification (eIDAS Substantial)"
        ),
        # Forms
        "form.email": "Email address",
        "form.password": "Password",
        "form.required": "Required field",
        "form.submit": "Submit",
        "form.cancel": "Cancel",
        "form.save_draft": "Save draft",
        # Delivery status
        "status.draft": "Draft",
        "status.deposited": "Deposited",
        "status.notified": "Notified",
        "status.available": "Available",
        "status.accepted": "Accepted",
        "status.refused": "Refused",
        "status.expired": "Expired",
        "status.received": "Received",
        # Qualification
        "qualification.qualified": "eIDAS Qualified Service",
        "qualification.dev": "Development mode",
        "qualification.dev_warning": (
            "This service is not qualified. Generated evidence has no legal value."
        ),
        # Errors
        "error.not_found": "Page not found",
        "error.unauthorized": "Unauthorized",
        "error.server": "Server error",
    },
}


@dataclass
class LanguageContext:
    """Language context for template rendering.

    Attributes:
        code: Two-letter language code (fr, en).
        name: Display name in the language.
        translations: Translation dictionary for the language.
    """

    code: str
    name: str
    translations: dict[str, str]


LANGUAGE_INFO = {
    "fr": LanguageContext(
        code="fr",
        name="Francais",
        translations=TRANSLATIONS["fr"],
    ),
    "en": LanguageContext(
        code="en",
        name="English",
        translations=TRANSLATIONS["en"],
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
        LanguageContext with translations and metadata.
    """
    return LANGUAGE_INFO.get(lang, LANGUAGE_INFO[DEFAULT_LANGUAGE])


def translate(key: str, lang: str = DEFAULT_LANGUAGE) -> str:
    """Translate a key to the specified language.

    Args:
        key: Translation key (e.g., "auth.login").
        lang: Target language code.

    Returns:
        Translated string, or the key itself if not found.
    """
    translations = TRANSLATIONS.get(lang, TRANSLATIONS[DEFAULT_LANGUAGE])
    return translations.get(key, key)


def create_translator(lang: str) -> callable:
    """Create a translation function bound to a specific language.

    This is useful for passing to templates as a callable.

    Args:
        lang: Target language code.

    Returns:
        Function that translates keys to the specified language.

    Example:
        >>> _ = create_translator("fr")
        >>> _("auth.login")
        "Se connecter"
    """

    def _translate(key: str) -> str:
        return translate(key, lang)

    return _translate
