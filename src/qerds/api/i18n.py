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
        # Email notifications
        "email.subject.notification": "Lettre recommandee electronique",
        "email.subject.reminder": "Rappel - Lettre recommandee en attente",
        "email.greeting": "Bonjour,",
        "email.notification.intro": (
            "Vous avez recu une lettre recommandee electronique qui attend votre action."
        ),
        "email.reminder.intro": (
            "Nous vous rappelons qu'une lettre recommandee electronique est en attente "
            "de votre action. La date limite approche."
        ),
        "email.delivery_info": "Informations de l'envoi",
        "email.reference": "Reference",
        "email.provider": "Operateur",
        "email.nature": "Nature",
        "email.nature_lre": "Lettre Recommandee Electronique (LRE)",
        "email.deadline_label": "Date limite pour accepter ou refuser",
        "email.days_remaining": "{days} jour(s) restant(s)",
        "email.action_button": "Consulter ma lettre recommandee",
        "email.action_button_reminder": "Agir maintenant",
        "email.auth_required": "Une authentification sera requise pour acceder au contenu.",
        "email.privacy_notice_title": "Note de confidentialite",
        "email.privacy_notice": (
            "Conformement a la reglementation, l'identite de l'expediteur et le contenu "
            "de l'envoi ne sont pas reveles dans cette notification. Ces informations "
            "seront accessibles apres votre authentification sur la plateforme securisee."
        ),
        "email.expiry_warning_title": "Important : que se passe-t-il si je n'agis pas ?",
        "email.expiry_warning": (
            "Si vous n'acceptez ni ne refusez cette lettre avant la date limite, "
            "elle sera consideree comme 'negligee' conformement a la loi. "
            "L'expediteur sera informe que vous n'avez pas retire l'envoi."
        ),
        "email.footer.auto_message": (
            "Cet e-mail a ete envoye automatiquement. Merci de ne pas y repondre."
        ),
        "email.legal_nature.lre": (
            "Lettre Recommandee Electronique (LRE) au sens de l'article L.100 "
            "du Code des Postes et des Communications Electroniques"
        ),
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
        # Email notifications
        "email.subject.notification": "Electronic registered delivery",
        "email.subject.reminder": "Reminder - Pending registered delivery",
        "email.greeting": "Hello,",
        "email.notification.intro": (
            "You have received an electronic registered delivery awaiting your action."
        ),
        "email.reminder.intro": (
            "This is a reminder that an electronic registered delivery is awaiting "
            "your action. The deadline is approaching."
        ),
        "email.delivery_info": "Delivery Information",
        "email.reference": "Reference",
        "email.provider": "Provider",
        "email.nature": "Type",
        "email.nature_lre": "Qualified Electronic Registered Delivery",
        "email.deadline_label": "Deadline to accept or refuse",
        "email.days_remaining": "{days} day(s) remaining",
        "email.action_button": "View my registered delivery",
        "email.action_button_reminder": "Take action now",
        "email.auth_required": "Authentication will be required to access the content.",
        "email.privacy_notice_title": "Privacy Notice",
        "email.privacy_notice": (
            "In accordance with regulations, the sender's identity and delivery content "
            "are not disclosed in this notification. This information will be accessible "
            "after you authenticate on the secure platform."
        ),
        "email.expiry_warning_title": "Important: What happens if I don't act?",
        "email.expiry_warning": (
            "If you neither accept nor refuse this delivery before the deadline, "
            "it will be marked as 'expired' in accordance with the law. "
            "The sender will be notified that you did not collect the delivery."
        ),
        "email.footer.auto_message": "This email was sent automatically. Please do not reply.",
        "email.legal_nature.lre": (
            "Qualified Electronic Registered Delivery (QERDS) under EU Regulation 910/2014 (eIDAS)"
        ),
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
