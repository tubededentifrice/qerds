"""HTML page routes for the QERDS frontend.

This router handles all HTML page rendering using Jinja2 templates.
Following the SSR-first approach, pages render meaningful content without JS.

Routes:
- / : Home/landing page (redirects to dashboard if logged in)
- /login : Login page
- /sender/dashboard : Sender dashboard
- /sender/new : New delivery form
- /recipient/pickup/{delivery_id} : Recipient pickup portal
- /recipient/accepted/{delivery_id} : Post-acceptance view
- /admin/dashboard : Admin dashboard
- /verify : Proof verification portal

Note: These routes render HTML templates. API routes are in separate routers.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from qerds.api.templates import build_template_context

if TYPE_CHECKING:
    from fastapi.templating import Jinja2Templates

router = APIRouter(tags=["pages"])


def _get_templates(request: Request) -> Jinja2Templates:
    """Get the Jinja2Templates instance from app state.

    Args:
        request: The request object containing app state.

    Returns:
        The configured Jinja2Templates instance.
    """
    return request.app.state.templates


# --- Mock data for demonstration ---
# These will be replaced with real database queries when the delivery service is complete


def _mock_user(role: str = "sender") -> dict[str, Any]:
    """Generate mock user data for template rendering."""
    if role == "sender":
        return {
            "id": "usr-12345",
            "name": "Marie Dupont",
            "email": "marie.dupont@example.fr",
            "initials": "MD",
            "role": role,
        }
    elif role == "admin":
        return {
            "id": "usr-admin",
            "name": "Admin QERDS",
            "email": "admin@qerds.local",
            "initials": "AQ",
            "role": role,
        }
    return None


def _mock_stats() -> dict[str, Any]:
    """Generate mock statistics for dashboard."""
    return {
        "this_month": 24,
        "pending": 3,
        "accepted": 18,
        "refused_or_expired": 3,
        "drafts": 2,
    }


def _mock_deliveries() -> list[dict[str, Any]]:
    """Generate mock delivery list for dashboard."""
    now = datetime.now()
    return [
        {
            "id": str(uuid4()),
            "recipient_email": "destinataire1@example.fr",
            "subject": "Mise en demeure - Facture impayee",
            "status": "notified",
            "created_at": (now - timedelta(days=2)).isoformat(),
            "created_at_formatted": (now - timedelta(days=2)).strftime("%d/%m/%Y %H:%M"),
        },
        {
            "id": str(uuid4()),
            "recipient_email": "client@company.com",
            "subject": "Resiliation de contrat",
            "status": "accepted",
            "created_at": (now - timedelta(days=5)).isoformat(),
            "created_at_formatted": (now - timedelta(days=5)).strftime("%d/%m/%Y %H:%M"),
        },
        {
            "id": str(uuid4()),
            "recipient_email": "jean.martin@mail.fr",
            "subject": "Convocation assemblee generale",
            "status": "available",
            "created_at": (now - timedelta(days=7)).isoformat(),
            "created_at_formatted": (now - timedelta(days=7)).strftime("%d/%m/%Y %H:%M"),
        },
    ]


def _mock_delivery_for_pickup(delivery_id: str) -> dict[str, Any]:
    """Generate mock delivery data for recipient pickup view."""
    now = datetime.now()
    return {
        "id": delivery_id,
        "subject": "Document important a retirer",
        "deposited_at": (now - timedelta(days=3)).isoformat(),
        "deposited_at_formatted": (now - timedelta(days=3)).strftime("%d %B %Y a %H:%M"),
        "expires_at": (now + timedelta(days=12)).isoformat(),
        "expires_at_formatted": (now + timedelta(days=12)).strftime("%d %B %Y"),
        "content_size": "1.2 Mo",
    }


def _mock_delivery_accepted(delivery_id: str) -> dict[str, Any]:
    """Generate mock delivery data for post-acceptance view."""
    now = datetime.now()
    return {
        "id": delivery_id,
        "subject": "Document important",
        "sender_name": "Entreprise ABC",
        "sender_email": "contact@entreprise-abc.fr",
        "deposited_at": (now - timedelta(days=5)).isoformat(),
        "deposited_at_formatted": (now - timedelta(days=5)).strftime("%d %B %Y a %H:%M"),
        "accepted_at": now.isoformat(),
        "accepted_at_formatted": now.strftime("%d %B %Y a %H:%M"),
        "content_filename": "contrat-2024.pdf",
        "content_size": "1.2 Mo",
        "proof_id": f"PRF-{delivery_id[:8].upper()}",
    }


def _mock_admin_stats() -> dict[str, Any]:
    """Generate mock admin statistics."""
    return {
        "today": 47,
        "month": 1248,
        "pending": 156,
        "acceptance_rate": "87%",
    }


def _mock_recent_events() -> list[dict[str, Any]]:
    """Generate mock recent events for admin dashboard."""
    now = datetime.now()
    return [
        {
            "timestamp": (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S"),
            "type": "deposited",
            "delivery_id": str(uuid4()),
            "details": "Nouveau depot par marie.dupont@example.fr",
        },
        {
            "timestamp": (now - timedelta(minutes=12)).strftime("%Y-%m-%d %H:%M:%S"),
            "type": "accepted",
            "delivery_id": str(uuid4()),
            "details": "Accepte par le destinataire",
        },
        {
            "timestamp": (now - timedelta(minutes=25)).strftime("%Y-%m-%d %H:%M:%S"),
            "type": "notified",
            "delivery_id": str(uuid4()),
            "details": "Notification envoyee",
        },
        {
            "timestamp": (now - timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S"),
            "type": "refused",
            "delivery_id": str(uuid4()),
            "details": "Refuse par le destinataire",
        },
        {
            "timestamp": (now - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"),
            "type": "expired",
            "delivery_id": str(uuid4()),
            "details": "Delai de retrait depasse",
        },
    ]


# --- Page Routes ---


@router.get("/", response_class=HTMLResponse)
async def home_page(request: Request) -> RedirectResponse:
    """Home page - redirects to appropriate dashboard based on auth status.

    For now, redirects to login page. When auth is implemented,
    will redirect to sender/admin dashboard based on user role.
    """
    # Check if user is authenticated (via request.state.user)
    user = getattr(request.state, "user", None)
    if user:
        if user.get("role") == "admin":
            return RedirectResponse(url="/admin/dashboard", status_code=302)
        return RedirectResponse(url="/sender/dashboard", status_code=302)

    return RedirectResponse(url="/login", status_code=302)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    """Render the login page.

    Shows FranceConnect+ button and email/password form.
    Displays dev mode warning if in non-qualified mode.
    """
    templates = _get_templates(request)
    context = build_template_context(request)
    return templates.TemplateResponse(request, "login.html", context)


@router.get("/logout", response_class=HTMLResponse)
async def logout_page(_request: Request) -> RedirectResponse:
    """Handle logout and redirect to login page.

    Clears the session cookie and redirects to the login page.
    For proper session revocation, the client should call POST /auth/logout first,
    but this GET endpoint provides a user-friendly redirect flow.

    Args:
        _request: FastAPI request object (unused but required for route handler).

    Returns:
        Redirect response to login page with cleared session cookie.
    """
    from qerds.api.middleware.auth import SESSION_COOKIE_NAME

    response = RedirectResponse(url="/login", status_code=302)
    # Clear the session cookie
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return response


@router.get("/sender/dashboard", response_class=HTMLResponse)
async def sender_dashboard(request: Request) -> HTMLResponse:
    """Render the sender dashboard.

    Shows delivery statistics, recent deliveries, and quick actions.
    """
    templates = _get_templates(request)
    context = build_template_context(
        request,
        active_page="dashboard",
        user=_mock_user("sender"),  # Mock user for now
        stats=_mock_stats(),
        deliveries=_mock_deliveries(),
    )
    return templates.TemplateResponse(request, "sender/dashboard.html", context)


@router.get("/sender/new", response_class=HTMLResponse)
async def sender_new_delivery(request: Request) -> HTMLResponse:
    """Render the new delivery form.

    Form for creating a new registered delivery with recipient,
    content, and delivery options.
    """
    templates = _get_templates(request)
    context = build_template_context(
        request,
        active_page="new",
        user=_mock_user("sender"),  # Mock user for now
    )
    return templates.TemplateResponse(request, "sender/new.html", context)


@router.get("/recipient/pickup/{delivery_id}", response_class=HTMLResponse)
async def recipient_pickup(request: Request, delivery_id: str) -> HTMLResponse:
    """Render the recipient pickup portal.

    Shows delivery information (with masked sender identity),
    and accept/refuse actions. Requires FranceConnect+ auth.
    """
    templates = _get_templates(request)

    # Check if user is authenticated
    user = getattr(request.state, "user", None)

    context = build_template_context(
        request,
        user=user,
        delivery=_mock_delivery_for_pickup(delivery_id),
    )
    return templates.TemplateResponse(request, "recipient/pickup.html", context)


@router.get("/recipient/accepted/{delivery_id}", response_class=HTMLResponse)
async def recipient_accepted(request: Request, delivery_id: str) -> HTMLResponse:
    """Render the post-acceptance view.

    Shows full delivery details, content download, and proof download.
    Only accessible after accepting the delivery.
    """
    templates = _get_templates(request)
    context = build_template_context(
        request,
        user=_mock_user("sender"),  # Mock - would be recipient
        delivery=_mock_delivery_accepted(delivery_id),
    )
    return templates.TemplateResponse(request, "recipient/accepted.html", context)


@router.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard(request: Request) -> HTMLResponse:
    """Render the admin dashboard.

    Shows qualification status, system health, statistics,
    recent activity, and audit actions.
    """
    templates = _get_templates(request)
    context = build_template_context(
        request,
        active_page="dashboard",
        user=_mock_user("admin"),  # Mock admin user
        stats=_mock_admin_stats(),
        recent_events=_mock_recent_events(),
    )
    return templates.TemplateResponse(request, "admin/dashboard.html", context)


@router.get("/verify", response_class=HTMLResponse)
async def verify_page(
    request: Request,
    id: str | None = None,
    token: str | None = None,
) -> HTMLResponse:
    """Render the proof verification portal.

    Allows third parties to verify the authenticity of evidence.
    Optionally accepts proof_id and token as query parameters.
    """
    templates = _get_templates(request)

    # If proof ID and token are provided, show verification result
    result = None
    if id and token:
        # Mock verification result for demonstration
        # Real implementation would call the evidence verification service
        result = {
            "valid": True,
            "proof_type": "Preuve d'acceptation",
            "issued_at": datetime.now().strftime("%d %B %Y a %H:%M"),
            "delivery_id": id,
            "show_parties": True,
            "sender_name": "Entreprise ABC",
            "recipient_name": "Jean Dupont",
            "signature_algorithm": "ECDSA-P384-SHA384",
            "tsa_name": "Chronosign (Qualifie eIDAS)",
            "document_hash": "a1b2c3d4e5f6...abcd1234",
        }

    context = build_template_context(
        request,
        proof_id=id,
        token=token,
        result=result,
    )
    return templates.TemplateResponse(request, "verify.html", context)
