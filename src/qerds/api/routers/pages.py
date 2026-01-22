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


def _mock_delivery_refused(delivery_id: str) -> dict[str, Any]:
    """Generate mock delivery data for post-refusal view."""
    now = datetime.now()
    return {
        "id": delivery_id,
        "subject": "Document important",
        "sender_name": "Entreprise ABC",
        "sender_email": "contact@entreprise-abc.fr",
        "deposited_at": (now - timedelta(days=5)).isoformat(),
        "deposited_at_formatted": (now - timedelta(days=5)).strftime("%d %B %Y a %H:%M"),
        "refused_at": now.isoformat(),
        "refused_at_formatted": now.strftime("%d %B %Y a %H:%M"),
        "proof_id": f"PRF-{delivery_id[:8].upper()}",
    }


def _mock_inbox_deliveries(
    filter_status: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Generate mock inbox deliveries for recipient.

    Returns:
        Tuple of (deliveries list, total count).
    """
    now = datetime.now()
    all_deliveries = [
        {
            "id": "d1a2b3c4-e5f6-7890-abcd-ef1234567890",
            "subject": "Mise en demeure - Facture impayee",
            "status": "available",
            "sender_name": None,  # Hidden pre-acceptance
            "created_at": (now - timedelta(days=2)).isoformat(),
            "created_at_formatted": (now - timedelta(days=2)).strftime("%d/%m/%Y"),
            "expires_at": (now + timedelta(days=13)).isoformat(),
            "expires_at_formatted": (now + timedelta(days=13)).strftime("%d/%m/%Y"),
        },
        {
            "id": "d2b3c4d5-f6a7-8901-bcde-f23456789012",
            "subject": "Convocation assemblee generale",
            "status": "notified",
            "sender_name": None,  # Hidden pre-acceptance
            "created_at": (now - timedelta(days=5)).isoformat(),
            "created_at_formatted": (now - timedelta(days=5)).strftime("%d/%m/%Y"),
            "expires_at": (now + timedelta(days=10)).isoformat(),
            "expires_at_formatted": (now + timedelta(days=10)).strftime("%d/%m/%Y"),
        },
        {
            "id": "d3c4d5e6-a7b8-9012-cdef-345678901234",
            "subject": "Resiliation de contrat",
            "status": "accepted",
            "sender_name": "Entreprise ABC",
            "created_at": (now - timedelta(days=10)).isoformat(),
            "created_at_formatted": (now - timedelta(days=10)).strftime("%d/%m/%Y"),
            "expires_at_formatted": None,
        },
        {
            "id": "d4d5e6f7-b8c9-0123-defa-456789012345",
            "subject": None,
            "status": "refused",
            "sender_name": "Cabinet Juridique Martin",
            "created_at": (now - timedelta(days=15)).isoformat(),
            "created_at_formatted": (now - timedelta(days=15)).strftime("%d/%m/%Y"),
            "expires_at_formatted": None,
        },
        {
            "id": "d5e6f7a8-c9d0-1234-efab-567890123456",
            "subject": "Rappel de paiement",
            "status": "expired",
            "sender_name": "Service Contentieux",
            "created_at": (now - timedelta(days=30)).isoformat(),
            "created_at_formatted": (now - timedelta(days=30)).strftime("%d/%m/%Y"),
            "expires_at_formatted": None,
        },
    ]

    # Apply filter if specified
    if filter_status and filter_status != "all":
        if filter_status == "pending":
            deliveries = [d for d in all_deliveries if d["status"] in ("available", "notified")]
        else:
            deliveries = [d for d in all_deliveries if d["status"] == filter_status]
    else:
        deliveries = all_deliveries

    return deliveries, len(deliveries)


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


@router.get("/recipient/refused/{delivery_id}", response_class=HTMLResponse)
async def recipient_refused(request: Request, delivery_id: str) -> HTMLResponse:
    """Render the post-refusal view.

    Shows delivery details with sender identity revealed (per CPCE),
    and refusal proof download. Content is not accessible after refusal.
    """
    templates = _get_templates(request)
    context = build_template_context(
        request,
        user=_mock_user("sender"),  # Mock - would be recipient
        delivery=_mock_delivery_refused(delivery_id),
    )
    return templates.TemplateResponse(request, "recipient/refused.html", context)


@router.get("/recipient/inbox", response_class=HTMLResponse)
async def recipient_inbox(
    request: Request,
    filter: str | None = None,
    page: int = 1,
) -> HTMLResponse:
    """Render the recipient inbox view.

    Lists pending deliveries with status indicators and filter options.
    Pre-acceptance deliveries show redacted sender identity per REQ-F03.
    """
    templates = _get_templates(request)

    # Get mock inbox data (real implementation would query database)
    deliveries, total = _mock_inbox_deliveries(filter)

    # Pagination parameters
    page_size = 20
    total_pages = max(1, (total + page_size - 1) // page_size)

    context = build_template_context(
        request,
        user=_mock_user("sender"),  # Mock - would be recipient
        deliveries=deliveries,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        filter=filter,
    )
    return templates.TemplateResponse(request, "recipient/inbox.html", context)


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
