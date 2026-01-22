"""QERDS API routers.

Each router handles a specific API namespace per specs/implementation/35-apis.md:
- pages: HTML page routes (login, dashboards, pickup, verify)
- auth: Authentication routes (OIDC/FranceConnect+)
- pickup: Recipient pickup portal with auth wall (REQ-E02, REQ-F03)
- sender: Sender operations (authenticated)
- recipient: Recipient portal operations
- consent: Consumer consent management (REQ-F06)
- verify: Third-party verification (public but token-gated)
- admin: Operational/admin endpoints (admin auth)
"""

from qerds.api.routers.admin import router as admin_router
from qerds.api.routers.auth import router as auth_router
from qerds.api.routers.consent import router as consent_router
from qerds.api.routers.pages import router as pages_router
from qerds.api.routers.pickup import router as pickup_router
from qerds.api.routers.recipient import router as recipient_router
from qerds.api.routers.sender import router as sender_router
from qerds.api.routers.verify import router as verify_router

__all__ = [
    "admin_router",
    "auth_router",
    "consent_router",
    "pages_router",
    "pickup_router",
    "recipient_router",
    "sender_router",
    "verify_router",
]
