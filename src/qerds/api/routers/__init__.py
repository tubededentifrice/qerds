"""QERDS API routers.

Each router handles a specific API namespace per specs/implementation/35-apis.md:
- sender: Sender operations (authenticated)
- recipient: Recipient portal operations
- verify: Third-party verification (public but token-gated)
- admin: Operational/admin endpoints (admin auth)
"""

from qerds.api.routers.admin import router as admin_router
from qerds.api.routers.recipient import router as recipient_router
from qerds.api.routers.sender import router as sender_router
from qerds.api.routers.verify import router as verify_router

__all__ = ["admin_router", "recipient_router", "sender_router", "verify_router"]
