"""Sender API router.

Handles sender operations for creating and managing deliveries.
All endpoints require sender authentication.

Covers requirements: REQ-B01, REQ-B02, REQ-B03, REQ-B05, REQ-C01
See specs/implementation/35-apis.md for API design.
"""

from fastapi import APIRouter

router = APIRouter(
    prefix="/sender",
    tags=["sender"],
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
    },
)


@router.get("/health")
async def health() -> dict[str, str]:
    """Health check for sender namespace.

    Returns:
        Health status for the sender API subsystem.
    """
    return {"status": "healthy", "namespace": "sender"}


# Future endpoints (stubs for documentation):
# POST /sender/deliveries - Create draft delivery
# GET /sender/deliveries - List sender's deliveries
# GET /sender/deliveries/{id} - Get delivery details
# POST /sender/deliveries/{id}/content - Upload content object
# POST /sender/deliveries/{id}/deposit - Submit delivery (emit EVT_DEPOSITED)
# DELETE /sender/deliveries/{id} - Cancel draft delivery
