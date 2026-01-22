"""Recipient API router.

Handles recipient portal operations for viewing and responding to deliveries.
All endpoints require recipient authentication.

Covers requirements: REQ-E02, REQ-F03, REQ-F04
See specs/implementation/35-apis.md for API design.
"""

from fastapi import APIRouter

router = APIRouter(
    prefix="/recipient",
    tags=["recipient"],
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
    },
)


@router.get("/health")
async def health() -> dict[str, str]:
    """Health check for recipient namespace.

    Returns:
        Health status for the recipient API subsystem.
    """
    return {"status": "healthy", "namespace": "recipient"}


# Future endpoints (stubs for documentation):
# GET /recipient/inbox - List pending deliveries (redacted pre-acceptance)
# GET /recipient/deliveries/{id} - Get delivery details
# POST /recipient/deliveries/{id}/accept - Accept delivery (emit EVT_ACCEPTED)
# POST /recipient/deliveries/{id}/refuse - Refuse delivery (emit EVT_REFUSED)
# GET /recipient/deliveries/{id}/content - Download content (post-acceptance only)
