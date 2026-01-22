"""Verification API router.

Handles third-party verification of delivery proofs (CPCE).
Endpoints are public but token-gated for access control.

Covers requirements: REQ-E03, REQ-F01, REQ-F03
See specs/implementation/35-apis.md for API design.
"""

from fastapi import APIRouter

router = APIRouter(
    prefix="/verify",
    tags=["verify"],
    responses={
        400: {"description": "Invalid verification request"},
        404: {"description": "Proof not found"},
    },
)


@router.get("/health")
async def health() -> dict[str, str]:
    """Health check for verify namespace.

    Returns:
        Health status for the verification API subsystem.
    """
    return {"status": "healthy", "namespace": "verify"}


# Future endpoints (stubs for documentation):
# GET /verify/proofs/{proof_id}?token=... - Verify proof and return result
#     Pre-acceptance: Returns provider identity + timestamps + integrity only
#     Post-acceptance: Returns full verification with parties
