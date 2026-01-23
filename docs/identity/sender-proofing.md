# Sender Identity Proofing

Covers: REQ-B05 (Sender identity verification methods)

This document describes how QERDS verifies sender identity with "very high confidence" as required by eIDAS/CPCE regulations.

## Requirement Summary

Per REQ-B05, the provider MUST verify the identity of the sender with a very high level of confidence using methods permitted by the applicable implementing rules/standards.

## Supported Proofing Methods

### 1. FranceConnect+ (Primary Method)

**Implementation**: `src/qerds/services/oidc.py`

FranceConnect+ is the primary identity proofing method for French LRE compliance. It provides government-verified identity through the French digital identity platform.

| ACR Claim | IAL Level | Description | Suitable For |
|-----------|-----------|-------------|--------------|
| `eidas2` | IAL2 (Substantial) | Remote identity proofing | Standard LRE senders |
| `eidas3` | IAL3 (High) | In-person proofing with biometric | High-assurance requirements |
| `eidas1` | IAL1 (Low) | Self-asserted | Rejected for LRE senders |

**ACR-to-IAL Mapping** (defined in `ACR_TO_IAL` constant):
```python
ACR_TO_IAL = {
    "eidas2": IALLevel.IAL2,  # Substantial assurance
    "eidas3": IALLevel.IAL3,  # High assurance
    "eidas1": IALLevel.IAL1,  # Low assurance (not accepted for LRE)
}
```

### 2. eIDAS Wallet (Future)

The European Digital Identity (EUDI) Wallet will be supported when available:
- LOA Substantial (equivalent to IAL2)
- LOA High (equivalent to IAL3)
- Cross-border interoperability within EU

**Status**: Not yet implemented. See issue tracking for updates.

### 3. Qualified Certificate (Future)

Qualified electronic signature certificates from qualified trust service providers:
- Certificate validation against EU Trusted Lists
- Maps to IAL3 (certificate issuance requires in-person verification)

**Status**: Not yet implemented. See issue tracking for updates.

### 4. Manual Review Process

For edge cases where automated proofing is not possible:
- Documented identity verification procedure
- Requires operator approval
- Audit trail of verification steps
- Limited to exceptional circumstances

**Status**: Process documented in operational procedures. Technical support implemented via `ProofingMethod.MANUAL_REVIEW` enum.

## Data Model

### SenderProofing Record

See: `src/qerds/db/models/parties.py`

Each identity proofing event creates a `SenderProofing` record:

| Field | Type | Description |
|-------|------|-------------|
| `proofing_id` | UUID | Unique identifier |
| `party_id` | UUID | Reference to the Party being proofed |
| `ial_level` | IALLevel | Achieved assurance level |
| `proofing_method` | ProofingMethod | Method used (FranceConnect+, etc.) |
| `proofed_at` | timestamp | When proofing occurred |
| `proofing_metadata` | JSONB | Provider-specific details (hashed sub, acr, etc.) |
| `expires_at` | timestamp | Session expiry (typically 24 hours) |

### IAL Level Enum

See: `src/qerds/db/models/base.py`

```python
class IALLevel(enum.Enum):
    IAL1 = "ial1"  # Self-asserted (email verification)
    IAL2 = "ial2"  # Remote proofing (FranceConnect)
    IAL3 = "ial3"  # In-person proofing (FranceConnect+)
```

### ProofingMethod Enum

```python
class ProofingMethod(enum.Enum):
    EMAIL_VERIFICATION = "email_verification"  # IAL1
    FRANCECONNECT = "franceconnect"            # IAL2
    FRANCECONNECT_PLUS = "franceconnect_plus"  # IAL2/IAL3
    MANUAL_REVIEW = "manual_review"            # Operator verified
```

## Authentication Flow

### Sender Registration Flow

```
1. Sender clicks "Sign in with FranceConnect+"
   -> GET /auth/login?flow=sender_identity

2. System generates state/nonce, redirects to FranceConnect+
   -> Redirect to FC+ authorization endpoint with acr_values=eidas2

3. User authenticates with FranceConnect+
   -> FC+ performs identity verification at IAL2/IAL3

4. FC+ redirects back with authorization code
   -> GET /auth/callback?code=...&state=...

5. System exchanges code for tokens
   -> POST to FC+ token endpoint

6. System fetches user info and maps ACR to IAL
   -> map_acr_to_ial(acr_claim)

7. System creates/updates Party record
   -> Links to external_id (hashed FC+ sub)

8. System creates SenderProofing record
   -> create_identity_proofing_record()
   -> Stores IAL level, method, metadata, expiry

9. System creates authenticated session
   -> Session metadata includes ial_level, proofing_id
```

### Code References

- Authorization URL generation: `FranceConnectService.create_authorization_url()`
- Token exchange: `FranceConnectService.exchange_code()`
- Identity verification: `FranceConnectService.verify_identity()`
- Proofing record: `create_identity_proofing_record()`
- Session creation: `_create_authenticated_session()` in `auth.py`

## Evidence Integration

### EVT_DEPOSITED Event

When a sender deposits content, the evidence event includes:

```python
event_metadata = {
    "sender_ial_level": "ial2",  # From session
    "content_count": 2,
    # Actor identification includes proofing reference
    "actor_identification": {
        "actor_type": "sender",
        "actor_ref": "<party_id>",
        # Future: "identity_proofing_ref": "<proofing_id>"
    }
}
```

See: `src/qerds/api/routers/sender.py` (deposit_delivery function)

### Recipient Actions

Pickup service enforces IAL requirements per jurisdiction:

```python
IAL_REQUIREMENTS = {
    "fr_lre": IALLevel.IAL2,  # CPCE requires substantial
    "eidas": IALLevel.IAL1,   # Base eIDAS allows lower
}
```

See: `src/qerds/services/pickup.py`

## Security Considerations

### Privacy Protection

- FranceConnect+ `sub` identifier is hashed before logging
- Only hash prefix stored in proofing_metadata (8 chars)
- Full claims not stored (only essential fields)

### Session Security

- State parameter: 256 bits entropy (CSRF protection)
- Nonce parameter: 256 bits entropy (replay protection)
- Constant-time comparison for state validation
- Session expiry: 24 hours (proofing validity)

### Token Handling

- Client secret stored as SecretStr (Pydantic)
- ID token nonce validated to prevent replay
- Access tokens not persisted beyond session

## Compliance Checklist

- [x] ACR-to-IAL mapping implemented
- [x] IAL level stored in SenderProofing record
- [x] IAL level included in session metadata
- [x] IAL level included in EVT_DEPOSITED event_metadata
- [x] Pickup service enforces IAL requirements
- [x] Privacy-preserving logging (hashed identifiers)
- [ ] Identity proofing reference linked to evidence events (enhancement)
- [ ] eIDAS wallet support (future)
- [ ] Qualified certificate support (future)

## Test Coverage

Tests for identity proofing are in:
- `tests/test_oidc.py` - OIDC flow and ACR mapping tests
- `tests/test_identity_proofing.py` - Proofing record tests (TODO)

Key test scenarios:
- eidas2 maps to IAL2
- eidas3 maps to IAL3
- eidas1 maps to IAL1 (rejected for LRE)
- Unknown ACR defaults to IAL1
- Proofing record created on successful authentication
- Session includes IAL level metadata
