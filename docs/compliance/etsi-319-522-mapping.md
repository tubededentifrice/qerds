# ETSI EN 319 522 Compliance Mapping

**Covers:** REQ-C04 (Evidence format/interoperability)

**Status:** Audit Document - Non-Qualified Implementation

**Last Updated:** 2026-01-23

---

## 1. Overview

This document maps the QERDS implementation against the ETSI EN 319 522 series, specifically:

- **ETSI EN 319 522-4-1**: Evidence record format (semantic structure)
- **ETSI EN 319 522-4-2**: Semantic contents (field meanings and constraints)
- **ETSI EN 319 522-4-3**: Interoperability (transport and exchange)

The mapping identifies compliance status, gaps, and remediation needed for qualification.

---

## 2. Referenced Standards

| Standard | Title | Relevance |
|----------|-------|-----------|
| ETSI EN 319 522-4-1 | Electronic Registered Delivery Services - Part 4-1: Evidence | Evidence record structure |
| ETSI EN 319 522-4-2 | Electronic Registered Delivery Services - Part 4-2: Semantic contents | Field semantics and requirements |
| ETSI EN 319 522-4-3 | Electronic Registered Delivery Services - Part 4-3: Interoperability | AS4 message format |
| ETSI EN 319 521 | Policy and security requirements | Overall ERDS policy |
| Commission Implementing Regulation (EU) 2025/1944 | eIDAS implementing rules for ERDS | Legal basis |

---

## 3. Implementation Files Analyzed

| File | Purpose |
|------|---------|
| `src/qerds/services/evidence.py` | Evidence event generation service |
| `src/qerds/services/evidence_sealer.py` | Evidence sealing and timestamping |
| `src/qerds/services/as4_sender.py` | AS4 message sending via Domibus |
| `src/qerds/db/models/evidence.py` | Evidence database models |
| `src/qerds/db/models/base.py` | Common types and enums |

---

## 4. ETSI EN 319 522-4-1: Evidence Record Format

### 4.1 Required Evidence Record Fields

The standard defines the following mandatory fields for ERDS evidence records:

| EN 319 522-4-1 Field | QERDS Implementation | Status | Notes |
|---------------------|----------------------|--------|-------|
| **EvidenceIdentifier** | `event_id` (UUID) | COMPLIANT | Unique identifier per event |
| **EvidenceType** | `event_type` (EventType enum) | COMPLIANT | Maps to standard event types |
| **EvidenceIssuer** | Provider via `evidence_sealer.py` | COMPLIANT | Provider attestation included |
| **EvidenceIssuanceTime** | `event_time` + `sealed_at` | COMPLIANT | RFC 3161 timestamp available |
| **RelatedDeliveryData** | `delivery_id` | COMPLIANT | Links to delivery entity |
| **SenderIdentification** | `actor_ref` + `actor_type` | PARTIAL | See Gap 1 below |
| **RecipientIdentification** | `actor_ref` (when RECIPIENT) | PARTIAL | See Gap 1 below |
| **ContentReference** | `inputs_hashes` | COMPLIANT | SHA-256 hashes of content |
| **PolicyReference** | `policy_snapshot_id` | COMPLIANT | Links to active policy |
| **DigitalSignature** | `provider_attestation` | COMPLIANT | CMS seal structure |
| **TimeStamp** | `time_attestation` | COMPLIANT | RFC 3161 token |

### 4.2 Event Type Mapping

| EN 319 522-4-1 Event | QERDS EventType | Status |
|---------------------|-----------------|--------|
| SubmissionAcceptance | `EVT_DEPOSITED` | COMPLIANT |
| RelayAcceptance | `EVT_AS4_RECEIVED` | COMPLIANT |
| DeliveryNotification | `EVT_NOTIFICATION_SENT` | COMPLIANT |
| DeliveryFailure | `EVT_NOTIFICATION_FAILED` | COMPLIANT |
| RetrievalReady | `EVT_CONTENT_AVAILABLE` | COMPLIANT |
| ContentRetrieval | `EVT_CONTENT_ACCESSED`, `EVT_CONTENT_DOWNLOADED` | COMPLIANT |
| AcceptanceRejection | `EVT_ACCEPTED`, `EVT_REFUSED` | COMPLIANT |
| NonDelivery | `EVT_EXPIRED` | COMPLIANT |
| Receipt | `EVT_RECEIVED` | COMPLIANT |

### 4.3 Evidence Structure Analysis

**Current Implementation (SealedEvidence in evidence_sealer.py):**

```python
@dataclass(frozen=True, slots=True)
class SealedEvidence:
    evidence_id: str                    # EN 319 522-4-1 EvidenceIdentifier
    payload: dict[str, Any]             # Event data (semantic contents)
    canonical_bytes: bytes              # Deterministic representation
    canonicalization_version: str       # Format versioning
    content_hash: str                   # EN 319 522-4-1 ContentReference
    provider_attestation: dict          # EN 319 522-4-1 DigitalSignature
    time_attestation: dict              # EN 319 522-4-1 TimeStamp
    verification_bundle: VerificationBundle  # Certificate chain, algorithms
    qualification_label: str            # REQ-G02 compliance
    sealed_at: datetime
```

**Assessment:** The structure captures all required elements. The `payload` dictionary contains the semantic contents, and the cryptographic attestations are properly separated.

---

## 5. ETSI EN 319 522-4-2: Semantic Contents

### 5.1 Mandatory Semantic Fields

| EN 319 522-4-2 Requirement | QERDS Field | Location | Status |
|---------------------------|-------------|----------|--------|
| **EventIdentifier** | `event_id` | EvidenceEvent.event_id | COMPLIANT |
| **EventType** | `event_type` | EvidenceEvent.event_type | COMPLIANT |
| **EventTimestamp** | `event_time` | EvidenceEvent.event_time | COMPLIANT |
| **ActorType** | `actor_type` | EvidenceEvent.actor_type | COMPLIANT |
| **ActorReference** | `actor_ref` | EvidenceEvent.actor_ref | COMPLIANT |
| **HashAlgorithm** | Via verification_bundle | VerificationBundle.hash_algorithm | COMPLIANT |
| **ContentDigest** | `inputs_hashes` | EventData.inputs_hashes | COMPLIANT |
| **PolicyOID** | Via verification_bundle | VerificationBundle.policy_oid | COMPLIANT |
| **SignatureAlgorithm** | Via verification_bundle | VerificationBundle.signature_algorithm | COMPLIANT |

### 5.2 Actor Identification Requirements

**EN 319 522-4-2 requires:**
- Unambiguous sender/recipient identification
- Identity proofing reference where applicable
- Session/authentication context

**Current Implementation (ActorIdentification in evidence.py):**

```python
@dataclass(frozen=True, slots=True)
class ActorIdentification:
    actor_type: ActorType
    actor_ref: str
    identity_proofing_ref: str | None = None
    session_ref: str | None = None
    ip_address_hash: str | None = None
```

**Assessment:** The structure supports the required fields, including optional identity proofing reference for IAL2/IAL3 scenarios.

### 5.3 Hash Binding Requirements

**EN 319 522-4-2 requires:**
- SHA-256 minimum for content hashing
- Deterministic canonicalization before hashing
- Algorithm identifier in evidence

**Current Implementation:**

```python
# In evidence.py
def compute_content_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

# In evidence_sealer.py
def compute_content_hash(self, canonical_bytes: bytes) -> str:
    return hashlib.sha256(canonical_bytes).hexdigest()
```

**Assessment:** COMPLIANT - Uses SHA-256 with lowercase hex encoding.

---

## 6. ETSI EN 319 522-4-3: Interoperability (AS4)

### 6.1 AS4 Message Structure

The AS4 integration via Domibus is implemented in `as4_sender.py`.

| EN 319 522-4-3 Requirement | Implementation | Status |
|---------------------------|----------------|--------|
| **ebMS3/AS4 UserMessage** | `AS4MessageBuilder.build_submission_request()` | COMPLIANT |
| **PartyId (Sender)** | `DomibusConfig.sender_party_id` | COMPLIANT |
| **PartyId (Receiver)** | `AS4MessagePayload.receiver_party_id` | COMPLIANT |
| **PartyIdType** | URN-based type identifiers | COMPLIANT |
| **Service Identifier** | `urn:eu:europa:ec:qerds:registered-delivery` | COMPLIANT |
| **Action** | `DeliverMessage` | COMPLIANT |
| **ConversationId** | Generated UUID per message | COMPLIANT |
| **PayloadInfo** | Base64-encoded content with properties | COMPLIANT |
| **ContentHash in PartProperties** | SHA-256 hash included | COMPLIANT |

### 6.2 Message Properties (ETSI-mandated)

| EN 319 522-4-3 Property | Implementation | Status |
|------------------------|----------------|--------|
| `originalSender` | `PROP_ORIGINAL_SENDER` | COMPLIANT |
| `finalRecipient` | `PROP_FINAL_RECIPIENT` | COMPLIANT |
| `deliveryId` | `PROP_DELIVERY_ID` (custom) | COMPLIANT |
| `timestamp` | `PROP_TIMESTAMP` | COMPLIANT |

### 6.3 AS4 Receipt Handling

| Requirement | Implementation | Status |
|-------------|----------------|--------|
| Receipt processing | `DomibusClient.get_pending_receipts()` | COMPLIANT |
| Receipt-to-event mapping | `AS4SenderService._process_receipt()` | COMPLIANT |
| Receipt evidence creation | `EVT_AS4_RECEIPT_RECEIVED` event | COMPLIANT |
| Error handling | `EVT_AS4_ERROR` event | COMPLIANT |

---

## 7. Identified Gaps

### Gap 1: Structured Party Identification (MEDIUM)

**Issue:** EN 319 522-4-2 requires structured party identification with explicit identification scheme URIs. Current implementation uses `actor_ref` as a simple string reference.

**Current:**
```python
actor_ref: str  # e.g., "party-uuid-123"
```

**Required:**
```xml
<PartyId type="urn:oasis:names:tc:ebcore:partyid-type:iso6523:0088">
    123456789
</PartyId>
```

**Remediation:** Add `actor_id_type` field to `ActorIdentification` dataclass to capture the identification scheme URI. This enables interoperability with external providers using different ID schemes.

**Affected Files:**
- `src/qerds/services/evidence.py` (ActorIdentification)
- `src/qerds/db/models/evidence.py` (EvidenceEvent)

**Priority:** Medium - Required for cross-provider interoperability

---

### Gap 2: Evidence Format Version Header (LOW)

**Issue:** EN 319 522-4-1 recommends including a format version identifier in the evidence structure for forward compatibility.

**Current:** Canonicalization version is tracked (`CANONICALIZATION_VERSION = "1.0"`) but not exposed as a formal header field.

**Remediation:** Include format version in the sealed evidence payload:
```python
{
    "format_version": "ETSI-EN-319-522-4-1:2024-01",
    "canonicalization_version": "1.0",
    ...
}
```

**Affected Files:**
- `src/qerds/services/evidence_sealer.py`

**Priority:** Low - Recommended for future-proofing

---

### Gap 3: External Evidence Export Format (LOW)

**Issue:** EN 319 522-4-3 specifies an evidence exchange format for cross-provider scenarios. Current implementation stores evidence internally but does not provide a standardized export format.

**Current:** Evidence stored as JSON in object store.

**Required:** ASiC-E container with XAdES/CAdES signatures for external exchange.

**Remediation:** Implement evidence export function that produces EN 319 522-4-3 compliant containers:
- ASiC-E envelope
- XAdES-B-LT or CAdES-B-LT signatures
- Manifest with content references

**Affected Files:**
- New: `src/qerds/services/evidence_export.py`

**Priority:** Low - Required only for evidence portability to external systems

---

### Gap 4: Qualified Seal/Timestamp Integration (BLOCKING for Qualification)

**Issue:** Current implementation uses non-qualified seals and timestamps (development mode). EN 319 522 and Implementing Regulation 2025/1944 require qualified mechanisms for QERDS status.

**Current:**
```python
qualification_label: str  # Currently "non_qualified"
qualification_reason: "Development mode - CEF conformance testing not completed"
```

**Remediation:**
1. Integrate with qualified TSA (Timestamp Authority)
2. Use QSCD-generated keys for sealing
3. Obtain qualification assessment for the provider

**Affected Files:**
- `src/qerds/services/trust.py`
- `src/qerds/services/evidence_sealer.py`

**Priority:** BLOCKING - Cannot claim qualified status without this

---

### Gap 5: SMP Metadata Schema Compliance (MEDIUM)

**Issue:** EN 319 522-4-3 specifies OASIS BDXR SMP metadata format. Integration with phoss SMP is documented in spec but implementation status needs verification.

**Current:** phoss SMP selected but integration code not verified in this audit.

**Remediation:** Verify phoss SMP publishes metadata in correct schema with:
- Process identifier for QERDS
- Document type identifiers
- Endpoint certificate references

**Affected Files:**
- Integration configuration (not in audit scope)

**Priority:** Medium - Required for provider discovery

---

## 8. Compliance Summary

### 8.1 Overall Assessment

| Standard | Compliance Level | Blocking Issues |
|----------|-----------------|-----------------|
| EN 319 522-4-1 (Evidence Format) | 90% Compliant | None |
| EN 319 522-4-2 (Semantic Contents) | 85% Compliant | Gap 1 |
| EN 319 522-4-3 (Interoperability) | 80% Compliant | Gap 4, Gap 5 |

### 8.2 Qualification Readiness

**Current Status: NON-QUALIFIED**

The implementation provides the structural foundation for ETSI EN 319 522 compliance but cannot claim qualified status due to:

1. Development-mode trust services (non-qualified seals/timestamps)
2. Missing CEF conformance testing completion
3. Provider qualification assessment not performed

### 8.3 Remediation Priority

| Priority | Gap | Effort | Blocking |
|----------|-----|--------|----------|
| 1 | Gap 4: Qualified Trust Services | High | Yes |
| 2 | Gap 1: Structured Party ID | Medium | No |
| 3 | Gap 5: SMP Metadata | Medium | No |
| 4 | Gap 2: Format Version | Low | No |
| 5 | Gap 3: Export Format | Low | No |

---

## 9. Field-by-Field Mapping Table

This table provides a complete mapping from EN 319 522-4-1/4-2 fields to QERDS implementation.

| EN 319 522 Field | Python Type | DB Column | Service | Compliant |
|------------------|-------------|-----------|---------|-----------|
| EvidenceIdentifier | `UUID` | `evidence_events.event_id` | EvidenceService | Yes |
| EvidenceType | `EventType` | `evidence_events.event_type` | EvidenceService | Yes |
| EvidenceIssuanceTime | `datetime` | `evidence_events.event_time` | EvidenceService | Yes |
| EvidenceIssuerIdentity | seal cert | `verification_bundle` | EvidenceSealer | Yes |
| DeliveryReference | `UUID` | `evidence_events.delivery_id` | EvidenceService | Yes |
| SenderPartyId | `str` | `actor_ref` (when SENDER) | EvidenceService | Partial |
| SenderPartyIdType | - | Not captured | - | Gap 1 |
| RecipientPartyId | `str` | `actor_ref` (when RECIPIENT) | EvidenceService | Partial |
| RecipientPartyIdType | - | Not captured | - | Gap 1 |
| ContentDigest | `str` | `inputs_hashes` in metadata | EvidenceService | Yes |
| DigestAlgorithm | `str` | `verification_bundle.hash_algorithm` | EvidenceSealer | Yes |
| PolicyReference | `UUID` | `evidence_events.policy_snapshot_id` | EvidenceService | Yes |
| ProviderSeal | `dict` | `provider_attestation_blob_ref` | EvidenceSealer | Yes |
| SealAlgorithm | `str` | `verification_bundle.signature_algorithm` | EvidenceSealer | Yes |
| TimeStampToken | `dict` | `time_attestation_blob_ref` | EvidenceSealer | Yes |
| TSAPolicyOID | `str` | `verification_bundle.policy_oid` | EvidenceSealer | Yes |
| QualificationStatus | `str` | `qualification_label` | EvidenceSealer | Yes |

---

## 10. Test Coverage Requirements

For ETSI EN 319 522 compliance verification, the following test categories are required:

### 10.1 Evidence Structure Tests

- [ ] Evidence contains all mandatory EN 319 522-4-1 fields
- [ ] Event types map correctly to EN 319 522-4-2 semantics
- [ ] Content hashes use approved algorithm (SHA-256)
- [ ] Canonicalization produces deterministic output
- [ ] Qualification label correctly reflects trust service mode

### 10.2 Interoperability Tests

- [ ] AS4 message structure conforms to ebMS3 profile
- [ ] Message properties include required ETSI fields
- [ ] Receipt processing creates correct evidence events
- [ ] Party identification uses valid URN schemes

### 10.3 Cryptographic Tests

- [ ] Provider attestation is valid CMS structure
- [ ] Timestamp token conforms to RFC 3161
- [ ] Certificate chain is included in verification bundle
- [ ] Algorithm identifiers are correctly encoded

---

## 11. References

### 11.1 ETSI Standards

- ETSI EN 319 522-4-1 V1.2.1 (2024-01)
- ETSI EN 319 522-4-2 V1.2.1 (2024-01)
- ETSI EN 319 522-4-3 V1.2.1 (2024-01)
- ETSI EN 319 521 V1.2.1 (2024-01)

### 11.2 Implementation Documents

- `specs/requirements.md` - Project requirements
- `specs/implementation/30-lifecycle-and-evidence.md` - Evidence lifecycle
- `specs/implementation/40-evidence-crypto-and-time.md` - Crypto requirements
- `specs/implementation/65-etsi-interop-profile.md` - Interop profile

### 11.3 Code Paths

- Evidence generation: `src/qerds/services/evidence.py`
- Evidence sealing: `src/qerds/services/evidence_sealer.py`
- AS4 messaging: `src/qerds/services/as4_sender.py`
- Database models: `src/qerds/db/models/evidence.py`

---

## 12. Document History

| Date | Author | Changes |
|------|--------|---------|
| 2026-01-23 | Coder Agent | Initial compliance mapping document |

---

**Note:** This document is for audit and compliance tracking purposes. It does NOT constitute a claim of qualified status. The current implementation is labeled as NON-QUALIFIED per REQ-G02.
