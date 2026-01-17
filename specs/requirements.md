# Qualified Electronic Registered Delivery Service (QERDS)
## Technical Specification (State-of-the-Art, eIDAS-compliant)

**Version:** 1.0  
**Scope:** This document defines all technical requirements for implementing an **open-source Qualified Electronic Registered Delivery Service (QERDS)** compliant with **eIDAS Article 44**, **ETSI EN 319 521 / 522**, and applicable French CPCE requirements (LRE).  
**Audience:** Engineering, security, cryptography, compliance, auditors.  
**Non-goal:** Business, pricing, or UI polish. This is a compliance-first technical spec.

---

## 1. Normative References (MUST comply)

The implementation MUST be designed to meet the following standards:

- Regulation (EU) No 910/2014 (eIDAS), **Article 44**
- ETSI EN 319 521 — Policy and security requirements for ERDS/QERDS
- ETSI EN 319 522-1/2/3 — Evidence formats, interfaces, event models
- ETSI EN 319 401 — General requirements for Trust Service Providers
- ETSI TS 119 461 — Identity proofing & verification
- French CPCE (L.100, R.53-1 et seq.) for LRE-specific rules

All requirements below are written assuming **Qualified** status (QERDS).  
Non-qualified ERDS is a strict subset and MUST NOT violate these constraints.

---

## 2. Core Legal-Technical Guarantees (Non-Negotiable)

The system MUST provide cryptographic and procedural guarantees for:

1. **Integrity** of content and metadata
2. **Identification** of sender and addressee
3. **Qualified time reference** for all lifecycle events
4. **Confidentiality** of content
5. **Traceability & non-repudiation** through signed evidence
6. **Long-term verifiability** (≥ 7 years)

Failure on any point breaks QERDS qualification.

---

## 3. System Architecture (Logical)

### 3.1 Mandatory Components

The system MUST be decomposed into the following logical components:

1. **ERDS Core Engine**
2. **Evidence & State Machine**
3. **Cryptographic Trust Services**
4. **Identity & Authentication Layer**
5. **Recipient Delivery Portal**
6. **Notification & Channel Manager**
7. **Evidence Store & Long-Term Archive**
8. **Audit & Verification Toolkit**

Each component MUST be independently auditable and testable.

---

## 4. Data Model (Canonical)

### 4.1 Registered Item

A *Registered Item* is the immutable object representing one delivery.

```json
RegisteredItem {
  item_id: UUIDv7,
  sender_id: SubjectID,
  recipient_id: SubjectID,
  content_objects: [ContentObject],
  metadata: Metadata,
  creation_time: ISO8601,
  content_hash: SHA256,
  item_hash: SHA256
}

	•	content_hash = hash of canonicalized content
	•	item_hash = hash(content_hash + metadata)
	•	Canonicalization MUST be deterministic and documented

4.2 ContentObject

ContentObject {
  type: "PDF" | "BINARY",
  original_bytes_hash: SHA256,
  rendered_bytes_hash: SHA256 | null,
  transformation_declared: boolean
}

If transformation occurs (HTML → PDF, etc.), it MUST be:
	•	explicitly declared
	•	recorded as evidence
	•	visible to sender and recipient

⸻

5. Identity & Authentication

5.1 Identity Assurance Levels

Actor | Minimum Level | Notes
Sender | HIGH | Required for QERDS
Recipient | SUBSTANTIAL | Before content release



5.2 Identity Proofing (TS 119 461)

Supported methods MUST include at least one of:
	•	Qualified certificate authentication
	•	Remote identity proofing (video / NFC / bank-ID style)
	•	Government eID (where available)

5.3 Identity Binding

Each subject MUST have:
SubjectID {
  subject_id: UUID,
  legal_identity_hash: SHA256,
  assurance_level: ENUM,
  proofing_events: [EvidenceRef]
}


Identity proofing events MUST be signed and timestamped evidence.

⸻

6. Delivery State Machine (Deterministic)

6.1 States

DRAFT
→ SUBMITTED
→ ACCEPTED_BY_SERVICE
→ NOTIFIED
→ (IDENTIFIED_RECIPIENT)
→ MADE_AVAILABLE
→ RECEIVED | REFUSED | EXPIRED

No state transition MAY occur without generating evidence.

6.2 Mandatory Events

Event | Evidence Required
Submission | Proof of Deposit
Acceptance | Proof of Acceptance
Notification | Proof of Notification
Identification | Proof of Identification
Availability | Proof of Availability
Receipt | Proof of Receipt
Refusal | Proof of Refusal
Expiry | Proof of Non-Claim

7. Evidence Model (Core of QERDS)

7.1 Evidence Object

Evidence {
  evidence_id: UUID,
  item_id: UUID,
  event_type: ENUM,
  event_time: QualifiedTimestamp,
  payload_hash: SHA256,
  signature: QualifiedElectronicSeal,
  previous_evidence_hash: SHA256 | null
}


	•	Evidence objects form a hash-chained ledger
	•	No deletion or mutation is permitted

7.2 Signatures & Timestamps
	•	All evidence MUST be sealed with a Qualified Electronic Seal
	•	All timestamps MUST be Qualified Electronic Time Stamps
	•	TSA failures MUST block state transitions

⸻

8. Cryptography & Key Management

8.1 Algorithms (Minimum)
	•	Hash: SHA-256 or stronger
	•	Symmetric: AES-256-GCM
	•	Asymmetric: RSA-3072 or ECC P-256+
	•	Signatures: ETSI-approved (CAdES / XAdES / JAdES)

8.2 Key Storage
	•	Private keys MUST be generated and stored in HSM or equivalent
	•	Dual control required for key operations
	•	Key rotation policy MUST exist and be enforced

⸻

9. Confidentiality & Access Control

9.1 Content Encryption
	•	Each Registered Item MUST use a unique DEK
	•	DEKs MUST be wrapped by KEK in HSM/KMS
	•	Content MUST NOT be accessible pre-identification

9.2 Access Rules


Actor | Access
Sender | Status + proofs only
Recipient | Content only after identification
Operator | No plaintext access

All access MUST generate audit logs.

⸻

10. Notification & Consent Logic (France-specific)

10.1 Recipient Type

RecipientType = PROFESSIONAL | CONSUMER

	•	CONSUMER requires prior consent to electronic delivery
	•	Consent MUST be stored as signed evidence

10.2 Notification Channels
	•	Email mandatory
	•	SMS recommended
	•	Notification MUST NOT expose content or sender identity

⸻

11. Retention & Long-Term Archiving

11.1 Minimum Retention

Artifact | Minimum
Proof of Deposit | 1 year
Other Evidence | 7 years

11.2 Crypto Aging
	•	Evidence MUST support re-timestamping
	•	Certificate chains, CRLs, OCSP MUST be preserved
	•	Archive MUST be WORM-like (append-only)

⸻

12. Operational Security Controls

The system MUST implement:
	•	Change management & signed releases
	•	Incident response & breach notification workflow
	•	Continuous monitoring (availability, TSA errors, queue health)
	•	Backup + disaster recovery with tested restores
	•	Separation of duties (ops / security / audit)

⸻

13. Audit & Verification Toolkit (Mandatory)

13.1 Verification CLI

An open-source verification tool MUST be provided to:
	•	Verify all evidence signatures and timestamps
	•	Reconstruct item state from evidence chain
	•	Detect missing or invalid transitions
	•	Produce human-readable audit reports

13.2 Audit Pack Generator

The system MUST be able to export:
	•	Evidence samples
	•	Configuration snapshots
	•	Cryptographic parameters
	•	Policy documents
	•	SBOM
	•	Key ceremony logs

⸻

14. Interoperability
	•	Evidence formats MUST follow ETSI EN 319 522
	•	Portal-based delivery is RECOMMENDED
	•	SMTP delivery MAY be supported but MUST NOT be relied upon for legal receipt

⸻

15. Open-Source Requirements
	•	Reproducible builds
	•	Deterministic hashing
	•	Signed releases
	•	Clear mapping:
eIDAS Article 44 → ETSI Control → Code Module → Test

⸻

16. Explicit Non-Compliance Traps (MUST avoid)
	•	Email-only “delivery”
	•	Unsigned or non-qualified timestamps
	•	Identity = email ownership
	•	Mutable logs
	•	Operator plaintext access
	•	Missing refusal / expiry evidence

⸻

17. Final Statement

If any single requirement in this document is not met, the system MUST NOT claim QERDS / LRE qualification.

This specification is intentionally strict:
auditors do not certify intentions — they certify invariants.
