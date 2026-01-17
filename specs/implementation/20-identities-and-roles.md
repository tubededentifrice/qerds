# Identities, parties, and authorization model

Covers: REQ-B03, REQ-B05, REQ-D02, REQ-E02, REQ-F06, REQ-H06

## Parties and core identities

The platform models at least these parties:

- **Provider operator**: the entity operating the platform instance.
- **Sender**: the party submitting/depositing content for delivery (REQ-B03).
- **Recipient**: the intended addressee (REQ-B03).
- **Relying party / verifier**: a third party verifying evidence, potentially with an identifier (CPCE) (REQ-F01).
- **Administrator / operator staff**: privileged users performing operational tasks (REQ-D02, REQ-H06).

Each party MAY be represented by:

- a natural person identity,
- a legal person identity (organization),
- a delegated representative (acting on behalf of a legal person).

## Identity assurance levels (IAL) and proofing

The platform MUST track, for each sender identity:

- `ial_level`: an assurance level indicator suitable to demonstrate “very high confidence” for the chosen onboarding method (REQ-B05).
- `proofing_method`: enumerated source (e.g., high-assurance eID, in-person ID, qualified certificate), to be aligned with applicable implementing rules/standards (REQ-B05).
- `proofing_evidence_refs`: references to stored proofing artifacts (documents, logs, third-party assertions), protected and access-controlled.

Non-obvious decision point (requires operator policy): the set of accepted proofing methods and what constitutes “very high” for the jurisdiction/use case. This MUST be configurable but auditable. (REQ-B05, REQ-A03)

## Recipient identification and access gates

The platform MUST enforce that only the intended recipient can access delivered content (REQ-E02):

- Content access is mediated by a **recipient session** bound to a recipient identity.
- Recipient authentication MUST be “strong enough” for the legal model and threat model.
- **For LRE (CPCE) mode**: The platform MUST enforce that non-professional recipients are identified at a level equivalent to **eIDAS Substantial** (or higher), as required by CPCE R.53-3. The platform MUST support integration with appropriate IdPs (e.g., FranceConnect+ or equivalent) to satisfy this. (REQ-B03, REQ-F01)

The platform MUST also support recipient-as-consumer consent to electronic LRE (REQ-F06):

- `consumer_consent = true/false`
- `consent_evidence_ref` (who, when, how, what was consented to)
- Consent MUST be checked before initiating LRE notifications for consumers.

## Authorization (RBAC/ABAC) and separation of duties

The platform MUST implement least privilege and separation of duties (REQ-D02, REQ-H06):

- Role classes: `admin`, `security_officer`, `auditor`, `support`, `sender_user`, `recipient_user`, `api_client`.
- ABAC attributes (examples): organization membership, case assignment, environment, purpose-of-access.
- Sensitive operations (evidence export, key operations, config changes) MUST require dual-control where policy requires it, and must be logged. (REQ-D02, REQ-H07)

## Identity data minimisation

All outward-facing representations (notifications, verification responses) MUST minimize personal data; support redaction profiles and jurisdiction-specific templates. (REQ-E03, REQ-F02, REQ-F03)

