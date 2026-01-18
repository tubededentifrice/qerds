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

The platform MUST track, for each sender/recipient identity:

- `ial_level`: an assurance level indicator (e.g., `IAL_LOW`, `IAL_SUBSTANTIAL`, `IAL_HIGH`).
- `proofing_method`: enumerated source.

### Selected Proofing Strategies (REQ-B05)

The platform implements an **Identity Broker** supporting three primary flows:

1.  **FranceConnect+ (Primary for LRE)**:
    -   Used to automatically assert `IAL_SUBSTANTIAL` or `IAL_HIGH`.
    -   Required for LRE recipients (non-professional) to accept delivery (CPCE R.53-3).
    -   Implementation: OIDC Client with specific ACR checks.

2.  **Generic OIDC (eIDAS Nodes)**:
    -   Support for external eIDAS nodes or corporate IdPs.
    -   The platform MUST map the provider's `acr` (Authentication Context Class Reference) claims to internal IALs.
    -   If `acr` is insufficient, the user remains at `IAL_LOW` until further verification.

3.  **Manual / Operator Verification (Fallback)**:
    -   A "Registration Authority" workflow for users lacking supported eID.
    -   **Process**: User uploads ID documents -> "Registration Officer" (Operator staff) reviews -> Officer signs an `EVT_IDENTITY_VERIFIED` event -> User IAL is upgraded.
    -   Strict separation of duties: Registration Officers are distinct from System Admins.

## Recipient identification and access gates

The platform MUST enforce that only the intended recipient can access delivered content (REQ-E02):

- Content access is mediated by a **recipient session** bound to a recipient identity.
- **Magic Links are insufficient**: A link sent via email serves ONLY as a "Claim Token" (proof of possession of the email address). It DOES NOT grant access to the content.
- **Authentication Wall**: Upon clicking the link, the recipient MUST authenticate (e.g., via FranceConnect+) to prove their identity matches the intended recipient (REQ-F01).

**For LRE (CPCE) mode**:
- The platform MUST enforce `IAL_SUBSTANTIAL` for the recipient before allowing "Acceptance" or "Refusal" actions.

The platform MUST also support recipient-as-consumer consent to electronic LRE (REQ-F06):

- `consumer_consent = true/false`
- `consent_evidence_ref` (who, when, how, what was consented to)
- Consent MUST be checked before initiating LRE notifications for consumers.

## Authorization (RBAC/ABAC) and separation of duties

The platform MUST implement least privilege and separation of duties (REQ-D02, REQ-H06):

- Role classes: `admin`, `security_officer`, `auditor`, `support`, `registration_officer`, `sender_user`, `recipient_user`, `api_client`.
- ABAC attributes (examples): organization membership, case assignment, environment, purpose-of-access.
- Sensitive operations (evidence export, key operations, config changes) MUST require dual-control where policy requires it, and must be logged. (REQ-D02, REQ-H07)

## Identity data minimisation

All outward-facing representations (notifications, verification responses) MUST minimize personal data; support redaction profiles and jurisdiction-specific templates. (REQ-E03, REQ-F02, REQ-F03)
