# CPS Section 1: Introduction

**Document Status**: SKELETON
**Classification**: Published

## 1.1 Overview

[TODO: Provide service overview]

This Certification Practice Statement (CPS) describes the practices employed by [Provider Name] in operating the QERDS/LRE (Qualified Electronic Registered Delivery Service / Lettre Recommandee Electronique) platform.

### 1.1.1 Service Description

The service provides:

- Electronic registered delivery with proof of sending and receiving
- Evidence generation for legally relevant events
- Secure content transmission with confidentiality protection
- Compliance with eIDAS Article 44 and France CPCE requirements

**Implementation**: See `specs/implementation/05-architecture.md` for service architecture.

## 1.2 Document Name and Identification

[TODO: Assign OID if required]

| Field | Value |
|-------|-------|
| Document Title | QERDS/LRE Certification Practice Statement |
| Document Version | 0.1 (SKELETON) |
| Document OID | [TODO: Assign if required] |
| Publication Date | [TODO] |

## 1.3 Participants

### 1.3.1 Provider

[TODO: Provider identification]

```
[Provider Legal Name]
[Registered Address]
[Registration Number]
[Qualified Status: TODO]
```

### 1.3.2 Subscribers (Senders)

Subscribers are entities that use the service to send registered deliveries.

**Identity verification**: See Section 3 and `specs/implementation/20-identities-and-roles.md` for sender identity verification requirements (REQ-B05).

### 1.3.3 Recipients

Recipients are individuals or entities that receive registered deliveries.

**Identification**: See Section 3 and `specs/implementation/20-identities-and-roles.md` for recipient identification (REQ-B03).

### 1.3.4 Relying Parties

Relying parties include:

- Courts and legal authorities
- Third parties verifying evidence
- Auditors and conformity assessment bodies

## 1.4 Service Usage

### 1.4.1 Appropriate Uses

[TODO: Define appropriate uses]

The service is intended for:

- Legally significant communications requiring proof of delivery
- Compliance with registered mail requirements (France LRE)
- [TODO: Other approved uses]

### 1.4.2 Prohibited Uses

[TODO: Define prohibited uses]

The service MUST NOT be used for:

- [TODO: List prohibited uses]

## 1.5 Policy Administration

### 1.5.1 Organization Administering the Document

[TODO: Responsible organization]

### 1.5.2 Contact Information

[TODO: Contact details]

```
Policy Administration Contact:
[Name/Role]
[Email]
[Phone]
[Address]
```

### 1.5.3 CPS Approval Procedures

[TODO: Define approval process]

Changes to this CPS require:

- [TODO: Approval requirements]

## 1.6 Definitions and Acronyms

### 1.6.1 Definitions

| Term | Definition |
|------|------------|
| ERDS | Electronic Registered Delivery Service |
| QERDS | Qualified Electronic Registered Delivery Service |
| LRE | Lettre Recommandee Electronique (France) |
| Evidence | Electronic data proving a lifecycle event |
| Qualified Seal | Electronic seal meeting eIDAS qualified requirements |
| [TODO] | [Additional definitions as needed] |

### 1.6.2 Acronyms

| Acronym | Expansion |
|---------|-----------|
| CPS | Certification Practice Statement |
| eIDAS | Electronic Identification, Authentication and Trust Services |
| CPCE | Code des Postes et Communications Electroniques |
| HSM | Hardware Security Module |
| QSCD | Qualified Signature/Seal Creation Device |
| TSA | Time-Stamping Authority |
| [TODO] | [Additional acronyms] |

## Cross-References

- **Service Architecture**: `specs/implementation/05-architecture.md`
- **Identities and Roles**: `specs/implementation/20-identities-and-roles.md`
- **Requirements**: `specs/requirements.md`

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | [TODO] | [TODO] | Initial skeleton |
