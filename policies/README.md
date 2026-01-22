# QERDS Policy Documentation

This directory contains the policy and practice statement documents required for QERDS/LRE qualification and conformity assessments.

**Covers**: REQ-A03 (Policies and CPS)

## Document Status

| Document | Status | Published | Last Review |
|----------|--------|-----------|-------------|
| [Security Policy](security-policy.md) | SKELETON | Internal | [TODO] |
| [Incident Policy](incident-policy.md) | SKELETON | Internal | [TODO] |
| [Continuity Policy](continuity-policy.md) | SKELETON | Internal | [TODO] |
| [Key Management Policy](key-management-policy.md) | SKELETON | Internal | [TODO] |
| [Evidence Management Policy](evidence-management-policy.md) | SKELETON | Internal | [TODO] |
| [Privacy Policy](privacy-policy.md) | SKELETON | Published | [TODO] |
| [Certification Practice Statement](cps/README.md) | SKELETON | Published | [TODO] |

## Publication Status

Documents are classified as:

- **Published**: Made available to relying parties, auditors, and the public
- **Internal**: Available to auditors and internal staff only
- **Confidential**: Restricted access (e.g., detailed security configurations)

Per ETSI EN 319 401 and EN 319 521, certain policy information MUST be published to relying parties. The CPS and Privacy Policy are always published. Other policies may have published summaries with internal detailed versions.

## Synchronization with Releases

Policy documents MUST be versioned alongside the platform code:

1. **Version tagging**: Each release includes a snapshot of all policy documents
2. **Evidence references**: Evidence objects reference the policy version in effect at creation time
3. **Audit trail**: Changes to policies are tracked in git history with attributable commits

See: `specs/implementation/80-audit-and-conformity.md` for audit pack requirements.

## Document Principles

These documents follow the DRY (Don't Repeat Yourself) principle:

- **Reference, don't duplicate**: Where implementation details exist in code or specs, reference the authoritative source
- **Normative outcomes**: Focus on WHAT must be true, not HOW (implementation details belong in specs)
- **Cross-references**: Use explicit links to specs, code modules, and requirement IDs

## Normative References

These policies are aligned with:

- ETSI EN 319 401 (General Policy Requirements for Trust Service Providers)
- ETSI EN 319 521 (Policy and Security Requirements for ERDS Providers)
- ETSI EN 319 522 (ERDS Evidence and Interoperability)
- Regulation (EU) 2025/1944 (Implementing rules for eIDAS ERDS)
- France CPCE Articles R.53-1 to R.53-4 and L.100 (LRE requirements)
- GDPR (Data protection requirements)

## Audit Pack Integration

These documents are included in audit packs as required by REQ-H01. The audit pack export includes:

- Current versions of all policy documents
- Historical versions for the audit period (via git)
- Evidence of policy review cycles

See: `specs/implementation/80-audit-and-conformity.md` for complete audit pack contents.

## Directory Structure

```
policies/
├── README.md                      # This file
├── security-policy.md             # Information security management framework
├── incident-policy.md             # Incident detection, handling, notification
├── continuity-policy.md           # Business continuity and disaster recovery
├── key-management-policy.md       # Key lifecycle management
├── evidence-management-policy.md  # Evidence creation, sealing, retention
├── privacy-policy.md              # Data protection and GDPR compliance
└── cps/                           # Certification Practice Statement
    ├── README.md                  # CPS structure overview
    ├── 01-introduction.md
    ├── 02-publication-repository.md
    ├── 03-identification-authentication.md
    ├── 04-certificate-lifecycle.md
    ├── 05-facility-management.md
    ├── 06-technical-security.md
    ├── 07-profile.md
    ├── 08-compliance-audit.md
    └── 09-other-matters.md
```
