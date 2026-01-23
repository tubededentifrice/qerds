# QERDS Qualification Guide

This guide explains what a trust service provider needs to do to obtain and maintain **Qualified Electronic Registered Delivery Service (QERDS)** status under the eIDAS Regulation.

This document covers REQ-A01 (Qualification) and REQ-G01 (No misleading claims).

## What is QERDS Qualification?

### eIDAS Article 44 Overview

The eIDAS Regulation (EU No 910/2014) establishes the legal framework for electronic registered delivery services in the EU. Article 44 defines the requirements that an electronic registered delivery service must meet to be considered "qualified."

A **qualified electronic registered delivery service (QERDS)** must:

1. Be provided by one or more qualified trust service provider(s)
2. Ensure identification of the sender with a high level of confidence
3. Ensure identification of the addressee before delivery
4. Secure sending and receiving of data with an advanced electronic seal or signature
5. Provide evidence of sending and receiving with qualified timestamps
6. Detect any alteration to the transmitted data

### Qualified vs Non-Qualified Distinction

| Aspect | Non-Qualified ERDS | Qualified ERDS (QERDS) |
|--------|-------------------|------------------------|
| Provider status | Any provider | Must be a qualified trust service provider |
| Supervision | Self-declared | Supervised by national authority |
| Conformity assessment | Optional | Mandatory, by accredited CAB |
| Trusted list | Not listed | Listed in EU Trusted Lists |
| Legal presumption | Must prove reliability in court | Presumption of data integrity and accurate sending/receiving timestamps (Article 44(2)) |
| Cryptographic requirements | Flexible | Must use qualified seals/timestamps |
| Interoperability | Optional | Required per implementing regulations |

### Legal Implications of Qualification

**Article 44(2) Presumption**: A qualified electronic registered delivery service enjoys the presumption of:

- Integrity of the data transmitted
- Sending of that data by the identified sender
- Receipt of that data by the identified addressee
- Accuracy of the date and time of sending and receipt indicated

This presumption shifts the burden of proof: rather than the sender having to prove delivery occurred, anyone disputing delivery must prove the evidence is incorrect.

**Cross-Border Recognition**: QERDS qualified in one EU Member State must be recognized as qualified throughout the EU (Article 44(3)).

## Prerequisites for Qualification

### Provider Organizational Requirements

Before seeking QERDS qualification, the provider must:

1. **Be a legal entity** established in an EU Member State (or with equivalent arrangements)

2. **Demonstrate financial stability** sufficient to operate a trust service and cover potential liabilities

3. **Have appropriate insurance or financial guarantees** to cover liability arising from the service

4. **Employ qualified personnel** with:
   - Knowledge of electronic registered delivery procedures
   - Security management expertise
   - Cryptographic operations experience
   - Incident response capabilities

5. **Establish governance structures** including:
   - Documented policies (security, incident, continuity, key management)
   - Defined roles and responsibilities
   - Management commitment to compliance

### Trust Service Provider Status

QERDS qualification builds on being a **qualified trust service provider** (QTSP). The provider must either:

- **Already be a QTSP** for another service (e.g., qualified signatures, seals, timestamps), or
- **Become a QTSP** specifically for ERDS

Requirements for QTSP status (eIDAS Article 24) include:

- Information security management system conforming to relevant standards
- Financial resources and liability coverage
- Reliable systems and products
- Qualified personnel
- Protection against forgery and theft of data
- Records retention (at minimum for the legal retention period after service termination)

### Conformity Assessment Body Selection

The provider must select a **conformity assessment body (CAB)** that is:

1. **Accredited** by the national accreditation body of an EU Member State
2. **Competent** to assess trust services, specifically ERDS
3. **Independent** from the provider being assessed

Finding a CAB:

- Check with your national supervisory body (list at: [EU Trusted Lists](https://eidas.ec.europa.eu/efda/tl-browser/))
- Look for CABs accredited under ISO/IEC 17065 for trust services
- Verify the CAB has experience with ERDS assessments

## Qualification Process Overview

### Phase 1: Preparation (3-6 months)

1. **Gap analysis**: Compare current operations against ETSI EN 319 401 and EN 319 521 requirements

2. **Policy development**: Create or update:
   - Trust Service Practice Statement (for ERDS)
   - Certificate/Evidence Policy
   - Security Policy
   - Key Management Policy
   - Business Continuity Plan
   - Incident Response Plan

3. **Technical implementation**: Deploy platform with all required capabilities:
   - Evidence generation for all lifecycle events
   - Qualified timestamps integration
   - Qualified seal/signature integration
   - Tamper-evident logging
   - Sender/recipient identification
   - Content confidentiality protection

4. **Operational readiness**: Establish:
   - Secure operations environment
   - Personnel training and awareness
   - Monitoring and alerting
   - Backup and recovery procedures

### Phase 2: Initial Conformity Assessment (1-3 months)

1. **Engage the CAB**: Provide documentation and access for assessment

2. **Document review**: CAB reviews policies, procedures, and technical documentation

3. **Technical assessment**: CAB evaluates:
   - Platform security controls
   - Cryptographic implementations
   - Evidence generation and protection
   - Identification mechanisms
   - Interoperability compliance

4. **Operational assessment**: CAB evaluates:
   - Physical security
   - Personnel security
   - Operational procedures
   - Incident handling capabilities

5. **Findings remediation**: Address any non-conformities identified

6. **Conformity assessment report**: CAB issues report stating conformity (or non-conformity) with requirements

### Phase 3: Notification and Trusted List Inclusion (1-3 months)

1. **Submit to supervisory body**: Provider submits:
   - Conformity assessment report
   - Supporting documentation
   - Notification of intent to provide qualified ERDS

2. **Supervisory body review**: National authority reviews submission

3. **Trusted list inclusion**: Upon approval, the service is added to the national trusted list and propagated to the EU-wide list

4. **Publication**: Service is now legally qualified and can claim QERDS status

### Phase 4: Ongoing Supervision

Qualification is not a one-time event. Ongoing obligations include:

- **Periodic audits**: At least every 24 months (per eIDAS Article 20)
- **Incident reporting**: Notify supervisory body of security breaches within 24 hours
- **Change notification**: Report material changes to service or organization
- **Annual reports**: Submit required operational reports
- **Continuous compliance**: Maintain all requirements at all times

## Platform Support for Qualification

### What the QERDS Platform Provides

The platform implements technical controls and generates evidence to support qualification:

| Requirement | Platform Capability | Operator Responsibility |
|-------------|---------------------|------------------------|
| Evidence generation (REQ-C01) | Generates evidence for all lifecycle events | Configure retention policies |
| Evidence authenticity (REQ-C02) | Applies seals/signatures to evidence | Provision qualified seal credentials |
| Trusted time (REQ-C03) | Integrates with timestamp services | Configure qualified TSA endpoint |
| Tamper-evident logs (REQ-C05, REQ-H03) | Hash-chained audit logs | Monitor log integrity, retain logs |
| Sender identification (REQ-B03, REQ-B05) | Supports high-assurance identification | Configure identity providers (e.g., FranceConnect+) |
| Confidentiality (REQ-E01) | Envelope encryption (AES-256-GCM) | Manage key material securely |
| Access control (REQ-D02) | RBAC/ABAC enforcement | Configure roles, conduct access reviews |
| Audit support (REQ-H01) | Audit pack export API | Generate packs for assessors |
| Traceability (REQ-A04) | Traceability matrix API | Maintain mapping to tests/evidence |

### What the Provider Must Do

The platform is a tool. The provider must:

1. **Operate the platform securely**
   - Deploy in a secure environment (see `docs/deployment/operator-checklist.md`)
   - Configure network security per `docs/deployment/network-security.md`
   - Implement backup/DR per `docs/runbooks/backup-dr.md`

2. **Integrate qualified trust services**
   - Provision and configure qualified timestamp service access
   - Provision and configure qualified seal/signature credentials
   - Ensure HSM/QSCD for qualified key storage (REQ-D04)

3. **Maintain operational compliance**
   - Conduct quarterly vulnerability scans (REQ-D05)
   - Arrange annual penetration tests (REQ-D06)
   - Perform periodic access reviews (REQ-H06)
   - Execute DR exercises (REQ-H08)

4. **Maintain documentation**
   - Keep policies current
   - Document configuration and changes
   - Retain evidence for required periods

5. **Handle incidents**
   - Monitor for security events
   - Respond to incidents per documented procedures
   - Report to supervisory body as required

### Configuration for Qualified Operation

To operate in qualified mode, set the environment variable:

```bash
QERDS_CLAIM_STATE=qualified
```

This setting:
- Enables strict validation of qualified prerequisites (HSM, qualified TSA, etc.)
- Enforces qualified-mode-only cryptographic operations
- Labels all evidence as qualified
- Prevents fallback to non-qualified alternatives

**Do not set this to `qualified` unless:**
- The provider is actually qualified and supervised
- The service is listed in the EU Trusted Lists
- All operational prerequisites are met

The platform also supports `QERDS_CLAIM_STATE=development` and `QERDS_CLAIM_STATE=non-qualified` for testing and non-qualified operation respectively. These modes clearly label all evidence as non-qualified.

## France LRE Specifics

When operating an LRE (lettre recommandee electronique) service in France, additional requirements from the CPCE (Code des postes et des communications electroniques) apply.

### CPCE Requirements Additional to eIDAS

| CPCE Requirement | eIDAS Equivalent | Additional Detail |
|------------------|------------------|-------------------|
| Recipient information (R. 53-2) | Partially covered | Must provide permanent access to proofs; third-party verification |
| Notification content (R. 53-3) | Not specified | Specific required information; pre-acceptance content restrictions |
| Sender identity protection | Not specified | Sender identity must not be disclosed before accept/refuse |
| 15-day acceptance window | Not specified | Minimum 15 days for recipient to act |
| Proof retention (R. 53-4) | General retention | Minimum 1 year for proof of receipt |
| Consumer consent (L. 100) | GDPR consent | Explicit prior consent for consumers to receive LRE |
| Human-readable proofs | Not specified | PDF receipts following French practice models |

### ARCEP Notification

The CPCE does not currently require ARCEP (Autorite de regulation des communications electroniques) notification specifically for LRE providers. However:

- If the LRE service involves telecommunications activities, ARCEP notification may apply
- Check current ARCEP guidance for any updates to notification requirements
- The supervisory body for trust services in France is ANSSI (Agence nationale de la securite des systemes d'information)

### French Qualification Path

For LRE qualification in France:

1. **Choose a French CAB** or one with mutual recognition for French trust services
2. **Engage with ANSSI** early to understand current requirements
3. **Meet both eIDAS and CPCE requirements** - the French trusted list includes both
4. **Consider dual qualification** if operating cross-border (some providers obtain qualification in multiple Member States)

## References

### Primary Legal Sources

- [eIDAS Regulation 910/2014](https://eur-lex.europa.eu/eli/reg/2014/910/oj) - Base regulation for electronic identification and trust services
- [Implementing Regulation 2025/1944](https://eur-lex.europa.eu/eli/reg_impl/2025/1944/oj) - Implementing rules for ERDS
- [CPCE L.100](https://www.legifrance.gouv.fr/codes/article_lc/LEGIARTI000031367432) - French LRE general provisions
- [CPCE R.53-2](https://www.legifrance.gouv.fr/codes/article_lc/LEGIARTI000031367428) - Recipient information requirements
- [CPCE R.53-3](https://www.legifrance.gouv.fr/codes/article_lc/LEGIARTI000031367426) - Notification content requirements

### Standards

- ETSI EN 319 401 - General policy requirements for trust service providers
- ETSI EN 319 521 - Policy and security requirements for ERDS providers
- ETSI EN 319 522 - ERDS evidence and interoperability (parts referenced in Implementing Regulation 2025/1944, Annex II)

### Platform Documentation

- `specs/requirements.md` - Full requirements specification
- `README.md` - Requirements status tracking
- `docs/deployment/operator-checklist.md` - Deployment and operational checklist
- `docs/deployment/network-security.md` - Network security configuration
- `docs/runbooks/backup-dr.md` - Backup and disaster recovery procedures

### External Resources

- [EU Trusted Lists Browser](https://eidas.ec.europa.eu/efda/tl-browser/) - Find qualified providers and CABs
- [ANSSI Trust Services](https://www.ssi.gouv.fr/en/regulation/) - French supervisory body for trust services

## Revision History

| Date | Change |
|------|--------|
| 2026-01-23 | Initial version |
