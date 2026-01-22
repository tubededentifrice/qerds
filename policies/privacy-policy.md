# Privacy Policy

**Document Status**: SKELETON
**Classification**: Published (relying party facing)
**Covers**: REQ-E03, GDPR compliance

## 1. Purpose and Scope

[TODO: Define the purpose and scope of this privacy policy]

This policy describes how the QERDS/LRE service processes personal data, ensuring compliance with:

- GDPR (Regulation (EU) 2016/679)
- France data protection law (Loi Informatique et Libertes)
- ETSI EN 319 401/521 privacy requirements
- CPCE requirements for LRE

**Note**: This is a SKELETON document. The actual privacy policy MUST be reviewed by legal counsel and adapted to the specific operator context.

## 2. Data Controller

[TODO: Identify the data controller]

```
[Provider Name]
[Address]
[Contact Information]
Data Protection Officer: [DPO Contact]
```

## 3. Personal Data Processed

### 3.1 Categories of Personal Data

[TODO: Complete this section based on implementation]

| Category | Data Elements | Purpose | Legal Basis |
|----------|---------------|---------|-------------|
| Sender identity | [TODO] | Delivery attribution | Contract/Legal obligation |
| Recipient identity | [TODO] | Delivery routing | Contract/Legal obligation |
| Delivery content | [TODO] | Service delivery | Contract |
| Evidence data | [TODO] | Legal proof | Legal obligation |
| Access logs | [TODO] | Security/Audit | Legitimate interest |

### 3.2 Special Categories

[TODO: Document if special category data is processed]

The service does not intentionally process special category data. However, delivery content may contain such data under sender control.

## 4. Purposes of Processing

### 4.1 Service Delivery

Personal data is processed to:

- Route deliveries to identified recipients
- Generate legally required evidence
- Provide access to delivery content
- Support verification by authorized parties

### 4.2 Legal Obligations

Personal data is processed to comply with:

- eIDAS ERDS requirements
- CPCE LRE requirements
- Evidence retention obligations

### 4.3 Security and Audit

Personal data is processed for:

- Security monitoring
- Audit trail maintenance
- Incident investigation

## 5. Legal Basis for Processing

[TODO: Confirm legal bases with legal counsel]

| Purpose | Legal Basis (GDPR Art. 6) |
|---------|---------------------------|
| Service delivery | 6(1)(b) Contract |
| Evidence generation | 6(1)(c) Legal obligation |
| Security logging | 6(1)(f) Legitimate interest |
| [TODO: Others] | [TODO] |

## 6. Data Minimisation

**Covers**: REQ-E03

### 6.1 Notification Data Minimisation

Notifications and public-facing endpoints MUST minimise personal data exposure.

**Implementation**: See `specs/implementation/30-lifecycle-and-evidence.md` for notification content rules (REQ-F02, REQ-F03).

### 6.2 Pre-Acceptance Restrictions

Per CPCE (REQ-F03), sender identity MUST NOT be disclosed to recipient before acceptance.

## 7. Data Retention

### 7.1 Retention Periods

[TODO: Define retention periods]

| Data Category | Retention Period | Legal Basis |
|---------------|------------------|-------------|
| Evidence (proofs) | Minimum 1 year (LRE) | CPCE |
| Delivery content | [TODO] | [TODO] |
| Access logs | [TODO] | [TODO] |

### 7.2 Retention Controls

**Implementation**: See `policies/evidence-management-policy.md` and `specs/implementation/70-storage-and-retention.md`.

## 8. Data Subject Rights

### 8.1 Rights Available

Data subjects have the following rights:

- **Access** (Art. 15): Right to access personal data
- **Rectification** (Art. 16): Right to correct inaccurate data
- **Erasure** (Art. 17): Right to erasure (with limitations for legal obligations)
- **Restriction** (Art. 18): Right to restrict processing
- **Portability** (Art. 20): Right to data portability
- **Object** (Art. 21): Right to object to processing

### 8.2 Exercising Rights

[TODO: Provide contact information and process]

To exercise these rights, contact:

```
[Contact method]
```

### 8.3 Limitations

Certain rights may be limited where processing is required for:

- Legal obligations (evidence retention)
- Establishment, exercise, or defense of legal claims

## 9. Data Security

[TODO: Summarize security measures]

Personal data is protected by:

- Encryption at rest and in transit
- Access controls (least privilege)
- Audit logging
- Incident response procedures

**Implementation**: See `policies/security-policy.md` for security framework.

## 10. Data Transfers

### 10.1 International Transfers

[TODO: Document international transfer mechanisms if applicable]

### 10.2 Sub-processors

[TODO: List sub-processors and their purposes]

## 11. Data Breach Notification

In case of a personal data breach:

- Supervisory authority notified within 72 hours (where required)
- Affected data subjects notified without undue delay (where high risk)

**Implementation**: See `policies/incident-policy.md` for breach procedures.

## 12. Contact Information

### 12.1 Data Protection Officer

[TODO: DPO contact information]

### 12.2 Supervisory Authority

[TODO: Relevant supervisory authority]

For France: CNIL (Commission Nationale de l'Informatique et des Libertes)

## 13. Policy Updates

This policy may be updated periodically. The current version is always available at [TODO: publication location].

Last updated: [TODO]

## Cross-References

- **Security Policy**: `policies/security-policy.md`
- **Incident Policy**: `policies/incident-policy.md`
- **Evidence Management**: `policies/evidence-management-policy.md`
- **Data Model**: `specs/implementation/25-data-model.md`
- **Lifecycle and Notifications**: `specs/implementation/30-lifecycle-and-evidence.md`
- **Storage and Retention**: `specs/implementation/70-storage-and-retention.md`

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | [TODO] | [TODO] | Initial skeleton |
