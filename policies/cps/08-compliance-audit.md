# CPS Section 8: Compliance Audit and Other Assessments

**Document Status**: SKELETON
**Classification**: Published (summary), Internal (details)
**Covers**: REQ-A02, REQ-A04, REQ-H01

## 8.1 Frequency and Circumstances of Assessment

### 8.1.1 Conformity Assessment Schedule

**Covers**: REQ-A02

[TODO: Define assessment schedule]

Conformity assessments are conducted:

- Initial: Prior to qualified status
- Periodic: At least every 24 months per eIDAS requirements
- Event-triggered: Following material changes

### 8.1.2 Surveillance Audits

[TODO: Define surveillance audit schedule]

### 8.1.3 Extraordinary Audits

Extraordinary audits may be triggered by:

- Security incidents
- Material changes to service
- Regulatory request
- [TODO: Other triggers]

## 8.2 Identity and Qualifications of Assessor

### 8.2.1 Assessor Requirements

[TODO: Define assessor requirements]

Conformity assessment bodies MUST be:

- Accredited per applicable EU requirements
- Independent from the provider
- Qualified for ERDS assessment

### 8.2.2 Assessor Relationship

[TODO: Define relationship requirements]

## 8.3 Assessor's Relationship to Assessed Entity

[TODO: Define independence requirements]

The assessor MUST be independent and have no conflicts of interest.

## 8.4 Topics Covered by Assessment

### 8.4.1 Assessment Scope

**Covers**: REQ-A02

Conformity assessment covers:

- Policy compliance (this CPS, related policies)
- Technical security controls
- Operational procedures
- Key management practices
- Evidence handling procedures
- Incident response capabilities
- Business continuity arrangements

### 8.4.2 Standards Assessed Against

Assessments verify compliance with:

- ETSI EN 319 401 (General TSP requirements)
- ETSI EN 319 521 (ERDS policy requirements)
- ETSI EN 319 522 (ERDS evidence and interop)
- Implementing Regulation (EU) 2025/1944
- [TODO: Additional standards]

## 8.5 Actions Taken as a Result of Deficiency

### 8.5.1 Non-Conformity Handling

[TODO: Define non-conformity handling]

Non-conformities are classified as:

- Major: Service suspension until resolved
- Minor: Corrective action within defined period
- Observation: Addressed in continuous improvement

### 8.5.2 Corrective Action

[TODO: Define corrective action process]

## 8.6 Communication of Results

### 8.6.1 Internal Communication

[TODO: Define internal communication]

### 8.6.2 Supervisory Authority Communication

Assessment results are communicated to the supervisory authority per eIDAS requirements.

### 8.6.3 Public Communication

[TODO: Define public communication policy]

## 8.7 Audit Pack Production

**Covers**: REQ-H01

### 8.7.1 Audit Pack Contents

The platform produces audit packs containing:

- Evidence samples with verification bundles
- Log integrity proofs
- Configuration snapshots
- Cryptographic policy documentation
- Key lifecycle ceremony logs
- Backup/DR exercise reports
- Vulnerability/pentest reports
- Incident timeline exports
- Policy/CPS documents
- SBOM and release metadata

**Implementation**: See `specs/implementation/80-audit-and-conformity.md` for complete audit pack specification.

### 8.7.2 Audit Pack Generation

Audit packs MUST:

- Be immutable once generated (sealed/timestamped)
- Record generation metadata (who, why, authorization)
- Support redaction profiles for different recipients

### 8.7.3 On-Demand Generation

Audit packs can be generated on demand for a defined time range.

## 8.8 Traceability Matrix

**Covers**: REQ-A04

### 8.8.1 Requirements Traceability

The project maintains a traceability matrix mapping:

- Requirement ID to implementation modules
- Requirement ID to verification artifacts (tests, audit evidence)

**Implementation**: See `specs/traceability.md` for the traceability mapping.

### 8.8.2 Traceability Maintenance

The traceability matrix is:

- Updated with each release
- Reviewed during conformity assessments
- Versioned alongside the codebase

## Cross-References

- **Audit Pack Requirements**: `specs/implementation/80-audit-and-conformity.md`
- **Traceability**: `specs/traceability.md`
- **Requirements**: `specs/requirements.md`
- **Security Policy**: `policies/security-policy.md`
- **Incident Policy**: `policies/incident-policy.md`
- **Continuity Policy**: `policies/continuity-policy.md`

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | [TODO] | [TODO] | Initial skeleton |
