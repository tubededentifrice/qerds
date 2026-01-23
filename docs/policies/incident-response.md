# Incident Response Policy

**Document ID**: POL-INC-001
**Version**: 0.1 (TEMPLATE)
**Classification**: Internal
**Covers**: REQ-D01 (Security management), REQ-H04 (Incident response support), REQ-A03 (Policies and CPS)

> **NOTICE**: This is a placeholder policy document. The provider MUST complete all TODO sections with operational details before the service can be considered qualified under eIDAS/ETSI EN 319 401/521.

---

## 1. Scope and Purpose

### 1.1 Scope

This policy applies to all security incidents affecting:

- The QERDS platform and its components
- Evidence integrity or availability
- Service availability or performance
- Personal data processed by the service
- Cryptographic assets or key material

### 1.2 Purpose

This Incident Response Policy establishes the framework for detecting, responding to, and recovering from security incidents affecting the QERDS service. It ensures:

- Timely detection and containment of incidents
- Preservation of evidence for forensic analysis
- Compliance with regulatory notification requirements (eIDAS, GDPR)
- Continuous improvement through post-incident review

### 1.3 Normative References

- Regulation (EU) No 910/2014 (eIDAS), Article 19 (security breach notification)
- Commission Implementing Regulation (EU) 2025/1944
- ETSI EN 319 401 (Section 7.9 - Incident management)
- ETSI EN 319 521 (Section 6.4 - Incident management for ERDS)
- GDPR Articles 33-34 (Data breach notification)

---

## 2. Roles and Responsibilities

> **TODO**: The provider MUST define the specific individuals or roles responsible for incident response.

### 2.1 Incident Response Team

| Role | Responsibilities | Assigned To | Contact |
|------|------------------|-------------|---------|
| Incident Commander | Overall incident coordination, decisions | TODO | TODO |
| Security Lead | Technical analysis, containment | TODO | TODO |
| Communications Lead | Internal/external notifications | TODO | TODO |
| Legal/Compliance | Regulatory notifications, legal advice | TODO | TODO |
| Service Manager | Service impact assessment, customer comms | TODO | TODO |

### 2.2 Escalation Path

> **TODO**: Define escalation contacts and thresholds.

| Severity | Escalation Contact | Response Time |
|----------|-------------------|---------------|
| Critical | TODO | 15 minutes |
| High | TODO | 1 hour |
| Medium | TODO | 4 hours |
| Low | TODO | 24 hours |

---

## 3. Incident Classification

### 3.1 Severity Levels

| Severity | Definition | Examples |
|----------|------------|----------|
| **Critical** | Service unavailable or evidence integrity compromised | Key compromise, data breach affecting evidence, complete service outage |
| **High** | Significant impact on service or data | Partial service degradation, unauthorized access attempt, evidence availability impact |
| **Medium** | Limited impact, contained | Failed intrusion attempt, localized system issue, performance degradation |
| **Low** | Minimal impact, no service disruption | Policy violations, minor misconfigurations, suspicious activity |

### 3.2 Incident Categories

- **Confidentiality**: Unauthorized access to data or systems
- **Integrity**: Unauthorized modification of data, evidence, or systems
- **Availability**: Service disruption or denial of service
- **Key Compromise**: Compromise of cryptographic keys or sealing material
- **Compliance**: Regulatory or policy violations

---

## 4. Detection and Reporting

### 4.1 Detection Sources

The following sources MUST be monitored for incident indicators:

- Application and security logs (tamper-evident audit logs)
- Infrastructure monitoring and alerting
- Intrusion detection systems
- User reports and helpdesk tickets
- Third-party notifications (security researchers, vendors)
- Supervisory body notifications

### 4.2 Reporting Channels

> **TODO**: Define internal and external reporting channels.

**Internal Reporting**:
- TODO: Security hotline/email
- TODO: Ticketing system for incidents
- TODO: Out-of-hours contact procedures

**External Reporting**:
- TODO: Supervisory body contact (for qualified TSP incidents)
- TODO: Data protection authority contact (for personal data breaches)

### 4.3 Reporting Obligations

| Event Type | Notify | Timeframe | Authority |
|------------|--------|-----------|-----------|
| Security breach affecting TSP | Supervisory body | Within 24 hours | eIDAS Art. 19 |
| Personal data breach | Data protection authority | Within 72 hours | GDPR Art. 33 |
| Personal data breach (high risk) | Affected individuals | Without undue delay | GDPR Art. 34 |

---

## 5. Response Procedures

### 5.1 Phase 1: Identification

> **TODO**: Document specific identification procedures.

**Objectives**:
- Confirm incident occurrence
- Classify severity and category
- Activate appropriate response level

**Actions**:
- [ ] Gather initial information (what, when, who, how)
- [ ] Review relevant logs and alerts
- [ ] Classify incident severity
- [ ] Notify Incident Commander (if severity warrants)
- [ ] Open incident ticket with timestamp

### 5.2 Phase 2: Containment

> **TODO**: Document specific containment procedures.

**Objectives**:
- Stop the incident from spreading
- Preserve evidence for analysis
- Minimize service impact

**Actions**:
- [ ] Implement immediate containment (isolate affected systems)
- [ ] Preserve forensic evidence (logs, memory dumps, disk images)
- [ ] Document all containment actions taken
- [ ] Assess need for short-term vs long-term containment

### 5.3 Phase 3: Eradication

> **TODO**: Document specific eradication procedures.

**Objectives**:
- Remove the threat from the environment
- Address root cause

**Actions**:
- [ ] Identify root cause
- [ ] Remove malicious artifacts
- [ ] Patch vulnerabilities
- [ ] Verify eradication complete

### 5.4 Phase 4: Recovery

> **TODO**: Document specific recovery procedures.

**Objectives**:
- Restore service to normal operation
- Verify system integrity
- Monitor for recurrence

**Actions**:
- [ ] Restore from verified clean backups (if needed)
- [ ] Verify evidence integrity post-recovery
- [ ] Implement enhanced monitoring
- [ ] Confirm service restoration

### 5.5 Phase 5: Lessons Learned

**Objectives**:
- Document the incident
- Identify improvements
- Update policies and procedures

**Actions**:
- [ ] Conduct post-incident review (within 5 business days)
- [ ] Document timeline, actions, and outcomes
- [ ] Identify process improvements
- [ ] Update detection rules and procedures
- [ ] Record in incident register

---

## 6. Evidence Preservation

### 6.1 Forensic Requirements

During any incident:

- All actions MUST be timestamped and documented
- System state MUST be captured before making changes
- Chain of custody MUST be maintained for all evidence
- Logs MUST NOT be modified (copy for analysis)

### 6.2 Platform Support

The QERDS platform provides incident response support (per REQ-H04):

- Tamper-evident audit logs
- Log export capabilities
- Timeline reconstruction for deliveries
- Alert integration points

**Reference**: See Admin API documentation for incident investigation endpoints.

---

## 7. Communication

### 7.1 Internal Communication

> **TODO**: Define internal communication procedures.

- Incident status updates: TODO: Frequency and channels
- Stakeholder notification: TODO: Who and when
- All-hands communication: TODO: Criteria and process

### 7.2 External Communication

> **TODO**: Define external communication procedures.

**Regulatory Bodies**:
- eIDAS supervisory body: TODO: Contact and process
- Data protection authority: TODO: Contact and process

**Customers**:
- Impact notification: TODO: Criteria and process
- Status page updates: TODO: URL and process

**Media/Public**:
- All external statements MUST be approved by: TODO: Role
- Designated spokesperson: TODO: Name/Role

---

## 8. Testing and Exercises

### 8.1 Exercise Schedule

| Exercise Type | Frequency | Scope |
|---------------|-----------|-------|
| Tabletop exercise | Quarterly | Response procedures |
| Technical drill | Semi-annually | Detection and containment |
| Full simulation | Annually | End-to-end response |

### 8.2 Exercise Documentation

> **TODO**: Document exercise results and improvements.

All exercises MUST be documented with:
- Scenario description
- Participants
- Findings and gaps
- Action items for improvement

---

## 9. Policy Review

### 9.1 Review Schedule

| Review Type | Frequency | Responsible |
|-------------|-----------|-------------|
| Policy review | Annual minimum | Security Officer |
| Post-incident review | After each significant incident | Incident Commander |
| Contact list update | Quarterly | Service Manager |

### 9.2 Change Triggers

This policy MUST be reviewed and updated when:

- After any significant incident
- Changes to regulatory requirements
- Changes to organizational structure
- Findings from exercises or audits

---

## 10. Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 0.1 | TODO | TODO | Initial template created |
| | | | |
| | | | |

---

## 11. Approval

> **TODO**: This policy MUST be formally approved before the service can be qualified.

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Security Officer | | | |
| Service Manager | | | |
| Legal/Compliance | | | |

---

## Appendix A: Incident Report Template

```
INCIDENT REPORT

Incident ID: INC-YYYY-NNNN
Date/Time Detected:
Date/Time Reported:
Reporter:
Incident Commander:

CLASSIFICATION
Severity: [ ] Critical [ ] High [ ] Medium [ ] Low
Category: [ ] Confidentiality [ ] Integrity [ ] Availability [ ] Key Compromise [ ] Compliance

DESCRIPTION
Brief description:

Systems affected:

Users/data affected:

TIMELINE
- [timestamp] Event description
- [timestamp] Event description

ACTIONS TAKEN
- [timestamp] Action description
- [timestamp] Action description

ROOT CAUSE
Description:

REMEDIATION
Actions completed:
Actions pending:

NOTIFICATIONS
[ ] Supervisory body (if required)
[ ] Data protection authority (if required)
[ ] Affected individuals (if required)

LESSONS LEARNED
Findings:
Improvements:

CLOSURE
Closed by:
Date:
```

---

## References

- `specs/requirements.md` - Requirement specifications
- `docs/policies/security-policy.md` - Security Policy
- `docs/policies/business-continuity.md` - Business Continuity Policy
- `docs/runbooks/backup-dr.md` - Backup and DR procedures
