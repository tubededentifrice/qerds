# Penetration Testing Runbook

**Covers**: REQ-D06 (Penetration testing), REQ-H09 (Vulnerability management evidence)

This runbook documents the penetration testing procedures for QERDS platform operators. All testing activities and findings MUST be recorded in the platform's vulnerability management system for audit compliance.

## Table of Contents

1. [Overview](#overview)
2. [Pentest Requirements](#pentest-requirements)
3. [Engagement Planning](#engagement-planning)
4. [Types of Testing](#types-of-testing)
5. [During the Engagement](#during-the-engagement)
6. [Results Processing](#results-processing)
7. [Remediation Workflow](#remediation-workflow)
8. [Recording Evidence](#recording-evidence)
9. [Internal Testing Option](#internal-testing-option)

---

## Overview

The QERDS platform requires annual penetration testing to meet eIDAS and ETSI EN 319 401 compliance requirements. This runbook provides procedures for planning, executing, and documenting penetration tests.

**Key Compliance Requirements**:
- Penetration testing at least once per year (REQ-D06)
- Testing of all externally-facing and critical internal systems
- Qualified testers with appropriate certifications
- All findings MUST be tracked and remediated
- Evidence MUST be exportable for audits (REQ-H09)

---

## Pentest Requirements

### Frequency

| Test Type | Minimum Frequency | When to Schedule |
|-----------|-------------------|------------------|
| External network pentest | Annually | Q1 recommended |
| Web application pentest | Annually | After major releases |
| API security testing | Annually | With application test |
| Retest after critical findings | Within 30 days | After remediation |

**Note**: Testing frequency may increase based on:
- Major infrastructure changes
- Significant application updates
- Post-incident requirements
- Regulatory mandate changes

### Scope

**In-scope systems** (MUST be tested):
- All externally-facing endpoints (public APIs, web interfaces)
- Authentication and authorization mechanisms
- Evidence generation and verification systems
- Cryptographic implementations
- Administrative interfaces
- API gateways and load balancers

**Critical internal systems** (MUST be tested):
- Database servers
- Key management systems (`qerds-trust`)
- Internal service-to-service communication
- Backup and recovery systems
- Audit log systems

### Tester Qualifications

The penetration testing provider MUST demonstrate:

| Requirement | Verification |
|-------------|--------------|
| Relevant certifications | OSCP, OSCE, GPEN, CREST, or equivalent |
| Experience with trust services | Prior engagements with TSPs, CAs, or similar |
| Insurance coverage | Professional liability insurance |
| NDA willingness | Signed before engagement |
| Independence | No conflicts of interest with the operator |

**Recommended certifications**:
- Offensive Security Certified Professional (OSCP)
- CREST Registered Penetration Tester
- GIAC Penetration Tester (GPEN)
- Certified Ethical Hacker (CEH) - as minimum baseline

---

## Engagement Planning

### Selecting a Pentest Provider

1. **Request proposals** from at least 3 qualified providers
2. **Evaluate proposals** against:
   - Methodology (OWASP, PTES, OSSTMM)
   - Team qualifications
   - Past experience with similar systems
   - Reporting quality (request sample reports)
   - Cost and timeline
3. **Check references** from similar engagements
4. **Verify insurance** and professional indemnity coverage

### Defining Scope and Rules of Engagement

Document the following in a formal Rules of Engagement (RoE) document:

**Scope Definition**:
```
Target Systems:
- Production: [yes/no - typically no for initial test]
- Staging: [yes/no]
- IP ranges: [list specific ranges]
- Domains: [list domains]
- Excluded systems: [any systems explicitly out of scope]

Testing Windows:
- Start date/time: [YYYY-MM-DD HH:MM UTC]
- End date/time: [YYYY-MM-DD HH:MM UTC]
- Permitted hours: [e.g., 09:00-18:00 local time]
```

**Permitted Activities**:
- Vulnerability scanning
- Manual exploitation attempts
- Password attacks (within limits)
- Social engineering (if approved - see below)

**Prohibited Activities**:
- Denial of service attacks (unless explicitly approved)
- Physical security testing (unless explicitly approved)
- Testing of third-party systems not owned by operator
- Data exfiltration of real user data
- Modification of production data

### Timing and Coordination

**Pre-engagement checklist**:

1. [ ] Sign NDA with testing provider
2. [ ] Sign Rules of Engagement document
3. [ ] Notify relevant stakeholders (operations, security, management)
4. [ ] Prepare test environment (if using staging)
5. [ ] Ensure monitoring is active to detect testing
6. [ ] Confirm emergency contact procedures
7. [ ] Document baseline system state

**Recommended timing**:
- Schedule during lower-traffic periods
- Avoid testing during critical business periods
- Allow buffer time before audit deadlines

### Emergency Contacts

Maintain a contact list for the engagement:

| Role | Contact | When to Contact |
|------|---------|-----------------|
| Operator Security Lead | [name, phone, email] | Any security concerns |
| Operations Team | [name, phone, email] | System availability issues |
| Pentest Lead | [name, phone, email] | Questions about scope |
| Management Escalation | [name, phone, email] | Critical findings |

---

## Types of Testing

### External Network Penetration Test

**Objective**: Identify vulnerabilities in externally-accessible infrastructure.

**Methodology**:
1. Reconnaissance (passive and active)
2. Port and service enumeration
3. Vulnerability identification
4. Exploitation attempts
5. Post-exploitation (if successful)
6. Documentation

**Key areas**:
- Firewall configuration
- Exposed services
- TLS/SSL configuration
- DNS security
- Network segmentation from external perspective

### Web Application Testing (OWASP Methodology)

**Objective**: Identify vulnerabilities in web applications following OWASP Testing Guide.

**OWASP Top 10 coverage** (MUST test all):
1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery (SSRF)

**Application-specific focus areas for QERDS**:
- Evidence generation integrity
- Signature and seal verification
- Time-stamping mechanisms
- Access control for deliveries
- Recipient identification flows

### API Security Testing

**Objective**: Identify vulnerabilities in REST/API endpoints.

**Key areas**:
- Authentication bypass
- Authorization flaws (BOLA, BFLA)
- Input validation
- Rate limiting
- Error handling and information disclosure
- API versioning issues

**QERDS-specific API tests**:
- `/api/v1/deliveries` - authorization controls
- `/api/v1/evidence` - integrity verification
- `/admin/*` - privilege escalation
- Webhook endpoints - SSRF and injection

### Social Engineering (Optional)

**When to include**: Only when explicitly approved by management.

**Types**:
- Phishing simulations (email-based)
- Vishing (phone-based)
- Physical access attempts

**Considerations**:
- Requires separate approval
- Must comply with employment law
- Results handled sensitively
- Focus on awareness improvement, not blame

---

## During the Engagement

### Monitoring for Issues

During active testing, the operations team SHOULD:

1. **Monitor system health**:
   ```bash
   # Check service status
   docker compose ps

   # Monitor resource usage
   docker stats

   # Check application logs for errors
   docker compose logs -f qerds-api
   ```

2. **Watch for unexpected impacts**:
   - Service degradation
   - Unusual error rates
   - Authentication failures spike
   - Resource exhaustion

3. **Distinguish testing from real attacks**:
   - Testers MUST use agreed-upon source IPs
   - Maintain communication channel for verification

### Communication Protocols

**Daily standups** (recommended for engagements > 3 days):
- Testers report progress
- Discuss any blockers
- Adjust scope if needed

**Immediate escalation** required for:
- Discovery of active compromise (not from testing)
- Critical vulnerability with evidence of prior exploitation
- System outage caused by testing
- Discovery of sensitive data exposure

**Communication channels**:
- Primary: Secure messaging (Signal, encrypted email)
- Backup: Phone (for emergencies)
- Documentation: Secure file sharing (encrypted)

### Out-of-Scope Handling

If testers discover potential issues in out-of-scope systems:

1. **Stop testing** the out-of-scope system immediately
2. **Document** what was discovered (without exploitation)
3. **Notify** the operator security lead
4. **Await decision** on whether to expand scope
5. **Update RoE** if scope is expanded

---

## Results Processing

### Receiving and Reviewing the Report

**Report delivery timeline**:
- Draft report: Within 5 business days of testing completion
- Review period: 5 business days for operator comments
- Final report: Within 3 business days of receiving comments

**Report contents** (MUST include):
- Executive summary
- Scope and methodology
- Findings with severity ratings
- Evidence (screenshots, logs, PoC code)
- Remediation recommendations
- Retest recommendations

### Severity Classification

Use a standard severity classification aligned with CVSS:

| Severity | CVSS Score | Description | Response Time |
|----------|------------|-------------|---------------|
| **Critical** | 9.0-10.0 | Immediate exploitation risk, system compromise | Immediate |
| **High** | 7.0-8.9 | Significant vulnerability, exploitation likely | 7 days |
| **Medium** | 4.0-6.9 | Moderate risk, exploitation possible | 30 days |
| **Low** | 0.1-3.9 | Minor risk, exploitation unlikely | 90 days |
| **Informational** | N/A | Best practice recommendations | As resources allow |

### Remediation Planning

For each finding, document:

1. **Finding ID**: Unique identifier for tracking
2. **Severity**: Using classification above
3. **Affected system(s)**: Specific components
4. **Root cause**: Why the vulnerability exists
5. **Remediation owner**: Person responsible
6. **Remediation plan**: Technical fix approach
7. **Target date**: Based on severity
8. **Verification method**: How to confirm fix

---

## Remediation Workflow

### Critical/High Findings: Immediate Remediation

**Timeline**: Begin remediation within 24 hours, complete within 7 days.

**Process**:

1. **Triage** (within 4 hours):
   - Confirm finding is valid
   - Assess actual impact in context
   - Identify immediate mitigations

2. **Mitigate** (within 24 hours):
   - Apply temporary controls (WAF rules, access restrictions)
   - Document mitigation in place

3. **Remediate** (within 7 days):
   - Develop and test fix
   - Deploy fix through change management
   - Verify fix in staging

4. **Verify** (within 14 days):
   - Request retest from pentest provider
   - Or perform internal verification with documented evidence

### Medium Findings: Planned Remediation

**Timeline**: Complete within 30 days.

**Process**:

1. **Prioritize** based on:
   - Exploitability
   - Business impact
   - Fix complexity

2. **Schedule** remediation work:
   - Add to sprint/development cycle
   - Assign owner and target date

3. **Track** progress:
   - Weekly status updates
   - Escalate if timeline slips

4. **Verify** fix before closing

### Low Findings: Risk Acceptance Review

**Timeline**: Review within 90 days, remediate or accept.

**Options**:

1. **Remediate**: Fix when convenient (e.g., during related work)
2. **Accept risk**: Document formal risk acceptance with:
   - Business justification
   - Compensating controls (if any)
   - Review date (maximum 1 year)
   - Approver signature (security lead + management)

### Retest Coordination

After remediation of Critical/High findings:

1. **Request retest** from original pentest provider
2. **Provide**:
   - List of remediated findings
   - Description of fixes applied
   - Access to updated environment
3. **Receive** retest report confirming:
   - Finding resolved, or
   - Finding persists (requires further work)
4. **Document** retest results in vulnerability tracking

---

## Recording Evidence

**CRITICAL**: All penetration testing activities and findings MUST be recorded in the platform for audit compliance.

### Recording a Pentest Engagement

Use the Admin API endpoint:

```bash
curl -X POST https://qerds.example.com/admin/vulnerability/pentest \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "engagement_id": "pentest-2024-annual",
    "provider": "Security Testing Corp",
    "start_date": "2024-02-01",
    "end_date": "2024-02-05",
    "scope": {
      "external_network": true,
      "web_application": true,
      "api_security": true,
      "social_engineering": false
    },
    "tester_certifications": ["OSCP", "CREST"],
    "methodology": "OWASP Testing Guide v4.2",
    "summary": "Annual penetration test completed",
    "findings_summary": {
      "critical": 0,
      "high": 1,
      "medium": 3,
      "low": 5,
      "informational": 2
    }
  }'
```

### Recording Individual Findings

```bash
curl -X POST https://qerds.example.com/admin/vulnerability/finding \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "engagement_id": "pentest-2024-annual",
    "finding_id": "PT-2024-001",
    "title": "SQL Injection in Search Parameter",
    "severity": "high",
    "cvss_score": 8.1,
    "affected_component": "qerds-api search endpoint",
    "description": "SQL injection vulnerability in search parameter allows...",
    "remediation_status": "in_progress",
    "remediation_owner": "dev-team",
    "target_date": "2024-02-12",
    "evidence_ref": "s3://qerds-audit/pentest/2024/finding-001-evidence.zip"
  }'
```

### Recording Remediation Completion

```bash
curl -X PATCH https://qerds.example.com/admin/vulnerability/finding/PT-2024-001 \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "remediation_status": "resolved",
    "resolution_date": "2024-02-10",
    "resolution_summary": "Parameterized query implemented, input validation added",
    "retest_date": "2024-02-15",
    "retest_result": "pass",
    "retest_evidence_ref": "s3://qerds-audit/pentest/2024/finding-001-retest.zip"
  }'
```

### Storing Pentest Reports Securely

Pentest reports contain sensitive information and MUST be stored securely:

1. **Encrypt** the report before storage
2. **Store** in the audit bucket:
   ```bash
   # Encrypt and upload
   gpg --encrypt --recipient security-team@example.com pentest-report-2024.pdf
   mc cp pentest-report-2024.pdf.gpg minio/qerds-audit/pentest/2024/
   ```
3. **Limit access** to security team and auditors only
4. **Record** the storage location in the engagement record

### Viewing Vulnerability Evidence

**List pentest engagements**:
```bash
curl https://qerds.example.com/admin/vulnerability/pentests \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Get findings for an engagement**:
```bash
curl "https://qerds.example.com/admin/vulnerability/findings?engagement_id=pentest-2024-annual" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Get remediation summary for audit**:
```bash
curl "https://qerds.example.com/admin/vulnerability/summary?year=2024" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

## Internal Testing Option

### When Internal Testing is Appropriate

Internal security assessments can supplement, but NOT replace, external penetration testing.

**Internal testing is appropriate for**:
- Pre-release security checks
- Continuous security monitoring
- Quick validation after patches
- Training and awareness

**External testing is REQUIRED for**:
- Annual compliance requirement (REQ-D06)
- Post-major-release validation
- Conformity assessment preparation
- After significant security incidents

### Tools for Internal Assessment

Recommended tools (self-hosted, no external dependencies):

**Vulnerability Scanning**:
- OpenVAS (network vulnerability scanner)
- Nuclei (fast vulnerability scanner)
- Nikto (web server scanner)

**Web Application Testing**:
- OWASP ZAP (web application scanner)
- Burp Suite Community (manual testing)
- SQLMap (SQL injection testing)

**API Testing**:
- Postman (with security collections)
- OWASP ZAP API scan mode

**Example: Running OWASP ZAP scan**:
```bash
# Pull ZAP image
docker pull zaproxy/zap-stable

# Run baseline scan against staging
docker run -t zaproxy/zap-stable zap-baseline.py \
  -t https://staging.qerds.example.com \
  -r zap-report.html

# Run full scan (longer, more thorough)
docker run -t zaproxy/zap-stable zap-full-scan.py \
  -t https://staging.qerds.example.com \
  -r zap-full-report.html
```

### Limitations of Internal Testing

Internal testing has inherent limitations:

| Limitation | Mitigation |
|------------|------------|
| Lack of external perspective | Annual external pentest |
| Potential blind spots | Rotate internal testers |
| Tool-only findings | Manual testing by external experts |
| Skill limitations | Training and certifications |
| Conflict of interest | Independent external validation |

**Documentation requirement**: When relying on internal testing between annual pentests, document:
- Tools used and versions
- Scope tested
- Findings and remediation
- Acknowledgment of limitations

---

## Audit Pack Inclusion

Penetration testing evidence is automatically included in audit packs generated via the Admin API. When generating an audit pack for conformity assessment, the pack will include:

- All pentest engagement records in the date range
- Finding summaries (not full technical details)
- Remediation status and timelines
- Retest confirmations
- Links to securely stored full reports (auditor access required)

---

## Troubleshooting

### Provider Selection Issues

- **No qualified providers available**: Expand search geographically, consider remote testing
- **Cost prohibitive**: Consider phased testing over multiple years, prioritize critical systems
- **Scheduling conflicts**: Book 3-6 months in advance

### During Testing Issues

- **Testing causes outages**: Pause testing, review RoE, adjust approach
- **Scope creep**: Refer to signed RoE, update if mutually agreed
- **Communication breakdown**: Escalate to management contacts

### Remediation Issues

- **Fix causes regression**: Revert, test in staging, apply proper fix
- **Timeline slipping**: Escalate, consider temporary mitigations
- **Disagreement on severity**: Use CVSS calculator, involve third party if needed

---

## References

- `specs/requirements.md` - REQ-D06 (Penetration testing), REQ-H09 (Vulnerability management evidence)
- `specs/implementation/90-security-and-ops-controls.md` - Security and ops controls specification
- ETSI EN 319 401 - General policy requirements for trust service providers
- Implementing Regulation (EU) 2025/1944 - Rules for applying eIDAS
- OWASP Testing Guide - https://owasp.org/www-project-web-security-testing-guide/
- PTES (Penetration Testing Execution Standard) - http://www.pentest-standard.org/
