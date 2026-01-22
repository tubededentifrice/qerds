---
name: security-check
description: Red-team security audit of current feature. Investigates vulnerabilities, permission gaps, and suggests fixes.
---

# Security Check Skill

Act as a **red-team penetration tester**. Thoroughly investigate the current feature or codebase area for security problems, permission gaps, and vulnerabilities.

## Scope

Analyze the code the user is working on (or the area they specify) for:

1. **Authentication & Authorization**
   - Missing or weak permission checks
   - Privilege escalation paths
   - Session management issues
   - IDOR (Insecure Direct Object Reference)

2. **Input Validation & Injection**
   - SQL injection (raw queries, f-strings in QuerySets)
   - XSS (Cross-Site Scripting) in templates
   - Command injection in subprocess calls
   - Path traversal in file operations
   - Template injection

3. **OWASP Top 10**
   - Broken access control
   - Cryptographic failures
   - Security misconfiguration
   - Vulnerable/outdated components
   - SSRF (Server-Side Request Forgery)

4. **Cryptographic Issues (Critical for QERDS)**
   - Weak or deprecated algorithms
   - Improper key management
   - Timing attacks in comparisons
   - Predictable random number generation
   - Missing or improper signatures/seals
   - Non-qualified implementations claimed as qualified

5. **Evidence & Audit Trail Issues**
   - Tamperable evidence records
   - Gaps in audit logging
   - Unauthorized evidence modification
   - Missing integrity checks

6. **Data Protection**
   - PII exposure in logs or responses
   - Missing rate limiting on sensitive endpoints
   - Insecure password handling
   - Unencrypted sensitive data

## Investigation Process

1. **Identify the target**: What feature/code is being audited?
2. **Map the attack surface**: Find all entry points (APIs, forms, URL params).
3. **Trace data flow**: Follow user input from request to database and back.
4. **Check permission boundaries**: Verify every action checks appropriate permissions.
5. **Test assumptions**: What happens if an attacker bypasses client-side validation?
6. **Review related code**: Check middleware, decorators, and shared utilities.

## Output Format

Provide findings in this structure:

### Findings

For each issue found:

```
**[SEVERITY] Issue Title**
- Location: `path/to/file.py:line_number`
- Description: What the vulnerability is
- Attack scenario: How an attacker could exploit it
- Fix: Concrete code change to remediate
```

Severity levels:
- **CRITICAL**: Immediate exploitation risk, data breach potential, evidence integrity compromise
- **HIGH**: Significant security impact, requires prompt fix
- **MEDIUM**: Defense-in-depth issue, should be addressed
- **LOW**: Minor issue or hardening opportunity
- **INFO**: Observation or best practice suggestion

### Summary

- Total issues by severity
- Most critical items requiring immediate attention
- Recommended remediation priority

## Example Checks

```python
# BAD: Missing permission check
def delete_evidence(request, evidence_id):
    evidence = get_object_or_404(Evidence, id=evidence_id)
    evidence.delete()  # Anyone can delete any evidence!

# GOOD: Proper authorization
def delete_evidence(request, evidence_id):
    evidence = get_object_or_404(Evidence, id=evidence_id)
    if evidence.owner != request.user and not request.user.is_admin:
        raise PermissionDenied
    # Note: Should evidence even be deletable? Check compliance requirements
```

```python
# BAD: Timing attack in secret comparison
if user_token == stored_token:
    return True

# GOOD: Constant-time comparison
import hmac
if hmac.compare_digest(user_token, stored_token):
    return True
```

```python
# BAD: Tamperable evidence
evidence.timestamp = datetime.now()  # Local time, easily spoofed

# GOOD: Use qualified time source
evidence.timestamp = qualified_time_service.get_timestamp()
evidence.timestamp_signature = sign_timestamp(evidence.timestamp)
```

## Reference

Consult these specs for security context:
- `specs/requirements.md` - Compliance requirements
- Any security-related specs in `specs/`

## After the Audit

1. Report all findings with severity ratings
2. Provide concrete fix suggestions with code examples
3. Highlight any issues that should block deployment
4. Flag any compliance implications (false qualified claims, evidence integrity)
5. Suggest additional hardening if appropriate
