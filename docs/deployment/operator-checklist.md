# QERDS Operator Deployment Checklist

Complete this checklist before deploying QERDS to production.

This checklist supports compliance with REQ-D07 (Network filtering) and related deployment requirements.

## Pre-Deployment

### Infrastructure

- [ ] Server meets minimum requirements (4 CPU, 8GB RAM, 100GB storage)
- [ ] Operating system is patched and up to date
- [ ] TLS certificates obtained (Let's Encrypt or organization CA)
- [ ] Domain name configured and DNS propagated
- [ ] Backup storage configured and tested
- [ ] Log aggregation infrastructure ready

### Network Security (REQ-D07)

- [ ] Run `make check-network-prod` - no critical issues
- [ ] Host firewall configured with default-deny ingress
- [ ] Reverse proxy installed and configured
- [ ] TLS termination configured on reverse proxy
- [ ] Security headers configured (HSTS, CSP, X-Frame-Options)
- [ ] qerds-trust service isolated from external access
- [ ] Database isolated from external access
- [ ] MinIO/S3 isolated from external access
- [ ] No development services accessible from network

### Configuration

- [ ] Environment variables set from secure source (not in code)
- [ ] `QERDS_CLAIM_STATE=qualified` set (only if actually qualified)
- [ ] Database credentials are unique (not defaults)
- [ ] MinIO/S3 credentials are unique (not defaults)
- [ ] SMTP configured for production relay
- [ ] FranceConnect+ OIDC credentials configured (if applicable)
- [ ] Application logging level set appropriately

### Secrets Management

- [ ] No secrets in code or docker-compose.yml
- [ ] Secrets loaded from secure source (HashiCorp Vault, AWS Secrets Manager, etc.)
- [ ] `.env` file secured with appropriate permissions (0600)
- [ ] Encryption keys backed up securely (separate from data)
- [ ] Key backup procedure documented and tested

### Docker Configuration

- [ ] Docker daemon configured securely
- [ ] Docker socket NOT exposed to containers
- [ ] Container images from trusted sources
- [ ] Image versions pinned (no `latest` tags in production)
- [ ] Resource limits configured for containers
- [ ] Containers run as non-root where possible

## Deployment

### Service Startup

- [ ] Run `docker compose up -d` (production profile)
- [ ] Verify all services start successfully
- [ ] Check service logs for errors
- [ ] Verify health endpoints responding

### Verification

- [ ] Application accessible via HTTPS
- [ ] TLS certificate valid and trusted
- [ ] HTTP redirects to HTTPS
- [ ] Authentication flow working end-to-end
- [ ] Test delivery completes successfully
- [ ] Evidence generation and storage verified

### Security Validation

- [ ] Port scan confirms only 443 (and 22 if needed) accessible
- [ ] Internal services not accessible from outside
- [ ] Security headers present in responses
- [ ] No sensitive information in error pages

## Post-Deployment

### Monitoring Setup

- [ ] Application logs forwarded to aggregation system
- [ ] Health check monitoring configured
- [ ] Alerting configured for service failures
- [ ] Alerting configured for security events
- [ ] Disk space monitoring enabled
- [ ] Certificate expiration monitoring configured

### Documentation

- [ ] Deployment documented (version, configuration, date)
- [ ] Runbook updated with this deployment's specifics
- [ ] Incident contacts verified and documented
- [ ] Recovery procedures documented and accessible

### Backup Verification

- [ ] Database backup running on schedule
- [ ] Backup restore test performed
- [ ] Evidence storage backup configured
- [ ] Backup integrity verification automated

## Periodic Checks

These should be scheduled as regular operational tasks:

### Weekly

- [ ] Review security alerts and logs
- [ ] Check certificate expiration status
- [ ] Verify backup completion

### Monthly

- [ ] Review and rotate any expiring credentials
- [ ] Check for system and dependency updates
- [ ] Review access logs for anomalies

### Quarterly

- [ ] Vulnerability scan (REQ-D05)
- [ ] Access review (REQ-H06)
- [ ] Backup restore test
- [ ] Run `make check-network-prod` against current configuration

### Annually

- [ ] Penetration test (REQ-D06)
- [ ] Full disaster recovery exercise (REQ-H08)
- [ ] Security policy review
- [ ] Certificate renewal (if not auto-renewing)

## Qualification Reminder

**Do not claim "qualified" status unless:**

- [ ] Provider is actually qualified and supervised for QERDS
- [ ] Service is listed in relevant EU trusted lists
- [ ] All normative requirements are demonstrably met
- [ ] Conformity assessment has been passed

See `specs/requirements.md` for the full requirements list and REQ-G01/REQ-G02 for compliance guardrails.

## Related Documentation

- [Network Security](network-security.md) - Detailed network security posture
- `specs/requirements.md` - Full requirements specification
- `README.md` - Requirements status tracking
