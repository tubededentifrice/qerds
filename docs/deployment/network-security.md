# Network Security and Service Exposure

This document defines the network security posture for QERDS deployments (REQ-D07).

## Default-Deny Principle

All QERDS deployments MUST follow a default-deny network posture:

- Only explicitly required ports are exposed
- Internal services communicate over private Docker networks only
- All external access goes through a reverse proxy
- Development bindings use 127.0.0.1 (localhost) only

## Service Exposure Matrix

| Service | Internal Port | Dev Binding | Production Exposure | Notes |
|---------|---------------|-------------|---------------------|-------|
| qerds-api | 8000 | 127.0.0.1:8000 | Via reverse proxy (443) | Only service exposed externally |
| qerds-worker | - | None | None | Background service, no ports |
| qerds-trust | 8080 | 127.0.0.1:8080 | None (internal only) | CRITICAL: Never expose externally |
| postgres | 5432 | 127.0.0.1:5432 | None (internal only) | Database access restricted |
| minio | 9000/9001 | 127.0.0.1:9000/9001 | None (internal only) | Object store internal |
| mailpit | 1025/8025 | 127.0.0.1:1025/8025 | None (dev only) | Remove or disable in production |
| mocks | 5000 | 0.0.0.0:5000 | None (dev only) | UI mockups server, dev profile only |

## Development Environment

In development, services bind to 127.0.0.1 only (per AGENTS.md constraints):

```yaml
# From docker-compose.yml - all production-relevant services bind to localhost
postgres:
  ports:
    - "127.0.0.1:5432:5432"

minio:
  ports:
    - "127.0.0.1:9000:9000"   # API
    - "127.0.0.1:9001:9001"   # Console

mailpit:
  ports:
    - "127.0.0.1:8025:8025"   # Web UI
    - "127.0.0.1:1025:1025"   # SMTP
```

This ensures that even in development, services are not accidentally exposed to the network.

## Production Requirements

### Reverse Proxy (Required)

A reverse proxy is REQUIRED for production deployments:

- Use nginx, Caddy, or Traefik as reverse proxy
- Terminate TLS at the reverse proxy
- Only expose port 443 (HTTPS) to the internet
- Configure proper security headers (HSTS, CSP, X-Frame-Options)

Example nginx configuration snippet:

```nginx
server {
    listen 443 ssl http2;
    server_name qerds.example.com;

    ssl_certificate /etc/ssl/certs/qerds.crt;
    ssl_certificate_key /etc/ssl/private/qerds.key;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Firewall Rules

Configure host firewall with default-deny ingress:

```bash
# Example iptables rules (adjust for your environment)

# Allow loopback
-A INPUT -i lo -j ACCEPT

# Allow established connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow HTTPS from internet
-A INPUT -p tcp --dport 443 -j ACCEPT

# Allow SSH (restricted to admin IPs)
-A INPUT -p tcp --dport 22 -s <admin-network>/24 -j ACCEPT

# Drop all other incoming traffic (default deny)
-A INPUT -j DROP
```

For cloud deployments, use equivalent security groups or firewall rules.

### Container Network Isolation

The docker-compose.yml creates a dedicated Docker network (`qerds_network`):

```yaml
networks:
  default:
    name: qerds_network
```

Production considerations:

- Do not use host networking (`network_mode: host`)
- Do not expose Docker socket to containers
- Use network policies if deploying on Kubernetes
- Consider separate networks for trust service isolation

### Service Isolation

The `qerds-trust` service handles cryptographic operations and MUST be isolated:

- No external port exposure (communicates only via internal network)
- API service connects to it via `http://qerds-trust:8080` (internal DNS)
- Consider additional network segmentation in high-security deployments

## Security Profiles

### Development Profile

Used for local development:

- Services bind to 127.0.0.1
- Mailpit available for email testing
- Mocks server available for UI development
- No TLS required (localhost only)

### Production Profile

Required for qualified service operation:

- Only qerds-api exposed (via reverse proxy)
- TLS termination at reverse proxy
- All other services internal only
- Mailpit disabled or removed
- Mocks server disabled

Enable with:

```bash
docker compose --profile production up
```

## Validation

Run the network security validation script:

```bash
# Basic check
make check-network

# Production-level check
make check-network-prod
```

The script validates:

- No internal-only services have external port bindings
- Development-only services are properly profiled
- Port bindings follow localhost conventions

## Security Checklist for Operators

Before going to production, verify:

### Network Exposure

- [ ] qerds-trust is NOT accessible from outside the container network
- [ ] PostgreSQL is NOT accessible from outside the container network
- [ ] MinIO/S3 is NOT accessible from outside the container network
- [ ] Only the reverse proxy is exposed on public interface

### TLS Configuration

- [ ] TLS certificates are valid and from a trusted CA
- [ ] TLS 1.2+ only (no SSLv3, TLS 1.0, TLS 1.1)
- [ ] Strong cipher suites configured
- [ ] HSTS headers enabled

### Development Services

- [ ] Mailpit is removed or disabled in production
- [ ] Mocks server is removed or disabled in production
- [ ] No debug endpoints are exposed

### Host Security

- [ ] Host firewall configured with default-deny
- [ ] Docker socket is not exposed to containers
- [ ] Containers run as non-root where possible
- [ ] Host SSH access restricted to admin IPs

## Related Documentation

- [Operator Deployment Checklist](operator-checklist.md) - Complete pre-deployment checklist
- `docker-compose.yml` - Service definitions and port bindings
- `specs/requirements.md` - REQ-D07 requirement specification
