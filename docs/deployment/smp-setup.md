# SMP Deployment (phoss SMP)

This document covers the deployment and configuration of phoss SMP for BDXR/Peppol service metadata publishing in QERDS.

## Overview

phoss SMP is an open-source Service Metadata Publisher that provides:

- **OASIS BDXR SMP 1.0/2.0**: Business Document Exchange standard
- **Peppol SMP 1.x**: Pan-European Public Procurement network standard
- **CEF eDelivery Compliance**: First SMP to be CEF conformant
- **REST API**: Programmatic access for metadata management

## Architecture

```
External Partners                    QERDS Stack
+-----------------+                 +---------------------------+
|                 |                 |                           |
| Partner ERDS    |<-- SMP Query -->| phoss SMP (port 8280)    |
| Provider        |   (BDXR/HTTP)   |     |                     |
|                 |                 |     | REST API            |
+-----------------+                 |     v                     |
                                    | qerds-api                 |
                                    |     |                     |
                                    |     v                     |
                                    | Domibus (AS4 routing)     |
                                    +---------------------------+
```

## Services

SMP services are optional and enabled via the `interop` profile.

| Service | Port | Purpose |
|---------|------|---------|
| `smp` | 8280 | SMP REST API + Admin UI |
| `smp-postgres` | (internal) | SMP metadata database |

## Quick Start

### 1. Start SMP Services

SMP is behind the `interop` profile and must be explicitly enabled:

```bash
# Start all interop services (Domibus + SMP)
docker compose --profile interop up -d

# Or start only specific services
docker compose --profile interop up -d smp-postgres smp

# Check status
docker compose --profile interop ps

# View logs
docker compose --profile interop logs smp
```

### 2. Verify SMP is Running

```bash
# Check status endpoint
curl http://localhost:8280/status

# Expected response includes:
# - smp.status: "OK"
# - smp.sql.db.connection-possible: true
```

### 3. Access Admin UI

Once SMP is running:

- **URL**: http://localhost:8280/
- **API Documentation**: http://localhost:8280/swagger-ui/

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SMP_DB_PASSWORD` | `smp_dev_password` | PostgreSQL database password |
| `SMP_ADMIN_PASSWORD` | `smp_admin_dev` | REST API admin password |

### Configuration Files

Located in `smp/config/`:

- `application.properties` - Main phoss SMP configuration
- `logback.xml` - Logging configuration

### Key Configuration Options

Edit `smp/config/application.properties`:

```properties
# Database
jdbc.url=jdbc:postgresql://smp-postgres:5432/smp
jdbc.user=smp
jdbc.password=${SMP_DB_PASSWORD:-smp_dev_password}

# SMP Identity
sml.smpid=QERDS-SMP-DEV
smp.publicurl=http://localhost:8280

# REST API
smp.rest.writable-api.enabled=true
smp.rest.user=smp-admin
smp.rest.password=${SMP_ADMIN_PASSWORD:-smp_admin_dev}
```

## Integration with QERDS

### Publishing Service Metadata

When a delivery is initiated, `qerds-api` publishes metadata to SMP:

```
1. qerds-api creates delivery record
2. qerds-api publishes service endpoint to SMP via REST
3. SMP stores metadata in PostgreSQL
4. Partner providers can query SMP for routing info
5. Domibus routes AS4 messages based on SMP metadata
```

### API Integration

#### Query Participant Metadata

```bash
# Get service metadata for a participant
curl http://localhost:8280/iso6523-actorid-upis::0088:1234567890123
```

#### Publish Service Metadata

```bash
# Create service group for participant
curl -X PUT \
  -H "Content-Type: application/xml" \
  -u smp-admin:smp_admin_dev \
  --data-binary @service-group.xml \
  http://localhost:8280/iso6523-actorid-upis::0088:1234567890123

# Add service metadata
curl -X PUT \
  -H "Content-Type: application/xml" \
  -u smp-admin:smp_admin_dev \
  --data-binary @service-metadata.xml \
  http://localhost:8280/iso6523-actorid-upis::0088:1234567890123/services/busdox-docid-qns::urn:example:document:1.0
```

#### Delete Metadata

```bash
# Remove service metadata
curl -X DELETE \
  -u smp-admin:smp_admin_dev \
  http://localhost:8280/iso6523-actorid-upis::0088:1234567890123/services/busdox-docid-qns::urn:example:document:1.0
```

## Security

### Development Mode (Default)

- HTTP-only (no TLS)
- Basic authentication for management API
- Flyway auto-manages database schema
- SML registration disabled

### Production Requirements

**Important**: From February 2026, Peppol SMP services MUST use HTTPS exclusively.

1. **Enable TLS**:
   ```properties
   smp.publicurl=https://smp.your-domain.com
   smp.https.required=true
   ```

2. **Configure Proper Certificates**:
   - Obtain TLS certificate from trusted CA
   - Configure reverse proxy (nginx/traefik) with TLS termination
   - Or configure Tomcat with HTTPS directly

3. **Change Default Credentials**:
   ```bash
   # Set in environment
   export SMP_DB_PASSWORD=secure_random_password
   export SMP_ADMIN_PASSWORD=secure_admin_password
   ```

4. **Enable SML Registration** (for Peppol network):
   ```properties
   sml.enabled=true
   sml.url=https://sml.peppolcentral.org/
   sml.client.cert.required=true
   ```

5. **Enable Client Certificates**:
   ```properties
   smp.clientcert.required=true
   ```

## Database Management

### View SMP Data

```bash
# Connect to SMP PostgreSQL
docker compose exec smp-postgres psql -U smp -d smp

# List participants
SELECT * FROM smp_ownership;

# List service metadata
SELECT * FROM smp_service_metadata;
```

### Backup Database

```bash
# Backup SMP database
docker compose exec smp-postgres pg_dump -U smp smp > smp_backup.sql

# Restore
docker compose exec -T smp-postgres psql -U smp smp < smp_backup.sql
```

## Troubleshooting

### SMP fails to start

```bash
# Check PostgreSQL is ready
docker compose logs smp-postgres

# Check SMP logs
docker compose logs smp

# Common issues:
# - PostgreSQL not ready: wait for healthcheck
# - Memory: increase JAVA_OPTS -Xmx value
# - Config file missing: verify volume mounts
```

### Database connection errors

```bash
# Test PostgreSQL connectivity
docker compose exec smp-postgres pg_isready -U smp -d smp

# Check database exists
docker compose exec smp-postgres psql -U smp -c "\\l"

# Verify Flyway migrations
docker compose logs smp | grep -i flyway
```

### REST API returns 401

1. Verify credentials in `application.properties`
2. Check `smp.rest.writable-api.enabled=true`
3. Ensure Basic Auth header is correct

### Cannot access admin UI

```bash
# Verify container is running
docker compose ps smp

# Check port binding
docker compose port smp 8080

# Check container logs
docker compose logs smp | tail -50
```

## Monitoring

### Health Check

```bash
# Basic health
curl http://localhost:8280/status

# Detailed status (JSON)
curl http://localhost:8280/status | jq .
```

### Metrics

phoss SMP exposes metrics at `/status` including:
- Database connection status
- Participant count
- Service metadata count
- Version information

## References

- [phoss SMP GitHub](https://github.com/phax/phoss-smp)
- [phoss SMP Wiki](https://github.com/phax/phoss-smp/wiki)
- [phoss SMP Configuration](https://github.com/phax/phoss-smp/wiki/Configuration)
- [OASIS BDXR SMP](https://docs.oasis-open.org/bdxr/bdx-smp/v2.0/bdx-smp-v2.0.html)
- [Peppol SMP Specification](https://docs.peppol.eu/edelivery/smp/)
- [ETSI EN 319 522 Interop Profile](../../specs/implementation/65-etsi-interop-profile.md)
- [smp/README.md](../../smp/README.md)
