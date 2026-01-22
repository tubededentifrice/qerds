# phoss SMP - Service Metadata Publisher

phoss SMP is the BDXR/SMP service metadata publisher used for ETSI EN 319 522 cross-provider interoperability.

## Overview

This configuration deploys phoss SMP as part of the QERDS Docker Compose stack to enable:
- Publishing service metadata for QERDS endpoints (BDXR SMP 1.0/2.0)
- Peppol SMP 1.x compatibility
- Service discovery for cross-provider message routing
- Certificate and endpoint information management

## Architecture

```
                    +------------------+
                    |   Other ERDS     |
                    |   Providers      |
                    +--------+---------+
                             |
                             | SMP Lookup (BDXR/Peppol)
                             |
+--------------------------------------------------+
|                    QERDS Stack                   |
|                                                  |
|  +-----------+      +----------+      +-------+  |
|  | qerds-api |<---->| phoss    |<---->|  PG   |  |
|  +-----------+ REST |   SMP    |      +-------+  |
|                     +----------+                 |
|                          |                       |
|                    BDXR Metadata                 |
+--------------------------------------------------+
```

## Quick Start

```bash
# Start phoss SMP (uses 'interop' profile)
docker compose --profile interop up -d

# Check status
docker compose --profile interop ps

# View logs
docker compose --profile interop logs smp
```

## Components

- **smp**: phoss SMP server (Tomcat 10.1 + JDK 17)
- **smp-postgres**: PostgreSQL 16 database for SMP metadata (separate from QERDS PostgreSQL)

## Configuration Files

- `config/application.properties` - Main phoss SMP configuration
- `config/logback.xml` - Logging configuration

## Access

- **Admin UI**: http://localhost:8280/
- **REST API**: http://localhost:8280/
- **Status API**: http://localhost:8280/status

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SMP_DB_PASSWORD` | `smp_dev_password` | PostgreSQL database password |
| `SMP_ADMIN_PASSWORD` | `smp_admin_dev` | Admin API password |

## Integration with QERDS

The `qerds-api` service integrates with phoss SMP via REST API:

1. **Publish metadata**: POST participant service metadata to SMP
2. **Update endpoints**: Modify service endpoint information
3. **Certificate management**: Update signing certificates
4. **Service discovery**: Query metadata for routing decisions

## API Examples

### Query Participant

```bash
# Get service metadata for a participant
curl http://localhost:8280/iso6523-actorid-upis::0088:1234567890123
```

### Publish Service Metadata (authenticated)

```bash
# Publish service metadata
curl -X PUT \
  -H "Content-Type: application/xml" \
  -u smp-admin:smp_admin_dev \
  --data-binary @service-metadata.xml \
  http://localhost:8280/iso6523-actorid-upis::0088:1234567890123/services/busdox-docid-qns::urn:oasis:names:specification:ubl:schema:xsd:Invoice-2::Invoice##UBL-2.1
```

## Security Notes

### Development Mode (Default)

- HTTP-only (no TLS)
- Basic authentication for management API
- Flyway auto-creates database schema

### Production Requirements

From February 2026, Peppol SMP services MUST use HTTPS exclusively.

1. **Enable TLS**:
   - Configure proper certificates
   - Update `smp.publicurl` with https://
   - Set `smp.https.required=true`

2. **Authentication**:
   - Change default admin credentials
   - Enable client certificate authentication if required

3. **SML Registration**:
   - Enable `sml.enabled=true`
   - Configure SML URL for network participation
   - Provide client certificate for SML

## References

- [phoss SMP GitHub](https://github.com/phax/phoss-smp)
- [phoss SMP Wiki](https://github.com/phax/phoss-smp/wiki)
- [ETSI EN 319 522 Interop Profile](../specs/implementation/65-etsi-interop-profile.md)
- [OASIS BDXR SMP](https://docs.oasis-open.org/bdxr/bdx-smp/v2.0/bdx-smp-v2.0.html)

## Troubleshooting

### SMP won't start

1. Check PostgreSQL is healthy: `docker compose logs smp-postgres`
2. Check SMP logs: `docker compose logs smp`
3. Verify database connectivity

### REST API errors

1. Check authentication credentials
2. Verify participant ID format
3. Review SMP logs for detailed errors

### Cannot access admin UI

1. Verify port 8280 is not in use
2. Check container health: `docker compose ps smp`
3. Check startup logs for errors
