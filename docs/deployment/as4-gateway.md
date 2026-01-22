# AS4 Gateway Deployment (Domibus)

This document covers the deployment and configuration of the Domibus AS4 gateway for ETSI EN 319 522 cross-provider interoperability.

## Overview

Domibus is an open-source AS4 Message Service Handler (MSH) maintained by the European Commission. It provides:

- **AS4 Protocol**: OASIS ebMS3/AS4 messaging standard implementation
- **eDelivery Compliance**: CEF eDelivery AS4 profile support
- **ETSI EN 319 522-4-2**: Transport binding for qualified electronic registered delivery

## Architecture

```
External Partners                    QERDS Stack
+-----------------+                 +---------------------------+
|                 |                 |                           |
| Partner ERDS    |<--- AS4/HTTPS -->| Domibus (port 8180)      |
| Provider        |                 |     |                     |
|                 |                 |     | REST API            |
+-----------------+                 |     v                     |
                                    | qerds-api                 |
                                    |     |                     |
                                    |     v                     |
                                    | PostgreSQL (evidence)     |
                                    +---------------------------+
```

## Services

Domibus services are optional and enabled via the `interop` profile.

| Service | Port | Purpose |
|---------|------|---------|
| `domibus` | 8180 | AS4 gateway + admin console |
| `domibus-mysql` | (internal) | Domibus state database |

## Quick Start

### 1. Download Database Schema

First, run the setup script to download the Domibus database schema:

```bash
./scripts/setup-domibus.sh
```

This downloads the official Domibus 4.0 MySQL schema from the EC eDelivery site.

### 2. Start Domibus Services

Domibus is behind the `interop` profile and must be explicitly enabled:

```bash
# Start Domibus services
docker compose --profile interop up -d

# Check status
docker compose --profile interop ps

# View logs
docker compose --profile interop logs domibus
```

### 3. Access Admin Console

Once Domibus is running:

- **URL**: http://localhost:8180/domibus
- **Default credentials**: admin / changeit (CHANGE IN PRODUCTION)

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DOMIBUS_MYSQL_ROOT_PASSWORD` | `domibus_root_dev` | MySQL root password |
| `DOMIBUS_DB_PASSWORD` | `domibus_dev_password` | Domibus DB user password |
| `DOMIBUS_KEYSTORE_PASSWORD` | `changeit` | Signing keystore password |
| `DOMIBUS_TRUSTSTORE_PASSWORD` | `changeit` | Truststore password |

### Configuration Files

Located in `domibus/config/`:

- `domibus.properties` - Main configuration (DB, security, plugins)
- `logback.xml` - Logging configuration

### Processing Modes (PModes)

PModes define how Domibus handles messages with specific partners. Configure via:

1. Admin console: http://localhost:8180/domibus -> PMode
2. Upload PMode XML file
3. REST API: `POST /rest/pmode`

## Integration with QERDS

### Outbound Messages (qerds-api -> Partner)

```
1. qerds-api creates delivery record
2. qerds-api calls Domibus REST API: POST /rest/message/submit
3. Domibus sends AS4 message to partner
4. Domibus receives AS4 receipt
5. qerds-api polls for status or receives webhook callback
6. qerds-api records evidence_event
```

### Inbound Messages (Partner -> qerds-api)

```
1. Partner sends AS4 message to Domibus
2. Domibus validates and stores message
3. qerds-api polls: GET /rest/message/pending
4. qerds-api retrieves message payload
5. qerds-api processes delivery
6. qerds-api acknowledges to Domibus
```

## Security

### Development Mode (Default)

- Self-signed certificates (auto-generated)
- HTTP between qerds-api and Domibus (internal network)
- Default admin credentials

### Production Requirements

1. **Replace certificates**:
   - Obtain certificates from qualified TSP
   - Import to keystore/truststore
   - Update `domibus.properties`

2. **Enable mTLS**:
   - Configure qerds-api with client certificate
   - Enable TLS on Domibus endpoints

3. **Change credentials**:
   - Update admin password via console
   - Rotate database passwords

4. **Network security**:
   - Firewall rules for AS4 port (8443 recommended for production)
   - TLS 1.2+ only

## Troubleshooting

### Domibus fails to start

```bash
# Check MySQL is ready
docker compose logs domibus-mysql

# Check Domibus logs
docker compose logs domibus

# Common issues:
# - MySQL not ready: increase start_period in healthcheck
# - Memory: increase JAVA_OPTS -Xmx value
```

### Message delivery fails

1. Check PMode configuration matches partner
2. Verify certificates are correctly installed
3. Check network connectivity to partner endpoint
4. Review Domibus error queue in admin console

### Admin console inaccessible

```bash
# Verify container is running
docker compose ps domibus

# Check port binding
docker compose port domibus 8080

# Check container logs for startup errors
docker compose logs domibus | tail -50
```

## Related Components

- **phoss SMP**: Service metadata publishing for endpoint discovery - see [smp-setup.md](./smp-setup.md)

## References

- [Domibus Documentation](https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/Domibus)
- [eDelivery AS4 Profile](https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/eDelivery+AS4)
- [ETSI EN 319 522-4-2](https://www.etsi.org/deliver/etsi_en/319500_319599/3195220402/)
- [domibus/README.md](../../domibus/README.md)
- [smp/README.md](../../smp/README.md)
- [specs/implementation/65-etsi-interop-profile.md](../../specs/implementation/65-etsi-interop-profile.md)
