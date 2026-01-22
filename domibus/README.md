# Domibus AS4 Gateway

Domibus is the AS4 Message Service Handler (MSH) used for ETSI EN 319 522 cross-provider interoperability.

## Overview

This configuration deploys Domibus as part of the QERDS Docker Compose stack to enable:
- AS4 message exchange with other QERDS/eDelivery providers
- Receipt/error protocol handling mapped to QERDS evidence events
- ETSI EN 319 522-4-2 compliant transport binding

## Architecture

```
                    +------------------+
                    |   Other ERDS     |
                    |   Providers      |
                    +--------+---------+
                             |
                             | AS4/HTTPS
                             |
+--------------------------------------------------+
|                    QERDS Stack                   |
|                                                  |
|  +-----------+      +----------+      +-------+  |
|  | qerds-api |<---->| Domibus  |<---->| MySQL |  |
|  +-----------+ REST +----------+      +-------+  |
|                          |                       |
|                     AS4 Profile                  |
+--------------------------------------------------+
```

## Quick Start

```bash
# 1. Download database schema
./scripts/setup-domibus.sh

# 2. Start Domibus (uses 'interop' profile)
docker compose --profile interop up -d

# 3. Check status
docker compose --profile interop ps
```

## Components

- **domibus**: Domibus AS4 gateway (Tomcat 8 + Java 8, FIWARE image)
- **domibus-mysql**: MySQL 5.7 database (required by Domibus, separate from QERDS PostgreSQL)

## Configuration Files

- `config/domibus.properties` - Main Domibus configuration
- `config/logback.xml` - Logging configuration
- `sql/01-domibus-schema.sql` - Database schema (created by setup script)

## Access

- **Admin Console**: http://localhost:8180/domibus
- **Default credentials**: admin / changeit (MUST be changed for production)

## Integration with QERDS

The `qerds-api` service integrates with Domibus via REST API:

1. **Outbound messages**: qerds-api POSTs to Domibus `/rest/message/submit`
2. **Inbound messages**: Domibus calls qerds-api webhook or qerds-api polls `/rest/message/pending`
3. **Receipts/Errors**: Mapped to QERDS `evidence_events` table

## Security Notes

### Development Mode
- Uses self-signed certificates
- Plaintext HTTP between qerds-api and Domibus (internal network)
- Default credentials enabled

### Production Requirements
- mTLS between qerds-api and Domibus
- Properly signed certificates from trusted CA
- Change all default passwords
- Enable HTTPS on admin console
- Configure firewall rules for AS4 port (8443)

## PModes

Processing Modes (PModes) define how Domibus handles messages. The default PMode is configured for development/testing.

Production deployments MUST:
1. Configure PModes per trading partner
2. Exchange certificates with partner APs
3. Register in SMP/BDXR for service discovery

## References

- [Domibus Administration Guide](https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/Domibus)
- [ETSI EN 319 522 Interop Profile](../specs/implementation/65-etsi-interop-profile.md)
- [eDelivery AS4 Profile](https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/eDelivery+AS4)

## Troubleshooting

### Domibus won't start
1. Check MySQL is healthy: `docker compose logs domibus-mysql`
2. Check Domibus logs: `docker compose logs domibus`
3. Verify database schema was created

### Message send fails
1. Check PMode configuration in admin console
2. Verify certificates are correctly installed
3. Check target AP is reachable

### Cannot access admin console
1. Verify port 8180 is not in use
2. Check container health: `docker compose ps`
