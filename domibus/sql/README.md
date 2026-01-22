# Domibus Database Schema

This directory contains the database initialization scripts for Domibus.

## Setup

The Domibus 4.0 MySQL schema file must be downloaded from the official EC eDelivery site:

1. Visit: https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/Domibus+database+installation+and+upgrade+scripts
2. Download the SQL scripts package
3. Extract `mysql5innoDb-4.0.ddl` (or the appropriate version)
4. Copy it to this directory as `01-domibus-schema.sql`

Alternatively, run the setup script:

```bash
./scripts/setup-domibus.sh
```

## Files

- `01-domibus-schema.sql` - Domibus database schema (DDL)
- `.gitkeep` - Keeps this directory in git

Note: The SQL schema file is not committed to git due to licensing considerations.
The FIWARE Domibus Docker image is based on Domibus 4.0.

## References

- [Domibus Database Scripts](https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/Domibus+database+installation+and+upgrade+scripts)
- [Domibus Administration Guide](https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/Domibus)
