#!/bin/bash
# Setup script for Domibus AS4 gateway database schema
# Downloads and prepares the Domibus 4.0 MySQL schema
#
# Usage: ./scripts/setup-domibus.sh
#
# This script downloads the Domibus SQL scripts from the official EC eDelivery
# site and prepares them for use with the Docker Compose setup.
#
# After running this script, start Domibus with:
#   docker compose --profile interop up -d

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DOMIBUS_SQL_DIR="$PROJECT_ROOT/domibus/sql"
DOMIBUS_VERSION="4.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check if schema already exists
if [[ -f "$DOMIBUS_SQL_DIR/01-domibus-schema.sql" ]]; then
    info "Domibus schema already exists at $DOMIBUS_SQL_DIR/01-domibus-schema.sql"
    read -p "Overwrite? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        info "Skipping schema download"
        exit 0
    fi
fi

info "Setting up Domibus $DOMIBUS_VERSION database schema..."

# The Domibus SQL scripts require authentication to download from EC site
# Users must manually download from:
# https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/Domibus+database+installation+and+upgrade+scripts

echo
warn "Automatic download is not available (EC site requires authentication)"
echo
echo "Manual setup required:"
echo "1. Visit: https://ec.europa.eu/digital-building-blocks/sites/display/DIGITAL/Domibus+database+installation+and+upgrade+scripts"
echo "2. Download: 'domibus-MSH-distribution-sql-scripts.zip'"
echo "3. Extract the zip and find: sql-scripts/mysql5innoDb-$DOMIBUS_VERSION.ddl"
echo "4. Copy it to: $DOMIBUS_SQL_DIR/01-domibus-schema.sql"
echo
echo "After copying the schema file, start Domibus with:"
echo "  docker compose --profile interop up -d"
echo
echo "Admin console will be available at:"
echo "  http://localhost:8180/domibus"
echo "  Default credentials: admin / changeit"
exit 0
