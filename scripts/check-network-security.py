#!/usr/bin/env python3
"""Validate network security posture for QERDS deployment (REQ-D07).

This script checks that the deployment follows default-deny principles
and that sensitive services are not exposed externally.

Usage:
    python scripts/check-network-security.py
    python scripts/check-network-security.py --docker-compose docker-compose.yml
    python scripts/check-network-security.py --production

Exit codes:
    0 - All checks passed (may have warnings)
    1 - Critical issues found
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Lazy import yaml to provide better error message if not installed
try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]


# Services that must NEVER be exposed externally (internal-only)
INTERNAL_ONLY_SERVICES = frozenset(
    {
        "qerds-trust",
        "postgres",
        "minio",
        "registry",
        "registry-auth-init",
    }
)

# Services that should not exist in production (dev-only)
DEV_ONLY_SERVICES = frozenset(
    {
        "mailpit",
        "mocks",
    }
)

# Allowed localhost bindings for development
LOCALHOST_PREFIXES = ("127.0.0.1:", "localhost:")


def parse_port_binding(port_spec: str | int) -> tuple[str | None, str]:
    """Parse a Docker port specification into host binding and port.

    Args:
        port_spec: Docker port specification (e.g., "127.0.0.1:8000:8000").

    Returns:
        Tuple of (host_binding, port_part) where host_binding may be None
        for unspecified bindings.

    Examples:
        "127.0.0.1:8000:8000" -> ("127.0.0.1:8000", "8000")
        "8000:8000" -> (None, "8000")
        "8000" -> (None, "8000")
    """
    port_str = str(port_spec)
    parts = port_str.split(":")

    if len(parts) == 3:
        # IP:host_port:container_port format
        return f"{parts[0]}:{parts[1]}", parts[2]
    elif len(parts) == 2:
        # host_port:container_port format (binds to all interfaces)
        return None, parts[1]
    else:
        # Just container_port (expose, not publish)
        return None, parts[0]


def is_localhost_binding(port_spec: str | int) -> bool:
    """Check if a port binding is restricted to localhost."""
    port_str = str(port_spec)
    return port_str.startswith(LOCALHOST_PREFIXES)


def check_docker_compose(compose_path: Path) -> list[str]:
    """Check docker-compose.yml for network security issues.

    Args:
        compose_path: Path to the docker-compose.yml file.

    Returns:
        List of issue strings (prefixed with CRITICAL/WARNING/INFO).
    """
    issues: list[str] = []

    with compose_path.open(encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    services = compose.get("services", {})

    for service_name, service_config in services.items():
        if service_config is None:
            continue

        ports = service_config.get("ports", [])

        for port in ports:
            port_str = str(port)

            # Check if internal-only service has non-localhost ports
            if service_name in INTERNAL_ONLY_SERVICES and not is_localhost_binding(port):
                issues.append(
                    f"CRITICAL: {service_name} exposes port {port_str} - "
                    "internal services must not be externally accessible"
                )

            # Check for 0.0.0.0 bindings or unspecified host (exposes to all interfaces)
            host_binding, _ = parse_port_binding(port)
            # S104 false positive: we're checking for this binding, not creating it
            is_all_interfaces = host_binding is None or host_binding.startswith(
                "0.0.0.0"  # noqa: S104
            )
            if is_all_interfaces and service_name not in {"qerds-api"}:
                issues.append(
                    f"WARNING: {service_name} binds to all interfaces ({port_str}) - "
                    "consider restricting to 127.0.0.1 in development"
                )

    return issues


def check_production_readiness(compose_path: Path) -> list[str]:
    """Check for dev-only services that shouldn't be in production.

    Args:
        compose_path: Path to the docker-compose.yml file.

    Returns:
        List of issue strings.
    """
    issues: list[str] = []

    with compose_path.open(encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    services = compose.get("services", {})

    for service_name in DEV_ONLY_SERVICES:
        if service_name in services:
            service = services[service_name]
            if service is None:
                continue

            # Check if it's in a dev-only profile
            profiles = service.get("profiles", [])
            if not profiles:
                issues.append(
                    f"INFO: {service_name} has no profile restriction - "
                    "ensure it's disabled or removed in production"
                )
            elif "dev" not in profiles and "development" not in profiles:
                issues.append(
                    f"INFO: {service_name} is not in a dev profile ({profiles}) - "
                    "verify it's properly controlled for production"
                )

    return issues


def check_network_isolation(compose_path: Path) -> list[str]:
    """Check for proper network isolation configuration.

    Args:
        compose_path: Path to the docker-compose.yml file.

    Returns:
        List of issue strings.
    """
    issues: list[str] = []

    with compose_path.open(encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    services = compose.get("services", {})

    for service_name, service_config in services.items():
        if service_config is None:
            continue

        # Check for host networking (security risk)
        network_mode = service_config.get("network_mode")
        if network_mode == "host":
            issues.append(
                f"CRITICAL: {service_name} uses host networking - "
                "this bypasses container network isolation"
            )

        # Check for privileged mode
        if service_config.get("privileged", False):
            issues.append(
                f"WARNING: {service_name} runs in privileged mode - "
                "verify this is necessary and document the reason"
            )

    return issues


def main() -> int:
    """Run the network security check.

    Returns:
        Exit code (0 for success, 1 for critical failures).
    """
    if yaml is None:
        print("ERROR: PyYAML is required. Install with: pip install pyyaml")
        return 1

    parser = argparse.ArgumentParser(description="Check QERDS network security posture (REQ-D07)")
    parser.add_argument(
        "--docker-compose",
        type=Path,
        default=None,
        help="Path to docker-compose.yml (default: auto-detect)",
    )
    parser.add_argument(
        "--production",
        action="store_true",
        help="Enable production-level checks (stricter)",
    )
    args = parser.parse_args()

    # Find docker-compose.yml
    if args.docker_compose:
        compose_path = args.docker_compose
    else:
        # Try to find it relative to script location or current directory
        script_dir = Path(__file__).parent
        project_root = script_dir.parent
        compose_path = project_root / "docker-compose.yml"
        if not compose_path.exists():
            compose_path = Path("docker-compose.yml")

    if not compose_path.exists():
        print(f"ERROR: docker-compose.yml not found at {compose_path}")
        return 1

    print(f"Checking network security in {compose_path}...")
    print()

    # Run all checks
    all_issues: list[str] = []

    all_issues.extend(check_docker_compose(compose_path))
    all_issues.extend(check_network_isolation(compose_path))

    if args.production:
        all_issues.extend(check_production_readiness(compose_path))

    # Report results
    if all_issues:
        print("Issues found:")
        for issue in all_issues:
            print(f"  - {issue}")
        print()

    # Count by severity
    critical_count = sum(1 for i in all_issues if i.startswith("CRITICAL"))
    warning_count = sum(1 for i in all_issues if i.startswith("WARNING"))
    info_count = sum(1 for i in all_issues if i.startswith("INFO"))

    # Summary
    print(f"Summary: {critical_count} critical, {warning_count} warnings, {info_count} info")

    if critical_count > 0:
        print("\nFAILED: Critical network security issues found")
        return 1

    if all_issues:
        print("\nPASSED with warnings")
    else:
        print("\nPASSED: No network security issues found")

    return 0


if __name__ == "__main__":
    sys.exit(main())
