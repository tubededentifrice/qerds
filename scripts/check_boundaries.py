#!/usr/bin/env python3
"""Validate backend/frontend separation boundaries.

This script enforces the architectural separation defined in
specs/implementation/95-architecture-boundaries.md (REQ-I01, REQ-I02).

Checks performed:
1. Templates don't import backend services directly
2. Static assets don't reference external CDNs
3. Backend services don't import template/static code

Usage:
    python scripts/check_boundaries.py
    # or
    make check-boundaries

Exit codes:
    0 - All boundary checks pass
    1 - Boundary violations found
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Certified core modules that frontend must not import directly
CERTIFIED_CORE_MODULES = [
    "qerds.services",
    "qerds.trust",
    "qerds.db.models",
    "qerds.worker",
]

# Frontend paths (should not contain backend imports)
FRONTEND_PATHS = [
    "src/qerds/templates",
    "src/qerds/static",
]

# External CDN patterns that should not appear in static assets
EXTERNAL_CDN_PATTERNS = [
    r"https?://cdn\.",
    r"https?://cdnjs\.",
    r"https?://unpkg\.com",
    r"https?://jsdelivr\.net",
    r"https?://ajax\.googleapis\.com",
    r"https?://fonts\.googleapis\.com",  # Self-host fonts instead
    r"https?://maxcdn\.",
    r"https?://stackpath\.",
]

# Allowed external URLs (exceptions for legitimate external links)
ALLOWED_EXTERNAL_PATTERNS = [
    r"https?://[^/]*\.legifrance\.gouv\.fr",  # Legal references
    r"https?://[^/]*\.eur-lex\.europa\.eu",  # EU law references
    r"https?://schemas\.",  # XML/JSON schema references
    r"https?://www\.w3\.org",  # W3C standards
    r"https?://[^/]*localhost",  # Local development
    r"https?://127\.0\.0\.1",  # Local development
]


def find_project_root() -> Path:
    """Find the project root directory.

    Returns:
        Path to the project root (contains src/ and specs/).
    """
    script_dir = Path(__file__).parent
    return script_dir.parent


def check_template_imports(project_root: Path) -> list[str]:
    """Check that templates don't contain direct backend imports.

    Templates should receive data via context, not by importing services.

    Args:
        project_root: Path to the project root directory.

    Returns:
        List of violation messages.
    """
    violations = []
    templates_dir = project_root / "src" / "qerds" / "templates"

    if not templates_dir.exists():
        return []

    # Pattern to detect Python import-like syntax in templates
    # Jinja2 doesn't support imports, but check for any attempts
    import_patterns = [
        r"\{%\s*import\s+['\"]?qerds\.",
        r"\{%\s*from\s+['\"]?qerds\.",
        r"\{\{\s*qerds\.services\.",
        r"\{\{\s*qerds\.trust\.",
        r"\{\{\s*qerds\.db\.models\.",
        r"\{\{\s*qerds\.worker\.",
    ]

    for template_file in templates_dir.rglob("*.html"):
        content = template_file.read_text(encoding="utf-8")
        rel_path = template_file.relative_to(project_root)

        for pattern in import_patterns:
            matches = re.findall(pattern, content)
            if matches:
                violations.append(
                    f"{rel_path}: Template contains backend module reference (pattern: {pattern})"
                )

    return violations


def check_static_assets_external_cdn(project_root: Path) -> list[str]:
    """Check that static assets don't reference external CDNs.

    Per CLAUDE.md, all runtime frontend assets must be self-hosted.

    Args:
        project_root: Path to the project root directory.

    Returns:
        List of violation messages.
    """
    violations = []
    static_dir = project_root / "src" / "qerds" / "static"

    if not static_dir.exists():
        return []

    # Check CSS and JS files
    for ext in ["*.css", "*.js"]:
        for static_file in static_dir.rglob(ext):
            content = static_file.read_text(encoding="utf-8")
            rel_path = static_file.relative_to(project_root)

            for cdn_pattern in EXTERNAL_CDN_PATTERNS:
                matches = re.findall(cdn_pattern, content, re.IGNORECASE)
                if matches:
                    violations.append(
                        f"{rel_path}: External CDN reference found "
                        f"(matched: {matches[0]}). Use self-hosted assets instead."
                    )

    return violations


def check_backend_frontend_isolation(project_root: Path) -> list[str]:
    """Check that backend services don't import frontend code.

    Backend services should not depend on templates or static assets.

    Args:
        project_root: Path to the project root directory.

    Returns:
        List of violation messages.
    """
    violations = []
    services_dir = project_root / "src" / "qerds" / "services"
    trust_dir = project_root / "src" / "qerds" / "trust"
    worker_dir = project_root / "src" / "qerds" / "worker"
    db_dir = project_root / "src" / "qerds" / "db"

    # Patterns that indicate frontend imports in backend code
    frontend_import_patterns = [
        r"from\s+qerds\.templates\s+import",
        r"from\s+qerds\.static\s+import",
        r"import\s+qerds\.templates",
        r"import\s+qerds\.static",
    ]

    backend_dirs = [services_dir, trust_dir, worker_dir, db_dir]

    for backend_dir in backend_dirs:
        if not backend_dir.exists():
            continue

        for py_file in backend_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            rel_path = py_file.relative_to(project_root)

            for pattern in frontend_import_patterns:
                if re.search(pattern, content):
                    violations.append(
                        f"{rel_path}: Backend module imports frontend code (pattern: {pattern})"
                    )

    return violations


def check_api_layer_has_no_business_logic(project_root: Path) -> list[str]:
    """Check that API routers delegate to services (advisory check).

    This is an advisory check - it looks for patterns that might indicate
    business logic in API routers that should be in services.

    Args:
        project_root: Path to the project root directory.

    Returns:
        List of warning messages (not failures).
    """
    warnings = []
    routers_dir = project_root / "src" / "qerds" / "api" / "routers"

    if not routers_dir.exists():
        return []

    # Patterns that might indicate business logic in routers
    # These are advisory only - there are legitimate uses
    advisory_patterns = [
        (r"\.commit\(\)", "Database commit in router (should be in service)"),
        (r"hashlib\.", "Hashing in router (should be in service)"),
        (r"cryptography\.", "Crypto in router (should be in trust service)"),
    ]

    for py_file in routers_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        rel_path = py_file.relative_to(project_root)

        for pattern, message in advisory_patterns:
            if re.search(pattern, content):
                warnings.append(f"{rel_path}: Advisory - {message}")

    return warnings


def check_templates_stateless(project_root: Path) -> list[str]:
    """Check that templates don't contain database/service calls.

    Templates should receive all data via context variables.

    Args:
        project_root: Path to the project root directory.

    Returns:
        List of violation messages.
    """
    violations = []
    templates_dir = project_root / "src" / "qerds" / "templates"

    if not templates_dir.exists():
        return []

    # Patterns that indicate stateful operations in templates
    stateful_patterns = [
        (r"\{\{.*\.query\(", "Database query in template"),
        (r"\{\{.*await\s+", "Async call in template"),
        (r"\{%.*\.execute\(", "SQL execution in template"),
        (r"\{\{.*\.session\.", "Database session access in template"),
    ]

    for template_file in templates_dir.rglob("*.html"):
        content = template_file.read_text(encoding="utf-8")
        rel_path = template_file.relative_to(project_root)

        for pattern, message in stateful_patterns:
            if re.search(pattern, content):
                violations.append(f"{rel_path}: {message}")

    return violations


def main() -> int:
    """Run all boundary checks.

    Returns:
        Exit code (0 for success, 1 for violations found).
    """
    project_root = find_project_root()

    print("=" * 60)
    print("Backend/Frontend Boundary Check (REQ-I01, REQ-I02)")
    print("=" * 60)
    print()

    all_violations = []
    all_warnings = []

    # Check 1: Template imports
    print("Checking template imports...")
    violations = check_template_imports(project_root)
    all_violations.extend(violations)
    print(f"  Found {len(violations)} violation(s)")

    # Check 2: External CDN references
    print("Checking static assets for external CDN references...")
    violations = check_static_assets_external_cdn(project_root)
    all_violations.extend(violations)
    print(f"  Found {len(violations)} violation(s)")

    # Check 3: Backend/frontend isolation
    print("Checking backend/frontend isolation...")
    violations = check_backend_frontend_isolation(project_root)
    all_violations.extend(violations)
    print(f"  Found {len(violations)} violation(s)")

    # Check 4: Template statelessness
    print("Checking template statelessness...")
    violations = check_templates_stateless(project_root)
    all_violations.extend(violations)
    print(f"  Found {len(violations)} violation(s)")

    # Check 5: API layer business logic (advisory)
    print("Checking API layer (advisory)...")
    warnings = check_api_layer_has_no_business_logic(project_root)
    all_warnings.extend(warnings)
    print(f"  Found {len(warnings)} advisory warning(s)")

    print()

    # Report violations
    if all_violations:
        print("VIOLATIONS FOUND:")
        print("-" * 40)
        for violation in all_violations:
            print(f"  - {violation}")
        print()

    # Report warnings (advisory only)
    if all_warnings:
        print("ADVISORY WARNINGS (not blocking):")
        print("-" * 40)
        for warning in all_warnings:
            print(f"  - {warning}")
        print()

    # Summary
    print("=" * 60)
    if all_violations:
        print(f"BOUNDARY CHECK FAILED - {len(all_violations)} violation(s) found")
        print()
        print("Fix the violations above to ensure proper backend/frontend separation.")
        print("See specs/implementation/95-architecture-boundaries.md for details.")
        return 1

    print("BOUNDARY CHECK PASSED")
    if all_warnings:
        print(f"({len(all_warnings)} advisory warning(s) - review recommended)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
