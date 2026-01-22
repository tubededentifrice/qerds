#!/usr/bin/env python3
"""
Validate that all requirements in specs/requirements.md have corresponding
entries in specs/traceability.md.

This script is part of the CI pipeline to ensure traceability coverage (REQ-A04).

Usage:
    python scripts/check-traceability.py
    # or
    make check-traceability

Exit codes:
    0 - All requirements have traceability entries
    1 - Missing or invalid entries found
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def extract_requirement_ids(content: str) -> set[str]:
    """
    Extract all REQ-* and SPEC-* IDs from a markdown file.

    Looks for patterns like:
    - **REQ-A01 (Title)**: Description
    - ### REQ-A01 (Title)
    """
    # Match REQ-X## or SPEC-X## patterns (letter + digits)
    pattern = r"\b(REQ-[A-Z]\d{2}|SPEC-[A-Z]\d{2})\b"
    matches = re.findall(pattern, content)
    return set(matches)


def extract_traceability_ids(content: str) -> set[str]:
    """
    Extract all requirement IDs documented in traceability.md.

    Looks for section headers like:
    - ### REQ-A01 (Title)
    - ### SPEC-J01 (Title)
    """
    # Match requirement headers in traceability format
    pattern = r"^###\s+(REQ-[A-Z]\d{2}|SPEC-[A-Z]\d{2})"
    matches = re.findall(pattern, content, re.MULTILINE)
    return set(matches)


def validate_traceability_format(content: str, req_ids: set[str]) -> list[str]:
    """
    Validate that each traceability entry has the required fields.

    Returns a list of validation errors.
    """
    errors = []
    required_fields = ["Status", "Description", "Implementation Modules", "Tests"]

    for req_id in req_ids:
        # Find the section for this requirement
        section_pattern = rf"###\s+{re.escape(req_id)}.*?(?=\n###|\n---|\Z)"
        match = re.search(section_pattern, content, re.DOTALL)

        if not match:
            continue  # Missing entries are caught elsewhere

        section = match.group(0)

        for field in required_fields:
            if f"**{field}**:" not in section:
                errors.append(f"{req_id}: Missing required field '{field}'")

    return errors


def main() -> int:
    """
    Main entry point for the traceability check.

    Returns exit code (0 for success, 1 for failure).
    """
    # Determine project root (script is in scripts/)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent

    requirements_path = project_root / "specs" / "requirements.md"
    traceability_path = project_root / "specs" / "traceability.md"

    # Check that files exist
    if not requirements_path.exists():
        print(f"ERROR: Requirements file not found: {requirements_path}")
        return 1

    if not traceability_path.exists():
        print(f"ERROR: Traceability file not found: {traceability_path}")
        return 1

    # Read files
    requirements_content = requirements_path.read_text(encoding="utf-8")
    traceability_content = traceability_path.read_text(encoding="utf-8")

    # Extract IDs
    requirement_ids = extract_requirement_ids(requirements_content)
    traceability_ids = extract_traceability_ids(traceability_content)

    # Find missing entries
    missing_ids = requirement_ids - traceability_ids
    extra_ids = traceability_ids - requirement_ids

    # Validate format
    format_errors = validate_traceability_format(traceability_content, traceability_ids)

    # Report results
    has_errors = False

    if missing_ids:
        has_errors = True
        print("MISSING TRACEABILITY ENTRIES:")
        for req_id in sorted(missing_ids):
            print(f"  - {req_id}")
        print()

    if extra_ids:
        # Extra entries are warnings, not errors (might be deprecated requirements)
        print("WARNING - Extra entries in traceability (not in requirements.md):")
        for req_id in sorted(extra_ids):
            print(f"  - {req_id}")
        print()

    if format_errors:
        has_errors = True
        print("FORMAT ERRORS:")
        for error in format_errors:
            print(f"  - {error}")
        print()

    # Summary
    total_requirements = len(requirement_ids)
    covered_requirements = len(requirement_ids & traceability_ids)

    print(
        f"Traceability coverage: {covered_requirements}/{total_requirements} requirements"
    )

    if has_errors:
        print("\nTRACEABILITY CHECK FAILED")
        return 1

    print("\nTRACEABILITY CHECK PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
