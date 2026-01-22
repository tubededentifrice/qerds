---
name: backend-development
description: Standard backend development practices for QERDS (Python 3.12+, PostgreSQL, pytest, ruff, compliance-first).
---

# Backend Development Skill

Use this skill whenever you are implementing or modifying **backend Python logic** in this repo.

## When to Use This Skill

- Writing or modifying services, APIs, middleware, or utilities.
- Implementing business logic (evidence handling, cryptography, notifications).
- Working with models and database operations.
- Adding or updating tests (pytest).

## Prerequisites

Before starting, read:

1. Root `CLAUDE.md`.
2. The relevant spec(s) in `specs/` for the area you're touching.
3. `specs/requirements.md` for compliance requirements.
4. Nearby code + tests for existing patterns.

## Technology Stack

Per `CLAUDE.md`, the target stack is:

| Component | Technology |
|-----------|------------|
| Runtime | Python 3.12+ |
| Database | PostgreSQL (production-ready from start) |
| Testing | pytest + pytest-cov |
| Lint/Format | ruff |
| Containers | Docker Compose |

Follow the specs and existing code, and **ask before introducing new dependencies**.

## Coding Standards

- **Type hints**: required on all new/modified public functions and methods.
- **Docstrings**: required for public functions/classes where behavior isn't obvious.
- **Prefer stdlib**: minimize external dependencies; justify any additions.
- **No `print()`** for app behavior; use Python `logging` module.

## Error Handling

- Use appropriate exceptions for validation failures.
- Prefer user-safe messages; don't leak secrets or internal state.
- Log errors with context for debugging.

## Cryptographic Code

When working with cryptographic operations:

- **Use well-audited libraries** (e.g., `cryptography`, `pyca`).
- **Document why** a specific algorithm or library is chosen.
- **Never roll your own crypto** for production use.
- **Use constant-time comparisons** for secrets (`hmac.compare_digest`).
- **Mark non-qualified** any dev/stub cryptographic implementations.

## Testing Requirements

- Add tests for all new behavior, including unhappy paths.
- Prefer pytest fixtures and factories over heavy setup in each test.
- Keep tests focused on behavior, not implementation details.
- **All tests must run in Docker** for reproducibility.
- Minimum 80% coverage overall, 95%+ for critical paths (crypto, auth, evidence).

## Documentation Requirements (DRY)

When behavior changes:

- Update relevant `specs/*.md`.
- Update `README.md` requirement status if a requirement is implemented.
- Prefer referencing code paths instead of duplicating definitions.

## Validation Checklist

Before considering work complete:

```bash
# Run in Docker
docker compose exec <service> ruff check .
docker compose exec <service> ruff format --check .
docker compose exec <service> pytest
```

All checks must pass.
