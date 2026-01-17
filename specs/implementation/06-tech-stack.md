# Recommended tech stack (audit-friendly)

Covers: REQ-A02, REQ-D01, REQ-D03, REQ-D08, REQ-H01

## Goals

- Keep dependencies minimal and widely reviewed to reduce audit surface area. (REQ-A02)
- Prefer Python standard library where practical; use small, established libraries when required. (project constraint)

## Proposed baseline (Python)

### Web API

- **FastAPI** (built on Starlette) for typed HTTP APIs and OpenAPI generation.
- **Uvicorn** as ASGI server.

Rationale: small ecosystem, strong typing/story for request/response validation, widely used and auditable.

### Database access

- **psycopg** (v3) for PostgreSQL connectivity.
- **SQLAlchemy 2.x** for schema and queries, with **Alembic** migrations.

Rationale: avoid bespoke SQL glue; ensure migrations are explicit and reviewable for audits.

### Background jobs

- Prefer a **PostgreSQL-backed job table** (no Redis) using `SELECT ... FOR UPDATE SKIP LOCKED`.

Rationale: fewer moving parts and simpler self-hosting.

### Cryptography

- **cryptography** (Python package) for vetted primitives (hashing, signatures, X.509 parsing) when not delegated to an HSM.
- **PKCS#11** integration for HSM/QSCD-backed signing in qualified mode (exact library to be confirmed per HSM vendor).

Rationale: in qualified mode, private key operations must be isolated to certified hardware anyway; software crypto is mainly for non-qualified/dev and verification tooling. (REQ-D03, REQ-D04)

## Non-goals

- Selecting a specific HSM vendor or making claims about qualification based on software alone.

