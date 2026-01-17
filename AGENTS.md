# Agent Instructions for QERDS

These instructions adapt the *general* parts of `../fj2/AGENTS.md` for this repository while explicitly **excluding** France‑Jeunes/Django‑specific items (no Django here).

## Ask First (CRITICAL)

When there’s any non-obvious decision or uncertainty (architecture, security model, crypto choices, UI wording/UX, legal/compliance interpretation, trade-offs, ambiguous requirements), stop and ask the user (**max 4 questions per batch**).

## Scope Guardrail (for now)

The user currently wants **agent instructions only**. Do not create implementation code or new specs unless explicitly requested in a later prompt.

## Hard Requirements (Project-Wide)

### Self-hosting
- All components must be **self-hostable** and kept within this repo (no reliance on third-party hosted providers).
- All runtime frontend assets must be self-hosted (no external CDN at runtime). Vendored frontend deps are fine (e.g., Tailwind), but must be served locally.

### Services in Docker
- `docker compose up` must bring up everything needed for a working dev platform.
- Mail testing must use **Mailpit**.
- S3-compatible storage in compose may use **MinIO** (approved by user).

### Data store
- Must be production-ready from the start: **no SQLite**.
- Prefer **PostgreSQL** for core state/evidence storage.

### Backend dependencies
- Prefer Python standard library.
- Small frameworks are allowed (user approved), but keep external deps minimal and justified.
- If cryptography libraries are needed, prefer minimal, well-audited choices and document why they’re required.

## Code Quality
- Use type hints everywhere.
- Keep functions small and focused.
- Write docstrings for public functions.
- Keep documentation DRY: reference code paths instead of duplicating schemas/behaviors in prose.

## Compliance Guardrail

Do **not** claim QERDS/LRE qualification unless *all* normative requirements are met. If any dev/stub mode exists (e.g., non-qualified signatures/timestamps), it must be clearly labeled as **non-qualified** and must not be presented as compliant.
