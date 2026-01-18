# Agent Instructions for QERDS

These instructions adapt the *general* parts of `../fj2/AGENTS.md` for this repository while explicitly **excluding** France‑Jeunes/Django‑specific items (no Django here).

## Ask First (CRITICAL)

When there’s any non-obvious decision or uncertainty (architecture, security model, crypto choices, UI wording/UX, legal/compliance interpretation, trade-offs, ambiguous requirements), stop and ask the user (**max 4 questions per batch**).

## Scope Guardrail (for now)

The user currently wants **high-level certification requirements and tracking only**. Do not implement product features unless explicitly requested.

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

## Documentation & Tracking (CRITICAL)

- `specs/requirements.md` is the single source of truth for high-level certification requirements (MUST/SHALL-level only; avoid implementation design here).
- `README.md` contains the requirements status tables and MUST stay in sync with `specs/requirements.md`:
  - If you add/remove/rename a requirement ID in `specs/requirements.md`, update the corresponding `README.md` table(s) in the same change.
  - Track both categories:
    - **Service/platform requirements** (what the service must do to be QERDS/LRE compatible).
    - **Provider operational obligations & technical enablers** (what the operator must be able to prove, and what the platform must enable: audit packs, immutable logs, DR evidence, etc.).
  - When implementing a requirement, flip the status from ❌ to ✅ and add a short comment (what/where), ideally pointing to code paths and tests.
- Never mark a requirement ✅ unless it is demonstrably implemented end-to-end (code + tests + operational notes where relevant).

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
