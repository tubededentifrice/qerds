# Agent Instructions for QERDS

## Ask First (CRITICAL)

When there’s any non-obvious decision or uncertainty (architecture, security model, crypto choices, UI wording/UX, legal/compliance interpretation, trade-offs, ambiguous requirements), stop and ask the user using the AskUserQuestion tool, with clear explanations and recommendations.

## Hard Requirements (Project-Wide)

### Self-hosting
- All components linked to requirements must be **self-hostable** and kept within this repo (no reliance on third-party hosted providers).
- All runtime frontend assets must be self-hosted (no external CDN at runtime). Vendored frontend deps are fine (e.g., Tailwind), but must be served locally.

### Services in Docker
- `docker compose up` must bring up everything needed for a working dev platform.
- Mail testing must use **Mailpit**.
- S3-compatible storage in compose may use **MinIO**.

### Data store
- Must be production-ready from the start: **no SQLite**.
- Prefer **PostgreSQL** for core state/evidence storage.

### Backend dependencies
- Prefer Python standard library.
- Small frameworks are allowed (user approved), but keep external deps minimal and justified.
- If cryptography libraries are needed, prefer minimal, well-audited choices and document why they're required.
- **Always use latest stable versions**: When adding dependencies, always specify the latest stable version. Check PyPI/npm before adding any dependency. Pin exact versions in requirements files for reproducibility.

## Code Quality
- Use type hints everywhere.
- Keep functions small and focused.
- Write docstrings for public functions.
- Keep documentation DRY: reference code paths instead of duplicating schemas/behaviors in prose.

### Frontend CSS Guidelines (Strictly Enforced)
- **Semantic class names**: Use classes that describe the element's purpose, not its appearance (e.g., `.delivery-card`, `.pickup-hero`, not `.blue-box`, `.large-text`)
- **CSS must be minimal**:
  - Use CSS variables for all colors, spacing, typography (defined in `:root`)
  - Target multiple elements in the same CSS block when they share styles
  - Avoid inline styles in templates; use classes instead
  - Group related selectors (e.g., `.btn--primary, .btn--secondary { ... }`)
- **No utility class proliferation**: Unlike Tailwind, avoid creating many single-purpose utility classes. Use semantic classes that encapsulate related styles.
- **Match the mocks**: Implementation must visually match the UI mocks in `mocks/`. Do not deviate from the design without explicit approval.
- **Reuse existing patterns**: Before creating new CSS, check if an existing class can be reused or extended.

### DRY (Don't Repeat Yourself) - Strictly Enforced
- **No copy-paste code**: If you're copying code, extract it into a shared function/module
- **Single source of truth**: Constants, config, and business logic must live in one place
- **Documentation follows code**: Don't duplicate info in docs that exists in code; reference it instead
- **Three strikes rule**: If a pattern appears 3+ times, refactor immediately (don't file an issue, fix it now)
- **Cross-cutting concerns**: Auth, logging, validation should use decorators/middleware, not inline repetition

### Test Coverage
- **Minimum**: 80% overall coverage required
- **Target**: 90% coverage
- New code should have tests before merging
- Critical paths (crypto, auth, evidence handling) should aim for 95%+
- **Tests must run in Docker**: All tests must run against Docker containers for reproducibility. Use `docker compose exec` or similar for running tests.

### Code Formatting & Linting
- **Ruff is mandatory**: Use `ruff` for both formatting (`ruff format`) and linting (`ruff check`). No other formatters/linters.
- Run `ruff check --fix` to auto-fix issues where possible
- Pre-commit hooks must enforce ruff
- CI must fail on ruff violations

## Git Worktrees (CRITICAL - Read Before Using)

When running parallel tasks with git worktrees, follow these rules **exactly** to avoid data loss.

### Worktree Creation Rules

1. **Create worktrees OUTSIDE the `.git/` directory**:
   ```bash
   # CORRECT - create in a sibling directory
   git worktree add ../qerds-worktrees/task-name feature/task-name

   # WRONG - never create inside .git/
   git worktree add .git/worktrees/task-name feature/task-name  # DON'T DO THIS
   ```

2. **Use absolute paths** to avoid confusion:
   ```bash
   git worktree add /home/ubuntu/git/qerds-worktrees/qerds-abc feature/qerds-abc
   ```

### NEVER Delete These Files

When working in a worktree, you may see these files in `git status`:
- `HEAD`, `ORIG_HEAD`, `FETCH_HEAD`
- `gitdir`, `commondir`
- `index`, `index.lock`

**These are CRITICAL git infrastructure files, NOT artifacts to clean up.**

⚠️ **NEVER run `rm` on these files** - doing so destroys the worktree and loses all uncommitted work.

### Commit Early and Often in Worktrees

Uncommitted work in a worktree is **not protected by git**. If the worktree is damaged, uncommitted changes are lost.

```bash
# In worktree: commit work frequently
git add -A
git commit -m "WIP: partial implementation"
git push -u origin feature/task-name
```

### Worktree Cleanup (Safe Method)

```bash
# List worktrees
git worktree list

# Remove a worktree SAFELY (preserves commits on the branch)
git worktree remove /path/to/worktree

# Clean up stale worktree references
git worktree prune -v
```

### Recovery if Worktree is Damaged

If a worktree becomes corrupted:
1. **Don't panic** - committed work is safe in the branch
2. Run `git worktree prune` from the main repo
3. Re-create the worktree: `git worktree add <path> <branch>`
4. Your committed changes will be there

### Shell Working Directory

If your shell's working directory is inside a worktree that gets deleted, **all bash commands will fail**. Recovery requires starting a new session with a valid working directory.

## Beads (bd) Issue Tracking

This project uses **bd** (beads) for issue tracking. All work must be tracked.

### Quick Reference
```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --status in_progress  # Claim work
bd close <id>         # Complete work
bd sync               # Sync with git
bd create "Title"     # Create new issue
```

### Issue Workflow
1. Run `bd ready` to find available work
2. Claim issue with `bd update <id> --status in_progress`
3. Complete the work
4. Run tests and linters
5. Close with `bd close <id>`
6. Sync with `bd sync`

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

## Self-Improvement Protocol

> **Self-Improving Document**: `CLAUDE.md` symlinks to `AGENTS.md`. When you encounter issues, unclear instructions, or discover better approaches, update `AGENTS.md` immediately. Future agents depend on accurate, current instructions.

### Code Quality Over Time
- When you spot code smells or technical debt while working, file an issue with `bd create`
- DRY violations: fix immediately (don't file an issue, refactor now)
- Other refactors: only when directly relevant to current work (avoid scope creep)
- Leave code cleaner than you found it, but stay focused on the task

### When to Update AGENTS.md
Update this file when:
- You discover a better approach or workflow
- Instructions are unclear, outdated, or misleading
- You find a common pitfall that future agents should avoid
- Quality gates or tooling changes
- New project conventions are established

### How to Update
1. Make the change clearly and concisely
2. Add context if the reasoning isn't obvious
3. Commit: `docs: update AGENTS.md - [what changed]`
4. Future agents will benefit from your improvements
