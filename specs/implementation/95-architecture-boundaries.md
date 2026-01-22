# Backend/Frontend Architecture Boundaries

Covers: REQ-I01, REQ-I02

This document defines the architectural separation between the certified backend
core and the frontend presentation layer, enabling independent updates to the
frontend without requiring re-certification of backend logic.

## Rationale

Per REQ-I01, the system must maintain a clear separation between:
- **Certified Core (Backend)**: Components subject to QERDS/LRE compliance audits
- **Frontend**: Presentation layer that can be updated independently

This separation allows:
1. Frontend styling and UX improvements without audit impact
2. Clear audit boundaries for certification assessments
3. Independent release cycles where appropriate
4. Clear responsibility assignment for security controls

## Component Classification

### Certified Core (Backend)

These components implement normative requirements and are subject to certification:

```
src/qerds/
  services/        # Business logic, evidence handling, lifecycle
    audit_log.py   # REQ-D08, REQ-H03 - Tamper-evident logging
    authz.py       # REQ-D02, REQ-E02 - Authorization enforcement
    email.py       # REQ-C01, REQ-F02 - Notification delivery
    evidence.py    # REQ-B01, REQ-C01-05 - Evidence generation
    job_queue.py   # REQ-C05, REQ-H02 - Background job processing
    lifecycle.py   # REQ-C01, REQ-F04 - Delivery state machine
    pdf.py         # REQ-F07 - Human-readable proof generation
    security_events.py  # REQ-D08 - Security event logging
    session.py     # REQ-D02 - Session management
    storage.py     # REQ-E01, REQ-H02 - Secure storage
    trust.py       # REQ-C02, REQ-C03 - Trust service integration

  trust/           # Signing, timestamping, key management
    main.py        # REQ-C02, REQ-C03, REQ-D04, REQ-G02

  db/              # Data model and migrations
    models/        # REQ-C05, REQ-H02 - Data integrity
    migrations/    # REQ-H05 - Change management

  core/            # Shared core utilities
    config.py      # REQ-G02 - Qualification mode control
    settings.py    # Application configuration

  worker/          # Background job runner
    main.py        # REQ-F04, REQ-H02 - Scheduled tasks

  api/middleware/  # Security middleware
    auth.py        # REQ-D02, REQ-B05 - Authentication
    errors.py      # Error handling
    request_id.py  # REQ-D08 - Request tracing
```

### API Layer (Boundary Interface)

The API layer serves as the **boundary interface** between backend and frontend:

```
src/qerds/api/
  main.py          # FastAPI application setup
  routers/         # HTTP endpoints (both HTML and JSON)
    admin.py       # Admin API endpoints
    pages.py       # HTML page rendering (calls templates)
    recipient.py   # Recipient API endpoints
    sender.py      # Sender API endpoints
    trust.py       # Trust service API endpoints
    verify.py      # Verification API endpoints
  templates.py     # Template context building (bridge to frontend)
  i18n.py          # Internationalization support
```

**Key Principle**: The API layer translates between HTTP requests and backend
services. It MUST NOT contain business logic - only request validation,
authentication enforcement, and response formatting.

### Frontend (Presentation Layer)

These components handle presentation only and are NOT part of the certified core:

```
src/qerds/
  templates/       # Jinja2 HTML templates
    base.html      # Base layout
    login.html     # Login page
    verify.html    # Verification portal
    admin/         # Admin UI templates
    email/         # Email templates (notification content)
    partials/      # Reusable template fragments
    pdf/           # PDF template fragments
    recipient/     # Recipient portal templates
    sender/        # Sender dashboard templates

  static/          # Static assets
    css/           # Stylesheets
      main.css     # Application styles
      fonts.css    # Font definitions
    js/            # JavaScript
      main.js      # Client-side interactions
    fonts/         # Self-hosted fonts

  locales/         # Localization files
    en.json        # English translations
    fr.json        # French translations
```

## Separation Rules

### Rule 1: Frontend Cannot Import Backend Services Directly

Templates and static assets MUST NOT contain direct imports of:
- `qerds.services.*`
- `qerds.trust.*`
- `qerds.db.models.*`
- `qerds.worker.*`

All data must flow through the API layer via template context variables.

**Correct pattern:**
```python
# In api/routers/pages.py
from qerds.services.evidence import EvidenceService

async def delivery_page(request: Request, delivery_id: str):
    # Service call happens in the API layer
    evidence_service = EvidenceService(session)
    events = await evidence_service.get_timeline(delivery_id)

    # Data passed to template via context
    return templates.TemplateResponse("delivery.html", {
        "events": events,  # Data, not service
    })
```

**Incorrect pattern:**
```html
<!-- WRONG: Template should never import services -->
{% set events = evidence_service.get_timeline(delivery_id) %}
```

### Rule 2: Backend Enforces All Security Controls

Per REQ-I02, all security controls MUST be enforced in the backend:

| Control | Backend Enforcement | Frontend Role |
|---------|---------------------|---------------|
| Authentication | `api/middleware/auth.py` | Display login form |
| Authorization | `services/authz.py` | Show/hide UI elements |
| Input validation | API routers (Pydantic) | Client-side hints only |
| Rate limiting | Backend middleware | Display error messages |
| CSRF protection | Backend middleware | Include tokens in forms |
| Session management | `services/session.py` | Store session cookie |

The frontend MAY provide additional client-side validation for UX, but the
backend MUST NOT rely on it for security.

### Rule 3: Static Assets Are Self-Contained

Static files (`static/`) MUST NOT:
- Reference external CDNs at runtime
- Include inline scripts that call backend services
- Contain configuration secrets

Static files MAY:
- Use HTMX to call API endpoints
- Reference other static assets
- Include feature flags passed via data attributes

### Rule 4: Templates Are Stateless

Templates MUST:
- Receive all data via context variables
- Not perform database queries
- Not call external services
- Not contain business logic beyond display formatting

Templates MAY:
- Use template filters for formatting (dates, numbers)
- Include conditional display logic based on context
- Generate URLs using FastAPI's URL routing
- Reference static assets

## Deployment Separation

While currently sharing a single Docker image for simplicity, the architecture
supports future separation:

### Current (Monolithic)

```
docker/
  Dockerfile.api   # Contains both backend code and frontend assets
```

Static assets are served by FastAPI's `StaticFiles` middleware.

### Future Option (Separated)

If needed for compliance or operational reasons:

```
docker/
  Dockerfile.api     # Backend only (no templates/static)
  Dockerfile.nginx   # Frontend assets + reverse proxy
```

This would allow:
- CDN caching of static assets
- Independent scaling of frontend serving
- Clearer audit boundary in Docker images

The current architecture is designed to support this separation without code
changes - only deployment configuration would change.

## CI Enforcement

The separation is enforced via `scripts/check_boundaries.py`:

1. **Import check**: Verifies templates don't import backend modules
2. **Static asset check**: Verifies no external CDN references
3. **Service isolation check**: Verifies services don't import template code

Run as part of CI:
```bash
python scripts/check_boundaries.py
```

## Audit Considerations

For certification assessments:

1. **Scope Definition**: The certified core is defined by the paths listed in
   "Certified Core (Backend)" above.

2. **Frontend Changes**: Changes to `templates/`, `static/`, or `locales/`
   do not require backend re-certification unless they modify API contracts.

3. **API Contract Changes**: Changes to the API layer that affect security
   controls or evidence generation require audit review.

4. **Traceability**: Each certified component maps to requirements in
   `specs/traceability.md`.

## References

- `specs/requirements.md` - REQ-I01, REQ-I02
- `specs/implementation/05-architecture.md` - System architecture
- `scripts/check_boundaries.py` - CI enforcement script
