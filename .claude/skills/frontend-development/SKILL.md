---
name: frontend-development
description: Standard frontend/template practices for QERDS (HTML templates, HTMX, Alpine.js, semantic CSS classes).
---

# Frontend Development Skill

Use this skill whenever you are implementing or modifying **templates, UI behavior, or styling** in this repo, specifically in:

- `templates/**`
- `static/**`

This skill is commonly used **alongside** Backend Development (templates usually require backend/context changes).

## When to Use This Skill

- Building or modifying HTML templates (pages, components, partials).
- Adding HTMX interactions (partial rendering, progressive enhancement).
- Light Alpine.js interactivity.
- Styling changes (prefer semantic classes).

## Prerequisites

Before starting, read:

1. Root `CLAUDE.md` (especially "Frontend CSS Guidelines").
2. Relevant specs if applicable.
3. Nearby templates and existing semantic class patterns.
4. UI mocks in `mocks/` directory.

## Rendering Rules

- SSR-first: pages must render meaningful content without JS.
- Use semantic HTML (`<main>`, `<nav>`, `<article>`, headings in order).
- Don't hide critical content behind HTMX-only flows.
- Ensure any interactive elements degrade gracefully.

## Styling Rules (from CLAUDE.md)

- **Semantic class names**: Use classes that describe the element's purpose, not its appearance (e.g., `.delivery-card`, `.evidence-panel`, not `.blue-box`, `.large-text`)
- **CSS must be minimal**:
  - Use CSS variables for all colors, spacing, typography (defined in `:root`)
  - Target multiple elements in the same CSS block when they share styles
  - Avoid inline styles in templates; use classes instead
  - Group related selectors
- **No utility class proliferation**: Avoid creating many single-purpose utility classes
- **Match the mocks**: Implementation must visually match the UI mocks in `mocks/`

## Template Structure

```
templates/
  base.html
  components/
  pages/
  partials/
```

Keep reusable UI in `templates/components/` and HTMX responses in `templates/partials/`.

## HTMX Patterns

- Use `hx-get`/`hx-post` with clear `hx-target` and `hx-swap`.
- Prefer server-rendered partials over client-side templating.
- Ensure forms have server-side validation messages in the swapped content.

## Alpine.js Guidelines

- Use for client-side state that doesn't need server round-trips.
- Keep components small and focused.
- Ensure critical content is visible without JS (progressive enhancement).

## Accessibility Checklist

- [ ] All interactive elements are real `<a>`/`<button>`/`<input>` elements.
- [ ] Inputs have labels and error messages are associated.
- [ ] Focus states remain visible.
- [ ] Color contrast meets WCAG AA standards.

## Validation Checklist

- [ ] Templates render without errors.
- [ ] No duplicated styling where a semantic class exists.
- [ ] HTMX flows still work with JS disabled (core content visible).
- [ ] All user-facing strings externalized for i18n (per SPEC-J01).
