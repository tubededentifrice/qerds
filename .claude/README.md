# Claude Code Configuration for QERDS

This directory contains Claude Code skills, agents, and commands for the project.

## Directory Structure

```
.claude/
├── README.md              # This file
├── settings.json          # Plugin configuration
├── skills/                # Implementation standards
│   ├── director/SKILL.md  # Top-level coordination
│   ├── backend-development/SKILL.md
│   ├── frontend-development/SKILL.md
│   └── security-check/SKILL.md
├── agents/                # Specialized agent definitions
│   ├── coder.md           # Implementation agent
│   ├── reviewer.md        # Quality/security review
│   ├── documenter.md      # Documentation verification
│   ├── commiter.md        # Git operations
│   └── oracle.md          # Deep research (use sparingly)
└── commands/              # Slash commands
    └── ai-slop.md         # Remove AI-generated code patterns
```

## Skills vs Agents

- **Skills** define *how* to do something (patterns, standards, checklists)
- **Agents** are *who* does something (specialized roles with focused responsibilities)

| Need | Use |
|------|-----|
| Plan cross-component work | Director skill |
| Implement code | Coder agent (loads backend/frontend skills) |
| Review changes | Reviewer agent |
| Update documentation | Documenter agent |
| Commit changes | Commiter agent |
| Research hard problems | Oracle agent |

## Agent Workflow

The Director orchestrates work through a quality-focused pipeline:

```
DIRECTOR (plans, coordinates, tracks issues)
    │
    ▼
1. CODER (implements with quality code, tests, comments)
    │
    ▼
2. REVIEWER (verifies quality, security, task completion)
    │
    ├── CHANGES_REQUIRED → back to CODER
    │
    └── APPROVED ↓
    │
    ▼
3. DOCUMENTER (ensures docs match code)
    │
    ▼
4. DIRECTOR (updates issue status)
    │
    ▼
5. COMMITER (git add, commit, push)
```

For critical decisions or blockers, the Director can invoke the **ORACLE** for deep research.

## Using Skills

Load skills by reading them:

```
Read: .claude/skills/director/SKILL.md
```

## Using Agents

Invoke agents via the Task tool:

```
subagent_type: "general-purpose"
prompt: |
  Read and follow: .claude/agents/coder.md

  Component: evidence
  Task: Add timestamp verification
  ...
```

## Using Commands

Run slash commands from the CLI:

```
/ai-slop
```

## Key Principles

1. **Compliance-first**: Every change considers certification/qualification impact
2. **Quality over speed**: The workflow includes review and documentation steps
3. **Separation of concerns**: Each agent has a focused role
4. **Iteration**: Director loops back to Coder based on Reviewer feedback
5. **DRY documentation**: Code is the source of truth; docs reference code

## Model Usage

- **Coder, Oracle**: Default model (most capable)
- **Reviewer, Documenter**: Sonnet (balanced)
- **Commiter**: Haiku (fast, simple tasks)
