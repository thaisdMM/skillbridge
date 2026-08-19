# SkillBridge — Root Context

Operational context for the monorepo. This file states **facts about the
environment**. It does not restate behavior rules, conventions, or
architectural decisions — those live in the files listed under
"Context files to load" and are authoritative there.

---

## Repository layout

Monorepo with two implementations of the same domain:

| Directory         | Status                                          |
| ----------------- | ----------------------------------------------- |
| `django_version/` | **Active.** All work targets this directory.    |
| `oop_version/`    | **Closed.** Historical reference only.          |

Never run project commands in `oop_version/`.

---

## Execution environment

- All project commands run inside Docker, from `django_version/`:
  `docker-compose exec web <command>`
  (e.g. `pytest`, `python manage.py makemigrations`, `python manage.py shell`).
- Never install packages on the system Python.
- The host virtualenv at `django_version/.venv/` is **IDE-only**. It is
  independent of Docker and is not the runtime.

---

## Stack

Python 3.14, Django 6.x, PostgreSQL 17, psycopg3, Argon2id, pytest-django,
Docker, GitHub Actions CI. DRF and drf-spectacular are planned but **not yet
installed**.

`.claude/rules/conventions.md` ("Stack and versions") names the one
authoritative file for each version, and the rule for reading `uv.lock`. Do
not duplicate version numbers here or there.

---

## Spec-Driven Development artifacts

GitHub Spec Kit is installed at `.specify/`.

- Project constitution: `.specify/memory/constitution.md`.
- Feature specs are written to `specs/<feature-branch>/` at the **monorepo
  root**, not inside `django_version/` — they describe domain features
  independently of the implementation
  (`.specify/scripts/bash/create-new-feature.sh:130`).
- Any command a spec triggers (tests, migrations, code) still executes
  inside Docker.

---

## Context files to load

**Already auto-loaded — do not re-read, do not duplicate:**

- `.claude/rules/conventions.md` — operational conventions.
- `.claude/rules/testing.md` — testing conventions.

**Load explicitly and obey in full, in any session that touches
`django_version/`:**

- `django_version/CLAUDE.md` — **the single source of truth for detailed
  behavior rules.** Not auto-loaded; read it before acting.
- `ARCHITECTURE.md` (repo root) — architectural decisions and their reasoning.

**Persona files** — load the one named for the session:
`django_version/AUDITOR.md`, `VERIFIER.md`, `PLANNER.md`, `DEVELOPER.md`,
`TEACHER.md`.

---

## Docs map

| File                          | Purpose                                       |
| ----------------------------- | --------------------------------------------- |
| `docs/ROADMAP_SKILLBRIDGE.md` | The project roadmap.                          |
| `docs/ROADMAP_STACK_TRIAGE.md`| Stack-refactor triage feeding the roadmap.    |
| `docs/SYSTEM_OVERVIEW.md`     | System overview.                              |
| `docs/tech_debt/`             | Known technical debt, one file per decision.  |
| `docs/adr/`                   | Architecture Decision Records.                |
