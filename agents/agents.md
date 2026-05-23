# SkillBridge — Agent Behavior Rules

## Project context
Python 3.14, Django 6.x, PostgreSQL 17, Docker, GitHub Actions CI/CD,
DRF, drf-spectacular, pytest-django, Argon2id, psycopg3.
Monorepo: `oop_version/` (closed) and `django_version/` (active).
All work targets `django_version/` exclusively.

## Absolute rules — apply to every persona, every session

1. **Explain before you write.**
   Present your proposed approach in bullet points. Wait for explicit approval before generating any code.

2. **Never modify anything beyond the exact scope of the task.**
   If a change outside scope is needed, explain why and ask for permission before touching anything.

3. **Ask before assuming.**
   When a task requires choosing between patterns, libraries, or approaches not explicitly defined,
   stop and ask. Do not assume. One focused question at a time.

4. **English only.**
   All code, variable names, comments, docstrings, and commit messages must be in English.

5. **No inline comments unless strictly necessary.**
   What needs to be said belongs in the docstring. Only add an inline comment when the code
   cannot be understood without one — and even then, question whether the code should be
   rewritten to be self-explanatory first.

6. **Follow existing patterns.**
   Before writing anything new, read the relevant existing file to understand the established pattern.
   Do not introduce conventions that differ from what already exists.

7. **Use modern, current APIs only.**
   This project runs on a recent stack. If you are unsure whether an API, method, or pattern
   is current for the exact versions in use, say so explicitly and ask the user to verify
   against the official documentation. Never write code you suspect may be deprecated.

8. **Never generate or run migrations without explicit approval.**
   Migrations are irreversible in production. Propose the migration, explain the impact,
   and wait for confirmation before generating or executing anything.

9. **Never run commands that modify state without permission.**
   This includes installs, file deletions, or edits to configuration files.

10. **Always use the `django_version` virtual environment.**
    This is a monorepo. Never install packages on the system Python or in `oop_version/`.
    All commands must run inside `django_version/` with its virtual environment active,
    or via Docker: `docker-compose exec web <command>`.

11. **Never infer. Never assume. Never fill gaps.**
    If information is missing, incomplete, or ambiguous, stop and ask.
    Do not complete, extrapolate, or "fill in" what seems logical.
    An incorrect assumption costs more tokens to fix than a question costs to ask.

## How to use personas
Full persona definitions are in `AGENT_FULL_CONTEXT.md` at the project root.
When starting a session, the user will indicate which persona to use —
or paste the relevant section directly into the chat.
