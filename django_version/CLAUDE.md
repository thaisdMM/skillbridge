# SkillBridge — Behavior Rules

## Project context

Python 3.14, Django 6.x, PostgreSQL 17, Docker, GitHub Actions CI/CD,
DRF, drf-spectacular, pytest-django, Argon2id, psycopg3.
Monorepo: `oop_version/` (closed) and `django_version/` (active).
All work targets `django_version/` exclusively.

## Absolute rules — apply to every persona, every session

1. **Never infer. Never assume. Never fill gaps.**
   If information is missing, incomplete, or ambiguous, stop and ask one
   focused question. Do not complete, extrapolate, or "fill in" what seems
   logical from context. This rule covers **missing or unclear information**:
   you do not have what you need to proceed.
   An incorrect assumption costs more tokens to fix than a question costs to ask.

2. **Always read the relevant files. Never pattern-match from training data.**
   When answering any question about the codebase or making any change to it,
   read every file that is relevant to the answer — not just the snippet
   pasted in chat. SkillBridge uses custom patterns (ABC over MTI, custom
   user model, custom validators, custom managers) that frequently differ
   from Django defaults seen in training data. Defaulting to the "usual"
   pattern is a violation of this rule.
   - **Read the full file, not just the visible snippet.** If the user
     shares a fragment, a class, or a method, open the complete file before
     responding. Inheritance and imports usually carry information that is
     not visible in the snippet.
   - **Read across the inheritance chain.** When a concrete model is the
     subject of the question, also read its abstract base and any validators
     or managers it uses. A question about `FreelancerProfile` may require
     reading `Profile`, `Freelancer`, and `BaseUser` before a correct answer
     is possible.

   Reading a file costs less than rewriting a wrong answer. If a tool call
   to read a file would resolve uncertainty, make the tool call — do not infer.

3. **Explain before you write.**
   Present your proposed approach in bullet points. Wait for explicit approval
   before generating any code.

4. **Never modify anything beyond the exact scope of the task.**
   If a change outside scope is needed, explain why and ask for permission
   before touching anything.

5. **Ask before choosing between valid options.**
   When a task requires choosing between patterns, libraries, or approaches
   that are not explicitly defined in the conventions, stop and ask. This
   rule covers **decisions between valid alternatives**: you have the
   information, but more than one path is reasonable and the user must
   decide. One focused question at a time.

6. **English only.**
   All code, variable names, comments, docstrings, and commit messages must
   be in English.

7. **No inline comments unless strictly necessary.**
   What needs to be said belongs in the docstring. Only add an inline comment
   when the code cannot be understood without one — and even then, question
   whether the code should be rewritten to be self-explanatory first.

8. **Follow existing patterns.**
   Before writing anything new, read the relevant existing file to understand
   the established pattern. Do not introduce conventions that differ from
   what already exists.

9. **Use modern, current APIs only.**
   This project runs on a recent stack. If you are unsure whether an API,
   method, or pattern is current for the exact versions in use, say so
   explicitly and ask the user to verify against the official documentation.
   Never write code you suspect may be deprecated.

10. **Never generate or run migrations without explicit approval.**
    Migrations are irreversible in production. Propose the migration, explain
    the impact, and wait for confirmation before generating or executing
    anything.

11. **Never run commands that modify state without permission.**
    This includes installs, file deletions, or edits to configuration files.

12. **All project commands run via Docker.**
    This is a monorepo. The active project lives in `django_version/`
    and all execution happens inside Docker:
    `docker-compose exec web <command>`.

    Examples:
    - `docker-compose exec web pytest`
    - `docker-compose exec web python manage.py makemigrations`
    - `docker-compose exec web python manage.py shell`

    The host venv at `django_version/.venv/` is independent of Docker.
    Keeping it activated during development is recommended
    for editor experience.

    Never install packages on the system Python. Never run project
    commands in `oop_version/` — that version is closed.

    Note on specs: spec artifacts live at the monorepo root in `specs/`,
    not inside `django_version/`, because they describe domain features
    independently of the implementation. Any command triggered by a spec
    (running tests, migrations, code) still executes inside Docker.
    with the venv active and via Docker.

## Rule 1 vs Rule 5 — clarification

These rules look similar but cover different situations:

- **Rule 1** applies when you **lack information**: a field is undefined,
  a path is unclear, a requirement is ambiguous. You cannot proceed because
  you do not know what is true.

- **Rule 5** applies when you **have the information but face a choice**:
  two valid patterns exist, two libraries could solve the problem, two
  layers could own a rule. You can proceed, but the user must choose
  which direction.

When in doubt, treat the situation as Rule 1 and ask.

## How to use personas

Full persona definitions are in `AGENT_FULL_CONTEXT.md` at the project root.
When starting a session, the user will indicate which persona to use —
or paste the relevant section directly into the chat.
