# STEP 1 — Principle vs. Context Split

Read-only analysis for `claude_code_setup_prompt.md`, STEP 1. No source files
were modified. This document is the proposed split between:

- **Candidate principles** → `.specify/memory/constitution.md` (non-negotiable
  governance rules), and
- **Operational context** → the future thin root `CLAUDE.md` (facts, not
  principles).

Every candidate is drawn **strictly from what the source files already say** —
nothing is invented or imported from training defaults. Each item cites the
file and section it came from. Items whose side is genuinely ambiguous are
listed separately as **Open Questions**, not silently placed.

Files read for this step: `django_version/CLAUDE.md`, `ARCHITECTURE.md`,
`.claude/rules/conventions.md`, and the five persona files
(`AUDITOR.md`, `VERIFIER.md`, `PLANNER.md`, `DEVELOPER.md`, `TEACHER.md`).
`.claude/rules/testing.md` was **not** used — the split does not touch testing
rules, so per STEP 1 it was left out.

---

## A. Candidate principles → constitution

Non-negotiable governance rules. Ordered strongest/most-cited first.

### P1 — Never infer, never assume, never fill gaps; ask one focused question
When information is missing, incomplete, or ambiguous, stop and ask rather than
extrapolate.
- **Source:** `django_version/CLAUDE.md` Rule 1 ("Absolute rules"). Repeated
  verbatim as Rule 1 in **every** persona: `AUDITOR.md`, `VERIFIER.md`,
  `PLANNER.md`, `DEVELOPER.md`, `TEACHER.md`.

### P2 — Ask before choosing between valid options; the user decides
When more than one valid path exists and the conventions do not pick one, present
options with trade-offs and let the user choose. One focused question at a time.
- **Source:** `django_version/CLAUDE.md` Rule 5 and the "Rule 1 vs Rule 5 —
  clarification" section; `DEVELOPER.md` Rule 2; `PLANNER.md` Rule 2 and its
  whole mandate.

### P3 — Always read the real files; never act from training-data patterns
Read the full file and the inheritance chain before answering or changing
anything. SkillBridge's custom patterns diverge from Django defaults, so
"the usual pattern" is not evidence.
- **Source:** `django_version/CLAUDE.md` Rule 2; `AUDITOR.md` Rule 2;
  `VERIFIER.md` Rule 2 + "Anti-training, anti-memory"; `DEVELOPER.md` Rule 3;
  `TEACHER.md` Rule 4; `PLANNER.md` Rule 3 + "Anti-training, anti-memory".

### P4 — Explain before writing; explicit human approval gate before code, migrations, and state-changing commands
Present the approach first; wait for explicit approval before generating code.
Never generate/run a migration or any state-changing command without permission.
- **Source:** `django_version/CLAUDE.md` Rules 3, 10, 11. (`conventions.md`
  "Stack and versions" adds that version changes are architectural decisions
  requiring explicit approval — same approval-gate principle.)

### P5 — Never modify anything beyond the exact scope of the task
Out-of-scope changes require explaining why and asking permission first.
- **Source:** `django_version/CLAUDE.md` Rule 4; `DEVELOPER.md` "Scope of the
  task".

### P6 — Use modern, current APIs only; verify against the pinned-version docs
If unsure whether an API is current for the pinned versions, say so and verify —
never write code suspected to be deprecated.
- **Source:** `django_version/CLAUDE.md` Rule 9. (This is the setup prompt's
  "modern/current APIs only" example, and the docs state it.)

### P7 — GDPR-first: no PII in output, ever (non-negotiable)
No emails, names, passwords, or any user identifier other than `user.id` in
logs, `__str__`/`__repr__`, error messages, or admin display.
- **Source:** `conventions.md` "GDPR logging policy" (states verbatim: "No PII
  appears in log output, ever. This is non-negotiable."); `ARCHITECTURE.md`
  "GDPR-Aligned Logging from Day One".

### P8 — Domain invariants live in the model layer; every validation rule belongs to exactly one layer
Invariants that must hold regardless of data source are enforced in the model's
`clean()`; each rule has a single owning layer (model / validator / serializer /
form). A logically unreachable validation is worse than none.
- **Source:** `conventions.md` "Model invariants — enforced via clean()",
  "Layer ownership", and "Field-to-validation contract".

### P9 — English only
All code, identifiers, comments, docstrings, commit messages, and produced
content in English.
- **Source:** `django_version/CLAUDE.md` Rule 6; the "Language" section of every
  persona file.

### P10 — During SDD implementation, the approved spec/plan/tasks are authoritative; a code/doc mismatch is stopped and reported, never silently resolved
When following Spec-Driven Development (spec.md → plan.md → tasks.md), the
approved spec artifacts lead the implementation. If the AI detects the code
diverging from them, it stops and notifies the user immediately rather than
silently picking a side (neither "the doc must be right" nor "the code must be
right").
- **Source:** user decision, 2026-07-26 session, resolving open Q6 below.
  Distinct from the AUDITOR/VERIFIER authority inversion (see Q6 note) — this
  principle governs SDD execution of new work, not the audit of existing code.

### "Deactivate, never delete"
`is_active=False` is the only supported lifecycle transition for user
accounts; `on_delete=models.PROTECT` (never `CASCADE`) enforces this at the
database level; deletion is disabled in Django Admin.
- **Source:** `ARCHITECTURE.md` "Principles Applied Throughout" (states it as
  a named principle in the summary table); `conventions.md` on_delete policy
  section. **Status: approved for constitution (user decision, Q1).**

---

## B. Operational context → root `CLAUDE.md`

Facts about the environment, not governance principles.

### C1 — Monorepo layout; active project is `django_version/` only
`oop_version/` (closed) and `django_version/` (active). All work targets
`django_version/` exclusively; never run project commands in `oop_version/`.
- **Source:** `django_version/CLAUDE.md` "Project context" + Rule 12;
  `ARCHITECTURE.md` "Monorepo Structure: `oop_version` → `django_version`".

### C2 — All project commands run via Docker
`docker-compose exec web <command>` (e.g. `pytest`, `makemigrations`, `shell`).
Never install packages on system Python.
- **Source:** `django_version/CLAUDE.md` Rule 12; `conventions.md` "Docker
  workflow".

### C3 — The host venv is IDE-only
`django_version/.venv/` is independent of Docker; keeping it active is a
recommended editor convenience, not a runtime.
- **Source:** `django_version/CLAUDE.md` Rule 12.

### C4 — Spec artifacts live at the monorepo root in `specs/`
They describe domain features independently of implementation; any command a
spec triggers still runs inside Docker.
- **Source:** `django_version/CLAUDE.md` Rule 12 ("Note on specs").

### C5 — The stack (facts, versions pinned elsewhere)
Python 3.14, Django 6.0.x, PostgreSQL 17, psycopg3, Argon2id, pytest-django,
DRF, drf-spectacular, Docker, GitHub Actions.
- **Source:** `django_version/CLAUDE.md` "Project context"; `conventions.md`
  "Stack and versions" (the authoritative pinned table — root `CLAUDE.md` should
  point, not duplicate).

### C6 — The docs map (where authority lives)
- `ARCHITECTURE.md` (repo root) — architectural decisions and their reasoning.
- `.claude/rules/conventions.md` + `.claude/rules/testing.md` — operational and
  testing conventions (**auto-loaded** per STEP 0; no pointer needed).
- `django_version/CLAUDE.md` — the single source of truth for detailed behavior
  rules.
- Persona files under `django_version/` (`AUDITOR`, `VERIFIER`, `PLANNER`,
  `DEVELOPER`, `TEACHER`).
- `docs/` — `ROADMAP_SKILLBRIDGE.md`, `ROADMAP_STACK_TRIAGE.md`,
  `SYSTEM_OVERVIEW.md`, `tech_debt.md`, `adr/`.
- **Source:** STEP 0 discovery (`docs/CLAUDE_SETUP_STEP0_DISCOVERY.md`) + the
  files themselves.

### C7 — Pointer facts for STEP 2 (consequence of STEP 0 auto-load findings)
`conventions.md` and `testing.md` are already auto-loaded → root `CLAUDE.md`
must **not** add a redundant pointer to them. `ARCHITECTURE.md` and
`django_version/CLAUDE.md` are the targets a thin root `CLAUDE.md` should tell
the agent to load and obey.
- **Source:** `docs/CLAUDE_SETUP_STEP0_DISCOVERY.md` §3.

---

## C. Open Questions — RESOLVED (user decisions, 2026-07-26)

### Q1 — "Deactivate, never delete" → **RESOLVED: constitution.**
Added above as its own principle entry.

### Q2 — "Simplicity / no over-engineering" → **RESOLVED: left out.**
Not stated as a declared principle anywhere in the source docs (only applied),
so per STEP 1's own "do not invent principles" instruction, it stays out.

### Q3 — Evidence discipline → **RESOLVED: stays persona-scoped.**
Not added as a universal constitution principle. Remains local to
`VERIFIER.md` / `PLANNER.md`.

### Q4 — CLAUDE.md R7 (no inline comments) / R8 (follow existing patterns) → **RESOLVED: confirmed, stay in conventions.**

### Q5 — "Who implements — by hand vs. delegate, case by case" → **RESOLVED: skip.**
Verified against the installed Spec Kit skills (`speckit-tasks/SKILL.md`,
`speckit-implement/SKILL.md`, `speckit-converge/SKILL.md`): no skill
auto-chains into `/speckit-implement` — `speckit-converge` only *recommends*
running it next (`speckit-converge/SKILL.md:236,238`) and `speckit-implement`
itself has its own internal STOP gate before proceeding
(`speckit-implement/SKILL.md:84-91`). Implementation only ever starts from an
explicit `/speckit-implement` invocation. Given that structural guarantee, and
that it would be redundant with P4 (approval gate before any code), this stays
out of the constitution as a standalone principle.

### Q6 — Authority hierarchy is NOT universal → still a caution, not resolved by removal
`AUDITOR.md` treats docs as authority over code; `VERIFIER.md` deliberately
**inverts** this (code/official docs over project docs) for auditing
*existing* code. This stays out of the constitution as a single principle —
confirmed, not reversed. **Distinct from P10 above**, which the user added on
top: P10 governs a different moment (SDD execution of *new* work from an
approved spec), not the audit of existing code. Both can coexist without
contradiction.

**Follow-up suggested by the user, not part of this session's scope:** audit
`ARCHITECTURE.md` / `conventions.md` themselves against the real
`django_version/` code, using the Auditor persona with those docs as the
primary target, to confirm they are not already stale before P10 treats
spec/plan/tasks as authoritative in future SDD work. Recommended as the next
session after this setup finishes.

---

## D. Constitution template structure — cross-checked against the installed template and skill

Read `.specify/templates/constitution-template.md` and the full
`speckit-constitution/SKILL.md` to verify the A-list principles actually map
onto the template's real structure, not just onto the source docs.

- **`### Core Principles` count is flexible.** `SKILL.md:68`: *"The user might
  require less or more principles than the ones used in the template... If a
  number is specified, respect that."* All approved principles (P1–P10 +
  "Deactivate, never delete") become individual numbered Core Principle
  entries — nothing needs to be trimmed to the template's example count of 5.
- **`[SECTION_2_NAME]` / `[SECTION_3_NAME]` are a scope risk, not a home for
  anything on this list.** These are generic, project-defined placeholders
  ("Additional Constraints" / "Development Workflow" in the template's own
  comments). The skill's derivation logic explicitly says it will *"infer from
  existing repo context (README, docs...)"* when a value isn't supplied
  (`SKILL.md:72`) — left unconstrained, it could auto-populate these sections
  from `ARCHITECTURE.md`/`conventions.md`, which would violate the setup
  prompt's locked decision that the constitution holds "only non-negotiable
  principles, plus one meta-rule." **Action for STEP 3:** the prepared input
  must explicitly instruct the skill to leave Sections 2/3 unused, with the
  one-line justification the skill itself allows for intentionally-undefined
  slots (`SKILL.md:81`).
- **The meta-rule's structural home is `## Governance`, not a principle.** The
  template's own comment example for that section reads: *"Use
  [GUIDANCE_FILE] for runtime development guidance"*
  (`constitution-template.md:47`) — this is structurally exactly the STEP 3
  meta-rule (operational context and detailed conventions live in
  `CLAUDE.md`/`conventions.md`/`ARCHITECTURE.md`, not duplicated in the
  constitution). **Action for STEP 3:** phrase the meta-rule as Governance
  content, not folded into a Core Principle.

This does not change the A/B split above — it only sharpens how STEP 3 will
phrase the input so the constitution-generation skill doesn't scope-creep
beyond the locked decision.

---

## STOP

Per the setup prompt: STEP 1 is read-only and ends here. All open questions are
resolved (Q1–Q6 above) and the template-structure cross-check is done. Awaiting
final approval of the full split (Sections A, B, D) before STEP 2 (the thin
root `CLAUDE.md`) is written.
