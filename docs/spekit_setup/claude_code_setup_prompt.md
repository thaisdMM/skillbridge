# Claude Code — Setup task: Root context (`CLAUDE.md`) + Spec Kit `constitution`

**Nature of this task:** project scaffolding only. You are setting up the
project context and the Spec Kit constitution. You are **not** implementing any
feature, spec, or code change. Do not start any task from the roadmap.

Work **command by command, with an approval gate at every STOP**. Do not chain
steps. After each STOP, wait for the user's explicit approval before continuing.

---

## Non-negotiable behavior for this session

1. **Never infer, never assume, never fill gaps.** If a path, a file, or an
   instruction is missing or ambiguous, stop and ask one focused question. A
   wrong assumption here corrupts the whole setup.
2. **Do not modify source code.** This session touches only: a new root
   `CLAUDE.md`, and the Spec Kit constitution at `.specify/memory/constitution.md`.
   Nothing else is edited without explicit approval.
3. **Flag, do not absorb.** If you notice a problem outside this task's scope,
   report it to the user and suggest a separate session. Do not fix it here.
4. **English only** for all file content you produce.
5. **Ground everything in the real repo.** Read the actual files before stating
   anything about structure. Do not rely on prior knowledge of Spec Kit's
   default layout — confirm against what is installed here.

---

## Locked decisions (already made with the user — do not re-litigate)

- **Engine:** GitHub Spec Kit, used command by command. No automatic
  `/speckit.implement`. The user decides case by case what she implements by
  hand vs. delegates.
- **Constitution scope:** the `constitution.md` holds **only non-negotiable
  principles**, plus one meta-rule stating that operational context and detailed
  conventions live in the context files (not duplicated in the constitution).
- **Root `CLAUDE.md`:** thin. Operational context + a pointer that tells the
  agent to also load and obey `django_version/CLAUDE.md` and the other context
  docs. It must **not** duplicate the detailed rules already written there, and
  it must **not** contain anything about the user personally (learning style,
  background). That is out of scope.
- **Out of scope for this session (do not touch, do not bundle):** rewriting or
  retiring `.claude/rules/sdd-workflow.md`; migrating `ARCHITECTURE.md` into
  ADRs; reorganizing `docs/`; the "brainstorm" step; and any feature/roadmap
  task.

---

## STEP 0 — Discovery (read only; produce a map; then STOP)

Do not write any file in this step. Confirm the real state of the repo and
report it back for approval.

1. List the repository tree from the monorepo root (top two levels, plus the
   contents of `docs/`, `.claude/`, and `.specify/`).
2. Confirm the exact location and existence of each of these, and report which
   were found and which were not:
   - `django_version/CLAUDE.md`
   - `ARCHITECTURE.md`
   - `.claude/rules/conventions.md`
   - `.claude/rules/testing.md`
   - `.claude/rules/sdd-workflow.md`
   - the persona files (`AUDITOR.md`, `VERIFIER.md`, `PLANNER.md`,
     `DEVELOPER.md`) — report their real path
   - `docs/` — list what is actually inside it (the user expects ~2 ADRs and a
     roadmap; confirm the real filenames)
   - `.specify/memory/constitution.md` and the constitution template
3. Determine **which of these files Claude Code auto-loads** in this project
   (e.g. `CLAUDE.md` files up the tree, `.claude/rules/*`). State how you
   determined it. This decides what the root `CLAUDE.md` still needs to point to
   vs. what is already loaded automatically. Do not guess — if you cannot
   determine it reliably, say so and ask.
4. Open the installed Spec Kit constitution command/skill file (under `.claude/`
   or `.specify/`) and report: how the command is invoked in *this* installation,
   and where it writes its output. Do not assume the invocation form.
5. **Known landmine — flag, do not fix:** `django_version/CLAUDE.md` references
   `AGENT_FULL_CONTEXT.md`, which no longer exists (the personas were split into
   individual files). Confirm whether that dead reference is still present and
   report it as a separate issue for a later session.

**STOP.** Present the map and wait for approval before Step 1.

---

## STEP 1 — Propose the principle vs. context split (read only; then STOP)

Read `django_version/CLAUDE.md`, `ARCHITECTURE.md`, `.claude/rules/conventions.md`,
and the persona files. Read `.claude/rules/testing.md` **only if** the split
turns out to touch testing rules.

Produce two lists, drawn **strictly from what those files already say** — do not
invent principles, do not import anything from your own training defaults:

- **Candidate principles → constitution** (non-negotiable governance rules).
  Examples of the *kind* of thing that qualifies, if and only if the docs
  already state them: "never infer / always ask", "approval gate per step; who
  implements code is decided case by case", "GDPR-first", "domain invariants
  live in the model layer", "modern/current APIs only", "simplicity / no
  over-engineering". For each candidate, cite the file and section it came from.
- **Operational context → root `CLAUDE.md`** (facts, not principles): monorepo;
  work only in `django_version/`; `oop_version/` is closed; commands run via
  `docker-compose exec web`; the venv at `django_version/.venv/` is IDE-only and
  independent of Docker; spec artifacts live at the monorepo root in `specs/`;
  the docs map.

If any item is genuinely ambiguous as to which side it belongs on, list it
separately as an open question rather than placing it.

**STOP.** The user approves, moves, or cuts items before anything is written.

---

## STEP 2 — Draft the root `CLAUDE.md` (write one file; then STOP)

Write a **thin** root `CLAUDE.md` containing only:

- The operational context approved in Step 1.
- A clear instruction that the agent must also load and obey
  `django_version/CLAUDE.md` and `ARCHITECTURE.md` (and any other context file
  that Step 0 showed is **not** already auto-loaded). Do not restate the detailed
  rules — point to them. `django_version/CLAUDE.md` remains the single source of
  truth for detailed behavior rules.
- Nothing about the user personally.

Keep it short. If Step 0 showed that some target is already auto-loaded, do not
add a redundant pointer to it — say so instead.

**STOP.** The user reviews and approves the file before Step 3.

---

## STEP 3 — Constitution (prepare input; run the command; then STOP)

1. Using the approved principle list from Step 1, prepare the natural-language
   input for the Spec Kit constitution command. Include the **meta-rule**:
   operational context and detailed conventions live in `CLAUDE.md` /
   `conventions.md` / `ARCHITECTURE.md`; the constitution does not duplicate them.
2. Show the user the exact input text and the exact command invocation (as
   confirmed in Step 0) **before running anything**.
3. On approval, run the command so it fills the template at
   `.specify/memory/constitution.md`.
4. Show the generated constitution. The user reads and iterates. Re-run with
   adjustments as needed until she approves.

**STOP.** End of setup. Do not proceed to any spec, feature, or roadmap task.

---

## What "done" looks like

- A thin root `CLAUDE.md` exists, pointing to the detailed docs, with no
  personal content and no duplicated rules.
- `.specify/memory/constitution.md` holds only principles + the meta-rule.
- The `AGENT_FULL_CONTEXT.md` dead reference has been reported (not fixed).
- No source code changed. No feature started.
