# STEP 0 — Discovery Report

Read-only discovery for `claude_code_setup_prompt.md`. No files were modified
during this step. Saved as a scratch file per explicit user request; the
setup prompt itself specifies this step's output is reported in chat only.

---

## 1. Repository tree (top two levels, plus docs/, .claude/, .specify/)

```
.
├── .claude/
│   ├── rules/
│   │   ├── conventions.md
│   │   ├── sdd-workflow.md      ← filename has a TRAILING SPACE, see §2
│   │   └── testing.md
│   ├── settings.local.json
│   └── skills/                  (speckit-* skill dirs, one SKILL.md each)
├── .specify/
│   ├── init-options.json
│   ├── integration.json
│   ├── integrations/
│   ├── memory/
│   │   └── constitution.md      ← still raw template, see §2
│   ├── scripts/bash/
│   ├── templates/
│   └── workflows/
├── .vscode/
├── ARCHITECTURE.md               ← at repo ROOT, not inside django_version/
├── README.md
├── claude_code_setup_prompt.md
├── docs/
│   ├── ROADMAP_SKILLBRIDGE.md    ← the real roadmap
│   ├── ROADMAP_STACK_TRIAGE.md   ← triage of stacks to refactor into the roadmap (separate purpose, not a duplicate)
│   ├── SYSTEM_OVERVIEW.md
│   ├── tech_debt.md
│   ├── adr/
│   │   ├── model-clean-assumes-converted-field-types.md
│   │   └── no-check-constraint-for-positive-amount-invariants.md
│   └── plan/                     ← exists, empty
├── django_version/                (active project — CLAUDE.md, models, tests, Docker)
│   ├── AUDITOR.md / DEVELOPER.md / PLANNER.md / TEACHER.md / VERIFIER.md
│   └── CLAUDE.md
└── oop_version/                   (closed, per root-level CLAUDE.md instructions still to be written)
```

No root-level `CLAUDE.md` currently exists.

---

## 2. Existence / location check

| Target | Found? | Location | Note |
|---|---|---|---|
| `django_version/CLAUDE.md` | Yes | `django_version/CLAUDE.md` | |
| `ARCHITECTURE.md` | Yes | repo root `./ARCHITECTURE.md` | **Not** inside `django_version/` |
| `.claude/rules/conventions.md` | Yes | as expected | |
| `.claude/rules/testing.md` | Yes | as expected | |
| `.claude/rules/sdd-workflow.md` | Yes, but... | `.claude/rules/` | Actual filename on disk is `sdd-workflow.md ` — **trailing space**. Confirmed with `ls -la` and a `os.listdir()` repr. Out of scope to fix per your instructions (flagging only). |
| `AUDITOR.md`, `VERIFIER.md`, `PLANNER.md`, `DEVELOPER.md` | Yes | all directly under `django_version/` (flat, not nested) | `django_version/TEACHER.md` also exists — a 5th persona file not mentioned in the setup prompt's list. |
| `docs/` contents | Matches, with clarification | see tree above | 2 ADRs in `docs/adr/` as expected. Two roadmap-named files exist but serve distinct purposes: `ROADMAP_SKILLBRIDGE.md` is the real roadmap, `ROADMAP_STACK_TRIAGE.md` is the stack-refactor triage feeding into it — not a duplicate. `SYSTEM_OVERVIEW.md` and `tech_debt.md` also present, plus an empty `docs/plan/` directory. |
| `.specify/memory/constitution.md` | Yes | as expected | Still the **raw, unfilled template** — every `[PLACEHOLDER]` token is untouched. Confirms the constitution command has never been run in this repo. |
| Constitution template | Yes | `.specify/templates/constitution-template.md` | |

---

## 3. What Claude Code auto-loads (this session)

Determined **empirically from this session's actual system-reminder
behavior**, not from reading harness source code (I don't have access to
that) — flagging this distinction per Rule 2.

Observed:
- `.claude/rules/conventions.md` and `.claude/rules/testing.md` content was
  injected into context automatically at session start, labeled *"project
  instructions, checked into the codebase"* — before I made any Read tool
  call for either file. **Auto-loaded.**
- `django_version/CLAUDE.md` content was likewise injected automatically via
  a system-reminder, without an explicit Read tool call from me, immediately
  after the user's message referenced `django_version/AUDITOR.md`. This is
  consistent with Claude Code loading nested `CLAUDE.md` files relevant to
  paths being worked with, in addition to any root-level one. **Auto-loaded**
  (in this session), triggered by the reference to a file inside
  `django_version/`.
- No root `CLAUDE.md` exists, so nothing loaded from repo root.
- `ARCHITECTURE.md`, `docs/*`, and `django_version/VERIFIER.md` /
  `PLANNER.md` / `DEVELOPER.md` / `TEACHER.md` were **not** auto-loaded this
  session. `AUDITOR.md` only entered context because I issued an explicit
  Read tool call after your `@`-mention — that is a manual read, not an
  auto-load.

**Caveat:** I cannot state with full certainty the exact rule the harness
uses to decide which nested `CLAUDE.md` files qualify (e.g., "any directory
containing a file explicitly referenced in the conversation" vs. some other
heuristic) — this is inferred from one session's observed behavior, not
from documentation I can point to. If this distinction matters for how the
root `CLAUDE.md` is worded in STEP 2, say so and I'll ask rather than guess
further.

**Practical implication for STEP 2:** `.claude/rules/conventions.md` and
`.claude/rules/testing.md` are already auto-loaded and do not need a pointer
from the root `CLAUDE.md`. `django_version/CLAUDE.md` appears to auto-load
too when files under `django_version/` are touched, but a root `CLAUDE.md`
should not rely on that being guaranteed in every future session/scenario —
this is exactly the kind of judgment call the prompt says to surface, not
resolve, at this stage.

---

## 4. Spec Kit constitution command — invocation and output

File: `.claude/skills/speckit-constitution/SKILL.md`

- **Installation type:** Claude Code Skill (not a slash-command markdown
  file under `.claude/commands/`). Frontmatter: `name: "speckit-constitution"`,
  `user-invocable: true`.
- **Invocation in this installation:** typed as `/speckit-constitution
  <principles or values text>` by the user, which Claude Code resolves to
  the `Skill` tool with `skill: "speckit-constitution"` and `args:
  <the text>`. (Per this session's own tool-list guidance: *"When the user
  types `/<skill-name>`, invoke it via Skill."*)
- **Output location:** confirmed in the SKILL.md body — step 1 loads
  `.specify/memory/constitution.md`; step 7 says *"Write the completed
  constitution back to `.specify/memory/constitution.md` (overwrite)."* If
  that file were missing, it would first be copied from
  `.specify/templates/constitution-template.md` — not needed here since the
  file already exists (as the raw template).
- **Extension hooks:** the skill checks for `.specify/extensions.yml`
  before and after running. Confirmed **that file does not exist** in this
  repo, so no pre/post hooks will fire.
- **Side detail:** the skill also reads and cross-checks
  `.specify/templates/plan-template.md`, `spec-template.md`,
  `tasks-template.md`, and other installed `speckit-*` command files for
  outdated references as part of its own consistency-propagation step —
  this happens automatically when the command runs, not something we need
  to do manually in STEP 3.

---

## 5. Known landmine — `AGENT_FULL_CONTEXT.md` dead reference

**Correction to the setup prompt's stated premise:** the prompt says
*"`django_version/CLAUDE.md` references `AGENT_FULL_CONTEXT.md`, which no
longer exists."* I grepped `django_version/CLAUDE.md` directly — **zero
matches**. That file does not currently contain this reference.

The actual dead reference lives elsewhere:

- **`.claude/rules/conventions.md:519`**:
  > "For historical context on why a decision was made, consult
  > `ARCHITECTURE.md`. For testing strategy, consult `testing.md`. For
  > behavior rules and persona definitions, consult `CLAUDE.md` and
  > `AGENT_FULL_CONTEXT.md` respectively."

  `AGENT_FULL_CONTEXT.md` does not exist anywhere in the repo (confirmed via
  repo-wide grep — the only other hits are inside `claude_code_setup_prompt.md`
  itself, describing this same landmine).

**Flagging, not fixing**, per the setup prompt's own instruction. Reported
for a later session — the real target for the fix is
`.claude/rules/conventions.md:519`, not `django_version/CLAUDE.md`.

---

## End of STEP 0

Per the setup prompt: **STOP here.** Waiting for your approval (or
corrections) before proposing the principle-vs-context split in STEP 1.
