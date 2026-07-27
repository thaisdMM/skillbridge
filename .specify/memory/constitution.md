<!--
SYNC IMPACT REPORT — 2026-07-27

Version change: (unfilled template) → 1.0.0
Bump rationale: first ratification. No prior version existed; the file was
byte-identical to .specify/templates/constitution-template.md.

Principles added (12, none modified or removed — nothing pre-existed):
  I.    Never Infer, Never Assume, Never Fill Gaps (NON-NEGOTIABLE)
  II.   Ask Before Choosing Between Valid Options
  III.  Ground Every Decision in the Real Files
  IV.   Explain First; Human Approval Gate Before Code (NON-NEGOTIABLE)
  V.    Strict Scope Discipline
  VI.   Modern, Current APIs Only
  VII.  GDPR First — No PII in Logs or Error Output (NON-NEGOTIABLE)
  VIII. One Layer Owns Each Rule; Invariants Live in the Model
  IX.   No Code Without Tests (NON-NEGOTIABLE)
  X.    Deactivate, Never Delete
  XI.   English Only
  XII.  Approved Spec Artifacts Lead Implementation

Sections added: Core Principles, Governance.
Sections removed: the template's two generic slots (SECTION_2_NAME and
SECTION_3_NAME) were deleted rather than retained. Justification: this constitution
holds
non-negotiable principles plus governance only; additional constraints and
development-workflow detail are owned by conventions.md, testing.md, and
ARCHITECTURE.md per the Governance meta-rule, and are not duplicated here.

Consistency propagation — run in READ-ONLY mode by explicit instruction. No file
other than this one was modified.
  ✅ .specify/templates/plan-template.md — no change needed. Its "Constitution
     Check" section (line 39) holds a placeholder reading "Gates determined based
     on constitution file" (line 43), which speckit-plan fills per feature at plan
     time from this file (speckit-plan/SKILL.md:62,66). The template is designed
     to stay generic; editing it would break that mechanism.
  ✅ .specify/templates/spec-template.md — no change needed. Contains no
     reference to the constitution or to any principle.
  ⚠ .specify/templates/tasks-template.md — PENDING, single line to review.
     Line 182 reads "Tests (if included) MUST be written and FAIL before
     implementation". Principle IX requires tests for every change but
     deliberately does NOT mandate test-first ordering — the human explicitly
     deferred adopting TDD as a rule (decision 2026-07-27). The line is
     conditional and is the template's own generic guidance, not a restatement of
     a principle, so it does not contradict Principle IX. Flagged only so the
     ordering claim is a conscious choice when TDD is revisited.
  ✅ installed speckit-* skills under .claude/skills/ — no outdated or
     agent-specific hardcoded references found.
  ✅ README.md — no reference to the constitution or to any principle.

Follow-up TODOs: none. No placeholder was deferred; no bracket token remains.
-->

# SkillBridge Constitution

## Core Principles

### I. Never Infer, Never Assume, Never Fill Gaps (NON-NEGOTIABLE)

When information is missing, incomplete, or ambiguous, work MUST stop and one
focused question MUST be asked. Nothing may be completed, extrapolated, or
"filled in" from surrounding context.

Rationale: an incorrect assumption costs more to undo than a question costs to
ask.

### II. Ask Before Choosing Between Valid Options

When more than one valid path exists and the project conventions do not select
one, the options and their trade-offs MUST be presented and the human decides.
One focused question at a time. A preference MAY be stated; the decision is never
taken unilaterally.

This differs from Principle I: here the information is present, but the direction
is the human's to choose.

### III. Ground Every Decision in the Real Files

Every answer and every change MUST be based on the actual files read in the
current context — the full file, and the full inheritance chain, not the pasted
snippet. Training-data patterns and memory of earlier conversations are never
evidence.

Rationale: this codebase deliberately diverges from Django defaults (abstract base
classes over multi-table inheritance, a custom user model and manager, custom
validators, `on_delete=PROTECT`), so "the usual pattern" is predictably wrong
here.

### IV. Explain First; Human Approval Gate Before Code (NON-NEGOTIABLE)

The proposed approach MUST be presented and explicitly approved before any code is
generated. Migrations MUST never be generated or run without explicit approval.
Commands that modify state — installs, deletions, configuration edits — MUST never
be run without permission. Dependency version changes are architectural decisions
and require the same approval.

### V. Strict Scope Discipline

Nothing outside the exact scope of the agreed task may be modified. A needed
out-of-scope change MUST be explained and approved before anything is touched.
Problems noticed outside scope are reported, not absorbed into the current work.

### VI. Modern, Current APIs Only

Only APIs current for the exact pinned versions of the stack may be used. If it is
unclear whether an API or pattern is current, that MUST be stated and verified
against the official documentation for the pinned version. Code suspected of being
deprecated MUST never be written.

### VII. GDPR First — No PII in Logs or Error Output (NON-NEGOTIABLE)

No email, name, password, or any user identifier other than the internal id may
appear in log output, in model string representations (`__str__` / `__repr__`), or
in error messages. When a fact about an input must be recorded, a derived
non-sensitive property is logged instead of the value — length or presence, never
the value itself. When in doubt, a field is treated as PII.

This rule governs logs, string representations, and error output. It does not
restrict the Django admin, which is access-controlled to authenticated staff and
legitimately displays name and email, because account administration is impossible
without them.

Rationale: the platform targets the European market; this was a constraint from the
first logging decision, not a retrofit.

### VIII. One Layer Owns Each Rule; Invariants Live in the Model

Every validation rule has exactly one owning layer, and that layer MUST be named
before the rule is written. Invariants that must hold regardless of where the data
came from belong in the model's `clean()`. Format and content rules belong in
reusable validators. Cross-field rules, many-to-many constraints, workflow-step
rules, and input normalization belong in the serializer or form.

A validation whose condition can never be true is worse than no validation and
MUST NOT be written.

### IX. No Code Without Tests (NON-NEGOTIABLE)

Every change to production code ships with the tests that cover it. A change is not
complete until its tests exist and the suite passes. Tests MUST follow
`.claude/rules/testing.md`, which remains authoritative for structure, fixtures,
database-access markers, and assertion style — this constitution does not restate
it. A test that would still pass if the behavior it claims to verify were deleted
is not a test and MUST be rewritten or removed.

Rationale: human decision, recorded 2026-07-27 — the project's standing rule is
that all code is tested and that tests obey `testing.md`.

### X. Deactivate, Never Delete

Setting `is_active=False` is the only supported lifecycle transition for accounts
and profiles. `on_delete=PROTECT` is used on every `ForeignKey` and
`OneToOneField`; `CASCADE` is rejected. Deletion is disabled in the admin.
Introducing physical deletion requires revisiting this policy explicitly and
documenting it before any model change.

### XI. English Only

All code, identifiers, comments, docstrings, commit messages, documents, and
generated content are written in English.

### XII. Approved Spec Artifacts Lead Implementation

During Spec-Driven Development, the approved `spec.md`, `plan.md`, and `tasks.md`
are authoritative for the work being implemented. If the code is found to diverge
from them, work MUST stop and the divergence MUST be reported — neither the
document nor the code may be silently assumed correct.

This governs execution of new work from an approved spec; it does not override the
evidence rules that apply when auditing existing code.

## Governance

**Meta-rule.** This constitution holds non-negotiable principles only. Operational
context and detailed conventions are NOT duplicated here and live in their own
files, which remain authoritative for their own domain:

- `CLAUDE.md` at the repository root — environment and operational context.
- `django_version/CLAUDE.md` — the single source of truth for detailed behavior
  rules.
- `.claude/rules/conventions.md` — operational conventions, including the pinned
  version table.
- `.claude/rules/testing.md` — testing conventions.
- `ARCHITECTURE.md` — architectural decisions and their reasoning.

Where a detail is needed at runtime, these files are consulted; this constitution
is not extended to restate them. If a convention file ever contradicts this
constitution, the conflict MUST be raised with the human and resolved explicitly —
never silently.

**Amendment procedure.** Amendments require explicit human approval, are recorded
in the Sync Impact Report at the top of this file, and carry a version bump.

**Versioning policy.** Semantic versioning applies: MAJOR for a principle removal
or incompatible redefinition, MINOR for a new or materially expanded principle,
PATCH for clarification and wording.

**Compliance review.** Every plan and every review verifies compliance with these
principles. Any deviation MUST be justified in writing and approved before it is
implemented.

**Version**: 1.0.0 | **Ratified**: 2026-07-27 | **Last Amended**: 2026-07-27
