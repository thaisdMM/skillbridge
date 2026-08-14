# Handoff: Phase 10 remediation planning

**Written**: 2026-08-06, at the end of the session that verified the Phase 10 audit.
**For**: the next session, which plans how to fix the seven confirmed Issues.
**Recommended persona**: Planner (`django_version/PLANNER.md`).

This file carries what is **not** recoverable from `tasks.md`, the audit, or the
code alone. Read it first, then work from the two audit documents as the
authority on the findings.

---

## 1. The chain that led here

| Document | What it is |
|---|---|
| `docs/skill-admin-findings-2026-08-04.md` | Original findings (F-1…F-8). Triggered the FR-002 amendment |
| `docs/audits/2026-08-06-audit-phase-10-fr-002.md` | Auditor's report on the Phase 10 implementation. 7 Issues, 1 Open Decision, 10 Observations |
| `docs/audits/2026-08-06-verification-of-audit-phase-10-fr-002.md` | **Verifier-equivalent.** Executed the mutations the Auditor only reasoned about |

The Planner's pipeline is `Auditor → Verifier → Planner → Developer`. The
verification document occupies the Verifier position. **Do not re-verify the
findings** — that work is done and measured.

---

## 2. Where the feature stands

**Test baseline: 268 passing** (`docker-compose exec web pytest` from
`django_version/`). Every plan must leave all 268 green; the count only grows.

| Task | Implemented? | Checkbox in `tasks.md` |
|---|---|---|
| T073–T077, T079 | **Yes**, committed (`ff732d9`, `7a9ecd9`) | **`- [ ]` — wrong** |
| T078, T080 | No — genuinely open | `- [ ]` — correct |

⚠️ **`tasks.md:620-646` shows every Phase 10 task unchecked.** Six of them are
done. T065, T066 and T067 are all amended to run *"after Phase 10"*, so as the
artifact reads today a future session cannot tell the phase is finished. Fixing
the checkbox state is itself a task for this plan.

**Note on O-1 in the audit**: it reports `1 failed, 33 passed`. That is **stale**
— the current result is `34 passed`. The Auditor's own `--create-db` run
rebuilt the test database and fixed the schema it diagnosed. Do not chase it.

---

## 3. ⚠️ Tooling: which commands are safe on an in-progress spec

This matters more than usual, because `tasks.md` carries hand-written amendment
history (T083, T084, the "Amended 2026-08-05" notes, the whole Phase 10 block)
that **no template can regenerate**.

**Safe:**

| Command | Why |
|---|---|
| `/speckit-analyze` | Explicitly read-only. Never writes |
| `/speckit-converge` | Contract is **"APPEND-ONLY, NEVER REWRITE"** (`SKILL.md:78-84`). Only appends a new `## Phase N: Convergence` section |
| `/speckit-checklist` | Writes a separate checklist file, does not touch spec artifacts |

**Destructive here — do NOT run:**

| Command | What it would do |
|---|---|
| `/speckit-tasks` | *"Generate tasks.md"* from the template — **erases the amendment history** |
| `/speckit-plan` | Regenerates `plan.md` and the design artifacts |
| `/speckit-specify` | Regenerates `spec.md`, including the amended FR-002 |

**The correction to a common assumption:** it is not that skills *cannot* edit
spec artifacts. They can, and three of them rewrite artifacts wholesale. The
danger is the opposite of "not allowed" — it is "allowed, and too broad".

**Caveat on `/speckit-converge`**: it derives unbuilt work from **spec
requirements**. The audit findings are test-coverage gaps that the spec does not
state as requirements, so converge will most likely **not** surface them. Adding
the remediation tasks to `tasks.md` should therefore be a **manual append by
Claude Code**, following the existing Phase 10 formatting by hand.

---

## 4. What the Planner must decide — one loop per finding

Per `PLANNER.md`, one finding, one decision, one task entry. Never bundle.

### Genuinely open — the user must choose

**Issue 1 — the two lowercasing layers disagree.** `clean()` lowercases in
CPython, the constraint lowercases in PostgreSQL. Measured: `lower('İ')` is `'i'`
in PostgreSQL and `'i̇'` (two characters) in Python. On that input the
field-level `skill_name_duplicate` is never raised; the error lands under
`__all__`. Data integrity never fails — only the message placement.
*Investigated already in the previous session, so the Planner does not need to
re-derive it:* `upper()` would diverge **more** (PostgreSQL and Python disagree
on `ß` and on `Straße`), and `casefold()` has no PostgreSQL equivalent, so it
would widen the gap. The known paths are (a) evaluate both sides in the database
via `Lower(Value(...))`, (b) a non-deterministic ICU collation, (c) accept and
document. Options must still be presented properly by the Planner.

**Issue 4 — the two `__repr__` tests.** Either assert the rendered form
literally, or collapse the pair into one test and drop the docstring claim. The
sibling `test_freelancer_profile_repr_representation` inherits whichever is
chosen. `CLAUDE.md` Rule 5 applies.

**OD-1 — the private-helper query-count test.** Three options in the audit
(keep private call / route through `get_deleted_objects()` / drop it). New
measurement available: `get_deleted_objects()` is **4 queries flat** at
selections of 1, 3, 5 and 10, **both with and without referring profiles** —
which closes the caveat the audit attached to option B.

### Mechanically clear — still need a task entry, but little to decide

- **Issue 2** — one model-path test: rename a saved skill onto another saved
  skill's name. Overlaps T078's scope; the audit suggests planning them together.
- **Issue 3** — mirror of the existing F-4 test, using
  `client_profile.interests` instead of `freelancer_profile.skills`.
- **Issue 6** — a field-metadata introspection test for `unique=True` (needs no
  database, per `testing.md`).
- **Issue 7** — the `test_base.py:33-51` boundary pair transposed to `name` at
  100 and 101 characters.
- **Issue 5** — qualify the `conventions.md` clause to the branch that issues
  the query.
- **Phase 10 checkbox state** — §2 above.

---

## 5. Files the planning session should attach

- `docs/audits/2026-08-06-audit-phase-10-fr-002.md` — the findings
- `docs/audits/2026-08-06-verification-of-audit-phase-10-fr-002.md` — the evidence
- `django_version/profiles/models/skill.py` — Issues 1, 6, 7
- `django_version/profiles/tests/models/test_skill.py` — Issues 2, 4, 6, 7
- `django_version/profiles/admin.py` + `tests/admin/test_skill_admin.py` — Issue 3, OD-1
- `django_version/profiles/tests/conftest.py` — fixtures for Issues 2 and 3
- `django_version/profiles/tests/models/test_base.py` — the `bio` pair Issue 7 copies
- `specs/001-profiles-admin-panel/tasks.md` — Phase 10 block, T078/T080
- `docs/adr/case-insensitive-skill-name-uniqueness.md` — Issue 1's *Consequences*
- `.claude/rules/conventions.md` — Issue 5
- this file

---

## 6. Constraints carried forward

- **Do not reopen** the settled decisions: case-insensitive uniqueness,
  unnormalized storage, the `skill_name_duplicate` code, the
  `clean()`-plus-`UniqueConstraint` mechanism, `unique=True` staying on the
  field, distinct-profile counting. Issue 1 is a coherence defect *inside* that
  mechanism, not an argument against it.
- **`CLAUDE.md` Rule 10** — Issue 1's option (a) changes only a queryset
  expression and generates **no** migration. Option (b) would. Confirm before
  any `makemigrations`.
- **ADRs stay under ~60 lines** and carry no task or requirement IDs
  (`conventions.md`, *Recording decisions*).
- Issue 1, if accepted, is recorded in the **existing** ADR's *Consequences* —
  not as a new ADR.

---

## 7. Suggested order of execution

1. **Issue 5 + the Phase 10 checkboxes** — documentation only, zero risk,
   unblocks T065/T066/T067 reasoning immediately.
2. **Issues 2, 3, 6, 7** — the four missing tests. Independent of each other,
   all measured, each has a sibling in the codebase to copy the shape from.
3. **Issue 4 and OD-1** — decided together; both are "change an existing test",
   both touch judgement rather than correctness.
4. **Issue 1** — last. It is the only one that changes production behaviour and
   the only one needing an ADR amendment.
5. **T078 and T080** — the genuinely unbuilt Phase 10 tasks. Plan T078 alongside
   Issue 2, per the audit's Handoff.

---

## 8. What this session did NOT do

No remediation was written, no task executed, no production or test file
changed. Repository state at the time of writing: one modified file
(`django_version/profiles/tests/models/test_skill.py`, pre-existing) plus the
two audit documents and this handoff, all untracked.
