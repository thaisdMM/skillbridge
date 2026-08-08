# Analysis — execution of the Phase 10 remediation plan

**Date**: 2026-08-08
**Persona**: read-only analysis. No project file was modified; this file is the
only artifact created.
**Plan under analysis**:
`specs/001-profiles-admin-panel/plan_phase-10-remediation_2026-08-06.md`
— eleven tasks and one decision record.
**Commits under analysis**: `abae1d1`, `e722e0e`, `028b83d`, `da1b87e`,
`3973612`, `f6dae41`, `c873d4e`, `61e63c0`, `1850962`, `5fb95a7`.

**Files read in full**

- `django_version/profiles/models/skill.py`
- `django_version/profiles/tests/models/test_skill.py`
- `django_version/profiles/tests/admin/test_skill_admin.py`
- `django_version/profiles/admin.py` (the aggregate and the refusal message)
- `django_version/profiles/tests/conftest.py` (the `skill`, `freelancer_profile`
  and `client_profile` fixtures)
- `docs/adr/skill-name-comparison-is-evaluated-in-the-database.md`
- `docs/adr/case-insensitive-skill-name-uniqueness.md`
- `.claude/rules/conventions.md` — the `skill_name_duplicate` entry
- `specs/001-profiles-admin-panel/tasks.md` — Phase 10, and T065/T066/T067
- `specs/001-profiles-admin-panel/quickstart.md` — section A
- `specs/001-profiles-admin-panel/spec.md` — FR-002/FR-003/FR-005 and the User
  Story 1 scenarios
- `specs/001-profiles-admin-panel/contracts/admin-surface.md` §1 and §4

**Not executed here**: the suite, `makemigrations --check --dry-run`, and the
quickstart walk. Two of the three are already accounted for below.

> **Correction, 2026-08-08.** The *Next steps* section of the first version of
> this file put T065, T066 and T067 immediately after Phase 10. **That was
> wrong.** Those three are Phase 9 gates, and *Dependencies & Execution Order*
> puts Phases 6, 7 and 8 between Phase 10 and Phase 9 — Phase 9 "depends on
> every story that is being shipped". Phase 10's amendments say the gates must
> run *no earlier* than Phase 10; they do not say Phase 10 is the last thing
> before them. The section below is rewritten. Findings G-1 and G-2 were also
> revised on the same day, for the reasons recorded against each.

---

## Verdict

**All eleven tasks landed, and the decision record was honoured.** Every
acceptance criterion in the plan is met, with one deliberate divergence
(D-1 below) that the human confirmed on 2026-08-08 and which stands.

`Skill.clean()`, `test_skill.py` and `test_skill_admin.py` are correct as they
stand. No defect was found in any of the three. Two gaps remain that **no task
in the plan covered** — they are not violations of it, they are work the plan
never reached (G-1 and G-2 below).

---

## Task-by-task conformance

| Task | Acceptance criteria | Carried by | Verdict |
|---|---|---|---|
| 1 — literal `__repr__` on both `Skill` tests | Both literals as prescribed; only `{reloaded_skill.id}` interpolated; docstrings unchanged; the marker on the reload test only | `abae1d1` | **Met** |
| 2 — qualify the marker rule in `conventions.md` | Clause replaced verbatim with the plan's text; the empty, whitespace-only and `None` branches named marker-free; no transient reference | `e722e0e` | **Met** |
| 3 — record Phase 10 in flight | Status block added at the head of the *Implementation* section; no checkbox touched; five added lines and nothing else | `028b83d` | **Met**, and reversed by Task 11 as designed |
| 4 — cover the edit path on the model | Test renames a saved skill onto a second saved skill's name; `name` key then code; `@pytest.mark.django_db` | `da1b87e`, reshaped by `3973612` | **Met, with D-1** |
| 5 — evaluate both sides in the database | `Lower(models.Value(self.name))`; no Python-side `.lower()` left in `clean()`; new ADR in MADR short form recording the `__iexact` rejection; sibling ADR's `Status` corrected and cross-linked | `c873d4e` | **Met** |
| 6 — `.distinct()` on the `ClientProfile` aggregate | Three selected skills on one client profile, one protected entry carrying `1`; marker present; mirrors the freelancer sibling's assertion shape | `f6dae41` | **Met** |
| 7 — the `max_length` boundary pair | 100 passes with no assertion body; 101 asserts `name` then `max_length`; **both** carry the marker | `3973612` | **Met** |
| 8 — guard `unique=True` | `Skill._meta.get_field("name").unique is True`; **no** marker | `3973612` | **Met** |
| OD-1 — the query-count test | Untouched: still calls `_count_referring_profiles` directly, still budgets two queries | — | **Honoured** |
| 9 — admin-path coverage (T078 + one) | Six tests; every failing case asserts the `name` key before any code; case 4 compares the **set**; case 2 re-reads the stored name; case 5 asserts validity; all six marked; T078's text amended by hand with a dated note | `61e63c0` | **Met** |
| 10 — the quickstart rows (T080 + one) | A10, A11, A12 appended after A9 in the four-column format; A10/A11 carry the references T080 words; A12 marked as the edit path; no existing row reworded | `1850962` | **Met** |
| 11 — close Phase 10 | T073–T080 all `- [X]`; the in-flight block gone; no task text reworded, renumbered or removed | `5fb95a7` | **Met** |

The plan's ordering constraint was respected: Task 1 first, Task 5 after the
test surface around it was complete, Task 9 after Task 5, Task 11 last. Neither
`/speckit-tasks`, `/speckit-plan` nor `/speckit-specify` was run on the feature —
the hand-written amendment history in `tasks.md` is intact, and the two new
blockquote notes follow the shape the file already used for T083 and T084.

---

## The three files the question named

### `profiles/models/skill.py` — `clean()`

Correct. The method reads in the order FR-003 then FR-002, which is what
`spec.md`'s *Skills* edge case prescribes: strip, refuse empty, then compare.

- Both sides of the comparison are now evaluated by PostgreSQL —
  `Lower("name")` against `Lower(models.Value(self.name))`. No Python-side
  `.lower()` remains, which is the whole of the Task 5 fix, and the reasoning
  is recorded in its own ADR rather than in the docstring, per *Code standards*.
- `models.Value(...)` was used instead of a new import, as the plan specified;
  the file's existing `models.`-prefixed idiom is unbroken.
- `.exclude(pk=self.pk)` is a no-op on an unsaved instance and does real work on
  a saved one — the self-conflict clause of FR-002 and the FR-005 recasing
  permission both depend on it, and both are now covered by tests.
- The `None` guard and the empty-after-strip branch both return or raise before
  the query, which is exactly the condition the amended `conventions.md` clause
  now states.
- The `clean()` shape matches the required pattern: `super().clean()` first,
  `logger.error` with no value logged, `gettext_lazy`, the dict form keyed on
  `name`, and a unique code.

The whitespace strip mutating `self.name` inside `clean()` sits against the
*Field-to-validation contract*'s "normalization belongs to the serializer or
form" rule. It is **not** raised here as a finding: the plan lists the strip
under Task 5's *OUT OF SCOPE* as correct and closed, FR-003 makes it a model
invariant by requirement, and the ADR contracts it.

### `profiles/tests/models/test_skill.py`

Correct. 22 test cases across 19 functions. The FR-002/FR-003 surface is now
covered on every branch:

| Rule | Covered by |
|---|---|
| Trim before comparing | `..._strips_whitespace`, `..._strips_the_name_before_comparing_it_with_existing_skills` |
| Empty after strip | `..._empty_name_raises_validation_error` (parametrized `""` / `"   "`), marker-free |
| `None` name | `..._none_name_passes_validation`, marker-free |
| Duplicate — add path, exact | `test_skill_name_uniqueness` |
| Duplicate — add path, case variant | `..._name_differing_only_in_case_...` |
| Duplicate — **edit path, foreign row** | `..._renaming_a_saved_skill_to_a_name_another_saved_skill_carries_...` |
| Self-conflict — unchanged name | `..._whose_name_did_not_change_passes_validation` |
| Self-conflict — recased in place (FR-005) | `..._recased_in_place_is_stored_with_the_new_capitalization` |
| The database case mapping | `..._compares_the_name_using_the_database_case_mapping` (`I` vs `İ`) |
| `max_length` | the 100 / 101 pair, both marked |
| `unique=True` on the field | `..._name_field_declares_unique`, unmarked |
| Database backstop | the two `IntegrityError` tests |

Marker placement is right throughout, and it is the part most likely to be got
wrong: the two `clean()`-only tests that never reach the query stay marker-free,
and both `max_length` tests carry the marker because `full_clean()` accumulates
errors rather than short-circuiting, so the lookup runs even on the failing one.

### `profiles/tests/admin/test_skill_admin.py`

Correct. The six new form tests drive the real `ModelForm` through
`get_form(...)` and read codes from `form.errors.as_data()`, matching the
established shape in `accounts/tests/admin/`. The change-form case builds
`get_form(admin_request, obj=renamed_skill)(data, instance=renamed_skill)`,
which is the only construction that puts a primary key in front of
`_post_clean()` — the path FR-002 exists to guard. The whitespace case compares
the **set** `{required, skill_name_empty}` rather than indexing, so Django's
internal error ordering is not encoded as if it were the contract. No test
asserts that the admin trims a name, per Task 9's explicit prohibition.

---

## Findings

| ID | Category | Severity | Location | Summary | Recommendation |
|---|---|---|---|---|---|
| D-1 | Plan/code drift | LOW | `test_skill.py:136-159`; plan Task 4 | The Task 4 test was shipped parametrized over `Python` / `python` / `PYTHON` and renamed to `..._to_a_name_another_saved_skill_carries_...`. The plan prescribed **one** test with a single case variant, and its *WHY THIS PATH* argued specifically against the exact repeat. **Confirmed by the human on 2026-08-08 as a deliberate decision, and it stands** — three inputs, one assertion, one behaviour, which is what `testing.md` reserves `parametrize` for. The plan's *DECIDED APPROACH*, *ACCEPTANCE CRITERIA* and *TEST PLAN* for Task 4 are now stale against the tree. | Add a dated amendment note to Task 4 of the plan file, in the shape the `tasks.md` notes use, recording the widening and why. The test itself needs no change. |
| G-1 | ~~Coverage gap — conventions~~ | **WITHDRAWN** | — | Filed as MEDIUM on the grounds that the new ADR's forward constraint (*"any future code comparing skill names must lower **in the database**"*) reached no auto-loaded file. **The grounds were wrong**: the constraint is guarded by an executing test, not by prose. `test_skill_clean_compares_the_name_using_the_database_case_mapping` goes red the moment a Python-side `.lower()` returns to `clean()`. For code that does not live in `clean()`, the sibling ADR already carries the governing rule — every writer of `Skill.name` must call `full_clean()` and must not normalize — so no future serializer should be reimplementing the comparison at all. | None. Resolved in the opposite direction on 2026-08-08: the ADR bullet was deleted as a false *Bad*, and the ADR pointers were removed from `conventions.md` rather than added to. See *Changes made after this analysis was written*. |
| G-2 | Coverage gap — tests | LOW | `test_skill_admin.py` | FR-005 says an administrator must be able to edit a skill's name. The change form has **refusal** coverage only; nothing drives an accepted edit through it. Originally filed as a missing `spec.md` scenario; the test gap is the substantive half. **Revised 2026-08-08**: a model-path test (`Python` → `Django`) was written and then removed as tautological — no mutation of `clean()` turns it red, because a free name is outside the duplicate lookup's reach, and the existing recase test detects strictly more. Any replacement must put the submitted name **inside** the lookup's reach. | Optional, one test: recase a saved skill through the change form (`get_form(request, obj=skill)` with `instance=skill`, submitting `python` against a stored `Python`) and assert the form is valid. It goes red if `.exclude(pk=self.pk)` is dropped, and it is the acceptance pair to the existing change-form refusal test. A `spec.md` scenario for renaming onto another record remains optional and independent. |

No CRITICAL and no HIGH finding. No constitution conflict was found within the
scope of this analysis. (`T086` records a known Principle X contradiction, but
it is Phase 5.1 work and outside Phase 10.)

---

## Changes made after this analysis was written

All on 2026-08-08, by the human, after the findings above were discussed:

- `docs/adr/skill-name-comparison-is-evaluated-in-the-database.md` — the final
  *Bad* bullet was deleted. It restated a cost already carried by the bullet
  above it, and it recorded as a drawback an obligation that **predates** this
  decision and that this decision discharged. The file is back to 60 lines.
- `.claude/rules/conventions.md` — the `skill_name_duplicate` entry was
  tightened from 16 lines to 13: the sentence explaining why the constraint
  cannot report against `name` (Django's routing mechanics, not a project
  convention) and the ADR pointer were both removed.
- `.claude/rules/conventions.md` — the last ADR-specific pointer, on the
  `SkillAdmin` bullet under *Admin conventions*, was removed too. **Standing
  rule from this session: the auto-loaded rule files name the `docs/adr/`
  directory, never an individual ADR.** A pointer to one file creates an
  implicit hierarchy — "these decisions matter, the rest do not" — that gets
  more wrong with every ADR written, and the path rots on rename.
- `.claude/rules/conventions.md`, *When in doubt* — the specific pointers were
  replaced by a general discipline: check `docs/adr/` before changing anything
  listed under *Established invariants* or *Admin conventions*.

---

## Metrics

- Plan tasks: **11** — 11 delivered, coverage **100%**.
- Decision records: **1** (OD-1) — honoured, no file changed.
- `tasks.md` Phase 10 tasks: **8** (T073–T080) — all `- [X]`.
- Quickstart section A rows: **12** (A1–A12), three added by Task 10.
- Findings: **3** raised — 0 critical, 0 high, 0 medium standing, 2 low, 1
  withdrawn on re-examination.
- Divergences from the plan text: **1**, sanctioned.
- Suite: **282 passing**, as measured at the close of Phase 10 on 2026-08-07.
  Not re-run in this session — that measurement is T065's job.
- `makemigrations --check --dry-run`: **no changes**, run by the human on
  2026-08-08. This is the substance of T066 and confirms Task 5's acceptance
  criterion that the fix generated no migration.

---

## Next steps, in order

Phase 10 closed. The execution order in `tasks.md` is
**Phase 5.1 → Phase 10 → Phase 6 → Phase 7 → Phase 8 → Phase 9**, so the work
that follows is the three unbuilt story phases, and the final gates come last.

1. **Phase 6 — User Story 4** (T040–T044). Verification of the combined account
   screen, which both inlines already support. T040 is the SC-009 gate on
   `accounts/tests/admin/test_admin.py`; T041 still owes the client-side half of
   the field-level error rule; T044 walks quickstart section E.
2. **Phase 7 — User Story 5** (T045–T052). Unbuilt: `accounts/admin.py` carries
   no `HasProfileFilter`, no `ProfilePresenceMixin` and no `profile_badge`, and
   `accounts/tests/admin/test_account_list_profile.py` does not exist.
3. **Phase 8 — User Story 6** (T053–T059). Unbuilt, and it shares both
   `list_filter` tuples with Phase 7 — deliver alongside it. T053 is a
   verification gate that must run **before** the attribute is written.
4. **T086 — the Principle X gap in the constitution.** Phase 5.1, still open,
   and the one repair that must not be applied unilaterally: explicit human
   approval plus a version bump, routed through `/speckit-constitution`.
5. **Phase 9 — Polish** (T060–T067), last. T060–T064 are documentation and
   review; **T065, T066 and T067 are the whole-system gates and must see the
   finished state.** Running any of them now measures a codebase that is still
   three phases from done, and they would have to run again.
6. **D-1**, the plan amendment for Task 4. Bookkeeping, any time.
7. **G-2**, the change-form acceptance test. Optional, any time.

Items 6 and 7 change no behaviour. On the gates: `makemigrations --check
--dry-run` was run clean on 2026-08-08 and section A of the quickstart was
walked, but neither closes its task — both are final-state gates.
