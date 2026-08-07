# Plan — Phase 10 remediation: the FR-002 audit findings, the open decision, and the two unbuilt tasks

**Date**: 2026-08-06
**Persona**: Planner (`django_version/PLANNER.md`). No production or test file was
modified while writing this plan.

This plan acts on `docs/audits/2026-08-06-audit-phase-10-fr-002.md` — seven
Issues, one Open Decision, ten Observations — as confirmed by
`docs/audits/2026-08-06-verification-of-audit-phase-10-fr-002.md`, which executed
the mutations the audit only reasoned about and found **all seven Issues real**.
The findings are not re-verified here. Entry conditions and the constraints
carried forward are in
`specs/001-profiles-admin-panel/handoff-phase-10-remediation.md`.

**Baseline correction.** The handoff records a 268-passing baseline. Measured on
2026-08-06 at the start of this planning session, the working tree is **267
passing, 1 failing** —
`profiles/tests/models/test_skill.py::test_skill_repr_representation`, from an
in-progress edit. Task 1 restores it. Every later task is written against 268
green.

Tasks appear in the order they were decided.

---

## TASK 1 — Assert the literal `__repr__` rendering on both `Skill` tests

**ORIGIN** — Issue 4 of the audit. Verification §2: CONFIRMED, with the audit's
rationale narrowed — the tests do pin the surrounding `__repr__` template; what
is unasserted is specifically the `category` rendering.

**PROBLEM** — Two `__repr__` tests exist solely because their docstrings claim a
distinction: the unsaved instance renders `category` as the `TextChoices` enum,
the reloaded one as a plain string. Both built their expectation by interpolating
the value under test (`{skill.category!r}`), so the claimed difference was
asserted nowhere. A partial in-progress edit hard-coded the `category` segment on
both, but left the `name` segment interpolated and dropped the `f` prefix on the
first test, which is why it currently fails.

**DECIDED APPROACH** — Both tests assert the rendered string literally. Only the
database-assigned `id` on the reloaded test stays interpolated, since a primary
key is not knowable in the source. Test layer only.

**WHY THIS PATH** — The distinction is real and measured (verification §2:
`Skill.Category.TECHNOLOGY` on the unsaved instance, `'TECHNOLOGY'` after
reload), and `testing.md` requires a test docstring to describe what is verified.
Asserting the literal makes the claim true rather than deleting it.
*(`TextChoices` members are `str` subclasses, so the two forms compare equal
under `==` and differ only under `repr()` — which is exactly why interpolating
the value hid the difference.)*

**ALTERNATIVES CONSIDERED**

- Collapse the pair into one test and drop the docstring claim, keeping the
  derived-expectation shape the sibling file uses — set aside: it stops asserting
  a real, measured round-trip difference instead of closing the gap.

**SCOPE** — `django_version/profiles/tests/models/test_skill.py`, the two
functions at lines 20-36. No other file.

**ACCEPTANCE CRITERIA**

- `test_skill_repr_representation` compares `repr(skill)` against a plain
  (non-`f`) string literal:
  `"Skill (id=None, name='Python', category=Skill.Category.TECHNOLOGY)"`.
- `test_skill_repr_representation_after_reload` compares against an f-string
  whose only interpolation is `{reloaded_skill.id}`; `name='Python'` and
  `category='TECHNOLOGY'` are literal.
- Both docstrings stay exactly as written — they now describe what is asserted.
- `docker-compose exec web pytest` from `django_version/` reports 268 passing.

**TEST PLAN** — No new test. `@pytest.mark.django_db` stays on the reload test,
which saves and queries, and stays off the unsaved test, which never touches the
database.

**OUT OF SCOPE** — Every other test in the file. `Skill.__repr__` itself, which
is correct. `test_freelancer_profile_repr_representation`
(`test_freelancer_profile.py:91-99`): it shares the derived-expectation shape but
the audit explicitly cleared it — its docstring claims nothing its assertion
misses — and converting it would make only `hourly_rate=50.00` literal, since
both ids are database-assigned. Decided 2026-08-06 to leave it untouched.

**OPEN QUESTIONS** — None.

---

## TASK 2 — Qualify the `Skill` marker rule in `conventions.md` to the branch that queries

**ORIGIN** — Issue 5 of the audit. Verification §2: CONFIRMED textually.

**PROBLEM** — The `skill_name_duplicate` entry under *Established invariants*
ends with *"this `clean()` issues a queryset lookup, so a test calling
`Skill.clean()` or `Skill.full_clean()` needs `@pytest.mark.django_db`."*
"Calling `clean()`" is the wrong condition: of the method's three exits only one
queries. The empty-after-strip branch raises before the lookup
(`skill.py:124-133`) and a `None` name never enters the block
(`skill.py:121`). As written, the clause instructs a future session to add
markers to two tests that must stay marker-free.

**DECIDED APPROACH** — Rewrite the clause to state the positive condition and
name the exempt branches explicitly. Documentation layer only.

Replacement text:

```
  → the duplicate lookup is a queryset query, so a test that reaches it —
    one whose `name` is still non-empty after the strip — needs
    `@pytest.mark.django_db`. A name that is empty, whitespace-only, or
    `None` raises or returns before the query and must stay marker-free.
```

**WHY THIS PATH** — `conventions.md` is auto-loaded into every session, so a
wrong instruction there propagates silently. The failure mode is concrete:
`test_skill_clean_empty_name_raises_validation_error` (`test_skill.py:54`) and
`test_skill_clean_none_name_passes_validation` (`test_skill.py:64`) pass today
with no marker, which under pytest-django's default database blocker is itself
proof they never reach a query. Marking them would contradict `testing.md`'s own
*Common mistakes to avoid* table. Naming the exemption rather than implying it
closes the exact hole that was found. *(pytest-django blocks database access in
unmarked tests by design, so an unmarked test that quietly starts querying fails
loudly instead of passing slowly — the exemption is a guard, not an
optimization.)*

**ALTERNATIVES CONSIDERED**

- State the positive condition only, terser, matching the neighbouring entries —
  set aside: it leaves the exemption to be inferred, and inference is what
  produced the defect.
- Leave the clause and correct the rule in `testing.md` instead — set aside:
  both files are auto-loaded, so the wrong instruction would still be in context.

**SCOPE** — `.claude/rules/conventions.md`, the `skill_name_duplicate` entry
under *Established invariants*. No other file, and no other entry in that list.

**ACCEPTANCE CRITERIA**

- The clause states the condition as reaching the duplicate lookup, not as
  calling `clean()`.
- The empty, whitespace-only and `None` branches are named as marker-free.
- The wording carries no requirement, task, finding, or roadmap reference, per
  the same file's *Recording decisions* rule.
- The two marker-free tests are unchanged and still pass.

**TEST PLAN** — No test changes. This task alters documentation only; the suite
must stay at its current count.

**OUT OF SCOPE** — Every other entry in *Established invariants*. `testing.md`.
Adding or removing a marker on any test.

**OPEN QUESTIONS** — None.

---

## TASK 3 — Record Phase 10's in-flight state at the head of the block in `tasks.md`

**ORIGIN** — The verification document §5, *corrected*. That section reports every
Phase 10 checkbox as still `- [ ]` and reads it as an oversight the audit missed.
It is not: the Developer session that built T073–T077 and T079 deliberately
deferred all eight ticks until the phase closes — *"Mark as [X] in
`specs/001-profiles-admin-panel/tasks.md`, once the audit findings are resolved:
T073, T074, T075, T076, T077, T078, T079, T080."* The repository state and the
session that produced it override the document.

**PROBLEM** — The deferral is sound, but while the phase is in flight the
artifact is opaque: a session opening `tasks.md` sees eight unticked boxes and no
way to tell that six are built. T065, T066 and T067 are each amended to run
*"after Phase 10"*, so the two live risks are re-implementing finished work and
leaving the three gates parked.

**Repository state, measured 2026-08-06**

| Task | State | Carried by |
|---|---|---|
| T073, T074, T075 | done, committed | `ff732d9` — `migrations/0007_…`, `models/skill.py` |
| T076, T079 | done, committed | `7a9ecd9` — `admin.py`, `tests/admin/test_skill_admin.py` |
| T077 | done, **uncommitted** | working-tree change to `tests/models/test_skill.py` |
| T078, T080 | genuinely open | — |

Migration `0007_skill_skill_unique_name_case_insensitive` is confirmed applied in
development (`showmigrations profiles` → `[X]`). T077 was written but never
committed: the Developer session stopped when the file went red, which is the
same red state Task 1 clears.

**DECIDED APPROACH** — Leave every checkbox untouched, honouring the deferral
policy. Add one status block at the head of the Phase 10 *Implementation*
section recording what is built, what is open, and that the ticks come in one
pass at the close. Documentation layer only.

```
> **Status 2026-08-06 — phase in flight.** T073–T077 and T079 are
> implemented; T077 is written but not yet committed. **T078 and T080 remain
> open**, and the audit remediation is in progress. Every box below is ticked
> in one pass once the phase closes.
```

**WHY THIS PATH** — It keeps the deferral rule the previous session set and
closes the legibility hole the verification correctly identified, even though it
misattributed the cause. The status block is removed by the same change that
finally ticks the boxes, so nothing accumulates in the artifact. It also corrects
a framing error worth recording: ticking these boxes would **not** unblock
T065/T066/T067 — those gates run after Phase 10, and Phase 10 still contains T078
and T080. *(A spec artifact like `tasks.md` is a channel between sessions, not a
build system — nothing reads the checkbox. Its only job is to stop the next
reader guessing.)*

**ALTERNATIVES CONSIDERED**

- Drop the task entirely and let the closing tick cover it — set aside: it leaves
  the artifact opaque for the whole remediation, which is exactly the window in
  which another session is most likely to read it.
- Tick T073–T077 and T079 immediately — set aside: it overrides the deferral
  policy and splits the phase's bookkeeping across two commits.

**SCOPE** — `specs/001-profiles-admin-panel/tasks.md`, the head of the Phase 10
*Implementation* section only. No checkbox is changed. No task text is reworded,
renumbered, or removed.

**ACCEPTANCE CRITERIA**

- The status block sits at the head of the Phase 10 *Implementation* section.
- It names T073–T077 and T079 as implemented, flags T077 as uncommitted, and
  names T078 and T080 as open.
- All eight checkboxes still read `- [ ]`.
- The hand-written amendment history the file carries is byte-identical
  elsewhere.
- The full suite is unaffected.

**TEST PLAN** — No test changes.

**OUT OF SCOPE** — T065, T066 and T067 themselves; their amendments are correct
and stay as written. Every phase other than Phase 10. **Do not run
`/speckit-tasks`, `/speckit-plan` or `/speckit-specify`** — each regenerates its
artifact from a template and would erase the hand-written amendment history
(handoff §3). This edit is made by hand.

**OPEN QUESTIONS** — None.

---

## TASK 4 — Cover the edit path of the duplicate rule on the model

**ORIGIN** — Issue 2 of the audit. Verification §2: CONFIRMED by executed
mutation.

**PROBLEM** — `Skill.clean()`'s duplicate lookup does two jobs: refuse a *new*
name that collides, and refuse a *rename* that collides with a different saved
row. Only the first is tested. Every test expecting `skill_name_duplicate` builds
an unsaved instance, so changing the guard to
`if duplicate_exists and self.pk is None:` leaves all 268 tests green
(verification §2). Production behaviour on the edit path is confirmed correct —
renaming a saved `ZzzBeta` onto an existing `ZzzAlpha` yields
`{'name': ['skill_name_duplicate']}` — so this is a coverage gap, not a defect.

**DECIDED APPROACH** — One model-path test in
`django_version/profiles/tests/models/test_skill.py`, placed beside the two
self-exclusion tests it complements (`:97-115`): create two skills, mutate the
second's `name` onto the first's in a different case, call `full_clean()`, assert
the `name` key is in `error_dict`, then assert the code.

**WHY THIS PATH** — The edit path is the only one where `.exclude(pk=self.pk)`
does real work against a *foreign* row, and it is where the self-exclusion and
the duplicate rule interact. *(On an unsaved instance `.exclude(pk=self.pk)` is
`.exclude(pk=None)`, which Django rewrites to `pk__isnull=True` and which
excludes nothing — so on the creation path the exclusion is a no-op, which is why
the existing tests cannot reach this branch.)* Using a name that differs in case
rather than an exact repeat exercises the case-insensitive comparison and the
foreign-row exclusion in the same call, which is one behaviour under
`testing.md`'s granularity rule.

**ALTERNATIVES CONSIDERED**

- Reach the edit path only through T078's admin tests — set aside: the gap is on
  the model path, where the sibling tests already live, and T078 is a separate
  task that can slip.

**SCOPE** — `django_version/profiles/tests/models/test_skill.py`. One new test
function. No production file.

**ACCEPTANCE CRITERIA**

- A test renames a saved skill onto a second saved skill's name, differing in
  case, and asserts the `name` key then `skill_name_duplicate`.
- It carries `@pytest.mark.django_db` — it saves rows and `clean()` queries.
- Applying the mutation `if duplicate_exists and self.pk is None:` makes this
  test, and only this test, fail.
- Suite green at 269.

**TEST PLAN** — One test, code `skill_name_duplicate`, key `name`, two-step
assertion per `testing.md`, `@pytest.mark.django_db`.

**OUT OF SCOPE** — The two self-exclusion tests, which are correct and stay as
they are (audit O-2 confirms both are justified). The admin path.

**DEPENDENT DECISION — carried into T078.** Decided 2026-08-06: T078 gains a
**sixth** case beyond the five `tasks.md` prescribes — the same rename driven
through the admin **change** form, `get_form(request, obj=skill)`, so the bound
`ModelForm` carries an instance with a primary key and `_post_clean()` runs
`full_clean()` on a saved model. T078's five prescribed cases all drive
`get_form(request)`, the *add* form with no instance, which never exercises the
screen an operator uses to edit a record — the very path the audit names as the
one FR-002 exists to guard. This requires a hand-edit to T078's text in
`tasks.md`, planned as part of T078's own task entry.

**OPEN QUESTIONS** — None.

---

## TASK 5 — Evaluate both sides of the duplicate comparison in the database

**ORIGIN** — Issue 1 of the audit. Verification §2: CONFIRMED, reproduced end to
end. The only finding in this plan that changes production behaviour.

**PROBLEM** — `skill.py:135-140` compares two values produced by *different
functions*: the left side is `Lower("name")`, evaluated by PostgreSQL; the right
side is `self.name.lower()`, evaluated by CPython. PostgreSQL's `lower()` is a
per-character mapping; CPython's `str.lower()` performs full Unicode case mapping
and can change the string's length. Measured 2026-08-06:

```
PG   lower('İ')  = 'i'     (1 character)
Py   'İ'.lower() = 'i̇'     (2 characters, U+0069 U+0307)
```

With `I` in the vocabulary and `İ` submitted, `full_clean()` does **not** raise
`skill_name_duplicate`. `validate_constraints()` catches the write afterwards and
files it under `__all__`; on a path that skips `full_clean()` it surfaces as a
raw `IntegrityError`. Data integrity never fails — the constraint holds in every
case. What is lost is precisely what `clean()` was added for: a message beside
the `name` field.

**DECIDED APPROACH** — Lowercase the candidate in the database as well, so both
sides go through the one function the constraint indexes. Model layer, one
expression:

```python
                Skill.objects.annotate(lower_name=Lower("name"))
-               .filter(lower_name=self.name.lower())
+               .filter(lower_name=Lower(models.Value(self.name)))
                .exclude(pk=self.pk)
                .exists()
```

`models.Value(...)` is preferred over a new `from django.db.models import Value`
line: the file already reaches for `models.`-prefixed members throughout
(`models.CharField`, `models.UniqueConstraint`), so no import changes. The
`Value` wrapper is required — a bare string in an expression position would be
read as a column reference.

**WHY THIS PATH** — Verified on the pinned stack (Django 6.0.7, PostgreSQL 17)
inside Docker on 2026-08-06:

```
SQL:  ... WHERE LOWER("skills"."name") = (LOWER(%s))
finds Python via DB-side lower: True
```

The name is passed as a bound parameter and lowered by PostgreSQL, so `clean()`
and `skill_unique_name_case_insensitive` now agree **by construction** rather
than by coincidence. The left-hand expression is unchanged, so the functional
index remains the one being matched. This is the same reasoning that already
rejected `__iexact` in `ff732d9` — two layers must not compare by different
criteria — applied one level finer: both layers say "lower", but one said it in
CPython. Likelihood is low for a curated English-language vocabulary; `İ` is
Turkish, and `ARCHITECTURE.md` frames the platform as targeting the European
market, so it is not purely hypothetical.

**ALTERNATIVES CONSIDERED**

- Accept the divergence and record it in the ADR's *Consequences* as a known
  limit — set aside: the fix is one expression and generates no migration, so
  the cost of closing it is lower than the cost of documenting it.
- A non-deterministic ICU collation on the column — already closed by
  `docs/adr/case-insensitive-skill-name-uniqueness.md`: it would make *every*
  comparison on `name` case-insensitive, for a column-type migration far larger
  than the problem. Not reopened.
- `__iexact` — closed in the session that built `ff732d9`: it compiles to
  `UPPER()` while the constraint indexes `LOWER()`, so the index would go unused,
  and uppercasing is lossy in German (`ß` and `ss` both uppercase to `SS`). **Do
  not "simplify" the lookup to `__iexact`.**

**SCOPE**

- `django_version/profiles/models/skill.py` — the filter expression only.
- `django_version/profiles/tests/models/test_skill.py` — one new test.
- `docs/adr/skill-name-comparison-is-evaluated-in-the-database.md` — new file.
- `docs/adr/case-insensitive-skill-name-uniqueness.md` — stale `Status` line and
  one cross-linking *Consequences* bullet.

**ACCEPTANCE CRITERIA**

- The filter compares `Lower("name")` against `Lower(models.Value(self.name))`.
  No Python-side `.lower()` remains in `clean()`.
- `docker-compose exec web python manage.py makemigrations --check --dry-run`
  reports **no changes** — nothing in `Meta` or on any field moved, so `CLAUDE.md`
  Rule 10 is not engaged. Confirm rather than assume.
- The new ADR follows the house MADR short form — title, `Date` / `Status` /
  `Applies to`, *Context and Problem Statement*, *Considered Options*, *Decision
  Outcome*, *Consequences* — and stays **under ~60 lines**. Its *Considered
  Options* records the `__iexact` rejection, which today exists only in a session
  handoff and would otherwise be lost. It carries no requirement, task, finding,
  or spec reference (`conventions.md`, *Recording decisions*).
- `case-insensitive-skill-name-uniqueness.md`'s `Status` no longer reads
  "implementation pending", and one *Consequences* bullet points to the new ADR.
  That file must not grow materially — it is already 67 lines, over the ceiling.
- Suite green, one test up.

**TEST PLAN** — One new test in `test_skill.py`: with a saved skill named `I`, a
candidate named `İ` raises `ValidationError`; assert `"name" in error_dict`, then
assert the code is `skill_name_duplicate`. `@pytest.mark.django_db` — it saves a
row and `clean()` queries. This test is **red before the change** (the error
arrives under `__all__` with code `None`) and green after, which is the
`testing.md` guarantee that it tests the line it targets.

**OUT OF SCOPE** — The `UniqueConstraint`, the migration, `unique=True`, the
strip, the empty-name branch, and the self-exclusion — all correct and all listed
as *do not reopen*. Any change to how names are **stored**: storage stays exactly
as typed, trimmed only.

**OPEN QUESTIONS** — None.

---

## TASK 6 — Cover `.distinct()` on the `ClientProfile` aggregate

**ORIGIN** — Issue 3 of the audit. Verification §2: CONFIRMED by executed
mutation, with a control proving the harness can go red.

**PROBLEM** — `admin.py:98` applies `.distinct()` to the `ClientProfile`
aggregate, and no test reaches it. The F-4 test
(`test_skill_admin.py:145-163`) attaches all three selected skills to a
**freelancer** profile only, so the client aggregate returns `0` with or without
`.distinct()`. The other client-involving test uses a **single** skill, the case
where references and profiles are equal by construction — the same blind spot
that let F-4 survive T018 in the first place, reproduced on the other model.
Measured:

```
.distinct() removed from ClientProfile     -> 268 passed   (uncovered)
.distinct() removed from FreelancerProfile -> 1 failed     (covered — the control)
```

**DECIDED APPROACH** — One test in
`django_version/profiles/tests/admin/test_skill_admin.py`, mirroring
`test_get_deleted_objects_counts_a_profile_referring_to_several_selected_skills_once`
with the three selected skills attached to `client_profile.interests` instead of
`freelancer_profile.skills`. Both fixtures already exist in
`profiles/tests/conftest.py`.

**WHY THIS PATH — and why there is no alternative.** The contract in
`contracts/admin-surface.md` §1 prescribes `.distinct()` on **both** aggregates,
so both need a guard. The only other shape — extending the existing freelancer
test to also attach a client profile — would put two behaviours in one function:
the test would then fail if either half broke, and the failure would not say
which, violating `testing.md`'s third granularity criterion (failure
attribution). A separate mirror is the single valid path.

**SCOPE** — `django_version/profiles/tests/admin/test_skill_admin.py`. One new
test function. No production file.

**ACCEPTANCE CRITERIA**

- The test attaches three selected skills to one client profile's `interests` and
  asserts a single protected entry carrying the count `1`.
- It carries `@pytest.mark.django_db`.
- Removing `.distinct()` from the `ClientProfile` aggregate makes this test, and
  only this test, fail.

**TEST PLAN** — One test, asserting `len(protected) == 1` and `"1" in
protected[0]`, matching the assertion shape of the freelancer sibling. Audit O-3
notes that a substring match on the count would also pass on `13` or `31`; it
discriminates correctly for the current message, which carries no other digit,
and the alternative would put a translatable string in an assertion. The sibling's
shape is followed rather than diverged from.

**OUT OF SCOPE** — The freelancer-side test, which is correct. The query-count
test, which is its own decision. `_count_referring_profiles` itself.

**OPEN QUESTIONS** — None.

---

## TASK 7 — Add the `max_length` boundary pair for `Skill.name`

**ORIGIN** — Issue 7 of the audit. Verification §2: CONFIRMED.

**PROBLEM** — `Skill.name` declares `max_length=100` and nothing exercises it.
Measured: a 100-character name passes `full_clean()`, a 101-character name yields
`keys=['name'] codes=['max_length']`. The limit could be changed to 10 or to 1000
and no test would notice — on the one field an administrator types into on the
single screen this feature adds.

**DECIDED APPROACH** — Two tests in
`django_version/profiles/tests/models/test_skill.py`: a name of exactly 100
characters passes `full_clean()`, and a name of 101 characters raises with the
`max_length` code on the `name` key.

**WHY THIS PATH — and why there is no alternative.** `CLAUDE.md` Rule 8 settles
the shape: the project already tests exactly this, on the same kind of
declaration, at `profiles/tests/models/test_base.py:33-51` for `Profile.bio` at
500 and 501 — and `testing.md` uses that second test as its worked example under
*Docstrings in tests*. Following the established pair is the convention, not a
choice. A field-metadata introspection test
(`Skill._meta.get_field("name").max_length == 100`) would be cheaper but weaker:
it asserts the declaration rather than the refusal, and the project has a
precedent for the behavioural form on this exact property.

**SCOPE** — `django_version/profiles/tests/models/test_skill.py`. Two new test
functions. No production file.

**ACCEPTANCE CRITERIA**

- A 100-character name passes `full_clean()` with no assertion body, matching the
  "passes validation" shape of `test_exactly_500_char_bio_passes_validation`.
- A 101-character name raises; the test asserts `"name" in error_dict` first,
  then that the code is `max_length`.
- **Both** carry `@pytest.mark.django_db`. This is not optional on the 101 case:
  `Model.full_clean()` calls `clean()` even after `clean_fields()` has already
  failed — it accumulates errors rather than short-circuiting — so the duplicate
  lookup runs on both tests. This is exactly the condition Task 2 rewrites the
  `conventions.md` clause to express.
- Changing `max_length` on the field makes at least one of the two fail.

**TEST PLAN** — Two tests. Codes: none asserted on the 100 case (it must not
raise), `max_length` on the 101 case, keyed on `name`, two-step assertion.

**OUT OF SCOPE** — `category`'s `max_length` and `choices` metadata, and
`Meta.db_table` / `verbose_name` — audit O-9 records these as deliberately
untested, with no project practice to follow. Do not file them.

**OPEN QUESTIONS** — None.

---

## TASK 8 — Guard `unique=True` on `Skill.name` with a field-metadata test

**ORIGIN** — Issue 6 of the audit. Verification §2: CONFIRMED by executed
mutation, with the schema inspected afterwards to rule out a reused database
masking it.

**PROBLEM** — `test_skill_name_uniqueness` used to assert `code == "unique"`, and
the field-level unique index was what produced that code, so the test died if
`unique=True` were removed. T077's repair correctly changed the assertion to
`skill_name_duplicate` — `clean()` now runs before `validate_unique()`, making
`unique` unreachable — but it was the only test touching `unique=True`, and
nothing replaced it. Measured with `--create-db`, so `--no-migrations` rebuilt
the schema from the mutated model:

```
unique=True removed from Skill.name  ->  268 passed

select indexname from pg_indexes where tablename='skills';
 skills_pkey
 skill_unique_name_case_insensitive        ← skills_name_key genuinely gone
```

A declaration the phase lists as *do not reopen* can be deleted with the whole
suite green.

**DECIDED APPROACH** — One field-metadata introspection test in
`django_version/profiles/tests/models/test_skill.py`:
`assert Skill._meta.get_field("name").unique is True`. No database access, so no
marker.

**WHY THIS PATH — and why a behavioural test is impossible.**
`skill_unique_name_case_insensitive` is strictly stronger than the field-level
index: anything an exact-match unique rejects, the `LOWER(name)` unique also
rejects. `unique=True` therefore has **no observable behaviour** the constraint
does not already provide — which is exactly why the ADR justifies keeping it on
migration-hygiene grounds (*"removing it would add an `AlterField` for no
behavioural gain"*), not behavioural ones. A test cannot observe what produces no
distinct observation, so a declaration-level guard is the only workable form.
*(`_meta` is Django's model introspection API: `Skill._meta.get_field("name")`
returns the field object itself, so the declaration can be asserted without
touching the database — a shape `testing.md` already lists as needing no marker.)*

**ALTERNATIVES CONSIDERED**

- Assert the constraint name inside the `IntegrityError` — set aside: it pins
  `skills_name_key`, a name PostgreSQL generated and no project document
  contracts, and it would really assert *which of two redundant indexes
  PostgreSQL happened to check first*.
- Accept the gap and rely on the ADR plus review — set aside: the guard costs two
  lines and fails on exactly the mutation the phase forbids.

**Known caveat, accepted.** This is a **new shape** for the project — nothing in
`profiles/tests/` or `accounts/tests/` asserts field metadata today, and audit
O-9 uses that same absence of precedent as a reason *not* to test `db_table` and
`verbose_name`. The distinction: those carry no decision, while `unique=True` is
a listed do-not-reopen item.

**SCOPE** — `django_version/profiles/tests/models/test_skill.py`. One new test
function. No production file.

**ACCEPTANCE CRITERIA**

- The test asserts `Skill._meta.get_field("name").unique is True`.
- It carries **no** `@pytest.mark.django_db` — introspection touches no database.
- Removing `unique=True` from the field makes this test, and only this test, fail.

**TEST PLAN** — One test, no `ValidationError`, no marker.

**OUT OF SCOPE** — `max_length` (Task 7 covers it behaviourally, per the
project's existing precedent). `Meta.db_table`, `Meta.verbose_name`, and the
`category` field's metadata — audit O-9 records these as deliberately untested.
The two database-level `IntegrityError` tests, which are correct as written.

**OPEN QUESTIONS** — None.

---

## DECISION RECORD — OD-1: the query-count test stays as written

**ORIGIN** — Open Decision 1 of the audit, re-measured in verification §3.

**No work is required.** This entry exists so a later session does not reopen it.

**DECIDED** — `test_counting_referring_profiles_issues_two_queries_for_a_selection_of_three_skills`
(`test_skill_admin.py:166-181`) keeps its direct call to the private
`SkillAdmin._count_referring_profiles`, and keeps its budget of **two** queries.

**WHY** — `docs/adr/skill-is-the-only-deletable-record.md:41-44` states the
contract in these words: *"one aggregate over each profile model, filtered by the
selected skills, two queries whatever the selection size."* **Two** is the
contracted number, and it is observable only on the helper. Routing through
`get_deleted_objects()` measures **4** — flat at selections of 1, 3, 5 and 10,
with and without referring profiles, so the audit's caveat about the collector's
share growing did not materialise (verification §3) — but two of those four
belong to Django's `NestedObjects` collector inside
`super().get_deleted_objects()`. A test asserting 4 no longer measures the
documented contract, and a Django upgrade could turn a `SkillAdmin` test red for
reasons unrelated to `SkillAdmin`. *(`NestedObjects` is Django's internal
collector that walks relations to build the "these related objects will also be
deleted" list on the confirmation page — an implementation detail of the admin,
not of this project's code.)*

Both options couple the test to something; the question is to what. The private
call couples to a name in a class this project owns, where a rename breaks
locally, obviously and cheaply. The public route couples to Django's internals,
where the break arrives from a dependency bump and reads as a false regression.
Audit O-4 reached a consistent conclusion: the helper's docstring already pins
"one aggregate query each" as stated behaviour.

**ALTERNATIVES CONSIDERED**

- Route through `get_deleted_objects()` and assert 4 — set aside for the reason
  above.
- Drop the query-count test — set aside: the non-scaling guarantee is the
  explicit second half of T079 and a stated Decision Outcome in the ADR, and
  would then survive only in prose.

**SCOPE** — No file changes. **Do not modify or delete this test.**

---

## TASK 9 — Admin-path coverage for the name rules (T078, extended by one case)

**ORIGIN** — T078, genuinely unbuilt. Finding F-3: FR-002 and FR-003 have no
admin-layer test at all today. Extended by the dependent decision recorded in
Task 4.

**PROBLEM** — Every test of the duplicate and empty-name rules runs on the model
path. The admin form — the screen this feature exists to add — is never driven,
so nothing proves the rules actually surface to an operator.

**DECIDED APPROACH** — Drive the real form in
`django_version/profiles/tests/admin/test_skill_admin.py`:
`SkillAdmin(Skill, django_admin.site).get_form(admin_request)(data)`, then assert
codes through `form.errors.as_data()`. This mirrors the established pattern in
`accounts/tests/admin/`, which builds `get_formset(admin_request)(data,
instance=…)` and reads `formset.forms[0].errors.as_data()`
(`test_client_profile_inline.py:246-253`). The `admin_request` fixture already
exists in the target file.

**Six cases** — the five `tasks.md` prescribes, plus one:

1. an exact duplicate is refused with `skill_name_duplicate`;
2. a case variant is refused with the same code, **and the existing skill still
   carries its original spelling** (FR-002's "the existing skill keeps its stored
   name");
3. `"  python  "` is refused — case and whitespace combined;
4. a whitespace-only name yields **both** `required` and `skill_name_empty` on
   `name`;
5. a brand-new name is accepted, so the rule is shown to refuse duplicates rather
   than everything;
6. **new** — a saved skill renamed onto another saved skill's name is refused
   through the **change** form, `get_form(admin_request, obj=skill)`, with the
   bound form carrying `instance=skill`.

**WHY THE SIXTH CASE** — The five prescribed cases all drive
`get_form(admin_request)`, the *add* form with no instance. Django builds a
different form for add and change, and only the change form produces a bound
`ModelForm` whose `_post_clean()` runs `full_clean()` on a model with a primary
key. The audit names the admin change form as *"the path FR-002 exists to guard,
and it is the saved path"*. Adding five add-form tests while leaving it undriven
would reproduce the shape of the gap Issue 2 just found.

**SCOPE**

- `django_version/profiles/tests/admin/test_skill_admin.py` — six new tests.
- `specs/001-profiles-admin-panel/tasks.md` — T078's text gains the sixth bullet,
  by hand, with a dated amendment note in the style the file already uses for
  T083 and T084. Do **not** regenerate the file.

**ACCEPTANCE CRITERIA**

- Every test asserts the `name` key is present in `form.errors.as_data()` before
  asserting any code.
- The single-code cases may use `[0].code`. **Case 4 must compare the set** —
  `{e.code for e in form.errors.as_data()["name"]}` — never an index, so the test
  does not encode Django's internal error ordering (`clean_fields()` before
  `clean()`) as if it were the contract.
- Case 2 additionally re-reads the existing skill and asserts its stored name is
  unchanged.
- Case 5 asserts the form is valid, proving the rule is not refusing everything.
- All six carry `@pytest.mark.django_db`.
- T078's amended text in `tasks.md` lists six bullets, with the amendment dated.

**TEST PLAN** — Codes asserted: `skill_name_duplicate` (cases 1, 2, 3, 6);
`{required, skill_name_empty}` as a set (case 4); no error (case 5). All keyed on
`name`.

**OUT OF SCOPE** — **Do not write a test asserting that the admin trims a name**
(finding F-2a). The form's `CharField` carries `strip=True`, so such a test
asserts Django's stripping and keeps passing with `Skill.clean()` deleted —
tautological under `testing.md`. The trim is covered on the model path, where it
is reachable. Also out: the `İ`/`I` divergence, which Task 5 covers on the model
path and which reaches the admin through the same `clean()`.

**OPEN QUESTIONS** — None.

---

## TASK 10 — Add the manual-validation rows for the amended rule (T080, extended by one row)

**ORIGIN** — T080, genuinely unbuilt.

**PROBLEM** — `quickstart.md` section A is nine rows, and every one is an *add* or
a *delete*. Nothing walks the amended FR-002, and nothing anywhere in the section
edits an existing skill — so the change form has no human validation either.

**DECIDED APPROACH** — Three rows appended to
`specs/001-profiles-admin-panel/quickstart.md` section A, after A9, in the
existing table format:

- **A10** — with `Python` in the vocabulary, adding `python` is refused with a
  message on the name field, no second row is created, and the existing skill is
  still spelled `Python`.
- **A11** — adding `JavaScript` stores it exactly as `JavaScript`, with no
  capitalization rule applied.
- **A12** *(new)* — opening an existing skill and renaming it onto another
  skill's name, differing in case, is refused with a message on the name field,
  and both skills keep their stored names.

**WHY THE THIRD ROW** — Manual validation earns its place where a test cannot
reach: whether the error actually renders beside the field in the real admin
template. Django renders the add form and the change form through different bound
form states, so a row that passes on one proves nothing about the other. The
automated coverage from Task 9 proves the *code* refuses the rename; A12 proves
the *message renders* on the screen an operator edits from.

**SCOPE**

- `specs/001-profiles-admin-panel/quickstart.md` — section A only, three rows
  appended after A9, same table format and column set.
- `specs/001-profiles-admin-panel/tasks.md` — T080's text gains the third row, by
  hand, with a dated amendment note in the style used for T083 and T084. Do
  **not** regenerate the file.

**ACCEPTANCE CRITERIA**

- Three rows, matching the four-column format of A1–A9.
- A10 and A11 carry their requirement references as `tasks.md` states them.
- A12 is marked as covering the same rule on the edit path.
- No existing row is reworded or renumbered.

**TEST PLAN** — None. This is the manual walk; T067 executes it, and T067 stays
out of scope here.

**OUT OF SCOPE** — Running the walk. Sections B–F. T067 itself.

**OPEN QUESTIONS** — None.

---

## TASK 11 — Close Phase 10 in `tasks.md`

**ORIGIN** — The deferral policy set by the Developer session that built
T073–T077 and T079: *"Mark as [X] … once the audit findings are resolved."*

**PROBLEM** — Until this runs, Phase 10 reads as unfinished and the three Phase 9
gates stay blocked.

**DECIDED APPROACH** — In one pass: set `- [X]` on T073, T074, T075, T076, T077,
T078, T079 and T080, and delete the in-flight status block Task 3 added.

**SCOPE** — `specs/001-profiles-admin-panel/tasks.md`, the Phase 10 block only.

**ACCEPTANCE CRITERIA**

- All eight Phase 10 boxes read `- [X]`.
- The in-flight status block is gone.
- No task text is reworded, renumbered, or removed — the hand-written amendment
  history is untouched.
- The full suite is green before this runs.

**TEST PLAN** — None.

**OUT OF SCOPE** — T065, T066 and T067. They become *runnable* once this lands,
but running them is not part of this plan.

**OPEN QUESTIONS** — None.

---

## Order of execution

| # | Task | Why here |
|---|---|---|
| 1 | **Task 1** — the `__repr__` literals | Restores the green baseline. Every later task is measured against it, so nothing else should start while the suite is red |
| 2 | **Task 2** — the `conventions.md` marker clause | Auto-loaded, zero risk, and it states the marker rule Tasks 4 and 7 have to follow. Correct it before writing tests under it |
| 3 | **Task 3** — the in-flight status block | Documentation, independent, cheap. Makes the artifact legible for the rest of the remediation |
| 4 | **Tasks 4, 6, 7, 8** — the four missing tests | Independent of each other and of everything else; any order. All test-only, no production file touched. Each has a sibling in the codebase to copy the shape from |
| 5 | **Task 5** — database-side lowercasing | The only task that changes production behaviour and the only one touching the ADRs. Held until the test surface around it is complete |
| 6 | **Task 9** — T078, the admin path | Written after Task 5 so the admin tests are authored against the final `clean()` behaviour. Carries the sixth case decided in Task 4 |
| 7 | **Task 10** — T080, the quickstart rows | Independent of everything; last of the content work |
| 8 | **Task 11** — close Phase 10 | Strictly last. Requires a green suite and every task above delivered |

**Commits.** Per `conventions.md`, commit after each logical group, with messages
readable by someone who never opened the spec — no requirement, task or finding
IDs, and no `Co-Authored-By` trailer.

**Verification after each group**, from `django_version/`:

```
docker-compose exec web pytest
docker-compose exec web python manage.py makemigrations --check --dry-run
```

The second matters most after Task 5 — it must report **no changes**, confirming
the fix generated no migration.

**Do not run** T040, T063, T065, T066 or T067. They are Phase 9 verification
gates and they run after Phase 10 closes.

**Do not run** `/speckit-tasks`, `/speckit-plan` or `/speckit-specify` on this
feature. Each regenerates its artifact from a template and would erase the
hand-written amendment history in `tasks.md` and the amended FR-002 in `spec.md`.
Every edit to a spec artifact in this plan is made by hand.

---

## Handoff

**Planned**: all seven audit Issues, the one Open Decision, the checkbox state,
and the two unbuilt Phase 10 tasks — **eleven tasks and one decision record**,
each decided by the user in its own loop. Nothing was left undecided.

| Source | Lands in |
|---|---|
| Issue 1 | Task 5 |
| Issue 2 | Task 4, extended into Task 9 |
| Issue 3 | Task 6 |
| Issue 4 | Task 1 |
| Issue 5 | Task 2 |
| Issue 6 | Task 8 |
| Issue 7 | Task 7 |
| OD-1 | Decision record — no work, do not reopen |
| Checkbox state | Task 3, closed by Task 11 |
| T078 | Task 9 |
| T080 | Task 10 |

**Plan file**: `specs/001-profiles-admin-panel/plan_phase-10-remediation_2026-08-06.md`
(this file).

**Open questions**: none. Every task entry reads `OPEN QUESTIONS — None`.

**Two corrections this plan makes to its own inputs**, so the next session does
not act on the superseded versions:

1. The handoff's **268-passing baseline is wrong for the current tree** — it is
   267 passing, 1 failing, from an in-progress edit to the `__repr__` test. Task 1
   restores it.
2. The verification document's **§5 reads the unticked Phase 10 checkboxes as an
   oversight**. They are a deliberate deferral by the session that built the
   phase. Task 3 and Task 11 honour the policy instead of overriding it.

A third, smaller one: the handoff states T077 is committed. It is not — all of
T077 lives in the one modified file in the working tree.

**Files the next session should attach**

- this plan
- `django_version/profiles/models/skill.py` — Tasks 5, 7, 8
- `django_version/profiles/tests/models/test_skill.py` — Tasks 1, 4, 5, 7, 8
- `django_version/profiles/tests/admin/test_skill_admin.py` — Tasks 6, 9
- `django_version/profiles/admin.py` — Task 6's target, read-only
- `django_version/profiles/tests/conftest.py` — the fixtures Tasks 4, 6 and 9 use
- `django_version/profiles/tests/models/test_base.py` — the `bio` pair Task 7 copies
- `accounts/tests/admin/test_client_profile_inline.py` — the form-driving shape Task 9 follows
- `.claude/rules/conventions.md` — Task 2
- `docs/adr/case-insensitive-skill-name-uniqueness.md` — Task 5
- `docs/adr/skill-is-the-only-deletable-record.md` — the OD-1 decision record
- `specs/001-profiles-admin-panel/tasks.md` — Tasks 3, 9, 10, 11
- `specs/001-profiles-admin-panel/quickstart.md` — Task 10
- `django_version/DEVELOPER.md`

**Recommended next persona**: Developer, starting at Task 1. Task 1 through Task
3 are small and independent and can be delivered in one sitting; Task 5 deserves
its own session, since it is the only production change and carries two ADR
edits.
