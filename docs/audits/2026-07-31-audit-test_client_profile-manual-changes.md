# Audit — manual changes to `profiles/tests/models/test_client_profile.py`

**Date:** 2026-07-31
**Persona:** Auditor (`django_version/AUDITOR.md`)
**Branch:** `feature/django-refactor`
**Follows:** `docs/audits/2026-07-28-audit-test_client_profile.md` and
`docs/audits/2026-07-29-verification-test_client_profile.md`

**Primary target**

- `django_version/profiles/tests/models/test_client_profile.py` (working tree,
  untracked)

**Context read (not the audit target)**

- `django_version/profiles/models/client_profile.py`
- `django_version/profiles/models/freelancer_profile.py`
- `django_version/profiles/models/base.py`
- `django_version/profiles/tests/conftest.py`
- `django_version/profiles/tests/models/test_freelancer_profile.py`
- `django_version/accounts/tests/models/test_base.py`
- `django_version/accounts/tests/models/test_freelancer.py`
- `django_version/CLAUDE.md`, `.claude/rules/testing.md`,
  `.claude/rules/conventions.md`

**Runtime evidence.** All commands executed inside Docker (`skillbridge-web-1`,
Python 3.14.6, Django 6.0.7, pytest 9.1.1, pytest-django 4.12.0). No file was
modified by this audit. Probes operate on unsaved in-memory instances and on
in-memory copies of field objects — no DB write, no file write.

```
$ docker-compose exec web pytest profiles/tests/models/test_client_profile.py
21 passed in 1.22s
```

21 collected = 20 test functions, one parametrized ×2 (was 18/17 at the
verification of 2026-07-29).

**Result:** 2 Issues · 1 Open Decision · 7 Observations

---

## Part 1 — Status of the previous findings

| Finding                                    | Status in the current file                                                            |
| ------------------------------------------ | ------------------------------------------------------------------------------------- |
| **I-1** `company_name` guard false branch   | ✅ **Closed correctly** — `test_client_profile_no_company_name_passes_validation` (`:96-103`) |
| **I-2** `get_display_info()` `ValueError`   | ✅ **Closed correctly** — `test_get_display_info_on_unsaved_instance` (`:156-162`)     |
| **I-3** `test_add_and_remove_interests`     | ✅ **Split** into `..._add_interests` (`:175`) and `..._remove_interests` (`:194`) — but see **A-1** and **A-2** |
| **I-4** missing `-> None`                   | ✅ **Closed** — `:256-258` now annotated                                               |
| **O-2** typos                               | ✅ `withespace` → `whitespace` (`:86`), `Validation_Error` → `ValidationError` with the code quoted (`:86`), `An max budget` → `A max budget` (`:51`). One new omission — see **B-4** |
| **O-3** trailing blank lines in the model   | ✅ **Reverted** — `git status` no longer lists `client_profile.py` as modified          |
| **Verifier's rename suggestion**            | ✅ Applied — `..._max_budget_accepts_null_at_database_level` (`:266`) — but see **A-2** |
| **OD-1** optional-field coverage            | ⏳ Still open — see Part 3                                                              |

### I-1's replacement is correct and non-tautological

`test_client_profile_no_company_name_passes_validation` (`:96-103`) constructs
with `company_name=""` and calls `full_clean()`. Delete the guard
`if self.company_name:` (`client_profile.py:142`) and `"".strip()` is falsy →
`company_name_empty` is raised → the test fails. It targets a real line of
project code, satisfying `testing.md:618-635`.

It also incidentally pins `blank=True` on `company_name` (probe below): with
`blank=False`, `clean_fields()` raises `This field cannot be blank.` and the
test fails. Two production declarations, one call, distinguishable by error code
in the traceback — acceptable, not a granularity violation.

### I-2's replacement is correct, and the DB marker is correctly absent

The audit's Direction proposed building the instance from
`valid_client_profile_data` and keeping `@pytest.mark.django_db` because the
fixture chain persists a `Client`. The implementation went further and dropped
the fixture entirely: `ClientProfile(user=Client(name="Unsave Client"))`. That
is **better**, and the missing marker is **correct, not an omission** —
`testing.md:397-404` says the marker is only for tests that touch the DB, and
this one does not. The proof is that the test passes: pytest-django blocks DB
access by default, so a green run is evidence no query was issued.

The test is also not tautological. The `ValueError` comes from the M2M line, not
from anything Django would raise regardless:

```
PROBE A - pk: None
PROBE A - user.name reads fine: Unsaved Client
PROBE A - ValueError raised, message starts: "ClientProfile (profile_id=None, user_id
PROBE B - dict without interests key builds fine: ['bio', 'company_name', 'max_budget', 'name', 'website_url']
```

PROBE B is the operational test from `testing.md:634` — mentally delete
`"interests": list(self.interests.values_list(...))` (`client_profile.py:125`)
and every other key still builds, so no `ValueError` is raised and the test
fails. It targets `ClientProfile`'s own decision to resolve the M2M eagerly.

---

## Part 2 — Issues (action required)

### A-1 — Dead statement in `test_client_profile_remove_interests`

- **What.** `reloaded_profile` is assigned at `:204-206` and never read: the
  next use is the reassignment at `:209-211`. The first `.get()` fires a real
  query (plus a `prefetch_related` query) whose result is discarded.
- **Where.** `django_version/profiles/tests/models/test_client_profile.py:204-206`.
- **Rule violated.** `conventions.md` → "Code standards", Clean Code /
  single responsibility ("one responsibility per function" — this statement
  belongs to the *add* behavior, which is now a separate test); and
  `testing.md:516-540` "One behavior per test", which the split was performed to
  satisfy. The leftover reload is the residue of the pre-split body.
- **Why it matters.** It reads as if the removal test also verifies the addition,
  which it does not — there is no assertion between the two `.get()` calls. A
  reader cannot tell whether the line is load-bearing setup or debris, and it
  costs two queries per run.
- **Direction.** The correct shape is already in the sibling test:
  `test_client_profile_add_interests` (`:175-190`) reloads exactly once, right
  before its assertions. In the removal test, `.add()` is setup and only the
  post-`.remove()` reload is the observation.

### A-2 — The client/freelancer test files are now asymmetric on four points

- **What.** Every remediation landed in `test_client_profile.py` only. Its
  counterpart still carries the defects the 2026-07-28 audit and the 2026-07-29
  verification identified as shared:

  | Item                              | `test_client_profile.py`                               | `test_freelancer_profile.py`                          |
  | --------------------------------- | ------------------------------------------------------ | ----------------------------------------------------- |
  | I-3 split                         | split (`:175`, `:194`)                                  | `test_add_and_remove_skills` (`:140-163`) — unsplit    |
  | I-2 unsaved `get_display_info`    | `:156-162`                                              | absent — same documented `Raises:` at `freelancer_profile.py:113-116` |
  | DB-level null test name           | `..._max_budget_accepts_null_at_database_level` (`:266`) | `..._hourly_rate_none_persists_on_save` (`:207`)       |
  | Optional-field creation coverage  | `company_name=""` covered (`:96`)                        | no equivalent                                          |

- **Where.** `django_version/profiles/tests/models/test_freelancer_profile.py`
  (the defect lives there; the asymmetry is what makes it an issue for the
  primary target).
- **Rule violated.** `CLAUDE.md` Rule 8 ("Follow existing patterns" — two files
  covering mirror-image models must not diverge in convention);
  `testing.md:516-540` (still violated by `test_add_and_remove_skills`);
  the 2026-07-28 audit's own Direction for I-3: *"treat both as one task"*.
- **Why it matters.** The two files are the reference for every future profile
  model. Whichever a developer opens first becomes the template, and they now
  teach opposite things. Concretely, `FreelancerProfile.get_display_info()`'s
  documented `ValueError` remains unguarded, which was the whole point of I-2.
- **Direction.** Apply the four changes already made here to
  `test_freelancer_profile.py` verbatim, substituting `skills` for `interests`
  and `hourly_rate` for `max_budget`. No new pattern needs to be invented.

---

## Part 3 — Your question: is `blank=True` coverage missing?

Short answer: **it splits in two, and only one half is worth writing.**

### Half 1 — invalid-value tests for `website_url`: do **not** write them

A test feeding `"not a url"` to `website_url` and expecting `ValidationError`
tests Django's `URLField`, not `ClientProfile`. `ClientProfile.clean()`
(`client_profile.py:128-169`) never mentions `website_url`; delete every line of
that method and such a test still passes. That is exactly the tautology
`testing.md:618-635` forbids, and the same verdict applies to a `max_length=200`
boundary test on `company_name` (`CharField` owns it) and to
`max_digits`/`decimal_places` on `max_budget` (`DecimalValidator` owns it).

The two files you asked me to read confirm this is the project's actual
standard, not just a written rule:

- `test_base.py` never feeds a 300-character email to probe `EmailField`'s
  `max_length`. Its email tests (`:107-151`) target the **project's**
  `validate_email` and assert project-specific codes (`empty_email`,
  `invalid_email`) — never Django's generic ones.
- `test_freelancer.py` has no test for `BooleanField` accepting `True`/`False`.
  It tests `is_available` only where the project made a decision: the default
  (`:23-29`) and the `is_active`/`is_available` invariant (`:88-108`).

### Half 2 — "all optional fields may be omitted": this one is **real**

`blank=True` is a project declaration, not framework behavior, so pinning it is
in scope by the same standard. And it is currently unpinned for three of the
four fields. Probe (in-memory only — `f.blank` flipped on the live field object,
no file touched):

```
PROBE C - company_name: blank=True null=False
PROBE C - website_url:  blank=True null=False
PROBE C - bio:          blank=True null=False
PROBE C - max_budget:   blank=True null=True

PROBE D [as declared]                  - minimal instance PASSES clean_fields + clean
PROBE D [blank=False on company_name]  - {'company_name': ['This field cannot be blank.']}
PROBE D [blank=False on website_url]   - {'website_url':  ['This field cannot be blank.']}
PROBE D [blank=False on bio]           - {'bio':          ['This field cannot be blank.']}
PROBE D [blank=False on max_budget]    - {'max_budget':   ['This field cannot be blank.']}
```

So a single `full_clean()` on a minimal instance fails if `blank=True` is
dropped from any of the four. Today, only `company_name` is covered (by I-1's
new test). Drop `blank=True` from `website_url` or `bio` tomorrow and the whole
suite stays green while every client without a website becomes unsaveable
through admin, forms, and DRF.

Two more facts that bound the answer:

- **`null=True` is a separate contract and is already covered.**
  `PROBE D [null=False on max_budget (blank still True)] - minimal instance
  PASSES` — `clean_fields()` skips blank-and-empty fields, so validation never
  sees the nullability change. `test_client_profile_max_budget_accepts_null_at_database_level`
  (`:266`) is the only guard, which is why the verifier's rename was right.
- **There is nothing analogous to add for the other fields.** `null=True`
  appears on exactly two model fields in the project (`max_budget`,
  `hourly_rate`); `company_name`, `website_url` and `bio` are `NOT NULL` with
  default `''`.

### Recommendation (you asked, so I am giving one)

Add **one** test — the audit's OD-1 option **B** — rather than four:

```
test_client_profile_optional_fields_can_be_omitted
    profile = ClientProfile(user=client_user)   # nothing else set
    profile.full_clean()                        # no assertion needed
```

Reasons it is one test and not four:

- It is one behavior ("all client-specific fields are optional"), one call, one
  state — `testing.md:528-540` is satisfied.
- Failure attribution, the usual argument for splitting, is preserved for free:
  `full_clean()` accumulates errors into `error_dict`, so the failure message
  names the offending field(s) directly. Splitting buys nothing.
- The no-assertion shape has direct precedent in the files you pointed me to:
  `test_clean_method_passes_for_valid_superuser` (`test_base.py:343-355`) and
  `test_freelancer_clean_passes_if_inactive_and_unavailable`
  (`test_freelancer.py:111-123`) both call `full_clean()` and assert nothing —
  "does not raise" *is* the assertion.

Two mechanical notes for whoever implements it: it needs
`@pytest.mark.django_db` (`full_clean()` → `validate_unique()` on the `user`
`OneToOneField` queries the DB — `testing.md:391-393`), and it must take the
`client_user` fixture, **not** `client_profile`, or the uniqueness check will
fail for an unrelated reason. Apply the mirror test to
`test_freelancer_profile.py` (`portfolio_url`, `bio`, `hourly_rate`) per A-2.

---

## Open Decisions — user choice needed

### OD-1 (carried over) — scope of the optional-field test

The recommendation above is option B of the original OD-1. Options A (add
nothing beyond the `company_name` test already written) and C (one test per
optional field) remain valid choices with the trade-offs stated in
`docs/audits/2026-07-28-audit-test_client_profile.md`. `testing.md` does not
choose; per `CLAUDE.md` Rule 5 the decision is yours. Whichever you pick,
apply it symmetrically to `test_freelancer_profile.py`.

---

## Observations / Learning Notes — no action needed

### B-1 — Test name breaks the file's naming convention

`test_get_display_info_on_unsaved_instance` (`:156`) is the only test in the
file without the `test_client_profile_` prefix; the other 19 have it. Cosmetic,
but the prefix is what keeps `pytest -k client_profile` meaningful once the
freelancer twin exists.

### B-2 — `"Unsave Client"` (`:159`)

Should read `"Unsaved Client"`. The value is never asserted on, so nothing
breaks.

### B-3 — Blank line after the docstring (`:158`)

No other test in the file separates its docstring from the first statement.

### B-4 — Two docstrings need a pass

| Where | Text                                                                    | Note                                                                                         |
| ----- | ----------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `:100` | `"""full_clean() does not raise ValidationError when company_name is not provided"""` | No terminating period — every other docstring in the file has one.                             |
| `:269` | `"""A ClientProfile created with max_budget=None guards the null=True."""` | The test does not "guard" anything; it *verifies* that the column accepts `NULL`. Also `testing.md:705-715` asks the docstring to describe the behavior, not the declaration being pinned. |

### B-5 — `assert profile.company_name == ""` (`:103`) is near-tautological

Same shape the previous audit flagged as O-5 for `max_budget` (`:79`): it
restates the value assigned two lines above. It is not fully vacuous — it weakly
pins that `ClientProfile.clean()` does not normalize `company_name`, unlike
`Skill.clean()`, which reassigns `self.name = self.name.strip()`. That
divergence is the verifier's still-open OQ-2. Harmless either way; noted so the
pattern is not copied as if it carried information.

### B-6 — Stray file in the working tree

`git status` lists an untracked, zero-byte file at the repository root of the
Django project:

```
?? "django_version/ClientProfile (profile_id=None, user_id=None, max_budget=10)"
```

Dated 2026-07-29 15:17 — it is the `__str__` of the unsaved profile from the
verification session's shell probe, captured by an unquoted shell redirection.
It is not test output and not part of the change. Delete it before committing;
nothing in the suite reads it.

### B-7 — Everything else in the file remains correct

Re-verified after the manual edits: DB-access declarations (every DB-touching
test carries `@pytest.mark.django_db`, the three pure-introspection/in-memory
tests correctly do not); `ValidationError` assertions all use the key-then-code
two-step (`testing.md:645-659`); imports still all used, ordering stdlib →
Django → local; `Skill` rows still created explicitly rather than relying on the
`--no-migrations`-skipped seed migration; `conftest.py` additions unchanged
since the verification and still compliant with the "no override consumers"
exception.

---

## Handoff — next session

**Audited.** The manual changes to
`django_version/profiles/tests/models/test_client_profile.py` (21 tests, up from
18), against the two prior reports, the production models, and the two
`accounts/` test files nominated as the pattern reference.

**Counts.** 2 Issues · 1 Open Decision · 7 Observations.

**Verdict on the manual work.** All four previous Issues are closed, and both
new tests (I-1, I-2) are correct and non-tautological — verified by runtime
probe, not by inspection. I-2's implementation is better than the Direction the
audit gave. Two defects were introduced or left behind: a dead statement
(A-1) and the client/freelancer asymmetry (A-2).

**Ready to implement without further input.** A-1 (delete three lines), B-1…B-4
(cosmetic), B-6 (delete the stray file). A-2 is mechanical but touches a second
file — confirm scope first per `CLAUDE.md` Rule 4.

**Blocked on you.** OD-1 (option A / B / C), and the verifier's OQ-2
(normalize-vs-reject divergence between `Skill.clean()` and
`ClientProfile.clean()`), which does not affect any test written so far.

**Files to attach next session.**

- `django_version/profiles/tests/models/test_client_profile.py`
- `django_version/profiles/tests/models/test_freelancer_profile.py`
- `django_version/profiles/models/client_profile.py`
- `django_version/profiles/models/freelancer_profile.py`
- `.claude/rules/testing.md`
- this report

**Recommended persona.** `DEVELOPER.md` for A-1, B-1…B-4 and B-6. `PLANNER.md`
for A-2 plus OD-1 once decided, so both profile test files are brought back into
symmetry in one pass.

**Verification command.**
`docker-compose exec web pytest profiles/tests/models/test_client_profile.py`
— run during this audit: **21 passed in 1.22s**.
