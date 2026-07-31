# Audit — `profiles/tests/models/test_client_profile.py`

**Date:** 2026-07-28
**Persona:** Auditor (`django_version/AUDITOR.md`)
**Branch:** `feature/django-refactor`

**Primary target**

- `django_version/profiles/tests/models/test_client_profile.py`

**Context read (not the audit target)**

- `django_version/profiles/models/client_profile.py`
- `django_version/profiles/models/base.py`
- `django_version/profiles/models/freelancer_profile.py`
- `django_version/profiles/tests/conftest.py`
- `django_version/profiles/tests/models/test_base.py`
- `django_version/profiles/tests/models/test_freelancer_profile.py`
- `django_version/CLAUDE.md`, `.claude/rules/testing.md`, `.claude/rules/conventions.md`

**Result:** 4 Issues · 1 Open Decision · 8 Observations

---

## Coverage map — `client_profile.py` vs. the test file

| Production element                          | Source line             | Covered by                                                                     | Status  |
| ------------------------------------------- | ----------------------- | ------------------------------------------------------------------------------ | ------- |
| Inherits `Profile`                          | `client_profile.py:22`  | `test_client_profile_inherits_from_profile_class`                              | ✅      |
| `user` OneToOne, `on_delete=PROTECT`        | `client_profile.py:44`  | `test_client_profile_on_delete_protect`                                        | ✅      |
| `user` implicit uniqueness (validation)     | `client_profile.py:44`  | `test_client_profile_user_uniqueness`                                          | ✅      |
| `user` uniqueness (DB level)                | `client_profile.py:44`  | `test_client_profile_user_uniqueness_enforced_at_database_level`               | ✅      |
| `company_name` — whitespace-only rejected   | `client_profile.py:142` | `test_client_profile_raises_validation_error_with_empty_company_name`          | ✅      |
| `company_name` — guard false branch (blank) | `client_profile.py:142` | —                                                                              | ❌ I-1  |
| `max_budget` — `<= 0` rejected              | `client_profile.py:159` | `test_client_profile_raises_validation_error_with_non_positive_max_budget`     | ✅      |
| `max_budget` — `None` guard branch          | `client_profile.py:157` | `test_client_profile_max_budget_none_passes_validation`                        | ✅      |
| `max_budget` — `None` persists              | `client_profile.py:59`  | `test_client_profile_max_budget_none_persists_on_save`                         | ✅      |
| `interests` M2M add/remove                  | `client_profile.py:68`  | `test_add_and_remove_interests`                                                | ⚠️ I-3 |
| `website_url`                               | `client_profile.py:77`  | asserted only inside creation/display tests                                    | ⚠️ OD-1 |
| `__str__` (inherited)                       | `base.py:62`            | `test_client_profile_str_representation`                                       | ✅      |
| `__repr__`                                  | `client_profile.py:90`  | `test_client_profile_repr_representation`                                      | ✅      |
| `get_display_info` — full dict              | `client_profile.py:103` | `test_client_profile_get_display_info`                                         | ✅      |
| `get_display_info` — empty interests        | `client_profile.py:125` | `test_client_profile_get_display_info_without_interests`                       | ✅      |
| `get_display_info` — documented `ValueError` on unsaved instance | `client_profile.py:114` | —                                                          | ❌ I-2  |
| `Meta.ordering` (inherited)                 | `base.py:60`            | `test_client_profile_ordering`                                                 | ✅      |
| `created_at` / `updated_at`                 | `base.py:44`            | `test_client_profile_created_at_is_set_on_creation`, `..._updated_at_changes_on_save` | ✅ |
| `bio` length validation                     | `base.py:36`            | `test_base.py` (abstract-base tests, via `FreelancerProfile`)                  | ✅ (by design) |

---

## Issues — action required

### I-1 — No test for the `company_name` guard's false branch (blank `company_name`)

- **What.** `ClientProfile.clean()` wraps the whitespace check in `if self.company_name:`. Nothing verifies that a blank/omitted `company_name` passes `full_clean()`.
- **Where.** `django_version/profiles/tests/models/test_client_profile.py` — missing test. Production code: `django_version/profiles/models/client_profile.py:142`.
- **Rule violated.** `testing.md` → "What to test in an abstract base model" item 2, *"every branch: valid, boundary, invalid, normalization"*, and the branch-coverage principle applied to `clean()` in `conventions.md` → "Model invariants — enforced via clean()".
- **Why it matters.** The guard is what makes `company_name` genuinely optional. Delete `if self.company_name:` and `""` still passes (`"".strip()` is falsy → raises `company_name_empty`) — no existing test catches that regression. The suite would go green on a model that rejects every client with no company name.
- **Direction.** The exact analogue already exists for the other optional field: `test_freelancer_profile_hourly_rate_none_passes_validation` (`test_freelancer_profile.py:190`) and its sibling in this same file, `test_client_profile_max_budget_none_passes_validation` (`test_client_profile.py:66`). Mirror that shape for `company_name`.

### I-2 — `get_display_info()`'s documented `ValueError` on an unsaved instance is untested

- **What.** The `get_display_info` docstring declares `Raises: ValueError: If called on an unsaved instance` (`client_profile.py:114-117`). No test exercises it.
- **Where.** `test_client_profile.py` — missing test (same gap exists in `test_freelancer_profile.py`).
- **Rule violated.** `AUDITOR.md` → "TEST GAPS: missing edge cases"; `testing.md` → "Abstract method contract" / branch coverage. A documented `Raises:` clause is part of the method contract.
- **Why it matters.** This is the M2M-on-unsaved-instance trap that `conventions.md` calls out explicitly ("Field-to-validation contract", special case ManyToManyField). If someone later reorders the dict so `interests` is resolved lazily or guards it with a `self.pk` check, the documented contract changes silently and nothing fails.
- **Direction.** Same assertion style as `test_base.py:54` (`test_unimplemented_get_display_info_raises_not_implemented_error`) — assert the exception type only, via `pytest.raises`. Build the instance unsaved from `valid_client_profile_data` (the `django_db` marker is still required, because the fixture chain persists a `Client`).

### I-3 — `test_add_and_remove_interests` covers two behaviors in one test

- **What.** The test asserts one state after `.add()`, mutates with `.remove()`, then asserts a second state — two state transitions, six assertions, "and" in the name.
- **Where.** `test_client_profile.py:166-189`.
- **Rule violated.** `testing.md` → "One behavior per test — granularity rule", criteria 1 (naming check: name needs "and") and 2 (one-call rule). The documented exception does **not** apply: it explicitly *never* covers "assertions on different states (before vs after a mutation)".
- **Why it matters.** A failure in the removal half reports as `test_add_and_remove_interests`, giving no attribution; and if the `add` assertions fail, the `remove` half never runs, so a second defect stays hidden until the first is fixed.
- **Direction.** Split into one test for association and one for disassociation. Note: `test_freelancer_profile.py:140` (`test_add_and_remove_skills`) has the identical defect — this file inherited it by following that pattern. Fixing only the client file leaves the two files asymmetric; treat both as one task.

### I-4 — Missing `-> None` return annotation on a test function

- **What.** `test_client_profile_user_uniqueness_enforced_at_database_level` has no return type annotation.
- **Where.** `test_client_profile.py:231-233`.
- **Rule violated.** `testing.md` → "Type hints in tests and fixtures": *"Test functions must always have return type `-> None`"*; listed again in "Common mistakes to avoid".
- **Why it matters.** Inconsistent with the other 16 tests in the file and with the freelancer counterpart (`test_freelancer_profile.py:235`, which is annotated). Breaks the file's own convention and any strict type-checking pass.
- **Direction.** Match the signature of the freelancer counterpart.

---

## Open Decisions — user choice needed

### OD-1 — Coverage for the optional `website_url` (and optional fields generally)

This answers the question raised in the audit request. Split it in two, because the two halves have different answers:

**Not open — do not add.** A test feeding an invalid URL (`"not a url"`, `"http://exa mple.com"`) and expecting a `ValidationError` tests Django's `URLField`, not `ClientProfile`. `testing.md` → "A test must fail if the behavior under test is removed" and `conventions.md` → "Field-to-validation contract" step 1 both forbid it: delete every line of `ClientProfile.clean()` and that test still passes. Same verdict for a `max_length=200` boundary test on `company_name` (`CharField` owns it) and for a `max_digits`/`decimal_places` test on `max_budget`.

**Genuinely open — omitted-optional-fields coverage.** `website_url` and `company_name` are `blank=True`; `max_budget` is `null=True, blank=True`; `bio` is `blank=True`. A test constructing a `ClientProfile` with only `user` and calling `full_clean()` would fail if `blank=True` were dropped from any of them. That is a model *design* decision, not framework behavior — but it is one assertion covering four fields.

| Option                                                                            | Trade-off                                                                                                                                                                        |
| --------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A** — Add I-1's `company_name` test only; no separate `website_url` coverage.     | Smallest suite. Covers the only `clean()` branch at stake. `blank=True` on `website_url` stays unguarded — a future `blank=False` would break creation without failing this file. |
| **B** — Add one `test_client_profile_minimal_creation_passes_validation` (only `user` set) *in addition to* I-1's test. | Pins the "all client-specific fields are optional" contract in one place. Costs one test. Slight overlap with I-1.                                                              |
| **C** — One test per optional field asserting it may be omitted.                    | Maximum failure attribution, strictly one behavior per test. Four near-identical tests; heaviest maintenance for the least marginal information.                                  |

`testing.md` does not choose between these. Whichever you pick, apply the same decision to `test_freelancer_profile.py` (`portfolio_url`, `hourly_rate`) so the two files stay symmetric.

---

## Observations / Learning Notes — no action needed

### O-1 — The new `company_name` test is sound

The test added at `test_client_profile.py:92-103` is **not** tautological, which is the trap `testing.md` warns about for `URLField`. Django's model-level `CharField` does not strip; `Field.validate()` treats only `[None, "", [], (), {}]` as empty, so `"   "` reaches `ClientProfile.clean()` intact and the `company_name_empty` branch is genuinely reachable. Delete `client_profile.py:145-154` and the test fails — it earns its place. The assertion shape (key check, then `.code`) follows `testing.md` → "ValidationError assertions in tests" exactly.

### O-2 — Typos ("digitação")

| Where                        | Text                                                        | Should read                                                          |
| ---------------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------- |
| `test_client_profile.py:96`  | `withespace`                                                | `whitespace`                                                          |
| `test_client_profile.py:96`  | `Validation_Error`                                          | `ValidationError` (and quote the code as `'company_name_empty'`, matching line 51) |
| `test_client_profile.py:96`  | docstring ends without a period                             | terminate the sentence, as every other docstring in the file does     |
| `test_client_profile.py:96`  | "A company_name provided with only withespace"              | e.g. "A company_name containing only whitespace…"                     |
| `test_client_profile.py:51`  | `"""An max budget <= 0 …`                                   | `A max budget` — copied from `test_freelancer_profile.py:63`, where `An hourly rate` was correct |

No typos found in test names, fixture names, or assertion strings.

### O-3 — Stray whitespace in the model file (uncommitted)

`git diff` shows the only working-tree change to `client_profile.py` is two blank lines appended at EOF (`client_profile.py:170-172`). It looks accidental and will trip `W391` under flake8/ruff. Cosmetic; mentioned so it is not committed unnoticed.

### O-4 — `test_client_profile_creation_and_saving` — name says "and", body is defensible

Seven assertions in one test (`:25-37`). This *does* fall under `testing.md`'s shared-expensive-setup exception: all assertions are facets of one object returned by a single `.get()`, and the setup persists a `Client` plus a `ClientProfile`. Only the name is imprecise ("creation_and_saving" describes one round-trip, not two behaviors). Identical to `test_freelancer_profile.py:26`. No action; noted so it is not mistaken for a violation of I-3's rule.

### O-5 — `assert profile.max_budget is None` is near-tautological

At `:79` (and `:203` in the freelancer file) the assertion restates the value assigned two lines above. The behavior actually under test is "`full_clean()` does not raise", which the call itself already expresses. Harmless, and it mirrors the established pattern — flagged only so the pattern is not copied into new files as if it carried information.

### O-6 — Correct DB-access declarations throughout

`test_client_profile_inherits_from_profile_class` (`:20`) and `test_client_profile_ordering` (`:240`) correctly omit `@pytest.mark.django_db` — pure introspection, no query. Every test calling `full_clean()`, `.create()`, or `.get()` carries the marker, including those whose fixtures already depend on `db` — which is what `testing.md` → "`db` fixture vs `@pytest.mark.django_db` marker" prescribes.

### O-7 — Imports and fixtures are clean

All eight imports are used (`time`, `Decimal`, `pytest`, `ValidationError`, `IntegrityError`, `models`, `transaction`, `Client`, `Profile`, `ClientProfile`, `Skill`); ordering follows stdlib → Django → local. The `conftest.py` additions comply with the "no override consumers" exception (`client_user` hardcodes its `create_user(...)` call rather than composing dict fixtures — correct, since no test overrides a `Client` field), and `valid_client_profile_data` is annotated `-> dict` unparametrized, matching the heterogeneous-dict rule.

One inconsistency, purely cosmetic: `client_user` uses `"Secure!Pass@123"` while `freelancer_user` uses `"SecurePass@123"`. Both satisfy the validators; no test depends on either value.

### O-8 — Skills seeded by migration are correctly not assumed

`test_client_profile_get_display_info` and `test_add_and_remove_interests` create their `Skill` rows explicitly instead of relying on `profiles/migrations/0002_seed_skills.py`, which `--no-migrations` skips. This is exactly what `testing.md` → "Note on `--no-migrations` and data migrations" requires.

---

## Handoff — next session

**Audited.** `django_version/profiles/tests/models/test_client_profile.py`, compared field-by-field and branch-by-branch against `profiles/models/client_profile.py` (plus its base `Profile`), and cross-checked against `test_freelancer_profile.py` for pattern symmetry.

**Counts.** 4 Issues · 1 Open Decision · 8 Observations.

**Blocking on the user.** OD-1 must be decided before I-1 is implemented (option B changes what gets written).

**Files to attach next session.**

- `django_version/profiles/tests/models/test_client_profile.py` (primary)
- `django_version/profiles/tests/models/test_freelancer_profile.py` (I-3 and OD-1 apply to it symmetrically)
- `django_version/profiles/tests/conftest.py`
- `django_version/profiles/models/client_profile.py`
- `django_version/profiles/models/base.py`
- `.claude/rules/testing.md`

**Recommended persona.** `DEVELOPER.md` for I-1, I-2, I-4 and the O-2 typos (mechanical, single correct fix each). `PLANNER.md` first if OD-1 is answered with option B or C, or if I-3 is to be resolved across both test files in one pass.

**Verification command.** `docker-compose exec web pytest profiles/tests/models/test_client_profile.py` — the file has not been executed as part of this audit; findings are from static review only.
