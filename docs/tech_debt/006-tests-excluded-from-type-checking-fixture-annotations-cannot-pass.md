# Technical Debt — Test code is excluded from type checking, and its fixture annotations could not pass it

**Status:** deferred
**Date recorded:** 2026-08-17
**Area:** `accounts/tests/`, `profiles/tests/`, `.claude/rules/testing.md`,
the `[tool.mypy]` table in `django_version/pyproject.toml`
**Applies to:** the baseline data fixtures (`valid_user_data`, `valid_freelancer_data`,
`valid_client_data`) and every test that reaches a manager through
`**{**valid_<model>_data, "field": value}`
**Related:** decision D10 in `docs/plan/plan_toolchain-ci-security_2026-08-15.md`, which
adopts `mypy` + `django-stubs` at production-only scope and defers the test scope here;
Open Decision 1 of `docs/audits/2026-08-17-audit-plan-toolchain-d10-d15.md`, which first
measured the collision; the *Type hints in tests and fixtures* section of
`.claude/rules/testing.md`, which is the rule this entry would eventually change

## The gap

D10 adds a type checker and points it at production code only. `accounts/tests/` and
`profiles/tests/` are outside its scope, so the type hints those files carry — which
`.claude/rules/conventions.md` mandates on every function and method — remain unverified
there. The suite is the larger half of the codebase by file count, and nothing checks its
annotations.

The scope was not chosen for convenience. Test code was measured and **cannot pass a type
check as currently written**, and the reason is a rule this project wrote down.

## What was measured

Run on 2026-08-17 from `django_version/`, disposably via `uvx`, with nothing installed into
the project and no file modified:

- `mypy 2.3.1`, `django-stubs[compatible-mypy] 6.1.0`, `django 6.1`, `psycopg[binary]`,
  `argon2-cffi`, `python-dotenv`
- the `django-stubs` plugin enabled, with `django_settings_module = config.settings`
- targets `accounts profiles config manage.py` — 68 source files
- default (non-strict) settings

Django 6.1 is the version D10's sibling decision D16 moves the project to; the pin at the
time of measurement was still 6.0.7.

**Result: 120 errors in 22 files, exit 1.**

| Error code | Count |
| --- | --- |
| `arg-type` | 61 |
| `attr-defined` | 20 |
| `import-not-found` | 18 |
| `return-value` | 7 |
| `misc` | 7 |
| `assignment` | 3 |
| `union-attr` | 2 |
| `var-annotated` | 1 |
| `override` | 1 |

By area: **18 in production code, 102 in test code.**

| Production file | Errors |
| --- | --- |
| `accounts/admin.py` | 12 |
| `accounts/models/base.py` | 4 |
| `profiles/admin.py` | 1 |
| `config/settings.py` | 1 |

All 18 `import-not-found` are `Cannot find implementation or library stub for module named
"pytest"` — an artifact of the disposable environment, which carried no `pytest`. They are
not a real finding and disappear when the check runs inside the project environment. The
audit's independent run, which had `pytest` present, reported 102 errors with an otherwise
identical breakdown.

### The dominant finding, and its actual cause

**60 of the 61 `arg-type` errors are `**` dict unpacking into
`BaseUserManager.create_user` / `create_superuser`.** The remaining one is unrelated (a
`None` passed where a `ModelForm` is expected, in `accounts/tests/admin/test_admin.py`).

| Type mypy inferred at the call | Errors | Where it comes from |
| --- | --- | --- |
| `dict[str, str \| bool]` | 36 | a fixture annotated with the union |
| `dict[str, object]` | 24 | an inline merge that injects a non-string |

They span **30 call sites across 9 files**, concentrated in
`accounts/tests/admin/test_admin.py` (14 sites) and `accounts/tests/models/test_base.py`
(5 sites).

**The cause is not the merge-and-override idiom.** It is the presence of a non-string value
in the dict. Measured on `accounts/tests/models/test_base.py`, where both shapes sit side by
side:

| Test | Override injects | mypy |
| --- | --- | --- |
| `test_create_user_normalizes_email` | a `str` | passes clean |
| `test_create_user_email_empty_raises_validation_error` | a `str` | passes clean |
| `test_create_user_invalid_email_raises_validation_error` | a `str` | passes clean |
| `test_create_user_accepts_extra_fields` | `is_available` (`bool`) | `arg-type` |
| `test_create_super_user_with_is_staff_false_raises_value_error` | `is_staff` (`bool`) | `arg-type` |
| `test_create_super_user_with_is_superuser_false_raises_value_error` | `is_superuser` (`bool`) | `arg-type` |
| `test_create_user_rejects_superuser_without_staff_status` | `is_staff`, `is_superuser` | `arg-type` |
| `test_create_user_rejects_non_staff_model_with_privileges` | `is_staff`, `is_superuser` | `arg-type` |

### Why mypy refuses, and why it is right to

`create_user` is declared in `accounts/models/base.py` as
`(email: str, name: str, password: str | None = None, **extra_fields: Any)`.

When a dict is unpacked into a call, the checker has only the dict's *value* type — it
cannot know which key fills which parameter. `dict[str, str]` satisfies every parameter.
`dict[str, str | bool]` does not: the annotation genuinely permits `{"email": True}`, so
refusing it is correct behaviour, not a false positive.

This lands on one line of `.claude/rules/testing.md` — the *Dict fixtures — homogeneous vs
heterogeneous* rule, which prescribes a union for "slightly heterogeneous" fixtures. That
rule was written for the human reading the fixture, before any type checker existed in this
project. Two fixtures carry the union today: `valid_freelancer_data` in
`accounts/tests/conftest.py` and `valid_freelancer_data` in `profiles/tests/conftest.py`.

Nothing else about the fixture pattern is implicated. Returning a plain `dict` rather than a
saved instance, composing fixtures by unpacking, and overriding a field per test are all
unaffected.

### The three remedies, each measured rather than assumed

| Remedy | Effect on the 60 errors | What it costs |
| --- | --- | --- |
| Annotate the baseline fixtures `dict[str, Any]` (or bare `dict`) | all 60 disappear, including the inline merges downstream | buys silence by asserting nothing; the same shape D9a rejected as a principle |
| Adopt `TypedDict` for the fixtures | all 60 disappear **and** a wrong override becomes an error naming the field | ~30 call sites gain a line each — see the composition caveat |
| Leave tests out of scope | none — they are simply unchecked | the annotations in the suite stay unverified |

**The `TypedDict` composition caveat, measured.** A `TypedDict` does not survive an inline
merge. Given `td: FreelancerData`:

```python
create_user(**td)                              # accepted
create_user(**{**td, "email": "x@y.com"})      # rejected — inferred dict[str, object]

data: FreelancerData = {**td, "email": "x@y.com"}   # re-annotating restores the type
create_user(**data)                                  # accepted
```

So adopting `TypedDict` requires binding each merge to an annotated variable first, or
building it through the constructor form `FreelancerData(**{...})`, or `copy()`-and-mutate.
All three were measured as accepted.

The payoff is equally concrete. With the merge re-annotated, a wrong value is caught at the
assignment and named:

```
error: Incompatible types (expression has type "int",
       TypedDict item "email" has type "str")  [typeddict-item]
```

Nothing catches that today.

## Why it is deferred, not implemented

**The measured value is in production code, and it is available now.** 18 errors, 12 of them
in `accounts/admin.py`, are what a type checker buys this project today. Extending scope to
tests changes 30 call sites and a rule file to surface errors that are, on inspection,
annotation imprecision in fixtures rather than defects in the code under test. The suite is
green and its behaviour is not in question.

**Changing the testing convention is a decision in its own right, not a side effect.**
`.claude/rules/testing.md` is auto-loaded into every session and governs how every future
test is written. Rewriting its fixture-annotation rule while deciding which type checker to
install would smuggle a convention change through a tooling decision — the same coupling
this whole replanning exists to stop.

**The cheap remedy is the wrong one.** Loosening the baseline fixtures to `dict[str, Any]`
would clear all 60 errors today with two edits, and it is exactly the move to avoid: it makes
the annotation weaker than what the project already has, in order to satisfy a checker. If
tests come into scope, they come in through `TypedDict`, which is stronger than today, not
weaker.

**Delivery speed is the reason, and it is a legitimate one at MVP stage.** This is a
deliberate deferral, not an oversight.

## Reversal criteria

Any one of these makes the deferral wrong, and the test scope should be taken on then:

1. **A defect reaches the suite that a type check would have caught** — a fixture handing a
   manager a value of the wrong type, surfacing as a confusing test failure rather than a
   clear one.
2. **DRF arrives (Phase 3) and tests start exercising serializers.** Serializer input is
   dict-shaped and heterogeneous by nature, which is where `TypedDict` earns its cost rather
   than merely paying it.
3. **The fixture set grows past the two conftest files.** A third app with its own
   `valid_<model>_data` fixtures multiplies the imprecision before anything verifies it.
4. **`.claude/rules/testing.md` is being revised for another reason.** The annotation rule
   should be settled in that pass rather than left to disagree with a tool the project runs.

## What to do when one of them fires

1. **Take it as its own decision, with its own entry in the plan or an ADR.** The decision is
   *"test fixtures are typed with `TypedDict`, and the suite enters the type checker's
   scope"* — a convention change first, a tooling change second.
2. **Define the fixture types where the fixtures live** — `UserData`, and
   `FreelancerData(UserData)` adding `is_available` — in each app's `conftest.py`, so the
   composition rule `testing.md` already prescribes carries over to types unchanged.
3. **Convert the 30 call sites to bind the merge before unpacking.** Prefer the annotated
   local (`data: FreelancerData = {**base, "field": value}`) over the constructor form: it
   reads closest to what the tests do today and is where the `typeddict-item` diagnostic
   lands.
4. **Rewrite the *Dict fixtures — homogeneous vs heterogeneous* rule in
   `.claude/rules/testing.md`.** The union guidance and the "strongly heterogeneous → plain
   `dict`" escape hatch both stop being correct once `TypedDict` is the pattern.
5. **Remove the test exclusion from the `[tool.mypy]` table last**, so the errors it then
   reports are the ones the conversion missed rather than the ones it exists to fix.
6. **Do not reach for `disable_error_code` scoped at the whole test tree.** Suppressing the
   rule rather than the directory is the principle D9a settled for `ruff`, and it applies
   unchanged here.
