# Verification — `mypy` adoption: the T5 collision, T6's real baseline, and the strictness flags

**Date:** 2026-08-29
**Tree:** `feature/django-refactor`
**Status:** **Verification complete. Every fix recorded here was executed and observed.**
No task entry, scope statement or acceptance criterion is written here — **this file is evidence,
not a plan.** The plan is `docs/plan/plan_toolchain-ci-security_2026-08-15.md`, and amending it is
the next session's work.

This file verifies `docs/plan/plan_toolchain-ci-security_2026-08-15.md` — specifically its **T6**
(`mypy`: fix the 18 production errors) and the decision behind it, **D10**. It supersedes nothing.
It records what measurement found when T6 was picked up for implementation, and what a verified
fix for each finding looks like.

Nothing in this file is written from training data. Every number below was produced by a command
executed on this machine on 2026-08-29 and is reproducible with the invocation in
_Measurement environment_. The complete set of verified edits is reproduced verbatim in
_Appendix — the verified diff_.

---

## Why this file exists

T6 states a baseline of **18 production errors in 4 files**. Measured on 2026-08-29, the real
baseline is **24 errors in 7 files**. The gap is not measurement error — it is caused by **T5**,
which landed after D10 took its measurement. Three of the seven files are outside T6's declared
scope, so T6 as written no longer describes the work in front of the Developer.

A second question was raised by the user while reviewing T6 and is answered here: whether a type
checker would produce false positives against Django's runtime dynamism, and whether adopting
`mypy` without `--strict` leaves the tool doing anything useful at all.

---

## Measurement environment

Run from `django_version/`. Nothing installed into the project, no project file modified, the
mypy cache directed outside the repository. `django_version/.env` supplies `SECRET_KEY`, which
the plugin needs because it initialises the Django app registry.

```
uvx --python 3.14 \
  --from "django-stubs[compatible-mypy]==6.1.0" \
  --with "django==6.1" --with "psycopg[binary]==3.3.4" --with "psycopg-pool==3.3.1" \
  --with "argon2-cffi==25.1.0" --with "python-dotenv==1.2.2" \
  mypy --config-file <throwaway>/mypy_probe.toml \
       --cache-dir <throwaway>/cache \
       --exclude '^(accounts|profiles)/tests/' \
       accounts profiles config manage.py
```

The throwaway config carries only what D10 specifies:

```toml
[tool.mypy]
plugins = ["mypy_django_plugin.main"]

[tool.django-stubs]
django_settings_module = "config.settings"
```

Resolved versions: **mypy 2.3.1**, **django-stubs 6.1.0** — the same pair D10 measured, and the
current latest of both on PyPI as of 2026-08-29. Host `uv` is 0.12.6; `.python-version` is
3.14.7.

`.mypy_cache/` was created inside `django_version/` by the first run before `--cache-dir` was
added, and was removed. `git status` is clean.

---

## Result 1 — the baseline is 24, not 18

`Found 24 errors in 7 files (checked 43 source files)`, exit 1.

| File | Errors | In T6's declared scope? |
| ---- | ------ | ----------------------- |
| `accounts/admin.py` | 15 | yes |
| `accounts/models/base.py` | 4 | yes |
| `profiles/admin.py` | 1 | yes |
| `config/settings.py` | 1 | yes |
| `accounts/models/freelancer.py` | 1 | **no** |
| `accounts/models/staff_user.py` | 1 | **no** |
| `profiles/models/skill.py` | 1 | **no** |

By error code: `attr-defined` 8, `misc` 6, `return-value` 3, `assignment` 3, `union-attr` 2,
`var-annotated` 1, `override` 1.

### The full baseline output, verbatim

```
accounts/models/base.py:87: error: "_T" has no attribute "set_password"  [attr-defined]
accounts/models/base.py:91: error: "_T" has no attribute "set_unusable_password"  [attr-defined]
accounts/models/base.py:96: error: "_T" has no attribute "id"  [attr-defined]
accounts/models/base.py:98: error: Incompatible return value type (got "_T", expected "BaseUser")  [return-value]
accounts/models/staff_user.py:55: error: Incompatible types in assignment (expression has type "list[CheckConstraint]", base class "TypedModelMeta" defined the type as "list[BaseConstraint] | tuple[BaseConstraint, ...]")  [assignment]
config/settings.py:24: error: Need type annotation for "ALLOWED_HOSTS" (hint: "ALLOWED_HOSTS: list[<type>] = ...")  [var-annotated]
profiles/models/skill.py:76: error: Incompatible types in assignment (expression has type "list[UniqueConstraint]", base class "TypedModelMeta" defined the type as "list[BaseConstraint] | tuple[BaseConstraint, ...]")  [assignment]
accounts/models/freelancer.py:58: error: Incompatible types in assignment (expression has type "list[CheckConstraint]", base class "TypedModelMeta" defined the type as "list[BaseConstraint] | tuple[BaseConstraint, ...]")  [assignment]
profiles/admin.py:52: error: Argument 1 of "get_deleted_objects" is incompatible with supertype "django.contrib.admin.options.ModelAdmin"; supertype defines the argument type as "Sequence[Any] | QuerySet[Any, Any]"  [override]
profiles/admin.py:52: note: This violates the Liskov substitution principle
accounts/admin.py:99: error: "ProfileInlineForm" has no attribute "_errors"  [attr-defined]
accounts/admin.py:101: error: "ProfileInlineForm" has no attribute "_errors"  [attr-defined]
accounts/admin.py:146: error: Item "None" of "Field | None" has no attribute "widget"  [union-attr]
accounts/admin.py:147: error: Item "None" of "Field | None" has no attribute "widget"  [union-attr]
accounts/admin.py:148: error: Incompatible return value type (got "Field | None", expected "Field")  [return-value]
accounts/admin.py:196: error: Incompatible return value type (got "tuple[tuple[str, _StrPromise], tuple[str, _StrPromise]]", expected "tuple[tuple[str, str], ...]")  [return-value]
accounts/admin.py:212: error: Cannot resolve keyword 'profile' into field. Choices are: created_at, email, is_active, is_staff, is_superuser, last_login, name, password  [misc]
accounts/admin.py:214: error: Cannot resolve keyword 'profile' into field. Choices are: created_at, email, is_active, is_staff, is_superuser, last_login, name, password  [misc]
accounts/admin.py:262: error: "ProfilePresenceMixin" has no attribute "model"  [attr-defined]
accounts/admin.py:264: error: "get_queryset" undefined in superclass  [misc]
accounts/admin.py:275: error: "BaseUser" has no attribute "has_profile"  [attr-defined]
accounts/admin.py:276: error: "BaseUser" has no attribute "has_profile"  [attr-defined]
accounts/admin.py:383: error: Cannot override instance variable (previously declared on base class "ModelAdmin") with class variable  [misc]
accounts/admin.py:571: error: Cannot override instance variable (previously declared on base class "ModelAdmin") with class variable  [misc]
accounts/admin.py:648: error: Cannot override instance variable (previously declared on base class "ModelAdmin") with class variable  [misc]
```

---

## Result 2 — T5 caused six of the twenty-four

D10 measured on 2026-08-17. **T5 closed on 2026-08-28**, eleven days later. Every one of the six
errors that D10 did not see traces to the `typing.ClassVar` annotations T5 introduced to satisfy
ruff's `RUF012`.

| Error | Symbol | Files |
| ----- | ------ | ----- |
| `Cannot override instance variable (previously declared on base class "ModelAdmin") with class variable` | `ModelAdmin.actions` | `accounts/admin.py` ×3 |
| `Incompatible types in assignment … base class "TypedModelMeta" defined the type as "list[BaseConstraint] \| tuple[BaseConstraint, ...]"` | `Meta.constraints` | `accounts/models/freelancer.py`, `accounts/models/staff_user.py`, `profiles/models/skill.py` |

Confirmed by reading each flagged line and by the commits that introduced them: `9c0666c`
(`annotate ModelAdmin.actions with ClassVar in admin.py`), `3dd9f0f` and `c6a06a0`
(`annotate Meta.constraints with ClassVar`), `d69cdcb` (`annotate Meta's class-level attributes
with ClassVar in skill.py`).

**The tension, stated plainly.** The superseding plan records that T5 closed *"in favor of
`typing.ClassVar` annotations over a per-file-ignore, so D9a's suppression principle stays
unamended."* That choice is what mypy now rejects. `ClassVar[list[CheckConstraint]]` narrows a
type django-stubs declares as `list[BaseConstraint]`, and narrowing a mutable container in an
override is unsound — mypy refuses it. The `actions` case is a different refusal: `ModelAdmin`
declares `actions` as an instance variable, and `ClassVar` cannot override an instance variable
at all, whatever the inner type.

**This was not a Planner decision.** T6 does not mention `ClassVar`. The annotation style was
chosen during implementation, without checking it against the task that was already planned to
follow. The lesson belongs in the record: a fix that satisfies one tool must be checked against
the tools the plan has already committed to adopting.

---

## Result 3 — the plugin resolves Django's dynamism; the false-positive fear does not hold

The user asked whether mypy would flag correct Django code it does not understand — citing
`self.user_id` on a `OneToOneField` and attribute access through a relation. Measured, it does
not.

- **`profiles/models/freelancer_profile.py` reports zero errors.** That file uses `self.user_id`
  in `__repr__`, `self.user.name` and `self.skills.values_list()` in `get_display_info()` — the
  three dynamic patterns in question. None was flagged.
- **The strongest evidence is an error, not a silence.** `accounts/admin.py` produces
  `Cannot resolve keyword 'profile' into field. Choices are: created_at, email, is_active,
  is_staff, is_superuser, last_login, name, password`. Enumerating a model's real fields is
  something only the Django plugin can do. The inference is active and deep.
- The three `id: int` declarations carrying `# Type hint for Pylint` comments
  (`accounts/models/base.py`, `profiles/models/skill.py`, `profiles/models/base.py`) produced no
  conflict with the plugin's own inference.

**The errors the user was seeing in the editor are Pylint's, not mypy's.** The message form
`Instance of 'X' has no 'Y' member` is Pylint `E1101`; mypy writes `"X" has no attribute "Y"`
followed by a bracketed error code. No Pylint configuration exists in the repository, so the
editor extension is running on defaults with no Django plugin — which is precisely the tool
shape that produces those false positives, and precisely what `django-stubs` avoids.

**One genuine limitation remains**, and it is small: `"BaseUser" has no attribute "has_profile"`
×2, arising from `.annotate(has_profile=Exists(...))`. A queryset annotation invents an attribute
at runtime that no static checker can see. Two errors, in a file already inside T6's scope.

Corroborating upstream evidence for the `<fk>_id` case: django-stubs issue **#1094**
(*"fk_id is not understood, fk.id is"*) was closed by a maintainer with the resolution
*"This should work when the plugin is enabled"* — the reporter had not enabled the plugin.

---

## Result 4 — nine of the thirteen strict flags cost nothing

Each flag measured individually against the 24-error baseline, same scope, same environment.

| Flag | Total | Δ vs baseline |
| ---- | ----- | ------------- |
| `disallow_incomplete_defs` | 24 | **+0** |
| `check_untyped_defs` | 24 | **+0** |
| `warn_unused_ignores` | 24 | **+0** |
| `warn_redundant_casts` | 24 | **+0** |
| `strict_equality` | 24 | **+0** |
| `no_implicit_reexport` | 24 | **+0** |
| `disallow_subclassing_any` | 24 | **+0** |
| `disallow_untyped_decorators` | 24 | **+0** |
| `extra_checks` | 24 | **+0** |
| `disallow_untyped_calls` | 25 | +1 |
| `warn_return_any` | 25 | +1 |
| `disallow_untyped_defs` | 29 | +5 |
| `disallow_any_generics` | 34 | **+10** |

The twelve cheapest flags together — every flag `--strict` enables **except**
`disallow_any_generics` — cost **+7 errors**, all of them missing annotations rather than wrong
ones:

```
accounts/apps.py:8: error: Function is missing a return type annotation  [no-untyped-def]
profiles/apps.py:8: error: Function is missing a return type annotation  [no-untyped-def]
manage.py:8: error: Function is missing a return type annotation  [no-untyped-def]
profiles/migrations/0002_seed_skills.py:39: error: Function is missing a type annotation  [no-untyped-def]
profiles/migrations/0002_seed_skills.py:48: error: Function is missing a type annotation  [no-untyped-def]
manage.py:23: error: Call to untyped function "main" in typed context  [no-untyped-call]
accounts/admin.py:264: error: Returning Any from function declared to return "QuerySet[BaseUser, BaseUser]"  [no-any-return]
```

`disallow_untyped_defs` is the flag that makes the project's own standard enforceable:
`conventions.md` requires type hints on every function and method signature, and until now
nothing verified it. Its five findings are all genuinely unannotated functions.

### Why the default (non-strict) mode is not weak here

Per mypy's own documentation, default mode *"will not type check dynamically typed functions"* —
a function with no annotations is skipped entirely — while *"once you have added type hints to a
function … mypy will automatically type check that function's body."* The concern that a
non-strict run checks almost nothing applies to codebases without annotations. This project
mandates them, so default mode already checks nearly everything; the flags close the remaining
gap and, critically, stop the standard from silently eroding.

### `disallow_any_generics` — measured, and deferred by the user

Its ten findings are not false positives; they are genuinely unparameterised generics:
`get_display_info() -> dict` in three profile models, `tuple[list, dict, set, list]` in
`profiles/admin.py`, and the django-stubs generics `ModelAdmin`, `ModelForm`, `StackedInline`,
`Field` and `BaseUserManager` used bare. Fixing them spreads across four files outside T6's scope
and, for the admin classes, means parameterising them by model. **The user has deferred this flag
for now.** It is recorded here so a later session does not mistake the omission for an oversight.

---

## The twenty-four, classified by how much judgement each fix needs

| Group | Errors | Files | Judgement required |
| ----- | ------ | ----- | ------------------ |
| **A — mechanical** | 1 | `config/settings.py` | none; mypy states the fix |
| **B — the T5 collision** | 6 | `accounts/admin.py`, `freelancer.py`, `staff_user.py`, `skill.py` | must satisfy ruff and mypy together — **candidates untested** |
| **C — the manager `TypeVar`** | 4 | `accounts/models/base.py` | one fix per T6; the correct bound is **not yet determined** |
| **D — Liskov override** | 1 | `profiles/admin.py` | widen a parameter annotation to the supertype's |
| **E — admin internals** | 9 | `accounts/admin.py` | mixed; some mechanical, some design |
| **F — the modelling question** | 3 | `accounts/admin.py` | **T6 says this returns to the Planner rather than being guessed** |

Group F is `Cannot resolve keyword 'profile'` ×2 and `"ProfilePresenceMixin" has no attribute
"model"`. Both stem from the same root: a queryset and a mixin typed against `BaseUser`, which is
abstract and carries neither the `profile` reverse relation nor a `model` attribute. The code is
correct at runtime — the queryset is always a `Freelancer` or `Client` one. The annotation is
what is wrong, and choosing the right one is a modelling judgement about how a queryset over two
independent concrete models should be typed.

---

## Verification results

Each candidate is applied to a throwaway copy of `django_version/` in a scratch directory —
never the working tree — and must clear every gate before it is allowed into a task entry. The
copy carries no `.env`; `SECRET_KEY` is supplied as a disposable environment variable.

### Group B — SOLVED. A tuple closes all six, with one boundary that must be respected

**The fix.** Replace the annotated mutable list with a plain tuple, and drop the now-unnecessary
`ClassVar`:

| Symbol | From | To |
| ------ | ---- | -- |
| `Meta.constraints` in `Freelancer`, `StaffUser`, `Skill` | `constraints: ClassVar[list[models.CheckConstraint]] = [ … ]` | `constraints = ( … ,)` |
| `ModelAdmin.actions` in `FreelancerAdmin`, `ClientAdmin`, `StaffUserAdmin` | `actions: ClassVar[list[str]] = [ … ]` | `actions = ( … ,)` |

`ClassVar` becomes an unused import in `accounts/models/freelancer.py` and
`accounts/models/staff_user.py`, where `constraints` was its only use, and
`accounts/admin.py` reduces to `from typing import Any`. **`profiles/models/skill.py` keeps the
import** — see the boundary below.

**Why it works on both tools at once.** mypy's own message names
`tuple[BaseConstraint, ...]` as an accepted type for `Meta.constraints`, so a tuple satisfies the
supertype instead of narrowing it. And a tuple is immutable, so ruff's `RUF012` — which exists to
catch a mutable value shared across every instance of a class — has nothing to flag, which is why
the `ClassVar` that caused the collision is no longer needed at all.

**Measured result:** `Found 18 errors in 4 files` — down from 24 in 7. That is exactly D10's
original count and its original file set, which is the strongest available confirmation that the
six extra errors were T5's and nothing else.

| Gate | Result |
| ---- | ------ |
| `mypy` (production scope) | 24 → **18 errors in 4 files** |
| `ruff check .` | **All checks passed** |
| `ruff format --check .` | **76 files already formatted** |
| `manage.py check` | **System check identified no issues (0 silenced)** |
| `manage.py makemigrations --check --dry-run` | **No changes detected** |
| `pytest` | **not yet run** — must run in Docker, see below |

### The boundary — `Meta.ordering` must NOT be converted

The first attempt converted `Meta.ordering` in `profiles/models/skill.py` to a tuple as well,
purely to retire the `ClassVar` import. `makemigrations --check --dry-run` then reported:

```
Migrations for 'profiles':
  profiles/migrations/0008_alter_skill_options.py
    ~ Change Meta options on skill
```

`ordering` is part of a model's **Meta options**, which Django tracks in migration state; changing
its container type is a state change and Django generates an `AlterModelOptions` for it.
`constraints` is not tracked that way and produced no diff. *(Migration state is Django's
recorded picture of what your models looked like at the last migration; `makemigrations` compares
the current models against it, so anything stored in that picture generates a migration when it
changes — even when the database itself would not change.)*

`Meta.ordering` produces **no mypy error** in the baseline. It must be left exactly as it is,
`ClassVar[list[str]]` included, and `profiles/models/skill.py` therefore keeps its
`from typing import ClassVar`. The same applies to `BaseUser.Meta.ordering` in
`accounts/models/base.py`, which was never touched.

**Consequence for the task entry:** the rule is *convert only what mypy actually flags*. Retiring
a `ClassVar` that is not causing an error is not cleanup — it costs a migration.

---

### Group C — SOLVED. One line closes all four

`BaseUserManager` subclasses django-stubs' generic `BaseUserManager` without supplying a type
parameter, so its `_T` stays an unbound `TypeVar` and `self.model(...)` produces a value mypy
knows nothing about.

| From | To |
| ---- | -- |
| `class BaseUserManager(DjangoBaseUserManager):` | `class BaseUserManager(DjangoBaseUserManager["BaseUser"]):` |

*(A generic class is one that takes a type in brackets, the way `list[str]` does. Django's manager
is written to be told which model it manages; left untold, every object it returns is an unknown
to the checker.)*

The forward reference is safe at runtime for two independent reasons: it is a string, and
Django's `BaseManager` implements `__class_getitem__` (`return cls`), so subscripting a manager
is a no-op. Confirmed against Django's `django/db/models/manager.py`.

**Result: 18 → 14.** T6's claim that the four are one fix holds exactly.

### Group A — SOLVED

`ALLOWED_HOSTS = []` → `ALLOWED_HOSTS: list[str] = []`. mypy states the fix in the error itself.
Phase 5 rewrites this line for a real deploy target regardless.

### Group D — SOLVED

`SkillAdmin.get_deleted_objects` declares its first parameter as `QuerySet[Skill] | list[Skill]`,
while the supertype declares `Sequence[Any] | QuerySet[Any, Any]`. A `list` is narrower than a
`Sequence`, and an override may not accept less than the method it replaces.

| From | To |
| ---- | -- |
| `objs: QuerySet[Skill] \| list[Skill]` | `objs: QuerySet[Skill] \| Sequence[Skill]` |

Applied to both `get_deleted_objects` and the `_count_referring_profiles` helper it calls, so the
two signatures stay consistent. `Skill` is preserved — the fix widens the container, not the
element. *(Liskov substitution: code holding the parent class must keep working when handed a
child. Accepting fewer kinds of argument than the parent breaks that.)*

**Result: 14 → 12**, all remaining errors in `accounts/admin.py`, matching T6's "12 of the 18 are
in one file".

### Group E — SOLVED. Three independent fixes, one of them a latent bug

| Error | Fix | Note |
| ----- | --- | ---- |
| `"ProfileInlineForm" has no attribute "_errors"` ×2 | use the public `self.errors` | django-stubs does not declare the private `_errors`. Inside `full_clean()`, after `super().full_clean()` has run, `_errors` is already populated, so the `errors` property returns it without re-entering validation |
| `Item "None" of "Field \| None" has no attribute "widget"` ×2, and the return ×1 | declare `-> forms.Field \| None` and guard with `if formfield is not None and …` | **This is a real latent bug, not a typing complaint.** The supertype returns `FormField \| None`, and Django does return `None` for some fields. The current code would raise `AttributeError` if it ever did |
| `lookups()` returns `_StrPromise`, not `str` | annotate the label as `StrOrPromise` | `gettext_lazy` returns a lazy promise, not a `str`. The supertype declares `Iterable[tuple[str, _StrOrPromise]] \| None` — the project's annotation was simply too narrow |

**Result: 12 → 6.**

#### The `django-stubs-ext` question D10 left open is now answered

D10 carried an open question: whether `django-stubs-ext` is needed, and whether it would be the
one dependency landing in `[project].dependencies` rather than the `dev` group.

**It is a transitive dependency and needs no declaration.** `django_stubs-6.1.0`'s metadata
declares `Requires-Dist: django-stubs-ext>=6.0.2`, so installing `django-stubs` installs it.

**But it must never be imported at runtime.** `django-stubs` lives in the `dev` group, so
anything reaching `django_stubs_ext` at import time would break a production install. The
`StrOrPromise` annotation therefore goes under a `TYPE_CHECKING` guard:

```python
if TYPE_CHECKING:
    from django_stubs_ext import StrOrPromise
```

No quotes on the annotation. Python 3.14 evaluates annotations lazily (PEP 649), so the name is
never resolved at runtime — and ruff's `UP037` actively removes the quotes if they are written.
Verified: `manage.py check` imports `accounts/admin.py` and reports no issues.

`django_stubs_ext.monkeypatch()` is **not** called and is not needed: Django's own `BaseManager`
already implements `__class_getitem__`, and the project types model `Meta` classes directly rather
than through `TypedModelMeta`.

---

## Running tally

| After | Errors | Files |
| ----- | ------ | ----- |
| Baseline | 24 | 7 |
| Group B — the T5 collision | 18 | 4 |
| Group C — the manager `TypeVar` | 14 | 3 |
| Groups A + D | 12 | 1 |
| Group E — admin internals | 6 | 1 |
| Group F — the modelling question | **0** | 0 |

All gates green at every step: `ruff check`, `ruff format --check`, `manage.py check`,
`makemigrations --check --dry-run`.

With the twelve flags additionally enabled, the total is **7** — the seven measured in Result 4,
confirming the flag cost is unchanged by any of these fixes.

---

### Group F — SOLVED. The user chose option A: follow the supertype

Six errors, all in `accounts/admin.py`, all one root cause. `HasProfileFilter` and
`ProfilePresenceMixin` are written against `BaseUser`, which is abstract: it has no `profile`
reverse relation, no `model` attribute, no `get_queryset`, and no `has_profile` — the last
invented at runtime by `.annotate()`. All of them exist on the concrete `Freelancer` and `Client`
that actually flow through this code.

**The options put to the user** were (A) follow what django-stubs itself declares on the
supertype, (B) define a `Protocol` expressing "an account model that has a profile", or (C) a
union of the two concrete models. **The user chose A**, on the reasoning that diverging from the
supertype is what created the problem.

| Site | From | To |
| ---- | ---- | -- |
| `HasProfileFilter.queryset` parameter and return | `QuerySet[BaseUser]` | `QuerySet[Any]` |
| `ProfilePresenceMixin` class statement | `class ProfilePresenceMixin:` | `class ProfilePresenceMixin(_AdminBase):` |
| `ProfilePresenceMixin.get_queryset` return | `QuerySet[BaseUser]` | `QuerySet[Any]` |
| `ProfilePresenceMixin.profile_badge` parameter | `obj: BaseUser` | `obj: Any` |

`_AdminBase` is declared once, beside the existing `TYPE_CHECKING` block:

```python
if TYPE_CHECKING:
    from django_stubs_ext import StrOrPromise

    _AdminBase = admin.ModelAdmin
else:
    _AdminBase = object
```

*(This is the standard way to type a mixin. The mixin is only ever combined with a `ModelAdmin`,
so the checker is told to treat it as one — while at runtime it stays a plain `object` and the
method resolution order is exactly what it was before.)*

`django-stubs` declares `SimpleListFilter.queryset` against `QuerySet[Any]`, so option A brings
the project's annotation back in line with the framework rather than inventing a narrower one.

**Result: 6 → 0.** `mypy` reports `Success: no issues found in 43 source files`.

---

## Final state — verified

| Gate | Result |
| ---- | ------ |
| `mypy`, production scope, no flags | **Success: no issues found in 43 source files** |
| `mypy` + the twelve flags | **7 errors** — exactly the seven already measured, all missing annotations |
| `ruff check .` | **All checks passed** |
| `ruff format --check .` | **76 files already formatted** |
| `python -m py_compile accounts/admin.py` | syntax OK |
| `manage.py check` | **System check identified no issues (0 silenced)** |
| `manage.py makemigrations --check --dry-run` | **No changes detected** |
| `pytest` | **not run** — see below |

---

## Tests still to run

1. ~~Groups A, B, C, D, E and F.~~ **All done — every fix above was executed and observed.**
2. **Regression gate, owned by the user.** The suite runs in Docker per the project's execution
   rule, and the scratch copy has no database. `docker-compose exec web pytest` must be green
   after each group reaches the working tree. `manage.py check` and `makemigrations --check` pass
   at every step, but the suite is the gate that closes it — with particular attention to the
   admin tests covering `ProfileInlineForm.full_clean` and `formfield_for_dbfield`, the two
   Group E fixes that touch behaviour.

**Do not re-measure any number in this file.** Each was produced by an executed command and is
reproducible from _Measurement environment_. A session picking this up should spend its effort on
the task entries, not on repeating the verification.

---

## Open questions for the user

1. **Group F — the modelling question.** Not answerable by measurement, and the only thing
   blocking the step-by-step. See _What remains_ above.
2. **Whether the twelve flags are declared explicitly or as `strict = true` minus one.** Listing
   them by name is more stable across mypy releases, since a future version may add a flag to
   `--strict`. To be decided when the configuration is written.
3. **Whether the T5 collision, once fixed, is recorded as an ADR.** It amends the reasoning
   behind D9a and T5's closure, and the project's convention sends decisions of that kind to
   `docs/adr/`.
4. ~~**Whether `django-stubs-ext` is required, and where it belongs.**~~ **Answered** — see
   _The `django-stubs-ext` question D10 left open is now answered_.

---

## What this session did not touch

The working tree was never modified. Every fix above was applied to a copy under a scratch
directory and verified there; `git status` on `django_version/` is clean. The `.mypy_cache/`
directory created by the first probe run was removed, and every later run wrote its cache outside
the repository.

---

## Suggested phasing — input for the plan, not a plan

Offered to whoever writes the task entries, because it was the shape the verification itself
followed and it keeps the error count small at every step. It is a suggestion, not a decision.

| Phase | What | Errors visible |
| ----- | ---- | -------------- |
| A | Declare `mypy` and `django-stubs` in the `dev` group, add `[tool.mypy]` and `[tool.django-stubs]`, **no flags** | 24 appear |
| B | Fix the 24, in the order A → B → C → D → E → F of the classification above | 24 → 0 |
| C | Enable the twelve flags | +7 appear |
| D | Fix the 7 | 7 → 0 |

The CI step stays where the plan put it: **T7**, a separate task, build-failing from its first
run, after these phases are complete and green.

Note that phase D's seven errors were measured but **not fixed** during this verification. They
are five missing return annotations (`ready()` in both `apps.py`, `main()` in `manage.py`, and
two functions in `profiles/migrations/0002_seed_skills.py`), one untyped call that resolves with
them, and one `no-any-return` in `accounts/admin.py`. Unlike everything in phases A–B, these
carry no verified fix — only a verified diagnosis.

---

## Appendix — the verified diff

Every edit below was applied together and cleared all gates listed in _Final state_.
Paths are relative to `django_version/`. This is a **reference**, not an instruction to
apply blind: the task entries should walk each change with its reasoning, and the user
implements them by hand.

Not included here, because they belong to the configuration rather than the code:
the `mypy` and `django-stubs` entries in the `dev` group, and the `[tool.mypy]` /
`[tool.django-stubs]` tables in `django_version/pyproject.toml`.

```diff
--- a/accounts/models/base.py
+++ b/accounts/models/base.py
@@ -28,7 +28,7 @@
 logger = logging.getLogger(__name__)
 
 
-class BaseUserManager(DjangoBaseUserManager):
+class BaseUserManager(DjangoBaseUserManager["BaseUser"]):
     """
     Custom manager for creating and managing BaseUser instances.
 
--- a/accounts/models/freelancer.py
+++ b/accounts/models/freelancer.py
@@ -7,7 +7,6 @@
 """
 
 import logging
-from typing import ClassVar
 
 from django.core.exceptions import ValidationError
 from django.db import models
@@ -55,12 +54,12 @@
         verbose_name = "Freelancer"
         verbose_name_plural = "Freelancers"
         db_table = "freelancers"
-        constraints: ClassVar[list[models.CheckConstraint]] = [
+        constraints = (
             models.CheckConstraint(
                 condition=~models.Q(is_active=False, is_available=True),
                 name="freelancer_no_inactive_available",
-            )
-        ]
+            ),
+        )
 
     def __repr__(self) -> str:
         """
--- a/accounts/models/staff_user.py
+++ b/accounts/models/staff_user.py
@@ -7,7 +7,6 @@
 """
 
 import logging
-from typing import ClassVar
 
 from django.core.exceptions import ValidationError
 from django.db import models
@@ -52,12 +51,12 @@
         verbose_name = "Staff User"
         verbose_name_plural = "Staff Users"
         db_table = "staff_users"
-        constraints: ClassVar[list[models.CheckConstraint]] = [
+        constraints = (
             models.CheckConstraint(
                 condition=~models.Q(is_active=True, is_staff=False),
                 name="staffuser_active_no_staff_status",
-            )
-        ]
+            ),
+        )
 
     def clean(self) -> None:
         """
--- a/profiles/models/skill.py
+++ b/profiles/models/skill.py
@@ -73,11 +73,11 @@
         verbose_name_plural = _("Skills")
         db_table = "skills"
         ordering: ClassVar[list[str]] = ["category", "name"]
-        constraints: ClassVar[list[models.UniqueConstraint]] = [
+        constraints = (
             models.UniqueConstraint(
                 Lower("name"), name="skill_unique_name_case_insensitive"
-            )
-        ]
+            ),
+        )
 
     def __str__(self) -> str:
         """
--- a/config/settings.py
+++ b/config/settings.py
@@ -21,7 +21,7 @@
 # SECURITY WARNING: don't run with debug turned on in production!
 DEBUG = os.getenv("DEBUG", "False") == "True"
 
-ALLOWED_HOSTS = []
+ALLOWED_HOSTS: list[str] = []
 
 
 # Application definition
--- a/profiles/admin.py
+++ b/profiles/admin.py
@@ -9,6 +9,8 @@
 inlines live in accounts/admin.py.
 """
 
+from collections.abc import Sequence
+
 from django.contrib import admin
 from django.db.models import QuerySet
 from django.http import HttpRequest
@@ -49,7 +51,7 @@
     )
 
     def get_deleted_objects(
-        self, objs: QuerySet[Skill] | list[Skill], request: HttpRequest
+        self, objs: QuerySet[Skill] | Sequence[Skill], request: HttpRequest
     ) -> tuple[list, dict, set, list]:
         """
         Mark the selected skills as protected while profiles still refer to them.
@@ -79,7 +81,7 @@
         return deletable_objects, model_count, perms_needed, protected
 
     @staticmethod
-    def _count_referring_profiles(objs: QuerySet[Skill] | list[Skill]) -> int:
+    def _count_referring_profiles(objs: QuerySet[Skill] | Sequence[Skill]) -> int:
         """
         Count the distinct profiles referring to any of the selected skills.
 
--- a/accounts/admin.py
+++ b/accounts/admin.py
@@ -15,7 +15,7 @@
 admins that own them. This module imports profiles.models, never profiles.admin.
 """
 
-from typing import Any, ClassVar
+from typing import TYPE_CHECKING, Any
 
 from django import forms
 from django.contrib import admin, messages
@@ -37,7 +37,14 @@
 from profiles.models.client_profile import ClientProfile
 from profiles.models.freelancer_profile import FreelancerProfile
 
+if TYPE_CHECKING:
+    from django_stubs_ext import StrOrPromise
 
+    _AdminBase = admin.ModelAdmin
+else:
+    _AdminBase = object
+
+
 class BaseAccountAdmin(admin.ModelAdmin):
     """
     Base admin holding the behavior shared by all account admins.
@@ -96,9 +103,9 @@
         super().full_clean()
         hidden_fields_with_errors = {
             name for name, field in self.fields.items() if field.widget.is_hidden
-        } & set(self._errors)
+        } & set(self.errors)
         for name in hidden_fields_with_errors:
-            for error in self._errors.pop(name).as_data():
+            for error in self.errors.pop(name).as_data():
                 self.add_error(None, error)
 
 
@@ -130,7 +137,7 @@
 
     def formfield_for_dbfield(
         self, db_field: models.Field, request: HttpRequest, **kwargs: Any
-    ) -> forms.Field:
+    ) -> forms.Field | None:
         """
         Strip the add-related control from every related field on the section.
 
@@ -143,7 +150,9 @@
                 it renders a related field.
         """
         formfield = super().formfield_for_dbfield(db_field, request, **kwargs)
-        if isinstance(formfield.widget, RelatedFieldWidgetWrapper):
+        if formfield is not None and isinstance(
+            formfield.widget, RelatedFieldWidgetWrapper
+        ):
             formfield.widget.can_add_related = False
         return formfield
 
@@ -186,7 +195,7 @@
 
     def lookups(
         self, request: HttpRequest, model_admin: admin.ModelAdmin
-    ) -> tuple[tuple[str, str], ...]:
+    ) -> tuple[tuple[str, StrOrPromise], ...]:
         """
         List the two groups an administrator can narrow the list to.
 
@@ -198,9 +207,7 @@
             ("no", _("Without a profile")),
         )
 
-    def queryset(
-        self, request: HttpRequest, queryset: QuerySet[BaseUser]
-    ) -> QuerySet[BaseUser]:
+    def queryset(self, request: HttpRequest, queryset: QuerySet[Any]) -> QuerySet[Any]:
         """
         Narrow the list to the group the administrator selected.
 
@@ -238,7 +245,7 @@
         return self.lookup_val is not None or super().has_output()
 
 
-class ProfilePresenceMixin:
+class ProfilePresenceMixin(_AdminBase):
     """
     Mixin providing the profile presence badge on an account list.
 
@@ -249,7 +256,7 @@
     the reverse accessor, which would cost one query per row.
     """
 
-    def get_queryset(self, request: HttpRequest) -> QuerySet[BaseUser]:
+    def get_queryset(self, request: HttpRequest) -> QuerySet[Any]:
         """
         Annotate every account on the page with whether it has a profile.
 
@@ -264,7 +271,7 @@
         return super().get_queryset(request).annotate(has_profile=Exists(profiles))
 
     @admin.display(description=_("Profile"))
-    def profile_badge(self, obj: BaseUser) -> SafeString:
+    def profile_badge(self, obj: Any) -> SafeString:
         """
         Build the profile presence badge for list display.
 
@@ -380,11 +387,11 @@
 
     inlines = (FreelancerProfileInline,)
 
-    actions: ClassVar[list[str]] = [
+    actions = (
         "activate_accounts",
         "set_available",
         "set_unavailable",
-    ]
+    )
 
     @admin.display(description=_("Availability"))
     def availability_badge(self, obj: Freelancer) -> SafeString:
@@ -568,7 +575,7 @@
 
     inlines = (ClientProfileInline,)
 
-    actions: ClassVar[list[str]] = ["activate_accounts"]
+    actions = ("activate_accounts",)
 
     @admin.action(description=_("Activate selected accounts"))
     def activate_accounts(
@@ -645,7 +652,7 @@
         ),
     )
 
-    actions: ClassVar[list[str]] = ["activate_accounts", "deactivate_accounts"]
+    actions = ("activate_accounts", "deactivate_accounts")
 
     @admin.action(description=_("Deactivate selected accounts"))
     def deactivate_accounts(
```
