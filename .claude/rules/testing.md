# SkillBridge — Testing Conventions

Load this file for every task that involves creating or modifying test files.

This is the single source of truth for testing rules in SkillBridge. For
the rationale behind architectural decisions (clean() patterns, layer
ownership, validator design), consult `conventions.md`. For absolute
behavior rules across the project, consult `CLAUDE.md`.

---

## Framework and runner

- **pytest-django** — no `unittest.TestCase`, no Django test client unless
  explicitly required.
- All tests run inside Docker: `docker-compose exec web pytest`.
- Configuration lives in `pytest.ini`. Active flags: `--no-migrations`,
  `--reuse-db`, `--strict-markers`, `--tb=short`, `-v`.

---

## File and folder structure

Test files mirror the source file being tested, one-to-one:

```
accounts/
  models/
    base.py
    freelancer.py
  tests/
    conftest.py           ← shared fixtures for app
    models/
      test_base.py        ← tests for accounts/models/base.py
      test_freelancer.py  ← tests for accounts/models/freelancer.py
    validators/
      test_validate_email.py
      test_validate_password.py

profiles/
  models/
    base.py
    freelancer_profile.py
  tests/
    conftest.py           ← shared fixtures for profiles app
    models/
      test_base.py
      test_freelancer_profile.py
```

Every test folder must have an `__init__.py`. Create it alongside the
test file.

---

## conftest.py — required before test files

Every app with tests must have a `conftest.py` at the `tests/` level.

**What belongs in `conftest.py`:**

- Shared fixtures used across multiple test files in the same app.
- Concrete dummy subclasses of abstract models, when no concrete subclass
  exists yet (see "Abstract models — testing strategy").
- Data fixtures (dicts, not saved instances) for flexibility.
- Saved instance fixtures only when multiple tests require a persisted
  object.

**What does NOT belong in `conftest.py`:**

- Test functions.
- Imports unused by any fixture.
- Fixtures used by only one test file — keep those local.

### Established pattern — `accounts/tests/conftest.py`

```python
"""Shared fixtures for accounts app tests."""
import pytest

from accounts.models.client import Client
from accounts.models.freelancer import Freelancer


@pytest.fixture
def valid_user_data() -> dict[str, str]:
    """Valid base data for creating any user.

    Returns a dict (not an object) for unpacking flexibility.
    """
    return {
        "email": "testuser@example.com",
        "name": "Test User",
        "password": "SecurePass@123",
    }


@pytest.fixture
def freelancer_user(db, valid_freelancer_data: dict[str, str | bool]) -> Freelancer:
    """Create and return a Freelancer instance saved in the test database."""
    return Freelancer.objects.create_user(**valid_freelancer_data)
```

Note the `db` parameter on `freelancer_user`. This is the pytest-django
fixture that grants database access to the fixture itself. See "Database
access in tests" below for the full mechanism.

---

## Data fixtures pattern — dicts and overrides

Always prefer returning a plain Python `dict` of valid model fields from
baseline data fixtures, rather than a persisted model instance or
pre-instantiated object.

### Baseline data fixture rule

Name baseline data fixtures `valid_<model_name>_data`. They must return a
`dict` of complete, valid parameters that can be unpacked to construct or
save the model.

```python
@pytest.fixture
def valid_user_data() -> dict[str, str]:
    """Valid base data for creating any user."""
    return {
        "email": "testuser@example.com",
        "name": "Test User",
        "password": "SecurePass@123",
    }
```

### Composition and inheritance rule

If a model builds upon or references another model, compose dictionaries
in `conftest.py` rather than duplicating keys:

```python
@pytest.fixture
def valid_freelancer_data(valid_user_data: dict[str, str]) -> dict[str, str | bool]:
    """Valid data to create a Freelancer user, inheriting from valid_user_data."""
    return {
        **valid_user_data,
        "is_available": True,
    }
```

### Exception — no override consumers

Composing a `valid_<related_model>_data` dict fixture (and the entity that
depends on it) is required only when at least one test actually needs to
override a field on that related model via
`{**valid_<related_model>_data, "field": value}`.

If no test in the app overrides any field of the related model, hardcoding
the literal values inline in the dependent fixture is acceptable and
preferred over adding a dict fixture with zero consumers. A dict fixture
with no override consumer is dead flexibility, not a composition gain.

Example: `profiles/tests/conftest.py`'s `freelancer_user` fixture hardcodes
its `Freelancer.objects.create_user(...)` call instead of composing
`valid_user_data` → `valid_freelancer_data`, as `accounts/tests/conftest.py`
does. This is correct: no test in `profiles/tests/` overrides an email,
name, password, or `is_available` value — every override in that app
targets profile fields (`hourly_rate`, `bio`, `portfolio_url`), never
freelancer fields. Adding `valid_user_data` and `valid_freelancer_data`
there would introduce two fixtures with no override consumer.

This exception stops applying the moment a test needs to override a field
on the related model — at that point, compose the dict fixtures per the
rule above.

### Merging and overriding in tests

When testing invalid inputs, edge cases, or boundary conditions, use
double-asterisk unpacking with dict merge (`{**valid_data, "field": value}`)
to mutate only the fields under test:

```python
@pytest.mark.django_db
def test_clean_method_raises_validation_error_for_superuser_without_staff_status(
    valid_user_data: dict[str, str],
) -> None:
    """Test that full_clean() raises ValidationError when is_superuser is True but is_staff is False."""
    user = StaffUser(
        **{
            **valid_user_data,
            "is_superuser": True,
            "is_staff": False,
        }
    )

    with pytest.raises(ValidationError) as exc_info:
        user.full_clean()

    assert "is_staff" in exc_info.value.error_dict
    assert exc_info.value.error_dict["is_staff"][0].code == "superuser_without_staff"

```

---

## Type hints in tests and fixtures

Write standard, clean type hints on test functions and fixtures.
Annotations document intent, support IDE autocompletion, and make
parameter signatures self-explanatory.

### Rules

- Test functions must always have return type `-> None`.
- Test function arguments and your own fixture inputs must have explicit
  type annotations.
- Fixtures must have a return type annotation.
- **Exception — pytest-django built-in fixtures** (`db`, `transactional_db`,
  `settings`, `client`, `admin_client`, etc.) do **not** require
  annotations. They are typed internally by the plugin and annotating
  them adds noise without benefit.

### Dict fixtures — homogeneous vs heterogeneous

The return type of a data fixture depends on the value types it contains.

**Homogeneous dict — parameterize fully:**

```python
@pytest.fixture
def valid_user_data() -> dict[str, str]:
    return {
        "email": "testuser@example.com",
        "name": "Test User",
        "password": "SecurePass@123",
    }
```

**Slightly heterogeneous (small, known union) — parameterize with union:**

```python
@pytest.fixture
def valid_freelancer_data(valid_user_data: dict[str, str]) -> dict[str, str | bool]:
    return {
        **valid_user_data,
        "is_available": True,
    }
```

**Strongly heterogeneous (model instances, Decimal, int, str) — return
unparametrized `dict`:**

```python
@pytest.fixture
def valid_freelancer_profile_data(freelancer_user: Freelancer) -> dict:
    """Valid data to create a FreelancerProfile instance."""
    return {
        "user": freelancer_user,
        "hourly_rate": Decimal("50.00"),
        "portfolio_url": "https://portfolio.example.com",
        "years_of_experience": 5,
        "bio": "Experienced Python developer looking for collaboration",
    }
```

Forcing a long union (`dict[str, str | int | Decimal | Freelancer]`) hurts
readability and breaks every time a field is added. Plain `dict` is
acceptable when the value types span multiple categories.

Never mix annotation styles for the same kind of fixture within the same
`conftest.py`.

---

## Abstract models — testing strategy

Abstract models (`abstract = True`) cannot be instantiated directly.
**Never write `AbstractModel(field=value)` in a test.**

### Preferred — use the most complete concrete subclass

When the app already has concrete subclasses (the default in SkillBridge),
test the abstract base behavior through the most complete concrete model.
This is the established pattern in `accounts/tests/models/test_base.py`,
which uses `Freelancer` to test `BaseUser` and `BaseUserManager`:

```python
# accounts/tests/models/test_base.py
"""
Tests for BaseUserManager (create_user and create_superuser methods).

Uses Freelancer as the concrete model since BaseUser is abstract.
Freelancer is the most complete concrete model (has is_available field).
"""

@pytest.mark.django_db
def test_create_user_saves_to_database(valid_user_data: dict[str, str]) -> None:
    user = Freelancer.objects.create_user(**valid_user_data)
    assert user.id is not None
```

Rationale: the concrete model exists, has real migrations, real database
tables, and matches the production codepath. No dummy class needed.

### Exception — abstraction without a concrete subclass yet

If a new abstract model is introduced before any concrete subclass exists,
define a dummy concrete subclass in `conftest.py`. This is rare and should
disappear once real concretes are implemented.

```python
# profiles/tests/conftest.py

class DummyProfile(Profile):
    """Concrete dummy subclass for testing Profile base behavior."""

    class Meta:
        app_label = "profiles"

    def get_display_info(self) -> dict:
        """Return minimal display info for testing."""
        return {"dummy": "info"}


@pytest.fixture(scope="function")
def dummy_profile_class() -> type[DummyProfile]:
    """Provide the DummyProfile class for instantiation in tests."""
    return DummyProfile
```

Never define dummy subclasses inside a test file — they belong in
`conftest.py` for reuse.

### Second exception — deliberately incomplete dummy, testing enforcement

The exception above covers a dummy that stands in for a concrete subclass
before one exists, and it implements the abstract contract. A second,
independent exception applies even after concrete subclasses exist:

A dummy concrete subclass that deliberately does **not** implement an
abstract method is permitted in `conftest.py` specifically to test item 3
of "What to test in an abstract base model" — **Abstract method
enforcement**, i.e. that `NotImplementedError` is raised on an
unimplemented subclass. No concrete subclass can exercise this case, since
every concrete subclass is, by definition, complete.

```python
# profiles/tests/conftest.py

class UnimplementedProfile(Profile):
    """Concrete dummy subclass of Profile that does not implement get_display_info.

    Used to test that NotImplementedError is raised appropriately on incomplete subclasses.
    """

    class Meta:
        app_label = "profiles"


@pytest.fixture(scope="function")
def unimplemented_profile() -> UnimplementedProfile:
    """Provide an unsaved instance of UnimplementedProfile."""
    return UnimplementedProfile()
```

This dummy is named for what it deliberately does _not_ do
(`UnimplementedProfile`), distinct from `DummyProfile` above, which
implements the contract. Do not remove this class or its instance fixture
on the grounds that a concrete subclass (e.g. `FreelancerProfile`) already
exists — that condition governs the first exception only, not this one.

Do not add a fixture that returns the class itself (e.g.
`unimplemented_profile_class`) unless a test actually consumes the class
directly. If a test needs the class only for a type hint, import it
directly from `conftest.py` instead of adding a fixture indirection.

---

## Database access in tests

pytest-django blocks database access by default. A test that touches the
database without declaring it raises `RuntimeError: Database access not
allowed`. This is a feature, not a bug — it forces explicit declaration of
which tests are DB-backed.

### When you need database access

You must declare database access if the test:

- Calls `.save()`, `.create()`, `.create_user()`, or any other ORM write
  method.
- Queries the database via the ORM (`.objects.filter()`, `.get()`,
  `.all()`, etc.).
- Calls `full_clean()` on a model with any `unique=True` field — **even
  on an unsaved instance**. `full_clean()` invokes `validate_unique()`
  internally, which issues a `SELECT` against the database.
- Checks `auto_now_add` / `auto_now` timestamps (only set on save).
- Checks `.id` is not `None` after creation (id is assigned on save).

You do **not** need database access if the test:

- Calls `clean()` alone (pure Python, no DB).
- Checks `Model._meta.abstract`, field metadata, or other introspection.
- Calls a pure-Python method like `get_display_info()` on an unsaved
  instance.
- Calls a validator function directly with no model involved
  (`validate_email("foo@bar.com")`).

**Important on `full_clean()`:** every concrete user model in SkillBridge
(`Freelancer`, `Client`, `StaffUser`) has `email` declared with
`unique=True` on `BaseUser`. This means any test that calls
`instance.full_clean()` on a user model must declare database access,
even when the instance is not saved.

### `db` fixture vs `@pytest.mark.django_db` marker

There are two equivalent ways to declare database access:

- The fixture `db`, received as a parameter — typically used in
  `conftest.py` on fixtures that create persisted objects:

```python
@pytest.fixture
def freelancer_user(db, valid_freelancer_data: dict[str, str | bool]) -> Freelancer:
    return Freelancer.objects.create_user(**valid_freelancer_data)
```

- The marker `@pytest.mark.django_db`, applied as a decorator — typically
  used on test functions:

```python
@pytest.mark.django_db
def test_create_user_saves_to_database(valid_user_data: dict[str, str]) -> None:
    user = Freelancer.objects.create_user(**valid_user_data)
    assert user.id is not None
```

The two mechanisms are technically equivalent. Internally, the marker
resolves to "include the `db` fixture in this test's fixture list". One is
not faster, safer, or stricter than the other.

**Convention in SkillBridge:**

- In `conftest.py`, use `db` as a fixture parameter on DB-backed fixtures.
- In test files, use `@pytest.mark.django_db` as a decorator on
  DB-touching tests.
- **Keep the marker even when the test consumes a fixture that already
  depends on `db`.** The marker is redundant in execution but documents,
  inside the test file itself, that the test touches the database. This
  is explicit-is-better-than-implicit by choice — readers do not need to
  open `conftest.py` to confirm DB involvement.

### `db` vs `transactional_db`

Both fixtures grant database access, but they use different isolation
strategies.

**Default — `db` and `@pytest.mark.django_db` (no arguments):**

- Wraps each test in a database transaction.
- Rolls back the transaction at the end of the test.
- Fast — no real commits, no flushing between tests.
- Equivalent to Django's `TestCase`.

Use this by default. It covers all tests of model logic, manager logic,
validators, and `clean()` behavior. These are the vast majority of tests
in SkillBridge.

**Exception — `transactional_db` and `@pytest.mark.django_db(transaction=True)`:**

- Uses real commits and flushes the database between tests.
- Significantly slower due to flushing.
- Equivalent to Django's `TransactionTestCase`.

Use the transactional mode **only** when the test must verify behavior
that depends on real commits:

- Code using `transaction.on_commit()` callbacks.
- Code that uses savepoints explicitly.
- Tests that run raw SQL and need to read ORM-created data in the same
  connection cycle.
- Concurrency tests that span multiple database connections.

If you are not testing one of the above scenarios, do not use the
transactional mode. It is purely a performance cost with no behavioral
benefit for typical tests.

### Note on `--no-migrations` and data migrations

`pytest.ini` runs the suite with `--no-migrations`. This means
pytest-django creates the test database schema directly from the current
state of the models (`syncdb`), skipping all migration files. The suite
runs faster, but with a consequence:

**Data migrations do not run during tests.**

This affects any migration whose purpose is to seed or modify data —
for example, `profiles/migrations/0002_seed_skills.py`, which populates
the `Skill` table with the controlled vocabulary. In production this
migration runs and creates the rows; in the test environment it does
not, and the `Skill` table starts empty.

Implications:

- If a test depends on seeded skills being present, it will fail in
  the test environment while working in production — a silent
  divergence.
- Tests that need specific `Skill` rows must create them explicitly
  inside the test or via a dedicated fixture.
- Do not assume any data created by `RunPython` migrations exists in
  the test database.

If a future test setup requires data migrations to run, the team can
opt out of `--no-migrations` for that specific run, but the default
should remain skipped for speed.

---

## One behavior per test — granularity rule

A test should verify a single behavior. When the test fails, its name
alone — without opening the body — must describe what broke. If the
name needs "and", "with", or "also" to stay accurate, the test is
doing too much; split it.

This is independent of `parametrize`. Granularity is about how many
_behaviors_ a test covers; `parametrize` is about how many _inputs_
exercise the same behavior with the same assertion. A parametrized
test still verifies one behavior.

### Operational criteria

Apply these mechanically, without judgment calls:

1. **Naming check.** Read the test name. Does it describe exactly one
   outcome? If it needs "and"/"with"/"also" to stay accurate, split it.
2. **One-call rule.** A test asserts on the result of a single call
   (or a single state transition). Different calls, different states,
   or different methods belong in different tests, even when they
   share setup.
3. **Failure attribution.** If two assertions in the same test can
   both fail, you must be able to tell which one broke from the
   failure alone. If you can't, the test is too broad.

### The exception — grouping by shared expensive setup

Group assertions into a single test only when **both** conditions
hold:

- All assertions describe facets of the **same return value** from a
  **single call** to the code under test.
- Reproducing the setup for each assertion would persist multiple
  objects to the database (multi-object insert, M2M relations, FK
  chains).

When both conditions hold, asserting on the full result in one test
(`assert returned_dict == { ... }`) is preferred over splitting facet
by facet, because the splits would repeat the same expensive setup
with no diagnostic gain.

The exception **never** covers:

- Assertions on different method calls.
- Assertions on different states (before vs after a mutation).
- Assertions on unrelated behaviors that happen to share a fixture.

### Project examples

**Separate — `accounts/tests/models/test_base.py`** splits
`create_user` into independent tests, one per behavior:
`test_create_user_saves_to_database`,
`test_create_user_stores_correct_email`,
`test_create_user_hashes_password`. Each shares the `create_user`
call as setup, but each verifies a distinct contract; when one
fails, the name says which.

**Group — `test_freelancer_profile_get_display_info`** asserts the
full `display_info` dict in a single test. Producing the return
value requires a `Freelancer`, a `FreelancerProfile`, and a `Skill`
joined through an M2M relation — splitting into seven tests (one per
dict key) would recreate that object graph seven times with no added
information.

---

## Parametrize for invalid input lists

When testing multiple invalid values against the same assertion, use
`@pytest.mark.parametrize` instead of writing one test per value. This is
the established pattern from `accounts/tests/models/test_base.py`:

```python
@pytest.mark.django_db
@pytest.mark.parametrize(
    "email",
    [
        "",
        "   ",
        "invalidemail.com",
        "@invalid.com",
        "user@.com",
    ],
)
def test_create_user_invalid_email_raises_validation_error(
    valid_user_data: dict[str, str],
    email: str,
) -> None:
    """Parameterized invalid emails all raise ValidationError."""
    with pytest.raises(ValidationError):
        Freelancer.objects.create_user(**{**valid_user_data, "email": email})
```

Use `parametrize` when: same assertion, same exception, different input
values.

Do not use `parametrize` when each case requires a different assertion or
a different error code. Each unique outcome deserves its own named test.

---

## A test must fail if the behavior under test is removed

A test only has value if it would fail when the behavior it claims to
verify is removed or broken. If an assertion would still pass with the
production logic deleted, the test is tautological — it verifies the
framework or the field type, not your code.

The most common form is asserting a rule that the field type already
enforces. A `clean()` check for whitespace in a `URLField` is
unreachable — the field rejects malformed URLs first — so a test that
feeds a whitespace URL and expects _your_ `clean()` to fail is really
testing Django's `URLField`, not your invariant. Before writing the
test, apply the Field-to-validation contract from `conventions.md`: if
the condition under test can never be triggered, there is nothing to
test — remove the check and the test together.

Rule of thumb: mentally delete the line of production code the test
targets. If the test still passes, it was not testing that line.

---

## ValidationError assertions in tests

Always assert on the `ValidationError` code, never on the message string.
Messages can change for translation or copy adjustments; codes are the
contract.

### Required two-step pattern

Before asserting the code, first assert that the field key exists in
`error_dict`. This prevents cryptic `KeyError` exceptions when a test
fails for an unexpected reason and the developer is left with no clue
which field actually failed.

```python
# CORRECT — key check first, then code check
with pytest.raises(ValidationError) as exc_info:
    user.full_clean()

assert "is_staff" in exc_info.value.error_dict
assert exc_info.value.error_dict["is_staff"][0].code == "superuser_without_staff"
```

```python
# WRONG — direct access without key check raises KeyError on failure
assert exc_info.value.error_dict["is_staff"][0].code == "superuser_without_staff"
```

```python
# WRONG — messages are not the contract
assert "must also have staff status" in str(exc_info.value)
```

### NotImplementedError — assert only the exception type

`NotImplementedError` raised by abstract methods often uses
`gettext_lazy` for the message, which does not resolve to a plain string
until accessed in a translation context. Asserting on the message string
is brittle.

```python
# CORRECT — only the exception type
with pytest.raises(NotImplementedError):
    profile.get_display_info()
```

```python
# WRONG — gettext_lazy may not resolve to the expected string
with pytest.raises(NotImplementedError) as exc_info:
    profile.get_display_info()
assert str(exc_info.value) == "Subclasses must implement get_display_info()."
```

### Error code reference

The full list of established error codes for validators is documented in
`conventions.md` under "Validators" (password, email, name codes). Error
codes raised by `clean()` methods are documented in `conventions.md`
under "Established invariants". Do not invent new codes without checking
that one does not already exist for the same condition.

The list in `conventions.md` is a best-effort reference, not an exhaustive
contract. If a `clean()` method raises a `code` not found there, verify it
in the model's source file before assuming it is undocumented or new.

---

## Docstrings in tests

Test docstrings are short and descriptive — one line is sufficient.
Describe the behavior being verified, not the implementation details.

```python
def test_exceeding_500_char_bio_raises_validation_error(
    dummy_profile_class: type[DummyProfile],
) -> None:
    """Biography exceeding 500 characters raises a bio_too_long ValidationError."""
```

Do not write multi-paragraph docstrings on test functions. Test class
docstrings (when classes are used) follow the same rule.

---

## Fixtures — scope guidelines

| Fixture type                     | Recommended scope                       |
| -------------------------------- | --------------------------------------- |
| Data dicts (no DB)               | `function` (default)                    |
| Unsaved model instances          | `function`                              |
| Model classes (dummy subclasses) | `function` (safe default) or `session`  |
| Saved DB instances               | `function` — each test gets clean state |

`function` is the default scope and the safe choice. Wider scopes
(`session`, `module`, `class`) introduce cross-test coupling and should
only be used when measured performance gain is meaningful.

---

## What to test in an abstract base model

When writing `test_base.py` for an abstract model, cover these and only
these:

1. **Abstract status** — `Model._meta.abstract is True`.
2. **Field validation via `clean()`** — every branch: valid, boundary,
   invalid, normalization.
3. **Abstract method enforcement** — `NotImplementedError` is raised on
   an unimplemented subclass.
4. **Abstract method contract** — an implemented subclass returns the
   expected value.

Do **not** test in the abstract base:

- Timestamps (`created_at`, `updated_at`) — test in concrete model tests.
- Database `.id` assignment — test in concrete model tests.
- Relations to other models — test in concrete model tests.

These belong to the concrete models because they only manifest on save,
which is concrete behavior.

---

## Import conventions in test files

```python
import pytest
from django.contrib.auth.hashers import check_password
from django.core.exceptions import ValidationError

from accounts.models.freelancer import Freelancer
```

- No `from __future__ import annotations` — the project runs on Python
  3.14 with native generic syntax.
- Order: standard library → Django → local imports. One blank line
  between groups.
- No unused imports.

---

## Common mistakes to avoid

| Mistake                                                                                             | Correct approach                                                                                                                    |
| --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Instantiating an abstract model directly                                                            | Use the most complete concrete subclass; fall back to a dummy in `conftest.py` if no concrete exists                                |
| Applying `@pytest.mark.django_db` to every test                                                     | Use only when the test touches the DB (see "When you need database access")                                                         |
| Omitting `@pytest.mark.django_db` from tests that call `full_clean()` on a model with `unique=True` | The marker is required — `validate_unique()` queries the database                                                                   |
| Annotating pytest-django built-in fixtures (`db`, `settings`, etc.)                                 | Leave them unannotated — the plugin provides the typing                                                                             |
| Defining dummy subclasses inside the test file                                                      | Define them in `conftest.py` for reuse                                                                                              |
| Writing one test per invalid value                                                                  | Use `@pytest.mark.parametrize` with same assertion, different inputs                                                                |
| Skipping `conftest.py` and duplicating fixtures across test files                                   | Always create `conftest.py` before writing test files                                                                               |
| Testing abstract model timestamps or `.id`                                                          | Defer to concrete model test files                                                                                                  |
| Returning saved objects from baseline data fixtures                                                 | Return raw dictionaries and unpack them at the test site                                                                            |
| Omitting type hints in tests or fixtures (except for built-in fixtures)                             | Use `-> None` on tests, explicit return types on fixtures                                                                           |
| Asserting on `error_dict[field][0].code` without first asserting the field key                      | Assert the key exists in `error_dict` first to avoid cryptic `KeyError` tracebacks                                                  |
| Asserting on a `ValidationError` message string                                                     | Assert the field key exists in `error_dict`, then assert the `code` — messages are not the contract                                 |
| Asserting on a `NotImplementedError` message string                                                 | Assert only the exception type — the message uses `gettext_lazy` and there is no `code`                                             |
| Assuming data migrations have run in the test database                                              | `--no-migrations` skips them — create needed seed data explicitly in tests or fixtures                                              |
| Using `@pytest.mark.django_db(transaction=True)` by default                                         | Use the default transactional rollback mode unless testing real commit behavior                                                     |
| Writing a test whose assertion still passes with the production logic removed                       | A test must fail when the behavior is deleted — drop tautological checks (see the Field-to-validation contract in `conventions.md`) |
