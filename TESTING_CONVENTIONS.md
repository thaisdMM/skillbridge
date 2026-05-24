# SkillBridge — Testing Conventions

Load this file for every task that involves creating or modifying test files.

---

## Framework and runner

- **pytest-django** — no `unittest.TestCase`, no Django test client unless explicitly required
- All tests run inside Docker: `docker-compose exec web pytest`
- Configuration lives in `pytest.ini` — key flags active: `--no-migrations`, `--reuse-db`, `--strict-markers`

---

## File and folder structure

Test files mirror the source file being tested, one-to-one:

```
accounts/
  models/
    base.py
    freelancer.py
  tests/
    conftest.py           ← shared fixtures for accounts app
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

Every test folder must have an `__init__.py`. Create it alongside the test file.

---

## conftest.py — always create before test files

Every app with tests must have a `conftest.py` at the `tests/` level.

**What belongs in conftest.py:**
- Shared fixtures used across multiple test files in the same app
- Concrete dummy subclasses of abstract models (see section below)
- Data fixtures (dicts, not saved instances) for flexibility
- Saved instance fixtures only when multiple tests require a persisted object

**What does NOT belong in conftest.py:**
- Test functions
- Imports unused by any fixture
- Fixtures used by only one test file (keep those local)

### accounts/tests/conftest.py — established pattern

```python
"""Shared fixtures for accounts app tests."""
import pytest
from accounts.models.freelancer import Freelancer
from accounts.models.client import Client

@pytest.fixture
def valid_user_data() -> dict[str, str]:
    """Valid base data for creating any user. Returns dict for unpacking flexibility."""
    return {
        "email": "testuser@example.com",
        "name": "Test User",
        "password": "SecurePass@123",
    }

@pytest.fixture
def freelancer_user(db, valid_freelancer_data) -> Freelancer:
    """Create and return a Freelancer instance saved in the test database."""
    return Freelancer.objects.create_user(**valid_freelancer_data)
```

---

## Abstract models — how to test them

Abstract models (`abstract = True`) cannot be directly instantiated in tests.
**Never do `AbstractModel(field=value)` in a test.**

### Correct pattern: define concrete dummy subclasses in conftest.py

When the app has no concrete subclass yet (e.g. early in a sprint), define dummy
subclasses inside `conftest.py`. Once concrete models exist, switch to using them.

```python
# profiles/tests/conftest.py

class DummyProfile(Profile):
    """Concrete dummy subclass for testing Profile base behavior."""
    class Meta:
        app_label = "profiles"

    def get_display_info(self) -> dict:
        """Returns minimal display info for testing."""
        return {"dummy": "info"}


class UnimplementedProfile(Profile):
    """Concrete dummy subclass that does NOT implement get_display_info."""
    class Meta:
        app_label = "profiles"


@pytest.fixture(scope="function")
def dummy_profile_class() -> type[DummyProfile]:
    """Fixture providing the DummyProfile class for instantiation in tests."""
    return DummyProfile


@pytest.fixture(scope="function")
def unimplemented_profile_class() -> type[UnimplementedProfile]:
    """Fixture providing the UnimplementedProfile class for testing NotImplementedError."""
    return UnimplementedProfile


@pytest.fixture(scope="function")
def dummy_profile() -> DummyProfile:
    """Fixture providing an unsaved DummyProfile instance with no arguments."""
    return DummyProfile()
```

### When concrete models exist (preferred — follows accounts pattern)

Once `FreelancerProfile` and `ClientProfile` exist, use them directly:

```python
# preferred — real model, real migration, no dummy needed
@pytest.fixture
def freelancer_profile(db, freelancer_user) -> FreelancerProfile:
    return FreelancerProfile.objects.create(user=freelancer_user, bio="Test bio")
```

---

## @pytest.mark.django_db — when to use and when NOT to use

This is a critical distinction. Applying `django_db` unnecessarily slows tests
and creates false dependencies on the database.

| Scenario | Needs `@pytest.mark.django_db`? |
|---|---|
| Calling `clean()` or `full_clean()` on an unsaved instance | **No** — these are pure Python calls |
| Checking `Model._meta.abstract` | **No** — metadata only |
| Calling a method like `get_display_info()` | **No** — pure Python |
| Calling `Model.objects.create_user(...)` | **Yes** — writes to DB |
| Calling `.save()` on an instance | **Yes** — writes to DB |
| Checking `auto_now_add` / `auto_now` timestamps | **Yes** — only set on save |
| Checking `.id` is not None after creation | **Yes** — id assigned on save |

### Rule of thumb

If the test does not call `.save()`, `.create()`, `.create_user()`, or query
the database via the ORM, it does not need `@pytest.mark.django_db`.

---

## parametrize — use for invalid input lists

When testing multiple invalid values for the same field, use `@pytest.mark.parametrize`
instead of writing one test per value. This is the established pattern from accounts:

```python
@pytest.mark.django_db
@pytest.mark.parametrize("email", [
    "",
    "   ",
    "invalidemail.com",
    "@invalid.com",
])
def test_create_user_invalid_email_raises_validation_error(valid_user_data, email):
    """Parameterized invalid emails all raise ValidationError."""
    with pytest.raises(ValidationError):
        Freelancer.objects.create_user(**{**valid_user_data, "email": email})
```

Use `parametrize` when: same assertion, same exception, different input values.
Do not use `parametrize` when each case requires a different assertion.

---

## ValidationError — always assert on code, never on message

```python
# CORRECT
assert exc_info.value.error_dict["bio"][0].code == "bio_too_long"

# WRONG — messages can change, codes are contracts
assert "cannot exceed 500 characters" in str(exc_info.value)
```

For `NotImplementedError`, assert only the exception type — do not assert the message string:

```python
# CORRECT
with pytest.raises(NotImplementedError):
    profile.get_display_info()

# WRONG — NotImplementedError message may use gettext_lazy which does not resolve to a plain string
assert str(exc_info.value) == "Subclasses must implement get_display_info()."
```

---

## Docstrings in tests

Test docstrings are short and descriptive — one line is sufficient.
They describe the behaviour being verified, not implementation details.

```python
def test_exceeding_500_char_bio_raises_validation_error(dummy_profile_class) -> None:
    """Biography exceeding 500 characters raises a bio_too_long ValidationError."""
```

Do not write multi-paragraph docstrings in test functions.
Test class docstrings (if used) follow the same rule.

---

## Fixtures — scope guidelines

| Fixture type | Recommended scope |
|---|---|
| Data dicts (no DB) | `function` (default) |
| Unsaved model instances | `function` |
| Model classes (dummy subclasses) | `function` (safe default) or `session` |
| Saved DB instances | `function` — each test gets a clean state |

---

## What to test in an abstract base model

When writing `test_base.py` for an abstract model, cover these and only these:

1. **`test_<model>_is_abstract()`** — verify `Model._meta.abstract is True`
2. **Field validation via `clean()`** — all branches: valid, boundary, invalid, normalization
3. **Abstract method enforcement** — verify `NotImplementedError` is raised on unimplemented subclass
4. **Abstract method contract** — verify implemented subclass returns expected value

Do NOT test in the abstract base:
- Timestamps (`created_at`, `updated_at`) — test in the concrete model tests
- Database ID — test in the concrete model tests
- Relations to other models — test in the concrete model tests

---

## import conventions in test files

```python
# CORRECT order
import pytest
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import check_password

from accounts.models.freelancer import Freelancer
```

- No `from __future__ import annotations` — project runs Python 3.14
- Standard library first, then Django, then local imports
- No unused imports

---

## Common mistakes to avoid

| Mistake | Correct approach |
|---|---|
| Instantiating an abstract model directly | Use a concrete dummy subclass from conftest |
| Applying `@pytest.mark.django_db` to every test | Only use when the test actually touches the DB |
| Asserting on error message strings | Assert on `ValidationError` codes |
| Defining dummy subclasses inside the test file | Define them in `conftest.py` for reuse |
| Writing one test per invalid value | Use `@pytest.mark.parametrize` |
| Skipping `conftest.py` | Always create it before writing test files |
| Testing abstract model timestamps | Defer to concrete model test files |
