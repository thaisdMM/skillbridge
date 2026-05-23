# SkillBridge — Full Technical Conventions

Load this file when working on a task that requires deeper architectural context.

---

## Stack and versions

| Technology      | Version              |
|-----------------|----------------------|
| Python          | 3.14                 |
| Django          | 6.x                  |
| PostgreSQL      | 17                   |
| psycopg         | 3.x                  |
| DRF             | latest compatible    |
| drf-spectacular | latest compatible    |
| pytest-django   | latest compatible    |
| Argon2id        | primary password hasher |
| PBKDF2          | fallback only        |

All commands run inside Docker:
```
docker-compose exec web python manage.py <command>
docker-compose exec web pytest
```

---

## Project structure

```
skillbridge/
  django_version/          ← active, all work goes here
    accounts/              ← Sprint 1 complete: models, admin, validators, 79 tests
    profiles/              ← Sprint 2 (next)
    jobs/                  ← Sprint 2 (next)
    django_version/        ← settings, urls, wsgi
    .env                   ← never committed
  oop_version/             ← closed, do not touch
  .agents/
    agents.md
    skills/
      conventions.md
      conventions_full.md  ← this file
  AGENT_FULL_CONTEXT.md
```

---

## User models — architecture

- `AUTH_USER_MODEL = "accounts.StaffUser"` — set before first migration, do not change
- Abstract base: `BaseUser(AbstractBaseUser)` — generates no database table
- Concrete models: `Freelancer`, `Client`, `StaffUser` — each with its own independent table
- No Multi-Table Inheritance — no implicit JOINs
- `USERNAME_FIELD = "email"` — email is the primary identifier

### Key patterns

```python
# user_type — always a property, never a field
@property
def user_type(self) -> str:
    return self.__class__.__name__.lower()

# __str__ — overridden in Freelancer and Client (not in StaffUser)
def __str__(self) -> str:
    return f"{self.user_type.capitalize()}: {self.name} ({self.email})"

# Managers — defined on BaseUser, never redeclared on concrete models

# StaffUser — overrides is_staff default only
is_staff = models.BooleanField(default=True)  # BaseUser default is False
```

### Model invariants enforced via clean()

```python
# Always use a dict with field as key — enables field-level error display
raise ValidationError({
    "is_staff": ValidationError(
        "Superuser must also have staff status.",
        code="superuser_without_staff"
    )
})

# Test asserts on code, never on message string
assert exc_info.value.error_dict["is_staff"][0].code == "superuser_without_staff"
```

Established invariants:
- `BaseUser.clean()`: `is_superuser=True` requires `is_staff=True`
- `Freelancer.clean()`: `is_active=False` requires `is_available=False`

---

## Validators

Location: `accounts/validators/user_validators.py`
Three validators: `validate_email`, `validate_user_name`, `validate_strong_password`

- Every failure case raises `ValidationError` with a unique `code`
- Tests always assert on the `code`, never on the message string
- Validators are reusable across models, serializers, and forms

---

## Logging pattern

```python
import logging
logger = logging.getLogger(__name__)

# debug — entry points, each validation step, intermediate results
logger.debug("Starting name validation")
logger.debug("Validating email")
logger.debug("Name validation failed - too short: %d", len(value))
logger.debug("Name validation successful")
logger.debug("Starting hashing password")
logger.debug("Password hashed successfully")
logger.debug("No password provided - setting unusable password")

# info — important operations completed successfully
logger.info("Starting user creation process")
logger.info("User created successfully: id=%s", user.id)

# error — business rule violations detected at runtime
logger.error("An inactive freelancer cannot be available.")
```

No PII in any log call. Never log emails, names, or passwords anywhere.

---

## Admin conventions

- Password fields are hidden in all admin classes
- `save_model` calls `set_unusable_password()` when password field is empty
- `has_delete_permission` returns `False` on all admin classes — use `is_active` for deactivation
- `Client` and `Freelancer` admin never expose `is_staff` or `is_superuser`
- `StaffUser` admin: `is_staff` editable by superusers only, `is_superuser` always readonly

---

## Test structure and conventions

```
accounts/
  tests/
    models/
      test_base.py          ← mirrors accounts/models/base.py
      test_freelancer.py    ← mirrors accounts/models/freelancer.py
    validators/
      test_validate_email.py
      test_validate_password.py
```

- Test file name mirrors the source file being tested
- Folder structure mirrors the app structure
- Framework: `pytest-django`
- Every test class and method has a Google Style docstring
- Assert on `ValidationError` codes, never on message strings
- One assert per behaviour is sufficient when it already implies the structure
- Factory Boy introduced in Sprint 3 — do not use before then

---

## GDPR logging policy

- No PII in logs: no emails, names, or passwords
- Log only `user.id` as the user identifier
- Policy applies across all apps, all sprints

---

## Code standards

- Google Style docstrings on every class, method, and function
- Type hints on every function and method signature
- No inline comments — what needs to be said goes in the docstring
- Clean Code: one responsibility per class, one responsibility per function
- SOLID principles throughout — especially Single Responsibility and Open/Closed
- All code, variable names, comments, docstrings, and commits in English
- Commit messages are multiline and descriptive
