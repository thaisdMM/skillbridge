# SkillBridge — Core Conventions

Essential reference for every coding session in `django_version/`.

---

## Stack

| Technology      | Version              |
|-----------------|----------------------|
| Python          | 3.14                 |
| Django          | 6.x                  |
| PostgreSQL      | 17                   |
| psycopg         | 3.x                  |
| DRF             | latest compatible    |
| drf-spectacular | latest compatible    |
| pytest-django   | latest compatible    |

All commands run inside Docker:
```
docker-compose exec web python manage.py <command>
docker-compose exec web pytest
```

---

## User models — critical facts

- `AUTH_USER_MODEL = "accounts.StaffUser"`
- Abstract base: `BaseUser` — generates no table
- Concrete models: `Freelancer`, `Client`, `StaffUser` — each has its own table
- No Multi-Table Inheritance
- `USERNAME_FIELD = "email"`
- Custom Validators over Django Built-ins
- Custom User Model: `AbstractBaseUser` + `BaseUserManager`
- Managers are defined on `BaseUser` — never redeclared on concrete models

## Model invariants — enforced via clean()

```python
# ValidationError always uses a dict with field as key and code on the inner error
raise ValidationError({
    "field_name": ValidationError("message", code="unique_code")
})
```

## Validators

Location: `accounts/validators/user_validators.py`
- `validate_email`, `validate_user_name`, `validate_strong_password`
- Every failure raises `ValidationError` with a unique `code`

---

## Logging pattern

```python
import logging
logger = logging.getLogger(__name__)

# debug — entry points, each validation step, each intermediate result
logger.debug("Starting name validation")
logger.debug("Name validation failed - too short: %d", len(name_stripped))
logger.debug("Name validation successful")

# info — important operations completed successfully
logger.info("User created successfully: id=%s", user.id)

# error — business rule violations (e.g. inside clean())
logger.error("An inactive freelancer cannot be available.")
```

No PII in any log call. Never log emails, names, or passwords.

---

## Test structure

```
accounts/
  tests/
    models/
      test_base.py        ← mirrors accounts/models/base.py
    validators/
      test_validate_email.py
```

- Framework: `pytest-django`
- Every test has a Google Style docstring
- Assert on `ValidationError` codes, never on message strings:
```python
assert exc_info.value.error_dict["is_staff"][0].code == "superuser_without_staff"
```
- One assert per behaviour is sufficient when it already implies the structure

---

## Code standards

- Google Style docstrings on every class, method, and function
- Type hints on every function and method signature
- No inline comments — what needs to be said goes in the docstring
- Clean Code: one responsibility per class, one per function
- SOLID principles throughout
- All code, variable names, comments, docstrings, and commits in English
