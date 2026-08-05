# SkillBridge — Conventions

This document consolidates the operational rules for working on
`django_version/`. It is the single source of truth for project conventions
and is loaded into context on every session.

Testing conventions are defined in `testing.md` — read that file before
writing or modifying tests.

---

## Stack and versions

Versions below are pinned in `django_version/requirements.txt`. Do not
modify versions without explicit approval — version changes are
architectural decisions, not maintenance updates.

| Technology     | Version pinned in requirements.txt |
| -------------- | ---------------------------------- |
| Python         | 3.14                               |
| Django         | 6.0.7                              |
| PostgreSQL     | 17 (docker-compose)                |
| psycopg        | 3.3.4                              |
| psycopg-binary | 3.3.4                              |
| psycopg-pool   | 3.3.1                              |
| argon2-cffi    | 25.1.0                             |
| pytest         | 9.1.1                              |
| pytest-django  | 4.12.0                             |
| python-dotenv  | 1.2.2                              |
| pillow         | 12.3.0                             |

**Not yet installed — pin exact version on install:**

- DRF (Django REST Framework)
- drf-spectacular

Never reference these as "latest compatible" in code or documentation.
When installed, update this table with the exact pinned version.

---

## Docker workflow

All commands run inside Docker. Never install packages on the system Python
or activate a non-project virtual environment.

```
docker-compose exec web python manage.py <command>
docker-compose exec web pytest
docker-compose exec web python manage.py makemigrations
```

The `web` service depends on the `db` service healthy state. PostgreSQL 17
is exposed on port 5432 inside the network and mapped to the host for
external tools (e.g. DBeaver).

---

## Architectural rules

These rules translate decisions documented in `ARCHITECTURE.md` into
operational constraints. The full reasoning and trade-offs live in
`ARCHITECTURE.md`; this section states what the agent must follow.

### Inheritance — Abstract Base Classes only

- Inherit from `BaseUser` via Abstract Base Classes (`abstract = True`).
- Never use Multi-Table Inheritance.
- New concrete user models follow the `Client` / `Freelancer` / `StaffUser`
  pattern: each has its own independent table, no implicit JOINs.

### Custom user model and AUTH_USER_MODEL

- `AUTH_USER_MODEL = "accounts.StaffUser"` is fixed.
- Never propose changing `AUTH_USER_MODEL` — this setting was chosen before
  the first migration and changing it now requires resetting the database.
- `USERNAME_FIELD = "email"` on `BaseUser`. Email is the primary identifier
  across the platform.
- Managers (`BaseUserManager`) are defined on `BaseUser` only — never
  redeclared on concrete models.

### ForeignKey and OneToOneField — on_delete policy

- Always use `on_delete=models.PROTECT` on every `ForeignKey` and
  `OneToOneField`.
- `CASCADE` is explicitly rejected. The platform deactivates accounts and
  profiles via `is_active=False`; it does not delete them.
- If a future requirement introduces physical deletion, the `on_delete`
  policy must be revisited explicitly and documented in `ARCHITECTURE.md`
  before any model change.

### Password hashing — Argon2id

- `Argon2PasswordHasher` is the primary hasher. `PBKDF2PasswordHasher` is
  a fallback for legacy compatibility only.
- Never modify `PASSWORD_HASHERS` in `settings.py` without explicit
  approval. This is an architectural decision, not a configuration tweak.

### Skill model — admin-managed vocabulary

- The `Skill` model is a controlled vocabulary managed exclusively by
  platform administrators.
- Freelancers select from the existing list. They never create skills.
- Any future API endpoint, serializer, or form that exposes `Skill` to
  freelancers must be read-only on `Skill` itself.
- A future "freelancer suggests, admin approves" workflow is documented
  in `ARCHITECTURE.md` as a known extension point. Until that workflow is
  designed and approved, freelancer-initiated skill creation is not
  permitted in any layer.

---

## User models — architecture

The user system uses three independent tables backed by an abstract base:

```
BaseUser (abstract = True, no table)
  ├── Freelancer    → freelancers table
  ├── Client        → clients table
  └── StaffUser     → staff_users table  (AUTH_USER_MODEL)
```

### Key patterns

```python
# user_type — always a property, never a field
@property
def user_type(self) -> str:
    return self.__class__.__name__.lower()

# __str__ and __repr__ — non-sensitive only (GDPR)
# Never include email, name, or any PII in string representations.
# These methods are read by logs, admin, shell, and error tracebacks.
def __str__(self) -> str:
    return f"{self.user_type.capitalize()} (id={self.id})"

def __repr__(self) -> str:
    return f"{self.__class__.__name__} (id={self.id})"

# Subclass may override __repr__ to include non-PII business fields:
def __repr__(self) -> str:
    return (
        f"{self.__class__.__name__} (id={self.id}, "
        f"is_available={self.is_available})"
    )

# Managers — defined on BaseUser, never redeclared on concrete models

# StaffUser — overrides is_staff default only
is_staff = models.BooleanField(default=True)  # BaseUser default is False
```

---

## Model invariants — enforced via clean()

Model invariants are rules that must hold regardless of where the data
comes from. Enforce them in `clean()` on the model.

### Before writing any clean() condition

Apply the Field-to-validation contract (see next section). Specifically,
ask: **given what the field type and Django already guarantee, can this
condition ever actually be `True`?**

A condition that is logically unreachable is worse than no validation
at all. For example, a `clean()` that checks whether a `URLField` value
contains whitespace is unreachable — `URLField` already rejects URLs with
whitespace as invalid format, so the condition never fires. Such a check
gives a false sense of safety. If a condition cannot be triggered, do not
write it.

### Required pattern for clean() that raises ValidationError

Every `clean()` that enforces an invariant follows the same structure:

```python
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

def clean(self) -> None:
    """
    Enforce <invariant description>.

    Raises:
        ValidationError: If <condition that triggers the rule>.
    """
    super().clean()
    if <condition that violates the invariant>:
        logger.error("<short non-PII message describing the violation>")
        raise ValidationError(
            {
                "<field_name>": ValidationError(
                    _("<Human-readable user-facing message.>"),
                    code="<unique_error_code>",
                )
            }
        )
```

Each element is mandatory:

- **`super().clean()`** — always call first. Preserves parent invariants
  in inheritance chains (e.g. `Freelancer.clean()` must call
  `BaseUser.clean()` first).
- **`logger.error(...)`** — log the violation before raising. Message
  must contain no PII (no email, no name, no value being validated).
- **`gettext_lazy as _`** — wrap user-facing messages for translation.
  The project targets the European market; messages must be translatable.
- **`{"field_name": ValidationError(...)}`** — dict form with field as
  key enables field-level error display in admin and DRF serializers.
  Never raise `ValidationError("message")` without the dict wrapper.
- **`code="unique_error_code"`** — every invariant has a unique code.
  Tests assert on the code, never on the message string.

### Tests assert on the code

```python
assert "is_staff" in exc_info.value.error_dict
assert exc_info.value.error_dict["is_staff"][0].code == "superuser_without_staff"
```

The message can change for translation or copy adjustments; the code is
the contract.

### Reference implementations

For the established pattern in this codebase, read:

- `accounts/models/base.py` — `BaseUser.clean()` (superuser/staff invariants)
- `accounts/models/freelancer.py` — `Freelancer.clean()` (active/available)
- `profiles/models/freelancer_profile.py` — `FreelancerProfile.clean()` (hourly_rate)
- `profiles/models/client_profile.py` — `ClientProfile.clean()` (company_name, max_budget)

Per Rule 2 of `CLAUDE.md`, read these files before writing a new `clean()`
— do not infer the pattern from training data.

### Established invariants (do not modify without approval)

- `BaseUser.clean()`: `is_superuser=True` requires `is_staff=True`
  → code: `superuser_without_staff`
- `BaseUser.clean()`: non-staff concrete models (`Client`, `Freelancer`)
  cannot have `is_staff=True` or `is_superuser=True`
  → code: `invalid_staff_privileges`
- `Freelancer.clean()`: `is_active=False` requires `is_available=False`
  → code: `freelancer_inactive_available`
  → also enforced at the database level by `CheckConstraint`
  `freelancer_no_inactive_available` on `Freelancer.Meta.constraints`.
  The constraint is the backstop for ORM paths that bypass `clean()`
  (direct `.update()`, scripts, shell). `clean()` remains the
  app-layer path for friendly field-level errors.
- `FreelancerProfile.clean()`: `hourly_rate`, if provided, must be > 0.
  → code: `hourly_rate_not_positive`
- `ClientProfile.clean()`: `company_name`, if provided, must not be empty
  after stripping whitespace.
  → code: `company_name_empty`
- `ClientProfile.clean()`: `max_budget`, if provided, must be > 0.
  → code: `max_budget_not_positive`
- `Skill.clean()`: `name` stripped of whitespace, cannot be empty after strip.
  → code: `skill_name_empty`
- `Skill.clean()`: `name` must not duplicate an existing skill's `name`,
  compared ignoring letter case. Storage is never normalized — the name is
  stored as entered, trimmed only. The lookup excludes the row being saved, so
  recasing a skill in place stays permitted.
  → code: `skill_name_duplicate`
  → also enforced at the database level by `UniqueConstraint(Lower("name"))`
  `skill_unique_name_case_insensitive` on `Skill.Meta.constraints`.
  The constraint is the backstop for ORM paths that bypass `clean()`
  (`.create()`, `.update()`, `bulk_create()`, shell). `clean()` remains the
  app-layer path for the friendly field-level error and owns it alone — the
  constraint cannot report against `name`. Reasoning:
  `docs/adr/case-insensitive-skill-name-uniqueness.md`.
  → this `clean()` issues a queryset lookup, so a test calling `Skill.clean()`
  or `Skill.full_clean()` needs `@pytest.mark.django_db`.

> **Note:** This list is not guaranteed to be exhaustive or fully up to date.
> If a `clean()` method raises a `code` not listed here, treat the source file
> as the authority and verify directly — then add the missing entry here.

---

## Field-to-validation contract

Before writing any field or any validation, verify layer ownership and
cross-layer interactions. Never write a field definition and its validation
in isolation.

Ask the following questions in order:

1. **Does Django or the field type already handle this?**
   `URLField` validates URL format. `EmailField` validates basic email
   structure. `blank=True` signals the field is optional — do not
   re-implement format validation already enforced by the field type.

   Then ask: given what the field type and Django already guarantee, can
   this condition in `clean()` ever actually be `True`? A condition that
   is logically unreachable is worse than no validation at all.

2. **Is this a model invariant?**
   A rule that must hold regardless of where the data comes from (API,
   admin, shell, migration). If yes: enforce in `clean()`.

3. **Is this a business workflow rule?**
   Something that only applies at a specific step — e.g. submitting a
   proposal, completing a profile, publishing a job. If yes: enforce in
   the serializer or form, not the model.

   **Special case — ManyToManyField:** M2M relationships are stored in a
   separate join table and do not exist on an unsaved instance. Any
   constraint that calls `self.<m2m_field>.count()` or `.all()` inside
   `clean()` will always fail on creation. M2M business rules belong
   exclusively at the serializer (`validate_<field>()`) or form
   (`clean_<field>()`) layer. Never enforce M2M constraints in `clean()`.

4. **Is this data normalization?**
   Stripping whitespace, lowercasing, formatting. Enforce at the
   serializer or form, not the model.

A validation that is logically unreachable is worse than no validation.
Verify that every condition in `clean()` can actually be triggered.

---

## Layer ownership

Each validation rule belongs to exactly one layer. Before writing any
rule, state which layer owns it and why.

- **Model `clean()`** — business invariants intrinsic to the model's own
  state. Must hold regardless of how the data arrives.
- **Validator function** — reusable field-level format or content rules
  (e.g. `validate_email`, `validate_strong_password`).
- **Serializer** — API-level rules, cross-field rules, M2M constraints,
  data normalization, workflow-step rules.
- **Form** — admin/UI-level rules, equivalent role to serializer for
  Django admin contexts.

Rules that apply only when submitting a proposal or completing a workflow
step do not belong in the model. Flag them and defer to the correct layer.

---

## clean() is not called automatically — Django default vs. project decision

This is **Django's default behavior**, Django
does not call `clean()` (or `full_clean()`) on `.save()`, `.create()`, or
`bulk_create()`. `clean()` runs automatically only through `ModelForm` and
Django Admin. In every other path (shell, ORM, migrations, bulk operations,
signals, services, management commands), `full_clean()` must be called
explicitly before saving if model-level validation is required.

**Project decision layered on top of that default:**
`BaseUserManager.create_user()` calls `full_clean()` explicitly before
`save()`, so the manager path enforces `clean()` invariants even though
Django would not do it on its own. Because `create_superuser()` delegates to
`create_user()`, this also covers `create_superuser()` and the
`createsuperuser` management command. Full reasoning in `ARCHITECTURE.md` →
_BaseUserManager — `full_clean()` Enforces Invariants at Creation_.

So, for the user models, `clean()` invariants are enforced across three
paths: Django Admin, the DRF serializer layer (when it calls it), **and** the
`BaseUserManager` creation path. A direct ORM write that bypasses the manager
(e.g. `Model(...).save()` without `full_clean()`) is still unprotected — the
database `unique=True` constraint remains the last-resort integrity
guarantee. Document any deliberate decision to skip `full_clean()` (e.g. in
data migrations) in `ARCHITECTURE.md`.

**Note on production-code policy:**
A general rule on when agents must add `full_clean()` before `.save()` in
production code (services, signals, management commands, scripts) is
intentionally deferred. It will be defined when the service layer and DRF
serializer patterns are designed. Until then, follow existing patterns in
each file and flag uncertainty under Rule 1 of `CLAUDE.md`.

---

## Validators

Location: `accounts/validators/user_validators.py`

Three validators cover the user input surface:

- `validate_email` — regex pattern with explicit empty-check first.
- `validate_user_name` — length checks (min 2, max 50), no regex.
- `validate_strong_password` — sequential conditional checks, one
  specific error code per failure case.

Rules for validators:

- Every failure raises `ValidationError` with a unique `code`.
- Tests assert on `code`, never on message string.
- Validators are reusable across models, serializers, and forms.
- Custom validators are preferred over Django built-ins when specific
  error codes are required. Django's `EmailValidator` returns generic
  errors; `validate_email` returns `empty_email` or `invalid_email`.

Established password error codes (do not rename without updating tests):

- `password_too_short`
- `password_contains_whitespace`
- `password_only_digits`
- `password_missing_lowercase`
- `password_missing_uppercase`
- `password_no_special_char`

Established email error codes:

- `empty_email`
- `invalid_email`

Established name error codes:

- `empty_name`
- `name_too_short`
- `name_too_long`

---

## Logging pattern

All apps use Python's `logging` module via a module-level logger.

```python
import logging
logger = logging.getLogger(__name__)
```

### Levels

```python
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

**Note the pattern in the third line:** `len(value)` is logged, not
`value` itself. When a validation needs to log something about the input,
log a derived non-sensitive property (length, presence, type) — never
the value being validated. This is the concrete shape of the "no PII"
rule in practice.

### Configuration

`LOGGING` is configured in `config/settings.py`:

- `accounts`, `profiles`, `jobs` loggers — `DEBUG` level, console handler.
- `django` — `INFO`.
- `django.db.backends` — `DEBUG` in development, `INFO` in production.
- Verbose formatter: `[LEVEL] timestamp - logger_name → message`.

---

## GDPR logging policy

No PII appears in log output, ever. This is non-negotiable.

- Never log emails, names, passwords, or any user identifier other than
  `user.id`.
- In profiles, `user.name` is used as the public display identifier in UI
  contexts only — never in log calls.
- Each validator logs entry, intermediate state, and outcome **without
  logging the value being validated**.
- When in doubt about whether a field is PII, treat it as PII.

SkillBridge targets the European market. GDPR compliance is a constraint
from the first logging decision, not a retrofit.

---

## Admin conventions

Established conventions for the Django admin layer:

- Password fields are hidden in all admin classes.
- `save_model` calls `set_unusable_password()` when the password field is
  empty on save (closes the Django default-behavior gap).
- `has_delete_permission` returns `False` on every admin class except
  `SkillAdmin`. Use `is_active=False` for deactivation.
- `SkillAdmin` permits deletion, and is the only admin class that does.
  `Skill` is curated vocabulary with no `is_active` field, so deactivation is
  not available to it. Removal is refused while any profile still refers to
  the skill, enforced in `SkillAdmin.get_deleted_objects()` — `on_delete` has
  no effect on a `ManyToManyField`. Do not suppress `has_delete_permission`
  on `SkillAdmin`; see `docs/adr/skill-is-the-only-deletable-record.md`.
- `has_module_perms` requires `is_active=True` AND `is_staff=True` to
  grant admin access.
- `Client` and `Freelancer` admin classes never expose `is_staff` or
  `is_superuser`. These are inherited from `BaseUser` for technical
  reasons but are not business attributes of these models.
- `StaffUser` admin: `is_staff` editable by superusers only;
  `is_superuser` always readonly.
- Promoting a `StaffUser` to superuser is a shell-only operation
  (`createsuperuser` or Django shell). It is intentionally not exposed
  in any admin form.

---

## Recording decisions

- Architectural decisions, and significant code or documentation decisions, go
  to `docs/adr/` — one decision per file, in **MADR short form**: title,
  `Date` / `Status` / `Applies to`, *Context and Problem Statement*,
  *Considered Options*, *Decision Outcome*, *Consequences*.
- **Keep an ADR under ~60 lines.** A long ADR is not what the MADR template is
  for, and it costs context on every session that reads one. Record the
  decision, the options rejected, and the reasoning that constrains future
  work. Do not walk through framework behavior — state the verified fact and
  move on.
- `ARCHITECTURE.md` is **closed to new entries** and will be refactored into
  `docs/adr/`. Add new decisions as ADRs, never to that file.
- Known technical debt goes to `docs/tech_debt/`, one decision per file.
- ADRs and convention files reference code, behavior and pinned versions —
  never requirement IDs, task IDs, spec paths, or roadmap items. Those are
  transient and rot when a feature directory is archived.

---

## Code standards

- Google Style docstrings on every class, method, and function.
- Type hints on every function and method signature.
- No inline comments — what needs to be said goes in the docstring. Add
  an inline comment only when the code cannot be understood without one,
  and even then question whether the code should be rewritten to be
  self-explanatory.
- Clean Code: one responsibility per class, one responsibility per
  function. If a function does more than one thing, split it.
- SOLID principles throughout — especially Single Responsibility and
  Open/Closed.
- All code, variable names, comments, docstrings, and commit messages
  in English.
- Commit messages are multiline with bullet points and descriptive.

---

## When in doubt

If a task involves validation logic, M2M constraints, `on_delete`
policies, layer ownership, or architectural decisions not clearly
covered here, ask the user before proceeding. Apply Rule 1 from
`CLAUDE.md`: do not infer, do not assume, do not fill gaps.

For historical context on why a decision was made, consult
`ARCHITECTURE.md`. For testing strategy, consult `testing.md`. For
behavior rules and persona definitions, consult `CLAUDE.md`
