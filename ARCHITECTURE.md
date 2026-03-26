# Architecture Decision Record — SkillBridge

This document records the key technical decisions made during the development of SkillBridge,
including the reasoning behind each choice and the trade-offs accepted.
It is intended for engineers and technical recruiters who want to understand
not just *what* was built, but *why*.

---

## 1. Monorepo Structure: `oop_version` → `django_version`

### Context

SkillBridge was always intended to be a Django application. However, at the time the project
started, Django had not yet been studied. Rather than write low-quality Django code without
the necessary foundation, the decision was made to first build a pure Python version of the
domain models to consolidate Object-Oriented Programming concepts in a real, professional
context.

### Decision

The repository was structured as a monorepo with two directories:

- `oop_version/` — pure Python implementation, used as a deliberate learning environment
- `django_version/` — the production-oriented Django implementation, active development

### What was built in `oop_version`

The OOP phase was not a throwaway exercise. It was used to implement and test:

- Abstract base class `User` with `Client` and `Freelancer` as concrete subclasses
- `from_storage()` factory methods on both concrete models to reconstruct instances from storage
- `UserProtocol` for structural typing via `typing.Protocol`, used in profile composition
- Abstract `Profile` base class with `FreelancerProfile` and `ClientProfile` concrete subclasses
- Skills and interests management with normalisation (Title Case), duplicate prevention,
  and last-item protection
- Custom validators for `email` using regex and `password` using logic and regex
- Name validation implemented directly inside the abstract `User` model in
  `_validate_creation_data` (min 2, max 50 characters), before a dedicated validators module
  existed for that field
- Argon2id password hashing
- Structured logging with GDPR-aligned practices (no PII in log output)
- 100 tests with pytest and coverage

### Why `oop_version` was closed

Once Django study had progressed to the point where the framework could be used properly,
the logical next step in the pure Python version would have been simulating a fake database
layer — which would have introduced complexity with no real-world value. The decision was made
to migrate to Django and apply the same concepts inside a real framework with a real database.

This was a deliberate architectural decision, not an abandonment.

---

## 2. Abstract Base Classes over Multi-Table Inheritance

### Context

The domain requires two distinct user types: `Client` and `Freelancer`. Django offers multiple
ways to model this.

### Options considered

**Option A — Multi-Table Inheritance**
Django creates one table for the parent model and one for each child. Every query on a child
model performs an implicit JOIN with the parent table.

**Option B — Abstract Base Classes** *(chosen)*
The parent model (`BaseUser`) is declared `abstract = True`. Django creates no table for it.
Each concrete model (`Client`, `Freelancer`) gets its own fully independent table with all
fields included.

### Decision

Abstract Base Classes were chosen. `BaseUser` is declared `abstract = True` and never
generates a database table. `Client` and `Freelancer` each have their own independent table
with all shared fields replicated.

### Reasoning

- `Client` and `Freelancer` are fundamentally different entities. They share common fields
  (email, name, password) but will have different relationships, permissions, and profile
  structures as the platform grows.
- Avoiding the implicit JOIN on every query is a meaningful performance decision at scale.

### Trade-off accepted

It is not possible to query `BaseUser.objects.all()` and retrieve both clients and freelancers
in a single queryset. If this requirement ever emerges, the architecture would need to be
revisited. For the current scope of SkillBridge, this trade-off is acceptable.

---

## 3. Custom User Model: `AbstractBaseUser` + `BaseUserManager`

### Context

Django's default user model uses `username` as the primary login field. The European job
market and modern professional platforms universally use `email` as the primary identifier.

### Decision

A fully custom user model was built from scratch using `AbstractBaseUser` and
`BaseUserManager`, with `USERNAME_FIELD = 'email'`.

The `BaseUserManager` implements:

- `create_user()` — validates email, name, and password using the custom validators before
  saving; logs only `user.id` (no PII)
- `create_superuser()` — enforces admin permissions (`is_staff`, `is_superuser`)
- Support for OAuth users via `password=None` using `set_unusable_password()`

The `BaseUser` model includes:

- Fields: `email` (unique), `name`, `created_at`, `is_active`, `is_staff`, `is_superuser`
- `user_type` property: returns `'client'` or `'freelancer'` dynamically via
  `__class__.__name__.lower()`
- `has_perm()` and `has_module_perms()` for Django admin integration

### Reasoning

- Email as login is the standard for professional platforms in Europe.
- Replacing the auth model mid-project is one of the most disruptive Django migrations
  possible — it requires resetting the entire database. Starting with a custom model avoids
  this entirely.
- Django's own documentation explicitly recommends setting up a custom user model at the
  start of a project, even if not immediately needed. This decision follows that
  recommendation.

---

## 4. Custom Validators over Django Built-ins

### Context

Django provides built-in validators such as `EmailValidator` and `validate_email`. These
cover basic cases but produce generic error messages that offer little guidance to the end
user. The `oop_version` already had hand-written validators for email and password that were
more specific than anything Django offered out of the box.

### Decision

The validators were rewritten as Django-compatible functions raising `ValidationError`, and
organised in `accounts/validators/user_validators.py`. Three validators cover the full input
surface: `validate_email`, `validate_user_name`, and `validate_strong_password`.

Each validator raises `ValidationError` with a unique `code` per failure case, which allows
tests to assert on the exact error code rather than on message strings — making the test
suite resilient to copy changes.

**`validate_email`** uses a single regex pattern against the stripped value, with an explicit
early check for empty or whitespace-only input that raises `code="empty_email"` before the
pattern is even evaluated.

**`validate_user_name`** applies sequential length checks (empty → too short → too long)
without regex, since the requirements — minimum 2, maximum 50 characters — do not need
pattern matching. This validator consolidates the name validation that in `oop_version` lived
inside the `User` model's `_validate_creation_data` method. Moving it here follows Single
Responsibility and makes it reusable by DRF serializers.

**`validate_strong_password`** is intentionally *not* a single regex. Password requirements
are validated as sequential conditional checks, each raising a distinct error with a specific
human-readable message:

- `password_too_short` — fewer than 8 characters
- `password_contains_whitespace` — spaces, tabs, or newlines present
- `password_only_digits` — no letters or special characters
- `password_all_uppercase` / `password_all_lowercase` — missing case diversity
- `password_no_special_char` — caught via `re.search(r"[^a-zA-Z0-9]", password)`

Regex is used only for this last check. A single-pattern approach was considered and
rejected: it would have produced one generic error message regardless of which requirement
failed, giving the user no actionable feedback. The sequential approach means a user who
submits `"weakpass"` learns exactly that a special character is missing — not that the
password is "invalid".

### Reasoning

- The custom validators were already more precise than Django's built-ins. Replacing them
  with weaker validators would have been a regression.
- `ValidationError` with named codes integrates cleanly with model `clean()` methods and
  DRF serializers — validation runs at the correct layer automatically.
- Unique error codes per failure case make tests stable and error handling in future API
  responses straightforward.

---

## 5. Argon2id as Password Hashing Algorithm

### Context

Password hashing was introduced in `oop_version` as a deliberate learning decision before
Django was involved, and carried through into `django_version`.

### Decision

Argon2id is configured as the primary password hashing algorithm via Django's
`PASSWORD_HASHERS` setting, with PBKDF2 as a fallback for compatibility.

```python
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]
```

### Reasoning

Argon2id is the winner of the Password Hashing Competition and the current recommended
algorithm for new applications. It was studied and applied from the beginning of the project
and carried through both versions consistently.

---

## 6. PostgreSQL with psycopg3 and Connection Pooling

### Decision

PostgreSQL 17 is the database, accessed via psycopg3 (the current-generation driver) with
connection pooling enabled via `OPTIONS.pool = True`.

`CONN_MAX_AGE` was explicitly removed from settings — it is incompatible with psycopg3
connection pooling and caused an error during initial setup.

### Reasoning

- PostgreSQL is the production standard for Django applications and the expected stack in
  the European backend market.
- psycopg3 is the current recommended driver; psycopg2 is in maintenance mode.
- Connection pooling reduces per-request overhead, relevant for a platform handling
  concurrent client and freelancer traffic.

---

## 7. GDPR-Aligned Logging from Day One

### Decision

Structured logging was introduced in `oop_version` and standardised across all modules
before the migration to Django. The same policy was carried into `django_version` without
exception.

The logging policy applied throughout:

- No emails, passwords, names, or any other PII appear in log output
- User identity is logged only via internal identifiers (e.g., `user.id`)
- In profiles, `user.name` is used as the public display identifier; `email` is kept private
  and never logged or displayed in public-facing output
- Each validator logs its entry point and outcome without logging the value being validated

### Reasoning

SkillBridge targets the European market. GDPR compliance was treated as a constraint from
the first logging decisions, not retrofitted later.

---

## 8. Docker and GitHub Actions CI

### Decision

Docker and docker-compose are used for local development:

- `python:3.14-slim` base image
- PostgreSQL 17 as a service with a healthcheck and named volume
- The `web` service depends on the `db` healthy state before starting
- Port `5433` exposed for external database access (e.g., DBeaver)
- `.env.example` documents all required environment variables

GitHub Actions CI runs `pytest` on every push to any branch, with PostgreSQL 17 as a service
and `working-directory` set to `django_version/` to account for the monorepo structure.

### Reasoning

Reproducible environments and automated testing on every push are baseline expectations for
professional engineering roles. These were treated as non-negotiable for a portfolio project,
not optional extras added at the end.

---

## Principles Applied Throughout

| Principle | Application |
|---|---|
| Single Responsibility | Models, validators, and services in separate files with clear scope |
| Open/Closed | Abstract base classes allow extension without modifying existing models |
| Liskov Substitution | `Client` and `Freelancer` are substitutable where `BaseUser` is expected |
| DRY | Shared fields and logic defined once in `BaseUser`, not duplicated across models |
| Type Hints | Used throughout for clarity and IDE support (Python 3.14) |
| Security by default | Argon2id, GDPR-aligned logging, and whitespace-safe validators from the start |
