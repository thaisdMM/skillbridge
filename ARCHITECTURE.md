# Architecture Decision Record — SkillBridge

This document records the key technical decisions made during the development of SkillBridge,
including the reasoning behind each choice and the trade-offs accepted.
It is intended for engineers and technical recruiters who want to understand
not just _what_ was built, but _why_.

---

## Monorepo Structure: `oop_version` → `django_version`

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

## Abstract Base Classes over Multi-Table Inheritance

### Context

The domain requires two distinct user types: `Client` and `Freelancer`. Django offers multiple
ways to model this.

### Options considered

**Option A — Multi-Table Inheritance**
Django creates one table for the parent model and one for each child. Every query on a child
model performs an implicit JOIN with the parent table.

**Option B — Abstract Base Classes** _(chosen)_
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

A third concrete model, `StaffUser`, follows this same Abstract Base Class pattern.
It is not a domain user type but the platform's authentication model; the reasoning
for its existence is documented in the AUTH_USER_MODEL section.

---

## Custom User Model: `AbstractBaseUser` + `BaseUserManager`

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

## AUTH_USER_MODEL — StaffUser as Authentication Model

### Decision

`AUTH_USER_MODEL = "accounts.StaffUser"` configured in `settings.py`
before the first migration. `StaffUser(BaseUser)` is the third concrete model
of the project, with its own table `staff_users`.

### Reasoning

Django requires that `AUTH_USER_MODEL` be defined before the first
migration — it is the only configuration that becomes extremely difficult
to change after migrations are applied with real data. `StaffUser` was
chosen instead of making `BaseUser` concrete to preserve the ABC vs MTI decision:
`Client` and `Freelancer` continue to be independent tables without JOIN.
A platform operator is not a client nor a freelancer —
correct separation of responsibilities. ForeignKeys that reference `settings.AUTH_USER_MODEL` point to `staff_users`.

---

## Custom Validators over Django Built-ins

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

**`validate_strong_password`** is intentionally _not_ a single regex. Password requirements
are validated as sequential conditional checks, each raising a distinct error with a specific
human-readable message:

- `password_too_short` — fewer than 8 characters
- `password_contains_whitespace` — any whitespace present, **including leading
  or trailing**; the validator does not strip the password (see _User Input
  Normalization — Owned by the Serializer Layer_)
- `password_only_digits` — no letters or special characters
- `password_all_uppercase` / `password_all_lowercase` — missing case diversity
- `password_no_special_char` — caught via `re.search(r"[^a-zA-Z0-9]", value)`

Regex is used only for this last check. A single-pattern approach was considered and
rejected: it would have produced one generic error message regardless of which requirement
failed, giving the user no actionable feedback. The sequential approach means a user who
submits `"weakpass"` learns exactly that a special character is missing — not that the
password is "invalid".

**Normalization inside validators is validation-local and is being relocated.**
The `.strip()` calls in `validate_email` and `validate_user_name` exist only to
make the *validation* whitespace-tolerant; they do not normalize the value that
is stored — storage normalization is performed separately by the manager
(`name.strip()` and Django's `normalize_email`). Per the project's
layer-ownership rule, normalization belongs to the serializer, not the
validator. Removing these strips is deferred until the DRF serializer exists; see
_User Input Normalization — Owned by the Serializer Layer_. `validate_strong_password`
is the deliberate exception: it no longer strips and rejects any whitespace
outright, because a password must never be silently altered — the reasoning is
recorded in that section.

### Reasoning

- The custom validators were already more precise than Django's built-ins. Replacing them
  with weaker validators would have been a regression.
- `ValidationError` with named codes integrates cleanly with model `clean()` methods and
  DRF serializers — validation runs at the correct layer automatically.
- Unique error codes per failure case make tests stable and error handling in future API
  responses straightforward.

---

## Argon2id as Password Hashing Algorithm

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

## PostgreSQL with psycopg3 and Connection Pooling

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

## GDPR-Aligned Logging from Day One

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

## Docker and GitHub Actions CI

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

## Django Admin — Password Handling

### Decision

Admin interfaces for `Client`, `Freelancer`, and `StaffUser` do not expose
a password input field. `save_model` calls `set_unusable_password()` when
the password field is empty on save.

### Reasoning

Users without a password receive `set_unusable_password()` via `create_user`,
which is the correct state for accounts pending OAuth login or email-based
invitation. Password creation is the responsibility of the authentication flow,
not the admin panel. The `save_model` override closes a Django default behavior
gap: `ModelAdmin` does not call `set_unusable_password()` automatically, which
would leave `password = ''` in the database for admin-created accounts.

---

## Django Admin — Staff Access Control

### Decision

`has_module_perms` in `BaseUser` requires both `is_active=True` and
`is_staff=True` to grant admin panel access.

### Reasoning

`is_staff` alone does not guarantee an account is operational. A deactivated
staff account loses admin access automatically without requiring manual flag
removal, reducing the risk of orphaned permissions after account suspension.

---

## Django Admin — Deletion Disabled

### Decision

`has_delete_permission` returns `False` across all three admin classes
(`FreelancerAdmin`, `ClientAdmin`, `StaffUserAdmin`).

### Reasoning

In a marketplace platform, user deletion is irreversible and affects
associated data such as contracts and history. Deactivation via `is_active`
is the correct lifecycle operation. Disabling deletion in the admin prevents
accidental data loss and aligns with GDPR requirements around data retention
and audit trails.

---

## Django Admin — Privilege Field Separation

### Decision

`Client` and `Freelancer` admin interfaces do not expose `is_staff` or
`is_superuser` fields. `StaffUserAdmin` exposes `is_staff` (editable by
superusers only) and `is_superuser` (always readonly).

### Reasoning

`is_staff` and `is_superuser` are not business attributes of `Client` or
`Freelancer` — they are inherited from `BaseUser` for technical reasons.
Exposing them would allow operators to accidentally or maliciously escalate
privileges. Promoting a `StaffUser` to superuser is intentionally a
shell-only operation (`createsuperuser` or Django shell), enforcing the
principle of least privilege. Granular permission groups are a planned future extension.

---

## BaseUser — Superuser Implies Staff Invariant

### Decision

`BaseUser.clean()` raises `ValidationError` if `is_superuser=True` and
`is_staff=False`.

### Reasoning

Django requires `is_staff=True` to access the admin panel. A superuser
without staff status can authenticate but cannot reach the admin interface,
producing an incoherent permission state. Enforcing this at the model level
via `clean()` protects all concrete models uniformly, regardless of whether
the save originates from the admin, API, or shell (`full_clean()` must be
called explicitly in the latter case).

---

## Freelancer — Active/Availability Invariant

### Decision

`Freelancer.clean()` raises `ValidationError` if `is_active=False` and
`is_available=True`.

### Reasoning

An inactive freelancer is not visible to clients on the platform. Allowing
an inactive account to be marked as available would produce corrupted state:
the freelancer would appear available in availability queries but could not
receive or respond to proposals. Enforcing this at the model level ensures
the rule applies across the admin, REST API, and shell.

---

## StaffUser — `is_staff` Default Override

### Decision

`StaffUser` overrides the `is_staff` field inherited from `BaseUser`, setting `default=True` instead of the inherited `default=False`.

### Reasoning

`BaseUser` defines `is_staff=False` as the default to protect `Client` and `Freelancer` — business users who must never have admin access by default. `StaffUser` exists specifically to represent platform operators whose sole purpose is administrative access via the Django admin panel. A `StaffUser` born with `is_staff=False` would be inconsistent with the model's own reason for existing: it would sit in the `staff_users` table but be unable to access the admin without manual intervention.

Keeping `is_superuser=False` as the inherited default is intentional. Staff access and superuser access are distinct privilege levels. Operators get admin access by default; superuser elevation remains an explicit, manual operation following the principle of least privilege.

### Trade-off accepted

Any code that creates a `StaffUser` without explicitly setting `is_staff=False` will produce an admin-enabled account. This is the intended behavior for this model and must be considered when writing tests that create `StaffUser` instances with non-default states.

---

## Skill — Controlled Vocabulary with Admin-Managed List

### Decision

`Skill` is a standalone model with `unique=True` on `name`, managed exclusively
by platform administrators. Freelancers select from the existing list — they
cannot create skills freely. The list is seeded with a curated set of ~30 skills
across four service categories: Technology, Design, Writing, and Marketing.

### Reasoning

The platform requires reliable filtering and matching between freelancer profiles
and job postings (`list_open_jobs(skills=...)`). Free-text skill
input would make this query fragile — the same skill entered as "python",
"Python", and "Python 3" would produce three separate, unmatchable records.
A controlled vocabulary solves this at the data layer, not the application layer.

The four categories (TECHNOLOGY, DESIGN, WRITING, MARKETING) were chosen to
reflect real freelance service areas with broad market demand, replacing the
generic TECHNICAL/LANGUAGE/SOFT taxonomy originally proposed. This aligns the
seed data with the platform's actual scope and makes category-based filtering
meaningful to end users.

### Trade-off accepted

Limiting skill creation to admins introduces friction when a freelancer's skill
does not exist in the list. Three approaches were considered for this:

- **Option A — Free text input**: rejected because it breaks filtering and
  matching at the query level.
- **Option B — User suggestion with admin approval** (e.g. `status=PENDING`
  awaiting admin review): considered viable for a future iteration. The current
  model does not prevent this extension without breaking changes.
- **Option C — Admin-only managed list** _(chosen)_: accepted for the current
  scope. Prioritises data consistency and query reliability over user freedom.

This constraint is intentional for the portfolio scope and is documented as a
known future extension point.

---

## Skill Seed — bulk_create Without clean() Validation

### Context

The `Skill` model defines a `clean()` method that strips whitespace from `name`
and raises `ValidationError` if the result is empty. Django does not call
`clean()` automatically on `bulk_create()`, `.create()`, or `.save()` — it must
be invoked explicitly via `full_clean()`.

### Decision

The data migration `0002_seed_skills` uses `bulk_create(ignore_conflicts=True)`
without calling `full_clean()` on each instance.

### Reasoning

Seed data is authored directly in source code, reviewed before commit, and
inserted in a controlled environment. The `clean()` method exists to protect
the database from errors introduced by platform administrators when creating
or editing skills via the Django Admin — the only valid insertion path outside
of migrations. That protection is unnecessary when the data source is the
codebase itself.

`ignore_conflicts=True` was added to guard against re-execution in unstable
environments (e.g. a `migrate` run twice due to a deployment error), preventing
`unique constraint` violations on `name` without requiring a try/except block.

### Trade-off accepted

Skipping `full_clean()` means whitespace errors or empty names in the seed list
would be inserted silently. This risk is accepted because:

- Seed data is static and visually reviewable before any migration runs.
- The `clean()` method remains active for the only valid insertion path outside
  of migrations: the Django Admin, restricted to platform administrators.
- If a seed entry is malformed, the fix is a code change and a new migration —
  not a runtime error to handle.

---

## FreelancerProfile — on_delete=PROTECT on OneToOneField

### Context

`FreelancerProfile` has a `OneToOneField` pointing to `Freelancer`.
Django requires an `on_delete` policy to be explicitly declared on every
`ForeignKey` and `OneToOneField`.

### Options considered

**Option A — CASCADE** _(original roadmap suggestion)_
Deletes the profile automatically if the linked `Freelancer` is deleted.

**Option B — PROTECT** _(chosen)_
Raises `ProtectedError` at the database level if a deletion of a `Freelancer`
with an associated profile is attempted.

### Decision

`on_delete=models.PROTECT` was chosen.

### Reasoning

The platform does not delete users — deactivation via `is_active=False` is
the only supported lifecycle transition for `Freelancer` accounts. This is
enforced at the Admin layer (`has_delete_permission = False` on all admin
classes) and is a documented architectural decision.

`PROTECT` makes this invariant explicit at the database level. If a deletion
is attempted by mistake — via shell, script, or a future admin change — the
database refuses and raises an error rather than silently removing the profile.
`CASCADE` would produce silent data loss in a scenario the architecture
explicitly prohibits.

### Trade-off accepted

If physical deletion of a `Freelancer` ever becomes a supported operation,
the `on_delete` policy will need to be revisited alongside the deactivation
strategy. This is considered a future extension point, not a current
requirement.

---

## FreelancerProfile — Minimum One Skill Enforced at Serializer Level

### Context

`FreelancerProfile.skills` is a `ManyToManyField`. The business rule requires
that every published profile has at least one skill associated with it.

### Decision

The minimum-one-skill constraint is not enforced in `FreelancerProfile.clean()`.
It is enforced at the serializer level in the DRF layer.

### Reasoning

Django's `ManyToManyField` relationship is stored in a separate join table and
is only available after the model instance has been saved to the database.
When `clean()` is called — either explicitly via `full_clean()` or by Django
Admin before saving — the M2M relationship does not yet exist on an unsaved
instance. Enforcing `self.skills.count() >= 1` in `clean()` would always fail
on creation, regardless of what the user selected.

The correct enforcement point for M2M business rules is the serializer
(`validate_skills()`) or the form (`clean_skills()`), where the data is
available before the instance is saved.

### Trade-off accepted

A `FreelancerProfile` can exist in the database without any skills if created
directly via the ORM (shell, fixtures, migrations). This is accepted because
the only valid creation paths for end users — the API and the Admin — enforce
the constraint at their respective validation layers.

---

## User Input Normalization — Owned by the Serializer Layer

### Context

User text input such as `email` and `name` carries incidental whitespace.
Trimming and formatting that input is *normalization* — distinct from
*validation* (rejecting input that breaks a rule). In the current codebase the
strip happens in the wrong places: inside the validators (`validate_email`,
`validate_user_name`) and inside the `create_user` manager (`name.strip()`,
alongside Django's `normalize_email`). `conventions.md` is explicit that
normalization is a serializer/form responsibility, not a model, manager, or
validator one.

### Decision

Normalization is owned by the DRF serializer layer. Validators validate only;
the manager persists only. The whitespace strips currently embedded in the
validators and the manager are recognized as misplaced and will be relocated to
the serializer when the DRF layer is built.

Passwords are a deliberate exception: they are **never** normalized at any
layer. `validate_strong_password` was corrected to stop stripping and now
rejects any whitespace — including leading and trailing — with
`password_contains_whitespace`.

### Reasoning

- **Layer ownership.** A normalization rule must live in exactly one layer.
  Spreading `.strip()` across the validator and the manager duplicates the rule
  and hides where it is owned.
- **The password bug that forced the issue.** `validate_strong_password`
  previously stripped a *local copy*, validated the stripped value, and then
  `create_user` hashed the *original* unstripped password. A password entered
  with edge spaces passed validation but was stored as the hash of a different
  string — the user could never log in, and no error was shown. Stripping a
  password is not normalization; it silently changes the secret. The correct
  fix was to remove the strip and reject whitespace outright, not to relocate
  it to another layer.
- **Email and name are genuinely normalizable.** Trimming `"  Test User  "` to
  `"Test User"` is safe and desirable, so their strip is relocated to the
  serializer rather than removed.

### Status and deferral

- **Done:** `validate_strong_password` no longer strips; leading/trailing
  whitespace is rejected with `password_contains_whitespace`.
- **Deferred until DRF exists:** removing the internal strips from
  `validate_email` and `validate_user_name`, and the `name.strip()` in
  `create_user`. These must be done in the same change that introduces the user
  serializer, so the normalization lands in the serializer rather than
  disappearing.

### Trade-off accepted

Until the serializer exists, the manager's `name.strip()` and `normalize_email`
remain the only normalization for non-API paths (shell, `createsuperuser`,
scripts, fixtures, Admin). Removing them before the serializer is in place would
leave those paths storing raw, unnormalized input. The strips therefore stay
until their replacement exists — the rule is relocated, never simply deleted.

---

## Principles Applied Throughout

| Principle                | Application                                                                                                                                                        |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Single Responsibility    | Models and validators in separate files with clear scope                                                                                                           |
| Open/Closed              | Abstract base classes allow extension without modifying existing models                                                                                            |
| Liskov Substitution      | `Client`, `Freelancer`, and `StaffUser` are substitutable where `BaseUser` is expected                                                                             |
| DRY                      | Shared fields and logic defined once in `BaseUser`, not duplicated across models                                                                                   |
| Type Hints               | Used throughout for clarity and IDE support (Python 3.14)                                                                                                          |
| Security by default      | Argon2id, GDPR-aligned logging, and whitespace-safe validators from the start                                                                                      |
| Deactivate, never delete | `is_active=False` is the only supported lifecycle transition; `on_delete=PROTECT` and admin `has_delete_permission=False` enforce this across ORM and admin layers |
