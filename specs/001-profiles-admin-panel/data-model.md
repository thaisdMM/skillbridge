# Phase 1 Data Model: Profiles Admin Panel

**Feature**: `001-profiles-admin-panel` | **Date**: 2026-07-28

**Input**: [spec.md](./spec.md), [research.md](./research.md)

This feature introduces **no new model, no new field, and no migration**. Every
entity below already exists in `django_version/`. This document records what the
admin layer binds to, which rules are already enforced and where, and the single
model-layer change the feature makes.

---

## Entities

### Skill — `profiles/models/skill.py`

Table `skills`. The controlled platform-wide vocabulary (spec Key Entities).

| Field | Type | Constraints |
|---|---|---|
| `id` | auto pk | — |
| `name` | `CharField(max_length=100)` | `unique=True` |
| `category` | `CharField(max_length=20)` | `choices=Category.choices` |

`Category` is a `TextChoices` with exactly four members: `TECHNOLOGY`, `DESIGN`,
`WRITING`, `MARKETING`. `Meta.ordering = ["category", "name"]`.

**No `created_at`, no `updated_at`.** This is why FR-021 is narrowed for the
skill screens — see [research.md](./research.md) R-002.

Seeded with 30 rows by `profiles/migrations/0002_seed_skills.py`. That migration
does **not** run under the test suite (`pytest.ini` sets `--no-migrations`), so
tests create the skills they need.

### FreelancerProfile — `profiles/models/freelancer_profile.py`

Table `freelancer_profiles`. Concrete subclass of the abstract `Profile`.

| Field | Type | Constraints | Source |
|---|---|---|---|
| `id` | auto pk | — | `Profile` |
| `bio` | `TextField(max_length=500)` | `blank=True`, `MaxLengthValidator(500)` | `Profile` |
| `created_at` | `DateTimeField` | `auto_now_add=True` | `Profile` |
| `updated_at` | `DateTimeField` | `auto_now=True` | `Profile` |
| `user` | `OneToOneField(Freelancer)` | `on_delete=PROTECT`, `related_name="profile"` | own |
| `hourly_rate` | `DecimalField(8, 2)` | `null=True`, `blank=True` | own |
| `skills` | `ManyToManyField(Skill)` | `blank=True` | own |
| `portfolio_url` | `URLField` | `blank=True` | own |
| `years_of_experience` | `PositiveIntegerField` | `default=0` | own |

### ClientProfile — `profiles/models/client_profile.py`

Table `client_profiles`. Concrete subclass of the abstract `Profile`.

| Field | Type | Constraints | Source |
|---|---|---|---|
| `id`, `bio`, `created_at`, `updated_at` | | as above | `Profile` |
| `user` | `OneToOneField(Client)` | `on_delete=PROTECT`, `related_name="profile"` | own |
| `company_name` | `CharField(max_length=200)` | `blank=True` | own |
| `max_budget` | `DecimalField(10, 2)` | `null=True`, `blank=True` | own |
| `interests` | `ManyToManyField(Skill)` | `blank=True` | own |
| `website_url` | `URLField` | `blank=True` | own |

### Freelancer / Client / StaffUser — `accounts/models/`

Concrete subclasses of the abstract `BaseUser` (`abstract = True`), each with its
own table (`freelancers`, `clients`, `staff_users`). Not modified by this
feature. Relevant to the admin layer:

- `is_active` — read by FR-029, displayed by the existing `status_badge`.
- `name`, `email` — the existing `search_fields`, the only route to a profile
  under the one-screen decision (SC-003).
- `Freelancer.is_available` plus the `freelancer_no_inactive_available`
  `CheckConstraint`.
- `StaffUser` has no profile relation at all, which is what makes FR-035
  structural rather than a rule to enforce.

---

## Relationships

```
Freelancer 1 ──── 0..1 FreelancerProfile ──── * Skill      (skills)
Client     1 ──── 0..1 ClientProfile     ──── * Skill      (interests)
StaffUser  ─────  (no profile relation)
```

- Both profile links are `OneToOneField` with `related_name="profile"`, so
  `freelancer.profile` and `client.profile` are reverse one-to-one accessors that
  raise `RelatedObjectDoesNotExist` when absent. The admin must test presence,
  never dereference blindly — see [research.md](./research.md) R-006.
- Both `Skill` links are `ManyToManyField` with default reverse accessors,
  `skill.freelancerprofile_set` and `skill.clientprofile_set`. **`on_delete` has
  no effect on a many-to-many**, which is why FR-028 requires explicit work — see
  [research.md](./research.md) R-004.

---

## Validation rules and their owning layer

Per Principle VIII, every rule names exactly one owning layer.

### Already enforced — surfaced, not re-implemented

| Rule | Code | Layer | Requirement |
|---|---|---|---|
| Skill name trimmed; not empty after strip | `skill_name_empty` | `Skill.clean()` | FR-003 |
| Skill name unique | `unique` (Django) | DB + `validate_unique()` | FR-002 |
| `hourly_rate > 0` when provided | `hourly_rate_not_positive` | `FreelancerProfile.clean()` | FR-008 |
| `company_name` not empty after strip | `company_name_empty` | `ClientProfile.clean()` | FR-016 |
| `max_budget > 0` when provided | `max_budget_not_positive` | `ClientProfile.clean()` | FR-015 |
| `bio` ≤ 500 characters | `max_length` (Django) | `Profile.bio` field | US2 scenario 6 |
| One profile per account | `unique` (Django) | `OneToOneField` + `max_num=1` | FR-007, FR-014 |
| Admin access requires active staff | — | `BaseUser.has_module_perms()` | FR-025 |

The admin surfaces all of these as field-level messages by calling
`full_clean()` through `ModelForm._post_clean` — Django's normal admin path. No
new validation code is written for them (FR-020).

### New — the one model change this feature makes

| Rule | Code | Layer | Requirement |
|---|---|---|---|
| A profile cannot be **created** for an account that is inactive in the state being saved | `profile_for_inactive_account` | `FreelancerProfile.clean()` and `ClientProfile.clean()` | FR-029 |

Shape, per `conventions.md`:

```python
def clean(self) -> None:
    super().clean()
    # ... existing branches unchanged ...
    if self.pk is None and <related account present> and not <account>.is_active:
        logger.error("Profile creation refused - account is inactive.")
        raise ValidationError(
            {
                "user": ValidationError(
                    _("A profile cannot be created for an inactive account."),
                    code="profile_for_inactive_account",
                )
            }
        )
```

Notes that govern the implementation:

- `self.pk is None` scopes the rule to creation. Editing an existing profile on a
  deactivated account stays allowed (FR-030), and deactivating an account never
  touches its profile (FR-031).
- The account read here is the **in-memory** instance carrying the value being
  saved, not a database re-read — this is what FR-029's "state being saved"
  clause demands. Mechanism in [research.md](./research.md) R-003.
- The FK must be checked for presence before dereferencing, or an unattached
  instance raises `RelatedObjectDoesNotExist` instead of `ValidationError`.
- `logger.error` carries no PII (Principle VII): no email, no name, no id of the
  account holder.

### Explicitly not model rules

| Rule | Requirement | Where it lives | Why not the model |
|---|---|---|---|
| A skill in use cannot be removed | FR-028 | `SkillAdmin.get_deleted_objects()` | FR-028 scopes it to the removal routes the skill screens offer; the count-and-refuse presentation is an admin concern |
| Skills cannot be created from the profile section | FR-010 | inline field configuration | A UI affordance, not a data rule |
| No profile may be destroyed | FR-023 | `can_delete=False` + `has_delete_permission` | Admin-layer suppression; `on_delete=PROTECT` already blocks the cascade route |

`skills` and `interests` are `ManyToManyField`s. `conventions.md` forbids M2M
constraints in `clean()`, and this feature introduces none — a profile with no
skills and a profile with no interests are both valid (spec.md:245).

---

## State transitions

Profiles have **no status field of their own** (FR-031). The only lifecycle state
that matters is the account's `is_active`, and the only transition this feature
constrains is profile creation:

| Account `is_active` being saved | Profile exists | Action | Outcome |
|---|---|---|---|
| `True` | no | fill profile section | created |
| `True` | yes | edit | saved |
| `False` | no | leave section untouched | nothing created, no error |
| `False` | no | fill profile section | **refused** — `profile_for_inactive_account` |
| `False` | yes | edit | saved (FR-030) |
| `True → False` | yes | edit in the same save | saved (FR-030) |
| `True → False` | no | fill profile section in the same save | **refused** — evaluated against the value being saved |
| `False → True` | no | fill profile section in the same save | created — the account is active by the end of the save |

The last two rows are the reason FR-029 must read the in-memory account rather
than the database.
