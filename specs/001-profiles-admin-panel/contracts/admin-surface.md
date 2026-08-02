# Contract: Django Admin Surface

**Feature**: `001-profiles-admin-panel` | **Date**: 2026-07-28

The interface this feature exposes is the Django admin site — there is no API,
no CLI and no public endpoint (DRF is not installed). This document is the
contract for that surface: what is registered, what each screen shows, and which
errors it must raise. Rationale lives in [research.md](../research.md); field
definitions live in [data-model.md](../data-model.md).

Everything below is additive except where marked **MODIFIED**. Anything not
listed keeps its current behavior (FR-024).

---

## 1. `profiles/admin.py` — `SkillAdmin`

Registered against `profiles.models.skill.Skill`. The only registered admin this
feature adds.

| Attribute | Value | Requirement |
|---|---|---|
| `list_display` | `("name", "category")` | FR-004 |
| `list_display_links` | `("name",)` | — |
| `list_filter` | `("category",)` | FR-004 |
| `search_fields` | `("name",)` | FR-004 |
| `ordering` | `("category", "name")` | FR-021 (narrowed, R-002) |
| `list_per_page` | `25` | FR-021 |
| `fieldsets` | one unnamed group: `("name", "category")` | FR-021 |

**Deletion is permitted** (FR-027) — `SkillAdmin` does **not** inherit
`BaseAccountAdmin` and does not suppress `has_delete_permission`. `Skill` is the
one record in this feature an administrator may permanently remove (SC-006).

### `get_deleted_objects()` override — FR-028

Signature per `ModelAdmin.get_deleted_objects(objs, request)`, returning
`(deletable_objects, model_count, perms_needed, protected)`.

Contract:

- For each skill in `objs`, count referring profiles as
  `skill.freelancerprofile_set.count() + skill.clientprofile_set.count()`.
- When the total across `objs` is greater than zero, `protected` MUST contain a
  **single summary string** stating that the skill is still in use and how many
  profiles refer to it.
- `protected` MUST NOT contain one entry per profile. FR-028 forbids enumerating
  the affected profiles individually; the administrator locates them with the
  skill filters defined in §3.
- The override MUST cover both removal routes, which it does by construction —
  `ModelAdmin._delete_view` and the built-in `delete_selected` action both call
  this method and both refuse when `protected` is non-empty.
- No profile may lose a skill as a side effect (SC-010).

**Behavioral guarantee**: a skill referred to only by profiles on **deactivated**
accounts is still in use and its removal is refused on the same terms
(spec.md:240). The count makes no reference to account status.

---

## 2. `accounts/admin.py` — profile sections **MODIFIED**

### `BaseProfileInline` — not registered, not attached to any model

Shared base for the two inlines (FR-022), sitting alongside the existing
`BaseAccountAdmin` and `StatusBadgeMixin`.

| Attribute | Value | Requirement |
|---|---|---|
| base class | `admin.StackedInline` | FR-021 (supports `fieldsets`) |
| `form` | `ProfileInlineForm` | FR-020, SC-004 |
| `extra` | `1` | FR-032, FR-036 |
| `max_num` | `1` | FR-007, FR-014 |
| `can_delete` | `False` | FR-023 |
| `has_delete_permission()` | returns `False` | FR-023, SC-006 |
| `readonly_fields` | `("created_at", "updated_at")` | FR-021 |
| `formfield_for_dbfield()` | clears `can_add_related` on every related field | FR-010, FR-022 |

### `ProfileInlineForm` — the form both sections use

Relocates errors raised against fields the section renders hidden to the form
level, so the section displays them. Each error keeps its original `code`; only
where it is displayed changes.

Without it, an error keyed to `user` — the key FR-029 uses — reaches the page
and is rendered nowhere: `admin/edit_inline/stacked.html` renders
`formset.non_form_errors`, `form.non_field_errors` and the per-field errors of
the fields named in the fieldsets, and `user` is in none of them. The
administrator would see only the generic "Please correct the error below". See
[research.md](../research.md) R-003, *Correction, 2026-08-01*.

**No vocabulary-management control of any kind** is offered on a profile
section — not only no ➕. Inside an account screen an administrator may attach
and detach existing skills; creating, renaming and deleting vocabulary happens
exclusively on the `Skill` screen (decision, 2026-08-01).

The suppression lives on `BaseProfileInline`, not on each inline, so both
sections inherit one definition (FR-022). It is applied in
`formfield_for_dbfield()` rather than `formfield_for_manytomany()`: on Django
6.0.7 the `RelatedFieldWidgetWrapper` that carries the flags is constructed in
`formfield_for_dbfield()` *after* `formfield_for_manytomany()` has returned, so
setting them in the latter has no effect on the rendered page (verified against
the pinned version, 2026-08-01).

Only `can_add_related` is set. `RelatedFieldWidgetWrapper.__init__` gates
`can_change_related` and `can_delete_related` behind
`supported = not widget.allow_multiple_selected and isinstance(widget, Select)`,
which is `False` for any multi-select widget — the ✏️ and 🗑️ controls cannot
render on a skills or interests widget regardless of configuration.

**Note on `max_num`.** `inlineformset_factory` forces `max_num = 1` whenever the
FK to the parent is unique (`django/forms/models.py`, `if fk.unique: max_num = 1`).
Both profile links are `OneToOneField`, so the declared `max_num = 1` is a
contract attribute rather than the mechanism — the one-profile-per-account
guarantee comes from the relation itself.

Behavior fixed by `extra=1, max_num=1` (R-005):

- Account **with** a profile → exactly one populated form, no way to add a
  second.
- Account **without** a profile → exactly one blank form, open for input even on
  a deactivated account and on the add form.
- Blank form left untouched → **no profile is created**.

### `FreelancerProfileInline(BaseProfileInline)`

`model = profiles.models.freelancer_profile.FreelancerProfile`.

Fieldsets (FR-006, FR-021):

| Group | Fields |
|---|---|
| unnamed | `hourly_rate`, `years_of_experience`, `portfolio_url` |
| `Skills` | `skills` |
| `Biography` | `bio` |
| `Important Dates` (collapsed) | `created_at`, `updated_at` |

`skills` is a multi-select over existing skills only, presented through
`filter_horizontal = ("skills",)` — a two-column available/chosen selector with
a search box (decision, 2026-08-01). The widget offers no vocabulary-management
control, per `BaseProfileInline` above.

`filter_horizontal` renders every option into the page, which suits the
vocabulary size the spec caps at (spec.md:352). Should the vocabulary ever reach
thousands, the replacement is `autocomplete_fields`, already viable because
`SkillAdmin` declares `search_fields = ("name",)`.

### `ClientProfileInline(BaseProfileInline)`

`model = profiles.models.client_profile.ClientProfile`.

| Group | Fields |
|---|---|
| unnamed | `company_name`, `max_budget`, `website_url` |
| `Interests` | `interests` |
| `Biography` | `bio` |
| `Important Dates` (collapsed) | `created_at`, `updated_at` |

Same FR-010 constraint on `interests`, and `filter_horizontal = ("interests",)`
for the same reason. The add-related suppression is inherited from
`BaseProfileInline` and needs no code on this class.

### Attachment

| Admin | Change | Requirement |
|---|---|---|
| `FreelancerAdmin` | `inlines = (FreelancerProfileInline,)` | FR-006, FR-026 |
| `ClientAdmin` | `inlines = (ClientProfileInline,)` | FR-013, FR-026 |
| `StaffUserAdmin` | **no inline** | FR-035 |

---

## 3. `accounts/admin.py` — account lists **MODIFIED**

### `ProfilePresenceMixin` — opt-in mixin

Composed by `FreelancerAdmin` and `ClientAdmin` only, exactly as
`StatusBadgeMixin` already is. `StaffUserAdmin` does not compose it, which
satisfies FR-035 structurally.

| Member | Contract | Requirement |
|---|---|---|
| `get_queryset()` | annotates profile presence with `Exists(...)`; MUST NOT add a query per row | FR-033, R-006 |
| `profile_badge` | `@admin.display` returning a coloured `format_html` badge, built the same way as `status_badge` | FR-033 |
| `HasProfileFilter` | `SimpleListFilter`, two choices, over `profile__isnull` | FR-034, SC-011 |

### Per-admin list changes

| Admin | `list_display` gains | `list_filter` gains |
|---|---|---|
| `FreelancerAdmin` | `profile_badge` | `HasProfileFilter`, `profile__skills` |
| `ClientAdmin` | `profile_badge` | `HasProfileFilter`, `profile__interests` |
| `StaffUserAdmin` | nothing | nothing |

Skill filters (FR-037, FR-038): the built-in related-field path is the intended
implementation, with a `SimpleListFilter` over the same lookup as the documented
fallback if the reverse-O2O-then-M2M path does not resolve on Django 6.0.7
(R-007). Either way the contract is identical:

- Filtering by a skill lists exactly the accounts whose profile refers to it.
- **Each account appears exactly once**, however many skills its profile has
  (FR-039, SC-012).
- Filtering by a skill no profile refers to yields an empty list and no error.

Everything already on these lists — `status_badge`, `availability_badge`,
`created_at_display`, `search_fields`, `ordering`, `list_per_page`, and every
existing action — is unchanged (FR-024, SC-009).

---

## 4. Error contract

Every rejection below is raised as a `ValidationError` carrying a field key and a
`code`, and is rendered as a message beside the offending field — never as a
failure page (FR-020, SC-004). Per `testing.md`, tests assert on the **code**.

| Trigger | Field key | Code | Status |
|---|---|---|---|
| Skill name empty after strip | `name` | `skill_name_empty` | existing |
| Skill name duplicates an existing one | `name` | `unique` | existing (Django) |
| `hourly_rate` ≤ 0 | `hourly_rate` | `hourly_rate_not_positive` | existing |
| `max_budget` ≤ 0 | `max_budget` | `max_budget_not_positive` | existing |
| `company_name` empty after strip | `company_name` | `company_name_empty` | existing |
| `bio` over 500 characters | `bio` | `max_length` | existing (Django) |
| Profile created for an account inactive in the state being saved | `user` | `profile_for_inactive_account` | **new** |

`profile_for_inactive_account` is raised against `user`, which the profile
section renders hidden. `ProfileInlineForm` (§2) moves it to the form level so
it is displayed above the section's fields. The key and code the model raises
are unchanged, and tests continue to assert the code.

`profile_for_inactive_account` is the only new code this feature introduces. It
must be added to the *Established invariants* list in
`.claude/rules/conventions.md`.

Removing an in-use skill is **not** in this table: it is refused through
`get_deleted_objects()`'s `protected` collection, which Django renders on the
delete-confirmation page, not through a `ValidationError`.

---

## 5. Access control — unchanged

All screens above are reachable only by an account with `is_active=True` and
`is_staff=True`, enforced by the existing `BaseUser.has_module_perms()`
(base.py:266-276). FR-025 requires no new production code; it is covered by test
only.

---

## 6. Explicit non-goals of this contract

- No standalone `FreelancerProfileAdmin` or `ClientProfileAdmin` is registered.
  Profile lists are deferred (spec.md:356).
- No profile search by `company_name`. The account search covers `name` and
  `email` only; this loss is recorded in spec.md:312.
- No API, serializer or schema. DRF and drf-spectacular are not installed.
- No new dependency, no model field, no migration.
