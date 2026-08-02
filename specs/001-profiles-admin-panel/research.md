# Phase 0 Research: Profiles Admin Panel

**Feature**: `001-profiles-admin-panel` | **Date**: 2026-07-28

**Input**: [spec.md](./spec.md), `.specify/memory/constitution.md`

All findings below are grounded in files read in this session (Constitution
Principle III). Where a Django behavior is asserted, the mechanism is named so it
can be verified against the pinned version (Django 6.0.7) at implementation time
(Principle VI).

---

## R-001: Where the profile inlines live, and the import direction

**Decision**: `FreelancerProfileInline` and `ClientProfileInline` are defined in
`django_version/accounts/admin.py`, next to the account admins that own them.
`django_version/profiles/admin.py` holds `SkillAdmin` and nothing else.
`accounts/admin.py` imports `profiles.models`; it never imports `profiles.admin`.

**Rationale**:

- An inline is not a screen. `inlines` is an attribute of the *parent*
  `ModelAdmin`; an `InlineModelAdmin` is never registered and has no URL of its
  own. `SkillAdmin` is a registered screen. The two are different kinds of
  object, so they live in different places.
- The spec retires FR-011, FR-012, FR-018 and FR-019 and states there are no
  profile lists in this feature (spec.md:309-312). With standalone profile
  screens out of scope, there is no profiles-side admin for `FreelancerProfile`
  or `ClientProfile` to belong to. The only registered admin this feature adds
  is `SkillAdmin`.
- The resulting coupling is `accounts.admin → profiles.models`, a normal and
  stable dependency, rather than `accounts.admin → profiles.admin`, an
  admin-module-to-admin-module coupling that would make admin load order
  implicit.
- No import cycle exists. `django.contrib.admin.apps.AdminConfig.ready()` calls
  `autodiscover_modules("admin")`, which runs only after `apps.populate()` has
  imported every app's models. `accounts/admin.py` importing
  `profiles.models.freelancer_profile` is therefore safe at admin-load time.
- It matches the structure already established in `accounts/admin.py`:
  `BaseAccountAdmin` (non-registered base) plus `StatusBadgeMixin` (opt-in
  mixin), recorded in `ARCHITECTURE.md` under *Django Admin — Shared Behavior
  via Base Class and Mixin*. This feature adds `BaseProfileInline` and
  `ProfilePresenceMixin` alongside them, in the same file, under the same
  pattern.

**Alternatives considered**:

- *All profile admin code in `profiles/admin.py`, imported by
  `accounts/admin.py`.* Rejected: splits each account screen across two files
  and makes `profiles.admin` execute early as a side effect of importing
  `accounts.admin`.
- *`profiles/admin.py` unregisters and re-registers the account admins.*
  Rejected: each account admin would then be defined in two files with one
  overriding the other, working against FR-022.

**Accepted cost (recorded as technical debt)**: when the deferred standalone
profile screens are built, `FreelancerProfileInline` (in `accounts`) and a
future `FreelancerProfileAdmin` (in `profiles`) will present the same model from
two apps and will need a shared base for fieldsets and delete suppression. This
is a deliberate trade to avoid duplicating both code and tests now, for screens
the spec explicitly defers.

---

## R-002: FR-021 cannot be met literally for the skill screens

**Decision**: FR-021's *"read-only creation and update timestamps"* and
*"most-recent-first ordering"* clauses are narrowed so that they apply only where
the model carries those fields. `SkillAdmin` keeps `Skill.Meta.ordering`
(`["category", "name"]`), has no timestamp fieldset, and honours every other
clause of FR-021: grouped fieldsets, `list_per_page = 25`, search, and filters.
No model field is added and no migration is generated.

**Rationale**: `profiles/models/skill.py` declares exactly two fields, `name` and
`category` (skill.py:53-67). There is no `created_at` and no `updated_at`, and
`Meta.ordering` is `["category", "name"]` (skill.py:73). FR-021 is unsatisfiable
for `Skill` as the model stands. Under Principle XII this divergence is reported
rather than silently resolved; the human chose the narrowing over a model change
(decision 2026-07-28).

**Alternatives considered**: adding `created_at`/`updated_at` to `Skill` with a
migration. Rejected by the human — it widens an admin-layer feature into a model
and migration change (Principles IV and X), and would still leave the ordering
clause needing a separate decision, since alphabetical grouping by category is
the semantically useful order for a controlled vocabulary.

**Consequence for the plan**: FR-021 compliance for `SkillAdmin` is verified
against the narrowed reading. SC-008's side-by-side review must be told that the
absence of a timestamp section on the skill screens is intended.

---

## R-003: FR-029 belongs in the model's `clean()`, not the admin

**Decision**: FR-029 is enforced by a new branch in `FreelancerProfile.clean()`
and `ClientProfile.clean()`:

```
if self.pk is None and the related account is not active:
    raise ValidationError({"user": ValidationError(_(...), code="profile_for_inactive_account")})
```

**Rationale**:

- Principle VIII places invariants that must hold regardless of where the data
  came from in the model's `clean()`. FR-029 is a rule about the profile's own
  state relative to its account, not a workflow-step rule, so the model owns it.
- The rule is reachable from an unsaved instance. During an admin save, Django's
  `ModelAdmin._changeform_view` builds the parent account with
  `form.save(commit=False)` — an unsaved instance already carrying the submitted
  `is_active` — and passes it to `_create_formsets` as the formset's `instance`.
  `BaseInlineFormSet.add_fields` replaces the FK field with an
  `InlineForeignKeyField` whose `clean()` returns that parent instance, so
  `construct_instance` sets it on the inline's instance before
  `ModelForm._post_clean` calls `full_clean()`. Inside `clean()`, the related
  account therefore carries the value **being saved**, which is precisely what
  FR-029 requires ("evaluated against the account status being saved, not the
  status the account held when the screen was opened").
- This is a `OneToOneField`, not a `ManyToManyField`. The `conventions.md`
  prohibition on M2M constraints in `clean()` does not apply: a forward FK/O2O is
  readable on an unsaved instance through the field's cache
  (`ForwardManyToOneDescriptor.__get__` returns the cached object when
  `user_id` is still `None`).
- `self.pk is None` restricts the rule to creation, which FR-030 requires — an
  existing profile stays editable on a deactivated account.

**Error-dict key**: `"user"`. The rule is about the related account, so `user` is
the field it concerns. Per `testing.md`, tests assert on the `code`, which is
unaffected by rendering.

**Correction, 2026-08-01 — the original display claim was wrong.** This entry
previously stated that because the inline renders `user` as a hidden field,
"Django surfaces the message at the top of the profile section labelled with the
field name". That is the behavior of Django's **default form rendering**, which
folds hidden-field errors into the top errors as `(Hidden field user) …`. The
**admin's** inline templates do not do this: `admin/edit_inline/stacked.html`
renders `formset.non_form_errors` (line 17) and `form.non_field_errors`
(line 25), plus per-field errors for the fields named in the fieldsets. `user`
is in none of those, so its error reached the page and was rendered **nowhere** —
the administrator saw only the generic "Please correct the error below".

Measured on the rendered response before the fix: the error was present in
`formset.errors` as `{'user': [...]}`, `form.non_field_errors()` was empty, and
the message string did not appear in the HTML at all. This violated FR-020 and
SC-004.

**Resolution** (decision, 2026-08-01): the model keeps raising with the `user`
key and the `profile_for_inactive_account` code — the contract in
`contracts/admin-surface.md` §4 is unchanged. The display problem is fixed in
the admin layer by `ProfileInlineForm` on `BaseProfileInline`, which relocates
errors raised against hidden fields to the form level, where the section renders
them. Alternatives rejected: attaching the error to a visible field such as
`bio` (lies about which field is wrong, already rejected above), and raising
`NON_FIELD_ERRORS` from the model (puts a presentation decision in the model
layer, against Principle VIII).

**Alternatives considered**:

- *Attach to `bio`.* Rejected: `bio` is not the cause of the refusal and may be
  empty.
- *A non-field error raised from a custom `BaseInlineFormSet.clean()`.*
  Rejected: it would put a model invariant in the form layer, contradicting
  Principle VIII, and would leave the ORM path unguarded.

**Known limitation to record**: Django does not call `clean()` on `.save()` or
`.objects.create()` (see `conventions.md`, *clean() is not called
automatically*). A direct ORM write bypassing the admin can still create a
profile on a deactivated account. Unlike `freelancer_no_inactive_available`,
this invariant spans two tables, so a `CheckConstraint` cannot back it up. The
admin path — the only path this feature builds — is covered.

**Guard required**: `clean()` must not raise `RelatedObjectDoesNotExist` when no
account is attached. The implementation checks the FK id / cached object before
dereferencing.

---

## R-004: `on_delete=PROTECT` does not protect a ManyToMany — FR-028 needs explicit work

**Decision**: FR-028 is enforced by overriding
`SkillAdmin.get_deleted_objects()`, returning a single summary string in the
`protected` collection when any profile refers to the skill.

**Rationale**:

- `on_delete` is a property of `ForeignKey`/`OneToOneField`. `Skill` is
  referenced by two `ManyToManyField`s — `FreelancerProfile.skills`
  (freelancer_profile.py:63) and `ClientProfile.interests`
  (client_profile.py:68) — and deleting a `Skill` silently deletes the join-table
  rows without raising `ProtectedError`. Without explicit work, FR-028 fails and
  SC-010 fails with it.
- `ModelAdmin.get_deleted_objects()` returns
  `(deletable_objects, model_count, perms_needed, protected)`. Both the
  single-object delete view (`ModelAdmin._delete_view`) and the built-in
  `delete_selected` action call it, and both refuse the deletion and render the
  protected block when `protected` is non-empty. One override therefore covers
  *"every removal route offered by the skill screens, including bulk actions"*.
- `protected` is rendered as a collection of strings, so returning one summary
  line carrying the count satisfies FR-028's requirement to report *how many*
  profiles refer to the skill while explicitly **not** enumerating them
  individually.

**Reverse accessors**: neither M2M declares `related_name`, so the reverse
managers are the Django defaults, `skill.freelancerprofile_set` and
`skill.clientprofile_set`. The count is the sum of the two.

**Alternatives considered**:

- *Override `delete_model` to no-op.* Rejected: `_delete_view` emits its success
  message after calling `delete_model`, so the administrator would be told the
  skill was deleted when it was not.
- *`has_delete_permission(request, obj)` returning `False` when in use.*
  Rejected as the sole mechanism: it hides the button with no explanation and
  carries no count, failing FR-028's reporting clause. It also does not reach the
  bulk action's queryset.
- *Enforcing the rule in `Skill.delete()`.* Rejected: FR-028 scopes the refusal
  to the removal routes offered by the skill screens, and a `delete()` override
  would not produce the admin's field-level presentation.

---

## R-005: One-profile-per-account and the optional blank form

**Decision**: both inlines are `admin.StackedInline` with `extra = 1`,
`max_num = 1`, `can_delete = False`, and `has_delete_permission()` returning
`False`.

**Rationale**:

- `StackedInline` renders one record as a vertical form and supports
  `fieldsets`, which FR-021 requires ("grouped field sections"). `TabularInline`
  would render the profile as a single wide row and cannot group fields.
- `BaseModelFormSet.total_form_count()` computes
  `max(initial_forms, min_num) + extra`, then clamps to `max_num`. With
  `extra=1, max_num=1`: an account **with** a profile yields `min(1+1, 1) = 1`
  populated form and no blank one (FR-007, FR-014 — no way to add a second); an
  account **without** a profile yields `0+1 = 1` blank form, which stays open for
  input on a deactivated account (FR-032) and on the add form (FR-036).
- `BaseModelFormSet.save_new_objects()` skips forms where `form.has_changed()` is
  `False`, so opening an account and saving without touching the profile section
  creates nothing (spec.md:246, FR-036's "MUST NOT create a profile
  automatically"). `years_of_experience` has `default=0`, so the untouched blank
  form compares equal to its initial data and is correctly treated as unchanged.
- `can_delete = False` plus `has_delete_permission → False` removes every
  removal control from the profile section (FR-023, SC-006). The database
  `OneToOneField` remains the backstop for the one-per-account rule on non-admin
  paths.

---

## R-006: Profile-presence column and filter without an N+1

**Decision**: `ProfilePresenceMixin` annotates the changelist queryset with
`Exists(...)` in `get_queryset()`, displays the result through a badge built the
same way as `StatusBadgeMixin.status_badge`, and pairs it with a
`SimpleListFilter` over `profile__isnull`.

**Rationale**:

- `Freelancer.profile` and `Client.profile` are reverse one-to-one accessors
  (`related_name="profile"` on both profile models). Accessing `.profile` on an
  account that has none raises `RelatedObjectDoesNotExist`, so the display
  callable must test presence rather than dereference. Doing that per row would
  issue one query per row — 25 extra queries per changelist page at
  `list_per_page = 25`. Annotating once in `get_queryset()` keeps it to a single
  query.
- FR-033 requires the indicator to be "presented the same way the existing status
  indicators on those lists are presented". Those are coloured `format_html`
  badges (`status_badge`, `availability_badge`), so the profile indicator is a
  badge, not a boolean tick.
- FR-035 is satisfied structurally: `StaffUserAdmin` does not compose the mixin,
  exactly as it already declines `StatusBadgeMixin`.

---

## R-007: Filtering the account lists by skill

**Decision**: attempt `list_filter = (..., "profile__skills")` on
`FreelancerAdmin` and `(..., "profile__interests")` on `ClientAdmin`. Verify
against Django 6.0.7 during implementation; fall back to a `SimpleListFilter`
over the same lookup if the built-in filter does not resolve the path.

**Rationale**:

- Django's `list_filter` accepts related-field paths using `__`, resolved by
  `django.contrib.admin.utils.get_fields_from_path`. The path here traverses a
  reverse `OneToOneField` (`profile`) and then a `ManyToManyField`, which is
  the less common shape and must be confirmed rather than assumed
  (Principle VI).
- FR-039 (each account at most once) is expected to hold two ways: filtering on
  a single skill id matches at most one join row per account because
  `(profile, skill)` pairs are unique in the join table; and Django's
  `ChangeList` applies `.distinct()` when a filter path spans a multi-valued
  relation. Both are verified by an explicit test rather than trusted.
- The spec caps the vocabulary in the hundreds (spec.md:352), so a dropdown of
  skills is acceptable and no autocomplete is required.

---

## R-008: Access control needs no new work

**Decision**: no permission code is written for FR-025.

**Rationale**: `BaseUser.has_module_perms()` already returns
`self.is_active and self.is_staff` (base.py:266-276), and `has_perm()` returns
`self.is_active and self.is_superuser`. Registering `SkillAdmin` and attaching
inlines changes nothing about how the admin site authorises access. A test
asserts the behavior; no production code is added.

---

## R-009: Pre-existing test gap — closed by the human before implementation

**Superseded 2026-07-31.** When this decision was written, `ClientProfile` had
**no test module**: `django_version/profiles/tests/models/` contained
`test_base.py`, `test_freelancer_profile.py` and `test_skill.py` only, leaving
the existing `ClientProfile.clean()` rules — `company_name_empty` and
`max_budget_not_positive`, both listed as established invariants in
`conventions.md` — untested. The gap was reported rather than absorbed, under
Principle V.

The human closed it directly, ahead of implementation: commit `8df77d4` added
`profiles/tests/models/test_client_profile.py` (19 tests, covering both
pre-existing rules) and commit `e4f7719` extended
`test_freelancer_profile.py`. The client fixtures the module needs —
`client_user`, `valid_client_profile_data`, `client_profile` — were added to
`profiles/tests/conftest.py` in the same work.

**Consequences for the plan**, recorded rather than silently applied
(Principle XII):

- T008 no longer creates the module. It **adds the `profile_for_inactive_account`
  cases to the existing `test_client_profile.py`**.
- T002 no longer adds the client fixtures. Only the `skill` fixture is missing.
- T062's second tech-debt entry is dropped — there is no untested-`ClientProfile`
  debt left to record.
- Backfilling the two pre-existing rules is no longer out of scope work waiting
  on a decision; it is done.

---

## R-010: No new dependencies, no migrations

**Decision**: this feature is admin-layer plus two `clean()` branches. It adds
no package to `requirements.txt` and generates no migration.

**Rationale**: everything needed is in `django.contrib.admin`, already in
`INSTALLED_APPS` (config/settings.py:29). DRF and drf-spectacular are not
installed and are not required — the deliverable is Django admin screens, not an
API. R-002 removed the only candidate model change. Adding a `clean()` branch
alters no field and no database schema, so `makemigrations` produces nothing.
