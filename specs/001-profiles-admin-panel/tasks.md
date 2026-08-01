# Tasks: Profiles Admin Panel

**Input**: Design documents from `/specs/001-profiles-admin-panel/`

**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md),
[research.md](./research.md), [data-model.md](./data-model.md),
[contracts/admin-surface.md](./contracts/admin-surface.md),
[quickstart.md](./quickstart.md)

**Tests**: **Required.** Constitution Principle IX (*No Code Without Tests*,
NON-NEGOTIABLE) makes tests mandatory for every production change. Test
ordering is **not** TDD — the human deferred adopting test-first as a rule
(constitution.md:39-46), so within each phase implementation precedes its tests
and neither is complete without the other.

**Organization**: Tasks are grouped by user story so each story can be
implemented, tested and demonstrated independently.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel — different files, no dependency on an
  incomplete task.
- **[Story]**: The user story the task belongs to (US1–US6).
- Every task names an exact file path.

## Path Conventions

- Spec artifacts live at the monorepo root under `specs/`.
- Source lives under `django_version/`. All paths below are monorepo-relative.
- **Every command runs inside Docker from `django_version/`**:
  `docker-compose exec web <command>`. Never on the host Python
  (`CLAUDE.md`, Rule 12).

## Constraints that govern every task

- **No new dependency, no model field, no migration** (research.md R-010).
  `makemigrations --check --dry-run` must stay clean throughout.
- **No PII** in any log line or error message (Principle VII).
- Tests follow `.claude/rules/testing.md`: assert the `ValidationError`
  **code**, never the message; assert the field key is in `error_dict` first;
  `--no-migrations` means `0002_seed_skills.py` never runs, so tests create
  their own `Skill` rows.
- Existing account-administration behavior must not regress (SC-009), except
  the three additions FR-024 names as intended.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Test scaffolding and a recorded green baseline before any change.

- [X] T001 Create the test package `django_version/profiles/tests/admin/__init__.py` (new package; `testing.md` requires `__init__.py` in every test folder)
- [X] T002 [P] Extend `django_version/profiles/tests/conftest.py` with the `skill` fixture, following the established dict-fixture and `db`-parameter patterns already in that file. The `client_user`, `valid_client_profile_data` and `client_profile` fixtures this task originally also asked for **already exist** — added by the human ahead of implementation (research.md R-009)
- [X] T003 [P] Extend `django_version/accounts/tests/conftest.py` with `skill` and saved-profile fixtures needed by the admin tests, composing the existing `freelancer_user` / `client_user` fixtures
- [X] T004 Record the green baseline: run `docker-compose exec web pytest` and `docker-compose exec web python manage.py makemigrations --check --dry-run` from `django_version/`, and note the passing test count for the SC-009 comparison later

**Checkpoint**: Fixtures available, baseline recorded.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The FR-029 model invariant and the shared inline base. Both are
consumed by User Story 2 **and** User Story 3, so they live here rather than
inside either story — this keeps US2 and US3 independently deliverable and
satisfies FR-022 (behavior defined once, not duplicated per screen).

**⚠️ CRITICAL**: User Story 1 does not depend on this phase and may proceed in
parallel. User Stories 2–6 must not begin until this phase is complete.

- [X] T005 [P] Add the `profile_for_inactive_account` branch to `FreelancerProfile.clean()` in `django_version/profiles/models/freelancer_profile.py`: guard `self.pk is None`, check the FK is present before dereferencing, read the **in-memory** account's `is_active`, `logger.error` with no PII, raise `ValidationError({"user": ValidationError(_( ... ), code="profile_for_inactive_account")})` per the shape in data-model.md:129-143
- [X] T006 [P] Add the identical `profile_for_inactive_account` branch to `ClientProfile.clean()` in `django_version/profiles/models/client_profile.py`
- [X] T007 Add FR-029 tests to `django_version/profiles/tests/models/test_freelancer_profile.py`: creation refused on an inactive account (`error_dict["user"][0].code == "profile_for_inactive_account"`), creation accepted on an active account, editing an existing profile on a deactivated account accepted (FR-030), and no `RelatedObjectDoesNotExist` when no account is attached
- [X] T008 [P] Add the same four FR-029 cases for `ClientProfile` to the existing `django_version/profiles/tests/models/test_client_profile.py`. **Revised 2026-07-31**: the module was created by the human ahead of implementation and already covers the pre-existing `company_name_empty` / `max_budget_not_positive` rules (research.md R-009), so this task extends it rather than creating it
- [X] T009 Add `BaseProfileInline` to `django_version/accounts/admin.py`: `admin.StackedInline` with `extra = 1`, `max_num = 1`, `can_delete = False`, `has_delete_permission()` returning `False`, `readonly_fields = ("created_at", "updated_at")`, placed beside the existing `BaseAccountAdmin` and `StatusBadgeMixin` per contracts/admin-surface.md §2
- [X] T010 Confirm the `clean()` changes generated no schema drift: `docker-compose exec web python manage.py makemigrations --check --dry-run` from `django_version/` must report "No changes detected"

**Checkpoint**: FR-029 enforced at the model layer and covered by tests; the
shared inline base exists. US2 and US3 can now start in parallel.

---

## Phase 3: User Story 1 - Curate the platform skill vocabulary (Priority: P1) 🎯 MVP

**Goal**: A dedicated `Skill` screen where an administrator adds, corrects,
searches, filters and removes vocabulary entries — with removal refused, and
counted, when any profile still refers to the skill.

**Independent Test**: Sign in as an administrator, add a skill in each of the
four service categories, search it by name, edit it, delete an unused one, and
confirm a skill a profile refers to cannot be deleted. Delivers value with no
profile work in place.

**Depends on**: Phase 1 only. Independent of Phase 2.

### Implementation for User Story 1

- [X] T011 [US1] Rewrite the stub `django_version/profiles/admin.py` as `SkillAdmin` registered against `profiles.models.skill.Skill`, with `list_display = ("name", "category")`, `list_display_links = ("name",)`, `list_filter = ("category",)`, `search_fields = ("name",)`, `ordering = ("category", "name")`, `list_per_page = 25`, and one unnamed fieldset `("name", "category")` — exactly the table in contracts/admin-surface.md §1
- [X] T012 [US1] Confirm `SkillAdmin` in `django_version/profiles/admin.py` does **not** inherit `BaseAccountAdmin` and does not suppress `has_delete_permission` — `Skill` is the one record this feature permits an administrator to permanently remove (FR-027, SC-006)
- [X] T013 [US1] Add the `get_deleted_objects(objs, request)` override to `SkillAdmin` in `django_version/profiles/admin.py`: count referring profiles as `skill.freelancerprofile_set.count() + skill.clientprofile_set.count()` across `objs`, and when the total is greater than zero return a `protected` collection holding a **single summary string** carrying the count — never one entry per profile (FR-028, research.md R-004)

### Tests for User Story 1

All in `django_version/profiles/tests/admin/test_skill_admin.py` (new file), so
these run sequentially, not in parallel.

- [X] T014 [US1] Create `django_version/profiles/tests/admin/test_skill_admin.py` and assert the `SkillAdmin` configuration contract: `list_display`, `list_display_links`, `list_filter`, `search_fields`, `ordering`, `list_per_page` and `fieldsets` match contracts/admin-surface.md §1 (FR-004, FR-021 narrowed per R-002)
- [X] T015 [US1] In `django_version/profiles/tests/admin/test_skill_admin.py`, assert `SkillAdmin.has_delete_permission()` returns `True` — deletion is permitted on this screen (FR-027)
- [X] T016 [US1] In `django_version/profiles/tests/admin/test_skill_admin.py`, assert `get_deleted_objects()` returns an empty `protected` for a skill no profile refers to (FR-027)
- [X] T017 [US1] In `django_version/profiles/tests/admin/test_skill_admin.py`, assert `get_deleted_objects()` returns a non-empty `protected` for a skill referred to by a freelancer profile, and separately for one referred to by a client profile (FR-028)
- [X] T018 [US1] In `django_version/profiles/tests/admin/test_skill_admin.py`, assert `protected` holds exactly **one** entry carrying the correct count when several profiles refer to the same skill — never one entry per profile (FR-028's no-enumeration clause)
- [X] T019 [US1] In `django_version/profiles/tests/admin/test_skill_admin.py`, assert the skill is **still attached** to every profile after a refused deletion and that no join-table row was removed (SC-010 — this is the test that catches the silent-M2M-detach failure mode named in plan.md:222)
- [X] T020 [US1] In `django_version/profiles/tests/admin/test_skill_admin.py`, assert the refusal covers the bulk route: the built-in `delete_selected` action over a queryset containing one in-use skill deletes nothing (FR-028, quickstart A9). If the shared `get_deleted_objects()` path does not cover the action on Django 6.0.7, apply the recorded fallback — a custom bulk action replacing `delete_selected` (plan.md:112-114) — and test that instead
- [X] T021 [US1] In `django_version/profiles/tests/admin/test_skill_admin.py`, assert a skill referred to only by profiles on **deactivated** accounts is still counted as in use and its removal refused on the same terms (spec.md:240)

**Checkpoint**: User Story 1 is fully functional and independently testable —
the MVP. Validate with quickstart.md section A.

---

## Phase 4: User Story 2 - Manage a freelancer's profile from their account screen (Priority: P2)

**Goal**: A freelancer's profile is created and edited inside that freelancer's
own account screen — hourly rate, years of experience, portfolio link,
biography and skills — with no separate profile screen.

**Independent Test**: Open an existing active freelancer account in the admin,
fill in the profile section, attach skills, save, reopen and confirm the values
persisted. Requires one freelancer account and one skill.

**Depends on**: Phase 2 (T005, T007, T009). Independent of US1 and US3.

### Implementation for User Story 2

- [ ] T022 [US2] Add `FreelancerProfileInline(BaseProfileInline)` to `django_version/accounts/admin.py` with `model = FreelancerProfile`, importing from `profiles.models.freelancer_profile` — import `profiles.models`, **never** `profiles.admin` (research.md R-001)
- [ ] T023 [US2] Define the `FreelancerProfileInline` fieldsets in `django_version/accounts/admin.py`: unnamed `("hourly_rate", "years_of_experience", "portfolio_url")`, `Skills` → `("skills",)`, `Biography` → `("bio",)`, `Important Dates` (collapsed) → `("created_at", "updated_at")` (FR-006, FR-021)
- [ ] T024 [US2] Configure the `skills` widget on `FreelancerProfileInline` in `django_version/accounts/admin.py` so no add-related "+" control is rendered — the vocabulary is created only through the skill screens (FR-010)
- [ ] T025 [US2] Attach `inlines = (FreelancerProfileInline,)` to `FreelancerAdmin` in `django_version/accounts/admin.py`, changing nothing else on that class (FR-024)

### Tests for User Story 2

All in `django_version/accounts/tests/admin/test_profile_inlines.py` (new file).

- [ ] T026 [US2] Create `django_version/accounts/tests/admin/test_profile_inlines.py` and assert `FreelancerProfileInline` is attached to `FreelancerAdmin` and carries the `BaseProfileInline` contract: `extra == 1`, `max_num == 1`, `can_delete is False`, `has_delete_permission()` returns `False`, `readonly_fields == ("created_at", "updated_at")` (FR-007, FR-023, SC-006)
- [ ] T027 [US2] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert the `FreelancerProfileInline` fieldsets match contracts/admin-surface.md §2 exactly (FR-006, FR-021)
- [ ] T028 [US2] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert the formset yields exactly **one** form for an account that already has a profile (no blank second form) and exactly one blank form for an account with none — including on the add form (FR-007, FR-032, FR-036, research.md R-005)
- [ ] T029 [US2] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert an untouched blank profile section creates **no** profile on save (`has_changed()` is `False`; `years_of_experience` defaults to `0` so the blank form compares equal to its initial data) (spec.md:246, FR-036)
- [ ] T030 [US2] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert the existing profile rules surface through the inline as field-level errors with their established codes: `hourly_rate_not_positive` on the `hourly_rate` key and `max_length` on `bio` for a 501-character biography (FR-008, FR-020, US2 scenarios 3 and 6)
- [ ] T031 [US2] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert the FR-029 core cases through the inline, reading the status **being saved** rather than the stored one: filling the section while unticking Active on a previously active account is refused, and filling it while ticking Active on a deactivated account is accepted (quickstart B10–B11 — passing B8 while failing these means the rule is reading the database, plan.md:223)

**Checkpoint**: User Stories 1 and 2 both work independently. Validate with
quickstart.md section B.

---

## Phase 5: User Story 3 - Manage a client's profile from their account screen (Priority: P3)

**Goal**: A client's profile — company name, maximum budget, website,
biography and areas of interest — created and edited inside that client's own
account screen.

**Independent Test**: Open an existing active client account, fill in the
profile section, attach interests, save, reopen and confirm the values
persisted. Requires one client account and one skill.

**Depends on**: Phase 2 (T006, T008, T009). Independent of US1 and US2, with
one shared-file note below.

> **File-sharing note**: T032–T035 edit `django_version/accounts/admin.py` and
> T036–T039 edit `django_version/accounts/tests/admin/test_profile_inlines.py`,
> both also touched by User Story 2. The stories are logically independent but
> must not be edited concurrently in the same file.

### Implementation for User Story 3

- [ ] T032 [US3] Add `ClientProfileInline(BaseProfileInline)` to `django_version/accounts/admin.py` with `model = ClientProfile`, importing from `profiles.models.client_profile`
- [ ] T033 [US3] Define the `ClientProfileInline` fieldsets in `django_version/accounts/admin.py`: unnamed `("company_name", "max_budget", "website_url")`, `Interests` → `("interests",)`, `Biography` → `("bio",)`, `Important Dates` (collapsed) → `("created_at", "updated_at")` (FR-013, FR-021)
- [ ] T034 [US3] Configure the `interests` widget on `ClientProfileInline` in `django_version/accounts/admin.py` so no add-related "+" control is rendered (FR-010)
- [ ] T035 [US3] Attach `inlines = (ClientProfileInline,)` to `ClientAdmin` in `django_version/accounts/admin.py`, changing nothing else on that class (FR-024)

### Tests for User Story 3

- [ ] T036 [US3] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert `ClientProfileInline` is attached to `ClientAdmin` and carries the `BaseProfileInline` contract (FR-014, FR-023)
- [ ] T037 [US3] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert the `ClientProfileInline` fieldsets match contracts/admin-surface.md §2 exactly (FR-013, FR-021)
- [ ] T038 [US3] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert the client rules surface through the inline with their established codes: `max_budget_not_positive` on `max_budget`, and `company_name_empty` on `company_name` for a whitespace-only name (FR-015, FR-016, US3 scenarios 3 and 4)
- [ ] T039 [US3] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert the client formset behaves as US2's does — one form when a profile exists, one blank form when none, nothing created from an untouched section — and that FR-029 is enforced through the client inline (FR-014, FR-032, FR-036)

**Checkpoint**: Both profile types are managed from their account screens.
Validate with quickstart.md section C.

---

## Phase 6: User Story 4 - Profile and account on one screen, without regressing account administration (Priority: P4)

**Goal**: Verify the combined screen as a whole — profile visible and editable
in place, absence of a profile clearly presented, profile rule violations shown
beside the offending field, and every existing account behavior untouched.

**Independent Test**: Open an account with a profile and confirm it is editable
in place; open one without and confirm a profile can be started there; re-run
the existing account-administration checks and confirm nothing regressed.

**Depends on**: Phases 4 and 5. This story is verification of the whole and
adds no production code unless a regression is found.

- [ ] T040 [US4] Run `docker-compose exec web pytest accounts/tests/admin/test_admin.py -v` from `django_version/` and confirm every test passes **unchanged** — this is the SC-009 gate. If any test needs modification, stop and report: only the three additions FR-024 names as intended are permitted to change behavior (Principle XII)
- [ ] T041 [US4] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert a profile rule violation raised from the account screen surfaces as a field-level error inside the profile section and never as an unhandled failure (FR-020, US4 scenario 4, SC-004)
- [ ] T042 [US4] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert `StaffUserAdmin.inlines` is empty — staff accounts have no profile section (FR-035, US4 scenario 5)
- [ ] T043 [US4] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert FR-025 access control still holds unchanged: `BaseUser.has_module_perms()` grants access only to `is_active=True` **and** `is_staff=True` accounts. No production code is added — this is covered by test only (research.md R-008)
- [ ] T044 [US4] Walk quickstart.md section E manually against the running container and confirm E1–E6: no Delete button on any account screen, unusable password on a passwordless save, `is_staff`/`is_superuser` read-only rules, freelancer bulk availability actions unchanged, field-level profile errors, and no admin access for an inactive staff account (FR-024)

**Checkpoint**: The combined screen is proven and account administration is
confirmed un-regressed.

---

## Phase 7: User Story 5 - See at a glance which accounts have a profile (Priority: P5)

**Goal**: The freelancer and client account lists show whether each account has
a profile and can be narrowed to either group — with no per-row query.

**Independent Test**: Create accounts with and without profiles, open both
lists, confirm the indicator matches reality per row, and confirm the filter
narrows the list to the expected group.

**Depends on**: Phase 2. Delivers most value after Phases 4–5, since profiles
must exist to be indicated.

### Implementation for User Story 5

- [ ] T045 [US5] Add `HasProfileFilter(admin.SimpleListFilter)` to `django_version/accounts/admin.py` with two choices over the `profile__isnull` lookup (FR-034, SC-011)
- [ ] T046 [US5] Add `ProfilePresenceMixin` to `django_version/accounts/admin.py` with a `get_queryset()` that annotates profile presence using `Exists(...)` — annotated **once**, never resolved per row (FR-033, research.md R-006)
- [ ] T047 [US5] Add the `profile_badge` display method to `ProfilePresenceMixin` in `django_version/accounts/admin.py`, built the same way as the existing `StatusBadgeMixin.status_badge` — an `@admin.display` returning a coloured `format_html` badge, not a boolean tick (FR-033)
- [ ] T048 [US5] Compose `ProfilePresenceMixin` into `FreelancerAdmin` and `ClientAdmin` in `django_version/accounts/admin.py`, add `profile_badge` to each `list_display` and `HasProfileFilter` to each `list_filter`. Do **not** compose it into `StaffUserAdmin` — FR-035 is satisfied structurally, exactly as `StatusBadgeMixin` already is

### Tests for User Story 5

All in `django_version/accounts/tests/admin/test_account_list_profile.py` (new
file).

- [ ] T049 [US5] Create `django_version/accounts/tests/admin/test_account_list_profile.py` and assert `profile_badge` reports presence correctly for a freelancer with a profile and for one without, and the same for clients (FR-033, US5 scenarios 1–2)
- [ ] T050 [US5] In `django_version/accounts/tests/admin/test_account_list_profile.py`, assert `HasProfileFilter` narrows each list to exactly the accounts without a profile, and to exactly those with one (FR-034, US5 scenarios 3–4, SC-011)
- [ ] T051 [US5] In `django_version/accounts/tests/admin/test_account_list_profile.py`, assert the changelist issues **no** per-row query for the badge — count queries with `django_assert_num_queries` over a page of accounts and confirm the count does not scale with the row count (R-006; quickstart D1 is the manual counterpart)
- [ ] T052 [US5] In `django_version/accounts/tests/admin/test_account_list_profile.py`, assert `StaffUserAdmin` neither defines nor inherits `profile_badge` and that `HasProfileFilter` is absent from its `list_filter`, mirroring the existing `test_freelancer_admin_neither_defines_nor_inherits_deactivate_accounts` style (FR-035, US5 scenario 5)

**Checkpoint**: Profile presence is visible and filterable on both account
lists. Validate with quickstart.md rows D1–D4 and D9.

---

## Phase 8: User Story 6 - Find accounts by skill (Priority: P6)

**Goal**: Narrow the freelancer list to everyone offering a given skill, and
the client list to everyone hiring for it — each account listed exactly once.

**Independent Test**: Give several freelancer profiles a known skill, filter the
freelancer list by it, confirm exactly those accounts appear and each appears
once; repeat on the client list with an area of interest.

**Depends on**: Phase 2 and, for meaningful data, Phases 4–5. Touches the same
two `list_filter` tuples as User Story 5, so the two are naturally delivered
together (spec.md:205-206).

### Implementation for User Story 6

- [ ] T053 [US6] **Verification gate (Principle VI)**: confirm against the pinned Django 6.0.7 that `list_filter` resolves a path traversing a reverse `OneToOneField` then a `ManyToManyField`. Check `django.contrib.admin.utils.get_fields_from_path` behavior for `profile__skills` in `docker-compose exec web python manage.py shell` before writing the attribute. Record the outcome (research.md R-007)
- [ ] T054 [US6] Add `"profile__skills"` to `FreelancerAdmin.list_filter` and `"profile__interests"` to `ClientAdmin.list_filter` in `django_version/accounts/admin.py`. If T053 showed the path does not resolve, implement the recorded fallback instead — a `SimpleListFilter` over the same lookup, placed beside `HasProfileFilter` in the same file. The contract in contracts/admin-surface.md §3 is identical either way (FR-037, FR-038)

### Tests for User Story 6

- [ ] T055 [US6] In `django_version/accounts/tests/admin/test_account_list_profile.py`, assert filtering the freelancer list by a skill lists exactly the freelancers whose profile refers to it, and no others (FR-037, US6 scenario 1)
- [ ] T056 [US6] In `django_version/accounts/tests/admin/test_account_list_profile.py`, assert filtering the client list by a skill lists exactly the clients listing it as an interest (FR-038, US6 scenario 2)
- [ ] T057 [US6] In `django_version/accounts/tests/admin/test_account_list_profile.py`, assert a freelancer whose profile refers to several skills appears **exactly once** when filtered by one of them — verify the duplicate is actually absent rather than trusting Django's `.distinct()` (FR-039, US6 scenario 3, SC-012)
- [ ] T058 [US6] In `django_version/accounts/tests/admin/test_account_list_profile.py`, assert filtering by a skill no profile refers to yields an empty list and raises no error (US6 scenario 4)
- [ ] T059 [US6] In `django_version/accounts/tests/admin/test_account_list_profile.py`, assert no skill filter is present on `StaffUserAdmin.list_filter` (FR-035, US6 scenario 5)

**Checkpoint**: All six user stories are independently functional. Validate with
quickstart.md rows D5–D9.

---

## Phase 9: Polish & Cross-Cutting Concerns

**Purpose**: Documentation the plan commits to, and the full validation gate.

- [ ] T060 [P] Add `profile_for_inactive_account` to the *Established invariants* list in `.claude/rules/conventions.md`, following the existing entry format (plan.md:234-235; quickstart.md "Done when")
- [ ] T061 [P] Record two decisions in `ARCHITECTURE.md`: the FR-021 narrowing for the skill screens (no timestamps on `Skill`, ordering by category then name — research.md R-002) and the FR-028 mechanism (`get_deleted_objects()`, because `on_delete=PROTECT` does not protect a many-to-many — research.md R-004)
- [ ] T062 [P] Add one entry to `docs/tech_debt.md`: the deferred standalone profile screens and the inline/ModelAdmin split they will create across `accounts` and `profiles` (research.md R-001). **Revised 2026-07-31**: the second entry this task originally asked for — `ClientProfile`'s untested rules — is dropped; the human closed that gap before implementation (research.md R-009)
- [ ] T063 Review `django_version/accounts/admin.py` and `django_version/profiles/admin.py` against `.claude/rules/conventions.md` *Code standards*: Google-style docstrings on every class and method, type hints on every signature, no inline comments, English only
- [ ] T064 Confirm no PII appears in the new `logger.error` calls in `django_version/profiles/models/freelancer_profile.py` and `django_version/profiles/models/client_profile.py` — no email, no name, no account-holder id (Principle VII)
- [ ] T065 Run the full suite: `docker-compose exec web pytest` from `django_version/`. Compare the passing count against the T004 baseline; every previously passing test must still pass (SC-009)
- [ ] T066 Run `docker-compose exec web python manage.py makemigrations --check --dry-run` from `django_version/` and confirm "No changes detected" — a non-empty result means a model change slipped in and must be raised before going further (Principle IV, research.md R-010)
- [ ] T067 Walk the full quickstart.md manual validation, sections A–F, and confirm every row behaves as stated — including section F's single intended exception, the absent timestamp section on the skill screens

---

## Dependencies & Execution Order

### Phase Dependencies

- **Phase 1 (Setup)**: No dependencies — start immediately.
- **Phase 2 (Foundational)**: Depends on Phase 1. **Blocks US2–US6.** Does
  **not** block US1.
- **Phase 3 (US1, P1)**: Depends on Phase 1 only. This is the MVP.
- **Phase 4 (US2, P2)**: Depends on Phase 2.
- **Phase 5 (US3, P3)**: Depends on Phase 2. Independent of US2, but shares two
  files with it — see the file-sharing note in Phase 5.
- **Phase 6 (US4, P4)**: Depends on Phases 4 and 5. It is verification of the
  combined screen, so both inlines must exist.
- **Phase 7 (US5, P5)**: Depends on Phase 2; meaningful data requires Phases
  4–5.
- **Phase 8 (US6, P6)**: Depends on Phase 2; shares both `list_filter` tuples
  with US5, so deliver alongside it.
- **Phase 9 (Polish)**: Depends on every story that is being shipped.

### User Story Dependencies

- **US1 (P1)** — fully independent. Ships alone as the MVP.
- **US2 (P2)** — needs Phase 2. Independent of US1 and US3.
- **US3 (P3)** — needs Phase 2. Independent of US1 and US2.
- **US4 (P4)** — needs US2 and US3; it verifies the whole combined screen.
- **US5 (P5)** — needs Phase 2; demonstrable once profiles exist.
- **US6 (P6)** — needs Phase 2; same two `list_filter` tuples as US5.

### Within Each Story

- Implementation precedes its tests (TDD is deliberately **not** mandated —
  constitution.md:39-46), and neither half is complete without the other
  (Principle IX).
- Model layer before admin layer: Phase 2's `clean()` branches exist before any
  inline surfaces them.
- Shared base before its subclasses: `BaseProfileInline` (T009) before
  `FreelancerProfileInline` (T022) and `ClientProfileInline` (T032).
- Verification gates (T053) run before the code that depends on them.

### Parallel Opportunities

- **Phase 1**: T002 and T003 run in parallel — different `conftest.py` files.
- **Phase 2**: T005 and T006 run in parallel — different model files. T008 runs
  in parallel with T007 — different test modules.
- **US1 vs Phase 2**: entirely disjoint file sets
  (`profiles/admin.py` + `profiles/tests/admin/` versus
  `profiles/models/` + `accounts/admin.py`), so the MVP can be built while the
  foundation is laid.
- **US2 vs US3**: logically independent, but both edit
  `accounts/admin.py` and `accounts/tests/admin/test_profile_inlines.py` — run
  them sequentially or on separate branches, never concurrently in the same
  file.
- **Phase 9**: T060, T061 and T062 run in parallel — three different documents.
- **Within a single test module**, tasks are sequential by construction. No `[P]`
  marker appears on two tasks writing the same file.

---

## Parallel Example: Phase 2 Foundational

```bash
# Two model files, no shared state — run together:
Task: "Add profile_for_inactive_account to FreelancerProfile.clean() in django_version/profiles/models/freelancer_profile.py"
Task: "Add profile_for_inactive_account to ClientProfile.clean() in django_version/profiles/models/client_profile.py"

# Then their tests, also in different modules:
Task: "FR-029 tests in django_version/profiles/tests/models/test_freelancer_profile.py"
Task: "Create django_version/profiles/tests/models/test_client_profile.py with FR-029 coverage"
```

## Parallel Example: MVP alongside the foundation

```bash
# Disjoint file sets — User Story 1 needs nothing from Phase 2:
Track A: T005–T010  (profiles/models/, accounts/admin.py)
Track B: T011–T021  (profiles/admin.py, profiles/tests/admin/)
```

---

## Implementation Strategy

### MVP First (User Story 1 only)

1. Complete Phase 1 (Setup).
2. Complete Phase 3 (US1 — `SkillAdmin`, including the FR-028 refusal).
3. **STOP and VALIDATE**: run `docker-compose exec web pytest profiles/tests/admin/ -v`
   and walk quickstart.md section A.
4. The skill vocabulary is now administrable on its own. This is a shippable
   increment — spec.md:47-49 states US1 "delivers standalone value even if
   nothing else ships".

Phase 2 is **not** required for the MVP. It is required for everything after.

### Incremental Delivery

1. Setup → baseline recorded.
2. **US1** → skill vocabulary administrable → demo (MVP).
3. Foundational → FR-029 enforced, shared inline base in place.
4. **US2** → freelancer profiles on the account screen → demo.
5. **US3** → client profiles on the account screen → demo.
6. **US4** → regression pass; the combined screen is proven.
7. **US5 + US6 together** → both account lists gain the badge and both filters
   → demo.
8. Polish → documentation, full suite, migration check, manual walkthrough.

### Parallel Team Strategy

With two developers, after Phase 1:

- Developer A: Phase 3 (US1) end to end — it shares no file with anything else.
- Developer B: Phase 2 (Foundational), then Phase 4 (US2).
- Both converge, then split Phase 5 (US3) and Phase 7+8 (US5/US6) — these two
  tracks touch different regions of `accounts/admin.py` and different test
  modules.
- Phase 6 (US4) is done once, by whoever finishes second.

---

## Notes

- `[P]` means different files and no dependency on an incomplete task.
- The `[Story]` label maps each task to a spec user story for traceability.
- Commit after each task or logical group; commit messages are multiline with
  bullet points, in English (`conventions.md`, *Code standards*).
- Stop at any checkpoint to validate a story independently.
- **Two verification gates carry recorded fallbacks** and cannot block
  delivery: the `list_filter` related path (T053/T054) and the
  `delete_selected` route through `get_deleted_objects()` (T020). Take the
  fallback rather than improvising a third option.
- If the code is found to diverge from spec.md, plan.md or this file, **stop and
  report** — neither the document nor the code may be silently assumed correct
  (Principle XII).
