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

- **No new dependency, no model field, and exactly one migration** (research.md
  R-010, amended 2026-08-05). That one migration is the
  `UniqueConstraint(Lower("name"))` on `Skill.Meta` required by FR-002 (T074,
  T075) — **scoped to `Skill` only**. Every other model stays under the original
  no-migration constraint. `makemigrations --check --dry-run` must report "No
  changes detected" at every point *except* between T074 and T075, and must
  report it again once T075 has been applied. See the *Migration exception* in
  Phase 10 and the amended T066.
  > This bullet previously read *"no model field, no migration … must stay clean
  > throughout"*. Corrected 2026-08-05 (T084): Phase 10 declared the exception
  > but this governing block, which is read first, was left contradicting it.
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
- [X] T013 [US1] Add the `get_deleted_objects(objs, request)` override to `SkillAdmin` in `django_version/profiles/admin.py`: count referring profiles as `skill.freelancerprofile_set.count() + skill.clientprofile_set.count()` across `objs`, and when the total is greater than zero return a `protected` collection holding a **single summary string** carrying the count — never one entry per profile (FR-028, research.md R-004). **⚠️ Counting method SUPERSEDED 2026-08-05 by T076 — do not implement the expression above.** It sums **references**, not distinct profiles: one profile referring to three selected skills contributes three, so a bulk selection over-reports (finding F-4), and it issues one `COUNT` per profile model per skill (finding F-6). Measured on the development database 2026-08-05: reported **7** where **3** profiles were affected. T076 replaces it with two aggregates over `FreelancerProfile` / `ClientProfile` filtered by the selection. **Still valid from this task**: the single-summary-string rule and the no-enumeration clause of FR-028, which T076 does not change. The `[X]` records that the override was built as specified at the time; the counting method is now wrong

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

- [X] T022 [US2] Add `FreelancerProfileInline(BaseProfileInline)` to `django_version/accounts/admin.py` with `model = FreelancerProfile`, importing from `profiles.models.freelancer_profile` — import `profiles.models`, **never** `profiles.admin` (research.md R-001)
- [X] T023 [US2] Define the `FreelancerProfileInline` fieldsets in `django_version/accounts/admin.py`: unnamed `("hourly_rate", "years_of_experience", "portfolio_url")`, `Skills` → `("skills",)`, `Biography` → `("bio",)`, `Important Dates` (collapsed) → `("created_at", "updated_at")` (FR-006, FR-021)
- [X] T024 [US2] Configure the `skills` widget on `FreelancerProfileInline` in `django_version/accounts/admin.py` so no add-related "+" control is rendered — the vocabulary is created only through the skill screens (FR-010). **Implemented differently from the literal wording, 2026-08-01, by human decision:** the suppression is a single `formfield_for_dbfield()` override on `BaseProfileInline` rather than a per-inline override, so `ClientProfileInline` inherits it and T034 needs no widget code (FR-022). The hook is `formfield_for_dbfield()`, **not** `formfield_for_manytomany()` — on Django 6.0.7 the `RelatedFieldWidgetWrapper` is built after the latter returns, so setting the flags there leaves the ➕ rendering (verified against the pinned version). Only `can_add_related` is set; `can_change_related` and `can_delete_related` are already `False` for any multi-select widget. `filter_horizontal = ("skills",)` added on the inline for usability. See contracts/admin-surface.md §2
- [X] T025 [US2] Attach `inlines = (FreelancerProfileInline,)` to `FreelancerAdmin` in `django_version/accounts/admin.py`, changing nothing else on that class (FR-024)

### Tests for User Story 2

All in `django_version/accounts/tests/admin/test_profile_inlines.py` (new file).

- [X] T026 [US2] Create `django_version/accounts/tests/admin/test_profile_inlines.py` and assert `FreelancerProfileInline` is attached to `FreelancerAdmin` and carries the `BaseProfileInline` contract: `extra == 1`, `max_num == 1`, `can_delete is False`, `has_delete_permission()` returns `False`, `readonly_fields == ("created_at", "updated_at")` (FR-007, FR-023, SC-006). Split into one test per attribute per the granularity rule in `testing.md`
- [X] T027 [US2] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert the `FreelancerProfileInline` fieldsets match contracts/admin-surface.md §2 exactly (FR-006, FR-021)
- [X] T028 [US2] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert the formset yields exactly **one** form for an account that already has a profile (no blank second form) and exactly one blank form for an account with none — including on the add form (FR-007, FR-032, FR-036, research.md R-005). **Finding, 2026-08-01:** these assertions are insensitive to the declared `max_num` — `inlineformset_factory` forces `max_num = 1` for a unique FK, so the guarantee comes from the `OneToOneField`, not from the attribute. The tests are kept as regression guards on the user-facing FR-007 behavior; the `max_num == 1` contract assertion lives in T026
- [X] T029 [US2] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert an untouched blank profile section creates **no** profile on save (`has_changed()` is `False`; `years_of_experience` defaults to `0` so the blank form compares equal to its initial data) (spec.md:246, FR-036)
- [X] T030 [US2] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert the existing profile rules surface through the inline as field-level errors with their established codes: `hourly_rate_not_positive` on the `hourly_rate` key and `max_length` on `bio` for a 501-character biography (FR-008, FR-020, US2 scenarios 3 and 6)
- [X] T031 [US2] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert the FR-029 core cases through the inline, reading the status **being saved** rather than the stored one: filling the section while unticking Active on a previously active account is refused, and filling it while ticking Active on a deactivated account is accepted (quickstart B10–B11 — passing B8 while failing these means the rule is reading the database, plan.md:223). Both cases confirmed to surface under the `user` key with code `profile_for_inactive_account`, per contracts/admin-surface.md §4

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

- [X] T032 [US3] Add `ClientProfileInline(BaseProfileInline)` to `django_version/accounts/admin.py` with `model = ClientProfile`, importing from `profiles.models.client_profile`
- [X] T033 [US3] Define the `ClientProfileInline` fieldsets in `django_version/accounts/admin.py`: unnamed `("company_name", "max_budget", "website_url")`, `Interests` → `("interests",)`, `Biography` → `("bio",)`, `Important Dates` (collapsed) → `("created_at", "updated_at")` (FR-013, FR-021)
- [X] T034 [US3] Configure the `interests` widget on `ClientProfileInline` in `django_version/accounts/admin.py` so no add-related "+" control is rendered (FR-010). **Satisfied by inheritance, 2026-08-04 — no widget code written.** The suppression is the `formfield_for_dbfield()` override placed on `BaseProfileInline` by T024, which `ClientProfileInline` inherits unchanged (FR-022). Verified load-bearing rather than assumed: deleting the assignment on the base fails `test_interests_widget_offers_no_add_related_control` and `test_rendered_interests_widget_carries_no_add_related_link`. Only `filter_horizontal = ("interests",)` was added on the inline (decision D2)
- [X] T035 [US3] Attach `inlines = (ClientProfileInline,)` to `ClientAdmin` in `django_version/accounts/admin.py`, changing nothing else on that class (FR-024)

### Tests for User Story 3

> **Test file split, 2026-08-04, by human decision.** `test_profile_inlines.py`
> had grown too large to absorb a second inline's tests. It was renamed
> (`git mv`, history preserved) to
> `django_version/accounts/tests/admin/test_freelancer_profile_inline.py`, and
> T036–T039 landed in a new sibling
> `django_version/accounts/tests/admin/test_client_profile_inline.py`. One file
> per inline matches the one-to-one source-mirroring rule in `testing.md`, and it
> removes the fixture-name ambiguity a merged file would have created — each file
> now owns an unqualified `valid_profile_section_data` meaning its own model. The
> task paths below are superseded by these two files.

- [X] T036 [US3] In `django_version/accounts/tests/admin/test_client_profile_inline.py`, assert `ClientProfileInline` is attached to `ClientAdmin` and carries the `BaseProfileInline` contract (FR-014, FR-023)
- [X] T037 [US3] In `django_version/accounts/tests/admin/test_client_profile_inline.py`, assert the `ClientProfileInline` fieldsets match contracts/admin-surface.md §2 exactly (FR-013, FR-021)
- [X] T038 [US3] In `django_version/accounts/tests/admin/test_client_profile_inline.py`, assert the client rules surface through the inline with their established codes: `max_budget_not_positive` on `max_budget`, and `company_name_empty` on `company_name` for a whitespace-only name (FR-015, FR-016, US3 scenarios 3 and 4). **Delivered in part, 2026-08-04 — the `company_name_empty` half is unreachable through the inline and was deliberately not written.** Django's form `CharField` carries `strip=True`, so `"   "` is cleaned to `""` before `ClientProfile.clean()` runs; `if self.company_name:` is then False and the branch never fires. Verified against the pinned 6.0.7 both at the field (`formfield().clean("   ")` returns `""`) and end-to-end through the bound formset, which reports **valid with no errors**. Per `testing.md` *A test must fail if the behavior under test is removed*, a test asserting the code here would simply fail, and one asserting the acceptance would pass with the model branch deleted — tautological, testing Django's `strip`, not our code. The invariant remains covered at its own layer by `profiles/tests/models/test_client_profile.py:86`. `max_budget_not_positive` is reachable and is asserted
- [X] T039 [US3] In `django_version/accounts/tests/admin/test_client_profile_inline.py`, assert the client formset behaves as US2's does — one form when a profile exists, one blank form when none, nothing created from an untouched section — and that FR-029 is enforced through the client inline (FR-014, FR-032, FR-036). FR-029 asserted under the `__all__` key, not `user` — `ProfileInlineForm` relocates it to the form level. Both the refusal and the relocation were mutation-checked

**Checkpoint**: Both profile types are managed from their account screens.
Validate with quickstart.md section C.

---

## Phase 5.1: Artifact repairs — align the spec set before Phase 10 (added 2026-08-05)

**Origin**: the cross-artifact analysis of 2026-08-05, run after the FR-002
amendment of 2026-08-04 had been propagated into `spec.md`, `data-model.md`,
`contracts/admin-surface.md`, `.claude/rules/conventions.md` and `tasks.md`
(T068–T072). That propagation **stopped short of three artifacts**, and the
audit's finding F-7 was never closed at all.

**Goal**: no artifact contradicts another before any Phase 10 code is written.

**Why this blocks Phase 10, and why it is not "respecting a wrong spec".**
Principle XII says *"neither the document nor the code may be silently assumed
correct"* — so an implementer who opens `plan.md`, reads "no migration", and then
reaches T074 **must stop and report**. Three of these repairs remove exactly that
stop-work condition. They do not overrule any decision: the decision (FR-002
case-insensitive, one migration) was made by the human on 2026-08-04 and is
recorded in `spec.md` *Clarifications*. These files are simply **stale**.
Finishing the propagation is bookkeeping, not a change of direction.

T083 is different in kind: it puts a rule into the spec that T073 already
implements but that no requirement stated. That one is a genuine gap, and the
spec is the right place for it under Principle XII.

**Depends on**: nothing. **Blocks**: Phase 10 (T073–T080).

- [X] T081 [P] Amend `specs/001-profiles-admin-panel/plan.md` for the one intended migration and the Principle X exception: the Summary's "no dependency, no field and no migration"; **Technical Context → Storage** ("Schema unchanged"); **Technical Context → Constraints** ("No model field and no migration"); the **Constitution Check row IV** verdict, which reads "PASS — feature generates no migration at all" and is a false PASS on a NON-NEGOTIABLE gate; **row X**, which records the FR-027 deletion exception as a plain PASS without noting it is absent from the constitution; the source tree, which omits `profiles/models/skill.py`, `profiles/migrations/` and `test_skill.py`; and *Follow-ups*, which omits F-7 and `skill_name_duplicate`. Add a dated amendment note in the shape used by `data-model.md:14-18`. **This is the highest-value repair in the phase** — plan.md is one of the three core artifacts and the only one still asserting the opposite of the approved decision
- [X] T082 [P] Amend `specs/001-profiles-admin-panel/research.md`: **R-010** ("No new dependencies, no migrations" → exactly one, scoped to `Skill`; *"alters no field and no database schema, so `makemigrations` produces nothing"*), and the closing line of **R-002** (*"No model field is added and no migration is generated"* — the first half stands, the second does not). Both are cited by `tasks.md` as the authority for the constraint Phase 10 supersedes, so leaving them unamended points the exception back at an unamended source. R-002's substance — the FR-021 narrowing, no timestamp field on `Skill` — is unchanged and must stay so
- [X] T083 [P] Add the **self-conflict rule** to `specs/001-profiles-admin-panel/spec.md`, which currently states it nowhere: FR-002's closing clause (*"an existing name MUST NOT be silently rewritten to the casing just submitted"*) reads on its own as forbidding `Python` → `python` on the same record, yet T073's self-exclusion, T077's fourth bullet and `data-model.md:153-156` all depend on it being permitted, attributing it to FR-005. Add the clause to FR-002, a pointer on FR-005, US1 acceptance scenarios for recasing-in-place and for saving unchanged, and a *Skills* edge case. **Blocks T073** — without it, T073 implements a rule the spec does not carry
- [X] T084 [P] Repair `specs/001-profiles-admin-panel/tasks.md` itself: annotate **T013** as superseded by T076 (it prescribes the reference-summing count T076 forbids, is marked `[X]`, and carries no revision note — unlike T008, T024, T034, T038 and T066, which all do); correct the **Constraints that govern every task** block, which still says "no migration … must stay clean throughout"; give **T065** and **T067** the ordering amendment only T066 received; rewrite **Dependencies & Execution Order**, which stopped at Phase 9 and never mentioned Phase 10; add Phase 5.1 and Phase 10 to **Incremental Delivery**; and fix **T078**'s positional `[0].code` assertion, which cannot reach the two codes its own whitespace bullet requires
- [X] T085 [P] Close finding **F-7** in `.claude/rules/conventions.md` *Admin conventions*, which still states `has_delete_permission` returns `False` on **all** admin classes — false since T012, and the audit recorded that the unqualified rule "invites a future session to 'fix' `SkillAdmin` back and break FR-027". Record the `SkillAdmin` exception in **two terse bullets**: the rule now reads "every admin class except `SkillAdmin`", and a second bullet states that `SkillAdmin` permits deletion, why (`Skill` has no `is_active` field), what guards it (`get_deleted_objects()`; `on_delete` has no effect on a `ManyToManyField`), the standing instruction not to suppress it, and a pointer to `docs/adr/skill-is-the-only-deletable-record.md`. Also drop the `skill_name_duplicate` entry's claim to be *"the only `clean()` that queries the database"* being the whole story — `FreelancerProfile.clean()` and `ClientProfile.clean()` dereference `self.user` via `_get_account()`, which issues a `SELECT` when the relation is not cached; that nuance belongs in the ADR, not here.
  > **Constraint on this task, set by the human 2026-08-05.** `conventions.md` is auto-loaded into every session and records **architecture and code/documentation conventions only**. It MUST NOT mention requirement IDs, task IDs, finding IDs, spec paths, phases, user stories, or the roadmap: those are transient, they rot when a feature directory is archived, and they cost context on every session. State the rule; put the reasoning and the audit trail in an ADR and link it. The first version of this task's output violated this and was rewritten. Verify with: `grep -nE "FR-[0-9]|SC-[0-9]|T0[0-9][0-9]|F-[0-9]|specs/|Phase [0-9]|US[0-9]" .claude/rules/conventions.md` — must return nothing
- [X] T087 [P] Record the two substantive decisions behind this feature's `Skill` work as ADRs in `docs/adr/`, following the MADR shape of the two existing files (`**Date:** / **Status:** / **Applies to:**`, *Context and Problem Statement*, *Considered Options*, *Decision Outcome*, a forward-looking constraint in a blockquote, and `* Good/Bad, because …` consequences): `skill-is-the-only-deletable-record.md` — why `Skill` is exempt from deactivate-never-delete, why `get_deleted_objects()` is the guard, why it counts distinct profiles over two aggregates, and the two standing constraints that must not be reverted; and `case-insensitive-skill-name-uniqueness.md` — why `clean()` plus `UniqueConstraint(Lower("name"))` rather than either alone, why a case-insensitive collation was rejected, why `unique=True` stays, why storage is never normalized, and why the `unique` code becomes unreachable. **Like the ADRs already in that directory, these reference code and behavior only — no requirement, task or finding IDs.** One decision per file, matching the `docs/tech_debt/` rule in `CLAUDE.md`. These absorb the reasoning removed from `conventions.md` by T071/T085 and the `get_deleted_objects()` half formerly assigned to `ARCHITECTURE.md` by T061
- [ ] T086 Close the **Principle X** gap in `.specify/memory/constitution.md`: it states *"Deletion is disabled in the admin"*, which FR-027, SC-006 and `SkillAdmin` contradict by design. **Requires explicit human approval and a version bump** — Governance mandates that amendments be *"recorded in the Sync Impact Report at the top of this file"* and carry a bump, and that a contradiction be *"raised with the human and resolved explicitly — never silently"*. An inline note would be that silent resolution, so this is the one repair in the phase that must **not** be applied unilaterally. Route: `/speckit-constitution`. Principle X's own closing sentence already permits the exception (*"Introducing physical deletion requires revisiting this policy explicitly and documenting it"*), and the human approved it on 2026-07-28 (plan.md), so this records a decision already taken rather than making a new one. **Do before T081's row X edit**, so the plan can cite the amended principle

**Checkpoint**: every artifact tells the same story. `grep -rn "no migration"`
across `specs/001-profiles-admin-panel/` and `plan.md` returns only amended,
dated notes. Phase 10 can start without a Principle XII stop-work.

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

> **⚠️ Execution order, 2026-08-05: Phase 5.1 and Phase 10 run before this
> phase.** Phase 10 changes `profiles/models/skill.py` and `profiles/admin.py`
> and repairs two tests; running the verification gates here and in Phase 9
> first means running them twice. See *Dependencies & Execution Order*, which is
> authoritative. Phase 6 itself is unaffected by Phase 10's changes — the file
> sets are disjoint — so the two may also run in parallel.

- [ ] T040 [US4] Run `docker-compose exec web pytest accounts/tests/admin/test_admin.py -v` from `django_version/` and confirm every test passes **unchanged** — this is the SC-009 gate. If any test needs modification, stop and report: only the three additions FR-024 names as intended are permitted to change behavior (Principle XII)
- [ ] T041 [US4] In `django_version/accounts/tests/admin/test_profile_inlines.py`, assert a profile rule violation raised from the account screen surfaces as a field-level error inside the profile section and never as an unhandled failure (FR-020, US4 scenario 4, SC-004). **Partly delivered in Phase 4, 2026-08-01**: manual validation found that `profile_for_inactive_account`, keyed to the hidden `user` field, was rendered nowhere — the screen showed only "Please correct the error below". Fixed by `ProfileInlineForm` on `BaseProfileInline`, covered by three tests in that module. What remains for T041 is the client-side equivalent and the "never an unhandled failure" half. See research.md R-003, *Correction, 2026-08-01*
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
- [ ] T061 [P] Record the FR-021 narrowing for the skill screens as an **ADR in `docs/adr/`** — no timestamps on `Skill`, so the timestamp and most-recent-first clauses are narrowed to apply only where the model carries those fields; ordering stays `("category", "name")` (research.md R-002). MADR short form, under ~60 lines, referencing code and behavior only — see *Recording decisions* in `conventions.md`. **Retargeted twice on 2026-08-05.** It originally asked for two decisions in `ARCHITECTURE.md`: (1) this FR-021 narrowing and (2) the FR-028 `get_deleted_objects()` mechanism. The second is already written as `docs/adr/skill-is-the-only-deletable-record.md` (T087) — do **not** duplicate it. The first moved out of `ARCHITECTURE.md` because that file is now **closed to new entries** by human decision and will itself be refactored into `docs/adr/`; all new architectural decisions are ADRs from now on
- [ ] T062 [P] Add one file to `docs/tech_debt/` (one decision per file, ADR-style — the directory replaced the single `tech_debt.md` on 2026-08-04): the deferred standalone profile screens and the inline/ModelAdmin split they will create across `accounts` and `profiles` (research.md R-001). **Revised 2026-07-31**: the second entry this task originally asked for — `ClientProfile`'s untested rules — is dropped; the human closed that gap before implementation (research.md R-009)
- [ ] T063 Review `django_version/accounts/admin.py` and `django_version/profiles/admin.py` against `.claude/rules/conventions.md` *Code standards*: Google-style docstrings on every class and method, type hints on every signature, no inline comments, English only
- [ ] T064 Confirm no PII appears in the new `logger.error` calls in `django_version/profiles/models/freelancer_profile.py` and `django_version/profiles/models/client_profile.py` — no email, no name, no account-holder id (Principle VII)
- [ ] T065 Run the full suite: `docker-compose exec web pytest` from `django_version/`. Compare the passing count against the T004 baseline; every previously passing test must still pass (SC-009). **Amended 2026-08-05: run this after Phase 10, never between T073 and T077.** T073 makes `test_skill.py`'s `test_skill_name_uniqueness` assertion (`code == "unique"`) unreachable and `test_skill_clean_strips_whitespace` hit pytest-django's DB blocker; T077 repairs both. Running T065 in that window reports failures that are expected and already accounted for, which would be misread as an SC-009 regression
- [ ] T066 Run `docker-compose exec web python manage.py makemigrations --check --dry-run` from `django_version/` and confirm "No changes detected" — a non-empty result means a model change slipped in and must be raised before going further (Principle IV, research.md R-010). **Amended 2026-08-05:** the FR-002 clarification of 2026-08-04 introduces **exactly one intentional migration** in `profiles/` — the `UniqueConstraint(Lower("name"))` on `Skill.Meta` (T074), generated and applied by T075. This gate now means: that migration exists, is committed **and is applied**, and the check reports "No changes detected" **afterwards**. Run this task after Phase 10, never before it. Any pending change beyond that one migration still means a model change slipped in and must be raised before going further
- [ ] T067 Walk the full quickstart.md manual validation, sections A–F, and confirm every row behaves as stated — including section F's single intended exception, the absent timestamp section on the skill screens. **Amended 2026-08-05: requires T080 first, and must run after Phase 10.** T080 adds rows A10 and A11, which are the only manual coverage of the amended FR-002; walking section A before T080 exercises the old rule and silently proves nothing about the new one. The schema-drift step and the *Done when* checklist in quickstart.md were corrected on 2026-08-05 to expect the one intended migration

---

## Dependencies & Execution Order

> **This section is the authoritative execution order.** Where a phase's
> physical position in this file differs from its position here, **this section
> wins**. Phase 5.1 and Phase 10 were both added after the original phases were
> written, and Phase 10's body sits at the end of the file for reference
> stability (it is cross-referenced by ID from T066, T065, T067 and from
> `docs/skill-admin-findings-2026-08-04.md`), not because it runs last.
> Rewritten 2026-08-05 (T084) — the previous version stopped at Phase 9 and
> never mentioned Phase 10, which is why T066 needed a hand-written "run this
> after Phase 10" note to compensate.

### Authoritative order

```text
Phase 1 → Phase 2 → Phase 3 → Phase 4 → Phase 5
       → Phase 5.1  (artifact repairs — BLOCKING, see below)
       → Phase 10   (FR-002 + audit follow-up: code, tests, migration)
       → Phase 6 → Phase 7 → Phase 8 → Phase 9
```

**Why Phase 10 moved ahead of Phases 6–9** *(decision 2026-08-05)*: Phases 6
and 9 are almost entirely whole-system verification gates (T040, T063, T065,
T066, T067), and Phase 10 changes the code and tests those gates measure.
Running the gates first means running them twice, and T065 in particular
**fails** if run between T073 and T077. The governing rule is: **every code and
test change lands before every whole-system verification gate.**

Phase 10 is safe to move because its file set —
`profiles/models/skill.py`, `profiles/admin.py`, `profiles/tests/models/test_skill.py`,
`profiles/tests/admin/test_skill_admin.py` — is **disjoint** from the file set of
Phases 6–8 (`accounts/admin.py`, `accounts/tests/admin/`). The two could even run
in parallel; sequential is simpler.

### Phase Dependencies

- **Phase 1 (Setup)**: No dependencies — start immediately.
- **Phase 2 (Foundational)**: Depends on Phase 1. **Blocks US2–US6.** Does
  **not** block US1.
- **Phase 3 (US1, P1)**: Depends on Phase 1 only. This is the MVP.
- **Phase 4 (US2, P2)**: Depends on Phase 2.
- **Phase 5 (US3, P3)**: Depends on Phase 2. Independent of US2, but shares two
  files with it — see the file-sharing note in Phase 5.
- **Phase 5.1 (Artifact repairs)**: Depends on nothing but must complete
  **before Phase 10**. T081/T082/T083 remove Principle XII stop-work conditions
  that would otherwise halt T073–T075; T083 supplies the FR-005 self-conflict
  rule T073 implements. **Blocks Phase 10.**
- **Phase 10 (FR-002 + audit follow-up)**: Depends on Phase 3 (complete) and
  Phase 5.1. **Blocks T063, T065, T066 and T067** in Phase 9. Independent of
  Phases 6, 7 and 8 — disjoint file sets.
- **Phase 6 (US4, P4)**: Depends on Phases 4 and 5. It is verification of the
  combined screen, so both inlines must exist.
- **Phase 7 (US5, P5)**: Depends on Phase 2; meaningful data requires Phases
  4–5.
- **Phase 8 (US6, P6)**: Depends on Phase 2; shares both `list_filter` tuples
  with US5, so deliver alongside it.
- **Phase 9 (Polish)**: Depends on every story that is being shipped **and on
  Phase 10**. T063 reviews `profiles/admin.py`, which T076 rewrites; T065, T066
  and T067 are the final gates and must see the finished state.

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
6. **Phase 5.1** → the spec artifacts agree with each other again; Principle XII
   stop-work conditions cleared.
7. **Phase 10** → FR-002 case-insensitive uniqueness (+ migration), the F-4/F-6
   count correction, and the F-3 admin tests → demo the refusal of `python`
   against `Python`.
8. **US4** → regression pass; the combined screen is proven.
9. **US5 + US6 together** → both account lists gain the badge and both filters
   → demo.
10. Polish → documentation, full suite, migration check, manual walkthrough.

> Steps 6 and 7 were inserted on 2026-08-05. They were previously numbered
> Phase 10 and listed nowhere in this sequence, which implied Polish was last.

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

---

## Phase 10: FR-002 case-insensitive skill-name uniqueness, and the skill-admin audit follow-up (added 2026-08-05)

**Origin**: the read-only audit in `docs/skill-admin-findings-2026-08-04.md`
(findings F-1, F-2, F-3, F-4, F-5, F-6) and the `/speckit-clarify` session of
2026-08-04, whose two answers are recorded under *Clarifications* in
[spec.md](./spec.md) and rewrote FR-002.

**Goal**: `python` is refused while `Python` exists, reported against the name
field, with the stored spelling never rewritten — enforced in `Skill.clean()`
and backed by a database constraint. Plus the three smaller corrections the same
audit produced: the missing admin tests (F-3), the inflated in-use count (F-4)
and the per-skill query count (F-6).

**Depends on**: Phase 3 (User Story 1), which is complete, **and Phase 5.1**,
which clears the Principle XII stop-work conditions in `plan.md` and
`research.md` and supplies the FR-005 self-conflict rule T073 implements. This
phase amends what T011–T021 built.

**Position in the execution order**: this phase runs **after Phase 5.1 and
before Phase 6** — not last, despite sitting at the end of this file. Its body
stays here for reference stability (it is cross-referenced by ID from T065,
T066, T067 and from `docs/skill-admin-findings-2026-08-04.md`). *Dependencies &
Execution Order* is authoritative. It **blocks** T063, T065, T066 and T067.

**Decisions already taken — do not reopen** (human, 2026-08-04 / 2026-08-05):

- Uniqueness is **case-insensitive**; storage is **not** normalized. The name is
  stored exactly as entered, trimmed only; on a conflict the existing skill
  keeps its spelling (spec.md *Clarifications*, FR-002).
- Mechanism: a case-insensitive check in `Skill.clean()` raising a new code on
  `name`, **plus** `UniqueConstraint(Lower("name"))` in `Skill.Meta` as the
  database backstop. This mirrors `freelancer_no_inactive_available`
  (`ARCHITECTURE.md`, *Freelancer — Active/Availability Invariant*). A
  constraint alone is not viable: Django reports expression-based constraint
  violations under `NON_FIELD_ERRORS`, which fails FR-002's "reporting the
  conflict against the name field". Verified against the pinned 6.0.7 on
  2026-08-05: `UniqueConstraint.validate()` raises with no field key;
  `Model.validate_constraints()` routes to a field only when the code is
  `unique` **and** the constraint declares exactly one `fields` entry, which an
  expression constraint does not; so `ValidationError.update_error_dict()` files
  it under `NON_FIELD_ERRORS`.
- Error code: `skill_name_duplicate`. Constraint name:
  `skill_unique_name_case_insensitive`.
- `unique=True` **stays** on the field. Removing it would add an `AlterField` to
  the migration for no behavioural gain.
- Recasing a skill **in place** (`Python` → `python` on that same row) stays
  permitted — that is FR-005. The lookup must exclude the row being saved.
- **F-5 does not become a constraint.** Recorded as technical debt instead —
  `docs/tech_debt/in-use-skill-removal-has-no-backstop-outside-the-admin.md`.

**Migration exception — scoped to this phase.** The constraint at the top of
this file (*"No new dependency, no model field, no migration"*, research.md
R-010) is superseded **for `Skill` only** by the FR-002 amendment. This phase
adds exactly **one** migration and no field. Every other model stays under the
original constraint, and T066 is amended accordingly.

**Migration pre-condition — closed.** A read-only query on 2026-08-05 returned
32 skills and **0** colliding groups on `LOWER(name)` in the development
database. The migration will not abort on existing data. Re-run the check
against any other environment before migrating it.

### Artifact amendments (applied 2026-08-05 during planning)

- [X] T068 [P] [US1] Propagate the FR-002 amendment into `specs/001-profiles-admin-panel/data-model.md`: the "no migration" claim in the opening paragraph, the `name` row of the `Skill` table, the removal of the `unique` (Django) row from *Already enforced*, and the new `skill_name_duplicate` row in *New — the model changes this feature makes* with the notes governing its implementation
- [X] T069 [P] [US1] Revise `specs/001-profiles-admin-panel/contracts/admin-surface.md` §4: the duplicate-name row is **revised in place** to `skill_name_duplicate` (not complemented — `unique` becomes unreachable on any path that runs `clean()`, so two rows for one trigger would document an impossible outcome); the whitespace row is corrected to `required` **and** `skill_name_empty` (finding F-2b, verified through the bound form on 6.0.7); the "only new code this feature introduces" paragraph now names both codes; §6 drops "no migration"
- [X] T070 [P] [US1] Revise `specs/001-profiles-admin-panel/contracts/admin-surface.md` §1: the `get_deleted_objects()` contract now prescribes **distinct profiles** over two aggregate queries instead of summing `freelancerprofile_set.count() + clientprofile_set.count()` per skill (findings F-4 and F-6). Measured on the development database, 2026-08-05: the old prescription reported 7 where 3 profiles were affected
- [X] T071 [P] [US1] Add `skill_name_duplicate` to the *Established invariants* list in `.claude/rules/conventions.md`, following the terse shape of the existing entries: the rule, the code, the database backstop, and the `@pytest.mark.django_db` consequence. **Separate from T060**, which covers `profile_for_inactive_account` — both codes must be listed, neither replaces the other. **Revised 2026-08-05, by human decision:** the entry as first written explained *why* the constraint cannot carry the message (Django's `NON_FIELD_ERRORS` routing). That is Django behavior, not a project convention, and `conventions.md` is auto-loaded into every session — it states what to do, not why. The reasoning moved to `docs/adr/case-insensitive-skill-name-uniqueness.md` (T087) and the entry now points there. **`conventions.md` must contain no requirement, task, finding, or roadmap reference of any kind**
- [X] T072 [P] [US1] Record finding F-5 in `docs/tech_debt/in-use-skill-removal-has-no-backstop-outside-the-admin.md`, following the format of `whitespace-only-company-name-accepted-in-admin.md`, with four reversal criteria and the steps to take when one fires

### Implementation

- [X] T073 [US1] Add the case-insensitive duplicate check to `Skill.clean()` in `django_version/profiles/models/skill.py`, **after** the existing strip and empty-name branches so FR-003 is applied before FR-002 (spec.md, *Skills* edge cases). Follow the required `clean()` shape in `conventions.md`: `logger.error` with no PII (log no name, no value — the name is not PII but the pattern logs derived facts only), message wrapped in `gettext_lazy`, and `raise ValidationError({"name": ValidationError(_(...), code="skill_name_duplicate")})`. The lookup is case-insensitive over the vocabulary and **must exclude the row being saved**, or editing a skill without changing its name would refuse itself and FR-005 recasing would become impossible. Skip the lookup when `name` is `None` or empty — the branches above have already spoken
- [X] T074 [US1] Add `constraints = [UniqueConstraint(Lower("name"), name="skill_unique_name_case_insensitive")]` to `Skill.Meta` in `django_version/profiles/models/skill.py`, importing `Lower` from `django.db.models.functions`. Keep `unique=True` on the field. This is the backstop for `.create()`, `.update()`, `bulk_create()` and shell writes, which never call `clean()` (`conventions.md`, *clean() is not called automatically*)
- [X] T075 [US1] Generate and apply the migration: `docker-compose exec web python manage.py makemigrations profiles` then `migrate`, from `django_version/`. **Requires explicit human approval before running** (`CLAUDE.md` Rule 10). Confirm the result is a single `AddConstraint` operation and nothing else — an `AlterField` in the output means `unique=True` was removed by mistake. The pre-condition is closed (0 collisions on 2026-08-05); if the command is ever run against another environment, re-check `LOWER(name)` collisions there first, because the migration aborts on one
- [X] T076 [US1] Correct `SkillAdmin.get_deleted_objects()` in `django_version/profiles/admin.py` to count **distinct profiles** rather than references, per the revised contract in contracts/admin-surface.md §1 — one aggregate over `FreelancerProfile` and one over `ClientProfile`, filtered by the selected skills, two queries whatever the selection size (findings F-4 and F-6 in one change). The refusal message, the single-summary-string rule and the no-enumeration clause of FR-028 are unchanged. Import the profile models from `profiles.models.*`, never from `profiles.admin` (research.md R-001)

### Tests

- [X] T077 [US1] Extend `django_version/profiles/tests/models/test_skill.py` for the new rule, and repair the two tests it invalidates:
  - `python` against an existing `Python` raises `skill_name_duplicate` on the `name` key — assert the key is in `error_dict` first, then the code (`testing.md`)
  - `"  python  "` against `Python` is refused with the same code — proves the trim runs before the comparison
  - saving an existing skill without changing its name is **accepted** — this is the test that fails if the self-exclusion is missing
  - recasing a skill in place (`Python` → `python` on that row) is accepted (FR-005)
  - a lowercase duplicate written through a path that skips validation raises `IntegrityError` — the database backstop, mirroring the existing `test_skill_name_uniqueness_enforced_at_database_level`
  - **repair 1**: `test_skill_name_uniqueness` asserts `code == "unique"`, which the change makes unreachable — `Model.full_clean()` excludes any field that already failed before running `validate_unique()`. Update the assertion to `skill_name_duplicate`. Verified against the pinned 6.0.7 on 2026-08-05: the same call returns `['unique']` today and `['skill_name_duplicate']` with the rule in place
  - **repair 2**: `test_skill_clean_strips_whitespace` has no `@pytest.mark.django_db` and does not need one today, because `clean()` is pure Python. Once `clean()` issues its lookup, the test hits pytest-django's blocker (`RuntimeError: Database access not allowed`). Add the marker. The other two `clean()` tests stay marker-free and must remain so: the empty-name test raises before the lookup, and the `None`-name test never reaches it
- [X] T078 [US1] Add the missing admin-path coverage to `django_version/profiles/tests/admin/test_skill_admin.py` (finding F-3 — FR-002 and FR-003 have no admin-layer test at all today). Drive the real form, `SkillAdmin(Skill, site).get_form(request)`, and assert codes through `form.errors.as_data()`, the pattern already used in `accounts/tests/admin/`. Assert the `name` key is present first, then the code — per `testing.md`. For the single-code cases `[0].code` is fine; for the two-code whitespace case below, compare the **set** of codes (`{e.code for e in form.errors.as_data()["name"]}`) rather than indexing, so the test does not encode Django's internal error ordering (`clean_fields()` before `clean()`) as if it were the contract:
  - an exact duplicate is refused with `skill_name_duplicate`
  - a case variant is refused with the same code, **and the existing skill still carries its original spelling** (FR-002's "the existing skill keeps its stored name")
  - `"  python  "` is refused — case and whitespace combined
  - a whitespace-only name yields **both** `required` and `skill_name_empty` on `name` (finding F-2b; a test asserting exactly one error would fail)
  - a brand-new name is accepted, so the rule is proven to refuse duplicates rather than everything
  - a saved skill renamed onto another saved skill's name is refused through the **change** form — `get_form(request, obj=skill)`, with the bound form carrying `instance=skill`
  - **Do not write a test asserting that the admin trims a name** (finding F-2a). The form's `CharField` carries `strip=True`, so such a test asserts Django's stripping and keeps passing with `Skill.clean()` deleted — tautological under `testing.md`'s *"a test must fail if the behavior under test is removed"*. The trim is covered on the model path, where it is reachable
  > **Sixth case added 2026-08-07.** This task originally prescribed five cases,
  > all of them driving `get_form(request)` — the *add* form, with no instance.
  > Django builds a different form for add and for change, and only the change
  > form produces a bound `ModelForm` whose `_post_clean()` runs `full_clean()`
  > on a model that already has a primary key. That is the saved path FR-002
  > exists to guard, and five add-form tests would have left it undriven —
  > reproducing the shape of the gap this task was written to close.
- [X] T079 [US1] Add the coverage T018 cannot provide, in `django_version/profiles/tests/admin/test_skill_admin.py`: several skills selected together, all referred to by the **same single profile**, produce a count of **1** — the current implementation reports one per reference and would say 3. Add a query-count guard with `django_assert_num_queries` showing the count does not scale with the size of the selection (finding F-6). T018 uses one skill and three profiles, which is the case where references and profiles happen to be equal, which is why it never caught this

### Manual validation

- [X] T080 [US1] Add three rows to `specs/001-profiles-admin-panel/quickstart.md` section A, after the existing A9, in the same table format: **A10** — with `Python` in the vocabulary, adding `python` is refused with a message on the name field, no second row is created, and the existing skill is still spelled `Python` (US1-8, FR-002); **A11** — adding `JavaScript` stores it exactly as `JavaScript`, with no capitalization rule applied (US1-9, FR-002 storage clause); **A12** — opening an existing skill and renaming it onto **another** skill's name, differing only in case, is refused with a message on the name field, and both skills keep their stored names (FR-002, edit path). T067 walks section A and would otherwise never exercise the amended rule
  > **Third row added 2026-08-07.** This task originally prescribed two rows,
  > both of them on the *add* form. Manual validation earns its place where a
  > test cannot reach: whether the message actually renders beside the name
  > field in the real admin template. Django renders the add form and the change
  > form through different bound form states, so a row that passes on one proves
  > nothing about the other. The automated coverage added to T078 proves the
  > code refuses the rename; A12 proves the message renders on the screen an
  > operator edits from

### Dependencies within this phase

- T068–T072 are applied. They touch five different documents and were
  independent of each other.
- T073 → T074 → T075 in sequence: the model rule, then the constraint, then the
  single migration carrying it.
- T076 is independent of T073–T075 — a different file and a different finding.
  It can be done first.
- T077 requires T073 and T074 (the `IntegrityError` case needs the constraint in
  the test schema; `--no-migrations` builds it straight from `Meta`, so T075 is
  not required for the suite to see it).
- T078 requires T073. T079 requires T076.
- T080 is independent of everything and can be written at any point.
- **T066 must run after this phase**, never before — see its amendment.
