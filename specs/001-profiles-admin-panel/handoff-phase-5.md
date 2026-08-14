# Handoff: Phase 5 (User Story 3 — client profile inline)

**Written**: 2026-08-01, at the end of the session that delivered Phase 4.
**For**: the next session, which implements T032–T039.

This file carries the state and the decisions that are **not** recoverable from
`tasks.md`, `plan.md` or the code alone. Read it before starting, then follow
`tasks.md` as the authority on what to build.

> **⚠️ SPENT — historical snapshot. Superseded 2026-08-05.** Phase 5 (T032–T039)
> is complete. This file records the state as of 2026-08-01 and is kept for its
> decision record only. **Two statements below are no longer true:** the test
> baseline has moved on, and *"this feature generates no migration"* was
> overtaken by the FR-002 clarification of 2026-08-04, which adds exactly one
> `AddConstraint` migration on `Skill` (tasks.md T074/T075). Do not take the
> `makemigrations` guidance below as current — see the amended T066.

---

## 1. Where the feature stands

| Phase | Status |
|---|---|
| Phase 1 — Setup (T001–T004) | Complete, marked `[X]` |
| Phase 2 — Foundational (T005–T010) | Complete, marked `[X]` |
| Phase 3 — US1, SkillAdmin (T011–T021) | Complete, marked `[X]` |
| **Phase 4 — US2, freelancer inline (T022–T031)** | **Complete, marked `[X]`, committed** |
| Phase 5 — US3, client inline (T032–T039) | **Not started — this is the next work** |

**Test baseline: 236 passing** (`docker-compose exec web pytest` from
`django_version/`). Phase 5 must leave every one of them passing; the count only
grows. `makemigrations --check --dry-run` reports **"No changes detected"** and
must keep reporting it — this feature generates no migration.
`accounts/tests/admin/test_admin.py` still passes unchanged (the SC-009 gate).

Quickstart section B was validated manually in the browser, including B8 and the
FR-029 refusal message now rendering visibly.

---

## 2. Phase 5 is mostly inheritance — read this before writing anything

`BaseProfileInline` grew in Phase 4. `ClientProfileInline` inherits **all** of
it, so T034 needs **no code at all** and several tasks are smaller than their
wording suggests.

What the base already provides (`django_version/accounts/admin.py`):

```python
class BaseProfileInline(admin.StackedInline):
    form = ProfileInlineForm          # moves hidden-field errors to form level
    extra = 1
    max_num = 1
    can_delete = False
    readonly_fields = ("created_at", "updated_at")

    def has_delete_permission(...) -> bool: return False
    def formfield_for_dbfield(...):        # clears can_add_related
```

So `ClientProfileInline` needs exactly three things:

```python
class ClientProfileInline(BaseProfileInline):
    model = ClientProfile
    filter_horizontal = ("interests",)
    fieldsets = (...)
```

- **T032** — `model = ClientProfile`, imported from `profiles.models.client_profile`.
  Import `profiles.models`, **never** `profiles.admin` (research.md R-001).
- **T033** — fieldsets: unnamed `("company_name", "max_budget", "website_url")`,
  `Interests` → `("interests",)`, `Biography` → `("bio",)`,
  `Important Dates` collapsed → `("created_at", "updated_at")`.
- **T034** — **nothing to write.** The add-related suppression is inherited.
  Add `filter_horizontal = ("interests",)` (decision D2 below). Mark the task
  `[X]` with a note saying it was satisfied by inheritance.
- **T035** — `inlines = (ClientProfileInline,)` on `ClientAdmin`, changing
  nothing else on that class.

Place `ClientProfileInline` directly above `ClientAdmin`, mirroring how
`FreelancerProfileInline` sits directly above `FreelancerAdmin`.

---

## 3. Decisions already binding on Phase 5

### D1 — the profile section offers no vocabulary controls

Inside an account screen an administrator may only attach and detach existing
skills; creating, renaming and deleting vocabulary happens exclusively on the
`Skill` screen. Inherited, nothing to do.

**Verified against Django 6.0.7, do not redo:** only `can_add_related` needs
clearing. `RelatedFieldWidgetWrapper.__init__` gates `can_change_related` and
`can_delete_related` behind
`supported = not widget.allow_multiple_selected and isinstance(widget, Select)`,
which is `False` for any multi-select — those two controls cannot render on an
`interests` widget regardless of configuration.

**Also verified:** the suppression must happen in `formfield_for_dbfield()`, not
`formfield_for_manytomany()`. The wrapper carrying the flags is constructed in
the former, *after* the latter returns.

### D2 — `filter_horizontal` for the interests widget

Two columns (available / chosen) with a search box. Apply
`filter_horizontal = ("interests",)`. The widget renders every option into the
page, which suits the vocabulary size spec.md:352 caps at; the replacement at
thousands of rows is `autocomplete_fields`, already viable because `SkillAdmin`
declares `search_fields = ("name",)`.

### D3 — shared behavior lives on `BaseProfileInline`

Settled in Phase 4: configuration identical for both inlines goes on the base,
not duplicated per inline (FR-022). This is why T034 is empty. If Phase 5 finds
another behavior both sections need, put it on the base and record the
deviation from the task wording, as T024 does.

### D4 — `max_num` is a contract attribute, not the mechanism

`inlineformset_factory` forces `max_num = 1` whenever the FK to the parent is
unique (`django/forms/models.py`, `if fk.unique: max_num = 1`). Both profile
links are `OneToOneField`, so the one-profile-per-account guarantee comes from
the relation. Assert `max_num == 1` as a contract attribute (T036), but do not
expect form-count tests to be sensitive to it.

---

## 4. Docstrings — the correction that keeps recurring

**This was the most frequent defect in Phases 2, 3 and 4. Get it right the
first time.**

A docstring describes **what the method, class or function actually does**. It
does not explain Django's internals, does not justify an architectural
decision, does not restate a business rule, and does not argue why an
alternative was rejected. That reasoning belongs in `research.md`, `plan.md`
and `ARCHITECTURE.md` — documents that already exist for it.

**Rejected** (explains Django's mechanics and the rationale):

```python
"""
Move hidden-field errors to the form level.

The admin's stacked.html renders only non_form_errors, non_field_errors and
the per-field errors of fields named in the fieldsets, so an error keyed to
the hidden user field would be rendered nowhere. Attaching it to bio was
rejected because bio is not the cause of the refusal.
"""
```

**Accepted** (describes the behavior of this method):

```python
"""
Validate the form and move errors raised against hidden fields.

Each error keeps its original code; only where it is displayed changes.
"""
```

Google style, type hints on every signature, no inline comments, English only —
per `.claude/rules/conventions.md` *Code standards*.

---

## 5. Tests — T036–T039

New tests go in the existing
`django_version/accounts/tests/admin/test_profile_inlines.py`, alongside the 27
freelancer tests. Mirror their structure and naming.

Fixtures available in `accounts/tests/conftest.py`: `valid_user_data`,
`valid_freelancer_data`, `valid_client_data`, `freelancer_user`, `client_user`,
`skill`, `freelancer_profile`, `client_profile`.

Patterns the Phase 4 module already establishes — follow them:

- **Construct the admin/inline inside each test**, not via a fixture:
  `inline_instance = ClientProfileInline(Client, django_admin.site)`. This is
  the established pattern in `test_admin.py` and `test_skill_admin.py`.
- **Local fixtures stay local.** `testing.md` is explicit that fixtures used by
  one file do not go in `conftest.py`; `test_admin.py` and `test_skill_admin.py`
  each define their own differently-shaped `admin_request`.
- **One behavior per test.** Phase 4 split the T026 contract into one test per
  attribute for this reason. Two calls in one test breaks the one-call rule.
- **The inline formset prefix is `profile`** for both models — it derives from
  `related_name="profile"`, which both profile models declare. Form data keys
  are `profile-0-<field>`. Verified, but re-confirm in the shell rather than
  trusting this sentence.
- **Compose section-data fixtures**, don't write parallel ones:
  `untouched_profile_section_data` is built from `valid_profile_section_data`.

### Two things worth knowing

1. **`profile_for_inactive_account` now surfaces under `__all__`, not `user`.**
   The model still raises it keyed to `user`; `ProfileInlineForm` relocates it
   to the form level so the admin can render it. Through the formset, assert:

   ```python
   errors = formset.forms[0].errors.as_data()
   assert "__all__" in errors
   assert errors["__all__"][0].code == "profile_for_inactive_account"
   ```

   Errors on **visible** fields (`max_budget`, `company_name`) are untouched and
   stay on their own key.

2. **T039's FR-029 case must read the status being saved.** Set `is_active` on
   the in-memory parent without saving it, then bind the formset to that
   instance. Verified in Phase 4: the FK cache is already populated with the
   in-memory parent, so `clean()` sees the submitted value and not a database
   re-read — but assert it rather than assuming it.

---

## 6. Practices from Phase 4 worth repeating — and one hard-won warning

- **Mutation-check the new tests.** After they pass, disable the production
  branch they target and confirm they fail. In Phase 4 this caught a
  tautological test that survived deleting the entire override, which was then
  removed. `testing.md` requires this; running the suite alone does not
  establish it.

- **⚠️ Mutation testing corrupted the running dev server in Phase 4. Do not
  repeat the mistake.** The script restored files with `shutil.move`, which
  preserves the backup's mtime — a mtime *earlier* than the mutated version's.
  Django's `StatReloader` only reloads when the mtime moves **forward**
  (`elif mtime > old_time`), so it never noticed the restore. The `runserver`
  worker kept executing a mutated `freelancer_profile.py` with the FR-029 branch
  disabled for about two hours, and the human's manual validation correctly
  reported profiles being created on inactive accounts while every fresh pytest
  process passed. If you mutate files: force the mtime forward on restore
  (`Path(p).touch()`), or run `docker-compose restart web` afterwards, and
  verify with the server log.

- **A passing test is not evidence that the running system works.** What
  resolved the Phase 4 investigation was `docker-compose logs web` — the record
  of what actually happened — not the suite. When manual validation and tests
  disagree, the manual observation is the fact; go to the server log first.

- **Verify Django behavior against the pinned 6.0.7 inside the container**
  (`inspect.getsource`), not from memory (Principle VI / CLAUDE.md Rule 9).
  Phase 4 found the handoff's own recommended snippet did not work on 6.0.7.

- **Every command runs in Docker from `django_version/`**:
  `docker-compose exec web pytest`.

---

## 7. State of the dev database

Relevant because quickstart section C is validated against it.

| | count |
|---|---|
| Skills | 32 |
| Freelancers | 4 — `python1` (inactive), `freelancer2` (active), `freelancer3` (inactive), `test@email.com` (inactive) |
| FreelancerProfile | 2 — on `python1` and `freelancer2` |
| Clients | 3, 2 active |
| **ClientProfile** | **0** |

Section C needs an **active client without a profile** for its C1/C2 rows and an
inactive one for the FR-029 case; check which of the three clients qualifies
before starting, and create what is missing from the shell.

---

## 8. Follow-ups still owed

These belong to Phase 9 but are recorded here so they are not lost:

- **T060** — add `profile_for_inactive_account` to *Established invariants* in
  `.claude/rules/conventions.md`.
- **T061** — record in `ARCHITECTURE.md`: the FR-021 narrowing for the skill
  screens, the FR-028 mechanism, **and** the two Phase 4 decisions — no
  vocabulary-management control on profile sections (D1), and hidden-field
  error relocation via `ProfileInlineForm`.
- **T062** — the `docs/tech_debt.md` entry for the deferred standalone profile
  screens.
- **New, not yet assigned to a task**: a profile cannot be removed through the
  admin by any route — `can_delete=False`, `has_delete_permission()` returns
  `False`, and neither profile model is registered as its own screen. Profiles
  also have no status of their own (FR-031), so there is nothing to deactivate
  either. A profile created by mistake is permanent admin-side and can only be
  removed from the shell. This follows from FR-023 and Principle X, but it is
  operationally relevant and is recorded nowhere. Decide whether it belongs in
  `docs/tech_debt.md` or in `ARCHITECTURE.md`.
