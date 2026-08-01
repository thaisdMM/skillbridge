# Handoff: Phase 4 (User Story 2 — freelancer profile inline)

**Written**: 2026-08-01, at the end of the session that delivered Phase 3.
**For**: the next session, which implements T022–T031.

This file carries the state and the decisions that are **not** recoverable from
`tasks.md`, `plan.md` or the code alone. Read it before starting, then follow
`tasks.md` as the authority on what to build.

---

## 1. Where the feature stands

| Phase | Status |
|---|---|
| Phase 1 — Setup (T001–T004) | Complete, marked `[X]` |
| Phase 2 — Foundational (T005–T010) | Complete, marked `[X]` |
| **Phase 3 — US1, SkillAdmin (T011–T021)** | **Complete, marked `[X]`** |
| Phase 4 — US2, freelancer inline (T022–T031) | **Not started — this is the next work** |

**Test baseline: 209 passing** (`docker-compose exec web pytest` from
`django_version/`). Phase 4 must leave every one of them passing; the count only
grows. `makemigrations --check --dry-run` reports **"No changes detected"** and
must keep reporting it — this feature generates no migration.

Nothing has been committed. The Phase 3 changes are in the working tree:
`django_version/profiles/admin.py` (rewritten from a stub) and
`django_version/profiles/tests/admin/test_skill_admin.py` (new, 15 tests).

**Quickstart section A (A1–A9) was manually validated in the browser and
passed**, including the refusal message rendering with its count and the skill
staying attached after a refused delete.

---

## 2. Decisions taken in the previous session

These were decided by the human during Phase 3. They are binding on Phase 4 and
are not yet written into the spec artifacts.

### D1 — The profile section offers no vocabulary controls at all (affects T024)

Django wraps a related-field widget with three controls: **➕ add**,
**✏️ change** and **🗑️ delete**, all of which act on the `Skill` table itself,
not on the profile's selection.

`contracts/admin-surface.md` §2 and FR-010 name only the ➕. **The human decided
to remove all three**: inside an account screen an administrator may only attach
and detach existing skills; creating, renaming and deleting vocabulary happens
exclusively on the `Skill` screen.

```python
formfield.widget.can_add_related = False
formfield.widget.can_change_related = False
formfield.widget.can_delete_related = False
```

This **widens FR-010 deliberately**. Two follow-ups are owed and were not done:

- add a line to `contracts/admin-surface.md` §2 stating the widget offers no
  vocabulary-management control, not just no ➕;
- record the decision in `ARCHITECTURE.md` alongside T061.

The same applies to `interests` on `ClientProfileInline` in Phase 5 (T034) — the
two screens must behave identically.

### D2 — `filter_horizontal` for the skills widget (affects T024)

Not in the contract; chosen for usability. It gives two columns
(available / chosen) with arrows and a search box, which is what "attach a skill
to this person / detach it" should look like.

Sizing was checked, not assumed: the widget renders every option into the page
HTML, which is fine for the 32 skills in the dev database and fine into the low
hundreds — the range `spec.md:352` caps the vocabulary at. If the vocabulary
ever reaches thousands, the replacement is `autocomplete_fields`, which already
works because `SkillAdmin` declares `search_fields = ("name",)`.

Apply `filter_horizontal = ("interests",)` on the client inline in Phase 5.

### D3 — Where the widget configuration should live (open, needs the human)

T024 says "configure the skills widget **on `FreelancerProfileInline`**" and
T034 repeats it for `ClientProfileInline`. But the configuration is identical
for both, and FR-022 requires behavior to be defined once rather than duplicated
per screen — which is exactly what `BaseProfileInline` exists for.

The previous session was about to put a single `formfield_for_manytomany()`
override on `BaseProfileInline`, so both inlines inherit it and Phase 5 needs no
widget code at all. **This deviates from the literal wording of T024/T034 and
touches a file finished in Phase 2, so confirm it with the human before
writing.** The alternative — the same six lines duplicated on each inline — is
what the tasks literally say.

### D4 — Skill deletion is all-or-nothing (Phase 3 context, do not re-litigate)

The human asked whether skill deletion should delete the unused skills in a
selection and skip the protected ones, in the style of the `set_available`
action. It was decided to keep `get_deleted_objects()` as written, because:

- Django's delete flow refuses the whole selection when `protected` is
  non-empty; the hook cannot subtract items from the queryset;
- deletion is irreversible, unlike the reversible state updates that the
  existing partial-success actions perform;
- one hook covers both the single-object delete view and the bulk action, while
  a custom action would cover only the bulk route;
- `quickstart.md` A9 already specifies "nothing is deleted" for a mixed
  selection.

The partial-delete custom action recorded as a fallback in `plan.md:112-114` is
**not needed**: it was verified against the Django 6.0.7 source in the container
that `delete_selected` calls `modeladmin.get_deleted_objects()` and deletes only
`if request.POST.get("post") and not protected`. That verification gate (T020)
is closed. The other gate, T053 (`list_filter` across a reverse O2O then M2M),
is still open and belongs to Phase 8.

---

## 3. Docstrings — the correction that had to be made repeatedly

**This was the most frequent defect in Phases 2 and 3. Get it right the first
time.**

A docstring describes **what the method, class or function actually does**. It
does not explain Django's internals, does not justify a design decision, and
does not argue why an alternative was rejected. That reasoning belongs in
`research.md`, `plan.md` and `ARCHITECTURE.md` — documents that already exist
for it.

**Rejected** (explains Django's mechanics and the rationale):

```python
"""
Refuse removal of a skill that a profile still refers to.

on_delete has no effect on a many-to-many relation, so deleting a skill
would drop its join-table rows and silently detach it from every profile
referring to it. Reporting the selection as protected stops the deletion on
both routes that consult this hook: the single-object delete view and the
built-in delete_selected action.
"""
```

**Accepted** (describes the behavior of this method):

```python
"""
Mark the selected skills as protected while profiles still refer to them.

Counts the freelancer and client profiles referring to the selection. When
the count is greater than zero, a single summary line carrying it is added
to the protected collection, which stops the deletion on both the delete
view and the delete selected action.

Args:
    objs: The skills selected for removal.
    request: The current admin request.

Returns:
    tuple: The deletable objects, the per-model counts, the permissions
        needed, and the protected collection.
"""
```

Google style, type hints on every signature, no inline comments, English only —
per `.claude/rules/conventions.md` *Code standards*.

---

## 4. What Phase 4 has to build

Authority is `tasks.md` T022–T031. Summary, so the reading has a shape:

**Production** — all in `django_version/accounts/admin.py`:

- T022 `FreelancerProfileInline(BaseProfileInline)`, `model = FreelancerProfile`,
  imported from `profiles.models.freelancer_profile`. Import `profiles.models`,
  **never** `profiles.admin` (research.md R-001).
- T023 fieldsets: unnamed `("hourly_rate", "years_of_experience",
  "portfolio_url")`, `Skills` → `("skills",)`, `Biography` → `("bio",)`,
  `Important Dates` collapsed → `("created_at", "updated_at")`.
- T024 the widget, per D1 + D2 + D3 above.
- T025 `inlines = (FreelancerProfileInline,)` on `FreelancerAdmin`, changing
  nothing else on that class.

`BaseProfileInline` already exists in that file from Phase 2 (`extra = 1`,
`max_num = 1`, `can_delete = False`, `has_delete_permission()` → `False`,
`readonly_fields = ("created_at", "updated_at")`).

**Tests** — new file `django_version/accounts/tests/admin/test_profile_inlines.py`
(T026–T031). The package `accounts/tests/admin/` already exists.

Fixtures already available in `accounts/tests/conftest.py`: `valid_user_data`,
`valid_freelancer_data`, `valid_client_data`, `freelancer_user`, `client_user`,
`skill`, `freelancer_profile`, `client_profile`.

### Three things worth knowing before writing those tests

1. **Assert error codes, not messages** (`testing.md`). Through a form or
   formset the codes are reached with `form.errors.as_data()`, which returns the
   `ValidationError` instances — plain `form.errors` gives rendered strings.
   Assert the field key is present first, then the code.

2. **T031 is the test that matters most.** It must prove FR-029 reads the
   account status **being saved**, not the stored one: set `is_active` on the
   in-memory parent without saving it, then bind the formset to that instance.
   If the implementation ever re-reads the database, quickstart B10–B12 break
   while B8 still passes — which looks correct and is not (`plan.md:223`). The
   model-layer tests written in Phase 2 already work this way.

3. **Verify the inline formset prefix in the shell before hard-coding form data
   keys.** `BaseInlineFormSet` derives it from the FK's `related_name`, which is
   `"profile"` on both profile models — confirm it rather than trusting this
   sentence.

---

## 5. Practices from the previous session worth repeating

- **Mutation-check the new tests.** After they pass, disable the production
  branch they target and confirm they fail. In Phase 3 this proved the
  `get_deleted_objects()` tests were real: 6 of 15 failed with the branch off.
  `testing.md` requires it ("a test must fail if the behavior under test is
  removed"); running the suite alone does not establish it.
- **Verify Django behavior against the pinned 6.0.7 inside the container**
  (`inspect.getsource`), not from memory (Principle VI / CLAUDE.md Rule 9).
- **Every command runs in Docker from `django_version/`**:
  `docker-compose exec web pytest`.

---

## 6. State of the dev database

Relevant because quickstart section B is validated against it:

| | count |
|---|---|
| Skills | 32 |
| Freelancers | 2, both active |
| Clients | 3, 2 active |
| FreelancerProfile | **1** — created via `manage.py shell` to validate A8/A9, with `Python` attached |
| ClientProfile | 0 |

That one profile was created from the shell because no admin route to create a
profile existed yet. Once T022–T025 land, that freelancer's account screen will
show a populated profile section — useful for quickstart B-rows, and a reminder
that B1 (an account **without** a profile) needs the other freelancer.
