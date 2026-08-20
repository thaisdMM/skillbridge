# Findings — `Skill` administration surface

**Date**: 2026-08-04
**Scope**: `django_version/profiles/admin.py` (`SkillAdmin`) and
`django_version/profiles/models/skill.py`, read against
`specs/001-profiles-admin-panel/` (spec.md, data-model.md,
contracts/admin-surface.md, research.md) and `.claude/rules/conventions.md`.
**Status**: read-only audit. No file was modified other than this one.

**Trigger**: the reported ability to create a skill named `python` while
`Python` already exists.

---

## Summary

The report is correct, and the cause is not the one the report assumed. The
admin **does** run `Skill.clean()` and **does** reject exact duplicates —
that machinery is intact. What is missing is that uniqueness is
**case-sensitive**, and nothing in the model, the admin, or the spec ever
said it should not be.

Eight findings below: one confirmed defect, one behaviour that is correct but
documented wrong, one test gap, two design gaps, and three documentation
gaps. Section 3 lists what was checked and found sound, so the audited
surface is not re-audited later.

| ID | Severity | Summary |
|---|---|---|
| F-1 | **CRITICAL** | Skill-name uniqueness is case-sensitive; `python` and `Python` coexist |
| F-2 | LOW | Whitespace handling is correct, but the error contract records the wrong codes |
| F-3 | HIGH | No test covers FR-002 or FR-003 through the admin at all |
| F-4 | MEDIUM | The in-use count inflates when several skills are bulk-deleted at once |
| F-5 | MEDIUM | The in-use removal rule has no backstop outside the admin |
| F-6 | LOW | `get_deleted_objects()` issues two queries per selected skill |
| F-7 | LOW | `conventions.md`'s "deletion is disabled on all admin classes" is now false |
| F-8 | LOW | `profile_for_inactive_account` was never added to *Established invariants* |

---

## 1. Findings

### F-1 — Uniqueness is case-sensitive — **CRITICAL**

**Where**: `django_version/profiles/models/skill.py:53-61`

`name` is a `CharField(unique=True)`. On PostgreSQL that is a btree unique
index over the raw text, which is case-sensitive. There is no
`UniqueConstraint(Lower("name"))` in `Skill.Meta`, no `CITextField`, and no
case normalization in `Skill.clean()` (`skill.py:97-124` strips whitespace and
nothing else).

Consequence: `Python`, `python`, `PYTHON` and `PythOn` are four distinct rows.
The seed migration (`profiles/migrations/0002_seed_skills.py`) already ships
`Python`, so the very first lowercase entry an administrator types creates the
collision.

**Why this matters more than a cosmetic duplicate:**

- `Skill.__str__` returns the bare name, so the `filter_horizontal` selector on
  the freelancer profile section renders two visually near-identical rows with
  no way to tell them apart.
- The skill filters on the account lists (FR-037/FR-038) split one real skill
  across two filter values — "who does Python?" silently returns a partial
  answer, defeating SC-012.
- It is expensive to undo. `spec.md:348` records that merging two duplicate
  skills into one is **not supported** and waits for the deferred profile
  screens. Once profiles refer to both spellings, the only route back is
  detaching them one profile at a time.

**Spec status — this is underspecified, not violated as written.** FR-002
(`spec.md:259`) says the system must reject a name that "duplicates an existing
skill" without defining what counts as a duplicate, and `data-model.md:109`
delegates the whole rule to Django's `unique`. So the code matches the letter of
the artifacts. It does not match their intent: US1 (`spec.md:40`) states the
administrator should be able to "check whether a skill already exists before
adding a near-duplicate", and the `Skill` entity definition (`spec.md:318`)
says plainly "Names are unique."

Fixing this changes FR-002 and needs a decision — see **Q1–Q3**.

---

### F-2 — Whitespace handling is correct; the error contract records it wrong — LOW

The concern that `Skill.clean()` is not applied in the admin does not hold.
Verified against the pinned Django 6.0.7 source
(`django/forms/models.py`, `BaseModelForm._post_clean`), the admin save path is:

1. The form field — a `forms.CharField` with `strip=True` by default —
   strips the submitted name.
2. `construct_instance()` writes it onto the instance.
3. `self.instance.full_clean(exclude=…, validate_unique=False, validate_constraints=False)`
   → **`Skill.clean()` runs here.**
4. `self.validate_unique()` runs **after**, against the value `clean()` left on
   the instance.

So FR-003 and FR-002 both hold on the admin path today, and `Python ` with a
trailing space is correctly rejected as a duplicate of `Python`. Two details
are worth recording:

**(a) `Skill.clean()`'s own `.strip()` is unreachable through the admin form** —
the form already stripped the value, so `self.name.strip()` is a no-op there.
It remains reachable and necessary on the shell, ORM and migration paths. This
is not a defect (the model must hold the invariant regardless of origin), but
per `testing.md` — *"a test must fail if the behavior under test is removed"* —
any test asserting that *the admin* trims a name is really asserting Django's
form `strip=True`, not `Skill.clean()`. Test the model path for that rule.

**(b) The error contract's whitespace row is inaccurate.**
`contracts/admin-surface.md:219` lists a single outcome for "Skill name empty
after strip": field `name`, code `skill_name_empty`. The admin actually raises
**two** errors on `name` for the input `"   "`:

- `required` — the form strips to `""`, and `name` is a required form field;
- `skill_name_empty` — `name` then enters `_get_validation_exclusions()` because
  it carries a form error, but exclusion only suppresses `clean_fields()` and
  `validate_unique()`. `Model.clean()` is still called, and it raises.

The user-visible outcome satisfies FR-003. But a test asserting that `name`
carries exactly one error would fail, and the contract row should say both.

Note that this is **not** the same shape as the documented
`company_name` tech debt
(`docs/tech_debt/002-whitespace-only-company-name-accepted-in-admin.md`). There,
`company_name` is `blank=True`, so the form produces `""` with no error and
`ClientProfile.clean()`'s `if self.company_name:` short-circuits. `Skill.name`
is required, so it does not have that hole.

---

### F-3 — FR-002 and FR-003 are untested on the admin path — HIGH

`django_version/profiles/tests/admin/test_skill_admin.py` covers the screen
configuration (T014), delete permission (T015) and the six removal-refusal
cases (T016–T021). It contains **no** test for rejecting a duplicate name and
**no** test for trimming — and no task in `tasks.md` asks for one.

`profiles/tests/models/test_skill.py` has `test_skill_name_uniqueness` and
`test_skill_name_uniqueness_enforced_at_database_level`, but both exercise
exact-case duplicates only.

The practical result is that the two rules most central to a curated
vocabulary — FR-002 and FR-003 — have no admin-layer regression guard, which
is why F-1 was found by hand rather than by the suite. This is a Principle IX
gap ("No Code Without Tests"), and it is worth closing independently of the
F-1 decision.

---

### F-4 — The in-use count inflates on multi-skill bulk deletion — MEDIUM

**Where**: `django_version/profiles/admin.py:72-75`

```python
referring_profiles = sum(
    skill.freelancerprofile_set.count() + skill.clientprofile_set.count()
    for skill in objs
)
```

This sums **references**, not distinct profiles. For a single skill the two are
identical, because the M2M join table holds each `(profile, skill)` pair at most
once. For a bulk selection they diverge: select three skills that one freelancer
profile happens to list, and the refusal reads *"Still in use by 3 profiles"*
when exactly one profile is affected.

FR-028 (`spec.md:264`) specifies "how many profiles refer to it", and
`contracts/admin-surface.md:42-43` prescribes precisely the summation above —
so the implementation matches its contract, and the contract is what carries
the imprecision. `delete_selected` is an explicitly supported route ("This
applies to every removal route offered by the skill screens"), so the case is
reachable.

The existing test T018 uses one skill and three profiles, so it cannot catch
this. See **Q4**.

---

### F-5 — The in-use rule has no backstop outside the admin — MEDIUM

`get_deleted_objects()` is an admin-layer guard and nothing else. A
`Skill.objects.filter(...).delete()` from the shell, a management command, a
data migration or a future DRF viewset deletes the skill and **silently drops
the M2M join rows** — a many-to-many relation takes no `on_delete`, and Django
cascades the auto-created through table unconditionally.

This is a deliberate asymmetry with the rest of the codebase.
`conventions.md` frames the `freelancer_no_inactive_available` `CheckConstraint`
as *"the backstop for ORM paths that bypass `clean()`"*, and mandates
`on_delete=PROTECT` on every FK and O2O. The skill vocabulary — the one record
type this feature permits permanent removal of — has no equivalent.

FR-028 scopes the rule to "every removal route offered by the skill screens",
so the implementation is in-scope-correct **today**. But SC-010
(`spec.md:337` — "zero profiles lose a skill without the administrator being
told") reads broader than the admin, and the hole opens the moment DRF lands.
See **Q5**.

---

### F-6 — `get_deleted_objects()` issues two queries per selected skill — LOW

The generator in `admin.py:72-75` runs one `COUNT` per profile model per skill.
Selecting 30 skills for deletion is 60 queries on top of Django's own
collector. At the scale the spec assumes (`spec.md:354` — hundreds of skills)
this is harmless, and a single aggregate over the two through tables would
collapse it. Recorded for completeness; no action recommended.

---

### F-7 — `conventions.md`'s admin rule is now false — LOW

`.claude/rules/conventions.md` → *Admin conventions* states:

> `has_delete_permission` returns `False` on all admin classes. Use
> `is_active=False` for deactivation.

`SkillAdmin` deliberately does not, per FR-027, SC-006,
`contracts/admin-surface.md:31-33` and task T012. As written, the rule invites a
future session to "fix" `SkillAdmin` back and break FR-027. The exception
belongs in the rule text, and it needs Constitution Principle X
("Deactivate, Never Delete") named alongside it, since `Skill` is the standing
exception to that principle too.

---

### F-8 — `profile_for_inactive_account` is missing from *Established invariants* — LOW

`contracts/admin-surface.md` §4 states that
`profile_for_inactive_account` *"is the only new code this feature introduces.
It must be added to the Established invariants list in
`.claude/rules/conventions.md`."* That list does not contain it. It is raised
by both `FreelancerProfile.clean()` (`freelancer_profile.py:163-175`) and
`ClientProfile.clean()` (`client_profile.py:175-188`).

---

## 2. What F-1 changes if left alone

Nothing breaks loudly. The vocabulary degrades quietly: every case variant
splits one concept into two, the split is invisible in the profile selector,
and each one that a profile picks up becomes harder to merge — with merging
explicitly out of scope until the deferred profile screens exist. The cost of
fixing this rises monotonically with the number of profiles created.

---

## 3. Checked and sound — not findings

Recorded so this surface is not re-audited later.

- **The reverse accessors are correct.** Neither `FreelancerProfile.skills`
  nor `ClientProfile.interests` declares a `related_name`, so
  `skill.freelancerprofile_set` and `skill.clientprofile_set` are the right
  defaults. A `related_name` added later silently breaks `admin.py:72-75`.
- **FR-025 (active-staff-only access) is satisfied without admin-layer code.**
  The gate is on the model — `BaseUser.has_module_perms`
  (`accounts/models/base.py:266`) — so `SkillAdmin` inherits it. Nothing is
  missing from `profiles/admin.py`.
- **FR-021 is intentionally narrowed for skills.** `Skill` has no
  `created_at`/`updated_at`, so the collapsed-timestamp and most-recent-first
  clauses are unsatisfiable. `research.md` R-002 records the human decision of
  2026-07-28 to narrow rather than change the model. `SkillAdmin`'s
  `ordering = ("category", "name")` and single unnamed fieldset match that
  decision.
- **FR-010 holds.** The add-related "+" is suppressed for both profile
  sections by `BaseProfileInline.formfield_for_dbfield`
  (`accounts/admin.py:131-148`); skills cannot be created from the profile
  section.
- **The removal refusal is sound and well tested.** Both routes
  (`_delete_view` and `delete_selected`) are covered, the refusal detaches
  nothing, a mixed selection deletes neither skill, and a skill referred to
  only from a deactivated account is still protected. `_in_use_summary` reports
  a count and never enumerates profiles, satisfying FR-028's no-enumeration
  clause and the GDPR posture.
- **`category` is safe.** Required, and constrained to the four
  `TextChoices` values by `validate_choice`.

---

## 4. Questions

Answers to Q1–Q3 determine the fix; Q4–Q6 are independent and can be answered
separately.

### Q1 — Is `python` intended to be a duplicate of `Python`? *(blocking F-1)*

This is a spec-level decision that amends FR-002 — I will not assume it.
My reading of US1 and the `Skill` entity definition is that it should be, but
the artifacts do not say so.

### Q2 — If yes, which mechanism? *(blocking F-1)*

| | Approach | Trade-off |
|---|---|---|
| **(a)** | Case-insensitive check in `Skill.clean()` raising a new code on `name`, **plus** `UniqueConstraint(Lower("name"))` in `Meta` as the database backstop | **Recommended.** Mirrors the established `freelancer_no_inactive_available` pattern exactly — friendly field-level error at the app layer, DB constraint for paths that bypass `clean()`. Costs one migration and a pre-flight audit of existing rows. |
| **(b)** | `clean()` check only | No migration. Leaves the same hole as F-5 — direct ORM writes still create duplicates. |
| **(c)** | `UniqueConstraint(Lower("name"))` only | Django surfaces expression-based constraint violations under `NON_FIELD_ERRORS`, not against `name` — this **fails FR-002's** "reporting the conflict against the name field". Not viable alone. |

### Q3 — Should the stored name also be normalized (e.g. forced capitalization)?

My recommendation is **no**: detect duplicates case-insensitively, store exactly
what the administrator typed. The seeded vocabulary contains `UI/UX Design`,
`C#`, `HTML/CSS`, `SEO Writing` and `C/C++` — any automatic casing rule mangles
several of them.

### Q4 — F-4: correct the count to distinct profiles, or accept it?

Correcting it also amends `contracts/admin-surface.md:42-43`, which prescribes
the current summation.

### Q5 — F-5: add a database backstop now, or defer to the DRF phase?

Deferring is defensible and would follow the established route — a
`docs/tech_debt/` entry with reversal criteria, as was done for the
`company_name` case.

### Q6 — Shall I check the live database for existing case-duplicates?

Required before any `UniqueConstraint(Lower("name"))` migration under Q2(a) —
the migration fails on an existing collision. This is a read-only
`docker-compose exec web` query and I will not run it without approval.

---

## 5. Suggested sequence once Q1–Q3 are answered

Listed for approval, not started. No code will be written before Rule 3
approval, and no migration generated before Rule 10 approval.

1. Amend FR-002 in `spec.md` to state the case rule explicitly, and
   `data-model.md:109` alongside it.
2. Add the F-3 admin tests — duplicate rejection and trimming — first, so the
   defect is red before it is green.
3. Implement the chosen Q2 mechanism, and register any new error code in
   *Established invariants*.
4. Close F-7 and F-8 in `conventions.md` in the same pass.
5. Decide F-4 and F-5 per Q4/Q5.
