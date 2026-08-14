# Technical Debt — The in-use skill removal rule has no backstop outside the admin

**Status:** deferred
**Date recorded:** 2026-08-05
**Area:** `profiles/admin.py`, `profiles/models/skill.py`
**Applies to:** deleting a `Skill` that a `FreelancerProfile` or a
`ClientProfile` still refers to
**Related:** FR-027, FR-028, SC-010 and quickstart rows A7–A9 in
`specs/001-profiles-admin-panel/`; tasks T013 and T016–T021 in that feature's
`tasks.md`; finding F-5 in `docs/skill-admin-findings-2026-08-04.md`

## The gap

`SkillAdmin.get_deleted_objects()` refuses to remove a skill while any profile
refers to it, and reports how many profiles are affected. That refusal is a
method on an admin screen. It runs when an administrator clicks Delete, on both
removal routes the screen offers — the delete view and the `delete_selected`
bulk action — and nowhere else.

Every other path deletes the skill without a word:

```python
Skill.objects.filter(name="Python").delete()   # shell, script, management command
Skill.objects.get(pk=1).delete()               # data migration
```

FR-028 requires the refusal on *"every removal route offered by the skill
screens"*, so the implementation is correct as specified. SC-010 — *"zero
profiles lose a skill without the administrator being told"* — reads wider than
the screens, and it is that wider reading this entry records as unmet.

## Why nothing stops the deletion

A `ManyToManyField` is not a column. Django creates a third table holding one
row per `(profile, skill)` pair, and that table carries the foreign keys.
Verified in the running container on 2026-08-05:

```
FreelancerProfile.skills  → table freelancer_profiles_skills
    FK freelancerprofile → FreelancerProfile | on_delete = CASCADE
    FK skill             → Skill             | on_delete = CASCADE

ClientProfile.interests   → table client_profiles_interests
    FK clientprofile → ClientProfile | on_delete = CASCADE
    FK skill         → Skill         | on_delete = CASCADE
```

**Those `CASCADE` values are not a project decision and were never declared.**
`ManyToManyField` accepts no `on_delete` argument, and Django writes `CASCADE`
literally into both foreign keys of the table it auto-creates. Verified against
the pinned Django 6.0.7 on 2026-08-05, at both levels:

- `django/db/models/fields/related.py`,
  `create_many_to_many_intermediary_model()` — both `models.ForeignKey(...)`
  calls carry `on_delete=CASCADE` as a literal, with no parameter routing to it;
- `inspect.signature(ManyToManyField.__init__)` has no `on_delete`, and passing
  one raises `TypeError: Field.__init__() got an unexpected keyword argument
  'on_delete'`.

For contrast, a plain `ForeignKey` has no default at all — `on_delete` is a
required positional argument, and omitting it raises `TypeError`. The `CASCADE`
here is specific to the intermediary model, not a project-wide Django default.

Overriding it means writing an explicit `through=` model with foreign keys of
our own — a schema change, not a configuration tweak.

The consequence: deleting a `Skill` row deletes the matching pair rows. No
profile is deleted and no error is raised. A profile simply, quietly, stops
having that skill. This is the failure mode `research.md` R-004 names — *"`on_delete`
has no effect on a many-to-many"* — the reason FR-028 needed explicit work in the
first place.

**Not related:** the `UniqueConstraint(Lower("name"))` added by the FR-002
amendment does not help here. It forbids two skills whose names match ignoring
case; it says nothing about deletion.

## Why deleting skills at all is correct, and not part of this debt

`Skill` is the one record in this feature an administrator may permanently
remove (FR-027, SC-006), and that is deliberate. Accounts are retired by
`is_active=False` because a person's record must survive; a vocabulary entry has
no such life. Deactivating a skill would mean carrying dead entries in a list
whose whole purpose is to stay curated. `Skill` therefore has no status field,
and `SkillAdmin` deliberately does not suppress `has_delete_permission`.

Nothing in this entry argues against that. The debt is narrower: the guard that
protects an **in-use** skill exists in one layer only.

## Why it is deferred, not implemented

Decided on 2026-08-05, alongside the FR-002 amendment: **no database-level
constraint is added for this.**

- **No route outside the admin exists today.** DRF is not installed, there is no
  management command that deletes skills, and no data migration does either. The
  hole is reachable only from a shell session typed by hand.
- **The available fix is disproportionate right now.** Closing it properly means
  an explicit `through=` model on both M2Ms with `on_delete=PROTECT` on the
  skill side. That is two new models, a migration per join table, and a change
  to how every existing query and fixture reaches the relation — for a path that
  currently has no callers. It is also an architectural change and would need an
  ADR before any model edit, per `conventions.md`.
- **The failure is loud enough when it matters.** The admin path — the only path
  administrators use — refuses, counts, and detaches nothing. Tasks T016–T021
  cover it, including the bulk route and the deactivated-account case.

This is the same reasoning and the same route already used for
`docs/tech_debt/002-whitespace-only-company-name-accepted-in-admin.md`: record the
gap, name what would change the assessment, and do not duplicate a rule across
layers before a caller exists.

## Reversal criteria

Any one of these makes the assessment above wrong, and the fix should be built
then rather than deferred again:

1. **A deletion route outside the skill screens appears.** A DRF viewset
   allowing `DELETE` on `Skill`, a management command, a data migration that
   prunes the vocabulary, or a new admin action that deletes without going
   through `get_deleted_objects()`.
2. **SC-010 is asserted beyond the admin** — for example a test, an audit, or a
   compliance statement claiming that no profile can lose a skill silently on
   any path.
3. **The M2M gains an explicit `through=` model for any other reason** (an
   `added_at` timestamp, a proficiency level). At that point the foreign keys
   become ours to declare and `on_delete=PROTECT` costs one argument.
4. **Profile skill history becomes meaningful** — if losing a pairing stops
   being recoverable by re-attaching the skill by hand.

## What to do when one of them fires

1. Write the ADR first. The decision is *"the skill join tables become explicit
   models so the skill side can be `PROTECT`"* — a schema decision, with the
   `on_delete` policy reasoning that `ARCHITECTURE.md` already applies to every
   FK and O2O in the project.
2. Add the two `through=` models, with `on_delete=PROTECT` on the skill foreign
   key and `CASCADE` on the profile side (a deleted profile should take its own
   pairings with it — though no profile is ever deleted today, per FR-023).
3. Keep `SkillAdmin.get_deleted_objects()` regardless. It is not made redundant:
   `PROTECT` raises `ProtectedError`, which is a crash page, not the counted,
   field-level refusal FR-028 requires. The admin guard stays the friendly
   layer, exactly as `clean()` sits above every `CheckConstraint` in this
   codebase.
4. Re-run quickstart rows A7–A9, plus a new row exercising the shell path.
