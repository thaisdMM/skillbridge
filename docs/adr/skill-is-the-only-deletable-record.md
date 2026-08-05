# `Skill` Is the Only Record Deletable in the Admin — Guarded by `get_deleted_objects()`

**Date:** 2026-08-05
**Status:** Accepted
**Applies to:** `SkillAdmin`, `profiles.models.skill.Skill`, and any future admin class
for curated reference data rather than a person's record.

## Context and Problem Statement

Project policy is deactivate, never delete: `on_delete=PROTECT` everywhere and
`has_delete_permission` returning `False` on every admin class. `Skill` declares only
`name` and `category` — it has **no `is_active` field**, so deactivation is not available
to it, and a misspelled or duplicated entry would have no retirement path at all.

`on_delete` also gives no protection here. Profiles refer to skills through
`ManyToManyField` (`FreelancerProfile.skills`, `ClientProfile.interests`), and a
many-to-many takes no `on_delete` — Django cascades the join table unconditionally.
Deleting an in-use skill silently drops the join rows, with no error at any layer.

## Considered Options

* Add `is_active` to `Skill` and deactivate it like everything else
* Keep deletion disabled; correct entries by renaming only
* Permit deletion, unguarded
* Permit deletion, guarded in `SkillAdmin.get_deleted_objects()`

## Decision Outcome

Chosen option: **"Permit deletion, guarded in `SkillAdmin.get_deleted_objects()`"**,
because `Skill` is curated reference data. The deactivate-never-delete policy protects
account and profile history; a wrong vocabulary entry has none worth keeping.

`is_active` was rejected as more invasive rather than safer: a field and a migration on a
two-field model, and an inactive skill still appears in every selector unless every query
filters it out. Renaming covers a misspelling but cannot remove a genuine duplicate.

`get_deleted_objects()` is the guard because it is the single choke point for both removal
routes — `ModelAdmin._delete_view` and the built-in `delete_selected` both call it, and
both refuse when the returned `protected` collection is non-empty.

The guard counts **distinct profiles**: one aggregate over each profile model, filtered by
the selected skills, two queries whatever the selection size. Summing per-skill reverse
counts instead counts *references* — one profile referring to three selected skills
contributes three (measured 2026-08-05: reported 7 where 3 profiles were affected).
Filtering forward from the profile models also makes the guard immune to a `related_name`
added later. It reports a count and never enumerates the profiles, so the refusal message
carries no personal data.

> **Do not suppress `has_delete_permission` on `SkillAdmin`**, and route any new removal
> path for `Skill` — bulk action, management command, service, API endpoint — through the
> same guard. None of them inherit it.

### Consequences

* Good, because the vocabulary is correctable while removal that would cost a profile its
  skill is refused, and one override covers both routes.
* Good, because no field and no migration are added, and the refusal carries no PII.
* Bad, because the lifecycle policy can no longer be stated without qualification —
  `.claude/rules/conventions.md` and the constitution's *Deactivate, Never Delete*
  principle both have to carry the exception.
* Bad, because the guard is admin-layer only; a shell or ORM delete still drops join rows
  silently. Recorded in
  `docs/tech_debt/in-use-skill-removal-has-no-backstop-outside-the-admin.md`.
