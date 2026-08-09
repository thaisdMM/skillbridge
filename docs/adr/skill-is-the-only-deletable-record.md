# `Skill` Is the Only Record Deletable in the Admin — Guarded by `get_deleted_objects()`

**Date:** 2026-08-05
**Status:** Accepted — reasoning amended 2026-08-09; the decision itself is unchanged.
**Applies to:** `SkillAdmin`, `profiles.models.skill.Skill`, and any future admin class
for curated reference data rather than a record of a person.

## Context and Problem Statement

Project policy is deactivate, never delete: `on_delete=PROTECT` on every `ForeignKey` and
`OneToOneField`, and `has_delete_permission` returning `False` on every admin class.
`Skill` does not fit that policy. It declares only `name` and `category` — with no
`is_active` field, a misspelled or duplicated entry has no retirement path at all.

Permitting deletion is not free either. Profiles refer to skills through
`ManyToManyField` (`FreelancerProfile.skills`, `ClientProfile.interests`), which takes no
`on_delete` — Django cascades the join table unconditionally. Deleting an in-use skill
drops the join rows silently: no profile is deleted, no error is raised, and a freelancer
simply stops having that skill.

## Considered Options

* Add `is_active` to `Skill` and deactivate it like everything else
* Keep deletion disabled; correct entries by renaming only
* Permit deletion, unguarded
* Permit deletion, guarded in `SkillAdmin.get_deleted_objects()`

## Decision Outcome

* Chosen option: **"Permit deletion, guarded in `SkillAdmin.get_deleted_objects()`"**,
  because deactivate-never-delete exists to protect a record of a person, and a skill is
  not one. A person's record is not reproducible: a re-created account is a different row,
  stripped of its history, its relations and its audit trail. A skill is reference data
  and fully fungible — its identity is its name and category, so a deleted entry
  re-created is the same entry returned, carrying no history and no personal data.

* Curation supports this on a separate axis, and the distinction matters. Administrators
  own the vocabulary and freelancers only select from it, so removal stays rare and
  deliberate, which is what makes a single admin-layer guard proportionate. It is **not**
  an argument that removal is harmless: the skill row is worthless, but the join rows it
  takes with it record what a freelancer claimed about themselves. The guard is what makes
  the operation safe, not the curation.

* Adding `is_active` would be more invasive rather than safer — a field and a migration on
  a two-field model, and an inactive skill still shows in every selector unless every
  query filters it out. Renaming fixes a misspelling but cannot remove a genuine
  duplicate. Leaving deletion unguarded fails the very case the guard exists for.

> **Do not suppress `has_delete_permission` on `SkillAdmin`**, and route any new removal
> path for `Skill` — bulk action, management command, service, API endpoint — through the
> same guard. None of them inherit it.

### Consequences

* Good, because the vocabulary stays curated. A list whose whole value is reliable
  filtering and matching decays once a wrong entry can only be hidden, never removed.
* Good, because the administrator learns what a removal would cost — a count of the
  profiles affected — instead of meeting a flat refusal or a silent success.
* Good, because the lifecycle policy now states what it protects and why, so it applies by
  category rather than by blanket.
* Bad, because that policy can no longer be stated without qualification:
  `.claude/rules/conventions.md` and the constitution's *Deactivate, Never Delete*
  principle both have to carry the exception.
* Bad, because the guard is admin-layer only; a shell or ORM delete still drops join rows
  silently. Recorded in
  `docs/tech_debt/in-use-skill-removal-has-no-backstop-outside-the-admin.md`.
