# Skill Admin Screens Carry No Timestamps and Order by Category, Not Recency

**Date:** 2026-08-13
**Status:** Accepted
**Applies to:** `SkillAdmin`, `profiles.models.skill.Skill`, and any future admin class
for a model that carries no timestamp fields.

## Context and Problem Statement

Every account admin class in the project presents the same two conventions: a readonly
timestamp fieldset, and most-recent-first ordering (`ordering = ("-created_at",)` on
`FreelancerAdmin`, `ClientAdmin` and `StaffUserAdmin`). Both read as platform-wide admin
conventions rather than per-model choices.

`Skill` cannot honour either. It declares exactly two fields, `name` and `category`.
There is no `created_at` and no `updated_at`, so there is nothing to display readonly and
nothing to order by. Either the model gains timestamp fields, or the two conventions are
stated as conditional on the model carrying them.

## Considered Options

* Add `created_at`/`updated_at` to `Skill` so the conventions apply uniformly
* Narrow both conventions to apply only where the model carries timestamp fields

## Decision Outcome

* Chosen option: **"Narrow both conventions"**. `SkillAdmin` keeps
  `ordering = ("category", "name")` mirroring `Skill.Meta.ordering`, declares no
  timestamp fieldset, and honours every other admin convention — grouped fieldsets,
  `list_per_page = 25`, search by name, and the category filter.

* Adding the fields would widen an admin-presentation concern into a model and a
  migration on a two-field model, to populate a fieldset nobody curating a vocabulary
  reads. When a skill was added carries no meaning: the vocabulary is a set, not a
  timeline.

* Alphabetical grouping by category is the order the screen actually needs. An
  administrator checking whether "Python" is already listed scans a grouped alphabetical
  list; most-recent-first would scatter the categories and make that scan impossible.
  Recency ordering earns its place on account screens because the newest account is the
  one an administrator is most likely to be looking for — a skill has no equivalent.

> The absence of a timestamp section on the skill screens is **intended**. Any review
> comparing admin classes side by side should read it as this decision, not as an
> omission. Restoring uniformity by adding the fields reopens this ADR.

### Consequences

* Good, because no field, no migration, and no schema change follows from an
  admin-layer presentation rule.
* Good, because the two conventions now state their own precondition, so the next model
  without timestamps inherits an answer instead of re-deciding.
* Bad, because the admin layer is no longer uniform, and the difference is only
  legible to a reader who finds this ADR. That cost is what this file exists to pay.
