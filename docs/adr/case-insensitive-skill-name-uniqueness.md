# Skill-Name Uniqueness Is Case-Insensitive; Stored Casing Is Never Normalized

**Date:** 2026-08-05
**Status:** Accepted — implemented in `Skill.clean()` and `Skill.Meta.constraints`.
**Applies to:** `Skill.name`, `Skill.clean()`, `Skill.Meta.constraints`, and any future
serializer, form, or import path writing a skill name.

## Context and Problem Statement

`Skill.name` is `CharField(unique=True)`. On PostgreSQL that is a btree unique index over
raw text, which is case-sensitive — so `Python`, `python` and `PYTHON` are distinct rows,
and the seeded vocabulary already ships `Python`.

The failure is quiet. `Skill.__str__` returns the bare name, so a profile selector renders
two identical-looking rows; a skill filter on the account lists splits one skill across two
values and returns half an answer. Merging skills is not supported, so the cost of undoing
it grows with every profile that picks up either spelling.

## Considered Options

* Case-insensitive check in `Skill.clean()` only
* `UniqueConstraint(Lower("name"))` in `Skill.Meta` only
* Both — `clean()` carries the message, the constraint is the database backstop
* A case-insensitive column type or collation on `name`

## Decision Outcome

Chosen option: **"Both"**, with **storage never normalized** — mirroring the two-layer
pattern already used for `freelancer_no_inactive_available`.

The constraint alone cannot put the error beside the name field. Verified on the pinned
Django 6.0.7: `Model.validate_constraints()` routes an error to a field only when the code
is `unique` **and** the constraint declares exactly one `fields` entry, so an expression
constraint lands under `NON_FIELD_ERRORS`. `clean()` alone is not enough either — it is not
called by `.create()`, `.update()`, `bulk_create()` or a shell write, which are exactly the
paths a vocabulary import would use.

A case-insensitive collation was rejected twice over: `CIText` is gone from modern Django,
and a collation would make *every* comparison on `name` case-insensitive, for a column-type
migration far larger than the problem requires. `unique=True` stays on the field — removing
it would add an `AlterField` for no behavioural gain.

Storage is not normalized because the casing is meaningful: `JavaScript`, `PHP`, `C#`,
`C/C++`, `HTML/CSS`, `UI/UX Design`. Any capitalization rule mangles several of them. Names
are stored exactly as typed, trimmed only; on a conflict the existing skill keeps its name.

Two ordering rules follow: trim before comparing, so `"  python  "` is refused against
`Python`; and exclude the row being saved, or saving a skill unchanged would refuse itself
and correcting its casing in place would be impossible.

> **Any serializer, form, command or import writing `Skill.name` must call `full_clean()`,
> and must not normalize casing.** Without `full_clean()` only the constraint fires, and it
> cannot produce a field-level message.

### Consequences

* Good, because one concept occupies one row — the selector shows a skill once and a skill
  filter returns the whole answer.
* Good, because it reuses the established two-layer pattern and preserves meaningful casing.
* Bad, because it adds a migration that **aborts if the target database already holds a case
  collision**. Development was checked 2026-08-05: 32 rows, 0 collisions. Any other
  environment must be re-checked before it is migrated.
* Bad, because this is the only `clean()` here that issues a queryset lookup, so tests
  touching it need database access — a real divergence from every other `clean()`.
* Bad, because "ignoring letter case" has to mean the same thing in both layers, which
  only holds if the comparison is evaluated in one engine — see
  `docs/adr/skill-name-comparison-is-evaluated-in-the-database.md`.
* Bad, because the `unique` code becomes unreachable once `clean()` refuses duplicates
  (`full_clean()` excludes already-failed fields before `validate_unique()`), so tests
  asserting it must move to `skill_name_duplicate`.
