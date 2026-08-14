# The Skill-Name Duplicate Comparison Is Evaluated Entirely in the Database

**Date:** 2026-08-07
**Status:** Accepted
**Applies to:** `Skill.clean()`, `skill_unique_name_case_insensitive`, and any future
serializer, form, command or import comparing skill names.

## Context and Problem Statement

`Skill.clean()` refuses a name an existing skill already carries when letter case is
ignored, and `UniqueConstraint(Lower("name"))` enforces the same rule in the database.
The two agreed only by coincidence: the lookup compared `Lower("name")`, evaluated by
PostgreSQL, against `self.name.lower()`, evaluated by CPython. PostgreSQL's `lower()`
maps per character; CPython's does full Unicode case mapping and can change the string's
length. Measured on PostgreSQL 17 and Python 3.14 on 2026-08-06:

```
PG   lower('İ')  = 'i'     (1 character)
Py   'İ'.lower() = 'i̇'     (2 characters, U+0069 U+0307)
```

With `I` in the vocabulary and `İ` submitted, `clean()` found no duplicate. Integrity
held — the constraint refused the write — but the operator got the violation under
`__all__` with no code, or a raw `IntegrityError` where `full_clean()` is skipped, instead
of the error beside the `name` field that `clean()` exists to produce. `İ` is Turkish, and
the platform targets the European market.

## Considered Options

- Keep the Python-side `.lower()` and record the divergence as a known limit
- `name__iexact=self.name`
- A non-deterministic ICU collation on the `name` column
- Lowercase the candidate in the database too: `Lower(models.Value(self.name))`

## Decision Outcome

Chosen option: **`Lower(models.Value(self.name))`**, so both sides go through the one
function the constraint indexes. Verified on Django 6.0.7 and PostgreSQL 17: the lookup
compiles to `WHERE LOWER("skills"."name") = (LOWER(%s))`, with the name bound as a
parameter. The indexed left-hand expression is untouched, so `clean()` and the constraint
now agree by construction rather than by coincidence. The `Value` wrapper is required —
a bare string in an expression position would be read as a column reference.

`__iexact` was rejected: it compiles to `UPPER()` while the constraint indexes `LOWER()`,
so the index would go unused, and uppercasing is lossy in German — `ß` and `ss` both
uppercase to `SS`. **Do not "simplify" the lookup to `__iexact`.** An ICU collation was
already closed by `docs/adr/case-insensitive-skill-name-uniqueness.md`. Documenting the
divergence was set aside because the fix is one expression and generates no migration.

### Consequences

- Good, because the field-level `skill_name_duplicate` message now reaches the operator
  for every name the constraint would refuse, not merely most of them.
- Good, because the comparison holds across the European alphabets the platform serves.
  Lowering is the direction that keeps them distinguishable, which is why `lower` was kept
  on both sides rather than moved to `upper` — that folds German `ß` and `ss` together.
- Good, because the change is one expression: no import, no field or `Meta` change, and
  `makemigrations --check` reports no changes.
- Bad, because the comparison costs a database round trip for a value already in memory,
  and reads correctly only if `Lower` is understood as PostgreSQL's, not Python's.
