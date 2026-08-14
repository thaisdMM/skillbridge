# Model `clean()` Assumes Converted Field Types — No Type Guard Added

**Date:** 2026-07-16
**Status:** Accepted
**Applies to:** `ClientProfile.max_budget`, `FreelancerProfile.hourly_rate`, and any
future numeric or typed invariant enforced in a model `clean()`.

## Context and Problem Statement

`ClientProfile.clean()` and `FreelancerProfile.clean()` compare their amount field
against `Decimal("0.00")` after a `is not None` guard. If a value that is not a
`Decimal` is assigned directly to the attribute — for example the string `"abc"` —
`Model.full_clean()` raises an unhandled `TypeError` instead of a `ValidationError`.

The mechanics: `full_clean()` runs `clean_fields()` first, which reports the bad value
with `code="invalid"` and stores that error; it does **not** overwrite the attribute.
`full_clean()` then runs `self.clean()` deliberately — so that the user sees every
error at once — but it only catches `ValidationError`. The `TypeError` escapes and
takes the already-collected `invalid` error with it.

Which paths can actually reach this state, and should `clean()` defend against it?

## Considered Options

* Leave `clean()` as is — no type guard
* Add a type guard inside `clean()` (`isinstance(self.max_budget, Decimal)`)
* Replace the `clean()` check with Django's built-in `MinValueValidator` on the field
* Replace the `clean()` check with a custom validator function on the field

## Decision Outcome

Chosen option: **"Leave `clean()` as is — no type guard"**, because no user-facing path
can reach the `TypeError`. Verified on Django 6.0.6:

| Path | Input `"abc"` | Result |
| --- | --- | --- |
| Admin / any `ModelForm` | `is_valid()` → `False` | `"Enter a number."` — the field is never assigned to the instance, so `clean()` never compares a string |
| DRF `ModelSerializer` (even one calling `full_clean()` in `validate()`) | `is_valid()` → `False` | `code="invalid"` — `to_internal_value()` converts before `validate()` runs |
| Shell / script assigning the attribute directly | — | `TypeError` |

Only a developer assigning a raw, unconverted value in the shell reaches it. In that
context a crash is the correct signal: it names the real mistake instead of hiding it
behind a friendly message.

**This is a closed decision.** Re-raising the `TypeError` as an audit finding requires
new evidence of a non-shell path that reaches it — for example an import command, a
service, or a fixture loader that assigns unconverted external input to the attribute.
The absence of a type guard is deliberate, not an oversight.

### Consequences

* Good, because `clean()` carries only the business invariant and no defensive code
  against a state that Django's own field conversion already reports as `invalid`.
* Good, because the mirror `FreelancerProfile.hourly_rate` requires no change, and no
  migration is generated.
* Bad, because `full_clean()` called directly on an instance holding an unconverted
  value raises `TypeError` rather than `ValidationError`, and the `invalid` error that
  `clean_fields()` had already collected is lost with it.
* Bad, because the invariant does not run under DRF by default — `ModelSerializer` does
  not call `clean()`. Closing that gap is a Phase 3 task, not a model-layer change.

## Pros and Cons of the Options

### Leave `clean()` as is — no type guard

* Good, because it is reachable only from a developer-trusted path already accepted
  elsewhere in the project.
* Good, because zero change, zero migration, zero divergence from the mirror.
* Bad, because a direct `full_clean()` in a script surfaces a `TypeError` instead of a
  field error.

### Add a type guard inside `clean()`

* Good, because it is local, keeps the project error code, and generates no migration.
* Good, because nothing is lost: `clean_fields()` has already recorded `invalid`.
* Bad, because it is defensive code against a case only the shell produces.
* Bad, because it must be duplicated in `FreelancerProfile` to avoid mirror divergence.

### Django's `MinValueValidator` on the field

* Good, because the `TypeError` disappears by construction — field validators run
  inside `clean_fields()`, after conversion, so they are never called with a bad type.
* Good, because DRF `ModelSerializer` copies model field validators into the serializer
  automatically, so the rule runs in the API with no extra code.
* Bad, because the error code becomes `min_value` instead of `max_budget_not_positive`,
  and tests assert on the code (`conventions.md` → *Tests assert on the code*).
* Bad, because `validators` is part of the field's `deconstruct()`, so it generates a
  migration.

### Custom validator function on the field

* Good, because it removes the `TypeError`, runs in DRF automatically, and preserves
  `max_budget_not_positive`.
* Bad, because it adds a custom validator where a Django built-in already covers the
  need. `conventions.md` → *Validators* prefers custom validators only when a specific
  error code is required — that condition does not outweigh the cost here.
* Bad, because it requires a new `profiles/validators/` package and a migration.
