# Positive-Amount Invariants Enforced by `clean()` Only — No `CheckConstraint`

**Date:** 2026-07-16
**Status:** Accepted
**Applies to:** `ClientProfile.max_budget`, `FreelancerProfile.hourly_rate`, and any
future amount field whose only invariant is a minimum value.

## Context and Problem Statement

`max_budget` and `hourly_rate` must be greater than zero when provided. Both are
enforced in the model `clean()` alone. `clean()` does not close the ORM gap:
`ClientProfile.objects.filter(...).update(max_budget=-5)` writes a negative amount
without raising.

The project already uses two-layer enforcement — `clean()` plus a `CheckConstraint` —
for `freelancer_no_inactive_available` and `staffuser_active_no_staff_status`. Does
that pattern extend to the positive-amount invariants?

## Decision Outcome

**No `CheckConstraint` is added.** The criterion for a database backstop in this project
is not "every invariant deserves one" — it is **"a concrete write path in the
application reaches the forbidden state"**. Both existing constraints were introduced
because the admin bulk action `activate_accounts` reaches the bad state; the constraint
is a backstop for a hole that demonstrably exists, not a precaution against a
hypothetical one.

No bulk action, admin action, manager, or service writes `max_budget` or `hourly_rate`.
The only realistic path is a developer running `.update()` in the shell — the same
developer-trusted path the project already accepts elsewhere.

This decision imposes a constraint on the admin layer, which is the reason it is
recorded rather than left implicit:

> **Admin bulk actions that write `max_budget` or `hourly_rate` are not permitted.**
> If such an action — or any import command, service, or migration that writes these
> fields from external input — is ever required, this decision must be revisited and a
> `CheckConstraint` added in the same change that introduces the write path.

### Consequences

* Good, because the constraint set stays small and every constraint in the schema maps
  to a real, named write path. The schema documents actual risk instead of ambient
  caution, which is what makes the two existing constraints legible.
* Good, because no migration is required and the mirror `FreelancerProfile.hourly_rate`
  stays consistent with `ClientProfile.max_budget` — a divergence between the two would
  be a cost of its own.
* Bad, because a direct `queryset.update(max_budget=-5)` writes a negative amount with
  no error at any layer. This is accepted: the ORM shell is developer-trusted, and the
  admin restriction above is what keeps that from becoming a user-reachable path.
