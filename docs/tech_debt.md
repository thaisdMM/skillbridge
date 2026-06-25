# Technical Debt — Bulk deactivation for end-user accounts

**Status:** deferred
**Date recorded:** 2026-06-24
**Area:** `accounts/admin.py`

## Decision deferred

Bulk deactivation is intentionally **not** available for end-user accounts
(`Client`, `Freelancer`) in the Django admin. Both are deactivated
individually through the change form. Bulk deactivation remains available only
for `StaffUser` (internal operators).

## Why it is deferred, not implemented

Deactivating an end user removes their access to the platform. At the current
project stage this is treated as a consequential, per-account action rather
than a bulk sweep, and both end-user types are kept consistent (individual
only). This is a design/policy choice — for `Client` it is not driven by any
model invariant; for `Freelancer` the active/availability invariant is an
additional technical reason.

## What to do if the platform scales to need it

If bulk deactivation of end users becomes a real operational need:

1. Reintroduce a shared `DeactivateAccountsMixin` in `accounts/admin.py` and
   compose it into `ClientAdmin` and `FreelancerAdmin`.
2. For `Client`: a single `queryset.update(is_active=False)` is safe — `Client`
   has no active-dependent invariant.
3. For `Freelancer`: the action must **not** use a blind bulk `update()`. It
   must iterate per instance, call `obj.clean()` before saving, and skip +
   report rows that would violate the active/availability invariant
   (`freelancer_no_inactive_available`). This mirrors the validated
   `set_available` action already in `FreelancerAdmin`.
4. Consider a confirmation step (intermediate admin page) given the impact of
   removing access for many users at once.
