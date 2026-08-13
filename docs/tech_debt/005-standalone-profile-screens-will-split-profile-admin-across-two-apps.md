# Technical Debt — Standalone profile screens will split profile admin across two apps

**Status:** deferred
**Date recorded:** 2026-08-13
**Area:** `accounts/admin.py`, `profiles/admin.py`
**Applies to:** `FreelancerProfileInline`, `ClientProfileInline`, `BaseProfileInline`,
and the future `FreelancerProfileAdmin` / `ClientProfileAdmin`
**Related:** R-001 in `specs/001-profiles-admin-panel/research.md` records the
placement decision and the alternatives rejected; this entry records only the cost
it accepted

## The gap

Profiles have no standalone admin screen. They are edited inline on the account
screen that owns them, so `FreelancerProfileInline` and `ClientProfileInline` live in
`accounts/admin.py`, next to the account admins that mount them. `profiles/admin.py`
registers `SkillAdmin` and nothing else.

The day standalone screens are built, a `FreelancerProfileAdmin` would belong in
`profiles/admin.py` — it is a registered screen for a `profiles` model — while
`FreelancerProfileInline` stays in `accounts/admin.py`. The same model would then be
presented from two apps, and the two presentations would have to agree on fieldsets,
readonly timestamps, and the refusal to delete.

`BaseProfileInline` already holds what the two inlines share, but it inherits
`admin.StackedInline`, so a `ModelAdmin` cannot reuse it as it stands.

## Why it is deferred, not implemented

**The inline supplies everything profile administration needs today.** An
administrator reaches a profile by opening the account it belongs to, and edits it
there without leaving the page — which is the behavior this feature set out to
deliver, not a workaround for a missing screen.

Building standalone screens as well would mean a second presentation of both profile
models and a full second suite of tests covering it, for no capability that does not
already exist. That cost is not justified at MVP stage, where delivery speed is the
priority. The debt is accepted deliberately: not an oversight, and not a design the
project intends to keep forever.

## Reversal criteria

Any one of these makes the deferral wrong, and the shared base should be built then:

1. **A profile must be reachable without its account** — a profile list, a direct
   profile URL, or any registered `ModelAdmin` for `FreelancerProfile` or
   `ClientProfile`.
2. **A third presentation of the same model appears** — most likely a DRF serializer
   with its own field grouping once the API layer is installed.
3. **The inline and a second presentation diverge by accident** — a fieldset or a
   delete rule changed in one place and not the other.

## What to do when one of them fires

1. Extract the presentation-shaped members — fieldsets, readonly fields, and the
   delete refusal — into a mixin that inherits from neither `StackedInline` nor
   `ModelAdmin`, so both can take it.
2. Leave the inline-only members (`extra`, `max_num`, `can_delete`, `form`) on
   `BaseProfileInline`. They have no meaning on a `ModelAdmin`.
3. Keep the import direction as it is: `accounts.admin` imports `profiles.models`,
   never `profiles.admin`.
4. Carry the delete suppression onto the new screen deliberately. A profile is
   retired with its account, never deleted, and a registered screen exposes a delete
   route the inline never did.
