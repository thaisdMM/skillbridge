# Technical Debt — The account search does not reach profile fields

**Status:** deferred
**Date recorded:** 2026-08-09
**Area:** `accounts/admin.py`
**Applies to:** `FreelancerAdmin.search_fields`, `ClientAdmin.search_fields`

## The gap

The account search box matches name and email. Two things an administrator
would reasonably type into it find nothing:

- **a skill** — "who offers Python?" is answerable only through the sidebar
  filter, one skill at a time;
- **a company name** — not searchable anywhere, and it lives on the client
  profile rather than on the account.

## Why it is deferred, not implemented

Profiles are administered inside the account screen, and the decision that put
them there also settled that profiles are not searched directly: the account is
the entry point, and the loss of client search by company name was recorded and
accepted at the time.

The skill half is partly served already — both account lists filter by skill,
which answers the same question through a different control. The company-name
half has no substitute.

## What it would take

One string per list: `"profile__skills__name"` on the freelancer search,
`"profile__interests__name"` on the client search. Django detects that the
search spans a many-valued relation and applies `.distinct()` itself, so no
account is listed twice — verified against the pinned Django 6.0.7 in
`ModelAdmin.get_search_results`.

Two things to decide then, not now:

1. **Skill and company name are one decision, not two.** Doing either alone
   leaves the same gap half open.
2. **What the box means.** Mixing identity ("who is this person?") with
   capability ("who can do this?") in a single field needs `search_help_text`
   stating what it covers, or the results look arbitrary.

## Reversal criteria

Any one of these makes deferring wrong:

1. Searching by skill or company name is asked for more than once in real use.
2. `company_name` gains a rule of its own — required, minimum length, format —
   which also reverses `002-whitespace-only-company-name-accepted-in-admin.md`.
3. The vocabulary outgrows what a sidebar filter can present, so the filter
   stops being a substitute for search.

## What to do when one of them fires

1. Amend the spec first: the criterion stating that profiles are not searched
   directly, and the admin surface contract, both of which currently record
   `search_fields` as unchanged.
2. Add both strings in the same change, with `search_help_text` on both lists.
3. Cover it with a test per list asserting that an account is found by its
   skill and listed exactly once.
