# Technical Debt — Whitespace-only company name is accepted in the admin

**Status:** deferred
**Date recorded:** 2026-08-04
**Area:** `profiles/models/client_profile.py`, `accounts/admin.py`
**Applies to:** `ClientProfile.company_name`
**Related:** FR-016, FR-020, US3-4 and quickstart row C1 in
`specs/001-profiles-admin-panel/`; task T038 in that feature's `tasks.md`

## The gap

`ClientProfile.clean()` refuses a `company_name` that is empty once surrounding
whitespace is removed, raising `company_name_empty`. That refusal never reaches
the Django admin. A company name typed as three spaces is saved as an empty
string, silently, with no message shown to the administrator.

FR-016 requires the refusal. FR-020 requires every rule enforced on the
underlying data to surface in the administration screens as a message attached
to the offending field. Neither holds for this one rule today.

## Why the rule does not fire

Django's form `CharField` carries `strip=True` by default. The admin form cleans
the submitted value **before** assigning it to the model instance, so `"   "`
becomes `""` and the guard `if self.company_name:` in `clean()` evaluates to
`False`. The branch is skipped entirely.

Verified against the pinned Django 6.0.7, at both levels:

- at the field — `company_name` `formfield().clean("   ")` returns `""`;
- end to end — the bound inline formset reports `is_valid() == True` with no
  errors, and tracing `ClientProfile.clean()` confirms it **is** called, once,
  receiving `''`.

The model rule is correct and the model test
`test_client_profile_raises_validation_error_with_empty_company_name` passes,
because it constructs the instance directly and bypasses the form, so the
whitespace survives. The test is valid — it covers a path the admin does not
use. No test covered the form-to-model path, which is why the gap stayed
invisible.

## Why it is deferred, not implemented

`company_name` is optional (`blank=True`). The stored outcome is already
correct: `"   "` normalizes to `""`, which is precisely what the second half of
FR-016 accepts as "no company name recorded". No invalid value is persisted and
no data is corrupted. What is missing is only the message telling the
administrator that their whitespace was discarded.

Closing it in the admin would mean a form-level rule duplicating one the model
already states, in a layer the project is already scheduled to replace. The fix
was designed and verified working on 6.0.7 before being rejected: a
`ClientProfileInlineForm` setting `strip = False` on the field and
re-implementing the check in `clean_company_name()` — roughly 20 lines of
production code plus three tests. It was judged disproportionate for an optional
free-text field carrying no presence, length or format rule of its own.

**This assessment changes** if `company_name` ever becomes required, gains a
minimum length or a format rule, or becomes searchable. Any of those makes
silent acceptance costly enough to enforce the refusal before the serializer
exists.

## What to do when the serializer arrives

Already covered by `docs/ROADMAP_SKILLBRIDGE.md` →
_TASK 3.x.x — ClientProfile / FreelancerProfile serializers: enforce clean()
invariants_ (SPRINT 3.2), which lists both `company_name_empty` and the
relocation of `company_name.strip()`.

1. Let the serializer own the normalization, and have it run the model
   invariants — `validate()` calling `full_clean(validate_unique=False)`, as
   that task already specifies.
2. **Check DRF's `CharField.trim_whitespace`.** It defaults to `True` and will
   reproduce this exact gap at the API layer if left untouched. Verify against
   the DRF version pinned on install — DRF is not installed yet, so this has
   not been confirmed against a pinned version.
3. **Keep the `company_name` branch in `ClientProfile.clean()`.** It is not dead
   code: it is the backstop for paths that touch neither form nor serializer
   (shell, scripts, data migrations), and it is what the serializer invokes.
4. Re-run quickstart row C1, annotated as deferred until this lands.
