# Quickstart: Validating the Profiles Admin Panel

**Feature**: `001-profiles-admin-panel` | **Date**: 2026-07-28

How to prove this feature works end to end. Scenario numbers map to the
acceptance scenarios in [spec.md](./spec.md); the surface under test is defined
in [contracts/admin-surface.md](./contracts/admin-surface.md).

This is a validation guide. Implementation code belongs in `tasks.md` and the
implementation phase, not here.

---

## Prerequisites

- Docker running, from `django_version/`. Every command below runs inside the
  container — never on the host Python.
- A superuser to sign in with. If none exists:

```bash
docker-compose up -d
docker-compose exec web python manage.py createsuperuser
```

`createsuperuser` delegates to `BaseUserManager.create_superuser()`, which calls
`full_clean()`, so the password must satisfy `validate_strong_password`.

- The skill vocabulary. In a real environment `profiles/migrations/0002_seed_skills.py`
  has already seeded 30 skills. Confirm:

```bash
docker-compose exec web python manage.py shell -c \
  "from profiles.models.skill import Skill; print(Skill.objects.count())"
```

Expect `30`. If it prints `0`, migrations have not run — `manage.py migrate`
first. **The test suite is different**: `pytest.ini` sets `--no-migrations`, so
the `skills` table starts empty there and tests must create their own rows.

---

## Automated validation

The suite is the primary gate. Nothing is complete until it passes
(Principle IX).

```bash
docker-compose exec web pytest
```

Targeted runs while working:

```bash
docker-compose exec web pytest profiles/tests/admin/ -v          # SkillAdmin
docker-compose exec web pytest accounts/tests/admin/ -v          # inlines + lists
docker-compose exec web pytest profiles/tests/models/ -v         # FR-029 clean()
docker-compose exec web pytest accounts/tests/admin/test_admin.py -v  # regression, SC-009
```

That last command is the SC-009 gate: every existing account-administration test
must still pass. The only permitted changes are those FR-024 names as intended —
the profile section, the profile indicator and its filter, and the skill filter.

Confirm no **unintended** schema drift:

```bash
docker-compose exec web python manage.py makemigrations --check --dry-run
```

Expect "No changes detected". A non-empty result means a model change slipped in
and must be raised before going further (Principle IV).

> **Amended 2026-08-05.** This line previously read *"no migration in this
> feature"*. The FR-002 clarification of 2026-08-04 introduces **exactly one**
> intentional migration — the `UniqueConstraint(Lower("name"))` on `Skill.Meta`
> (`skill_unique_name_case_insensitive`), tasks.md T074/T075. Run this check
> **after** that migration is generated and applied; "No changes detected" is
> then the correct expectation. Any pending change beyond that one migration
> still means something slipped in. See research.md R-010, amended.

---

## Manual validation

Sign in at `http://localhost:8000/admin/`.

### A. Skill vocabulary — User Story 1

| # | Do this | Expect | Scenario |
|---|---|---|---|
| A1 | Open **Profiles → Skills** | List with `name` and `category`, 25 rows per page, ordered by category then name, search box, category filter | FR-004, FR-021 |
| A2 | Add a skill with a name and category | Saved, appears in the list | US1-1 |
| A3 | Add a skill reusing an existing name | Refused with a message **on the name field** | US1-2 |
| A4 | Add a skill named `"  Docker  "` | Stored as `Docker` | US1-3 |
| A5 | Add a skill named `"   "` | Refused with a message on the name field | US1-4 |
| A6 | Filter by category, then search by name | Only matching skills listed | US1-5 |
| A7 | Delete a skill no profile refers to | Permanently removed | US1-6, FR-027 |
| A8 | Delete a skill at least one profile refers to | Refused, with a message giving the **count** of profiles — and no list of individual profiles | US1-7, FR-028 |
| A9 | Select several skills → **Delete selected** with one in use | Same refusal; nothing is deleted | FR-028 (bulk) |
| A10 | With `Python` in the vocabulary, add a skill named `python` | Refused with a message **on the name field**; no second row created; the existing skill is still spelled `Python` | US1-8, FR-002 |
| A11 | Add a skill named `JavaScript` | Stored exactly as `JavaScript` — no capitalization rule applied | US1-9, FR-002 storage clause |
| A12 | Open an existing skill and rename it onto **another** skill's name, differing only in case | Refused with a message on the name field; both skills keep their stored names | FR-002 (edit path) |

After A8 and A9, re-open an affected profile and confirm the skill is **still
attached** — nothing may be detached as a side effect (SC-010).

### B. Freelancer profile on the account screen — User Story 2

| # | Do this | Expect | Scenario |
|---|---|---|---|
| B1 | Open an **active** freelancer with no profile | Profile section present and empty, no way to add a second | US2-1, FR-032 |
| B2 | Fill it in, attach ≥3 skills, save | Stored and linked; reopening shows the values | US2-1, US2-5, SC-002 |
| B3 | Set `hourly_rate` to `0`, then `-10` | Refused, message on the hourly rate field | US2-3 |
| B4 | Leave `hourly_rate` empty, save | Saved with no rate | US2-4 |
| B5 | Paste a 501-character biography | Refused, message on the biography field | US2-6 |
| B6 | Look for a delete control on the profile section | **None exists** | FR-023, SC-006 |
| B7 | Look for a "+" to create a new skill next to the skills widget | **None exists** | FR-010 |
| B8 | Open a **deactivated** freelancer with no profile, fill the section, save | Refused, field-level message; **no profile created** | US2-7, FR-029 |
| B9 | Open a **deactivated** freelancer that **has** a profile, change a value, save | Saved | US2-8, FR-030 |
| B10 | Open an **active** freelancer with no profile, fill the section, untick **Active**, save | Refused — evaluated against the status being saved | spec.md:229 |
| B11 | Open a **deactivated** freelancer with no profile, tick **Active**, fill the section, save | Accepted | spec.md:230 |
| B12 | Untick **Active** on a freelancer that **has** a profile and edit the profile in the same save | Accepted | spec.md:231 |
| B13 | **Add freelancer**: fill account fields + profile section, save | Both created | US2-9, FR-036 |
| B14 | **Add freelancer**: fill account fields only, save | Account created, **no profile** | US2-10, FR-036 |
| B15 | Open any account, touch nothing, save | No empty profile appears | spec.md:246 |

B10–B12 are the FR-029 core. Getting them wrong while B8 passes means the rule
is reading the database instead of the value being saved.

### C. Client profile on the account screen — User Story 3

Repeat section B against a client account, substituting: `max_budget` for
`hourly_rate` (US3-3), `interests` for `skills` (US3-5), `website_url` for
`portfolio_url`. Add:

| # | Do this | Expect | Scenario |
|---|---|---|---|
| C1 | Set `company_name` to three spaces, save | ⏳ **Deferred — currently accepted and stored empty.** Intended: refused, message on the company name field | US3-4 |
| C2 | Leave `company_name` empty, save | Accepted | FR-016 |

**On C1** — this row does **not** pass today, and that is a recorded decision,
not a regression. The admin form strips the value to `""` before
`ClientProfile.clean()` sees it, so `company_name_empty` never fires; the value
is stored empty, which is the correct outcome for an optional field, but no
message is shown. Full reasoning, verification against Django 6.0.7 and the
criteria that would reverse the decision are in
`docs/tech_debt/002-whitespace-only-company-name-accepted-in-admin.md`. It is
scheduled in `docs/ROADMAP_SKILLBRIDGE.md` → SPRINT 3.2.

Note the values in this table are written as bare descriptions, not quoted
literals — type **three spaces**, not `"   "` with the quotation marks. Quotes
typed into the field are ordinary characters and are stored as such.

### D. Account lists — User Stories 5 and 6

With some accounts having profiles and some not, and a known skill (say
`Python`) attached to several freelancer profiles:

| # | Do this | Expect | Scenario |
|---|---|---|---|
| D1 | Open the freelancer list | Each row shows whether that account has a profile, styled like the existing status badges | US5-1, FR-033 |
| D2 | Open the client list | Same | US5-2 |
| D3 | Filter to **without a profile** | Only profile-less accounts | US5-3, SC-011 |
| D4 | Filter to **with a profile** | Only accounts that have one | US5-4 |
| D5 | Filter the freelancer list by `Python` | Only freelancers whose profile lists it | US6-1 |
| D6 | Filter the client list by a skill | Only clients listing it as an interest | US6-2 |
| D7 | Filter by a skill held by a freelancer with several skills | That freelancer appears **exactly once** | US6-3, FR-039, SC-012 |
| D8 | Filter the freelancer list by `Python`, then open each account it lists and remove `Python` from its profile, saving the account each time | The list loses a row per save, and `Python` stays selected and offered while any profile still holds it. After the last one the filtered list comes back with no rows, `Python` is gone from the sidebar, and no error is shown | US6-4 |
| D9 | Open the **staff** list | No profile badge, no profile filter, no skill filter | US5-5, US6-5, FR-035 |
| D10 | Read the skill filter in the sidebar | Only the skills a profile on that list refers to, not the whole vocabulary | FR-037, FR-038 |

D1 is also a performance check. Open Django's SQL log (`django.db.backends` is at
`DEBUG` in development) and confirm the changelist does **not** issue one query
per row for the profile badge (R-006).

### E. No regression on account administration — User Story 4

| # | Do this | Expect | Scenario |
|---|---|---|---|
| E1 | Look for a Delete button on any account screen | **None** | FR-024 |
| E2 | Save a new account with no password | Password unusable, never blank | FR-024 |
| E3 | Sign in as a non-superuser staff account, open a staff account | `is_staff` read-only; `is_superuser` read-only for everyone | FR-024 |
| E4 | Run the freelancer bulk availability actions | Behave exactly as before | FR-024 |
| E5 | Break a profile rule and save from the account screen | Message beside the offending field **inside the profile section** — never a failure page | US4-4, SC-004 |
| E6 | Sign in as a staff account with `is_active=False` | No admin access at all | FR-025 |

### F. Consistency review — SC-008

Open a skill screen and an account screen side by side and compare field
grouping, collapsed sections, page size, ordering and read-only timestamps.
Expect zero discrepancies, **with one intended exception**: the skill screens
have no timestamp section and are ordered by category then name, because `Skill`
carries no timestamp fields. This narrowing of FR-021 is a recorded decision —
see [research.md](./research.md) R-002. It is not a discrepancy.

---

## Done when

- [ ] `docker-compose exec web pytest` passes in full.
- [ ] The one intended migration — `skill_unique_name_case_insensitive` on
      `Skill` (FR-002) — exists, is committed, and is **applied**; and
      `makemigrations --check --dry-run` reports no changes **afterwards**.
      Amended 2026-08-05; this line previously read simply "reports no changes".
- [ ] Every row in sections A–F behaves as stated.
- [ ] `accounts/tests/admin/test_admin.py` passes unchanged (SC-009).
- [ ] `profile_for_inactive_account` **and** `skill_name_duplicate` are both in
      the *Established invariants* list in `.claude/rules/conventions.md`.
- [ ] *Admin conventions* in `.claude/rules/conventions.md` records the
      `SkillAdmin` deletion exception (finding F-7, T085).
