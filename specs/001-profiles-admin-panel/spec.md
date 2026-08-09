# Feature Specification: Profiles Admin Panel

**Feature Branch**: `001-profiles-admin-panel` (spec directory; no git branch was created by this command — current branch is `feature/django-refactor`)

**Created**: 2026-07-27

**Status**: Draft

**Input**: User description: "I need to create the admin panel to app profiles. I need to create a admin for profiles that create profiles, create skills and do all the profiles requirements, but at the same time I need to connect this admin from profiles with the django_version/accounts/admin.py for accounts app. For the django_version/profiles/admin.py we have the follow the same standard established in the django_version/accounts/admin.py. if you have questions you can ask me."

## Shape of this feature *(decided 2026-07-27)*

Profiles are **not** given screens of their own. A freelancer profile and a
client profile are created, viewed and edited **on the account screen of the
account they belong to** — one combined screen per account.

The skill vocabulary keeps its own dedicated screen, because a skill belongs to
the whole platform and is not attached to any single account.

Three changes to the existing account administration are **intended**, not
accidental: the account screen gains a profile section, and the freelancer and
client account **lists** gain both an indicator and filter for whether an account
has a profile, and a filter by the skills that account's profile refers to.
Everything else about account administration stays exactly as it is.

Staff accounts have no profile. Neither the staff account screen nor the staff
account list changes in any way.

## Clarifications

### Session 2026-08-04

- Q: FR-002 — should skill-name uniqueness be case-insensitive? → A: Case-insensitive. `python` is a duplicate of `Python` and is rejected against the name field.
- Q: FR-002 — should the stored skill name be normalized to a capitalization standard? → A: No normalization. The name is stored exactly as entered, whitespace-trimmed only; on a case-insensitive conflict the existing skill keeps its stored name.

## User Scenarios & Testing *(mandatory)*

The single actor in this feature is a **platform administrator** — an active
staff account with administration access. No end user (freelancer or client)
interacts with this feature; profile self-service is out of scope.

### User Story 1 - Curate the platform skill vocabulary (Priority: P1)

An administrator opens the administration area and manages the controlled list of
skills that the whole platform draws on. They add a new skill, give it a service
category, correct the spelling of an existing one, browse or search the list to
check whether a skill already exists before adding a near-duplicate, and remove
an entry that turned out to be wrong or duplicated.

**Why this priority**: Skills are a controlled vocabulary owned exclusively by
administrators — freelancers and clients only select from the list, they never
create entries. Every other story in this feature depends on skills already
existing: a freelancer profile cannot declare expertise and a client profile
cannot declare interests until the vocabulary is populated. This story delivers
standalone value even if nothing else ships, because it is the only supported way
to grow or correct the vocabulary.

**Independent Test**: Fully testable by signing in as an administrator, adding a
skill in each service category, searching for it by name, editing it, removing an
unused one, and confirming a skill that a profile refers to cannot be removed.
Delivers value with no profile work in place.

**Acceptance Scenarios**:

1. **Given** an administrator on the skills screen, **When** they add a skill with a name and a service category, **Then** the skill is saved and appears in the list.
2. **Given** a skill name that already exists, **When** the administrator tries to add it again, **Then** the save is rejected with a field-level message on the name, and no duplicate is created.
3. **Given** a skill name entered with leading or trailing spaces, **When** the administrator saves, **Then** the stored name is trimmed.
4. **Given** a name consisting only of whitespace, **When** the administrator saves, **Then** the save is rejected with a field-level message on the name.
5. **Given** a populated skill list, **When** the administrator filters by service category or searches by name, **Then** only matching skills are listed.
6. **Given** a skill that no freelancer profile lists as a skill and no client profile lists as an area of interest, **When** the administrator removes it, **Then** it is permanently removed from the vocabulary.
7. **Given** a skill that at least one profile still refers to, **When** the administrator tries to remove it, **Then** the removal is refused with a message stating that the skill is still in use and how many profiles refer to it, and the skill remains attached to every profile that refers to it.
8. **Given** an existing skill named `Python`, **When** the administrator tries to add `python`, **Then** the save is rejected with a field-level message on the name, no duplicate is created, and the existing skill is still named `Python`.
9. **Given** a name whose casing is meaningful, such as `JavaScript`, **When** the administrator saves it, **Then** the stored name is exactly `JavaScript` — the platform applies no capitalization rule of its own.
10. **Given** an existing skill named `Python`, **When** the administrator edits **that same skill** and changes its name to `python`, **Then** the change is accepted and the skill is stored as `python`. Correcting the casing of an existing entry is editing it (FR-005), not adding a duplicate.
11. **Given** an existing skill, **When** the administrator opens it and saves without changing the name, **Then** the save is accepted — a skill never conflicts with itself.

---

### User Story 2 - Manage a freelancer's profile from their account screen (Priority: P2)

An administrator finds an existing freelancer account using the account search,
opens it, and works on that freelancer's profile **on the same screen**: hourly
rate, years of experience, portfolio link, biography, and the skills that
freelancer offers. Returning later, they open the same account and correct the
details.

**Why this priority**: Freelancer profiles carry the data the marketplace matches
on. They are the richest profile type and the one that exercises every kind of
field in this feature. Ranked below skills only because a freelancer profile
cannot declare skills until the vocabulary exists.

**Independent Test**: Fully testable by opening an existing active freelancer
account in the administration area, filling in its profile section, attaching
skills, saving, then reopening the account and confirming the values persisted.
Requires only that at least one freelancer account and one skill exist. The
account is reached through the account search that already exists.

**Acceptance Scenarios**:

1. **Given** an active freelancer account with no profile, **When** the administrator fills in the profile section on that account screen and saves, **Then** the profile is stored and linked to that account.
2. **Given** a freelancer account that already has a profile, **When** the administrator opens it, **Then** exactly one profile is presented for editing and there is no way to add a second.
3. **Given** the profile section with an hourly rate of zero or a negative value, **When** the administrator saves, **Then** the save is rejected with a field-level message on the hourly rate.
4. **Given** the profile section with the hourly rate left empty, **When** the administrator saves, **Then** the profile is stored with no rate recorded.
5. **Given** an existing profile, **When** the administrator attaches or removes skills and saves, **Then** the profile's skill set reflects the change.
6. **Given** a biography longer than 500 characters, **When** the administrator saves, **Then** the save is rejected with a field-level message on the biography.
7. **Given** a deactivated freelancer account with no profile, **When** the administrator fills in the profile section and saves, **Then** the save is refused with a field-level message and no profile is created.
8. **Given** a deactivated freelancer account that already has a profile, **When** the administrator corrects a value and saves, **Then** the change is stored.
9. **Given** an administrator adding a brand-new freelancer account, **When** they fill in the account fields and the profile section together and save, **Then** the account and its profile are both created.
10. **Given** an administrator adding a brand-new freelancer account, **When** they fill in only the account fields and save, **Then** the account is created with no profile.

---

### User Story 3 - Manage a client's profile from their account screen (Priority: P3)

An administrator finds an existing client account using the account search, opens
it, and works on that client's profile **on the same screen**: company name,
maximum project budget, website, biography, and the areas of interest that client
is hiring for.

**Why this priority**: Client profiles complete the two-sided marketplace and
reuse the same interaction patterns proven by freelancer profiles, so they carry
less delivery risk. Ranked below freelancer profiles because matching and
discovery work begins on the supply side.

**Independent Test**: Fully testable by opening an existing active client account
in the administration area, filling in its profile section, attaching interests,
saving, then reopening the account and confirming the values persisted. Requires
only that at least one client account and one skill exist. The account is reached
through the account search that already exists.

**Acceptance Scenarios**:

1. **Given** an active client account with no profile, **When** the administrator fills in the profile section on that account screen and saves, **Then** the profile is stored and linked to that account.
2. **Given** a client account that already has a profile, **When** the administrator opens it, **Then** exactly one profile is presented for editing and there is no way to add a second.
3. **Given** the profile section with a maximum budget of zero or a negative value, **When** the administrator saves, **Then** the save is rejected with a field-level message on the budget.
4. **Given** a company name consisting only of whitespace, **When** the administrator saves, **Then** the save is rejected with a field-level message on the company name.
5. **Given** an existing profile, **When** the administrator attaches or removes areas of interest and saves, **Then** the profile's interest set reflects the change.
6. **Given** a deactivated client account with no profile, **When** the administrator fills in the profile section and saves, **Then** the save is refused with a field-level message and no profile is created.
7. **Given** a deactivated client account that already has a profile, **When** the administrator corrects a value and saves, **Then** the change is stored.
8. **Given** an administrator adding a brand-new client account, **When** they fill in the account fields and the profile section together and save, **Then** the account and its profile are both created.
9. **Given** an administrator adding a brand-new client account, **When** they fill in only the account fields and save, **Then** the account is created with no profile.

---

### User Story 4 - Profile and account on one screen, without regressing account administration (Priority: P4)

An administrator opening a freelancer or client account sees that account's
profile on the same screen and works on both together. Everything the account
screen already does keeps working exactly as before.

**Why this priority**: This story covers the cross-cutting guarantees of the
combined screen — how an absent profile is presented, how profile rule violations
are surfaced from within the account screen, and the promise that existing
account administration is untouched. It is ranked last among the profile stories
because it is verification of the whole, and because it is the part that touches
the already-working account administration screens; isolating that risk is
deliberate.

**Independent Test**: Fully testable by opening an account that has a profile and
confirming the profile is editable in place; opening an account with no profile
and confirming the absence is clear and a profile can be started there; and
re-running the existing account administration checks to confirm nothing regressed.

**Acceptance Scenarios**:

1. **Given** a freelancer or client account that has a profile, **When** the administrator opens that account, **Then** the profile is shown on the same screen and can be edited there.
2. **Given** an account with no profile yet, **When** the administrator opens that account, **Then** the absence of a profile is clear and a profile can be created from that same screen.
3. **Given** a change made to the profile on the account screen, **When** the administrator saves, **Then** the change is stored.
4. **Given** a value that breaks one of the profile rules, **When** the administrator saves from the account screen, **Then** the rejection is shown as a message next to the offending field within the profile section, and never as a failure page.
5. **Given** the existing account behavior — deactivation instead of deletion, hidden password handling, staff-only privilege controls — **When** the profile section is added, **Then** none of that behavior changes.

---

### User Story 5 - See at a glance which accounts have a profile (Priority: P5)

An administrator scanning the freelancer or client account list can tell which
accounts already have a profile and which are still missing one, and can narrow
the list to just one group or the other — for example, to work through every
freelancer who has not been given a profile yet.

**Why this priority**: With no standalone profile lists in this feature, the
account list is the only place this question can be answered. It is a discovery
aid rather than a new capability, and it depends on profiles existing, so it is
ranked after the stories that create them.

**Independent Test**: Fully testable by creating some accounts with profiles and
some without, opening the freelancer and client account lists, confirming the
indicator matches reality for each row, and confirming the filter narrows the
list to the expected group.

**Acceptance Scenarios**:

1. **Given** a freelancer account list containing accounts with and without profiles, **When** the administrator views it, **Then** each row shows whether that account has a profile.
2. **Given** a client account list containing accounts with and without profiles, **When** the administrator views it, **Then** each row shows whether that account has a profile.
3. **Given** either of those lists, **When** the administrator filters to accounts without a profile, **Then** only accounts with no profile are listed.
4. **Given** either of those lists, **When** the administrator filters to accounts with a profile, **Then** only accounts that have one are listed.
5. **Given** the staff account list, **When** the administrator views it, **Then** no profile indicator or profile filter is present.

---

### User Story 6 - Find accounts by skill (Priority: P6)

An administrator narrows the freelancer account list to everyone who offers a
given skill — every freelancer who does Python, say — or narrows the client list
to everyone hiring for it. They use this to match supply to demand, to see how
well covered a skill is, and to check who would be affected before changing the
vocabulary.

**Why this priority**: This is a capability of the administration panel in its
own right, not a support act for skill removal. Answering "who does X?" is a
routine administrative need, and the account lists are the only place it can be
answered while standalone profile screens remain deferred. It also happens to
supply the route FR-028 assumes — an administrator told a skill is still in use
can now find the profiles concerned — but that is a consequence, not the
justification. Ranked last because it depends on both skills and profiles
already existing, and because it can be delivered alongside User Story 5, which
touches the same lists.

**Independent Test**: Fully testable by giving several freelancer profiles a
known skill, filtering the freelancer account list by it, and confirming exactly
those accounts are listed and each appears once; then repeating on the client
list with an area of interest.

**Acceptance Scenarios**:

1. **Given** freelancer profiles that refer to a given skill and others that do not, **When** the administrator filters the freelancer account list by that skill, **Then** only the freelancers whose profile refers to it are listed.
2. **Given** client profiles listing a given skill as an area of interest, **When** the administrator filters the client account list by it, **Then** only those clients are listed.
3. **Given** a freelancer whose profile refers to several skills, **When** the administrator filters by one of them, **Then** that freelancer appears exactly once in the list.
4. **Given** a skill that no profile refers to, **When** the administrator filters by it, **Then** the list is empty and no error occurs.
5. **Given** the staff account list, **When** the administrator views it, **Then** no skill filter is present.

---

### Edge Cases

**Profiles and account status**

- An administrator opens a deactivated account that **already has** a profile and saves without touching the profile section — allowed. Nothing is created and nothing is refused.
- An administrator opens a deactivated account with **no** profile and saves without touching the profile section — allowed. No profile is brought into existence, so there is nothing to refuse.
- An administrator opens an **active** account with no profile, fills in the profile section, unticks "active", and saves — **refused**. A profile is never brought into existence attached to an account being deactivated in the same save.
- An administrator opens a **deactivated** account with no profile, ticks "active", fills in the profile section, and saves — **accepted**. The account is active by the end of that save.
- An administrator unticks "active" on an account that **already has** a profile and edits that profile in the same save — **accepted**. Only creation is blocked by deactivation; editing an existing profile is not.
- Deactivating an account leaves its profile exactly as it is. The profile is neither altered nor removed, and stays editable.
- An account is created and given a profile in the same save — permitted. The profile section is available while adding a new account, but filling it is optional and no profile is ever created automatically alongside an account.
- A new account is added with the profile section left untouched — the account is created with no profile, which is a valid state.

**Skills**

- A skill is added whose name differs from an existing one only in letter case — refused as a duplicate, reported on the name field. This matters more than an ordinary duplicate: two casings of one skill split the vocabulary invisibly (the selector shows two near-identical rows, and a skill filter on the account lists returns only half the answer), and merging duplicate skills is not supported in this feature — see the accepted limitation under Assumptions.
- A skill is added whose name differs from an existing one in letter case **and** in surrounding whitespace, e.g. `"  python  "` against `Python` — refused. Trimming happens first (FR-003), then the case-insensitive comparison (FR-002).
- An **existing** skill is edited and its casing corrected in place, `Python` → `python` on that same record — accepted. The case-insensitive rule compares one entry against the others, never against itself, so the record being saved is excluded from the comparison. Without that exclusion, opening any skill and saving it unchanged would refuse itself and FR-005 would be unusable. *(Clause made explicit in the spec on 2026-08-05; it follows from the 2026-08-04 decision and was already assumed by data-model.md and tasks.md.)*
- A skill is removed while freelancer profiles or client profiles still refer to it — refused, with a message stating the skill is still in use. Nothing is detached from any profile.
- An administrator is told a skill is still in use and needs to detach it from the profiles concerned before removing it. The refusal states how many profiles are affected; the administrator finds them by filtering the account lists by that skill, then detaches it from each one. Detaching is done one profile at a time — see the accepted limitation under Assumptions.
- A skill referred to only by profiles on deactivated accounts is still in use, and its removal is refused on the same terms.

**General**

- An account holds at most one profile. With the profile presented inside the account screen, this is enforced by the shape of the screen itself; the underlying one-per-account rule remains the backstop for every other path into the data.
- A freelancer profile is saved with no skills attached, or a client profile with no interests — permitted. The underlying data treats both as optional, and administrators need to record partial profiles.
- An administrator opens an account, touches nothing in the profile section, and saves. No empty profile is brought into existence by a save the administrator did not intend.
- Two administrators edit the same account at the same time — last write wins, consistent with the rest of the administration area.
- A monetary value is entered with more precision than is stored (e.g. more than two decimal places), or beyond the maximum storable amount.
- Text fields are submitted with surrounding whitespace only.
- The skill vocabulary grows large enough that picking skills inside the profile section becomes unwieldy.

## Requirements *(mandatory)*

### Functional Requirements

**Skill vocabulary**

- **FR-001**: Administrators MUST be able to create a skill by supplying a name and one of the platform's four service categories.
- **FR-002**: The system MUST reject a skill whose name duplicates an existing skill, reporting the conflict against the name field. Two names duplicate each other when they match **ignoring letter case**: with `Python` already in the vocabulary, `python`, `PYTHON` and `PythOn` are all duplicates and are all rejected. Comparison is case-insensitive; **storage is not normalized** — the system MUST store a skill name exactly as the administrator entered it, apart from the whitespace trimming required by FR-003, and MUST NOT apply any capitalization rule of its own. The vocabulary contains names whose casing is meaningful (`JavaScript`, `PHP`, `C#`, `C/C++`, `HTML/CSS`, `UI/UX Design`) and rewriting them would corrupt the vocabulary this feature exists to curate. Where a case-insensitive conflict is detected, the existing skill keeps its stored name and the incoming entry is rejected; an existing name MUST NOT be silently rewritten to the casing just submitted. **This rule governs one entry against another, never an entry against itself**: a skill MUST NOT conflict with its own stored name, so editing a skill without changing its name MUST be accepted, and changing the casing of an existing skill in place (`Python` → `python` on that same record) MUST be accepted as the ordinary edit FR-005 permits. What FR-002 forbids is a *new or different* entry displacing an existing one's casing.
- **FR-003**: The system MUST trim surrounding whitespace from a skill name before storing it, and MUST reject a name that is empty once trimmed, reporting the error against the name field.
- **FR-004**: Administrators MUST be able to browse skills, search them by name, and filter them by service category.
- **FR-005**: Administrators MUST be able to edit an existing skill's name and category. This includes correcting only its capitalization (`Python` → `python` on that same record), which FR-002's case-insensitive rule MUST NOT block — see the self-conflict clause there.
- **FR-027**: Administrators MUST be able to permanently remove a skill that no freelancer profile lists as a skill and no client profile lists as an area of interest.
- **FR-028**: The system MUST refuse removal of a skill that at least one profile still refers to, reporting that the skill is still in use and how many profiles refer to it, and MUST NOT detach it from any profile as a side effect. The message MUST NOT enumerate the affected profiles individually; the administrator locates them with the skill filter on the account lists (FR-037, FR-038). This applies to every removal route offered by the skill screens, including bulk actions.

**Freelancer profiles**

- **FR-006**: Administrators MUST be able to create and edit a freelancer's profile from within that freelancer's account screen, recording biography, hourly rate, years of experience, portfolio link, and skills.
- **FR-007**: The system MUST enforce at most one profile per freelancer account, reporting a violation as a field-level error rather than a server failure.
- **FR-008**: The system MUST reject an hourly rate that is zero or negative, reporting the error against the hourly rate field, and MUST accept a profile with no hourly rate recorded.
- **FR-009**: Administrators MUST be able to attach any number of existing skills to a freelancer profile, and to detach them.
- **FR-010**: Administrators MUST NOT be able to create a new skill from within the profile section — the vocabulary is curated only through the skill screens (FR-001).

**Client profiles**

- **FR-013**: Administrators MUST be able to create and edit a client's profile from within that client's account screen, recording biography, company name, maximum budget, website, and areas of interest.
- **FR-014**: The system MUST enforce at most one profile per client account, reporting a violation as a field-level error rather than a server failure.
- **FR-015**: The system MUST reject a maximum budget that is zero or negative, reporting the error against the budget field, and MUST accept a profile with no budget recorded.
- **FR-016**: The system MUST reject a company name that is empty once surrounding whitespace is removed, reporting the error against the company name field, and MUST accept a profile with no company name recorded.
  > **Partially delivered, deferred 2026-08-04.** The second half holds: a profile with no company name is accepted. The first half does **not** surface in the admin — the form's `strip=True` reduces a whitespace-only name to `""` before `ClientProfile.clean()` runs, so `company_name_empty` never fires there. The rule still holds on paths that bypass the form. The stored outcome is correct (`"   "` becomes `""`, i.e. "no company name recorded"); only the message is missing. Deferred to the serializer phase rather than duplicated in the admin form — reasoning, verification and reversal criteria in `docs/tech_debt/002-whitespace-only-company-name-accepted-in-admin.md`. This is also the one exception to FR-020 below.
- **FR-017**: Administrators MUST be able to attach any number of existing skills as a client's areas of interest, and to detach them.

**Profile lifecycle and account status**

- **FR-029**: The system MUST refuse to create a profile for an account that is deactivated in the state being saved, reporting the refusal as a field-level message. The rule is evaluated against the account status being saved, not the status the account held when the screen was opened.
- **FR-030**: An existing profile MUST remain editable while its account is deactivated. Correcting a person's details MUST NOT require reactivating their account.
- **FR-031**: Deactivating an account MUST NOT alter, clear, or remove its profile. A profile has no status of its own; it goes dormant with the account and the record stays intact.
- **FR-032**: On a deactivated account with no profile, the profile section MUST remain open for input; the refusal MUST happen at save, as a message next to the offending field. The section MUST NOT be hidden or disabled instead.
- **FR-036**: The profile section MUST be available while adding a new freelancer or client account, so that an account and its profile can be created in a single save. Filling it MUST be optional, and the system MUST NOT create a profile automatically for a new account.

**Account lists**

- **FR-033**: The freelancer and client account lists MUST show, for each account, whether that account has a profile, presented the same way the existing status indicators on those lists are presented.
- **FR-034**: Administrators MUST be able to filter the freelancer and client account lists by whether an account has a profile.
- **FR-037**: Administrators MUST be able to filter the freelancer account list by a skill, listing every freelancer whose profile refers to that skill.
- **FR-038**: Administrators MUST be able to filter the client account list by a skill, listing every client whose profile lists that skill as an area of interest.
- **FR-039**: An account MUST appear at most once in a filtered list, however many skills its profile refers to.
- **FR-035**: The staff account list MUST NOT gain a profile indicator, a profile filter, or a skill filter. Staff accounts have no profile.

**Shared behavior and consistency with account administration**

- **FR-020**: Every rule already enforced on the underlying profile and skill data MUST surface in the administration screens as a message attached to the offending field, never as an unhandled failure.
  > **One recorded exception, 2026-08-04:** `company_name_empty` does not surface in the admin. See the note on FR-016 and `docs/tech_debt/002-whitespace-only-company-name-accepted-in-admin.md`. Every other rule in the error contract does surface.
- **FR-021**: The skill screens MUST present the same interaction conventions already established for account administration: grouped field sections, collapsed timestamp sections, a fixed number of rows per page, most-recent-first ordering, and read-only creation and update timestamps. The profile section MUST present the same conventions as the account screen that contains it, including grouped fields and read-only creation and update timestamps.
- **FR-022**: Behavior shared between the profile section, the skill screens and the account screens MUST be defined once and reused, not duplicated per screen.
- **FR-023**: The system MUST NOT permit a profile to be permanently destroyed through these screens, by any route. A profile is retired by deactivating the account it belongs to, never by removal. Any removal control that would otherwise appear on the profile section MUST be suppressed.
- **FR-024**: Deactivation instead of deletion, password handling on save, and staff-only privilege controls MUST all remain exactly as they are today on the account screens. Three additions to account administration are intended and are not regressions: the profile section on the freelancer and client account screens; the profile indicator and its filter on the freelancer and client account lists; and the skill filter on those same lists.
- **FR-025**: Access to the profile section and the skill screens MUST be restricted to active staff accounts, on the same terms as the existing account screens.
- **FR-026**: A freelancer or client account's profile MUST be presented and editable within that account's own screen, with no separate profile screen required to reach it.

**Requirements removed by the one-screen decision (IDs retired, not reused)**

- **FR-011, FR-012, FR-018, FR-019** described standalone profile lists with their own search, filters and columns. There are no profile lists in this feature. Administrators reach a profile by finding the account it belongs to, using the account search that already exists.
- **Known loss**: searching a client by **company name** is not possible under this decision, because company name lives on the profile and the account search covers name and email only. This capability returns when the deferred profile screens are built.

### Key Entities

- **Skill**: A named capability in a curated platform-wide vocabulary, belonging to exactly one of four service categories (technology, design, writing, marketing). Names are unique, compared **without regard to letter case**, and stored exactly as entered — the platform never rewrites the casing an administrator chose. Created, corrected and removed only by administrators; freelancers and clients select from the list and never extend it. A skill has no active/inactive status — it exists or it does not — and it can be permanently removed only while no profile refers to it.
- **Freelancer Profile**: The professional record attached to exactly one freelancer account, and administered as part of that account. Holds a biography, an optional hourly rate, years of experience, an optional portfolio link, and any number of skills. Records when it was created and last updated. Has no status of its own: it goes dormant with its account and is never removed.
- **Client Profile**: The record attached to exactly one client account, and administered as part of that account. Holds a biography, an optional company name, an optional maximum project budget, an optional website, and any number of areas of interest drawn from the same skill vocabulary. Records when it was created and last updated. Has no status of its own, on the same terms as a freelancer profile.
- **Account (freelancer / client)**: The existing user record a profile belongs to, and the only route by which a profile is reached. Supplies the identity — name and email — that the existing account search matches on, and the activation status that governs whether a profile may be created. Its list shows whether it has a profile and can be narrowed to the accounts whose profile refers to a given skill. Its own fields are not otherwise created or modified by this feature.
- **Administrator**: An active staff account with access to the administration area. The only actor in this feature.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An administrator can add a new skill to the platform vocabulary in under 30 seconds, without leaving the administration area.
- **SC-002**: An administrator can complete a freelancer's profile — including attaching at least three skills — in under 3 minutes, starting from the account screen.
- **SC-003**: An administrator can reach any existing profile in 3 interactions or fewer, using the existing account search by the account holder's name or email. Profiles are not searched directly; the account is the entry point.
- **SC-004**: 100% of the rejections listed in the acceptance scenarios are shown as a message next to the field that caused them; zero produce an unhandled failure page.
- **SC-005**: An administrator never leaves the account screen to view or edit that account's profile — zero navigation steps between an account and its profile.
- **SC-006**: No profile can be permanently destroyed through these screens, by any route. The only record an administrator can permanently remove is a skill that no profile refers to.
- **SC-007**: A newly onboarded administrator, given only the screens themselves, completes the fill-in-a-profile task without external instruction on their first attempt.
- **SC-008**: The skill screens present the same conventions as the existing account screens, and the profile section presents the same conventions as the account screen containing it — verified by a reviewer comparing side by side, with zero discrepancies in field grouping, ordering, pagination and read-only timestamps.
- **SC-009**: Every existing account-administration behavior check still passes, with the sole exception of checks that the two intended additions in FR-024 necessarily change.
- **SC-010**: 100% of attempts to remove an in-use skill are refused, and zero profiles lose a skill without the administrator being told.
- **SC-011**: An administrator can list every account that has no profile in a single filter action.
- **SC-012**: An administrator can list every account whose profile refers to a given skill in a single filter action, with each account appearing exactly once.

## Assumptions

- **Actor**: The only user of this feature is an administrator working in the platform's administration area. Freelancer and client self-service profile editing is explicitly out of scope.
- **Accounts are not otherwise changed**: This feature attaches profiles to accounts, whether the account already exists or is being created in the same save. It does not change how accounts themselves are created, edited or deactivated, beyond reading the account status being saved in order to apply FR-029.
- **Profiles are optional**: An account without a profile is a valid state. Nothing in this feature forces a profile to exist, and no profile is brought into existence by saving an account whose profile section was left untouched.
- **Partial profiles are valid**: A profile with no hourly rate, no budget, no company name, no skills, or no interests is accepted. The underlying data treats these as optional and administrators need to record what they have.
- **Three new business rules arrive with this feature**, and everything else surfaces rules that already govern the data: (1) a profile cannot be created for an account that is deactivated in the state being saved (FR-029), (2) a skill that any profile still refers to cannot be removed (FR-028), and (3) skill-name uniqueness is case-insensitive (FR-002) — a tightening of the existing uniqueness rule, which the data enforces case-sensitively today, decided 2026-08-04. Beyond these three, no new rule is introduced — this feature does not, for example, require a freelancer to declare a minimum number of skills.
- **Accepted limitation — retiring a skill that is in use**: detaching a skill from the profiles that refer to it is done one profile at a time. Renaming a skill (FR-005) is the supported way to correct a wrong or misspelled vocabulary entry, and touches no profile at all. Merging two duplicate skills into one is not supported here and waits for the deferred profile screens. This is accepted rather than solved: removing an in-use skill is rare, and renaming covers ordinary vocabulary housekeeping.
- **Why the skill filter exists**: the filter introduced by User Story 6 is justified by everyday administrative use — answering "who offers this skill?" — and not by the skill-removal workflow. That workflow benefits from it, but would not on its own justify building it.
- **Skill creation stays centralized**: Skills are added only through the skill screens. Allowing skill creation from inside the profile section would let the vocabulary grow uncontrolled, which the platform explicitly rejects.
- **The vocabulary starts populated**: The platform already ships a seeded baseline of 30 skills spread across the four service categories. User Story 1 is about growing and correcting that baseline, not about starting from an empty list. FR-002's case-insensitive rule assumes the vocabulary already in place holds no two names differing only in letter case; existing data must be confirmed free of such collisions before the rule can be enforced.
- **Consistency is measured against account administration**: "The same standard" means the conventions visible in the existing account screens — grouped sections, collapsed timestamps, search and filter controls, fixed page size, most-recent-first ordering, and shared behavior defined once and reused.
- **Presentation of status**: Where the combined screen or the account lists show activation, availability, or the presence of a profile, they reuse the visual treatment already established on the account screens rather than inventing a new one.
- **Scale**: The skill vocabulary is expected to stay in the hundreds and the profile count in the thousands. No bulk import and no search infrastructure beyond what the account screens already use is assumed necessary.

### Out of scope

- **Standalone profile screens** — dedicated screens for browsing, searching and filtering freelancer profiles and client profiles as lists in their own right are **deliberately deferred to a later feature**. This is a scope decision, not an oversight.
- **Self-service profile rules** — a freelancer or client whose own account is deactivated must not be able to create or edit their own profile. This rule is held and recorded here so it is not lost, but self-service is not part of this feature and the rule is **not** built into these administration screens.
- Profile self-service by freelancers and clients generally.
- Profile approval or moderation workflows.
- Reporting, analytics, and exporting profile data.
- A "freelancer suggests a skill, administrator approves" workflow.
- Any public-facing profile page.

## Dependencies

- The existing account administration behavior for freelancer, client, and staff accounts, which this feature extends in the two intended ways recorded in FR-024 and must not otherwise change.
- The existing account search, which becomes the only route to a profile under the one-screen decision.
- The existing account activation status, which FR-029 through FR-032 depend on.
- The existing profile and skill data definitions, including their validation rules and the relationship between a profile and its account.
- The relationship between a profile and the skills it refers to, which FR-028 depends on to determine whether a skill is in use.
- A populated skill vocabulary. A seeded baseline ships with the platform; environments that skip data seeding start empty and must have skills created before any profile can declare skills or interests.
