# Specification Quality Checklist: Profiles Admin Panel

**Purpose**: Validate specification completeness and quality before proceeding to planning
**Created**: 2026-07-27
**Feature**: [spec.md](../spec.md)

## Content Quality

- [x] No implementation details (languages, frameworks, APIs)
- [x] Focused on user value and business needs
- [x] Written for non-technical stakeholders
- [x] All mandatory sections completed

## Requirement Completeness

- [x] No [NEEDS CLARIFICATION] markers remain
- [x] Requirements are testable and unambiguous
- [x] Success criteria are measurable
- [x] Success criteria are technology-agnostic (no implementation details)
- [x] All acceptance scenarios are defined
- [x] Edge cases are identified
- [x] Scope is clearly bounded
- [x] Dependencies and assumptions identified

## Feature Readiness

- [x] All functional requirements have clear acceptance criteria
- [x] User scenarios cover primary flows
- [x] Feature meets measurable outcomes defined in Success Criteria
- [x] No implementation details leak into specification

## Decision log

### Q1 — Where profiles are administered *(answered, iteration 2)*

Profiles are administered **on the account screen** of the account they belong
to; there are no standalone profile screens. Skills keep a dedicated screen.
Standalone profile screens are deliberately deferred to a later feature.

Consequences recorded in the spec: FR-011, FR-012, FR-018 and FR-019 removed
(IDs retired, not reused); loss of client search by company name recorded
explicitly; User Story 4 rewritten as the cross-cutting one-screen story.

### Q2 — Retiring a profile or a skill *(answered, iteration 3)*

Two different answers for two different things:

- **Profiles are never destroyed.** A profile has no status of its own and
  follows its account; it is retired by deactivating that account. → FR-023,
  FR-031, SC-006.
- **A skill may be permanently removed, but only while unused.** If any
  freelancer profile or client profile refers to it, removal is refused with a
  message, and nothing is detached silently. → FR-027, FR-028, SC-010.

This is a deliberate, narrow exception to the "nothing is permanently
destroyed" promise. FR-023 and SC-006 were **rewritten**, not merely unmarked,
so the promise and its one exception are both stated accurately.

### Q3 — Deactivated accounts and their profiles *(answered, iteration 3)*

Creating is blocked; editing is not.

- No profile may be created for an account deactivated **in the state being
  saved** — evaluated against what is being saved, not what was loaded.
  → FR-029.
- An existing profile stays editable while its account is deactivated, which
  also serves the European right to have personal details corrected. → FR-030.
- Deactivating an account leaves its profile untouched. → FR-031.
- The profile section stays open for input on a deactivated account; the
  refusal happens at save, consistent with every other rejection in this
  feature. → FR-032.

### Q4 — Profile indicator on account lists *(answered, iteration 3)*

Added now. Freelancer and client account lists show whether each account has a
profile and can be filtered by it; staff lists get nothing. → FR-033, FR-034,
FR-035, User Story 5, SC-011.

Recorded in the spec as an **intended** change to account administration
alongside the profile section, so it does not read as contradicting the
no-regression promise. → FR-024, SC-009.

### Q5 — Profile on the account add form *(answered, iteration 4)*

Permitted, but never automatic. The profile section is available while adding a
brand-new freelancer or client account, so an account and its profile can be
created in one save. Filling it is optional, and no profile is ever created
automatically alongside an account. → FR-036, two new scenarios each on User
Stories 2 and 3, two resolved edge cases, and a reworded "Accounts are not
otherwise changed" assumption.

### Q6 — Finding which profiles use a skill *(answered, iteration 5)*

The account lists gain a **filter by skill**, and the refusal message reports
only **how many** profiles are affected — it does not enumerate them.
→ FR-037, FR-038, FR-039, User Story 6, SC-012, amended FR-028 and US1
scenario 7.

The justification was corrected during the discussion. The filter was first
proposed as a fix for the skill-removal workflow, where it is weak: it makes a
rare operation possible but not fast. It is justified instead as an everyday
capability of the panel — answering "who offers this skill?" — with the removal
workflow benefiting as a consequence. Recorded in Assumptions so the reasoning
is not lost.

Two accepted limitations recorded rather than solved: detaching a skill from
many profiles is done one profile at a time, and merging duplicate skills is
not supported and waits for the deferred profile screens. Renaming (FR-005)
remains the supported route for ordinary vocabulary corrections and touches no
profile.

## Notes

**All checklist items pass. The specification is ready for `/speckit-plan`.**

Six questions were raised and all six were answered by the human; none was
resolved by assumption. Final shape: 6 user stories, 35 functional
requirements (4 IDs retired, not reused), 12 success criteria.

Carried forward for the planning phase — flagged here, not blocking:

- **Story independence**: User Stories 2 and 3 cannot ship without the profile
  section that User Story 4 describes, so US4 is partly a prerequisite of
  P2/P3 rather than a follow-on. US4 was reframed as cross-cutting
  verification to keep the ordering workable. If `/speckit-plan` produces an
  unexpected task order, this is the cause.
- **Performance to watch**: the profile indicator on the account lists
  (FR-033) reads a related record for every row and risks one query per row
  unless the profile is fetched together with the account. This is the most
  likely performance regression in the feature.
- **Known wrinkle**: filtering an account list by a skill traverses a
  many-to-many relation, which can list the same account more than once.
  FR-039 states the required outcome; the plan must decide how it is achieved.
- **Not measured**: the cost estimates discussed while deciding Q6 were
  structural reasoning, not measurements. Nothing was benchmarked.
