# Verification of the Phase 10 audit — executed, not reasoned

**Date**: 2026-08-06
**Verifies**: `docs/audits/2026-08-06-audit-phase-10-fr-002.md`
**Status**: read-only verification. No project file was modified. This file is
the only artifact created.

**Why this exists**: the auditor disclosed that three of its seven Issues
(2, 3 and 6) rested on a *mutation argument it did not execute* — "delete this
production line and the suite stays green" was reasoned from reading the tests,
not measured. That is exactly the class of claim an audit can get wrong. This
document closes that gap by running the mutations.

---

## Verdict

**All seven Issues are real.** The three unexecuted claims were confirmed by
measurement. The audit also contains one stale statement, one overstated
rationale, one caveat that resolves in the opposite direction from the warning,
and one omission — all recorded in §4 and §5.

The user's instinct was correct: **the production code is sound; the tests are
the weak part.** `skill.py` behaves correctly on every path exercised except the
Unicode edge of Issue 1, and even there data integrity never fails — only the
placement of the error message degrades.

---

## 1. Method

Mutating the repository to test it would have been unacceptable. Instead:

- `/app` was copied to `/tmp/mutant` **inside the container**. No file in
  `/Users/thaismoreira/skillbridge` was read-write at any point.
- The copy ran against its **own test database** (`DB_NAME=skillbridge_mutant`),
  so the project's `--reuse-db` test database was never rebuilt from mutated
  models.
- After each mutation the **full 268-test suite** was run, not just the two
  audited files.
- Both `/tmp/mutant` and `test_skillbridge_mutant` were deleted afterwards.

**Baselines**

| Run | Result |
|---|---|
| Two audited files, project tree | 34 passed |
| Full suite, project tree | 268 passed |
| Full suite, unmutated sandbox copy | 268 passed |
| Full suite, project tree, after all verification work | 268 passed |

### 1.1 The control — proving the harness can detect breakage

A green result after a mutation is only meaningful if the setup is capable of
going red. The audit states the **freelancer** half of `.distinct()` *is*
covered (Issue 3, and the O-10 note). That was mutated as a control:

```
CONTROL: .distinct() removed from the FreelancerProfile aggregate
-> 1 failed, 267 passed
   test_get_deleted_objects_counts_a_profile_referring_to_several_selected_skills_once
   AssertionError: assert '1' in 'Still in use by 3 profiles. ...'
```

The harness detects breakage. Every green result below is therefore evidence,
not an artifact of a misconfigured sandbox.

---

## 2. Issue-by-issue verification

| Issue | Audit claim | Status | Basis |
|---|---|---|---|
| 1 | Python/PostgreSQL lowercasing diverge | **CONFIRMED** | executed |
| 2 | Edit path untested; restricting to creation stays green | **CONFIRMED** | executed mutation |
| 3 | `ClientProfile` `.distinct()` uncovered | **CONFIRMED** | executed mutation + control |
| 4 | `__repr__` docstrings claim what neither asserts | **CONFIRMED** (rationale narrowed) | executed |
| 5 | `conventions.md` marker rule over-broad | **CONFIRMED** | textual |
| 6 | `unique=True` unguarded; removing it stays green | **CONFIRMED** | executed mutation |
| 7 | `max_length=100` untested | **CONFIRMED** | executed |

### Issue 1 — the two layers genuinely disagree

```
PG   lower('İ') = 'i'    (length 1)
Py   'İ'.lower() = 'i̇'   (length 2)   -> equal = False
```

End to end, with an existing skill named `I` and the candidate `İ`:

```
full_clean() -> error_dict keys = ['__all__']
                key='__all__'  codes=[None]
```

The error is **not** `skill_name_duplicate`, and **not** on the `name` key. This
is precisely the outcome FR-002's "reporting the conflict against the name
field" exists to prevent, and precisely the `NON_FIELD_ERRORS` routing the ADR
cites as the reason a constraint alone was rejected as a mechanism.

Data integrity is never at risk — the constraint holds. What is lost is the
field-level message.

### Issue 2 — confirmed as a coverage gap, not a defect

Mutation applied — the duplicate check made to fire only for unsaved instances:

```python
if duplicate_exists and self.pk is None:   # was: if duplicate_exists:
```

```
-> 268 passed
```

The entire suite is blind to the edit path. Separately, production behaviour on
that path was confirmed **correct**: renaming a saved `ZzzBeta` onto the
existing `ZzzAlpha` yields `{'name': ['skill_name_duplicate']}`. So this is a
missing test, not a bug — the audit's characterisation is accurate.

### Issue 3 — confirmed, with the asymmetry measured in both directions

```
.distinct() removed from ClientProfile   -> 268 passed   (uncovered)
.distinct() removed from FreelancerProfile -> 1 failed   (covered)
```

Reading `test_skill_admin.py:145-163` confirms the cause: the F-4 test attaches
all three selected skills to `freelancer_profile.skills` only, so the
`ClientProfile` aggregate returns `0` with or without `.distinct()`.

### Issue 4 — confirmed, but the audit's reasoning is narrower than stated

```
unsaved-with-enum   repr = Skill (id=None, name='Python', category=Skill.Category.TECHNOLOGY)
unsaved-with-string repr = Skill (id=None, name='Python', category='TECHNOLOGY')

existing assertion passes with an enum   category: True
existing assertion passes with a string  category: True
```

The docstrings' claimed distinction — enum on the unsaved instance, plain string
after reload — is asserted by neither test. The finding stands.

The audit's phrasing ("if `__repr__` stopped distinguishing the two, both tests
still pass") is too strong: the tests **do** pin the `__repr__` template text, so
a change to the surrounding format would fail them. What is unasserted is
specifically the *category rendering*, which is the only thing the docstrings
talk about. Right finding, narrower mechanism.

### Issue 5 — confirmed textually

`.claude/rules/conventions.md` states that a test calling `Skill.clean()` or
`Skill.full_clean()` **needs** `@pytest.mark.django_db`. T077's repair 2 states
the opposite for two named tests: *"The other two `clean()` tests stay
marker-free and must remain so."*

Both marker-free tests
(`test_skill_clean_empty_name_raises_validation_error`,
`test_skill_clean_none_name_passes_validation`) pass in the suite, which under
pytest-django's default DB blocker is itself proof they never reach the query.
The correct condition is "reaches the duplicate lookup", not "calls `clean()`".

### Issue 6 — confirmed, and the result is not vacuous

`unique=True` removed from `Skill.name`, suite run with `--create-db` so
`--no-migrations` rebuilt the schema from the mutated model:

```
-> 268 passed
```

Schema verified afterwards, to rule out a reused database masking the mutation:

```sql
select indexname from pg_indexes where tablename='skills';
 skills_pkey
 skill_unique_name_case_insensitive
```

`skills_name_key` is genuinely gone and the suite still passed. Nothing in the
project guards a declaration the phase marks as *do not reopen*.

### Issue 7 — confirmed

```
100-char name  -> passes full_clean()
101-char name  -> keys=['name']  codes=['max_length']
```

A real, reachable boundary with zero coverage. `max_length` could be changed to
`10` or `1000` and no test would notice. The project already tests exactly this
shape at `profiles/tests/models/test_base.py:33-51` for `Profile.bio`.

---

## 3. OD-1 — the open decision, re-measured

The audit measured option B at 4 queries but warned the figure was taken
"against skills with no referring profiles — the collector's share may differ
once related rows exist."

Measured on the public path, `get_deleted_objects()`, both ways:

| selection size | no referring profiles | with referring profiles |
|---|---|---|
| 1 | 4 | 4 |
| 3 | 4 | 4 |
| 5 | 4 | 4 |
| 10 | 4 | 4 |

**The caveat does not materialise.** The count is flat at 4 in every case. This
resolves in option B's favour — it is a safer choice than the audit represented,
though the residual risk it names (two of the four queries belong to Django's
`NestedObjects` collector and could change on a Django upgrade) is unaffected by
this measurement and remains a real consideration.

---

## 4. Corrections to the audit

**4.1 — O-1 is stale and should not be chased.**
The audit reports `1 failed, 33 passed` on the two audited files. Today the same
command gives **34 passed**. The auditor's own `--create-db` run rebuilt the
test database, which fixed the stale schema it diagnosed. The diagnosis was
correct; the recorded state is obsolete. A session acting on O-1 would hunt a
failure that no longer exists.

**4.2 — Issue 4's rationale is overstated.** See §2, Issue 4.

**4.3 — OD-1's warning resolves the other way.** See §3.

---

## 5. Finding the audit missed

**Every Phase 10 checkbox in `tasks.md` is still unchecked.**

`specs/001-profiles-admin-panel/tasks.md:620-646` carries `- [ ]` on T073, T074,
T075, T076, T077, T078, T079 and T080 — despite T073–T077 and T079 being
implemented and committed (`ff732d9`, `7a9ecd9`), which the audit's own Handoff
section states.

This matters because T065, T066 and T067 are all amended to run *"after Phase
10"*. As the artifact reads today, a future session cannot tell Phase 10 is
finished. The two live risks are re-implementing T073–T077 against code that
already exists, or leaving the three gates blocked indefinitely.

T078 and T080 are correctly unchecked — they are genuinely not done.

---

## 6. Suggested priority

Nothing below was started. Listed for decision.

1. **Cheapest and now measured** — the four missing tests: Issue 2 (edit path),
   Issue 3 (client-profile mirror), Issue 6 (field-metadata guard for
   `unique=True`), Issue 7 (the 100/101 boundary pair). Each has an existing
   sibling in the codebase to follow.
2. **Documentation correctness** — Issue 5 in `conventions.md`, and the Phase 10
   checkbox state in §5.
3. **Needs a human decision** — Issue 1. Low likelihood for an English-language
   vocabulary; the fix means moving the lowercasing into the database so both
   layers use one function. Its *Consequences* belong in the existing ADR.
4. **A choice between valid options** — Issue 4: assert the rendered form
   literally, or collapse the pair and drop the claim. `CLAUDE.md` Rule 5
   applies; the sibling `test_freelancer_profile_repr_representation` inherits
   whichever is chosen.
5. **Open decision** — OD-1, now with §3's numbers available.

---

## 7. Scope of this verification

**Verified**: the seven Issues and OD-1.

**Not verified**: Observations O-2 through O-10 were not systematically
re-checked, except where they intersected an Issue — O-1 (corrected in §4.1) and
O-10's reverse-accessor claim (consistent with the Issue 3 control result). They
are recorded in the audit as no-action notes and were left as such.

**Not done**: no remediation was written, no task was executed, no test or
production line was changed in the project tree. Repository state at the end of
this verification is identical to its state at the start — one modified file
(`test_skill.py`, pre-existing) and one untracked file (the audit).
