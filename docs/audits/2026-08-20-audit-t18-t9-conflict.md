# Audit — do T18 and T9 conflict?

**Date**: 2026-08-20
**Persona**: Auditor (read-only). No project file was modified. This report is the only file
written.
**Primary target**: `docs/plan/plan_toolchain-ci-security_2026-08-15.md`, task entries **T18**
and **T9**, and the decisions they implement (**D18** with both amendments, **D21**, **D8**).
**Context, not the target**: `.github/dependabot.yml`, `.github/workflows/ci.yml`,
`django_version/uv.lock`, T15, T19, the *Order of execution*.

**The question asked**: implementation is at T15, T1, T2, T3, T18, T9 done, decision log closed
at D21. Do T18 and T9 contradict each other?

**Revision note.** This report was re-audited against itself on the same day, at the user's
request, before being handed to the Planner. Three findings changed — one strengthened, one
narrowed, one partly withdrawn. What changed and why is recorded under *Self-audit*, so the Planner
acts on the corrected findings rather than the first pass.

---

## Answer

**No. T18 and T9 do not conflict.** They are complementary halves of one configuration, correctly
ordered, and they touch disjoint surfaces:

| | T18 | T9 |
| --- | --- | --- |
| Surface | Repository settings (server-side) | Two files in `.github/` |
| Mechanism governed | Dependabot **security** updates | Dependabot **version** updates |
| Takes effect | The moment the toggle flips | Only once the file reaches the default branch |
| Files touched | none | `ci.yml`, `dependabot.yml` (new) |

D18 amendment 1 established the fact that makes them non-overlapping: `dependabot.yml` cannot
filter security updates at all, so the file T9 writes could never re-enable, weaken, or contradict
the toggle T18 turned off. Each task states the other's boundary explicitly — T18 forbids creating
`dependabot.yml` from the settings page *because T9 owns that file*; T9 declares `Requires T18`
*because the toggle produces the pull requests the file cannot filter*.

**Verified against the live repository, 2026-08-20:**

- `dependabot_security_updates.status` → `disabled` (T18 acceptance ✓)
- `repos/…/dependabot/alerts` returns a list, not a 403 (T18 acceptance ✓ — alerts survived)
- `gh pr list` → `#6`, `#7`, `#8`, `#9` all `CLOSED`, no open pull request by `app/dependabot`
  (T18 acceptance ✓)
- `.github/dependabot.yml` carries exactly two entries, `github-actions` at `/` and `uv` at
  `/django_version`, both `monthly`, no `oop_version` path (T9 acceptance ✓)
- The two `chore(ci)` commits produced green runs; the three `docs(plan)` commits after them
  produced no run at all (T9 acceptance ✓, both halves)
- `django_version/uv.lock` resolves `sqlparse` to **0.6.0**, the patched version — which is what
  T18's decision to close `#7` and to leave four high-severity alerts standing rests on

The three defects below sit in the **seam** between T18/T9 and what follows them — the merge and
T19 — not between T18 and T9 themselves.

---

## Issues — action required

### Issue 1 — The closing line of *Order of execution* claims more than its own justification supports

**What.** The section's final line calls T18 independent of the sequence, and offers a reason that
establishes something weaker.

**Where.** `docs/plan/plan_toolchain-ci-security_2026-08-15.md`, *Order of execution*:

- Constraint 4 (line 4418): *"**T18 before T9, and both before any merge to `main`.**"*
- Table row 6 (line 4436): T9 — *Waits on: T2, T18*.
- Closing line (4452–4453): *"**Independent of the whole sequence:** T18, which needs no file to
  exist and no task to precede it."*

The reason given — *"needs no file to exist and no task to precede it"* — is accurate: T18 has no
predecessor. The claim it supports is broader. Independence *from the sequence* means ordering
freedom in both directions, and T18 has none in the forward direction, because constraint 4 and
table row 6 both make it a predecessor of T9.

**Rule violated.** The plan is the durable record of *why* the order was what it was — the role
`conventions.md` → *Recording decisions* assigns to an ADR. A constraint stated in one paragraph
and loosened thirty lines later stops functioning as a record.

**Why it matters.** Lowest severity of the three, and not zero. Both tasks are done, so nothing can
go wrong today. The cost is that this line is the section's last word, which is the part a reader
carries away when re-planning or writing the retrospective — and taken at face value it says T18
could have run after T9. That is the ordering D18 amendment 1 exists to prevent, and which would
have left security updates opening `oop_version/` pull requests for the whole span of the remaining
work.

**Direction.** Narrow the claim to the reason already given in the same sentence; nothing needs
re-deciding. The parallel construction one line above — *"Independent of each other, in any order:
T12, T14, T16"* — is the sense in which T18 is **not** independent, and constraint 4 already states
the accurate version.

---

### Issue 2 — T19 step 1 cannot reach its expected value, and the happy path triggers its own stop condition

**What.** T19's first step reads the manifest path from the Dependabot alert stream and requires
`django_version/uv.lock`. After the merge that value cannot be there — and the two outcomes the
step branches on do not include the one that will actually occur.

**Where.** T19, *Step 1* (lines 4300–4326); T18's closing *Do not* paragraph (lines 4284–4288);
the *Order of execution* table, row 7, the merge (line 4437).

**The mechanism.** `manifest_path` is a property of an **alert**, and an alert exists only where an
advisory has matched a resolved dependency. Confirmed this session, `django_version/uv.lock`
resolves `sqlparse` to the patched 0.6.0, so after the merge no advisory is outstanding against
anything the `uv` manifest resolves. `django_version/uv.lock` therefore appears in no alert, and
step 1's query cannot return it.

**What the query will return instead.** Measured today, the alert stream holds seven alerts: three
`dismissed` against `oop_version/requirements.txt`, and four `open` against
`django_version/requirements.txt`. The API lists dismissed and fixed alerts alongside open ones —
verified, the three dismissed ones came back in this session's own query. So after the merge:

- If T18's unmeasured premise **holds** and the four `sqlparse` alerts self-close, they change
  state but stay in the stream. `[.[] | .dependency.manifest_path] | unique` returns
  `["django_version/requirements.txt", "oop_version/requirements.txt"]`.
- If it **does not hold**, the same two values come back, with the `sqlparse` four still `open`.

Either way the answer is *"anything else"*, which step 1 handles by instructing the Developer to
**create no rule and return to the Planner**. The list is not empty in either case, so the *"If
that returns an empty list"* fallback — take the value from the rules-screen autocomplete — is
never reached.

**Rule violated.** The plan's own *Evidence discipline*, and the standard the rest of the document
holds itself to: T9, T13 and T19 itself each separate a verifiable half from an unverifiable one
and name what happens to each. Step 1 instead branches on two cases and omits the one its own
preceding tasks make certain.

**Why it matters.** This is not a silent failure — the guard is real and it fires. The consequence
is worse in a different way: **T19 as written blocks on its expected happy path.** The merge
succeeds, T18's premise holds, every prior task behaves exactly as planned — and T19 still stops at
step 1 and returns to the Planner, because the value it was told to expect describes a state (an
open advisory against the `uv` manifest) that nobody wants to exist. T19 is scheduled immediately
after the merge, and the earliest moment its precondition could be met is the next advisory against
a `django_version` dependency, which may be months away or never.

A second consequence is worth naming separately. T18's premise — that the four `sqlparse` alerts
close on their own at the merge — is labelled *"stated as reasoning, not measured"*, and no task
checks it. It is no longer load-bearing for T19, now that step 1 blocks either way, but it is
load-bearing for T18's own decision not to dismiss three high-severity findings by hand. If it
fails, the Security tab keeps them and the only remaining remedy is the manual dismissal T18 argued
against starting.

**Direction.** Two things return to the Planner, and neither is a judgement call the Developer can
take at the rules screen:

1. What `manifest` value the pull-request rule is written against, given that the alert stream
   cannot supply one for the `uv` manifest until an advisory fires. The rules-screen autocomplete
   is the other candidate source — the Developer note of 2026-08-19 observed it offering
   `django_version/requirements.txt`, but whether it is fed by the alert stream or by the
   dependency graph was never established, and that distinction now decides whether T19 can run at
   all. T19's *Returns to the Planner* list is where this belongs.
2. Whether the merge gets an acceptance criterion of its own. Step 7 of the sequence currently has
   none, and it is the only place the `sqlparse` premise can be checked. T9's *"Deferred
   verification — it can only be taken after the merge"* is the shape already in use.

---

### Issue 3 — Two verification debts were settled by T9's green run, and the plan still lists them as open

**What.** T9 landed green, which answers two questions the plan still records as outstanding — and
leaves a third open that a first reading of the same run appears to close.

**Where.** The *Verification debts* section; and T9's *"Verifications to perform before writing the
SHAs"* (lines 4049–4051).

**Settled by runs `32280676936` and `32281841857`, both `success` on `feature/django-refactor`:**

- **Whether `actions/checkout@v7` and `actions/setup-python@v7` are drop-in for this workflow.**
  Both are pinned at those majors in `ci.yml` and both steps ran clean. This closes T9's own
  pre-write verification, and D8 Item 2's amendment rested on it.
- **Which file `actions/setup-python`'s `python-version-file` input accepts.** The workflow passes
  `django_version/.python-version` and the step succeeded. D6's first amendment introduced that
  input and left the accepted filename to the action's own documentation; execution has answered
  it.

**Not settled, and it must not be recorded as settled.** The third debt — *"whether a job-level
`permissions` block replaces or is intersected with the workflow-level one"* — is **not** closed by
this run. D8 Item 1's amendment designed the falsification test as *"if it intersects,
`actions/checkout` fails on step 1 of the first push"*, and checkout did not fail. But this
repository is **public**, and the plan's own struck-through debt two bullets earlier records that
`actions/checkout` may function under `permissions: {}` for exactly that reason. The green run is
consistent with both hypotheses and discriminates between neither. The falsification test D8 Item 1
designed cannot run on a public repository at all.

**Rule violated.** The plan's Status line claims currency — *"Complete as a plan, as of
2026-08-19"* — and `conventions.md` → *Recording decisions* requires an artifact to state the
verified fact rather than restate the open question.

**Why it matters.** This plan uses strike-through consistently for debts that closed (the `uv`
package-ecosystem value, the security-updates-toggle question, the ruff default rule set). Two
unstruck entries make settled questions look open, and the next session pays to re-derive what a
green run already proved. The third carries the opposite risk: retiring a live question on evidence
that does not support it, and leaving the wrong reason on the record.

**Direction.** Two edits with opposite signs. Strike through the two that closed, naming the run
that settled each — the treatment the other closed debts already received. For the third, add the
sentence recording *why* it cannot be settled here, so a future session does not read the green run
as the answer.

---

## Open Decisions — user choice needed

### Decision A — what to do about the implicit ignore created by closing the four pull requests

**The fact.** The Dependabot comment received on `#6` is its standard reply to a pull request
closed unmerged:

> *"OK, I won't notify you again about this release, but will get in touch when a new version is
> available."*

Closing the pull request records an **implicit ignore for that dependency at that specific
version**. It is not permanent and not dependency-wide: the second half of the sentence is the
operative one — a *newer* version re-notifies. The offer of `@dependabot ignore this major
version` / `ignore this minor version` is Dependabot proposing to *widen* that ignore; neither was
issued, so only the narrow version-level ignore exists.

**Why three of the four are inert.** `#6` (Pygments), `#8` (pytest) and `#9` (python-dotenv) are
`pip` pull requests against `oop_version/requirements.txt`. `dependabot.yml` declares no entry for
that ecosystem or that directory, so version updates never run there; an ignore recorded against a
mechanism that is switched off costs nothing. This is T18 working as designed.

**Why the fourth is a question.** `#7` was `sqlparse` 0.5.5 → 0.6.0, `pip` ecosystem, directory
`/django_version` — the same directory T9's file declares under the **`uv`** ecosystem. What is
not documented on either GitHub page consulted is the key the implicit ignore is stored under:
whether it includes the ecosystem and the manifest, or only the dependency and version. `sqlparse`
is the highest-severity package in this repository's history, which is the only reason this is
worth a decision rather than a shrug.

**The exposure is fully bounded, and this is now measured rather than assumed.** `uv.lock` resolves
`sqlparse` to 0.6.0 — the exact version the ignore names. Even under the widest reading of the key,
the ignore can only suppress a re-offer of the version already installed. A future 0.6.1 is a new
version and re-notifies.

| Option | Pros | Cons |
| --- | --- | --- |
| **1. Treat as inert, record nothing** | Costs nothing; the ignored version is measured to be the installed one, so there is nothing left to suppress; the ecosystem keys almost certainly differ | Leaves an untested reading on the repository's highest-severity package; nothing surfaces it if the reading is wrong; a future reader has no trace of why a `sqlparse` pull request never arrived |
| **2. Record as a watch line in `docs/tech_debt/011`** | T19 already writes that file, so the marginal cost is one sentence; it lands where the other invisible-in-a-diff Dependabot state is recorded; visible at the moment someone asks | Records an unknown rather than a decision; the file's subject is the auto-triage rules, not this; may never fire |
| **3. Settle it by reading before deciding** | Turns a reading into a fact, which is what *Evidence discipline* asks for; the answer also bears on whether T19's rules interact with implicit ignores at all | Costs a documentation pass on a page that may not state the key; delays T19, which Issue 2 has already blocked; the exposure is measured to be nil |

Not recommended here — this is a genuine choice between three defensible positions, and D18 is
closed, so reopening it is the user's call.

---

## Observations / Learning Notes — no action needed

**O1 — `dependabot.yml` matches T9's instruction exactly.** Two entries, `github-actions` at `/`
and `uv` at `/django_version`, both `interval: monthly`, no third entry, `oop_version/` declared
nowhere. T9's acceptance criterion *"names no directory under `oop_version/`"* is met.

**O2 — `github-actions` at `directory: "/"` cannot reach `oop_version/`.** That ecosystem scans
`.github/workflows/` and composite-action definitions. A search of the whole tree found no
`action.yml` or `action.yaml` anywhere, and `oop_version/` holds only `README.md`,
`requirements.txt`, `src/` and `tests/`. T18's guarantee — *"a directory root `CLAUDE.md` declares
closed can never again produce a pull request or an Actions run"* — holds against T9's file.
Whether `/` is the *only* accepted value for that ecosystem was not verified and is not needed: it
is the correct one here either way.

**O3 — After the merge, the settings page will show Dependabot version updates as enabled.** The
file *is* that toggle. T18's *"It is the only toggle that changes"* was accurate at T18's time.
Recorded here so that a later settings review does not read the flipped state as someone having
violated T18's *"Do not touch Dependabot version updates on this page"*.

**O4 — The duplicate-run cost has not been paid yet, and will start at the merge.** The four
Dependabot runs of 2026-08-18 were `event: push` only, because `main`'s `ci.yml` had no
`pull_request` trigger at that time. After the merge, each Dependabot pull request will produce
two runs — the `concurrency` group keys on `github.ref`, which differs between the two events.
This is accepted explicitly in D8 Item 3 and its amendment; it is restated here only because run
noise was T18's stated cost driver, so the number is about to change for a reason unrelated to
T18.

**O5 — D21's founding measurement confirmed independently.** All four Dependabot runs of
2026-08-18 concluded `failure`, `#7` against `django_version` included. That is the evidence D21
rests on, and it reproduces.

**O6 — Flagged, not guessed: whether an auto-triage *open a pull request* rule needs a matching
version-update entry.** T19 step 3 records one documented precondition (security updates must be
off). Whether the action *additionally* requires `dependabot.yml` to declare version updates for
that ecosystem and directory was not established on either page read. If it does, T9's `uv` entry
at `/django_version` happens to satisfy it — by coincidence, not by design, since T9 and T19 come
from different amendments. Worth settling alongside Issue 2, since both concern whether T19 can run
at all.

**O7 — `sqlparse` confirmed at 0.6.0 in `django_version/uv.lock`.** Verified with a targeted
lookup, with the user's permission, under `conventions.md` → *Reading `uv.lock` — ask first* (the
security-advisory case the rule permits). This closes the only claim this audit carried from the
plan rather than from measurement. It confirms T18's reasoning for closing `#7` and for leaving the
four alerts standing, it bounds Decision A to nil, and it is what establishes Issue 2's mechanism —
a patched dependency raises no alert, so the manifest path T19 expects cannot exist.

**O8 — Do not reopen `#6`–`#9`.** Dependabot's comment offers it — *"just re-open this PR and I'll
resolve any conflicts on it"*. `#7` would reapply a fix to `django_version/requirements.txt`, a
file this branch deletes, and to a version `uv.lock` already carries. The other three would restore
exactly the cost T18 removed.

---

## Self-audit

Re-run against this report before handing it to the Planner. Three findings changed.

**Issue 2 — the first pass was wrong on the mechanism, and understated the consequence.** It
claimed T19 step 1's guard *"tests for a value that is unexpected, not for one that is stale"*, so
a stale value would pass through and the rule would fail silently. Re-reading step 1: its guard is
*"if the value is anything else"*, which catches a stale value as readily as a malformed one. The
guard works. What the re-audit found instead is more consequential — the expected value
`django_version/uv.lock` cannot appear in the alert stream at all once the vulnerability is
patched, so **every** post-merge path through step 1 hits the guard, including the one where
everything goes right. The finding moved from *"a guard that misses"* to *"a precondition that
cannot be met"*, and the direction changed with it, from *add a check to the merge* to *the value's
source has to be re-decided*.

**Issue 3 — one of three bullets is withdrawn.** The first pass recorded the workflow-level versus
job-level `permissions` question as settled by the green run. It is not. This repository is public,
so `actions/checkout` may succeed under an empty token grant regardless of which semantics apply —
a point the plan itself already makes, two bullets above the entry in question. The green run
cannot discriminate between the two hypotheses. Handing the Planner a false "settled" here would
have retired a live question and left the wrong reason on the record.

**Issue 1 — narrowed.** The first pass called it *"two incompatible things"*. On re-reading, the
sentence admits a charitable reading — independence about T18's *inputs* rather than its ordering —
under which it is true. The precise defect is smaller and cleaner: the claim is broader than the
justification offered for it in the same sentence. Stated that way it is still worth fixing, and it
is the lowest-severity item in the report.

**Unchanged on re-audit:** the answer to the question asked, all eight observations, and Decision
A's three options — though O7's measurement now bounds A's exposure to nil, which the first pass
could only assume.

**The common failure in both corrected findings** was concluding from the expected shape of the
problem rather than from the text in front of the reader: describing how T19's guard behaves
without checking the sentence, and reading a green run as proof without asking what else would
produce a green run on a public repository. `AUDITOR.md` Rule 2 is the rule that covers it.

---

## Handoff

**Audited.** T18 and T9 of `docs/plan/plan_toolchain-ci-security_2026-08-15.md` against each
other, against D18 (both amendments), D21 and D8, and against the live repository state measured
via `gh` and `uv.lock` on 2026-08-20. Then re-audited against itself.

**Result.** No conflict between the two tasks. **3 Issues**, **1 Open Decision**, **8
Observations** — all in the seam between T18/T9 and what comes after them.

**Nothing here blocks the merge.** Issues 1 and 3 are edits to the plan's record. Issue 2 must be
resolved before T19 is attempted, and cannot be resolved before the merge, because it turns on what
the dependency graph reports once the default branch describes the project through `uv`.

**Files the next session should attach.**

- `docs/plan/plan_toolchain-ci-security_2026-08-15.md` — sections *Verification debts*, T18, T19,
  *Order of execution*
- `.github/dependabot.yml`, `.github/workflows/ci.yml`
- this report

**Recommended persona for the next session: Planner**, after the merge.

**What the Planner is being asked to do — and what it is not.** Three of the four items are edits
to the plan's own record: narrow Issue 1's claim, strike the two settled debts and annotate the
third as unsettleable here, and give step 7 of the sequence an acceptance criterion. The fourth is
a real re-decision and must not be resolved as an edit: **T19 step 1 needs a different source for
its `manifest` value**, because the source it names cannot produce one. Decision A stays with the
user.
