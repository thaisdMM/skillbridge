# Plan — verified audit findings, publication readiness

**Date:** 2026-08-13
**Persona:** Planner
**Acts on:** `VERIFICACAO_AUDITORIA_SKILLBRIDGE.md` (2026-08-12), which verified
`AUDITORIA_SKILLBRIDGE.md` (2026-08-11) and `HANDOFF_PUBLICACAO_SKILLBRIDGE.md`.
**Tree:** `feature/django-refactor`, HEAD `19b3ac9`.
**Files modified by this session:** this plan only. No production file was touched.

Findings the Verifier confirmed are not re-verified here. What is planned is the
path to fix each one. Task entries appear in the order the user decided them.

## Attack order

| Block | Findings | Why here |
|---|---|---|
| **A — before `speckit-implement` runs** | conventions.md incomplete; T065 has no baseline | These close Phase 9 with an error inside if left for later |
| **B — documentation vs. code** | README version, CI badge, dead links, `profiles` absent, `.gitignore`, self-contradicting docs | Developer resolves directly, no decision needed |
| **C — user decision only** | licence | Legal choice, not a technical one |
| **D — the audit's own errors** | test category split, code count, line citations | Optional: fix at source, or leave the verification as errata |
| **Deferred by the user** | publishing/merge (after the spec closes); `validate_strong_password` (MVP briefing); orphan files | Already decided |

---

## TASK 1 — Complete the *Established invariants* list in `conventions.md`

**ORIGIN** — Verification report, 🟤 PARTIAL #3 (audit §13.8 item 6). The audit
reported one missing code; verification found two.

**PROBLEM** — `.claude/rules/conventions.md` lists 8 invariant codes. The source
raises 10. Missing: `staffuser_active_without_staff` and
`profile_for_inactive_account`.

Confirmed by reading the source, not by trusting the report:

| Code | Raised at |
|---|---|
| `staffuser_active_without_staff` | `accounts/models/staff_user.py:86` |
| `profile_for_inactive_account` | `profiles/models/freelancer_profile.py:172` **and** `profiles/models/client_profile.py:184` |

**DECIDED APPROACH** — Add three entries to the *Established invariants* list in
`.claude/rules/conventions.md`, one per model, in this wording:

```
- `StaffUser.clean()`: `is_active=True` requires `is_staff=True`
  → code: `staffuser_active_without_staff`
- `FreelancerProfile.clean()`: on creation only (`self.pk is None`), the
  account the profile belongs to must be active. Deactivating an account
  that already has a profile stays permitted.
  → code: `profile_for_inactive_account`
  → raised on the `user` field
- `ClientProfile.clean()`: on creation only (`self.pk is None`), the
  account the profile belongs to must be active. Deactivating an account
  that already has a profile stays permitted.
  → code: `profile_for_inactive_account`
  → raised on the `user` field
```

`specs/001-profiles-admin-panel/tasks.md` is **not** amended. T060 stays as
written; this task satisfies it ahead of time.

**WHY THIS PATH** — The creation-only scope is not decoration. Both profile
models guard the rule behind `if self.pk is None:`
(`freelancer_profile.py:163`, `client_profile.py:175`), so the rule refuses
*creating* a profile for an inactive account and says nothing about
*deactivating* an account that already has one. An entry omitting that reads as
the stronger rule, and the serializer and form layers would be written
defensively against a constraint the model does not impose.

*(`self.pk is None` is how Django distinguishes an object that has never been
written to the database from one being edited — the primary key is assigned on
the first `save()`. A check inside that branch runs once in an object's life.)*

**ALTERNATIVES CONSIDERED**
- Two entries, with both profile models sharing one bullet — shorter, but breaks
  the one-entry-per-model shape the existing 8 entries follow.
- Three entries in the existing terse style, without `self.pk is None` — visually
  consistent with the current list, but states a rule stronger than the code's.
- Widening T060 in `tasks.md` — rejected by the user: the spec task is not
  amended; the gap is closed here instead.

**SCOPE** — `.claude/rules/conventions.md`, *Established invariants* section only.

**ACCEPTANCE CRITERIA**
- `grep -rhoE 'code="[a-z_]+"' accounts/models/ profiles/models/ | sort -u`
  returns 10 codes, and all 10 appear in the list.
- No duplicated entry for `profile_for_inactive_account`.
- The closing "not guaranteed to be exhaustive" note is left in place.

**TEST PLAN** — None. Documentation only; no behavior changes.

**OUT OF SCOPE** — The `Skill` entries, the `CheckConstraint` notes, and every
other section of `conventions.md`.

**OPEN QUESTIONS** — None. One note for the Developer: when `speckit-implement`
later reaches T060, the code will already be present. T060 is then a checkbox to
tick, not an edit — do not let it append a second `profile_for_inactive_account`
entry.

---

## TASK 2 — Close T065 on a stated criterion, and record the FR-002 carve-out

**ORIGIN** — Verification report, 🟤 PARTIAL #6 ("T065 já executado"), and open
question 3.

**PROBLEM** — T065 (`tasks.md:407`) requires two things: run the suite, **and**
compare the passing count against the T004 baseline. The run happened
(`304 passed`). The comparison cannot happen: T004 (`tasks.md:64`, marked `[X]`)
instructed the implementer to note the passing count, and that number was never
written down. Searched and not found in `tasks.md`, in `docs/audits/`, or in any
commit message.

A second gap sits behind it. SC-009 (`spec.md:350`) requires that every existing
behavior check still passes, *"with the sole exception of checks that the two
intended additions in FR-024 necessarily change."* A real exception occurred that
SC-009 does not name — an **FR-002** one, documented at `tasks.md:407`: T073's
case-insensitive skill rule made `test_skill_name_uniqueness`'s `code == "unique"`
assertion unreachable and made `test_skill_clean_strips_whitespace` hit
pytest-django's DB blocker; T077 repaired both.

**DECIDED APPROACH** — Close T065 on four direct proofs instead of a count
comparison, with the substitution stated in writing:

1. `docker-compose exec web pytest` → `304 passed`, 0 failed, 0 skipped, 0 xfail.
2. No test file was deleted since the spec commit —
   `git diff --diff-filter=D --name-only e1691bd HEAD -- 'django_version/**/tests/**'`
   returns empty. **Already run during this planning session; the result is empty.**
3. No test function was removed over the same range.
4. The single SC-009 exception is the FR-002 one above, named explicitly — the
   same way SC-009 names FR-024.

**WHY THIS PATH** — A count comparison is a weak instrument for the property
SC-009 actually asserts. Two tests rewritten in place leave the total unchanged,
so the score stays identical while the event passes unseen — which is exactly
what happened with T073/T077. Proof 2 tests the property directly and cost one
command. Proof 4 exists because the user recognised the episode from memory
during planning; it closes a carve-out neither the audit nor the verification had
assessed.

**ALTERNATIVES CONSIDERED**
- Reconstruct the exact T004 number in a `git worktree` at `e1691bd` — closes
  T065 to the letter, but `pytest.ini` runs `--reuse-db` against a schema built
  from today's models, so it would likely need `--create-db`; and the number
  alone still cannot see the T073/T077 episode.
- Compare against the earliest *recorded* baseline (209, `handoff-phase-4.md:29`,
  with the chain running 209 → 236 → 268 → 304) — uses figures actually written
  in the spec artifacts, but 209 is a Phase 4 figure, not T004's, so it proves
  nothing about tests predating Phase 4.

**SCOPE** — This plan file, plus **one line appended to T065** in
`specs/001-profiles-admin-panel/tasks.md` at the moment the task is marked done.
That line records *how* the task was closed; it does not amend *what* the task
asks for. Nothing else in `tasks.md` is touched.

Wording for that line:

```
Closed 2026-08-__ on a stated criterion rather than the T004 comparison: the
T004 baseline count was never recorded anywhere. Closed on 304 passed / 0
failed, no test file or test function deleted since e1691bd, and one named
SC-009 exception — the FR-002 one (T073 broke test_skill_name_uniqueness and
test_skill_clean_strips_whitespace; T077 repaired both), which SC-009 does not
list because it names only FR-024.
```

**ACCEPTANCE CRITERIA**
- The suite runs green at 304 with 0 failed and 0 skipped.
- The deletion check returns empty (re-run at implementation time, not trusted
  from this plan).
- The stated criterion and the FR-002 carve-out are recorded somewhere a future
  reader of the ticked T065 checkbox will find.

**TEST PLAN** — The full suite is the test: `docker-compose exec web pytest` from
`django_version/`, run after Phase 10 per T065's 2026-08-05 amendment, never
between T073 and T077.

**OUT OF SCOPE** — Amending T065's requirement text. Re-litigating the FR-002
decision itself, which is settled and documented in
`docs/audits/2026-08-06-audit-phase-10-fr-002.md`.

**OPEN QUESTIONS** — None.

---

## TASK 3 — Repair and update `django_version/README.md`

**ORIGIN** — Verification report, 🟤 PARTIAL #4 (audit §13.8 items 1–4) and
🟣 HOLDS "no README mentions the `profiles` app".

**PROBLEM** — Four factual defects, plus an omission. The README declares
Django **6.0.3** while `requirements.txt` pins **6.0.7**; the CI badge's link URL
contains `actionsZ/workflows` and 404s; two links point at `./ARCHITECTURE.md`,
which sits at the monorepo root, not in `django_version/`; and it cites a
`ROADMAP.md` that does not exist. The omission: the `profiles` app — 4 models,
the whole admin panel and 104 tests — is not mentioned anywhere.

Line numbers below are the **verified** ones. The audit's citations for items 3
and 4 (`:6`, `:45`, `:96`) are wrong; do not use them.

**DECIDED APPROACH** — One file, `django_version/README.md`. Two kinds of edit.

*Mechanical repairs — one correct value each, no alternative exists:*

| Line | Now | Becomes |
|---|---|---|
| 3 | `…/actionsZ/workflows/ci.yml` in the **link** URL | `…/actions/workflows/ci.yml` (the image URL is already correct) |
| 7 | `[ARCHITECTURE.md](./ARCHITECTURE.md)` | `(../ARCHITECTURE.md)` |
| 16 | `Django 6.0.3` | `Django 6.0.7` |
| 47 | `[ARCHITECTURE.md](./ARCHITECTURE.md)` | `(../ARCHITECTURE.md)` |
| 91 | `` `ROADMAP.md` `` | `[docs/ROADMAP_SKILLBRIDGE.md](../docs/ROADMAP_SKILLBRIDGE.md)` |

*Content update — make `profiles` and the admin panel visible:*

1. **Architecture section** — after the existing user-model diagram, add the
   profile and skill layer:
   `Profile` (abstract) → `FreelancerProfile`, `ClientProfile`; `Skill` as a
   controlled vocabulary shared by both through `ManyToManyField`.
2. **Rename "Foundation"** to a section covering both apps, with `accounts/`
   keeping its current bullet list and `profiles/` gaining an equivalent one:
   the four models, the `clean()` invariants, and the 30 seeded skills across 4
   categories (`profiles/migrations/0002_seed_skills.py`).
3. **New short "Admin panel" subsection**, stating the design honestly:
   profiles have **no standalone screen**. They are edited inline on the account
   screen — `FreelancerProfileInline` and `ClientProfileInline`
   (`accounts/admin.py:284`, `:472`) — so an administrator never leaves the
   account to view or edit its profile. `SkillAdmin`
   (`profiles/admin.py:23`) is the one screen `profiles` owns, and the one
   admin class in the project that permits deletion, refused while any profile
   still refers to the skill.
4. **Tests** — state 304 passing, and the accounts/profiles split (200 / 104).
5. **Key decisions** — one bullet for `Skill` as an admin-curated vocabulary
   freelancers select from and never create.

**WHY THIS PATH** — Item 3 above is the one that must not be written from the
audit. The audit and the handoff both describe "o painel de administração de
perfis", which reads as a standalone profiles screen. The code says otherwise:
`profiles/admin.py` registers `SkillAdmin` and nothing else. Writing it the
audit's way would put a false claim in the first document a reviewer reads —
the same class of error as the `6.0.3` line this task exists to fix. Stated
correctly it is a *stronger* claim, because "the administrator never leaves the
account screen" is a deliberate design outcome (SC-005), not an absence.

**ALTERNATIVES CONSIDERED**
- A short paragraph inside the existing "Foundation" section — set aside as
  under-representing an app that carries 4 models and the admin work.
- Deferring the content update to a dedicated README session after T067 — set
  aside by the user: T067 was already walked manually, and the README is not
  a document that feeds ADRs, so it has no dependency to wait on.
- Updating the root `README.md` too — out of scope here; a second description
  of the same app is a second thing to keep in sync.

**SCOPE** — `django_version/README.md` only. Not `README.md` at the root, not
`oop_version/README.md`, not `ARCHITECTURE.md`.

**ACCEPTANCE CRITERIA**
- Every version, count and path in the file is verified against the tree at
  the time of writing, not copied from `AUDITORIA_SKILLBRIDGE.md`.
- Both `ARCHITECTURE.md` links and the roadmap link resolve when the file is
  viewed on GitHub.
- The badge link URL and the badge image URL point at the same workflow.
- The file states that profiles are edited inline on the account screen and
  have no standalone screen.
- The file stays under **150 lines** (currently 98). Growth is content, not prose.

**TEST PLAN** — None; documentation. Manual check: open the rendered file and
click every link.

**OUT OF SCOPE** — Restructuring the Quick Start, the author section, or the
tech-stack table beyond the version fix. Screenshots — the user may add them in
a later dedicated session.

**OPEN QUESTIONS** — None.

---

## TASK 4 — Correct the hyphen/underscore mismatch in `.gitignore`

**ORIGIN** — Verification report, 🟤 PARTIAL #5 (audit §13.8 item 10).

**PROBLEM** — `.gitignore` writes `oop-version/` and `django-version/` with a
hyphen; the directories use an underscore. Eight rules match no path in the
repository. Harmless today, armed for later: roadmap TASK 4.2.1 and 4.2.2 create
`staticfiles/` and `media/`, and on that day they enter the commit.

**DECIDED APPROACH** — Replace the hyphen with an underscore on eight lines.
Verified line numbers (the audit's ranges 12-13, 17-20 and 23-24 are all wrong):

| Lines | Rules |
|---|---|
| 10-11 | `oop-version/.venv/`, `django-version/.venv/` |
| 20-23 | `django-version/db.sqlite3`, `django-version/*.log`, `django-version/staticfiles/`, `django-version/media/` |
| 26-27 | `oop-version/.coverage`, `oop-version/.pytest_cache/` |

**WHY THIS PATH** — There is one correct value: the directories are named
`oop_version/` and `django_version/`. Verified safe to apply —
`git ls-files | grep -E "staticfiles/|media/|\.log$|db\.sqlite3"` returns
nothing, so no currently tracked file becomes ignored by the change. Run during
this planning session.

*(A `.gitignore` rule that matches nothing fails silently — git never warns that
a pattern is dead. That is why this survived: the venv is ignored by the
`.gitignore` that `venv` generates inside itself, so the broken root rule never
produced a visible symptom.)*

**ALTERNATIVES CONSIDERED** — None. Restructuring `.gitignore` more broadly is
not a finding and is not planned here.

**SCOPE** — `.gitignore` at the repository root, the eight lines above.

**ACCEPTANCE CRITERIA**
- No `-version/` string remains in the file.
- `git status --porcelain` shows no file newly ignored or newly tracked as a
  result.

**TEST PLAN** — None; configuration.

**OUT OF SCOPE** — Adding new ignore rules, reordering sections, the
`.venv/`-generated `.gitignore` inside the virtualenv.

**OPEN QUESTIONS** — None.

---

## TASK 5 — Close the resolved follow-up in the constitution's Sync Impact Report

**ORIGIN** — Verification report, 🟣 HOLDS "the constitution's follow-up is
resolved but unannotated" (audit §13.1).

**PROBLEM** — The 2026-08-09 Sync Impact Report in `.specify/memory/constitution.md`
marks two `ARCHITECTURE.md` lines as `⚠ PENDING, two lines now too broad` and
closes with `Follow-up TODOs: the two ARCHITECTURE.md lines above`. Both were
resolved in the target file; the annotation was never updated.

**DECIDED APPROACH** — Leave the 2026-08-09 block untouched. Append one dated
resolution line at the end of that block, before the closing `-->`:

```
Resolved 2026-08-13: ARCHITECTURE.md:825-828 now scopes has_delete_permission
to the account admin classes and names Skill as the exemption; the
"Deactivate, never delete" row at :951 carries the same exception. Both point
at docs/adr/skill-is-the-only-deletable-record.md. The follow-up above is
closed. Note the constitution's citation of line 949 has drifted — the content
it describes now sits at :951.
```

**WHY THIS PATH** — A Sync Impact Report is a dated record of one version bump:
it states what was true on 2026-08-09. Rewriting `⚠` into `✅` would make the
document assert about that date something that only became true later, and
erases the fact that the gap existed at all. Appending keeps the trail readable
for whoever audits the constitution next. The line-949-vs-951 drift is folded in
because the Verifier found it and no other document records it.

**ALTERNATIVES CONSIDERED**
- Edit in place, `⚠` → `✅`, and delete the TODO line — visually cleanest, but
  rewrites a dated historical record.
- Open a new Sync Impact Report block dated today — matches the file's existing
  stacked-block format, but such a block normally accompanies a version bump,
  and no principle changed here.

**SCOPE** — `.specify/memory/constitution.md`, the 2026-08-09 comment block only.
No principle text is touched. The constitution version stays **1.1.0**.

**ACCEPTANCE CRITERIA**
- The `⚠` line and the `Follow-up TODOs` line are still present, unedited.
- The appended line is dated and names both `ARCHITECTURE.md` targets.
- `grep -c "SYNC IMPACT REPORT" .specify/memory/constitution.md` still returns 2.

**TEST PLAN** — None; documentation.

**OUT OF SCOPE** — Editing `ARCHITECTURE.md` itself (closed to new entries).
Bumping the constitution version. The 2026-07-27 block.

**OPEN QUESTIONS** — None.

---

## TASK 6 — Reconcile roadmap TASK 2.1.5b and 2.1.6 with the code

**ORIGIN** — Verification report, 🟣 HOLDS "roadmap TASK 2.1.5b (0/18) and 2.1.6
(0/8) unchecked" (audit §13.2).

**PROBLEM** — Neither task has a single box ticked, while the work is done and
green. Worse, two statements in them are now false, and ticking the boxes
without correcting those statements would record something that never happened.

Verified during planning:

1. `docs/ROADMAP_SKILLBRIDGE.md:910` states
   `**Status:** PENDING — nenhum teste existe ainda para ClientProfile
   (confirmado: profiles/tests/models/ não contém test_client_profile.py)`.
   The file exists and holds **26 tests**.
2. All 18 planned behaviors are covered, but **four under different names** —
   the roadmap's names point at tests that do not exist:

   | Roadmap name | Actual test |
   |---|---|
   | `..._max_budget_none_persists_on_save` | `..._max_budget_accepts_null_at_database_level` |
   | `..._with_whitespace_company_name` | `..._with_empty_company_name` (passes `"   "`, asserts `company_name_empty`) |
   | `..._empty_company_name_passes_validation` | `..._no_company_name_passes_validation` (passes `""`) |
   | `test_add_and_remove_interests` | split into `..._add_interests` **and** `..._remove_interests` |

3. TASK 2.1.6's third box reads `Admin com TabularInline`. The code uses
   **`StackedInline`** — `BaseProfileInline(admin.StackedInline)`,
   `accounts/admin.py:105`. The task's own closing line is
   *"Conceitos para estudar: TabularInline vs StackedInline"*: the choice was
   made deliberately and went the other way.

**DECIDED APPROACH** — In `docs/ROADMAP_SKILLBRIDGE.md`:

- TASK 2.1.5b: tick all 18 boxes; replace the false `Status: PENDING` line with
  a `CONCLUÍDA` line naming the file and its 26 tests; add a short note listing
  the four name divergences and why the last one became two tests (the
  one-behavior-per-test rule in `testing.md`).
- TASK 2.1.6: tick all boxes; change `TabularInline` to `StackedInline` with a
  one-line note that the inline style was chosen deliberately, closing the
  task's own study item. The `queryset.update()` box is a standing constraint,
  not a step — leave its text intact and tick it as respected.

**WHY THIS PATH** — There is no alternative worth listing: leaving it wrong is
not an option, and ticking it verbatim would publish two false statements. The
only real judgement is the level of detail on the name divergences, and the
divergences must be recorded because the roadmap otherwise names four tests that
do not exist — the same defect class as the audit's wrong line numbers.

**SCOPE** — `docs/ROADMAP_SKILLBRIDGE.md`, TASK 2.1.5b (from line ~910) and
TASK 2.1.6 (from line ~963) only.

**ACCEPTANCE CRITERIA**
- No unchecked box remains in either task.
- No test name in TASK 2.1.5b fails a `grep -q "def <name>"` against
  `django_version/profiles/tests/models/test_client_profile.py`.
- The word `TabularInline` no longer describes what was built.
- The `Status: PENDING` line for 2.1.5b is gone.

**TEST PLAN** — None; documentation. Verify with the `grep` loop above.

**OUT OF SCOPE** — Every other task in the 2014-line roadmap. The STACK TRIAGE
section. Any Phase 2.2 (`jobs`) task.

**OPEN QUESTIONS** — None.

---

## TASK 7 — Flip `spec.md` out of `Draft` when Phase 9 closes

**ORIGIN** — Verification report, 🟣 HOLDS "spec 001 status figures"
(audit §12, §13.8 item 8).

**PROBLEM** — `specs/001-profiles-admin-panel/spec.md:7` reads
`**Status**: Draft` with 79 of 87 tasks complete and the quality checklist at
16/16.

**DECIDED APPROACH** — Change line 7 to `**Status**: Completed`, **as the last
step of closing Phase 9** — not now. Six of the eight pending tasks are real
work; flipping the status while they are open would replace one false statement
with another.

**WHY THIS PATH** — `.specify/templates/spec-template.md:7` ships `Draft` as the
initial value and defines no vocabulary for the other states, so `Completed` is
a choice, not a convention being followed. It is picked for reading plainly to a
reviewer who does not know Spec Kit.

**ALTERNATIVES CONSIDERED** — Flipping it now, ahead of the remaining tasks —
rejected: it would be inaccurate on the day it is written.

**SCOPE** — `specs/001-profiles-admin-panel/spec.md`, line 7 only.

**ACCEPTANCE CRITERIA**
- `grep -cE '^- \[ \]' specs/001-profiles-admin-panel/tasks.md` returns 0 before
  the line is changed.
- Line 7 reads `**Status**: Completed`.

**TEST PLAN** — None; documentation.

**OUT OF SCOPE** — Any other line of `spec.md`. The FR and SC text.

**OPEN QUESTIONS** — None.

---

## TASK 8 — Add an MIT licence

**ORIGIN** — Verification report, 🟣 HOLDS handoff P1.5. The GitHub API returns
`"license": null` for a public repository.

**PROBLEM** — No licence file exists. Without one, nobody is formally permitted
to use or redistribute the code, and GitHub shows an empty licence field on a
public portfolio repository.

**DECIDED APPROACH** — Create `LICENSE` at the **monorepo root** (not inside
`django_version/`) with the standard MIT text, copyright line
`Copyright (c) 2025-2026 Thaís Moreira`. The repository's first commit is
`d0318dd`, 2025-12-20, so the range starts at 2025.

**WHY THIS PATH** — Chosen by the user. MIT is the low-friction default for a
portfolio repository: recognised at a glance and compatible with any employer's
policy on cloning and running the project. GitHub detects a root `LICENSE` file
automatically and populates the API field the audit found empty.

**ALTERNATIVES CONSIDERED**
- Apache 2.0 — a long file and a patent grant disproportionate to this project.
- GPL-3.0 — copyleft would discourage the exact behaviour a portfolio wants,
  since some employers will not clone GPL code.
- An explicit all-rights-reserved notice — resolves the empty field but sends
  the opposite signal to a reviewer.

**SCOPE** — One new file: `LICENSE` at the repository root.

**ACCEPTANCE CRITERIA**
- The file is named exactly `LICENSE`, with no extension, at the root.
- It holds the unmodified MIT text with the copyright line above.
- After the branch is published, `curl https://api.github.com/repos/thaisdMM/skillbridge`
  reports `"license": {"key": "mit", …}` instead of `null`.

**TEST PLAN** — None.

**OUT OF SCOPE** — A licence header in source files. A separate licence for
`oop_version/`. Any `NOTICE` or `CONTRIBUTING` file.

**OPEN QUESTIONS** — None. The API check in the acceptance criteria can only run
after the work is published, which the user has scheduled for after the spec
closes.

---

## TASK 9 — Correct the audit at source, with an errata block and a Limitation

**ORIGIN** — Verification report, 🔵 DOES NOT HOLD #1 and #2, and 🟤 PARTIAL #4
and #5 (the line citations).

**PROBLEM** — Three defects in `AUDITORIA_SKILLBRIDGE.md` itself. None touches a
CV claim, but one now contradicts a file this plan corrects.

| Where | Says | Should say |
|---|---|---|
| line 293 | `6 clean() implementados; 9 códigos distintos` | `10 códigos distintos` — its own table below already lists ten |
| line 494 | `models = 157 · admin = 87 · validators = 32 · base abstrata = 5 (+23 restantes…)` | `models = 157 · admin = 115 · validators = 32` = 304, no remainder |
| §13.8 item 3 | `README.md:6` and `:45` | **7** and **47** |
| §13.8 item 4 | `README.md:96` | **91** |
| §13.8 item 10 | `.gitignore` 12-13, 17-20, 23-24 | **10-11**, **20-23**, **26-27** |

Line 494 has three faults at once: `admin` undercounts by 28 — exactly the size
of `test_freelancer_profile_inline.py`; `base abstrata = 5` counts
`profiles/tests/models/test_base.py` a second time when those 5 are already
inside the 157; and `+23 restantes` is not a category but a plug added to force
the line to total 304.

**DECIDED APPROACH** — Both, as the user chose:

1. **Errata block at the top of the file**, short: three bullets naming the
   corrections, a pointer to `VERIFICACAO_AUDITORIA_SKILLBRIDGE.md` (2026-08-12)
   as their source, and a pointer to the new Limitation for the full statement.
2. **Correct the body** at the five places in the table above.
3. **Add Limitation 15**, in the voice Limitation 13 already established —
   *"Erro corrigido […], registrado aqui por transparência"* — declaring each
   correction and attributing it to the verification session.

The top block stays short and defers detail to Limitation 15, so the two do not
restate each other.

**WHY THIS PATH** — The audit already has a method for this. Limitation 13
records that the "188 commits behind" claim was wrong, explains that the fault
was one of method, and states that §1 was rebuilt — body corrected, correction
declared. Following the document's own precedent is stronger than importing a
convention from elsewhere. The errata block is added on top because, unlike the
constitution's single header, these wrong numbers sit scattered through a
1269-line body, and a reader who jumps straight to §7 would otherwise still read
`admin = 87`.

**ALTERNATIVES CONSIDERED**
- Errata block only, body untouched — cheaper and lower-risk, but leaves the
  wrong figures in place for anyone reading a section directly.
- Leave both documents alone and treat the verification as the errata — zero
  work, but relies on the two files (1269 and 640 lines) always being read as a
  pair, and leaves `9 códigos distintos` contradicting the `conventions.md` list
  that Task 1 corrects to ten.

**SCOPE** — `AUDITORIA_SKILLBRIDGE.md` only: a new block at the top, the five
corrections in the table, and one new entry in the Limitations section.

**ACCEPTANCE CRITERIA**
- `grep -n "9 códigos distintos\|admin = 87\|+23 restantes\|base abstrata = 5"`
  returns nothing.
- `157 + 115 + 32` appears as the partition and sums to 304 with no remainder.
- No line citation in §13.8 items 3, 4 and 10 points at the wrong line — check
  each against `django_version/README.md` and `.gitignore` directly.
- The Limitations section holds a 15th entry, dated, attributing the corrections
  to the 2026-08-12 verification.
- No measurement in the body is changed other than the five above.

**TEST PLAN** — None; documentation.

**OUT OF SCOPE** — `VERIFICACAO_AUDITORIA_SKILLBRIDGE.md`, which is correct as
written and is the source of these corrections. Re-measuring anything the audit
reports. **`HANDOFF_PUBLICACAO_SKILLBRIDGE.md`** — it inherits the same wrong
README line numbers in P1.1–P1.4 and item 10, but **this plan supersedes it as
the working fix list**, so those numbers are no longer worked from. Correcting
the handoff is optional and is not planned here.

**OPEN QUESTIONS** — None.

---

## Deferred — recorded, not planned

These were raised by the audit or the verification and are **not** tasks in this
plan. Each is deferred by a decision already on record.

| Item | Status |
|---|---|
| Publishing / merging the 8 unpushed commits and the 61-commit `origin/main` gap | Deferred by the user to after this plan and the spec close. It is the largest finding by impact; nothing here blocks it once Tasks 1 and 2 land. |
| `validate_strong_password` not in `AUTH_PASSWORD_VALIDATORS` — a `StaffUser` can change their own password to a weak one | **Deferred to the MVP briefing by the user on 2026-08-13, knowingly.** Investigated in full first: the chain, an empirical comparison of both paths, the exposure boundary and the shape of the fix are recorded in `BRIEFING_PLANNER_MVP_SKILLBRIDGE.md` §3.3.1, so the next session does not repeat the work. Two findings from that investigation: the exposure is **narrower** than reported — `StaffUserAdmin` is a plain `ModelAdmin`, so only `/admin/password_change/` (own password) is affected — and removing the two Django built-ins was the **right** call, since they duplicate codes the project's own validator raises. The gap is a half-finished substitution, not a missing rule. |
| Orphans — `jobs` logger with no app, empty `accounts/services/__init__.py`, `pillow` with no consumer, `ready()` with a `pass` body, empty `docs/plan/`, `.claude/rules/sdd-workflow.md ` with a trailing space in its filename | Out of scope per `HANDOFF_PUBLICACAO_SKILLBRIDGE.md:103`. Confirmed present during this session: the trailing space and the empty directory both reproduce. |
| Linter, formatter, coverage, pre-commit, type checker | Out of scope per the same handoff section. |

---

## Order of execution

Tasks 1–9 touch nine different files and are independent of each other.

- **Before `speckit-implement` runs Phase 9:** Tasks 1 and 2. Task 1 satisfies
  T060 ahead of time; Task 2 settles how T065 closes. Running `implement`
  without them closes Phase 9 with an incomplete invariants list and a
  comparison that has no reference point.
- **Any time:** Tasks 3, 4, 5, 6, 8, 9.
- **Last, as the closing step of Phase 9:** Task 7 — its acceptance criterion is
  that no task remains unchecked.

One commit per file, per the *Commit messages* rule in `conventions.md`. Task 9
is the only entry that touches a file this plan's own findings came from; commit
it separately from the rest.

The user walks the result manually before any commit — the plan hands off after
the edits are applied and the suite is green, not after committing.

---

## Handoff for the next session

**What was planned.** Nine tasks covering every finding the 2026-08-12
verification confirmed, except those listed under *Deferred* above. Two of the
nine (1 and 2) are gates on Phase 9; the rest are documentation and
configuration repairs. No production code changes in any task — no model, no
admin, no test is touched.

**Findings resolved into tasks.**

| Task | Finding |
|---|---|
| 1 | `conventions.md` missing two invariant codes |
| 2 | T065 has no T004 baseline to compare against |
| 3 | README: Django version, CI badge link, two dead links, `profiles` invisible |
| 4 | `.gitignore` hyphen/underscore mismatch |
| 5 | Constitution follow-up resolved but unannotated |
| 6 | Roadmap TASK 2.1.5b and 2.1.6 unchecked, with two false statements inside |
| 7 | `spec.md` still `Status: Draft` |
| 8 | No licence |
| 9 | Three errors in the audit itself |

**Open questions still awaiting an answer.** None. All three questions the
verification left open were answered during this session:

1. T060 is **not** widened — Task 1 closes the gap outside the spec.
2. The handoff is **not** worked as a literal fix list — this plan supersedes
   it, so its wrong line numbers no longer matter.
3. The T004 baseline was never recorded anywhere — Task 2 replaces the count
   comparison with four stated proofs.

**Two things found during planning that neither the audit nor the verification
had.** Both are inside Task 6, and both would have produced a false record if
the roadmap boxes had simply been ticked:

- Four of TASK 2.1.5b's 18 planned test names do not exist under those names.
  All 18 behaviors are covered; the names diverged, and one test became two
  under the one-behavior-per-test rule.
- TASK 2.1.6 specifies `TabularInline`; the code uses `StackedInline`
  (`accounts/admin.py:105`), which was a deliberate choice the task itself set
  out to study.

**Files the next session should attach.**
- This plan.
- The file for the task being implemented, and only that file.
- `.claude/rules/conventions.md` for Task 1 (already auto-loaded).
- `specs/001-profiles-admin-panel/tasks.md` for Task 2 (T065 at line 407).

**Recommended persona.** **Developer**, starting with Tasks 1 and 2 — they are
the only two that gate `speckit-implement`. Use **Teacher** first if the FR-002
carve-out in Task 2 or the `self.pk is None` scope in Task 1 should be explained
in more depth before being written.
