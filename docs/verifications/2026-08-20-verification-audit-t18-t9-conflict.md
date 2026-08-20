# Verification — `docs/audits/2026-08-20-audit-t18-t9-conflict.md`

**Date**: 2026-08-20
**Persona**: Verifier (read-only). No file was modified other than this one.
**Audit under verification**: `docs/audits/2026-08-20-audit-t18-t9-conflict.md`
(1 Answer · 3 Issues · 1 Open Decision · 8 Observations).
**Plan the audit targets**: `docs/plan/plan_toolchain-ci-security_2026-08-15.md`, entries D6
(first amendment), D8 (three items, three amendments), D18 (entry, both amendments, the
Developer note), D21, T9, T15, T18, T19, _Verification debts_, _Order of execution_.

**Primary sources read in full, in the current context**

- `docs/audits/2026-08-20-audit-t18-t9-conflict.md`
- `docs/plan/plan_toolchain-ci-security_2026-08-15.md` — only the ranges the user scoped:
  D6 amendment 1, D8 in full, D18 in full, D21, _Verification debts_, T9, T15, T18, T19,
  _Order of execution_. The rest of the file was deliberately not opened.
- `.github/workflows/ci.yml`, `.github/dependabot.yml`, `django_version/.python-version`
- `django_version/VERIFIER.md`, root `CLAUDE.md`, `django_version/CLAUDE.md`,
  `.claude/rules/conventions.md`, `.claude/rules/testing.md`

**Executed on this machine (read-only commands)**

- `gh api repos/thaisdMM/skillbridge` — `security_and_analysis`, `visibility`, `default_branch`.
- `gh api repos/thaisdMM/skillbridge/dependabot/alerts` — number, package, ecosystem,
  `manifest_path`, severity, state for all seven alerts.
- **T19 step 1's query, run verbatim as the plan writes it**, and again with `?state=open`,
  plus a `group_by(.state)` count. This is the decisive evidence for the addendum to Part 1 and
  it changes what Issue 2 hands to the Planner.
- `gh pr list --state all` — author, state, base and head refs for `#1`–`#9`.
- `gh run list` and `gh api …/actions/runs/<id>` — event, branch, conclusion, `head_sha`.
- `gh run view <id> --log` — the `Set up job`, `Set up Python` and `Install uv` step logs of
  run `32280676936`. **This is the decisive evidence for Issue 3** and is described below.
- `gh pr view 6 --json comments` — Dependabot's closing comment, verbatim.
- `git log`, `git ls-tree`, `git show origin/main:.github/workflows/ci.yml`,
  `git ls-files` — commit/push topology, branch and `main` manifests, absence of any
  `action.yml`/`action.yaml`.
- `docker-compose exec -T web python -c "import sqlparse; print(sqlparse.__version__)"` —
  read-only, no state change. It settles Observation O7 **without opening `uv.lock`**, so the
  permission the audit requested is not needed.

**Official documentation consulted** — GitHub Actions workflow syntax (`permissions`,
`jobs.<job_id>.permissions`), Dependabot options reference (`directory`, `ignore`,
`open-pull-requests-limit`, accepted `package-ecosystem` values), Configuring Dependabot
security updates, Keeping your actions up to date with Dependabot.

**Scope.** Only the audit's own claims are verified. No new finding about the plan or the
application is raised, and no severity label is reclassified. One fact discovered incidentally
while reading a run log is recorded at the end, explicitly outside the audit's scope and
explicitly not a verdict.

---

## Part 1 — finding by finding

### 🟤 The Answer — "No. T18 and T9 do not conflict." — **PARTIAL**

**The conclusion holds. One of its stated premises is over-broad, and one of its five measured
bullets is false.**

**The conclusion, verified independently.** T18 is a repository toggle; T9 is two files. The
toggle reads `disabled` today (`gh api …/security_and_analysis` →
`{"dependabot_security_updates":{"status":"disabled"}, …}`). `.github/dependabot.yml` as
committed at `3cc1871` contains two entries, `github-actions` at `/` and `uv` at
`/django_version`, both `interval: "monthly"`, and no `ignore`, `allow` or `oop_version` key of
any kind. Nothing in that file can set a repository toggle. The two tasks govern disjoint
surfaces and the conclusion is correct.

**The premise that is over-broad.** The audit writes: _"D18 amendment 1 established the fact
that makes them non-overlapping: `dependabot.yml` cannot filter security updates **at all**."_
That premise is inherited from D18's amendment, which states _"`ignore` carries the
version-updates icon only, so an `/oop_version` entry with `dependency-name: "*"` suppresses
nothing on the security side."_ **GitHub's current documentation says otherwise.** The
_Dependabot options reference_ marks `ignore` as applying to version updates **and** security
updates, and _Configuring Dependabot security updates_ states that a `dependabot.yml` file can
_"override the default behavior of Dependabot security updates"_, subject to the condition D18
itself quoted — _"the `directory` must be the path to the manifest files … and you should not
specify a `target-branch`"_. D18 read that condition as governing `directory` alone; it governs
whether the whole entry applies to security updates.

_Stated with its limit:_ the icon badges themselves do not survive the page's conversion to
text, so this rests on the reference's prose and on the security-updates page, read twice with
consistent results — not on the badges the plan cites. It is strong, not absolute.

**Why the conclusion survives anyway.** The narrower true statement carries it: with the
repository toggle off, no `dependabot.yml` key turns security updates back on, and the file T9
actually wrote declares no `ignore` and no `oop_version` entry. T18 and T9 do not conflict for
that reason, which is independent of whether `ignore` reaches security updates.

**The four measured bullets that hold**, re-measured today:

| Audit's bullet | Measured |
| --- | --- |
| `dependabot_security_updates.status` → `disabled` | ✓ |
| alerts endpoint returns a list, not 403 | ✓ seven alerts returned |
| `#6`–`#9` all `CLOSED`, none open by `app/dependabot` | ✓ all four `CLOSED` |
| `dependabot.yml` has exactly two entries, no `oop_version` path | ✓ |

### 🔵 The Answer's fifth bullet — "the three `docs(plan)` commits after them produced no run at all (T9 acceptance ✓, both halves)" — **DOES NOT HOLD**

**Measured.** `git log` on `feature/django-refactor`, newest first:

```
78a0a2f docs(plan): adopt the manifest-path rules and correct the licence premise
3cc1871 chore(ci): add dependabot.yml watching the actions and django_version
46d31ce chore(ci): harden permissions, pin the actions and generate the key in ci.yml
4a718a4 docs(plan): record the manifest-path rule the Dependabot screen offers
a58d24f docs(plan): narrow the Dependabot decision and add the generated CI secret key
```

Three failures in one sentence:

1. **Only one `docs(plan)` commit follows the two `chore(ci)` commits**, not three. `a58d24f`
   and `4a718a4` precede them.
2. **`78a0a2f` has never been pushed.** `git log origin/feature/django-refactor..HEAD` returns
   exactly that one commit. It produced no run because no push carried it — which is evidence
   about nothing.
3. **The push topology shows the opposite half was tested.** Run `32280676936` has
   `head_sha = 46d31ce`; the previous run, `32238754532`, has `head_sha = bab18f7`. One push
   therefore carried `bab18f7..46d31ce` — seven commits mixing `pyproject.toml`, the
   `Dockerfile`, `ci.yml` **and** three documentation commits — and it ran.

**Consequence for T9's acceptance criterion.** T9 requires _"A documentation-only push produces
no run; a push mixing documentation and code does."_ The **second half is verified** by run
`32280676936`. The **first half is not verified at all**: no documentation-only push has
occurred since `paths-ignore` landed in `46d31ce`. The audit marks both halves ✓; one of them
is untested, and D8 Item 3's amendment names precisely this as the trap — _"A wrong path filter
fails silently — it skips a run that was wanted, and nothing reports that."_

**Open question for the user.** Pushing `78a0a2f` on its own would settle it in one action, and
it is the only remaining unpushed commit. Should that be done before the merge, given that the
merge is what makes the filter live on `main`?

---

### 🟤 Issue 1 — "The *Order of execution* contradicts its own constraint about T18" — **PARTIAL**

**Verified first, against the file.** All three citations are accurate:

- Constraint 4 (`docs/plan/plan_toolchain-ci-security_2026-08-15.md`, _Order of execution_,
  numbered constraint 4): _"**T18 before T9, and both before any merge to `main`.**"_
- The sequence table, T9's row: _Waits on: T2, T18_.
- The closing paragraph: _"**Independent of the whole sequence:** T18, which needs no file to
  exist and no task to precede it."_

**What holds.** The label _"Independent of the whole sequence"_ is genuinely wrong and genuinely
skimmable. Read alone, it licenses placing T18 anywhere in the order, which constraint 4
forbids. It is worth restating, and the audit's Direction — restate constraint 4's claim,
re-decide nothing — is proportionate. The cost today is zero, as the audit says: both tasks are
done and the table row already carries the true dependency.

**What does not hold — the audit misidentifies which clause is wrong.** The audit writes:
_"The paragraph's other claim — 'needs no file to exist' — is correct as written and can stand
unchanged"_, which implies the defective clause is _"and no task to precede it."_ **That clause
is true.** T18's own row in the sequence table carries `—` in the _Waits on_ column, and T18's
entry states no prerequisite. Both elaborating clauses are accurate; the defect is entirely in
the heading label they hang off.

**Why the distinction matters operationally.** The audit's Handoff sends this to a Planner
session as an edit. A Planner acting on the audit as written would delete a true statement and
leave the false label standing. The correct edit is the reverse: keep both clauses, replace
_"Independent of the whole sequence"_ with something that says what the clauses actually say —
that T18 has no predecessor, while T9 has T18 as one.

---

### 🟤 Issue 2 — "No task owns verifying that the four `sqlparse` alerts actually close at the merge" — **PARTIAL**

**Measured independently, today.** `gh api repos/thaisdMM/skillbridge/dependabot/alerts`:

| Alert | Package | Ecosystem | `manifest_path` | Severity | State |
| --- | --- | --- | --- | --- | --- |
| 1 | sqlparse | pip | `django_version/requirements.txt` | medium | **open** |
| 2 | sqlparse | pip | `django_version/requirements.txt` | high | **open** |
| 3 | sqlparse | pip | `django_version/requirements.txt` | high | **open** |
| 4 | sqlparse | pip | `django_version/requirements.txt` | high | **open** |
| 5 | Pygments | pip | `oop_version/requirements.txt` | low | dismissed |
| 6 | pytest | pip | `oop_version/requirements.txt` | medium | dismissed |
| 7 | python-dotenv | pip | `oop_version/requirements.txt` | medium | dismissed |

The audit's measurement reproduces exactly: four open, all against
`django_version/requirements.txt`, three `high` and one `medium`.

**The half that holds.** T18's closing paragraph does carry the label without an owner —
_"**Stated as reasoning, not measured:** they are expected to close on their own once the merge
removes `django_version/requirements.txt` from the default branch"_ — and step 7 of the
sequence, the merge, carries no acceptance criterion of any kind. Read against the plan's own
_Evidence discipline_ section, an unmeasured premise with no named check is a real gap, and
adding one costs a sentence.

**The half that does not hold, and it is the half the audit calls "the expensive one."** The
audit claims **T19 breaks silently**: that a stale `django_version/requirements.txt` would come
back from step 1's query and be written into a rule, because _"the guard tests for a value that
is unexpected, not for one that is stale."_

**T19 step 1 was read in full, and it catches exactly this case.** Three separate mechanisms,
any one of which fires:

1. **Step 1 opens with a gate on the merge itself**, before the alerts are queried at all:
   `gh api …/contents/django_version/uv.lock` must return `uv.lock` and
   `gh api …/contents/django_version/requirements.txt` must return **404**, and the step says
   _"Do not open the rules screen before both commands below agree."_ If the manifest is still
   on the default branch, the task stops before step 2.
2. **The guard is written as an open set, not a closed one.** _"**Expected:
   `django_version/uv.lock`. Not verified.** If the value is **anything else** —
   `django_version/pyproject.toml`, a path without the directory prefix, or two entries where
   one was expected — **write it down, create no rule, and return to the Planner.**"_
   `django_version/requirements.txt` is anything else. The three examples are illustrative; the
   condition is `≠ django_version/uv.lock`.
3. **T19's acceptance criterion re-reads the alerts and records their state.** It requires
   `gh api …/dependabot/alerts --jq '[.[] | {pkg:…, path:.dependency.manifest_path, state}]'`
   to run clean and _"its output is pasted into the tech-debt entry as the baseline at creation
   time."_ Whether alerts 1–4 left the `open` state is therefore observed and written to
   `docs/tech_debt/011`.

**So the shape the audit asks for already exists.** Its Direction asks for _"a post-merge check,
taken before T19 step 2 opens the rules screen, that alerts 1–4 have left the `open` state and
that the manifest the dependency graph now reports is the `uv` one."_ That is a description of
T19 step 1. The audit's own next sentence — _"T19 step 1's 'If that returns an empty list'
branch is where the result lands"_ — concedes that step 1 is the place, while the finding above
it says step 1 does not catch the case.

**What genuinely remains, stated at its real size.** The merge, as step 7, has no acceptance
criterion, and no entry says in words _"confirm alerts 1–4 are no longer open."_ That is a
one-line documentation gap in the sequence table, not a silent failure mode in T19. It is the
same class as Issue 1, not the class the audit assigned it.

> **Superseded in part — see the addendum to Part 1.** After this verdict was written, the
> Auditor withdrew this finding and offered a different one in its place. That replacement was
> measured and it **holds**: T19 step 1 does have a real defect, in the query rather than in the
> guard. The verdict above stands as written — _"T19 breaks silently"_ remains wrong — but the
> sentence _"a one-line documentation gap in the sequence table"_ no longer describes everything
> that is owed here. The addendum carries the measurement and the corrected consequence.

---

### 🟤 Issue 3 — "Three verification debts were settled by T9's green run, and the plan still lists them as open" — **PARTIAL**

**All three are indeed unstruck.** Confirmed in the _Verification debts_ section. One citation
is wrong: the audit locates all three at _"the final three bullets"_. Two are
(`actions/checkout@v7`/`setup-python@v7`, and the job-level `permissions` question, with the
struck `checkout@v4` bullet between them); the `python-version-file` debt is the **second**
bullet of the section, not one of the last three.

**Both runs re-verified.** `32280676936` (`head_sha 46d31ce`) and `32281841857`
(`head_sha 3cc1871`), both `event: push` on `feature/django-refactor`, both `success`, every
step `success` except the two badge steps, which are `skipped` by their
`if: github.ref == 'refs/heads/main'` condition.

#### 🔵 Bullet A — the job-level `permissions` question — **the conclusion is right; the audit's justification DOES NOT HOLD**

**The audit's reasoning.** _"`actions/checkout` succeeded at step 1. That is exactly the
falsification test D8 Item 1's amendment was designed around — 'if it intersects,
`actions/checkout` fails on step 1 of the first push'. It did not fail, so the job-level block
grants rather than intersects."_

**Why that inference is invalid.** It affirms the consequent through a premise the plan itself
records as unresolved. If job-level `permissions` intersected with the workflow-level
`permissions: {}`, the token would carry zero scopes — and whether `actions/checkout` fails
with zero scopes **on a public repository** was never established. The plan says so twice:

- D8 Item 1, _Alternatives considered_: _"`permissions: {}` at the workflow level with no
  job-level grant … nothing then grants `contents: read`, so this depends on whether a public
  repository retains implicit read access for `checkout`, which the audit could confirm only
  from secondary sources."_
- _Verification debts_: _"~~Whether `actions/checkout@v4` functions under `permissions: {}` on
  this repository.~~ **No longer load-bearing after Item 1's amendment**"_ — struck as
  irrelevant, never answered.

The repository is `public` (`gh api …/--jq '.visibility'` → `public`), and GitHub's own
documentation notes that public repositories grant a read token in cases where the configured
permissions would not. A green checkout is therefore consistent with **both** hypotheses, and
proves neither. The audit's own second failure mode — a guard that looks like it fires but
does not — applies to its own argument here.

**The debt is nevertheless settled, by a different and decisive source.** The runner prints the
token's actual grant at the top of every job. From
`gh run view 32280676936 --log`, the `Set up job` step:

```
##[group]GITHUB_TOKEN Permissions
Contents: read
Metadata: read
Secret source: Actions
```

`ci.yml` declares `permissions: {}` at the workflow level and `permissions: contents: read` on
the `test` job. Under intersection the group would read `Contents: none`. It reads
`Contents: read`. **The job-level block replaces the workflow-level one.** The debt closes, and
the record should name this log group rather than the checkout step — the difference is between
a fact and a coincidence.

_Also visible in the same group, and worth carrying to T9's deferred verification:_
`Secret source: Actions`, the counterpart of the `Secret source: Dependabot` line D21 quotes
from run `32122772733`.

#### 🟣 Bullet B — `actions/checkout@v7` and `actions/setup-python@v7` are drop-in — **HOLDS**

`ci.yml` pins `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1` and
`actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0`. Both steps report
`success` in both runs. The debt asks exactly whether they function in this workflow, including
the runner Node version change it names; two green runs answer it.

#### 🟣 Bullet C — which file `python-version-file` accepts — **HOLDS, on stronger evidence than the audit gives**

The audit says only that _"the workflow passes `django_version/.python-version` and the step
succeeded."_ The log is explicit. From the `Set up Python` step of run `32280676936`:

```
with:
  python-version-file: django_version/.python-version
…
Resolved django_version/.python-version as 3.14.7
Successfully set up CPython (3.14.7)
```

`django_version/.python-version` contains `3.14.7`. The action read the file, resolved it, and
installed that interpreter.

**One boundary on what this settles.** D6's amendment framed the debt as _"uv's guide names
both `.python-version` and `pyproject.toml`; the authority is that action's own documentation."_
The run proves `.python-version` is accepted; it says nothing about `pyproject.toml`. That is
sufficient, because the same amendment already closed that branch — _"If only `.python-version`
is supported, that file is created — nothing else changes"_ — and the file exists. The
strike-through should say what was proved, not more.

---

### 🟣 Decision A — the implicit ignore created by closing `#6`–`#9` — **the facts HOLD; the decision is the user's**

**Dependabot's comment, verified verbatim** (`gh pr view 6 --json comments`):

> _"OK, I won't notify you again about this release, but will get in touch when a new version is
> available. If you'd rather skip all updates until the next major or minor version, let me know
> by commenting `@dependabot ignore this major version` or `@dependabot ignore this minor
> version`. If you change your mind, just re-open this PR and I'll resolve any conflicts on it."_

Neither widening command was issued on `#6`. The audit's reading of the sentence — a
version-level ignore, not a dependency-wide one — matches the text.

**The three inert pull requests, verified.** `#6` `dependabot/pip/oop_version/pygments-2.20.0`,
`#8` `dependabot/pip/oop_version/pytest-9.0.3`, `#9`
`dependabot/pip/oop_version/python-dotenv-1.2.2` — all `pip`, all `/oop_version`.
`.github/dependabot.yml` declares no `pip` entry and no `oop_version` directory, so no version
update runs there. Inert, as the audit says.

**The fourth, verified.** `#7` is `dependabot/pip/django_version/sqlparse-0.6.0` — `pip`
ecosystem, `/django_version`, the directory T9's file declares under `uv`. The audit's question
is real and its framing is accurate: neither page consulted documents the key the implicit
ignore is stored under.

**The exposure bound is now measured rather than quoted.** The audit bounds the risk on the
plan's claim that `uv.lock` resolves `sqlparse` to `0.6.0`, and flags in O7 that it did not
verify this. Verified here without opening `uv.lock`:

```
$ docker-compose exec -T web python -c "import sqlparse, django; print(sqlparse.__version__, django.get_version())"
0.6.0 6.1
```

The container's environment is provisioned by `uv sync` from `uv.lock` (D3/D4), so the resolved
version is `0.6.0`. **The ignore therefore names a version the project already has**, under
every reading of the storage key. Option 1's stated risk — _"leaves an untested assumption on
the repository's highest-severity package"_ — is smaller than the table presents it: the untested
part is the key's shape, not the exposure, and the exposure is zero for `0.6.0` and absent for
any later release.

The three options remain defensible and the choice is not the Verifier's to make.

---

### Observations

**🟣 O1 — `dependabot.yml` matches T9's instruction exactly — HOLDS.** File read in full:
two entries, `github-actions` at `directory: "/"` and `uv` at `directory: "/django_version"`,
both `schedule: interval: "monthly"`, no third entry, no `oop_version`.

**🟣 O2 — `github-actions` at `/` cannot reach `oop_version/` — HOLDS, with a normative source
the audit did not cite.** GitHub's _Dependabot options reference_: _"For GitHub Actions, use the
value `/`. Dependabot will search the `/.github/workflows` directory, as well as the
`action.yml`/`action.yaml` file from the root directory."_ So the scan is bounded to two
locations, both outside `oop_version/`. `git ls-files | grep -iE 'action\.ya?ml'` returns
nothing, and `git ls-tree -r HEAD oop_version/` shows only `README.md`, `requirements.txt`,
`src/` and `tests/`. The audit's tree-wide search was broader than the ecosystem actually
scans, so its conclusion holds a fortiori. Its parenthetical — _"`/` is also the only valid
value for that ecosystem"_ — matches the reference's wording.

**🟠 O3 — after the merge the settings page will show version updates as enabled — reasoning,
not measured, and correctly so.** Version updates are enabled by the presence of
`dependabot.yml` on the default branch, which is the documented mechanism, so the prediction
follows. The specific string the settings page will render was not read, here or in the audit.
Recording it so a later settings review does not misread the flipped state is sound, and no
verdict is available until the merge lands.

**🟣 O4 — the duplicate-run cost starts at the merge — HOLDS.** Two halves, both verified.
`git show origin/main:.github/workflows/ci.yml` carries `on: push: branches: ["**"]` and no
`pull_request` trigger, which is why all four Dependabot runs of 2026-08-18 are `event: push`
(`gh run list`). And `ci.yml` on this branch keys concurrency on
`group: ${{ github.workflow }}-${{ github.ref }}` — `github.ref` is `refs/heads/<branch>` for
`push` and `refs/pull/<n>/merge` for `pull_request`, so the two runs land in different groups
and neither cancels the other.

**🟣 O5 — D21's founding measurement reproduces — HOLDS.** `gh run list` shows runs
`32122771698`, `32122772733`, `32122773100`, `32122774259`, all `conclusion: failure`, all
`event: push` on the four `dependabot/…` branches on 2026-08-18. `32122772733` is the
`/django_version` `sqlparse` run D21 quotes.

**🟣 O6 — flagged, not guessed — HOLDS as a properly flagged unknown.** Whether an _open a pull
request_ auto-triage rule additionally requires a matching version-update entry in
`dependabot.yml` was not established on the pages read here either. The audit's judgement that
it is worth settling before T19 step 3 is sound, and its honesty about the coincidence — T9's
`uv` entry at `/django_version` would satisfy such a requirement by accident — is exactly the
right register.

**🟣 O7 — the `sqlparse` 0.6.0 claim — HOLDS, and the permission request is no longer needed.**
The audit asks for permission to open `uv.lock` under `conventions.md` → _Reading `uv.lock` —
ask first_. The container answers the same question at no context cost and with stronger
evidence, since it reports what is actually installed rather than what is resolved:
`sqlparse 0.6.0`. The rule was not breached and `uv.lock` was not opened.

**🟣 O8 — do not reopen `#6`–`#9` — HOLDS.** `git ls-tree HEAD django_version/` shows
`pyproject.toml` and `uv.lock` and no `requirements.txt`, while
`git ls-tree origin/main django_version/` still shows `requirements.txt`. Reopening `#7` would
reapply a fix to a file this branch deletes, as the audit says.

---

## Part 1 (addendum) — the Auditor's four self-corrections, verified

Placed before the summary on purpose, for the reason the summary is placed last: it is a set of
findings, and the summary below is derived from it.

After the report above was delivered, the user relayed four self-corrections the Auditor had
proposed to its own report — not yet applied to
`docs/audits/2026-08-20-audit-t18-t9-conflict.md`, which is still at its first version on disk.
Each is verified here on the same terms as the original findings.

### 🟣 Self-correction 1 — Issue 3's evidence was not a falsification test — **HOLDS**

The Auditor now states that the green run does not discriminate, because a public repository may
let `actions/checkout` function under a token with no scopes, and that the plan already recorded
that gap two bullets above in the same section. Both points are correct and both were reached
independently above.

**Incomplete in one respect, and it matters for what the Planner does.** The Auditor stops at
"the debt is not settled." It **is** settled — by the `GITHUB_TOKEN Permissions` group of run
`32280676936`, quoted under bullet A above. If the correction is applied as described, the plan
keeps a debt open that already has its answer in hand. The edit is to **replace the evidence**,
not to withdraw the conclusion.

### 🟣 Self-correction 2 — Issue 2's mechanism was wrong, and the replacement finding — **HOLDS, and the replacement is stronger than its own argument**

**The withdrawal is correct** and matches the verdict above: the guard reads _"If the value is
anything else"_, which is an open set, so a stale value trips it.

**The replacement finding, measured.** The Auditor now argues that T19 step 1 stops in *every*
path, because `manifest_path` belongs to an alert, the alert stream cannot carry
`django_version/uv.lock` while nothing in `uv.lock` is vulnerable, and the empty-list fallback
never fires because closed alerts stay listed. Run verbatim, today:

```
$ gh api repos/thaisdMM/skillbridge/dependabot/alerts \
    --jq '[.[] | .dependency.manifest_path] | unique'
["django_version/requirements.txt","oop_version/requirements.txt"]

$ gh api "repos/thaisdMM/skillbridge/dependabot/alerts?state=open" \
    --jq '[.[] | .dependency.manifest_path] | unique'
["django_version/requirements.txt"]

$ gh api repos/thaisdMM/skillbridge/dependabot/alerts \
    --jq '[.[] | .state] | group_by(.) | map({state:.[0], n:length})'
[{"n":3,"state":"dismissed"},{"n":4,"state":"open"}]
```

**The alerts endpoint applies no default state filter.** The three `dismissed` `oop_version`
alerts stay in the listing, so the query returns **two** manifests, and T19 step 1's guard —
_"or two entries where one was expected"_ — fires. The empty-list fallback cannot run. This is
true today and stays true after the merge, whatever state alerts 1–4 end up in.

**Two corrections to the Auditor's reasoning, one weakening and one strengthening.**

- The conclusion does **not** depend on _"não existe advisory contra nada que o `uv.lock`
  resolve"_. The three dismissed `oop_version` alerts alone make the list non-empty and its
  value ≠ `django_version/uv.lock`. The finding therefore survives a new advisory landing
  tomorrow — that would make three entries, and the guard fires on those too.
- **"Stops" is not "fails silently", and they are opposite failure modes.** The withdrawn
  finding claimed T19 would write a wrong rule quietly; this one says T19 halts and returns to
  the Planner even on the happy path. They need different repairs, and only the second is real.

**The repair, and it absorbs Issue 2's original concern.** Adding `?state=open` to step 1's query
makes the step behave as written: an empty list means alerts 1–4 closed at the merge — T18's
unmeasured premise confirmed, and the documented fallback to the `manifest` autocomplete takes
over — while `django_version/requirements.txt` means they did not close, which is the finding
the step already knows how to report. **This gives Issue 2's orphaned premise the named owner it
was missing**, in one line, inside a task that has not run yet. The merge step's missing
acceptance criterion becomes optional rather than necessary.

### 🟣 Self-correction 3 — Issue 1 reframed as over-broad rather than contradictory — **HOLDS**

_"The claim is broader than the justification given in the same sentence"_ is the accurate
description, and it converges with the PARTIAL verdict above. **The caveat from that verdict
still applies to the edit itself**: the defect is the label _"Independent of the whole
sequence"_, and both elaborating clauses — including _"no task to precede it"_ — are true and
must survive.

### 🔵 Self-correction 4 — removing the `/`-only assertion from O2 — **DOES NOT HOLD as an edit**

Withdrawing an unverified assertion is the right instinct, and at the time the Auditor wrote it
the assertion had no source. **It has one now.** GitHub's _Dependabot options reference_: _"For
GitHub Actions, use the value `/`. Dependabot will search the `/.github/workflows` directory, as
well as the `action.yml`/`action.yaml` file from the root directory."_

Deleting the sentence removes a verified fact and weakens O2, whose whole point is that
`oop_version/` is unreachable by that ecosystem. **Keep the claim and attach the citation.**

---

## Part 2 — Summary

**Holds (7)**

- The Answer's central conclusion: T18 and T9 do not conflict, and its four repository-state
  measurements reproduce exactly.
- Issue 3, bullet B — `checkout@v7` / `setup-python@v7` are drop-in.
- Issue 3, bullet C — `python-version-file` accepts `django_version/.python-version`, proved by
  `Resolved django_version/.python-version as 3.14.7` in the run log.
- Decision A — every fact it rests on, including the Dependabot comment verbatim; and its
  exposure bound is now measured (`sqlparse 0.6.0` installed) rather than quoted.
- Observations O1, O2, O4, O5, O6, O7, O8.

**Does not hold (2)**

- **The Answer's fifth measured bullet.** Only one `docs(plan)` commit follows the two
  `chore(ci)` commits, and it was never pushed. T9's _"a documentation-only push produces no
  run"_ criterion is **not** verified; only its mixed-push half is.
- **Issue 3's justification for bullet A.** A green `actions/checkout` on a **public**
  repository does not discriminate between "replaces" and "intersects", and the plan itself
  records that gap twice. The debt is settled anyway — by the run log's `GITHUB_TOKEN
  Permissions / Contents: read` group, which is a direct measurement of the grant.

**Partial (3)**

- **Issue 1.** The label _"Independent of the whole sequence"_ is genuinely misleading and worth
  restating. But the audit points at the wrong clause: _"no task to precede it"_ is **true** and
  matches T18's `—` in the _Waits on_ column. A Planner acting on the audit as written would
  delete a true statement and leave the false label.
- **Issue 2.** The merge step genuinely carries no acceptance criterion. But _"T19 breaks
  silently"_ does not hold: step 1 gates on `requirements.txt` returning 404 before the rules
  screen is opened, its guard fires on **any** value other than `django_version/uv.lock`, and
  T19's acceptance criterion records every alert's `path` and `state` into
  `docs/tech_debt/011`. **What the addendum adds:** the finding underneath was real but sits in
  the query, not the guard — the alerts endpoint applies no default state filter, so step 1
  halts on every path, including the one where the merge went right. One line (`?state=open`)
  repairs it and gives Issue 2's orphaned premise its owner.
- **Issue 3 overall.** All three debts are genuinely unstruck and genuinely settled, so the
  Direction is right. One citation is wrong (the `python-version-file` debt is the section's
  second bullet, not one of the last three) and one justification is invalid (bullet A, above).
- **The Answer's premise** _"`dependabot.yml` cannot filter security updates at all"_ — inherited
  from D18's amendment, and contradicted by GitHub's _Dependabot options reference_ (`ignore`
  applies to both update types) and _Configuring Dependabot security updates_. The conclusion
  survives on a narrower premise.

**Open questions for the user (3)**

1. ~~**T9's untested acceptance half.** `78a0a2f` is the only unpushed commit and is
   documentation-only. Pushing it alone would verify _"a documentation-only push produces no
   run"_ in one action.~~ **Closed 2026-08-20 — the user took it.** `78a0a2f` (one file, under
   `docs/`) was pushed alone; `git log -1 origin/feature/django-refactor` now reports it, and
   `gh run list` still reports `32281841857` (`head_sha 3cc1871`) as the newest run. **No run
   was created.** T9's `paths-ignore` criterion is now verified in both halves, and the plan
   records it.
2. **D18's `ignore` premise.** The amendment's sentence _"`ignore` carries the version-updates
   icon only"_ contradicts the current options reference. This does not change what was decided
   — security updates are off at the toggle, which is stronger than any file — but it is the
   **second** false premise found in that amendment, after the licence gate the Developer note
   already corrected. Does the amendment get a second correction, or is it left as the record of
   what was believed at the time?
3. **Issue 2's real scope.** Given that T19 step 1 already performs the post-merge check, is the
   remaining work still worth a task — or is it one sentence added to step 7 of the sequence
   table, in the same class as Issue 1?

---

## Incidental — outside the audit's scope, and not a verdict

Recorded because it was read directly from a public run log while verifying Issue 3, and
because it bears on a constraint D21 wrote for itself. It is **not** a finding, it is **not** a
verdict on anything the Auditor raised, and no action is proposed here.

D21's _Open questions carried to the task_ states two constraints on the generated key: _"it
must not print the value, and it must run before the first step that imports Django settings."_
The second holds — the generation step is step 2, before `uv run pytest`. The first does not:
`$GITHUB_ENV` values are not masked by the runner, so the generated key appears in cleartext in
the `env:` group of **every subsequent step** of the public run log. From run `32280676936`,
the `Set up Python` step:

```
env:
  …
  SECRET_KEY: pP3sBnlN/Jwh3n/AbAgHHLID4UjuD8DYGJdUTJcZ/HWedfhG5k7cQg8n8+RJ93Yh
```

The generation step itself does not leak it — the runner echoes the `run:` line unexpanded. The
consequence is bounded by D21's own reasoning (_"The value protects nothing"_): the value is
random per run and signs sessions against a throwaway Postgres whose credentials are already
literal in the file. Whether the stated constraint should be met anyway, dropped, or reworded is
a question for an Auditor or Planner session, not for this one.

---

## Handoff

**Verified.** `docs/audits/2026-08-20-audit-t18-t9-conflict.md` — its Answer (conclusion plus
five measured bullets), 3 Issues, 1 Open Decision and 8 Observations, against the scoped
entries of `docs/plan/plan_toolchain-ci-security_2026-08-15.md`, the two `.github/` files,
GitHub's current Dependabot and Actions documentation, and the live repository measured via
`gh` on 2026-08-20.

**Counts.** Original report: HOLDS **7** · DOES NOT HOLD **2** · PARTIAL **3** · OPEN QUESTIONS
**3**. Addendum (the Auditor's four self-corrections): HOLDS **3** · DOES NOT HOLD **1**.

**One defect changed class after the addendum.** T19 step 1's query is not a documentation
problem. Every other item in this report is.

**The audit's central answer stands.** T18 and T9 do not conflict. Nothing found here blocks the
merge.

**What changed for the next session.**

- Issue 1 is smaller than the audit sized it. Issue 2 as written is wrong — T19 step 1 already
  is the post-merge check its Direction asks for — but the addendum replaces it with a measured
  defect in that same step: the query returns alerts of every state, so it halts on every path.
  `?state=open` is the whole repair.
- Issue 3's Direction is right and its evidence for bullet A must be replaced before it is
  written into the plan: cite the run log's `GITHUB_TOKEN Permissions` group, not the checkout
  step.
- One acceptance criterion the audit marked verified is not verified, and the action that would
  verify it is a single push.

**Open questions still awaiting the user's answer.** The three listed in Part 2.

**Files the next session should attach.**

- `docs/plan/plan_toolchain-ci-security_2026-08-15.md` — _Verification debts_, D18 (amendment 1),
  T9, T18, T19, _Order of execution_
- `docs/audits/2026-08-20-audit-t18-t9-conflict.md`
- this report
- `.github/workflows/ci.yml`, `.github/dependabot.yml`

**Recommended persona for the next session: Planner.** Every surviving item is an edit to the
plan — restating the closing paragraph's label without deleting its true clauses, giving step 7
of the sequence a one-line criterion, and striking the three settled debts with the corrected
evidence for the `permissions` one. Decision A is the user's, and its exposure is now measured
rather than assumed, which may make option 1 more defensible than the table presented it.
