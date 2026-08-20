# Audit — `docs/plan/plan_toolchain-ci-security_2026-08-15.md`, decisions D2–D9a

**Date**: 2026-08-16
**Persona**: Auditor (read-only). No project file was modified; this report and its
Portuguese counterpart are the only files written.
**Primary target**: the closed decisions **D2 to D9a** of
`docs/plan/plan_toolchain-ci-security_2026-08-15.md`.

**Explicitly out of scope for this pass**, at the user's instruction:

- **D1** (adoption of `uv`) — settled, treated as the premise everything else is re-examined
  against. No evidence was found against it.
- **D10–D15** — the open decisions. Their option space is the subject of a separate session.

**The question this audit answers.** The closed decisions were taken while reacting to a
superseded plan. Two premises changed afterwards: `uv` was adopted, and the whole stack is
candidate for an upgrade. Given those two premises, does each closed decision still hold, and
where was the option space narrowed without justification?

---

## Evidence legend

Every finding below carries one or more tags. **Nothing in this report is asserted from
training data without being marked as such.**

| Tag | Meaning |
| --- | --- |
| `[WEB]` | Read from official documentation or an authoritative API **in this session**. URL given. |
| `[MEASURED]` | A command executed on this machine in this session. Output shown or quoted. |
| `[FILE]` | Read from a file in this repository in this session. |
| `[REASONING]` | My inference from the above. Not a citation. Marked wherever it appears. |
| `[TRAINING]` | Stated from model training data. **Used nowhere in this report as the basis of a finding.** |

---

## Section 0 — Version reality, verified this session

Read from the PyPI JSON API, the GitHub REST API and `endoflife.date` on 2026-08-16.
`[WEB]` `[MEASURED]`

| Component | Project pins | Current release | Note |
| --- | --- | --- | --- |
| Python (image) | `3.14.6-slim` `[FILE]` | 3.14.7 (2026-08-05) | one patch behind |
| Django | `6.0.7` `[FILE]` | **6.1** (2026-08-05); last 6.0 patch is **6.0.8** | 6.0 mainstream support **ended 2026-08-04**; extended (security) support to 2027-04 |
| pytest | `9.1.1` | 9.1.1 | current |
| pytest-django | `4.12.0` | **4.14.0** | two minors behind |
| psycopg / -binary / -pool | `3.3.4` / `3.3.4` / `3.3.1` | same | current |
| argon2-cffi | `25.1.0` | 25.1.0 | current |
| python-dotenv | `1.2.2` | 1.2.2 | current |
| `ruff` | (to be pinned) | **0.16.3** (2026-08-13) | the version the plan measured is still the latest |
| `uv` | (to be pinned) | **0.12.5** (2026-08-14) | host has 0.10.9 `[MEASURED]`; plan cites 0.11.30 in the venv |
| `actions/checkout` | plan pins `v4` | **v7.0.1** (2026-07-20) | three majors behind |
| `actions/setup-python` | plan pins `v5` | **v7.0.0** (2026-07-20) | two majors behind |
| `astral-sh/setup-uv` | not considered | v10.0.1 (2026-08-14) | see Issue 3 |

Sources: `https://pypi.org/pypi/<pkg>/json`; `gh api repos/<owner>/<repo>/releases/latest`;
`https://www.djangoproject.com/download/`; `https://endoflife.date/api/python.json`.

### D9's measurements were re-run, not cited

The plan's own instruction was that any finding depending on its numbers must re-measure.
Executed from `django_version/` with `uvx ruff@0.16.3`, nothing installed, no file modified
`[MEASURED]`:

| Measurement | Plan states | Reproduced today |
| --- | --- | --- |
| Default rule set, whole project | 67 findings, 26 fixable | **67 findings, 26 fixable** |
| Default rule set, `migrations/` excluded | 38 | **38** |
| `RUF012` inside the two `migrations/` dirs | 28 | **28** (14 + 14) |
| `select = ["E501"]` alone | 176 | **176** |

Executed in the container `[MEASURED]`:

- `python -V` → `Python 3.14.6`; `django.get_version()` → `6.0.7`.
- `manage.py makemigrations --check` → `No changes detected`, exit 0.
- `manage.py check --deploy` → 7 warnings (W004, W008, W009, W012, W016, W018, W020), exit 0.

**Every empirical claim D7, D9 and D9a rest on reproduces exactly.** The audit below does not
dispute any of them.

---

# Issues — action required

## Issue 1 — D3 rejected the system-environment alternative on an evidence claim that uv's own Docker guide contradicts

**What.** D3 sets aside `UV_PROJECT_ENVIRONMENT=/usr/local` (installing into the image's system
Python) with this stated reason: *"Set aside on evidence grounds: uv's environment-variable
reference describes the variable as pointing at a *virtual environment* and does not confirm a
system prefix."* `[FILE]` — plan, D3, *Alternatives considered*.

uv's *Using uv in Docker* guide states the opposite, in the section on using the environment
`[WEB]` — https://docs.astral.sh/uv/guides/integration/docker/:

> "Alternatively, the `UV_PROJECT_ENVIRONMENT` setting can be set before syncing to install to
> the system Python environment and skip environment activation entirely."

**Rule violated.** The plan's own *Evidence discipline* section ("Every mechanism is verified in
the current session against … official documentation for the pinned version"), and `AUDITOR.md`'s
"do not bluff" clause applied to the Planner persona. `CLAUDE.md` Rule 2.

**Why it matters.** The rejected option was rejected for being undocumented. It is documented, on
the exact page D3 cites for its other three claims. That does not make the option better than
`/opt/venv` — but it removes the discriminator D3 used, so the choice was never actually made on
its merits. Anyone reading D3 later will believe uv does not support the system-prefix form, and
that belief is false.

**Direction.** Re-state D3's rejection on a real discriminator, or re-take the choice. The
option space is laid out in **Open Decision G**. Note the decision *outcome* (an environment
outside the bind mount) is not in dispute here — only the reason recorded for excluding one
alternative.

---

## Issue 2 — D6's cost argument against building the image in CI rests on an incomplete fact

**What.** D6 states `[FILE]`:

> "Layer caching does not persist between runner VMs, so an in-CI build starts from scratch each
> time: pulling the base image, running `apt-get`, and installing every package."

That is true only of a build run on the default `docker` driver with no cache backend
configured. Docker documents a GitHub Actions cache backend for BuildKit `[WEB]` —
https://docs.docker.com/build/cache/backends/gha/ — enabled with `cache-from: type=gha` and
`cache-to: type=gha,mode=max`, with the documented constraint: *"This cache storage backend is
not supported with the default `docker` driver"* (a buildx builder is required), and documented
limits on cache size, branch scope and API rate limiting.

**Rule violated.** Same as Issue 1: the plan's *Evidence discipline*, and `CLAUDE.md` Rule 9
(do not describe tool behavior from memory).

**Why it matters.** That sentence does two jobs in D6: it justifies preferring a plain build step
over running the suite inside the image, and it sets the expectation that the build step is
expensive. Both were decided against a cost that is configurable, not fixed. The plan already
carries an open question — *"The `docker build` step's duration is not measured"* — which is the
right instinct; but that duration is a function of a caching decision D6 never knew it was
taking.

**Direction.** The measurement D6 defers should be taken against both shapes (uncached build, and
buildx with `type=gha`), and the option that follows is laid out in **Open Decision B**.

---

## Issue 3 — D6 never states how `uv` reaches the CI runner, and keeps `actions/setup-python` without asking whether it is still needed

**What.** D6 decides that `ci.yml` *"keeps installing dependencies on the GitHub runner — `uv
sync --locked` replacing `pip install -r requirements.txt`"* `[FILE]`. `ci.yml` today has two
steps that matter here `[FILE]` — `.github/workflows/ci.yml`:

```yaml
- name: Set up Python
  uses: actions/setup-python@v5
  with:
    python-version: "3.14.6"

- name: Install dependencies
  run: pip install -r requirements.txt
```

Nothing in D6 says what puts the `uv` binary on the runner, and nothing re-examines the
`setup-python` step. uv's own GitHub Actions guide `[WEB]` —
https://docs.astral.sh/uv/guides/integration/github/ — documents:

- installing uv with the `astral-sh/setup-uv` action, pinned by commit SHA in the official
  example, with *"It is considered best practice to pin to a specific uv version"*;
- caching via `enable-cache: true` on that action;
- **two** ways of providing Python: `uv python install` (which respects the project's pinned
  version), or `actions/setup-python` with `python-version-file` pointing at `.python-version`
  or `pyproject.toml`.

`astral-sh/setup-uv` is at v10.0.1 `[MEASURED]` (`gh api`).

**Rule violated.** `CLAUDE.md` Rule 1 (a missing mechanism is a gap, not a detail). The plan's own
standard: D3 was not considered closed until the exact mechanism for installing uv **in the
image** was cited; the runner half received no equivalent treatment.

**Why it matters.** Three separate consequences, none of them cosmetic:

1. The Developer will improvise the install (curl installer, `pip install uv`, or the action) —
   and `pip install uv` is precisely the pattern D1 recorded as a hazard ("a tool that manages
   virtual environments does not belong inside the one it manages").
2. **CI caching disappears from the plan entirely.** The superseded plan had a `cache: pip`
   task; audit Issue 11 and the verification both worked on it. After D1, `cache: pip` is
   meaningless — and no decision replaced it. `enable-cache: true` on `setup-uv` is the
   documented replacement and appears nowhere.
3. It interacts with **D8 Item 2**: if `setup-uv` is adopted, there is a fourth action to pin,
   and D8's "all three actions" rule silently becomes a rule about four.

**Direction.** The runner-provisioning mechanism needs the same treatment D3 gave the image.
Option space in **Open Decision A**.

---

## Issue 4 — D8 Item 2 would SHA-pin two GitHub-maintained actions at majors that are two and three releases old, in a repository with no Dependabot configuration

**What.** D8 Item 2 resolves and pins `actions/checkout@v4` and `actions/setup-python@v5` to
commit SHAs, and records the accepted cost: *"`actions/checkout` and `actions/setup-python` stop
receiving fixes published by moving their tags … There is no `.github/dependabot.yml` in this
repository — verified … — so updates are manual today."* `[FILE]`

Two facts change the shape of that cost:

- **The majors being pinned are stale.** Latest releases, read this session `[MEASURED]`
  (`gh api repos/<r>/releases/latest`): `actions/checkout` → **v7.0.1** (2026-07-20);
  `actions/setup-python` → **v7.0.0** (2026-07-20). The plan pins v4 and v5. Its instruction to
  *"re-resolve at implementation time"* does not help: re-resolving `v4` yields v4.
- **Dependabot does handle SHA pins.** GitHub's changelog `[WEB]` —
  https://github.blog/changelog/2022-10-31-dependabot-now-updates-comments-in-github-actions-workflows-referencing-action-versions/:
  *"Dependabot will now update the semver version in comments when updating Actions workflows
  with a commit SHA version."* (The current Dependabot docs page for GitHub Actions does not
  restate this `[WEB]` — which is why the plan's verification debt was left open; the changelog
  is the official source that closes it.)

**Rule violated.** `AUDITOR.md`, *DOCUMENTED ≠ SOUND*: D8 correctly identified SHA pinning as the
hardening measure, and then applied it to a version state nobody checked. `conventions.md`,
*Stack and versions*: a version choice is a decision, and `v4`/`v5` were inherited from the
existing `ci.yml`, never chosen.

**Why it matters.** SHA pinning converts "the maintainer might not update this" into "this
cannot update itself". Applied to a current major, that is the intended trade. Applied to a major
three releases old, it freezes a known-stale dependency permanently, and the durability argument
D8 used for Item 1 ("the effective permission stops living in a settings screen") argues against
doing it without also deciding the update path.

**Direction.** Item 2 needs to be paired with two things it currently lacks: a major-version
decision for the two GitHub-maintained actions, and a decision on `.github/dependabot.yml`.
Option space in **Open Decision C**.

---

## Issue 5 — D2 moves tool configuration into `pyproject.toml` but leaves `pytest.ini` outside the decision, and pytest's precedence rules make that omission load-bearing

**What.** D2 states that tool configuration *"(`[tool.ruff]`, `[tool.mypy]`,
`[tool.coverage.*]`) lives in that same file, replacing the four standalone config files the
superseded plan would have created."* `[FILE]` `django_version/pytest.ini` already exists on
disk `[FILE]` and is named nowhere in D2 — neither as staying, nor as moving.

pytest's configuration reference `[WEB]` — https://docs.pytest.org/en/stable/reference/customize.html
— lists the candidates in precedence order — `pytest.toml`, `.pytest.toml`, `pytest.ini`,
`.pytest.ini`, `pyproject.toml`, `tox.ini`, `setup.cfg` — and states:

> "Options from multiple `configfiles` candidates are never merged - the first match wins."

The same page records that `pytest.toml` was *"Added in version 9.0"*, i.e. it exists in the
pinned pytest 9.1.1.

**Rule violated.** `CLAUDE.md` Rule 1 (the plan leaves an ambiguity that the Developer will have
to resolve by assumption) and `conventions.md`'s general principle that a rule lives in exactly
one place.

**Why it matters.** The failure mode is silent, and it is the same class D2 exists to prevent.
Once `pyproject.toml` is in `django_version/`, the natural next edit — by the user, by a future
agent, or by a tool's own `init` — is to add `[tool.pytest.ini_options]` to it. With `pytest.ini`
present, that section is **ignored entirely**, with no warning, and `rootdir` continues to be
derived from `pytest.ini`. A test-suite configuration that is read by nobody is exactly the
"green here, red there" drift D2's own reasoning about mypy discovery is about.

**Direction.** D2 needs one line stating which file is pytest's configuration home after the
migration. Option space in **Open Decision F**. Note this is not an argument for moving it —
staying is defensible; the finding is that nothing decided it.

---

# Open Decisions — user choice needed

The user explicitly asked for a recommendation on each. Each block therefore ends with
**My opinion** (clearly marked as opinion), **Where I could be wrong**, and **When disagreeing
with me is legitimate**.

A reminder of the user's own rule, applied throughout: *editing `ci.yml`, `Dockerfile`,
`pytest.ini` or `pyproject.toml` is not a con* — it is the work. Cons below are CI time, real
risk, recurring maintenance, or lost capability.

---

## Open Decision A — how CI provisions `uv` and Python (gap under D6)

Sources for every mechanism: uv's GitHub Actions guide `[WEB]`
(https://docs.astral.sh/uv/guides/integration/github/), `gh api` release data `[MEASURED]`.

**Option A1 — `astral-sh/setup-uv` action, `enable-cache: true`, keep `actions/setup-python`**

| Pros | Cons |
| --- | --- |
| The path uv's own documentation shows first | A fourth action in the workflow, which D8 Item 2 must then cover |
| Restores dependency caching, which vanished from the plan when `cache: pip` died with pip | Two components now assert a Python version (the action's input and `requires-python`), which can disagree |
| The action is versioned and SHA-pinnable like the others | One more third-party (Astral-maintained) action in the trust boundary |

**Option A2 — `astral-sh/setup-uv` + `uv python install`, drop `actions/setup-python`**

| Pros | Cons |
| --- | --- |
| One source of truth for the Python version — the project's own pin, not a duplicated literal in `ci.yml` | uv downloads a Python build on each run unless cached; net time not measured here |
| One fewer GitHub-maintained action to pin and keep current (see Issue 4) | The Python build uv installs is a python-build-standalone distribution, not the one `actions/setup-python` provides — a different binary than today's CI |
| Matches the container, where uv also owns the environment | The image still uses the `python:3.14.6-slim` base, so "one source of truth" is only true within CI |

**Option A3 — install uv with the standalone installer in a `run:` step**

| Pros | Cons |
| --- | --- |
| No new action in the trust boundary | Version pinning becomes a hand-written URL/env var nobody's tooling watches |
| Identical mechanism on any CI provider | No caching unless hand-built |
| Fully visible in the workflow file, nothing hidden in an action | A `curl \| sh` step in a workflow whose entire purpose is supply-chain hardening |

**Option A4 — no separate uv install: run CI inside the built image** — this is Open Decision B's
option B4 and is decided there, not here.

**My opinion (opinion, not a finding).** A1. It restores the caching the replanning silently
dropped, and it changes the least about how CI resolves Python while the stack-update question
(Open Decision I) is still open. A2 is the tidier end state and I would expect to migrate to it
once the Python version lives in `pyproject.toml`'s `requires-python` and a `.python-version`
file — but doing both in the same change makes a CI failure ambiguous.
**Where I could be wrong:** I did not measure `uv python install`'s cost on a cold runner, so A2's
only stated con is unquantified. **Legitimate disagreement:** if you prefer one mechanism to own
Python everywhere and are willing to absorb one noisy CI run to get it, A2 straight away is a
sound call.

---

## Open Decision B — whether and how CI builds the image (re-opening D6's second half)

Sources: Docker's GHA cache backend page `[WEB]`
(https://docs.docker.com/build/cache/backends/gha/); the repo's own `ci.yml` and
`docker-compose.yml` `[FILE]`.

**Option B1 — no image build in CI (status quo)**

| Pros | Cons |
| --- | --- |
| Zero added CI minutes | Two of this plan's acceptance criteria ("the image still builds") stay unverifiable by any gate |
| Nothing new can break the pipeline | A `Dockerfile` regression is discovered by a human, on their machine, at an arbitrary later time |
| Consistent with the recorded habit of walking the quickstart manually before commits | The uv migration changes the `Dockerfile` substantially; this is the worst moment to have no gate on it |

**Option B2 — plain `docker build` step, uncached (D6 as written)**

| Pros | Cons |
| --- | --- |
| Simplest possible step; no builder setup, no cache keys | Pays a full `apt-get` + full dependency install on every push, forever |
| Proves the `Dockerfile` builds, which is exactly the criterion in question | The cost lands on every branch push, including docs-only commits |
| No cache to go stale or to debug | Slowest of the three build shapes |

**Option B3 — `docker/setup-buildx-action` + `docker/build-push-action` with `cache-from/to: type=gha`**

| Pros | Cons |
| --- | --- |
| Same guarantee as B2 at a fraction of the steady-state time — layers are reused across runs | Two more third-party actions in the trust boundary, both needing SHA pins |
| Cache is scoped and evicted by GitHub; no volume to clean up | Documented limits apply: repository cache budget, branch-scoped visibility, API rate limiting |
| The cache also makes B4 affordable if you later want it | A cache miss (new branch, evicted entry) silently costs B2's full time — measurement must cover both cases |

**Option B4 — build the image, then run the suite and the tools inside it**

| Pros | Cons |
| --- | --- |
| Makes root `CLAUDE.md` Rule 12 literally true in CI too — one environment, not two | Highest CI time even with cache; the container must reach the `postgres` service, which is a new wiring question |
| Kills the Ubuntu-vs-Debian divergence D6 names as the remaining gap | Debugging a red CI run gains a layer of indirection |
| Any tool added later is automatically covered, because it is in the image (D4 already put it there) | Furthest from the current workflow, so the migration risk concentrates in one change |

**My opinion (opinion).** B3. D6 chose B2 partly on a fact that Issue 2 shows to be
configurable, and the plan's own deferred measurement is the right way to settle it — but it
should be taken on B3, not only B2. If the measured B3 steady-state build is under roughly a
minute, the "only on `main`" fallback D6 holds in reserve stops being needed at all.
**Where I could be wrong:** I have not measured this repository's build, cached or uncached; a
`slim` base with three `apt-get` packages and a lockfile install may already be fast enough that
B2's simplicity wins outright. **Legitimate disagreement:** preferring B2 to keep the trust
boundary at three actions instead of five is a coherent security position, and it is the same
reasoning D8 Item 2 rests on.

---

## Open Decision C — action pinning strategy (re-opening D8 Item 2)

Sources: `gh api` release data `[MEASURED]`; GitHub's Dependabot changelog `[WEB]`; GitHub's
immutable-releases changelog `[WEB]`
(https://github.blog/changelog/2025-10-28-immutable-releases-are-now-generally-available/ — GA
2025-10-28; *"tags are protected from being moved or deleted"* for releases published under it,
where the publishing repository has enabled it).

**Option C1 — SHA-pin all three actions at their current majors (D8 as written)**

| Pros | Cons |
| --- | --- |
| Enables the repository's `sha_pinning_required` toggle, which D8 correctly identified | Freezes `checkout` at v4 and `setup-python` at v5 while v7/v7 exist (Issue 4) |
| One rule, no per-action judgement to remember | Without Dependabot, updates depend on someone remembering to look |
| Immutable by construction, independent of any GitHub feature flag | The `# vX.Y.Z` comment beside each SHA becomes stale the moment the SHA is bumped by hand |

**Option C2 — bump to current majors first, then SHA-pin all, and add `.github/dependabot.yml`**

| Pros | Cons |
| --- | --- |
| Same hardening as C1 without inheriting a stale dependency | Dependabot PRs arrive on a cadence and someone must merge them |
| Dependabot updates SHA pins **and** the version comment `[WEB]` — the maintenance cost D8 accepted becomes bounded | A major bump of `checkout`/`setup-python` is a behavior change to verify once |
| The update path is versioned in the repository, matching D8 Item 1's own durability argument | Adds a second automation surface to understand |

**Option C3 — SHA-pin only `schneegans/dynamic-badges-action`; tag-pin the GitHub-maintained two**

| Pros | Cons |
| --- | --- |
| Treats the only action that combines third-party authorship with a live credential | `sha_pinning_required` becomes unusable, which is what decided D8 against this |
| `@v7`/`@v7` stay readable and keep receiving fixes automatically | The rule lives in a maintainer's memory, not in a platform setting |
| Smallest ongoing maintenance of all options | Inconsistent with the plan's own framing of the pipeline as a supply-chain surface |

**Option C4 — remove the badge step, then pin whatever remains**

| Pros | Cons |
| --- | --- |
| Dissolves the credential exposure instead of managing it — no `GIST_SECRET` in any job | Loses the live test-count badge, which is deliberate portfolio work |
| Two actions left, both GitHub-maintained | The README keeps only the native workflow-status badge |
| No third-party action in the pipeline at all | Does not answer the pinning question for the remaining two |

**My opinion (opinion).** C2. Issue 4 is the whole reason: C1's hardening is real, but applied to
v4/v5 it locks in staleness, and the fact that closes the plan's own verification debt —
Dependabot does update SHA pins and their comments — removes the cost that made C1 feel like the
cheap option. **Where I could be wrong:** I did not verify that `checkout` v7 and `setup-python`
v7 are drop-in for this workflow; a major bump can change defaults, and that verification is a
real (one-time) cost I am waving at rather than measuring. **Legitimate disagreement:** if you do
not want a bot opening PRs on a portfolio repository, C1 plus a calendar reminder is defensible —
but then the major bump should still happen before the SHAs are written.

---

## Open Decision D — token permissions granularity (re-opening D8 Item 1)

D8 set `permissions: {}` aside because *"whether `actions/checkout@v4` still functions with zero
scopes on this repository was **not verified**"* `[FILE]`.

**What I found, and its limits.** Multiple secondary sources state that public repositories
retain implicit read access to `contents` regardless of the `permissions:` block `[WEB]`, so
`checkout` works under `permissions: {}`. **I did not find this stated in GitHub's own
documentation**, and I am flagging that rather than presenting it as settled. `[REASONING]` on
the gap between the two.

| Option | Pros | Cons |
| --- | --- | --- |
| **D1 — `permissions: contents: read`** (plan as written) | Drops `packages: read`, the one extra scope measured today; unambiguous to read; certain to work | Grants a scope the workflow may not need |
| **D2 — `permissions: {}` at workflow level** | Strictest documented form; nothing to re-audit when a step is added | Rests on a behavior I could only confirm from secondary sources; a wrong answer fails the first step of every push |
| **D3 — `permissions: {}` at workflow level, `contents: read` on the `test` job** | Default-deny with an explicit, reviewable grant; a future job starts from zero | Two blocks instead of one for a single-job workflow |

**My opinion (opinion).** D1 now, and treat D2/D3 as a cheap experiment on a branch later. The
measured security delta between all three is close to nothing on a public repository that
publishes no package, so buying certainty is worth more than buying strictness here.
**Where I could be wrong:** if the secondary sources are right — and they are consistent with
each other — D3 is strictly better and costs one extra line. **Legitimate disagreement:**
running one throwaway push to settle it empirically is faster than this paragraph, and if you do
that and it passes, D3 is the better answer.

---

## Open Decision E — trigger shape and run volume (re-opening D8 Item 3)

D8 accepted *"a noisier Actions history"* and duplicate runs while a PR is open. Two standard
mitigations exist and neither was put on the table.

| Option | Pros | Cons |
| --- | --- | --- |
| **E1 — `push` + `pull_request`** (plan as written) | Tests the merge result before the button is pressed; both README badges point at `main` | Two runs per push while a PR is open; superseded runs keep executing to completion |
| **E2 — E1 plus a `concurrency` group with `cancel-in-progress`** | A new push cancels the stale run instead of racing it; directly answers the "noisier history" cost | A cancelled run shows as cancelled, not failed — one more state to read |
| **E3 — E1 plus `paths-ignore` for docs-only paths** | This repository commits documentation heavily; CI on a `docs/` edit proves nothing | A path filter that is wrong is invisible — it skips a run you wanted; `paths-ignore` interacts with required checks if you ever add them |
| **E4 — `pull_request` + `push` restricted to `main`** | Removes duplicate runs entirely | No CI at all on a branch with no open PR, which is most of this repository's history `[FILE]` — the plan's `gh run list` reading shows 13 of 15 runs on the feature branch |

**My opinion (opinion).** E1 + E2. The concurrency group is three lines, costs nothing when it
never fires, and it is aimed exactly at the cost D8 wrote down and accepted. I would hold E3
until the `docker build` step exists — that is the step whose cost makes path filtering worth
the risk. **Where I could be wrong:** with one developer pushing in batches, duplicate runs may
never actually overlap, making E2 pure ceremony. **Legitimate disagreement:** wanting every run
to complete so the history is a full record is a real preference, and it excludes E2.

---

## Open Decision F — where pytest's configuration lives after `pyproject.toml` arrives (gap under D2, Issue 5)

Source: pytest's configuration reference `[WEB]`.

| Option | Pros | Cons |
| --- | --- | --- |
| **F1 — `pytest.ini` stays, and D2 says so explicitly** | Zero behavior change; `rootdir` stays where it is; highest-precedence file after the new `pytest.toml` forms | Two configuration homes in one directory; the "one file" argument D2 makes for the other tools does not hold for the suite |
| **F2 — move to `[tool.pytest.ini_options]` in `pyproject.toml`** | One configuration file, which is D2's stated goal; `rootdir` becomes the `pyproject.toml` directory — the same directory, so no change in practice | INI-style values inside TOML (`addopts` as a multi-line string) read less naturally than `pytest.ini` |
| **F3 — move to `pytest.toml`** (new in pytest 9.0 `[WEB]`) | Native TOML, no `[tool.…]` nesting; highest precedence, so nothing can silently shadow it | Newest of the three formats — the smallest body of examples and tooling support to lean on |

**My opinion (opinion).** F2. D2's whole argument is that one file beats four, and the pytest
suite is the one tool configuration that would sit outside it for no stated reason. The
`addopts` readability cost is the only real one and it is small.
**Where I could be wrong:** if any editor or extension you rely on discovers tests by looking for
`pytest.ini`, F2 breaks that and I have not checked your VS Code setup. **Legitimate
disagreement:** F1 with one explicit sentence in D2 fully closes Issue 5 — the finding is the
silence, not the file.

---

## Open Decision G — where the container's environment lives (re-opening D3 on correct evidence, Issue 1)

Sources: uv's Docker guide `[WEB]` — all four remedies below are named on that page.

| Option | Pros | Cons |
| --- | --- | --- |
| **G1 — `UV_PROJECT_ENVIRONMENT=/opt/venv`, on `PATH`** (plan as written) | Both bind-mount failure modes become structurally impossible; declared in the `Dockerfile` where a reader looks; `docker-compose exec web pytest` keeps working verbatim | An unconventional path a newcomer will not expect; `/opt/venv` acquires an owner, which D15 must then reconcile |
| **G2 — `UV_PROJECT_ENVIRONMENT` set to the system prefix** | Documented by uv for exactly this purpose (Issue 1); closest to today's `pip install` image; no `PATH` manipulation | No isolation between application and system packages inside the image; a `uv sync` inside the container mutates the system environment |
| **G3 — anonymous volume over `/app/.venv`** | Keeps the conventional `.venv` path; first remedy uv's guide names | The mechanism is invisible from the `Dockerfile`; anonymous volumes go stale until `docker compose down -v` — the silent-drift class D1 exists to remove |
| **G4 — `docker compose watch` with `ignore: [.venv/]`** | uv's guide names it; no bind mount to fight, so no shadowing at all | Replaces the bind-mount workflow the project uses today; `watch` is a different development loop, not a config tweak |

**My opinion (opinion).** G1 stands — the decision was right; only its rejection of G2 was
argued badly. G1 is the only option where both failure modes are impossible rather than merely
avoided, and that is worth an unconventional path. **Where I could be wrong:** G2's isolation
cost is close to theoretical inside a single-purpose container, and it would remove one
interaction with the still-open D15. **Legitimate disagreement:** if D15 concludes that a
non-root user plus `/opt/venv` ownership is fiddly, revisiting G2 on that ground is
legitimate — it just has to be argued on ownership, not on documentation.

---

## Open Decision H — how the quality tools are provisioned (a question `uv` created that nobody asked)

D5 places every tool in a single `dev` group `[FILE]`. `uv` makes a second shape possible that
did not exist under `pip`, and the plan never names it. Sources: uv settings reference `[WEB]`
(https://docs.astral.sh/uv/reference/settings/), which documents `required-version`
(*"Enforce a requirement on the version of uv … uv will exit with an error"*) and
`default-groups`; ruff's settings reference `[WEB]` (https://docs.astral.sh/ruff/settings/),
which documents the same idea for ruff: *"Enforce a requirement on the version of Ruff, to
enforce at runtime."*

| Option | Pros | Cons |
| --- | --- | --- |
| **H1 — every tool in the `dev` group** (plan as written) | One lockfile pins every tool exactly, in CI, in the image and on the host; `uv sync --locked` fails loudly on mismatch; tools are present in the image, which D4 requires | The linter's own transitive dependencies enter the project's resolution graph |
| **H2 — tools run via `uvx tool@version` / `uv tool install`** | Tools stay out of the project graph entirely; trivially runnable at a different version for a one-off measurement | Versions are pinned in whatever file invokes them (`ci.yml`, a hook config) — several places instead of one, and no lockfile guarantees them |
| **H3 — H1 plus `required-version` for ruff (and `[tool.uv] required-version`)** | Closes D9's one accepted risk at the config layer: a ruff whose default rule set changed cannot run silently against this project | One more version literal to bump alongside the lockfile entry — two places for one number |

**My opinion (opinion).** H1, and H3 only if D9's version-dependence keeps bothering you. The
lockfile already gives the guarantee; `required-version` mostly converts a lockfile mismatch into
an earlier, clearer error. H2 is the wrong shape here because D4 deliberately put the tools in the
image. **Where I could be wrong:** I have not measured how much the tools inflate the resolution
graph or the image; if the image grows materially past its measured 285 MB, that changes the
weighting. **Legitimate disagreement:** using `uvx` for something genuinely occasional — a
one-off security scan, say — while keeping ruff and pytest in the group is a reasonable hybrid.

---

## Open Decision I — the stack update, scoped to what it changes inside D2–D9a

The user's prompt records this as *"a proposal of mine, not a decision taken"*, and
`conventions.md` requires a version change to be an explicit, approved architectural decision.
The full stack decision belongs with the D10–D15 session; what follows is only the part that
lands inside the decisions audited here. All version facts from Section 0 `[WEB]` `[MEASURED]`.

| Option | Pros | Cons |
| --- | --- | --- |
| **I1 — freeze versions, migrate to `uv` at exactly today's pins** | The migration's diff contains one variable — the tooling — so a failure is unambiguous | Locks in Django 6.0.7 when 6.0.8 exists and 6.0's mainstream support ended 2026-08-04; the upgrade then happens later, against a `uv.lock` that must be redone anyway |
| **I2 — patch-level only (Django 6.0.8, Python 3.14.7, pytest-django 4.14.0), then migrate** | Removes the "pinned below the last patch of a series in security-only support" state; patch upgrades carry the smallest behavior risk | Still on a series whose mainstream support has ended, so the 6.1 question returns within months |
| **I3 — full upgrade to Django 6.1 as part of the migration** | The venv is being recreated regardless, so the marginal cost is genuinely low; 6.1 supports Python 3.12–3.14 | 6.1 has real backwards-incompatible changes to verify, e.g. `EMAIL_*` settings deprecated in favour of `MAILERS`, `first()`/`last()` ordering, admin `wide` class removal `[WEB]` |
| **I4 — move to the LTS series (5.2)** | The only LTS on offer; extended support to 2028-04 | A downgrade from the current code's Django 6.0 baseline; contradicts the project's own positioning on a modern stack |

**Two concrete interactions with the decisions audited here** `[WEB]` — Django 6.1 release notes:

1. **D7's baseline moves.** Django 6.1 adds `security.W027` (CSP nonce without the context
   processor) and a **deployment-only** `mail.E001` — an ERROR-class check. D7 chose to block at
   ERROR precisely so the step has teeth; under 6.1 that choice becomes materially more
   significant, and the "7 warnings, exit 0" baseline must be re-measured after any upgrade.
2. **D7's step gains a dependency.** From the 6.1 backwards-incompatible changes: *"The `check`
   management command now supplies all `databases` if not specified. Callers should be prepared
   for databases to be accessed."* D7's `check --deploy` step is therefore no longer safely
   database-independent under 6.1 — in CI the `postgres` service exists, so it works, but the
   reasoning D7 recorded stops being true.

**My opinion (opinion).** I2 during the migration, I3 as its own decision immediately after. The
user's argument — the venv is being recreated anyway, so version bumps are nearly free — is right
about *cost* and does not address *diagnosis*: if the uv migration and a Django minor upgrade land
in one change and CI goes red, there is no cheap way to tell which caused it. Patch bumps do not
carry that risk; a minor with documented breaking changes does.
**Where I could be wrong:** I have not audited this codebase against the 6.1 incompatibility list
(no `EMAIL_*` settings exist in `config/settings.py` `[FILE]`, and the admin change is cosmetic),
so the real 6.1 risk here may be near zero, which would make I3-in-one-step fine. **Legitimate
disagreement:** if you would rather pay one confusing debugging session than run two migrations,
I3 straight away is a defensible call — and it is your call, not mine, under `conventions.md`.

---

# Observations / Learning Notes — no action required

**O1 — D9 and D9a are the best-evidenced entries in the plan, and they reproduce exactly.**
Re-measured today with the same tool version: 67 / 38 / 28 / 176 `[MEASURED]`. `ruff` 0.16.3 is
still the latest release on PyPI (2026-08-13) `[WEB]`, so the plan's correction of both audits'
stale description of the default rule set remains current.

**O2 — the host `uv` is five minors behind.** `~/.local/bin/uv --version` → `uv 0.10.9
(f675560f3 2026-03-06)` `[MEASURED]`; latest is 0.12.5 `[WEB]`. Not a finding — D1 already
records that the version to pin is fixed at implementation time — noted because measurements
taken with the host binary describe 0.10.9's behavior, not the version that will be pinned.

**O3 — one uv 0.12 behavior change worth knowing, which does not affect anything decided.**
`uv run project/script.py` now starts project discovery from the script's directory `[WEB]` (uv
CHANGELOG). `uv run --directory <dir>` — the mechanism D2 rests on — is still documented in the
current CLI reference: *"Change to the given directory prior to running the command"* `[WEB]`.
The related `--project` flag (*"Discover a project in the given directory"*) exists as a lighter
alternative and is likely relevant to D14, which is not in this pass's scope.

**O4 — `conventions.md`'s version table will be wrong the moment `pyproject.toml` lands.** It
names `django_version/requirements.txt` as where versions are pinned `[FILE]`. No decision in
D2–D9a schedules that edit, and the plan's "items that need no decision" list does not include
it. Mentioned rather than filed as an Issue because the plan has not written its task entries
yet — but it belongs in one.

**O5 — `.dockerignore` and the root `.gitignore` do not yet cover `uv`'s artifacts.** The plan's
task list already covers `.ruff_cache/` and `.mypy_cache/`. `django_version/.dockerignore`
excludes `.venv/` `[FILE]`, which is what matters for D3; `uv.lock` and `pyproject.toml` must
**not** be excluded, since the image needs them. Flagged only so the Developer does not
generalise the "exclude the new files" instinct.

**O6 — `pillow` is still pinned and PostgreSQL 17 is unaffected by the 6.1 question.** Django 6.1
drops support for PostgreSQL 14 `[WEB]`; `docker-compose.yml` runs `postgres:17.10` `[FILE]`, so
the upgrade path is clear on that axis.

**O7 — the `check --deploy` W009 warning is about the prefix, as D7 says.** Reproduced today:
the local run reports W009 `[MEASURED]`, and Django's message names the three conditions
(under 50 characters, under 5 unique characters, or the `django-insecure-` prefix). D7's
measurement that the key clears both numeric thresholds is not re-verified here — it required
reading the key, which I did not do.

**O8 — where this audit deliberately stopped.** D10–D15 were not audited, per instruction. Two
things surfaced while auditing D2–D9a that belong to them and are recorded so they are not
re-derived: (a) if `astral-sh/setup-uv` is adopted (Open Decision A), D8's pinning rule covers
four actions, not three; (b) `uv run --project` may be a lighter alternative to
`uv run --directory` for D14's hook entries.

---

# Decisions that survive

Audited against both new premises — `uv` adopted, stack upgrade proposed — and still correct:

| Decision | Why it survives |
| --- | --- |
| **D2** — `pyproject.toml`, `uv.lock` and `.venv` inside `django_version/` | The two reasons that decided it are structural and unaffected by either premise: the repository holds two Python projects, and `docker-compose.yml`'s `build: .` context would have to be reshaped for a root-level file `[FILE]`. The uv workspace alternative still buys nothing while `oop_version/` is closed. **Issue 5 is a gap inside it, not a reason to move the file.** |
| **D3 (outcome)** — the container environment lives outside the bind mount | Both failure modes it names are real and are structurally removed by the choice; `PATH` keeps every documented `docker-compose exec web …` command working verbatim. Only the *reason recorded for rejecting the system-prefix alternative* is wrong (Issue 1). |
| **D4** — the image installs development dependencies too | Rests on a fact I re-read today: `Dockerfile:31` is `CMD ["python", "manage.py", "runserver", …]` `[FILE]`. It is a development image; there is no production image to keep lean. `uv` does not change this, and the alternative (`--no-dev`) still breaks `docker-compose exec web pytest`. |
| **D5** — a single `dev` group | The argument is about misclassification risk, not about `pip` versus `uv`, so neither premise touches it. `uv sync` installing the default group without being told is confirmed in uv's settings reference (`default-groups`) `[WEB]`. The recorded revisit trigger is the right shape: the migration to named groups is one file. |
| **D6 (direction)** — CI installs on the runner rather than running everything in the image | The reasoning survives on its strongest leg: with `uv sync --locked`, all three environments install from one lockfile and the command fails loudly on mismatch. Only the *cost model* for the added build step is wrong (Issue 2) and the *provisioning mechanism* is missing (Issue 3). |
| **D7** — `makemigrations --check` blocking, `check --deploy` blocking at ERROR | Both re-measured today: `No changes detected`, exit 0; 7 warnings, exit 0 `[MEASURED]`. The gap it closes is structural — `--no-migrations` in `pytest.ini` `[FILE]` means no test can fail for a missing migration. The Django 6.1 interactions in Open Decision I refine this entry; they do not overturn it. |
| **D8 Item 1** — a workflow-level `permissions: contents: read` | The durability argument (the effective permission stops living in an account settings screen) is independent of both premises. Open Decision D is about going further, not about going back. |
| **D8 Item 3** — add the `pull_request` trigger, defer the schedule | The evidence is the repository's own run history, and the deferral reasoning — do not plan a trigger around a `pip-audit` step that does not exist yet — is the same discipline D5 used. Open Decision E adds mitigations for the cost it accepted; it does not dispute the trigger. |
| **D9** — ruff's default rule set, unmodified | The strongest entry in the plan. Re-measured exactly today, against a ruff version that is still the current release `[MEASURED]` `[WEB]`. The accepted cost (a version-dependent default) is correctly bounded by the lockfile. |
| **D9a** — `migrations/` stays linted, `RUF012` suppressed there | Re-measured: 28 of the 29 migration findings are `RUF012`, split 14/14 across the two apps `[MEASURED]`. The reasoning — migrations are the one tree `--no-migrations` guarantees no test ever executes — is stronger after re-reading `pytest.ini`, not weaker. |

**Nothing in D2–D9a needs to be reopened because of `uv` itself.** The two premises that changed
did not invalidate a single decision outcome. What they exposed is narrower and is captured in
the five Issues: one alternative rejected on a false documentation claim, one cost model that is
configurable rather than fixed, one missing mechanism, one version state nobody checked, and one
configuration file nobody assigned a home.

---

# Handoff — next session

**What was audited.** The closed decisions D2 through D9a of
`docs/plan/plan_toolchain-ci-security_2026-08-15.md`, against the real files
(`Dockerfile`, `docker-compose.yml`, `ci.yml`, `requirements.txt`, `pytest.ini`,
`config/settings.py`, root `.gitignore`, `django_version/.dockerignore`), against official
documentation read this session for uv, ruff, pytest, Docker, GitHub Actions and Django, and
against measurements re-run on this machine and inside the container.

**Counts.** 5 Issues · 9 Open Decisions · 8 Observations · 10 decision entries that survive.

**The two Issues that change a decision's content**, rather than its wording: Issue 3 (D6 is not
implementable as written — nothing puts `uv` on the runner) and Issue 4 (D8 Item 2 would pin
stale majors permanently). Issues 1 and 2 correct evidence behind decisions whose outcome may
well stand. Issue 5 is a one-line gap with a silent failure mode.

**What the next session should attach.**

- `docs/plan/plan_toolchain-ci-security_2026-08-15.md` (the plan being revised)
- this audit and its Portuguese counterpart
- `django_version/Dockerfile`, `django_version/docker-compose.yml`,
  `django_version/requirements.txt`, `django_version/pytest.ini`
- `.github/workflows/ci.yml`, root `.gitignore`, `django_version/.dockerignore`
- `.claude/rules/conventions.md` (its version table is affected — Observation O4)

**Recommended next persona.** Planner, to take the nine Open Decisions with the user and amend
D2, D3, D6 and D8 in place. Nothing here is Developer work: three of the five Issues change what
a task would be, and none of the Open Decisions has a single correct answer.

**Carried forward to the D10–D15 session** (not audited here): if `astral-sh/setup-uv` is
adopted, D8's pinning rule covers four actions; `uv run --project` may serve D14 better than
`uv run --directory`; and the stack-update decision (Open Decision I) must be recorded as a
decision under `conventions.md`, not absorbed as a side effect of the migration.
