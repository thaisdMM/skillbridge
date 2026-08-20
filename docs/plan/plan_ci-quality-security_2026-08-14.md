# Plan — CI quality and security tooling, infra hygiene

**Date:** 2026-08-14
**Persona:** Planner
**Acts on:** infra/CI review conducted directly in this session (`django_version/Dockerfile`,
`django_version/docker-compose.yml`, `.github/workflows/ci.yml`,
`django_version/config/settings.py`), confirmed by the user's own restatement of which
findings to act on. No separate Auditor/Verifier session preceded this one.
**Tree:** `feature/django-refactor`.
**Files modified by this session:** this plan only. No production file was touched.

**Scope boundary, decided with the user before this plan started:** findings whose correct
answer depends on a hosting target not yet chosen (a production `docker-compose`/platform
config, the concrete `ALLOWED_HOSTS` value, switching `runserver` for a WSGI server, a
production Dockerfile stage) are explicitly excluded from this plan. They stay open until
Phase 5 of `docs/ROADMAP_SKILLBRIDGE.md` picks a deploy target. See
`docs/BRIEFING_PLANNER_MVP_SKILLBRIDGE.md` and the "Docker and GitHub Actions CI" section of
`ARCHITECTURE.md` for the decisions already on record.

Findings in this plan are not re-verified — they were read directly from the current files in
this session. Task entries appear in the order the user decided them.

---

## TASK 1 — Split `requirements.txt` into production and development dependency files

**ORIGIN** — Infra review conducted in this session. Prerequisite for every quality/security
tool this plan adds: without a split, each new dev-only tool would be installed into the
production Docker image.

**PROBLEM** — `django_version/requirements.txt` currently lists only production runtime
dependencies (Django, psycopg, argon2-cffi, pillow, etc.), but has no separate file for
dev-only tooling. Every finding below (linter, formatter, type checker, coverage, pre-commit,
dependency scanner, secret scanner, static analyzer) is a dev-only dependency — it never runs
in the deployed application. Adding them directly to `requirements.txt` would inflate the
production image and mix two responsibilities in the file `conventions.md` names as the single
source of truth for pinned versions.

**DECIDED APPROACH** — Create `django_version/requirements-dev.txt`, starting with
`-r requirements.txt`, followed by the dev-only tools this plan adds (appended by each
subsequent task in this plan as its tool is decided). `django_version/requirements.txt` keeps
only production runtime dependencies, unchanged from its current content. `Dockerfile`
continues installing from `requirements.txt` only — no production Dockerfile/stage exists yet,
and creating one is out of scope (see Scope boundary above). `ci.yml` and local dev setup
install from `requirements-dev.txt`.

**WHY THIS PATH** — Matches the project's existing dependency-file format instead of
introducing a new packaging system. Migrating to `pyproject.toml` with dependency groups was
raised by the user as a genuinely reasonable direction — timing favors it, since the project
currently has only two apps with models and no other layers built yet — but it carries its own
scope (build backend choice, `dependency-groups` per PEP 735 vs. the older
`optional-dependencies` extra, updating `Dockerfile`, `ci.yml`, and the `conventions.md` table
that names `requirements.txt` as the source of truth for pinned versions). Bundling it into
this plan would couple a packaging-format migration to the CI tooling additions this plan
exists to deliver. It is deferred to its own near-term Planner session instead (see Open
Questions) — the same pattern `ARCHITECTURE.md` already uses in "User Input Normalization —
Owned by the Serializer Layer": recognize the right fix, write down why it is not done now, and
revisit at its own moment.

*(Aside: a "dev dependency" is any package that helps whoever writes the code — linting,
testing, type-checking — and is never executed by the running application itself.)*

**ALTERNATIVES CONSIDERED**
- Single `requirements.txt` (status quo) — rejected: inflates the production image with tools
  that never run there, and mixes two responsibilities in one file.
- Migrate to `pyproject.toml` with dependency groups now — considered the better long-term
  direction; explicitly deferred to its own task rather than folded into this one (see Open
  Questions), specifically because its current support in `pip` for Python 3.14 has not been
  verified against official documentation yet, and deciding it without that verification would
  be planning from assumption.

**SCOPE** — `django_version/requirements-dev.txt` (new file). No change to
`django_version/requirements.txt`'s content in this task — it stops being "the" dependency
file and becomes "the production dependency file," but nothing in it changes. No change to
`Dockerfile` or `docker-compose.yml`.

**ACCEPTANCE CRITERIA**
- `django_version/requirements-dev.txt` exists and begins with `-r requirements.txt`.
- `pip install -r requirements-dev.txt` succeeds inside Docker.
- `django_version/requirements.txt` is byte-identical to its current committed content.

**TEST PLAN** — None. This is a dependency manifest, not application logic. Verification is
the install command succeeding inside Docker, per `conventions.md`'s Docker-workflow rule.

**OUT OF SCOPE** — Creating a production Dockerfile/stage; migrating to `pyproject.toml`;
adding any actual tool to either file in this task — it only creates the tools-free
`requirements-dev.txt` shell. Each subsequent task in this plan appends its own tool to it.

**OPEN QUESTIONS** — Migration to `pyproject.toml` with `dependency-groups` (PEP 735) is
deferred to a separate, near-term Planner session, once its current support in `pip` for the
project's pinned Python 3.14 has been verified against official documentation — not assumed
from training data.

---

## TASK 2 — Add `ruff` for linting and formatting

**ORIGIN** — Infra review conducted in this session; part of the "quality tooling in CI" block
the user scoped into this plan.

**PROBLEM** — No linter or formatter exists in the project. Code style (unused imports, import
order, line length, formatting consistency) is unchecked before merge.

**DECIDED APPROACH** — Add `ruff` to `django_version/requirements-dev.txt` (created in
Task 1). Add a standalone `django_version/ruff.toml` for its configuration — no `pyproject.toml`
exists yet (Task 1 deferred that migration), so `ruff.toml` is ruff's own supported
config-file format for this case, placed in `django_version/` to match where `pytest.ini`
already lives, since every project command already runs from that directory. Add two steps to
`.github/workflows/ci.yml`: `ruff check .` (lint) and `ruff format --check .` (formatting
check, fails the build without rewriting files — rewriting is a local `ruff format .` run by
the developer, not a CI responsibility).

Rule selection starts from ruff's own default rule set (`E`, `F` — pycodestyle errors and
Pyflakes — plus `I` for import sorting, replacing `isort`). This is the standard starting point
documented by the tool itself, not a contested choice; expanding the rule set later is a small,
low-risk change and does not need to be decided now.

**WHY THIS PATH** — Decided by the user: `ruff` over the classic `flake8` + `isort` + `black`
combination, for the reasons discussed — one tool, one config, faster, and the direction most
new Python projects are moving toward.

**ALTERNATIVES CONSIDERED**
- `flake8` + `isort` + `black` — rejected: three packages, three configs, slower, more
  moving parts for the same outcome.

**SCOPE** — `django_version/requirements-dev.txt` (append `ruff`, exact pinned version).
New file `django_version/ruff.toml`. `.github/workflows/ci.yml` (add the two `ruff` steps).

**ACCEPTANCE CRITERIA**
- `ruff` appears in `requirements-dev.txt` with an exact pinned version (no `latest` or
  unpinned entry, per `conventions.md`'s versioning rule).
- `django_version/ruff.toml` exists and targets Python 3.14.
- `ruff check .` exits 0 inside Docker.
- `ruff format --check .` exits 0 inside Docker.
- `ci.yml` runs both commands as separate steps, and the job fails if either does.

**TEST PLAN** — None. Tooling configuration, not application logic. Verification is the CI
job passing on ruff's own checks.

**OUT OF SCOPE** — Wiring `ruff` into a pre-commit hook (separate task, later in this plan).
Type checking (separate task, next). Expanding the rule set beyond the starting default.

**OPEN QUESTIONS** — The Developer should run `ruff check .` and `ruff format --check .`
locally first, before wiring the CI steps as build-failing, to see how many violations already
exist in the current codebase. If the count is large, come back to the user to decide whether
fixing them belongs in this same task or in a separate follow-up cleanup task, rather than
silently expanding this task's scope.

---

## TASK 3 — Add `mypy` with `django-stubs` for static type checking

**ORIGIN** — Infra review conducted in this session; part of the "quality tooling in CI" block
the user scoped into this plan.

**PROBLEM** — `conventions.md` mandates type hints on every function and method signature, but
nothing verifies they are correct. A function annotated `-> str` that actually returns an `int`
raises no error anywhere today — the hints are unenforced documentation.

**DECIDED APPROACH** — Add `mypy` and `django-stubs` to `django_version/requirements-dev.txt`
(created in Task 1). Add a standalone `django_version/mypy.ini` for configuration — same
reasoning as `ruff.toml` in Task 2: no `pyproject.toml` exists yet, and `django_version/` is
where every project config file already lives. Enable the `django-stubs` mypy plugin, pointed
at `config.settings` (`[mypy.plugins.django-stubs] django_settings_module = config.settings`),
so mypy understands Django-specific typing (querysets, managers, model fields) instead of
treating them as untyped. Add a `mypy .` step to `.github/workflows/ci.yml` that fails the
build on type errors.

**WHY THIS PATH** — Decided by the user: `mypy` + `django-stubs` over `pyright`. For this
project specifically, Django-aware type checking matters more than raw speed — the codebase is
still small, so `pyright`'s speed advantage has no practical effect yet — and `mypy` is the tool
most commonly named explicitly when a Python/Django job posting mentions type checking.

**ALTERNATIVES CONSIDERED**
- `pyright` — rejected: weaker Django ecosystem support (no equivalent to `django-stubs`'s
  maturity), and less frequently the specific tool named in Django job postings.

**SCOPE** — `django_version/requirements-dev.txt` (append `mypy` and `django-stubs`, exact
pinned versions). New file `django_version/mypy.ini`. `.github/workflows/ci.yml` (add the
`mypy` step).

**ACCEPTANCE CRITERIA**
- `mypy` and `django-stubs` appear in `requirements-dev.txt` with exact pinned versions.
- `django_version/mypy.ini` exists and configures the `django-stubs` plugin against
  `config.settings`.
- `mypy .` runs inside Docker without a configuration error.
- `ci.yml` runs `mypy .` as a step, and the job fails if it reports type errors.

**TEST PLAN** — None. Tooling configuration, not application logic. Verification is the CI job
passing on mypy's own checks.

**OUT OF SCOPE** — Wiring `mypy` into a pre-commit hook (separate task, later in this plan).
Fixing every type error mypy surfaces on its first run against the existing codebase — see Open
Questions.

**OPEN QUESTIONS** — Same caution as Task 2: the Developer should run `mypy .` locally first,
before making the CI step build-failing, to see how many pre-existing type errors surface. This
project's custom patterns (Abstract Base Classes instead of Multi-Table Inheritance, a custom
`BaseUserManager`, custom validators) are exactly the kind of code `django-stubs` sometimes
misreads. If the error count is large, or if `django-stubs` produces false positives against
these patterns that would require `# type: ignore` comments or stub overrides, come back to the
user before deciding how to proceed — do not silently suppress errors to make the build pass.

---

## TASK 4 — Add `pytest-cov` for test coverage measurement, staged toward an enforced floor

**ORIGIN** — Infra review conducted in this session; also raised independently in
`docs/BRIEFING_PLANNER_MVP_SKILLBRIDGE.md` §3.3: coverage "was never measured" — 304 tests and
4,330 lines of test code are explicitly flagged there as not a substitute for it.

**PROBLEM** — The project has 304 tests, but nothing measures how much of the production code
they actually exercise. `pytest-cov`/`coverage` are not installed in `django_version/`, though
both existed in the closed `oop_version/requirements.txt`.

**DECIDED APPROACH** — Add `pytest-cov` to `django_version/requirements-dev.txt` (created in
Task 1). Measure only `accounts` and `profiles` — the apps containing the project's actual
logic — excluding `migrations/`, `apps.py`, and `__init__.py` files: these are
`startapp`/`startproject` boilerplate that execute merely by being imported, which would
inflate the percentage without reflecting real test reach. `config/` (settings, urls,
wsgi/asgi) is excluded entirely from the metric — it is validated implicitly by the test suite
running at all (a broken `settings.py` fails every test at collection, not just its own), not
by a dedicated coverage percentage.

Configuration lives in a standalone `django_version/.coveragerc` (no `pyproject.toml` yet —
Task 1's open question) with:
```
[run]
source = accounts,profiles
omit = */migrations/*, */apps.py, */__init__.py
```

Rollout is staged in two steps, both executed by the Developer inside this single task — not
split into a separate future task:

1. Run `pytest --cov --cov-report=term-missing` once and report the real baseline percentage to
   the user, before touching `ci.yml`.
2. With the real number in hand, add a step to `.github/workflows/ci.yml` running the same
   command with `--cov-fail-under=<N>`, where `N` is agreed with the user based on that
   baseline — either locked exactly at the current number (any regression fails immediately) or
   a small buffer below it, per the user's choice at that time.

**WHY THIS PATH** — The user wants an enforced floor (stronger signal for a portfolio project)
but only once a real baseline exists — deciding a threshold blind would be planning from
assumption, which Rule 1 of the Planner forbids: it could either fail the build immediately on
pre-existing debt nobody chose to take on today, or sit so low it protects nothing. Scoping to
`accounts`/`profiles` and excluding boilerplate keeps the percentage meaningful instead of
padded by files that execute without being tested in any real sense.

*(Aside: coverage measures reach, not quality — "was this line executed at least once," not
"did the test that ran it check anything meaningful." A lower-than-expected number does not
mean the tests already written, like the admin-behavior tests from spec 001, are weak — it only
shows which lines nothing has touched yet.)*

**ALTERNATIVES CONSIDERED**
- Measure `django_version/` in full (`--cov=.`, no `omit`) — rejected: boilerplate
  (`settings.py`, empty migrations, `apps.py`) executes on import alone and would inflate the
  percentage without reflecting real test effort.
- Set `--cov-fail-under` immediately, without a baseline run — rejected: no measurement has
  ever existed for this codebase; a blind threshold is a guess, not a decision.
- Defer the floor decision to a fully separate future Planner session — rejected in favor of a
  two-step sequence inside this same task, so the user gets the enforced floor she asked for
  without an extra planning round-trip.

**SCOPE** — `django_version/requirements-dev.txt` (append `pytest-cov`, exact pinned version).
New file `django_version/.coveragerc`. `.github/workflows/ci.yml` (add the coverage step,
including `--cov-fail-under` once `N` is agreed).

**ACCEPTANCE CRITERIA**
- `pytest-cov` appears in `requirements-dev.txt` with an exact pinned version.
- `django_version/.coveragerc` exists with `source = accounts,profiles` and the stated `omit`
  patterns.
- `pytest --cov --cov-report=term-missing` runs inside Docker and reports a percentage for
  `accounts` and `profiles` only — `config/` does not appear in the report.
- The real baseline percentage is reported to the user before `--cov-fail-under` is added to
  `ci.yml`.
- `ci.yml` runs the coverage command as a step; once `N` is agreed, the job fails if coverage
  drops below it.

**TEST PLAN** — None. Tooling configuration, not application logic. Verification is the
coverage command's own report and, once wired, the CI job's pass/fail against the agreed
threshold.

**OUT OF SCOPE** — Coverage for a `jobs` app (does not exist yet). Branch coverage vs. line
coverage (line coverage is `coverage.py`'s default and is not being reconsidered here).
Uploading reports to an external service (e.g. Codecov) — `term-missing` in the CI log is
sufficient for now.

**OPEN QUESTIONS** — The exact value of `N` (the enforced floor) is not decided in this
planning session — it depends on the real baseline the Developer reports in step 1. The user
must confirm `N` (exact lock vs. small buffer) before step 2 adds `--cov-fail-under` to
`ci.yml`.

---

## TASK 5 — Add `pre-commit` hooks running `ruff` and `mypy`

**ORIGIN** — Infra review conducted in this session. `docs/BRIEFING_PLANNER_MVP_SKILLBRIDGE.md`
§3.3 names `pre-commit` explicitly among the quality tools that do not exist yet.

**PROBLEM** — Even with `ruff`/`mypy`/coverage wired into CI (Tasks 2–4), the first point an
error surfaces today is after a push — a full CI round trip (push, wait, see the failure, fix,
push again) instead of at commit time, locally.

**DECIDED APPROACH** — Adopt the `pre-commit` framework. Add `pre-commit` to
`django_version/requirements-dev.txt`. Add `.pre-commit-config.yaml` at the **monorepo root** —
unlike `ruff.toml`, `mypy.ini`, and `.coveragerc` (tool-level configs, read from wherever the
tool is invoked), a pre-commit hook is a Git-level mechanism tied to the single `.git/`
directory at the repository root, so its config cannot live inside `django_version/`.

Both hooks (`ruff check` + `ruff format --check`, and `mypy`) run as `language: system` entries,
invoking the `ruff`/`mypy` already installed in `django_version/.venv/` — the host virtualenv
the root `CLAUDE.md` documents as existing for editor experience, independent of Docker. This
ties the hooks to the exact versions pinned in `requirements-dev.txt` (Tasks 2 and 3), instead
of the community `ruff-pre-commit`/`mirrors-mypy` hooks, which manage their own isolated
per-hook environments pinned by a separate `rev:` field — a second version to keep in sync with
`requirements-dev.txt`, and a source of exactly the kind of silent drift (local pre-commit
passing on a version CI does not run) this task exists to prevent.

Both hooks are scoped to `files: ^django_version/`, so `oop_version/` (closed) is never touched
by either hook, matching the root `CLAUDE.md` rule against running project commands there.

Both `ruff` and `mypy` run at commit time, not only `ruff` — see Why below.

**WHY THIS PATH** — The user confirmed running both checks at commit time, correcting an
assumption in my first pass at this finding: I had recommended `ruff`-only in pre-commit,
reasoning that `mypy` is slower and would add friction. The user pointed out that her actual
constraint is calendar time to reach MVP, not command runtime — the suite already runs 304
tests in 12.13s, so execution speed is not the bottleneck. Under that constraint, catching a
type error at commit time is strictly better than discovering it after a full CI round trip
(push → wait → see failure → fix → push again), which costs more real time than a slightly
longer commit. The one genuine risk — `django-stubs` false positives against this project's
custom patterns making early commits fail on noise, not real errors — is addressed by
sequencing: Task 3 stabilizes `mypy` against the real codebase before this task is implemented,
so by the time these hooks exist, `mypy` is no longer likely to block commits on false alarms.

**ALTERNATIVES CONSIDERED**
- `pre-commit` running only `ruff`, with `mypy` staying CI-only — my initial recommendation,
  based on runtime speed; withdrawn once the user clarified the real constraint (see Why).
- No `pre-commit` adoption at all — rejected: contradicts a tool the briefing names explicitly
  as missing, and a priority the user had already declared before this session started.
- Community-managed hooks (`ruff-pre-commit`, `mirrors-mypy`) — rejected: introduces a second,
  separate version-pinning mechanism that can drift from `requirements-dev.txt`.

**SCOPE** — Monorepo root `.pre-commit-config.yaml` (new file).
`django_version/requirements-dev.txt` (append `pre-commit`, exact pinned version). No change to
`Dockerfile` or `docker-compose.yml` — these hooks run on the host at commit time, not inside
the container.

**ACCEPTANCE CRITERIA**
- `.pre-commit-config.yaml` exists at the monorepo root with two `language: system` hooks
  (`ruff check` + `ruff format --check`, and `mypy`), both scoped to `files: ^django_version/`.
- `pre-commit` appears in `requirements-dev.txt` with an exact pinned version.
- `django_version/.venv/` has `requirements-dev.txt` installed into it (see Open Questions).
- `pre-commit install` has been run once, and this one-time step is documented somewhere a
  fresh clone will see it.
- A commit touching a file inside `django_version/` with a `ruff` or `mypy` violation is
  blocked locally, before it reaches `git push`.
- A commit touching only `oop_version/` is unaffected by either hook.

**TEST PLAN** — None. Tooling configuration, not application logic.

**OUT OF SCOPE** — Adding the coverage check (Task 4) to the pre-commit hook: a full test run is
slow enough to defeat the purpose of a fast local check, so coverage stays CI-only. Generic
hygiene hooks (trailing-whitespace, end-of-file-fixer, etc.) — not raised as a finding in this
session; would need its own decision if wanted later.

**OPEN QUESTIONS**
- Whether `django_version/.venv/` currently has `requirements-dev.txt` (or even
  `requirements.txt`) installed is unverified in this session. The Developer must check, and
  install if missing, before wiring these hooks — otherwise the `language: system` hooks fail
  with a "command not found" error rather than a real lint/type finding.
- Running `git commit` is inherently a host-level operation, not something that happens inside a
  Docker container. Pre-commit hooks running on the host — rather than via
  `docker-compose exec web` — is therefore a necessary exception to the root `CLAUDE.md` rule
  that all project commands run via Docker, not a violation of it. Recorded here so it is a
  conscious exception, not a silent one.

---

## TASK 6 — Add `pip-audit` for dependency vulnerability scanning

**ORIGIN** — Infra review conducted in this session; the security-tooling gap that opened this
whole planning session.

**PROBLEM** — `requirements.txt` pins roughly 19 packages (Django, psycopg, argon2-cffi,
pillow, etc.). None of them are checked against known CVEs. A version that was safe when pinned
but has a vulnerability discovered later goes unnoticed indefinitely.

**DECIDED APPROACH** — Add `pip-audit` to `django_version/requirements-dev.txt`. Add two steps
to `.github/workflows/ci.yml`: `pip-audit -r requirements.txt` and
`pip-audit -r requirements-dev.txt` — both files audited, since a vulnerable dev-only tool
still compromises the CI pipeline or a developer's machine, not just what ships to users. The
job fails if either command reports a known vulnerability.

**WHY THIS PATH** — `pip-audit` is maintained by the PyPA (the same organization that maintains
`pip` itself), checks against the official PyPI Advisory Database and OSV (backed by
Google/OSSF), and requires no account or API key. `safety` was seriously considered — the user
researched it independently and found it has more GitHub stars (2k vs. `pip-audit`'s 1.3k) —
but confirmed it requires login/API key for full database access, which would mean a
`SAFETY_API_KEY` secret in CI and a broken "clone and run" experience for anyone reproducing the
project without their own `safety` account. For a portfolio project, that reproducibility cost
was judged to outweigh a moderate, non-decisive popularity difference. Whether `safety`'s
commercial database has broader CVE coverage than PyPI Advisory DB/OSV is a genuine unknown, not
resolved in this session, and is not claimed as a point in either tool's favor.

**ALTERNATIVES CONSIDERED**
- `safety` — rejected for this MVP on the reproducibility cost above; left open as a possible
  second, complementary scanner in the future, out of scope for now.

**SCOPE** — `django_version/requirements-dev.txt` (append `pip-audit`, exact pinned version).
`.github/workflows/ci.yml` (add the two `pip-audit` steps).

**ACCEPTANCE CRITERIA**
- `pip-audit` appears in `requirements-dev.txt` with an exact pinned version.
- `ci.yml` runs `pip-audit -r requirements.txt` and `pip-audit -r requirements-dev.txt` as
  steps.
- The job fails if either command reports a known vulnerability.

**TEST PLAN** — None. Tooling, not application logic.

**OUT OF SCOPE** — Adding `safety` as a second scanner. Remediating any vulnerability
`pip-audit` might find on its first run against the currently pinned versions — see Open
Questions.

**OPEN QUESTIONS** — The Developer should run `pip-audit` locally first, before wiring it as
CI-blocking, in case a currently pinned version already has a known vulnerability. If one turns
up, come back to the user to decide the upgrade path — `conventions.md` treats a version change
as an architectural decision, not a routine maintenance update, so a version bump here is not the
Developer's call to make silently.

---

## TASK 7 — Add secret scanning: GitHub native protection plus a `gitleaks` pre-commit hook

**ORIGIN** — Infra review conducted in this session; security-tooling block.

**PROBLEM** — No secret scanning exists at any layer. `.env` and `.env.local` are already
gitignored (`django_version/.gitignore`), but that only stops that specific file from being
committed — it does nothing about a key or password pasted directly into code, a settings file,
or a test fixture by mistake.

**DECIDED APPROACH** — Two layers, mirroring the `clean()` + `CheckConstraint` pattern already
established in `ARCHITECTURE.md` (an application-layer check backed by a database-level
backstop):

1. **Backstop, after push:** confirm the public `thaisdMM/skillbridge` repository has GitHub's
   native secret scanning active (on by default for public repositories) and its push
   protection enabled (Settings → Code security) — turning it on if it is not already. This is
   a repository setting, not a code change: no new file, no new dependency.
2. **First line, before commit:** add `gitleaks` as a third hook in the
   `.pre-commit-config.yaml` created in Task 5, scoped to `files: ^django_version/` like the
   other two hooks. Unlike `ruff`/`mypy`, `gitleaks` is a standalone Go binary, not a Python
   package, so it cannot run as a `language: system` hook against `django_version/.venv/` the
   way the other two do — there is no existing pip-installed copy to point to. It runs via the
   community-maintained `gitleaks/gitleaks` pre-commit hook instead, which manages its own
   binary. This is the one exception to Task 5's "no separate pinning mechanism" reasoning,
   because no equivalent already-installed copy exists for this tool.

**WHY THIS PATH** — The user chose both layers over relying on GitHub's native scanning alone.
Catching a secret only after push still means it was briefly exposed on a public server,
requiring rotation of the leaked credential regardless of how fast it is removed. Catching it
before the commit even happens avoids that exposure entirely.

**ALTERNATIVES CONSIDERED**
- GitHub native scanning only — rejected: leaves the gap between commit and push where the
  secret already sits in local history, and does not prevent the brief public exposure a
  before-commit catch avoids.
- No secret scanning, reasoning the project is new and `.env` is already gitignored — not
  seriously considered: gitignoring `.env` does not stop a secret pasted inline in a `.py` file.

**SCOPE** — Monorepo root `.pre-commit-config.yaml` (Task 5's file, extended with a third hook,
not a new file). GitHub repository settings (Code security page) — not a file in the
repository.

**ACCEPTANCE CRITERIA**
- GitHub secret scanning is confirmed active, and push protection is confirmed enabled, in the
  repository's Code security settings.
- `.pre-commit-config.yaml` has a third hook running `gitleaks`, scoped to
  `files: ^django_version/`.
- A commit introducing a string matching a known secret pattern inside `django_version/` is
  blocked locally, before it reaches `git push`.

**TEST PLAN** — None. Tooling and repository configuration, not application logic.

**OUT OF SCOPE** — Scanning the existing git history for secrets already committed in the past —
a one-time audit action (`gitleaks detect` against full history), not a recurring check; see
Open Questions. Remediation of any past leak such a scan might find.

**OPEN QUESTIONS**
- Whether to run a one-time `gitleaks` scan of the full git history (not just future commits) is
  a separate decision for the user. If a real secret was ever committed and later removed, it
  likely still exists in history — git does not purge old content on a later commit. Worth a
  short follow-up decision once this task lands, not bundled into it.
- `gitleaks`' default rule set may false-positive against this project's own test fixtures — for
  example, `testing.md`'s documented `valid_user_data` pattern uses a fake but password-shaped
  string (`"SecurePass@123"`) across `accounts/tests/conftest.py`. The Developer should run
  `gitleaks` locally once before wiring it in, and add an allowlist entry for known-fake test
  fixtures if it flags them.

---

## TASK 8 — Add `bandit` for static security analysis

**ORIGIN** — Infra review conducted in this session; security-tooling block.

**PROBLEM** — Nothing analyzes the project's own Python code for security anti-patterns —
hardcoded passwords, unsafe `subprocess` use, unparametrized SQL, `eval`, and similar.

**DECIDED APPROACH** — Add `bandit` to `django_version/requirements-dev.txt`. Scope it to
`accounts` and `profiles` only, excluding `migrations/` and `tests/` in both apps — `tests/` is
excluded specifically because the project's fixtures use password-shaped fake strings (e.g.
`testing.md`'s documented `valid_user_data` pattern, `"SecurePass@123"`), which `bandit`'s
`B106` hardcoded-password check is known to false-positive against; the same reasoning already
applied to `gitleaks` in Task 7.

Runs in both layers already established in this plan:
1. A fourth `language: system` hook in `.pre-commit-config.yaml` (Tasks 5 and 7's file),
   invoking `bandit` from `django_version/.venv/`, targeted at `accounts/` and `profiles/` with
   `tests/` and `migrations/` excluded.
2. A step in `.github/workflows/ci.yml` running the same scoped command, failing the build on
   any finding.

**WHY THIS PATH** — `bandit` is the purpose-built tool for this exact problem in Python,
maintained by PyCQA (the same group behind `flake8`), free, no account required — the only
serious option evaluated. `semgrep` was considered and set aside for the same reproducibility
reason that ruled out `safety` in Task 6: its easier setup path depends on a cloud account
(`semgrep.dev`); a fully local, custom-rule `semgrep` configuration would be more setup effort
for no clear gain over `bandit` at this project's current scope. Running in both layers (not
CI-only) follows the same reasoning already decided in Task 5 for `ruff`/`mypy`: catching a
finding at commit time beats a CI round trip, and `bandit`'s static analysis is fast enough not
to add meaningful friction.

**ALTERNATIVES CONSIDERED**
- `semgrep` — rejected: easier usage path depends on a cloud account, the same cost that ruled
  out `safety`; a local-only setup would need custom rule configuration for no clear benefit
  over `bandit` here.
- CI-only, no pre-commit hook — not chosen; kept consistent with the reasoning already decided
  in Task 5.

**SCOPE** — `django_version/requirements-dev.txt` (append `bandit`, exact pinned version).
`.pre-commit-config.yaml` (Tasks 5/7's file, add a fourth hook). `.github/workflows/ci.yml`
(add a `bandit` step).

**ACCEPTANCE CRITERIA**
- `bandit` appears in `requirements-dev.txt` with an exact pinned version.
- `.pre-commit-config.yaml` has a fourth hook running `bandit` as `language: system` against
  `django_version/.venv/`, targeting only `accounts/` and `profiles/`, excluding `tests/` and
  `migrations/` in both.
- `ci.yml` runs the same scoped `bandit` command as a step; the job fails on any finding.
- A commit introducing a flagged pattern (e.g. `eval()`, `subprocess` with `shell=True`) inside
  `accounts/` or `profiles/` outside `tests/`/`migrations/` is blocked locally before reaching
  `git push`.

**TEST PLAN** — None. Tooling, not application logic.

**OUT OF SCOPE** — Scanning `config/` (settings) — not raised as part of this finding; a
separate decision if wanted later. Remediating any finding `bandit` surfaces on its first run.

**OPEN QUESTIONS** — Same caution as Tasks 2, 3, and 7: the Developer should run `bandit`
locally first, before wiring it as blocking in either layer, to see how many findings surface
against the current codebase — including confirming that excluding `tests/` was enough to avoid
the `B106` false-positive risk, or whether other checks also need a targeted suppression.
`bandit` supports inline `# nosec` comments and a skip list; the user should confirm any
suppression before the Developer adds one silently.

---

## TASK 9 — `ci.yml` trigger refinements: `permissions:`, pip cache now; `pull_request` deferred

**ORIGIN** — Infra review conducted in this session; three small `ci.yml` items grouped because
two are settled defaults and one turned out, on inspection, to be a genuinely open question
rather than a quick fix.

**PROBLEM** — Three gaps in `.github/workflows/ci.yml`: no explicit `permissions:` block (the
`GITHUB_TOKEN` runs with its default, broader-than-needed scope); no dependency cache for `pip`
(slower installs on every run); and a trigger (`on: push: branches: ["**"]`) that was flagged as
possibly incomplete for pull-request-based work.

**DECIDED APPROACH**
- Add `permissions: contents: read` at the workflow level. The job only checks out code and runs
  tests; the badge-update step authenticates with its own `secrets.GIST_SECRET`, not
  `GITHUB_TOKEN`, so read-only `contents` is sufficient.
- Enable `cache: pip` on the existing `actions/setup-python@v5` step — a built-in option, no new
  configuration surface.
- **`pull_request` trigger: deferred, not added.** Investigation during this session found the
  original framing of this as a gap was incomplete. GitHub associates a check run with a commit
  SHA, not with the event that produced it — since the user's workflow always opens PRs from
  branches inside this same repository (confirmed against her own PR history, #1–#5, all
  `thaisdMM` branches merged into `main`, never a fork), the existing `push` trigger already
  produces a check run attached to the PR's head commit, which GitHub already surfaces on the PR
  page. The gap `pull_request` would actually close — running CI for a PR opened from an
  external fork, where `push` never fires because the push happens in the forker's repository,
  not this one — does not apply to the user's current workflow, but she considers it a real gap
  worth closing given the repository is public and could someday receive an outside
  contribution. Naively adding `pull_request` on top of the existing `push` trigger, without
  restructuring it, would double-run CI on every PR commit for no gain today. The proper fix —
  narrowing `push` to `main` (post-merge confirmation) and adding `pull_request` for all PR
  validation — is a small but real reshape of the trigger, not a one-line addition, and is
  deferred until it is actually needed.

**WHY THIS PATH** — The first two items are uncontested best practice with no real alternative.
The third was corrected mid-session: my first framing understated how much the existing `push`
trigger already covers for a same-repository PR workflow, and overstated the cost of leaving it
as-is. Deferring — rather than either adding it now or dropping it as not-a-problem — matches
the user's own read that repository visibility (public) makes this worth revisiting once it
actually matters, not never.

*(Aside: GitHub does not auto-run Actions workflows for a first-time fork contributor's PR by
default — it holds the run for manual approval by a maintainer. A fork itself never changes this
repository; only an approved, merged PR does. This is a second, independent safety gate on top
of the trigger question above.)*

**ALTERNATIVES CONSIDERED**
- Add `pull_request` now, on top of `push: branches: ["**"]` — rejected: doubles CI runs per PR
  commit without closing a gap that applies to the user's actual workflow today.
- Drop the `pull_request` question entirely as "not a real problem" — rejected by the user: a
  public repository accepting outside contributions someday is a real enough possibility to keep
  as a recorded, revisitable decision rather than closing it silently.

**SCOPE** — `.github/workflows/ci.yml`: add `permissions:` and `cache: pip` now. No trigger
change in this task.

**ACCEPTANCE CRITERIA**
- `ci.yml` declares `permissions: contents: read` at the workflow or job level.
- The `actions/setup-python@v5` step has `cache: pip` enabled.
- The `on:` trigger is unchanged from `push: branches: ["**"]` in this task.

**TEST PLAN** — None. Tooling/workflow configuration.

**OUT OF SCOPE** — Restructuring the trigger (`push` narrowed to `main` + `pull_request` added
for PR validation) — this is the deferred work itself, not part of this task.

**OPEN QUESTIONS** — Revisit the trigger restructuring when either becomes true: (a) the
repository receives, or the user actively starts inviting, outside contributions; or (b) the
project reaches a portfolio-facing milestone (e.g. Phase 5 deploy) where showing a clean,
fork-friendly contribution workflow has standalone value. Until then, this stays an open,
recorded decision — not resolved in this session.

---

## TASK 10 — Remove the orphan `pillow` dependency and its Docker system libraries

**ORIGIN** — Infra review conducted in this session; independently flagged in
`docs/BRIEFING_PLANNER_MVP_SKILLBRIDGE.md` §3.3 as an orphan.

**PROBLEM** — `pillow==12.3.0` is pinned in `django_version/requirements.txt`, and its system
libraries (`libjpeg-dev`, `zlib1g-dev`) are compiled into the Docker image via the `Dockerfile`'s
`apt-get install` step, but `grep -rn "PIL\|ImageField\|import Image" accounts profiles config`
returns nothing — no `ImageField`, no `PIL` import, anywhere in the project. Confirmed as
genuinely unused, not just suspected.

**DECIDED APPROACH** — Remove `pillow==12.3.0` from `django_version/requirements.txt`. Remove
the `libjpeg-dev` and `zlib1g-dev` lines from the `RUN apt-get install` step in
`django_version/Dockerfile`. If a future task introduces image handling (e.g. a profile picture
upload feature), `pillow` and its system libraries are re-added at that time, scoped to that
task.

**WHY THIS PATH** — The user confirmed no planned use exists today — likely installed
incidentally rather than deliberately. An unused dependency is pure cost: it inflates the
production image and widens the surface `pip-audit` (Task 6) has to check, for zero benefit.
Removing now and re-adding when a real feature needs it keeps `requirements.txt` an accurate
reflection of what the running application actually uses.

**ALTERNATIVES CONSIDERED**
- Keep it "just in case" — rejected by the user: no concrete plan exists, and an unused
  dependency has cost (image size, audit surface) with no offsetting benefit.

**SCOPE** — `django_version/requirements.txt` (remove the `pillow` line).
`django_version/Dockerfile` (remove `libjpeg-dev` and `zlib1g-dev` from the `apt-get install`
step).

**ACCEPTANCE CRITERIA**
- `pillow` no longer appears in `requirements.txt`.
- `libjpeg-dev` and `zlib1g-dev` no longer appear in the `Dockerfile`'s `apt-get install` line.
- The Docker image builds successfully after the change.
- The full test suite still passes, confirming nothing silently depended on `pillow` being
  present.

**TEST PLAN** — None new. The existing suite passing after the change is the verification that
nothing depended on it.

**OUT OF SCOPE** — Re-adding `pillow` for any future image-handling feature — that is a new
task, decided when that feature is actually planned.

**OPEN QUESTIONS** — None.

---

## TASK 11 — Defer the `web` service `HEALTHCHECK` until a dedicated `/health/` endpoint exists

**ORIGIN** — Infra review conducted in this session.

**PROBLEM** — `db` has a `healthcheck` in `docker-compose.yml`; `web` does not. Nothing in the
current `docker-compose.yml` depends on `web` being healthy (no orchestration layered on top of
it in dev), and Django has no built-in "is the server alive" endpoint to point a `HEALTHCHECK`
at today.

**DECIDED APPROACH** — Defer. When DRF is introduced (Phase 3 of the roadmap), add one
dedicated, purpose-built endpoint (e.g. `GET /health/`, no authentication, minimal work,
optionally a trivial database ping) whose only job is answering this question — not repurpose
an existing business route, DRF or otherwise, as a stand-in. Once that endpoint exists, add
`HEALTHCHECK` to the `web` service in `Dockerfile`/`docker-compose.yml` pointing at it.

**WHY THIS PATH** — The user asked whether a DRF route, once one exists, would be a better
target than `/admin/login/`. Clarified that repurposing any business endpoint — a DRF resource
or the admin login page — carries the same conceptual problem: it borrows a route built for
something else, running whatever middleware, auth, or serialization that route carries just to
answer "is the server up," and coupling the health signal to unrelated business logic. What DRF
actually changes is not "a better route to borrow" — it is that once DRF's view/URL patterns
exist in the codebase, adding one tiny dedicated endpoint becomes a cheap, natural addition,
which is strictly better than borrowing anything, DRF-flavored or not.

**ALTERNATIVES CONSIDERED**
- Point `HEALTHCHECK` at `/admin/login/` now — rejected: borrows a business route not built for
  this purpose, rendering a full HTML page (templating, CSRF, static references) just to prove
  the server is up.
- Point `HEALTHCHECK` at a DRF business route once DRF exists — rejected: same borrowing
  problem as `/admin/login/`, just with a DRF flavor.
- Build a dedicated `/health/` endpoint now, before DRF — considered, not chosen: a one-off
  Django view and URL just for this has more relative setup cost today than it will once DRF's
  routing patterns already exist in the codebase for other reasons.

**SCOPE** — None in this task — this is a deferral, no file changes now.

**ACCEPTANCE CRITERIA** — Not applicable; nothing is implemented in this task.

**TEST PLAN** — None.

**OUT OF SCOPE** — Implementing the `/health/` endpoint or the `HEALTHCHECK` directive itself —
both belong to the follow-up task, once DRF exists.

**OPEN QUESTIONS** — Revisit when Phase 3 (DRF) begins: add a dedicated `/health/` endpoint and
wire `HEALTHCHECK` to it at that point, not before.

---

## TASK 12 — Add a non-root user to the `Dockerfile`, with an empirical dev-friction check

**ORIGIN** — Infra review conducted in this session.

**PROBLEM** — No `USER` directive exists in `django_version/Dockerfile`; the container runs as
root.

**DECIDED APPROACH** — Create a non-root user in the `Dockerfile` with UID `1000` (the common
default first-user UID), and switch to it via `USER` before `CMD`. Add a verification step for
the Developer: build the image, create a file from inside the running container (e.g. let a
migration run, or `touch` a throwaway file), and confirm the resulting file is usable — readable,
writable, deletable without `sudo` — from the host, given `docker-compose.yml`'s bind mount
(`.:/app`). Docker Desktop on macOS was flagged during this session as generally handling
UID/GID mapping across a bind mount more gracefully than native Linux Docker, but this is not
confirmed with certainty for this exact setup — hence the empirical check rather than assuming
either way.

**WHY THIS PATH** — The user confirmed Option A over deferring to a future production-only
Dockerfile stage. Matches the "run first, verify, come back if there's friction" pattern already
used consistently in this plan (Tasks 2, 3, 7, 8) rather than deciding blind.

**ALTERNATIVES CONSIDERED**
- Defer to a future production-only Dockerfile stage — not chosen: unlike the items deferred to
  Phase 5 at this plan's start (`ALLOWED_HOSTS`, `docker-compose.prod.yml`), this does not depend
  on knowing the deploy target, so there was no structural reason to defer it.

**SCOPE** — `django_version/Dockerfile` (add user creation and the `USER` directive).

**ACCEPTANCE CRITERIA**
- `Dockerfile` creates a non-root user (UID `1000`) and switches to it before `CMD`.
- The image builds successfully.
- A file created inside the running container, via the bind mount, is confirmed usable from the
  host without `sudo`.
- If that check fails, the task is not marked done silently — the friction is reported to the
  user before proceeding, per this plan's established pattern.

**TEST PLAN** — None. Infrastructure, not application logic. Verification is the empirical
file-ownership check above.

**OUT OF SCOPE** — A separate production-only Dockerfile stage — already part of the Phase 5
bucket established at the start of this plan.

**OPEN QUESTIONS** — If the empirical check reveals real bind-mount friction on this specific
macOS + Docker Desktop setup, come back to the user to decide between accepting the friction,
falling back to a deferred production-only stage, or matching the container UID to the host
user's actual UID via a build `ARG` — do not silently pick one.

---

## TASK 13 — Record every deferred decision from this plan as a `docs/tech_debt/` entry

**ORIGIN** — A process gap the user identified directly in this session: a decision deferred
only inside a CI/tooling plan file is not durable the way `docs/tech_debt/` or the roadmap are —
without an explicit task to move it, it risks being forgotten exactly the way earlier roadmap
gaps were (the premise of `docs/BRIEFING_PLANNER_MVP_SKILLBRIDGE.md` itself).

**PROBLEM** — This plan defers five decisions (Tasks 1, 6, 7, 9, 11), each with real reasoning
and a revisit trigger, but recorded only inside this plan file. Once this plan is implemented and
the file stops being actively read, none of the five are visible anywhere the project already
looks for open decisions.

**DECIDED APPROACH** — As the final step of implementing this plan — after Task 12, before
starting any task outside this plan — create five new files in `docs/tech_debt/`, numbered `006`
through `010` (continuing the existing sequence; the last entry on disk is `005`), following the
exact structure of the existing entries (`# Technical Debt — <title>`; `Status` / `Date recorded`
/ `Area`; `## Decision deferred`; `## Why it is deferred, not implemented`; a concrete
"what to do" section):

- `006` — `pyproject.toml` migration deferred in favor of a `requirements.txt` /
  `requirements-dev.txt` split (Task 1).
- `007` — `safety` as a second dependency scanner, alongside `pip-audit` (Task 6).
- `008` — one-time `gitleaks` scan of the full git history not yet run (Task 7).
- `009` — `ci.yml` `pull_request` trigger restructuring for fork-based contributions (Task 9).
- `010` — `web` service `HEALTHCHECK` deferred until a dedicated `/health/` endpoint exists in
  Phase 3 (Task 11).

Content for each file is drawn directly from this plan's corresponding task entry (its Decided
Approach, Why This Path, and Open Questions) — this task transcribes and reformats; it does not
re-decide anything.

**WHY THIS PATH** — `docs/tech_debt/` is already the project's established mechanism for exactly
this shape of item — a deliberate, documented deferral with a revisit trigger — per
`conventions.md`'s "one decision per file, sequence-numbered" rule and the existing pattern in
`001`–`005`. Using an existing, conventional home is preferable to leaving these five items to be
manually transcribed during the future roadmap-prioritization Planner session, which may not
happen soon, and which is exactly the kind of gap that produced this entire re-planning effort.

**ALTERNATIVES CONSIDERED**
- Leave the deferred items only inside this plan file, to be manually copied during the future
  roadmap-prioritization session — rejected by the user: relies on memory across sessions, the
  exact failure mode this task exists to prevent.
- Add the five items directly into `docs/ROADMAP_SKILLBRIDGE.md` now, in this session —
  rejected: this session's scope is CI/quality/security tooling, not roadmap restructuring; the
  roadmap's actual reorganization is explicitly the next planning session already agreed with the
  user (see this plan's header). Editing a 2,014-line roadmap piecemeal, ahead of that dedicated
  session, risks the same kind of drift the roadmap already suffers from.

**SCOPE** — `docs/tech_debt/006` through `010` (five new files). No other file changes in this
task.

**ACCEPTANCE CRITERIA**
- Five new files exist in `docs/tech_debt/`, numbered `006`–`010`, one per deferred item above.
- Each follows the existing template exactly, including a "what to do" section stating the
  revisit trigger already decided in this plan — not a new one invented here.
- Each entry's `Area` field names the actual file(s) the deferred item touches, per its task
  entry in this plan.
- No content is added beyond what this plan already decided.

**TEST PLAN** — None. Documentation only.

**OUT OF SCOPE** — Actually resolving any of the five deferred decisions. Editing
`docs/ROADMAP_SKILLBRIDGE.md`.

**OPEN QUESTIONS** — None. This task is a direct transcription of decisions already made in this
plan.

---

## Order of execution

1. **Task 1** (`requirements-dev.txt` split) — first; every other tooling task appends to the
   file this task creates.
2. **Tasks 2, 3, 4, 6, 8** (`ruff`, `mypy`, `pytest-cov`, `pip-audit`, `bandit`) — independent of
   each other, all depend only on Task 1. Any order among these five is fine.
3. **Task 5** (`pre-commit` config) — after Tasks 2 and 3 specifically: Task 5's own reasoning
   requires `mypy` to be stabilized against the real codebase before it is wired into a
   commit-blocking hook.
4. **Tasks 7 and 8's pre-commit hooks, and Task 7's GitHub settings** — after Task 5, since both
   extend the `.pre-commit-config.yaml` file Task 5 creates. (Task 8's `requirements-dev.txt` and
   CI portions have no such dependency and can happen anytime after Task 1.)
5. **Task 9** (`ci.yml` refinements) — independent; natural to do once the CI steps from Tasks 2,
   3, 4, 6, 8 already exist, so `permissions:`/`cache` apply to the fuller workflow, but not a
   hard dependency.
6. **Task 10** (remove `pillow`) — fully independent, no dependency on any other task.
7. **Task 11** (HEALTHCHECK) — no implementation now; deferred to Phase 3.
8. **Task 12** (non-root user) — independent of the tooling tasks; touches only `Dockerfile`.
9. **Task 13** (transcribe deferred items to `docs/tech_debt/`) — last, always. It depends on
   every other task's reasoning being finalized, which it now is.

