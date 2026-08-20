# Audit — `docs/plan/plan_ci-quality-security_2026-08-14.md`

**Date**: 2026-08-15
**Persona**: Auditor (read-only). No file was modified other than this one.
**Primary target**: `docs/plan/plan_ci-quality-security_2026-08-14.md` (Tasks 1–13).

**Read as context, in full**

- `django_version/requirements.txt`
- `django_version/Dockerfile`
- `django_version/docker-compose.yml`
- `django_version/pytest.ini`
- `django_version/config/settings.py`
- `.github/workflows/ci.yml`
- `.gitignore` (repository root — the only one that exists)
- `docs/BRIEFING_PLANNER_MVP_SKILLBRIDGE.md` §3.3
- `django_version/CLAUDE.md`, `ARCHITECTURE.md`, `.claude/rules/conventions.md`,
  `.claude/rules/testing.md`, `django_version/AUDITOR.md`

**Verified on disk, not assumed**: the contents of `requirements.txt`; the absence of
`django_version/.gitignore`; the presence of `django_version/.venv/` and which executables it
contains; the last `docs/tech_debt/` sequence number (`005`); the `--no-migrations` flag in
`pytest.ini`; the `SECRET_KEY` guard in `settings.py`.

**Settled decisions were not reopened.** Nothing below argues against `ruff` over
`flake8`+`isort`+`black`, `mypy` over `pyright`, `pip-audit` over `safety`, running both `ruff`
and `mypy` at commit time, removing `pillow`, deferring the `HEALTHCHECK`, or deferring the
`pull_request` trigger. Those are the user's calls and they are sound. The findings below are
defects *inside* the chosen approaches, plus gaps in what the plan chose to cover.

**Scope note.** The plan's own scope boundary excludes findings that depend on an unchosen
hosting target (`ALLOWED_HOSTS`, WSGI server, production Dockerfile stage). That boundary is
respected here. Issues 12 and 13 below are inside the boundary: neither depends on knowing the
deploy target.

---

## Issues — action required

### Issue 1 — Task 1's problem statement is factually wrong: `requirements.txt` already contains dev-only dependencies

**What** — Task 1 states that `django_version/requirements.txt` "currently lists only production
runtime dependencies." It does not. The file is a flat `pip freeze` dump that includes the test
toolchain.

**Where** — Plan lines 33–37 (PROBLEM), lines 40–45 (DECIDED APPROACH), line 80 (ACCEPTANCE
CRITERIA). Against `django_version/requirements.txt`.

**The evidence** — of the 19 pinned packages, these are test-only and never execute in the
deployed application:

| Package | Why it is dev-only |
| --- | --- |
| `pytest==9.1.1` | test runner |
| `pytest-django==4.12.0` | test runner plugin |
| `iniconfig==2.3.0` | transitive dependency of `pytest` |
| `pluggy==1.6.0` | transitive dependency of `pytest` |
| `packaging==26.2` | transitive dependency of `pytest` |
| `Pygments==2.20.0` | transitive dependency of `pytest` (traceback highlighting) |

**Rule violated** — `conventions.md`, "Stack and versions": `requirements.txt` is named as the
single source of truth for pinned versions, and the plan builds its entire dependency-split
rationale on a claim about that file's contents that is contradicted by the file itself.
`CLAUDE.md` Rule 2 (read the file; never pattern-match) applies to the planning session that
produced this claim.

**Why it matters** — three concrete consequences, all inside this plan:

1. The split does not achieve its own stated goal. Task 1 exists so that "each new dev-only tool
   would [not] be installed into the production Docker image" (plan lines 28–29). After Task 1
   as written, the production image still installs `pytest`, `pytest-django`, and four
   transitive dependencies.
2. Task 4 puts `pytest-cov` in `requirements-dev.txt` while `pytest` — the thing it is a plugin
   for — stays in `requirements.txt`. One tool, split across two files, with no rule explaining
   the boundary.
3. Task 6 runs `pip-audit -r requirements.txt` and `pip-audit -r requirements-dev.txt` as two
   separate steps whose whole point is the production/dev distinction. With the current file
   contents, the "production" audit is auditing the test runner.

The `ACCEPTANCE CRITERIA` at line 80 — "`requirements.txt` is byte-identical to its current
committed content" — turns the error into a locked-in requirement. A Verifier checking that
criterion would pass a split that did not split anything.

**Direction** — the correct classification decision belongs to the user, not to me. What the
plan needs is for Task 1's PROBLEM to state the file's actual contents, and for its DECIDED
APPROACH to say explicitly which of the six packages above move to `requirements-dev.txt`. Task
10 in this same plan already establishes the reasoning pattern for "a dependency that does not
belong in the production image is pure cost" (plan lines 659–663) — that reasoning applies here
identically and was not applied.

---

### Issue 2 — No task installs `requirements-dev.txt` inside Docker, yet four tasks assert acceptance criteria that require it

**What** — Task 1 states "`Dockerfile` continues installing from `requirements.txt` only"
(plan lines 44–45) and its SCOPE says "No change to `Dockerfile` or `docker-compose.yml`" (line
75). No later task changes that. Nothing in the plan ever installs `ruff`, `mypy`,
`pytest-cov`, `pip-audit`, or `bandit` into the container. But four tasks state acceptance
criteria that can only be met inside the container.

**Where** —

| Plan line | Acceptance criterion | Tool present in image? |
| --- | --- | --- |
| 79 | "`pip install -r requirements-dev.txt` succeeds inside Docker" | — the file is never `COPY`d in |
| 133–134 | "`ruff check .` exits 0 inside Docker" / "`ruff format --check .` exits 0 inside Docker" | no |
| 185 | "`mypy .` runs inside Docker without a configuration error" | no |
| 273 | "`pytest --cov --cov-report=term-missing` runs inside Docker" | no |

Against `django_version/Dockerfile` (`COPY requirements.txt .` / `RUN pip install ... -r
requirements.txt`) and `django_version/docker-compose.yml` (`build: .`, no separate dev target).

**Rule violated** — root `CLAUDE.md`, "Execution environment": *all* project commands run via
`docker-compose exec web`. `django_version/CLAUDE.md` Rule 12 states the same as an absolute
rule. The plan writes acceptance criteria in that idiom while removing the only mechanism that
would satisfy them.

**Why it matters** — the Developer implementing Task 2 will run
`docker-compose exec web ruff check .` and get `ruff: command not found`. The plan gives no
guidance at that point, so the Developer will improvise: either install the tools into the
production image (defeating Task 1 entirely) or run them on the host venv (silently abandoning
the Docker rule for five tools, without the conscious exception the plan grants pre-commit at
lines 373–377).

This is the plan's largest structural gap. It is not a wording problem — the plan is
simultaneously committed to "the production image stays lean" and "dev tooling runs inside
Docker," with no mechanism reconciling them, and the mechanism that *would* reconcile them (a
multi-stage `Dockerfile`, or a dev-only build stage/service) was pushed into the Phase 5 scope
boundary at lines 44–45.

**Direction** — the plan needs one explicit decision on where the five new tools execute, before
Task 2 begins. `ARCHITECTURE.md` → "Docker and GitHub Actions CI" records the current one-stage
setup and its reasoning; whatever is decided extends that entry. Note the interaction with
Issue 3: `ci.yml` does not run inside Docker at all, so the CI half of every tooling task is
unaffected by this — only the "inside Docker" acceptance criteria are.

---

### Issue 3 — Task 1 describes a `ci.yml` change that appears in neither its SCOPE nor its ACCEPTANCE CRITERIA

**What** — Task 1's DECIDED APPROACH says "`ci.yml` and local dev setup install from
`requirements-dev.txt`" (line 45). Its SCOPE section (lines 72–75) lists only the new file and
explicitly says what does *not* change; `ci.yml` is not mentioned. Its ACCEPTANCE CRITERIA (lines
78–80) contain no `ci.yml` item.

**Where** — plan line 45 versus lines 72–75 and 78–80. Against `.github/workflows/ci.yml` line
49 (`run: pip install -r requirements.txt`).

**Rule violated** — the plan's own internal contract: every other task in this file lists every
touched file under SCOPE and states a verifiable criterion for it (compare Task 2, lines
126–135, which scopes and asserts its `ci.yml` edit correctly).

**Why it matters** — every tooling task from Task 2 onward assumes CI has the dev dependencies
installed. If the `ci.yml` line is not changed in Task 1, Task 2's first CI run fails on
`ruff: command not found`, and the failure will look like a Task 2 defect rather than a Task 1
omission. A Verifier working from acceptance criteria alone would mark Task 1 complete with the
change missing.

**Direction** — add `.github/workflows/ci.yml` to Task 1's SCOPE and a matching criterion to its
ACCEPTANCE CRITERIA. Task 2's SCOPE line 127 is the pattern to follow.

---

### Issue 4 — `mypy.ini` in `django_version/` will not be found by the pre-commit hook, producing exactly the drift Task 5 exists to prevent

**What** — Task 3 places `mypy.ini` in `django_version/` (lines 161–163). Task 5 runs `mypy` as
a `language: system` pre-commit hook. `pre-commit` executes every hook with the working
directory set to the repository root. `mypy` discovers its configuration file in the current
working directory only — it does not walk up from the source files being checked, the way `ruff`
does.

**Where** — plan lines 161–163 and 166–167 (Task 3) against lines 313–318 (Task 5).

**Rule violated** — Task 5's own stated purpose: it rejects the community hooks specifically to
avoid "silent drift (local pre-commit passing on a version CI does not run)" (lines 317–318).
The configuration it specifies reintroduces the same class of drift by a different route.

**Why it matters** — from the repository root, `mypy` finds no `mypy.ini`, so it runs with its
built-in defaults: **no `django-stubs` plugin**, no `django_settings_module`. Django models,
managers, and querysets are then treated as untyped. The hook will pass on code that CI — which
runs from `django_version/` via `defaults.run.working-directory` — rejects. That is a
commit-time check that reports green while the real check is red.

Note that this defect is specific to `mypy`. `ruff` resolves configuration hierarchically from
each checked file's directory upward, so `django_version/ruff.toml` is found correctly from the
root. The plan treats the two tools as having identical config-discovery behavior (lines
161–163 explicitly say "same reasoning as `ruff.toml` in Task 2"); they do not.

**Direction** — Task 3 and Task 5 must agree on one mechanism. Either the hook passes the config
explicitly (`--config-file`), or the config moves to a location the root-level invocation finds.
This interacts with Open Decision 1 below: a single root `pyproject.toml` holding tool config
resolves it for all four tools at once.

---

### Issue 5 — Task 8's bandit pre-commit hook targets paths that do not exist from the repository root, and no task sets `pass_filenames`

**What** — two independent defects in how Tasks 5, 7, and 8 specify their hooks.

**(a) Wrong paths.** Task 8 requires the hook to be "targeted at `accounts/` and `profiles/`"
(line 521) and restates it in ACCEPTANCE CRITERIA as "targeting only `accounts/` and
`profiles/`" (lines 548–549). `pre-commit` runs from the repository root, where those
directories are `django_version/accounts/` and `django_version/profiles/`. The hook as specified
will fail with a path error.

**(b) `pass_filenames` is never addressed.** `pre-commit` appends the matched changed filenames
to the hook's command by default. This breaks two hooks in different ways:

- **`bandit`** receives its fixed targets *and* the changed filenames — the `tests/` and
  `migrations/` exclusions that Task 8 relies on (lines 511–515) are bypassed for any file
  pre-commit passes in explicitly.
- **`mypy`** receives only the changed files. Type-checking a subset of a package in isolation
  is a known source of both false positives (unresolved imports from files not passed) and false
  negatives (an error introduced in an unchanged file that a changed file now triggers). Task
  5's Open Questions (lines 368–377) anticipate `django-stubs` false positives from the
  project's ABC patterns but not this, which is the more likely source of noise.

**Where** — plan lines 521, 548–549 (paths); lines 313–318 and 519–522 (hooks specified with no
`pass_filenames` and no `args`).

**Rule violated** — `CLAUDE.md` Rule 9 (use current, verified APIs; do not write configuration
suspected to be wrong) and Rule 1 (do not fill gaps by assumption). The `pre-commit` hook
contract — cwd, `pass_filenames`, `args`, `files` — was not verified against the tool's own
documentation before the config was specified in three tasks.

**Why it matters** — Task 5 is ordered after Tasks 2 and 3 precisely so that `mypy` is stable
before it becomes commit-blocking (lines 862–864). That sequencing is correct and does not help
here: the noise comes from how the hook invokes `mypy`, not from `mypy`'s findings.

**Direction** — the three hook-defining tasks (5, 7, 8) need one verified `pre-commit`
configuration contract stated once, covering cwd, `pass_filenames`, `args`, and `files`, rather
than three tasks each describing their hook in prose. Verify against `pre-commit`'s own
documentation for the version pinned in Task 5 — do not carry over the shapes described in this
plan.

---

### Issue 6 — `language: system` does not invoke the `.venv` binaries the plan says it invokes

**What** — Task 5 states the hooks run "as `language: system` entries, invoking the `ruff`/`mypy`
already installed in `django_version/.venv/`" (lines 313–315). `language: system` means
`pre-commit` resolves the entry against `PATH` as it exists in the process that ran `git commit`.
It does not activate, or know about, `django_version/.venv/`.

**Where** — plan lines 313–318. Against root `CLAUDE.md`, "Execution environment": the host
virtualenv is "IDE-only… independent of Docker and is not the runtime."

**Rule violated** — `CLAUDE.md` Rule 1: the mechanism was assumed rather than verified. The
conclusion the plan draws from it ("This ties the hooks to the exact versions pinned in
`requirements-dev.txt`", lines 315–316) does not follow from the configuration described.

**Why it matters** — the binding to pinned versions is the entire justification for choosing
`language: system` over the community hooks (lines 316–318). Without it, the choice loses its
rationale. Concretely: a commit made from an editor's Git UI, from a shell where the venv is not
activated, or by any tooling that shells out to `git`, either runs a different `ruff`/`mypy`
found elsewhere on `PATH` or fails with `command not found` — which is the failure Task 5's own
Open Question at lines 369–372 anticipates but attributes solely to the venv not being
installed.

**Direction** — the fix is to make the entry an explicit path rather than a bare command name, so
resolution does not depend on the ambient shell. Verify the exact form against `pre-commit`'s
documentation before writing it; this audit does not prescribe the syntax.

Separately, this audit verified the state Task 5's first Open Question (lines 369–372) leaves
open: `django_version/.venv/bin/` contains `pytest`, `django-admin`, `dotenv`, `pygmentize`,
`sqlformat`, and `uv` — so `requirements.txt` **is** installed there. None of `ruff`, `mypy`,
`bandit`, `pre-commit`, or `pip-audit` is present, as expected before implementation.

---

### Issue 7 — Scoping `gitleaks` to `^django_version/` leaves the most likely leak sites unscanned

**What** — Task 7 scopes the `gitleaks` hook to `files: ^django_version/`, "like the other two
hooks" (lines 452–454, restated at lines 479–480).

**Where** — plan lines 452–454, 479–480.

**Rule violated** — the task's own stated purpose (lines 442–444): the problem it exists to solve
is "a key or password pasted directly into code, a settings file, or a test fixture by mistake."
A path filter that excludes most of the repository does not solve that problem.

**Why it matters** — the scoping reasoning is inherited from Tasks 5 and 8, where it is correct:
`ruff`, `mypy`, and `bandit` are Python tools and `oop_version/` is closed, so restricting them
matches root `CLAUDE.md`'s rule against running project commands there. A secret scanner is a
different kind of tool and the same reasoning does not transfer. Under the filter as specified,
these are never scanned:

- `.github/workflows/ci.yml` — which already handles two secrets (`secrets.SECRET_KEY`,
  `secrets.GIST_SECRET`) and is exactly where a token gets pasted inline during debugging
- everything at the repository root, including `.pre-commit-config.yaml` itself
- `docs/`, `specs/`, `.specify/` — a connection string pasted into a plan or spec is a real leak
- `oop_version/` — closed to *development*, but its files are still in a public repository; a
  secret there is exposed regardless of the directory's status

The GitHub-native layer (Task 7's step 1) does cover the whole repository, so this is a gap in
the "first line, before commit" layer only — but that layer is the one the user chose
specifically to avoid the brief public exposure that push-time detection cannot prevent (lines
460–463). Narrowing it to one subdirectory removes most of the value that choice was made for.

**Direction** — the exclusion needs to be decided from what a secret scanner is for, not
inherited from the linters. The plan's own two-layer reasoning at lines 443–446 (application
check plus backstop, mirroring `clean()` + `CheckConstraint`) is the right frame: the two layers
should cover the same surface, or the difference should be a recorded decision.

---

### Issue 8 — Task 7 cites a file that does not exist

**What** — Task 7's PROBLEM states that "`.env` and `.env.local` are already gitignored
(`django_version/.gitignore`)".

**Where** — plan lines 441–442. `django_version/.gitignore` does not exist. The patterns are in
the repository-root `.gitignore` (entries `.env` and `.env.local`).

**Rule violated** — `CLAUDE.md` Rule 2 (read the file before asserting what it contains) and
`AUDITOR.md`'s "do not bluff" rule, which applies equally to the Planner persona.

**Why it matters** — no functional consequence: the root patterns are unanchored, so they match
`.env` at any depth, and the protection the sentence claims is genuinely in place. The finding is
that a task's premise cites a nonexistent file, which means the Developer will look for it and
not find it — and, more importantly, that the same reading gap is what produced Issues 1 and 7.

**Direction** — correct the citation to the root `.gitignore`.

---

### Issue 9 — Task 2 misstates ruff's default rule set, and the set it describes conflicts with `ruff format`

**What** — Task 2 says rule selection "starts from ruff's own default rule set (`E`, `F` —
pycodestyle errors and Pyflakes — plus `I` for import sorting)" and calls this "the standard
starting point documented by the tool itself, not a contested choice" (lines 113–116).

`ruff`'s default selection is not the full `E` prefix. It is a deliberate subset that omits the
line-length rule, because line length is the formatter's responsibility. Writing
`select = ["E", "F", "I"]` — the literal reading of lines 113–116 — enables the full pycodestyle
error set including line-length checking.

**Where** — plan lines 113–116.

**Rule violated** — `CLAUDE.md` Rule 9: do not write configuration you have not verified against
the current documentation for the pinned version. `conventions.md`, "Stack and versions": the
exact pinned version determines behavior and must not be described as "the standard".

**Why it matters** — two consequences. First, `ruff check` and `ruff format` will disagree:
`ruff format` will produce lines that `ruff check` then rejects, and the CI job runs both as
build-failing steps (lines 133–135), so the build cannot be made green by running the formatter.
Second, the existing codebase already has lines that exceed the common default —
`config/settings.py`'s `AUTH_PASSWORD_VALIDATORS` entries are the clearest example. This inflates
the violation count that Task 2's Open Question (lines 143–147) asks the Developer to measure,
which is the number the user will use to decide whether cleanup belongs in this task or a
follow-up. A misleading count corrupts that decision.

**Direction** — Task 2 must state the actual default for the `ruff` version it pins, verified
against ruff's documentation, and state explicitly whether the rule set is being left at the
default or expanded — those are different decisions and the task currently reads as both.

---

### Issue 10 — Task 3 gives `mypy` no `exclude`, and does not name the runtime-environment dependency that `django_settings_module` creates

**What** — two omissions in Task 3's configuration.

**(a) No `exclude`.** The task specifies `mypy .` run from `django_version/` (lines 166–167,
185) with a `mypy.ini` that configures only the plugin and `django_settings_module` (lines
163–166). Nothing excludes `accounts/migrations/` and `profiles/migrations/` — machine-generated
files that the project neither writes by hand nor holds to `conventions.md`'s type-hint rule.

**(b) `django_settings_module` makes the type checker depend on runtime environment
configuration.** The `django-stubs` plugin loads the Django settings module. `config/settings.py`
calls `load_dotenv(BASE_DIR / ".env")` and then raises `ValueError("SECRET_KEY not found in
environment variables")` if `SECRET_KEY` is absent. So `mypy` does not fail with a type error
when the environment is incomplete — it aborts with an application exception.

**Where** — plan lines 161–167, 182–187. Against `config/settings.py` (the `SECRET_KEY` guard and
`load_dotenv` call) and `.github/workflows/ci.yml` lines 30–37.

**Rule violated** — `CLAUDE.md` Rule 1 (an unstated dependency is a gap, not a detail) and
`conventions.md`'s Docker-workflow rule, which the acceptance criterion at line 185 invokes
("runs inside Docker") without the plan having established that the tool exists there — see
Issue 2.

**Why it matters** — the environment happens to be populated on two of the three paths, which is
why this will not surface immediately and will be confusing when it does:

| Path | `SECRET_KEY` available? | Result |
| --- | --- | --- |
| CI | yes — job-level `env:` block, line 31 | works |
| Pre-commit on host | yes — `django_version/.env` exists and `load_dotenv` reads it | works |
| Any context without `.env` or the env vars | no | `mypy` aborts with `ValueError`, not a type error |

The third row includes a fresh clone before `.env` is created, and any future runner or container
that does not inherit the secret. The failure mode — a type checker crashing on a missing
application secret — is opaque enough to cost real debugging time, and the plan never names the
coupling.

**Direction** — Task 3 needs `exclude` patterns in its SCOPE and ACCEPTANCE CRITERIA, and needs
to state the environment precondition that `django_settings_module` introduces. Whether the
right answer is a dedicated type-checking settings module or an env precondition documented for
the Developer is a design question, not something to resolve here.

*Verification note:* whether `mypy` skips dot-prefixed directories such as `django_version/.venv/`
by default was not confirmed against mypy's documentation in this session. It should be checked
before the `exclude` list is written, rather than assumed either way.

---

### Issue 11 — `cache: pip` will not find the dependency file, because `working-directory` does not apply to action inputs

**What** — Task 9 specifies enabling `cache: pip` on the existing `actions/setup-python@v5` step
and calls it "a built-in option, no new configuration surface" (lines 583–584).

The workflow sets `defaults.run.working-directory: django_version` (`ci.yml` lines 11–13). That
default applies to `run:` steps only. It has no effect on an action's own inputs, so
`setup-python` resolves its cache dependency path relative to the repository root — where no
`requirements.txt` exists.

**Where** — plan lines 583–584, 626. Against `.github/workflows/ci.yml` lines 11–13 and 43–46.

**Rule violated** — `CLAUDE.md` Rule 9 and Rule 1: the option's resolution behavior was assumed,
not verified.

**Why it matters** — the step will either fail outright or silently cache nothing, which is the
worse outcome: Task 9's acceptance criterion (line 626) is "the `actions/setup-python@v5` step
has `cache: pip` enabled" — satisfied by a step that is enabled and doing nothing. The stated
benefit (faster installs) never materialises and nothing reports that.

There is a second-order interaction with Task 1: whichever file CI installs from after Task 1
(`requirements-dev.txt`, per line 45 — see Issue 3) is the file the cache key must hash. Hashing
`requirements.txt` alone would produce a stale cache every time a dev tool version changes.

**Direction** — `cache-dependency-path` must be set explicitly to the repository-relative path of
the file CI actually installs. Verify the exact default resolution behavior against
`actions/setup-python`'s documentation for `v5` before writing the value; this audit did not
confirm what the default glob is, only that `working-directory` does not influence it.

---

### Issue 12 — No task adds a missing-migration check, and `--no-migrations` means the 304-test suite structurally cannot catch one

**What** — the plan adds five quality/security tools and never adds
`python manage.py makemigrations --check --dry-run` to CI.

**Where** — the plan as a whole. Against `django_version/pytest.ini` line 10 (`--no-migrations`)
and `testing.md`, "Note on `--no-migrations` and data migrations."

**Rule violated** — this is a gap against current practice for the pinned stack, not against a
project document. `testing.md` already documents the mechanism and one of its consequences
(data migrations do not run); the second consequence is not documented anywhere and is the more
dangerous one.

**Why it matters** — `--no-migrations` makes pytest-django build the test schema directly from
the current model state. A model change committed **without** its migration therefore produces a
fully green suite: the schema is generated from the models, so it matches the models by
construction. The 304 tests cannot detect the omission. Neither can `ruff`, `mypy`, `bandit`,
`pip-audit`, or `gitleaks` — none of them reads migration state.

That leaves the project with no automated detection at all for a defect class that:

- is easy to commit (`CLAUDE.md` Rule 10 requires explicit approval before generating a
  migration, which makes "model edited, migration deferred, migration forgotten" a realistic
  sequence rather than a hypothetical one)
- surfaces only at `migrate` time in a real environment
- is exactly the class of drift this plan's whole premise (`BRIEFING_PLANNER_MVP_SKILLBRIDGE.md`)
  is about catching mechanically instead of by memory

The check is one CI step, needs no new dependency, and depends on no deploy-target decision — it
is inside this plan's scope boundary.

**Direction** — this belongs in the plan as its own task, sequenced with the other `ci.yml`
edits. `conventions.md`'s Docker-workflow section already establishes the `manage.py` invocation
form. The interaction with `CLAUDE.md` Rule 10 needs one line of thought: the check *detects* a
missing migration, it must not *generate* one.

---

### Issue 13 — The security block adds `bandit` but not `manage.py check --deploy`, which is the higher-value Django security signal

**What** — Tasks 6, 7, and 8 form the plan's security block: dependency CVEs, secrets, and static
analysis of Python code. Django's own deployment security checklist — `manage.py check --deploy`
— is not in the plan.

**Where** — the plan as a whole. Against `config/settings.py`.

**Rule violated** — a gap against current practice for the pinned stack (Django 6.0.7), the
second authority level in `AUDITOR.md`'s "What to check."

**Why it matters** — `bandit` is a general-purpose Python scanner. Against a Django codebase
consisting of models, validators, managers, and admin classes — no `subprocess`, no `eval`, no
raw SQL, no `yaml.load` — its realistic yield is close to zero, which Task 8's own Open Question
(lines 560–565) half-anticipates by budgeting for false positives rather than findings.
`check --deploy` targets the settings surface where this project's actual security posture is
decided, and `config/settings.py` currently has real gaps in exactly that surface.

The plan's scope boundary is the complication and it needs stating precisely, not waving away:
several `check --deploy` warnings (`SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`,
`SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `ALLOWED_HOSTS`) genuinely depend on a hosting
target that Phase 5 has not chosen, and are correctly excluded by the boundary at plan lines
13–18. But *running* the check is not hosting-dependent. A step that runs it and reports —
whether blocking now or informational until Phase 5 — costs nothing, needs no dependency, and
gives the Phase 5 planning session a concrete list instead of a fresh investigation.

Note also that Task 8's exclusion of `config/` from `bandit` (line 557, "not raised as part of
this finding") compounds this: the security block, taken as a whole, scans the two app packages
and never looks at the settings module at all.

**Direction** — this is a task-level omission, not a defect inside an existing task. Whether it
lands as blocking or informational is the user's call and interacts with the Phase 5 boundary.
`ARCHITECTURE.md` → "Docker and GitHub Actions CI" is where the resulting decision is recorded.

---

### Issue 14 — The workflow grants a third-party action access to a secret while pinned to a mutable tag

**What** — `ci.yml` uses `schneegans/dynamic-badges-action@v1.9.0` and passes it
`secrets.GIST_SECRET`. `v1.9.0` is a Git tag, which the action's owner can repoint at any commit
at any time. Task 9 reviews this workflow, adds `permissions:` and `cache: pip`, and does not
address it.

**Where** — `.github/workflows/ci.yml` lines 59–69. Plan Task 9 (lines 569–638).

**Rule violated** — a gap against GitHub's own hardening guidance for Actions, which is the
governing current practice for the pinned `actions/*@v4`/`@v5` and third-party actions in this
workflow.

**Why it matters** — this is the same threat model as Task 6 (`pip-audit`, a dependency you did
not write executing in your pipeline) and Task 7 (a leaked credential), applied to the one
dependency in the pipeline that already holds a credential. A compromised or repointed tag runs
attacker-controlled code in the job with `GIST_SECRET` in its environment. The plan is a
supply-chain and secret-security plan; leaving its own pipeline's third-party dependency
unpinned is an inconsistency in the plan's coverage, not a general nitpick about action pinning.

The distinction that matters: `actions/checkout` and `actions/setup-python` are
GitHub-maintained, and tag-pinning them is a defensible risk position.
`schneegans/dynamic-badges-action` is a third-party action that receives a secret — a materially
different case, and the only one of the three where the plan's own security reasoning applies
directly.

**Direction** — commit-SHA pinning is the standard mitigation. Whether it applies to all three
actions or only the third-party one is a decision, and Task 9 is where it belongs since that
task already owns the `ci.yml` hardening edits.

---

### Issue 15 — `pip-audit` only on `push` does not solve the problem Task 6 states

**What** — Task 6's PROBLEM is: "A version that was safe when pinned but has a vulnerability
discovered later goes unnoticed indefinitely" (lines 387–388). Its DECIDED APPROACH wires
`pip-audit` into `ci.yml`, whose only trigger is `on: push` (`ci.yml` lines 3–5), and Task 9
explicitly leaves the trigger unchanged (line 627).

**Where** — plan lines 386–394 versus lines 621–627 and `.github/workflows/ci.yml` lines 3–5.

**Rule violated** — internal inconsistency between a task's stated problem and its acceptance
criteria. The criteria (lines 415–418) verify that the command runs and that the job fails on a
finding; none of them verifies that a CVE published during a quiet period is detected.

**Why it matters** — the detection latency equals the interval between pushes. Advisories are
published continuously and pushes are not. For a portfolio project with gaps between working
sessions, a Django or psycopg advisory published on a Monday is invisible until the next commit,
which is precisely the "goes unnoticed indefinitely" state the task opened with. Push-triggered
auditing catches the *other* case well — a newly added or bumped dependency that is already
known-vulnerable — but the plan states the first case as its problem and delivers the second.

There is a second, opposite consequence worth deciding at the same time: `pip-audit` as a
hard-blocking step means a newly published advisory against a pinned version blocks *every*
commit, including unrelated ones, until a version bump — and `conventions.md` makes that bump an
architectural decision requiring approval, not something the Developer resolves on the spot
(which Task 6's own Open Question at lines 426–430 correctly recognises). The plan has no
position for what the Developer does while blocked.

**Direction** — the standard complement is a scheduled trigger, an automated dependency-update
service, or both; the plan mentions neither. This is a task-level gap in Task 6, and it
interacts with the `pull_request`/trigger restructuring already deferred in Task 9 — both are
questions about what `ci.yml`'s `on:` block should contain.

---

## Open Decisions — user choice needed

### Open Decision 1 — Tool configuration in a root `pyproject.toml` versus three standalone files

Task 1 defers the `pyproject.toml` migration and Tasks 2, 3, and 4 each create a standalone
config file as a consequence (`ruff.toml`, `mypy.ini`, `.coveragerc`), with Task 8 adding
`bandit` configuration on top.

Two things in that reasoning are worth putting in front of the user:

**The deferral conflates two separable decisions.** Task 1 defers `pyproject.toml` because of its
packaging scope — build backend, PEP 735 versus `optional-dependencies`, `Dockerfile`, `ci.yml`,
and the `conventions.md` version table (lines 51–55). All of that is true of `pyproject.toml`
*as a dependency-management file*. `pyproject.toml` as a **tool-configuration file only** —
`[tool.ruff]`, `[tool.mypy]`, `[tool.coverage.run]`, `[tool.bandit]`, with no `[project]` table,
no build backend, and `requirements.txt` untouched — carries none of that scope. It is supported
by every tool in this plan and changes nothing about how dependencies are declared or installed.

**The stated reason for deferring is imprecise.** Lines 68–70 and 89–92 defer pending
verification of "its current support in `pip` for the project's pinned Python 3.14." PEP 735
support is a function of the `pip` version, not the Python version — those are different things
to verify, and the one named is not the one that decides it. Separately, `django_version/.venv/`
already contains `uv`, which is relevant context the plan does not mention.

| Option | Trade-off |
| --- | --- |
| **A — keep three/four standalone files** (plan as written) | Matches each tool's own documented config format. Costs: four files to consolidate later; and it is the direct cause of Issue 4, since `mypy.ini` in `django_version/` is invisible to a root-level `pre-commit` invocation. |
| **B — a root `pyproject.toml` holding tool config only** | One file, found from the repository root, which resolves Issue 4 for all tools at once. No packaging decision, no `Dockerfile`/`ci.yml` change, no `conventions.md` table change — `requirements.txt` stays the dependency source of truth. Costs: introduces a file whose presence may invite the packaging migration before it has been decided; `pytest.ini` would either stay separate or move too, a second small decision. |
| **C — resolve the packaging migration first**, then configure tools inside it | Avoids doing the work twice. Costs: blocks this entire plan behind the deferred decision, which is what Task 1 deliberately chose not to do — and that choice was sound. |

The plan's reasoning for deferring the packaging migration stands on its own merits. What is
open is whether the *config-file* question was ever separated from it, and it was not.

---

### Open Decision 2 — `bandit` as a separate tool versus `ruff`'s bundled security rules

Task 8 states that `bandit` is "the only serious option evaluated" (line 524) and considers only
`semgrep` as an alternative. `ruff` — already being adopted in Task 2, already installed, already
configured, already wired into both CI and pre-commit — ships a port of `bandit`'s rule set under
its own `S` prefix. That option was not evaluated.

This is a genuine choice with real trade-offs, not a single-answer problem:

| Option | Trade-off |
| --- | --- |
| **A — `bandit` as a separate tool** (plan as written) | The reference implementation; complete and current rule set; `# nosec` suppressions and skip lists behave as documented upstream. Costs: a fifth dependency, a fifth CI step, a fourth pre-commit hook, and a separate exclusion mechanism to keep aligned with `ruff`'s. |
| **B — `ruff --select S`, no `bandit`** | Zero new dependencies, zero new steps, one exclusion mechanism, one config, one cache. Costs: `ruff`'s port is not guaranteed to be rule-for-rule complete against upstream `bandit` for the pinned versions — this must be verified, not assumed — and suppression uses `# noqa`, not `# nosec`. |
| **C — both** | Maximum coverage. Costs: overlapping findings reported twice with different codes, and two suppression mechanisms; hard to justify at this codebase's size. |

Two facts make this worth deciding rather than defaulting: `bandit`'s realistic yield against
this specific codebase is low (see Issue 13), and Task 8's `tests/` exclusion exists to dodge a
`B106` false positive — a rule-level problem that both options solve, with `ruff`'s per-file
ignore mechanism being the one already in use for other rules.

---

### Open Decision 3 — What `bandit` (or `ruff --select S`) actually scans

Whichever tool wins Open Decision 2, Task 8's scope decisions need revisiting as their own
question, because two of them work against the task's purpose:

- **`config/` excluded** (line 557, "not raised as part of this finding"). This is the settings
  module — the highest-value target for a security scanner in a Django project, and the one place
  where a hardcoded credential would do the most damage. Excluding it means the plan's entire
  security block never reads `settings.py`.
- **all of `tests/` excluded** (lines 511–515) to avoid `B106` firing on the documented
  `"SecurePass@123"` fixture from `testing.md`. Excluding an entire tree to silence one rule is a
  blunt instrument; the targeted alternative is to disable the hardcoded-password rules for test
  paths only, leaving every other check active there.

| Option | Trade-off |
| --- | --- |
| **A — plan as written** | Simplest config; guaranteed no false-positive noise from fixtures. Costs: `settings.py` unscanned; test code entirely unscanned. |
| **B — include `config/`, keep `tests/` excluded** | Closes the more significant gap with one line of config. Costs: may surface findings in `settings.py` on the first run that need a decision — which is what the plan's own "run locally first" pattern is designed for. |
| **C — include `config/`, and in `tests/` disable only the hardcoded-password rules** | Full coverage with targeted suppression; the exclusion is documented as being about one rule, not one directory. Costs: slightly more config; needs one verification run to confirm no other rule fires on fixtures. |

`conventions.md`'s Layer-ownership principle — a rule belongs to exactly one place, stated
explicitly — argues for the suppression being scoped to the rule it is about. But the choice is
the user's.

---

### Open Decision 4 — Whether CI should build the Docker image at all

`ci.yml` installs dependencies directly on the runner and never builds the image. The Docker
image is therefore validated only by a human running `docker-compose build` locally.

This plan changes the `Dockerfile` twice — Task 10 removes `pillow`, `libjpeg-dev`, and
`zlib1g-dev`; Task 12 adds a non-root user — and both tasks carry an acceptance criterion that
the image still builds (lines 676, 768). Neither criterion can be checked by CI as it stands.

| Option | Trade-off |
| --- | --- |
| **A — status quo, human verification** (plan as written) | No CI time cost. Consistent with `human-walks-quickstart-before-commits`. Costs: a `Dockerfile` regression is invisible to CI indefinitely; Tasks 10 and 12's acceptance criteria are unverifiable by any automated gate. |
| **B — add a `docker build` step** | Both tasks' criteria become mechanically checkable; the divergence between the CI environment and the development environment stops being silent. Costs: real CI minutes on every push; a second place where the Python version is asserted. |
| **C — run the whole test job inside the built image** | Removes the CI/dev environment divergence entirely, and would resolve Issue 2 as a side effect by making "inside Docker" the literal truth for CI too. Costs: the largest change to `ci.yml` in this plan by far, and well beyond what this planning session scoped. |

Raised because Issue 2 and this question have the same root — CI and development install from
different files into different environments — and the plan treats them as unrelated.

---

## Observations / Learning Notes — no action needed

**O1 — `libpq-dev` may be as orphaned as `pillow` was.** `requirements.txt` pins
`psycopg-binary==3.3.4`, the wheel that bundles its own libpq; the `Dockerfile` also installs
`libpq-dev` via `apt-get`. If the binary wheel is what is actually used at runtime, the system
package is redundant — the same finding as `pillow`, in the same `apt-get` line Task 10 already
edits. Not raised as an Issue because it is easy to get wrong from documentation alone and the
empirical check (drop it, rebuild, run the suite) is trivial. Worth mentioning to the Developer
while Task 10 has that line open.

**O2 — Task 13 under-counts the deferrals it exists to record.** It names five (Tasks 1, 6, 7, 9,
11). By its own criterion — "a deliberate, documented deferral with a revisit trigger" — the plan
also defers: `config/` scanning in Task 8 (line 557), branch coverage and external report upload
in Task 4 (lines 284–287), rule-set expansion in Task 2 (lines 140–141), generic hygiene hooks in
Task 5 (lines 365–366), and Task 12's conditional fallback (lines 780–783). Whether all of those
deserve a `docs/tech_debt/` file is a judgement call; Task 8's `config/` exclusion is the one with
a security consequence and is the strongest candidate for a sixth entry. The `006`–`010`
numbering itself is correct — `005` is confirmed as the last entry on disk.

**O3 — Task 1's "byte-identical" criterion is invalidated later in the same plan.** Line 80
requires `requirements.txt` to be byte-identical to its committed content; Task 10 removes the
`pillow` line from it. Execution order (Task 1 first, Task 10 ninth) means no conflict during
implementation, but a Verifier checking acceptance criteria after the plan completes will find
the criterion false. Worth phrasing as a point-in-time statement.

**O4 — no task gitignores the new cache directories.** `ruff` and `mypy` write `.ruff_cache/` and
`.mypy_cache/` into the directory they run from — inside the bind-mounted, git-tracked
`django_version/`. The root `.gitignore` covers `.pytest_cache/`, `.coverage`, and `htmlcov/`, so
Task 4 is fine; Tasks 2 and 3 are not, and neither scopes a `.gitignore` edit. Cosmetic, but it
will produce untracked-file noise on the first run.

**O5 — `pip-audit` will audit the production dependencies twice.** `requirements-dev.txt` begins
with `-r requirements.txt` (line 78), and Task 6 runs `pip-audit` against both files (lines
390–393). Whether `pip-audit`'s requirements parsing follows the nested `-r` was not verified in
this session. If it does, the production set is scanned twice — harmless, slightly slower. Noted
so it is not mistaken for a defect if it shows up in the CI log.

**O6 — Task 4's exclusion rationale is looser than its conclusion.** Excluding `apps.py` and
`__init__.py` is justified as removing "boilerplate that execute[s] merely by being imported"
(lines 220–222). Every model module's class body also executes on import; that property does not
distinguish boilerplate from real code. The exclusions are still the right ones — for the
simpler reason that nobody writes tests for `startapp` scaffolding — but the stated reason does
not carry the conclusion, and a future reader may generalise from it incorrectly.

**O7 — security items in the briefing that this plan does not pick up.**
`BRIEFING_PLANNER_MVP_SKILLBRIDGE.md` §3.3 records two settings-level security gaps, both
confirmed against `config/settings.py` in this session: `validate_strong_password` is wired into
neither `AUTH_PASSWORD_VALIDATORS` nor any field's `validators=[...]`, so an admin password
change does not apply the project's own strength rule; and `AUTH_PASSWORD_VALIDATORS` declares
two of Django's four defaults. Outside this plan's tooling scope and already tracked in the
briefing — noted only because no tool this plan adds would ever surface either one, so
implementing all thirteen tasks does not close them.

**O8 — the dead `jobs` logger.** `config/settings.py` configures a `jobs` logger for an app that
does not exist in `INSTALLED_APPS`. Already recorded in the briefing's orphan list; harmless.

**O9 — `.venv` state, resolving half of Task 5's first Open Question.** Verified this session:
`django_version/.venv/bin/` contains `pytest`, `django-admin`, `dotenv`, `pygmentize`,
`sqlformat`, `python3.14`, and `uv` — so `requirements.txt` is installed there. None of the
plan's five new tools is present, as expected pre-implementation. The remaining half of that
question (installing `requirements-dev.txt` into it) still stands.

**O10 — what the plan gets right, so a rewrite does not lose it.** The "run the tool locally
first, report the real number, then decide whether to make it blocking" pattern (Tasks 2, 3, 4,
7, 8, 12) is the strongest thing in this document and is applied consistently. Task 9's
correction of its own earlier framing on the `pull_request` trigger, Task 11's refusal to
repurpose a business route as a health check, and Task 13's existence at all are all sound
judgement. The findings above are about mechanism and coverage, not about how the plan reasons.

---

## Handoff — next session

**What was audited.** `docs/plan/plan_ci-quality-security_2026-08-14.md`, Tasks 1–13, against the
files it proposes to change (`requirements.txt`, `Dockerfile`, `docker-compose.yml`, `ci.yml`,
`pytest.ini`, `config/settings.py`, root `.gitignore`) and against the project's authority
documents.

**Counts.** 15 Issues · 4 Open Decisions · 10 Observations.

**The four that block implementation.** Issues 1, 2, 3, and 4 are load-bearing: Task 1's premise
is wrong about its own target file, no mechanism installs the dev tools where four tasks assert
they run, Task 1's `ci.yml` edit is unscoped, and the pre-commit/`mypy` config pairing produces a
green local check against a red CI check. Tasks 2–5 cannot be implemented as written until those
four are resolved. Issues 9, 10, 11, and 5 are configuration defects inside individual tasks and
can be fixed task by task. Issues 12, 13, 14, and 15 are coverage gaps — they add work rather
than correcting it, and are the user's call on scope.

**Recommended next persona.** Planner, revising this plan file. This is not Developer work: four
of the Issues change what the tasks *are*, and all four Open Decisions require the user to
choose before any task is written. Nothing here should go to a Developer session until the plan
is corrected.

**Files the next session should attach.**

- `docs/plan/plan_ci-quality-security_2026-08-14.md` (the file being revised)
- this audit
- `django_version/requirements.txt`, `django_version/Dockerfile`,
  `django_version/docker-compose.yml`, `django_version/pytest.ini`
- `.github/workflows/ci.yml`, root `.gitignore`
- `django_version/config/settings.py`
- `docs/BRIEFING_PLANNER_MVP_SKILLBRIDGE.md` (§3.3)
- `ARCHITECTURE.md` → "Docker and GitHub Actions CI" (where the resulting decisions are recorded)

**What the next session must verify against official documentation, not training data** — this
plan pins five new tools and specifies configuration for four of them without a single
verification step of this kind, while Task 1 correctly demands exactly that before adopting PEP
735. The asymmetry is itself worth noting:

- `ruff`'s actual default rule selection for the version to be pinned (Issue 9)
- `pre-commit`'s hook contract: working directory, `pass_filenames`, `args`, `files`, and how
  `language: system` resolves an entry (Issues 5, 6)
- `mypy`'s config-file discovery rules and its default directory-traversal behavior (Issues 4,
  10)
- `actions/setup-python@v5`'s `cache-dependency-path` default resolution (Issue 11)
- `django-stubs` compatibility with Django 6.0.7 and Python 3.14 — Task 3's Open Questions
  anticipate false positives from this project's ABC patterns but never ask whether the plugin
  supports the pinned Django version at all
- `ruff`'s `S` rule set completeness against upstream `bandit`, if Open Decision 2 goes that way
- whether `pip-audit -r` follows a nested `-r` include (Observation O5)
