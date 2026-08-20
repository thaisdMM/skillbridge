# Verification — `docs/audits/2026-08-15-audit-plan-ci-quality-security.md`

**Date**: 2026-08-15
**Persona**: Verifier (read-only). No file was modified other than this one.
**Audit under verification**: `docs/audits/2026-08-15-audit-plan-ci-quality-security.md`
(15 Issues · 4 Open Decisions · 10 Observations).
**Plan the audit targets**: `docs/plan/plan_ci-quality-security_2026-08-14.md` (Tasks 1–13).

**Primary sources read in full, in the current context**

- `django_version/requirements.txt`, `django_version/Dockerfile`,
  `django_version/.dockerignore`, `django_version/docker-compose.yml`,
  `django_version/pytest.ini`, `django_version/config/settings.py`,
  `django_version/accounts/models/base.py`
- `.github/workflows/ci.yml`, root `.gitignore`
- `django_version/CLAUDE.md`, root `CLAUDE.md`, `.claude/rules/conventions.md`,
  `.claude/rules/testing.md`, `django_version/VERIFIER.md`

**Executed on this machine (read-only commands)**

- `ls -a` on the repository root and on `django_version/` — established which `.gitignore`
  files exist and that `django_version/.dockerignore` and `django_version/.env` exist.
- `django_version/.venv/bin/pip show pytest` / `pip show pygments` — established the real
  dependency edges behind Issue 1's table.
- `awk 'length > 88'` over `django_version/{accounts,profiles,config}` — established that
  E501-class violations already exist (Issue 9).

**Official documentation consulted, for the behavior each finding turns on** — mypy config
discovery and source crawling (including `mypy/config_parser.py` and `mypy/find_sources.py`
on `master`), pre-commit hook contract, Ruff default rules / configuration discovery /
formatter compatibility, `actions/setup-python` pip cache source, the gitleaks
`.pre-commit-hooks.yaml`, pytest-django `--no-migrations`, GitHub Actions security hardening,
bandit configuration.

**Docker was not used.** Verifying these findings required no state change and no running
container: every claim resolved against source files, official documentation, or read-only
host commands. Nothing here was installed, and no container command was run.

**Scope.** Only the audit's own claims are verified. No new finding about the plan is raised,
and no severity label is reclassified.

---

## Part 1 — Finding by finding

### 🟣 Issue 1 — `requirements.txt` already contains dev-only dependencies — **HOLDS**

`django_version/requirements.txt` pins `pytest==9.1.1` and `pytest-django==4.12.0`. Neither is
imported by any code path the deployed application executes; both are the test toolchain,
which `.claude/rules/conventions.md` itself lists under "Stack and versions" as testing
packages.

The four transitive rows in the audit's table are confirmed by package metadata rather than by
inference:

```
$ django_version/.venv/bin/pip show pytest
Requires: iniconfig, packaging, pluggy, pygments

$ django_version/.venv/bin/pip show pygments
Required-by: pytest
```

So `iniconfig`, `packaging`, `pluggy` and `Pygments` are in the file because `pytest` is — all
six rows of the audit's table are correct. Task 1's PROBLEM statement ("currently lists only
production runtime dependencies") is therefore false about its own target file, and the
consequences the audit draws follow: the split as specified leaves the test runner in the
production install, and Task 6's "production" audit step audits it.

*Aside, not a finding:* the venv has `pytest 9.0.2` and `pygments 2.19.2` installed, while
`requirements.txt` pins `pytest==9.1.1`. The host venv has drifted from the pinned set. This
does not affect any verdict — it is noted because Issue 6 and O9 both reason about what that
venv contains.

---

### 🟤 Issue 2 — nothing installs the dev tools where four tasks assert they run — **PARTIAL**

**The part that holds.** No task in the plan installs `ruff`, `mypy`, `pytest-cov`,
`pip-audit` or `bandit` into the image. `Dockerfile:22` installs from `requirements.txt` only,
Task 1 explicitly declines to change it, and no later task revisits it. Tasks 2, 3 and 4 then
assert acceptance criteria in the form "runs inside Docker" (plan lines 133–134, 185, 273).
Those criteria cannot be met by the image the plan produces, and root `CLAUDE.md` →
"Execution environment" plus `django_version/CLAUDE.md` Rule 12 leave the Developer no
sanctioned alternative. The structural conflict the audit names — "the production image stays
lean" versus "dev tooling runs inside Docker", with no mechanism reconciling them — is real
and is the plan's largest gap.

**The part that does not hold.** The table row for plan line 79 claims the file "is never
`COPY`d in". `Dockerfile:25` is `COPY . .`, and `django_version/.dockerignore` excludes
`__pycache__/`, `.venv/`, `.env`, `.git/`, `.pytest_cache/`, `htmlcov/`, `.coverage` and
`.DS_Store` — not `requirements-dev.txt`. Independently, `docker-compose.yml:25-26` bind-mounts
`.:/app`, so the file is present in the running container regardless of the image. Task 1's
criterion `pip install -r requirements-dev.txt` succeeding inside Docker is therefore
satisfiable as written.

**What that correction does not rescue.** An install performed with
`docker-compose exec web pip install …` lives in the container's writable layer only. It is
lost on the next `docker-compose up --build`, on any container recreation, and it never exists
for a fresh clone. So the tools are not *reliably* present inside Docker, which is the same
conclusion by a more precise route — and arguably a sharper statement of the gap than the one
the audit made.

---

### 🟣 Issue 3 — Task 1's `ci.yml` change is in neither SCOPE nor ACCEPTANCE CRITERIA — **HOLDS**

Plan line 45 states "`ci.yml` and local dev setup install from `requirements-dev.txt`". Task 1's
SCOPE (plan lines 72–75) names only the new file and the files that do *not* change; `ci.yml`
is absent. Its ACCEPTANCE CRITERIA (lines 78–80) has three bullets, none about `ci.yml`.
`.github/workflows/ci.yml:48-49` currently runs `pip install -r requirements.txt`.

The consequence the audit describes is mechanical: with that line unchanged, the first CI run
of Task 2 fails at `ruff: command not found`, and the acceptance criteria of Task 1 would still
all read as satisfied.

---

### 🟣 Issue 4 — `mypy.ini` in `django_version/` is invisible to a root-level pre-commit run — **HOLDS**

Verified against mypy's own source rather than the audit's reasoning.
`mypy/config_parser.py` → `_find_config_file()` begins:

```python
current_dir = os.path.abspath(os.getcwd())
```

and walks *upward* from there, stopping at the repository root. The documented search order in
each directory is `mypy.ini`, `.mypy.ini`, `pyproject.toml` (with `[tool.mypy]`), `setup.cfg`
(with `[mypy]`), then user-level fallbacks (mypy docs, "The mypy configuration file").

pre-commit executes hooks from the top of the repository, and the repository root here *is* the
git root — so the upward walk starts at the root and terminates there. It never descends into
`django_version/`. `django_version/mypy.ini` is not found. mypy then runs with built-in
defaults: no `django-stubs` plugin, no `django_settings_module`. A hook that reports green
against a check CI runs red is exactly the drift Task 5 exists to prevent.

One refinement to the audit's wording: current mypy *does* walk up — the audit says it "does
not walk up from the source files being checked". The correct statement is that it walks up
**from the current working directory**, not from the checked files. The conclusion is unchanged
and, if anything, firmer: from the root, the walk cannot reach a subdirectory config by any
route.

The contrast the audit draws with Ruff is also correct. Ruff's documentation: *"Ruff supports
hierarchical configuration, such that the 'closest' config file in the directory hierarchy is
used for every individual file"* — so `django_version/ruff.toml` **is** found for files under
`django_version/`, even when Ruff is invoked from the root. The plan's "same reasoning as
`ruff.toml` in Task 2" (line 162) is the false step.

A second consequence the audit does not state, from the same root: with cwd at the repository
root, `django_settings_module = config.settings` is not importable either, since `config` lives
under `django_version/`.

---

### 🟣 Issue 5 — bandit's hook paths and the unaddressed `pass_filenames` — **HOLDS**

**(a)** pre-commit runs hooks from the repository root. `accounts/` and `profiles/` do not exist
there; they are `django_version/accounts/` and `django_version/profiles/`. Task 8's requirement
(plan lines 521, 548–549) is therefore unrunnable as written.

**(b)** pre-commit's documented default is `pass_filenames: true` — *"(optional: default `true`)
whether to pass filenames to the hook or not"* — with `files` acting as a `re.search` filter
over the changed paths, not as a scope argument to the command. Neither Task 5 nor Task 8
addresses `pass_filenames` or `args`, so both hooks inherit the default: `bandit` receives its
fixed targets *plus* the changed filenames (bypassing its own `tests/`/`migrations/`
exclusions), and `mypy` receives a file subset rather than the package.

---

### 🟣 Issue 6 — `language: system` does not invoke the `.venv` binaries — **HOLDS**

pre-commit's documentation on `system`: *"System hooks provide a way to write hooks for
system-level executables … This hook type will not be given a virtual environment to work
with."* The entry is resolved against the `PATH` of the process that invoked `git commit`.
Nothing in the configuration points at `django_version/.venv/`, and pre-commit does not
activate it.

The plan's claim at lines 315–316 — "This ties the hooks to the exact versions pinned in
`requirements-dev.txt`" — does not follow from the mechanism it describes. The binding holds
only when the shell running `git commit` happens to have that venv on `PATH`; root `CLAUDE.md`
recommends keeping it active, but an editor Git UI or any tool shelling out to `git` need not.
And, as noted under Issue 1, that venv is already drifting from the pinned versions, so even
the best case does not give the guarantee the plan claims.

**One currency point in the plan's favour of being revisited, not a new finding**: pre-commit's
current documentation records that `language: system` was renamed in 4.4.0 and that *"the alias
will be removed in a future version"*. The plan pins `pre-commit` without naming a version;
whichever version is pinned, the language key should be verified against that version's
documentation (`django_version/CLAUDE.md` Rule 9).

---

### 🟤 Issue 7 — the `gitleaks` scoping gap — **PARTIAL**

**The mechanism the audit describes does not hold.** The upstream hook definition
(`gitleaks/gitleaks` → `.pre-commit-hooks.yaml`) is:

```yaml
- id: gitleaks
  entry: gitleaks git --pre-commit --redact --staged --verbose
  language: golang
  pass_filenames: false
```

With `pass_filenames: false` and `--staged`, gitleaks scans the entire staged diff. Filenames
are never handed to it, so `files: ^django_version/` cannot restrict *what* is scanned. The
audit's list of things that "are never scanned" — `ci.yml`, root files, `docs/`, `oop_version/`
— is therefore incorrect as stated: whenever the hook runs, those files are scanned if they are
staged.

**The gap itself holds, in a different shape.** In pre-commit, `files` decides *whether the hook
runs at all*: a hook with no matching changed file is skipped unless `always_run: true` (which
the plan does not specify). So the real behavior is binary — a commit that touches no file under
`django_version/` runs no secret scan whatsoever. A commit that edits only
`.github/workflows/ci.yml`, only `docs/`, or only `.pre-commit-config.yaml` is exactly the
commit the audit worries about, and it is unprotected. The audit's conclusion (the
before-commit layer does not cover the surface the task exists to protect) survives; its
explanation of why does not.

Note that the plan is wrong in the *same* way the audit is: plan lines 452–454 and 479–480 also
assume `files:` scopes the scan. Whatever is decided, it should be decided from the hook's
actual contract.

---

### 🟣 Issue 8 — Task 7 cites a file that does not exist — **HOLDS**

There is no `django_version/.gitignore`. `find . -maxdepth 3 -name .gitignore` returns
`./.gitignore`, plus tool-generated files inside `.pytest_cache/` and `.venv/` directories in
both versions — none of them a project file. The root `.gitignore` carries the entries
`.env` and `.env.local`.

The audit's own qualification is also correct: the patterns are unanchored, so they match at any
depth and the protection Task 7 claims genuinely exists. The defect is the citation, not the
coverage.

---

### 🟣 Issue 9 — Task 2 misstates Ruff's default rule set — **HOLDS**

Ruff's documentation states that the default set omits *"any stylistic rules that overlap with
the use of a formatter"*, and the Default Rules listing enables only `E722`, `E902` and `W605`
from pycodestyle. `E501` (line-too-long) is **not** in the default set. Writing
`select = ["E", "F", "I"]` — the literal reading of plan lines 113–116 — turns the whole
pycodestyle error prefix on, `E501` included.

The plan is imprecise in a second direction as well: `I001` is already part of Ruff's current
default set, so "plus `I` for import sorting" also misdescribes what the default gives.

Both stated consequences check out:

1. Ruff's formatter documentation: *"the formatter only makes a best-effort attempt to wrap
   lines at the configured line-length. As such, formatted code may exceed the line length,
   leading to line-too-long (E501) errors."* With both `ruff check` and `ruff format --check`
   wired as build-failing steps (plan lines 133–135), a file the formatter cannot fix leaves no
   green path.
2. Such a file already exists. `django_version/config/settings.py:94` is 91 characters — the
   `UserAttributeSimilarityValidator` dotted path inside `AUTH_PASSWORD_VALIDATORS`, a single
   string literal the formatter will not split (Ruff's `line-length` default is 88). A sweep
   over `accounts/`, `profiles/` and `config/` finds over-88 lines in ~30 files, most heavily in
   migrations and test files.

---

### 🟣 Issue 10 — no `exclude`, and the undeclared runtime dependency of `django_settings_module` — **HOLDS**

**(a)** Confirmed by reading the task: Task 3's SCOPE (plan lines 178–180) and ACCEPTANCE
CRITERIA (182–187) specify only the plugin and `django_settings_module`. No `exclude` for
`accounts/migrations/` and `profiles/migrations/` is stated anywhere.

**(b)** Confirmed against the file. `config/settings.py:9` calls `load_dotenv(BASE_DIR / ".env")`
and `config/settings.py:16-18` raises `ValueError("SECRET_KEY not found in environment
variables")` when the variable is absent. The `django-stubs` plugin imports the settings module
named by `django_settings_module`, so an incomplete environment produces an application
exception, not a type error. The audit's three-row table is right on each row:
`ci.yml:30-37` supplies `SECRET_KEY` from `secrets.SECRET_KEY` in CI; `django_version/.env`
exists on this machine and `load_dotenv` resolves it by absolute path, so cwd does not matter
for the host case; anything else aborts.

**Resolving the audit's own verification note.** The audit left open whether mypy skips
dot-prefixed directories such as `django_version/.venv/`. It does. `mypy/find_sources.py`:

```python
if name in ("__pycache__", "site-packages", "node_modules") or name.startswith("."):
    continue
```

So `mypy .` from `django_version/` will not crawl `.venv/`. The `exclude` list still needs to
be written for the migrations, but it does not need to defend against the venv.

---

### 🟤 Issue 11 — `cache: pip` and `working-directory` — **PARTIAL**

**What holds.** `defaults.run.working-directory` (`ci.yml:11-13`) applies to `run:` steps only
and has no effect on an action's inputs. That premise is correct.

**What does not hold — the predicted failure.** `actions/setup-python`'s pip cache distributor
carries its own default:

```typescript
constructor(
    private pythonVersion: string,
    cacheDependencyPath = '**/requirements.txt'
  ) {
```

`**/requirements.txt` is a recursive glob evaluated from the workspace root, and it matches
`django_version/requirements.txt` (and also `oop_version/requirements.txt`, which exists). So
the step neither fails for want of a file nor silently caches nothing — it works, and hashes
both matched files into the key. The audit's core sentence — "`setup-python` resolves its cache
dependency path relative to the repository root — where no `requirements.txt` exists" — is
wrong: the default is recursive, not root-only.

**What survives.** The second-order point in the audit's last paragraph is correct and is the
part worth acting on: after Task 1, CI installs from `requirements-dev.txt` (plan line 45),
while the default key hashes `requirements.txt` — so bumping a dev tool's pinned version would
not invalidate the cache. Setting `cache-dependency-path` explicitly is still the right
instruction; the reason is key correctness, not a broken lookup. A side effect worth one line
of thought while deciding: under the default, editing `oop_version/requirements.txt` — a closed
directory — invalidates the cache for the active project.

---

### 🟣 Issue 12 — no missing-migration check, and `--no-migrations` cannot catch one — **HOLDS**

`django_version/pytest.ini:10` carries `--no-migrations`. pytest-django's documentation: *"Using
`--no-migrations` (alias: `--nomigrations`) will disable Django migrations and create the
database by inspecting all models."* A schema built by inspecting the models matches the models
by construction, so a model change committed without its migration produces a fully green suite.

None of the five tools the plan adds reads migration state, and `.github/workflows/ci.yml`'s
only quality gate is `pytest` (line 52). So the claim "no automated detection at all for this
defect class" is accurate for the repository as it stands and as the plan would leave it. The
audit's framing of the risk is also fair: `django_version/CLAUDE.md` Rule 10 requires explicit
approval before generating a migration, which makes "model edited, migration deferred, migration
forgotten" a realistic sequence.

`makemigrations --check --dry-run` needs no new dependency and no hosting decision, so the audit
is right that it sits inside the plan's own scope boundary. This is a coverage gap, not a defect
inside an existing task — whether it enters the plan is the user's scope call.

---

### 🟣 Issue 13 — the security block omits `manage.py check --deploy` — **HOLDS**, with one part marked as judgment

Verified factually: Tasks 6–8 cover CVEs, secrets and Python static analysis, and nothing in the
plan runs Django's own deployment checklist. Task 8 excludes `config/` explicitly (plan line
557), so the security block never reads `config/settings.py` — which currently has
`ALLOWED_HOSTS = []`, `DEBUG` from the environment, and no `SECURE_*` / cookie settings at all.
The audit's statement that *running* the check is not hosting-dependent, even though several of
its warnings are, is correct.

Marked as judgment, not verified fact: "`bandit`'s realistic yield … is close to zero" and
"`check --deploy` … is the higher-value Django security signal". Both are reasonable readings of
a codebase with no `subprocess`, `eval` or raw SQL, but neither was measured in the audit or
here. The omission holds regardless of how the two tools rank.

---

### 🟣 Issue 14 — a third-party action holding a secret is pinned to a mutable tag — **HOLDS**

`.github/workflows/ci.yml:59-68` uses `schneegans/dynamic-badges-action@v1.9.0` and passes
`auth: ${{ secrets.GIST_SECRET }}`. GitHub's security-hardening guidance: *"Pinning an action to
a full-length commit SHA is currently the only way to use an action as an immutable release"*,
and *"there is risk to this approach even if you trust the author, because a tag can be moved or
deleted if a bad actor gains access to the repository storing the action."*

The audit's distinction between GitHub-maintained actions and a third-party action that receives
a credential is the same distinction GitHub's own guidance draws, and Task 9 is the task already
editing this workflow's hardening surface. The `if: github.ref == 'refs/heads/main'` and
`continue-on-error: true` on that step do not change the exposure: when it does run, the secret
is in the step's environment.

---

### 🟣 Issue 15 — `pip-audit` on `push` only does not solve Task 6's stated problem — **HOLDS**

`.github/workflows/ci.yml:3-5` triggers on `push` to `**` and nothing else; Task 9 leaves the
trigger unchanged (plan lines 621–627). Detection latency therefore equals the interval between
pushes, while Task 6's PROBLEM (plan lines 387–388) is about a vulnerability *discovered after*
pinning. Push-triggered auditing addresses the adjacent case — a newly added or bumped
dependency that is already known-vulnerable — which is not the case the task states.

The audit's second point is also sound and follows from a project rule rather than from
preference: `.claude/rules/conventions.md` → "Stack and versions" makes a version change an
approval-gated decision, so a hard-blocking `pip-audit` step can block every commit on an
advisory the Developer is not authorised to resolve. The plan states no position for that state.

---

### Open Decisions

#### 🟤 Open Decision 1 — root `pyproject.toml` for tool config — **PARTIAL** (the framing holds; one supporting claim is imprecise)

**Holds.** The separation the audit draws is real: `pyproject.toml` carrying only `[tool.*]`
sections, with no `[project]` table and no build backend, changes nothing about how dependencies
are declared, and Task 1's deferral reasoning (build backend, PEP 735, `Dockerfile`, `ci.yml`,
the `conventions.md` table) is entirely about the dependency-management role. That the
config-file question was never separated from the packaging question is a fair reading of plan
lines 51–58 and 89–92.

**Holds.** "PEP 735 support is a function of the `pip` version, not the Python version" is
correct — `dependency-groups` is consumed by the installer, and Task 1's stated verification
target ("its current support in `pip` for the project's pinned Python 3.14", lines 68–70 and
89–92) names the wrong variable.

**Holds.** Option B would resolve Issue 4: with the config at the repository root, mypy's
upward walk from the root finds it, per `_find_config_file()` above.

**Imprecise.** "It is supported by every tool in this plan" over-states bandit's case. bandit
does not auto-discover `pyproject.toml`: it must be passed explicitly (`-c pyproject.toml`), and
the TOML support requires the `toml` extra — bandit's own documentation shows
`additional_dependencies: ["bandit[toml]"]` for its pre-commit usage. Ruff, mypy and coverage do
read their `[tool.*]` sections from a discovered `pyproject.toml`; bandit needs an explicit flag
and an extra. That does not defeat Option B, but it is a fourth line of configuration the option
should be costed with.

**Open question for you, not a verdict:** was `uv`'s presence in `django_version/.venv/bin/`
(alongside `uvx`) deliberate — i.e. is `uv` part of your intended workflow — or incidental? The
audit raises it as relevant context; whether it is depends on history I do not have.

#### 🟣 Open Decision 2 — `bandit` versus Ruff's `S` rules — **HOLDS** as a genuine, undecided choice

Ruff's rule index lists the `S` prefix as its port of `flake8-bandit` (itself a wrapper over
bandit's checks), so the option exists and Task 8 did not evaluate it — verified against the
plan, which names `semgrep` as the only alternative considered (plan lines 524–532). The audit's
caveat is the right one to carry into the decision: Ruff's documentation presents the `S` rules
without asserting parity with upstream bandit, so completeness must be verified against the
pinned versions rather than assumed. The trade-off table itself is a decision aid, not a claim
to verify.

#### 🟣 Open Decision 3 — what the security scanner actually scans — **HOLDS**

Both premises are verified against the plan: `config/` is excluded (line 557) and all of
`tests/` is excluded to dodge `B106` (lines 511–515). The consequence — the plan's security
block never reads `config/settings.py` — is the same fact Issue 13 rests on, and is correct.
Which of the three options to take is the user's call.

#### 🟣 Open Decision 4 — whether CI should build the image — **HOLDS**

`.github/workflows/ci.yml` installs on the runner (line 49) and never runs `docker build`;
`docker-compose.yml:23` builds only on the developer's machine. Tasks 10 and 12 both carry an
acceptance criterion that the image still builds (plan lines 676, 768), and neither is checkable
by CI as it stands. The audit's observation that this shares a root cause with Issue 2 is
accurate.

### Observations

- 🟠 **O1 — `libpq-dev`.** Plausible and worth the empirical check, not verified here.
  `requirements.txt:10-12` pins `psycopg`, `psycopg-binary` and `psycopg-pool`; the binary wheel
  bundles its own libpq, which is why the audit suspects `Dockerfile:15`'s `libpq-dev` is
  redundant. Whether anything in the build still needs `pg_config` from that package is exactly
  what a rebuild would settle — the audit's own recommendation. Reasoning, not a verified fact.
- 🟣 **O2 — Task 13 under-counts.** Verified: each additional deferral the audit lists exists at
  the plan lines cited. Whether each deserves a file is judgment; the `005` sequence claim is
  confirmed — `docs/tech_debt/` ends at `005-standalone-profile-screens-…`.
- 🟣 **O3 — "byte-identical" invalidated later.** Verified: plan line 80 versus Task 10's removal
  of the `pillow` line from the same file.
- 🟣 **O4 — cache directories not gitignored.** Verified: the root `.gitignore` covers
  `.pytest_cache/`, `.coverage` and `htmlcov/`, and contains no `.ruff_cache/` or `.mypy_cache/`
  entry. `django_version/.dockerignore` does not list them either — a second, smaller instance
  of the same omission.
- 🟠 **O5 — nested `-r` in `pip-audit`.** Correctly labelled unverified by the audit; also not
  verified here. Left open deliberately rather than answered from memory.
- 🟣 **O6 — Task 4's exclusion rationale.** The stylistic point is fair: "executes merely by
  being imported" is true of every module in the project, so it does not distinguish
  `apps.py`/`__init__.py` from real code. The exclusions themselves are not disputed by the
  audit and are not disputed here.
- 🟣 **O7 — briefing security items.** Verified against source. `config/settings.py:92-99`
  declares two of Django's four default validators (`UserAttributeSimilarityValidator`,
  `CommonPasswordValidator`), and `validate_strong_password` appears nowhere in `settings.py`
  and on no field's `validators=[…]`: `accounts/models/base.py:177,184` wire `validate_email`
  and `validate_user_name` only. The custom rule runs at exactly one place —
  `accounts/models/base.py:76`, inside `BaseUserManager.create_user` — so a password set through
  any other path does not go through it. The audit's point stands: no tool this plan adds would
  surface either gap.
- 🟣 **O8 — the dead `jobs` logger.** Verified: `config/settings.py:159-163` configures it;
  `INSTALLED_APPS` (lines 28–37) lists only `accounts` and `profiles`.
- 🟤 **O9 — `.venv` state.** The listed binaries are present (`pytest`, `django-admin`, `dotenv`,
  `pygmentize`, `sqlformat`, `python3.14`, `uv`), plus `pip`, `py.test` and `uvx`, and none of
  the plan's five new tools is there. One correction to the conclusion "`requirements.txt` **is**
  installed there": the installed `pytest` is `9.0.2` and `pygments` is `2.19.2`, while the file
  pins `pytest==9.1.1`. What is installed is *a* set of those packages, not the pinned set — which
  matters for Issue 6, since a `language: system` hook resolving to that venv would run
  unpinned-drifted versions.
- 🟣 **O10 — what the plan gets right.** Verified as a fair reading: the "run it locally first,
  report the real number, then decide whether to make it blocking" pattern is present in Tasks 2,
  3, 4, 7, 8 and 12, and Task 9's self-correction and Task 11's refusal to borrow a business
  route are on the page as described.

---

## Part 2 — Summary

**HOLDS (11 of 15 Issues)** — 1, 3, 4, 5, 6, 8, 9, 10, 12, 13, 14, 15.
*(Issue 13 holds as an omission; its ranking of `check --deploy` above `bandit` is judgment, not
a verified fact.)*

**PARTIAL (3)**

- **Issue 2** — the structural gap holds; the sub-claim that `requirements-dev.txt` "is never
  `COPY`d in" is wrong (`Dockerfile:25` is `COPY . .`, and the bind mount supplies it anyway).
  The durable form of the gap: an in-container `pip install` is ephemeral.
- **Issue 7** — the coverage gap holds, but not for the stated reason. `pass_filenames: false`
  on the upstream gitleaks hook means `files:` cannot limit *what* is scanned; it limits *when
  the hook runs at all*. The plan makes the same mistake.
- **Issue 11** — "`working-directory` does not apply to action inputs" holds; the predicted
  failure does not. `setup-python`'s pip default is the recursive glob `**/requirements.txt`,
  which does match `django_version/requirements.txt`. What survives is the cache-key point:
  after Task 1, CI installs `requirements-dev.txt` while the default key hashes
  `requirements.txt`.

**DOES NOT HOLD (0)** — no finding collapses entirely.

**Observations** — O2, O3, O4, O6, O7, O8, O10 verified. O9 partial (the venv has drifted from
the pinned versions). O1 and O5 remain unverified, as the audit itself marked them.

**Two claims where I am more confident than the audit was**

- Issue 4 is *stronger* than the audit stated, and now rests on mypy's source rather than on an
  inferred behavior.
- Issue 10's open verification note is closed: mypy skips dot-prefixed directories, so `.venv/`
  is not a hazard for `mypy .`.

**Open questions for the user**

1. Is `uv` in `django_version/.venv/bin/` a deliberate part of your workflow? Open Decision 1
   would read differently if so, and I do not have that history.
2. The host venv has drifted from `requirements.txt` (`pytest 9.0.2` installed, `9.1.1` pinned).
   Was that intentional, or is the venv simply stale? Issue 6 and O9 both reason about it, and
   Task 5's whole justification for `language: system` is version-fidelity.

**One thing the audit did not do, and I did not do either:** neither of us measured the plan's
tools against the codebase. Every "how many violations exist" question in the plan's Open
Questions is still open, and it should stay a Developer measurement, not a planning estimate.

---

## Handoff — next session

**What was verified.** `docs/audits/2026-08-15-audit-plan-ci-quality-security.md` in full: 15
Issues, 4 Open Decisions, 10 Observations, against the real files, official documentation for
the pinned stack, and read-only host commands.

**Counts.** HOLDS 11 · PARTIAL 3 · DOES NOT HOLD 0 · Open Questions 2 (plus O1 and O5 left
unverified by both passes).

**What this means for the plan.** The audit's four "blocking" findings survive verification —
Issues 1, 3 and 4 intact, Issue 2 in a corrected but not weakened form. Issue 11 is the one item
that should *not* be actioned as written: the cache is not broken, only the cache key would be
wrong after Task 1. Issue 7 should be re-decided from the gitleaks hook's real contract rather
than from either document.

**Files the next session should attach.**

- `docs/plan/plan_ci-quality-security_2026-08-14.md` (the file being revised)
- `docs/audits/2026-08-15-audit-plan-ci-quality-security.md` (the audit)
- this verification
- `django_version/requirements.txt`, `django_version/Dockerfile`,
  `django_version/.dockerignore`, `django_version/docker-compose.yml`,
  `django_version/pytest.ini`
- `.github/workflows/ci.yml`, root `.gitignore`
- `django_version/config/settings.py`
- `ARCHITECTURE.md` → "Docker and GitHub Actions CI"

**Recommended next persona.** Planner, revising the plan file. Nothing here is Developer work
yet: the corrections change what Tasks 1–5 *are*, and the four Open Decisions still need the
user's choice. If the two open questions above are answered first, Open Decision 1 can be
settled in the same session.
