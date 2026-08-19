# Plan — Toolchain, CI quality and security (revised)

**Date:** 2026-08-15
**Persona:** Planner
**Tree:** `feature/django-refactor`
**Status:** Complete as a plan, as of 2026-08-19. The Decision log runs D1–D21 with nothing
open; the task entries T1–T19 and the _Order of execution_ are written; the deferrals are
recorded in `docs/tech_debt/006`–`010`. **T15, T1, T2, T3, T18 and T9 are implemented.** The next
step in the sequence is the **merge to `main`**, then **T19**.

Everything decided on 2026-08-19 came from implementation rather than from an audit: T15 showed
that Dependabot's default configuration cannot be aimed by `dependabot.yml` (D18, amendment 1) and
that no Dependabot-triggered run can read a repository secret (D21); T18 then showed that the
custom auto-triage rule amendment 1 had set aside is available on public repositories after all —
a Planner error, corrected in place, and acted on by D18's amendment 2 and T19.
**Files modified by this session:** this plan only. No production file was touched.

## What this plan supersedes, and why it is a new file

This plan replaces `docs/plan/plan_ci-quality-security_2026-08-14.md`.

That file is **kept unchanged rather than edited**.
`docs/audits/2026-08-15-audit-plan-ci-quality-security.md` and
`docs/audits/2026-08-15-verification-audit-plan-ci-quality-security.md` cite it by line
number throughout; editing it in place would invalidate every citation in both documents and
destroy the decision trail they audit.

## What this plan acts on

- **Audit:** `docs/audits/2026-08-15-audit-plan-ci-quality-security.md` — 15 Issues,
  4 Open Decisions, 10 Observations.
- **Verification:** `docs/audits/2026-08-15-verification-audit-plan-ci-quality-security.md` —
  11 HOLD, 3 PARTIAL, 0 collapsed.
- **Second audit, on this plan itself:**
  `docs/audits/2026-08-16-audit-plan-toolchain-d2-d9a.md` — 5 Issues, 9 Open Decisions,
  8 Observations, 10 decision entries confirmed as surviving. It answers a different question
  from the first two: not "what is wrong with the superseded plan" but "where did the closed
  decisions inherit a narrowed option space from it". Entries added or amended from 2026-08-17
  onward act on that audit and say so.

The superseded plan was rebuilt rather than patched for two reasons. Four of the audit's
findings change what the tasks _are_, not how they are worded. And the user reopened the
dependency-management decision the superseded plan's Task 1 rested on — with that decision
changed, its Tasks 1–6 and 8 no longer describe the work to be done.

## Scope boundary — carried over unchanged

Findings whose correct answer depends on a hosting target not yet chosen — a production
compose/platform config, the concrete `ALLOWED_HOSTS` value, replacing `runserver` with a WSGI
server, a production Dockerfile stage — stay out of this plan. They remain open until Phase 5
of `docs/ROADMAP_SKILLBRIDGE.md` picks a deploy target.

## Evidence discipline

Nothing in this plan is written from training data or from the superseded plan's wording. Every
mechanism is verified in the current session against one of: the real file in this repository,
official documentation for the pinned version, or a read-only command executed on this machine.
Claims that remain unverified are labelled as such and carry the verification step the Developer
must perform first.

---

# Decision log

## D1 — Dependency management: adopt `uv` with `pyproject.toml` and `uv.lock`

**Decided:** 2026-08-15. Replaces the superseded plan's Task 1 in full.

### What was reopened

The superseded plan decided to keep `pip`, split `requirements.txt` into a production file and
a `requirements-dev.txt`, and defer `pyproject.toml` to a later session. Audit Issue 1 showed
the premise of that task was false, and the user reopened the decision rather than repair it.

### The evidence that decided it

**The stated premise was false.** `django_version/requirements.txt` is described by the
superseded plan as listing "only production runtime dependencies". Of its 19 pinned lines, six
are the test toolchain — `pytest`, `pytest-django`, and `pytest`'s four transitive dependencies
`iniconfig`, `packaging`, `pluggy`, `Pygments`. The split as specified would have left all six
installed in the production image, which is the exact outcome the task existed to prevent.

**The file cannot distinguish chosen dependencies from inherited ones.** It is a flat
`pip freeze` dump. Seven of the nineteen entries were chosen deliberately; the remaining twelve
are transitive. Removing a direct dependency therefore requires hand-tracing which of the twelve
came with it — the situation the `pillow` removal already walks into.

**Nothing keeps any environment matching the file.** Measured this session with
`django_version/.venv/bin/pip list` against `requirements.txt`:

| Package       | Pinned | Installed in `.venv` |
| ------------- | ------ | -------------------- |
| Django        | 6.0.7  | 6.0.3                |
| pytest        | 9.1.1  | 9.0.2                |
| pytest-django | 4.12.0 | 4.11.1               |
| psycopg       | 3.3.4  | 3.3.2                |
| pillow        | 12.3.0 | 12.1.1               |
| Pygments      | 2.20.0 | 2.19.2               |

Every checked package diverges. The venv additionally contains `uv 0.11.30`, which
`requirements.txt` does not declare at all. `.claude/rules/conventions.md` names
`requirements.txt` as the single source of truth for pinned versions; measured against the
environment it is supposed to describe, it currently is not one.

This is the finding that decided the option. A `requirements.txt` split — the superseded plan's
path — addresses the first two points and leaves the third untouched. `uv sync` resolves the
third by construction: the environment either matches `uv.lock` or the command fails.

**The consequence for the superseded plan's Task 5.** That task justified running pre-commit
hooks against `django_version/.venv/` on the grounds that doing so "ties the hooks to the exact
versions pinned in `requirements-dev.txt`". Given the drift measured above, that binding is
already false today: such a hook would run pytest 9.0.2 while CI runs 9.1.1.

**The deferral rationale did not survive checking.** The superseded plan deferred
`pyproject.toml` partly on the cost of choosing a build backend. uv's official documentation
(_Configuring projects_) states that a `[project]` table without a `[build-system]` table causes
uv to install the project's dependencies without attempting to build the project itself. A
Django application needs no build backend, so that cost does not exist.

### Verified against official documentation this session

- Installing uv into an image: `COPY --from=ghcr.io/astral-sh/uv:<version> /uv /uvx /bin/`,
  with the version pinned — uv docs, _Using uv in Docker_.
- A bind-mounted project directory colliding with the container's `.venv` is a documented
  problem with documented remedies (an anonymous volume over `/app/.venv`, or directing the
  project environment elsewhere) — same page. This is the subject of D3.
- Dependency groups follow PEP 735 `[dependency-groups]`; `--dev` is shorthand for
  `--group dev`; `uv sync --no-dev`, `--group`, `--only-group`, `--no-default-groups` select
  them — uv docs, _Managing dependencies_.
- `uv run --directory <dir>` changes directory before executing the command (confirmed against
  `uv run --help` on this machine, uv 0.11.30). This is the mechanism that closes audit Issue 4
  under D2 option A.

### Known housekeeping this decision creates

- **`uv` must not live inside the project venv.** Two installations exist on this machine:
  `~/.local/bin/uv` (0.10.9, official installer) and `uv 0.11.30` as a pip package inside
  `django_version/.venv/`. Which one answers on `PATH` depends on whether the venv is active —
  a third silent divergence. A tool that manages virtual environments does not belong inside the
  one it manages.
- **The host venv is recreated** as part of the migration, not upgraded in place.
- The root `.gitignore` already covers `django_version/.venv/`, and
  `django_version/.dockerignore` already excludes `.venv/`. No change needed for either.

### Alternatives considered

- **`pip` + corrected `requirements.txt` / `requirements-dev.txt` split** — the superseded
  plan's path with its premise fixed. Set aside: smallest diff and no new concept to learn, but
  it leaves the environment-drift failure mode fully in place, and the user has already declared
  an intent to move to `uv`, which would mean adapting the Dockerfile, CI and pre-commit twice.
- **`pyproject.toml` for tool configuration only, dependencies staying in `requirements`
  files** — resolves audit Issue 4 but inherits every dependency-side cost above, and reaches
  the same destination in two steps instead of one.
- **`pyproject.toml` with PEP 735 `dependency-groups`, installed by `pip`** — viable;
  `pip 26.1.2` on this machine supports `pip install --group` (confirmed via `pip install
--help`). Set aside: it produces no lockfile, so exact transitive versions stop being pinned
  and reproducibility gets _worse_ than today unless a separate locking step is added.

### Open questions carried to the tasks

- The exact `uv` version to pin is not decided here. uv's own documentation currently
  illustrates a version newer than either installation on this machine; the Developer pins the
  version verified at implementation time, per `conventions.md`'s rule that versions are fixed
  explicitly and never described as "latest".
- Whether `uv.lock` is committed is treated as settled by the purpose of the migration — a
  lockfile that is not committed reproduces nothing — but it is stated in the task's acceptance
  criteria rather than assumed.

---

## D2 — Where `pyproject.toml` lives: inside `django_version/`

**Decided:** 2026-08-15. Closes audit Issue 4 and Open Decision 1.

`pyproject.toml`, `uv.lock` and the project `.venv` all live in `django_version/`, alongside
the `Dockerfile`, `docker-compose.yml` and `pytest.ini` already there. Tool configuration
(`[tool.ruff]`, `[tool.mypy]`, `[tool.coverage.*]`) lives in that same file, replacing the four
standalone config files the superseded plan would have created.

### The problem this had to solve

The superseded plan placed `mypy.ini` in `django_version/` and justified it as "same reasoning
as `ruff.toml`". The two tools do not discover configuration the same way:

- **Ruff** resolves configuration hierarchically from each checked file's directory upward, so
  a config in `django_version/` is found even when Ruff is invoked from the repository root.
- **mypy** searches from the **current working directory** and walks _upward_ only
  (`mypy/config_parser.py` → `_find_config_file`). Invoked from the repository root, it walks
  toward the filesystem root and never descends into `django_version/`.

Because pre-commit executes every hook from the repository root, a mypy hook would find no
configuration, run without the `django-stubs` plugin and without `django_settings_module`, treat
every Django construct as untyped, and pass — while CI, which runs from `django_version/` via
`defaults.run.working-directory`, finds the configuration and fails. A commit-time check
reporting green against a red CI check is the exact drift the superseded plan's hook task
existed to prevent.

### Why the config location stopped deciding this

`uv run --directory <dir> <command>` changes directory before executing the command (confirmed
against `uv run --help`, uv 0.11.30, this machine). A hook entry of
`uv run --directory django_version mypy` therefore executes with the working directory inside
`django_version/`, where the configuration is found. The defect is closed without moving the
configuration.

Independently: pre-commit has no per-hook working-directory option, and this is an
acknowledged upstream limitation rather than a configuration gap (pre-commit issues #466,
#1417, #2317, and #2951, the last describing this exact mypy-in-a-monorepo case).
`lefthook` offers a first-class `root:` key for the same purpose. Which hook runner to adopt is
therefore a real choice and is deferred to its own decision, not settled here.

### Why inside `django_version/` rather than at the repository root

- **The repository contains two Python projects, not one.** `django_version/` and
  `oop_version/` each carry their own `requirements.txt` and their own `.venv`. A
  `pyproject.toml` at the root would declare the monorepo itself to be a single Python project,
  which is not true of this repository.
- **It preserves the Docker build context.** `docker-compose.yml` declares `build: .` from
  `django_version/`. A root-level `pyproject.toml` and `uv.lock` would be outside that context
  and unreachable by `COPY`, forcing `context: ..` plus `dockerfile: django_version/Dockerfile`,
  and a new root `.dockerignore` — the existing `django_version/.dockerignore` is read from the
  build context root and would stop applying.
- **It preserves the project's own rule.** Root `CLAUDE.md` states that all project commands run
  from `django_version/`. The root option requires an explicitly declared exception to it.

### The cost this accepts

The user opens the repository root in VS Code. With the project defined one level down, the
editor needs its interpreter and test working directory pointed at `django_version/` — roughly
three lines in `.vscode/settings.json`. `.vscode/` is currently listed in the root `.gitignore`,
so such a file would not survive a fresh clone. Whether to un-ignore
`.vscode/settings.json` or to document the settings instead is a separate one-line decision,
recorded here and deliberately not taken in this entry.

### Alternatives considered

- **Root `pyproject.toml`** — the only advantage that survived checking was closing audit
  Issue 4, which `uv run --directory` closes at the chosen location. Measured, its build-context
  cost is small in bytes (a root `.dockerignore` excluding both `.venv/` directories and `.git/`
  leaves roughly 2 MB of added context) but structural in configuration: two files reshaped, one
  new file, and an exception to a documented project rule.
- **A uv workspace: root `pyproject.toml` declaring `django_version/` as a member** — the
  uv-native monorepo layout. Set aside: it inherits the root option's build-context cost, adds a
  concept whose payoff requires a second active member, and `oop_version/` is closed.

### Amendment, 2026-08-17 — `pytest.ini` is deleted and its configuration moves to `[tool.pytest]` (closes Issue 5 of the 2026-08-16 audit)

D2 listed `[tool.ruff]`, `[tool.mypy]` and `[tool.coverage.*]` as moving into `pyproject.toml`
and named `django_version/pytest.ini` nowhere — neither as staying nor as moving. That silence
has a failure mode, and it is silent by construction.

**Decided:** `django_version/pytest.ini` is **deleted**, and its sixteen lines move to a
`[tool.pytest]` table in `django_version/pyproject.toml`, in the same change.

**Deleting the file is mandatory, not stylistic.** pytest's configuration reference lists the
candidates in precedence order — `pytest.toml`, `.pytest.toml`, `pytest.ini`, `.pytest.ini`,
`pyproject.toml`, `tox.ini`, `setup.cfg` — and states that _"pytest.ini files take precedence
over other files (except pytest.toml and .pytest.toml), even when empty"_ and that _"options
from multiple configfiles candidates are never merged - the first match wins."_ With
`pytest.ini` left in place, a `[tool.pytest]` table in `pyproject.toml` is never read at all,
and nothing warns. Moving the content without removing the file produces a configuration that
looks authoritative and governs nothing.

**The table is `[tool.pytest]`, not `[tool.pytest.ini_options]`.** Both exist and they are
different: _"Use [tool.pytest] to leverage native TOML types (supported since pytest 9.0)"_
versus _"Use [tool.pytest.ini_options] for INI-style configuration (supported since pytest
6.0)"_. The project pins pytest 9.1.1, so the native form is available. Under it `addopts`
and `markers` become TOML arrays rather than INI strings — the migration reads better than the
file it replaces, which removes the only cost this option was thought to carry.

**`rootdir` does not move.** _"If one is matched, it becomes the configfile and its directory
becomes the rootdir."_ D2 places `pyproject.toml` in `django_version/`, which is where
`pytest.ini` sits today.

**Instruction to the Developer:** write `[tool.pytest]` only. Do not add a
`[tool.pytest.ini_options]` table alongside it — pytest's documentation does not state what
happens when both are present, and this plan does not depend on finding out.

**One live rule file follows the move.** `.claude/rules/testing.md` states _"Configuration
lives in `pytest.ini`"_ and lists the active flags, and it refers to `pytest.ini` again when
explaining the `--no-migrations` consequence for data migrations. It is auto-loaded into every
session, so leaving it pointing at a deleted file sends every future agent to a path that does
not exist. It is rewritten in the same change, and it is the only rule file this amendment
touches — the same edit is **not** made to `specs/`, `docs/audits/` or the superseded plan,
which record what was true when they were written (D16's synchronisation subtask states that
boundary in full).

**Alternatives considered**

- **Keep `pytest.ini`, and say so explicitly in D2** — zero behavior change, and it closes the
  finding, since the defect is the silence rather than the file. Set aside: it leaves two
  configuration homes in one directory and the shadowing trap intact, merely documented, while
  D2's whole argument is that one file beats four.
- **Move to `pytest.toml`** (new in pytest 9.0, section `[pytest]`, highest precedence) —
  nothing can shadow it, by construction. Set aside: its advantage evaporates once `pytest.ini`
  is deleted, and it adds a file rather than removing one, against D2's stated goal.

---

## D3 — How the container installs its packages: a project environment outside the bind mount

**Decided:** 2026-08-15. Prerequisite for closing audit Issue 2.

The `Dockerfile` sets `UV_PROJECT_ENVIRONMENT` to a path outside `/app` (`/opt/venv`) and puts
that environment's `bin/` on `PATH`. `uv sync` in the image therefore builds the environment
outside the bind-mounted project directory.

### The problem this avoids

`docker-compose.yml` bind-mounts `.:/app`, so at runtime the host's `django_version/` covers
`/app` and hides whatever the image built there. Today this is harmless: `pip install` writes to
the image's system site-packages, outside `/app`.

uv's default is to create the project environment as `.venv` **inside the project directory** —
`/app/.venv` in the container, directly under the mount. That produces two failure modes:

1. `uv sync` at image build time creates `/app/.venv` with Linux binaries; at runtime the mount
   replaces it with the host's macOS/arm64 `.venv`, which cannot execute in the container.
2. `uv sync` run _inside_ the container writes through the mount into the host's
   `django_version/.venv`, replacing the developer's working environment with Linux binaries.

The second is the serious one: it damages the host machine, and it is a single command that
anyone — or any agent — would run without suspicion.

### Why this path

- Both failure modes become structurally impossible rather than merely unlikely.
- The mechanism is declared in the `Dockerfile`, where a reader looks, rather than in a compose
  volume entry that the `Dockerfile` gives no hint of.
- With the environment's `bin/` on `PATH`, `docker-compose exec web pytest` and
  `docker-compose exec web python manage.py …` keep working verbatim, so root `CLAUDE.md`
  Rule 12 stays literally true and no command in `conventions.md` changes shape.
- `UV_PROJECT_ENVIRONMENT` is documented in uv's environment-variable reference as "the path to
  the directory to use for a project virtual environment" — one documented behavior, no
  unverified assumption.

### Alternatives considered

- **An anonymous volume masking `/app/.venv`** (`- /app/.venv` in `docker-compose.yml`) — the
  first remedy uv's Docker guide names, and it keeps the conventional `.venv` path. Set aside:
  the mechanism is invisible from the `Dockerfile`, and anonymous volumes go stale — a
  dependency added and the image rebuilt still leaves the container running the old volume
  until `docker compose down -v`. That is the same silent-drift failure class that motivated
  adopting uv in D1.
- **Installing into the image's system Python** — closest to the current `Dockerfile`, which
  `pip install`s into the system Python, and the simplest mental model. Set aside; the reason
  is restated below, because the one recorded here originally was false.

### Amendment, 2026-08-17 — the rejection of the system-environment option is re-argued (closes Issue 1 of the 2026-08-16 audit)

The decision stands. The reason recorded for excluding the system-environment option did not,
and it was the only discriminator D3 offered.

**What was wrong.** D3 set the option aside on the grounds that uv's documentation _"describes
the variable as pointing at a virtual environment and does not confirm a system prefix"_. uv's
_Using uv in Docker_ guide — the same page D3 cites for its other three claims — says the
opposite: _"Alternatively, the `UV_PROJECT_ENVIRONMENT` setting can be set before syncing to
install to the system Python environment and skip environment activation entirely."_ An option
was rejected for being undocumented while being documented.

**A second correction, this one to the audit rather than to the plan.** The audit's own
preference for the chosen option rests on it being _"the only option where both failure modes
are impossible rather than merely avoided"_. That does not separate the two: a system prefix is
also outside `/app`, so the bind mount cannot reach it either, and both failure modes are
structurally removed under either. What separates them is something else.

**The real discriminator, and it is the reason D3 keeps its outcome.** `uv sync` exists to make
the environment _match the lockfile exactly_ — that property is the whole basis of D1, recorded
there as "the environment either matches `uv.lock` or the command fails". Pointed at the image's
system prefix, "matches exactly" comes to include removing the `pip`, `setuptools` and `wheel`
that the `python:*-slim` base image ships. The option would trade the guarantee D1 was adopted
for against a risk to the image's own base. Isolation between the application's dependencies
and the interpreter's is the second, smaller reason.

_Labelled as reasoning, not measurement:_ uv's pruning behavior against a system prefix
specifically was not executed. It is inferred from `uv sync`'s documented semantics. If uv
treats a system prefix as a special case and does not prune, this argument weakens and the
option deserves re-examination — on that ground, not on the documentation one.

**What the documentation does and does not settle.** uv's guide lists three remedies for the
mounted-`.venv` collision — an anonymous volume over `/app/.venv`, `docker compose watch` with
the environment excluded via `ignore`, and pointing the environment path outside the mount —
and **recommends none of them.** "Follow the documented pattern" therefore does not decide this;
it is an engineering choice, and this project's is isolation.

**Fourth alternative, recorded because the guide names it and D3 did not.**
`docker compose watch` with `ignore: [.venv/]` removes the bind mount entirely, so nothing can
shadow anything. Set aside: it replaces the development loop the project uses today rather than
adjusting a configuration, which is well outside this plan's scope.

**Carried to D15.** `/opt/venv` has an owner, and the non-root user decision has to reconcile
that. If it concludes the ownership handling is awkward, revisiting the system-environment
option on _that_ ground is legitimate — on ownership, never on documentation.

### Open questions carried to the task

- The exact `uv sync` invocation in the `Dockerfile` (layer caching with `--no-install-project`,
  `UV_COMPILE_BYTECODE`, `UV_LINK_MODE=copy`) follows uv's documented Docker pattern and is
  written at implementation time against the docs for the pinned uv version.

---

## D4 — The image installs the development dependencies

**Decided:** 2026-08-15. Closes audit Issue 2.

The `Dockerfile` runs a full `uv sync --locked`, development dependencies included. The single
image carries Django, psycopg, the test toolchain and every quality/security tool this plan
adds.

### What was actually being protected

The superseded plan justified its dependency split as keeping dev tooling out of "the
production Docker image", while the same task stated that no production Dockerfile or stage
exists and that creating one is out of scope. The audit named this as the plan's largest
structural gap: a simultaneous commitment to "the production image stays lean" and "dev tooling
runs inside Docker", with no mechanism reconciling them.

`Dockerfile` line 31 settles which image actually exists:

```dockerfile
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
```

`runserver` is Django's development server, which Django's own documentation rules out for
production use. The image is a development image. There is no production image to keep lean;
one is created in Phase 5, when a deploy target exists, and is outside this plan's scope
boundary.

### Why this path

- It closes audit Issue 2 by construction: `docker-compose exec web ruff check .` works because
  `ruff` is in the image, not because someone installed it into a container's writable layer.
  An in-container `pip install` does not survive container recreation and never exists for a
  fresh clone — the durable form of Issue 2 that the verification established.
- Root `CLAUDE.md` Rule 12 ("all project commands run via `docker-compose exec web`") becomes
  literally true for every tool, not only for `pytest`, which the image already carries today.
- It matches what the image already is.

### Alternatives considered

- **A multi-stage `Dockerfile` now, with a lean base stage and a `dev` stage** — set aside: it
  crosses this plan's scope boundary, which excludes the production Dockerfile precisely because
  its correct shape depends on the deploy target Phase 5 has not chosen. A stage called
  "production" that still runs `runserver` is not one.
- **Production dependencies only in the image, dev tooling on the host and in CI**
  (`uv sync --locked --no-dev`) — set aside: it breaks `docker-compose exec web pytest`, which
  works today, and reproduces exactly the gap audit Issue 2 described.

### Acceptance instrumentation carried to the task

The Developer records `docker image ls` output for the project image before and after the
migration and reports both numbers. Measured on this machine at planning time,
`skillbridge-web:latest` is 285 MB. This is instrumentation, not a threshold — no size limit is
being set.

_Note, not part of this decision:_ `django_version-web:latest` (254 MB, four months old) is an
orphan image from before `name: skillbridge` was added to `docker-compose.yml`; Compose derives
the image name from the directory when `name:` is absent. Removing it is the user's call and is
not part of any task in this plan.

---

## D5 — Dependency groups: a single `dev` group

**Decided:** 2026-08-15. Completes the correction of audit Issue 1.

`pyproject.toml` declares production dependencies under `[project].dependencies` and every
development dependency — test toolchain and all quality/security tools this plan adds — under a
single `dev` group in `[dependency-groups]`.

### What this fixes

`pytest` and `pytest-django` move out of the production dependency set, where
`requirements.txt` currently places them while the superseded plan described that file as
holding production dependencies only. The four transitive entries that exist in the file solely
because `pytest` does — `iniconfig`, `packaging`, `pluggy`, `Pygments` — stop being declared at
all; uv resolves them and records them in `uv.lock`. Roughly seven hand-declared dependencies
replace nineteen hand-maintained lines.

### Why a single group

- `uv sync` includes the `dev` group by default, so no invocation in the `Dockerfile`, in CI, or
  on the host has to name it.
- Classification happens at install time under both options (`uv add X` versus
  `uv add --dev X`; both flags confirmed against `uv add --help`, uv 0.11.30). A single dev
  group makes that a binary question — "does this run in production?" — rather than a choice
  among four buckets where the answer is sometimes genuinely ambiguous.
- A misclassification is silent: nothing warns when a linter is added without the flag and lands
  in the production set. That is precisely the failure this plan is correcting in Issue 1, and
  more buckets multiply the chance of repeating it.

### Alternatives considered

- **Named groups (`test`, `lint`, `security`) with `dev` including them** — better self-
  documentation, and it would let CI install only what each step needs. Set aside: that saving
  only materialises if CI runs separate jobs, which is not yet decided (`ci.yml` currently has a
  single `test` job), so choosing it now would be planning from an assumption about a CI shape
  that does not exist. The `include-group` syntax would also need verification against uv's
  documentation before being written.

### Amendment, 2026-08-17 — the group is confirmed as the provisioning mechanism, and `required-version` is declined (closes Open Decision H of the 2026-08-16 audit)

D5 chose a single `dev` group without comparing it to anything, because under `pip` there was
nothing to compare it to. `uv` created a second shape the plan never named — running a tool
disposably with `uvx <tool>@<version>`, so it never enters the project at all — and both `uv`
and `ruff` document a `required-version` key that would bear on the risk D9 knowingly accepted.
Both were examined and both are declined.

**Running the tools via `uvx` is rejected on D4.** D4 deliberately put the tools in the image so
that `docker-compose exec web ruff check .` works because `ruff` is there, not because someone
installed it into a container's writable layer. `uvx` undoes that. It also moves the version pin
into every site that invokes the tool — `ci.yml`, a hook configuration — instead of one
lockfile, and nothing guarantees those sites agree.

**`required-version` is rejected, and the reason is worth recording because the argument for it
is real.** ruff's settings reference documents it as _"Enforce a requirement on the version of
Ruff, to enforce at runtime"_, and uv's settings reference documents the equivalent
(`[tool.uv] required-version`, _"uv will exit with an error"_). The case for adopting it: a ruff
invoked from outside the project environment — an editor extension shipping its own bundled
binary is the concrete instance — can disagree with CI silently, which is the class of drift
this plan exists to remove. _(Reasoning, not measured: the VS Code Ruff extension's bundling
behavior was not verified against its documentation.)_

What defeats it is the strict form's cost. `required-version = "=="` would block
`uvx ruff@<version>`, which is exactly how D9 produced its measurements and how the 2026-08-16
audit reproduced them. The loose form (`>=`) permits the newer version and therefore does not
guard the only scenario that matters — ruff 0.16.0 replacing the default rule set. So the strict
form closes the measurement path this project's evidence discipline depends on, and the loose
form closes nothing.

And the risk it would guard is already bounded where D9 put it: `uv.lock` pins the exact ruff
version, so a rule-set change can only arrive through a deliberate lock update, never silently
between two runs of the same commit. The editor-disagreement problem is real but belongs where
it lives — pointing the extension at the project's ruff — not in a second version literal that
has to be bumped in step with the lockfile.

**Recorded as available and deliberately not adopted.** If D14 selects a hook runner that
invokes tools from outside the project environment, `required-version` becomes the cheap defense
and this entry is revisited then.

### Revisit trigger

The user stated the intent to move to named groups once classification is habitual and the risk
of putting a package in the wrong group has passed. The migration is moving lines between tables
in one file plus `uv lock`; nothing outside `pyproject.toml` changes. ~~Whether this becomes a
`docs/tech_debt/` entry is decided with the other deferrals at the end of this plan.~~
**Recorded 2026-08-17 as
`docs/tech_debt/007-single-dev-dependency-group-instead-of-named-groups.md`**, with the
`include-group` syntax carried there as the one thing to verify before migrating.

---

## D6 — CI installs on the runner and adds a step that builds the image

**Decided:** 2026-08-15. Closes audit Open Decision 4.

`ci.yml` keeps installing dependencies on the GitHub runner — `uv sync --locked` replacing
`pip install -r requirements.txt` — and runs the test suite and the quality tools there. A
separate step runs `docker build` so that a broken `Dockerfile` fails CI.

### What this fixes

`ci.yml` never builds the image today; `docker-compose.yml` builds it only on the developer's
machine. Two tasks in this plan modify the `Dockerfile` — removing `pillow` with its system
libraries, and the uv migration itself — and both carry an acceptance criterion that the image
still builds. Neither is checkable by any automated gate as CI stands.

### Why not run everything inside the image

That option was the audit's strongest form of Open Decision 4, and D1 changed its value.

Before uv, the project had three environments receiving their packages at three different
moments — the host venv, the last-built image, and each CI run — with nothing comparing them.
That is how the host venv reached four months of drift unnoticed. Running CI inside the image
would have collapsed two of the three.

`uv sync --locked` addresses the same root by a different route: all three environments install
from one lockfile, and the command fails loudly rather than silently diverging when the
environment cannot match it. What remains different between the runner and the image is the
operating system underneath — Ubuntu versus Debian slim — which is a real but much narrower
class of divergence than package versions.

The benefit that would still be uniquely C's — proving the image builds — is what option B buys
directly, without paying a full image build on every push. Layer caching does not persist
between runner VMs, so an in-CI build starts from scratch each time: pulling the base image,
running `apt-get`, and installing every package.

### Alternatives considered

- **Install on the runner only, never build the image** — fastest, smallest change. Set aside:
  it leaves two of this plan's own acceptance criteria unverifiable by any gate, which is the
  class of defect this replanning exists to stop repeating.
- **Build the image and run everything inside it** — see above.

### Amendment, 2026-08-17 — how the runner gets `uv` and Python (closes Issue 3 of the 2026-08-16 audit)

D6 decided that CI installs on the runner with `uv sync --locked` and never said what puts the
`uv` binary there. It also lost something without noticing: the superseded plan had a
`cache: pip` step, and when `pip` left, dependency caching left with it and no decision
replaced it.

**Decided:** `ci.yml` installs `uv` with the `astral-sh/setup-uv` action, with
`enable-cache: true`, and keeps `actions/setup-python` — but **the hardcoded
`python-version: "3.14.6"` is replaced by `python-version-file`**, so the Python version is
read from the project rather than repeated in the workflow.

uv's GitHub Actions guide documents all three pieces: installing uv via `astral-sh/setup-uv`
(pinned by commit SHA in its own example, with _"It is considered best practice to pin to a
specific uv version"_), caching via `enable-cache: true`, and providing Python either with
`uv python install` or with `actions/setup-python` reading `python-version-file` from
`.python-version` or `pyproject.toml`.

**Why this rather than letting `uv` own Python too.** The argument that reached for
`uv python install` was single-source-of-truth: after D16 the workflow would otherwise repeat
a Python patch number that also lives in the `Dockerfile`. That argument does not separate the
two options — `python-version-file` gives `actions/setup-python` the same property, from the
same file, while keeping the Python build GitHub ships and paying no per-run download for a
python-build-standalone distribution whose cold-runner cost was never measured.

**Consequences to carry forward.**

- **D8 Item 2's pinning rule now covers four actions, not three.** `astral-sh/setup-uv` is a
  third-party action and is pinned on the same terms as the rest.
- **Which file `python-version-file` reads is a verification debt.** uv's guide names both
  `.python-version` and `pyproject.toml`; the authority on what `actions/setup-python` accepts
  is that action's own documentation for the version finally pinned, which was not read here.
  If only `.python-version` is supported, that file is created — nothing else changes.
- **The uv version to pin** follows D1's rule: fixed at implementation time, never described
  as latest.

**Alternatives considered**

- **`astral-sh/setup-uv` plus `uv python install`, dropping `actions/setup-python`** — one
  fewer GitHub-maintained action to pin and keep current, and it mirrors the container, where
  uv owns the environment. Set aside: its single-source-of-truth advantage is delivered by
  `python-version-file` at no cost, it downloads a Python distribution on each uncached run,
  and the binary differs from the one CI uses today.
- **Installing uv with the standalone installer in a `run:` step** — no new action in the
  trust boundary, and identical on any CI provider. Set aside: the version pin becomes a
  hand-written URL that no tooling watches, caching would have to be built by hand, and a
  `curl | sh` step sits badly in a workflow whose purpose is supply-chain hardening.
- **Improvising nothing and letting the Developer decide** — the status quo of D6 as written.
  Set aside: the likely improvisation is `pip install uv`, which D1 recorded as the hazard of
  putting an environment manager inside the environment it manages.

### Amendment 2, 2026-08-17 — the build step stays uncached, and lands after the `Dockerfile` cleanup (closes Issue 2 of the 2026-08-16 audit)

D6 preferred a plain build step over running the suite inside the image partly on this
sentence: _"Layer caching does not persist between runner VMs, so an in-CI build starts from
scratch each time."_ That is true only of the default `docker` driver with no cache backend.
Docker documents a GitHub Actions cache backend (`cache-from: type=gha`,
`cache-to: type=gha,mode=max`), which requires a buildx builder — _"This cache storage backend
is not supported with the default `docker` driver"_. The cost D6 treated as fixed is
configurable.

**Decided:** the build step is a plain `docker build`, **uncached**, and it is added **after**
the `Dockerfile` cleanup task (the `pillow` removal and the `libpq-dev` check), so the measured
duration describes the final image rather than the current one.

**What decided it, and neither reason is a preference.**

1. **The cache expires faster than this project's working rhythm.** GitHub's dependency-caching
   reference: _"GitHub will remove any cache entries that have not been accessed in over 7
   days"_, with LRU eviction against a 10 GB per-repository budget. D8 Item 3 measured a
   47-day gap between runs on this repository (2026-05-31 → 2026-07-17). A cache with a 7-day
   idle life is cold on most returns to the project, so the caching option would be paid for
   and would deliver the uncached time anyway.
2. **This plan is deleting the only expensive layer.** The `Dockerfile`'s cost is concentrated
   in `RUN apt-get update && apt-get install -y --no-install-recommends libpq-dev libjpeg-dev
zlib1g-dev`. The cleanup task already removes `libjpeg-dev` and `zlib1g-dev` with `pillow`,
   and puts `libpq-dev` in question because `psycopg-binary` bundles its own libpq. If
   `libpq-dev` also goes, the `apt-get` step disappears entirely and the build reduces to
   pulling a slim base and running `uv sync` over roughly seven direct dependencies. There is
   little left for a cache to hold.

**The costs this avoids, stated so the choice is not re-litigated from taste.** The caching
option adds two third-party actions — `docker/setup-buildx-action` and
`docker/build-push-action` — taking the workflow to six actions, each pinned under D8's rule.
It also adds a documented failure mode that has nothing to do with the code under test:
Docker's page on the backend records that the Actions cache API can throttle a build into a
timeout, and recommends passing `ghtoken` to reduce the request volume. A red build caused by
a cache service is a real cost on a public repository whose README badges point at `main`.

**Money is not a factor either way.** The repository is public (`gh api repos/…` →
`"private": false`), and D8 Item 3 already verified that Actions usage is free for public
repositories on standard GitHub-hosted runners. The uncached build's cost is wall-clock wait,
not billing.

**Alternatives considered**

- **buildx with `cache-from/to: type=gha`** — the pattern Docker's own documentation
  recommends, and the option the 2026-08-16 audit preferred. Set aside on the two measured
  facts above, not on complexity aversion: for this repository's cadence the cache is usually
  cold, and the layer worth caching is being removed by this same plan.
- **No build step at all** — set aside for the reason D6 already gave, now stronger: the
  `Dockerfile` is edited three times by this plan (the cleanup, the uv migration, and D16's
  base-image bump) with no automated gate on any of them.
- **Building the image and running the suite and tools inside it** — still the only option that
  removes the Ubuntu-versus-Debian divergence, and still beyond this plan's scope. Unchanged
  from D6 as written.

### Open questions carried to the task

- The `docker build` step's duration is not measured. GitHub prints per-step duration in the
  Actions UI, so the measurement is one push and costs nothing. The Developer reports the
  number from a run taken **after** the `Dockerfile` cleanup. **Threshold agreed with the
  user:** above roughly 90 seconds, the caching option is revisited with the real number in
  hand; below it, the step stays as decided. The other fallback D6 recorded — restricting the
  build to pushes to `main` — remains available and is the user's call.

---

## D7 — CI runs Django's own two checks: missing migrations (blocking) and `check --deploy` (blocking at ERROR)

**Decided:** 2026-08-15. Closes audit Issues 12 and 13, both verified as HOLDS.

`ci.yml` gains two steps, neither of which needs a new dependency or a deploy target:

- `python manage.py makemigrations --check` — fails the job when a model change was committed
  without its migration.
- `python manage.py check --deploy` — run at its default `--fail-level ERROR`, so it reports
  Django's deployment warnings in the log and fails the job only on an ERROR-level finding.

### What was missing

The superseded plan added five third-party tools and neither of Django's own checks. None of the
five reads migration state, and its security block excluded `config/` from the scanner, so
`config/settings.py` — where this project's security posture is actually decided — was read by
no tool at all.

**The missing-migration gap is structural, not incidental.** `pytest.ini` runs the suite with
`--no-migrations`, which pytest-django's own help text describes as _"Disable Django migrations
on test setup"_. The test schema is then built by inspecting the models, so it matches the models
by construction and no test can fail because a migration is absent. `django_version/CLAUDE.md`
Rule 10 requires explicit approval before generating a migration, which makes "model edited,
migration deferred, migration forgotten" an ordinary path through this project's workflow rather
than a hypothetical one.

### Measured in the container this session, not cited

`docker-compose exec web python manage.py makemigrations --check --dry-run` → `No changes
detected`, exit 0. The step enters CI green and turns red only when a migration is genuinely
missing.

Two facts corrected against Django 6.0.7 running in the image:

- `--check` **implies `--dry-run`** (`manage.py makemigrations --help`), so the second flag is
  redundant. The audit's suggested form carried both. The step detects; it never writes, so it
  does not collide with Rule 10.
- An unreachable database produces a `RuntimeWarning` and the command continues — read directly
  from `makemigrations.py` in the image, where `check_consistent_history` is wrapped in
  `except OperationalError`. The step therefore does not depend on CI's postgres service.

`docker-compose exec web python manage.py check --deploy` → 7 warnings, **exit 0**. Confirmed
against `manage.py check --help`: `--fail-level` _"Default is ERROR"_, so WARNING-level findings
never fail the command.

All 7 warnings are outside this plan's scope boundary or are artifacts of a development
environment:

| Code | Setting                 | Owner                                                            |
| ---- | ----------------------- | ---------------------------------------------------------------- |
| W004 | `SECURE_HSTS_SECONDS`   | hosting target (Phase 5)                                         |
| W008 | `SECURE_SSL_REDIRECT`   | hosting target (Phase 5)                                         |
| W012 | `SESSION_COOKIE_SECURE` | hosting target (Phase 5)                                         |
| W016 | `CSRF_COOKIE_SECURE`    | hosting target (Phase 5)                                         |
| W020 | `ALLOWED_HOSTS` empty   | hosting target (Phase 5)                                         |
| W018 | `DEBUG=True`            | local `.env`; CI leaves `DEBUG` unset, so it resolves to `False` |
| W009 | `SECRET_KEY`            | local `.env`                                                     |

W009 fires on the local key for one reason only. Measured without printing the value: 66
characters, 34 distinct characters, prefixed `django-insecure-`. Django's own check module
defines the three thresholds as `django-insecure-`, `50`, `5`, so the key clears both numbers and
is flagged solely for the prefix that `startproject` stamps on generated keys. Whether W009 also
fires in CI depends on the value behind `secrets.SECRET_KEY`, which cannot be read from here.

### Why blocking at ERROR rather than the alternatives

Running at the default fail level keeps the step silent while the only findings are the
hosting-dependent warnings, and turns it into a real gate the moment Django reports something it
rates ERROR. The step's value in the meantime is the log: when Phase 5 picks a deploy target,
that session inherits a concrete list instead of starting an investigation.

### Alternatives considered

- **Informational only (`continue-on-error: true`)** — set aside: a step that can never fail is
  a step nobody reads, and seven standing warnings already guarantee an eighth would go unnoticed.
- **Blocking at `--fail-level WARNING`, with the five hosting codes in
  `SILENCED_SYSTEM_CHECKS`** — the only option that actually watches for a new warning. Set
  aside: `SILENCED_SYSTEM_CHECKS` is a global `settings.py` setting, so silencing for CI's
  benefit also silences in production later; it writes a production file to keep a CI gate green;
  and it would suppress precisely the findings this plan's scope boundary says must stay open
  until Phase 5. The W009 exposure is a second cost — if the GitHub secret carries the
  `django-insecure-` prefix, every push fails until the secret is regenerated.

### Open questions carried to the task

- Step ordering relative to `pytest` is the Developer's call; both steps are fast and neither
  depends on the suite.
- Whether `check --deploy`'s standing warning list is worth capturing into the Phase 5 planning
  input is not decided here.

### Flagged, deliberately not absorbed into this plan

Reading `pytest.ini` for this decision surfaced three things neither audit raised. They are
recorded here as signals, not as tasks, per `PLANNER.md`'s rule against absorbing new findings:

- `--no-migrations` means the 14 migration files in `accounts/migrations/` and
  `profiles/migrations/` are never executed by the suite. The D7 check covers the dangerous case
  (a model without its migration) but not a migration that is present and broken.
- `--reuse-db` and `--no-migrations` together mean a reused test database keeps a schema from a
  previous run. `--create-db` is the documented override (`pytest --help`). Stated as reasoning;
  not measured.
- The `slow` and `integration` markers are declared in `pytest.ini` and used by no test — grep
  over `accounts/`, `profiles/` and `config/` returns nothing.

---

## D8 — `ci.yml` triggers and hardening: explicit token permissions, SHA-pinned actions, a `pull_request` trigger

**Decided:** 2026-08-15. Closes audit Issue 14 and the trigger half of Issue 15; the scheduled-run
half is deferred, see _Item 3_.

Three independent items, decided one at a time. All three land in `.github/workflows/ci.yml`.

### Item 1 — a workflow-level `permissions: contents: read`

The workflow declares no `permissions:` block anywhere. Read with `gh api` this session:

```
$ gh api repos/thaisdMM/skillbridge/actions/permissions/workflow
{"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}
```

So the token today carries `contents: read` **and** `packages: read`. GitHub's workflow-syntax
reference: _"If you specify the access for any of these permissions, all of those that are not
specified are set to `none`."_ Declaring `contents: read` therefore drops exactly one scope,
`packages: read`, on a public repository that publishes no package.

**The measured security delta is close to nothing, and the decision was taken knowing that.**
What it buys is durability: the effective permission stops living in an account settings screen
that appears in no diff and no review, and survives a move to an organization whose default
differs.

Verified as a precondition: restricting `GITHUB_TOKEN` cannot break the badge step, which
authenticates with `secrets.GIST_SECRET` (`ci.yml:64`), a separate credential. No step in the
workflow publishes a release, comments on a pull request, or writes to the repository.

**Alternatives considered**

- **Job-level `permissions:`** — set aside: with one job it is the same thing, and a second job
  added later without its own block silently reinherits the account default.
- **`permissions: {}`** (all scopes denied) — the strictest form, and documented as such. Set
  aside: whether `actions/checkout@v4` still functions with zero scopes on this repository was
  **not verified**, and the failure would land on the first step of every push.
- **Status quo** — set aside on the durability argument above, not on measured exposure.

#### Amendment to Item 1, 2026-08-17 — default-deny at the workflow, the grant on the job (closes Open Decision D of the 2026-08-16 audit)

**Decided:** `ci.yml` declares `permissions: {}` at the workflow level and
`permissions: contents: read` on the `test` job.

**Why this is not the same decision as Item 1's, and not a stricter version of it either.**
GitHub's workflow-syntax reference states that _"if you specify the access for any of these
permissions, all of those that are not specified are set to `none`"_. So Item 1's
workflow-level `contents: read` already denies all fifteen other scopes. **In scopes granted
today, this amendment and Item 1 are identical** — `ci.yml` has exactly one job, and that job
ends up with `contents: read` either way.

The single difference is what a job added later inherits when it declares nothing:

|                   | the `test` job today | a new job with no `permissions` block           |
| ----------------- | -------------------- | ----------------------------------------------- |
| Item 1 as written | `contents: read`     | inherits `contents: read` silently              |
| This amendment    | `contents: read`     | gets nothing, and fails loudly on its first run |

That is the whole value, and it is the reason to take it: the second row is a failure that
announces itself at the moment the job is written, instead of a scope granted by inheritance
that no review ever looks at. GitHub's own guidance is the standard being applied — _"As a good
security practice, you should grant the `GITHUB_TOKEN` the least required access."_

**What a new job in this project would actually need**, so the pattern is not re-derived: a
lint job or a `docker build` job needs `contents: read` and nothing else. Beyond that,
`pull-requests: write` to comment on a PR, `security-events: write` to publish scan results,
`pages: write` plus `id-token: write` to publish to Pages, `contents: write` to push a commit
or cut a release. None of them is `packages: read` — the one extra scope the account default
grants today and that nothing here uses.

**`permissions: read-all` was considered and is rejected as a widening.** It grants read on
every scope that accepts it. Measured against the account default that Item 1 read
(`contents: read` plus `packages: read`), it would take the token from two scopes to more than
a dozen — the opposite of what Item 1 exists to do, and directly against the least-privilege
guidance quoted above. The concrete cost, stated because the abstract one persuades nobody:
under Item 2's own threat model, a moved tag on the badge action runs third-party code with
this token in its environment. Under `contents: read` that code reads source that is already
public. Under `read-all` it also reads `vulnerability-alerts` and `security-events` — Dependabot
alerts and scan results, which are **not** public even on a public repository.

**Unaffected, verified under Item 1 and re-stated here:** the badge step authenticates with
`secrets.GIST_SECRET`, a separate credential. No `permissions` value touches it.

**The one thing not verified, and how it settles.** Whether a job-level `permissions` block
_replaces_ the workflow-level one or is _intersected_ with it is not stated on GitHub's
"Controlling permissions for GITHUB_TOKEN" or "Assigning permissions to jobs" pages, both read
this session. Consistent secondary sources say it replaces. This amendment does not depend on
resolving it by reading: if it intersects, the `test` job receives nothing, `actions/checkout`
fails on step 1 of the first push, and the revert is replacing `permissions: {}` with
`permissions: contents: read` — one line. A loud, immediate, free failure with a one-line
revert is not a risk worth choosing the weaker option to avoid.

**Alternatives considered** (superseding the three bullets above)

- **`permissions: contents: read` at the workflow level, no job-level block** (Item 1 as
  written) — certain to work, and identical in effect today. Set aside: a second job added
  later inherits a scope it never asked for.
- **`permissions: {}` at the workflow level with no job-level grant** — the strictest form. Set
  aside: nothing then grants `contents: read`, so this depends on whether a public repository
  retains implicit read access for `checkout`, which the audit could confirm only from
  secondary sources. The amendment gets the same posture without depending on that answer.
- **`permissions: read-all`** — rejected above, as a widening rather than a hardening.
- **Status quo** — set aside on Item 1's durability argument, unchanged.

### Item 2 — all three actions pinned to a full commit SHA

`ci.yml` uses `schneegans/dynamic-badges-action@v1.9.0` and hands it `secrets.GIST_SECRET`
(`ci.yml:62-64`). A Git tag is movable by the action's owner, so the credential is exposed to
whatever that tag points at. GitHub's hardening guidance: _"Pinning an action to a full-length
commit SHA is currently the only way to use an action as an immutable release."_

Resolved via the GitHub API this session — **the Developer re-resolves at implementation time
rather than copying these**:

| Action                             | Tag      | Commit                                     |
| ---------------------------------- | -------- | ------------------------------------------ |
| `schneegans/dynamic-badges-action` | `v1.9.0` | `28b0fa8bdeb46170ac397105ece0c1fe58f68910` |
| `actions/checkout`                 | `v4`     | `11d5960a326750d5838078e36cf38b85af677262` |
| `actions/setup-python`             | `v5`     | `a26af69be951a213d495a4c3e4e4022e16d87065` |

**What decided all three rather than only the third-party one.** The repository-level Actions
settings expose a toggle that the plan had not accounted for:

```
$ gh api repos/thaisdMM/skillbridge/actions/permissions
{"enabled":true,"allowed_actions":"all","sha_pinning_required":false}
```

GitHub's REST reference describes `sha_pinning_required` as controlling _"whether actions must be
pinned to a full-length commit SHA."_ Pinning only the third-party action leaves that toggle
unusable, so the rule would rest on the maintainer remembering the criterion ("pin the ones that
receive a secret") every time an action is added. Pinning all three makes the rule enforceable by
the platform instead of by memory.

**The cost accepted.** `actions/checkout` and `actions/setup-python` stop receiving fixes
published by moving their tags, and three 40-character SHAs replace three readable tags. There is
no `.github/dependabot.yml` in this repository — verified, `.github/` contains only `workflows/`
— so updates are manual today.

**Alternatives considered**

- **Pin only `schneegans/dynamic-badges-action`** — treats the only action that combines
  third-party authorship with access to a credential, and keeps `@v4`/`@v5` legible. Set aside
  once `sha_pinning_required` was found: it is the option that cannot be locked in.
- **Remove the badge step entirely** — dissolves the threat instead of managing it, and
  `README.md:3` already carries GitHub's native workflow-status badge, so the README would keep
  an indicator. Set aside: it discards the live test-count badge (`README.md:4`), which is
  deliberate portfolio work.
- **Status quo** — set aside. `continue-on-error: true` and the `main`-only condition on that
  step narrow the window but not the exposure: when the step runs, the secret is in its
  environment.

#### Amendment to Item 2, 2026-08-17 — bump to the current majors first, pin four actions, add Dependabot (closes Issue 4 of the 2026-08-16 audit)

Item 2 identified SHA pinning as the right hardening measure and then applied it to a version
state nobody checked. Latest releases, read from `gh api repos/<r>/releases/latest`:
`actions/checkout` is at **v7.0.1** (2026-07-20) and `actions/setup-python` at **v7.0.0**
(2026-07-20). Item 2 pins v4 and v5, and its own instruction to re-resolve the SHA at
implementation time does not help — re-resolving `v4` yields v4. SHA pinning converts _"the
maintainer might not update this"_ into _"this cannot update itself"_; applied to a major three
releases old, it freezes a stale dependency permanently.

**Decided, three parts:**

1. **`actions/checkout` and `actions/setup-python` are bumped to their current majors first**,
   and the SHAs are resolved against those. Pinning v4/v5 is ruled out in every scenario.
2. **Four actions are pinned, not three.** D6's first amendment added `astral-sh/setup-uv` to
   the workflow; it is third-party and is pinned on the same terms as the rest. Item 2's "all
   three actions" is superseded by "every action in the workflow", which is the form that
   survives another action being added.
3. **`.github/dependabot.yml` is created**, covering the `github-actions` ecosystem, so the
   pins have a versioned update path instead of depending on memory.

**What changed the cost model.** Item 2 accepted permanent manual maintenance and left "whether
Dependabot updates SHA-pinned actions" as a verification debt, because GitHub's page on keeping
actions up to date does not mention SHA pinning. The GitHub changelog of 2022-10-31 closes it:
_"Dependabot will now update the semver version in comments when updating Actions workflows
with a commit SHA version."_ It updates the SHA **and** the `# vX.Y.Z` comment beside it. The
maintenance cost Item 2 accepted as permanent is bounded.

The `sha_pinning_required` toggle read under Item 2 (`gh api repos/…/actions/permissions` →
`"sha_pinning_required": false`) is what still argues for pinning every action rather than only
the one holding a credential: a rule the platform can enforce beats a rule a maintainer has to
remember.

**The costs accepted.** Dependabot opens pull requests on a cadence and someone has to merge
them; the `github-actions` ecosystem supports `interval: monthly`, which is the shape to reach
for first. And a major bump of two actions is a behavior change to verify once — see the
verification debts.

**Alternatives considered**

- **Pin all four at the majors Item 2 named (v4/v5)** — one rule, no per-action judgement. Set
  aside: it is the option that locks in staleness, and the Dependabot fact removes the low
  maintenance cost that made it attractive.
- **Pin only `schneegans/dynamic-badges-action`, leave the GitHub-maintained ones on tags** —
  treats the only action combining third-party authorship with a live credential, and keeps
  the tags legible and self-updating. Set aside for the reason Item 2 already gave:
  `sha_pinning_required` becomes unusable, so the rule lives in memory rather than in a
  platform setting.
- **Remove the badge step and pin what remains** — dissolves the `GIST_SECRET` exposure rather
  than managing it. Set aside: it discards the live test-count badge, which is deliberate
  portfolio work, and it still leaves the pinning question open for the rest.

### Item 3 — add a `pull_request` trigger; defer the scheduled run

`on:` currently carries `push: branches: ["**"]` and nothing else.

**What the run history shows.** `gh run list` returns 15 runs, every one of them `event: push`,
13 of them on `feature/django-refactor`. CI already runs on the working branch, and the merge of
a pull request into `main` already triggers a run of its own. Two corrections follow from this
data:

- The thing that updates only on merge is the **badge**, not CI: both badge steps carry
  `if: github.ref == 'refs/heads/main'` (`ci.yml:55,60`).
- CI triggers on `push`, never on `commit`. Seven commits authored on 2026-08-14 produced roughly
  three runs, because commits were pushed in batches. Raising CI frequency is a habit change, not
  a workflow change.

**What `pull_request` adds that `push` cannot.** GitHub's event reference: _"Your CI tests run
against the merged result, not just the head branch alone."_ With `push` alone, an integration
break is discovered after `main` already carries it; with `pull_request`, the PR shows red before
the merge button is used. Both README badges point at `main`, so a broken `main` is publicly
visible on a portfolio repository.

**Cost accepted:** while a PR is open, each push produces two runs — one for the branch, one for
the merge result. Verified as free of charge: _"GitHub Actions usage is free for … public
repositories that use standard GitHub-hosted runners."_ The cost is a noisier Actions history.

**The scheduled run is deferred, not rejected.** Audit Issue 15's point holds — `pip-audit` on
`push` only detects a newly published advisory at the next push, and the measured gap between
runs on this repository has reached 47 days (2026-05-31 → 2026-07-17). But `pip-audit` is the
schedule's only beneficiary, and its task has not been written yet; adding the trigger now would
be planning around a step that does not exist, the same reasoning D5 used to reject named
dependency groups. **The question returns when the `pip-audit` task is drafted** — not at D12,
which covers static analysis rather than dependency auditing.

One fact to carry into that decision, verified now so it is not re-derived: _"In a public
repository, scheduled workflows are automatically disabled when no repository activity has
occurred in 60 days."_ A schedule would cover gaps up to that limit and switch itself off beyond
it.

**Alternatives considered**

- **`push` only (status quo)** — set aside: it leaves integration failures discoverable only
  after `main` carries them.
- **`push` + `schedule`** — deferred as above.
- **All three triggers** — set aside: it bundles the deferred decision into a decided one.
- **Restricting `push` to `main` and leaving branches to `pull_request`** — would remove the
  duplicate runs, at the cost of no CI on a branch with no open PR. Not evaluated further; raised
  only so the Developer does not treat it as an oversight.

#### Amendment to Item 3, 2026-08-17 — add a concurrency group and a docs path filter (closes Open Decision E of the 2026-08-16 audit)

Item 3's trigger decision stands: `pull_request` is added, `push: branches: ["**"]` is kept,
and the scheduled run stays deferred to the `pip-audit` task. What Item 3 did was **write down
two costs and accept them without looking for a mitigation** — duplicate runs while a pull
request is open, and superseded runs executing to completion. Both have a standard remedy.

**Decided, two additions.**

1. **A `concurrency` group with `cancel-in-progress: true`.** A new push cancels the run it
   supersedes instead of racing it. The group key is per-workflow and per-ref, so a `push` run
   and its `pull_request` counterpart do not cancel each other — the two events carry different
   `github.ref` values for the same branch. The exact expression is written against GitHub's
   workflow-syntax reference at implementation time rather than copied from here.
2. **`paths-ignore` covering `docs/**`and the Markdown files at the repository root.** This
repository commits documentation heavily — the working tree during this planning session
carried seven untracked files under`docs/`— and with D6's amendment 2 adding a`docker build`step, a documentation-only push would otherwise pay a base-image pull, an`apt-get`and a`uv sync` for nothing.

**What is deliberately left OUT of the path filter, and this is the load-bearing part:**
`.claude/rules/**` and `specs/**` are **not** ignored. The rule files are project rules that
agents load every session, not reading material, and a change to them is worth a run; `specs/`
is excluded from the filter out of prudence, at no cost. Only `docs/**` and root Markdown are
filtered.

**The trap this accepts, stated so it is not rediscovered.** A wrong path filter fails silently
— it skips a run that was wanted, and nothing reports that. And if branch protection with
required status checks is ever configured, a skipped required check stays pending and blocks the
merge; GitHub's documented workaround is a dummy job carrying the same name. No required checks
exist on this repository today, so this is a condition to remember rather than a cost being paid
now. Note also that `paths-ignore` skips a run only when **every** changed file matches the
filter, so a push mixing code and documentation still runs — which is the desired behavior.

**Alternatives considered**

- **Item 3 as written, with no mitigation** — set aside: the concurrency group is three lines,
  costs nothing on the runs where it never fires, and targets exactly the cost Item 3 wrote
  down.
- **Restricting `push` to `main` and leaving branches to `pull_request`** — removes duplicate
  runs entirely. Set aside on Item 3's own measured evidence: 13 of the repository's 15 runs
  were on a feature branch, so this trades a noise cost for a coverage cost, and removes
  feedback exactly where it is worth most.
- **The concurrency group without `cancel-in-progress`** — queues rather than cancels. Not
  pursued: it defers the duplicate work instead of removing it.

### Recorded but not planned — settings that live outside the repository

`allowed_actions: "all"` and `sha_pinning_required: false` are repository/account settings, not
files. They cannot be versioned, reviewed in a diff, or restored by a clone, so no task in this
plan can own them. `allowed_actions: "all"` is what permits this workflow to run at all and is
correct as it stands; tightening it would control _which_ action may run, never _which version_,
so it is not a substitute for Item 2.

### Open questions carried to the task

- The scope of the token behind `secrets.GIST_SECRET` was not read — GitHub secrets are
  write-only through the API. The user recalls granting `gist` only, which would bound a leak to
  read/write over that account's gists. Worth confirming at
  `https://github.com/settings/tokens` before the task is implemented.
- Whether Dependabot updates SHA-pinned actions was **not confirmed**: the official page on
  keeping actions up to date does not mention SHA pinning. This decides whether Item 2's manual
  maintenance cost is permanent or removable, and belongs in the verification debts below.

---

## D9 — `ruff` rule selection: adopt the tool's own default set, unmodified

**Decided:** 2026-08-15. Closes audit Issue 9, verified as a HOLD.

`pyproject.toml` declares `[tool.ruff]` with **no `select` and no `ignore`**. The linter runs
whatever `ruff` ships as its default rule set for the pinned version, and `ruff format` runs
alongside it. `line-length` stays at the tool's default.

### What was wrong in the superseded plan

It specified `select = ["E", "F", "I"]` and described that as _"ruff's own default rule set …
the standard starting point documented by the tool itself, not a contested choice"_. Three
separate errors in one sentence:

- The full `E` prefix is not the default, and selecting it enables `E501` (line-too-long).
- `I001` is already in the default, so naming `I` adds nothing.
- The set it describes was never any version's default.

### The correction the audit could not have made

Both the audit and the verification state that ruff's default enables only `E722`, `E902` and
`W605` from pycodestyle. That was accurate until July 2026 and is now stale.

**ruff v0.16.0, released 2026-07-23, replaced the default rule set — 413 rules by default, up
from 59** (Astral blog, _Ruff v0.16.0_). The same release _removed_ 18 opinionated rules from
the default (`E401`, `E402`, `E701`, `E702`, `E703`, `E711`, `E712`, `E713`, `E714`, `E721`,
`E731`, `E741`, `E742`, `E743`, `F403`, `F405`, `F406`, `F722`). The current release is
**0.16.3** (PyPI JSON API, read this session).

Read directly from ruff's _Default Rules_ page this session, which now lists **416 rules**:

- `E501` is **not** in the default. From pycodestyle only `E722` and `E902` appear.
- `I001` **is** in the default.
- From `flake8-bandit`, only `S102`, `S110` and `S112` are in the default — three rules, not the
  prefix. **This is an input to D12**, not a decision taken here.
- From pydocstyle only `D419`; from pep8-naming only `N999`; no `ANN` rule at all.

So the audit's conclusion holds — `["E", "F", "I"]` is wrong and conflicts with the formatter —
but the correct destination is not the set either document assumed.

### The formatter conflict, in the tool's own words

Ruff's formatter documentation: _"The formatter only makes a best-effort attempt to wrap lines
at the configured line-length. As such, formatted code may exceed the line length, leading to
E501 errors."_ With `ruff check` and `ruff format --check` both wired as build-failing steps,
an `E501` the formatter cannot fix leaves no green path.

That is not hypothetical here. Measured on this repository with `awk 'length > 88'` over
`accounts/`, `profiles/`, `config/` and `manage.py` — 68 files, **176 lines over 88 characters**,
longest 253:

| Area            | Lines > 88 |
| --------------- | ---------- |
| `*/migrations/` | 59         |
| `*/tests/`      | 101        |
| Production code | 16         |

The 16 production lines are almost all docstrings and single string literals, which the
formatter does not split — `config/settings.py:94` (the `UserAttributeSimilarityValidator`
dotted path), `profiles/models/client_profile.py:5`, `accounts/admin.py:128`. Clearing them
would mean rewriting docstrings by hand to satisfy a linter.

### Measured before deciding, not estimated

Run this session with `uvx ruff@0.16.3` from `django_version/`. Nothing was installed into the
project and no file was modified.

| Configuration                                              | Findings | Auto-fixable |
| ---------------------------------------------------------- | -------- | ------------ |
| Default set, whole project                                 | **67**   | 26           |
| Default set, excluding `migrations/`                       | **38**   | 25           |
| `select = ["E4","E7","E9","F","I"]` (the pre-0.16 default) | 17       | 15           |
| `select = ["E501"]` alone                                  | **176**  | 0            |

The last row is what decided against every variant that turns `E501` on: one rule produces
nearly three times the findings of the entire 416-rule default, and not one of them is
auto-fixable.

The 38 findings outside `migrations/`, by rule:

| Rule                              | Count | Auto-fixable |
| --------------------------------- | ----- | ------------ |
| `I001` unsorted-imports           | 12    | yes          |
| `RUF012` mutable-class-default    | 10    | no           |
| `SIM117` multiple-with-statements | 6     | yes          |
| `RUF022` unsorted-dunder-all      | 3     | yes          |
| `F401` unused-import              | 2     | yes          |
| `F821` undefined-name             | 2     | no           |
| `PIE790` unnecessary-placeholder  | 2     | yes          |
| `SIM102` collapsible-if           | 1     | no           |

Thirteen findings need a human. Ten of those are the same `RUF012`, a mechanical annotation
change concentrated in `accounts/admin.py`, `profiles/models/skill.py` and the model modules.

Of the 29 findings that disappear when `migrations/` is excluded, 28 are `RUF012` on the
generated `dependencies = [...]` line. That is input to the scope question below, not a reason
to change the rule set.

`ruff format --check .` reports **18 of 75 files would be reformatted** — a single one-time
`ruff format .`, with no decision attached.

### Why this path

- The v0.16 default was redesigned specifically to coexist with a formatter, so the conflict
  the audit found is absent by construction rather than by an `ignore` entry someone must
  maintain and justify.
- The measured cost is 13 manual edits, which is not a cleanup project.
- It is the largest coverage this plan can buy for zero configuration: real-bug families (`B`,
  `F`), modernization (`UP`), performance (`PERF`), simplification (`SIM`) and `RUF`.

### The cost accepted, stated plainly

The default set is **version-dependent**. It already changed once, in 0.16.0, and a future
release may change it again — which means a `uv lock` that bumps ruff can change what CI
enforces with no configuration file having been edited. This was raised before the decision and
accepted knowingly: `uv.lock` pins the exact ruff version, so the change can only arrive through
a deliberate lock update, never silently between two runs of the same commit.

### Alternatives considered

- **`select = ["E4", "E7", "E9", "F", "I"]`** — the pre-0.16 default, which Astral documents as
  the way to restore the old behavior. Measured at 17 findings, 15 of them auto-fixable, and it
  makes the enforced set an explicit written contract that a version bump cannot move. Set
  aside: it deliberately adopts a set upstream had just abandoned as too narrow, and the
  predictability argument it rests on is largely delivered by the lockfile instead.
- **`select = ["E", "F", "I"]` with `ignore = ["E501"]`** — the superseded plan's set with its
  defect patched. Set aside on measured grounds: the full `E` prefix restores the 14 opinionated
  rules v0.16 had just removed from the default, while still covering fewer real-bug families
  than the default does. It is smaller than the default on the axis that matters and larger on
  the axis that does not.

### Amendment, 2026-08-17 — the decision becomes "the default set **plus** `extend-select = ["S"]`" (required by D12)

D9's decision is stated above as `[tool.ruff]` with **no `select` and no `ignore`**. D12 selects
ruff's `S` rules for static security analysis, which adds an `extend-select` and a
`per-file-ignores` entry. **D9's text is no longer literally true, and this amendment is what
keeps the plan and the file in agreement** — leaving D9 unqualified while `pyproject.toml`
carries an `extend-select` is precisely the documentation-versus-reality drift this replanning
exists to stop.

**What actually changed, and what did not.** The _rule-set_ decision stands entirely: the
default set is adopted unmodified, no rule is removed from it, `line-length` stays at the
tool's default, and `E501` stays off. What is added is one prefix the default deliberately
omits, for a purpose D9 did not cover. D9 recorded the relevant fact itself: of the
`flake8-bandit` family, only `S102`, `S110` and `S112` are in the default — three rules, not
the prefix — _"This is an input to D12, not a decision taken here."_ That input has now been
spent.

**The precise form after D12:**

- `extend-select = ["S"]` — `extend`, not `select`, so the default set is preserved rather than
  replaced. This is the distinction that keeps D9's decision intact; a bare
  `select = ["S", …]` would discard the 416-rule default and re-open everything D9 measured.
- `per-file-ignores` for `S101` and `S106` under `*/tests/*` — the only two codes measured, and
  scoped per D9a's principle.
- Still **no `ignore`** at the top level, and no rule of the default set suppressed anywhere.

**The cost D9 accepted is unchanged in kind and slightly widened in surface.** D9 knowingly
accepted that the default set is version-dependent and can move on a `uv lock` that bumps
ruff. The `S` prefix carries the same property: its 73 rules are the 73 that version ships.
The same bound applies — `uv.lock` pins the exact version, so a change arrives only through a
deliberate lock update, never silently between two runs of the same commit.

### Investigated while measuring: invocation directory — resolved, nothing to declare

Measured before `pyproject.toml` exists, the same code and the same rule set give different
results depending on where ruff is invoked from:

```
$ cd django_version && ruff check .                            → 67
$ ruff check .                     # from the monorepo root    → 74 in django_version/
```

The delta is entirely `I001` (13 versus 20). Ruff decides whether an import is first-party from
its `src` setting, so with no configuration anywhere, `accounts` and `profiles` look
first-party from `django_version/` and third-party from the root, and import ordering is judged
differently.

**This does not survive D2, and needs no `src` declaration.** Ruff's _Configuration_ page,
under config file discovery: _"the 'closest' config file in the directory hierarchy is used for
every individual file, with all paths in the config file (e.g., `exclude` globs, `src` paths)
being resolved relative to the directory containing that config file."_ With `pyproject.toml`
in `django_version/`, the default `src = [".", "src"]` resolves to `django_version` regardless
of the invocation directory.

Verified by construction rather than by citation — a throwaway mirror of the layout, a
`pyproject.toml` in the subdirectory, and imports ordered correctly only if the local package is
treated as first-party:

```
$ cd sub && ruff check --select I001 .    → All checks passed!
$ cd ..   && ruff check --select I001 .   → All checks passed!   (from the parent)
```

**What remains for D14, and it is a different problem.** Hierarchical configuration configures
a subdirectory; it does not exclude one, and the same page states that _"Ruff does not merge
settings across configuration files; instead, the 'closest' configuration file is used, and any
parent configuration files are ignored."_ Run from the monorepo root, ruff still reads
`oop_version/` — 49 findings there, 123 in total — under default settings, since no config file
sits near those files. `ci.yml` already sets `working-directory: django_version` and D2 places
the configuration there, so both decided paths are clean. Only a hook runner invoking ruff from
the repository root would reach the closed directory, which makes it a question about
invocation scope for D14, not about ruff configuration.

### Open questions carried to the task

- **Ruff's file scope is not settled by this entry** — see D9a, which follows.
- The exact ruff version to pin is fixed at implementation time per `conventions.md`; 0.16.3 is
  what was measured here.
- `RUF012` on Django class attributes (`list_display`, `fieldsets`, `Meta` members) is a known
  friction point between the rule and the framework's idiom. Whether the fix is `ClassVar`
  annotations or a per-file ignore is the Developer's measurement, made with the real diff in
  hand.

### Flagged, deliberately not absorbed into this plan

`F821` reports `Undefined name BaseUser` at `accounts/models/base.py:43` and `:104` — the
manager's return annotations name a class defined later in the same module, with no
`from __future__ import annotations`.

Verified in the container rather than reasoned about:

```
$ docker-compose exec web python -V
Python 3.14.6
$ docker-compose exec web python -c "<the same pattern>"
OK: module imported, no exception
get_type_hints -> {'return': <class '__main__.BaseUser'>}
```

The annotation resolves, and resolves correctly. This is not a latent runtime defect on the
pinned Python; the rule is reporting a pattern that was unsafe before annotations became
lazily evaluated. Neither audit raised it, so per `PLANNER.md` it is recorded as a signal and
belongs to an Auditor session, not to a task here. What the Developer needs from this plan is
only that two `F821` findings exist and are not bugs.

---

## D9a — `ruff` scope: `migrations/` stays linted, with `RUF012` alone suppressed there

**Decided:** 2026-08-15. Completes D9. No `exclude` or `extend-exclude` entry is added.

`pyproject.toml` declares one `[tool.ruff.lint.per-file-ignores]` entry silencing `RUF012` under
`*/migrations/*`. Migration files stay inside ruff's scope for every other rule.

### The choice this was between

Excluding the two `migrations/` directories outright, or suppressing the single rule that
accounts for the noise. Both remove the same findings today; they differ in what happens to a
migration written in the future.

### What was measured

All 29 findings inside `accounts/migrations/` and `profiles/migrations/`, listed individually:

| Finding                        | Count | Where                                                            |
| ------------------------------ | ----- | ---------------------------------------------------------------- |
| `RUF012` mutable-class-default | 28    | `dependencies = [...]` and `operations = [...]`, in all 14 files |
| `I001` unsorted-imports        | 1     | `accounts/migrations/0001_initial.py`, auto-fixable              |

`RUF012` fires on the two attributes Django's `Migration` class requires. They are present in
every migration, hand-written ones included: in `profiles/migrations/0002_seed_skills.py` — a
`RunPython` data migration authored by hand, recorded in `ARCHITECTURE.md` under _Skill Seed —
bulk_create Without clean() Validation_ — the two findings sit on `dependencies` and
`operations`, and nothing in the hand-written `SKILLS_TO_SEED` list, `seed_skills` or
`remove_skills` is flagged at all.

So the suppression is not a boundary between generated and hand-written files. It is a boundary
between one rule and every other rule, applied uniformly to both kinds of file.

### Why this path

Migrations are the least protected code in the repository. `pytest.ini` runs the suite with
`--no-migrations`, so as `.claude/rules/testing.md` records, migration files are never executed
by the test suite — the 14 files in `accounts/migrations/` and `profiles/migrations/` are the
one place where a defect reaches a real database without a test having run over it. `RUF012` is
noise there because the pattern it objects to is mandated by the framework; `F821`, `F401` and
the rest are not noise there, and excluding the directory would discard them along with the
noise.

The project already has one hand-written data migration and will gain more when `jobs` exists.

### The cost accepted

Two lines of configuration instead of one, and one `I001` finding in a generated file that has
to be fixed rather than ignored. It is auto-fixable.

### Alternatives considered

- **`extend-exclude = ["*/migrations/*"]`** — one line, and it matches the plain reasoning that
  generated code is not linted. Set aside: 13 of the 14 files are generated, but the fourteenth
  is not, and a blanket exclusion silences every rule in the only tree the test suite never
  executes. Recorded as cheaply reversible in either direction — swapping between the two is an
  edit to one file, with no migration, no test change and no runtime effect — so if the targeted
  form proves noisy in practice, switching costs nothing.

### Consistency note carried forward

This is the same shape as audit Open Decision 3, which asks whether all of `tests/` is excluded
from the security scanner to silence one hardcoded-password rule. ~~That question is still open
under D12.~~ **Closed 2026-08-17: D12 decided it the same way** — `per-file-ignores` for `S101`
and `S106` under `*/tests/*`, with `config/` kept in scope — so this plan carries one principle
rather than two. `.claude/rules/conventions.md` → _Layer ownership_ is the reason to prefer
scoping a suppression to the rule it is actually about.

### Amendment, 2026-08-17 — the "least protected code" premise is weakened (required by D17)

D9a's _Why this path_ section opens with: _"Migrations are the least protected code in the
repository. `pytest.ini` runs the suite with `--no-migrations`, so as `.claude/rules/testing.md`
records, migration files are never executed by the test suite — the 14 files in
`accounts/migrations/` and `profiles/migrations/` are the one place where a defect reaches a real
database without a test having run over it."_

D17 removes `--no-migrations`, so the migration files **are** executed on every construction of
the test database. The strong form of that sentence no longer holds.

**The decision stands, and its other argument carries it alone.** D9a's real reasoning is the
rule-versus-directory boundary: `RUF012` is noise in `migrations/` because the pattern it objects
to is mandated by Django's `Migration` class, while `F821`, `F401` and the rest are not noise
there, and a blanket `extend-exclude` would discard the second along with the first. That argument
never depended on how protected the directory was, and one of the 14 files is hand-written
regardless.

**What survives of the premise, stated precisely.** After D17 the migrations are _exercised_, not
_verified_: a file that raises, or that produces a schema the models disagree with, now turns the
suite red — but no test asserts anything about a migration's content, and the seed migration's
data is deleted before any test can see it (D17, cost 3). So migrations remain the least directly
tested code in the repository; they are no longer the untouched code the original sentence
described.

---

## D10 — Type checking: `mypy` + `django-stubs`, production code only, made blocking in a second task

**Decided:** 2026-08-17. Closes the D10 open item, audit Issue 10 of the 2026-08-15 pass, and
Open Decision 1 of `docs/audits/2026-08-17-audit-plan-toolchain-d10-d15.md`. Also corrects the
environment-coupling description that audit's Issue 2 found wrong in both directions.

`pyproject.toml` declares `mypy` and `django-stubs` in the `dev` group (D5), enables the
`django-stubs` mypy plugin, and points it at `config.settings`. The check covers production
code — `accounts/`, `profiles/`, `config/`, `manage.py` — and excludes `accounts/tests/` and
`profiles/tests/`. `migrations/` stays **in** scope. The CI step is added build-failing, in a
second task, after the errors the first task fixes are gone.

### Why the plugin decides the tool

`django-stubs`' own README states the support levels, read this session: **mypy** gets
_"full and complete support with multiple advanced features with our custom mypy plugin"_,
while **pyright**, **pyrefly** and **ty** each get _"basic support, checked in CI"_. Those
three consume the stubs; none loads the plugin.

The plugin is the entire reason to type-check a Django project — it resolves model fields,
related managers and settings. Every alternative delivers the generic half of the check
(_does this return a `str`?_) and discards the Django half (_is this a `QuerySet[Freelancer]`?_).

_(Aside: a mypy plugin is code that runs inside the checker and teaches it things the type
system cannot express on its own — for instance that `Freelancer.objects` yields `Freelancer`,
which no amount of annotation in your own files would establish.)_

**The compatibility question the superseded plan never asked is now answered**, from the same
README:

| django-stubs | mypy       | Django  | Python          |
| ------------ | ---------- | ------- | --------------- |
| **6.1.0**    | 1.13 – 2.3 | **6.1** | **3.11 – 3.14** |
| 6.0.9        | 1.13 – 2.3 | 6.0     | 3.10 – 3.14     |

6.1.0 covers D16's destination exactly — Django 6.1, Python 3.14 — and mypy 2.3.1 sits inside
its supported range. This settles the _"django-stubs support for Django 6.0.7 and Python 3.14"_
verification debt; the version it had to be checked against changed under D16, and the answer
is clean.

### What was measured, in this repository

Run 2026-08-17 from `django_version/` via `uvx`, nothing installed into the project and no file
modified: `mypy 2.3.1` + `django-stubs[compatible-mypy] 6.1.0` + `django 6.1` + `psycopg[binary]`

- `argon2-cffi` + `python-dotenv`, plugin enabled, default (non-strict) settings, over
  `accounts profiles config manage.py` — 68 source files.

**120 errors in 22 files, exit 1.** Of those, 18 are `Cannot find implementation or library stub
for module named "pytest"`, an artifact of the disposable environment carrying no `pytest`; they
do not exist when the check runs inside the project environment. The 2026-08-17 audit's
independent run, which had `pytest` present, reported 102 with an otherwise identical breakdown —
the two measurements agree.

| Area                | Errors |
| ------------------- | ------ |
| **Production code** | **18** |
| Test code           | 102    |

| Production file           | Errors | Nature                                                                      |
| ------------------------- | ------ | --------------------------------------------------------------------------- |
| `accounts/admin.py`       | 12     | mixed; see the open question below                                          |
| `accounts/models/base.py` | 4      | one fix — the manager's `TypeVar` has no bound                              |
| `profiles/admin.py`       | 1      | isolated                                                                    |
| `config/settings.py`      | 1      | `ALLOWED_HOSTS = []` needs an annotation; Phase 5 rewrites that line anyway |

**`migrations/` produced zero errors** and is therefore not excluded. The original open item
asked for an `exclude` covering the generated migration directories; measured, there is nothing
there to exclude, and adding one would be a suppression without a cause. This applies D9a's
principle unchanged — suppress the rule, never the directory — and it is measured under
non-strict settings, which is what this decision adopts.

### Why tests are out of scope, and where that debt lives

102 of the 120 errors are in test code, and **60 of the 61 `arg-type` errors are one shape**:
a dict unpacked into `BaseUserManager.create_user`. The cause was isolated by measurement and
it is narrower than the audit described.

It is **not** the merge-and-override idiom `.claude/rules/testing.md` prescribes. In
`accounts/tests/models/test_base.py`, `test_create_user_normalizes_email`,
`test_create_user_email_empty_raises_validation_error` and
`test_create_user_invalid_email_raises_validation_error` all use that idiom with a `str`
override and pass clean. The failures are the tests that inject a **non-string** —
`test_create_user_accepts_extra_fields` (`is_available`),
`test_create_super_user_with_is_staff_false_raises_value_error`,
`test_create_super_user_with_is_superuser_false_raises_value_error`,
`test_create_user_rejects_superuser_without_staff_status` and
`test_create_user_rejects_non_staff_model_with_privileges`.

The collision is with a single line of `testing.md` — the rule prescribing a union
(`dict[str, str | bool]`) for slightly heterogeneous fixtures — and the checker is right to
refuse it: that annotation genuinely permits `{"email": True}`.

Bringing tests into scope therefore means changing a rule file that is auto-loaded into every
session, across roughly 30 call sites in 9 files. That is a convention decision, not a tooling
one, and smuggling it through a type-checker installation is the coupling this replanning
exists to stop. **It is recorded in full — every measurement, all three remedies, and the
`TypedDict` composition caveat — in `docs/tech_debt/006-tests-excluded-from-type-checking-fixture-annotations-cannot-pass.md`.**

One instruction from that entry is repeated here because it is the tempting wrong move:
annotating the baseline fixtures `dict[str, Any]` clears all 60 errors with two edits, and it
is refused. It buys silence by making the annotation weaker than what the project already has.

### The environment coupling — corrected, and what it constrains

The open item stated that the plugin _"imports the module named by `django_settings_module`"_
and that _"in any context without `.env` or the environment variables mypy aborts"_. Both halves
were wrong, in opposite directions.

- **Narrower than stated.** `config/settings.py` derives `BASE_DIR` from its own location and
  calls `load_dotenv(BASE_DIR / ".env")` with an absolute path. The working directory is
  irrelevant; a run from the repository root resolves `.env` exactly as one from
  `django_version/` does. The failing case is a machine with no `django_version/.env` **and** no
  exported `SECRET_KEY`.
- **Wider than stated, and this is the load-bearing half.** The plugin does not merely import
  settings — it initialises the Django app registry, which imports the configured database
  backend. Measured: with `django-stubs`, `django` and `python-dotenv` present but no psycopg,
  mypy fails with `INTERNAL ERROR … Error loading psycopg2 or psycopg module` while constructing
  the plugin. Adding `psycopg[binary]` and `argon2-cffi` made it run.

**A type check therefore requires the project's entire production dependency set installed.**
Three consequences:

| Context                                         | Works?                                                                    |
| ----------------------------------------------- | ------------------------------------------------------------------------- |
| Inside the image (D4 installs everything)       | yes                                                                       |
| On the CI runner, after `uv sync --locked` (D6) | yes                                                                       |
| In a hook                                       | **only** if the hook executes inside the project environment (`uv run …`) |
| As a standalone `uvx mypy` step                 | never                                                                     |

The third row is a hard constraint on **D14**, and is the reason D10 is decided before it.

### How it lands: two tasks, not one

The 18 production errors are fixed in one task; a second task adds the CI step, build-failing
from its first run.

The alternative shapes were a single task that fixes and wires together, or a non-blocking step
now made blocking later. The second is refused for the reason D7 already gave when it rejected
`continue-on-error`: a step that cannot fail is a step nobody reads. The first is refused
because of where the errors sit — 12 of the 18 are in one file, and at least two of those are
the case recorded as O2 in the 2026-08-17 audit: `accounts/admin.py` calls
`queryset.filter(profile__isnull=…)` on a parameter annotated `QuerySet[BaseUser]`, and
`BaseUser` is abstract and carries no `profile` reverse relation. **The code is correct** — at
runtime the queryset is a `Freelancer` or `Client` one, which does have it — so what is wrong is
the annotation, and choosing the right one may be a modelling judgement rather than an edit.

Splitting means that if it turns out to be a judgement, it returns to the Planner without a
half-finished task, and the CI step still enters with teeth. The instrument is the same one D16
uses: separate the commits so a failure is attributable.

### Configuration shape, read from upstream this session

```toml
[tool.mypy]
plugins = ["mypy_django_plugin.main"]

[tool.django-stubs]
django_settings_module = "config.settings"
```

Note the table is `[tool.django-stubs]`, **not** `[tool.mypy.plugins.django-stubs]` — the latter
is the `mypy.ini` form and does not carry over to `pyproject.toml`. Both forms appear in the
upstream README and confusing them yields a plugin that loads with no settings module.

Strict mode is **not** enabled. Every number above was measured under default settings, and a
strictness decision taken without its own measurement would repeat the superseded plan's error.

### Alternatives considered

- **`ty` (Astral) 0.0.72** — one vendor with `uv` and `ruff`, one config, one mental model, and
  10×–100× faster by Astral's own benchmark. Set aside on two grounds: no plugin, so the
  Django-aware half of the check is unavailable; and its own version policy states that
  _"breaking changes, including changes to diagnostics, may occur between any two versions"_ —
  which is the D9 risk without D9's stable-release floor. Recorded as the option to revisit if
  `ty` reaches a stable series and django-stubs' support level for it changes.
- **`pyright` / `basedpyright`** — best editor story of the four, and django-stubs checks
  Pyright in CI. Set aside: no plugin, same loss as `ty`, and `pyright` proper ships as an npm
  package, adding a Node runtime to an image D4 keeps deliberately simple.
- **`pyrefly` (Meta) 1.2.0** — past 1.0, so unlike `ty` it is not self-declared unstable. Set
  aside: no plugin, smallest ecosystem of the four, and no baseline was measured for it here.
- **No type checker; defer to Phase 3 with DRF** — serializers and views are where type checking
  pays most, and neither exists yet. Set aside: `conventions.md` mandates type hints on every
  signature and nothing verifies them today, so the rule is currently unenforced; and the
  measured production yield includes the one finding that looks like a real modelling
  inaccuracy.
- **Scope S2 — check tests too** — deferred to `docs/tech_debt/006-…`, per the reasoning above.

### Consequences for other entries

- **D14 inherits a constraint**, not a preference: whichever runner it selects, a mypy hook must
  invoke the tool inside the project environment. `uvx mypy` is ruled out by measurement.
- **The `.gitignore` / `.dockerignore` item under _Items that need no decision_ is now
  concrete**: the cache directory is `.mypy_cache/`, which is what that item already names. Had
  D10 gone to `ty`, `pyright` or `pyrefly`, that line would have been wrong.
- **D16's second argument is corrected, not its outcome** — see the note appended to that entry.

### Open questions carried to the task

- **The 12 errors in `accounts/admin.py` are not pre-diagnosed here.** The Developer fixes what
  is an annotation error and stops at anything that requires choosing how a queryset over two
  independent concrete models should be typed — that returns to the Planner.
- **Whether `django-stubs-ext` is needed, and if so where it belongs.** Upstream describes it as
  a _production_ dependency enabling runtime support for generic annotations, and separately
  notes that having it installed makes model `Meta` classes type-check without further changes.
  Whether `django-stubs` already pulls it in transitively was **not verified**. If it turns out
  to be required explicitly, it is the one dependency in this plan that would land in
  `[project].dependencies` rather than the `dev` group, which is worth a deliberate note under
  D5 rather than a silent `uv add`.
- The exact `mypy` and `django-stubs` versions are pinned at implementation time per
  `conventions.md`; 2.3.1 and 6.1.0 are what was measured here.

---

## D11 — Coverage: `pytest-cov` in `addopts`, with a 95% floor blocking from the first run

**Decided:** 2026-08-17. Closes the D11 open item and Open Decision 2 of
`docs/audits/2026-08-17-audit-plan-toolchain-d10-d15.md`. **Issue 5 of that audit does not
hold** — it is corrected below by execution, not amended.

`pyproject.toml` declares `pytest-cov` in the `dev` group (D5). The `addopts` array in
`[tool.pytest]` (D2's amendment) gains **`--cov` with no value** and `--cov-fail-under=95`.
`[tool.coverage.run]` carries `source`, `branch` and `omit`. The gate is build-failing from its
first run, in a single task.

### The measurement that decided it — taken because nothing had ever measured this

Run 2026-08-17 in a disposable container (`docker-compose run --rm`), so nothing was installed
into the project or into the running `web` container; `.coverage` was deleted afterwards and the
working tree left unchanged.

| Scope                                               | Statements | Missed | Coverage |
| --------------------------------------------------- | ---------- | ------ | -------- |
| **Production code** (no `tests/`, no `migrations/`) | 598        | 20     | **97%**  |
| Production plus tests, no `migrations/`             | 2318       | 20     | 99%      |
| Everything measured                                 | 2391       | 93     | 96%      |

`branch = true` does not move the number: production carries 96 branches with 3 partial, and the
production figure is 97% either way. It is rigour at no measured cost.

The 20 uncovered production statements, so the number is not read as a mystery:

| File                                      | Statements | What they are                                          |
| ----------------------------------------- | ---------- | ------------------------------------------------------ |
| `accounts/admin.py`                       | 8          | the only real gap                                      |
| `config/asgi.py` + `config/wsgi.py`       | 4 + 4      | Django scaffolding; no test imports either module      |
| `accounts/views.py` + `profiles/views.py` | 1 + 1      | empty modules — the import line only                   |
| `config/settings.py`                      | 1          | the `raise ValueError` guarding a missing `SECRET_KEY` |
| `profiles/models/base.py`                 | 1          | one line                                               |

**The measurement inverts the audit's own conditional.** Open Decision 2 recorded that _"if the
real number is very low (say under 50 %), option C becomes much more attractive than my
recommendation"_ — option C being a changed-lines gate. At 97% that option loses its premise: it
exists to give a project with no baseline something to enforce, and this baseline is high.

### Issue 5 does not hold, and it was settled by running it rather than by reading

Issue 5 states that `pytest-cov` overrides coverage's `parallel`, `source` and `branch`, so part
of the `[tool.coverage.*]` table D2 moves into `pyproject.toml` would be inert. Three runs in a
disposable container, with the configuration written to `/tmp` so no project file was touched:

| Configuration under test                                                      | Result                                                                       |
| ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `branch = true` in the config file, **no** `--cov-branch` on the command line | **honoured** — Branch and BrPart columns appear                              |
| `source = ["accounts"]` in the config, `--cov=profiles` on the command line   | **overridden** — only `profiles` files reported                              |
| `source` + `branch` + `omit` in the config, **`--cov` with no value**         | **all three honoured** — only `accounts`, no tests, no migrations, branch on |

pytest-cov's own configuration page is conditional, and the conditions were dropped in the
reading that produced the finding:

> _"If you use the `--cov=something` option (**with a value**) then coverage's `source` option
> will also get overridden."_
> _"**If you use the `--cov-branch` option** then coverage's `branch` option will also get
> overridden."_
> _"This plugin overrides the `parallel` option of coverage."_

Only `parallel` is overridden unconditionally, and this project runs the suite in one process,
so it would not set that key in the first place. **D2's `[tool.coverage.*]` table therefore moves
whole.** What the finding actually produces is one instruction rather than a split table:
`addopts` uses bare `--cov`, and never `--cov=<value>` or `--cov-branch`. Writing `--cov=accounts`
at some later date would silently disable the `source` key in the file — that is the trap, and it
is the only one.

### Why the floor blocks from the first run, and why 95

The gate starts green by measurement rather than by hope: 97% measured against a 95% floor. Two
percentage points is roughly twelve statements of headroom — loose enough that one new helper
does not turn CI red by accident, tight enough to stop a module arriving with no tests at all.

A floor set at the measured number is refused deliberately. Any new file carrying one uncovered
line would fail the build, and the cheapest repair available to whoever hits it is to lower the
number — which trains the project to lower the floor instead of raising the coverage. The floor
is a ratchet: it moves up when the real number moves up, as a decision.

**One task, not two.** D10 needed two because its baseline entered red — 18 errors to fix before
the step could have teeth. This baseline enters green, so there is nothing to fix first, and the
reasoning D7 used against `continue-on-error` applies unchanged: a step that cannot fail is a step
nobody reads.

### The `omit` list, and why it does not depend on the `--no-migrations` question

`*/tests/*` is omitted because test files are executed by definition; counting them inflates the
denominator and dilutes the signal. Measured, they contribute 1720 statements at 100%.

`*/migrations/*` is omitted, and the reason survives either outcome of the still-open
`--no-migrations` question — which is why D11 did not have to wait for it:

| Regime                         | What happens to migrations                            | Why they stay out of the count                                                             |
| ------------------------------ | ----------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| With `--no-migrations` (today) | never executed → 0%                                   | including them **depresses** the number; it would measure a runner flag, not missing tests |
| Without `--no-migrations`      | executed during database setup → effectively complete | including them **inflates** the number; it would measure Django's migration executor       |

Measured under today's regime: of the 93 uncovered statements in the whole project, **73 are
migrations**, and 13 of those are `profiles/migrations/0002_seed_skills.py` — a hand-written data
migration that no test has ever executed.

Neither exclusion is the shape D9a rules out. D9a refuses silencing a _directory_ to hide a rule's
findings; here the directories carry no findings to hide, and the exclusion is about what the
denominator is meant to represent.

### Alternatives considered

- **`coverage` invoked directly (`coverage run -m pytest` + `coverage report`)** — one dependency
  instead of two, every configuration key honoured with no conditional clause at all, and Issue
  5's trap removed by construction. Set aside: the suite stops being invoked as `pytest`, so root
  `CLAUDE.md` Rule 12's canonical command gains a second form, CI gains a second step, and
  `docker-compose exec web pytest` stops producing coverage — the local habit loses the
  measurement, leaving it something only CI performs.
- **A changed-lines gate (`diff-cover` or equivalent)** — the audit's option C, and the right
  answer for a project with no baseline. Set aside on the measurement: at 97% there is no missing
  baseline to work around, and it would add a third tool, a base ref to diff against on a
  long-lived feature branch, and a second definition of "covered" to maintain.
- **Measure and report with no gate, deferring the floor** — the audit's own recommendation,
  which paired option A with staging so the floor could be set _"from the measured number"_. Set
  aside because that measurement has now been taken: the only thing staging bought was waiting for
  it, and what remains is a deferral to record in `docs/tech_debt/` in exchange for nothing.
  **This is the one point where this entry departs from the audit's stated preference.**
- **A floor at the measured 97%** — see above; it makes lowering the floor the cheapest repair
  available to whoever trips it.

### Open questions and verification debts carried to the task

- **Whether `coverage` discovers `django_version/pyproject.toml` as its configuration file
  without `--cov-config`.** All three experiments above passed the configuration explicitly
  (`--cov-config=/tmp/…`) so that no project file was written. Discovery is expected, since
  pytest's `rootdir` is `django_version/`, but it was **not measured**, and it is the difference
  between the table governing the run and governing nothing — the same failure mode D2's
  `pytest.ini` amendment exists to prevent. The Developer confirms it once, by setting a key and
  observing it take effect.
- **`parallel` was not tested**, because nothing in this project runs the suite in parallel.
- The exact `pytest-cov` version is pinned at implementation time per `conventions.md`; 7.1.0 is
  what was measured here.
- The 8 uncovered statements in `accounts/admin.py` are not diagnosed here. Whether they are a
  missing test or unreachable code belongs to whoever writes the tests; it is not a precondition
  for the gate, which passes with them uncovered.

### Flagged, deliberately not absorbed into this plan

Two things surfaced while measuring. Per `PLANNER.md` they are recorded as signals, not tasks:

- **A test failed once in three runs and did not reproduce.**
  `profiles/tests/models/test_client_profile.py::test_client_profile_get_display_info` failed on
  the first coverage run; it passes in isolation, passes in the full suite, and passes on a second
  run with `pytest-cov` loaded. The traceback was lost to output truncation and was not recovered,
  so the cause is unknown. It is not an effect of `pytest-cov`.
- **D16 states the suite has 272 tests.** Measured 2026-08-17: **304 passed**. A stale number
  inside a closed entry, worth one line's correction the next time that entry is touched.

---

## D12 — Static security analysis: ruff's `S` rules, with `config/` in scope

**Decided:** 2026-08-17. Closes the D12 open item, audit Open Decisions 2 and 3 of the
2026-08-15 pass, and Open Decision 3 of
`docs/audits/2026-08-17-audit-plan-toolchain-d10-d15.md`. **Amends D9** — see the amendment
appended to that entry.

`pyproject.toml` adds `extend-select = ["S"]` under `[tool.ruff.lint]`, and one
`[tool.ruff.lint.per-file-ignores]` entry silencing `S101` and `S106` under `*/tests/*`.
`config/` stays in scope. No separate security tool is installed.

### What this buys, stated honestly: nothing today

Measured 2026-08-17 from `django_version/`, both tools run disposably via `uvx`, nothing
installed into the project and no file modified:

| Tool                           | Whole project                                     | **Production code only** |
| ------------------------------ | ------------------------------------------------- | ------------------------ |
| `ruff 0.16.3 check --select S` | 356 — 355 × `S101` assert, 1 × `S106`             | **0**                    |
| `bandit 1.9.4`                 | 363 — 355 × `B101` assert, 7 × `B105`, 1 × `B106` | **0**                    |

Both find nothing in production code. This codebase has no `subprocess`, no `eval`, no raw
SQL, and reads `SECRET_KEY` from the environment. Every finding is `assert` in a test, which
is what pytest requires.

**So this decision is not buying detection — it is buying coverage for code that does not
exist yet** (`jobs`, DRF views and serializers). When the benefit is in the future, what
decides is the recurring cost, not the detection delta. That is the whole argument for the
option chosen.

### Why ruff's `S` rather than bandit

**Rule inventory, read from ruff's own registry this session** (`ruff rule --all
--output-format json`, filtered to the `S` prefix): **73 rules**. The Django-relevant ones are
all present:

| Code   | Rule                         |
| ------ | ---------------------------- |
| `S308` | `suspicious-mark-safe-usage` |
| `S610` | `django-extra`               |
| `S611` | `django-raw-sql`             |
| `S608` | `hardcoded-sql-expression`   |

The 2026-08-17 audit measured bandit's inventory at 75 distinct IDs and the genuine
bandit-only set, for a Django project, at **three rules** — `B613` trojansource, `B614`
pytorch-load, `B615` huggingface-unsafe-download — two of which are machine-learning framework
checks. `B703` django-mark-safe is covered by ruff under a different number (`S308`).
**bandit's inventory was not re-verified in this session**; the 73 on the ruff side was.

**The one measured behavioural divergence is inside tests.** bandit's `B105` flags
`"password": "SecurePass@123"` inside dict literals — 7 hits, all in `conftest.py` and
`test_base.py`; ruff's `S105` flags none of them. Both agree on the single keyword-argument
case (`B106` / `S106`, in `accounts/tests/conftest.py`). Every one of those seven is a
documented fake fixture password, and both options suppress that area regardless — so the
divergence exists and buys nothing here.

Against that: bandit is a second tool, a second config, a second CI step and a second pin, and
it does not auto-discover `pyproject.toml` — it needs `-c pyproject.toml` **and** the
`bandit[toml]` extra, established by the 2026-08-15 verification and unchanged.

### The scope, and the repair it makes

The superseded plan excluded `config/` **and** all of `tests/`. The consequence was that its
entire security block never read `config/settings.py` — the module where this project's
security posture is actually decided. That was its worst structural gap, and keeping `config/`
in scope is what closes it.

The suppression follows D9a's principle unchanged — **suppress the rule, not the directory**:

```toml
[tool.ruff.lint]
extend-select = ["S"]

[tool.ruff.lint.per-file-ignores]
"*/tests/*" = ["S101", "S106"]
```

Neither suppressed rule is a concession. `S101` objects to `assert`, which pytest _requires_
as its assertion mechanism — 355 of them. `S106` fires on a fixture password that
`.claude/rules/testing.md` documents as deliberately fake. The two codes are exactly what was
measured; nothing was suppressed pre-emptively.

**Verified by execution, not by citation.** The shape above was run against a throwaway mirror
of this project's layout — an app with a `tests/` subdirectory, a `config/`, and a rule
violation in each:

```
accounts/models/base.py:2:5: S101 Use of `assert` detected          ← production, reported
config/settings.py:1:10:    S105 hardcoded password assigned        ← config in scope, reported
accounts/tests/test_x.py:   S101 and S106 both silent               ← suppression works
```

**One trap found while verifying it, recorded so it is not rediscovered.** `*/tests/*` requires
a directory before `tests/`. It matches `accounts/tests/…` and `profiles/tests/…`, which is
every test file this project has, and it does **not** match a top-level `tests/` directory —
confirmed by running the same config against a layout with the test tree at the root, where
neither rule was suppressed. If a test tree is ever added outside an app, this glob must be
revisited or it will fail silently in the safe direction (reporting, not hiding).

### Alternatives considered

- **`bandit` as a separate tool** — the reference implementation, and "we run bandit" is a
  legible line in a portfolio README. Set aside on the measured facts: identical production
  yield (0 versus 0), near-identical inventories (73 versus 75), all Django-specific checks
  present in ruff, and its only real exclusive findings here are in test fixtures that both
  options suppress. What it would add is `B613` plus two ML checks, at the cost of a second
  tool with a documented config-discovery problem.
- **Both tools** — union of coverage, at the price of two tools reporting the same 355 assert
  findings and two suppression lists that must not drift apart. Measured marginal yield on this
  codebase today: zero findings either tool does not already produce.
- **Neither; rely on D7's `check --deploy` and defer** — defensible on the measurement, since
  both tools score 0 in production and D7 already covers `config/settings.py`. Set aside: the
  value is in the code not yet written, and the chosen option costs no new dependency and no
  new CI step, so there is nothing to save by deferring.
- **`semgrep`** — named by the superseded plan as the only alternative it considered. Not
  re-evaluated here: its easier setup path depends on a cloud account, which is the same
  reproducibility cost that ruled out `safety`, and a local-only rule set would be more work
  than either option above for no measured gain.

### Open questions and verification debts carried to the task

- **Behavioural parity with bandit is not established, and this entry does not claim it.** The
  comparison is by rule _number_ on ruff's side plus one spot check (`B703` → `S308`). The
  `B105` / `S105` divergence measured above is proof that two rules can share a number and
  differ in what they detect. A rule-by-rule behavioural comparison was not performed and is
  real work; it is not a prerequisite for this decision, because the production yield of both
  tools is currently zero.
- **The suppression list is re-measured when it stops being true.** `S107`
  (`hardcoded-password-default`) surfaced in the verification mirror because that file defined
  a function with a password default. No test in this project does today, so it is not
  suppressed. If one is written, the finding is a signal to look, not a reason to widen the
  ignore list without measuring.
- The exact ruff version is pinned at implementation time per `conventions.md`; 0.16.3 is what
  was measured here.

---

## D13 — Secret scanning: `gitleaks` in CI with custom Django rules, and a widened `.gitignore`

**Decided:** 2026-08-17. Closes the D13 open item, audit Issue 7 of the 2026-08-15 pass, and Open
Decision 4 of `docs/audits/2026-08-17-audit-plan-toolchain-d10-d15.md`. **Corrects the premise of
Issue 3 of that audit**, which is measured below rather than argued.

`ci.yml` gains a `gitleaks` step. A `.gitleaks.toml` at the repository root extends the default
rule set with two rules for this project's own secret shapes, plus a path allowlist. **No hook** —
this entry is deliberately independent of D14. Separately, the root `.gitignore` replaces its two
exact `.env` entries with `.env*` and an exception for `.env.example`.

### The baseline, re-measured before deciding anything

```
$ gh api repos/thaisdMM/skillbridge --jq '{private,security_and_analysis}'
private: false
secret_scanning:                        enabled
secret_scanning_push_protection:        enabled
secret_scanning_non_provider_patterns:  disabled
secret_scanning_validity_checks:        disabled
```

A scanner already runs on every push and already blocks. GitHub's documentation establishes that
non-provider patterns are _"available for organization-owned repositories on GitHub Team with
GitHub Secret Protection enabled"_ — this repository is personally owned, so that tier is not a
toggle the user can flip. The `disabled` above is a ceiling, not a setting.

_(The alerts endpoint returned HTTP 503 twice this session, so the audit's measurement of zero
open alerts was **not** re-confirmed here.)_

### The hook contract, read verbatim from upstream

`gitleaks/gitleaks` → `.pre-commit-hooks.yaml`, fetched through the GitHub API this session:

```yaml
- id: gitleaks
  entry: gitleaks git --pre-commit --redact --staged --verbose
  language: golang
  pass_filenames: false
- id: gitleaks-docker
  entry: zricethezav/gitleaks git --pre-commit --redact --staged --verbose
  language: docker_image
  pass_filenames: false
- id: gitleaks-system
  entry: gitleaks git --pre-commit --redact --staged --verbose
  language: system
```

Three facts follow, and the second is what removed the hook from this decision:

1. **`pass_filenames: false` is confirmed** on the two primary hooks. A `files:` key can decide
   _whether the hook runs_, never _what it reads_ — exactly as the open item recorded.
2. **No variant is free.** `golang` makes the runner build gitleaks from source with a Go
   toolchain; `docker_image` requires Docker running at commit time; `system` requires the binary
   already installed. There is no cheap way to host this in a hook.
3. **`gitleaks-system` omits `pass_filenames: false`**, so it would receive staged filenames
   appended to a command that already carries `--staged`. It is the variant not to choose.

### What decided it: the default rule set misses this project's own secret

Measured 2026-08-17 with `zricethezav/gitleaks:v8.30.1` in Docker, against **fake** secrets
written to a scratch directory outside the repository. Twenty Django-shaped `SECRET_KEY` samples
across four shapes — with and without the `django-insecure-` prefix, with Django's own punctuated
charset and with an alphanumeric one, in `.py` assignment form and in `.env` form:

| Secret class                                                        | GitHub push protection | gitleaks, default rules         | gitleaks + custom rule    |
| ------------------------------------------------------------------- | ---------------------- | ------------------------------- | ------------------------- |
| Provider tokens (GitHub PAT, Stripe, AWS access key)                | **blocks**             | catches                         | catches                   |
| High-entropy generic secret (random DB password, connection string) | no                     | **catches** (`generic-api-key`) | catches                   |
| **Django `SECRET_KEY`**                                             | no                     | **0 of 20**                     | **10 of 10**              |
| Low-entropy human-chosen password                                   | no                     | misses                          | catches, by variable name |

**This is the correction to Issue 3.** That finding framed the gap as _"a Django `SECRET_KEY`, a
`DB_PASSWORD`, or the contents of `.env` are exactly the non-provider class… that is the gap D13
should be sized against"_, and treated gitleaks as the thing that closes it. Measured, the default
rule set does not close it for the `SECRET_KEY`. The question was never _"gitleaks or nothing?"_
— it is **"what has to be written for it to catch anything that matters here?"**, and the answer
is roughly twelve lines.

_Labelled as reasoning, not measurement:_ the mechanism behind the miss was **not** isolated.
Prefix and charset were tested independently and both shapes were missed, so no single explanation
survives. What is established is the rate, and it reproduced across every shape tried.

### The configuration this decision rests on

```toml
[extend]
useDefault = true

[[rules]]
id = "django-secret-key"
regex = '''(?i)secret_key[a-z0-9_]*\s*[:=]\s*["']?([^"'\s]{20,})["']?'''
keywords = ["secret_key"]
```

A second rule of the same shape covers `db_password` / `database_password` / `postgres_password`.
Both are starting points written during planning, not reviewed regexes — see the open questions.

### The full history is clean, and that sub-decision is now closed rather than planned

`gitleaks git` over all **261 commits**, which is the mode CI and the hook use — as opposed to
`dir`, which reads the working tree including files `.gitignore` excludes:

| Rule set                       | Findings across the whole history |
| ------------------------------ | --------------------------------- |
| gitleaks default               | **0**                             |
| default + the two custom rules | **7, none of them a leak**        |

All seven, itemised: two in `.github/workflows/ci.yml` (the postgres service password, hardcoded
by design and not a secret), three in `.env.example` files (deliberate placeholders, committed on
purpose), one in `django_version/docker-compose.yml` (`${DB_PASSWORD}` — a variable reference, a
plain false positive), and one inside a `docs/audits/` file that discusses a password.

**No real secret has ever been committed to this repository.** The one-time history scan the audit
proposed as a sub-decision was performed while deciding this entry; it does not become a task.

### The feared false-positive load does not exist

The audit and this plan both expected the project's password-shaped fixtures to be the cost of
adopting a scanner — 355 `assert` statements and seven literal fixture passwords. Measured:
**zero findings anywhere under `accounts/tests/` or `profiles/tests/`**, with the default rules and
with the custom ones. No `tests/` allowlist entry is needed. The allowlist covers four paths, all
of them configuration or documentation.

### The cheapest part of this decision is not a tool

Measured with `git check-ignore`:

| Path                                                                  | Ignored today |
| --------------------------------------------------------------------- | ------------- |
| `.env`, `.env.local`, `django_version/.env`                           | yes           |
| `.env.prod`, `.env.production`, `.env.ci`, `django_version/.env.prod` | **no**        |

The ignore list protects two exact names, not the family. Replacing them with `.env*` plus
`!.env.example` closes the most likely leak vector outright, costs one line, and is independent of
every option below — it would be worth doing even under option A.

### Alternatives considered

- **Rely on push protection alone, with the `.gitignore` widened** — already running, server-side,
  unskippable, and the history is provably clean. Set aside on the measured gap: a `SECRET_KEY`
  pasted into a `.py` or a Markdown file is seen by nothing, and the `.gitignore` cannot help
  there because the file is one the project legitimately tracks.
- **gitleaks with the default rule set only** — set aside as dominated: it measures 0 on the one
  secret class this project actually holds, so it would add a CI step and a pin in exchange for
  coverage the platform layer already provides.
- **gitleaks in a hook as well as CI** — the only option that prevents the secret from reaching a
  public repository at all, and the audit's preference conditional on D14. Set aside on fact 2 of
  the hook contract above: every variant costs a Go build, a Docker daemon at commit time, or a
  pre-installed binary, and D14 has not chosen a runner. Coupling the two entries would repeat the
  reasoning D5 rejected — planning around a shape that does not exist yet. **Recorded as the
  upgrade to revisit if D14 selects a runner that can host gitleaks cheaply.**
- **`trufflehog`** — its distinguishing feature is verifying candidates against the issuing
  provider, which pays off precisely on the provider class GitHub already blocks here for free. It
  would carry the same blind spot for the Django key, and whether it accepts an equivalent custom
  rule was not measured. It also introduces outbound network calls from a workflow this plan is
  hardening.
- **`detect-secrets`** — last release 2024-05-06. Not a live option.

### Open questions and verification debts carried to the task

- **The two custom rules are unreviewed.** They fire on any line assigning 20+ characters to a
  name containing `secret_key`. On this repository that produced 8 working-tree findings, every one
  explainable; on a larger codebase they may be noisier. The Developer treats them as a starting
  point and tunes against a real run, not against this entry.
- **The `--pre-commit --staged` mode was not tested**, only `dir` and `git`. That custom rules
  apply identically there is expected and unverified — it matters only if the hook upgrade above is
  ever taken.
- **The allowlist should be scoped by rule and path, not globally.** Allowlisting all of
  `ci.yml` is broader than the finding requires; the Developer narrows it to the rule that fires.
- **Why the default rule set misses the Django key was not established.** If upstream changes it,
  the custom rules become redundant, which costs nothing.
- The exact gitleaks version is pinned at implementation time per `conventions.md`; v8.30.1
  (released 2026-03-21) is what was measured here.

---

## D14 — Hook runner: `pre-commit` with local hooks, running `ruff` and nothing else

**Decided:** 2026-08-17. Closes the D14 open item and Open Decision 5 of
`docs/audits/2026-08-17-audit-plan-toolchain-d10-d15.md`. Also closes two conditionals other
entries left open — D13's gitleaks-hook upgrade and D5's `required-version` — both of them
negative. **This entry departs from the audit's stated preference**; see _Where this diverges
from the audit_.

A `.pre-commit-config.yaml` at the **repository root** declares two hooks, both `repo: local`,
both invoking the project's own tools through `uv run --project django_version`: `ruff format`
and `ruff check --fix`. Nothing else runs at commit time. `mypy`, Django's two checks, the test
suite, coverage and `gitleaks` stay in CI, where D6–D13 put them.

### Why this decision is smaller than the plan expected it to be

Two entries handed D14 a problem. D2 recorded that pre-commit has no per-hook working directory
— an acknowledged upstream limitation, issues #466, #1417, #2317, #2951 — and called the choice
of runner "a real choice" on that ground. D9 added a second input: run from the monorepo root,
ruff reads the closed `oop_version/` tree, 49 findings, and hierarchical configuration configures
a subdirectory without excluding another.

Both facts are true. **Neither reaches this project's realistic hook set**, and that is what
decides this entry.

1. **The set worth running at commit time is two tools**, and both are ruff. Everything else is
   excluded by a constraint another decision already established, not by preference — see the
   table below.
2. **Ruff's configuration half was settled by D9, by execution.** With `pyproject.toml` in
   `django_version/`, ruff resolves `src` relative to the config file, so an invocation from the
   parent directory produces the same answer as one from inside. What D9 left open was _scope_,
   not configuration.
3. **A hook receives staged files, not a directory.** `oop_version/` is closed, so no commit
   stages a file there, and a hook that lints the staged paths never reaches it — whatever the
   runner. The 49 findings are a property of `ruff check .`, not of a hook.
   _(Reasoning from documented behaviour, not measured; recorded as a verification debt below.)_

The working-directory defect — the reason D14 existed as a decision at all — is therefore paid
by no option. What remains is a smaller question: is the convenience worth a recurring
dependency, and which runner costs least to keep.

### What runs at commit time, and why nothing else does

| Check                                      | Where           | What excludes it from the hook                                                                                |
| ------------------------------------------ | --------------- | ------------------------------------------------------------------------------------------------------------- |
| `ruff format`                              | hook **and** CI | —                                                                                                             |
| `ruff check --fix`                         | hook **and** CI | —                                                                                                             |
| `mypy`                                     | CI only         | D10: needs the entire production dependency set, and its answer is a whole-project answer, not a per-file one |
| `pytest`, coverage                         | CI only         | needs the postgres service; D11's own measurement runs the suite in ~10 s                                     |
| `makemigrations --check`, `check --deploy` | CI only         | D7, and after D16 `check` accesses the database                                                               |
| `gitleaks`                                 | CI only         | D13, fact 2 of the hook contract — see _Consequences_                                                         |

The two that remain are the two whose failure is trivial to fix at the moment it is reported and
irritating to receive as a red CI run minutes later. That is the whole value being bought here.

### The flag that shapes the configuration, read from uv's CLI reference this session

D2's amendment established `uv run --directory django_version <tool>` as the mechanism that puts
a hook inside the project. uv documents two flags, and they are not interchangeable:

- `--directory` — _"Change to the given directory prior to running the command. Relative paths
  are resolved with the given directory as the base."_
- `--project` — _"Discover a project in the given directory. … Other command-line arguments (such
  as relative paths) will be resolved relative to the current working directory. See
  `--directory` to change the working directory entirely."_

pre-commit executes hooks from the repository root and appends staged filenames relative to it.
With `--directory`, the working directory moves into `django_version/` and those paths stop
resolving — a hook that passes filenames breaks. With `--project`, the project environment is
found and the paths still resolve.

**So `--project` is the flag for a hook that passes filenames, and `--directory` remains correct
for a whole-project invocation that passes none.** D2's amendment is not wrong; it is the right
flag for the case it was written about (`mypy`, whole project, `pass_filenames: false`).

One further property, from uv's project documentation: _"When using `run`, uv will ensure that
the project environment is up-to-date before running the given command."_ A hook can therefore
never execute a ruff other than the one `uv.lock` pins — which is what removes pre-commit's
second cost, below.

### The shape

```yaml
repos:
  - repo: local
    hooks:
      - id: ruff-format
        name: ruff format
        entry: uv run --project django_version ruff format
        language: unsupported
        types_or: [python, pyi]
        files: ^django_version/

      - id: ruff-check
        name: ruff check
        entry: uv run --project django_version ruff check --fix
        language: unsupported
        types_or: [python, pyi]
        files: ^django_version/
```

Two details the Developer must not copy from an older tutorial:

- **`language: unsupported`, not `language: system`.** pre-commit's supported-languages
  reference, read this session: _"new in 4.4.0: previously `language: system`. the alias will be
  removed in a future version"_. The equivalent rename applies to `script` → `unsupported_script`.
  Write the spelling current for the version pinned.
- **`files: ^django_version/` decides whether the hook runs, and narrows what it receives.** It
  is the key doing the job D9's `oop_version` input asked for, and it is the same distinction
  D13 recorded about gitleaks: `files:` governs the file list a hook is given, which is exactly
  what is wanted here because these hooks _do_ accept filenames.

### Why `pre-commit` rather than `lefthook` or `prek`

The distinguishing feature of each alternative addresses the defect established above as not
being paid.

**`prek` 0.4.14** — its workspace mode is documented as _"Hooks run within their project's root
directory"_ and _"Only files within the project's directory tree are passed to its hooks"_, with
`files`/`exclude` _"matched against the file path relative to the project root — i.e. the
directory containing the configuration file"_. That is genuinely the cleanest answer to the
working-directory problem, and it uses `uv` internally, which fits D1. It is set aside because
the property it is chosen for is not needed here, and its cost is not nothing: a 0.4.x release
line on a repository whose purpose is to be read by someone else.

**`lefthook` v2.1.10** — **two corrections to the audit, both from documentation read this
session.** The audit recorded that `root:` is _"listed in the command-level reference, but its
behaviour is not documented on the page I read"_. It is documented, on its own page: `root`
_"change the CWD for the command you execute"_; _"For `pre-push` and `pre-commit` hooks and for
the custom `files` command `root` option is used to filter file paths"_; and _"Globs are always
calculated from the actual root of the git repo — `root` does not affect glob matching."_ The
audit also treated it as a Go binary outside the Python ecosystem; it is published on PyPI at
2.1.10, the same version as its GitHub release, so installability is not a cost. What remains
true is the audit's real objection: lefthook does not run tools itself, so every command is a
shell line written and maintained by hand.

**What makes `pre-commit`'s own recorded costs evaporate here.** The audit's two objections were
the working-directory limitation and _"the versions in `.pre-commit-config.yaml` and in
`uv.lock` are two sources of truth"_. The second is a property of using upstream hook
repositories, which carry a `rev:`. With every hook declared `repo: local` and executed through
`uv run`, there is no `rev:` anywhere and `uv.lock` is the only pin — the same guarantee D1 was
adopted for.

**And the exit is cheap.** `prek` consumes the same `.pre-commit-config.yaml`, so choosing
pre-commit does not foreclose it; if `prek` reaches a stable series, the migration is installing
a different binary.

### Where this diverges from the audit

The audit recommended _"D, or C"_ — no runner, or `prek`. This entry takes `pre-commit`.

The agreement is complete on the part that matters most: a hook layer is convenience, not
control. Hooks are skippable with `--no-verify`, so CI has to run everything regardless, and this
plan has already made CI comprehensive.

The disagreement is narrow. The audit chose `prek` _for_ its workspace mode — _"the only option
that removes the working-directory defect at the source instead of routing around it"_. That
defect is not paid by this project's hook set, so the property is bought and unused, while its
cost lands on the axis the audit itself named: _"`pre-commit` on a CV means something; `prek`
means nothing yet."_

### The costs accepted

1. **The runner is a user-level installation, not a project dependency.** The git hook script
   invokes the binary by name, so a runner living only inside `django_version/.venv` would not be
   on `PATH` when git runs the hook. It is installed with `uv tool install` or an equivalent, and
   it is one more thing to keep current. **This is true of all three runners and is not a
   discriminator** — it is recorded so the Developer does not add `pre-commit` to the `dev` group
   and expect the hook to work.
2. **Every commit performs an implicit environment sync.** That is the property, not a defect —
   it is what guarantees the hook's ruff is the lockfile's ruff — but it means commit latency is
   not zero, and a commit made while `uv.lock` is out of date will update the environment.
3. **A green commit is not a verified commit.** `--no-verify` skips the hooks entirely, and the
   hooks cover two of the eight checks CI runs. Nothing in this entry changes where the control
   lives.
4. **A rename in flight.** `language: system` is an alias slated for removal; the config carries
   a name that has to be correct for the pinned version.

### Hooks run on the host, and root `CLAUDE.md` Rule 12 says commands run in Docker

Rule 12 states that all project commands run via `docker-compose exec web`. A git hook cannot
honour that: it fires on the developer's machine at a moment when the container may not be
running, and delegating to `docker compose exec -T web` would make every commit depend on a
running container — the same objection that removed gitleaks' `docker_image` variant from D13.

D2's amendment already assumed a host-side `uv run` hook entry; this entry makes the exception
explicit rather than implicit. **Whether Rule 12 gains a sentence recognising git hooks as its
one exception is a one-line documentation question and is left to the user**, not folded into a
task here.

### Alternatives considered

- **`prek` 0.4.14 in workspace mode, config at `django_version/.pre-commit-config.yaml`** — see
  above. Recorded as the option to revisit if `prek` reaches a stable series, since the config
  format is identical and the migration is a binary swap.
- **`lefthook` v2.1.10 with `root: django_version/`** — see above; set aside because it solves a
  problem not paid here and, unlike the other two, requires every check to be written as a shell
  line.
- **No hook runner; CI is the gate** — the audit's first preference, and genuinely defensible:
  zero recurring maintenance, and for a single-committer repository the drift a hook prevents is
  drift CI reports minutes later. Set aside on the one thing CI cannot give back: `ruff format`
  is a fix applied at the moment of writing, and as a CI failure it is a round trip for a
  reformatting that the tool performs automatically.
- **`pre-commit` with upstream hook repositories** (`repo: https://github.com/astral-sh/ruff-pre-commit`
  with a `rev:`) — the conventional shape, and it needs no `uv` on the host. Set aside: it is the
  configuration that creates the two-sources-of-truth cost the audit charged against pre-commit,
  and nothing compares the `rev:` with `uv.lock`.
- **Adding `mypy` to the hook set** — technically available: `uv run --directory django_version
mypy` with `pass_filenames: false` satisfies D10's constraint. Set aside on commit latency
  against value: the 2026-08-17 audit measured a full run at ≈7 s including download, and mypy's
  answer is a whole-project answer that CI already produces on every push. Recorded as a cheap
  addition if the CI round trip on type errors proves annoying in practice.

### Consequences for other entries

- **D13's conditional closes negative.** D13 recorded the gitleaks hook as _"the upgrade to
  revisit if D14 selects a runner that can host gitleaks cheaply"_. `pre-commit` does not: the
  upstream contract's three variants require a Go build, a Docker daemon at commit time, or a
  pre-installed binary, and that is a property of the hook definition rather than of the runner —
  no runner choice would have changed it. D13 stands as written, CI-only.
- **D5's `required-version` stays declined.** D5 recorded it as the cheap defence _"if D14
  selects a hook runner that invokes tools from outside the project environment"_. It does not:
  `uv run --project` executes inside it, and syncs first.
- **D10's constraint is satisfied by not being exercised.** D10 required that a mypy hook invoke
  the tool inside the project environment; no mypy hook exists. If one is added later, the
  invocation is `uv run --directory django_version mypy` with `pass_filenames: false`.
- **D9's `oop_version` input is answered**, by `files: ^django_version/` plus staged-file passing
  rather than by any ruff configuration. D9's own conclusion — that its configuration half is
  settled — is unchanged.
- **D2's mechanism is refined, not replaced.** `--directory` and `--project` are both correct,
  for different hook shapes; the distinction is recorded above so it is not rediscovered.

### Open questions and verification debts carried to the task

- **Nothing in this entry was executed.** Every fact above is documentation read this session,
  and the two inferences are labelled where they appear. The `uv` on this machine predates the
  version this project will pin, and running the runners disposably through it was declined, so
  no hook was ever installed or fired. **The Developer's first act is to run both hooks once.**
- **The acceptance criterion must test something that can fail**, following the shape Issue 4 of
  the 2026-08-17 audit forced on D15: with a Python file under `django_version/` staged carrying
  a deliberate formatting error and a deliberate lint error, `git commit` fails and names the
  hook; with a file staged under `oop_version/` alone, neither hook runs. The second half is what
  verifies the reasoning in point 3 above, and it is the one that would expose it as wrong.
- **The current spelling of `language: system`** is read from pre-commit's supported-languages
  reference for the version pinned, not copied from this entry.
- **Whether `ruff format` reformats a file the commit did not touch** is prevented by construction
  here — the hooks receive staged paths — but the Developer confirms it rather than assuming it,
  since it is the behaviour that makes a formatting hook either pleasant or infuriating.
- The exact `pre-commit` version is pinned at implementation time per `conventions.md`; 4.6.2 is
  what the 2026-08-17 audit read.

---

## D15 — A non-root user in the `Dockerfile`, with an acceptance criterion that can actually fail

**Decided:** 2026-08-17. Closes the D15 open item and Open Decision 6 of
`docs/audits/2026-08-17-audit-plan-toolchain-d10-d15.md`. **Corrects the replacement acceptance
criterion that audit's Issue 4 proposed** — measured below, it is tautological on this machine
for the same reason as the criterion it was written to replace.

The `Dockerfile` creates a non-root user, gives it ownership of `/opt/venv` (D3), and switches to
it with `USER`. The `python:*-slim` base ships no non-root user — measured by the 2026-08-17
audit, `uid=0(root)` on Debian 13.6 — so this is a real addition, not the activation of something
already present.

### What was measured, and it settles both halves of this entry

Run 2026-08-17 with `docker run --rm --user <uid>:<gid>` against the real `django_version/` bind
mount, using the base image already in the local cache. Nothing was built, no project file was
modified, and the probe file each run created was removed inside the same run (verified:
`no probe files left`).

| `--user` requested | How the mount presents `manage.py` inside the container | File / directory / subdirectory write |
| ------------------ | ------------------------------------------------------- | ------------------------------------- |
| `0:0`              | `uid=0 gid=0`                                           | OK                                    |
| `1000:1000`        | `uid=1000 gid=1000`                                     | OK                                    |
| `1234:1234`        | `uid=1234 gid=1234`                                     | OK                                    |
| `4242:4242`        | `uid=4242 gid=4242`                                     | OK                                    |

Host-side the same file is `uid=501 gid=20`, before and after.

**Docker Desktop's VirtioFS presents every file in the bind mount as owned by whichever UID is
accessing it.** There is no mapping: a UID that exists nowhere on the host (4242) is presented
and permitted exactly like any other.

Two conclusions follow, and they point in opposite directions.

1. **The risk that could have defeated this decision does not exist on this machine.** A non-root
   user cannot break the bind-mount workflow here — a migration written by `makemigrations`,
   pytest creating `.pytest_cache/`, a tool cache — all succeed under any UID. Had the probe come
   back `DENIED`, the option taken would have been _stay root_.
2. **The acceptance criterion the audit proposed cannot fail here either.** See below.

### The criterion, and why the audit's replacement had to be replaced in turn

Issue 4 was right about the inherited criterion: _"bind-mounted files stay usable from the host"_
cannot fail on this machine, because Docker Desktop _"will succeed, but `stat` will not be
affected"_ on `chown`. It proposed testing instead _"the container able to write `__pycache__`,
`.pytest_cache` and migration files into the bind mount"_. Measured, **that passes for every
possible UID**, including a nonsensical one — the same defect one level deeper. Replacing a
criterion that always passes with another criterion that always passes would leave this entry
certifying nothing while appearing rigorous.

**A second, smaller correction, read from the file rather than measured.** `__pycache__` should
not appear in any criterion at all: `django_version/Dockerfile` sets
`ENV PYTHONDONTWRITEBYTECODE=1`, which applies to `docker-compose exec` as well, so the container
does not write `__pycache__` today — with or without a non-root user. The container's real write
surface inside the mount is `.pytest_cache/`, generated migration files, the tool caches D9–D11
introduce, and the `pyproject.toml` / `uv.lock` half of a `docker-compose exec web uv add`.

**The criterion this entry adopts, split by what can and cannot fail:**

| Half                                                                           | Status                                                                                                   | How it is checked                                                                                                                                                                   |
| ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/opt/venv` readable and executable by the new user, and writable by `uv sync` | **Real — fails loudly when wrong**, because it is inside the image, where Linux permissions are enforced | the image build fails, or `docker-compose exec web pytest` cannot find its interpreter                                                                                              |
| Anything the container writes into the bind mount                              | **Unverifiable on this machine**, measured above                                                         | recorded as `docs/tech_debt/010-non-root-user-bind-mount-behaviour-is-unverifiable-on-macos.md`, naming where it _would_ be verified: a Linux host, or the Phase 5 production image |

Naming the second half unverifiable is the point of this entry, not an omission from it.

**And the verifiable half has an automated gate for free.** D6's amendment 2 adds a `docker build`
step to CI. A `chown` in the wrong place, or a `uv sync` running after `USER` without write access
to `/opt/venv`, fails that step — so this decision is guarded on every push rather than by the
Developer remembering.

### What this buys, stated honestly

Not security today. `Dockerfile:31` is `runserver`, and D4 already established that this is a
development image, bind-mounted, on localhost. What it buys is the habit established before
Phase 5 — when a production image makes it load-bearing — and a `USER` line in a `Dockerfile`
that exists to be read.

### The ordering constraint the Developer owns

`uv sync` must be able to write `/opt/venv`. Either it runs as root before `USER`, with the
`chown` after it, or the directory is created and chowned first and synced afterwards. Which
form is written against uv's documented Docker pattern at implementation time — D3 already
carries that open question. What this entry adds is that the choice now has an ownership
constraint attached, and that CI's build step is what catches getting it wrong.

Related, and easy to get wrong in the other direction: files placed by `COPY . .` are owned by
root. Under the compose workflow the bind mount covers `/app` at runtime, so this is invisible
day to day; `COPY --chown=` is the documented mechanism if the image is ever run without the
mount, which is Phase 5's problem rather than this task's.

### Alternatives considered

- **Stay root; decide it with the production image in Phase 5** — defensible on D4's own logic,
  and it was the option the measurement was run to test. Set aside: the plan already opens the
  `Dockerfile` three times (the `pillow` cleanup, the uv migration, D16's base bump), the
  addition is small, and the one way it could have gone wrong on this machine was measured and
  does not occur.
- **Non-root _and_ reopening D3's system-environment option on the ownership ground** — D3's
  amendment explicitly invites this. Set aside: D3's real discriminator is `uv sync` pruning
  `pip`/`setuptools` from the base image, which ownership does not touch, and reopening on
  ownership would also require measuring the pruning claim D3 labelled as reasoning. Nothing
  measured here makes the ownership handling awkward enough to justify it.
- **"Non-root only in the production image"** — the previous option under a different name. The
  production image does not exist and is outside this plan's scope boundary.

### Open questions carried to the task

- **The `chown` friction is not measured.** No image with a non-root user was built in this
  session, so whether it is one line or one line plus a surprise is unknown. The CI build step
  exposes it on the first push.
- **The UID value is unconstrained by anything measured here.** Every UID behaves identically on
  this machine, so the choice matters only on a Linux host, where matching the developer's own
  UID is the conventional reason to pick 1000. The superseded plan's 1000 is carried over on that
  ground and nothing stronger.
- **The measured VirtioFS behaviour is a property of Docker Desktop, not of the image.** The
  probe ran against `python:3.14.6-slim`; D16 moves the base to a newer patch, which does not
  affect it.

---

## D16 — Stack update: Django 6.1, Python 3.14.7, pytest-django 4.14.0, applied in a second commit

**Decided:** 2026-08-17. Closes Open Decision I of
`docs/audits/2026-08-16-audit-plan-toolchain-d2-d9a.md`.

Numbered 16 because D10–D15 are already reserved in _Planning state_ for the still-open
topics. This entry is a version decision, not one of those.

The stack moves to the current releases as part of this migration:

| Component      | Was    | Becomes    |
| -------------- | ------ | ---------- |
| Django         | 6.0.7  | **6.1**    |
| Python (image) | 3.14.6 | **3.14.7** |
| pytest-django  | 4.12.0 | **4.14.0** |

`.claude/rules/conventions.md` → _Stack and versions_ makes a version change an architectural
decision requiring explicit approval rather than a maintenance update. This entry is that
approval, recorded as a decision instead of happening as a side effect of the uv migration.

### It lands in two commits, not one

1. **Commit 1** — the uv migration at today's pins. `pyproject.toml`, `uv.lock`, `Dockerfile`
   and `ci.yml` change; no version moves. The suite must be green before the next commit.
2. **Commit 2** — the version bump, and only the version bump. `pyproject.toml` and `uv lock`.

This is what settles the objection that a tooling migration and a framework upgrade landing
together make a red CI ambiguous. The separation is bought with commit ordering, not with
calendar time: the two commits belong to the same working session, and the second follows the
first as soon as the suite is green. A deferral measured in days would be D-I2 wearing D-I3's
name.

### Why the upgrade rather than staying on 6.0

**Every backwards-incompatible item in the 6.1 release notes was checked against this
codebase, by searching the code rather than by reading the list.** Measured 2026-08-17 over
`accounts/`, `profiles/`, `config/` and `manage.py`:

| 6.1 change                                                                      | Present in this codebase                                                                                    | Consequence |
| ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ----------- |
| Admin `wide` class removed                                                      | No — only `"collapse"` is used, in `accounts/admin.py`                                                      | none        |
| `select_related()` with no arguments deprecated                                 | Not used anywhere                                                                                           | none        |
| `values_list(flat=True)` with no field name deprecated                          | Used only _with_ a field name, in `FreelancerProfile.get_display_info` and `ClientProfile.get_display_info` | none        |
| `first()` / `last()` ordering change                                            | Neither method is used                                                                                      | none        |
| `ModelAdmin.list_select_related` deprecation                                    | Not used                                                                                                    | none        |
| Overriding `ModelAdmin.get_actions()` deprecated                                | Not overridden; the admin classes only set `actions = [...]`                                                | none        |
| `EMAIL_*` settings deprecated in favour of `MAILERS`                            | `config/settings.py` declares no `EMAIL_*` setting at all                                                   | none        |
| New `security.W027` (CSP nonce without context processor)                       | `MIDDLEWARE` contains no `ContentSecurityPolicyMiddleware`                                                  | never fires |
| PostgreSQL 14 support dropped; 6.1 requires 15+                                 | `docker-compose.yml` runs `postgres:17.10`                                                                  | none        |
| PBKDF2 default iterations 1,200,000 → 1,500,000                                 | `Argon2PasswordHasher` is primary; PBKDF2 is the legacy fallback with no stored hashes                      | none        |
| Signed-cookie salt derivation; `SIGNED_COOKIE_LEGACY_SALT_FALLBACK` now `False` | No deployed environment, no live signed cookie                                                              | none        |

Two items that read as threatening in the notes and are not:

- **`ForeignKey.on_delete` gained `DB_CASCADE` / `DB_SET_NULL` / `DB_SET_DEFAULT`.** These are
  additions. `PROTECT` is unchanged, so `conventions.md`'s `on_delete=PROTECT` rule is
  untouched and is not reopened by this entry.
- **`delete_confirmation_max_display`** governs truncation on admin delete-confirmation pages
  and inline protected-deletion errors — the exact path `SkillAdmin.get_deleted_objects()`
  feeds. Its default is `None`, meaning no truncation, which is today's behavior. It changes
  nothing unless deliberately set.

**The second reason was a dependency this project has not yet installed — and it does not
survive checking.** ~~`django-stubs` 6.1.0 lists Django 6.1 under full support and Django 6.0
under partial support; 6.0.8 is the last release with full 6.0 support. Staying on 6.0.7 forces
D10 to choose between an older stubs release and partial support.~~

**Withdrawn 2026-08-17** (Issue 1 of `docs/audits/2026-08-17-audit-plan-toolchain-d10-d15.md`,
re-verified against the upstream compatibility matrix while deciding D10). **`django-stubs`
6.0.9 exists and lists Django 6.0 under _full_ support**, with the same mypy range (1.13 – 2.3)
and the same Python range as 6.1.0. Staying on Django 6.0 would have forced no compromise on
D10 at all. The claim was false when written.

**The outcome is unaffected, and the reason is worth stating rather than assuming.** The
support-lifecycle argument above carries this entry on its own: Django 6.0 mainstream support
ended 2026-08-04 and 6.1 runs to April 2027. This entry keeps its decision and loses one of its
two arguments — the same shape as D3's amendment, which kept its outcome after the
documentation claim behind it turned out to be backwards.

### The residual risks, and where each is settled

None of these blocks the upgrade; each is a verification the Developer performs.

1. **`mail.E001` is a deployment-only ERROR-level check, new in 6.1.** D7 makes
   `check --deploy` blocking at ERROR precisely so the step has teeth, so an ERROR firing on
   day one turns CI red. The check guards against a non-production email backend in the
   `default` `MAILERS` entry, and this project defines no `MAILERS`, so it is not expected to
   fire — **but this was not measured**, because measuring it requires Django 6.1 installed.
   **`check --deploy` must be run under 6.1 and its output recorded before the step is made
   build-failing.** This is the one open verification this entry creates.
2. **`check` now supplies all databases when none is specified**, so the command should be
   expected to access the database. D7's recorded reasoning that its two steps are
   database-independent stays true for `makemigrations --check` and stops being true for
   `check --deploy`. CI has the `postgres` service, so the step works; the _reasoning_ in D7 is
   amended by this entry, not the step.
3. **D7's measured baseline moves.** "7 warnings, exit 0" was measured on 6.0.7. It is
   re-measured under 6.1 as part of commit 2. `security.W027` is ruled out above; the rest of
   the delta is unknown until measured.
4. **The admin change-form layout changed** — fields below labels, help text before the input,
   validation errors between them. The suite has 272 tests, some of which run a real request
   cycle and read `response.content` (the profile-section tests under
   `accounts/tests/admin/`). Those assert that an error _string_ appears in the response, which
   is layout-independent, so the expected impact is nil. Running the suite settles it in
   seconds, and commit ordering makes any failure attributable.

### Alternatives considered

- **Freeze at today's pins and migrate to uv only** — one variable in the migration diff.
  Set aside: it pins 6.0.7 knowing 6.0.8 exists, keeps the project on a series whose mainstream
  support ended 2026-08-04, and defers an upgrade that would then have to redo `uv.lock`
  anyway. The diagnostic benefit it buys is delivered instead by the two-commit sequence above.
- **Patch level only (Django 6.0.x), 6.1 as a later decision** — the recommendation this
  session opened with, and it was withdrawn on the evidence above. It leaves the project on a
  series in security-only support. ~~and forces D10 to choose between an older `django-stubs`
  and partial support~~ — that second ground was withdrawn on 2026-08-17; `django-stubs` 6.0.9
  supports Django 6.0 fully, so this alternative is set aside on the support lifecycle alone.
  Note also that the patch to compare against is **6.0.9**, not the 6.0.8 this entry originally
  named.
- **Move to the 5.2 LTS series** — the only LTS on offer, supported to 2028-04. Set aside: it
  is a downgrade from the code's current Django 6.0 baseline and contradicts the project's own
  positioning on a current stack. No technical need for it exists here.

### Subtask — synchronise the documents that state a pinned version

Commit 2 carries a version number that several files repeat. **Which files are rewritten is
not a judgement call left to the Developer** — the three categories below were established by
searching the repository on 2026-08-17, and the boundary between them is the point of this
subtask.

**Category A — live statements of the pinned stack. Rewritten by commit 2.**

| File                                                  | What it states today                                                      | Note                                                                                  |
| ----------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `django_version/Dockerfile`                           | `FROM python:3.14.6-slim`                                                 | must agree with the project's Python pin                                              |
| `.github/workflows/ci.yml`                            | `python-version: "3.14.6"` on the `setup-python` step                     | superseded by the D6 amendment, which replaces the literal with `python-version-file` |
| `.claude/rules/conventions.md` → _Stack and versions_ | the whole table — Django `6.0.7`, `pytest-django 4.12.0`, `pillow 12.3.0` | also names `requirements.txt` as where versions are pinned, which stops being true    |
| `README.md`                                           | "Django 6.0.7 + PostgreSQL 17"                                            | the only version literal in the README                                                |

`django_version/requirements.txt` is not listed because D1 removes it.

**Category B — statements about the _series_, which 6.0 → 6.1 does not invalidate. Left
alone.** Root `CLAUDE.md` and `django_version/CLAUDE.md` both say "Python 3.14, Django 6.x,
PostgreSQL 17"; `ARCHITECTURE.md` refers to "PostgreSQL 17" and "Python 3.14". All remain
true. `docker-compose.yml`'s `postgres:17.10` is unaffected — Django 6.1 drops PostgreSQL 14
and requires 15 or higher.

**Category C — historical records. Must not be rewritten, and the Developer is instructed
not to.** `specs/001-profiles-admin-panel/` states "verified against Django 6.0.7" in roughly
ten places. That is a record of what a past verification was run against, not a claim about
the current pin; rewriting it to 6.1 would assert a verification that never happened. The same
applies to the dated entries in `docs/ROADMAP_SKILLBRIDGE.md` and
`docs/ROADMAP_STACK_TRIAGE.md`, to every file in `docs/audits/`, and to
`docs/plan/plan_ci-quality-security_2026-08-14.md` — which this plan already keeps unchanged
for exactly this reason.

**Acceptance for the subtask:** after commit 2, no Category A file states a superseded
version; no Category C file was modified; and the Python patch in the `Dockerfile` base image
agrees with the project's Python pin.

### Open questions carried to the task

- The exact Django 6.1 patch release, the exact `pytest-django` release, and the exact Python
  patch are fixed at implementation time per `conventions.md`, not copied from this table.
- Whether `pillow` is removed before or during commit 1 — the removal is already listed under
  _Items that need no decision_, and it touches the same `conventions.md` table this subtask
  rewrites.

---

## D17 — The test suite runs the migrations, with the seeded vocabulary emptied by a session fixture

**Decided:** 2026-08-17. Closes the first of the three `pytest.ini` observations D7 flagged and
deliberately left to the user, and the _Open questions for the user_ entry asking whether those
observations become a decision of their own.

Numbered 17 because D13–D15 stay reserved for the still-open topics.

`--no-migrations` is removed from the `addopts` array in `[tool.pytest]` (D2's amendment). A new
`django_version/conftest.py` overrides pytest-django's `django_db_setup` fixture to empty the
`Skill` table once per session, immediately after the test database is built.
`.claude/rules/testing.md` is rewritten in the same change. **No test file is touched.**

### What the flag was actually buying, measured rather than assumed

`--no-migrations` is documented by pytest-django as _"disable Django migrations and create the
database by inspecting all models"_. The reason usually given for it is speed. Measured on this
codebase, 2026-08-17, both runs rebuilding the database from scratch:

| Invocation                                                                 | Result     | Wall time |
| -------------------------------------------------------------------------- | ---------- | --------- |
| `pytest --create-db` (schema built from the models)                        | 304 passed | 10.35 s   |
| `pytest --create-db --migrations` (schema built by replaying the 14 files) | 304 passed | 10.19 s   |

The difference is inside the noise. **Speed was never what the flag was buying here.** What it was
buying is an empty `Skill` table: `profiles/migrations/0002_seed_skills.py` is a data migration
that inserts **30 rows**, and with migrations disabled it never runs.

Turned on without any other change, the suite reports **21 failed, 260 passed, 23 errors**. Every
one of the 44 touches `Skill`, and every failure is the same collision:

```
django.db.utils.IntegrityError: duplicate key value violates unique constraint "skills_name_key"
DETAIL:  Key (name)=(Python) already exists.
```

Nothing else moved. **260 tests passed against a schema built entirely by the migrations**, with
no `column … does not exist` and no `relation … does not exist` anywhere — which is the measured
evidence that the 14 migrations apply cleanly today and that the schema they produce agrees with
the models. The 23 ERRORs rather than FAILUREs are collisions inside fixtures, before the test
body runs.

### What this catches that nothing else in the project does

Eight tests in this repository carry a name asserting that the **database** refuses something:

```
test_skill_name_uniqueness_enforced_at_database_level
test_skill_case_insensitive_name_uniqueness_enforced_at_database_level
test_freelancer_profile_user_uniqueness_enforced_at_database_level
test_client_profile_user_uniqueness_enforced_at_database_level
test_freelancer_profile_hourly_rate_accepts_null_at_database_level
test_client_profile_max_budget_accepts_null_at_database_level
```

plus the two expecting `IntegrityError` from a direct `.update()` — the `CheckConstraint`s
`freelancer_no_inactive_available` and `staffuser_active_no_staff_status`.

Those constraints were installed by migrations: `accounts/migrations/0006_…` and
`profiles/migrations/0007_skill_skill_unique_name_case_insensitive.py`. Under `--no-migrations`
the database those tests run against is built from `Meta.constraints`, so what they verify is the
model _declaration_. They do not verify that the migration installed anything.

The failure mode that follows is silent in every direction: a migration hand-edited so a
constraint disappears from it leaves the model still declaring it, the test still green, and the
production database — which is built by replaying migrations — without the constraint. Neither
the suite (it builds from the models), nor D7's `makemigrations --check` (it compares models to
migration _files_ and never executes one), nor CI catches that today.

_(Aside: `makemigrations --check` and this decision guard different things. The first asks "does a
model change lack its migration file?". This one asks "does the file, when run, produce the
database the models describe?")_

### The shape, verified by execution

```python
# django_version/conftest.py
@pytest.fixture(scope="session")
def django_db_setup(django_db_setup, django_db_blocker):
    from profiles.models.skill import Skill

    with django_db_blocker.unblock():
        Skill.objects.all().delete()
```

This is pytest-django's documented pattern for touching the test database once it exists:
_"Notice `django_db_setup` in the argument list. This triggers the original pytest-django fixture
to create the test database"_, and _"`django_db_blocker` is the object which can allow specific
code paths to have access to the database"_. The deletion happens at session setup, outside the
per-test transaction, so it is not rolled back and each test still starts from an empty table.

Run 2026-08-17 with the fixture placed outside the project tree so no project file was written:
the fixture reported `(30, {'profiles.Skill': 30})` and the suite returned **304 passed** with
`--migrations` enabled.

**It must be a `conftest.py`, not a plugin, and this was established the hard way.** The same
fixture loaded with `pytest -p <module>` **never ran** — the skill count stayed at 30 and all 44
failures persisted. Command-line plugins are registered before `pytest-django`, which then
redefines `django_db_setup` over the top; conftest fixtures take precedence over plugin fixtures,
which is why the documented placement is the working one. The Developer must not "simplify" this
into a plugin.

Two details the Developer owns: the file sits at the **root of `django_version/`**, not inside an
app's `tests/`, because `accounts` tests collide too; and the model import is **inside** the
function, which is the form that was verified — a module-level import in `conftest.py` was not
tested and risks `AppRegistryNotReady`. A Google-style docstring is required per
`conventions.md`.

### The costs accepted

1. **The fixture is a list that grows.** Any future data migration that inserts rows collides the
   same way and must be added here. The failure mode is a red suite whose cause sits in a file
   nobody thinks to open.
2. **The divergence from production becomes deliberate.** Tests already run against an empty
   `Skill` table, a state the deployed application never has; this decision does not remove that,
   it makes it explicit and puts it in one place. Removing it is the alternative rejected below.
3. **Seed _data_ correctness becomes unverifiable.** The fixture deletes the 30 rows before any
   test sees them, so what is validated is that `seed_skills` runs without raising, not that it
   produced the right vocabulary. Its reverse, `remove_skills`, still never executes. The escape
   hatch, if this ever matters, is a test importing `seed_skills` and calling it directly.
4. **`.claude/rules/testing.md` is rewritten in the same change**, not later. Its section _"Note
   on `--no-migrations` and data migrations"_ becomes false in full, its list of active `addopts`
   flags changes, and its _Common mistakes_ row about assuming data migrations have run inverts.
   It is auto-loaded into every session, so leaving it stale sends every future agent to the wrong
   conclusion — the same reasoning D2's amendment used for the `pytest.ini` path.

### What this does not fix

The stale-database trap belongs to `--reuse-db`, which is a separate flag and is **not** changed
here. pytest-django is explicit: _"`--reuse-db` will not pick up schema changes between test runs.
You must run the tests with `--reuse-db --create-db` to re-create the database according to the
new schema."_ ~~After a model change, `pytest --create-db` remains a manual step, and the error it
saves you from still arrives as a confusing `column … does not exist` rather than as a message
about a stale schema. That is the second of D7's three observations and stays open.~~

**Amended 2026-08-17 by D19.** `--reuse-db` is removed, so the trap described above is removed
with it and `pytest --create-db` stops being a manual step. This section's first sentence — that
the trap belongs to a separate flag not changed _here_ — remains accurate about D17 itself; what
is superseded is its conclusion that the trap stays. D17's outcome is untouched, and D19 records
the cost the removal accepts.

### Alternatives considered

- **Keep `--no-migrations`, and run with migrations manually from time to time** — zero change,
  zero maintenance, and it was the user's initial position. Set aside on the signal-to-noise
  argument this plan has already used twice (D7 against `continue-on-error`, D12 on `S101`): with
  44 known failures present on every such run, a 45th new one is buried, and the check depends on
  remembering to perform it. It works only while the number 44 is remembered accurately, which
  drifts as the suite grows.
- **Rewrite the 44 tests so they tolerate a seeded vocabulary** — the only option that removes the
  divergence rather than managing it, and it would leave the seed data verifiable. Set aside on
  cost: 44 tests across 6 files, against a benefit the 8-line fixture delivers in full for the
  migration-execution half. Recorded as the path to take if cost 1 or cost 3 above ever bites.
- **Disabling migrations for the `profiles` app alone via `MIGRATION_MODULES`** — not viable: it
  operates per application, not per migration file, so it would also drop the schema migrations
  that install `skill_unique_name_case_insensitive`, which is one of the constraints this decision
  exists to exercise.

### Consequences for other entries

- **D9a's stated reason is amended** — see the amendment appended to that entry. Its outcome is
  untouched.
- **D7's first flagged observation is resolved.** _"The D7 check covers the dangerous case (a model
  without its migration) but not a migration that is present and broken"_ — the second half is now
  covered on every run, locally and in CI.
- **D11 is unaffected.** `omit = ["*/migrations/*"]` was written to survive this decision: the
  second column of its regime table is the one that now applies, and migrations stay out of the
  coverage denominator so the reported figure does not move.
- **`.claude/rules/testing.md` is edited by two decisions.** D2's amendment rewrites its
  `pytest.ini` references; this entry rewrites its `--no-migrations` section. If they land in
  separate commits, the second must be written against the first's result, not against the file as
  it stands today.

### Open questions carried to the task

- **The measured timings are `--create-db` figures.** Whether an ordinary `--reuse-db` run is
  affected at all was not measured separately; on a reused database no migration is replayed under
  either setting, so the expectation is no difference. Stated as reasoning.
- The `django_db_setup` override was verified against pytest-django 4.12.0. D16 moves the pin to
  4.14.0, and the fixture is re-confirmed once on that version.

---

## D18 — Dependency auditing: Dependabot, with the CI gate deferred until `uv audit` leaves preview

**Decided:** 2026-08-17. Closes Open Decision 7 of
`docs/audits/2026-08-17-audit-plan-toolchain-d10-d15.md` — the `pip-audit` step this plan
inherited unexamined from the superseded plan — and **closes D8 Item 3's deferred `schedule:`
question as unnecessary rather than answering it.** Numbered 18 because D10–D15 were reserved
for the audit's own topics and 16–17 are taken.

Dependabot **alerts** and Dependabot **security updates** are enabled on the repository, and the
`.github/dependabot.yml` that D8 Item 2's amendment creates gains a second entry,
`package-ecosystem: "uv"`. **No dependency-audit step is added to `ci.yml`**, and no new package
enters the `dev` group. The deferral is recorded in `docs/tech_debt/` with the revisit trigger
below.

### The baseline, re-measured — and it is worse than the audit recorded

The audit reported `dependabot_security_updates: {"status": "disabled"}`. Measured 2026-08-17:

```
$ gh api repos/thaisdMM/skillbridge --jq '.security_and_analysis'
{"dependabot_security_updates":{"status":"disabled"}, …}

$ gh api repos/thaisdMM/skillbridge/dependabot/alerts
403 — "Dependabot alerts are disabled for this repository."

$ ls -a .github/
workflows
```

**The alerts are off, not merely the updates.** A security update is the pull request that
follows an alert; with alerts disabled there is no alert stream to follow, so nothing at all
currently watches this project's dependencies. This entry is therefore not about strengthening
dependency monitoring — it is the decision to have any.

### Dependabot supports `uv` natively, which the audit left as an open risk

Two official changelog entries settle it. Version updates: _"Dependabot version updates now
support uv in general availability"_ (2025-03-13), configured as `package-ecosystem: "uv"`.
Security alerts and updates: _"Dependabot now supports security alerts and updates for uv. When
vulnerabilities are detected in your uv dependencies, Dependabot can automatically open security
alerts and pull requests to update to secure versions."_ (2025-12-16).

That answers the audit's recorded reservation — _"Only covers what Dependabot parses; D8's
amendment creates `.github/dependabot.yml` for `github-actions` only, so the Python ecosystem
would need adding"_. The Python ecosystem is added as `uv`, reading this project's own
`pyproject.toml` and `uv.lock`, with none of the impedance mismatch of declaring it as `pip`.

**Verification debt, recorded because the reading was not clean.** GitHub's supported-ecosystems
_table_ could not be read directly — it returned truncated twice, and one of those readings
asserted that `uv` was absent from it. The claim above rests on the two changelog entries, which
are unambiguous. The Developer confirms the exact `package-ecosystem` value against that table
before writing the file. If `uv` should turn out to be unavailable, the fallback is **not**
`pip` — which would not parse `uv.lock` — but reopening this entry.

### `uv audit` is in preview, and that is what decided against it

The audit recommended _"use `uv audit` as the CI gate"_, on the ground that the command _"is
listed in uv's CLI reference with no preview or experimental marker"_. Astral's own announcement
of the feature says the opposite: _"Both of these features are in preview for now. They're
considered unstable and there may be breaking changes as we iterate on their design."_ The
command reads uv's locked resolution and queries OSV; support for `requirements.txt` and PEP
751's `pylock.toml` is described as planned, not present.

**What rules it out today is consistency inside this plan, not novelty aversion.** D10 rejected
`ty` — Astral's type checker — quoting its version policy, _"breaking changes, including changes
to diagnostics, may occur between any two versions"_, and calling it _"the D9 risk without D9's
stable-release floor"_. `uv audit` carries the identical property. Adopting it here while
rejecting `ty` there would apply two standards inside one plan, and a build-failing gate is the
worst place to accept a diagnostic surface that may move between versions.

### Why no CI gate at all, rather than `pip-audit`

What a gate adds over the alert stream is refusing a merge. What it costs is a red build caused
by an advisory published against code nobody touched, on a push about something else. With
alerts enabled, the same advisory arrives as a pull request carrying its own fix, without a
workflow run — so the marginal detection is small and the marginal failure mode is not.

`pip-audit` 2.10.1 stays the correct choice _if_ a gate is wanted before `uv audit` stabilises:
PyPA-maintained, stable, known interface. Its cost here is one more `dev` dependency and one
more pin, plus a translation step — it does not read `uv.lock`, so it audits either the
environment already synced by `uv sync --locked` (invoked through `uv run`) or a `uv export`ed
requirements file. _Both forms are expected to work; neither was executed._

### What this closes elsewhere, and it is the most useful part of the entry

**D8 Item 3's deferred `schedule:` trigger is closed as unnecessary.** D8 deferred it because
_"`pip-audit` on `push` only detects a newly published advisory at the next push"_, with a
measured 47-day gap between runs on this repository, and stated that _"the question returns when
the `pip-audit` task is drafted"_. It has now been drafted and the answer is that the beneficiary
is not being added: Dependabot's alerts arrive without any workflow run, which removes the
latency the schedule existed to cover. D8's own carried-forward fact reinforces it — in a public
repository, _"scheduled workflows are automatically disabled when no repository activity has
occurred in 60 days"_, a limit the alert stream does not have.

### An action no task can own

Enabling the two toggles is a repository setting, not a file. It belongs to the same class as
`allowed_actions` and `sha_pinning_required` under D8's _Recorded but not planned — settings that
live outside the repository_: not versionable, not visible in a diff, not restored by a clone.
The `dependabot.yml` entry is a file and belongs to a task; the toggles are the user's action,
and the task's acceptance criterion is the API reporting them enabled.

### The revisit trigger

**When `uv audit` leaves preview**, it becomes a gate costing no new dependency and no new pin —
`uv` is already in the image (D4) and on the runner (D6) — reading `uv.lock` directly. That is
the moment to reopen this entry. Until then, a gate means `pip-audit`.

### Alternatives considered

- **Dependabot plus `uv audit` in CI** — the audit's recommendation; set aside on the preview
  status and the D10 consistency argument above.
- **Dependabot plus `pip-audit` in CI** — set aside on cost against marginal detection. It is
  also legitimate for a reason that no measurement of this repository can capture: a CI step
  naming a recognised security tool is legible in a portfolio in a way a repository setting is
  not. If it is ever chosen for that reason, the entry should say so plainly rather than argue it
  on coverage — the same instruction D12 carries about bandit.
- **Nothing at all** — set aside on the measurement. With alerts disabled, the status quo is not
  "adequate monitoring, gate deferred"; it is no monitoring.

### Open questions and verification debts carried to the task

- **The two halves of Dependabot are configured in different places, and only one is a file.**
  The security half follows from the repository toggles; the `uv` entry in `.github/dependabot.yml`
  governs routine **version** updates on a schedule. _Stated as reasoning — GitHub's page
  distinguishing the two was not read this session._ The Developer confirms it, because it
  decides whether the file entry is required for the security coverage this entry is being taken
  for, or is an addition on top of it.
- ~~**Whether routine version-update pull requests are wanted at all**~~ **Decided 2026-08-17:
  yes, at `interval: monthly`**, matching the shape D8's amendment reached for on the
  `github-actions` ecosystem. The reason is a rule specific to this project rather than a general
  preference: `.claude/rules/conventions.md` → _Stack and versions_ makes a version change an
  architectural decision requiring explicit approval, not a maintenance update. A Dependabot pull
  request is exactly that shape — it changes nothing on its own and arrives as a proposal to
  approve or close — so the rule gains a mechanism instead of depending on someone remembering to
  look. D16 is the concrete cost of not looking: a Django series whose mainstream support had
  already ended. Dropping the version half while keeping the security half stays available if the
  pull requests prove noisy.
- **Nothing in this entry was executed beyond the two `gh api` reads above.** `uv audit` has never
  run on this machine — the installed `uv` predates the subcommand — so its exit code, severity
  filtering and ignore mechanism are unknown, and the revisit above is the point at which they
  get measured.

### Amendment, 2026-08-19 — security updates are turned off, alerts stay on, and the version half carries the load, scoped to `/django_version`

D18 enabled both halves of Dependabot and assumed `dependabot.yml` could aim them. Implementing
T15 proved it cannot. **The goal does not change and the outcome does**: this project keeps
dependency monitoring, and stops paying for it in `oop_version/` pull requests and red runs.

**What T15 produced, measured 2026-08-19.** Four security-update pull requests, opened
2026-08-18 against `main`: `#6` (Pygments), `#8` (pytest) and `#9` (python-dotenv) against
`oop_version/requirements.txt`, and `#7` (sqlparse) against `django_version/requirements.txt`.
All four are **still open**, each with a failing `test` check. The three `oop_version` alerts
were dismissed as `not_used` on 2026-08-19 — **dismissing an alert did not close its pull
request**, which is the fact that turns this from housekeeping into a decision.

**Why the file D18 planned cannot fix it.** Read this session in GitHub's _Dependabot options
reference_:

- `ignore` carries the version-updates icon only, so an `/oop_version` entry with
  `dependency-name: "*"` suppresses nothing on the security side.
- `open-pull-requests-limit: 0` is documented as disabling **version** updates.
- `directory` / `directories` govern where version updates look; for security updates the
  reference says only that the directory _"must be the path to the manifest files"_ for the
  configuration to apply to them.

The measurement settles it more directly than the reading does: there is no `dependabot.yml` in
this repository at all, so version updates were never enabled, and all four pull requests
arrived anyway. Security updates follow the repository toggle and the dependency graph, not the
file.

~~**The one lever that filters by directory is not available here.** Custom auto-triage rules can
target _"Manifest path (for repository-level rules only)"_, but the same documentation gates
custom rules behind GitHub Code Security on organization-owned repositories, or GitHub Team with
a licence. The user has neither.~~

**This paragraph is false, and the error was the Planner's.** GitHub's _About Dependabot
auto-triage rules_ reads _"Custom auto-triage rules for Dependabot alerts are available on public
repositories and on any organization-owned repositories in GitHub Team with GitHub Code Security
enabled"_ — the gate applies to private and internal repositories, and this one is public. The
sentence above was written from a summary of that page rather than from the sentence itself. See
the Developer note below, and the second amendment that acts on it. **The rest of this amendment
stands**: `dependabot.yml` still cannot filter security updates, and the configuration it decided
is still what is in force.

**Decided.** Dependabot **security updates are disabled** at the repository toggle. Dependabot
**alerts stay enabled**. `.github/dependabot.yml` declares `package-ecosystem: "uv"` at
`directory: "/django_version"` and `package-ecosystem: "github-actions"`, both at
`interval: monthly`. `oop_version/` is declared nowhere.

**What this costs, stated plainly.** Detection does not move: an advisory against a
`django_version` dependency still raises an alert immediately. What moves is the automatic fix —
it arrives with the monthly version-update run instead of within hours. Against this
repository's measured cadence (D8 Item 3: a 47-day gap between runs), that latency sits inside
the noise. What it buys is that a directory root `CLAUDE.md` declares closed can never again
produce a pull request or an Actions run, permanently, without editing anything inside it.

**The residual, accepted rather than hidden.** Alerts are not filterable by directory either, so
a future advisory against an `oop_version` package still appears in the Security tab. An alert
creates no branch, no pull request and no workflow run — it costs one dismissal and never
reaches the Actions history, which is where the visible cost was.

**The `uv` verification debt closes, in D18's favour.** GitHub's _Dependabot options reference_
lists **UV** among the accepted `package-ecosystem` values. D18 rested on two changelog entries
because the supported-ecosystems table would not read cleanly; a normative page now confirms it,
and T15's carried instruction — _"if `uv` is unavailable, the fallback is reopening D18"_ — does
not fire.

**And D18's other open question is answered by the same evidence.** It asked whether the security
half follows from the toggles alone or requires the file entry. Measured: the toggles alone. The
file entry governs version updates only.

**Alternatives considered**

- **Keep security updates on and dismiss each `oop_version` alert as it arrives** — the status
  quo since 2026-08-18. Set aside on measurement: dismissal leaves the pull request open, so the
  manual cost is two actions per advisory, recurring indefinitely, against a closed directory.
- ~~**A custom auto-triage rule on manifest path** — the only lever that filters exactly the right
  thing while keeping security fixes immediate for `django_version`. Set aside: licence-gated,
  and this is a free personal public repository.~~ **Set aside on a false premise; adopted by the
  second amendment below.**
- **Remove `oop_version/requirements.txt` so it leaves the dependency graph** — effective, and
  it needs no repository setting. Set aside: it edits a closed directory to change the behaviour
  of a service, and it destroys the record of what that version was pinned to.
- **Turn Dependabot off entirely** — set aside on D18's original measurement, unchanged: without
  it nothing watches this project's dependencies, and the three high-severity `sqlparse` alerts
  against the active project were found by it rather than by review.

#### Developer note, 2026-08-19 — the licence gate does not apply to this repository, and the manifest-path rule is available

**Written by the Developer, not the Planner.** It records a measurement that contradicts a
premise stated above. The decision it bears on stays open and belongs to a Planner session.

T18 instructed the Developer to stop and report if the Dependabot rules screen offered a custom
rule with a manifest-path condition. **It does.** Observed on _Dependabot rules → New rule_: a
rule-name field, a state control, an _Add rule metadata_ filter list carrying `severity`,
`package`, `ecosystem`, `scope`, **`manifest`**, `cwe`, `cve_id`, `ghsa_id`, `epss`, `malware`
and `classification`, and two rule actions — _Dismiss alerts_ and _Open a pull request to resolve
alerts_. The `manifest` filter's autocomplete offered `django_version/requirements.txt`.

**The premise this contradicts.** The amendment above states that custom rules are gated behind
GitHub Code Security on organization-owned repositories or GitHub Team with a licence, and that
_"the user has neither"_. GitHub's _About Dependabot auto-triage rules_ states that custom rules
are available _"on public repositories and on any organization-owned repositories in GitHub Team
with GitHub Code Security enabled"_. The gate applies to private and internal repositories. This
repository is public, so the option the amendment set aside is available at no cost.

**Three further facts, read from GitHub's documentation this session and not measured by
execution:**

- The manifest-path filter is documented as _"for repository-level rules only"_, which is the
  screen described above.
- For an _open a pull request_ rule to take effect, _"you must ensure that Dependabot security
  updates are disabled"_ — the state the repository is already in.
- Rules _"apply to both future and current alerts"_.

**What the Developer did not do, and why.** The rule was not created. The `manifest` value on
offer is computed from the dependency graph of the default branch, where
`django_version/requirements.txt` still exists; this branch deletes it in favour of
`pyproject.toml` and `uv.lock`. A rule written against the current value would match nothing
after the merge, and would fail silently rather than report. Whether the filter accepts a path
prefix or a wildcard is documented on neither page read.

**Carried to the Planner, unresolved here.** Whether to adopt the rule, and in which shape. The
reading taken this session is that the two mechanisms are orthogonal — the rule governs
alert-to-pull-request behaviour, `dependabot.yml` governs version updates — so the file T9 writes
is unaffected either way; what the amendment above would stop paying is the monthly latency it
accepted as the price. The earliest moment the rule can be written correctly is the first merge
to `main` that removes `django_version/requirements.txt`, and the check that the moment has
arrived is the `manifest` autocomplete offering `django_version/uv.lock` instead.

### Amendment 2, 2026-08-19 — both auto-triage rules are adopted, after the merge

**Decided:** two custom repository rules, filtered on `manifest`. One opens pull requests for
`django_version` alerts; one dismisses `oop_version` alerts. `dependabot.yml` does not change, and
Dependabot security updates stay **off** — the pull-request rule requires that state.

This buys back both costs amendment 1 accepted: the monthly latency on the active project, and the
recurring manual dismissal on the closed one. It costs two objects that live in a settings panel
and appear in no diff, which is why **T19 records their exact definitions in
`docs/tech_debt/011`** rather than trusting the panel to be self-documenting.

**Written as a task, not as reasoning.** The shape of each rule, the order they are created in,
what to observe, and what returns to the Planner are all in T19. Nothing about this amendment is
left for the Developer to work out.

**Alternatives considered**

- **The pull-request rule alone** — restores immediacy, leaves `oop_version` alerts needing manual
  dismissal. Set aside: it is the cheaper half of the same mechanism, and the manual cost is the
  one that recurs.
- **The dismiss rule alone** — silences the closed directory, leaves the active project's fixes on
  the monthly cycle. Set aside for the same reason in reverse.
- **Neither, as amendment 1 decided** — set aside now that the premise that forced it is corrected.

---

## D19 — `--reuse-db` is removed: every run builds the test database

**Decided:** 2026-08-17. Closes the second of the three `pytest.ini` observations D7 flagged.

`--reuse-db` is dropped from the `addopts` array in `[tool.pytest]` (D2's amendment). pytest-django
returns to its default: the test database is created at the start of a session and destroyed at
the end. `pytest --create-db` stops being a step anyone has to remember.

### The problem it removes

`--reuse-db` keeps the test database between runs. Combined with a model change, the reused
database keeps the previous schema, and the failure surfaces as `column … does not exist` — an
error that describes a symptom and names neither the cause nor the cure. pytest-django is explicit
that _"`--reuse-db` will not pick up schema changes between test runs"_ and that `--create-db` is
the override.

This project is more exposed to it than most: `django_version/CLAUDE.md` Rule 10 requires explicit
approval before a migration is generated, so "model edited, migration deferred" is an ordinary
state here rather than an unusual one — the same reasoning D7 used when it made
`makemigrations --check` a CI step.

### What decided it, and it was the user's call against the Planner's recommendation

The Planner recommended the cheaper form: keep the flag and add one line to
`.claude/rules/testing.md` naming the symptom and the cure, on the ground that the file is already
being rewritten by D2 and D17 so the marginal cost is zero. **The user chose removal**, with the
reason recorded here in their own terms: the database is not heavy today, and if the suite ever
becomes slow enough for the reuse to be worth its trap, the flag comes back.

That reasoning is sound on the evidence available, and the evidence has a hole worth naming.

### The number that exists, and the number that does not

D17 measured two full rebuilds of the test database, both at 304 tests:

| Invocation                        | Result     | Wall time |
| --------------------------------- | ---------- | --------- |
| `pytest --create-db`              | 304 passed | 10.35 s   |
| `pytest --create-db --migrations` | 304 passed | 10.19 s   |

**So the cost of the regime this decision adopts is known: roughly 10 s**, and D17 established that
replaying the 14 migrations is inside the noise, which matters because D17 also turned migrations
on — without it, a no-reuse run would have to be re-measured.

**What was never measured is a warm `--reuse-db` run** — that is, what the reuse was actually
saving. D17 recorded this as an open question in exactly these terms, and it stays open. The
decision is therefore taken knowing the price and not the discount. Given a 10 s suite, the
discount cannot be large in absolute terms, but that is reasoning, not measurement.

### The revisit trigger

The flag returns if the suite becomes slow enough that per-run database creation is felt. Its
return costs one line in `addopts`, and the trap it reintroduces is documented in
`.claude/rules/testing.md` by this same change.

### Alternatives considered

- **Keep `--reuse-db`, document the symptom and the cure in `testing.md`** — the Planner's
  recommendation, at zero marginal cost since that file is rewritten by D2 and D17 regardless. Set
  aside by the user: it keeps a trap and manages it with a document, and the speed it buys is not
  needed at this size.
- **Keep `--reuse-db` and add `--create-db` to CI only** — CI already starts from an empty
  database each run, so it would change nothing there and leave the local trap untouched.
- **Leave the observation open**, as D7 did. Set aside: it has now been raised twice and costs one
  character to settle.

### Consequences for other entries

- **D17's _What this does not fix_ section is amended.** It states that the stale-database trap
  _"belongs to `--reuse-db`, which is a separate flag and is **not** changed here"_, and that
  `pytest --create-db` _"remains a manual step"_. Both sentences are superseded by this entry.
  D17's outcome is untouched.
- **`.claude/rules/testing.md` is now edited by three decisions**, not two. Its list of active
  flags loses `--reuse-db` here, loses `--no-migrations` under D17, and its `pytest.ini` references
  are rewritten under D2. If they land in separate commits, each must be written against the
  previous one's result.

---

## D20 — The unused `slow` and `integration` markers are dropped

**Decided:** 2026-08-17. Closes the third and last of the three `pytest.ini` observations D7
flagged. With it, D7's flagged list is fully worked through.

The `markers` entry moving into `[tool.pytest]` under D2's amendment carries neither `slow` nor
`integration`. Both are declared today and used by no test — D7 measured it, by grep over
`accounts/`, `profiles/` and `config/`.

### Why dropping rather than keeping

The migration D2 already forces is what decides the timing: the configuration is being rewritten
from INI to TOML, where `markers` becomes an array. Carrying two dead entries across that rewrite
is the moment to not do it.

`--strict-markers` is what makes this safe, and it is already in `addopts`. Under it, a test
decorated with an undeclared marker **fails** with a message naming the marker and telling the
author to register it. So the day a test genuinely needs `integration`, the suite says so
immediately; reintroducing the declaration is one array element.

The cost of keeping them is not neutral: a declared marker is a statement that the suite has a slow
tier and an external-service tier. It has neither. `.claude/rules/testing.md` is auto-loaded into
every session, so the claim is read by every future agent as if it were true.

### Alternatives considered

- **Keep both, expecting `jobs` and DRF to use them** — plausible: an `integration` tier is a
  reasonable thing for a DRF project to grow. Set aside on `--strict-markers`: the declaration is
  not what makes the marker available later, it is one line written at the moment it is first
  needed, by whoever needs it.
- **Keep `integration`, drop `slow`** — a half-measure with the same objection, and it would need a
  reason to prefer one dead declaration over the other. There is none.

---

## D21 — CI generates its `SECRET_KEY` per run instead of reading it from a secret

**Decided:** 2026-08-19. Closes the first of the three facts T9 recorded on 2026-08-19, and is
the precondition for D18's amendment being worth anything.

`ci.yml` stops taking `SECRET_KEY` from `secrets.SECRET_KEY` and generates a random value inside
the job, before any Django command runs.

### The problem, measured rather than reasoned

From run `32122772733`, the run of Dependabot pull request `#7`:

```
Secret source: Dependabot
  SECRET_KEY:
raise ValueError("SECRET_KEY not found in environment variables")
##[error]Process completed with exit code 1
```

All four Dependabot runs failed identically. `config/settings.py` reads `SECRET_KEY` from the
environment and raises when it is absent, and GitHub's Dependabot-on-Actions troubleshooting
reference gives the cause: _"When a Dependabot event triggers a workflow, the only secrets
available to the workflow are Dependabot secrets. GitHub Actions secrets are not available."_
The same page applies it to `push`, `pull_request`, `pull_request_review` and
`pull_request_review_comment` alike, so D8 Item 3's `pull_request` trigger does not change it.
Measured: `gh api repos/…/dependabot/secrets` → `{"total_count": 0}`.

**This is not an `oop_version` problem.** It fires on any Dependabot-triggered run, including the
monthly `uv` version-update pull request that D18's amendment now makes the only automatic fix
path. A check that is red for a reason unrelated to the diff cannot gate a dependency bump.

### Why generating it, rather than registering a Dependabot secret

- **The value protects nothing.** The CI `SECRET_KEY` signs sessions against a throwaway Postgres
  service whose credentials are already literal in the workflow — the `services.postgres.env`
  block and the job `env` block both carry them in the file. Treating one of the two as a secret
  and the other as public is ceremony, not a boundary.
- **It lands in a diff.** A Dependabot secret is a settings-panel value that no clone restores
  and no review sees — the class this plan already records twice as a durability problem (D8's
  _Recorded but not planned_, and T15). This replanning session exists because a settings-panel
  action produced consequences no file described.
- **It removes a duplicate that can drift.** Under the secret option the same value exists as an
  Actions secret and as a Dependabot secret, and rotating one silently leaves the other stale.

### The cost accepted, and it lands on D7

D7 measured `check --deploy` producing 7 warnings and recorded that whether **W009**
(`SECRET_KEY`) fires in CI _"depends on the value behind `secrets.SECRET_KEY`, which cannot be
read from here"_. Under this decision it becomes knowable, and it probably stops firing: a
generated value carries no `django-insecure-` prefix and clears Django's length and distinct-
character thresholds. **T10 records the baseline measured under the generated key**, rather than
inheriting D7's number.

_Second, smaller:_ the `SECRET_KEY` Actions secret becomes unused. Whether it is deleted is the
user's call and is not a task criterion — it is a repository setting, and nothing breaks either
way.

### Alternatives considered

- **Register `SECRET_KEY` as a Dependabot secret** — the fix T9 called minimal, and it needs no
  diff at all. Set aside on the three points above; the decisive one is that it answers an
  invisible-configuration failure with more invisible configuration.
- **A fallback expression, `${{ secrets.SECRET_KEY || '<literal>' }}`** — one line, and it keeps
  the real secret on ordinary runs. Set aside: the literal sits in the file anyway, so it pays
  D13's allowlist cost without avoiding the appearance of a committed secret, and if the real
  secret ever disappears by accident the workflow passes silently on the fallback instead of
  failing.
- **Skipping the job for the `dependabot[bot]` actor** — set aside for the reason T9 already
  gave: it removes the gate rather than repairing it.

### Open questions carried to the task

- The exact generation form is the Developer's, written against the runner's available tooling
  and GitHub's `$GITHUB_ENV` documentation. Two constraints on it: it must not print the value,
  and it must run before the first step that imports Django settings.

---

# Planning state

## Closed

D1–D6, the structural decisions: every one of them changed the shape of the others, and each is
recorded above with the evidence that decided it. D7 and D8 are closed on top of them and
reshape nothing. D9 and D9a close the ruff question — rule set and file scope — and reshape
nothing either.

D16 closes the stack-update question. It reshapes nothing structurally, but it moves D7's
measured baseline and adds one verification the Developer must perform before D7's
`check --deploy` step is made build-failing.

D17 closes the first of the three `pytest.ini` observations D7 flagged and left to the user: the
suite stops running with `--no-migrations`, and a session fixture empties the seeded skill
vocabulary so that no test has to change. It reshapes nothing, amends D9a's stated reason, and
adds a second rewrite of `.claude/rules/testing.md` that must be sequenced with D2's.

**The 2026-08-16 audit is fully worked through as of 2026-08-17** — all 5 Issues and all 9 Open
Decisions (A–I), each decided with the user and each amending its entry in place:

| Audit item                                                      | Decided                                                                                      | Landed in            |
| --------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | -------------------- |
| Open Decision I — stack update                                  | Django 6.1, Python 3.14.7, pytest-django 4.14.0, in a second commit                          | **D16** (new)        |
| Open Decision A / Issue 3 — how CI gets `uv` and Python         | `astral-sh/setup-uv` with `enable-cache`, keep `setup-python` but read `python-version-file` | D6, amendment 1      |
| Open Decision B / Issue 2 — whether and how CI builds the image | plain uncached `docker build`, added after the `Dockerfile` cleanup                          | D6, amendment 2      |
| Open Decision C / Issue 4 — action pinning                      | bump to current majors first, SHA-pin four actions, add `dependabot.yml`                     | D8 Item 2, amendment |
| Open Decision D — token permissions                             | `permissions: {}` at the workflow, `contents: read` on the job                               | D8 Item 1, amendment |
| Open Decision E — trigger shape and run volume                  | keep the triggers, add `concurrency` + `cancel-in-progress` and a `docs/**` path filter      | D8 Item 3, amendment |
| Open Decision F / Issue 5 — pytest's configuration home         | delete `pytest.ini`, move to `[tool.pytest]`                                                 | D2, amendment        |
| Open Decision G / Issue 1 — the container's environment         | outcome unchanged; the rejection of the system-prefix option re-argued                       | D3, amendment        |
| Open Decision H — how the tools are provisioned                 | the `dev` group; `uvx` and `required-version` both declined, with reasons                    | D5, amendment        |

The 2026-08-16 audit raised five Issues against the entries above. **All five are closed**, each
taken with the user as its own decision, and each amending the entry it corrects in place. In
every case the audit's finding held; in no case did the decision's _outcome_ change, which is
the point worth carrying forward — the defects were in evidence, cost models and omissions, not
in the destinations:

| Issue                                                                                         | Entry it corrects | Status                                              |
| --------------------------------------------------------------------------------------------- | ----------------- | --------------------------------------------------- |
| 1 — the system-prefix alternative was rejected on a documentation claim uv contradicts        | D3                | **closed 2026-08-17** — see D3's amendment          |
| 2 — the "no layer cache in CI" cost model is configurable, not fixed                          | D6                | **closed 2026-08-17** — see D6's amendment 2        |
| 3 — nothing states how `uv` reaches the CI runner, and dependency caching vanished with `pip` | D6                | **closed 2026-08-17** — see D6's amendment          |
| 4 — SHA-pinning `actions/checkout@v4` and `setup-python@v5` freezes stale majors              | D8 Item 2         | **closed 2026-08-17** — see the amendment to Item 2 |
| 5 — `pytest.ini` was never assigned a home once `pyproject.toml` lands                        | D2                | **closed 2026-08-17** — see D2's amendment          |

**The 2026-08-17 audit is being worked through, starting with the entry that constrains the
others.** `docs/audits/2026-08-17-audit-plan-toolchain-d10-d15.md` raised 5 Issues and 7 Open
Decisions against D10–D15 and the deferrals.

| Audit item                                                                              | Decided                                                                                                                                                                      | Landed in                                         |
| --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| Open Decision 1 — type checker and scope                                                | `mypy` + `django-stubs`, production code only, blocking in a second task                                                                                                     | **D10** (new)                                     |
| Issue 2 — D10's environment coupling described wrongly in both directions               | corrected against a measured run; carried to D14 as a constraint                                                                                                             | D10, _The environment coupling_                   |
| Issue 1 — D16 rejects Django 6.0 partly on a false `django-stubs` fact                  | argument withdrawn, outcome unchanged                                                                                                                                        | D16, _Why the upgrade rather than staying on 6.0_ |
| Open Decision 3 — static security analysis, tool and scope                              | ruff's `S` rules via `extend-select`, `S101`/`S106` suppressed under `*/tests/*`, `config/` kept in scope                                                                    | **D12** (new), plus an amendment to **D9**        |
| Open Decision 2 — coverage measurement and floor                                        | `pytest-cov` in `addopts`, `branch = true`, 95% floor blocking from the first run, one task                                                                                  | **D11** (new)                                     |
| Issue 5 — `[tool.coverage.*]` partly inert once `pytest-cov` is chosen                  | **does not hold.** Verified by execution: only `parallel` is overridden unconditionally, so D2's table moves whole                                                           | D11, _Issue 5 does not hold_                      |
| Open Decision 4 / Issue 3 — secret scanning, sized against the platform baseline        | `gitleaks` in CI with custom Django rules, no hook, plus a widened `.gitignore`; the history scan was performed rather than planned                                          | **D13** (new)                                     |
| Issue 3's premise — that gitleaks closes the non-provider gap                           | **corrected.** Measured: the default rule set misses a Django `SECRET_KEY` 20 times out of 20; a ~12-line custom rule catches 10 of 10                                       | D13, _What decided it_                            |
| Open Decision 5 — hook runner, and what it runs                                         | `pre-commit` with `repo: local` hooks through `uv run --project django_version`, running `ruff format` and `ruff check --fix` only                                           | **D14** (new)                                     |
| Open Decision 5, two claims about `lefthook`                                            | **corrected.** Its `root:` key _is_ documented on its own page, and it _is_ published on PyPI at the same version as its GitHub release                                      | D14, _Why `pre-commit` rather than_               |
| Open Decision 6 / Issue 4 — non-root user, and an acceptance criterion that cannot fail | non-root `USER` owning `/opt/venv`; the criterion split into the half that can fail and the half recorded as unverifiable here                                               | **D15** (new)                                     |
| Issue 4's replacement criterion                                                         | **also does not hold.** Measured: VirtioFS presents the mount as owned by whichever UID accesses it, so a bind-mount write test passes for every UID, 4242 included          | D15, _What was measured_                          |
| Open Decision 7 — dependency auditing                                                   | Dependabot alerts and security updates, `package-ecosystem: "uv"`, **no CI gate**; D8's `schedule:` question closed as unnecessary                                           | **D18** (new)                                     |
| Open Decision 7's premise — that `uv audit` carries no preview marker                   | **corrected.** Astral's own announcement: _"in preview … considered unstable and there may be breaking changes as we iterate"_ — the same ground D10 used to reject `ty`     | D18, _`uv audit` is in preview_                   |
| Open Decision 7's baseline                                                              | **worse than recorded.** Dependabot _alerts_ are disabled, not only security updates: the alerts endpoint returns 403 _"Dependabot alerts are disabled for this repository"_ | D18, _The baseline_                               |

D10 also settles two things listed elsewhere as open: the `migrations/` exclusion the original
open item asked for is **not** added, because migrations measure zero errors; and the
`.mypy_cache/` line under _Items that need no decision_ is confirmed as the right cache
directory now that the tool is chosen.

The test-scope half of D10 is deferred and recorded as
`docs/tech_debt/006-tests-excluded-from-type-checking-fixture-annotations-cannot-pass.md`,
which carries the full measurement, the three remedies, and the instruction not to resolve it
by weakening the fixture annotations.

~~Open inside the closed decisions: the scheduled-run question D8 hands to the `pip-audit` task.~~
**Closed 2026-08-17 by D18**, and closed as unnecessary rather than answered: no dependency-audit
step is added, and Dependabot's alerts arrive without a workflow run, which removes the latency
the schedule existed to cover.
D9 also leaves D14 one measured input — run from the monorepo root, ruff reads `oop_version/`,
and hierarchical configuration does not exclude a subdirectory — but that is a question about
invocation scope, not about ruff's configuration, which is settled.

**2026-08-19 — two entries reopened by implementation, not by an audit.** T15 was implemented on
2026-08-18, and what it produced falsified two things D18 had assumed. Both were re-decided with
the user and neither came from a review of the plan; they came from running it.

| What implementation showed                                                                                   | Decided                                                                                      | Landed in         |
| ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------- | ----------------- |
| `dependabot.yml` cannot keep security updates out of `oop_version/` — the file governs version updates only  | security updates off, alerts on, version updates monthly and scoped to `/django_version`     | **D18** amendment |
| No Dependabot-triggered run can read a repository secret, so every one of them failed on an empty `SECRET_KEY` | `ci.yml` generates the key per run instead of reading a secret                               | **D21** (new)     |

Neither reverses a decision on its own terms: D18 still holds that this project keeps dependency
monitoring, and D8 still holds that CI is hardened rather than loosened for the bot. What changed
is the mechanism, in both cases because the platform does not work the way the entry assumed.

## Open — decisions still to take, in the suggested order

**None remain. Every decision in this section was closed on 2026-08-17**, and with D18 the
2026-08-17 audit is fully worked through: all 5 Issues and all 7 Open Decisions. Three of its
conclusions were overturned by execution or by reading the source it cited — Issue 5 (D11),
Issue 3's premise (D13), Issue 4's replacement criterion (D15) — and two more of its factual
claims were corrected (`lefthook` under D14, `uv audit`'s preview status under D18). The list
below is kept struck through rather than deleted, so the order the decisions were taken in
remains readable.

What is left of this plan is not decisions: it is the **task entries**, the **Order of
execution** section, and the `docs/tech_debt/` entries recording the deferrals.

**Quality tooling**

- ~~**D10 — `mypy` scope and its environment coupling.**~~ **Closed 2026-08-17** — see the D10
  entry in the Decision log.
- ~~**D11 — Coverage floor.**~~ **Closed 2026-08-17** — see the D11 entry in the Decision log.
  Coverage was measured for the first time while deciding it: **97% on production code**, which
  removed the reason the threshold could not be fixed in planning.

**Security**

- ~~**D12 — Static security analysis: tool and scope.**~~ **Closed 2026-08-17** — see the D12
  entry in the Decision log, and the amendment it required to D9.
- ~~**D13 — Secret scanning.**~~ **Closed 2026-08-17** — see the D13 entry in the Decision log.
  The hook contract was read verbatim and confirmed the `pass_filenames: false` concern; the hook
  was then dropped from the decision on installation cost, leaving D13 independent of D14. The
  history scan and the fixture-noise question were both answered by measurement rather than
  deferred.

**Hooks**

- ~~**D14 — Which hook runner, and what it runs.**~~ **Closed 2026-08-17** — see the D14 entry in
  the Decision log. The working-directory defect that made this a decision turned out not to be
  paid by this project's realistic hook set, which reduced the entry to a maintenance-cost
  question. Two of the audit's factual claims about `lefthook` were corrected against its own
  documentation, and `uv`'s `--project` / `--directory` distinction refined D2's mechanism.

**Infrastructure**

- ~~**D15 — Non-root user in the `Dockerfile`.**~~ **Closed 2026-08-17** — see the D15 entry in
  the Decision log. The outcome matches the superseded plan's (a non-root user), but for a reason
  that had to be measured rather than inherited, and with a different acceptance criterion: the
  bind-mount half is recorded as unverifiable on this machine, and the `/opt/venv` half is
  guarded by the `docker build` step D6 adds to CI.

## Items that need no decision — they become tasks directly

- Remove `pillow==12.3.0` from the dependencies and `libjpeg-dev`/`zlib1g-dev` from the
  `Dockerfile`'s `apt-get` step. Confirmed unused: no `ImageField`, no `PIL` import anywhere.
  While that line is open, check whether `libpq-dev` is equally redundant given that
  `psycopg-binary` bundles its own libpq — the empirical check is to drop it, rebuild, and run
  the suite (audit Observation O1, explicitly left unverified by both the audit and the
  verification). **This task runs before the `docker build` step of D6's amendment 2**, which
  is measured against the cleaned image.
- Defer the `web` service `HEALTHCHECK` until a dedicated `/health/` endpoint exists, rather
  than pointing it at a business route. Revisit when DRF arrives in Phase 3. **Recorded as
  `docs/tech_debt/009-web-service-has-no-healthcheck.md`.**
- Add `.ruff_cache/` and `.mypy_cache/` to the root `.gitignore`, and to
  `django_version/.dockerignore` (audit Observation O4).
- **Un-ignore `.vscode/settings.json`** in the root `.gitignore` — `.vscode/` stays ignored, with
  an exception for that one file — and write into it the interpreter and test working directory
  D2 requires. **Decided 2026-08-17.** The reason is this repository's layout rather than a
  preference: it contains two Python projects, and `oop_version/` carries its own `.venv` and its
  own `requirements.txt`, so an editor opened at the root can resolve imports against the closed
  project. A versioned settings file prevents that and survives a fresh clone; documentation
  depends on being read before the editor is opened.
- **Remove the orphan `django_version-web:latest` image (254 MB). Decided 2026-08-17**, on
  D4's own instrumentation: that entry asks the Developer to record `docker image ls` before and
  after the migration and report both numbers, and an orphan whose name is one character from the
  real image is what makes someone report the wrong one.
- Rewrite `.claude/rules/conventions.md` → _Stack and versions_: its version numbers change
  under D16, and it names `django_version/requirements.txt` as where versions are pinned, which
  stops being true once `pyproject.toml` lands (2026-08-16 audit, Observation O4).
- ~~Record every deferral in this plan as a `docs/tech_debt/` entry, continuing the existing
  sequence (the last entry on disk is `005`).~~ **Done 2026-08-17**, and the reasoning that
  required it holds: a deferral recorded only inside a plan file is not durable once the plan
  stops being read.

  | Entry                                     | Deferral                                               | Decision                      |
  | ----------------------------------------- | ------------------------------------------------------ | ----------------------------- |
  | `006-tests-excluded-from-type-checking-…` | test code stays outside the type checker               | D10                           |
  | `007-single-dev-dependency-group-…`       | one `dev` group instead of named groups                | D5                            |
  | `008-no-dependency-audit-gate-in-ci`      | no build-failing audit until `uv audit` stabilises     | D18                           |
  | `009-web-service-has-no-healthcheck`      | no `HEALTHCHECK` until a `/health/` endpoint exists    | _Items that need no decision_ |
  | `010-non-root-user-bind-mount-…`          | the bind-mount half of D15 cannot be verified on macOS | D15                           |

  T17 remains open for anything a task turns up during implementation.

## Open questions for the user, carried forward

- Whether the `docker build` step added in D6 runs on every push or only on pushes to `main`.
  To be answered with the measured build duration in hand, not before (D6).
- ~~Whether `.vscode/settings.json` is versioned (D2).~~ **Answered 2026-08-17: it is** — see
  _Items that need no decision_.
- ~~Whether the orphan `django_version-web:latest` image is removed.~~ **Answered 2026-08-17: it
  is** — see _Items that need no decision_.
- ~~Whether the three `pytest.ini` observations flagged under D7 enter this plan as a decision of
  their own.~~ **Fully answered 2026-08-17.** All three became decisions: **D17** (migrations run
  in the suite), **D19** (`--reuse-db` removed), **D20** (the unused markers dropped). D7's
  flagged list is closed.
- Whether the `F821` findings flagged under D9 go to an Auditor session. Verified in the
  container that the annotations resolve correctly on Python 3.14.6, so nothing is broken; what
  is open is only how the two findings are silenced. Neither audit raised them.
- ~~Whether `ci.yml` gains a `schedule:` trigger.~~ **Answered 2026-08-17 by D18: it does not**,
  and the question is closed as unnecessary rather than deferred again. No dependency-audit step
  is added, so the schedule has no beneficiary, and Dependabot's alerts arrive without a workflow
  run at all.
- ~~**New, created by D18:** whether routine `uv` **version**-update pull requests are wanted, or
  only the security half.~~ **Answered 2026-08-19, and the answer inverted the expectation: the
  version half is kept and the security half is dropped.** The two are indeed configured in
  different places, and that is what decided it — the security half is a repository toggle that
  applies to every manifest in the dependency graph, `oop_version/` included, and no file can
  narrow it; the version half is declared per directory. See D18's amendment.
- **New, created by T1:** whether the now-empty `RUN apt-get install` step in
  `django_version/Dockerfile` is deleted outright. T1 removed `pillow`'s libraries and, on the
  empirical result, `libpq-dev` too — nothing is left for the step to install. Left in place
  rather than removed, because a task later in this plan may still need `apt-get` for a system
  package this plan did not foresee, and this plan never decided the step's fate. Revisit once
  every task is implemented (after T17); if still empty then, remove it.

## Verification debts — to be settled against official documentation, not training data

The superseded plan pinned five tools and specified configuration for four of them without a
single verification step of this kind. These must not be inherited:

- The exact `uv` version to pin, and uv's current documented Docker layering pattern for it.
- **Which file `actions/setup-python`'s `python-version-file` input accepts** — uv's guide
  names `.python-version` and `pyproject.toml`; the authority is that action's own
  documentation for the version pinned (D6 amendment).
- **`manage.py check --deploy` under Django 6.1** — whether the new ERROR-level `mail.E001`
  fires with no `MAILERS` defined, and what the new warning baseline is. D7 blocks at ERROR, so
  this must be measured before that step is made build-failing (D16).
- ~~Ruff's actual default rule selection for the version pinned.~~ **Settled under D9**, against
  ruff's _Default Rules_ page and the v0.16.0 release notes, and measured by running
  `ruff@0.16.3` on this codebase. Both audits' description of that default is stale: v0.16.0
  replaced it. The Developer re-reads the page for whatever version is finally pinned.
- ~~`django-stubs` support for Django 6.0.7 and Python 3.14 (D10).~~ **Settled 2026-08-17**
  against the upstream compatibility matrix, and the version it had to be checked against moved
  under D16: `django-stubs` 6.1.0 supports Django 6.1, mypy 1.13 – 2.3 and Python 3.11 – 3.14.
  Recorded in D10.
- **Whether `django-stubs-ext` is required explicitly, or arrives transitively with
  `django-stubs`.** Upstream describes it as a _production_ dependency. If it must be declared,
  it is the one package in this plan that lands in `[project].dependencies` rather than the
  `dev` group, which D5 should note deliberately (D10).
- **Ruff's `S` rule completeness against upstream `bandit`** — **partially settled 2026-08-17
  under D12, and deliberately left open on one axis.** Measured: ruff ships **73** `S` rules
  (read from `ruff rule --all`), all Django-specific ones present; both tools yield **0** on
  this project's production code. What is _not_ established is behavioural parity rule by rule:
  the comparison is by rule number, and the measured `B105` / `S105` divergence proves two
  rules can share a number and differ. D12 does not depend on closing this, because the
  production yield of both tools is currently zero — but a future finding in `jobs` or a DRF
  view is the moment to revisit it. bandit's own inventory (75 IDs) was taken from the
  2026-08-17 audit and **not** re-verified.
- **Whether `coverage` discovers `django_version/pyproject.toml` without `--cov-config`.** The
  three experiments that settled Issue 5 passed the configuration path explicitly, so that no
  project file had to be written. Discovery is expected from pytest's `rootdir`, but it is
  unmeasured, and it decides whether `[tool.coverage.run]` governs the run or nothing at all
  (D11).
- ~~The hook contract of whichever runner D14 selects — working directory, filename passing,
  argument handling, and path filters.~~ **Settled by reading under D14, and unmeasured in
  full.** `pre-commit` executes hooks from the repository root with no per-hook override, and
  `uv run --project` keeps relative paths resolving against it while still finding the project
  environment — both read from official documentation. **What is not measured is the whole of
  D14**: no hook was ever installed or fired, because the `uv` on this machine predates the
  version this project will pin. The load-bearing inference — that a hook receiving staged paths
  never reaches `oop_version/`, so D9's 49 findings are a property of `ruff check .` rather than
  of any runner — is stated in D14 as reasoning and is what D14's acceptance criterion exists to
  falsify.
- ~~Whether `pip-audit`/`uv`'s audit path follows a nested requirements include, if relevant after
  D1 removed the `-r` nesting (audit Observation O5, left unverified by both passes).~~ **Moot
  as of D18** — no dependency-audit tool is adopted, and `requirements.txt` is removed by D1.
  It returns only if the revisit trigger in D18 fires.
- ~~**Which `package-ecosystem` value Dependabot accepts for a `uv` project.**~~ **Settled
  2026-08-19** against GitHub's _Dependabot options reference_, which lists **UV** among the
  accepted values. The supported-ecosystems table still would not read cleanly; the options
  reference is normative and was legible (D18 amendment).
- ~~**Whether Dependabot security updates require the `dependabot.yml` entry, or follow from the
  repository toggles alone.**~~ **Settled 2026-08-19 by measurement, not by reading: the toggles
  alone.** Four security-update pull requests were opened against a repository containing no
  `dependabot.yml` at all. The consequence is the one D18's amendment acts on — the file governs
  version updates only, so it cannot keep security updates out of `oop_version/`.
- **New, created by D21: that a Dependabot-authored pull request passes CI under a generated
  `SECRET_KEY`.** It cannot be verified before the merge, because only Dependabot can produce a
  run with the restricted secret source. Carried as T9's deferred verification.
- ~~Whether Dependabot updates actions pinned to a full commit SHA.~~ **Settled 2026-08-17**
  against the GitHub changelog of 2022-10-31: it updates the SHA and the version comment
  beside it. Item 2's amendment rests on this.
- **Whether `actions/checkout@v7` and `actions/setup-python@v7` are drop-in for this
  workflow.** The recent `checkout` majors changed the runner Node version, and `setup-python`
  v7 must accept the `python-version-file` input that D6's first amendment introduces. One
  verification, taken once, before the SHAs are written (D8 Item 2 amendment).
- ~~Whether `actions/checkout@v4` functions under `permissions: {}` on this repository.~~ **No
  longer load-bearing after Item 1's amendment**, which grants `contents: read` on the job
  rather than relying on implicit public-repository read.
- **Whether a job-level `permissions` block replaces or is intersected with the workflow-level
  one.** Not stated on either GitHub page read on 2026-08-17. Item 1's amendment is written so
  that the wrong answer produces a step-1 failure on the first push with a one-line revert, so
  this settles empirically rather than by reading (D8 Item 1).

---

# Tasks

## How these entries are written, and where they deliberately differ from `PLANNER.md`

`PLANNER.md` prescribes _WHY THIS PATH_ and _ALTERNATIVES CONSIDERED_ on every task entry. Those
sections are **not repeated here**. This plan's Decision log already carries them at length, with
the evidence that produced each one, and duplicating that content would double a file that agents
load in full. Each task names the decision it implements; the decision is where the reasoning
lives, and the Developer reads it before starting.

What every task entry does carry: what to do, the exact files it may touch, what must be true
when it is finished, what it must not touch, and the questions that return to the Planner rather
than being resolved by the Developer.

**The suite is 304 tests and green.** Unless a task says otherwise, "the suite stays green" means
304 passed, and any change in that number is reported rather than absorbed.

---

## T1 — `Dockerfile` cleanup: remove `pillow` and its system libraries, and test `libpq-dev`

**Status: Done — 2026-08-18.**

**Result.** `pillow`, `libjpeg-dev` and `zlib1g-dev` removed. `libpq-dev` dropped empirically and
kept dropped — a full rebuild without it gave 304 passed, confirming `psycopg-binary` bundles its
own libpq. **Image size: 311 MB → 244 MB.** D4's 285 MB is a planning-time figure; 311 MB is what
this task measured immediately before editing, and is the one the 244 MB compares against. The
now-empty `apt-get` step was left in place deliberately — see _Open questions_.

**Implements:** _Items that need no decision_. **Blocks:** T11 (D6's build step is measured
against the cleaned image).

**Problem.** `requirements.txt` pins `pillow==12.3.0` and the `Dockerfile` installs `libjpeg-dev`
and `zlib1g-dev` for it. Nothing imports `PIL` and no model declares an `ImageField`. Separately,
`libpq-dev` may be redundant because `psycopg-binary` bundles its own libpq — never verified by
either audit.

**Do.** Remove `pillow` from `requirements.txt`; remove `libjpeg-dev` and `zlib1g-dev` from the
`apt-get` line. Then, as a separate empirical step, drop `libpq-dev`, rebuild, and run the suite.
Keep the removal only if the suite passes; restore it and record the failure if not.

**Scope.** `django_version/Dockerfile`, `django_version/requirements.txt`.

**Acceptance.** The image builds. `docker-compose exec web pytest` → 304 passed. The `libpq-dev`
outcome is recorded either way — a kept dependency with a measured reason is a result, not a
failure. Image size before and after is reported.

**Out of scope.** The uv migration; anything in `ci.yml`.

---

## T2 — Migrate to `uv`: `pyproject.toml`, `uv.lock`, the image, and CI installation

**Status: Done — 2026-08-19.**

**Result.** `uv` 0.12.5 pinned in the image and in `ci.yml`. `uv sync --locked` succeeds on the
host and in the image; `docker-compose exec web pytest` → 304 passed, invoked unchanged. No
`.venv` exists inside `/app`, `sys.executable` reports `/opt/venv/bin/python`, and `uv` is not a
package in the project environment. **Image size: 244 MB → 251 MB** — the pre-migration figure is
T1's 244 MB, not the 285 MB the acceptance criteria below quote, which predates T1's cleanup.

**Verification debts settled.**

- `[tool.pytest]` governs the run, confirmed empirically rather than by inspection: breaking
  `python_files` on purpose collected 0 items, and restoring it collected the suite again. This
  also settles the debt about `pyproject.toml` being discovered without `--cov-config`.
- `actions/setup-python@v5` accepts `.python-version`, `pyproject.toml` and `.tool-versions` for
  `python-version-file`. `.python-version` was chosen because `pyproject.toml` carries only
  `requires-python = ">=3.14"`, a range — reading it would replace the workflow's exact patch pin
  with "any 3.14.x" and let CI diverge from the image.

**Notes and deviations.**

- `UV_PYTHON_DOWNLOADS=never` was added to the `Dockerfile` beyond what this task asked, so the
  build fails loudly instead of silently fetching a managed interpreter. uv's documented default
  (`python-preference = managed`) prefers a matching system interpreter over a download, so no
  equivalent setting was needed on the runner.
- `[tool.coverage.*]` does not exist in this repository yet, so item 2's "move it whole" was a
  no-op. That table is created with the coverage task.
- The four transitive dependencies uv resolved above the versions `requirements.txt` pinned
  (`sqlparse`, `pygments`, `packaging`, `cffi`) were left at uv's resolution. A `[tool.uv]`
  `constraint-dependencies` block pinning them was written and then reverted: it works, but it
  would freeze security-relevant transitives where Dependabot could not move them.
- `actions/setup-python` stayed at `@v5` although `v7.0.0` is current, and `astral-sh/setup-uv`
  entered on a tag rather than a SHA. Both are deliberate: version moves belong to D16, and SHA
  pinning to D8.
- Item 7 was taken further than "rewrite what became false": _Stack and versions_ in
  `.claude/rules/conventions.md` no longer restates any version number, naming the one
  authoritative file for each instead, and it gained a rule requiring permission before reading
  `uv.lock`. Root `CLAUDE.md`'s pointer to that section followed — one file beyond this task's
  scope, edited with the user's approval, as were `django_version/AUDITOR.md` and
  `django_version/DEVELOPER.md`, which cited `requirements.txt` with a fixed version list.

**Implements:** D1, D2 and its amendment, D3 and its amendment, D4, D5 and its amendment, D6 and
its amendment 1. This is **D16's commit 1**: no version moves in this task.

**Do.**

1. Create `django_version/pyproject.toml` with `[project].dependencies` (production only) and a
   single `dev` group in `[dependency-groups]`, and `django_version/uv.lock`. Commit the lockfile.
2. Move tool configuration into that file. **Delete `django_version/pytest.ini`** and write its
   sixteen lines as `[tool.pytest]` — the native TOML table, **not** `[tool.pytest.ini_options]`,
   and never both. Move `[tool.coverage.*]` whole (D11 established the table is not overridden).
3. `Dockerfile`: install uv by `COPY --from=ghcr.io/astral-sh/uv:<pinned> /uv /uvx /bin/`, set
   `UV_PROJECT_ENVIRONMENT=/opt/venv`, put `/opt/venv/bin` on `PATH`, and run a full
   `uv sync --locked` including the `dev` group.
4. `ci.yml`: `astral-sh/setup-uv` with `enable-cache: true`; keep `actions/setup-python` but
   replace the hardcoded `python-version` with `python-version-file`; replace
   `pip install -r requirements.txt` with `uv sync --locked`.
5. Delete `django_version/requirements.txt`.
6. Add `.ruff_cache/` and `.mypy_cache/` to the root `.gitignore` and to
   `django_version/.dockerignore`.
7. Rewrite the two rule files that state something this task makes false:
   `.claude/rules/testing.md` (its `pytest.ini` references) and `.claude/rules/conventions.md` →
   _Stack and versions_ (it names `requirements.txt` as where versions are pinned).

**Scope.** `django_version/pyproject.toml`, `django_version/uv.lock`,
`django_version/requirements.txt` (deleted), `django_version/pytest.ini` (deleted),
`django_version/Dockerfile`, `.github/workflows/ci.yml`, root `.gitignore`,
`django_version/.dockerignore`, `.claude/rules/testing.md`, `.claude/rules/conventions.md`.

**Commits.** Not one. Follow `conventions.md`: the `pyproject.toml`/`uv.lock`/`requirements.txt`
change is one; the `Dockerfile` is one; `ci.yml` is one; each rule file is its own.

**Acceptance.**

- `uv sync --locked` succeeds on the host and in the image.
- `docker-compose exec web pytest` → 304 passed, invoked exactly as it is today.
- `[tool.pytest]` actually governs the run — verified by setting a key and observing it take
  effect, not by inspection. The same check settles the open verification debt about whether
  `coverage` discovers `django_version/pyproject.toml` without `--cov-config`.
- No `.venv` is created inside `/app`, and the host's `django_version/.venv` is not overwritten by
  any command run in the container.
- Image size before and after is reported (D4's instrumentation; 285 MB was the pre-migration
  figure).
- `uv` does not appear as a package inside the project environment.

**Out of scope.** Every version number. `pillow` (T1 removed it). Any tool this plan adds later —
this task installs the test toolchain and nothing else new.

**Open questions that return to the Planner.** Whether `django-stubs-ext` must be declared
explicitly: if it does, it is the one package in this plan landing in `[project].dependencies`
rather than the `dev` group, and D5 records the exception deliberately rather than absorbing it.

---

## T3 — Stack bump: Django 6.1, Python 3.14.7, pytest-django 4.14.0

**Status: Done — 2026-08-19.**

**Result.** All three pins moved: Django `6.0.7` → `6.1`, pytest-django `4.12.0` → `4.14.0`,
base image `python:3.14.6-slim` → `python:3.14.7-slim`. Each was confirmed at implementation
time to be the current release rather than copied from D16's table: PyPI offers no 6.1 patch
above `6.1` and no pytest-django above `4.14.0`, and `3.14.7-slim` is the highest Python tag
published. **Django publishes the release as `6.1`, not `6.1.0`** — that is the literal the pin
carries. `uv lock` touched 8 lines and moved no package other than those two.
`docker-compose exec web pytest` → **304 passed**.

**D16's open verification, settled.** `check --deploy` under Django 6.1 returns **7 issues,
exit 0** — `security.W004`, `W008`, `W009`, `W012`, `W016`, `W018`, `W020`. This is identical
to D7's baseline measured on 6.0.7: the delta D16 flagged as unknown is nil. **`mail.E001` does
not fire**, as predicted from `config/settings.py` declaring no `MAILERS`, and `security.W027`
does not fire either. D7's step may now be made build-failing at ERROR.

**Notes and deviations.**

- **`.python-version` was edited, though this task's _Scope_ does not list it.** D16's Category A
  predates the file — the uv migration created it. `conventions.md` now names it as the one
  authoritative Python pin, the `Dockerfile` copies it before `uv sync --locked`, and
  `UV_PYTHON_DOWNLOADS=never` forbids fetching a managed interpreter, so leaving it at 3.14.6
  against a 3.14.7 base image would have failed the build. `ci.yml` reads the same file through
  `python-version-file`, so runner and image move together from one edit.
- **Two READMEs carry a live version literal, not one.** D16's Category A calls the root
  `README.md` "the only version literal in the README"; a repository-wide sweep found a second in
  `django_version/README.md`'s _Tech Stack_ table. Both were updated, with the user's approval for
  the file outside _Scope_.
- **`.claude/rules/conventions.md` needed no edit.** It is in _Scope_ and in Category A, but the
  uv migration had already rewritten _Stack and versions_ to name the authoritative file for each
  version instead of restating any. The acceptance criterion is met by that earlier change.
- The sweep confirmed no Category C file was modified. Every remaining match for a superseded
  version — `docs/audits/`, `docs/verifications/`, `docs/adr/`, `docs/tech_debt/`, the roadmaps,
  `specs/001-profiles-admin-panel/`, and the generated header of `profiles/migrations/0007` — is a
  record of what a past verification ran against, and stays as written.
- Neither README mentions `uv` in its stack description. That is incomplete rather than false, and
  is left for the Planner.

**Implements:** D16, its commit 2 and its synchronisation subtask. **Follows T2 immediately**, in
the same session, once the suite is green.

**Do.** Move the three pins in `pyproject.toml`, run `uv lock`, and bump the `Dockerfile` base
tag. Then rewrite the Category A files D16 lists: `.claude/rules/conventions.md` → _Stack and
versions_, and `README.md`'s single version literal. `ci.yml` needs no edit — T2 replaced its
literal with `python-version-file`.

**Scope.** `django_version/pyproject.toml`, `django_version/uv.lock`,
`django_version/Dockerfile`, `.claude/rules/conventions.md`, `README.md`.

**Acceptance.** Suite green. **`manage.py check --deploy` is run under 6.1 and its output
recorded** — this is D16's one open verification, and D7's step must not be made build-failing
until it is done. No Category C file is modified: `specs/`, `docs/audits/`, the roadmaps and the
superseded plan record what was true when written.

**Out of scope.** Category B files — root `CLAUDE.md`, `django_version/CLAUDE.md` and
`ARCHITECTURE.md` say "Django 6.x", which stays true.

---

## T4 — The suite runs the migrations; `--reuse-db` and the unused markers go

**Implements:** D17, D19, D20. One task because all three edit the same two files.

**Do.** From the `addopts` array in `[tool.pytest]`, remove `--no-migrations` and `--reuse-db`.
From `markers`, remove `slow` and `integration`. Create `django_version/conftest.py` overriding
`django_db_setup` to empty the `Skill` table once per session, with the model import **inside** the
function and a Google-style docstring.

**Scope.** `django_version/pyproject.toml`, `django_version/conftest.py` (new),
`.claude/rules/testing.md`.

**Acceptance.** 304 passed with migrations executing. The `Skill` table is empty when the first
test runs. **No test file is modified** — if a test needs changing, the decision returns to the
Planner. `.claude/rules/testing.md` no longer contains its _"Note on `--no-migrations` and data
migrations"_ section, its list of active flags matches the file, and its _Common mistakes_ row
about assuming data migrations have run is inverted.

**Out of scope.** Rewriting the 44 tests that collide with the seeded vocabulary — D17 considered
and rejected that. Verifying the seed _data_: D17 records that as a knowingly accepted cost.

**Instruction the Developer must not optimise away.** The fixture must live in `conftest.py`. D17
measured that the identical fixture loaded with `pytest -p <module>` never runs, because
command-line plugins register before pytest-django, which then redefines `django_db_setup` over
the top.

---

## T5 — `ruff`: configuration, the one-time format, and the findings

**Implements:** D9 and its amendment, D9a, D12.

**Do.** Add `[tool.ruff]` with **no `select` and no `ignore`**, `extend-select = ["S"]` under
`[tool.ruff.lint]`, and two `per-file-ignores` entries — `RUF012` under `*/migrations/*`, and
`S101` + `S106` under `*/tests/*`. `line-length` stays at the default. Run `ruff format .` once.
Then fix the findings: D9 measured 38 outside `migrations/`, 25 auto-fixable, leaving 13 that need
a human, 10 of them the same `RUF012`.

**Scope.** `django_version/pyproject.toml`, plus the source files the fixes touch.

**Acceptance.** `ruff check .` and `ruff format --check .` both clean from `django_version/`.
Production code reports **0** findings for the `S` rules. `config/` is in scope — verify by
confirming `config/settings.py` is among the files ruff reports on. Suite green.

**Out of scope.** Excluding any directory. Adding a top-level `ignore`.

**Known, and not bugs.** Two `F821` findings at `accounts/models/base.py` — the manager's return
annotations name a class defined later in the module. Verified in the container that they resolve
correctly on the pinned Python. How they are silenced is the Developer's call; that they are not
defects is established.

**Open question that returns to the Planner.** Whether `RUF012` on Django's admin and `Meta`
attributes is fixed with `ClassVar` annotations or a per-file ignore — decided with the real diff
in hand, and if the answer is a per-file ignore it is an amendment to D9a's principle, not a
silent addition.

---

## T6 — `mypy`: fix the 18 production errors

**Implements:** D10, its first task. **Does not add a CI step.**

**Do.** Add `[tool.mypy]` with `plugins = ["mypy_django_plugin.main"]` and `[tool.django-stubs]`
with `django_settings_module = "config.settings"` — note it is `[tool.django-stubs]`, **not**
`[tool.mypy.plugins.django-stubs]`, which is the `mypy.ini` form. Declare `mypy` and
`django-stubs` in the `dev` group. Scope the check to `accounts/`, `profiles/`, `config/` and
`manage.py`, excluding `accounts/tests/` and `profiles/tests/`. `migrations/` stays **in** scope —
measured at zero errors. Strict mode is **not** enabled. Then fix the 18.

**Scope.** `django_version/pyproject.toml`, `accounts/admin.py`, `accounts/models/base.py`,
`profiles/admin.py`, `config/settings.py`.

**Acceptance.** mypy over the production scope reports 0 errors. Suite green. Four of the errors
in `accounts/models/base.py` are one fix — the manager's `TypeVar` has no bound.

**Out of scope.** Test files, and anything that would require editing `.claude/rules/testing.md`'s
fixture-annotation rule. That is deferred in
`docs/tech_debt/006-tests-excluded-from-type-checking-fixture-annotations-cannot-pass.md`.

**Explicitly refused.** Annotating the baseline fixtures `dict[str, Any]`. It clears 60 errors
with two edits and buys silence by making the annotation weaker than what the project already
has.

**Open question that returns to the Planner.** `accounts/admin.py` calls
`queryset.filter(profile__isnull=…)` on a parameter annotated `QuerySet[BaseUser]`, and `BaseUser`
is abstract with no `profile` relation. **The code is correct; the annotation is not.** If choosing
the right annotation turns out to be a modelling judgement about how a queryset over two
independent concrete models should be typed, it comes back to the Planner rather than being
guessed.

---

## T7 — `mypy`: add the CI step, build-failing from its first run

**Implements:** D10, its second task. **Requires T6 finished and green.**

**Scope.** `.github/workflows/ci.yml`.

**Acceptance.** The step fails the job on a deliberately introduced type error, and passes on
`main`. No `continue-on-error`.

---

## T8 — Coverage: `pytest-cov` with a 95% floor

**Implements:** D11.

**Do.** Declare `pytest-cov` in the `dev` group. Add **`--cov` with no value** and
`--cov-fail-under=95` to `addopts`. `[tool.coverage.run]` carries `source`, `branch = true`, and
`omit` for `*/tests/*` and `*/migrations/*`.

**Scope.** `django_version/pyproject.toml`.

**Acceptance.** Production coverage reports ~97% and the gate passes. Branch columns appear,
proving `branch = true` is honoured from the file. The `omit` entries take effect — tests and
migrations are absent from the report.

**The one trap, stated so it is not walked into.** `addopts` must never carry `--cov=<value>` or
`--cov-branch`. Either one silently overrides the corresponding key in `[tool.coverage.run]`.
Bare `--cov` honours all three, verified by execution under D11.

**Out of scope.** Diagnosing the 8 uncovered statements in `accounts/admin.py`. The gate passes
with them uncovered.

---

## T9 — `ci.yml` hardening, triggers, the generated `SECRET_KEY`, and `dependabot.yml`

**Implements:** D8, all three items and all three amendments; the file half of D18 **as amended
2026-08-19**; and D21.

**Requires T3** (done) **and T18**, which turns off the toggle producing the pull requests this
task's file cannot filter. **This task precedes any merge to `main`.**

**Why it precedes the merge.** The four open `sqlparse` alerts — three of them high — are computed
from `django_version/requirements.txt` as it stands on `main`, which this branch deletes.
`uv.lock` already resolves `sqlparse` to the patched 0.6.0, so the fix travels with the merge; the
monitoring does not. Dependabot reads `dependabot.yml` from the default branch, so the `uv` entry
starts working when the merge lands and not before — which is precisely why it has to be in the
merge.

**Corrected 2026-08-19.** An earlier version of this entry recorded the three `oop_version` pull
requests as closed, and left it unverified whether `dependabot.yml` could keep security updates out
of that directory. Both are settled: measured, `#6`, `#7`, `#8` and `#9` are all still open with a
failing `test` check, and D18's amendment establishes that the file cannot filter security updates
at all. Closing the pull requests belongs to T18.

**Do.**

- `permissions: {}` at the workflow level and `permissions: contents: read` on the `test` job.
- Bump `actions/checkout` and `actions/setup-python` to their current majors **first**, then
  SHA-pin all four actions with the version in a trailing comment.
- Add the `pull_request` trigger, a `concurrency` group with `cancel-in-progress: true`, and
  `paths-ignore` covering `docs/**` and root Markdown — **not** `.claude/rules/**` and **not**
  `specs/**`.
- Replace `SECRET_KEY: ${{ secrets.SECRET_KEY }}` in the job `env` block with a step that generates
  a random value into `$GITHUB_ENV` before any Django command runs (D21).
- Create `.github/dependabot.yml` with exactly two entries: `github-actions`, and `uv` at
  `directory: "/django_version"`. Both at `interval: monthly`. **`oop_version/` is declared
  nowhere**, and no third entry is added for completeness.

**Scope.** `.github/workflows/ci.yml`, `.github/dependabot.yml` (new).

**Acceptance.** CI is green on the first push after the change. All four actions carry a
40-character SHA. A documentation-only push produces no run; a push mixing documentation and code
does. `.github/dependabot.yml` names no directory under `oop_version/`.

**Deferred verification — it can only be taken after the merge.** That a Dependabot-authored pull
request reports a **green** `test` check. It is the only proof that D21 works against the
restricted secret source, and nothing on this branch can produce it. Record it against the first
monthly `uv` pull request; if it is red, the finding returns to the Planner rather than being
resolved by skipping the job.

**Verifications to perform before writing the SHAs.** That `actions/checkout` and
`actions/setup-python` at their current majors are drop-in for this workflow, and that
`setup-python` accepts the `python-version-file` input T2 introduced.

**The failure this is written to survive.** Whether a job-level `permissions` block replaces or
intersects the workflow-level one is not documented. If it intersects, `actions/checkout` fails on
step 1 of the first push and the revert is replacing `permissions: {}` with
`permissions: contents: read` — one line.

---

## T10 — CI runs Django's own two checks

**Implements:** D7. **Requires T3**, because `check --deploy` must be measured under Django 6.1
before it is made build-failing.

**Do.** Add `python manage.py makemigrations --check` (the flag implies `--dry-run`; do not pass
both) and `python manage.py check --deploy` at its default `--fail-level ERROR`.

**Scope.** `.github/workflows/ci.yml`.

**Acceptance.** Both steps pass on `main`. `makemigrations --check` fails on a deliberately
uncommitted model change. The `check --deploy` warning baseline under 6.1 is recorded in the run
log, and **`mail.E001` is confirmed not to fire** with no `MAILERS` defined — if it does, the step
does not become build-failing and the finding returns to the Planner.

---

## T11 — CI builds the image

**Implements:** D6, amendment 2. **Requires T1 and T2.**

**Do.** A plain, uncached `docker build`. No buildx, no `type=gha` cache.

**Scope.** `.github/workflows/ci.yml`.

**Acceptance.** The step passes, and **its duration is reported from the Actions UI**. Above
roughly 90 seconds, the caching option is revisited with the real number in hand; below it, the
step stays as decided.

---

## T12 — Secret scanning: `gitleaks` in CI, and a widened `.gitignore`

**Implements:** D13.

**Do.** Add a `gitleaks` step to `ci.yml` and a `.gitleaks.toml` at the repository root with
`useDefault = true` plus two custom rules — one for Django `SECRET_KEY` shapes, one for the
`db_password` family — and a path allowlist. Separately, replace the root `.gitignore`'s two exact
`.env` entries with `.env*` plus `!.env.example`.

**Scope.** `.github/workflows/ci.yml`, `.gitleaks.toml` (new), root `.gitignore`.

**Acceptance.** `git check-ignore` reports `.env.prod`, `.env.production` and `.env.ci` as
ignored, and `.env.example` as **not** ignored. The CI step passes on the current tree. A fake
Django `SECRET_KEY` committed to a scratch branch is caught, and that branch is deleted.

**Do not.** Add a hook — D14 closed that conditional negative. Allowlist a whole file when the
finding is one rule: the allowlist is scoped by rule _and_ path.

**Treat as a starting point.** The two custom regexes were written during planning and are
unreviewed. They produced 8 working-tree findings on this repository, all explainable. Tune
against a real run.

---

## T13 — Non-root user in the `Dockerfile`

**Implements:** D15. **Requires T2** (`/opt/venv` must exist) **and T11** (which is what guards
it).

**Do.** Create a non-root user, give it ownership of `/opt/venv`, and add `USER` before the
default command. `uv sync` must still be able to write the environment — either it runs as root
before `USER` with the `chown` after, or the directory is created and chowned first and synced
afterwards.

**Scope.** `django_version/Dockerfile`.

**Acceptance — and read D15 before writing it.** The verifiable half: the image builds, and
`docker-compose exec web pytest` → 304 passed as the new user, which proves `/opt/venv` is
readable and executable by it. **The bind-mount half is not testable on this machine and no
criterion may claim it is** — measured, Docker Desktop's VirtioFS presents the mount as owned by
whichever UID accesses it, so a write test passes for every UID including one that exists nowhere.
Record it as verified on a Linux host or in Phase 5, not here.

---

## T14 — `pre-commit` hooks: `ruff` only

**Implements:** D14. **Requires T2 and T5.**

**Do.** A `.pre-commit-config.yaml` at the repository root with two `repo: local` hooks —
`ruff format` and `ruff check --fix` — each with `entry: uv run --project django_version <tool>`,
`files: ^django_version/`, and the language value current for the pinned version
(`unsupported`, formerly `system`; confirm the spelling).

**Scope.** `.pre-commit-config.yaml` (new).

**Acceptance — the second half is the one that matters.** With a Python file under
`django_version/` staged carrying a deliberate formatting error and a deliberate lint error,
`git commit` fails and names the hook. **With a file staged under `oop_version/` alone, neither
hook runs.** The second is what tests D14's load-bearing inference, and it is the one that would
expose it as wrong.

**Do not.** Use `--directory` on a hook that passes filenames — it moves the working directory and
the root-relative paths stop resolving. Add `mypy`, `pytest` or `gitleaks` to the hook set.

---

## T15 — Enable Dependabot alerts and security updates

**Status: Done — 2026-08-18.**

**Implements:** D18, its repository half.

**This task has no file.** It is two toggles in the repository's security settings, which no diff
records and no clone restores — the same class as `sha_pinning_required` under D8's _Recorded but
not planned_.

**Acceptance.** `gh api repos/<r> --jq '.security_and_analysis'` reports
`dependabot_security_updates: enabled`, and `gh api repos/<r>/dependabot/alerts` returns a list
rather than the 403 it returns today.

~~**Verify before writing `dependabot.yml` in T9.** That `uv` is the accepted `package-ecosystem`
value, against GitHub's supported-ecosystems table.~~ **Settled 2026-08-19:** GitHub's
_Dependabot options reference_ lists **UV** among the accepted values. D18 is not reopened.

**Partly reversed by T18, and deliberately left standing here.** The security-updates half
enabled by this task is turned off on 2026-08-19 — see D18's amendment for what implementing this
task exposed and why the narrower configuration replaces it. This entry is not edited to match,
because the sequence is the finding: the default configuration was enabled on purpose, and it was
narrowed on purpose once its cost was measured. Anyone tempted to re-enable security updates
"because monitoring looks incomplete" should read D18's amendment first.

---

## T16 — Version the editor configuration

**Implements:** the decided item under _Items that need no decision_. **Requires T2.**

**Do.** In the root `.gitignore`, keep `.vscode/` ignored and add an exception for
`.vscode/settings.json`. Write that file with the interpreter and test working directory pointed
at `django_version/`.

**Scope.** root `.gitignore`, `.vscode/settings.json` (new).

**Acceptance.** A fresh clone opens at the repository root with the interpreter resolving to the
project environment, and the test runner rooted at `django_version/`. No machine-specific absolute
path appears in the file.

---

## T17 — Record the deferrals in `docs/tech_debt/`

**Implements:** the last item under _Items that need no decision_. **Runs last**, so it records
what actually happened rather than what was planned.

**Already written on 2026-08-17**, before implementation began: `007` (the single `dev` group),
`008` (no dependency-audit gate in CI), `009` (no `HEALTHCHECK`) and `010` (the bind-mount half
of D15 unverifiable on macOS), joining `006` (test code outside the type checker).

**What remains for this task** is anything implementation turns up that was not foreseeable in
planning — a verification that fails, a decision a task hands back, a cost that proves larger
than the entry recording it assumed. Continue the sequence from `010`, one file per deferral,
following the shape of the files already on disk.

**Scope.** `docs/tech_debt/`.

**Not tech debt, and must not be filed as such.** The signals this plan flagged and deliberately
did not absorb — the two `F821` findings, the test that failed once in three runs without
reproducing, and `accounts/admin.py`'s 8 uncovered statements and 12 mypy errors — are **agenda
for an Auditor session**, not recorded debt. Filing them as debt would assert a decision nobody
took.

---

## T18 — Turn off Dependabot security updates, and clear the four pull requests it opened

**Implements:** the repository half of D18 **as amended 2026-08-19**. **Runs before T9**, and
before any merge to `main`.

**This task has no file either**, for the reason T15 had none: both halves live in the
repository's settings, which no diff records and no clone restores. It is a separate task rather
than an edit to T15 so the trail stays readable — the default configuration was enabled
deliberately on 2026-08-18, and it is narrowed deliberately on 2026-08-19 because implementing it
measured what the default costs.

**Where.** Repository **Settings → Advanced Security**. Every toggle named below is on that one
page.

**Do.**

- Turn **Dependabot security updates** off. It is the only toggle that changes.
- Leave **Dependabot alerts** on, and leave **Dependency graph** on — the alert stream is the
  detection half this plan keeps, and it does not exist without the graph.
- **Do not touch Dependabot version updates on this page, and do not create the file it offers.**
  Version updates is not a toggle: the control opens a web editor holding GitHub's starter
  `dependabot.yml` template, and saving it commits that file **to the default branch**. T9 writes
  the real file in this branch instead, for two reasons. `main` today carries
  `django_version/requirements.txt` and neither `pyproject.toml` nor `uv.lock`, so a `uv` entry
  committed there would point at a manifest that does not yet exist on that branch — _stated as
  reasoning, not measured: the expected result is a failing Dependabot update job rather than any
  damage._ And a file created on `main` while T9 creates the same path here is a merge conflict
  bought for nothing. The template also defaults to `interval: "weekly"` and `directory: "/"`,
  neither of which is what D18's amendment decided.
- Touch nothing else on the page — **Dependabot rules**, malware alerts, grouped security updates,
  private vulnerability reporting, code scanning and secret protection are all outside this task.
- Close pull requests `#6`, `#7`, `#8` and `#9`. `#7` (`sqlparse` in `/django_version`) closes on
  the same evidence as the other three: `uv.lock` on this branch already resolves the patched
  0.6.0, so the pull request would apply a fix to a file the merge deletes.

**The latency cost D18's amendment accepted is smaller than it recorded, and GitHub's own settings
page is the source.** The Dependabot alerts toggle is described there as _"Receive alerts for
vulnerabilities that affect your dependencies **and manually generate Dependabot pull requests** to
resolve these vulnerabilities."_ So with alerts on and security updates off, the fix pull request
is still available on demand from the alert, for an advisory worth acting on immediately. The
monthly cycle becomes the default path rather than the only one.

**One thing to look at while on that page, and it can reopen D18's amendment.** The page shows
_"Dependabot rules — 1 rule enabled"_, which is the auto-triage surface; the enabled rule is
expected to be GitHub's preset rather than a custom one. D18's amendment set aside the manifest-path
rule because custom rules are documented as licence-gated. **If that screen offers creating a custom
rule with a manifest-path condition on this repository, say so before finishing this task** — that
option is strictly better than the one decided here, because it filters `oop_version/` while keeping
security fixes immediate for `django_version`. If it does not, proceed as decided; the decision was
taken knowing this was the fallback.

**Acceptance.**

- `gh api repos/<r> --jq '.security_and_analysis.dependabot_security_updates.status'` reports
  `disabled`.
- `gh api repos/<r>/dependabot/alerts` still returns a list rather than a 403 — alerts survived
  the change.
- `gh pr list` shows no open pull request authored by `app/dependabot`.

**Do not** dismiss the four open `sqlparse` alerts to tidy the Security tab. _Stated as reasoning,
not measured:_ they are expected to close on their own once the merge removes
`django_version/requirements.txt` from the default branch. Dismissing a real high-severity finding
by hand is a habit worth not starting, and if they do not close on their own, that is worth
knowing rather than hiding.

---

## T19 — Two Dependabot auto-triage rules: open pull requests for `django_version`, dismiss `oop_version`

**Implements:** D18, amendment 2. **Runs after the merge to `main`, and not before** — step 1
states why and how to confirm it.

**Two of the three steps are repository settings and one is a file.** The settings half is the
user's to click; the Developer walks them through it, verifies by API, and writes the file.

### Step 1 — confirm the merge has landed and read the real manifest value

Do not open the rules screen before both commands below agree.

```
gh api repos/thaisdMM/skillbridge/contents/django_version/uv.lock --jq '.name'
gh api repos/thaisdMM/skillbridge/contents/django_version/requirements.txt --jq '.name'
```

The first must return `uv.lock`; the second must return a 404. That is the state in which the
dependency graph on the default branch describes the project through `uv`.

Then read the manifest path Dependabot itself uses, rather than assuming it:

```
gh api repos/thaisdMM/skillbridge/dependabot/alerts \
  --jq '[.[] | .dependency.manifest_path] | unique'
```

**If that returns an empty list** — no alert open at that moment — take the value from the
`manifest` filter's autocomplete on the rules screen in step 2 instead, and write down what it
offered.

**Expected: `django_version/uv.lock`. Not verified.** If the value is anything else —
`django_version/pyproject.toml`, a path without the directory prefix, or two entries where one was
expected — **write it down, create no rule, and return to the Planner.** A rule filtered on a path
that does not exist matches nothing and reports nothing.

### Step 2 — create the dismiss rule first

`Settings → Advanced Security → Dependabot rules → New rule`. Create it exactly as follows:

| Field | Value |
| ----- | ----- |
| Rule name | `oop-version-closed-directory` |
| State | Enabled |
| Metadata filter | `manifest` = `oop_version/requirements.txt` |
| Action | **Dismiss alerts** |

Nothing else is set. No severity filter, no ecosystem filter, no scope filter — the directory is
the whole criterion, and narrowing it further would let an alert through.

This rule is created first because it is the reversible one: if it behaves unexpectedly, deleting
it restores exactly the state before this task.

### Step 3 — create the pull-request rule

| Field | Value |
| ----- | ----- |
| Rule name | `django-version-security-prs` |
| State | Enabled |
| Metadata filter | `manifest` = the value confirmed in step 1 |
| Action | **Open a pull request to resolve alerts** |

**Precondition, and confirm it before saving:** Dependabot security updates must be **off**.
Documentation read on 2026-08-19: for an _open a pull request_ rule to take effect, _"you must
ensure that Dependabot security updates are disabled"_. T18 turned it off; if it is on, stop —
someone re-enabled it, and that is a finding, not something to fix silently.

### Step 4 — record the rules where a diff can carry them

Write `docs/tech_debt/011-dependabot-auto-triage-rules-live-outside-the-repository.md`, following
the shape of the files already on disk. It must contain both tables above verbatim, the value
observed in step 1, and one sentence on the consequence: no clone, fork or transfer restores these
rules, so a repository moved or recreated silently loses both behaviours.

### Scope

`docs/tech_debt/011-dependabot-auto-triage-rules-live-outside-the-repository.md` (new). No other
file. `.github/dependabot.yml` is **not** edited by this task.

### Acceptance

- The Dependabot rules screen lists both rules, both enabled, alongside whatever preset was
  already there.
- `gh api repos/thaisdMM/skillbridge --jq '.security_and_analysis.dependabot_security_updates.status'`
  still reports `disabled`.
- `gh api repos/thaisdMM/skillbridge/dependabot/alerts --jq '[.[] | {pkg:.dependency.package.name, path:.dependency.manifest_path, state}]'`
  runs clean and its output is pasted into the tech-debt entry as the baseline at creation time.
- The tech-debt entry exists and carries both rule definitions.

### Deferred verification — cannot be taken in this task

That a new advisory against a `django_version` dependency produces a Dependabot pull request with
a **green** `test` check, and that a new advisory against `oop_version` is auto-dismissed with no
pull request. Neither can be forced; both are observed the first time they happen. If the
`django_version` pull request is red, that is D21 failing and it returns to the Planner.

### Do not

- Do not re-enable Dependabot security updates. It would restore `oop_version` pull requests and,
  per the documentation quoted in step 3, disable the rule created in step 3.
- Do not edit or delete `.github/dependabot.yml`. Monthly version updates stay exactly as T9
  wrote them; these rules are a separate layer.
- Do not add a severity, ecosystem or scope filter to either rule "to be safe". Each extra filter
  is a condition an alert can fail to meet, and a rule that silently stops matching is the failure
  mode this task is written to avoid.
- Do not delete the preset rule already enabled on the screen. It was not examined by this plan.

### Returns to the Planner rather than being decided here

- The manifest value not matching step 1's expectation.
- The `manifest` filter rejecting the value, or accepting only a wildcard or prefix form — record
  the exact form accepted.
- Dependabot security updates found enabled at step 3.

---

# Order of execution

Four things constrain the order; everything else is free.

1. **T1 before T2**, because T1 edits `requirements.txt` and T2 deletes it.
2. **T2 before almost everything**, because it creates `pyproject.toml`, which nine other tasks
   configure.
3. **T3 immediately after T2**, in the same session. D16 bought its diagnostic value with commit
   ordering, not with calendar time: if the two land together a red suite is ambiguous, and if
   they are separated by days the separation is no longer a sequence.
4. **T18 before T9, and both before any merge to `main`.** T18 is server-side and takes effect the
   moment the toggle flips, so it stops new pull requests immediately; T9's `dependabot.yml` is
   inert until it reaches the default branch, which is also the merge that deletes the manifest
   `django_version`'s current monitoring is computed from. Reversing the two would leave security
   updates producing `oop_version` pull requests for the whole span of the remaining work.
   **Both are done as of 2026-08-19, so the merge is unblocked.**
5. **T19 after the merge**, and the merge is therefore an explicit step in this sequence rather
   than something that happens whenever the branch feels finished. T19's filters are written
   against the manifest paths the default branch's dependency graph reports, and the merge is what
   changes them from `django_version/requirements.txt` to the `uv` pair.

| #   | Task                                                           | Waits on | Why                                                                                                                                        |
| --- | -------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | ~~**T15** — enable Dependabot~~ **done 2026-08-18**            | —        | Free, server-side, and nothing watched dependencies before it. Its security half is narrowed by T18                                        |
| 2   | ~~**T1** — `Dockerfile` cleanup~~ **done**                     | —        | `requirements.txt` must still exist                                                                                                        |
| 3   | ~~**T2** — uv migration~~ **done**                             | T1       | D16 commit 1                                                                                                                               |
| 4   | ~~**T3** — stack bump~~ **done 2026-08-19**                    | T2       | D16 commit 2, same session, once green                                                                                                     |
| 5   | ~~**T18** — narrow Dependabot to `/django_version`~~ **done 2026-08-19** | —        | Server-side and immediate. Every day it waited was another closed-directory pull request and another red run                      |
| 6   | ~~**T9** — CI hardening, generated `SECRET_KEY`, `dependabot.yml`~~ **done 2026-08-19** | T2, T18  | Moved up from position 10: it is what the merge to `main` depends on, and D21 is what makes any Dependabot run capable of passing |
| 7   | **Merge `feature/django-refactor` into `main`**                | T9       | Not a task, and listed anyway because two later items depend on it: it activates `dependabot.yml`, closes the four `sqlparse` alerts with the manifest they are computed from, and is what T19's filters are written against |
| 8   | **T19** — the two Dependabot auto-triage rules                 | the merge | The `manifest` values only become correct once the default branch describes the project through `uv`                                      |
| 9   | **T4** — migrations in the suite, `--reuse-db` and markers out | T3       | Needs `[tool.pytest]`, and D17's fixture is re-confirmed on pytest-django 4.14.0                                                           |
| 10  | **T5** — ruff                                                  | T2       | Touches many source files; landing it before the type work keeps the two diffs separable                                                   |
| 11  | **T6** — fix the 18 mypy errors                                | T3, T5   | django-stubs 6.1.0 targets Django 6.1                                                                                                      |
| 12  | **T7** — mypy CI step                                          | T6       | Enters build-failing, so the errors must be gone                                                                                           |
| 13  | **T8** — coverage                                              | T4       | Measures the final test regime, not the interim one                                                                                        |
| 14  | **T10** — Django's two checks                                  | T3, T9   | `check --deploy` must be measured under 6.1, and under D21's generated key                                                                 |
| 15  | **T11** — `docker build` step                                  | T1, T2   | Measured against the cleaned, migrated image                                                                                               |
| 16  | **T13** — non-root user                                        | T2, T11  | T11 is the automated gate on getting the ownership wrong                                                                                   |
| 17  | **T12** — gitleaks                                             | T9       | Independent of everything else; grouped with the CI work                                                                                   |
| 18  | **T14** — pre-commit hooks                                     | T2, T5   | The ruff configuration must exist for the hooks to run it                                                                                  |
| 19  | **T16** — editor configuration                                 | T2       | The interpreter path depends on where the environment ends up                                                                              |
| 20  | **T17** — tech debt entries                                    | all      | Records what happened                                                                                                                      |

**Independent of each other, in any order:** T12, T14, T16. **Independent of the whole sequence:**
T18, which needs no file to exist and no task to precede it.

**The two places where a task can stop and return to the Planner**, rather than being finished by
a judgement call: the `QuerySet[BaseUser]` annotation in T6, and `mail.E001` firing under Django
6.1 in T10. Both are named in their entries with what to do instead.
