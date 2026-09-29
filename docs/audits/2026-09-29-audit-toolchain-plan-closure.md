# Closing note — Toolchain, CI quality and security plan

**Date:** 2026-09-29
**Persona:** Auditor
**Subject:** `docs/plan/plan_toolchain-ci-security_2026-08-15.md`
**Status:** Closed. The plan ends with this note.

## How the plan ends

Tasks T1–T19, T6a and T6b are closed. The two that remained are resolved here rather than run as
written:

- **T17** (record deferrals in `docs/tech_debt/`) — the debt candidates are listed below as an
  optional backlog. None is written yet.
- **T20** (distil implementation notes into `docs/IMPLEMENTATION_NOTES.md`) — that file is not
  created. What deserves a durable record goes to `docs/adr/` when it is a real decision; the rest
  is kept in this note.

One ADR came out of this closure: `docs/adr/uv-manages-the-django-project-from-django-version.md`.
Everything else below is a backlog to pick from if and when it is worth it. Closure notes can be
wrong, so a candidate is checked against the real files before anything is written from it.

## Criteria for the backlog

- **ADR** — a technical choice between two or more viable options whose reason must survive, so
  nobody undoes it. Obvious options and the status quo are not listed. Context carries the user's
  real motive; only verified facts; *Consequences* only when a real resulting state exists.
- **Technical debt** — something done knowingly not-best to prioritise delivery, with a repayment
  that exists and is intended.
- **Neither** — a discovery, an accepted consequence, a pending verification.

## What the plan delivered — from the task closure notes

Only the `pyproject.toml` row was re-verified by execution in this closure; the others are as the
plan recorded them. This table is a summary. What each task found — its measurements, deviations
from the entry as written, and corrections — is in that task's entry in the plan, under its
**Result**, **Notes and deviations** and **Closed** sections.

| Area | Outcome |
| ---- | ------- |
| Dependencies | `uv` 0.12.5, `pyproject.toml` and `uv.lock` in `django_version/`; `requirements.txt` and `pytest.ini` deleted. Django 6.1, Python 3.14.7, pytest-django 4.14.0 |
| Image | `pillow`, `libjpeg-dev`, `zlib1g-dev` and `libpq-dev` removed (`psycopg[binary]` bundles libpq): 311 MB → 244 MB, then 251 MB with `uv`. Environment in `/opt/venv`, outside the bind mount. Runs as non-root user `app` (uid/gid 1000); the directory is chowned before `uv sync`, and a build without the `chown` was shown to fail |
| Test suite | runs the migrations; the seeded `Skill` rows are emptied by `django_db_setup` in the root `conftest.py`; no `--reuse-db`; 304 tests |
| `ruff` | default rule set plus `S`, two `per-file-ignores`, no `select`/`ignore` |
| `mypy` | `django-stubs` plugin, production code only, twelve of the thirteen `--strict` flags (`disallow_any_generics` deferred). One latent bug fixed on the way: `formfield_for_dbfield` could raise on a `None` form field |
| Coverage | `pytest-cov`, branch, `source = ["."]`, `manage.py` omitted, 95% floor; 97.00% |
| CI | jobs `test` (postgres, `pytest`, `makemigrations --check`), `quality` (ruff, mypy, `check --deploy` at ERROR), `build` (plain `docker build`, 18 s), `secrets` (`gitleaks`, 9 s). `permissions: {}` with per-job grants, every action SHA-pinned, `pull_request` trigger, `concurrency`, `paths-ignore` for `docs/**` and root Markdown. `SECRET_KEY` generated per run |
| `check --deploy` in CI | 5 warnings (`W004`, `W008`, `W012`, `W016`, `W020`), all owned by the Phase 5 deploy target; `mail.E001` does not fire |
| Dependabot | alerts on, security updates off, monthly `uv` and `github-actions` updates, three triage rules (see `docs/adr/dependabot-triage-rules-live-outside-version-control.md`) |
| Hooks | `pre-commit` with two local `ruff` hooks through `uv run --project django_version`, scoped to `django_version/` |
| Editor | `.vscode/settings.json` versioned; Pylint switched off |

## Verified in this closure — `django_version/pyproject.toml`

Run in the `web` container: `uv lock --check` in sync; `mypy` → `Success: no issues found in 43
source files`; `ruff check .` clean; `ruff format --check .` → `76 files already formatted`;
`makemigrations --check` → `No changes detected`; `pytest` → 304 passed, 97.00%. No competing
`pytest.ini`, `mypy.ini`, `setup.cfg` or `.coveragerc`. `mypy --help` on 2.3.1 confirms the twelve
flags are `--strict` minus `disallow_any_generics`.

**Divergences found:**

1. **Corrected:** `.claude/rules/testing.md` listed three active pytest flags and omitted `--cov`
   and `--cov-fail-under=95`. It now lists all five and records that a single test file run alone
   fails the floor (50 passed, 67.71%) unless `--no-cov` is passed.
2. `disallow_any_generics` costs **14 errors in 5 files** today, not the 10 in 4 the plan recorded
   for the `011` entry — `BaseUserManager` no longer appears, `_AdminBase` now does.
3. `docs/tech_debt/006` records 102 test errors under default mypy settings; with the twelve flags
   the test files report **118 errors in 10 files** (70 `arg-type`, 13 `no-untyped-def`).
4. `docs/tech_debt/007`'s reversal criterion 1 — "CI is split into more than one job" — has fired.
   The measured saving the plan meant to add there (1 s on a warm cache) was never added.
5. The plan says `--cov-branch` in `addopts` overrides `[tool.coverage.run]`; with `branch = true`
   it changes nothing.

## Backlog — ADR candidates

Not verified against the files unless marked.

| Candidate | Plan source |
| --------- | ----------- |
| The suite runs the migrations; seeded rows emptied in the root `conftest.py`; no `--reuse-db` (the user's call against the Planner's recommendation) — *config verified* | D17, D19 |
| `ruff`: default set plus `S`, suppressing a rule per path rather than excluding a directory — *config verified* | D9, D9a, D12 |
| `mypy` + `django-stubs`, production only, twelve flags listed rather than `strict = true` — *config verified* | D10 |
| Coverage: 95% floor, `source = ["."]`, `manage.py` omitted — *config verified* | D11 |
| Environment at `/opt/venv`, outside the bind mount | D3 |
| The image is a development image and installs the `dev` group | D4 |
| `psycopg[binary]` rather than building against `libpq-dev` | T1 |
| Non-root user, chowned before `uv sync` | D15 |
| CI installs on the runner and builds the image in its own uncached job | D6 |
| CI jobs split by what they need; `if: ${{ !cancelled() }}` on later steps | D22 |
| `check --deploy` blocking at ERROR; `makemigrations --check` | D7 |
| `permissions: {}`, SHA-pinned actions, monthly Dependabot for actions | D8 items 1–2 |
| `pull_request`, `concurrency`, `paths-ignore` excluding `.claude/rules/` and `specs/` | D8 item 3 |
| `SECRET_KEY` generated per run | D21 |
| `gitleaks` in CI, allowlist by rule and path; `.env*` with `!.env.example` | D13 |
| `pre-commit` hooks run `ruff` only | D14 |
| Pylint off; `ruff` and `mypy` are the only checkers (the user chose among four options) | T16 |
| Admin typed by following the supertype, `QuerySet[Any]` (options A/B/C put to the user) | D10, group F |
| `Meta.ordering` stays `ClassVar[list[str]]` while `constraints` and `actions` became tuples — converting it generates a migration (the user earlier decided against an ADR) | T5, T6 |

## Backlog — technical-debt candidates

| Candidate | State |
| --------- | ----- |
| `011` — `disallow_any_generics` deferred, including the annotated local in `ProfilePresenceMixin.get_queryset` | real debt; measure again before writing (divergence 2) |
| `007` — single `dev` group | reversal criterion fired (divergence 4): repay, update, or reclassify |
| `006` — tests outside the type checker | numbers stale (divergence 3) |
| `009` — no `HEALTHCHECK`; `010` — bind-mount behaviour unverifiable on macOS | may not meet the debt criterion; `010` reads as a verification gap |
| `008` — no dependency-audit gate in CI | check whether it records the scheduled CI run deferred with it |
| `sha_pinning_required` | every action was pinned so this repository setting could be enabled; no task enabled it |
| The three `# Type hint for Pylint` comments | false now that Pylint is off; removal needs a mypy measurement first |
| The two custom `gitleaks` regexes | recorded as unreviewed at creation |
| `pre-commit` installed with `uv tool install`, outside the lock | only `minimum_pre_commit_version` records a version |

## Worth knowing — neither ADR nor debt

- `django_stubs_ext` must stay behind `TYPE_CHECKING`. The image and CI always install the `dev`
  group, so nothing would catch a runtime import.
- The `*/tests/*` glob does not match a top-level `tests/` directory.
- `git check-ignore -v` changes its exit-code meaning when the last matching pattern is a negation;
  use `-q`.
- In `.gitignore`, `dir/` cannot be re-included by `!dir/file`; `dir/*` can.
- `mypy` needs a `SECRET_KEY` in the environment: without one the plugin fails with exit 2 and
  `Error constructing plugin instance`, which reads as a broken workflow rather than a type error.
- Auditor agenda, deliberately not absorbed: the two `F821` findings, the test that failed once in
  three runs, the 8 uncovered statements in `accounts/admin.py`.
- One premise was reasoned, never executed: that `uv sync` against the system prefix would prune
  the base image's packages — the remaining reason `/opt/venv` was chosen over it.

## What stays open

- **Whether the first `django_version` advisory arrives attributed to `uv.lock`**, which confirms
  the triage rule's filter. Observed when it happens.
- **`007`**, whose reversal criterion has fired.

**Settled since the plan closed:** a Dependabot pull request reports a green `test` check. Pull
request #11 (`python-dotenv` 1.2.2 → 1.2.3) passed `test` on both of its runs, `32372238069` and
`32372242913`, which is the proof the generated `SECRET_KEY` works for Dependabot-triggered runs.
