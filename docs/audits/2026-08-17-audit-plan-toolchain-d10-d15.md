# Audit — `docs/plan/plan_toolchain-ci-security_2026-08-15.md`, decisions D10–D15 and the remainder

**Date**: 2026-08-17
**Persona**: Auditor (read-only). No project file was modified; this report and its Portuguese
counterpart are the only files written.
**Primary target**: the **open** decisions **D10 to D15** of
`docs/plan/plan_toolchain-ci-security_2026-08-15.md`, plus the entries added on 2026-08-17
that condition them (**D16**, and the deferrals listed under *Planning state*).

**Out of scope for this pass**, because the previous audit covered them and the user has since
closed every item it raised:

- **D1** — adoption of `uv`. Premise. No evidence was found against it in this session either.
- **D2–D9a** — audited by `docs/audits/2026-08-16-audit-plan-toolchain-d2-d9a.md`; all 5 Issues
  and all 9 Open Decisions from that pass are recorded as closed in the plan's *Planning state*.
  They are re-examined here **only where a D10–D15 outcome would change them** — which happens
  twice, and both are flagged.

**The question this audit answers.** The same one the previous pass answered for the closed
decisions, now asked of the open ones: given that `uv` is adopted and the stack is being
updated, is the option space the plan records for D10–D15 the *complete* one, or was it
inherited from the superseded plan and never widened?

---

## Evidence legend

Every finding below carries one or more tags. **Nothing in this report is asserted from
training data.**

| Tag | Meaning |
| --- | --- |
| `[WEB]` | Read from official documentation or an authoritative API **in this session**. URL given. |
| `[MEASURED]` | A command executed on this machine in this session. Output shown or quoted. |
| `[FILE]` | Read from a file in this repository in this session. |
| `[REASONING]` | My inference from the above. Not a citation. Marked wherever it appears. |
| `[TRAINING]` | Stated from model training data. **Used nowhere in this report as the basis of a finding.** |

**Disclosure of state changed by this session.** Three commands wrote outside the project:
`uvx` populated the `uv` cache with disposable tool downloads (authorised in the prompt);
`docker run --rm python:3.14.6-slim id` pulled that public base image into the local Docker
image cache; and two scratch files were written to the session scratchpad. **No file in the
repository, no container, and no project environment was modified.**

---

## Section 0 — Version reality for the tools D10–D15 choose between

Read from the PyPI JSON API and the GitHub REST API on 2026-08-17. `[WEB]` `[MEASURED]`

| Tool | Latest release | Date | Relevance |
| --- | --- | --- | --- |
| `mypy` | **2.3.1** | 2026-08-15 | D10 option A |
| `django-stubs` / `-ext` | **6.1.0** | 2026-08-12 | D10 option A |
| `ty` (Astral) | **0.0.72** | 2026-08-14 | D10 option B |
| `pyright` | 1.1.411 | 2026-06-25 | D10 option C |
| `basedpyright` | 1.39.10 | 2026-08-13 | D10 option C |
| `pyrefly` (Meta) | **1.2.0** | 2026-08-01 | D10 option D — **not in the plan** |
| `pytest-cov` | **7.1.0** | 2026-03-21 | D11 option A |
| `coverage` | 7.15.4 | 2026-08-06 | D11 option B |
| `bandit` | 1.9.4 | 2026-02-25 | D12 option B |
| `ruff` | 0.16.3 | 2026-08-13 | D12 option A (already adopted by D9) |
| `gitleaks` | v8.30.1 | 2026-03-21 | D13 |
| `trufflehog` | v3.97.0 | 2026-08-14 | D13 — **not in the plan** |
| `detect-secrets` | 1.5.0 | **2024-05-06** | D13 — effectively dormant, see O6 |
| `pre-commit` | 4.6.2 | 2026-08-10 | D14 option A |
| `lefthook` | v2.1.10 | 2026-07-08 | D14 option B |
| `prek` | **0.4.14** | **2026-08-17** | D14 option C — **not in the plan** |
| `pip-audit` | 2.10.1 | 2026-06-10 | deferred dependency-audit decision |
| `uv` | 0.12.5 | 2026-08-14 | ships `uv audit` — see Open Decision 7 |

Sources: `https://pypi.org/pypi/<pkg>/json`; `gh api repos/<owner>/<repo>/releases/latest`.

### django-stubs support matrix, read from upstream `[WEB]`

`https://raw.githubusercontent.com/typeddjango/django-stubs/master/README.md`, verbatim rows:

| django-stubs | Mypy version | Django version | Django partial support | Python version |
| --- | --- | --- | --- | --- |
| 6.1.0 | 1.13 - 2.3 | 6.1 | 6.0, 5.2 | 3.11 - 3.14 |
| **6.0.9** | 1.13 - 2.3 | **6.0** | 5.2, 5.1, 5.0 | 3.10 - 3.14 |
| 6.0.8 | 1.13 - 2.3 | 6.0 | 5.2, 5.1, 5.0 | 3.10 - 3.14 |

The same page states that mypy is the only checker receiving *"full and complete support with
multiple advanced features"*, and that **Pyright, Pyrefly and Ty each have "basic support,
checked in CI"** — the stubs are consumed, the mypy plugin is not.

### Two baselines measured on this codebase, not estimated

Both are the numbers D10 and D12 need and neither the plan nor any prior audit has.

**Type checking `[MEASURED]`** — `mypy 2.3.1` + `django-stubs[compatible-mypy] 6.1.0` +
`Django 6.1`, run disposably via `uvx -p 3.14` from `django_version/`, default (non-strict)
settings, plugin enabled with `django_settings_module = "config.settings"`, over
`accounts profiles config manage.py`:

```
Found 102 errors in 14 files (checked 68 source files)
```

Wall time ≈ 7 s including download. Distribution:

| Area | Errors |
| --- | --- |
| `accounts/tests/` | 72 |
| `profiles/tests/` | 12 |
| `accounts/admin.py` | 12 |
| `accounts/models/base.py` | 4 |
| `profiles/admin.py` | 1 |
| `config/settings.py` | 1 |
| **Production code total** | **18** |
| **Test code total** | **84** |

By error code: `arg-type` 61, `attr-defined` 20, `return-value` 7, `misc` 7, `assignment` 3,
`union-attr` 2, `var-annotated` 1, `override` 1.

**The single most important fact in that table:** 61 of the 102 errors are `arg-type`, and
almost all of them are one pattern — `Model.objects.create_user(**{**valid_user_data, "field":
value})`. That pattern is not incidental. It is **mandated** by `.claude/rules/testing.md`
(*"Merging and overriding in tests"* — *"use double-asterisk unpacking with dict merge"*) and by
the `dict[str, str | bool]` return annotations the same file prescribes. mypy cannot narrow a
`dict[str, str | bool]` splat against a signature of `(email: str, name: str, password: str |
None)`. **D10's real cost is therefore not "fix 102 errors" — it is a collision between a type
checker and a testing convention this project has written down as a rule.** `[MEASURED]`
`[FILE]` `[REASONING]` for the causal link.

**Static security analysis `[MEASURED]`** — run from `django_version/`:

| Tool | Whole project | Production code only (tests excluded) |
| --- | --- | --- |
| `uvx ruff@0.16.3 check --select S` | 356 (355 × `S101`, 1 × `S106`) | **0 — `All checks passed!`** |
| `uvx bandit@1.9.4 -r accounts profiles config manage.py` | 363 (355 × `B101`, 7 × `B105`, 1 × `B106`) | **0** |

Rule-inventory comparison, computed from each tool's own registry `[MEASURED]`: ruff exposes
**73** `flake8-bandit` (`S`) rules; bandit exposes **75** distinct IDs (42 plugin tests + 33
blacklist entries). By code number the divergence is four bandit IDs with no `S` counterpart —
`B613` trojansource, `B614` pytorch-load, `B615` huggingface-unsafe-download, `B703`
django-mark-safe — and two `S` codes with no bandit counterpart (`S320`, `S410`). `B703` is
covered by ruff under a different number (`S308 suspicious-mark-safe-usage`), so the genuine
bandit-only set for a Django project is **three rules, two of which are ML-framework checks.**
Django-specific coverage is present in both: `S610 django-extra`, `S611 django-raw-sql`,
`S308 mark-safe`.

One real behavioural difference was found, and it is inside tests: bandit's `B105` flags
`"password": "SecurePass@123"` inside dict literals (7 hits, all in `conftest.py` and
`test_base.py`); ruff's `S105` flags none of them. Both agree on the single keyword-argument
case (`B106`/`S106`, `accounts/tests/conftest.py:81`). `[MEASURED]`

---

# Issues — action required

## Issue 1 — D16 rejects staying on Django 6.0 partly on a django-stubs fact that is wrong

**What.** D16 states: *"`django-stubs` 6.1.0 lists Django 6.1 under full support and Django 6.0
under partial support; **6.0.8 is the last release with full 6.0 support**."* It is not.
**`django-stubs 6.0.9` was published on 2026-08-07** — ten days before the entry was written —
and the upstream compatibility matrix lists it with **Django 6.0 under full support**, mypy
1.13–2.3, Python 3.10–3.14. `[WEB]` `[MEASURED]`

```
$ curl -s https://pypi.org/pypi/django-stubs/json   # release dates
6.0.7 2026-07-14
6.0.8 2026-08-06
6.0.9 2026-08-07
6.1.0 2026-08-12
```

**Where.** `docs/plan/plan_toolchain-ci-security_2026-08-15.md`, D16, section *"Why the upgrade
rather than staying on 6.0"*, second reason; and the *Alternatives considered* bullet that
rejects "Patch level only (Django 6.0.8)" on the same ground.

**Rule violated.** The plan's own *Evidence discipline* section — *"Every mechanism is verified
in the current session against … official documentation for the pinned version"* — and
`django_version/CLAUDE.md` Rule 9.

**Why it matters.** D16 offers two reasons for jumping a minor version. The first — Django 6.0
mainstream support ended **2026-08-04**, 6.1 is supported to April 2027 `[WEB]`
(`https://www.djangoproject.com/download/`) — is **correct and survives**. The second, that
staying on 6.0 *"forces D10 to choose between an older stubs release and partial support"*, is
false: `django-stubs 6.0.9` is current, fully supports Django 6.0, and supports the same mypy
and Python ranges as 6.1.0. **The outcome of D16 is very likely unaffected. The evidence behind
it is not**, and D10 is about to be decided on top of that sentence.

**Direction.** The entry needs the correction, not a reversal — the support-lifecycle argument
carries it alone. The pattern to follow is D3's own 2026-08-17 amendment, which kept the outcome
and re-argued the reason after a documentation claim was found to be backwards.

---

## Issue 2 — D10 describes the `django-stubs` coupling in a shape that is both too wide and too narrow, and the measured shape changes where mypy can run

**What.** D10's open-item text says the plugin *"imports the module named by
`django_settings_module`; `config/settings.py` calls `load_dotenv` and raises `ValueError` …
**so in any context without `.env` or the environment variables mypy aborts**"*. Two corrections,
in opposite directions.

**(a) Too wide.** `config/settings.py:6-9` is
`BASE_DIR = Path(__file__).resolve().parent.parent` followed by
`load_dotenv(BASE_DIR / ".env")` `[FILE]`. That path is **absolute and derived from the settings
file's own location**, so the working directory is irrelevant — a hook invoked from the
repository root resolves `.env` exactly as CI does. The failing context is not "any context
without `.env`"; it is "a machine where `django_version/.env` does not exist *and* `SECRET_KEY`
is not exported" — a fresh clone, or CI if the secret is ever missing. That is narrower, and it
matters because the working-directory anxiety that shaped D2 and D14 does **not** apply here.

**(b) Too narrow, and this is the load-bearing half.** The plugin does not merely *import*
settings; it initialises the Django app registry, which imports the configured database backend.
Measured — the same probe, with `django-stubs`, `django` and `python-dotenv` present but no
psycopg `[MEASURED]`:

```
error: INTERNAL ERROR -- ...
Error constructing plugin instance of NewSemanalDjangoPlugin
  File ".../django/db/backends/postgresql/base.py", line 30, in <module>
    raise ImproperlyConfigured("Error loading psycopg2 or psycopg module")
```

Adding `psycopg[binary]` and `argon2-cffi` made it run and produce the 102-error baseline.

**Where.** `docs/plan/plan_toolchain-ci-security_2026-08-15.md`, *Planning state* → *Open* → D10.

**Rule violated.** `django_version/CLAUDE.md` Rule 2 (read the file, do not pattern-match) and
the plan's *Evidence discipline*.

**Why it matters.** It decides **where a type-check step can exist at all**. A mypy run needs
the project's *entire production dependency set installed*, not the stubs. Three consequences
the plan has nowhere: the check works in the image (D4 installs everything) and on the CI runner
(after `uv sync --locked`); it works in a hook **only** if the hook executes inside the project
environment (`uv run …`), which is exactly the axis D14 is deciding on; and it can never be a
standalone `uvx mypy` step. It also means a type-check step **is not free of the database
configuration** even though it never opens a connection.

**Direction.** The D10 entry should state the coupling as measured — app-registry
initialisation, not settings import — and carry it into D14 as a constraint on the hook runner,
the same way D2's *"Why the config location stopped deciding this"* section carries `uv run
--directory` forward.

---

## Issue 3 — D13 plans secret scanning without recording that this repository already has secret scanning and push protection enabled

**What.** D13 frames the decision as gitleaks-or-nothing, and the risk as unscanned commits. The
platform baseline was never read. Measured `[MEASURED]`:

```
$ gh api repos/thaisdMM/skillbridge --jq '{private,security_and_analysis}'
{"private":false,
 "security_and_analysis":{
   "secret_scanning":{"status":"enabled"},
   "secret_scanning_push_protection":{"status":"enabled"},
   "secret_scanning_non_provider_patterns":{"status":"disabled"},
   "secret_scanning_validity_checks":{"status":"disabled"},
   "dependabot_security_updates":{"status":"disabled"}}}

$ gh api repos/thaisdMM/skillbridge/secret-scanning/alerts
[]
```

So a scanner already runs on every push, **already blocks** pushes that match, and currently
reports zero alerts. GitHub's documentation confirms this is free and automatic on public
repositories: *"Secret scanning runs automatically for free"* on public repositories, and push
protection *"Stops you from pushing secrets to public repositories on GitHub"* and *"Is enabled
by default"* `[WEB]`
(`https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning`,
`.../about-push-protection`).

**Where.** `docs/plan/plan_toolchain-ci-security_2026-08-15.md`, *Planning state* → *Open* → D13.

**Rule violated.** `AUDITOR.md` / the plan's own *Evidence discipline*: a decision about adding a
control must first establish what control exists. Also `django_version/CLAUDE.md` Rule 1 — the
plan filled a gap ("nothing scans") instead of reading it.

**Why it matters.** It inverts the question. D13 as written asks *"do we add a secret scanner?"*
The real question is *"what does gitleaks catch that GitHub's free tier does not?"* — and that
question has a precise, verifiable answer, which is the second half of the finding: **GitHub's
free public-repository scanning covers provider patterns only.** Scanning for *non-provider*
patterns (private keys, HTTP auth headers, connection strings, generic passwords) is *"available
for organization-owned repositories on GitHub Team with GitHub Secret Protection enabled"*
`[WEB]` — this repository is personally owned and public, so it is **not** available, free or
otherwise, and the `disabled` status above is not a toggle the user can flip.

A Django `SECRET_KEY`, a `DB_PASSWORD`, or the contents of `.env` are exactly the non-provider
class. **The platform layer that is already on would not catch any of them.** That is the gap
D13 should be sized against — not against zero.

**Direction.** D13's entry needs the measured baseline above before its options are weighed. The
option space is laid out in Open Decision 4.

---

## Issue 4 — D15 inherits an acceptance criterion that cannot validate what it claims on this machine

**What.** D15 records that the superseded plan *"decided to add one (UID 1000) with an empirical
check that bind-mounted files stay usable from the host"*, and instructs that the decision be
re-taken because `/opt/venv` now has an owner. The re-take is correct. **The empirical check is
not**, and it is being carried over unexamined.

Docker Desktop on macOS shares the project directory through VirtioFS, and Docker's own release
documentation records that *"VirtioFS filesharing performance was increased by not persisting
(fake) file ownership changes on the host. Calls to `chown` will succeed, but `stat` will not be
affected."* `[WEB]` (`https://docs.docker.com/desktop/release-notes/`). Host UID/GID are not
enforced against the container's user the way they are on native Linux.

**Where.** `docs/plan/plan_toolchain-ci-security_2026-08-15.md`, *Planning state* → *Open* → D15.

**Rule violated.** The plan's *Evidence discipline* — a verification step that passes regardless
of the outcome it claims to test is not evidence. Same class as the tautological-test rule in
`.claude/rules/testing.md` (*"A test must fail if the behavior under test is removed"*).

**Why it matters.** The check will pass on this machine whatever UID is chosen, and will
therefore certify nothing about the environment where the ownership question is real — a Linux
host, the CI runner, or the Phase 5 production image. Confirmed premise, measured `[MEASURED]`:

```
$ docker run --rm python:3.14.6-slim sh -c 'id; cat /etc/debian_version'
uid=0(root) gid=0(root) groups=0(root)
13.6
```

The base image runs as root and ships no non-root user, so D15 is a real change — but its
acceptance criterion has to test the thing that can actually break: `/opt/venv` readability and
`uv sync` writability under the new user, and the ability to write `__pycache__`, `.pytest_cache`
and migration files into the bind mount.

**Direction.** Re-specify the criterion in the entry rather than in the task. The pattern to
follow is D6's amendment 2, which replaced an inherited cost model with two measured facts.

---

## Issue 5 — D2's amendment moves `[tool.coverage.*]` into `pyproject.toml` before D11 has decided whether anything will read three of its keys

**What.** D2 lists `[tool.coverage.*]` among the tables moving into `pyproject.toml`. If D11
selects `pytest-cov`, part of that table is inert: pytest-cov's own configuration documentation
states that it **overrides coverage's `parallel`, `source` and `branch` options**, *"making
those settings in `.coveragerc` pointless when using pytest-cov"* `[WEB]`
(`https://pytest-cov.readthedocs.io/en/latest/config.html`). `branch` in particular has to be
requested as `--cov-branch` on the command line instead.

**Where.** D2, the list of tool tables; and *Planning state* → *Open* → D11.

**Rule violated.** The plan's own reasoning in D2's 2026-08-17 amendment: configuration that
*"looks authoritative and governs nothing"* is the defect that amendment exists to remove. This
is the same failure mode in a different file section.

**Why it matters.** It is small in size and identical in shape to the `pytest.ini` shadowing
finding the plan already treated as load-bearing: a reader (or an agent) sets `branch = true`
under `[tool.coverage.run]`, gets no branch coverage, and nothing warns. The plan states no
ordering dependency between D2 and D11, so this lands silently.

**Direction.** Either decide D11 first, or have D2's entry name which coverage keys move
(`[tool.coverage.report]`, `[tool.coverage.paths]`, `omit`/`exclude_lines`) and which are
delegated to `addopts`. The measurement to settle it belongs to D11, not to a task.

---

# Open Decisions — user choice needed

You asked for my opinion on each. It is given, marked as opinion, with where I may be wrong and
what a legitimate disagreement would look like.

Ground rule applied throughout, from your prompt: *editing `ci.yml`, `Dockerfile`, `pytest.ini`
or `pyproject.toml` is not a con* — the cons below are CI time, real risk, recurring maintenance
or lost capability only.

---

## Open Decision 1 — D10: which type checker, and over what scope

Two questions in one entry. Take the tool first; the scope question applies to whichever tool
wins and is the one carrying the measured cost.

### The tool

**Option A — `mypy` 2.3.x + `django-stubs` 6.1.0 with the mypy plugin**

| Pros | Cons |
| --- | --- |
| The only checker with *"full and complete support"* from django-stubs; the plugin resolves model fields, related managers and settings `[WEB]` | Requires the entire production dependency set installed to run at all (Issue 2) — no standalone invocation |
| Measured on this codebase: runs in ≈7 s, 102 errors, of which only 18 are in production code `[MEASURED]` | mypy 2.0 turned on `--local-partial-types` and `--strict-bytes` by default and dropped `--python-version 3.9`; a major-version upgrade is a behaviour change to absorb `[WEB]` |
| Mature, and the reference the whole Python typing ecosystem is written against | Slowest of the four options; the plugin adds a `django-stubs` + `django-stubs-ext` pin that must track Django |

**Option B — `ty` (Astral)**

| Pros | Cons |
| --- | --- |
| Same house as `uv` and `ruff`: one vendor, one config file, one mental model | Version policy, verbatim: *"ty uses `0.0.x` versioning. ty does not yet have a stable API; breaking changes, including changes to diagnostics, may occur between any two versions"* `[WEB]` |
| 10×–100× faster than mypy and Pyright by Astral's own benchmark `[WEB]` | **No mypy plugin support** — django-stubs gives it *"basic support"* only, so Django-specific inference (managers, field descriptors, settings) is not available `[WEB]` |
| Rich diagnostics, per-file overrides, first-class project support `[WEB]` | A `uv.lock` bump could change what CI enforces — the same risk D9 accepted for ruff, but here without a stable-release floor |

**Option C — `pyright` / `basedpyright`**

| Pros | Cons |
| --- | --- |
| django-stubs checks Pyright in CI, so the stubs are consumed `[WEB]` | No plugin support; same Django-inference loss as B |
| `basedpyright` is a Python-packaged fork, so it installs from PyPI like every other tool here | `pyright` proper ships as an npm package with a Node runtime — a second toolchain in an image D4 keeps deliberately simple |
| Strongest editor story of the four (it is the VS Code Python engine) | Its strict mode is materially stricter than mypy's default; the 18-error production baseline would not transfer |

**Option D — `pyrefly` (Meta), 1.2.0**

| Pros | Cons |
| --- | --- |
| Past 1.0, so unlike `ty` it is not self-declared unstable `[WEB]` | django-stubs gives it *"basic support"* only — same plugin loss as B and C `[WEB]` |
| Fast, Rust, single binary | Smallest ecosystem of the four; least written about, least likely to be the thing a reviewer recognises |
| Migration guides from mypy and pyright exist upstream `[WEB]` | No measurement was taken on this codebase in this session — I would be guessing at its baseline |

**Option E — no type checker in this plan; defer to Phase 3 (DRF)**

| Pros | Cons |
| --- | --- |
| The measured production-code yield is 18 errors, of which several are annotation accuracy rather than defects (O2, O3) | Gives up the one finding that looks like a genuine modelling error (`accounts/admin.py:212`, O2) |
| Serializers and views are where type checking pays; neither exists yet | Type hints are already mandatory in `conventions.md` — nothing verifies them, so the rule is unenforced today |
| Removes the convention collision described below entirely, for now | Deferral has to be recorded in `docs/tech_debt/`, and the decision returns anyway |

**There is no fifth tool.** I looked; `pytype` and `pyre` are not viable choices for a
Python 3.14 project in 2026 and I am not manufacturing options to balance a table.

### The scope, and why it is the real decision

| Option | What it enforces | Measured cost |
| --- | --- | --- |
| **S1 — production code only** (`exclude` tests and migrations) | 18 errors `[MEASURED]` | Small, one sitting. `accounts/admin.py` carries 12 of them |
| **S2 — everything** | 102 errors `[MEASURED]` | 84 of them are in tests, and ~61 are the `**{**valid_data, …}` splat the testing rules *require* |
| **S3 — everything, with tests at a relaxed error set** | between the two | Two configurations to keep coherent |

S2 is the option that has to be understood before it is chosen. The dominant error is not sloppy
test code; it is `.claude/rules/testing.md`'s own prescribed pattern meeting a checker that
cannot narrow a `dict[str, str | bool]` splat. Choosing S2 means either changing that rule
(e.g. `TypedDict` fixtures) or writing a broad `disable_error_code` for tests — and the second is
the shape D9a rejected for ruff (*"scoping a suppression to the rule it is actually about"*).

### My opinion, and it is opinion

**A + S1**: mypy with django-stubs, over production code only, no strict mode, not blocking in
the first commit. The plugin is the entire reason to type-check a Django project — every other
option in the table gives up the Django-aware half and keeps only the generic half. And S1 is
where the measured value is: 18 errors, in the two files (`accounts/admin.py`, `accounts/models/base.py`)
where this project's cleverest code lives.

**Where I could be wrong.** If your priority is a single Astral toolchain and editor speed,
B is defensible and the 0.0.x churn is a real but bounded cost — `uv.lock` pins it. I have not
measured `ty` or `pyrefly` on this codebase, so I cannot tell you what their baselines are; if
that number matters to you, ask for it before deciding.

**Where disagreeing with me is legitimate.** If you intend `tests/` to be type-checked as
first-class code — a defensible position for a portfolio repository — then S2 is right and the
testing convention should change to `TypedDict`, which is a better fixture pattern anyway. That
is a bigger decision than D10 and should be taken as its own, not smuggled in through a type
checker.

---

## Open Decision 2 — D11: coverage measurement, and whether there is a floor

**Option A — `pytest-cov` 7.1.0**

| Pros | Cons |
| --- | --- |
| One flag (`--cov`) in `addopts`; nothing changes about how the suite is invoked | Overrides coverage's `parallel`, `source` and `branch` settings, so part of `[tool.coverage.run]` is inert (Issue 5) `[WEB]` |
| `--cov-fail-under` gives the CI gate directly `[WEB]` | Documented caveat: *"If you change the working directory … you might also need to use `--cov-config`"* — relevant to D14 `[WEB]` |
| Requires `coverage[toml]>=7.10.6` and `pytest>=7`, both already satisfied `[MEASURED]` | One more dependency in the `dev` group than option B |

**Option B — `coverage` 7.15.4 directly (`coverage run -m pytest` + `coverage report`)**

| Pros | Cons |
| --- | --- |
| One dependency instead of two; no plugin between pytest and the measurement | The suite is no longer invoked as `pytest`, so root `CLAUDE.md` Rule 12's canonical command gains a second form |
| Every `[tool.coverage.*]` key is honoured — nothing is overridden | Two commands in CI instead of one step |
| `coverage report --fail-under` is the same gate | Local use is less ergonomic; the habit `docker-compose exec web pytest` stops producing coverage |

**Option C — coverage plus a diff gate (`diff-cover` or equivalent)**

| Pros | Cons |
| --- | --- |
| Solves the real problem of a project with no baseline: enforce coverage on *changed lines*, not on the whole tree | A third tool, and one whose value only appears once pull requests are the workflow — D8 Item 3 has only just added the `pull_request` trigger |
| No arbitrary global threshold has to be invented | Needs a base ref to diff against; on a long-lived feature branch this is fiddly |
| The floor rises by construction as code is written | Adds a second definition of "covered" to explain |

**Option D — measure, report, no gate (the plan's own staged approach), and defer the floor**

| Pros | Cons |
| --- | --- |
| Coverage has never been measured here; a threshold chosen in planning is a number invented from nothing | A metric nobody gates on is a metric nobody reads — the same argument D7 used to reject `continue-on-error` |
| Costs one CI step and no decision | The deferral must be recorded in `docs/tech_debt/` |

**No alternative exists to `coverage.py` itself.** Options A, B and C are all coverage.py with
different front ends. I am not going to invent a competitor.

### My opinion

**A, with D's staging**: `pytest-cov`, wired into `addopts`, reporting to the CI log with **no
`--cov-fail-under` in the first commit**. Then set the floor from the measured number, at or just
below it, so the gate starts green and can only ratchet up. The plan already reached this shape
and it is right; the only thing to add is Issue 5's configuration split.

**Where I could be wrong.** I did not measure coverage — running it requires installing
`pytest-cov` in the container, which is a state change I did not have permission for. If the real
number is very low (say under 50 %), option C becomes much more attractive than my
recommendation, because a global floor at 45 % would be a number that certifies nothing.

**Where disagreeing with me is legitimate.** If you want one dependency less and are willing to
type a longer command, B is a clean, defensible choice — and it removes Issue 5 entirely.

---

## Open Decision 3 — D12: static security analysis, tool and scope

This is the decision where measurement, not argument, does the work.

**Option A — ruff's `S` rules (`extend-select = ["S"]`), with `S101` suppressed in tests**

| Pros | Cons |
| --- | --- |
| Zero new dependency, zero new CI step, zero new hook: ruff is already adopted by D9 | **It amends D9.** D9's decision is *"no `select` and no `ignore`"*; this adds `extend-select` and a `per-file-ignores` entry, and that has to be recorded as an amendment, not slipped in |
| 73 `S` rules, including the three Django-specific ones (`S610` extra, `S611` raw SQL, `S308` mark_safe) `[MEASURED]` | Ruff's documentation does not assert parity with upstream bandit — the plan's own verification debt, now partly measured but not closed in general |
| Measured: 0 findings in production code, 355 × `S101` in tests only `[MEASURED]` | `S101` on 355 asserts must be suppressed per-file, or the signal is buried |

**Option B — `bandit` 1.9.4 as a separate tool**

| Pros | Cons |
| --- | --- |
| The reference implementation; "we run bandit" is a legible line in a portfolio README | A second tool, a second config, a second CI step, and a second thing to keep pinned |
| Catches `B105` inside dict literals, which ruff's `S105` misses — 7 hits here, all in test fixtures `[MEASURED]` | Does not auto-discover `pyproject.toml`: needs `-c pyproject.toml` **and** the `bandit[toml]` extra (established by the 2026-08-15 verification, and unchanged) |
| Three checks ruff has no equivalent for: `B613` trojansource, `B614` pytorch, `B615` huggingface `[MEASURED]` | Two of those three are ML-framework checks with no possible relevance to this codebase; measured production yield here is **0** `[MEASURED]` |

**Option C — both**

| Pros | Cons |
| --- | --- |
| Union of coverage, including `B613` and `B105`-in-dicts | Two tools reporting 355 duplicate assert findings on the same files |
| Belt and braces on the one axis where a false negative is expensive | Recurring maintenance of two suppression lists that must not drift apart |
| — | Measured marginal yield on this codebase today: zero findings either tool does not already produce in production code |

**Option D — neither; rely on `check --deploy` (D7) and defer**

| Pros | Cons |
| --- | --- |
| Both tools measure **0** on production code today `[MEASURED]`; the codebase has no `subprocess`, no `eval`, no raw SQL | Insurance is bought before the fire, not after — the value is in the code not yet written (`jobs`, DRF views) |
| D7 already covers the file that actually decides this project's security posture (`config/settings.py`) | Leaves the plan's security block resting on one Django command |
| — | Recorded deferral, another `docs/tech_debt/` entry |

### The scope question, which the plan correctly links to D9a

The superseded plan excluded all of `tests/` to silence one rule. D9a already decided the
principle for ruff: **suppress the rule, not the directory.** Applying it here means
`per-file-ignores` for `S101` (and `S105`/`S106` if fixture passwords are to stay as they are)
under `*/tests/*`, and `config/` **stays in scope** — which repairs the superseded plan's worst
structural gap, where the security block never read `config/settings.py`.

### My opinion

**A.** Ruff's `S` set, `extend-select`, with `S101` (and `S106`) suppressed under `*/tests/*`,
recorded as an explicit amendment to D9. The measured facts decide it: identical production
yield (0 vs 0), near-identical rule inventories (73 vs 75), all three Django-specific checks
present in ruff, and the only real bandit-only findings on this codebase are in test fixtures
that both options suppress anyway. Adding bandit buys `B613` trojansource and two ML checks, at
the price of a second tool with a documented `pyproject.toml` discovery problem.

**Where I could be wrong.** My parity comparison was by rule *number*, plus one spot check
(`B703` → `S308`). Two rules can share a number and differ in what they actually detect — the
`B105`/`S105` divergence I measured is proof that they do. A rule-by-rule behavioural comparison
was not performed and would be a real piece of work.

**Where disagreeing with me is legitimate.** If the goal is a CV artefact that names a
recognised security tool, B has value that no measurement of this codebase can capture, and that
is a legitimate reason. Say so explicitly in the entry if that is the reason, rather than
arguing it on coverage.

---

## Open Decision 4 — D13: secret scanning, sized against a platform layer that is already running

Read Issue 3 first. The baseline is: GitHub secret scanning **and** push protection are already
enabled and blocking, zero alerts, provider patterns only, and the non-provider tier is not
purchasable for a personally-owned repository. `[MEASURED]` `[WEB]`

**Option A — rely on GitHub's push protection alone; add nothing**

| Pros | Cons |
| --- | --- |
| Already on, already blocking, zero configuration, zero maintenance, zero CI time `[MEASURED]` | Covers **provider patterns only** — it would not stop a Django `SECRET_KEY`, a `DB_PASSWORD`, or a pasted `.env` `[WEB]` |
| Runs on the server, so it cannot be bypassed by a developer skipping hooks | Nothing scans *history*; a secret committed before today stays committed |
| No false-positive management on 355 password-shaped test fixtures | The project's realistic leak is exactly the class this misses |

**Option B — `gitleaks` in CI only**

| Pros | Cons |
| --- | --- |
| Catches the non-provider class GitHub's free tier does not `[WEB]` | Detection is post-push: the secret is already on GitHub when CI reports it |
| No hook runner needed, so it is independent of D14 | Adds CI wall-clock on every run |
| Can scan full history in the same tool, once, as a separate job | Needs an allowlist for this project's password-shaped fixtures, which must be maintained |

**Option C — `gitleaks` in hooks *and* CI**

| Pros | Cons |
| --- | --- |
| Blocks before the secret leaves the machine, and catches the bypass case in CI | Requires D14 to be decided first, and couples the two entries |
| The upstream hook's real contract is now known (`pass_filenames: false`, `--staged`), so it can be configured correctly this time | The hook is skippable (`--no-verify`), so CI is still required — the hook is convenience, not the control |
| Same allowlist serves both | Two invocation sites for one tool to keep in step |

**Option D — `trufflehog` v3.97.0 instead of gitleaks**

| Pros | Cons |
| --- | --- |
| Verifies candidate secrets against the issuing provider, which collapses false positives | Verification means outbound network calls from CI — a new egress behaviour in a workflow being hardened |
| Actively released (2026-08-14) `[MEASURED]` | Verification is worth most for provider secrets, which is precisely the class GitHub already covers for free here |
| Broad detector set | Heavier than gitleaks for the same job on a repository this size |

**Option E — `detect-secrets`** — listed only to be dismissed: last release **2024-05-06**
`[MEASURED]`. Not a live option in 2026, and I am not going to pad the table with it.

### The sub-decisions inside D13, which are separate from the tool

1. **A one-time history scan.** The repository has **261 commits** `[MEASURED]`. Scanning it once
   is minutes of work and answers a question that otherwise stays permanently open. This is
   independent of the tool choice and, in my view, worth doing whichever option wins.
2. **The fixture problem.** `accounts/tests/conftest.py` and friends contain literal strings like
   `"SecurePass@123"` — measured as 7 `B105` hits `[MEASURED]`. Any scanner needs an allowlist
   entry, path-scoped, not a global disable.
3. **`.env` is already covered.** The root `.gitignore` carries `.env` and `.env.local`
   unanchored, so they match at any depth `[FILE]` — established by the 2026-08-15 verification
   and re-read this session.

### My opinion

**C if D14 produces a hook runner; B if it does not.** The reason is the measured gap and
nothing else: the platform already blocks the secrets that come with a recognisable provider
prefix, and it structurally cannot block the one this project would plausibly leak. Plus the
one-time history scan, regardless.

**Where I could be wrong.** I did not run gitleaks against this repository — it is a Go binary,
not a `uvx` target, and installing it is a state change I did not have permission to make. So I
cannot tell you its false-positive rate here. If it turns out to fire on every fixture and every
migration, option A plus discipline is a more honest answer than a scanner whose output is
routinely ignored.

**Where disagreeing with me is legitimate.** "Push protection is on, `.env` is gitignored, and I
am the only committer" is a coherent risk position for a solo portfolio project. If you take it,
take it explicitly as a `docs/tech_debt/` entry with that reasoning — not by leaving D13 open.

---

## Open Decision 5 — D14: hook runner, including the option the plan never named

**Option A — `pre-commit` 4.6.2 with `uv run --directory django_version <tool>`**

| Pros | Cons |
| --- | --- |
| The ecosystem standard; the format most upstream tools ship a hook definition for | No per-hook working directory, and it is an acknowledged upstream limitation (issues #466, #1417, #2317, #2951) — the workaround has to be repeated in every hook entry |
| D2 already verified the `uv run --directory` workaround works | Manages its own environments per hook, which duplicates what `uv.lock` exists to pin — the versions in `.pre-commit-config.yaml` and in `uv.lock` are two sources of truth |
| Widely recognised; a reviewer knows what it is | `language: system` was renamed in 4.4.0 with the alias slated for removal — a currency check to carry |

**Option B — `lefthook` v2.1.10**

| Pros | Cons |
| --- | --- |
| First-class `root:` key at the command level, which is exactly the monorepo problem here `[WEB]` | Does not run tools itself — every command is a shell line you write and maintain |
| Single Go binary, fast, no per-hook environment machinery | Smallest Python-ecosystem presence of the three; no upstream hook definitions to reuse (e.g. gitleaks ships a `pre-commit` hook, not a lefthook one) |
| Configuration is legible and explicit | The `root` key is listed in the command-level reference, but its behaviour is **not documented on the page I read** — verify before relying on it `[WEB]` |

**Option C — `prek` 0.4.14 — not considered anywhere in the plan**

| Pros | Cons |
| --- | --- |
| **Drop-in for `pre-commit`**: same `.pre-commit-config.yaml`, same hook repositories `[WEB]` | Version **0.4.14**, first-party but young; released the same day as this audit `[MEASURED]` |
| **Workspace mode solves D2's and D14's core problem directly**: *"Each directory containing a `.pre-commit-config.yaml` file is considered a project … Hooks run within their project's root directory … Only files within the project's directory tree are passed to its hooks"* `[WEB]` | Its ecosystem is pre-commit's, so it inherits pre-commit's two-sources-of-truth version problem unless hooks are declared `local` |
| Uses `uv` internally to build hook environments, which aligns with D1; single Rust binary, no Python runtime dependency `[WEB]` | Smaller community; if it stalls, the exit is back to pre-commit — cheap, since the config format is identical |

**Option D — no hook runner; CI is the gate**

| Pros | Cons |
| --- | --- |
| Zero recurring maintenance, zero commit-time latency, zero new concept | Feedback moves from seconds to a CI round trip |
| Hooks are skippable (`--no-verify`), so CI has to run everything anyway — the hook layer is never the control | `ruff format` in particular is far more pleasant at commit time than as a CI failure |
| For a single-committer repository, the drift a hook prevents is drift you would see in CI minutes later | Nothing catches a secret before it leaves the machine (interacts with Open Decision 4) |

**Nothing exists here that I have omitted.** Plain `.git/hooks` shell scripts are technically an
option and are not a serious one — they are unversioned and not shared by a clone.

### My opinion

**D, or C.** In that order, and the honest reason is the same for both: for a solo developer with
a CI pipeline that this plan is already making comprehensive, a hook runner is a convenience
layer, not a control. If you want the convenience — and `ruff format` at commit time is a real
quality-of-life gain — then **C**, because it is the only option that removes the working-directory
defect at the source instead of routing around it, and because it uses `uv` internally, which is
the toolchain you just chose.

**Where I could be wrong.** `prek` is at 0.4.x and I have not run it. Its workspace claim is read
from its documentation, not measured. If you take it, the acceptance criterion should be
"a mypy hook, invoked from the repository root, finds `django_version/pyproject.toml`" — the
exact defect that made this a decision at all.

**Where disagreeing with me is legitimate.** `pre-commit` on a CV means something; `prek` means
nothing yet. If the repository is a portfolio artefact first, A is a legitimate choice for a
legitimate reason — and D2's `uv run --directory` workaround is already verified, so it costs you
one extra token per hook entry and nothing else.

---

## Open Decision 6 — D15: non-root user in the `Dockerfile`

Read Issue 4 first: the acceptance criterion the plan carries over cannot fail on this machine.

**Option A — add a non-root `USER`, with `/opt/venv` owned by it**

| Pros | Cons |
| --- | --- |
| Standard container hardening, and the base image is root today `[MEASURED]` | `/opt/venv` (D3) must be `chown`ed at build time and stay writable for `uv sync` — one more ordering constraint in the `Dockerfile` |
| The habit is established before Phase 5, when a production image makes it load-bearing | On a Linux host, bind-mounted files written in the container land with the container UID; on macOS VirtioFS this does not surface `[WEB]` — so the real cost is invisible on the machine where it is being developed |
| Cheap to verify properly once the criterion is rewritten | Anything the container writes into the mount (migrations, `__pycache__`, `.pytest_cache`) becomes an ownership question that must actually be tested, not assumed |

**Option B — stay root; revisit when a production image exists**

| Pros | Cons |
| --- | --- |
| `Dockerfile:31` is `runserver` `[FILE]` — D4 already established this is a development image, and D3's environment is already outside the mount | Leaves an obvious, well-known hardening item unaddressed in a repository whose purpose is to demonstrate practice |
| Nothing about the bind-mount workflow changes | The decision returns in Phase 5 anyway |
| Zero risk of the ownership friction above | A reviewer reading the `Dockerfile` sees no `USER` line |

**Option C — non-root *and* revisit D3's system-environment option on the ownership ground**

| Pros | Cons |
| --- | --- |
| D3's own amendment explicitly invites this: *"If it concludes the ownership handling is awkward, revisiting the system-environment option on **that** ground is legitimate"* | Reopens a closed decision, and D3's real discriminator (`uv sync` pruning the base image's `pip`/`setuptools`) is unaffected by the ownership question |
| Would collapse two configuration concerns into one | D3 flagged that pruning behaviour as *"reasoning, not measurement"* — reopening on ownership means also measuring the pruning claim |
| — | More work than the problem justifies at this stage |

### My opinion

**A, with the acceptance criterion rewritten per Issue 4.** The change is small, it is correct
practice, and the plan's own scope boundary does not exclude it. But the criterion must test what
can actually break — `/opt/venv` readable and `uv sync`-writable as the new user, and the
container able to write `__pycache__`, `.pytest_cache` and a generated migration into the bind
mount — rather than "files stay usable from the host", which macOS will certify regardless.

**Where I could be wrong.** I did not build an image with a non-root user, so I have not measured
the friction. It may be nil, or it may be a `chown -R` on `/opt/venv` plus one surprise.

**Where disagreeing with me is legitimate.** B is entirely defensible on D4's own logic: this is
a development image, `runserver` is in the `CMD`, and the hardening that matters happens in
Phase 5 with a real production stage. If you take B, record it as tech debt with that reasoning.

---

## Open Decision 7 — dependency auditing: the deferred `pip-audit` step now has an option the plan does not know about

Not numbered in the plan. D8 Item 3 defers the `schedule:` trigger *"until the `pip-audit` task
is drafted"*, and `pip-audit` itself is an unexamined inheritance from the superseded plan — the
same class of narrowing this audit was commissioned to find.

**What changed.** Current `uv` ships an `audit` subcommand — *"Audit the project's
dependencies"* — listed in uv's CLI reference with no preview or experimental marker `[WEB]`
(`https://docs.astral.sh/uv/reference/cli/`). Its release history shows it querying the **OSV**
service, with JSON output added in 0.11.15 and SARIF output in 0.11.22 `[MEASURED]`
(`gh api repos/astral-sh/uv/releases`). The `uv` installed on this machine is **0.10.9** and
predates it, so I could not run it `[MEASURED]`.

| Option | Pros | Cons |
| --- | --- | --- |
| **`pip-audit` 2.10.1** | Purpose-built, PyPA-maintained, well known; queries PyPI's advisory database | One more `dev` dependency and one more pin; the superseded plan chose it without comparing anything |
| **`uv audit`** | Zero new dependency — `uv` is already in the image and on the runner under D6; reads `uv.lock` natively; SARIF output feeds GitHub code scanning `[WEB]` | Newer surface than `pip-audit`; **not measured by me**; ties the audit step to the `uv` version pinned |
| **Dependabot alerts + security updates** | Server-side, no CI time, opens PRs with the fix; measured today as `dependabot_security_updates: "disabled"` `[MEASURED]` — it is off, and turning it on is free | Only covers what Dependabot parses; D8's amendment creates `.github/dependabot.yml` for `github-actions` only, so the Python ecosystem would need adding |
| **Two of the above** | Server-side detection plus a build gate | Two alert streams for the same advisories |

**The fact that most changes the shape of D8 Item 3's deferral:** Dependabot alerts arrive
without a workflow run at all. The scheduled-run question exists because *"`pip-audit` on `push`
only detects a newly published advisory at the next push"*, and the repository's measured gap
between runs reached 47 days. **Dependabot removes that latency without a `schedule:` trigger**,
which means the deferred decision may dissolve rather than need answering.

### My opinion

**Enable Dependabot security updates and extend `.github/dependabot.yml` to the Python
ecosystem, and use `uv audit` as the CI gate** — subject to one verification I could not perform:
run `uv audit` against the real `uv.lock` once it exists, confirm its exit code on findings, and
compare its output against one `pip-audit` run before committing to it.

**Where I could be wrong.** I have not executed `uv audit`. Everything above is documentation and
release-note reading. If it turns out to lack a usable exit code or ignore mechanism,
`pip-audit` remains the right answer and nothing is lost.

---

# Observations / Learning Notes — no action required

**O1 — current `uv` also ships `format` and `check` subcommands.** *"Format Python code in the
project"* and *"Run checks on the project"* `[WEB]`. Neither changes D9's rule-set decision; they
are invocation conveniences. Worth knowing before someone rediscovers them as a "new option".

**O2 — mypy surfaced one production finding worth a look, and it is not a runtime bug.**
`accounts/admin.py:212` and `:214` call `queryset.filter(profile__isnull=…)` on a parameter
annotated `QuerySet[BaseUser]`, and mypy reports *"Cannot resolve keyword 'profile' into field"*
`[MEASURED]`. `BaseUser` is abstract and carries no `profile` reverse relation; at runtime the
queryset is a `Freelancer` or `Client` one, which does. **The annotation is inaccurate; the code
works.** Per `PLANNER.md`'s rule against absorbing new findings, this is a signal for an Auditor
session on `accounts/admin.py`, not a task here.

**O3 — four of the 18 production errors are one small fix.** `accounts/models/base.py:85-96`
reports `"_T" has no attribute "set_password" / "set_unusable_password" / "id"` and one
`return-value` `[MEASURED]`. The manager's type variable is unbound; a bound on the `TypeVar`
resolves all four. Recorded so D10's cost is not overestimated.

**O4 — `config/settings.py:23` needs one annotation.** `ALLOWED_HOSTS = []` produces
*"Need type annotation"* `[MEASURED]` `[FILE]`. Phase 5 rewrites that line anyway.

**O5 — settings raises at import time, and every tool inherits it.** `config/settings.py:17-18`
raises `ValueError` when `SECRET_KEY` is absent `[FILE]`. That is a deliberate fail-fast and not
a defect, but it means any tool that imports settings — the django-stubs plugin, `manage.py
check`, a future `drf-spectacular` schema generation step — fails with an application exception
rather than a tool diagnostic. Worth remembering when a CI step fails confusingly.

**O6 — `detect-secrets` is dormant.** Last release 2024-05-06 `[MEASURED]`. Listed in
Open Decision 4 only so nobody proposes it later as an unexamined option.

**O7 — the history scan is cheap.** 261 commits `[MEASURED]`. Whatever D13 decides, a one-time
full-history scan is a bounded piece of work, not a project.

**O8 — `secret_scanning_validity_checks` is `disabled` and I did not establish whether it is
available here.** `[MEASURED]` for the status; **not verified** for the entitlement. Given that
non-provider patterns are org-and-paid-only, I would expect the same, but I did not read a page
that says so and I am not asserting it.

**O9 — D14 is greenfield.** No `.pre-commit-config.yaml`, no `lefthook.yml`, no `.prek` config
exists anywhere in the repository `[MEASURED]`. There is no migration cost in any direction,
which makes the "drop-in compatibility" advantage of `prek` worth less here than it would be
elsewhere — and correspondingly makes `lefthook` cheaper than it would be for an existing setup.

**O10 — the base image confirms D15's premise and nothing more.** `python:3.14.6-slim` is Debian
13.6 and runs as `uid=0(root)` with no non-root user provided `[MEASURED]`.

**O11 — `.gitignore` additions listed under *Items that need no decision* depend on D10.**
`.mypy_cache/` is the right entry only if D10 picks mypy; `ty`, `pyright` and `pyrefly` write
different cache directories. One line, but it is downstream of a decision the plan lists as open.

---

# Decisions that survive

Re-examined from the D10–D15 angle — that is, asking whether an open decision's outcome could
force one of them to move.

| Decision | Why it survives this pass |
| --- | --- |
| **D16 (outcome)** — Django 6.1, Python 3.14.7, pytest-django 4.14.0, in a second commit | The support-lifecycle argument is verified and sufficient on its own: 6.0 mainstream support ended **2026-08-04**, 6.1 runs to **April 2027** `[WEB]`. Every backwards-incompatible item in its table was checked against the code by the Planner, and I found no reason to dispute the method. Only the django-stubs sub-argument is wrong (Issue 1), and it was never the load-bearing one. The two-commit sequence is the right instrument. |
| **D2 (location)** — `pyproject.toml` in `django_version/` | Nothing in D10–D15 argues for moving it. If D14 selects `prek`, its workspace mode reinforces the choice — a per-project config directory is exactly what it expects. Issue 5 is a gap in what the file contains, not in where it lives. |
| **D4** — the image installs development dependencies | This is what makes D10, D11 and D12 runnable at all. Issue 2's measured finding strengthens it: a type-check step needs the full runtime dependency set, which only D4's image and the CI runner provide. |
| **D5** — a single `dev` group | Four more tools landing in one group is exactly the case D5 was argued for. The `uvx` rejection in its amendment is reinforced by Issue 2: `uvx mypy` cannot work here, because the plugin needs the project's own dependencies. |
| **D7** — Django's own two checks | Untouched by every option in D10–D15, and it remains the only part of the security block that reads `config/settings.py` if D12 goes to option D. |
| **D9a** — suppress the rule, not the directory | Directly reusable as the scope principle for D12, and the plan already links them. Applying it consistently is the cheapest way to keep one principle in this plan rather than two. |
| **D8 Item 2 amendment** — pin every action, add `dependabot.yml` | Open Decision 7 extends it (add the Python ecosystem, enable security updates) rather than disputing it. |

**One closed decision would be amended, not reopened, by an open one.** If D12 goes to option A,
**D9's "no `select` and no `ignore`" is no longer literally true** — it becomes "the default set
plus `extend-select = ["S"]`, with `per-file-ignores`". That is a legitimate amendment and it must
be written as one; leaving D9's text unqualified while `pyproject.toml` contains an
`extend-select` is the documentation-versus-reality drift this whole replanning exists to stop.

---

# Handoff — next session

**What was audited.** The open decisions **D10–D15** of
`docs/plan/plan_toolchain-ci-security_2026-08-15.md`, plus **D16** and the deferrals recorded
under *Planning state*, against: the real files (`Dockerfile`, `docker-compose.yml`,
`requirements.txt`, `pytest.ini`, `config/settings.py`, `ci.yml`, root `.gitignore`,
`django_version/.dockerignore`); official documentation read this session for django-stubs, ty,
pyrefly, pytest-cov, coverage, uv, GitHub secret scanning, GitHub push protection, Docker
Desktop, lefthook, prek and Django's release schedule; the PyPI and GitHub REST APIs; and
measurements executed on this machine — a full mypy + django-stubs baseline, a ruff-`S`-versus-
bandit comparison including rule-inventory diffs, and the repository's live GitHub security
settings.

**Counts.** 5 Issues · 7 Open Decisions · 11 Observations · 7 decision entries that survive.

**The two Issues that change what a decision *is*, rather than its wording:** Issue 2 (D10's
coupling is app-registry initialisation, which constrains D14) and Issue 3 (D13 is sized against
zero when a blocking platform layer is already running). Issue 1 corrects evidence behind a
decision whose outcome stands. Issues 4 and 5 are one-line gaps with silent failure modes.

**Three options the plan had never put on the table**, which is what this audit was commissioned
to find: **`prek`** for D14 (drop-in on pre-commit's format, and its workspace mode removes the
working-directory defect at source), **`uv audit`** for the deferred dependency-audit step (zero
new dependency), and **GitHub's already-enabled push protection** as the baseline D13 must be
measured against rather than the blank slate it assumes.

**What the next session should attach.**

- `docs/plan/plan_toolchain-ci-security_2026-08-15.md` (the plan being revised)
- this audit and its Portuguese counterpart
- `docs/audits/2026-08-16-audit-plan-toolchain-d2-d9a.md` (the previous pass, for D9/D9a's
  reasoning, which D12 reuses)
- `django_version/config/settings.py`, `django_version/Dockerfile`, `django_version/pytest.ini`
- `.claude/rules/testing.md` — **required** if D10 is decided at scope S2, since the collision is
  with that file's mandated fixture pattern
- `.github/workflows/ci.yml`

**Recommended next persona.** Planner, to take the seven Open Decisions with the user and amend
D16, D2 and D9 in place while writing D10–D15. Nothing here is Developer work: none of the seven
has a single correct answer, and two of the five Issues change what a task would be.

**One measurement the next session should commission before deciding D11**, because I could not
take it without permission to change container state: run the suite under coverage once and
report the real number. Option C in Open Decision 2 becomes the right answer instead of option A
if that number is low.
