# Technical Debt — Every development dependency lives in one `dev` group, not in named groups

**Status:** deferred
**Date recorded:** 2026-08-17
**Area:** `[dependency-groups]` in `django_version/pyproject.toml`
**Applies to:** the test toolchain (`pytest`, `pytest-django`, `pytest-cov`) and every
quality and security tool the toolchain plan adds (`ruff`, `mypy`, `django-stubs`)
**Related:** decision D5 in `docs/plan/plan_toolchain-ci-security_2026-08-15.md` and its
2026-08-17 amendment, which chose the single group and declined both `uvx` and
`required-version`; D6, which decides that CI installs on the runner in a single job

## The gap

Every development dependency is declared under one `dev` group. A reader of
`pyproject.toml` cannot tell from the file which packages the test suite needs, which the
linter needs, and which exist only for the security checks. Nothing installs a subset:
every environment that is not production installs all of them.

The alternative — named groups (`test`, `lint`, `security`) with `dev` including them via
`include-group` — is what makes that distinction legible, and it is what would let a CI job
install only what its own step needs.

## Why it is deferred, not implemented

**The saving it would buy does not exist yet.** Named groups pay off when CI runs separate
jobs that each install a subset. `.github/workflows/ci.yml` has exactly one job, `test`, and
whether it is ever split is undecided. Choosing named groups now would be organising the
dependency file around a CI shape that does not exist — the same reasoning D5 used when it
first took this decision.

**A misclassification is silent, and more buckets multiply the chance of one.** Nothing
warns when a linter is added without the group flag and lands in the production dependency
set. That is precisely the defect the toolchain plan was correcting: `requirements.txt`
carried `pytest` and its four transitive dependencies while being described as production
only. A single `dev` group makes classification a binary question — *does this run in
production?* — where the answer is never genuinely ambiguous. Four buckets introduce
questions like *is `django-stubs` lint or test?*, which have no correct answer.

**The user stated the intent to move once classification is habitual.** This entry records
that intent so it survives the plan.

**Delivery speed is part of the reason, and it is legitimate at MVP stage.** This is a
deliberate deferral, not an oversight.

## What the migration actually costs, so it is not overestimated

Moving lines between tables in one file, plus `uv lock`. **Nothing outside
`django_version/pyproject.toml` changes** — not the `Dockerfile`, not `ci.yml`, not the hook
configuration — because `uv sync` includes the `dev` group by default and would continue to,
with `dev` declared as including the named groups.

## Reversal criteria

Any one of these makes the deferral wrong:

1. **CI is split into more than one job** — a lint job, a type-check job, a build job. At
   that point each job installs a subset, and the named groups stop being documentation and
   start being a measured saving in install time.
2. **A package is discovered in the wrong set.** One misclassification found in review is
   evidence that the binary question is no longer being asked, which is the only thing
   keeping the single group honest.
3. **The dev group passes roughly a dozen packages.** The toolchain plan takes it to
   about seven. Past a dozen, the file stops being readable at a glance, which is the
   condition the single group depends on.
4. **A dependency is needed by exactly one tool and by nothing else**, and its presence in
   every developer environment becomes a question someone has to ask.

## What to do when one of them fires

1. Declare `test`, `lint` and `security` groups, and keep `dev` as a group that includes
   them, so `uv sync` with no arguments still installs everything and no invocation anywhere
   has to change.
2. **Verify `include-group` against uv's documentation for the pinned version first.** D5
   recorded that the syntax was never checked, and it is the one mechanism the migration
   depends on.
3. Move the packages, run `uv lock`, and confirm the image and CI still install the same set
   as before — the migration should be a no-op in what ends up installed.
4. Only then, if CI has been split, narrow the individual jobs to `--only-group`.
