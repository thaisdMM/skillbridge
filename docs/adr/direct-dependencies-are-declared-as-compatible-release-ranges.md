# Direct Dependencies Are Declared as Compatible-Release Ranges, and `uv.lock` Pins Them

**Date:** 2026-10-19
**Status:** Accepted — supersedes the `==` pin rule in
[uv-manages-the-django-project-from-django-version.md](uv-manages-the-django-project-from-django-version.md).
**Applies to:** `django_version/pyproject.toml`, `django_version/uv.lock`, `.github/dependabot.yml`.

## Context and Problem Statement

Every direct dependency carried an exact `==` pin in `pyproject.toml`, on the reasoning that the
Docker image must install the same versions every time. The image and CI install with
`uv sync --locked`, which fails when `uv.lock` disagrees with `pyproject.toml` and otherwise
installs exactly what `uv.lock` records. Reproducibility therefore comes from the lock file; the
`==` pins only repeated it.

The repetition had a cost. Every patch release needed a manifest edit, so Dependabot opened one pull
request per package, each touching the same two files. A security update for Django — the
installed `6.1` falls inside an advisory's `>= 6.1a1, < 6.1.1` range — failed three times in
a row as `dependency_file_not_resolvable`, and no fix pull request was opened.

## Considered Options

* Keep exact `==` pins
* Lower bound only (`>=`)
* Compatible-release ranges (`~=X.Y.Z`, i.e. `>=X.Y.Z, <X.(Y+1)`)

## Decision Outcome

Chosen option: **compatible-release ranges**.

* Every entry under `[project].dependencies` and `[dependency-groups].dev` is declared `~=X.Y.Z`.
  The lower bound is the oldest version the project accepts; `uv.lock` holds the exact version.
* `uv sync --locked` stays the install command in the image and CI.
* `.github/dependabot.yml` sets `versioning-strategy: lockfile-only` for the `uv` ecosystem:
  patch releases arrive as `uv.lock`-only pull requests.
* `>=` alone was rejected: a feature release (Django `6.2`, a `ruff` `0.x` minor that changes lint
  rules) could enter through any `uv lock`, without anyone deciding it.

### Consequences

* Good, because a patch release no longer edits `pyproject.toml`, and the image stays reproducible
  through `uv.lock`.
* Good, because raising a lower bound remains an explicit act when a fix must be guaranteed — as
  `Django~=6.1.1` guarantees the patched release.
* Bad, because `lockfile-only` makes Dependabot ignore releases outside a range. Moving to the next
  feature release is a manual edit of the range, and nothing announces that one exists.
* Neutral, because whether the ranges also clear the `dependency_file_not_resolvable` failure is not
  established. The next advisory against a `django_version` dependency settles it.
