# The Django Project Is Managed by `uv`, From a `pyproject.toml` Inside `django_version/`

**Date:** 2026-08-19
**Status:** Accepted
**Applies to:** `django_version/pyproject.toml`, `django_version/uv.lock`.

## Context and Problem Statement

The project installed its dependencies with `pip` from `requirements.txt`. `uv` was preferred:
dependencies declared in one file with their exact versions locked, and a simpler way to run the
tools the project adds, `ruff` and `mypy` among them.

## Considered Options

* Keep `pip` with `requirements.txt`
* Move to `uv` with `pyproject.toml` and `uv.lock`

## Decision Outcome

Chosen option: **`uv` with `pyproject.toml` and `uv.lock`**, both in `django_version/`.

* `requirements.txt` and `pytest.ini` are deleted.
* Production dependencies are under `[project].dependencies`, development tools under a single
  `dev` group, each with an exact `==` pin. `uv.lock` is committed.
* The image and CI install with `uv sync --locked`.
* Tool configuration lives in the same file: `[tool.pytest]`, `[tool.coverage.run]`,
  `[tool.mypy]`, `[tool.django-stubs]`, `[tool.ruff]`.
