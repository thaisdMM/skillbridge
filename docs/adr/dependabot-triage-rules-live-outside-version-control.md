# Dependabot Alerts Are Triaged by Repository Rules That Live Outside Version Control

**Date:** 2026-08-21
**Status:** Accepted — one filter value is unverified; see *Consequences*.
**Applies to:** the three custom rules under `Code security → Dependabot rules`, the
repository-level `dependabot_security_updates` setting, and `.github/dependabot.yml`.

## Context and Problem Statement

Dependabot security updates open a fix pull request for every alert that has a patch, and they are
a repository-wide switch: `.github/dependabot.yml` aims *version* updates at a directory, but it
cannot aim security updates at anything.

This monorepo holds an active `django_version/` and a closed `oop_version/`. With security updates
on, the closed directory — pinned to old versions nobody will ever raise — produced a pull request
per advisory and a red CI run with each. Turning them off stopped that, and took the fix pull
requests for the active directory with it.

A third problem surfaced when `django_version/requirements.txt` was replaced by `pyproject.toml`
and `uv.lock`. The dependency graph kept the deleted manifest: thirty hours after the file left the
default branch, four alerts computed from it were still open — against a package the new lock file
already pins at a patched version.

## Considered Options

* Leave security updates enabled, and dismiss the closed directory's alerts by hand
* Leave them disabled, and let the monthly version-update cycle be the only fix path
* Leave them disabled, and restore fix pull requests for one directory through custom rules
* Filter those rules on `Ecosystem` rather than on manifest path

## Decision Outcome

* Chosen option: **three repository-level auto-triage rules, security updates left disabled.**

  | Rule | Filter | Action |
  | ---- | ------ | ------ |
  | `django-version-dead-manifest` | `manifest:django_version/requirements.txt` | Dismiss, indefinitely |
  | `oop-version-closed-directory` | `manifest:oop_version/requirements.txt` | Dismiss, indefinitely |
  | `django-version-security-prs` | `manifest:django_version/uv.lock` | Open a pull request |

* **Security updates stay disabled** because an *open a pull request* rule takes effect only on a
  repository that has them off. Re-enabling them disables the third rule and restores the closed
  directory's pull requests.

* **Both dismiss rules are indefinite.** The alternative, *until a patch is available*, lifts a
  dismissal the moment an upstream patch exists — which, for a directory nobody will update and a
  manifest that no longer exists, is exactly when the alert would come back.

* **`Ecosystem` was rejected on measurement:** every alert in this repository reports `pip`, in both
  directories, so it cannot tell them apart. Manifest path is the only filter that can.

* **`uv.lock` rather than `pyproject.toml`**, because the declaration file lists direct dependencies
  only while the lock file carries the resolved set, and every advisory this project has received
  was against a package reached transitively. That is an argument from the resolved set, not a
  measurement.

### Consequences

* Good, because an advisory against the active directory now produces a fix pull request in hours
  rather than waiting up to a month for the version-update cycle.
* Good, because the closed directory no longer needs a manual dismissal per advisory.
* Good, because alerts stay enabled throughout. These rules change what happens to an alert, never
  whether it is raised.
* Bad, because none of the three exists in any file. No clone, fork or transfer restores them, and
  deleting one breaks nothing visibly — no test fails, no build turns red. The table above is their
  only reproducible record.
* Bad, because `django-version-dead-manifest` silences a path that no longer exists and so reads as
  dead configuration. Whether the dependency graph ever drops a deleted manifest is not
  established. **Do not delete the rule because the file it names is gone** — that is why it exists.
* Bad, because the `uv.lock` filter is unverified and fails silently if wrong. The first advisory
  against a `django_version` dependency settles it: an alert arriving with no pull request beside it
  is the symptom, and the repair is one string.
* Neutral, because the GitHub preset *Dismiss low-impact alerts for development-scoped
  dependencies* is enabled alongside these three and was not examined here.
