# Technical Debt — Nothing in CI blocks a build on a vulnerable dependency

**Status:** deferred
**Date recorded:** 2026-08-17
**Area:** `.github/workflows/ci.yml`, `.github/dependabot.yml`
**Applies to:** every package in `django_version/uv.lock`, direct and transitive
**Related:** decision D18 in `docs/plan/plan_toolchain-ci-security_2026-08-15.md`, which
enables Dependabot and defers the gate here; D8 Item 3, whose deferred `schedule:` trigger
D18 closes as unnecessary; D10, whose rejection of `ty` on preview-status grounds is the
argument reused here

## The gap

Dependency advisories reach this project through **Dependabot alerts only**. Nothing refuses
a merge. A pull request that introduces — or leaves in place — a dependency with a known
advisory is not stopped by any automated check; the advisory arrives separately, as an alert
and a pull request of its own.

What was declined is a build-failing audit step. `pip-audit` was the tool the superseded
plan named, and `uv audit` is the newer alternative.

## What was measured

Read and executed on 2026-08-17:

- **The baseline was worse than the audit reporting it had recorded.** The audit reported
  `dependabot_security_updates: {"status": "disabled"}`. The alerts endpoint returns
  `403 — "Dependabot alerts are disabled for this repository."` Alerts were off, not merely
  the automated updates, so before D18 **nothing at all** was watching this project's
  dependencies. D18 turns both on, which is why this entry records a missing *gate* rather
  than missing monitoring.
- **`uv audit` is in preview.** Astral's own announcement: *"Both of these features are in
  preview for now. They're considered unstable and there may be breaking changes as we
  iterate on their design."* It reads uv's locked resolution and queries OSV; support for
  `requirements.txt` and PEP 751's `pylock.toml` is described as planned, not present.
- **Dependabot supports `uv` natively** — version updates in general availability since
  2025-03-13 as `package-ecosystem: "uv"`, and security alerts and updates since 2025-12-16.

`uv audit` has **never been executed on this project**: the `uv` installed on the
development machine predates the subcommand. Its exit code, severity filtering and ignore
mechanism are unknown.

## Why it is deferred, not implemented

**The tool that would cost nothing is unstable, and the plan already rejected that trade
once.** D10 refused `ty` — Astral's type checker — quoting its version policy, *"breaking
changes, including changes to diagnostics, may occur between any two versions"*. `uv audit`
carries the same property. Adopting it as a build-failing gate while rejecting `ty` on that
ground would apply two standards inside one plan, and a blocking gate is the worst place to
accept a diagnostic surface that may move between versions.

**The tool that is stable costs more than the gap it closes.** `pip-audit` is PyPA-maintained
and well understood, but it adds a dependency and a pin, it does not read `uv.lock` — it
would audit either the synced environment or an exported requirements file — and it queries a
different advisory source from the OSV data Dependabot uses, producing two streams for the
same advisories.

**What a gate adds over the alert stream is narrow.** It refuses a merge. What it costs is a
red build caused by an advisory published against code nobody touched, on a push about
something else. With alerts enabled, the same advisory arrives as a pull request carrying its
own fix, without a workflow run.

**Delivery speed is part of the reason, and it is legitimate at MVP stage.** The project has
roughly seven direct dependencies and is pre-production.

## Reversal criteria

Any one of these makes the deferral wrong:

1. **`uv audit` leaves preview.** This is the primary trigger. At that point the gate costs
   no new dependency and no new pin — `uv` is already in the image and on the CI runner — and
   reads `uv.lock` directly. The deferral has no remaining argument.
2. **The project acquires a deploy target (Phase 5).** A gate that refuses to ship is worth
   more than a gate that refuses to merge, and the calculation above assumes nothing is
   deployed.
3. **A Dependabot alert is missed or ignored long enough to matter.** The alert stream is the
   whole control here; evidence that it is not being read is evidence that a blocking gate is
   needed.
4. **The dependency surface grows substantially** — DRF, drf-spectacular and their transitive
   sets in Phase 3 are the concrete case.

## What to do when one of them fires

1. **If the trigger is criterion 1**, add `uv audit` as a CI step and measure three things
   before making it build-failing: its exit code on a finding, whether it has a usable ignore
   mechanism, and its output against one `pip-audit` run on the same lockfile. D18 records
   that none of these was ever measured.
2. **If the trigger is anything else and `uv audit` is still in preview**, the tool is
   `pip-audit`, not `uv audit`. Declare it in the `dev` group, and decide deliberately whether
   it audits the synced environment through `uv run` or an exported requirements file.
3. **Revisit `schedule:` at the same time, and expect the answer to stay no.** D8 Item 3
   deferred a scheduled trigger because a push-only audit detects a newly published advisory
   only at the next push, with a measured 47-day gap between runs on this repository. D18
   closed it because Dependabot's alerts arrive without a workflow run. That remains true with
   a gate added: the gate protects the merge, the alert stream covers the gap. Note also that
   in a public repository a scheduled workflow is disabled automatically after 60 days of
   inactivity.
4. **Do not add both tools.** Two streams for the same advisories is the cost this entry
   already names.
