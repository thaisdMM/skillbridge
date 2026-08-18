# Technical Debt — The `web` service has no `HEALTHCHECK`, because there is no endpoint to point one at

**Status:** deferred
**Date recorded:** 2026-08-17
**Area:** `django_version/docker-compose.yml`, `django_version/Dockerfile`
**Applies to:** the `web` service only. The `db` service already has a healthcheck
(`pg_isready`), and `web` already waits on it via
`depends_on: db: condition: service_healthy`
**Related:** the *Items that need no decision* section of
`docs/plan/plan_toolchain-ci-security_2026-08-15.md`, which records the deferral; Phase 3 of
`docs/ROADMAP_SKILLBRIDGE.md`, where DRF arrives

## The gap

`docker-compose.yml` declares no `healthcheck` for `web`. Docker therefore reports the
container as running whenever the process is alive, which says nothing about whether Django
can serve a request — a container that boots and then fails on every request is
indistinguishable from a healthy one.

The asymmetry is visible in the file: `db` has a healthcheck and `web` depends on it, so the
project already uses the mechanism and simply does not apply it to the service that answers
requests.

## Why it is deferred, not implemented

**There is no correct URL to probe.** The application exposes no dedicated health endpoint.
The available alternatives are all wrong for a different reason:

| Candidate probe | Why it is not used |
| --- | --- |
| A business route | Couples container liveness to a feature's availability, and turns a route change into a health failure |
| `/admin/` | Redirects to a login page; a probe would be asserting that the admin is reachable, which is not what liveness means |
| A TCP connect to port 8000 | Passes as soon as the socket is open, which is roughly what "running" already tells you |

Pointing a healthcheck at any of them produces a signal that is either misleading or
redundant. A healthcheck that cannot fail for the right reason is the same defect this
project has already rejected in test criteria: a check that passes regardless of the
condition it claims to observe.

**The right fix is a `/health/` endpoint**, which is application work, not compose
configuration, and it belongs with the layer that will own routing.

**Delivery speed is part of the reason, and it is legitimate at MVP stage.** The compose
setup is a single-developer local environment where a broken `web` container is discovered by
the developer within seconds.

## Reversal criteria

Any one of these makes the deferral wrong:

1. **DRF arrives (Phase 3).** A URL layer with real routing is exactly when adding
   `/health/` stops being a special case and becomes one more route.
2. **A deploy target is chosen (Phase 5).** Orchestrators and platform health probes are the
   consumer this feature actually exists for; a production container without a health probe
   is a real gap rather than a cosmetic one.
3. **Anything is added to compose that should wait on `web` being ready**, the way `web`
   waits on `db` today. `depends_on: condition: service_healthy` needs a healthcheck to have
   a meaning.
4. **A container is observed running while failing every request**, in local development or
   anywhere else.

## What to do when one of them fires

1. Add a `/health/` view that returns a small JSON body and a 200, and decide **explicitly**
   whether it touches the database. Both are defensible and they measure different things —
   liveness against readiness — and the choice must be recorded rather than fall out of
   whichever is easier to write.
2. Keep it out of authentication and out of any middleware that could make it fail for a
   reason unrelated to health.
3. Add the `healthcheck` block to the `web` service, with `interval`, `timeout` and `retries`
   in the same shape the `db` service already uses, so the file carries one convention rather
   than two.
4. If it is being added because of criterion 2, write it against the production stage rather
   than the development image — `Dockerfile:31` runs `runserver`, and the healthcheck should
   describe the process that actually serves traffic.
