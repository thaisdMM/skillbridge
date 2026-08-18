# Technical Debt — The non-root container user's effect on bind-mounted files cannot be verified on this machine

**Status:** accepted, unverifiable here
**Date recorded:** 2026-08-17
**Area:** `django_version/Dockerfile` (the `USER` line), `django_version/docker-compose.yml`
(the `.:/app` bind mount)
**Applies to:** everything the container writes into the mounted project directory —
generated migration files, `.pytest_cache/`, the tool caches, and the
`pyproject.toml` / `uv.lock` half of a `uv add` run inside the container
**Related:** decision D15 in `docs/plan/plan_toolchain-ci-security_2026-08-15.md`, which
adopts the non-root user and splits its acceptance criterion; Issue 4 of
`docs/audits/2026-08-17-audit-plan-toolchain-d10-d15.md`, which correctly rejected the
inherited criterion and proposed a replacement that turned out to have the same defect

## The gap

The `Dockerfile` runs as a non-root user. On a Linux host, files that a container writes into
a bind mount land owned by the container's UID, which may not match the host user's — the
classic source of files the developer cannot edit without `sudo`.

**Whether that happens here cannot be established on this machine**, so the decision to add
the user was taken with that half of its consequences unverified.

## What was measured, and why it settles nothing about Linux

Run 2026-08-17 with `docker run --rm --user <uid>:<gid>` against the real `django_version/`
bind mount. Nothing was built; each probe file was removed inside the same run.

| `--user` requested | How the mount presents `manage.py` inside the container | File / directory / subdirectory write |
| --- | --- | --- |
| `0:0` | `uid=0 gid=0` | OK |
| `1000:1000` | `uid=1000 gid=1000` | OK |
| `1234:1234` | `uid=1234 gid=1234` | OK |
| `4242:4242` | `uid=4242 gid=4242` | OK |

Host-side the same file is `uid=501 gid=20`, before and after.

**Docker Desktop's VirtioFS presents every file in the mount as owned by whichever UID is
accessing it.** There is no mapping. A UID that exists nowhere on the host is presented and
permitted exactly like any other.

Two things follow. The good one: a non-root user cannot break the development workflow on
this machine, whatever UID is chosen. The one recorded here: **no test of bind-mount
ownership can fail on this machine**, so no criterion run here can certify the behaviour on a
host where it is real.

This is the second criterion to fall to the same defect. The superseded plan's — *"bind-mounted
files stay usable from the host"* — was rejected because Docker Desktop's `chown` succeeds
without affecting `stat`. Its proposed replacement — *"the container can write `__pycache__`,
`.pytest_cache` and migration files into the bind mount"* — passes for every UID, as measured
above. A third formulation should be assumed to have the same problem until it is run
somewhere else.

**A smaller correction, from the file rather than from measurement.** `__pycache__` should
not appear in any such criterion regardless: `django_version/Dockerfile` sets
`ENV PYTHONDONTWRITEBYTECODE=1`, which applies to `docker-compose exec` as well, so the
container does not write it at all.

## What *is* verified, so the gap is not overstated

The half of D15 that lives inside the image is real and enforced: `/opt/venv` must be
readable and executable by the new user and writable by `uv sync`, and Linux permissions
apply there normally. A mistake fails the image build or the first
`docker-compose exec web pytest`, and the `docker build` step CI gains under D6 is what
catches it before it reaches `main`.

## Why it is accepted rather than resolved

**There is nowhere to run the test.** Development happens on macOS, CI installs on the runner
rather than running the container, and no production image exists. Manufacturing a Linux
environment solely to verify an ownership property of a development image is work out of
proportion to the risk.

**The risk it leaves open is bounded and loud.** The failure mode is a file the developer
cannot edit, discovered immediately, with a well-known remedy: match the container UID to the
host user's, or set `user:` on the service in `docker-compose.yml`.

## Reversal criteria

Any one of these means the verification must actually be performed:

1. **Development moves to, or is shared with, a Linux host.** This is the case the entry
   exists for.
2. **A production image is built (Phase 5).** The ownership question stops being about
   developer convenience and becomes part of the deployment's file permissions.
3. **CI begins running the container** rather than only building it — the GitHub runner is
   Linux, so any step executing inside the image verifies this for free.
4. **A contributor other than the current developer clones the repository** and runs the
   container.

## What to do when one of them fires

1. Run the same probe on that host: as the container's user, write a file, a directory, and a
   file inside an existing subdirectory of the mount, and then check the ownership **from the
   host** — which is the step that carries no information on macOS and all of it on Linux.
2. If the files land unusable, the remedy is matching UIDs, not removing the `USER` line:
   either build with a UID matching the host user, or set `user: "${UID}:${GID}"` on the
   `web` service.
3. Record the result in D15, replacing the row this entry marks unverifiable. It is the one
   piece of that decision taken on reasoning rather than measurement.
