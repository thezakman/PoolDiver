# Vendored third-party tools

This directory bundles external tools that PoolDiver invokes as **separate
subprocesses** (arm's-length execution), so PoolDiver works out of the box
without a separate install.

## enumerate-iam

- Upstream: https://github.com/andresriancho/enumerate-iam
- Author: Andres Riancho
- License: **GPLv3** (see `enumerate-iam/LICENSE`)

Only the runtime files are vendored; the upstream repo's bundled `aws-sdk-js`
(used solely to regenerate `bruteforce_tests.py`) and git history are omitted.

> ⚠️ **Licensing note.** `enumerate-iam` is GPLv3, while PoolDiver itself is
> Apache 2.0. PoolDiver only *executes* it as a separate program (it does not
> import or link it), which the FSF considers mere aggregation rather than a
> derivative work. The GPLv3 license and copyright notice are preserved intact
> in `enumerate-iam/`. If you redistribute this project, keep them in place.
