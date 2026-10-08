# Source lineage

This source tree contains the accepted Kaigen Tox Core integration of
TokTok/c-toxcore `v0.2.24-rc.2`.

Source inputs:

- Kaigen fork baseline `b89934a6c152e5645697ee2974c9a5859855ad7c`, including
  its Windows socket-inheritance and HTTP CONNECT framing fixes;
- the complete upstream source delta from TokTok/c-toxcore
  `1d79022fb4e56dffe0bbd075d47e00f7a0b62ab3` to
  `e033325ac3472d571274ec70fdb5a220a22b01bc` (`v0.2.24-rc.2`);
- cmp commit `52bfcfa17d2eb4322da2037ad625f5575129cece`, vendored under `third_party/cmp` with its MIT license preserved.

Kaigen-maintained changes cover bounded parsing and allocation, TCP receive and
priority-queue work limits, group-announce admission limits, UDP shared-key work
budgets, proportional net-crypto receive storage, relay fan-in handling, and the
associated regression fixtures. Kaigen also caps friend-request retry delay.

The upstream update adds group-handshake signature/encryption-key consistency
checks, Windows LAN broadcast corrections, bounded IP/port parsing, group
announcement timing changes, and RTP/MSI memory-safety fixes. Kaigen's C01-C06
resource and allocation protections remain in place. The C01 stale-announcement
cleanup now uses the upstream shared 60-second timeout; its admission limit,
live-chat accounting, and cleanup-before-admission behavior are retained.
The A/V fixes are included in the source; no A/V runtime-validation claim is
made here.

Upstream version metadata, changelog, test configuration, and packaging metadata
are included. Three upstream CI changes target files absent from this
fork (`.github/scripts/cmake-osx`, `.github/workflows/ci.yml`, and
`.circleci/config.yml`); those files remain absent. This update does not enable
upstream workflows or claim a Kaigen CI run or release.

The previous `0.2.23-kaigen.1` publication recorded pre-documentation tree
`5242cf03b041c72cd8d27981d00909744efab915`. That historical identity belongs
to the previous publication. Pin this integration by its exact Kaigen repository
commit. Product dependency selection and release publication remain separate
from this source integration.

Project Tox and TokTok names belong to their respective maintainers. This
repository preserves their original authorship and licensing and is maintained
independently for Kaigen releases.
