# Source lineage

Kaigen Tox Core 0.2.23-kaigen.1 is derived from:

- TokTok/c-toxcore commit `1d79022fb4e56dffe0bbd075d47e00f7a0b62ab3`;
- cmp commit `52bfcfa17d2eb4322da2037ad625f5575129cece`, vendored under `third_party/cmp` with its MIT license preserved.

Kaigen-maintained changes cover bounded parsing and allocation, TCP receive and
priority-queue work limits, group-announce admission limits, UDP shared-key work
budgets, proportional net-crypto receive storage, relay fan-in handling, and the
associated regression fixtures. Kaigen also caps friend-request retry delay.

The source snapshot used for this publication has the pre-documentation Git tree
`5242cf03b041c72cd8d27981d00909744efab915`. Kaigen release builds materialize
that same core source from the pinned upstream inputs and ordered patch series.

Project Tox and TokTok names belong to their respective maintainers. This
repository preserves their original authorship and licensing and is maintained
independently for Kaigen releases.
