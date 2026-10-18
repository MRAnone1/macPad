# Published diagnostic milestone and fresh inventory — 2026-10-18

## FACT — publication scope

The fourteen shared diagnostic/evidence files from the previous checkpoint
were committed separately and pushed to the user's two forks. Remote branch
heads were independently read back and matched:

- [MacWSBootingGuide commit 0e8cdd8](https://github.com/MRAnone1/MacWSBootingGuide/commit/0e8cdd8112741a26f876870881510f5f91ff5f42).
- [macPad commit 4a0baef](https://github.com/MRAnone1/macPad/commit/4a0baef8fd42bf0fa0393ecdbd5e70028dfe16ac).

Both use branch `codex/ipados-1641-swap-diagnostics-20261017`. Original
upstream branches were not changed. The main publication checkout starts
from upstream `2e45bd7`; the original checkout's existing uncommitted work
was preserved. The companion starts from `a18da08`. New diagnostic files
are aligned; divergent existing production code was not overwritten.
The earlier [precommit synchronization record](ipados-1641-diagnostic-synchronization-20261017.json)
remains a historical snapshot. Its pending-publication wording does not
claim that a later push failed or that the full freeze workflow is complete.

The current publication commit was separately tested: **742 tests in 52.870
seconds, 6 failures, 8 errors, 12 skipped**. Its exact fourteen failed case
identifiers match the earlier main clean-HEAD subset. The private log SHA-256
is `471d6d25e84145bc93c2c41e0bf63bfa29e1294cd59705c193523ada54fbaace`.
The companion run had 738 tests and the same failed-case set. The focused
81-test reader/route/cache run passed in both checkouts and in the main
publication checkout. No complete suite is described as passing.

## FACT — today's read-only device snapshot

The [fresh inventory](macws-port-inventory-2026-10-18.json) confirms iPad13,6,
iPadOS 16.4.1 / 20E252, Dopamine 3.0.10, and macOS 13.4 / 22F66. All nine
hashed standalone files match the October 17 snapshot, including the
selected WindowServer, both streamgate hooks, wrapper and dyld.
The worker hashed 6,940,480 bytes in approximately 0.174 seconds, with its
28-second device alarm and now explicitly frozen 38-second host timeout.
The same boot was observed within the inventory and against the retained
v46 source-bound session field; raw session identities remain private.

There was one SpringBoard and one backboardd, no WindowServer, no listed
loader/debugger/log sampler, nine MacWS-named processes, no listed diagnostic
markers, and two nominal public thermal samples. Available Data space was
96,121,630,720 bytes. These are snapshots, not foreground, responsiveness,
visible output, continuous stability or fresh rootfs mount attribution.

Trustcache information now contains **166 distinct CDHashes**, compared
with 164 in the October 17 initial inventory. This worker made no trustcache
mutation calls and did not test admission. The two-entry difference is
observed; its cause is **unattributed**. Previous diagnostic zero-add counters
must not be read as a complete audit that the entire backend stayed unchanged
between those snapshots.

The separate [cache/header inventory](macws-cache-framework-identities-2026-10-18.json)
freshly verifies eleven selected image UUIDs/header hashes in 47 declared
cache files, with 135 reads / 1,251,574 bytes in approximately 0.046 seconds.
The worker's shared deadline is eight seconds, its device alarm twelve
seconds, and its frozen host timeout twenty seconds. Native iPadOS and
Ventura image roles remain distinct. These are complete selected Mach-O
header/load-command ranges, **not full framework hashes, signed-page
verification, or loaded-native-image evidence**.

Both workers ran via SSH stdin; no device files, jobs, new workloads, explicit
kernel-memory reads, or jailbreak primitive initializations were created.
There was no owned device diagnostic artifact to remove from these inventory
runs. Source, host runner/envelope and raw receipt hashes are included in the
redacted exports; detailed raw state remains private.

## THEORY and remaining work

The existing coexistence route may contribute to the saved display wait.
Matching addresses, original code windows and filesystem identities do not
establish that mechanism. A fresh bounded display-failure reproduction,
actual original WindowServer Begin/Cancel statuses, a proven upstream failing
invariant, narrow repair and visible/protocol device acceptance remain open.

A separate own-client one-shot Begin→Cancel diagnostic is being prepared
locally. Builds and fake controls are not a real client status witness. It
requires verified isolated signing/deployment, an independently controlled
watchdog and exact loaded compatibility-image binding before any active pair.
No such pair, new display run, runtime repair or Hypervisor work occurred in
this publication/inventory step. Even a successful own-client pair would not
prove the original WindowServer statuses, physical presentation or freeze
cause. This device/build remains an **unverified port**.
