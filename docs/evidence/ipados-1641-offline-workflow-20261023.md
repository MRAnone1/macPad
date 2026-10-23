# Shared offline workflow rehearsal — 2026-10-23

The iPad remains unavailable. This pass adds six portable integration tests and
documentation. It makes **no device/SSH call, native observer run, delivery,
trust change, job, resume or payload execution**. No actual session,
prerequisite or native control receipt is created. Production/runtime sources,
the five-file delivery bundle and all native gates remain unchanged.

## FACT — one common fixture reaches all four boundaries

Previously the individual test modules used separate invented contexts. The
session fixture omitted cleanup's two directory records and used a candidate
signature limit that did not match the reviewed static plan. That fixture could
test projection but could not demonstrate compatibility with cleanup.

The new [workflow test](../../misc/test_macws_swap_pair_workflow.py) completes
one invented in-memory delivery/observer context using the exact reviewed
static plan, five file records and both directory records. It passes that same
context through projection, normal-control preparation, result decoding and
cleanup preparation. Raw input bytes, delivery/plan digests and all projected
candidate/source tokens are explicitly compared across the boundaries. Native
controls remain empty in the projected prerequisites.

The control and cleanup payloads are **compiled only**. The invented normal
report is rebound to that projected configuration; its positive decoder result
means internal consistency of supplied bytes. External freshness, authenticity
and device acceptance stay false. Cleanup preparation still requires a future
live observer before any deletion and grants no native cleanup verification.
No historical native receipt or timestamp is substituted as current evidence.

The other five cases exercise missing directory records, nonzero GID, a
candidate signature mismatch, a delivered candidate-token mismatch and a
foreign admission nonce. The mismatched signature/token/session cases refuse.
Native-library loading, subprocess launch, signal/kill calls, nonce generation
and selected filesystem mutation entry points are prohibited in all six tests.
Pinned local source reads remain allowed. Full-suite verification separately
runs finite local test/compiler processes; those are not device operations.

## FACT — cleanup has a stricter contract

Missing directory records can pass projection and control preparation but
cleanup refuses with `exact two delivery directories`. The exact receiver's
successful source path records both directories and refreshes their tokens
after installing children. The old incomplete fixture is not proof of a
receiver or current device failure.

The receiver/pipeline/projector require root UID but do not apply cleanup's
GID-zero requirement. A synthetic GID of 501 passes those preparation stages
and cleanup refuses with `root-owned delivery stat`. This is a source- and
synthetic-data-supported policy difference; no actual current delivery has
been measured here. No gate is weakened and no production fix is justified.
Before a future control, check the actual receipt against the complete cleanup
contract. Refusal must preserve the receipt and files; do not rewrite tokens,
owners or group values to manufacture acceptance.

The [redacted evidence receipt](ipados-1641-offline-workflow-20261023.json) records exact source hashes,
source locations, private audit/review digests and validation results. The
independent review found no scoped privacy or simulated-acceptance blocker.
Only public synthetic helper data and already published static identities are
used; actual runtime/boot/process/file witnesses remain excluded.

| Validation | Publication | Companion |
| --- | --- | --- |
| Shared workflow tests | 6 pass | 6 pass |
| Portable swap-pair tests total | 127 pass | 127 pass |
| Complete suite | 894 tests, 52.603 s | 890 tests, 51.011 s |
| Complete-suite baseline | Same 14 failed-case identifiers | Same 14 failed-case identifiers |
| Protocol, runtime-switch audit, diff | Pass | Pass |
| Tracked shell syntax | 41 pass | 41 pass |

Both complete suites remain **not passing**: six failures, eight errors and
twelve skips, with no new failed-case identifier. Selected runtime/preparation
sources remain unchanged around both suites. No affected native component
requires rebuilding in this test/documentation-only change.

## THEORY and deferred device acceptance

The shared rehearsal may prevent mixed-input preparation mistakes. It does not
reproduce, explain or fix the original MacWS display freeze. All 19 October
inventories remain historical. A new read-only inventory, exclusive delivery,
fresh source/token/trust/boot/UI observations and native-clock admission remain
required when the iPad returns. Start with one bounded normal stopped control,
retain complete or partial output and verify scoped process/job/file cleanup.
Three genuine accepted stopped controls remain required before an active pair.
Visible device acceptance and duration/stability checks remain open.
