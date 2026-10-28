# iPadOS 16.4.1: next single stopped control

Updated 2026-10-25: the original stopped process and exact service from the
[failed 24 October control](evidence/ipados-1641-normal-control-20261024.md)
have been retired through a separately reviewed process-only capability.
One exact-service SIGKILL and one bootout returned quietly; copied native
ESRCH and exact service absence verify retirement. Both test labels are now
absent, but control scratch and staged payloads remain. Ten of eleven fresh
observer checks pass; scratch absence is the sole refusal. **Do not dispatch
another control or repeat staging on this occupied scratch baseline.** See
the [process recovery evidence](evidence/ipados-1641-process-retirement-20261025.md).
This iPad13,6 / 20E252 / Ventura 13.4 / 22F66 port remains unverified.
Historical inventories and consistent JSON are not current native evidence.

The ordered gates below remain the procedure for a future independently
reviewed attempt after file ownership/cleanup is resolved. Current snapshots do
not replace original file-ownership tokens omitted from the controller report.

The [offline ownership-capture primitive](evidence/ipados-1641-ownership-capture-20261025.md)
is not integrated or deployed. The [retained-artifact cleanup design](ipados-1641-retained-artifact-cleanup-design.md)
defines a distinct current selection after fresh complete capture,
private durable archive and independent absence gates; it does not restore
missing original tokens. The [26 October archive/reference core](evidence/ipados-1641-retained-artifact-20261026.md)
passes host tests, but has no live native adapter, bounded worker/transport or
deployment. Do not invoke it on the device from a fabricated freshness backend
or archive JSON. No new control is authorized.

The [27 October read-only adapter](evidence/ipados-1641-retained-observer-20261027.md)
now validates the original inputs and exposes an explicit native read-only API.
It has only host acceptance so far. The
[28 October lossless frame and self-deadline worker](evidence/ipados-1641-retained-worker-frame-20261028.md)
now fit the unchanged stdin cap and pass host tests. A reviewed one-attempt host
capturer, current inventory and native capture are still missing. Capture-only
provenance cannot admit cleanup; no existing R3 limit may be silently expanded.

## Resolve these host prerequisites first

Reviewed private capture, session-storage, normal-only and cleanup transports
were used or validated for the 2026-10-24 attempt. The separate 25 October
process-only helper used the original process witness without fabricating
`OwnedFiles` or weakening its checks. These are not published live dispatch
commands. Original scratch-file authority remains unresolved. The
historical inventory wrappers dispatch at top level and use already occupied
output names. Do not rerun them unchanged. The projector and cleanup builder
provide no transport. Keep actual endpoints, keys, runtime tokens and raw
receipts outside Git. Do not improvise missing dispatch or recovery commands.

## Ordered gates

| Gate | Required evidence/action | Refusal condition |
| --- | --- | --- |
| Availability | Current confirmation: available, unlocked, charging, normal touch response. Verify visible responsiveness separately from SSH. | Unavailable, abnormal or uncertain device state. |
| Fresh inventory | A newly reviewed exclusive capture of hardware/iPadOS/macOS builds, jailbreak/trust backend, rootfs/mount/space, exact target Mach-O architectures/UUIDs/hashes, cache identities, jobs/processes/UI/boot/thermal state. | Unknown/changed identities, missing measurements or conflicting workload. An I/O error never proves absence. |
| Before delivery | Fresh read-only observer v4: both fixed `user/501` labels and both scratch names absent; stable UI/boot, nominal thermal state and exact trusted dependencies. Candidate absence before staging is not admission. | Present/redirected/unknown label, occupied destination/scratch, changed dependency or conflicting workload. |
| Exclusive delivery | The project's diagnostic-probe pipeline with the exact pinned bundle. Preserve original receiver output, successful exit and delivery bytes. It stages five files/two directories without running them or changing trust. | Existing/raced objects, timeout, partial output/copy or refusal. Preserve evidence; no overwrite or automatic retry. |
| Cleanup contract | Validate the actual delivery against `reviewed_delivery_plan.json` with the cleanup builder before any control. Require five file records, two directory records, complete tokens, UID/GID zero, fixed modes and exact hashes/signature. | Missing records or mismatched ownership/content. Projection alone has weaker directory/group gates. Never rewrite an incompatible receipt. |
| New observation/session | Complete post-stage v4 observation, all eleven checks true, stable boot/UI, exact trusted candidate/dependencies and matching tokens. Project original observer/delivery/plan/QA bytes using pinned sources and a separately supplied new nonce; retain private outputs exclusively. | Partial observation, changed token/signature, absent trust or refusal. Do not silently add trust or reuse historical prerequisites. |
| One normal attempt | Prepare only `normal_ready_stop`. The frozen normal-only adapter requires reviewed transport and new exclusive output storage. Native execute must check its live shared clock, prerequisite age in [0,300] seconds, health, ownership and source identity before jobs. | Stale/future data, clock/source/boot/UI mismatch, occupied labels/scratch or incomplete host wiring. Never edit timestamps to pass. |
| Result and cleanup | Retain bounded lossless stdout/stderr, exit/timeout state, exact inputs and full/partial report. Decode against the same config. Verify exact owned job, native process generation and scratch cleanup, then use the prepared five-file/two-directory cleanup with a repeated fresh baseline. Finally check device responsiveness and thermal state. | Unknown/live owner, mismatched paths/tokens, foreign children, access/I/O error, partial report or deadline. Preserve partial effects; missing counters stay null. |

## Attempt limits and recovery ownership

One normal attempt has a 10-second active window, 8-second cleanup reserve and
35-second host bound. No automatic retry. A host timeout or terminated SSH
child proves neither remote cleanup nor physical responsiveness; a userspace
timer cannot guarantee recovery from a kernel stall.

The controller/watchdog may stop only the exact recorded service/program/
arguments/boot/process-birth/file identity. It must not resume a stopped job
merely to terminate it. Verify its exact `user/501` label and owned native
generation absent and its scoped scratch/plist/log retired before delivery
file cleanup. If ownership or recovery is uncertain, stop and reobserve.
Do not use a global kill, recursive removal or blanket trustcache reset.

The delivery cleanup signals no jobs. It validates all five files and both
directories before any unlink, rechecks each object, and preserves negative or
partial results. Its 8-second deadline/12-second alarm does not establish
atomic namespace ownership or native cleanup acceptance.

A consistent normal capture requires one bootstrap, one first resume, zero
second resumes, verified stopped C-ready state, the expected watchdog trigger
and verified exact cleanup. Parser consistency alone authenticates no JSON.
Three genuine fresh, source/session/boot-bound stopped controls
(`normal_ready_stop`, `parent_pipe_EOF`, `active_deadline`) remain required
before considering an active pair. This handoff contains no active dispatch.
The original freeze still needs an exact-binary or copied runtime witness
supporting its failing invariant before a runtime fix.

See [the tools and frozen source bindings](../misc/macws_swap_pair/README.md),
[the shared workflow rehearsal](evidence/ipados-1641-offline-workflow-20261023.md)
and [the diagnostic delivery pipeline](diagnostic-probe-pipeline.md).
