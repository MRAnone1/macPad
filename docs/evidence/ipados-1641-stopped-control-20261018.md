# Refused stopped control, report repair and cleanup — 2026-10-18

This remains an **unverified iPad13,6 / iPadOS 16.4.1/20E252 port**, with
Ventura 13.4/22F66 userspace and Dopamine 3.0.10. The
[redacted receipt](ipados-1641-stopped-control-20261018.json) binds private
inventory, runtime, cleanup and host-test witnesses by SHA-256. No Apple
payload, credential, process identity or runtime address is published.

## FACT — read-only inventory before dispatch

Fresh inventory confirms the nine previously selected standalone hashes,
eleven selected framework identities and 47 declared cache files. Hardware,
kernel/build, jailbreak backend, rootfs, free space and current runtime were
observed before staging. UI process generations repeat and thermal samples
are nominal. Additional immediate dependency observations include bounded
fat-header/code-page checks for the CydiaSubstrate dependency; they do not
establish recursive closure or actual loaded-image binding.

The prior public [device](macws-port-inventory-2026-10-18.json) and
[cache](macws-cache-framework-identities-2026-10-18.json) inventories remain
historical snapshots. The new raw inventory hashes are in today's receipt.

Two diagnostic port assumptions were rejected before active-pair admission:

| Observation | Narrow diagnostic change | Evidence limit |
| --- | --- | --- |
| Native `ps` reports unknown state `?s` for UI processes | Use status in a complete native 136-byte proc_bsdinfo block; validate layout, PID and birth | Own suspended probe later copies SSTOP=4; no general process-state inference |
| Python3.9.9 monotonic values have a per-process epoch | Use explicit public Mach absolute time with the observed 125/3 timebase | Two copied native processes agree on the shared counter; no synthetic freshness timestamps |

SDK layout builds cover arm64 and arm64e. The selected own arm64 binary's
signed code pages and unchanged Begin→Cancel machine-code order were checked
before trust admission; those checks do not prove native call success.

## FACT — one dispatched control was refused

The isolated project pipeline delivered exactly five files into two absent,
exclusively created directories. Delivery itself made zero trust changes,
program executions, job operations or resumes. One reviewed own arm64 CDHash
was separately admitted and read back in the current trustcache.

The v5 normal stopped-control dispatch created its owned job. A copied
launchctl response maps `system/<owned label>` to `user/501/<owned label>`
and includes an exact service-identifier warning on stderr. The backend
correctly refused its previously required empty-stderr invariant. Explicit
`user/foreground` and `user/501` queries then return the same owned job with
empty stderr.

The outer controller returned only EBADF. Its finalizer closed the same pipe
write descriptor twice, losing the inner error, counters and watchdog report.
**Missing counters are unknown, not zero.** A separate runtime witness copies
the exact owned process path/birth and complete native SSTOP=4 block. The log
contains only the launch wrapper's initial-suspension messages; C-ready was
not observed. The selected control path has no active second-resume site.
No accepted native control or active Begin/Cancel result was produced.

The configured watchdog deadline did **not** establish job cleanup: the
stopped job remained and required the separately scoped recovery below.
This is a diagnostic-control failure, not a new reproduction of the original
WindowServer display/freeze failure.

## FACT — narrow report repair and host tests

New private controller v6 transfers pipe ownership before each close, never
retries an uncertain descriptor number, records finalizer failures, continues
remaining cleanup/restoration, and rejects acceptance when an error exists.
The full-`execute()` regression fails frozen v5 with EBADF and passes v6.
Fourteen new lifecycle tests cover normal/EOF/deadline behavior, protocol
failure, descriptor/write/communicate errors and alarm restoration.

All **88 host tests pass**, retaining the previous 74. An independent source
review and rerun found no blocker in that scope; 54 prior regular files remain
hash-identical. The caller also preserves source-bound partial reports and
tracebacks; unavailable resume counts remain null. These are synthetic backend
and watchdog tests using real local pipe descriptors, not native acceptance.

V6 deliberately retains the observed launchd-domain refusal. It has not been
deployed. The new pinned bundle has 34 provenance files, including before/after
regression evidence. Its [isolated delivery helper](../diagnostic-probe-pipeline.md)
has 25 passing synthetic tests; the local bundle builder has 13. Default delivery
is local metadata only, and explicit installation cannot launch the controller.
Host output-size checks cap accepted output after capture, not capture memory.

Full repository suites are **not passing**: publication 767 tests in 47.014 s,
companion 763 in 41.330 s; each has 6 failures, 8 errors and 12 skips. The exact 14
failed-case identifiers match the retained baseline. Logs/source hashes and
case identifiers are in the receipt. Shell syntax, runtime-switch audit and
protocol checks also pass. No libmachook code changed in this pass.

## FACT — scoped cleanup and remaining trust change

Recovery rechecked exact job arguments/program, frozen file hashes, native
process birth/state, boot/UI identities and directory/file tokens. It signalled
only the exact `user/501` owned job with SIGKILL, then booted out that job.
An initial strict absence parser refused the actual `uid: 501` wording; it
removed no files. A new copied absence witness then supported the corrected,
separate cleanup check. The old process generation is absent.

Two scratch files and their directory, followed by all five staged payloads
and their two directories, were removed through verified directory descriptors.
The final read-only observation confirms both job labels/scratch directories
absent, unchanged UI generations, nominal thermal state, and the expected
missing-candidate refusal. Visible responsiveness after the failed control is
still awaiting operator confirmation; process identities do not prove it.

The reviewed own CDHash remains in the existing jailbreak trustcache:
166→167 distinct entries. Cleanup did not clear that global cache. Therefore
filesystem/job cleanup is verified, but a complete trust-backend rollback is
not claimed.

## THEORY and acceptance still open

Neither the original display mechanism nor its freeze cause is proven here.
No production runtime repair, fresh original WindowServer swap status or
physical-panel experiment occurred. Correct and verify the copied service-domain
invariant before dispatching another control. All three genuine stopped controls
must pass with their reports and known-generation cleanup before considering
one own Begin/Cancel pair. Even that pair would not prove the original
WindowServer behavior. Original-failure reproduction, a proven invariant,
production repair and device acceptance remain outstanding.
