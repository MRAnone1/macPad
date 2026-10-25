# Original stopped test process retired — 25 October 2026

This is process/service recovery for the failed
[24 October normal control](ipados-1641-normal-control-20261024.md).
The iPad13,6 / iPadOS 16.4.1 (20E252) / Ventura 13.4 (22F66) port remains
unverified. The original display/freeze cause is still unknown. The
[machine-readable evidence](ipados-1641-process-retirement-20261025.json)
contains selected facts and private receipt hashes; no raw process identities,
credentials, endpoints or Apple binaries are published.

## FACT: original process authority is distinct from file authority

The original report retained the initial native SSTOP observation, complete
136-byte BSD-info block, exact probe path and process birth. The old session,
actual executing payload, delivery receipt and returned wire bytes are retained
unchanged. Their source/config/artifact digests bind this specific historical
attempt. A local search confirmed the original scratch directory/file tokens
were not retained. Current matching files cannot replace those missing tokens.

The new [process-retirement core](../../misc/macws_swap_pair/process_retirement.py)
therefore retires only the originally recorded process/service. It does not
call `stop_owned`, fabricate `OwnedFiles`, replace its file checks, delete any
file or confer scratch ownership. Its ordinary invocation prints metadata;
native construction, transport and original-input authentication belong to an
explicit private caller. Consistent arbitrary JSON is not authenticated input.
The public core is byte-identical to the independently reviewed core used here.

## FACT: fresh inventory and read-only preflight

The user confirmed the iPad was available, unlocked, charging and responsive.
Fresh inventory matched hardware/builds, the original boot, nine directly
hashed Mach-O identities and eleven framework header/load-command identities
across the two cache namespaces. Full framework bytes and live code pages were
not attested. About 87.32 GiB was free and both thermal samples were nominal.
The trustcache had **172 entries**, compared with 167 on 24 October; the own
probe hash was present. This difference is recorded, not rewritten as unchanged.
This pass performed no signing or trust mutation.

The bounded read-only snapshot matched the original native birth/path/SSTOP
state, original candidate delivery token, exact current service PID/arguments,
unchanged installed three-source package and pinned wrapper. The other test
label was absent. Boot/UI/thermal checks passed before and after the snapshot.
The plist was checked against the actual `control_normal` configuration.
Its current tokens were observations only.

The final recovery-specific read-only call repeated its native gates and
reported zero mutation attempts. Old admission timestamps were not refreshed
or reused as current control authorization. This was a separate recovery of
the original recorded generation; the normal controller's admission and
resume rules were not changed.

## FACT: one scoped retirement and copied native absence

Immediately before the first effect, the helper required the original build,
boot/UI, nominal thermal state, current candidate stat/hash/UUID/trust and
dependencies, exact config-derived plist content, exact fixed `user/501`
service, and the original native stopped generation. It called the unchanged
`RealBackend.bind(stopped=True, allow_wrapper=False)` path/inode/stat gate.
No wrapper alias fallback or new process adoption was permitted.

| Copied result | Observation |
| --- | --- |
| Exact-service `launchctl kill SIGKILL` | one, quiet exit 0 |
| Exact-service `launchctl bootout` | one, quiet exit 0 |
| Original-generation native absence queries | two, `proc_pidinfo` returned 0 / ESRCH |
| Final exact service | absent in the recognized fixed-domain query |
| Worker interval | approximately 0.443 seconds |
| Transport | complete, quiet, exit 0; no timeout or overflow |
| Resume, debug, bootstrap, signing or trust operations | none |
| File/directory removal | none |

There were twenty allowlisted commands: four UI process inventories, four
trust-info reads, ten fixed-job prints, one SIGKILL and one bootout. The source
rechecked the original generation and service before bootout and copied the
native absence results. The complete original worker bytes match the stored
host envelope. An independent review of these actual receipts supports
process/service retirement, separately from the earlier source/test review.

Fresh observer v4 then completed ten of eleven checks: both test labels were
absent, no blocked workload remained, candidate/dependencies and file
observations were stable, boot/UI matched, and thermal values were 0/0.
The only refusal was `both_scratch_absent`: the run scratch is absent and
the control scratch remains. Trust membership was stable *within this new
observer capture*; this does not mean 172 equals the previous 167 entries.
The user confirmed normal touch responsiveness after retirement.

## Cleanup and acceptance boundaries

The five delivered files and their two directories were not removed. The
control scratch remains, and no original scratch token was recovered. The
fixed delivery cleanup still refuses that occupied scratch baseline. No new
control or active pair was dispatched. Zero of the three required stopped
controls are accepted; physical stable presentation and freeze remediation
remain unaccepted. Do not infer any of these from successful process recovery.

The earlier statement that all recovery was blocked was conservative scope
reasoning: missing file tokens prevented reuse of the existing cleanup route.
The separately designed and reviewed process-only capability used the distinct
original process witness. This did not relax that cleanup route or retroactively
manufacture original file ownership.

The [future witness design](../ipados-1641-recovery-witness-design.md) describes
preserving original file tokens and the exact first failed bind observation.
It distinguishes final-report retention from durable host preservation before
bootstrap. It has not been deployed and does not authorize a new run or alias
acceptance. The earlier wrapper-alias explanation remains THEORY.

## Tests, review findings and timing limits

The core's 44 synthetic tests and the private transport/worker's sixteen tests
passed with exact final source hashes unchanged. Negative cases include wrong
build/boot/UI, replaced birth/raw stop/stat/source, wrapper spelling, service
redirect, changed plist, failed/partial/noisy commands, unknown bootout,
contradictory success flags, unknown native absence, finite reaping and no
file-deletion or resume capability. Tests use invented identities and mocked
effects; they do not count as native stopped controls.

Before any dispatch, review corrected a soft alarm into a self-only hard exit
and rejected contradictory positive transport summaries with unknown bootout
or missing native absence evidence. An initial fixture used full `st_mode`
bits while the actual pinned receiver emits `stat.S_IMODE` permission bits.
The retained original delivery reproduced that draft refusal; the corrected
core accepts the same unchanged bytes. Its fixture now executes the pinned
receiver's actual token projection. Existing owner/mode/link/hash guards remain.

The private worker keeps a twelve-second self-exit timer armed through output
flush; the core has an eight-second bound and the host capture twenty seconds.
Loss, partial output or worker exit 124 means unknown effects, never permission
to retry. Userspace timers cannot guarantee recovery from a kernel stall.
Checking a launchd service and acting on it is not atomic; this scoped recovery
assumes an exclusive operator and retains that limitation explicitly. The
private JSON decoder rejects duplicate keys and literal NaN/Infinity; exponent
overflow is a recorded parser limitation. Acceptance booleans/counters are
strictly typed, and the actual pinned worker returned finite timings.

The complete suites, runtime-switch audit, C protocol, shell syntax and diff
checks are recorded in the JSON evidence. Known native Metal failures remain
failures, not skips or GPU passes. Controller, backend, watchdog, probe, hooks,
pipeline, signed bundle and cleanup builder are unchanged. No libmachook build
or Apple-binary patch was needed for this Python diagnostic capability.

| Final local validation | Guide | macPad |
| --- | --- | --- |
| New process-retirement tests | 44 pass | 44 pass |
| Existing portable swap-pair controls | 129 pass | 129 pass |
| Complete tests executed | 950 | 946 |
| Complete-suite failures / errors / skips | 43 / 0 / 13 | 43 / 0 / 13 |
| Failed native Metal methods | 11 | 11 |
| Runtime-switch audit / C protocol | pass / pass | pass / pass |
| Shell syntax | 38 files pass | 41 files pass |
| Diff whitespace | pass | pass |

Both complete runs retained unchanged source hashes. The
[new public tests](../../misc/test_macws_process_retirement.py) use invented
identities and the actual pinned receiver token projection. The sixteen
additional private transport tests bring that separate recovery core/transport
rehearsal to sixty tests; none of those is native device acceptance.
