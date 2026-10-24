# iPadOS 16.4.1: one normal control refused before first resume

Recorded on 2026-10-24, Europe/Zurich. This iPad13,6 / iPadOS 16.4.1
(20E252) / Ventura 13.4 (22F66) / Dopamine 3.0.10 port remains unverified.
The original display/freeze issue is not diagnosed or fixed by this result.
The [machine-readable record](ipados-1641-normal-control-20261024.json)
contains an allowlisted summary and private evidence digests, not raw device
identities or Apple binaries.

## FACT: fresh inventory and bounded staging

The user confirmed the iPad was unlocked, charging and responsive before the
attempt. Fresh read-only inventory matched the previous nine directly hashed
Mach-O files and eleven framework header/load-command identities across 47
cache files. This does not hash complete frameworks or attest live code pages.
The builds and rootfs identities matched; about 87.13 GiB was free, both thermal
samples were nominal, and the 167-entry trust membership contained the pinned
own probe. Hardware/build/cache observations were not borrowed as fresh data
from the previous day.

Before staging, both fixed `user/501` labels and both scratch directories were
absent. Ten of eleven observer checks passed; the sole expected refusal was
the missing candidate. The diagnostic-probe pipeline then exclusively staged
the five pinned files and two directories. The original receiver report was
complete and quiet. Its actual file/directory tokens, UID/GID zero, modes,
contents and signed-artifact contract passed the unchanged cleanup builder
before dispatch. Delivery did not run the probe or mutate trust.

A new post-stage observer passed all eleven checks without refusals. The host
persisted its original observation, delivery, plan and canonical QA bytes in
an unused private session, with a separately generated nonce. The normal-only
adapter made exactly one dispatch. The unchanged native controller rechecked
its live clock/freshness and source/health/baseline gates before bootstrap.

## FACT: the control failed at the ownership guard

The bounded SSH capture completed with a full copied v7 report, native caller
exit zero and empty stderr. The host adapter correctly returned failure:

| Copied observation | Result |
| --- | --- |
| Bootstrap calls recorded | 1 |
| First / second resumes recorded | 0 / 0 |
| Debug-admission calls recorded | 0 |
| Initial probe state | Native `proc_bsdinfo` SSTOP, complete 136-byte block |
| C-ready stop verified | false |
| Watchdog trigger | `health_or_source_exception` |
| Watchdog failure and cleanup failure | `Refused: exact target path/inode` |
| Accepted normal control / verified cleanup | false / false |

The initial stopped witness has the expected exact probe path. The watchdog's
combined guard requires the expected path spelling and same-file identity,
with a separate pinned-wrapper startup branch. It did not copy the path/stat
observation that caused its refusal. The result therefore does not distinguish
a transient wrapper-path mismatch from an inode/path failure. The parent
preserved files after an uncertain started generation. A successful transport
is not successful control or cleanup.

The subsequent v4 observer returned a complete negative report: the control
label was present. Its nonzero exit and original bytes were preserved rather
than rewritten into a successful baseline. There was no second control or
active-pair dispatch.

## FACT and THEORY: read-only follow-up

A separate bounded read-only snapshot copied the same recorded native process
generation, still SSTOP, before and after the read. Boot/UI identities matched
the session, thermal values were zero, the candidate token matched delivery,
and the wrapper hash matched its frozen source profile. Its logical path
differs from its current resolved path. One control scratch directory and its
two files remain; the run scratch directory is absent. The copied plist matches
the effective `control_normal` config, and the log contains no C-ready record.
The user confirmed normal touch responsiveness after the attempt.

THEORY: the watchdog may have sampled a rootless wrapper path before SETEXEC
which differed from its configured logical spelling. The current alias
observation does not recover that earlier sample or establish the freeze cause.
No runtime guard was relaxed and no runtime patch was made from this theory.

Two limitations of the follow-up are retained explicitly. Its first SSH
invocation was blocked by the host network permission boundary before stdin
delivery; a separately reserved read-only capture followed after permission
was granted. Also, the snapshot compared the plist with the base session's
`run` operation. An offline comparison of the unchanged copied bytes against
the actual adapter-selected `control_normal` operation passes. Both the
original false comparison and the separate context correction remain private;
the raw report was not repaired.

## Cleanup remains incomplete; next work is ownership evidence

The original controller/watchdog held directory/file ownership tokens but did
not serialize them into its returned report. The current snapshot cannot
recover those original tokens. A matching current filename, plist or process
is not adopted as new ownership authority. The exact job/process/scratch
cleanup remains unverified, so the five-file/two-directory delivery cleanup
was not executed. The staged payloads, stopped job and control scratch are
retained. Do not rerun staging or another control on this occupied baseline.
No global kill, recursive removal, trust reset or historical recovery wrapper
was used. Complete the original-ownership/recovery design and independently
review it before any further mutation; a new runtime attempt also needs a
copied offending path/birth/stat witness. Do not broaden the path gate merely
to obtain a positive result.

## Narrow host decoder correction and validation

The existing v7 producer initializes `pair_result_private` to JSON null even
for stopped controls. The previous host decoder rejected every occurrence of
that key; the former fixture omitted it and duplicated an overbroad projection.
A source-bound synthetic replay reproduced the mismatch before changing the
host decoder. The fix allows only absent or exact null, keeps the full report
unchanged, and uses the pinned producer's real allowlisted projection in tests.
Objects, arrays, false, zero and strings still refuse after digests are rebound.
The later actual negative report also contains the producer's null placeholder;
it remains rejected for its genuine control/cleanup failures.

This compatibility change is supported by exact owned-source replay and the
copied field, not by a successful native stopped control or Apple-binary
disassembly. All three generated native payloads are byte-identical before
and after the host-only change. Controller, watchdog, runtime support, probe,
pipeline, delivery bundle and cleanup builder remain unchanged.

| Validation on final public source bytes | Guide | macPad |
| --- | --- | --- |
| Portable swap-pair tests | 129 pass | 129 pass |
| Full tests executed | 906 | 902 |
| Full-suite failures / errors / skips | 43 / 0 / 13 | 43 / 0 / 13 |
| Failed native Metal methods | 11 | 11 |
| Runtime-switch audit / C protocol | pass / pass | pass / pass |
| Shell syntax | 38 files pass | 41 files pass |
| Diff whitespace check | pass | pass |

The full suites remain failing only in the previously recorded native Metal
controls. They are not green and are not replaced by portable test success.
Private normal-transport, session-persistence and cleanup-transport helpers
passed 14, 11 and 17 synthetic host tests respectively before the attempt.
Synthetic tests provide no native device acceptance. No libmachook change or
rebuild was required. Zero of the three required stopped controls are accepted;
active Begin/Cancel, visible stable presentation and freeze remediation remain
unaccepted.
