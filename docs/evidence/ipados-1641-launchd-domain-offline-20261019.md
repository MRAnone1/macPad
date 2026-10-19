# Offline launchd-domain repair — 2026-10-19

The user confirms normal touch responsiveness after the
[previous stopped-control failure](ipados-1641-stopped-control-20261018.md).
That closes the pending human responsiveness check for that earlier event.
It does not establish native watchdog acceptance, display stability or a
freeze fix. The iPad is now unavailable, so **this pass performs zero device
or SSH commands, deployments, trust changes, signals or resumes**. No fresh
device inventory is claimed. This remains an unverified iPad13,6 /
iPadOS 16.4.1 / 20E252 port.

## FACT — copied invariant and narrow source change

The historical native replies show the owned job in `user/501`. A system
query redirects there with a warning; explicit `user/501` print, kill and
bootout succeeded, and its absence reply names UID 501 with status 113.
Controller v6 refused the redirect. V7 uses the one explicit `user/501`
domain consistently for bootstrap, print, kickstart, kill and bootout.

The parser requires the exact service header/domain, program, argument block,
plist/log paths and typed PID when present. It rejects missing or duplicate
owned fields, foreign identities, redirects, warnings and unknown output.
Absence requires the exact label/UID text, status 113 and empty stdout.
Mutation results require status 0 and empty stdout/stderr. No warning is
silently reclassified as success. Native generation/file ownership checks
and the v6 exactly-once descriptor/report-preservation repair remain intact.

The same copied-string regression reproduces v6's stderr refusal and passes
v7. Those strings are historical observations replayed locally; they are not
new device evidence. In particular, explicit-domain **bootstrap/kickstart
credentials and native v7 behavior remain unverified**.

The [three public controller sources](../../misc/macws_swap_pair/README.md)
are byte-identical to the frozen private v7 sources, with hashes bound by the
[redacted receipt](ipados-1641-launchd-domain-offline-20261019.json).
No raw runtime fixture, prerequisite, credentials or Apple binary payload is
published. Default controller invocation only hashes local files and prints
metadata. A portable test forbids CDLL, child-process, signal and timer
operations during that default.

## FACT — offline validation and delivery preparation

| Check | Result | Scope |
| --- | --- | --- |
| Frozen controller tests | 107 pass, retaining all previous 88 | Synthetic backend/watchdog; 19 new domain/lifecycle cases |
| Public portable tests | 7 pass | Synthetic replies and guarded metadata default; no private fixture |
| Isolated pipeline tests | 25 pass | Temporary host files and mocked transport |
| Private bundle builder | 13 pass | Local provenance and exclusive-copy checks |
| Independent source/replay review | No scoped blocker | 72 historical source/evidence files unchanged; no native calls |

The complete repository suites remain **not passing**: publication 774 tests
in 54.110 s, companion 770 in 47.678 s; both have 6 failures, 8 errors and 12 skipped.
Their exact 14 failed-case identifiers equal the retained baseline. The receipt
records case IDs, logs and code-source hashes. Runtime-switch audit, shell
syntax and diff checks also pass. No libmachook or display-runtime code changed.

The host-only bundle contains 41 selected provenance files. Its manifest SHA256
is `d2c843dc9930b28342c9b57d11bbee2bbe12202b1147dec11137106646d13263`.
All copies were compared to their frozen originals. Only five payload files
can be selected by the [isolated delivery helper](../diagnostic-probe-pipeline.md);
the raw copied fixture remains host-only and outside Git. No v7 file has been
delivered. There is no new device artifact to clean up in this pass. The
previous device cleanup and retained trustcache entry remain historical facts,
not a current readback.

## THEORY and device gates

The domain repair addresses the proven diagnostic-control mismatch. It does
not explain the original WindowServer freeze. No original failure was
reproduced and no active own-client Begin/Cancel result was obtained here.
Native device acceptance remains false.

When the iPad is available again, begin with new read-only hardware/build,
rootfs/space/trust/runtime and exact artifact identity checks. Confirm the
explicit domain's absent labels and no conflicting processes/scratch before
exclusive delivery. Use new file tokens and same-session source/clock-bound
prerequisites. Run one normal stopped control and verify its complete report,
known-generation absence and cleanup before the EOF/deadline controls. All
three genuine controls must pass before considering an active own-client pair.
Historical receipts must never be substituted for those fresh prerequisites.
