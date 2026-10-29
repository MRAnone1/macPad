# Retained diagnostic artifact cleanup design — 25 October 2026

The design below was frozen on 25 October. The
[26 October offline implementation](evidence/ipados-1641-retained-artifact-20261026.md)
now supplies a tested host archive and fixed-scope reference cleanup core.
It supplies no native observation backend, hard worker deadline, transport or
deployment. No device cleanup has been attempted; the last observed two-file
scratch and five-file delivery are retained. This remains separate from unchanged
v7 original-ownership cleanup and does not make the failed control acceptable.

The [27 October adapter preparation](evidence/ipados-1641-retained-observer-20261027.md)
adds original-input validation and a read-only native wrapper/capture API.
It remains untested on the device and has no reviewed hard worker/transport.
No removal is authorized by its capture-only provenance or host tests.

## Authority and evidence

The user's continuing diagnostic-cleanup authorization supplies the scope.
AGENTS.md step 12 requires removing only explicitly scoped diagnostic markers;
it does not prescribe creation-time inode tokens for every separately reviewed
cleanup capability. The existing `OwnedFiles` and fixed delivery cleanup do
require their original ownership evidence, and those gates remain unchanged.

FACT: both real pre-stage and post-stage observations recorded both scratch
paths absent. The original controller independently refuses existing scratch;
`OwnedFiles.create()` exclusively creates only `job.plist` and `probe.log`.
The retained snapshots contain exactly those names, a root-owned 0700 directory
and root-owned 0600 files. The complete 1,540-byte plist matches the effective
`control_normal` configuration; the complete 386-byte log is retained. Their
hashes agree between the copied snapshots. The process/service has since been
retired using its original native birth witness.

FACT: original creation-time scratch inode tokens were not retained. Later
snapshots describe currently observed objects. The latest retained snapshot
contains stat5, ownership and modes but **does not contain file link counts**.
It therefore cannot satisfy the complete future selection contract by itself.

INFERENCE: namespace, content and exclusive-creation lineage strongly attribute
these objects to the diagnostic. They do not prove original vnode continuity.
A separate capability could deliberately select these exact current retained
artifacts for archived removal. It must never rename that selection as recovered
original ownership or feed it to `OwnedFiles`/the existing cleanup contract.

## Required sequence for a separate future capability

1. Freeze the original returned wire/report/session/delivery bytes, effective
   control configuration, process-retirement receipt, retained snapshot and
   final reviewed implementation hashes. Historical evidence stays unchanged.
2. Make a new read-only capture of the exact fixed directory
   `/private/var/tmp/macws-swap-pair-control-20261018` and exactly `job.plist`
   and `probe.log`. Require root UID/GID, modes 0700/0600, regular files,
   file link count one, bounded complete bytes, stat5 plus type/mode/owner/link
   fields and before/after stability. Reject additional entries and symlinks;
   handle fixed intentional parent anchors explicitly, never arbitrary aliases.
3. Match both files to the already copied bytes and the plist to the original
   effective configuration. An unexplained change requires investigation;
   regenerating a manifest must not silently admit it.
4. Exclusively archive the complete fresh returned wire bytes, both files,
   manifest and provenance privately. Fsync/read back every archive file and
   its directory before granting any removal. Failed or partial preservation
   allows zero removals. This preserves bytes, not historical vnode identity.
5. Require a fresh independent baseline: original boot, copied native absence
   of the retired generation, both fixed services absent, no candidate/test
   workload, unchanged relevant sources/artifacts, stable UI, nominal thermal
   state and an exclusive operator. Old admission times confer no freshness.
   PID reuse or an ambiguous native query must refuse; never signal a process.
6. Open reviewed fixed parent/child directories through held no-follow
   descriptors. Require held-FD/path agreement and the full reviewed manifest
   for the directory and both files before any effect. Hold file FDs too.
7. Before each descriptor-relative unlink, repeat relevant absence/health
   gates and check directory identity/exact remaining entries and that file's
   identity, type, link count, UID/GID, mode, size, timestamps and hash. Unlink
   only the two fixed names, then remove only the exact empty directory.
8. Record attempted and completed effects separately. Timeout, changed object,
   partial action or lost output means partial/unknown result, followed by
   read-only observation. No retry, silent token refresh or recursive removal.
9. Independently verify exact scratch absence and unchanged health/job state.
   Only then reconsider the existing five-file/two-directory delivery cleanup,
   using its original delivery tokens and a fresh all-pass observer baseline.
10. Test substitutions, hardlinks, foreign children, changed boot/session,
    reappearing jobs/processes, partial/noisy captures, archive/fsync failures,
    per-effect failures and unknown outcomes. Default entry points stay inert;
    independently review final source, transport and actual receipts.

The new capability must provide no `OwnedFiles` substitute, source/QA pin
relaxation, job creation, resume, process signal, trust mutation or probe run.
Userspace check-then-unlink is not atomic against another root writer, even
with held descriptors; preserve the exclusive-operator limitation. Timers do
not guarantee recovery from a kernel stall. Foreign content, unexplained
changes, failed archive/identity checks, uncertain absence, concurrent writers
or uncertain effects stop the operation.

No stopped control is authorized by this design. The original freeze cause,
three genuine stopped controls, full cleanup and device acceptance remain open.
See the [last actual process recovery](evidence/ipados-1641-process-retirement-20261025.md)
and [future witness design](ipados-1641-recovery-witness-design.md).


The [28 October frame/worker preparation](evidence/ipados-1641-retained-worker-frame-20261028.md)
adds lossless bounded inputs and a host-tested self-only deadline through stdout
flush. It supplies no live transport, current device witness or cleanup grant.
Original validators and scoped removal guards remain unchanged.


The [29 October capturer/assessor](evidence/ipados-1641-retained-capturer-20261029.md)
adds host-only one-attempt raw preservation and strict reported-capture checks.
It performs no automatic retained archive or removal. A positive size check
cannot replace archive durability, fresh native cleanup gates or verification.
