# Cleanup package and host attempt preparation — 8 November 2026

**FACT — offline scope.** The new byte-only package, decode-only stdin builder
and host archive/attempt preparation pass 49 focused methods in each repository.
The iPad was not contacted. This remains an unverified iPad13,6 / 20E252 /
Ventura 13.4 / 22F66 port. The original display/freeze failure is unresolved;
no native cleanup, candidate execution or stopped control was attempted.

## Byte package and execution boundary

`cleanup_package.py` accepts exactly twelve entries: five reviewed source
modules, the unchanged successful delivery bytes, five full archived blobs and
explicit historical context. All twelve independently supplied pins are
checked before context parsing. Four context roles refer to direct imports;
the fifth source, `readonly_observer.py`, is required by `retained_observer.py`.
An AST inventory of these exact versions closes those project imports. The
generic decoder's names and matching hashes alone do not prove a source closure
executable, current native evidence authentic or any action authorized.

`cleanup_decode_payload.py` is separate from the unchanged older
`cleanup_payload.py`. Its default branch executes neither bootstrap nor frame.
Only `--decode` hashes both bootstrap sources and the frame before executing
the two fixed bootstrap libraries. It never compiles, imports or executes the
five framed sources, constructs cleanup, queries native state or writes an
archive. Unknown action/extra arguments refuse. Tests use poison framed
programs and altered pins/manifests, duplicates, malformed contexts, boolean
integer aliases, excess sizes and decompression floods.

The actual historical bytes produce **309,615 decoded bytes**, a **75,488-byte
frame** and **128,057-byte stdin program**. Existing 128-KiB compressed,
2-MiB decoded and 256-KiB stdin limits remain unchanged. The exact reconstructed
archive is 238,990 bytes, SHA
`334b492d658959a556a04ec2436a308617aa2bddc95457d40baae27d9125b2f4`.
The original receipt, context, binary and source blobs remain immutable. The
repr-based stdin renderer preserves input dictionary insertion order; its
byte identity is pinned after building, not inferred from semantic pin-map
equality. No old payload is rewritten to match another ordering.

## Host durability and once-only scope

`CleanupAttempt` in `cleanup_preparation.py` validates bytes and external pins
without I/O at construction. Explicit `prepare(parent)` creates a private
`cleanup-<archive-sha256>` slot, preserves the exact archive using exclusive
creation, file/directory/parent fsync and held-FD readback, then constructs an
unchanged `capture_journal.Journal` for the actual stdin bytes and bound intent.
Changing a nonce or payload cannot create another slot for the same archive
in that parent. The trusted caller must retain the same parent across restarts
and exclude capable writers. This is no cross-parent/machine/root exclusion
proof. Hash identity is not semantic/native archive authentication.

Preparation and dispatch-intent phases are consumed before their first effect.
`mark_dispatch()` rechecks archive bytes, identity, private names and held
physical parent chain, then durably marks one intent; it invokes no transport.
Only the direct successful returns attest this process's completed persistence
sequence. Saved receipt bits cannot reconstruct historical fsync. A future
device callback must genuinely perform its own archive sequence outside the
selected cleanup namespaces; a remote lambda accepting the host digest cannot
be described as direct host persistence verification.

Review found a raw-preservation ordering gap in the private draft. The current
full/partial raw-save phases first use the unchanged journal's safe namespace
and raw preservation, then check the separate archive. A changed archive still
causes terminal refusal and prevents assessment, while known received raw bytes
remain preserved. Assessment retains its archive precheck. A corrected host
witness and regression tests verify this endpoint; this is no iPad failure
witness. Tests also cover file/parent/dispatch fsync errors, replaced/symlinked
parents and archives, repeated phases and FD closure after initial stat faults.
Partial artifacts remain; there is no deletion, retry or rollback helper.

## Actual historical-byte host exercise

A new exclusive host-only fixture used the real archived contents and source
pins, preserved archive and dispatch intent, ran the decode-only child locally,
durably saved its original stdout/stderr before parsing, and then saved its
assessment. All nine archive/journal files were read back after close. No
framed source or diagnostic binary ran. Historical UI/boot/clock context was
neither refreshed nor presented as current. The private report hash is recorded
in the companion JSON; runtime tokens and copied blobs stay outside Git.

Both full suites ran **1,442 / 1,438 tests**, with exactly the same **43 known
Metal failures**, zero errors and 13 skips as the preceding cleanup-core run.
They are not fully green. All 55 old selected source pins stayed unchanged;
all 60 selected old/new pins remained stable during testing. Runtime-switch
audits (286/85/444) and C protocol builds/runs pass in both trees. No shell or
native binary changed, so no architecture build or deployment is claimed.
Independent source feedback caught the ordering issue; a completed final
independent execution review and native qualification are still pending.

## Remaining native work and hypotheses

**FACT:** the trusted current native gate/clock/exclusivity integration, genuine
device archive callback, action worker with self-alarm through serialization
and flush, and reviewed native one-attempt transport are not implemented by
these helpers. Host-only decode success is not device acceptance. A process
list or JSON `exclusive_operator: true` cannot prove exclusion of privileged
writers; the core's check-to-unlink race boundary remains unchanged.

**THEORY to test:** the intended current-selection cleanup → unchanged exclusive
v5 redelivery → exact four trust prerequisites → fresh all-eleven observer →
new-nonce unchanged v7 route can reach the three stopped controls. Confirm only
with fresh device identities, copied raw witnesses, independently reviewed
native boundaries, visible responsiveness and endpoint acceptance. No original
freeze cause is established by package or archive tests. See the
[cleanup core](ipados-1641-current-installation-cleanup-20261107.md) and
[single-control handoff](../ipados-1641-one-control-handoff.md).
