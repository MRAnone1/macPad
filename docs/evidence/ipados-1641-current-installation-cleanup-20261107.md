# Current installation selection and cleanup core — 7 November 2026

## Result and scope

The new `current_installation_cleanup.py` implements a distinct, explicitly
requested action for the fixed five diagnostic files and two directories. It
acquires current deletion tokens during that action. The original delivery
receipt remains immutable installation provenance; its old `dev`/inode/times
are not substituted or reused as current ownership authority.

Import, construction and `run()` without `cleanup=True` perform no filesystem
action. Execution requires explicit trusted filesystem, gate, shared-clock and
archive-verification objects. There is no native gate factory, command-line
deployment, worker, transport or iPad acceptance in this change. All filesystem
actions tested here used the Mac's own temporary directories. No iPad access,
file removal, trust mutation or control execution occurred in this pass.

## Action contract

The constructor checks the externally pinned original successful receipt,
its fixed paths/profile and five fixed production content hashes. It requires
complete immutable archived file bytes matching those hashes and lengths.
It builds one bounded archive containing the original receipt and all five
blobs. Before opening any selected filesystem path, a trusted archive callback
must directly finish successfully for those exact bytes/hash. A saved `true`
receipt bit is not accepted as that callback result. The callback's actual
durability implementation remains the caller's responsibility.

The explicit action consumes its one use before the first callback. It then
requires fresh, bounded observations tied to the requested nonce, exact
device/kernel/rootfs/boot/UI generation, source hashes and shared clock profile.
Both diagnostic labels and scratch names must be absent, thermal state nominal,
and the trusted caller must establish workload absence and exclusive operation.
These are caller contracts; consistent supplied JSON does not authenticate a
native witness. The core supplies no real device observer.

Both physical parents, two child directories and all five files are held by
descriptors. All seven selected objects must pass complete current type, owner,
mode, link, content and linked-versus-held checks before any unlink. Directory
names must be exact; unrelated parent siblings are preserved. Intermediate
symlinks and symlink/hardlink file substitutions refuse. The intentional
rootless anchor is bracketed by its literal and full token.

Before each of at most five unlinks and two rmdirs, the core rechecks gates,
physical chains, complete remaining tokens, contents and namespace snapshots.
Only the directory/parent affected by its own successful syscall can acquire
an updated full snapshot; every other token/name list must remain identical.
The final check requires absence through the held parents and unchanged sibling
entries. Gate age and the cooperative eight-second deadline cover final closes
as well. Finalization failure removes a positive verification claim.

Attempt intent is recorded before each syscall. A failure stops further actions,
retains partial selection, file tokens, offending copied bytes and completed
syscall records, and produces `partial_or_unknown` after any attempted mutation.
The object cannot be retried; there is no recursive removal, fallback, signal,
trust operation or rollback. A future caller still must durably journal its
intent/raw result and provide a source-pinned worker with an alarm through
serialization/flush. Cooperative checks cannot interrupt a blocked kernel call.
One-use state is local to this object; the host must also consume a durable
attempt slot before dispatch. Process death can leave no returned report and
must remain an unknown-effect outcome, never permission to retry.

## Host filesystem witness and race boundary

RUNTIME-CONFIRMED **on the host**, with invented gate metadata and owned test
paths: an initial prototype required a removed directory's held FD to have
`nlink == 0`. A copied witness instead shows `nlink` **2 before and 2 after** a
successful rmdir while the directory entry returns ENOENT. That assumption was
rejected. The original negative report and its source hash remain private.

Directory removal is therefore verified at its real endpoint: successful rmdir,
the held directory identity, ENOENT through the held parent, and exactly the
parent entry set minus that directory. The observed post-removal record remains
in the result; a positive directory link count is not translated into failure
or fictional zero. Regular-file post-unlink link checks remain in place.

This is not atomic conditional-inode deletion. A test replaces a name in the
last check-to-unlink window: the held file link check detects the mismatch and
stops subsequent deletion, but cannot undo the already executed syscall. This
is why excluding other privileged writers is a necessary caller precondition.
No result claims atomic namespace ownership or recovery of historical ownership.

## Validation

Thirty host test methods pass. They exercise real held-FD operations,
all-seven-before-first-effect ordering, changed current devices/inodes,
foreign/missing children, linked-file and directory substitution, symlinks and
hardlinks, wrong modes/typed owners, stale/bad health gates, changed rootless
anchors, immutable/partial copied data, archive callback refusal, effects followed
by exceptions, failed rmdir, reappearance, final close failures and deadline
expiry. Invented fixtures patch content hashes/ownership only within test code;
there is no production synthetic bypass.
An independent source/FD-contract review and independent run of all thirty
tests found no blocker for the offline dependency-injected core. Native
qualification remains a separate step.

A separate host fixture used the actual immutable delivery receipt and all five
archived contents, **174,394 bytes**, with the production content-hash table
unchanged. It fsynced/read back its archive before cleanup and verified all five
unlinks/two rmdirs in owned temporary directories. Health/clock were simulated
and ownership was mapped to the host fixture; it is not device acceptance or
current native freshness. Private payloads, tokens and copied bytes stay private.

A further host-only witness showed Python dictionary equality accepting a
boolean `True` where the actual clock profile required integer `1`. The core
now validates the actual clock object's profile types before comparison, as it
already does for supplied gate metadata. The additional regression refuses
this malformed profile before opening any selected filesystem path. The old
misconfiguration witness remains private; it is not a device-clock failure.

Both full suites ran: **1,393 / 1,389 tests**, exactly the same 43 known native
Metal failure records as the earlier 7 November baseline, zero Errors and 13
Skips each. The suites are not fully green. All 53 prior frozen source/test pins
match; all 55 old/new pins remained unchanged during these runs. Both runtime
switch audits pass (286 names, 85 flag files, 444 entries) and both C protocol
builds/runs pass. No shell or native binary changed; there is no architecture
build/deployment in this host component change.

Native gate/archive integration, bounded source framing/transport, independent
native qualification, exact trust restoration, fresh all-eleven observation and
three genuine stopped controls remain pending. No old v7 validator, receipt,
timestamp or `new_vnode` claim was rewritten. The display/freeze cause remains
open. The current research port remains unverified.

[Machine-readable evidence](ipados-1641-current-installation-cleanup-20261107.json) ·
[Exact trust postcondition and selected delivery route](ipados-1641-jbctl-trust-transition-20261107.md) ·
[Control handoff](../ipados-1641-one-control-handoff.md)
