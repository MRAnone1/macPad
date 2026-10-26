# Retained-artifact offline implementation — 26 October 2026

FACT: this pass implements and tests host archive and fixed-scope reference
cleanup helpers. It makes zero device connections or device changes. The user
reported that the iPad is unavailable until 18:00 Europe/Zurich today; work
stays offline. No automatic device access is scheduled for that time.

## Implemented scope

`retained_archive.py` exclusively creates a caller-owned 0700 archive directory
and exactly six 0600 one-link regular files: original bounded nonempty wire,
manifest, provenance, complete plist/log and receipt. Each file is fully written,
fsynced and read back through its held descriptor. Directory/parent fsync,
full stat/path/entry checks and final readback precede successful return.
Partial artifacts remain on failure; no rollback, overwrite or retry exists.

A persisted true receipt can exist before its final fsync succeeds. Therefore
the caller must retain the original successful creation return and require a
fresh `verify_archive()` before dispatch. Verification binds both files, wire,
manifest and provenance to caller-frozen expectations. It refuses a coordinated
blob/receipt rewrite. It checks current bytes and explicitly denies proving past
fsync, native authenticity or device acceptance. These are trusted-host claims,
not guarantees against hardware/kernel failure or another root writer.

`retained_cleanup.py` selects exactly the fixed current control scratch and its
`job.plist`/`probe.log`. It holds no-follow path-chain and file descriptors,
requires root UID/GID and 0700/0600 modes, regular one-link files, complete stat
fields, exact entries, bounded complete bytes and both caller-frozen earlier
content hashes. The trusted caller must derive the plist from the original
effective config and log from the retained copy; new observations cannot refresh
those expectations. No original vnode continuity is asserted or recovered.

Its explicit one-use core binds manifest/provenance/archive/context and asks a
caller-supplied observation backend for actual boot/source/artifact/UI/thermal,
both-service absence, retired-generation native ESRCH, no candidate/test workload,
other scratch absence and exclusivity. All gates must be exact/typed/fresh.
The only effects are at most two descriptor-relative unlinks and one exact
empty-directory removal. Full file/remaining-entry/anchor checks precede each.
Directory identity/mode/owner remain fixed while its timestamps may change due
to our own deletions. Parent anchors and exact path absence are rechecked after
removal. The core checks an 8-second cooperative budget and at-most-1-second
observation freshness immediately before effects and final acceptance.

The result preserves bounded copied backend observations, failed stage, fixed
refusal, digest bindings and separate attempted/completed effects. An effect
followed by an exception, changed second file, reappearing job, failed postgate,
changed parent or expired/stale final check yields partial/unknown, no retry.
The retained observations are copied backend dictionaries, not authenticated
original native wire. A future real adapter must retain that wire separately.

## Tests and review

39 archive and 39 core tests pass privately and in each repository. They use
only self-owned host temporary files; scope/owner constants are patched narrowly
for synthetic core tests. A real host archive-to-verifier-to-core test checks
canonical digest interoperability and exact filesystem effects. No synthetic
backend or fixture becomes native authority.

Coverage includes partial/zero writes and all nine fsync failure positions,
failed readbacks, persisted true receipt after fsync failure, exclusive names,
symlinks/FIFO/hardlinks/substitutions, extra/missing entries, hostile bounded
JSON, wrong contexts/content/gates, PID reuse/errors, stale/regressing clocks,
second-file replacement after first unlink, syscalls that happen then raise,
parent replacement and post-removal failures. Default imports/CLIs are inert.

Independent review found the coordinated archive rewrite and freshness after
filesystem reads/final parent checks; frozen expected file hashes and clock
regressions now cover those cases. Root also added FD closure on initial stat
failure and preserved failing gate evidence. See the
[machine-readable final evidence](ipados-1641-retained-artifact-20261026.json)
for final hashes, review provenance and full-suite results. Native Metal failures
remain explicitly retained; the full suites are not reported green.

## Unfinished native integration

No actual native observation backend, hard worker deadline, authenticated bounded
transport, current native capture or device dispatch is supplied. The caller must
authenticate original report/config/delivery/retirement/snapshot lineage and
fresh state; consistent JSON alone cannot do this. No active entry point exposes
an executable device command. No staged file or frozen v7 source/QA/bundle/
observer/cleanup pin changed, and no Apple binary/native hook was rebuilt.

Before any device action, independently review new live wiring, notify the user,
confirm current availability/state and make a fresh read-only capture including
exact entries and link counts. The old snapshot lacks link counts and cannot
supply current selection admission. Only a completely preserved fresh archive
and independent gates can precede a bounded one-shot removal; independently
verify its actual receipt and baseline before the unchanged five-file delivery
cleanup. Unknown effects require read-only reobservation, never automatic retry.

The last device state is historical, not measured here. File cleanup, three
genuine stopped controls, native device acceptance and the original display/
freeze cause or fix remain open. The wrapper-alias explanation remains THEORY.
