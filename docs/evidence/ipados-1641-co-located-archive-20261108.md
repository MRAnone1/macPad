# Co-located cleanup archive callback — 8 November 2026

**FACT — host acceptance only.** `current_cleanup_archive.py` adds an explicit,
one-use archive callback for the unchanged current-installation cleanup core.
Twenty-four focused methods pass in each repository, including an independent
final public-source review. The helper has not been deployed or tested on the
iPad. This remains an unverified iPad13,6 / 20E252 / Ventura 13.4 / 22F66 port;
no native acceptance, working action transport or original freeze fix follows.

## Local archive contract

`CoLocatedArchive` construction and metadata are inert. The caller supplies
exact archive bytes, separate external archive and original-delivery hashes,
explicit structural context and a reviewed physical private parent. The
constructor decodes the bounded canonical archive and reuses the unchanged
core's inert production validation to reconstruct it exactly. Neither copied
historical context nor a matching hash establishes current native state.

The explicit callback consumes its sole invocation before path I/O. It requires
effective process UID/GID zero, a physical `0700` archive parent, stable `0755` watched
parents and disjoint archive/selection namespaces. It creates one deterministic
per-archive slot and fixed `archive.private.bin`, using exclusive creation,
bounded writes, file/directory/parent fsync, exact held-FD readback and path
checks. Its direct successful return is `None` only after all closes succeed.
Operation intents precede effects. Partial artifacts remain on refusal; no
overwrite, retry, rollback, selected-file cleanup or transport is provided.

That direct return describes this process's co-located archive sequence. A
copied report cannot prove past fsync, remote host persistence, native
authenticity or execution authority. The separate
[host attempt preparation](ipados-1641-cleanup-preparation-20261108.md) remains
responsible for its own direct host persistence contract.

Namespace checks reject lexical ancestors/descendants, symlinks and direct
watched-parent device/inode aliases along the held archive-parent chain. They
do not prove the absence of every deep bind or mount alias. **Fresh native
mount/namespace inventory, a trusted current health/identity gate and exclusion
of capable privileged writers remain mandatory caller prerequisites.** A
process scan or JSON true bit alone cannot establish that exclusion.

## Archive effects precede the cleanup clock and may precede refusal

The unchanged core calls the archive callback before selected-path I/O and
before starting its **eight-second cooperative cleanup clock**. The callback
has no independent full-worker deadline. A future reviewed **12-second worker
alarm** must cover the whole archive/action/output path, serialization, flush
and descriptor closure. That worker/alarm is not supplied here, and a userspace
alarm cannot guarantee recovery from a kernel stall. No timing limit was
extended and the archive must not be described as covered by the core's eight
seconds.

**Runtime-confirmed on an owned host fixture:** the copied v3 witness records
four completed archive operation groups: directory creation; exclusive file
create/write/file-fsync/readback; archive-directory fsync; parent fsync. These
are four report groups, not an exact syscall count. The subsequent invented
gate had thermal value `1`; the core returned `health_or_exclusivity_refusal`,
`outcome="refused_before_effect"`, and empty `attempted`/`completed` lists.
Its selection backend had no events, while its archive callback had already
completed. Thus that core outcome means no attempted **selection cleanup**;
it never means zero total archive effects. Preserve both reports separately.

Only `refusal-after-archive-witness-v3` is the successful copied witness used
here. Earlier private v1/v2 fixture setup failures remain retained and do not
establish this endpoint. The witness uses invented health/clock data and host
owner/path/group mapping. It establishes no iPad failure or freeze cause.
Its exact private report hash is recorded in the companion JSON.

## Original-content host exercise and validation

A separate owned-host exercise used the unchanged original successful delivery
receipt and all five full archived production contents, **174,394 bytes**.
The production content-hash table was unchanged. Its exact **238,990-byte**
archive has SHA
`334b492d658959a556a04ec2436a308617aa2bddc95457d40baae27d9125b2f4`.
Health and clock were invented/historical; only the host owner, paths and process
group were mapped for the fixture. The direct archive `None` return occurred
before any core selection or clock access. The core then verified five unlinks
and two directory removals in those owned host paths. No diagnostic binary
ran, no original receipt was rewritten, and no iPad object was altered by this
exercise. These results qualify the host composition only.

The 24 tests cover inert construction, malformed/pin-changed archives,
noncanonical base64, namespace conflicts, direct aliases, existing slots,
symlink/owner/mode/parent changes, zero write progress, partial writes and fsync
errors, substituted entries, held-FD stat faults, final close failures and
archive-then-core-refusal composition. An independent review ran the exact
public candidates in both trees with no offline-publication blocker; native
qualification remains false.

Full suites ran **1,466 / 1,462 tests**, retaining exactly the same **43 known
Metal failures**, zero errors and 13 skips as the preceding host-preparation
run. They are not fully green. All 60 old selected source pins are unchanged;
all 62 selected pins stayed stable during testing. Runtime-switch audits
(286/85/444) and C protocol builds/runs pass in both repositories. No shell or
native binary changed; no architecture build or deployment is claimed.

Follow-up to the earlier 49-method increment: its final independent host review
is now complete, with 49 focused methods passing in each exact committed tree,
nine shared blobs equal and 55 older selected pins unchanged. Its report SHA is
`ab4513b15ba0e84972965a889b2353ac850972023fbe83636827679abdd98e69`.
This later result does not rewrite the historical evidence that recorded the
review as pending, and supplies no native acceptance.

## Remaining qualification

**THEORY to test:** after fresh device identities/health/mount/namespace
inventory and independently reviewed gates, writer exclusion, worker alarm and
bounded once-only transport, this callback can satisfy the real co-located
archive precondition before native selected-file cleanup. Confirm with copied
runtime output and the direct callback return on the exact device/build;
consistent reports or host fixtures are insufficient. The following exclusive
v5 redelivery, exact four trust prerequisites, fresh all-eleven observer,
new-nonce unchanged v7 session and three genuine stopped controls remain open.
See the [core boundary](ipados-1641-current-installation-cleanup-20261107.md)
and [control handoff](../ipados-1641-one-control-handoff.md).
