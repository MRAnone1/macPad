# Exact jbctl return paths and trust-transition check — 7 November 2026

## Result

FACT: four read-only device witnesses were copied on **1 November**, after the
user confirmed the device was available, unlocked, charging and responsive.
Their raw streams and transport records were saved before assessment. This
note and the host tests were finalized on **7 November**; no device query was
made on 7 November, and the earlier readiness statement is historical.

The 1 November observer again completed nine of eleven checks. Probe, wrapper
and both hooks have the exact known content/signatures/pages but remain absent
from the reported trust set. This is a reproduced prerequisite refusal, not
proof of AMFI execution denial or a reproduction/fix of the display freeze.

RE-CONFIRMED: the exact copied `jbctl` can return zero for an unsuccessful
`trustcache info` client call. A new pure `trust_transition.assess()` therefore
requires complete parsed query output and the exact expected membership-set
change for one of four fixed diagnostic hashes. It executes no command and is
not yet connected to a native restoration adapter.

## Preserved device facts

| 1 November observation | Result compared with 31 October |
| --- | --- |
| Hardware/kernel/iPadOS | Same iPad13,6, Darwin 22.4.0, iPadOS 16.4.1 / 20E252 |
| Jailbreak/rootfs | Same Dopamine 3.0.10 and macOS 13.4 / 22F66 |
| Boot and copied UI generations | Same; UI generations also stable within the new witness |
| Direct Mach-O identities | All nine unchanged |
| Selected cache-image header identities | All eleven unchanged; header evidence only |
| Reported trust set | Exactly the same 145 hashes as the 31 October runtime witness |
| Exact diagnostic jobs and scratch paths | Both absent before and after |
| Current artifact records | All four observations unchanged; signatures/pages valid, reported membership false |
| Free `/private/var` space | 91,359,744,000 B, about 85.0854 GiB; 119,402,496 B less |

The four completed phases were port inventory, cache/header inventory, current
runtime observation and a bounded read-only copy of `jbctl`. All transports
completed with exit 0 and empty stderr. The copied binary is 173,152 bytes with
SHA-256 `64701bf3968cc4f79fe39b7e581e4db0e3aefb10cefcaf24dfd1737a8c6e599c`.
The copy bracketed native metadata, the exact rootless anchor and held physical
directory/file identities. It did not execute the copied file. Exact raw hashes
and byte counts are in the accompanying JSON; private paths, boot IDs and bytes
remain private.

## Exact-binary evidence

Addresses below are **unslid virtual addresses**, from the copied binary.

| Slice / UUID | Info call and error branch | Forced zero result | Add client call |
| --- | --- | --- | --- |
| arm64 / `c2466aa4-2f3e-374f-a78b-6c6d751999c5` | `0x100005158`, `0x100005170` | `0x1000053d0` | `0x1000054b4` |
| arm64e / `092eb768-2a8a-3272-99b8-f19f22b34492` | `0x1000051dc`, `0x1000051f4` | `0x10000545c` | `0x100005540` |

In each slice the `info` call's nonzero return branches to code that stores zero
in the eventual `main` return slot. This is why exit status alone cannot prove a
successful query, and empty stdout cannot be interpreted as an empty trust set.
The preserved excerpt is included in the JSON with the full disassembly hashes.
The existing read-only parser already refuses an empty, malformed or incomplete
group; it remains unchanged.

The `add` branch checks real UID zero, takes `argv[3]`, requires 40 characters,
converts the hex string, passes a decoded 20-byte buffer to
`jbclient_root_trustcache_add_cdhash`, and returns its client result. This
supports a narrowly fixed invocation; it does not prove that any particular
call changed membership. No add, clear, update or restart command was issued.

## Narrow host check

The new module accepts only `candidate`, `wrapper`, `hook_arm64` or
`hook_arm64e`; their fixed CDHashes match the copied 1 November signed-file
observations. It requires bounded original byte streams, strict integer zero
status, complete capture, no timeout/overflow/cleanup error, and quiet complete
queries. The target must be absent before an attempted addition. Afterward the
parsed set must equal `before | {target}` exactly: a missing target, lost hash
or unrelated new hash refuses.

Addition stdout/stderr are preserved as bounded bytes without being interpreted
as proof of success. A refusal never proves zero mutations and grants no retry
or rollback. Callers must durably preserve raw/partial results before parsing.
The result is non-authoritative: native authenticity/freshness, execution,
session, cleanup and device acceptance all remain false. File identity, boot,
health and one-attempt mutation gates still belong to the future native adapter.

Eleven invented host test methods cover the exact transition, all four roles,
already-present targets, zero-exit empty info, unchanged membership, unrelated
changes, malformed/truncated groups, byte bounds, bool/status confusion and
partial transports. Eight private copy-worker tests also pass, including real
host-owned held-FD reads, symlink/hardlink refusal and evidence retention on a
linked-token race. Neither set is device acceptance.

Both full suites ran on 7 November: **1,363 / 1,359 tests**, exactly the same
43 known native Metal failure records as 1 November, zero Errors and 13 Skips
each. They are not fully green. All 51 previously frozen sources match their
baseline; all 53 old/new source/test hashes remained unchanged during the runs.
Both runtime-switch audits pass (286 names, 85 source flag files, 444 entries),
and both C protocol builds/runs pass. No shell or native binary changed; no
arm64/arm64e build or device deployment is part of this pure host check.

## Route selected for a fresh session

Source review supports **fresh exclusive delivery through the existing v7
pipeline**. The projector validates whichever genuine successful delivery
receipt is supplied; it is not bound to the old receipt's date or hash. It then
matches current candidate/source tokens to that new receipt. The receiver
creates absent files exclusively, preserving the meaning of `new_vnode=True`.

This route still needs a separate, default-off current-selection cleanup for
the fixed five files and two directories. It must select and verify all seven
objects with fresh held-FD/content/boot/health/absence gates before its first
unlink, recheck each linked identity, and retain partial action evidence.
It must not reconstruct old `OwnedFiles`, rewrite the original receipt, use
stale `dev` values or reinterpret the offline checker's false authority flags.
Trust membership is not an execution prerequisite for deleting these exact
diagnostic files; all relevant cleanup identity/health gates remain required.
The old cleanup and all eleven execution checks remain unchanged.

The unchanged 41-file delivery bundle still passes its host dry plan. Its
envelope is **284,358 bytes**, exceeding R3's 262,144-byte stdin cap. Use the
reviewed delivery pipeline's separate bounded 1-MiB contract with durable raw
journaling before receipt parsing; do not silently enlarge R3. No delivery was
performed in this pass.

The remaining sequence is scoped current cleanup, genuine exclusive redelivery,
four-artifact trust restoration, a fresh all-eleven observer, a new nonce/session
and three genuine stopped controls before an active Begin/Cancel experiment.
The cleanup action, journaled delivery integration and native trust adapter are
not implemented by this pure postcondition module. Zero stopped controls are
accepted so far. The original control/path refusal and display/freeze cause
remain open; the later changed `dev` values do not explain the older failure.

[Machine-readable evidence](ipados-1641-jbctl-trust-transition-20261107.json) ·
[Prior offline installation check](ipados-1641-installation-revalidation-20261101.md) ·
[Control handoff](../ipados-1641-one-control-handoff.md)
