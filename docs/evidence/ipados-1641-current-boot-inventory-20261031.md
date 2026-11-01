# Current-boot inventory and session refusal — 31 October 2026

Documentation finalized 1 November; all device observations below were copied
on 31 October. They are not a current readiness confirmation.

## Outcome

FACT: four bounded read-only witnesses completed over the existing SSH route:
port inventory, filesystem/cache identities, the existing current-runtime
observer and a delivery-file audit. Original stdout/stderr and transport metadata
were preserved in exclusive host journals before assessment. There were no
candidate executions, job mutations, explicit trust mutations, device file
writes or removals.

The copied boot UUID differs from the historical session; current UI PID rows
also differ. **The historical retained-session capture was not dispatched.**
No original config, timestamp, nonce, source pin, delivery receipt or historical
witness was rewritten. This is a session-admission refusal, not a reproduced
MacWS freeze, a fix or device acceptance.

## Copied observations

| Observation | Result |
| --- | --- |
| Device/build | iPad13,6, iPadOS 16.4.1 / 20E252, Darwin 22.4.0 |
| Rootfs/build | macOS 13.4 / 22F66; existing logical paths unchanged |
| Jailbreak | Dopamine 3.0.10; reported trust backend responds as root |
| Direct Mach-O files | Exact nine names, byte counts, SHA-256 and complete slices match prior witness |
| Cache images | Exact 11 selected image UUIDs, architectures and header-range hashes match; both cache namespaces accepted |
| Free data space | 91,479,146,496 B, approximately 85.20 GiB |
| Thermal/UI | Nominal thermal; copied current native UI generations stable and not stopped |
| Jobs | Both exact user/501 diagnostic labels absent before and after |
| Scratch | Both diagnostic scratch paths absent before and after |
| Signed artifacts | Probe, wrapper and both hooks present; exact content/UUID/CodeDirectory pages validated |
| Reported trust membership | Those four hashes absent from the reported current Jailbreak trust set |
| Original delivery | All five file contents match; each full file token and each created-directory token differs only in `dev` |

The current observer completed in 0.262343 seconds with eight fixed read
commands. Nine of eleven checks passed. The two negative checks are
`candidate_present_identity_trusted` and
`frozen_dependencies_present_identity_trusted`. A complete negative report
remains negative. No execution-denial conclusion follows merely from absence
in this reported trust set; other kernel acceptance routes were not tested.

The previous reported set had 172 hashes. Current port inventory saw 142:
75 old-only and 45 new-only hashes. The later runtime witness saw 145, with
three additional hashes and no removals since the port copy. Membership was
stable across the runtime witness's own two samples. The source of these set
changes is not established. This workflow issued only trust-info queries.

The control scratch was still retained on 25 October; the run scratch was
already absent. They are both absent in the new copies. Their removal time and
cause are unknown; this pass did not remove them. Historical retained-scratch
cleanup is therefore no longer a current removal step.

The initial host comparison incorrectly required exactly one rootfs mount row.
Both copied complete mount objects are identical; neither has an exact rootfs
mount target. Their containing `/private/var` row is the same. There is no
observed mount change. The first comparison remains private as rejected
analysis, alongside its corrected successor; original bytes are unchanged.

## Delivery-file audit

FACT: the complete audit copied five files, 174,394 source bytes, into a
244,512-byte raw report. It exited 1 with empty stderr because all nine original
lineage comparisons refused: two parents, two created directories and five
files. This is a complete negative report, not a transport failure.

Every file's SHA-256 matches the original successful installation. For all five
full `stat9` file tokens and both created-directory tokens, the only changed
field is `dev`; inode, size, timestamps, mode, ownership and link count match.
For the two parents, only the compared identity subset (`dev`, `ino`, `mode`,
`uid`, `gid`) supports that statement. Parent size, timestamps and link count
were not original ownership-comparison fields.

Current physical directory chains, full directory tokens/name lists, the exact
rootless anchor literal/token and before/after current-boot metadata were stable
within the audit. These observations do not establish persistent volume UUID
continuity or recover old `OwnedFiles` authority. No old token was normalized,
no receipt was restamped, and the audit grants no cleanup or session authority.

One earlier audit transport call stopped at a copied local sandbox connection
denial: exit 255, no stdout, 69 bytes of stderr and incomplete stdin. No audit
witness was received. The occupied journal was retained. After a fresh client
network grant and explicit review, one separately named continuation used the
identical payload, expectation and boot binding. There was no automatic retry
or overwrite. Empty output or exit 255 alone was not treated as proof of remote
effects or their absence.

## Validation and limits

All 68 new private host tests pass again on 1 November: 12 inventory/runtime
wrapper fixtures, 50 audit/host/worker tests and six explicit-continuation guard
tests. These include changed evidence retention, physical-FD races, source and
output bounds, the actual 12-second worker self-deadline, default-inert behavior
and refusal to reuse an occupied journal. Real build-only paths passed before
the device calls. Final wrappers, exact worker/input sources, R3 and the journal
were reviewed before their calls. The existing baseline observer uses a null
baseline; it copies current state without manufacturing historical session
admission. Journal file sizes/hashes were read back after capture; completed
fsync steps are based on direct successful method returns, not on a later
persisted true bit alone.

Only documentation/evidence changes in the publication repositories. Existing
runtime/observer/capturer/QA/protocol/pipeline source pins remain unchanged.
The last full suites are from **29 October**: 1,334 / 1,330 tests, the same 43
known native Metal failures, zero Errors and 13 Skips. They were not rerun for
this documentation-only change. Host tests and the 31 October read-only
captures are not new native acceptance.

Port/cache observations are filesystem identities, not loaded-image or full
framework code-page acceptance. Existing port command output is buffered before
its truncation checks, and continuous inventory alarm coverage through final
stdout flush is not proven. Original alarms/budgets and bounded R3 output/time
limits remain unchanged. The new audit has a 12-second self-deadline through
serialization/flush, 20-second host transport limit and 2-MiB output cap.
Timers do not guarantee kernel recovery or remote cancellation. Source pins
assume a trusted host/interpreter.

## Next bounded route

Preserve the original successful delivery as immutable installation provenance.
A new, versioned installation-revalidation record must describe the current
boot's independently copied tokens and all validated content/signature evidence.
It must not replace old `dev` values, silently re-admit the old session or confer
old cleanup ownership. That route remains unimplemented and unaccepted.

The diagnostic-probe pipeline refuses occupied delivery destinations and
deliberately performs zero trust mutations. A broad rebuild/postinstall is not
an exact four-artifact trust restoration route and must not be substituted for
a reviewed narrow action. No trust restoration was attempted.

The current negative observer cannot create a projected session. Establish the
reviewed installation and trust prerequisites, then require a new all-pass
observer and a genuinely new config/nonce bound to current native boot/UI state.
Never refresh old times or relax old identity guards to force a pass. Three
genuine stopped controls are still required before any active Begin/Cancel
experiment; zero are accepted so far.

THEORY: a restart may explain the changed ephemeral trust state and filesystem
device numbers. Captured UUID/set/token differences do not establish those
causal mechanisms. The MacWS display/freeze invariant and its producing layer
remain open.

[Machine-readable evidence and exact identities](ipados-1641-current-boot-inventory-20261031.json) ·
[Previous host capturer](ipados-1641-retained-capturer-20261029.md) ·
[Control handoff](../ipados-1641-one-control-handoff.md)
