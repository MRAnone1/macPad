# Ownership-capture offline preparation — 25 October 2026

This pass adds a reference ownership-witness snapshot/decoder and a separately
reviewed retained-artifact cleanup design. It makes **zero device calls** and
changes no installed payload, controller, watchdog, trust state or Apple binary.
No file cleanup, new stopped control or display/freeze fix is accepted.

## FACT: implemented and tested offline

`misc/macws_swap_pair/ownership_capture.py` is a byte-identical copy of the
independently reviewed private primitive. Its 27 synthetic tests use the actual
unchanged byte-pinned v7 `OwnedFiles` in self-owned host temporary directories.
Only the synthetic fixed scratch paths are narrowly patched. Public tests
change just their import and repository-relative source locations.

Capture binds the exact three-source map and existing config validation,
freezes the caller-held object's **stored** directory/two-file tokens, calls
its unchanged read-only `checked()` and rejects subsequent token mutation.
It returns a typed, deep-copied witness with configuration/admission/operation/
nonce/boot/source bindings. The immutable plist hash must match the configuration;
the mutable log hash stays null. Validation/decoding has no cleanup or action
route. Six provenance/action/acceptance/durability flags remain false.

Source leaf reads use no-follow/nonblocking descriptors, bounded complete reads
and stable stat fields. The JSON envelope is bounded to 16 KiB, with depth/node/
string/collection limits, strict token types, duplicate-key rejection and
nonfinite-number refusal. Independent review caught a Python equal-float token
comparison; canonical post-check comparison and its regression now reject it.
Root review also added FIFO and short-read regressions.

The tests cover original token fidelity, deep copies, inode replacement,
symlinks, extra/missing entries, immutable content changes, log size, changed
session/operation/config/source, malformed/digest/byte/structure limits,
source substitution/short reads/changes, token changes during validation and
inert defaults. Guards prohibit native construction, network, subprocesses,
signals and file writes/deletes during the helper APIs. Test fixtures themselves
create/remove their own temporary files; that is not a device operation.

## Limits and unfinished integration

This is a trusted-caller reference primitive. Matching source files and the
exact class do **not** authenticate loaded code, creation timing, caller
history, current-token provenance or freshness. Reconstructing an object from
current tokens cannot acquire original authority merely by passing this API.
No witness from this pass is native control evidence. The unchanged runtime's
`checked()` retains its existing I/O/concurrency limits; a structural budget
is not a hard wall-clock bound or defense against another root writer.

The existing controller/watchdog never calls this helper. Watchdog matching
acknowledgment, first bind-refusal capture, durable host preservation before
bootstrap and coherent future source/QA/schema/bundle/observer migration remain
open. A final-report field alone would still be lost with a lost final report.
No wrapper/path gate has been relaxed, and the old failure's alias explanation
remains THEORY.

The [separate cleanup design](../ipados-1641-retained-artifact-cleanup-design.md)
selects exact **current retained** diagnostics only after fresh complete capture,
content lineage, a durable byte archive and independent native absence gates.
It has no implementation or transport yet. Later tokens never become original
`OwnedFiles` authority. The prior snapshot lacks link counts, so it cannot by
itself satisfy the future full manifest. The two scratch files and five staged
payloads remain retained; existing original delivery cleanup remains unchanged.

## Validation and continuation

See the [machine-readable dated evidence](ipados-1641-ownership-capture-20261025.json)
for final source hashes and exact focused/full-suite results. The full suites
retain the known 43 native Metal failure records and are not reported green.
Protocol, runtime-switch audit, shell syntax and diff checks are recorded
separately. No new runtime switch is introduced.

The iPad can remain in standby for offline work. Before another device access,
notify the user, then use a reviewed fresh read-only capture. File cleanup must
be resolved before any new control. Zero of three genuine stopped controls are
accepted; original freeze diagnosis and device acceptance remain open.
