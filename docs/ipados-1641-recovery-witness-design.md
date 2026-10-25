# Future ownership and bind-refusal witness design — 25 October 2026

Offline design only. No runtime or device file,
source pin, transport, or native-control state is changed by this design.
This is observability/recovery preparation, not a display/freeze fix and not
authority to rerun the occupied 24 October control.

## Reviewed scope and confirmed gap

Read all 2,009 lines of the publication AGENTS.md. The companion is the same
document except for the ten-line historical location/standby observation;
the complete common content and that difference were reconciled. Applicable
rules remain exact evidence, fail-closed identities, default-inert diagnostics,
scoped cleanup, no speculative runtime relaxation, and separate native
acceptance.

Reviewed the current pinned `controller.py`, `runtime_support.py` and
`watchdog.py`, the complete original normal stdin and returned stdout, all
session JSON inputs, normal host/decoded envelopes, and subsequent read-only
snapshot. Nested JSON stdout envelopes were decoded for the token search;
source literals and later stat values were not adopted as runtime authority.

FACT: `controller.execute()` creates `OwnedFiles` at line 320 and passes its
directory token and two file tokens only in the independent watchdog's stdin
body at lines 322–332. The controller report and watchdog event never copy
that body. The initial stopped probe/birth witness *is* copied to the original
report. Delivery tokens in session `tokens.private.json` identify the three
installed Python sources; they do not identify runtime scratch objects.

FACT: the original normal stdout is a complete 3,009-byte JSON object, SHA256
`3d90ab04efd4d1a848f46b559309654478dbfe67b000a1866b0a8d6f564c330e`.
It contains no original scratch directory/file ownership token. Nor do the
inspected original inputs/envelopes. Later snapshot tokens explicitly describe
current observations. Original scratch ownership is not recoverable from
this saved artifact set. This does not assert that matching-looking current
objects are foreign; it asserts that their original identity was not retained.

FACT: `RealBackend.bind()` lines 588–603 has a logical-wrapper branch followed
by the combined exact path/samefile gate. Python short-circuits path equality
before `samefile`, then performs a separate expected executable stat-token
check. Both original watchdog errors copy only `Refused: exact target
path/inode`. Neither serializes the observation that failed. A later logical
versus resolved wrapper path cannot reconstruct the earlier offending sample.

THEORY: a resolved startup-wrapper spelling may explain that refusal. It
remains unproved. The proposed diagnostics must never normalize a failed path,
accept an alias, replace original ownership, or change the rejection result.

## Smallest useful future instrumentation

1. Immediately after successful `OwnedFiles.create()`, and before starting
   the watchdog or bootstrapping launchd, copy a bounded ownership witness
   into the controller's private report. Copy the *original stored tokens*
   after `files.checked()`, rather than manufacture a replacement token from
   a fresh path stat. Include schema, operation, exact scratch path, admission
   digest, run nonce, source map, boot binding, directory `[dev, ino]`, the
   exact `job.plist` and `probe.log` identities, immutable plist hash, and
   log hash null. Deep-copy so later mutation cannot alter the frozen record.
   Return the same witness/digest in the watchdog ready/final reports after
   its inherited directory FD and supplied tokens pass `checked()`.

2. Add bounded structured *first bind refusal* evidence to `RealBackend`.
   Record its stage and actual copied process witness before evaluating the
   failing predicate. On refusal freeze it once; subsequent cleanup binds
   must not overwrite it. Copy the controller backend's and the independent
   watchdog backend's separate records in their own finally paths. Keep a
   separate last-bind record only if it is needed; never relabel it as first.

3. The refusal record needs the exact logical expected paths, actual
   `proc_pidpath` string, copied 136-byte BSD-info block/digest/birth/status,
   expected birth or null, `allow_wrapper`/`stopped` arguments, selected
   branch, path equality result, and the actual stat/samefile values used by
   the guard. Preserve evaluation order: if path equality is false,
   `samefile_evaluated` is false and its result/stats are null. If a query
   raises or is short, retain bounded return/error metadata and keep unknown
   fields null. Do not introduce extra diagnostic reads in the predicate and
   call them the original measurements. Any optional `realpath` or separate
   no-follow stat is a distinctly labelled later diagnostic observation.

4. Keep the existing refusal, first/second-resume counts, deadline, health,
   ownership, signal and cleanup gates unchanged. The recorder has no action
   callback, fallback, signal, adoption or execution route. Bounded recorder
   failure also refuses; evidence serialization never makes an unsuccessful
   control acceptable. The default CLI/import remains metadata-only.

This is the smallest final-report retention change. It is **not durable
host preservation before bootstrap**: a lost final report can still lose
these original tokens. Do not advertise that stronger guarantee.

## If durable preservation before bootstrap is required

Use a separately reviewed, two-phase future diagnostic, rather than claim
that adding an in-memory field is sufficient:

- An explicit ownership-preparation call checks fresh baseline/source/QA,
  exclusively creates the two scratch files and directory, validates the
  original FD/token witness, fsyncs its newly written immutable file and
  directory, returns only the bounded source/session-bound ownership record,
  and exits **without watchdog, bootstrap, debug admission or resume**.
- The host preserves the complete original returned bytes exclusively,
  fsyncs/readbacks the private receipt and parent directory, and writes a
  digest/provenance manifest. Failed/partial preservation authorizes no job.
- A second explicit call consumes those original bytes. It revalidates age,
  device/source/session/admission/boot/UI/thermal/exclusivity, opens the exact
  scratch directory with `O_DIRECTORY|O_NOFOLLOW`, verifies the saved original
  tokens and immutable plist through the held FD, then enters the same
  independent-watchdog protocol. It does not call `OwnedFiles.create()` again
  or replace the token record. Changed/missing/replaced objects refuse.
- Abandoned preparation needs separately reviewed exact owned-file cleanup
  using that first receipt and an absent-job baseline. Partial creation stays
  explicit and conservative. No recursive cleanup or token adoption.

The diagnostic offending process does not exist before bootstrap. Therefore
only file ownership can be preserved before launchd mutation; the offending
path/birth/stat sample must be retained at the later failed bind, before
cleanup/signaling. Scratch creation itself is a mutation and must be described
honestly. This two-phase design is more than the minimal report-only fix;
its additional action surface needs its own design review and tests before
implementation. Neither version authorizes a current device run.

## Exact source pin migration required for future implementation

Preserve the current v7 package and its staged bytes for old evidence. Current
three-source bindings are:

| Source | SHA256 |
| --- | --- |
| controller.py | `955c50b5cb2b30b8f0aefd69720675d04c91126dec17c802fb09be8c42197977` |
| runtime_support.py | `5d09cf9380afaa2409661a58909d1bfee41d81943f1b2306facb0cd94ee10fe0` |
| watchdog.py | `c28ec9edd30bf86613c7cb29693697901228b579100b8b181a4dc47915f00e0a` |

Prefer a parallel explicitly versioned future source package and report/config
schemas, with v7 decoder/fixtures retained unchanged. Do not overwrite old
runtime files or turn the v7 preparer into a permissive mixed-version loader.
No new source digest can be predeclared until its final bytes exist.

Migration has a dependency order:

1. Freeze/review/test the future controller/support/watchdog bytes, including
   any explicitly named extra reporter module in the source map. Recompute
   all affected exact source digests together.
2. Generate new canonical offline QA bound to exactly that map. Retain all
   previous guards and label all synthetic execution as such. Do not reuse
   v7 QA `ebee0b...`, an old native control, or a manually edited pass receipt.
3. Produce a new delivery bundle/manifest/plan with those source/QA hashes.
   A changed runtime cannot use the existing five-file bundle. Leave the
   unchanged signed C probe identity/profile intact if its bytes are unchanged;
   do not re-sign Apple binaries or mutate trust merely to migrate Python.
4. Create version-specific read-only observer inputs/support pin, preparer,
   projector and cleanup contract. Their pins currently bind the v7 support,
   QA, bundle, plan, observer and source maps. Recompute bottom-up, then freeze
   the resulting aggregate hashes in the host persistence/transport adapters.
   Do not only replace the first SOURCES dictionary found by search.
5. If new staging/labels/scratch are introduced, enforce absence of the old
   occupied labels/processes/scratch too. A new name must not bypass the
   existing refusal. Fresh pipeline delivery/token receipts are mandatory.
6. Preserve old captured inputs, generated stdin, raw stdout and decoder replay.
   Verify the old actual negative report still refuses in its original decoder.
   Future controls start at zero accepted controls and need their own current
   original-byte witnesses after recovery/baseline/device-state checks.

The C probe, frozen wrapper, libmachook, GPU ABI, control resume boundary and
freeze semantics need no change for this observation gap. Do not present
source migration as acceptance of any of those components.

## Required synthetic tests and acceptance limits

- Default imports/CLIs make zero native calls, child jobs, network calls,
  signals or filesystem mutations. Future execution needs an explicit route.
- An actual `OwnedFiles` created in a temporary host directory produces a
  typed deep-copied witness matching its original tokens; reject unexpected
  entries, symlinks, replacement directory/file inodes, malformed/duplicate
  keys, oversized fields and changed immutable plist. Unknown log hash stays
  null, not an invented immutable hash.
- A fake execute trace proves the ownership snapshot and matching watchdog
  acknowledgment precede bootstrap. Snapshot/acknowledgment failure yields
  zero bootstrap/debug/resume calls and explicit partial cleanup status.
- For the optional durable two-phase design, test failed/short writes, fsync
  and directory-fsync failures, existing receipt names, readback mismatch,
  partial creation, stale/wrong-session/boot/source receipts, abandoned
  preparation and no job after any host persistence failure. No current-token
  refresh can make a rejected original witness acceptable.
- Exercise the real future bind function with explicit fake process/job/stat
  dependencies: exact target, exact logical wrapper, differently spelled
  wrapper, unrelated path, same spelling/different inode, stat-token change,
  birth change, stopped=false, short query and errno. Compare gate results
  against v7 on every case. Do not add alias acceptance to make a test green.
- Verify path-false skips samefile/stat exactly as v7, and missing fields are
  null. First monitor refusal survives a different cleanup refusal; controller
  and watchdog records remain separate. Cap all witness/frame sizes and time.
- Run exact owned-source controller/watchdog replay on a forced bind failure;
  original ownership and the offending copied evidence remain in the full
  negative report. Portable decode/projection checks must preserve originals,
  reject non-null pair results, reject fabricated success and retain unknown
  counts. No synthetic fixture becomes native control authority.
- Test each old/new source/schema/QA/bundle/pin mismatch before module/native
  execution. Regenerate coherent version-specific fixtures instead of merely
  substituting digests. Mirror shared final files to both repositories; run
  focused/full suites, runtime-switch audit, protocol, shell and diff checks.

Native acceptance remains separate: no new control until the existing job
has been safely retired and the occupied baseline handled; then a fresh
authorized device state/inventory, fully checked delivery, one bounded normal
stopped control, exact cleanup and copied offending witness. Zero native
stopped controls are accepted by this design. Display/freeze diagnosis and
visible stability remain open. Process-only job retirement, if independently
supported by the original birth witness, does not confer scratch-file ownership.
