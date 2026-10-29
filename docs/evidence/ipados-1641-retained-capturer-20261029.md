# One-attempt retained capture preservation — 29 October 2026

## Facts and scope

FACT: no device connection, iPad-native query, delivery, job signal, stopped
control or file cleanup occurred in this pass. The display/freeze invariant
remains unproven. The last actual process/service retirement is still the
25 October recovery; no new cleanup or device acceptance follows here.

Three host-only modules add the missing preservation path:

- `capture_journal.py` exclusively reserves one new private directory, preserves
  exact stdin and intent, fsyncs and reads back files and directories before
  dispatch, and preserves raw stdout/stderr plus transport status before any
  semantic assessment. Full success has eight fixed files. A malformed trusted
  callback returning just one known stream has a terminal partial path: only
  actual known bytes are written, missing streams stay absent, and no assessment
  or retry is allowed. Every failed phase consumes the instance and preserves
  partial artifacts; close only closes FDs.
- `capture_result.py` strictly parses a complete quiet, source-bound report.
  It checks codec/frame/all 13 entry pins, original byte bindings, typed status
  and zero-authority fields, both stable manifest/file copies, context/provenance
  gates, copied process/trust commands, UI BSD/path blocks, generation absence,
  artifact/dependency identity summaries and observation limits. Positive JSON
  is only what the selected worker reported. It supplies no independent native
  authenticity or fresh cleanup authority. `archive_size_eligible` checks the
  unchanged 2-MiB wire cap; a coherent 2–4-MiB capture is preserved but ineligible
  for that archive step.
- `retained_capturer.py` ties an exact payload to historical Inputs and consumes
  one attempt before IO. The explicit trusted callback is reached once, only
  after successful durable preparation and dispatch intent. Exact returned
  streams are durable before parsing. Timeouts, noisy/partial bytes, cap
  sentinels, malformed output and exit 124/255 cannot cause a retry or authorize
  actions. Transport failure never supplies proof of zero remote effects.

The private endpoint adapter has default-inert and build-only modes, fixed
unused `capture-once` output, exact source/test/QA/worker/configuration/R3 pins,
20-second unchanged R3 invocation and no retry/stage-selection option. Its
fresh in-memory host package validates all four existing dependency sources
before executing any, then loads the three new pinned modules. No ambient
module or filesystem package lookup selects validator code. Endpoint/options,
keys, raw receipts and the adapter remain private. Live use still requires
current device-state confirmation and a fresh read-only port inventory from
the trusted operator; old reports and JSON true bits establish neither.

## Host validation

114 private tests pass: 44 journal, 40 assessment, 21 orchestration and 9 private
adapter tests. The 105 public tests are the first three groups. Actual owned
host files exercise short writes, file/parent fsync and readback failures,
symlinks/hardlinks/substitutions, foreign files, phase reuse, transport sentinels,
one-stream/empty-stream distinctions and raw-before-assessment ordering.
Invented coherent positive reports and mutations exercise the strict assessor;
its positive test forbids filesystem/device/native/process capabilities.

Independent review confirmed the orchestration and final private adapter.
An additional independent compatibility check generated a capture through the
actual published Observer/capture API with a synthetic copying backend, then
passed it to the new assessor: 8 read commands, 6 copied BSD records, 20 counted
native-call placeholders and a reported positive result. These were invented
host records, not actual native calls. The initial journal38 and exact R3 pipe
contract were independently exercised, followed by final partial-path review.
All final sources are bound to the private QA receipt. A fresh-process actual
build-only run passes with the unchanged **190,950-byte worker** and original
payload digest; no native backend or device callback is constructed.

Full suites run **1,334 / 1,330 tests**, with exactly the same **43 known
native Metal failures**, zero Errors and 13 Skips as the previous baseline.
They are not all green. Relevant sources are unchanged during tests. Both
runtime audits (286 names / 85 flags / 444 entries), C-protocol checks and
38 / 41 shell syntax checks pass. Forty-three previously frozen source/test/
pipeline files remain unchanged.

## Limits and next step

Host fsync/readback sequences and Python parsing are bounded by bytes and
structure, not a hard kernel/heap/IO-recovery guarantee. FD/path checks cannot
make operations atomic against another same-UID/root writer; an exclusive
operator and trusted host/interpreter remain premises. A persisted true receipt
cannot prove a final fsync completed; retain the direct successful call return.
An occupied or partial fixed output must not be removed to retry an uncertain
attempt. Local SSH-child cleanup cannot establish remote cancellation.

Worker self-alarm 12 seconds, host budget 20 seconds, stdin 256 KiB, stdout
4 MiB and stderr 16 KiB remain unchanged. One overflow byte is preserved. The
worker, original v7 runtime, validators, QA, pipeline and cleanup guards remain
unchanged. No Apple binary or runtime path/alias patch is introduced.

THEORY: path spelling or identity timing may explain the old refusal; no new
runtime witness establishes that explanation. No capture-only provenance can
admit Cleaner. Next are current read-only inventory and one bounded native
capture; then complete private archive, fresh independent gates, scoped cleanup
and verification before another stopped control. Zero of three genuine stopped
controls are accepted; active Begin/Cancel, freeze fix and device acceptance
remain open.

[Machine-readable evidence](ipados-1641-retained-capturer-20261029.json) ·
[Previous frame/worker evidence](ipados-1641-retained-worker-frame-20261028.md) ·
[Cleanup design](../ipados-1641-retained-artifact-cleanup-design.md)
