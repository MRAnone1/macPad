# Own swap-pair controller v7 — unverified port

These three own Python sources are byte-identical to the frozen v7 controller,
backend and independent watchdog reviewed on 2026-10-19. The linked
[offline evidence](../../docs/evidence/ipados-1641-launchd-domain-offline-20261019.md)
binds their hashes to 107 synthetic host tests, including the copied native
service-domain regression and retained descriptor/report-finalization tests.
The private raw fixture and reports are excluded from Git.

Latest device result: [25 October process recovery](../../docs/evidence/ipados-1641-process-retirement-20261025.md)
retired the original stopped job from the failed 24 October control. Both
labels are absent; control scratch and delivery cleanup remain unresolved.
Do not dispatch another control on that occupied scratch baseline.

Default invocation only hashes the three local sources and prints metadata:

```sh
python3 misc/macws_swap_pair/controller.py
```

No native API, job, trust, signing or deployment operation is performed by that
default. Successful stopped-control and active-pair execution remain unverified.
Native controls require explicit fresh source-bound prerequisites; active pairs
additionally require three genuine stopped controls.
Hardware/build/rootfs/hook/signature/clock/ownership gates remain
specific to the recorded iPad13,6 / iPadOS 16.4.1/20E252 port. The code is not a
portable generic launchd or iPadOS controller.

Use the project's [isolated delivery pipeline](../../docs/diagnostic-probe-pipeline.md)
for its pinned private own-probe bundle. It copies five files without running
them. These public copies make the implementation reviewable; they do not
replace the pinned bundle or create device acceptance. Explicit execution
reports contain private native state and must stay outside public logs/Git.
Do not dispatch while the device is unavailable, or reuse historical receipts
as fresh prerequisites.

Portable synthetic controls use no private fixture or device:

```sh
python3 -m unittest discover -s misc -p 'test_macws_swap_pair.py'
```

## Offline handoff tools — 2026-10-19

The [handoff evidence](../../docs/evidence/ipados-1641-offline-handoff-20261019.md)
records the separate read-only observer v4 and stopped-control payload preparer
v7r2. Their ordinary invocations print metadata without native APIs, signals,
child processes or device access:

```sh
python3 misc/macws_swap_pair/readonly_observer.py
python3 misc/macws_swap_pair/prepare_control_payload.py
```

`observer_inputs.json` contains exact own runtime-support source, static
build/signature identities and historical evidence digests. Its baseline is
null. It is neither a current inventory nor an admission receipt. Explicit
observation is separately gated by the exact observer/input hashes. It was
unverified on the device at that offline handoff. Only fixed read-only commands are permitted, including
the two `user/501` label queries; present, redirected or unknown jobs refuse.
The observer retains partial observations when final clock or budget reporting
fails. Unavailable fields stay null and all admission flags stay false.
Hardware/build/rootfs/free-space/cache inventory is still required separately.

The payload preparer provides **no transport** and supports only the three
stopped controls. Building a private payload requires explicit config,
prerequisite, installed-source-token, source-directory and canonical QA paths,
plus an exclusive output path. `offline_qa.json` is the unchanged canonical v7
synthetic QA document. The preparer checks exact source/QA hashes and input
structure. It creates no session, token, native witness or current timestamp.
It cannot check device freshness at preparation time. Actual execution must
revalidate prerequisites against the native shared clock and current backend
before any job can start.

The pure result decoder preserves bounded stdout/stderr and timeout data. A
positive structural interpretation requires the explicit expected config and
consistent full report, source/control/session bindings, native-state bytes,
cleanup, projection and receipt digests. This is internal consistency of
supplied bytes; it authenticates no arbitrary JSON and grants no device,
freshness or active-pair acceptance. Partial failures retain unknown counters
as null. There is no live dispatch command in this handoff.

Portable tests use synthetic fixtures only:

```sh
python3 -m unittest discover -s misc -p 'test_macws_swap_pair*.py'
```

The five-file delivery bundle and runtime controller sources are unchanged.
Neither historical v5/v6 session files nor historical read-only observer output
may be reused as fresh control prerequisites. Device tests were deferred at
that handoff while the iPad was unavailable.

## Explicit session and cleanup preparation — 2026-10-23

`project_session.py` has a metadata-only CLI and one explicit Python API. It
requires original observer-v4, validated delivery/plan and canonical QA bytes,
an external nonce and exact source paths. It returns v7 structures and original
raw provenance in memory. It writes no session files, generates no nonce and
reads no current clock. Native execute must still check actual age and state.
The output contains private runtime data when real inputs are supplied; retain
it only in exclusive private storage. Arbitrary consistent JSON is not
authenticated device evidence.

`cleanup_payload.py` also defaults to metadata and provides no transport. Its
explicit builder requires the exact own observer/input bytes,
`reviewed_delivery_plan.json` and an actual validated delivery receipt. The
static plan contains own paths/signature hashes, not a native installation
receipt. The generated source repeats a live read-only baseline and can remove
only the five pinned payloads and their two verified directories. Full
identity/content checks precede every unlink; partial failures stay negative.
Final absence distinguishes FileNotFoundError from I/O/access failures. This
does not prove atomic namespace ownership or native cleanup acceptance.

Neither tool is an automatic dispatch, recovery or active-pair command. The
[dated evidence](../../docs/evidence/ipados-1641-offline-session-20261023.md)
records the synthetic tests and private normal-control transport review.
All 19 October native inventories remain historical; the unavailable iPad was
not accessed in the 23 October pass.

## Shared offline workflow rehearsal — 2026-10-23

The [workflow tests](../test_macws_swap_pair_workflow.py) connect projection,
normal-control preparation/decoding and cleanup preparation using one invented
in-memory observer/delivery context and the exact reviewed static plan. Five
file records, both directory records, candidate/source tokens and preserved raw
digests must agree across these boundaries. The generated control and cleanup
payloads are compiled only; neither is executed. The invented normal report is
rebound to that same configuration and proves decoder consistency only.

The six tests also record an important contract boundary: projection accepts
root UID without requiring group zero or the two cleanup directory records.
Cleanup requires both directory records and UID/GID zero. Its refusal remains
in place. A successful receiver normally records both directories, so the old
session test's empty directory array is incomplete test data, not evidence of
a receiver failure. No current device failure or policy fix is established.
When fresh delivery bytes become available, check the complete cleanup contract
before dispatching a control. An incompatible receipt must not be rewritten
to make cleanup preparation accept it.

See the [dated rehearsal evidence](../../docs/evidence/ipados-1641-offline-workflow-20261023.md).
The complete suite at that rehearsal contained 127 portable swap-pair tests.
Freshness, authenticity, cleanup verification and device acceptance remain
unverified by this rehearsal.

The [single-control handoff](../../docs/ipados-1641-one-control-handoff.md)
orders the fresh inventory, delivery, admission, one normal attempt and exact
cleanup gates. It also records private capture/storage/transport wiring that
must be reviewed before dispatch. It executes no commands.

## Actual negative normal control — 2026-10-24

One fresh admitted normal attempt recorded one bootstrap and zero resumes.
The independent watchdog refused its exact path/inode guard and could not
verify cleanup. At the end of that attempt, the job, stopped native process,
control scratch and staged delivery remained. The process-only follow-up below
retired the job. The offending
path/stat sample was not copied, and a current snapshot cannot recreate the
original scratch ownership tokens. No runtime identity guard was relaxed.
See the [dated evidence and cleanup limitation](../../docs/evidence/ipados-1641-normal-control-20261024.md).

The host decoder now accepts the producer's absent-or-exact-null
`pair_result_private` placeholder. Its full report remains unchanged; non-null
values still refuse. The fixture uses the exact pinned producer projection.
All 129 portable tests pass. The actual negative report remains refused, the
full suites retain their native Metal failures, and zero stopped controls are
accepted. This host compatibility fix grants no active-pair or freeze acceptance.

## Process-only recovery — 2026-10-25

`process_retirement.py` is a separate dependency-injected capability; its
ordinary invocation prints metadata. It constructs no native backend and
provides no transport, default execution, `OwnedFiles` substitute, file deletion,
resume, new job or trust mutation. Its explicit API needs original copied
config/report/delivery evidence and a separately reviewed real caller. JSON
consistency alone grants no authority. Historical times are not refreshed.

The reviewed private caller verified the original native stopped generation,
source/artifact/token and exact current service, called the unchanged runtime
bind gate with wrapper fallback disabled, then made one exact-service SIGKILL
and one bootout. Copied ESRCH and job absence verify process/service retirement.
Both labels are free; control scratch is the sole refusal among eleven fresh
observer checks. File ownership/cleanup, three stopped-control acceptance and
freeze remediation remain open. No new control was attempted.

The public core is byte-identical to that executed helper. Its 44 synthetic
tests are in `misc/test_macws_process_retirement.py`; sixteen private host/
worker tests cover timing, bounded capture and partial-effect refusal. The
[dated recovery evidence](../../docs/evidence/ipados-1641-process-retirement-20261025.md)
records actual scope, known full-suite failures and non-atomic service limits.
The [future witness design](../../docs/ipados-1641-recovery-witness-design.md)
preserves original file tokens and first-refusal observations for future work;
it has not been deployed. The staged v7 package remains unchanged.

## Offline ownership capture — 2026-10-25

`ownership_capture.py` is a reference stored-token snapshot/decoder, with 27
synthetic tests in `misc/test_macws_ownership_capture.py`. Import/default CLI
is metadata-only. Explicit capture verifies the exact v7 source bytes and
config, freezes the caller-held original `OwnedFiles` tokens, calls unchanged
`checked()` and returns a strict independent copy. The mutable log hash stays
null; no current tokens are adopted. Source leaf reads are nonblocking and
no-follow, bounded and stable; the unchanged runtime check retains its existing
I/O/concurrency limits. This is a trusted-caller helper, not a Python sandbox
or an authenticated native witness. It cannot prove creation timing or loaded
code integrity and grants no action authority.

It has no controller integration, watchdog acknowledgment, durable receipt,
transport or cleanup route. Future integration requires coherent versioned
source/QA/bundle migration. The [dated offline evidence](../../docs/evidence/ipados-1641-ownership-capture-20261025.md)
and [separate retained-artifact cleanup design](../../docs/ipados-1641-retained-artifact-cleanup-design.md)
record what remains before another device action. Existing runtime switches
and their inventory are unchanged; no native control or freeze fix is accepted.

## Retained-artifact archive and cleanup reference — 2026-10-26

`retained_archive.py` exclusively preserves a complete bounded wire capture,
manifest/provenance and two files in a private host directory. All six files,
the archive directory and parent are fsynced/read back. `verify_archive()`
requires caller-frozen expected manifest, provenance, wire and both file hashes;
rewriting a blob and receipt together cannot refresh those expectations.
Only the direct successful creation return establishes completion of that
process's fsync steps. A persisted true bit or later verification cannot prove
past durability or native authenticity. Failures preserve partial artifacts.

`retained_cleanup.py` provides read-only selection and an explicit one-use
reference core for only the fixed two-file control scratch. It requires both
content hashes from previously copied evidence, a matching successful archive
receipt and a trusted caller supplying fresh copied boot/source/UI/thermal,
original-generation ESRCH, both-services absence and no candidate/test workload
checks. No real observation backend or transport is provided. Its only effects
are two exact FD-relative unlinks and one exact empty-directory removal, with
full identity/content/link checks, held path anchors and per-effect freshness.
The result preserves bounded gate observations, failed stage, refusal and
attempted/completed effects. Unknown/partial results never retry.

Both defaults are inert. The 8-second cooperative budget and 1-second freshness
checks are not hard I/O interruption, kernel recovery or protection against
another root writer. No `OwnedFiles` authority is reconstructed; the old runtime,
QA, bundle and delivery cleanup remain unchanged. 39 archive and 39 core tests
use only self-owned host temporary files, including actual archive-to-core
integration. These are not native acceptance. See the
[dated scope, results and open live-adapter requirements](../../docs/evidence/ipados-1641-retained-artifact-20261026.md).

## Read-only retained observer — 2026-10-27

`retained_inputs.py` binds six original raw artifacts and the unchanged v7
context plus full five-file/two-directory delivery validators. Historical
retirement wire/generation/job/command data and complete old plist/log are
checked offline. Current selection never inherits old scratch inode authority.
Inputs, returned maps and canonical JSON are bounded and mutation-checked.

`retained_observer.py` provides an explicit native read-only factory, state
observations and two-copy retained-file capture. It strictly parses every
process/trust row, copies native query blocks before refusal, validates original
artifact tokens/hashes/signatures/trust, and holds/revalidates complete physical
path chains. The intentional rootless target is exact; its freshly copied lexical
spelling/inode stays pinned for the whole session. Gates retain their oldest
observation time. Failed stages and bounded current copies remain in the report.

Defaults are inert. 43 input and 38 observer tests pass, including real temporary
host archive→Cleaner→Observer integration and disposable host pipe faults. No
native query or device cleanup was executed. Cooperative budgets, one-block
negative command overshoot, loaded-module trust and root-writer races remain
explicit limits. At that checkpoint there was no hard worker/transport; the historical
retirement wire exceeded unchanged R3 stdin capacity after base64. Capture-only provenance
cannot authorize final cleanup. See the
[dated evidence and remaining integration requirements](../../docs/evidence/ipados-1641-retained-observer-20261027.md).


## Lossless frame and read-only worker — 2026-10-28

`retained_frame.py` encodes exact caller-pinned bytes with a canonical bounded
metadata table and a single bounded zlib stream. Foreign/missing entries,
changed offsets/hashes, incomplete or concatenated streams and expansion bombs
refuse. All six original historical artifacts remain complete. The frame cap
is 128 KiB, metadata 8 KiB, each entry 512 KiB and all entries 2 MiB.

`retained_worker.py.in` is a reviewed template requiring all six placeholders
rendered once by a trusted caller; it is not an executable dispatch command.
False capture mode is inert. True arms a 12-second self-only exit before decode
and keeps it through serialization/write/flush. It rejects ambient package
modules, checks every one of 13 entry hashes before helper execution and calls
only the explicit read-only capture API. New optional embedded-source APIs avoid
staging validators; the unchanged original validator still requires the three
installed runtime sources. Pins do not attest arbitrary loaded Python objects.

The actual offline payload is 190,950 bytes within unchanged 256 KiB stdin,
with 419,088 original bytes round-tripped. 93 new host tests pass, including the
unmodified 12-second self-exit. Oversized/unserializable captures produce an
explicit negative omitted-report receipt; it is not a complete native witness.
No transport, device capture or cleanup is provided. The alarm cannot promise
kernel recovery or cleanup of every managed read child after abrupt exit.
See the [dated evidence and next prerequisites](../../docs/evidence/ipados-1641-retained-worker-frame-20261028.md).


## One-attempt host preservation — 2026-10-29

`capture_journal.py` creates one exclusive host journal, preserves stdin/intent
before dispatch, and fsyncs/readbacks raw stdout/stderr and transport status
before semantic assessment. Partial known streams are preserved without
inventing missing bytes; all failures consume their phase, never retry/delete.
`capture_result.assess()` validates complete source-bound worker/selection/gate
and trace reports with bounded parsing. It returns digest summaries and what
the worker reported, never independent native authenticity or cleanup authority.
A 2–4-MiB report stays preserved but exceeds the unchanged 2-MiB archive cap.

`retained_capturer.OneShotCapture` binds payload and original Inputs, invokes an
explicit trusted transport callback at most once after durable dispatch intent,
and journals raw bytes before calling the assessor. Defaults construct no
endpoint, SSH process or native backend. The private fixed adapter still needs
current device readiness and fresh read-only inventory before live use. No
archive or Cleaner is called automatically. 105 public host tests pass;
114 private tests include adapter boundaries. See the
[dated evidence and remaining device steps](../../docs/evidence/ipados-1641-retained-capturer-20261029.md).
