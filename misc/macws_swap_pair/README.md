# Own swap-pair controller v7 — unverified port

These three own Python sources are byte-identical to the frozen v7 controller,
backend and independent watchdog reviewed on 2026-10-19. The linked
[offline evidence](../../docs/evidence/ipados-1641-launchd-domain-offline-20261019.md)
binds their hashes to 107 synthetic host tests, including the copied native
service-domain regression and retained descriptor/report-finalization tests.
The private raw fixture and reports are excluded from Git.

Default invocation only hashes the three local sources and prints metadata:

```sh
python3 misc/macws_swap_pair/controller.py
```

No native API, job, trust, signing or deployment operation is performed by that
default. Native execution remains unverified and requires explicit, fresh,
source-bound prerequisite files and three genuine stopped controls before an
active pair. Hardware/build/rootfs/hook/signature/clock/ownership gates remain
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
observation is separately gated by the exact observer/input hashes and remains
unverified on the device. Only fixed read-only commands are permitted, including
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
Neither historical v5/v6 session files nor the read-only observer output may
be reused as new control prerequisites. Device tests remain deferred while the
iPad is unavailable.

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
The complete suite of portable swap-pair controls now contains 127 tests.
Freshness, authenticity, cleanup verification and device acceptance remain
unverified by this rehearsal.
