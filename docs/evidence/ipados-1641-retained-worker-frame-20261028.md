# Retained-file read-only worker preparation — 28 October 2026

## Scope and facts

FACT: this pass performed no device commands, native iPad queries, delivery,
process signals, file cleanup, stopped control or active pair. The last native
process/service retirement remains the separate 25 October recovery. Its old
scratch files and delivered diagnostic files have not been removed by this pass.
The display/freeze invariant and device acceptance remain open.

FACT: the original retirement stdout is 228,407 bytes. Base64 alone would be
304,544 bytes and exceeds unchanged R3 stdin capacity of 262,144 bytes. A first
JSON/base64-inside-zlib frame also failed its size check; it was rejected. No
old transport limit, historical timestamp, original byte or source pin was
changed to make a payload fit.

The final frame stores a small canonical metadata table and concatenated raw
entry bytes in one bounded zlib stream. Caller-frozen names and hashes select
all six complete historical artifacts and seven exact source/plan entries.
The decoder rejects extra/incomplete streams, decompression overflow, malformed
or noncanonical metadata, foreign/missing names, changed sizes/offsets/hashes
and trailing bytes. It does not execute or import an entry. No historical
projection replaces the original wire.

`retained_inputs.py` now optionally accepts exactly three pinned immutable
validator/plan byte strings. All are checked before their first execution.
The unchanged original validator still reads and hashes the three installed
runtime files at their real device directory. `retained_observer.py` optionally
accepts its two exact dependency source bytes after a reviewed fresh loader
has loaded them. These options avoid staging any new device files. Existing
default file paths, original source guards and control behavior remain.

The reviewed worker template is read-only and requires an explicit boolean
capture mode. Metadata mode performs no decoding, helper execution or native
construction. Capture mode arms a self-only 12-second alarm before decoding;
the alarm remains armed through serialization, stdout write and flush. A fresh
package namespace rejects ambient conflicts. Every entry is rehashed before
the first helper executes, then the worker invokes historical validation and
the explicit native read-only capture API. There is no Cleaner or transport
dispatch in the template.

Normal refusals retain bounded partial observations and copied bytes. If full
JSON output exceeds 4 MiB or cannot be serialized, the worker emits an explicit
negative omitted-report receipt. That receipt is not a complete current native
wire witness and cannot authorize archive or cleanup. Transport truncation,
timeout, partial output and unknown results cannot authorize retry or cleanup.

## Validation and remaining work

The final offline build round-trips **419,088 original bytes** into a
**126,321-byte frame** and a **190,950-byte complete worker**, below unchanged
262,144-byte stdin capacity. All six original evidence hashes and all seven
source/plan hashes match. A host execution of this exact frame/worker, with
native/child capabilities explicitly forbidden, reaches the expected missing
installed-runtime refusal before any native construction. This is a negative
host integration check, not a device capture.

**93 new tests pass**: 49 frame, 17 embedded-input, 5 embedded-observer and
22 worker cases. These cover incomplete/concatenated streams, expansion bombs,
canonical metadata and offsets, substitutions, all-source-before-exec binding,
missing original runtime files, ambient namespace conflicts, partial captures,
output overflow and default-inert paths. Own disposable host children verify
both an unmodified 12-second self-exit with status 124 and the alarm still armed
at stdout flush; shorter derived fixtures cover other timeout stages.
Independent final codec/worker/build-only review found no blocking issue and
independently passed 71 frame/worker tests. The embedded observer source and
Inputs path were separately reviewed. These results are host evidence only.

Full suites run **1,229 / 1,225 tests** with exactly the same **43 known
native Metal failures**, zero Errors and 13 Skips as the previous baseline.
The suites are not all green; this pass adds no native acceptance. Relevant
sources are unchanged during tests. Both runtime audits (286 names / 85 flag
files / 444 entries), C protocol checks, 38 / 41 shell syntax checks and diff
checks pass. Thirty-five previously frozen source/test/pipeline files remain
unchanged; only the new embedded APIs and new framing/worker tooling change.

The private build-only tool has no SSH/device execution capability. It verifies
the final source pins, replays the six unchanged historical artifacts, checks
lossless frame round-trip, compiles the rendered worker and refuses a payload
over the unchanged 256 KiB stdin cap. Source/byte hashes authenticate only the
reviewed caller-selected bytes under a trusted host/interpreter assumption;
they do not attest arbitrary loaded Python state or native authenticity.

The alarm exits only the disposable worker. It does not guarantee recovery
from a kernel stall or cleanup of every managed read child after abrupt exit.
The existing 8-second cooperative observer budget, one-second gate freshness,
bounded command/file/native queries, root-writer race limitation and exclusive
operator premise remain. This frame cap is not a hard interpreter heap bound.

THEORY: the old refusal may involve path spelling or identity timing. This
pass supplies no new runtime witness establishing that explanation and changes
no Apple binary, alias guard or runtime path behavior.

Next: independently review a one-attempt host capturer that durably preserves
intent, exact stdin/stdout/stderr and transport outcome under existing limits.
After current device availability and normal operation are confirmed, collect
fresh read-only port inventory and one bounded capture. Full private archival,
fresh native gates and the separately reviewed scoped cleanup are still needed
before considering another stopped control. No capture-only provenance can
admit final cleanup.


Source hashes, measured byte counts and final gate results are recorded in the
[public JSON receipt](ipados-1641-retained-worker-frame-20261028.json). Complete
old inputs, rendered worker/frame, host-only negative result and QA logs stay
private. No Apple binaries, device identifiers, credentials or endpoint
configuration are included. See the
[previous adapter evidence](ipados-1641-retained-observer-20261027.md) and
[cleanup design](../ipados-1641-retained-artifact-cleanup-design.md).
