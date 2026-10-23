# Host-suite failure triage and one-control handoff — 2026-10-23

The iPad remains unavailable. This pass changes four host test harnesses and
documentation only. There is **no iPad/SSH access, device deployment, native
observer/control, trust mutation or actual admission/session receipt**. The
production verifier/trust code, probes, v7 runtime, frozen preparation sources
and delivery bundle remain unchanged. No freeze reproduction or device fix is
claimed.

## FACT — bounded before/after host witnesses

The 14 previous failure/setup-error entries divide into seven Settings fixture
cases, one Office CPU-fixture compiler error, two Metal class compiler errors
and four No-Copy native failures. Each group was reproduced before a change.
The [redacted receipt](ipados-1641-host-suite-triage-20261023.json) binds source hashes, private compiler/mode/
runtime witnesses, independent reviews and final suite logs.

The Settings fixture requests mode `04755`, but copied host stats immediately
report `00755`, including after a repeated chmod and signature scan. The
unchanged verifier correctly refuses a carrier missing the setuid bit before
later registration/signature assertions. The test now explicitly models only
the invented carrier's permission bits. Real file kind, owner, contents and all
trust identity fields remain real; other paths, bytes paths and integer file
descriptors delegate unchanged. The negative test still models `0755` and
requires the actual verifier's rejection. All nine Settings tests pass; the
seven earlier failed cases now reach their intended checks. This is synthetic
fixture portability, not native setuid or Settings acceptance.

On this arm64 macOS 27.0.1/26A434 host with SDK 27.0, Apple clang 21 promotes
the newly deprecated managed-storage APIs to errors under `-Werror`. The sole
compiler behavior change is an explicit `-mmacosx-version-min=13.0` in the
three historical Ventura harnesses. Identical Objective-C source compiles in
the one-variable A/B; `-Wall -Wextra -Werror` and every runtime assertion are
retained. No warning is suppressed and no skip rule is added. Office's actual
CPU bitmap/Objective-C method/errno/budget test now passes. This establishes
neither a GPU result nor compatibility with the unavailable iPad.

## FACT — the native GPU controls still fail

The two Metal class setup errors previously prevented their ten methods from
running. They now expose 39 failing native subtest records across seven
methods, plus two passing invalid-input methods and one existing missing
private Office-fixture skip. These newly reached failures must not be hidden
or counted as successful controls.

Private copies add only one BOOL diagnostic immediately after
`MTLCreateSystemDefaultDevice`. No branch or resource request changes. Two
allocation-only No-Copy runs report `HOST_NOCOPY_DEVICE_PRESENT=0` and exit 4.
Sampling reports `HOST_SAMPLING_DEVICE_PRESENT=0`/exit 4 and stride reports
`HOST_STRIDE_DEVICE_PRESENT=0`/exit 3. No GPU submission or pixel contract is
reached in those executions. Finite witness executables are removed; their
source/binary hashes and raw results remain private. Public probes are
byte-identical. The reason Metal returns nil is **THEORY/open**; process
restrictions are not established as its cause, and hardware failure is not
inferred. No unavailable native result is converted to a pass or a new skip.

| Validation | Publication | Companion |
| --- | --- | --- |
| Settings fixture suite | 9 pass | 9 pass |
| Portable swap-pair controls | 127 pass | 127 pass |
| Complete suite | 904 tests, 51.470 s | 900 tests, 44.279 s |
| Remaining result | 43 failure records / 11 native methods, 0 errors, 13 skips | Same |
| Protocol, runtime-switch audit and diff | Pass | Pass |
| Tracked shell syntax | 41 pass | 41 pass |

The complete suites remain **not passing**. Ten original failure/setup-error
entries are resolved, while four original No-Copy failures remain and 39
previously blocked native subtest failures are now visible. The 43 records are
not 43 independent new runtime regressions: production/probe sources are
unchanged and the compiler gate now allows the existing checks to execute.
Selected source hashes remain unchanged around both final suites. No native
component requires a new device build for this test/documentation-only change.

## Next device attempt

The [single-control handoff](../ipados-1641-one-control-handoff.md) consolidates
fresh read-only inventory, exclusive staging, actual complete cleanup tokens,
fresh observer/native-clock admission, one normal stopped attempt and exact
owned-state cleanup. It explicitly records missing private capture/storage/
connection/cleanup wiring; it is not currently a live dispatch command.
Historical top-level inventory runners must not be rerun with their occupied
output names. No active pair or automatic retry is scheduled. Three genuine
accepted stopped controls remain required before considering an active pair.
Visible responsiveness, native cleanup, freeze cause and stability remain
device-dependent and unverified.
