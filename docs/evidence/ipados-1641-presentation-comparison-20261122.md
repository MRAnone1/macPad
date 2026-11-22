# Standalone UIKit and Metal lifecycle comparison

Implementation and unsigned builds: 20 November 2026. Local verification:
22 November 2026. The iPad was unavailable; no device connection, installation,
trust operation, or device test was attempted. This port remains unverified.

## FACT — diagnostic implementation

The [standalone Xcode project](../../misc/presentation_lifecycle_preview/README.md)
implements the comparison proposed in the
[16 November evidence review](ipados-1641-inventory-and-freeze-20261116.md).
It uses public UIKit, Metal and MetalKit APIs with ordinary configurable Apple
development signing. Its minimum deployment target is iOS/iPadOS 16.4.
No team, signing identity, provisioning profile, private framework or custom
entitlement is embedded. It is independent of the existing MacWS installation
and jailbreak diagnostics.

Each app process permits one run in either UIKit or Metal mode. Both show red
and green above blue and yellow. The first requested frame and the one requested
after an actual background-to-active transition each require a separate human
color confirmation. UIKit does not initialize Metal. Metal creates its device
and pipeline only after Start, manually submits at most two command buffers,
and checks four interior texture pixels after command completion. No continuous
render loop, automatic retry, or main-thread GPU completion wait is used.

For device builds, drawable time and ID are copied inside the presentation
callback. Deferred UI work uses those copied values and the captured frame
identity. This avoids the deferred drawable getter pattern implicated by the
earlier preview crash. Each frame requires a completed GPU command, matching
samples and a finite positive presentation timestamp before human confirmation
is enabled. Unknown resources, failed samples, invalid presentation timestamps,
or an interruption before observation stop the run without another submission.

The installed device SDK's `MTLDrawable.h` documents a zero `presentedTime` for
an unpresented or skipped frame. The installed Simulator SDK omits the callback
and drawable timing members used here. An initial Simulator compilation failed
on those three members. The final Simulator branch explicitly exports
`presentation_callback_supported: false` and records the missing capability;
it does not produce device presentation events or timestamps.

The JSON export retains at most 256 events, reports dropped events, and refuses
a payload above 1 MiB. A UUID and frame number distinguish callbacks. Event
timestamps include wall and monotonic time. The app has no automatic callback
deadline. Stop prevents further submissions while the app responds; an already
committed GPU command is not cancelled. Late callbacks can still be recorded.

## FACT — local validation

Xcode 26.0, build 17A324, supplied the iPhoneOS and iPhoneSimulator 26.0 SDKs.
Builds used Debug and `CODE_SIGNING_ALLOWED=NO`; the device output is unsigned.
Build logs include CoreSimulator discovery/service diagnostics. Neither final
build contains a compiler warning or error attributed to `main.m`.

| Check | Result |
| --- | --- |
| Device compile and link, arm64 | Build succeeded |
| Simulator compile and link, arm64 and x86_64 | Build succeeded |
| Clang static analysis, device arm64 | Succeeded, zero diagnostics |
| Info/project plist and shared scheme XML | Valid |
| Guide regression suite | 1,479 tests; 43 failures, 13 skips, zero errors |
| macPad regression suite | 1,475 tests; 43 failures, 13 skips, zero errors |
| Failed case IDs against saved 9 November baseline | Exact ordered match in each repository |
| Runtime-switch audit, each repository | Passed: 286 names, 85 source flag files, 444 recorded entries |
| C protocol compile with warnings as errors and execution, each repository | Passed |

The exact embedded shader strings were copied to a private `.metal` file for
an offline compilation check. The `metal` wrapper refused execution because
the optional Xcode Metal Toolchain is not installed. No shader compiler ran.
The ordinary Objective-C builds do not compile these runtime shader strings;
shader compilation, pipeline creation and the actual pixels remain unverified.
No runtime or toolchain download was started.

The existing regression suites remain failing; their unchanged failure records
are host Metal control failures. They do not exercise this new app's lifecycle.
No automated UI run or visible-output acceptance was obtained. A successful
read-only `simctl list -j runtimes` outside the sandbox returned an empty runtime
list, so no Simulator app was installed or launched. No Simulator runtime was
downloaded. Generated binaries, raw build attempts and regression logs remain
in the private host workspace. All finite build and test commands completed;
no app, sampler, debugger or device job was launched by this work.

[Machine-readable identities and validation](ipados-1641-presentation-comparison-20261122.json)
record source, binary and log SHA-256 values and Mach-O UUIDs. The protected
original checkout and historical capture bytes were not edited.

## THEORY — what the paired trial can resolve

A repeatable app-only failure with responsive Home and touch would narrow the
search to the app's lifecycle or presentation path. A matching system watchdog
after Home and touch stop responding would establish a broader UI stall. The
comparison has not yet produced either result. The archived swap wait does not
by itself identify the operation that caused the original stall.

No native binary or existing MacWS runtime was patched: the failing invariant
behind the system stall remains unsupported by a new bounded runtime witness.
This diagnostic app prepares that witness; it is not a freeze fix.

## Pending physical acceptance

Use normal Apple development signing and the documented fresh-process sequence
once the iPad is available, unlocked, charging and responsive. Preserve each
original exported report under a separate name. Require target `device`, the
expected mode, two frame requests under one run UUID, zero dropped events, both
human confirmations and the actual background/active transition. For Metal,
require each frame's successful command status, four matching samples and
positive presentation callback. Record Home/touch responsiveness and symptom
time separately; correlate any new Analytics or Xcode report with that time.

A Simulator report cannot satisfy device presentation acceptance. Any failed or
stopped trial remains incomplete evidence. Recheck device state, thermals and
new crash reports before drawing conclusions. Ordinary app installation and
the device trial remain pending. A successful standalone comparison would
still require follow-up against the original MacWS display path.

[Machine-readable evidence and artifact fingerprints](ipados-1641-presentation-comparison-20261122.json)
