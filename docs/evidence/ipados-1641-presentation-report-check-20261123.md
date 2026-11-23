# Host check for standalone presentation records

23 November 2026. The iPad was not ready. This work used only invented host
fixtures and local source files. There was no device connection, deployment,
trust operation, native binary patch or device acceptance. The iPad13,6 /
20E252 port and original display stall remain unverified.

## FACT — correction to the first format interpretation

A further copied-source experiment found a type mismatch in the first checker
and its invented fixtures. In the unchanged app, C expressions boxed with
`@(!...)`, `@(... != nil)` and `@(... && ...)` select `numberWithInt:`. The
compiler AST for arm64 iOS 16.4 with the installed iPhoneOS 26.0 SDK confirms
this for capability, pipeline and presentation flags. A typed `BOOL` selects
`numberWithBool:`. An independent local macOS Foundation serialization witness
emitted integer `1` for the former expressions and boolean `true` for typed BOOL.
This is host and compiler evidence, not an observed iPad export.

The final consumer therefore requires integer `0/1` for
`presentation_callback_supported` and integer `1` for successful
`pipeline_ready` and `positive_presented_time`. Genuine BOOL fields retain
strict boolean typing. A new test checks both sides of this distinction.
The initial boolean fixtures and 46-test run remain retained separately as
v1 attempts; final logs and mutation outputs use v2 names. The 22 November
note's `presentation_callback_supported: false` wording was an incorrect
boolean interpretation of numeric zero, not a validated runtime result.
The current README is corrected. No Objective-C app source was changed.

## FACT — record consumer and bounded failure

The standalone preview's `outcome` field can be copied into an incomplete
JSON file. It is not evidence that every endpoint exists. The new
[`check_report.py`](../../misc/presentation_lifecycle_preview/check_report.py)
checks the published producer's exact v1 schema and bundle version `1`, the
two requested frames, actual endpoint records and both human-confirmation
records. No input source is imported or executed. The CLI reads at most
1 MiB plus one overflow byte per file and writes its assessment to stdout.
It performs no device, subprocess, network or report-file write operation.

One preserved, explicitly synthetic input claimed the successful final outcome
and both confirmations but omitted frame 2's UIKit draw record. The CLI refused
it with exit 2, empty stderr and reason `confirmation_before_endpoints`. This
is a bounded host reproduction of a false-success claim. It is not a runtime
witness of the original iPad freeze.

The checker rejects missing or duplicate endpoints, mixed run/frame identities,
unknown fields and variants, nonfinite numbers, bools in integer fields,
duplicate JSON keys, over-limit inputs, dropped events, failed/stopped outcomes,
invalid pixels/status/timestamps and unsupported bundle versions. Device Metal
records require a commit, successful GPU completion with four exact BGRA samples,
and positive advancing presentation timestamps and drawable IDs. It permits
either callback arrival order and nonadjacent drawable IDs.

Array order is retained. Callback timestamps are created on separate threads
before insertion on the main thread, so global timestamp ordering is not
required. Pre-run and post-completion lifecycle events are supported. The
Simulator's unavailable-callback marker occurs before commit; default validation
refuses Simulator input, while explicit `--allow-simulator` checks its reduced
record structure without inventing device presentation evidence.

Independent review found a stale-lifecycle case: after a recorded background
and return, a second inactive/background transition could leave a previous
return flag set in the first checker draft. The consumer now clears that flag
on renewed inactivity, background entry and foreground entry. A subsequent
frame 2 request needs a new active transition after background. Dedicated
negative tests preserve both stale-background and stale-inactive cases.

Pair checks require UIKit followed by Metal, distinct reported run UUIDs and
equal reported target, machine, OS/build, bundle version, initial thermal state
and low-power setting. Neither single-record nor pair success authenticates
these claims. Every assessment keeps `device_acceptance` and
`authenticity_verified` false, `human_review_required` true and
`original_freeze_fixed` false. Compatible metadata does not establish matching
orientation, window geometry, charging state, fresh processes or Home/touch
responsiveness. The current app does not record all of these observations.

## FACT — host validation

All 47 final synthetic unit tests pass, including CLI success/refusal paths,
both callback orders, reordered captured times, lifecycle edges, parser limits,
Simulator capabilities and incompatible pairs. A separate deterministic
exercise replaced every value position in three invented report shapes with
15 alternative values. Of 7,335 inputs, 6,764 were refused and 571 retained
consistent structure. All successful assessments retained the conservative
flags above. There were zero unexpected exceptions. These counts are host
input-validation results, not display or hardware tests.

The accompanying JSON records final regression totals, baseline failure
comparison, audit/protocol results, source hashes and retained raw-log hashes.
Synthetic inputs and stdout/stderr remain separately named in the private
workspace. No genuine app export was available.

The Objective-C app, plist, Xcode project and shared scheme match the prior
build inputs. No iOS rebuild was needed for this host-only checker. The
[22 November limits](ipados-1641-presentation-comparison-20261122.md) remain:
no installed Simulator runtime, missing optional Metal Toolchain, unsigned
device product, and no runtime shader/pipeline or physical display acceptance.
The protected original checkout and archived captures were not edited.

## THEORY — next device observation

Once the iPad is ready, obtain a fresh read-only starting inventory and confirm
normal touch, charging and unlocked state before a bounded trial. Normally
sign and install the separate app, retain the original UIKit and Metal exports
under distinct names, then run the checker on copies or original saved exports.
It will not modify either. Independently observe colors and Home/touch behavior
and correlate any new system report by time. A consistent record can support
that review; it cannot establish a freeze fix or replace the missing physical
trial. No native patch is justified by these synthetic inputs.

[Machine-readable host evidence](ipados-1641-presentation-report-check-20261123.json)
