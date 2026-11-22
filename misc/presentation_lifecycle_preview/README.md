# Presentation lifecycle comparison

Standalone Objective-C iOS application for comparing a UIKit presentation with a bounded MetalKit presentation using public APIs. The product is `MacWSPresentationCompare.app`, with bundle identifier `dev.macws.presentationcompare`, and supports iPhone and iPad on iOS/iPadOS 16.4 or later.

This project has no external dependencies, private frameworks, custom entitlements, or integration with the repository's installation scripts. Building it does not establish device display correctness, responsiveness, or performance. See the [dated evidence and acceptance record](../../docs/evidence/ipados-1641-presentation-comparison-20261122.md) for validation status and device-test limits.

## Build without installing

Use a full Xcode installation containing the required iOS SDK. Running a Simulator also requires an installed iOS Simulator runtime; compiling for a generic Simulator destination does not. The Command Line Tools installation alone is insufficient. Run these commands from this directory; adjust `DEVELOPER_DIR` if Xcode is installed elsewhere.

Simulator build:

```sh
env DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  xcodebuild -project MacWSPresentationCompare.xcodeproj \
  -scheme MacWSPresentationCompare -configuration Debug \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath /tmp/macws-presentation-compare-simulator \
  CODE_SIGNING_ALLOWED=NO build
```

Unsigned device build for compile and link validation:

```sh
env DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  xcodebuild -project MacWSPresentationCompare.xcodeproj \
  -scheme MacWSPresentationCompare -configuration Debug \
  -destination 'generic/platform=iOS' \
  -derivedDataPath /tmp/macws-presentation-compare-device \
  CODE_SIGNING_ALLOWED=NO build
```

These commands compile the app and do not install or launch it. An unsigned device product cannot be installed through the normal Xcode device workflow.

## Normal Apple signing and running

Open `MacWSPresentationCompare.xcodeproj` in Xcode, select the `MacWSPresentationCompare` scheme, and choose an iOS Simulator or an available device. For a device, configure your own development team under **Signing & Capabilities**. Automatic signing is the default; manual signing can instead be selected there with your own certificate and provisioning profile. No team, certificate, or profile is embedded in this project.

For a signed command-line build, use the device build command above, omit `CODE_SIGNING_ALLOWED=NO`, and supply `DEVELOPMENT_TEAM=YOUR_TEAM_ID`. Any account, profile creation, or device installation remains a normal Xcode operation. Record Simulator observations separately from physical-device acceptance.

## Finite paired trial

Physical-device acceptance is pending as of 22 November 2026. When the device is available, use the same orientation, window size, charging state, and starting thermal state for both modes. The fixture has red and green above blue and yellow. The app uses application lifecycle notifications and permits one two-frame run per process launch.

1. Start with a fresh app process, select **UIKit**, and tap **Start**. The UIKit control does not initialize Metal.
2. When **Four colors visible** becomes available, inspect all four fields and tap it once. This records the first human confirmation.
3. Open Home and verify that Home and touch respond, then return to the app once. An actual `UIApplicationDidEnterBackgroundNotification` followed by becoming active permits frame 2; a brief inactive interruption alone does not.
4. Inspect the colors again, tap **Four colors visible** a second time, and select **Share report**. Save the UIKit report under a distinct name.
5. End that app process and launch a fresh one. Repeat the same sequence with **Metal** and save its report separately. Returning from Home resumes the existing run and does not create a fresh process.

There is no continuous renderer or automatic retry loop. Metal submits at most one command buffer for each of the two requested frames. The app has no automatic callback deadline. If a wait persists, use **Stop** while the app responds and share the incomplete report. Stop marks the run as stopped and prevents further frame submissions; it does not cancel a GPU command already committed. Late callback events may still be recorded. Record any Home or touch nonresponse and its time before considering another trial.

## Reading the report

The JSON report separates app events, GPU completion, drawable presentation, and human confirmation. A candidate completed trial needs `outcome: "two_frames_observed_and_confirmed"`, `dropped_events: 0`, one consistent run identifier, frame numbers 1 and 2, two `human_colors_visible` events, and the recorded background/active transition between frames. UIKit records `uikit_draw`; that draw callback alone does not establish visible output.

On a physical device, each Metal frame also requires a `command_completed` event with status 4 (`MTLCommandBufferStatusCompleted`) and `four_samples_match: true`, plus a `drawable_presented` event with a finite positive `presented_time` and `positive_presented_time: true`. The drawable properties are read inside the presentation callback. A zero or nonfinite timestamp fails the run. Four interior BGRA samples establish the sampled texture contents; the separate human confirmations and Home/touch observations establish the visible and interactive part of this trial.

The Simulator build reports `target: "simulator"` and `presentation_callback_supported: false`. Its SDK does not expose the device drawable presentation callback used here, so each Metal frame records `presentation_callback_unavailable` and permits human confirmation after GPU completion and pixel checks. It emits no substitute device presentation timestamp. A Simulator outcome can exercise the app flow and readback checks, but cannot satisfy the physical-device presentation requirement.

Reports retain at most 256 events and count later dropped events. Export refuses a JSON payload over 1 MiB. Review the OS/build metadata, target, mode, outcome, and event sequence before interpreting a report. A completed standalone trial does not establish that the original MacWS display stall is fixed; compare any reproduced symptom and system report by time in the dated acceptance record.
