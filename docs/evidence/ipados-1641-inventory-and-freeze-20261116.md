# Confirmed 9 November inventory and display stall evidence

Reviewed on 16 November 2026. The device reports were captured on 9 November
after a separate SSH connection timeout. The later runtime and port journals
each contain a complete quiet exit-zero transport. All seven file lengths
and hashes in each journal receipt matched. The companion JSON records the
input and raw output hashes. The reports and device identifiers remain in
the private capture directories.

## FACT — 9 November device inventory

The port report identifies iPad13,6, iPadOS 16.4.1 (20E252), Ventura 13.4
rootfs (22F66) and Dopamine 3.0.10. Nine direct Mach-O records matched the
1 November records, including their hashes, byte counts, and architecture
and UUID lists. Five paths returned `FileNotFoundError`. The separate cache
header inventory and full `jbctl` byte copy still date to 1 November. The
9 November port report directly hashed the installed `jbctl` and recorded its
arm64 and arm64e slices.

The mount listing contained the same 14 rows as on 1 November after ignoring
order. The captured listing included the containing `/private/var` mount.
Available space was 82,177,224,704 bytes (76.53 GiB), down 9,182,519,296 bytes
(8.55 GiB) from 1 November.

The runtime and port captures agreed on boot identity and the reported trust
set of 147 entries. Both UI process generations matched the 8 November runtime
capture. Thermal readings were nominal. Nine of eleven runtime checks passed.
All four diagnostic artifacts matched their saved identities, and all four
hashes were missing from the reported trust set. This is the recorded reason
for the diagnostic readiness refusal on 9 November. Current device state
remains unknown on the review date.

## FACT — archived system UI watchdog reports

The original 9 October backboardd and SpringBoard diagnostic reports both
record WATCHDOG service timeouts at 22:40:19 CEST. The reports identify the
backboardd HID run loop and SpringBoard main queue. Archived stack analysis
places the backboardd display thread in a framebuffer swap wait. The reports'
60 seconds refer to time since the last successful service check-in. The
visible freeze duration and initiating operation remain unresolved.

The earlier preview app crash recorded an invalid memory access in a deferred
`presentedTime` getter. It has its own process, time and crash signature.
The archived display signposts around the system stall can locate retained
events in time. Their coverage leaves the stall onset and trigger unknown.

## THEORY — isolate app presentation from the system UI stall

Use a normally signed, self-contained app with the same four-color fixture
for both paths. Compare one static UIKit view with one finite Metal frame.
Keep the scene and timing the same, including one foreground–Home–foreground
transition. Record scene activity, command completion, drawable presentation,
and whether Home and touch continue responding. An app-only failure while
Home and touch respond would narrow the search to the app's lifecycle or
presentation path. A matching UI watchdog report after Home and touch stop
responding would establish a broader stall. Match any report against the
time of the observed symptom.

The local Simulator query failed to connect to CoreSimulatorService. The
paired comparison and device acceptance remain pending.

[Machine-readable evidence](ipados-1641-inventory-and-freeze-20261116.json)
