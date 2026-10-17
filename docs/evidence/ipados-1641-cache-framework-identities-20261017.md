# iPadOS 16.4.1: filesystem cache/framework identity inventory, 2026-10-17

## Result and scope

**FACT — fresh read-only filesystem inventory:** eleven selected framework
images were identified in 47 declared shared-cache files: six native iPadOS
images across 45 files and five Ventura rootfs images across two files. Main
cache/subcache UUID associations, selected image/header UUID agreement,
repeated header bytes, and repeated cache metadata checks passed. The device
is `iPad13,6`, iPadOS `16.4.1 / 20E252`, Ventura `13.4 / 22F66`, and remains
an **unverified port**. The [redacted cache receipt](macws-cache-framework-identities-2026-10-17.json)
records each image's architecture, UUID, complete header-range byte count and
SHA-256. The [initial port inventory](macws-port-inventory-2026-10-17.json)
records hardware, jailbreak, free space, selected standalone binaries and
runtime snapshot; its unfinished list describes that earlier checkpoint,
not a retroactively updated checklist.

These are **header-range hashes**, not full framework hashes. This pass did
not prove that the native images were loaded into a running process, rerun
full signed-code-page verification, identify a freeze cause, or accept a
fix. No framework was loaded to obtain the inventory.

## Exact framework identities

All eleven selected headers report arm64e. UUIDs are static image identities,
not boot-session identities.

| Namespace | Image | UUID | Hashed header range, bytes |
|---|---|---|---:|
| Native iPadOS | Metal | `fc81787c-3d56-358e-8215-8495d583f6d4` | 5,288 |
| Native iPadOS | AGXMetal13_3 | `e25d17ad-26a8-35d1-a400-8220edcd7d0c` | 4,832 |
| Native iPadOS | QuartzCore | `0ae8ceb8-0dd6-363f-951d-16aac60a0951` | 7,112 |
| Native iPadOS | IOMobileFramebuffer | `d2cce008-351e-3781-8774-0ed863d941e7` | 2,328 |
| Native iPadOS | IOGPU | `4a495b72-eeeb-3d74-a7b5-1088f0ea60d7` | 4,496 |
| Native iPadOS | SpringBoard framework | `45ddeb5e-05b0-3bf3-bb8b-d78e6b95ebb3` | 24,632 |
| Ventura rootfs | Metal | `2bab169c-42da-36e3-955a-f30b709ec2ad` | 5,112 |
| Ventura rootfs | AGXMetal13_3 | `727c250e-554d-3921-a5b3-48dae6195b79` | 4,968 |
| Ventura rootfs | QuartzCore | `cf853bbd-01b6-3f46-ada1-ec70fd2dc9dc` | 6,280 |
| Ventura rootfs | IOMobileFramebuffer | `9485c742-b91f-3c6c-897c-ab2c8acf7625` | 2,384 |
| Ventura rootfs | IOGPU | `ce2b5551-857f-3edd-9e4f-435215cc8c27` | 4,584 |

The native SpringBoard framework is distinct from the standalone executable
inventoried earlier (executable UUID
`44055250-e230-3c4a-9b04-e7756054cbe0`). Both identities are retained;
they must not be conflated.

## Bounded inventory and parser refusals

The v3 worker made 135 file reads requesting and returning 1,251,574 bytes,
within 256 calls and 8 MiB. Its shared read deadline was eight seconds, device
alarm twelve seconds, and recorded host timeout twenty seconds. Device
inventory elapsed time was 0.028239292 seconds. The host envelope records
exit zero without a host timeout. The worker repeated boot identity, header
bytes and stat metadata; equality does not establish an atomic snapshot.

An earlier v2 attempt refused two input cases and its receipt was preserved:

- After five native images, v2 refused its generic Mach-O header/load-command
  extent check; that receipt did not copy the failing image's header fields.
  The subsequent v3 run identifies SpringBoard's 24,600 load-command bytes,
  beyond v2's fixed 16-KiB range. Unchanged native cache metadata/header
  hashes connect these observations; this size attribution is retrospective.
  V3 reads the complete bounded 24,632-byte header and load commands, with
  a 64-KiB ceiling.
- A Ventura filename sharing the cache prefix was not a declared subcache.
  V3 selects declared subcache filenames/UUIDs from the main cache manifest;
  one unselected prefix file was recorded privately and not opened as a
  cache in v3.

These were **inventory-parser refusals**, not a reproduction of the display
failure and not evidence that the device's caches were corrupt. The v3
parser change addresses those bounded input cases; it is not a display or
freeze fix.

Fourteen offline v3 positive/negative parser tests passed. The
[portable worker](../../misc/macos_cache_framework_inventory.py) is byte-identical
to that executed v3 source. The
[portable tests](../../misc/test_macos_cache_framework_inventory.py) rename only
the imported module. Their separate portable rerun passed all fourteen controls,
and the combined reader/route/cache run passed 81 tests. They cover budget
precharging and deadline cleanup, short reads, header drift,
duplicate paths, UUID mismatch, missing main tables or declared subcaches,
valid zero-image subcache tables, manifest selection that ignores an
unselected prefix file, complete headers over 16 KiB, and refusal over the
64-KiB ceiling. Default preparation made no transport calls. This is parser
verification; it does not grant device acceptance to the port.

## Rootfs and runtime supplement

**FACT — directory/stat and `df` observation:** the rootfs directory was not
a separate mountpoint, shared the Data filesystem's stat device, and `df`
reported `/dev/disk1s2` mounted at `/private/var`. This attributes the observed
backing directory to Data; it does not audit every mount nested inside the
rootfs. The initial inventory had 97,581,932,544 bytes available and a
writable statvfs result. These values describe the measured moment.

The initial snapshot had one SpringBoard, one backboardd, zero WindowServer,
zero listed loader/host/display/signing/debug/log-sampler processes, nine
MacWS-named processes, and two nominal thermal readings. Existing trustcache
information was readable, with 164 distinct existing CDHashes, on jailbreak
version `3.0.10`; admitting a new hash was not tested. Snapshot process
counts and thermal readings are not visible-output or continuous-stability
acceptance.

A separate bounded read-only tool search found no on-device LLDB,
debugserver or tmux at the searched paths. No debugger was attached. The
cache inventory and rootfs/tool supplement were from the same boot as the
[bounded v46 producer observation](ipados-1641-producer-swap-routes-runtime-20261017.md).
The inventory itself created no device files, jobs, new GPU workloads,
framework loads, kernel-memory reads, or jailbreak primitive initializations;
there was no device diagnostic artifact to remove.

## Provenance and limits

| Retained item | SHA-256 |
|---|---|
| Portable cache identity JSON | `f53738bbeb99fea58bafd2e159446de0d56f1446aae86a732273abe58853c845` |
| Portable initial inventory JSON | `2ef89f7b8c78755eced71b04b92306bf57125a16c233b32b0f975f2c6e77185b` |
| Private v3 device receipt | `746fcd87e121977a4b5d1640abb24e98a94f045cfa4d76dddb57f46b74a78c44` |
| Private v3 host envelope | `a6672e24583def90e64851d4e61bba5469127c47e974eb86f44f7f330e30d496` |
| V3 worker source | `e25ff917ab42d17e36b757d3ed4b9aa51d184fdf1ce04c3a6156149ecdbffcd4` |
| Original v3 parser tests | `24f129661fb377cf178892d2e46feaa74646bd17f98da6021544be9bfa1e690c` |
| Portable parser tests (module import renamed) | `4fe4627c0a046749b4496545fac14211d12f35156df856c6813ceab2578623af` |
| V3 host runner | `181749b969a055c95e29a8246a6a10a0305887cb190065a9c24d3e89a7816147` |
| Rootfs/tool supplement receipt | `4129a5965d9c1574d1ffbccc22103aa64e96382b4b6fe463b7e61c78d76b8514` |
| Rootfs/tool supplement host envelope | `b9e638f03617beb39b201dee7ad8a233505e6709c1f978b32084e4fa33e3023f` |
| Rootfs/tool supplement executed source | `5cf39f14790813ac343e1ff9b0ed6b482235a6228b8757dbf58a00bb264e32ef` |

The two linked JSON files were copied byte-for-byte from their existing
redacted exports. Private receipts retain detailed source/bounds and raw
metadata; this portable record publishes their hashes, not their private
contents. Full Apple cache/framework payloads, runtime addresses, registry
identifiers and boot-session identifiers are not published. The initial
inventory's 28-second device alarm is retained in its executed source; a
37-second host timeout was not frozen into that initial host envelope and is
not independently certified by this record. The v3 host envelope separately
records its own twenty-second timeout.

**THEORY remains unproved:** the coexistence SwapEnd/Cancel/completion route
could contribute to the saved display wait. Filesystem identities cannot
establish that causal claim. A fresh bounded failure, original call-status
witness, supported failing invariant, narrow repair and real device
acceptance remain outstanding. This note does not claim completion of the
repository synchronization/commit/push workflow.
