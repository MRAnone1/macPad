# iPadOS 16.4.1: bounded producer swap-route observation, 2026-10-17

## Result and acceptance scope

**FACT — runtime-confirmed observation:** one owned WindowServer startup on
`iPad13,6`, iPadOS `16.4.1 / 20E252`, Ventura rootfs `13.4 / 22F66`
produced two framebuffer registrations. All six Begin/End/Cancel method-slot
low addresses matched the exact selected IOMobileFramebuffer functions; the
coexistence flag was exactly `1`; the public SwapEnd entry's bounded
literal-load/branch route pointed to the selected libmachook hook's low
address. Fourteen route byte ranges were repeated unchanged in the same held
task context. The redacted [v46 runtime receipt](macws-swap-routes-producer-2026-10-17.json)
is the portable evidence for these statements.

This accepts a finite passive address/byte observation only. It does **not**
authenticate pointer authentication codes (PAC), prove function callability,
observe an original SwapBegin/Cancel return value, reproduce the display
freeze, or accept a fix. No fix was installed in this run. This device/build
remains an **unverified port**. The [fresh inventory](macws-port-inventory-2026-10-17.json)
and [cache identity supplement](ipados-1641-cache-framework-identities-20261017.md)
record the relevant platform and binary identities.

## Exact identities and diagnostic boundary

The selected WindowServer is arm64, UUID
`465422c7-3cfc-3e9f-9c04-813f3a265aa6`, SHA-256
`b8386dbd24ceedb70fc82eab9c74a315e83d19131282522a3fc55ca2a69be416`.
The selected arm64 hook is UUID `2552c7f2-0946-3525-9771-d6d48b44c0e9`,
SHA-256 `bcd544a537fc81cbc16ec3fb8de2c7677708d35ada10c0caf044ba83f005340b`.
Its retained arm64e counterpart is UUID
`8d9d059f-f308-3a07-be9e-bb23123ba997`, SHA-256
`803bcccf8cb9afd8d3b96bdbe88ca13d79463e6a09f2c192d346bc5300541008`.
The observation does not establish execution of the arm64e counterpart.

The exact macOS IOMobileFramebuffer UUID is
`9485c742-b91f-3c6c-897c-ab2c8acf7625`. The diagnostic profile binds the
three slots at framebuffer offsets `+0x720`, `+0x728`, `+0x758` to image
function offsets `+0x4334`, `+0x4400`, `+0x4714`, respectively, and the
public SwapEnd entry at image offset `+0x11cc`. It verifies five exact
framework instruction-window hashes, including the retained pre-existing
SwapEnd length adaptation, before classifying the route. These are
static image-relative offsets, not published runtime addresses.

The [pure Python observer](../../misc/macos_producer_swap_routes.py) performs
no native calls, task acquisition, function invocation, or memory writes.
It consumes the caller's existing bounded reader and retained task; the
composition variant keeps the original final guard checks and release path.
Unknown identity, flag state, method target, branch shape, identity drift,
byte drift, or exhausted shared budget refuses the observation. Branch
classification accepts only an unconditional immediate branch or a bounded
64-bit literal load with a matching BR/BRAAZ register, with at most two hops.
Masking pointer words to the low 39 bits is address classification, **not PAC
verification**. This fail-closed diagnostic is not a freeze repair.

## Bounded runtime witness and cleanup

Five new controls (preflight, native registry, description, process birth,
and watchdog) were from the same boot and at most 5.007 seconds old at the
producer start; all were within the required 300-second limit. There was
one owned producer job attempt, one exact-target debug admission, one resume,
and one reader launch.

| Measurement | Observed | Bound |
|---|---:|---:|
| Controller elapsed time | 3.12452275 s | finite controller/watchdog |
| Shared VM reads | 944 | 2,048 |
| Requested VM bytes | 178,428 | 2,097,152 |
| Shared reader deadline | — | 5 s |
| Process birth metadata queries | 14 | caller-controlled |
| Mach descriptions | 16 | caller-controlled |
| Native registry query budget charges | 85 | 384 |
| Native registry query method calls | 84 | shared query budget |
| Native registry acquisitions / successful release attempts | 28 / 28 | owned cleanup |
| Retained route guard ranges | 14 | 32 |

The two direct-child/first-parent relations repeated equal; first-parent
identities/classes equalled the originally described services. The service
class was `AppleCLCD2`, the client class
`IOMobileFramebufferUserClient`. There were no query exceptions or recorded
native ownership uncertainty. This does not prove a unique provider, an
internal client-provider field, atomicity, or fully pinned object lifetimes.

**FACT — cleanup verified by the controller receipt:** the owned job and
producer were absent, owned files were removed, and bootout exited zero.
Its identifier advisory warning was retained. UI process identities, eight
app entries and their backups, seven selected files, two cache headers and
signatures, and the boot session repeated unchanged. There were zero new
runtime installations and zero new trustcache entries; eleven existing
CodeDirectories were required. Full cache signed-page validation is a
historical 13 October result and was **not rerun here**.

The observer made zero right-extraction, IOServiceOpen, IOServiceClose,
GPU-selector, and kernel-primitive initialization calls. The original GPU
error pattern was not observed during this startup. The run did not launch
a new visible window or exercise input; absence of that pattern and process
survival are not stability evidence or a completed-frame witness.

## Local verification and retained provenance

**FACT — focused checks passed:** 13 tests for the
[route observer](../../misc/test_macos_producer_swap_routes.py) and eight
held-task composition tests passed, for **21 focused tests**. Controls cover
supported branch forms, refused unknown forms/cycles/out-of-range literals
and register mismatches, disabled flags, changed targets, shared budgets and
deadlines, identity/byte drift, same-task composition, final guard reuse, and
release on refusal. A later portable rerun of the registration parser/full-flow,
route, and cache modules passed 81 tests. Seventeen default/missing-prerequisite cases also passed:
default and prepare-only paths made no transport call, and missing fresh
controls refused before transport.

**FACT — full suite did not pass:** 899 tests in 53.897 seconds reported
**6 failures, 8 errors, 12 skipped**. A clean archive of HEAD
`b8eaed6223dc40374e16b20101b27055f69650d4` ran the five affected modules
(31 tests in 1.820 seconds) and reproduced exactly the same fourteen failed
case identifiers: seven Settings cases (five errors/two failures), the Office
CPU bitmap observer case (one error), the TextureSampling and TextureStride
stock-control class setups (two errors), and four NoCopy stock Metal cases
(four failures). This establishes the same failed-case set on that baseline;
it does not turn either run into a pass or establish every failure's cause.

The companion checkout separately ran 738 tests in 50.921 seconds, with
6 failures, 8 errors, and 12 skips; its exact fourteen failed case identifiers
match the main run and clean-HEAD subset. Its runtime-switch audit passed
with 286 environment names, 85 source flag files, and 443 entries. These
counts belong to different repository baselines, not combined pass totals.

Runtime-switch audit passed with 286 source/plist environment names, 84 flag
files, and 442 recorded entries. Strict C protocol validator build/run and
`git diff --check` passed. No production libmachook source was changed by
this diagnostic, so this pass did not rebuild or deploy libmachook.

| Retained item | SHA-256 |
|---|---|
| Portable v46 runtime JSON | `0c9d788acfc0b15246eaaa1ba903d742931b29f691240c0810219b12d443e9d2` |
| Private controller receipt | `38312a9a813884b256744c87a4f5ae1f4e53730c50c4219bfdf0d5da9aac2071` |
| Private host envelope | `91c1535bc32902dc359dc7a02f6282fba7df386815cafba96c507c09b8618bc0` |
| Bound executed source | `b4e4c90fdead715ca1a3298eeedafea2c63cce0a9e3625e018892c7e8a9c2703` |
| Controller body | `6657fc6622290181fe1fcc70ccedc873c3838518cef156482c74884e309e299c` |
| Route observer source | `6c68b0b2372b90dd75006e7954effc0edcb0709b8a589c09eaf8252c53c3f21a` |
| Route observer tests | `8862488a0ca60b3abee23ecdfcd82c0c9ebdc5e6bf1fc6f3728b46fd044ad1b4` |
| Held-task variant source | `2b09f0b8bbf2c483af231ebe257b7c7308bc6f0d8a35c56341c916f76f0c1468` |
| Held-task variant tests | `c1373e51d85ba492cea671214810c4fd78c8d754e6f0e0bcaf388cb371a39eca` |
| Observer wrapper source | `3db45b32c8cc4f8d63f93dd2aefa9d9ff915624ddd3aa786636e1c4027cc31d4` |
| Exact route profile | `cb2e5226cdfc7a40c9318b91bcc6a9902ff225b39c50f8d36fb162e992881795` |
| Offline QA receipt | `5cffe7d780e810b9ad200dc9363ce9c3b9aff0f54254de5e45c04b8f5c2011f5` |
| Full suite log | `ba0eea71411352ea880fad8e067778fe290cff0c2c909ac981d1935c9d9187b3` |
| Clean HEAD subset log | `02651d93cceeb4e5bb8941fba93799718f98bec7918369bb7d90460004b95728` |
| Suite reconciliation receipt | `bf5a7a0fc4696b2050e4c1bf00a3cabe1db1bf19251d7bd4a61808f663256caf` |
| Audit/protocol/diff receipt | `dcb8d39cfe7ebf03a9a730e08e48e4be9a371ab439cb4c1408c5885a08d84469` |

Hashes identify the retained private receipts and source snapshots; those
private artifacts are not included in this portable record. Raw task/port,
process, boot-session, registry, pointer, and Apple instruction bytes remain
private. The JSON is copied byte-for-byte from its existing redacted export.

## THEORY and remaining work

**THEORY:** the existing coexistence SwapEnd-to-Cancel/completion route may
contribute to the previously saved display wait. Matching live addresses and
an armed flag do not establish that this path ran, what status its original
calls returned, or that it caused the freeze. Confirming/refuting this theory
requires a bounded exact-binary runtime witness of original call status and
completion/progress, followed by a controlled failure comparison.

A fresh bounded display-failure reproduction, supported failing invariant,
narrow repair, device acceptance on actual visible/protocol output, and
separate repository synchronization/commits/pushes are still outstanding at
this evidence checkpoint.
