# Read-only device resumption — 2026-10-23

After the host-only triage, the user reported the iPad available, unlocked,
charging and normally responsive. Three bounded read-only workers then
completed over the existing authenticated SSH connection: port inventory,
cache/header inventory and the source-bound observer-v4 pre-stage check.
No candidate, stopped control, active pair, payload installation, launchd
mutation or trust modification was performed. No actual new control-session
or admission receipt was created. Raw device tokens/process/boot identities
and full output remain private.

## FACT — copied current inventories

The device reports iPad13,6, iPadOS 16.4.1/20E252, Ventura 13.4/22F66 and
Dopamine 3.0.10. The nine directly readable Mach-O hashes/slice identities
match 19 October. Five cache-only file paths are not directly hashed.
Eleven selected framework header/load-command identities across 47 cache
files match the historical UUID/hash inventory. These are not whole-framework
digests, live-image measurements or signed-code-page acceptance.

About 87.16 GiB is available. The two coarse public thermal samples are
nominal. Trustcache enumeration returns 167 entries including the retained
own probe CDHash. The reported boot identity agrees within and between both
inventories and with the historical observation; that does not make historical
prerequisites fresh. The cache worker reads 1,251,574 bytes in 135 calls under
its explicit read budget. The port worker retains post-read accounting caps;
the new host wrapper separately enforces bounded streaming capture.

## FACT — pre-stage observation refuses full admission

Observer v4 completes with ten of eleven baseline checks true: exact build,
stable boot/UI, nominal thermal state, no blocked workloads, both fixed
`user/501` job labels absent, both scratch names absent, stable trust/file
observations and exact trusted dependencies. The candidate is absent before
exclusive staging. `candidate_present_identity_trusted` is therefore false
and is the sole reported refusal. No finalization refusal is present.

This is the expected pre-stage state, not complete admission. The observer
retains false runtime/device acceptance. No missing executable is invented,
no JSON field is rewritten and no trust change is used to obtain a pass.
The [redacted receipt](ipados-1641-readonly-resume-20261023.json) binds the
original private raw digests, exact worker/observer/transport sources and
reported checks. The local parser initially treated a nested identity object
as a string; correcting the host comparison did not rerun or modify the
recorded inventory.

## Remaining gates

[The one-control handoff](../ipados-1641-one-control-handoff.md) still requires
reviewed private capture/session persistence, cleanup transport and exact
owned-state recovery before dispatch. Next would be exclusive pinned
five-file/two-directory delivery, actual complete ownership/tokens, a fresh
post-stage observer and native-clock admission. These current inventories
must not be projected into a control session while the candidate is absent.
No stopped control, original freeze cause or visible stability is accepted
by this read-only resumption. Three genuine accepted stopped controls remain
required before considering an active pair.
