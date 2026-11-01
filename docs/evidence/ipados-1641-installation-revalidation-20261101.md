# Offline installation revalidation — 1 November 2026

## Result

FACT: the new bytes-only checker recomputes the delivery comparison without
rewriting the original receipt. It successfully checked the actual saved
31 October audit: five full copied files, 174,394 bytes, matching original
content hashes and exactly nine original-lineage refusals. Full file and
created-directory tokens differ only in `dev`; parent comparisons cover only
`dev`, `ino`, `mode`, `uid` and `gid`. All current copied brackets remain stable.
The original negative audit stays negative.

This is a reproducible offline evidence check. No device call, trust change,
cleanup, session projection or native control occurred on 1 November. The
display/freeze invariant remains unresolved and the port remains unverified.

## Change and boundary

`misc/macws_swap_pair/installation_revalidation.py` defaults to metadata only.
Its explicit `revalidate()` API takes immutable raw bytes for the original
successful installation receipt, the complete negative audit and its transport
record. The caller supplies independently selected full input hashes, four
auditor source hashes, the expectation hash and a separately copied boot/profile
binding. The checker reconstructs the original audit expectation, requires
complete quiet transport with exit 1, recomputes every full copied hash, and
checks exact schemas/types, bounded JSON/base64, physical paths, before/after
tokens, directory names, rootless anchor and the nine ordered refusals.

Only this observed per-path `dev`-change case is accepted. Missing changes,
other compared-field changes, partial data, new authority claims or additional
failures refuse. Old/current records remain separate in the private output;
no old token is normalized or substituted. The result creates no `new_vnode`,
config, prerequisites or `OwnedFiles` capability. Every execution, session,
trust, cleanup, ownership, native-freshness and volume-continuity flag is false.

The hashes bind supplied bytes; they do not authenticate who produced them.
The trusted caller must preserve and independently review their provenance.
Consistent invented JSON/pins remain invented evidence. Historical signature
fields are checked structurally, not re-parsed as current Mach-O signatures.
The checker does not query trust, loaded images, macOS rootfs build, UI or a
native clock. It infers neither cross-path device-number mapping nor persistent
volume/vnode continuity or a cause for the changed numbers.

The existing v7 projector deliberately still compares current candidate tokens
with the original exclusive-delivery tokens. Its receipt/runtime consumers also
require `new_vnode=True`; this new record must not be inserted there as a shim.
Those consumers, their source pins and all live execution behavior are unchanged.
A future execution transition needs a coherent new version and fresh native
gates. The four reported trust prerequisites and three genuine stopped controls
remain outstanding. A broad postinstall is not an exact trust-restoration route.

## Validation

Eighteen new host test methods pass, including repinned adversarial fixtures
that exercise semantic refusal after the input-hash checks. They cover changed
bytes/tokens, aliases, foreign children, incomplete capture, duplicate/nonfinite
JSON, bool/integer confusion, source/expectation substitutions, authority claims,
boot/anchor/directory races and exact refusal sets. Invented fixtures are clearly
labelled and never promoted to device evidence. Two independent reviews found
no blocker. Root separately reviewed the code and checked the actual copied
inputs using the independently pinned current-runtime boot binding.

Both full suites ran on 1 November: **1,352 / 1,348 tests**, exactly the same
43 known native Metal failure records as 29 October, zero Errors and 13 Skips
each. They are not fully green. All 49 previously frozen sources match their
baseline; all 51 old/new source/test hashes remain unchanged during the runs.
Both runtime-switch audits pass (286 names, 85 source flag files, 444 entries),
and both C protocol builds/runs pass. No shell or native binary changed; there
is no affected arm64/arm64e build or device deployment in this offline change.

The complete record contains private paths, tokens and copied source bytes and
remains private. The accompanying public JSON includes only hashes, counts,
limits and validation results. The 31 October raw witnesses and the initial
local connection-denial journal remain unchanged.

[Public machine-readable evidence](ipados-1641-installation-revalidation-20261101.json) ·
[Copied device facts](ipados-1641-current-boot-inventory-20261031.md) ·
[Remaining control route](../ipados-1641-one-control-handoff.md)
