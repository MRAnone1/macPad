# Current cleanup gate and observation age

9 November 2026

The new `current_cleanup_gate.py` collects two read-only brackets per gate.
Each bracket checks the exact device and rootfs build, boot identity, UI
generations and executable paths, thermal state, scratch absence and competing
workloads. The intervening launchd queries use the existing source-bound
absence parser for the two fixed jobs. The observer rejects extra Python and
PyPy processes and the known chroot wrapper. The native factory identifies its
own `python3` process using `os.getpid()`.

The caller supplies a trusted direct check for an exclusion lease held across
archival, cleanup and finalization. The gate checks that lease before and after
its reads. Named process absence is one observation within that contract.
Each of the nine allowed windows uses a fresh scope of the frozen read-only
observer. Four commands per window allow 36 commands across the gate's
lifetime. The one-second window and eight-second action deadline use the
same Mach clock. An error terminates this gate instance.

## Host timing witness

**FACT.** A controlled host fixture used 0.60 seconds of simulated scan time
and 0.45 seconds of additional simulated namespace work before the first
unlink. An injected comparison variant differed by one timestamp expression.

| Timestamp passed to the cleanup core | Attempted effects | Outcome |
| --- | ---: | --- |
| End of gate scan | 7 | Five unlinks and two directory removals completed in the owned host fixture |
| Start of gate scan | 0 | `gate_stale_before_unlink` |

The gate now timestamps the start of the window. This lets the core count the
age of the earliest evidence when it checks again before an effect. The test
uses an owned host filesystem and synthetic clock, health and lease data.
The companion JSON records the source and witness hashes.

## Device evidence

**FACT.** The completed 8 November read-only SSH report passed 9 of 11 checks.
All four inspected artifact identities matched and all four corresponding
hashes were absent from the reported jailbreak trust set of 147 entries.
The SpringBoard generation had changed since 1 November. It remained stable
within the 8 November report. On 9 November the new port inventory returned
SSH exit 255 with a connection timeout before authentication and zero stdout.
The host retained the exact streams. Current device state remains unknown
after that attempt.

**THEORY.** Fresh native data and a real exclusion lease can supply the
observations required by the current cleanup core. The next device step is a
fresh read-only inventory. Native gate qualification also needs a source-pinned
action worker with an alarm covering archival through report flush and close.
The gate snapshot provides a bounded structured summary. A worker needs a
separate capture path for native command and API evidence. The original
display freeze remains unresolved.

## Host checks

Both repositories passed all 13 focused tests, including independent runs.
Full suites ran 1,479 and 1,475 tests. Each reported the same 43 known Metal
failures as the preceding run, zero errors and 13 skips. All 62 previous
selected source pins and both new pins matched. The runtime switch audit and
C protocol tests passed in both trees.
