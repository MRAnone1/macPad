# Own swap-pair controller v7 — unverified port

These three own Python sources are byte-identical to the frozen v7 controller,
backend and independent watchdog reviewed on 2026-10-19. The linked
[offline evidence](../../docs/evidence/ipados-1641-launchd-domain-offline-20261019.md)
binds their hashes to 107 synthetic host tests, including the copied native
service-domain regression and retained descriptor/report-finalization tests.
The private raw fixture and reports are excluded from Git.

Default invocation only hashes the three local sources and prints metadata:

```sh
python3 misc/macws_swap_pair/controller.py
```

No native API, job, trust, signing or deployment operation is performed by that
default. Native execution remains unverified and requires explicit, fresh,
source-bound prerequisite files and three genuine stopped controls before an
active pair. Hardware/build/rootfs/hook/signature/clock/ownership gates remain
specific to the recorded iPad13,6 / iPadOS 16.4.1/20E252 port. The code is not a
portable generic launchd or iPadOS controller.

Use the project's [isolated delivery pipeline](../../docs/diagnostic-probe-pipeline.md)
for its pinned private own-probe bundle. It copies five files without running
them. These public copies make the implementation reviewable; they do not
replace the pinned bundle or create device acceptance. Explicit execution
reports contain private native state and must stay outside public logs/Git.
Do not dispatch while the device is unavailable, or reuse historical receipts
as fresh prerequisites.

Portable synthetic controls use no private fixture or device:

```sh
python3 -m unittest discover -s misc -p 'test_macws_swap_pair.py'
```
