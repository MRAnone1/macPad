# Isolated own-probe delivery

This diagnostic component delivers the reviewed own-client swap-pair probe and
its controller sources. It is preparation for an unverified iPad13,6 / iPadOS
16.4.1 / 20E252 port, not a display or freeze fix. The production source overlay,
builds, postinstall, daemon operations and workspace restart are bypassed before
any of them runs. Existing pipeline components retain their original flow.

Default invocation performs local metadata checks only:

```bash
bash misc/device_pipeline.sh --component diagnostic-probe \
  --probe-bundle /absolute/private/delivery-bundle.local-v1
```

The bundle may also be specified by its `manifest.private.json` path. Only the
frozen manifest SHA-256
`a4c52d5f9d01ac07e516f99f297444a0a7dfabf0dd0e496d8e6b8f7ad2c1283a`
is admitted. All 34 regular provenance files are hash checked, including the
unselected arm64e artifact and build/signing/controller QA sources. Bundle
payloads and private provenance remain outside Git. The own arm64 Mach-O UUID,
CodeDirectory CDHash and five signed code pages are checked against the pinned
host signature metadata. This verifies code-page hashes, not AMFI admission.

Only an explicit `--install` copies files. Supply an explicit device and the
already validated SSH identity/known-host options; no default device is chosen
for this component's installation. The options environment variable is a JSON
array of SSH arguments, not a shell command. Capture installation stdout in a
private receipt: it contains filesystem identities and resolved rootless paths.

```bash
MACWS_DEVICE='<root@device>' MACWS_DEVICE_PORT='<port>' \
MACWS_DIAGNOSTIC_SSH_OPTIONS_JSON='["-i","/absolute/private/key","-o","IdentitiesOnly=yes"]' \
bash misc/device_pipeline.sh --component diagnostic-probe \
  --probe-bundle /absolute/private/delivery-bundle.local-v1 --install \
  > /absolute/private/new-delivery-receipt.json
```

The selected five files are `probe.arm64` in the dated rootfs probe directory,
and `controller.py`, `runtime_support.py`, `watchdog.py`, and canonical offline
QA JSON in the dated rootless controller directory. arm64e installation is
refused by the helper CLI. Python files are copied as data and never imported
on the device by delivery. The probe is never launched. Delivery performs zero
trustcache changes, launchd bootstrap/debug admission, signals or resumes.

The finite SSH stdin envelope is at most 1 MiB; the host timeout is at most
20 seconds, the receiver has a 12-second alarm and an 8-second deadline.
Installation requires root and exact hardware/kernel/iPadOS/macOS builds.
Host output-size checks apply after capture completes; they bound accepted
output, not peak capture memory. The wall timeout remains twenty seconds.
The legitimate `/var/jb` Dopamine preboot/procursus symlink is resolved and
recorded; canonical parents are opened component by component with no-follow
directory descriptors and must be root-owned without group/other write access.
No ownership or permission repair is attempted.

Both destination directories must be absent before any creation. Directories
and files are created exclusively, each file's final mode is settled before its
accepted stat token, bytes are read back, and final names, hashes and dev/inode
tokens are rechecked. A pre-existing or raced destination is preserved. A
partial failed copy is also preserved with a refusal receipt; there is no
automatic guessed cleanup or overwrite/retry. The caller must re-observe the
exact recorded files before any separately scoped cleanup. A new vnode here
means an exclusively created file at a previously absent name, not a kernel
mapping or code-signature-cache observation.

Successful delivery proves those five bytes and filesystem identities only.
It does not establish current dependency closure, trust membership, loaded
images, native watchdog controls, Begin/Cancel results, presentation, stability,
or device acceptance. Source and receiver hashes in the plan/receipt bind the
delivery version; freeze reviewed sources before producing a runtime receipt.
A userspace timeout cannot guarantee recovery from a kernel stall.

Host controls use synthetic Mach-O bytes and temporary directories, never SSH
or a native job. Run `python3 -m unittest discover -s misc -p
'test_macws_diagnostic_probe_pipeline.py'`, `bash -n misc/device_pipeline.sh`,
and `git diff --check` before delivery.

The pinned bundle carries controller v6 (88 host controls). Its fourteen new
full-execute controls cover exactly-once descriptor closure and retention of
partial/error reports through finalization. The same normal-control regression
fails frozen v5 with EBADF and passes v6. The five additional provenance files
carry those tests, the comparison runner, receipt and before/after logs.

The process-state gate uses native proc_bsdinfo status rather than the observed
unknown ps output. A copied device witness now establishes initial SSTOP=4.
The clock uses public Mach absolute time and the observed 125/3 timebase across
processes; this device's Python3.9.9 process-relative monotonic epoch is not
used for cross-process freshness. These are narrow diagnostic observations.

**Controller execution remains blocked.** The actual v5 stopped control refused
a redirected system service query: the owned job exists in user/501. v6 fixes
descriptor/report handling only and deliberately retains that domain refusal.
It has not been deployed or device-accepted. Correct and review the separately
witnessed service-domain invariant before any further control dispatch. No
native control or active Begin/Cancel acceptance is established by this bundle.
See the [dated control and cleanup evidence](evidence/ipados-1641-stopped-control-20261018.md).

SSH options allow only explicit identity/cipher/known-host and bounded
connection settings. TTY, background, stdin redirection, forwarding and caller
command/config changes are refused. Transport ignores external SSH configuration
and keeps a finite foreground stdin session.
