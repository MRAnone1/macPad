"""Temporary synthetic delivery controls; no network, candidate or native job."""
import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

import macws_diagnostic_probe_pipeline as host
import macws_diagnostic_probe_receiver as receiver


def synthetic_probe():
    data = bytearray(128)
    struct.pack_into("<8I", data, 0, 0xfeedfacf, 0x100000c, 0, 2, 2, 40, 0, 0)
    struct.pack_into("<II16s", data, 32, 0x1b, 24, uuid.UUID("12345678-1234-1234-1234-123456789012").bytes)
    struct.pack_into("<4I", data, 56, 0x1d, 16, 128, 104)
    directory = bytearray(84)
    struct.pack_into(">9I", directory, 0, 0xfade0c02, 84, 0x20001, 0, 52, 44, 0, 1, 128)
    struct.pack_into("4B", directory, 36, 32, 2, 0, 12)
    directory[44:52] = b"probe\0\0\0"
    directory[52:84] = bytes.fromhex(receiver.sha(data))
    return bytes(data) + struct.pack(">5I", 0xfade0cc0, 104, 1, 0, 20) + directory


class DeliveryFixture:
    def __init__(self, path):
        self.bundle = path / "bundle"
        self.bundle.mkdir()
        self.files = {name: (synthetic_probe() if name == "probe.arm64" else (name + " fake").encode())
                      for name in receiver.SELECTED}
        self.files.update({"provenance-%02d" % i: b"local fake provenance" for i in range(36)})
        rows = []
        for name, raw in sorted(self.files.items()):
            selected = receiver.SELECTED.get(name)
            rows.append({"name": name, "bytes": len(raw), "sha256": receiver.sha(raw),
                         "intended_device_path": (selected[0] + "/" + selected[1] + "/" + name) if selected else None,
                         "intended_device_mode": format(selected[2], "04o") if selected else None})
            (self.bundle / name).write_bytes(raw)
        self.manifest = {"schema": "macws.swap-pair.local-delivery-bundle.v1", "files": rows,
                         "content_rows_sha256": receiver.sha(receiver.canonical(rows)),
                         "host_signature_results": {"arm64": receiver.probe_signature(self.files["probe.arm64"])}}
        self.raw = receiver.canonical(self.manifest)
        (self.bundle / "manifest.private.json").write_bytes(self.raw)
        self.manifest_sha = receiver.sha(self.raw)
        self.destinations = {receiver.PROBE_PARENT: path / "rootfs-parent",
                             receiver.CONTROLLER_PARENT: path / "rootless-parent"}
        for target in self.destinations.values():
            target.mkdir()

    def parent_opener(self, logical, check):
        check()
        target = self.destinations[logical]
        fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        return fd, str(target), os.fstat(fd)

    def recheck(self, logical, resolved, value):
        if str(self.destinations[logical]) != resolved:
            raise receiver.Refused("fake logical parent changed")
        receiver.require(receiver.dir_identity(os.stat(resolved)) == receiver.dir_identity(value), "fake parent changed")

    def install(self, files, signature, report, **kwargs):
        return receiver.install(files, signature, report, gate=lambda: None, parent_opener=self.parent_opener,
                                parent_recheck=self.recheck, owner_uid=os.getuid(), **kwargs)

    @staticmethod
    def report():
        return {"parents_private": [], "created_directories_private": [], "installed_files_private": [],
                "installation_verified": False}


class ProbeDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name)
        self.fixture = DeliveryFixture(self.path)
        self.pin = patch.object(receiver, "MANIFEST_SHA256", self.fixture.manifest_sha)
        self.pin.start()
        self.host_pin = patch.object(host, "MANIFEST_SHA256", self.fixture.manifest_sha)
        self.host_pin.start()

    def tearDown(self):
        self.host_pin.stop()
        self.pin.stop()
        self.temporary.cleanup()

    def prepared(self):
        plan, envelope = host.prepare_bundle(self.fixture.bundle)
        payload = receiver.decode_json(envelope)["payload"]
        files, signature = receiver.parse_payload(payload)
        return plan, envelope, files, signature

    def test_default_plan_has_no_transport_or_execution(self):
        with patch.object(host.subprocess, "run", side_effect=AssertionError("network forbidden")), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(host.main(["--probe-bundle", str(self.fixture.bundle)]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["device_commands"], 0)
        self.assertEqual(result["provenance_files_verified"], 41)
        self.assertEqual(len(result["payload_files"]), 5)
        self.assertFalse(result["runtime_accepted"])

    def test_manifest_file_argument_supported(self):
        plan, _ = host.prepare_bundle(self.fixture.bundle / "manifest.private.json")
        self.assertEqual(plan["architecture"], "arm64")

    def test_roundtrip_creates_new_files_final_modes_and_tokens(self):
        _, _, files, signature = self.prepared()
        report = self.fixture.report()
        self.fixture.install(files, signature, report)
        self.assertTrue(report["installation_verified"])
        self.assertEqual(len(report["installed_files_private"]), 5)
        for row in report["installed_files_private"]:
            parent, directory, mode = receiver.SELECTED[row["name"]]
            path = self.fixture.destinations[parent] / directory / row["name"]
            self.assertEqual(path.read_bytes(), files[row["name"]])
            self.assertEqual(receiver.token(path.stat()), row["stat"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
            self.assertTrue(row["previously_absent"] and row["new_vnode_created_exclusively"])

    def test_existing_directory_preserved_before_any_creation(self):
        _, _, files, signature = self.prepared()
        destination = self.fixture.destinations[receiver.CONTROLLER_PARENT] / receiver.CONTROLLER_DIR
        destination.mkdir()
        (destination / "unknown").write_bytes(b"preserve")
        with self.assertRaisesRegex(receiver.Refused, "already exists"):
            self.fixture.install(files, signature, self.fixture.report())
        self.assertEqual((destination / "unknown").read_bytes(), b"preserve")
        self.assertFalse((self.fixture.destinations[receiver.PROBE_PARENT] / receiver.PROBE_DIR).exists())

    def test_existing_symlink_target_preserved(self):
        _, _, files, signature = self.prepared()
        destination = self.fixture.destinations[receiver.PROBE_PARENT] / receiver.PROBE_DIR
        destination.symlink_to(self.path / "unrelated")
        with self.assertRaisesRegex(receiver.Refused, "already exists"):
            self.fixture.install(files, signature, self.fixture.report())
        self.assertTrue(destination.is_symlink())

    def test_second_parent_race_preserves_first_created_directory(self):
        _, _, files, signature = self.prepared()
        original = os.mkdir
        calls = []
        def race(name, mode=0o777, *, dir_fd=None):
            calls.append(name)
            if name == receiver.CONTROLLER_DIR:
                original(name, mode, dir_fd=dir_fd)
            return original(name, mode, dir_fd=dir_fd)
        report = self.fixture.report()
        with patch.object(receiver.os, "mkdir", side_effect=race):
            with self.assertRaises(FileExistsError):
                self.fixture.install(files, signature, report)
        self.assertEqual(len(report["created_directories_private"]), 1)
        self.assertFalse(report["installation_verified"])
        self.assertTrue((self.fixture.destinations[receiver.PROBE_PARENT] / receiver.PROBE_DIR).is_dir())

    def test_partial_write_failure_is_preserved_without_cleanup(self):
        _, _, files, signature = self.prepared()
        original = os.write
        writes = []
        def fail(fd, raw):
            writes.append(fd)
            if len(writes) == 2:
                raise OSError("synthetic disk refusal")
            return original(fd, raw[:5])
        report = self.fixture.report()
        with patch.object(receiver.os, "write", side_effect=fail):
            with self.assertRaisesRegex(OSError, "disk refusal"):
                self.fixture.install(files, signature, report)
        partial = self.fixture.destinations[receiver.PROBE_PARENT] / receiver.PROBE_DIR / "probe.arm64"
        self.assertEqual(partial.read_bytes(), files["probe.arm64"][:5])
        self.assertFalse(report["installation_verified"])

    def test_deadline_refuses_before_mutation(self):
        _, _, files, signature = self.prepared()
        with self.assertRaisesRegex(receiver.Refused, "deadline"):
            self.fixture.install(files, signature, self.fixture.report(), clock=iter([0.0, 9.0]).__next__)
        self.assertTrue(all(list(path.iterdir()) == [] for path in self.fixture.destinations.values()))

    def test_gate_refusal_creates_nothing(self):
        _, _, files, signature = self.prepared()
        with self.assertRaisesRegex(receiver.Refused, "wrong device"):
            receiver.install(files, signature, self.fixture.report(),
                             gate=lambda: (_ for _ in ()).throw(receiver.Refused("wrong device")))
        self.assertTrue(all(list(path.iterdir()) == [] for path in self.fixture.destinations.values()))

    def test_corrupt_provenance_file_refuses_plan(self):
        (self.fixture.bundle / "provenance-01").write_bytes(b"changed")
        with self.assertRaisesRegex(receiver.Refused, "content differs"):
            host.prepare_bundle(self.fixture.bundle)

    def test_unreviewed_manifest_refuses(self):
        (self.fixture.bundle / "manifest.private.json").write_bytes(self.fixture.raw + b" ")
        with self.assertRaisesRegex(receiver.Refused, "unreviewed"):
            host.prepare_bundle(self.fixture.bundle)

    def test_symlink_local_source_refuses(self):
        original = self.fixture.bundle / "provenance-01"
        original.unlink()
        original.symlink_to(self.fixture.bundle / "provenance-02")
        with self.assertRaises(OSError):
            host.prepare_bundle(self.fixture.bundle)

    def test_extra_local_file_refuses(self):
        (self.fixture.bundle / "extra").write_bytes(b"no")
        with self.assertRaisesRegex(receiver.Refused, "unexpected"):
            host.prepare_bundle(self.fixture.bundle)

    def test_duplicate_json_keys_refuse(self):
        with self.assertRaisesRegex(receiver.Refused, "duplicate"):
            receiver.decode_json(b'{"key":1,"key":2}')

    def test_corrupt_signed_page_refuses(self):
        raw = bytearray(synthetic_probe())
        raw[100] = 1
        with self.assertRaisesRegex(receiver.Refused, "code page mismatch"):
            receiver.probe_signature(raw)

    def test_wrong_architecture_refuses(self):
        raw = bytearray(synthetic_probe())
        struct.pack_into("<I", raw, 8, 2)
        with self.assertRaisesRegex(receiver.Refused, "thin arm64"):
            receiver.probe_signature(raw)

    def test_receiver_rejects_extra_file(self):
        _, envelope, _, _ = self.prepared()
        payload = receiver.decode_json(envelope)["payload"]
        payload["files_b64"]["probe.arm64e"] = ""
        with self.assertRaisesRegex(receiver.Refused, "five selected"):
            receiver.parse_payload(payload)

    def test_transport_enforces_timeout_and_uses_only_stdin_payload(self):
        plan, envelope, _, _ = self.prepared()
        seen = []
        report = {"schema": "macws.diagnostic-probe.delivery.private.v1",
                  "receiver_sha256": plan["receiver_source_sha256"],
                  "bundle_manifest_sha256": self.fixture.manifest_sha,
                  "installation_verified": False, "candidate_executions": 0,
                  "controller_executions": 0, "trust_mutations": 0,
                  "native_dependency_closure_currently_verified": False, "current_trust_verified": False,
                  "device_acceptance": False, "runtime_accepted": False, "freeze_cause_or_fix_proven": False,
                  "automatic_cleanup_attempted": False}
        def fake_run(args, **kwargs):
            seen.append((args, kwargs))
            return subprocess.CompletedProcess(args, 1, receiver.canonical(report), b"")
        actual, code = host.install(plan, envelope, device="root@example.invalid", port=22,
                                    options=["-i", "/private/key-with spaces"], run=fake_run)
        self.assertEqual(code, 1)
        self.assertEqual(seen[0][1]["input"], envelope)
        self.assertEqual(seen[0][1]["timeout"], 20)
        self.assertIn("/private/key-with spaces", seen[0][0])
        self.assertNotIn("probe.arm64", seen[0][0][-1])
        self.assertFalse(actual["installation_verified"])
        with self.assertRaisesRegex(receiver.Refused, "<=20"):
            host.install(plan, envelope, device="root@example.invalid", port=22, options=[], timeout=21, run=fake_run)

    def test_host_refuses_execution_or_acceptance_claim(self):
        plan, _, _, _ = self.prepared()
        base = {"schema": "macws.diagnostic-probe.delivery.private.v1",
                "receiver_sha256": plan["receiver_source_sha256"],
                "bundle_manifest_sha256": self.fixture.manifest_sha,
                "installation_verified": False, "candidate_executions": 0,
                "controller_executions": 0, "trust_mutations": 0,
                "native_dependency_closure_currently_verified": False, "current_trust_verified": False,
                "device_acceptance": False, "runtime_accepted": False, "freeze_cause_or_fix_proven": False,
                "automatic_cleanup_attempted": False}
        host.validate_receipt(base, plan, 1)
        for field in ("candidate_executions", "controller_executions", "trust_mutations",
                      "current_trust_verified", "device_acceptance", "automatic_cleanup_attempted"):
            report = copy.deepcopy(base)
            report[field] = 1
            with self.assertRaises(receiver.Refused):
                host.validate_receipt(report, plan, 1)

    def test_wrong_logical_parent_is_rechecked(self):
        _, _, files, signature = self.prepared()
        calls = []
        def changed(logical, resolved, value):
            calls.append(logical)
            if len(calls) == 2:
                raise receiver.Refused("logical parent changed")
        with patch.object(self.fixture, "recheck", side_effect=changed):
            with self.assertRaisesRegex(receiver.Refused, "logical parent changed"):
                self.fixture.install(files, signature, self.fixture.report())
        self.assertTrue((self.fixture.destinations[receiver.PROBE_PARENT] / receiver.PROBE_DIR).exists())
        self.assertFalse((self.fixture.destinations[receiver.CONTROLLER_PARENT] / receiver.CONTROLLER_DIR).exists())

    def test_install_requires_explicit_device(self):
        plan, envelope, _, _ = self.prepared()
        with self.assertRaisesRegex(receiver.Refused, "explicit SSH device"):
            host.install(plan, envelope, device=None, port=22, options=[], run=lambda *a, **k: self.fail("SSH used"))

    def test_ssh_options_cannot_background_redirect_or_forward(self):
        for options in (["-f"], ["-n"], ["-t"], ["-L", "1:host:2"], ["-F", "/arbitrary/config"],
                        ["-o", "ProxyCommand=arbitrary"], ["-o", "RemoteCommand=arbitrary"],
                        ["-o", "StdinNull=yes"], ["-o", "ConnectTimeout=999"]):
            with self.subTest(options=options), self.assertRaises(receiver.Refused):
                host.ssh_options(json.dumps(options))

    def test_ssh_options_accept_only_bounded_identity_and_connection_settings(self):
        options = ["-i", "/private/key-with spaces", "-c", "aes128-ctr", "-o", "BatchMode=yes",
                   "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=15"]
        self.assertEqual(host.ssh_options(json.dumps(options)), options)

    def test_shell_dispatch_refuses_restart_before_network(self):
        result = subprocess.run(["bash", str(Path(host.__file__).with_name("device_pipeline.sh")),
                                 "--component", "diagnostic-probe", "--probe-bundle", str(self.fixture.bundle),
                                 "--restart-workspace"], capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"refuses workspace", result.stderr)

    def test_diagnostic_flags_cannot_change_existing_component(self):
        result = subprocess.run(["bash", str(Path(host.__file__).with_name("device_pipeline.sh")),
                                 "--component", "runtime", "--probe-bundle", str(self.fixture.bundle)],
                                capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"require --component diagnostic-probe", result.stderr)


if __name__ == "__main__":
    unittest.main()
