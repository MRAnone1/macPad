"""Synthetic host-filesystem fault tests; no device or network actions."""

import contextlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from macws_swap_pair import retained_archive as archive


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="macws-archive-synthetic-")
        # macOS /var is an intentional OS alias. The API itself never follows it.
        self.parent = Path(self.temporary.name).resolve()
        self.target = self.parent / "capture-1"
        self.manifest = {"schema": "synthetic.manifest.v1", "files": {"a": 7}}
        self.provenance = {"source": "synthetic", "verified": False}
        self.files = {"job.plist": b"synthetic plist\0", "probe.log": b"synthetic log\n"}
        self.wire = b'{"synthetic":true}\n'

    def tearDown(self):
        self.temporary.cleanup()

    def create(self, **overrides):
        kwargs = dict(wire=self.wire, manifest=self.manifest,
                      provenance=self.provenance, files=self.files)
        kwargs.update(overrides)
        return archive.archive_bytes(self.parent, "capture-1", **kwargs)

    def verify(self, **overrides):
        kwargs = dict(expected_manifest=self.manifest,
                      expected_provenance=self.provenance,
                      expected_wire_sha256=archive.sha256(self.wire),
                      expected_file_sha256={name: archive.sha256(data)
                                            for name, data in self.files.items()})
        kwargs.update(overrides)
        return archive.verify_archive(self.target, **kwargs)

    def test_success_exact_receipt_entries_modes_and_bytes(self):
        result = self.create()
        self.assertEqual(set(result), {"schema", "manifest_sha256", "provenance_sha256",
                                     "wire_sha256", "file_sha256", "durable_archive_verified",
                                     "native_evidence_authenticity_verified", "device_acceptance"})
        self.assertIs(result["durable_archive_verified"], True)
        self.assertIs(result["native_evidence_authenticity_verified"], False)
        self.assertIs(result["device_acceptance"], False)
        self.assertEqual({p.name for p in self.target.iterdir()}, archive.ENTRY_NAMES)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o700)
        for path in self.target.iterdir():
            info = path.stat()
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_uid, os.geteuid())
            self.assertEqual(info.st_nlink, 1)
        self.assertEqual((self.target / "job.plist.private.bin").read_bytes(), self.files["job.plist"])
        checked = self.verify()
        self.assertEqual(checked["receipt"], result)
        self.assertIs(checked["verification"]["current_bytes_verified"], True)
        self.assertIs(checked["verification"]["past_fsync_independently_verified"], False)

    def test_partial_writes_complete_before_success(self):
        original = os.write
        counts = []

        def short_write(fd, data):
            counts.append(len(data))
            return original(fd, data[:max(1, len(data) // 3)])

        with mock.patch.object(archive.os, "write", side_effect=short_write):
            self.create()
        self.assertGreater(len(counts), 6)
        self.verify()

    def test_zero_write_preserves_partial_and_refuses(self):
        with mock.patch.object(archive.os, "write", return_value=0):
            with self.assertRaises(archive.ArchiveRefused):
                self.create()
        self.assertTrue(self.target.is_dir())
        self.assertEqual((self.target / "wire.private.bin").stat().st_size, 0)
        self.assertFalse((self.target / "receipt.private.json").exists())
        with self.assertRaises(FileExistsError):
            self.create()

    def test_invalid_write_result_refuses(self):
        for result in (-1, True, 999999):
            with self.subTest(result=result):
                name = "bad-write-" + str(result)
                with mock.patch.object(archive.os, "write", return_value=result):
                    with self.assertRaises(archive.ArchiveRefused):
                        archive.archive_bytes(self.parent, name, wire=self.wire,
                                              manifest={}, provenance={}, files=self.files)

    def test_each_fsync_failure_refuses_and_keeps_partial(self):
        original = os.fsync
        # Five payloads, first directory, receipt, final directory, parent.
        for fail_at in range(1, 10):
            with self.subTest(fail_at=fail_at):
                count = [0]

                def injected(fd):
                    count[0] += 1
                    if count[0] == fail_at:
                        raise OSError("synthetic fsync failure")
                    return original(fd)

                name = "fail-fsync-" + str(fail_at)
                with mock.patch.object(archive.os, "fsync", side_effect=injected):
                    with self.assertRaises(OSError):
                        archive.archive_bytes(self.parent, name, wire=self.wire,
                                              manifest={}, provenance={}, files=self.files)
                self.assertTrue((self.parent / name).is_dir())

    def test_true_persisted_receipt_does_not_prove_last_fsync(self):
        original = os.fsync
        count = [0]

        def injected(fd):
            count[0] += 1
            if count[0] == 8:
                raise OSError("synthetic final directory fsync failure")
            return original(fd)

        with mock.patch.object(archive.os, "fsync", side_effect=injected):
            with self.assertRaises(OSError):
                self.create()
        self.assertIs(json.loads((self.target / "receipt.private.json").read_bytes())[
            "durable_archive_verified"], True)
        self.assertIs(self.verify()["verification"]["past_fsync_independently_verified"], False)

    def test_creation_readback_failure_preserves_partial(self):
        with mock.patch.object(archive, "_read_fd", return_value=b"wrong"):
            with self.assertRaises(archive.ArchiveRefused):
                self.create()
        self.assertTrue(self.target.is_dir())
        self.assertFalse((self.target / "receipt.private.json").exists())

    def test_final_creation_readback_failure_refuses(self):
        original = archive._read_fd
        count = [0]

        def injected(fd, limit):
            count[0] += 1
            return b"wrong" if count[0] == 7 else original(fd, limit)

        with mock.patch.object(archive, "_read_fd", side_effect=injected):
            with self.assertRaises(archive.ArchiveRefused):
                self.create()
        self.assertTrue((self.target / "receipt.private.json").exists())

    def test_preexisting_archive_is_not_overwritten(self):
        self.create()
        original = {p.name: (p.stat().st_ino, p.read_bytes()) for p in self.target.iterdir()}
        with self.assertRaises(FileExistsError):
            self.create()
        self.assertEqual(original, {p.name: (p.stat().st_ino, p.read_bytes())
                                    for p in self.target.iterdir()})

    def test_preexisting_archive_symlink_refused(self):
        other = self.parent / "other"
        other.mkdir(mode=0o700)
        self.target.symlink_to(other, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            self.create()
        self.assertEqual(list(other.iterdir()), [])

    def test_parent_symlink_refused(self):
        alias = self.parent / "alias"
        alias.symlink_to(self.parent, target_is_directory=True)
        with self.assertRaises(OSError):
            archive.archive_bytes(alias, "new", wire=self.wire, manifest={},
                                  provenance={}, files=self.files)
        self.assertFalse((self.parent / "new").exists())

    def test_parent_ancestor_symlink_refused(self):
        actual = self.parent / "actual"
        actual.mkdir(mode=0o700)
        child = actual / "child"
        child.mkdir(mode=0o700)
        alias = self.parent / "alias"
        alias.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(OSError):
            archive.archive_bytes(alias / "child", "new", wire=self.wire,
                                  manifest={}, provenance={}, files=self.files)

    def test_untrusted_writable_parent_refused(self):
        self.parent.chmod(0o777)
        try:
            with self.assertRaises(archive.ArchiveRefused):
                self.create()
        finally:
            self.parent.chmod(0o700)
        self.assertFalse(self.target.exists())

    def test_hostile_archive_names_refuse_before_open(self):
        for name in ("", ".", "..", "../x", "/x", "a/b", "a\0b", "a" * 97, b"bytes"):
            with self.subTest(name=name), mock.patch.object(archive.os, "open") as opened:
                with self.assertRaises(archive.ArchiveRefused):
                    archive.archive_bytes(self.parent, name, wire=self.wire,
                                          manifest={}, provenance={}, files=self.files)
                opened.assert_not_called()

    def test_hostile_parent_paths_refuse(self):
        for path in ("relative", str(self.parent) + "/../other", str(self.parent) + "//x",
                     str(self.parent) + "/", "/a\0b", b"/bytes"):
            with self.subTest(path=path):
                with self.assertRaises(archive.ArchiveRefused):
                    archive.archive_bytes(path, "capture", wire=self.wire,
                                          manifest={}, provenance={}, files=self.files)

    def test_raw_bytes_and_file_limits_reject_before_open(self):
        cases = [{"wire": b""}, {"wire": bytearray(b"x")}, {"wire": b"x" * (archive.WIRE_LIMIT + 1)},
                 {"files": {"job.plist": b"x"}},
                 {"files": {**self.files, "foreign": b"x"}},
                 {"files": {**self.files, "job.plist": b"x" * 65537}},
                 {"files": {**self.files, "probe.log": b"x" * 262145}},
                 {"files": {**self.files, "probe.log": bytearray(b"x")}}]
        for case in cases:
            with self.subTest(case=list(case)), mock.patch.object(archive.os, "open") as opened:
                with self.assertRaises(archive.ArchiveRefused):
                    self.create(**case)
                opened.assert_not_called()

    def test_empty_wire_forged_receipt_is_refused(self):
        self.create()
        (self.target / "wire.private.bin").write_bytes(b"")
        receipt = archive._receipt(archive.canonical_json(self.manifest),
                                   archive.canonical_json(self.provenance), b"", self.files)
        (self.target / "receipt.private.json").write_bytes(archive.canonical_json(receipt))
        with self.assertRaises(archive.ArchiveRefused):
            self.verify(expected_wire_sha256=archive.sha256(b""))

    def test_maximum_bytes_and_empty_files_are_supported(self):
        self.create(wire=b"x" * archive.WIRE_LIMIT,
                    files={"job.plist": b"x" * 65536, "probe.log": b""})
        archive.verify_archive(self.target, expected_manifest=self.manifest,
                               expected_provenance=self.provenance,
                               expected_wire_sha256=archive.sha256(b"x" * archive.WIRE_LIMIT),
                               expected_file_sha256={"job.plist": archive.sha256(b"x" * 65536),
                                                     "probe.log": archive.sha256(b"")})

    def test_hostile_plain_json_rejects_before_open(self):
        cycle = []
        cycle.append(cycle)
        deep = []
        for _ in range(34):
            deep = [deep]
        class Strange(dict):
            pass
        cases = [[], Strange(), {1: "numeric key"}, {"x": b"bytes"}, {"x": (1,)},
                 {"x": math.inf}, {"x": math.nan}, {"x": -math.inf},
                 {"x": 2**63}, {"x": -(2**63) - 1}, {"x": "\ud800"},
                 {"x": "a" * 65537}, {"x": [None] * 20001},
                 {"x": cycle}, {"x": deep}, {"x": ["a" * 65536] * 5}]
        for value in cases:
            with self.subTest(kind=type(value).__name__), mock.patch.object(archive.os, "open") as opened:
                with self.assertRaises(archive.ArchiveRefused):
                    self.create(manifest=value)
                opened.assert_not_called()

    def test_frozen_input_not_silently_refreshed_after_validation(self):
        original = os.mkdir
        original_manifest = archive.canonical_json(self.manifest)

        def injected(*args, **kwargs):
            self.manifest["files"]["a"] = 8
            self.files["job.plist"] = b"replacement caller mapping"
            return original(*args, **kwargs)

        with mock.patch.object(archive.os, "mkdir", side_effect=injected):
            result = self.create()
        self.assertEqual(result["manifest_sha256"], archive.sha256(original_manifest))
        self.assertEqual((self.target / "job.plist.private.bin").read_bytes(), b"synthetic plist\0")
        with self.assertRaises(archive.ArchiveRefused):
            self.verify()

    def test_created_file_substitution_is_refused(self):
        original = os.fsync
        once = [False]

        def injected(fd):
            result = original(fd)
            if not once[0]:
                once[0] = True
                path = self.target / "wire.private.bin"
                path.rename(self.target / "original-wire")
                path.write_bytes(self.wire)
                path.chmod(0o600)
            return result

        with mock.patch.object(archive.os, "fsync", side_effect=injected):
            with self.assertRaises(archive.ArchiveRefused):
                self.create()
        self.assertTrue((self.target / "original-wire").exists())

    def test_file_hardlink_is_refused(self):
        self.create()
        os.link(self.target / "probe.log.private.bin", self.parent / "extra-hardlink")
        with self.assertRaises(archive.ArchiveRefused):
            self.verify()

    def test_file_symlink_is_refused(self):
        self.create()
        path = self.target / "probe.log.private.bin"
        path.unlink()
        path.symlink_to(self.target / "wire.private.bin")
        with self.assertRaises(OSError):
            self.verify()

    def test_fifo_is_refused_without_blocking(self):
        self.create()
        path = self.target / "probe.log.private.bin"
        path.unlink()
        os.mkfifo(path, mode=0o600)
        with self.assertRaises(archive.ArchiveRefused):
            self.verify()

    def test_directory_symlink_is_refused(self):
        self.create()
        moved = self.parent / "moved"
        self.target.rename(moved)
        self.target.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(OSError):
            self.verify()

    def test_extra_or_missing_entry_is_refused(self):
        self.create()
        extra = self.target / "foreign"
        extra.write_bytes(b"foreign")
        with self.assertRaises(archive.ArchiveRefused):
            self.verify()
        extra.unlink()
        (self.target / "probe.log.private.bin").unlink()
        with self.assertRaises(archive.ArchiveRefused):
            self.verify()

    def test_wrong_directory_mode_is_refused(self):
        self.create()
        self.target.chmod(0o750)
        with self.assertRaises(archive.ArchiveRefused):
            self.verify()

    def test_wrong_file_mode_is_refused(self):
        self.create()
        (self.target / "job.plist.private.bin").chmod(0o640)
        with self.assertRaises(archive.ArchiveRefused):
            self.verify()

    def test_verifier_checks_owner(self):
        self.create()
        with mock.patch.object(archive.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(archive.ArchiveRefused):
                self.verify()

    def test_changed_blob_is_refused(self):
        self.create()
        (self.target / "job.plist.private.bin").write_bytes(b"different")
        with self.assertRaises(archive.ArchiveRefused):
            self.verify()

    def test_coherent_blob_and_receipt_rewrite_is_refused(self):
        self.create()
        altered_files = {**self.files, "probe.log": b"coherent forged log\n"}
        (self.target / "probe.log.private.bin").write_bytes(altered_files["probe.log"])
        receipt = archive._receipt(archive.canonical_json(self.manifest),
                                   archive.canonical_json(self.provenance),
                                   self.wire, altered_files)
        (self.target / "receipt.private.json").write_bytes(archive.canonical_json(receipt))
        with self.assertRaises(archive.ArchiveRefused):
            self.verify()

    def test_hostile_expected_file_hashes_refuse_before_open(self):
        good = {name: archive.sha256(data) for name, data in self.files.items()}
        cases = [None, [], {}, {"job.plist": good["job.plist"]},
                 {**good, "extra": "0" * 64}, {**good, "probe.log": "A" * 64},
                 {**good, "probe.log": False}, {**good, "probe.log": b"0" * 64}]
        for value in cases:
            with self.subTest(value=value), mock.patch.object(archive.os, "open") as opened:
                with self.assertRaises(archive.ArchiveRefused):
                    self.verify(expected_file_sha256=value)
                opened.assert_not_called()

    def test_changed_manifest_or_provenance_expectations_refuse(self):
        self.create()
        for options in ({"expected_manifest": {"changed": True}},
                        {"expected_provenance": {"changed": True}},
                        {"expected_wire_sha256": "0" * 64},
                        {"expected_wire_sha256": "A" * 64}):
            with self.subTest(options=options):
                with self.assertRaises(archive.ArchiveRefused):
                    self.verify(**options)

    def test_noncanonical_or_hostile_receipt_is_refused(self):
        self.create()
        path = self.target / "receipt.private.json"
        original = path.read_bytes()
        values = [original.rstrip(b"\n"), b'{"x":1,"x":2}\n', b'{"x":NaN}\n',
                  b'{"x":1e999}\n', b'{}\n', b'\xff',
                  json.dumps(json.loads(original), indent=2).encode() + b"\n"]
        for value in values:
            with self.subTest(value=value[:20]):
                path.write_bytes(value)
                with self.assertRaises(archive.ArchiveRefused):
                    self.verify()

    def test_verified_receipt_boolean_counterfeits_refuse(self):
        self.create()
        path = self.target / "receipt.private.json"
        receipt = json.loads(path.read_bytes())
        for field, value in (("durable_archive_verified", 1),
                             ("native_evidence_authenticity_verified", True),
                             ("device_acceptance", True)):
            with self.subTest(field=field):
                changed = {**receipt, field: value}
                path.write_bytes(archive.canonical_json(changed))
                with self.assertRaises(archive.ArchiveRefused):
                    self.verify()

    def test_verify_detects_substitution_after_first_read(self):
        self.create()
        original = archive._read_fd
        once = [False]

        def injected(fd, limit):
            data = original(fd, limit)
            if not once[0]:
                once[0] = True
                path = self.target / "wire.private.bin"
                path.rename(self.parent / "old-wire")
                path.write_bytes(self.wire)
                path.chmod(0o600)
            return data

        with mock.patch.object(archive, "_read_fd", side_effect=injected):
            with self.assertRaises(archive.ArchiveRefused):
                self.verify()

    def test_verify_detects_same_inode_content_change_during_read(self):
        self.create()
        original = archive._read_fd
        once = [False]

        def injected(fd, limit):
            data = original(fd, limit)
            if not once[0]:
                once[0] = True
                (self.target / "wire.private.bin").write_bytes(b"modified")
            return data

        with mock.patch.object(archive, "_read_fd", side_effect=injected):
            with self.assertRaises(archive.ArchiveRefused):
                self.verify()

    def test_verification_does_not_fsync_or_write(self):
        self.create()
        with mock.patch.object(archive.os, "fsync", side_effect=AssertionError("no fsync")), \
             mock.patch.object(archive.os, "write", side_effect=AssertionError("no write")), \
             mock.patch.object(archive.os, "mkdir", side_effect=AssertionError("no mkdir")):
            self.verify()

    def test_import_and_default_cli_are_inert(self):
        source = Path(archive.__file__).read_text()
        code = compile(source, "synthetic-retained-archive", "exec")
        for module_name in ("synthetic_module", "__main__"):
            with self.subTest(name=module_name), contextlib.ExitStack() as stack:
                for name in ("open", "mkdir", "unlink", "rmdir", "write", "fsync"):
                    stack.enter_context(mock.patch.object(os, name, side_effect=AssertionError("no effects")))
                output = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                exec(code, {"__name__": module_name})
                if module_name == "__main__":
                    self.assertIs(json.loads(output.getvalue())["native_actions_available"], False)
                else:
                    self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
