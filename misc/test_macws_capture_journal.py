"""Host-tempfile adversarial tests; no network or device backend exists."""

import contextlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from macws_swap_pair import capture_journal as journal
archive = journal.archive
REFUSALS = (journal.JournalRefused, archive.ArchiveRefused, OSError)


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.parent = self.base / "captures"
        self.parent.mkdir(mode=0o700)
        self.instances = []

    def tearDown(self):
        for item in self.instances:
            item.close()
        self.temporary.cleanup()

    def make(self, *, name="capture-once", payload=b"pass\n", intent=None):
        result = journal.Journal(str(self.parent), name, payload=payload,
                                 intent={} if intent is None else intent)
        self.instances.append(result)
        return result

    def dispatched(self):
        item = self.make()
        item.mark_dispatch()
        return item

    def transported(self):
        item = self.dispatched()
        item.save_transport(stdout=b"raw\xff\0\n", stderr=b"err\xfe", transport={"returncode": 124})
        return item

    def assert_refuses_no_repeat(self, item, operation):
        with self.assertRaises(REFUSALS):
            operation()
        with self.assertRaises(journal.JournalRefused):
            item.mark_dispatch()
        with self.assertRaises(journal.JournalRefused):
            item.save_transport(stdout=b"", stderr=b"", transport={})

    def test_complete_capture_preserves_every_original_byte_and_permissions(self):
        payload = b"\0payload\xff"
        stdout, stderr = b"\xff\xfe{broken json\0", b"\x80error\n"
        item = self.make(payload=payload, intent={"operation": "read-only"})
        preparation = item.preparation_receipt
        self.assertEqual(preparation["phase"], "prepared")
        self.assertEqual(set(preparation["files"]), set(journal._BASE))
        dispatch = item.mark_dispatch()
        self.assertEqual(dispatch["phase"], "dispatch-intent-preserved")
        raw_receipt = item.save_transport(stdout=stdout, stderr=stderr,
                                          transport={"returncode": 124})
        self.assertEqual(raw_receipt["phase"], "transport-preserved")
        self.assertEqual(set(Path(item.directory).iterdir()),
                         {Path(item.directory) / name for name in journal._TRANSPORT})
        receipt = item.save_assessment({"accepted": False, "reason": "invalid JSON"})
        directory = Path(item.directory)
        self.assertEqual((directory / "stdin.private.py").read_bytes(), payload)
        self.assertEqual((directory / "stdout.original.private.bin").read_bytes(), stdout)
        self.assertEqual((directory / "stderr.original.private.bin").read_bytes(), stderr)
        self.assertEqual(set(p.name for p in directory.iterdir()), set(journal._RESULT))
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for path in directory.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
        self.assertTrue(receipt["host_durability_steps_completed"])
        self.assertFalse(receipt["native_evidence_authenticity_verified"])
        self.assertFalse(receipt["device_acceptance"])
        self.assertEqual(receipt, json.loads((directory / "receipt.private.json").read_bytes()))
        self.assertEqual(receipt["files"]["stdout.original.private.bin"],
                         {"bytes": len(stdout), "sha256": archive.sha256(stdout)})
        self.assertNotIn("receipt.private.json", receipt["files"])

    def test_preparation_receipt_is_copied(self):
        item = self.make()
        original = item.preparation_receipt
        original["files"].clear()
        self.assertEqual(set(item.preparation_receipt["files"]), set(journal._BASE))

    def test_empty_transport_bytes_are_retained(self):
        item = self.dispatched()
        receipt = item.save_result(stdout=b"", stderr=b"", transport={}, assessment={})
        self.assertEqual(receipt["files"]["stdout.original.private.bin"]["bytes"], 0)
        self.assertEqual((Path(item.directory) / "stderr.original.private.bin").read_bytes(), b"")

    def test_exact_transport_overflow_sentinels_are_retained(self):
        item = self.dispatched()
        stdout = b"x" * journal.STDOUT_LIMIT
        stderr = b"y" * journal.STDERR_LIMIT
        item.save_transport(stdout=stdout, stderr=stderr, transport={"overflow": True})
        self.assertEqual((Path(item.directory) / "stdout.original.private.bin").read_bytes(), stdout)
        self.assertEqual((Path(item.directory) / "stderr.original.private.bin").read_bytes(), stderr)

    def test_payload_exact_limit(self):
        self.make(payload=b"x" * journal.PAYLOAD_LIMIT)

    def test_payload_empty_oversized_or_wrong_type_refuses_before_directory(self):
        for number, payload in enumerate((b"", b"x" * (journal.PAYLOAD_LIMIT + 1),
                                            bytearray(b"x"), "x", None)):
            with self.subTest(payload_type=type(payload)):
                with self.assertRaises(journal.JournalRefused):
                    self.make(name="case-" + str(number), payload=payload)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_names_cannot_escape_or_reuse_capture_directory(self):
        for name in ("..", ".", "/absolute", "a/b", "a\0b", "a" * 97, ""):
            with self.subTest(name=name):
                with self.assertRaises(journal.JournalRefused):
                    self.make(name=name)
        item = self.make()
        snapshot = {p.name: p.read_bytes() for p in Path(item.directory).iterdir()}
        with self.assertRaises(FileExistsError):
            self.make()
        self.assertEqual({p.name: p.read_bytes() for p in Path(item.directory).iterdir()}, snapshot)

    def test_parent_requires_owned_0700_or_0755(self):
        os.chmod(self.parent, 0o750)
        with self.assertRaises(journal.JournalRefused):
            self.make()
        self.assertEqual(list(self.parent.iterdir()), [])
        os.chmod(self.parent, 0o755)
        self.make()

    def test_parent_owner_mismatch_refuses(self):
        real_fstat = os.fstat
        def foreign(fd):
            result = real_fstat(fd)
            if stat.S_ISDIR(result.st_mode) and result.st_ino == self.parent.stat().st_ino:
                values = list(result)
                values[4] = os.geteuid() + 1
                return os.stat_result(values)
            return result
        with mock.patch.object(archive.os, "fstat", side_effect=foreign):
            with self.assertRaises(archive.ArchiveRefused):
                self.make()
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_intermediate_symlink_parent_refuses(self):
        link = self.base / "alias"
        link.symlink_to(self.parent, target_is_directory=True)
        with self.assertRaises(OSError):
            journal.Journal(str(link), "capture-once", payload=b"x", intent={})
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_unsafe_parent_components_refuse(self):
        for path in ("relative", str(self.parent) + "/", str(self.parent) + "/../captures",
                     str(self.base) + "//captures", "/", str(self.parent) + "/."):
            with self.subTest(path=path):
                with self.assertRaises(archive.ArchiveRefused):
                    journal.Journal(path, "capture-once", payload=b"x", intent={})

    def test_preexisting_symlink_directory_is_not_followed(self):
        target = self.base / "foreign"
        target.mkdir()
        (self.parent / "capture-once").symlink_to(target, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            self.make()
        self.assertEqual(list(target.iterdir()), [])

    def test_no_progress_write_preserves_partial_without_dispatch(self):
        invoked = mock.Mock()
        with mock.patch.object(archive.os, "write", return_value=0):
            with self.assertRaises(archive.ArchiveRefused):
                item = self.make()
                invoked(item)
        invoked.assert_not_called()
        directory = self.parent / "capture-once"
        self.assertTrue(directory.is_dir())
        self.assertEqual(set(p.name for p in directory.iterdir()), {"stdin.private.py"})
        self.assertEqual((directory / "stdin.private.py").read_bytes(), b"")
        with self.assertRaises(FileExistsError):
            self.make()

    def test_partial_writes_are_completed_and_read_back(self):
        real_write = os.write
        with mock.patch.object(archive.os, "write", side_effect=lambda fd, data: real_write(fd, data[:3])):
            item = self.dispatched()
            item.save_result(stdout=b"a" * 101, stderr=b"b" * 31, transport={}, assessment={})
        self.assertEqual((Path(item.directory) / "stdout.original.private.bin").read_bytes(), b"a" * 101)

    def test_preparation_fsync_failure_prevents_transport_and_keeps_partial(self):
        invoked = mock.Mock()
        with mock.patch.object(archive.os, "fsync", side_effect=OSError("fsync failed")):
            with self.assertRaises(OSError):
                item = self.make()
                invoked(item)
        invoked.assert_not_called()
        self.assertTrue((self.parent / "capture-once" / "stdin.private.py").is_file())

    def test_preparation_read_failure_prevents_transport_and_keeps_partial(self):
        invoked = mock.Mock()
        with mock.patch.object(archive.os, "read", side_effect=OSError("read failed")):
            with self.assertRaises(OSError):
                item = self.make()
                invoked(item)
        invoked.assert_not_called()
        self.assertTrue((self.parent / "capture-once" / "stdin.private.py").is_file())

    def test_readback_mismatch_is_not_accepted(self):
        with mock.patch.object(archive, "_read_checked", return_value=(b"wrong", (1,))):
            with self.assertRaises(archive.ArchiveRefused):
                self.make()
        self.assertTrue((self.parent / "capture-once" / "stdin.private.py").is_file())

    def test_directory_syncs_precede_preparation_return(self):
        real_fsync = os.fsync
        events = []
        def sync(fd):
            events.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
            return real_fsync(fd)
        with mock.patch.object(archive.os, "fsync", side_effect=sync):
            self.make()
        self.assertEqual(events, ["file", "file", "directory", "directory"])

    def test_foreign_child_prevents_dispatch(self):
        item = self.make()
        (Path(item.directory) / "foreign").write_bytes(b"do not delete")
        self.assert_refuses_no_repeat(item, item.mark_dispatch)
        self.assertEqual((Path(item.directory) / "foreign").read_bytes(), b"do not delete")

    def test_payload_substitution_prevents_dispatch(self):
        item = self.make()
        path = Path(item.directory) / "stdin.private.py"
        path.rename(path.with_name("old"))
        path.write_bytes(b"pass\n")
        os.chmod(path, 0o600)
        self.assert_refuses_no_repeat(item, item.mark_dispatch)

    def test_same_inode_payload_change_prevents_dispatch(self):
        item = self.make()
        (Path(item.directory) / "stdin.private.py").write_bytes(b"evil\n")
        self.assert_refuses_no_repeat(item, item.mark_dispatch)

    def test_hardlink_prevents_dispatch(self):
        item = self.make()
        os.link(Path(item.directory) / "stdin.private.py", self.base / "linked")
        self.assert_refuses_no_repeat(item, item.mark_dispatch)

    def test_payload_symlink_prevents_dispatch(self):
        item = self.make()
        path = Path(item.directory) / "stdin.private.py"
        path.unlink()
        path.symlink_to(self.base / "unused")
        self.assert_refuses_no_repeat(item, item.mark_dispatch)

    def test_capture_directory_substitution_prevents_dispatch(self):
        item = self.make()
        path = Path(item.directory)
        path.rename(self.parent / "retained-original")
        path.mkdir(mode=0o700)
        self.assert_refuses_no_repeat(item, item.mark_dispatch)
        self.assertEqual(list(path.iterdir()), [])

    def test_parent_path_substitution_prevents_dispatch(self):
        item = self.make()
        self.parent.rename(self.base / "retained-parent")
        self.parent.mkdir(mode=0o700)
        self.assert_refuses_no_repeat(item, item.mark_dispatch)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_private_directory_mode_change_prevents_dispatch(self):
        item = self.make()
        os.chmod(item.directory, 0o755)
        self.assert_refuses_no_repeat(item, item.mark_dispatch)

    def test_dispatch_sync_failure_consumes_attempt_and_preserves_intent(self):
        item = self.make()
        real_fsync = os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("directory sync failed")
            return real_fsync(fd)
        with mock.patch.object(archive.os, "fsync", side_effect=fail_directory):
            self.assert_refuses_no_repeat(item, item.mark_dispatch)
        dispatch = json.loads((Path(item.directory) / "dispatch-intent.private.json").read_bytes())
        self.assertFalse(dispatch["transport_invocation_confirmed"])

    def test_phase_order_and_once_only(self):
        item = self.make()
        with self.assertRaises(journal.JournalRefused):
            item.save_transport(stdout=b"", stderr=b"", transport={})
        with self.assertRaises(journal.JournalRefused):
            item.save_assessment({})
        item.mark_dispatch()
        with self.assertRaises(journal.JournalRefused):
            item.mark_dispatch()
        item.save_transport(stdout=b"", stderr=b"", transport={})
        with self.assertRaises(journal.JournalRefused):
            item.save_transport(stdout=b"", stderr=b"", transport={})
        item.save_assessment({})
        with self.assertRaises(journal.JournalRefused):
            item.save_assessment({})

    def test_over_limit_or_nonbytes_result_refuses_before_any_raw_write(self):
        for index, (stdout, stderr) in enumerate(((b"x" * (journal.STDOUT_LIMIT + 1), b""),
                                                  (b"", b"y" * (journal.STDERR_LIMIT + 1)),
                                                  (bytearray(), b""), (b"", ""))):
            with self.subTest(index=index):
                item = self.make(name="case-" + str(index))
                item.mark_dispatch()
                self.assert_refuses_no_repeat(item, lambda: item.save_transport(
                    stdout=stdout, stderr=stderr, transport={}))
                self.assertEqual(set(p.name for p in Path(item.directory).iterdir()), set(journal._DISPATCH))

    def test_invalid_transport_json_keeps_both_original_raw_streams(self):
        item = self.dispatched()
        with self.assertRaises(archive.ArchiveRefused):
            item.save_transport(stdout=b"\xffraw", stderr=b"\xfeerr", transport={"bad": math.inf})
        self.assertEqual((Path(item.directory) / "stdout.original.private.bin").read_bytes(), b"\xffraw")
        self.assertEqual((Path(item.directory) / "stderr.original.private.bin").read_bytes(), b"\xfeerr")
        self.assertFalse((Path(item.directory) / "transport.private.json").exists())
        with self.assertRaises(journal.JournalRefused):
            item.save_transport(stdout=b"", stderr=b"", transport={})

    def test_invalid_assessment_keeps_transport_and_consumes_phase(self):
        item = self.transported()
        with self.assertRaises(archive.ArchiveRefused):
            item.save_assessment({"bad": object()})
        self.assertEqual(set(p.name for p in Path(item.directory).iterdir()), set(journal._TRANSPORT))
        with self.assertRaises(journal.JournalRefused):
            item.save_assessment({})

    def test_recursive_or_nonfinite_intent_refuses_before_creation(self):
        cycle = {}
        cycle["self"] = cycle
        for intent in (cycle, {"x": math.nan}, {"x": "\ud800"}, {1: "key"}, []):
            with self.subTest(kind=type(intent)):
                with self.assertRaises(archive.ArchiveRefused):
                    self.make(intent=intent)
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_transport_bytes_stable_after_caller_metadata_mutation(self):
        item = self.dispatched()
        transport = {"sub": {"returncode": 0}}
        item.save_transport(stdout=b"", stderr=b"", transport=transport)
        transport["sub"]["returncode"] = 99
        item.save_assessment({})
        self.assertEqual(json.loads((Path(item.directory) / "transport.private.json").read_bytes()),
                         {"sub": {"returncode": 0}})

    def test_raw_change_after_durability_prevents_assessment(self):
        item = self.transported()
        (Path(item.directory) / "stdout.original.private.bin").write_bytes(b"replaced")
        with self.assertRaises(REFUSALS):
            item.save_assessment({})
        self.assertFalse((Path(item.directory) / "assessment.private.json").exists())

    def test_final_parent_fsync_failure_leaves_true_receipt_without_success_return(self):
        item = self.transported()
        real_fsync = os.fsync
        def fail_parent(fd):
            if fd == item._parent_fd:
                raise OSError("last parent sync failed")
            return real_fsync(fd)
        with mock.patch.object(archive.os, "fsync", side_effect=fail_parent):
            with self.assertRaises(OSError):
                item.save_assessment({"accepted": False})
        receipt = json.loads((Path(item.directory) / "receipt.private.json").read_bytes())
        self.assertTrue(receipt["host_durability_steps_completed"])
        with self.assertRaises(journal.JournalRefused):
            item.save_assessment({})

    def test_close_only_closes_descriptors_and_is_idempotent(self):
        item = self.dispatched()
        fds = [item._parent_fd, item._directory_fd] + [fd for fd, _ in item._held.values()]
        names = set(Path(item.directory).iterdir())
        item.close()
        item.close()
        self.assertEqual(set(Path(item.directory).iterdir()), names)
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)
        with self.assertRaises(journal.JournalRefused):
            item.mark_dispatch()

    def test_context_manager_exception_preserves_partial_capture(self):
        with self.assertRaises(RuntimeError):
            with self.make() as item:
                item.mark_dispatch()
                raise RuntimeError("caller stopped")
        self.assertEqual(set(p.name for p in Path(item.directory).iterdir()), set(journal._DISPATCH))
        self.assertIsNone(item._directory_fd)

    def test_default_metadata_performs_no_filesystem_open(self):
        output = io.StringIO()
        with mock.patch.object(os, "open", side_effect=AssertionError("unexpected open")):
            with contextlib.redirect_stdout(output):
                journal.main()
        self.assertFalse(json.loads(output.getvalue())["native_actions_available"])

    def test_partial_stdout_preserves_known_bytes_without_fabricated_stderr(self):
        item = self.dispatched()
        raw = b"\xffpartial\0stdout"
        receipt = item.save_partial_transport(streams={"stdout": raw},
                                               transport={"contract_complete": False})
        directory = Path(item.directory)
        self.assertEqual((directory / "stdout.original.private.bin").read_bytes(), raw)
        self.assertFalse((directory / "stderr.original.private.bin").exists())
        self.assertFalse((directory / "assessment.private.json").exists())
        self.assertEqual(receipt["phase"], "partial-transport-preserved")
        self.assertEqual(receipt["captured_streams"], ["stdout"])
        self.assertEqual(receipt["missing_streams"], ["stderr"])
        self.assertNotIn("stderr.original.private.bin", receipt["files"])
        self.assertFalse(receipt["transport_contract_complete"])
        self.assertFalse(receipt["assessment_performed"])
        self.assertFalse(receipt["native_evidence_authenticity_verified"])
        self.assertFalse(receipt["device_acceptance"])
        with self.assertRaises(journal.JournalRefused):
            item.save_assessment({})
        with self.assertRaises(journal.JournalRefused):
            item.save_partial_transport(streams={"stderr": b"late"}, transport={})
        with self.assertRaises(journal.JournalRefused):
            item.save_transport(stdout=b"", stderr=b"", transport={})

    def test_partial_known_empty_stderr_is_distinct_from_unknown_stdout(self):
        item = self.dispatched()
        receipt = item.save_partial_transport(streams={"stderr": b""}, transport={})
        directory = Path(item.directory)
        self.assertEqual((directory / "stderr.original.private.bin").read_bytes(), b"")
        self.assertFalse((directory / "stdout.original.private.bin").exists())
        self.assertEqual(receipt["files"]["stderr.original.private.bin"],
                         {"bytes": 0, "sha256": archive.sha256(b"")})
        self.assertEqual(receipt["missing_streams"], ["stdout"])

    def test_partial_both_streams_never_admits_assessment(self):
        item = self.dispatched()
        streams = {"stdout": b"\xfe", "stderr": b"\xff"}
        receipt = item.save_partial_transport(streams=streams, transport={"returncode": None})
        self.assertEqual(receipt["captured_streams"], ["stderr", "stdout"])
        self.assertEqual(receipt["missing_streams"], [])
        self.assertFalse(receipt["transport_contract_complete"])
        self.assertEqual(set(p.name for p in Path(item.directory).iterdir()),
                         set(journal._TRANSPORT) | {"receipt.private.json"})
        with self.assertRaises(journal.JournalRefused):
            item.save_assessment({"accepted": True})

    def test_partial_invalid_subset_or_bytes_consumes_phase_without_writes(self):
        invalid = ({}, [], {"other": b"x"}, {"stdout": bytearray(b"x")},
                   {"stdout": "x"}, {"stdout": b"x" * (journal.STDOUT_LIMIT + 1)},
                   {"stderr": b"x" * (journal.STDERR_LIMIT + 1)})
        for index, streams in enumerate(invalid):
            with self.subTest(index=index):
                item = self.make(name="case-" + str(index))
                item.mark_dispatch()
                with self.assertRaises(journal.JournalRefused):
                    item.save_partial_transport(streams=streams, transport={})
                self.assertEqual(set(p.name for p in Path(item.directory).iterdir()),
                                 set(journal._DISPATCH))
                with self.assertRaises(journal.JournalRefused):
                    item.save_partial_transport(streams={"stdout": b""}, transport={})

    def test_partial_invalid_metadata_keeps_raw_and_precedes_validation_with_syncs(self):
        item = self.dispatched()
        real_fsync = os.fsync
        events = []
        def sync(fd):
            events.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
            return real_fsync(fd)
        def refuse_metadata(_):
            self.assertEqual(events, ["file", "directory", "directory"])
            raise archive.ArchiveRefused("metadata invalid")
        with mock.patch.object(archive.os, "fsync", side_effect=sync):
            with mock.patch.object(archive, "canonical_json", side_effect=refuse_metadata):
                with self.assertRaises(archive.ArchiveRefused):
                    item.save_partial_transport(streams={"stderr": b"\xfforiginal"}, transport={})
        directory = Path(item.directory)
        self.assertEqual((directory / "stderr.original.private.bin").read_bytes(), b"\xfforiginal")
        self.assertEqual(set(p.name for p in directory.iterdir()),
                         set(journal._DISPATCH) | {"stderr.original.private.bin"})
        with self.assertRaises(journal.JournalRefused):
            item.save_assessment({})

    def test_partial_last_fsync_failure_keeps_receipt_but_refuses_success_and_retry(self):
        item = self.dispatched()
        real_fsync = os.fsync
        calls = [0]
        def fail_last_parent(fd):
            if fd == item._parent_fd:
                calls[0] += 1
                if calls[0] == 2:
                    raise OSError("partial final parent sync failed")
            return real_fsync(fd)
        with mock.patch.object(archive.os, "fsync", side_effect=fail_last_parent):
            with self.assertRaises(OSError):
                item.save_partial_transport(streams={"stdout": b"original"}, transport={})
        receipt = json.loads((Path(item.directory) / "receipt.private.json").read_bytes())
        self.assertTrue(receipt["host_durability_steps_completed"])
        self.assertFalse(receipt["transport_contract_complete"])
        with self.assertRaises(journal.JournalRefused):
            item.save_partial_transport(streams={"stdout": b"retry"}, transport={})


if __name__ == "__main__":
    unittest.main()
