"""Host filesystem/fault tests. No device, transport, or cleanup execution."""
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

from macws_swap_pair import cleanup_preparation as subject


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class CleanupAttemptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cleanup-attempt-", dir="/private/tmp")
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.raw = b'fixed opaque archive bytes\x00\xff\n'
        self.payload = b'print("decode only")\n'
        self.kwargs = dict(archive_raw=self.raw, archive_sha256=sha(self.raw),
            payload=self.payload, payload_sha256=sha(self.payload),
            intent={"attempt_nonce": "a" * 32, "test_only": True})
        self.attempt = subject.CleanupAttempt(**self.kwargs)
        self.addCleanup(self.attempt.close)
        self.slot = self.parent / ("cleanup-" + sha(self.raw))
        self.capture = self.slot / "capture"

    def prepared(self, *, dispatched=False):
        report = self.attempt.prepare(str(self.parent))
        if dispatched:
            self.attempt.mark_dispatch()
        return report

    def mutate_archive(self):
        (self.slot / "archive.private.bin").write_bytes(b"changed after dispatch")

    def test_constructor_and_default_metadata_open_nothing(self):
        with mock.patch.object(subject.os, "open", side_effect=AssertionError("open")), \
             mock.patch.object(subject.os, "mkdir", side_effect=AssertionError("mkdir")), \
             mock.patch.object(subject.os, "fsync", side_effect=AssertionError("fsync")):
            subject.CleanupAttempt(**self.kwargs)
            self.assertTrue(subject.metadata()["default_inert"])
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_external_pins_types_bounds_and_intent_refuse_before_io(self):
        cases = [("archive_raw", b""), ("archive_raw", b"x" * (subject.ARCHIVE_LIMIT + 1)),
                 ("archive_raw", bytearray(self.raw)), ("archive_sha256", "0" * 64),
                 ("archive_sha256", True), ("payload", b""),
                 ("payload", b"x" * (subject.journal.PAYLOAD_LIMIT + 1)),
                 ("payload_sha256", "A" * 64), ("payload_sha256", "0" * 64),
                 ("intent", {"bad": float("nan")})]
        with mock.patch.object(subject.os, "open", side_effect=AssertionError("open")):
            for key, value in cases:
                with self.subTest(key=key, value_type=type(value).__name__):
                    with self.assertRaises((subject.AttemptRefused, subject.archive.ArchiveRefused)):
                        subject.CleanupAttempt(**dict(self.kwargs, **{key: value}))

    def test_prepare_preserves_exact_archive_payload_and_private_modes(self):
        report = self.prepared()
        self.assertEqual(set(p.name for p in self.slot.iterdir()), {"archive.private.bin", "capture"})
        self.assertEqual(set(p.name for p in self.capture.iterdir()), {"stdin.private.py", "intent.private.json"})
        self.assertEqual((self.slot / "archive.private.bin").read_bytes(), self.raw)
        self.assertEqual((self.capture / "stdin.private.py").read_bytes(), self.payload)
        for path in (self.slot, self.capture):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        for path in (self.slot / "archive.private.bin", self.capture / "stdin.private.py",
                     self.capture / "intent.private.json"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual(report["directory_private"], str(self.slot))
        self.assertTrue(report["archive_sequence_completed_in_this_invocation"])
        self.assertFalse(report["native_actions_available"])
        self.assertFalse(report["device_acceptance"])
        self.assertFalse(report["global_exclusivity_proven"])
        self.assertFalse(report["default_inert"])
        self.assertFalse((self.slot / "receipt.private.json").exists())

    def test_caller_intent_is_frozen_and_binds_both_payloads(self):
        self.kwargs["intent"]["attempt_nonce"] = "changed after construction"
        self.prepared()
        value = json.loads((self.capture / "intent.private.json").read_bytes())
        self.assertEqual(value["caller_intent_private"]["attempt_nonce"], "a" * 32)
        self.assertEqual(value["archive_sha256"], sha(self.raw))
        self.assertEqual(value["payload_sha256"], sha(self.payload))
        self.assertFalse(value["native_evidence_authenticity_verified"])

    def test_repeated_prepare_and_nonce_changes_cannot_reuse_same_archive_slot(self):
        self.prepared()
        with self.assertRaises(subject.AttemptRefused):
            self.attempt.prepare(str(self.parent))
        other_payload = self.payload + b"# different nonce\n"
        other = subject.CleanupAttempt(**dict(self.kwargs, payload=other_payload,
            payload_sha256=sha(other_payload), intent={"attempt_nonce": "b" * 32}))
        self.addCleanup(other.close)
        with self.assertRaises(FileExistsError):
            other.prepare(str(self.parent))
        self.assertEqual(set(p.name for p in self.parent.iterdir()), {self.slot.name})
        self.assertEqual((self.capture / "stdin.private.py").read_bytes(), self.payload)

    def test_parent_failure_consumes_prepare_before_first_effect(self):
        with self.assertRaises(subject.archive.ArchiveRefused):
            self.attempt.prepare("relative/path")
        with self.assertRaises(subject.AttemptRefused):
            self.attempt.prepare(str(self.parent))
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_symlink_parent_refuses_without_creating_slot(self):
        link = self.parent / "alias"
        link.symlink_to(self.parent, target_is_directory=True)
        with self.assertRaises(OSError):
            self.attempt.prepare(str(link))
        self.assertEqual(set(p.name for p in self.parent.iterdir()), {"alias"})

    def test_parent_mode_refuses(self):
        self.parent.chmod(0o777)
        try:
            with self.assertRaises(subject.archive.ArchiveRefused):
                self.attempt.prepare(str(self.parent))
        finally:
            self.parent.chmod(0o700)
        self.assertFalse(self.slot.exists())

    def test_initial_and_child_fstat_failures_close_every_opened_fd(self):
        real_open, real_fstat = os.open, os.fstat
        for failing_call in (1, 2):
            with self.subTest(failing_call=failing_call):
                opened, count = [], [0]
                attempt = subject.CleanupAttempt(**self.kwargs)
                self.addCleanup(attempt.close)
                def tracked_open(*args, **kwargs):
                    fd = real_open(*args, **kwargs)
                    opened.append(fd)
                    return fd
                def failing_fstat(fd):
                    count[0] += 1
                    if count[0] == failing_call:
                        raise OSError(errno.EIO, "injected initial fstat")
                    return real_fstat(fd)
                with mock.patch.object(subject.os, "open", side_effect=tracked_open), \
                     mock.patch.object(subject.os, "fstat", side_effect=failing_fstat):
                    with self.assertRaises(OSError):
                        attempt.prepare(str(self.parent))
                self.assertEqual(len(opened), failing_call)
                for fd in opened:
                    with self.assertRaises(OSError) as caught:
                        real_fstat(fd)
                    self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_file_or_parent_fsync_failure_retains_archive_without_dispatch(self):
        real_fsync = os.fsync
        for failing_call in (1, 3):
            with self.subTest(failing_call=failing_call):
                parent = self.parent / str(failing_call)
                parent.mkdir(mode=0o700)
                attempt = subject.CleanupAttempt(**self.kwargs)
                self.addCleanup(attempt.close)
                count = [0]
                def failing_fsync(fd):
                    count[0] += 1
                    if count[0] == failing_call:
                        raise OSError(errno.EIO, "injected fsync")
                    return real_fsync(fd)
                with mock.patch.object(subject.os, "fsync", side_effect=failing_fsync):
                    with self.assertRaises(OSError):
                        attempt.prepare(str(parent))
                slot = parent / self.slot.name
                self.assertEqual(set(p.name for p in slot.iterdir()), {"archive.private.bin"})
                self.assertEqual((slot / "archive.private.bin").read_bytes(), self.raw)
                with self.assertRaises(subject.AttemptRefused):
                    attempt.prepare(str(parent))

    def test_nested_journal_preparation_failure_retains_both_partial_layers(self):
        real_fsync, count = os.fsync, [0]
        def failing_fsync(fd):
            count[0] += 1
            if count[0] == 4:
                raise OSError(errno.EIO, "injected journal payload fsync")
            return real_fsync(fd)
        with mock.patch.object(subject.os, "fsync", side_effect=failing_fsync):
            with self.assertRaises(OSError):
                self.prepared()
        self.assertEqual((self.slot / "archive.private.bin").read_bytes(), self.raw)
        self.assertEqual((self.capture / "stdin.private.py").read_bytes(), self.payload)
        self.assertFalse((self.capture / "intent.private.json").exists())
        self.assertFalse((self.capture / "dispatch-intent.private.json").exists())

    def test_archive_changes_refuse_dispatch_and_consume_transition(self):
        self.prepared()
        self.mutate_archive()
        with self.assertRaises((subject.AttemptRefused, subject.archive.ArchiveRefused)):
            self.attempt.mark_dispatch()
        (self.slot / "archive.private.bin").write_bytes(self.raw)
        with self.assertRaises(subject.AttemptRefused):
            self.attempt.mark_dispatch()
        self.assertFalse((self.capture / "dispatch-intent.private.json").exists())

    def test_identical_bytes_replacement_refuses_dispatch(self):
        self.prepared()
        path = self.slot / "archive.private.bin"
        path.unlink()
        path.write_bytes(self.raw)
        path.chmod(0o600)
        with self.assertRaises((subject.AttemptRefused, subject.archive.ArchiveRefused)):
            self.attempt.mark_dispatch()
        self.assertFalse((self.capture / "dispatch-intent.private.json").exists())

    def test_foreign_slot_entry_refuses_dispatch_and_is_retained(self):
        self.prepared()
        foreign = self.slot / "foreign"
        foreign.write_bytes(b"belongs to another operator")
        with self.assertRaises(subject.AttemptRefused):
            self.attempt.mark_dispatch()
        self.assertEqual(foreign.read_bytes(), b"belongs to another operator")
        self.assertFalse((self.capture / "dispatch-intent.private.json").exists())

    def test_held_parent_and_root_identity_are_rechecked(self):
        self.prepared()
        real_lstat = os.lstat
        def changed_root(path, *args, **kwargs):
            value = real_lstat(path, *args, **kwargs)
            if path == "/":
                words = list(value)
                words[1] += 1
                return os.stat_result(words)
            return value
        with mock.patch.object(subject.os, "lstat", side_effect=changed_root):
            with self.assertRaises(subject.AttemptRefused):
                self.attempt.mark_dispatch()
        self.assertFalse((self.capture / "dispatch-intent.private.json").exists())

    def test_replaced_parent_path_refuses_dispatch(self):
        ledger = self.parent / "ledger"
        ledger.mkdir(mode=0o700)
        self.attempt.prepare(str(ledger))
        ledger.rename(self.parent / "original-ledger")
        ledger.mkdir(mode=0o700)
        with self.assertRaises(subject.AttemptRefused):
            self.attempt.mark_dispatch()
        original_capture = self.parent / "original-ledger" / self.slot.name / "capture"
        self.assertFalse((original_capture / "dispatch-intent.private.json").exists())
        self.assertEqual(list(ledger.iterdir()), [])

    def test_dispatch_intent_is_once_and_invokes_no_transport(self):
        self.prepared()
        report = self.attempt.mark_dispatch()
        self.assertEqual(report["phase"], "dispatch-intent-preserved")
        dispatch = json.loads((self.capture / "dispatch-intent.private.json").read_bytes())
        self.assertEqual(dispatch["payload_sha256"], sha(self.payload))
        self.assertFalse(dispatch["transport_invocation_confirmed"])
        with self.assertRaises(subject.AttemptRefused):
            self.attempt.mark_dispatch()
        self.assertFalse((self.capture / "stdout.original.private.bin").exists())

    def test_transport_bytes_are_preserved_before_assessment(self):
        self.prepared(dispatched=True)
        out, err = b"\x00not parsed JSON\xff", b"\xfeoriginal error\n"
        report = self.attempt.save_transport(stdout=out, stderr=err, transport={"local_test": True})
        self.assertEqual(report["phase"], "transport-preserved")
        self.assertEqual((self.capture / "stdout.original.private.bin").read_bytes(), out)
        self.assertEqual((self.capture / "stderr.original.private.bin").read_bytes(), err)
        self.assertFalse((self.capture / "assessment.private.json").exists())
        self.attempt.save_assessment({"offline_only": True, "device_acceptance": False})
        self.assertTrue((self.capture / "assessment.private.json").exists())

    def test_dispatch_fsync_failure_retains_intent_and_consumes_phase(self):
        self.prepared()
        with mock.patch.object(subject.os, "fsync", side_effect=OSError(errno.EIO, "fixture fsync failure")):
            with self.assertRaises(OSError):
                self.attempt.mark_dispatch()
        intent = self.capture / "dispatch-intent.private.json"
        self.assertEqual(json.loads(intent.read_bytes())["payload_sha256"], sha(self.payload))
        with self.assertRaises(subject.AttemptRefused):
            self.attempt.mark_dispatch()
        self.assertFalse((self.capture / "stdout.original.private.bin").exists())

    def test_changed_archive_does_not_discard_received_raw_streams(self):
        self.prepared(dispatched=True)
        self.mutate_archive()
        with self.assertRaises((subject.AttemptRefused, subject.archive.ArchiveRefused)):
            self.attempt.save_transport(stdout=b"received stdout", stderr=b"received stderr",
                                        transport={"local_test": True})
        self.assertEqual((self.capture / "stdout.original.private.bin").read_bytes(), b"received stdout")
        self.assertEqual((self.capture / "stderr.original.private.bin").read_bytes(), b"received stderr")
        with self.assertRaises(subject.AttemptRefused):
            self.attempt.save_assessment({"must_not_run": True})
        self.assertFalse((self.capture / "assessment.private.json").exists())

    def test_changed_archive_preserves_only_known_partial_streams(self):
        self.prepared(dispatched=True)
        self.mutate_archive()
        with self.assertRaises((subject.AttemptRefused, subject.archive.ArchiveRefused)):
            self.attempt.save_partial_transport(streams={"stdout": b""},
                transport={"contract_complete": False})
        self.assertEqual((self.capture / "stdout.original.private.bin").read_bytes(), b"")
        self.assertFalse((self.capture / "stderr.original.private.bin").exists())
        self.assertFalse((self.capture / "assessment.private.json").exists())

    def test_invalid_transport_metadata_still_retains_original_streams(self):
        self.prepared(dispatched=True)
        with self.assertRaises(subject.archive.ArchiveRefused):
            self.attempt.save_transport(stdout=b"original", stderr=b"error",
                transport={"invalid": object()})
        self.assertEqual((self.capture / "stdout.original.private.bin").read_bytes(), b"original")
        self.assertEqual((self.capture / "stderr.original.private.bin").read_bytes(), b"error")

    def test_assessment_checks_archive_before_writing_any_assessment(self):
        self.prepared(dispatched=True)
        self.attempt.save_transport(stdout=b"raw", stderr=b"", transport={"local_test": True})
        self.mutate_archive()
        with self.assertRaises((subject.AttemptRefused, subject.archive.ArchiveRefused)):
            self.attempt.save_assessment({"must_not_be_saved": True})
        self.assertFalse((self.capture / "assessment.private.json").exists())

    def test_close_retains_files_and_prevents_all_later_transitions(self):
        self.prepared(dispatched=True)
        self.attempt.close()
        self.attempt.close()
        self.assertEqual((self.slot / "archive.private.bin").read_bytes(), self.raw)
        self.assertTrue((self.capture / "dispatch-intent.private.json").exists())
        with self.assertRaises(subject.AttemptRefused):
            self.attempt.mark_dispatch()
        with self.assertRaises(subject.AttemptRefused):
            self.attempt.prepare(str(self.parent))


if __name__ == "__main__":
    unittest.main()
