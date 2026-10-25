"""Invented host fixtures only; actual pinned OwnedFiles in temporary paths.

No native, transport, signal or launchd call. Only tests create/remove their
own temporary files; the primitive's explicit paths are patched together with
the runtime's two fixed scratch constants for this synthetic scope only.
"""
import builtins
from contextlib import ExitStack, redirect_stdout
import copy
import ctypes
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from macws_swap_pair import ownership_capture as c

DIRECTORY = Path(__file__).resolve().parent
RUNTIME_DIRECTORY = DIRECTORY / "macws_swap_pair"


def load_runtime(directory=RUNTIME_DIRECTORY):
    spec = importlib.util.spec_from_file_location("synthetic_original_owned_files_support", directory / "runtime_support.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def config(runtime):
    return {
        "schema": "macws.swap-pair.live-config.v7", "operation": "control_normal", "arch": "arm64",
        "run_nonce": "a" * 32, "profile_sha256": runtime.PROBE_PROFILE_SHA256,
        "loaded_hook_profile_sha256": runtime.PROBE_PROFILE_SHA256,
        "signed_probe_sha256": "3" * 64, "signed_probe_uuid": runtime.PROBE_BUILDS["arm64"][1],
        "signed_probe_cdhash": "4" * 40, "installed_probe_token": [1, 2, 50000, 1000, 1000],
        "boot_private": "11111111-2222-3333-4444-555555555555",
        "UI_private": {"SpringBoard": [101, 1000, 1], "backboardd": [102, 1000, 2]},
        "source_sha256": dict(c.SOURCES), "active_seconds": 10, "cleanup_seconds": 8,
        "offline_QA_sha256": "ebee0b881b5f589c4ca100c5dbcd4c72faa946b0bf741511a7396138139ae29c",
        "candidate_limits": dict(runtime.PROBE_LIMITS),
        "clock_info": {"domain": "mach_absolute_time.absolute_seconds.v1", "numer": 125, "denom": 3},
    }


def forbidden(*args, **kwargs):
    raise AssertionError("native/network/job/signal/mutation forbidden")


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-owned-files-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = load_runtime()
        patches = ExitStack()
        self.addCleanup(patches.close)
        run, control = str(self.root / "run"), str(self.root / "control")
        patches.enter_context(patch.object(self.runtime, "SCRATCH", run))
        patches.enter_context(patch.object(self.runtime, "CONTROL_SCRATCH", control))
        patches.enter_context(patch.dict(c.SCRATCH_BY_OPERATION,
                                        {name: run if name == "run" else control for name in c.SCRATCH_BY_OPERATION}))
        self.config = config(self.runtime)
        self.files = self.runtime.OwnedFiles.create(self.config)
        self.addCleanup(os.close, self.files.fd)

    def guards(self):
        stack = ExitStack()
        for owner, name in (
            (ctypes, "CDLL"), (subprocess, "run"), (subprocess, "Popen"),
            (socket, "socket"), (socket, "create_connection"), (os, "kill"),
            (signal, "signal"), (signal, "alarm"), (signal, "setitimer"),
            (os, "mkdir"), (os, "unlink"), (os, "remove"), (os, "rmdir"),
            (os, "rename"), (os, "replace"), (os, "write"),
            (Path, "write_bytes"), (Path, "write_text"),
        ):
            stack.enter_context(patch.object(owner, name, forbidden))
        original_open = os.open
        def readonly_open(path, flags, *args, **kwargs):
            self.assertEqual(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_EXCL |
                                      os.O_TRUNC | os.O_APPEND), 0)
            return original_open(path, flags, *args, **kwargs)
        stack.enter_context(patch.object(os, "open", readonly_open))
        original_builtin_open = builtins.open
        def readonly_builtin_open(file, mode="r", *args, **kwargs):
            self.assertFalse(any(letter in mode for letter in "wax+"))
            return original_builtin_open(file, mode, *args, **kwargs)
        stack.enter_context(patch.object(builtins, "open", readonly_builtin_open))
        return stack

    def capture(self, **changes):
        arguments = {"runtime": self.runtime, "config": self.config, "current_sources": dict(c.SOURCES)}
        arguments.update(changes)
        with self.guards():
            return c.capture_owned_files(self.files, **arguments)

    def validate(self, value, **changes):
        arguments = {"runtime": self.runtime, "config": self.config, "current_sources": dict(c.SOURCES)}
        arguments.update(changes)
        with self.guards():
            return c.validate_witness(value, **arguments)

    def rehash(self, value):
        value["witness_sha256"] = hashlib.sha256(c.canonical(value["witness"])).hexdigest()
        return value

    def test_actual_owned_files_snapshot_matches_original_tokens_and_null_log_hash(self):
        before = copy.deepcopy((self.files.directory_token, self.files.files, self.config))
        result = self.capture()
        witness = result["witness"]
        self.assertEqual(witness["directory_token_private"], before[0])
        self.assertEqual(witness["files_private"], before[1])
        self.assertEqual(witness["config_sha256"], self.runtime.config_sha(self.config))
        self.assertEqual(witness["admission_sha256"], self.runtime.admission_sha(self.config))
        self.assertIsNone(witness["files_private"]["probe.log"]["sha256"])
        self.assertTrue(all(witness[key] is False for key in c.FALSE_FLAGS))
        self.assertEqual(before, (self.files.directory_token, self.files.files, self.config))

    def test_capture_is_deep_copy_in_both_directions(self):
        result = self.capture()
        original = copy.deepcopy(result)
        self.files.files["probe.log"]["identity"][1] += 1
        self.files.directory_token[1] += 1
        self.config["source_sha256"]["controller.py"] = "0" * 64
        self.assertEqual(result, original)
        result["witness"]["files_private"]["job.plist"]["identity"][1] += 1
        self.assertNotEqual(result["witness"]["files_private"], self.files.files)

    def test_validation_returns_independent_copy(self):
        captured = self.capture()
        validated = self.validate(captured)
        validated["witness"]["source_sha256"]["watchdog.py"] = "0" * 64
        self.assertEqual(captured["witness"]["source_sha256"], c.SOURCES)

    def test_replacement_directory_refuses_and_does_not_adopt_fresh_tokens(self):
        original = copy.deepcopy(self.files.directory_token)
        Path(self.files.path).rename(self.root / "retained-original")
        Path(self.files.path).mkdir()
        with self.assertRaises(self.runtime.Refused):
            self.capture()
        self.assertEqual(self.files.directory_token, original)

    def test_directory_symlink_refuses(self):
        Path(self.files.path).rename(self.root / "retained-original")
        Path(self.files.path).symlink_to(self.root / "retained-original", target_is_directory=True)
        with self.assertRaises(self.runtime.Refused):
            self.capture()

    def test_replacement_file_refuses_without_refresh(self):
        for name in ("job.plist", "probe.log"):
            with self.subTest(name=name):
                path = Path(self.files.path) / name
                original = copy.deepcopy(self.files.files[name])
                parked = self.root / ("original-" + name)
                path.rename(parked)
                path.write_bytes(parked.read_bytes())
                with self.assertRaises(self.runtime.Refused):
                    self.capture()
                self.assertEqual(self.files.files[name], original)
                path.unlink()
                parked.rename(path)

    def test_file_symlink_refuses(self):
        path = Path(self.files.path) / "probe.log"
        path.rename(self.root / "original-log")
        path.symlink_to(self.root / "original-log")
        with self.assertRaises(self.runtime.Refused):
            self.capture()

    def test_extra_entry_refuses(self):
        (Path(self.files.path) / "unexpected").write_bytes(b"synthetic")
        with self.assertRaises(self.runtime.Refused):
            self.capture()

    def test_changed_immutable_plist_refuses_even_on_original_inode(self):
        (Path(self.files.path) / "job.plist").write_bytes(b"synthetic changed plist")
        with self.assertRaises(self.runtime.Refused):
            self.capture()

    def test_mutable_log_bounded_and_hash_stays_null(self):
        log = Path(self.files.path) / "probe.log"
        log.write_bytes(b"invented log\n")
        self.assertIsNone(self.capture()["witness"]["files_private"]["probe.log"]["sha256"])
        log.write_bytes(b"x" * (256 * 1024 + 1))
        with self.assertRaises(self.runtime.Refused):
            self.capture()

    def test_changed_config_session_operation_boot_and_source_refuse_old_witness(self):
        captured = self.capture()
        changes = {
            "run_nonce": "b" * 32,
            "boot_private": "22222222-3333-4444-5555-666666666666",
            "operation": "control_deadline",
            "active_seconds": 9,
        }
        for key, value in changes.items():
            changed = copy.deepcopy(self.config); changed[key] = value
            with self.subTest(key=key), self.assertRaises(c.Refused):
                self.validate(captured, config=changed)
        changed = copy.deepcopy(self.config)
        changed["source_sha256"]["controller.py"] = "0" * 64
        with self.assertRaises(c.Refused):
            self.capture(config=changed)
        changed = dict(c.SOURCES); changed["controller.py"] = "0" * 64
        with self.assertRaises(c.Refused):
            self.capture(current_sources=changed)

    def test_real_v7_config_rejections_remain_rejections(self):
        for key, value in (("operation", "unknown"), ("active_seconds", 11),
                           ("cleanup_seconds", 9), ("schema", "future"),
                           ("arch", "other"), ("run_nonce", "n" * 32)):
            changed = copy.deepcopy(self.config); changed[key] = value
            with self.subTest(key=key), self.assertRaises(self.runtime.Refused):
                self.runtime.config_checked(changed)
            with self.subTest(key=key), self.assertRaises(self.runtime.Refused):
                self.capture(config=changed)

    def test_source_byte_mutation_refuses_before_owned_check(self):
        directory = self.root / "source-copy"; directory.mkdir()
        for name in c.SOURCES:
            (directory / name).write_bytes((RUNTIME_DIRECTORY / name).read_bytes())
        (directory / "controller.py").write_bytes(b"not executed")
        with patch.object(self.runtime, "__file__", str(directory / "runtime_support.py")), \
             patch.object(self.runtime.OwnedFiles, "checked", forbidden):
            with self.assertRaisesRegex(c.Refused, "pinned source bytes"):
                self.capture()

    def test_source_symlink_refuses_before_runtime_config_or_owned_check(self):
        directory = self.root / "source-symlink"; directory.mkdir()
        for name in c.SOURCES:
            (directory / name).symlink_to(RUNTIME_DIRECTORY / name)
        with patch.object(self.runtime, "__file__", str(directory / "runtime_support.py")), \
             patch.object(self.runtime, "config_checked", forbidden), \
             patch.object(self.runtime.OwnedFiles, "checked", forbidden):
            with self.assertRaises(OSError):
                self.capture()

    def test_missing_directory_or_file_refuses(self):
        path = Path(self.files.path)
        for name in ("job.plist", "probe.log"):
            original = path / name; parked = self.root / name
            original.rename(parked)
            with self.assertRaises(self.runtime.Refused):
                self.capture()
            parked.rename(original)
        path.rename(self.root / "parked-directory")
        with self.assertRaises(FileNotFoundError):
            self.capture()

    def test_stored_token_changes_during_checked_refuse_without_action(self):
        original_checked = self.runtime.OwnedFiles.checked
        def changing_checked(files):
            result = original_checked(files)
            files.directory_token[1] += 1
            return result
        with patch.object(self.runtime.OwnedFiles, "checked", changing_checked):
            with self.assertRaisesRegex(c.Refused, "changed during check"):
                self.capture()

    def test_equal_float_token_substitution_during_checked_refuses(self):
        original_checked = self.runtime.OwnedFiles.checked
        for target in ("directory", "job.plist", "probe.log"):
            directory = copy.deepcopy(self.files.directory_token)
            files = copy.deepcopy(self.files.files)
            def changing_checked(owned):
                result = original_checked(owned)
                token = owned.directory_token if target == "directory" else owned.files[target]["identity"]
                token[0] = float(token[0])
                return result
            with self.subTest(target=target), patch.object(self.runtime.OwnedFiles, "checked", changing_checked):
                with self.assertRaisesRegex(c.Refused, "changed during check"):
                    self.capture()
            self.files.directory_token = directory
            self.files.files = files

    def test_arbitrary_or_subclass_object_is_not_original_owned_files(self):
        class Subclass(self.runtime.OwnedFiles):
            pass
        substitute = Subclass(self.files.fd, self.files.directory_token, self.files.files, self.files.path)
        for value in (object(), substitute):
            with self.subTest(value=type(value)), self.guards(), self.assertRaises(c.Refused):
                c.capture_owned_files(value, runtime=self.runtime, config=self.config, current_sources=c.SOURCES)

    def test_source_fifo_refuses_without_a_writer(self):
        fifo = self.root / "source-fifo"
        os.mkfifo(fifo)
        original_open = os.open
        def nonblocking_open(path, flags, *args, **kwargs):
            # Assert before opening: a regression cannot hang this test.
            self.assertTrue(flags & os.O_NONBLOCK)
            return original_open(path, flags, *args, **kwargs)
        with patch.object(os, "open", nonblocking_open), self.assertRaises(c.Refused):
            c._source_bytes(fifo)

    def test_source_symlink_refuses(self):
        source = RUNTIME_DIRECTORY / "runtime_support.py"
        link = self.root / "source-link"
        link.symlink_to(source)
        with self.assertRaises(OSError):
            c._source_bytes(link)

    def test_source_short_reads_are_collected_completely(self):
        original_read = os.read
        path = RUNTIME_DIRECTORY / "runtime_support.py"
        expected = path.read_bytes()
        with patch.object(os, "read", lambda fd, length: original_read(fd, min(length, 7))):
            self.assertEqual(c._source_bytes(path), expected)

    def test_source_premature_eof_refuses(self):
        with patch.object(os, "read", return_value=b""), self.assertRaises(c.Refused):
            self.capture()

    def test_source_stat_change_during_read_refuses(self):
        path = self.root / "changing-source"
        path.write_bytes(b"original bounded source")
        original_read = os.read
        changed = False
        def changing_read(fd, length):
            nonlocal changed
            raw = original_read(fd, length)
            if not changed:
                changed = True
                path.write_bytes(b"changed length")
            return raw
        with patch.object(os, "read", changing_read), self.assertRaises(c.Refused):
            c._source_bytes(path)

    def test_rehashed_authority_schema_and_malformed_fields_refuse(self):
        captured = self.capture()
        mutations = [lambda w: w.update(extra=True), lambda w: w.update(operation="run"),
                     lambda w: w.update(schema="other"),
                     lambda w: w["directory_token_private"].__setitem__(1, True),
                     lambda w: w["directory_token_private"].__setitem__(1, 1 << 64),
                     lambda w: w["files_private"]["probe.log"].update(sha256="0" * 64),
                     lambda w: w["files_private"]["job.plist"].update(sha256="0" * 64),
                     lambda w: w["files_private"]["probe.log"].update(extra=True),
                     lambda w: w["files_private"]["probe.log"]["identity"].__setitem__(1, 0),
                     lambda w: w["files_private"]["probe.log"].update(identity=w["directory_token_private"]),
                     lambda w: w["files_private"]["probe.log"].update(identity=w["files_private"]["job.plist"]["identity"])]
        mutations += [(lambda w, key=key: w.update({key: True})) for key in c.FALSE_FLAGS]
        for index, mutate in enumerate(mutations):
            changed = copy.deepcopy(captured); mutate(changed["witness"])
            with self.subTest(index=index), self.assertRaises(c.Refused):
                self.validate(self.rehash(changed))

    def test_digest_and_complete_byte_bounds_refuse(self):
        captured = self.capture()
        captured["witness_sha256"] = "0" * 64
        with self.assertRaises(c.Refused):
            self.validate(captured)
        for value in ({"x": "x" * 4097}, {"x": [None] * 65}, {"x": float("nan")},
                      {"x": float("inf")}, {"x": -1}):
            with self.subTest(value=type(value["x"])), self.assertRaises(c.Refused):
                c.canonical(value)
        nested = None
        for _ in range(12): nested = [nested]
        with self.assertRaises(c.Refused): c.canonical(nested)

    def test_decoder_refuses_duplicate_keys_nonfinite_malformed_and_oversize(self):
        raw = c.canonical(self.capture())
        arguments = {"runtime": self.runtime, "config": self.config, "current_sources": c.SOURCES}
        with self.guards():
            self.assertEqual(c.decode_witness(raw, **arguments), self.capture())
            for bad in (raw.replace(b'"witness":', b'"witness":null,"witness":', 1),
                        raw.replace(b'"operation":', b'"operation":null,"operation":', 1),
                        b'{"witness":NaN}', b"[", b"\xff", b" " * (c.LIMIT + 1)):
                with self.subTest(length=len(bad)), self.assertRaises(c.Refused):
                    c.decode_witness(bad, **arguments)

    def test_default_import_and_cli_only_metadata_have_no_capabilities(self):
        source = (RUNTIME_DIRECTORY / "ownership_capture.py").read_bytes()
        code = compile(source, "<offline-default>", "exec")
        for name in ("synthetic_import", "__main__"):
            output = io.StringIO()
            with self.guards(), patch.object(os, "open", forbidden), redirect_stdout(output):
                namespace = {"__name__": name}
                exec(code, namespace)
            if name == "__main__":
                self.assertEqual(json.loads(output.getvalue()), c.metadata())
            else:
                self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
