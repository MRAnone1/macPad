"""Synthetic inputs and explicitly mapped temporary filesystem only.

No device/native API/transport. All apparent owner/stat/observation facts are
invented for tests. Filesystem tests replace only content digests with toy
payload digests while preserving the production five paths/two directories.
"""
import contextlib
import builtins
import copy
import ctypes
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from macws_swap_pair import cleanup_payload as c

HERE = Path(__file__).resolve().parent
PLAN_RAW = (HERE / "macws_swap_pair" / "reviewed_delivery_plan.json").read_bytes()
PLAN = json.loads(PLAN_RAW)
OBSERVER_RAW = (HERE / "macws_swap_pair" / "readonly_observer.py").read_bytes()
INPUTS_RAW = (HERE / "macws_swap_pair" / "observer_inputs.json").read_bytes()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def forbidden(*args, **kwargs):
    raise AssertionError("native/transport/default filesystem effects forbidden")


def delivery_for(plan, stats=None):
    """Invented in-memory receipt; not a fresh-looking device file."""
    stats = {} if stats is None else stats
    rows, dirs = [], []
    for index, row in enumerate(plan["payload_files"]):
        value = stats.get(row["path"], {"dev": 1, "ino": 100 + index, "size": 100, "mtime_ns": 123,
                                      "ctime_ns": 456, "mode": int(row["mode"], 8), "uid": 0, "gid": 0, "nlink": 1})
        rows.append({"name": row["name"], "path": row["path"], "sha256": row["sha256"], "stat": value,
                     "previously_absent": True, "new_vnode_created_exclusively": True})
    for index, path in enumerate(c.DIRECTORIES):
        value = stats.get(path, {"dev": 1, "ino": 200 + index, "size": 100, "mtime_ns": 123,
                                "ctime_ns": 456, "mode": 0o700, "uid": 0, "gid": 0, "nlink": 2})
        dirs.append({"path": path, "stat": value})
    return {"schema": "macws.diagnostic-probe.delivery.private.v1", "receiver_sha256": c.RECEIVER_SHA,
            "bundle_manifest_sha256": c.MANIFEST_SHA, "installation_verified": True,
            "installed_files_private": rows, "created_directories_private": dirs,
            "parents_private": [{"logical": path.rsplit("/", 1)[0], "target_previously_absent": True} for path in c.DIRECTORIES],
            "probe_signature": plan["probe_signature_host_verified"], "candidate_executions": 0,
            "controller_executions": 0, "trust_mutations": 0, "automatic_cleanup_attempted": False,
            "native_dependency_closure_currently_verified": False, "current_trust_verified": False,
            "device_acceptance": False, "runtime_accepted": False, "freeze_cause_or_fix_proven": False}


def baseline_for(delivery):
    candidate = next(row for row in delivery["installed_files_private"] if row["path"].endswith("/probe.arm64"))
    return {"schema": "macws.swap-pair.read-only-admission-observations.v4", "observer_source_sha256": c.OBSERVER_SHA,
            "inputs_sha256": c.INPUT_SHA, "launchd_domain": "user/501", "observation_completed": True,
            "observed_baseline_checks_passed": True, "refusals": [], "finalization_refusals": [],
            "checks": {name: True for name in c.CHECKS}, "fully_admitted": False, "runtime_accepted": False,
            "device_acceptance": False, "runtime_controls_verified": False, "freshness_verified": False,
            "new_vnode": None, "mutations": 0, "candidate_executions": 0, "launchd_mutations": 0, "trust_mutations": 0,
            "files_after_private": {"candidate": {"path": candidate["path"], "sha256": candidate["sha256"],
                "stat_token_private": [candidate["stat"][key] for key in c.STAT_KEYS[:5]],
                "present": True, "identity_verified": True, "trust_member": True}}}


class MappedFS:
    """Real temporary file bytes/inodes, explicitly synthetic root-owner view."""
    def __init__(self, root):
        self.parents = {path.rsplit("/", 1)[0]: root / ("parent-" + str(index)) for index, path in enumerate(c.DIRECTORIES)}
        self.paths, self.fds, self.opens = {}, {}, {}
        self.original_stats = {}
        self.deleted = []
        self.mutate_second = False
        self.forge_original_stat = False
        self.same_inode_after_mutation = False
        self.fail_unlink_number = None
        self.fail_rmdir_number = None
        self.removed_dirs = 0
        self.close_failure_once = False
        for parent in self.parents.values():
            parent.mkdir()
        for directory in c.DIRECTORIES:
            target = self.parents[directory.rsplit("/", 1)[0]] / directory.rsplit("/", 1)[1]
            target.mkdir(mode=0o700)
            self.paths[directory] = target
        self.toy_files = {}
        for path, (mode, _) in c.FILES.items():
            data = ("synthetic toy payload:" + path.rsplit("/", 1)[1]).encode()
            target = self.paths[path.rsplit("/", 1)[0]] / path.rsplit("/", 1)[1]
            target.write_bytes(data); target.chmod(mode)
            self.paths[path] = target
            self.toy_files[path] = (mode, hashlib.sha256(data).hexdigest())
        self.original_stats = {key: self.view(value.stat(), key) for key, value in self.paths.items()}

    def view(self, value, logical):
        if self.forge_original_stat and logical.endswith("/probe.arm64") and self.opens.get(logical, 0) > 1:
            return self.original_stats[logical]
        return SimpleNamespace(**{name: getattr(value, name) for name in
            ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink")}, st_uid=0, st_gid=0)

    def open(self, path, flags, *, dir_fd=None):
        if dir_fd is None:
            if path not in self.parents:
                raise AssertionError("unexpected absolute open outside fixed parents")
            actual, logical = self.parents[path], path
        else:
            logical = self.fds[dir_fd] + "/" + path
            actual = self.paths[logical]
        self.opens[logical] = self.opens.get(logical, 0) + 1
        if self.mutate_second and logical.endswith("/probe.arm64") and self.opens[logical] == 2:
            before = actual.stat()
            with actual.open("r+b") as stream:
                stream.write(b"X" * before.st_size)
            self.same_inode_after_mutation = actual.stat().st_ino == before.st_ino
        fd = os.open(actual, flags)
        self.fds[fd] = logical
        return fd

    def close(self, fd):
        os.close(fd); self.fds.pop(fd, None)
        if self.close_failure_once:
            self.close_failure_once = False
            raise OSError(5, "synthetic close after actual local descriptor closure")

    def fstat(self, fd):
        return self.view(os.fstat(fd), self.fds[fd])

    def stat(self, name, *, dir_fd=None, follow_symlinks):
        logical = name if dir_fd is None else self.fds[dir_fd] + "/" + name
        return self.view(os.stat(self.paths[logical], follow_symlinks=follow_symlinks), logical)

    read = staticmethod(os.read)
    listdir = staticmethod(os.listdir)

    def unlink(self, name, *, dir_fd):
        if self.fail_unlink_number == len(self.deleted) + 1:
            raise OSError(5, "synthetic second unlink failure")
        logical = self.fds[dir_fd] + "/" + name
        os.unlink(name, dir_fd=dir_fd); self.deleted.append(logical)

    def rmdir(self, name, *, dir_fd):
        if self.fail_rmdir_number == self.removed_dirs + 1:
            raise OSError(5, "synthetic scoped rmdir failure")
        os.rmdir(name, dir_fd=dir_fd)
        self.removed_dirs += 1

    def lexists(self, path):
        return os.path.lexists(self.paths[path])


class ConstructionTests(unittest.TestCase):
    def test_default_metadata_has_no_source_or_filesystem_native_transport_effects(self):
        with patch.object(c, "validate_plan", forbidden), patch.object(c.os, "open", forbidden), \
                patch.object(ctypes, "CDLL", forbidden), patch.object(subprocess, "Popen", forbidden), \
                patch.object(c.signal, "alarm", forbidden), patch.object(c.signal, "signal", forbidden), \
                contextlib.redirect_stdout(io.StringIO()) as captured:
            self.assertEqual(c.main([]), 0)
        value = json.loads(captured.getvalue())
        self.assertFalse(value["cleanup_requested"]); self.assertFalse(value["transport_provided"])
        self.assertFalse(value["device_acceptance"]); self.assertFalse(value["current_freshness_verified"])

    def test_real_static_own_plan_digest_and_fixed_paths_validate(self):
        self.assertEqual(c.sha(PLAN_RAW), c.PLAN_SHA)
        self.assertEqual(c.validate_plan(PLAN_RAW), PLAN)
        self.assertEqual(len(c.FILES), 5); self.assertEqual(len(c.DIRECTORIES), 2)

    def test_changed_plan_receiver_or_manifest_refused(self):
        with self.assertRaises(ValueError): c.validate_plan(PLAN_RAW + b" ")
        for field in ("receiver_sha256", "bundle_manifest_sha256", "schema"):
            value = delivery_for(PLAN); value[field] = "foreign"
            with self.subTest(field=field), self.assertRaises(ValueError): c.validate_delivery(value, PLAN)

    def test_foreign_file_directory_or_duplicate_vnode_set_refused(self):
        for kind in ("foreign-file", "extra-file", "foreign-dir", "extra-dir", "duplicate-vnode"):
            value = delivery_for(PLAN)
            if kind == "foreign-file": value["installed_files_private"][0]["path"] = "/foreign/file"
            elif kind == "extra-file": value["installed_files_private"].append(copy.deepcopy(value["installed_files_private"][0]))
            elif kind == "foreign-dir": value["created_directories_private"][0]["path"] = "/foreign/directory"
            elif kind == "extra-dir": value["created_directories_private"].append(copy.deepcopy(value["created_directories_private"][0]))
            else: value["installed_files_private"][1]["stat"]["ino"] = value["installed_files_private"][0]["stat"]["ino"]
            with self.subTest(kind=kind), self.assertRaises(ValueError): c.validate_delivery(value, PLAN)

    def test_changed_mode_owner_nlink_or_bool_token_refused(self):
        for field, bad in (("uid", 501), ("gid", 501), ("mode", 0o777), ("nlink", 2), ("ino", True), ("size", c.MAX_FILE_BYTES + 1)):
            value = delivery_for(PLAN); value["installed_files_private"][0]["stat"][field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError): c.validate_delivery(value, PLAN)

    def test_old_nonexclusive_or_incomplete_delivery_refused(self):
        for field in ("new_vnode_created_exclusively", "previously_absent"):
            value = delivery_for(PLAN); value["installed_files_private"][0][field] = False
            with self.subTest(field=field), self.assertRaises(ValueError): c.validate_delivery(value, PLAN)
        value = delivery_for(PLAN); value["installation_verified"] = False
        with self.assertRaises(ValueError): c.validate_delivery(value, PLAN)

    def test_duplicate_nonfinite_nonobject_json_refused(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'[]', b''):
            with self.subTest(raw=raw), self.assertRaises(ValueError): c.strict_object(raw, 1000)

    def test_source_and_input_drift_refuse_before_plan_read_or_native_effect(self):
        with patch.object(c, "validate_plan", forbidden), patch.object(ctypes, "CDLL", forbidden), patch.object(subprocess, "Popen", forbidden):
            with self.assertRaises(ValueError):
                c.build_cleanup_payload(observer_source=b"changed", observer_inputs=b"changed", plan_raw=PLAN_RAW, delivery_raw=encoded(delivery_for(PLAN)))

    def test_exact_source_inputs_delivery_builds_deterministic_bounded_payload_without_execution(self):
        delivery_raw = encoded(delivery_for(PLAN)); before = (OBSERVER_RAW, INPUTS_RAW, PLAN_RAW, delivery_raw)
        with patch.object(ctypes, "CDLL", forbidden), patch.object(subprocess, "Popen", forbidden), \
                patch.object(c.os, "unlink", forbidden), patch.object(c.os, "rmdir", forbidden), patch.object(c.signal, "alarm", forbidden):
            first, info = c.build_cleanup_payload(observer_source=OBSERVER_RAW, observer_inputs=INPUTS_RAW, plan_raw=PLAN_RAW, delivery_raw=delivery_raw)
            second, _ = c.build_cleanup_payload(observer_source=OBSERVER_RAW, observer_inputs=INPUTS_RAW, plan_raw=PLAN_RAW, delivery_raw=delivery_raw)
        self.assertEqual(first, second); compile(first, "<compile-only-cleanup-test>", "exec")
        self.assertLessEqual(len(first), 256 * 1024); self.assertEqual(info["raw_delivery_sha256"], c.sha(delivery_raw))
        self.assertTrue(info["requires_live_readonly_baseline"]); self.assertFalse(info["current_freshness_verified"])
        self.assertEqual(before, (OBSERVER_RAW, INPUTS_RAW, PLAN_RAW, delivery_raw))
        self.assertIn(b"namespace[\"execute\"]", first); self.assertIn(b"signal.alarm(ALARM_SECONDS)", first)

    def test_good_source_changed_inputs_and_foreign_delivery_refuse_without_execution(self):
        with self.assertRaises(ValueError):
            c.build_cleanup_payload(observer_source=OBSERVER_RAW, observer_inputs=INPUTS_RAW+b" ", plan_raw=PLAN_RAW, delivery_raw=encoded(delivery_for(PLAN)))
        delivery = delivery_for(PLAN); delivery["installed_files_private"][0]["path"] = "/foreign/preserve"
        with self.assertRaises(ValueError):
            c.build_cleanup_payload(observer_source=OBSERVER_RAW, observer_inputs=INPUTS_RAW, plan_raw=PLAN_RAW, delivery_raw=encoded(delivery))

    def test_compiled_payload_preserves_negative_fake_observation_before_any_file_open(self):
        delivery = delivery_for(PLAN)
        source, _ = c.build_cleanup_payload(observer_source=OBSERVER_RAW, observer_inputs=INPUTS_RAW, plan_raw=PLAN_RAW, delivery_raw=encoded(delivery))
        baseline = baseline_for(delivery); baseline["observation_completed"] = False; baseline["observed_baseline_checks_passed"] = False
        observed_sources, alarms = [], []
        def fake_observer_exec(code, namespace):
            self.assertEqual(code.co_filename, "<hash-bound-cleanup-observer-v4>")
            observed_sources.append(True)
            namespace["execute"] = lambda *args: copy.deepcopy(baseline)
        with patch.object(c.os, "open", forbidden), patch.object(c.os, "unlink", forbidden), patch.object(c.os, "rmdir", forbidden), \
                patch.object(ctypes, "CDLL", forbidden), patch.object(subprocess, "Popen", forbidden), \
                patch.object(c.signal, "signal", lambda *args: 0), patch.object(c.signal, "alarm", lambda value: alarms.append(value)), \
                contextlib.redirect_stdout(io.StringIO()) as captured:
            builtins.exec(compile(source, "<synthetic-compiled-cleanup>", "exec"), {"exec": fake_observer_exec})
        result = json.loads(captured.getvalue())
        self.assertEqual(observed_sources, [True]); self.assertEqual(alarms, [12, 0])
        self.assertFalse(result["cleanup_verified"]); self.assertEqual(result["removed_files_private"], [])
        self.assertEqual(result["copied_readonly_before_private"], baseline)
        self.assertEqual(result["raw_delivery_sha256"], c.sha(encoded(delivery)))


class FilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.fs = MappedFS(Path(self.temp.name))
        self.patch = patch.object(c, "FILES", self.fs.toy_files); self.patch.start(); self.addCleanup(self.patch.stop)
        self.plan = copy.deepcopy(PLAN)
        for row in self.plan["payload_files"]:
            row["sha256"] = self.fs.toy_files[row["path"]][1]
        stats = {path: c.stat_values(self.fs.view(target.stat(), path)) for path, target in self.fs.paths.items()}
        self.delivery = delivery_for(self.plan, stats); self.baseline = baseline_for(self.delivery)

    def clean(self, **kwargs):
        return c.cleanup_scoped(self.delivery, self.plan, self.baseline, fs=self.fs, **kwargs)

    def test_complete_cleanup_removes_only_five_files_two_dirs(self):
        result = self.clean()
        self.assertTrue(result["cleanup_verified"]); self.assertTrue(result["simulation_only"])
        self.assertEqual(set(result["removed_files_private"]), set(c.FILES))
        self.assertEqual(set(result["removed_directories_private"]), set(c.DIRECTORIES))
        self.assertEqual(result["trust_mutations"], 0); self.assertEqual(result["job_mutations"], 0)
        self.assertFalse(result["device_acceptance"]); self.assertFalse(result["atomic_namespace_ownership_claimed"])

    def test_last_directory_foreign_child_refuses_before_any_deletion(self):
        foreign = self.fs.paths[c.CONTROL_DIR] / "foreign.keep"
        foreign.write_bytes(b"preserve foreign")
        result = self.clean()
        self.assertFalse(result["cleanup_verified"]); self.assertEqual(self.fs.deleted, [])
        self.assertEqual(foreign.read_bytes(), b"preserve foreign")

    def test_last_file_changed_before_prevalidation_refuses_all_deletion(self):
        last = list(c.FILES)[-1]; self.fs.paths[last].write_bytes(b"foreign replacement")
        result = self.clean()
        self.assertFalse(result["cleanup_verified"]); self.assertEqual(self.fs.deleted, [])

    def test_same_vnode_changed_bytes_between_passes_refuse_before_unlink(self):
        self.fs.mutate_second = True
        result = self.clean()
        self.assertTrue(self.fs.same_inode_after_mutation)
        self.assertFalse(result["cleanup_verified"]); self.assertEqual(self.fs.deleted, [])

    def test_same_vnode_with_original_stat_view_still_fails_hash_recheck(self):
        self.fs.mutate_second = self.fs.forge_original_stat = True
        result = self.clean()
        self.assertTrue(self.fs.same_inode_after_mutation)
        self.assertFalse(result["cleanup_verified"]); self.assertEqual(self.fs.deleted, [])
        self.assertIn("bytes/path/token changed", result["error_private"])

    def test_negative_or_partial_baseline_never_deletes(self):
        for key, value in (("observation_completed", False), ("observed_baseline_checks_passed", False), ("freshness_verified", True)):
            before = copy.deepcopy(self.baseline); self.baseline[key] = value
            result = self.clean(); self.assertFalse(result["cleanup_verified"]); self.assertEqual(self.fs.deleted, [])
            self.baseline = before

    def test_baseline_candidate_token_mismatch_never_deletes(self):
        self.baseline["files_after_private"]["candidate"]["stat_token_private"][1] += 1
        result = self.clean()
        self.assertFalse(result["cleanup_verified"]); self.assertEqual(self.fs.deleted, [])

    def test_positive_minimal_or_missing_check_baseline_refuses(self):
        del self.baseline["checks"][next(iter(c.CHECKS))]
        result = self.clean()
        self.assertFalse(result["cleanup_verified"]); self.assertEqual(self.fs.deleted, [])

    def test_partial_removal_survives_later_unlink_failure(self):
        self.fs.fail_unlink_number = 2
        result = self.clean()
        self.assertFalse(result["cleanup_verified"]); self.assertEqual(len(result["removed_files_private"]), 1)
        self.assertEqual(result["removed_files_private"], self.fs.deleted)
        self.assertEqual(len(result["attempted_files_private"]), 2)

    def test_partial_directory_removal_failure_preserves_all_completed_file_counts(self):
        self.fs.fail_rmdir_number = 2
        result = self.clean()
        self.assertFalse(result["cleanup_verified"])
        self.assertEqual(len(result["removed_files_private"]), 5); self.assertEqual(len(result["removed_directories_private"]), 1)
        self.assertTrue(self.fs.paths[c.CONTROL_DIR].exists()); self.assertEqual(list(self.fs.paths[c.CONTROL_DIR].iterdir()), [])

    def test_complete_file_token_mode_link_and_directory_identity_refuse(self):
        for target in ("file-mode", "file-link", "dir-mode"):
            if target == "file-mode": self.delivery["installed_files_private"][0]["stat"]["mtime_ns"] += 1
            elif target == "file-link": self.delivery["installed_files_private"][0]["stat"]["nlink"] = 2
            else: self.delivery["created_directories_private"][0]["stat"]["ino"] += 1
            result = self.clean(); self.assertFalse(result["cleanup_verified"]); self.assertEqual(self.fs.deleted, [])

    def test_expired_global_deadline_before_filesystem_mutation(self):
        result = self.clean(clock=lambda: 9, started=0)
        self.assertFalse(result["cleanup_verified"]); self.assertEqual(self.fs.deleted, [])

    def test_descriptor_close_failure_does_not_discard_report(self):
        self.fs.close_failure_once = True
        result = self.clean()
        self.assertFalse(result["cleanup_verified"]); self.assertEqual(self.fs.deleted, [])
        self.assertIn("close", result["error_private"])

    def test_initial_clock_failure_preserves_negative_report(self):
        def broken(): raise OSError(5, "synthetic clock failure")
        result = self.clean(clock=broken)
        self.assertFalse(result["cleanup_verified"]); self.assertIsNone(result["elapsed_seconds"])
        self.assertEqual(self.fs.deleted, [])

    def final_absence_failure(self, error_number):
        real_stat = os.stat
        targets = {str(path) for path in self.fs.paths.values()}
        failures = []
        def failed_final_stat(path, *args, **kwargs):
            if self.fs.removed_dirs == 2 and str(path) in targets and kwargs.get("follow_symlinks") is False:
                failures.append(str(path))
                raise OSError(error_number, "synthetic final absence lookup failure")
            return real_stat(path, *args, **kwargs)
        with patch.object(os, "stat", failed_final_stat):
            result = self.clean()
        self.assertEqual(len(failures), 1)
        self.assertFalse(result["cleanup_verified"])
        self.assertIn("final absence lookup failure", result["error_private"])
        self.assertEqual(len(result["removed_files_private"]), 5)
        self.assertEqual(len(result["attempted_files_private"]), 5)
        self.assertEqual(len(result["removed_directories_private"]), 2)
        self.assertEqual(len(result["attempted_directories_private"]), 2)

    def test_final_absence_EIO_is_negative_and_retains_completed_counts(self):
        self.final_absence_failure(errno.EIO)

    def test_final_absence_EACCES_is_negative_and_retains_completed_counts(self):
        self.final_absence_failure(errno.EACCES)

    def test_last_absence_stat_crossing_deadline_refuses_with_completed_counts(self):
        value = [0]
        original = self.fs.stat
        def slow_last_stat(name, *, dir_fd=None, follow_symlinks):
            try:
                return original(name, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
            finally:
                if dir_fd is None and name == c.DIRECTORIES[-1]: value[0] = 9
        self.fs.stat = slow_last_stat
        result = self.clean(clock=lambda: value[0])
        self.assertFalse(result["cleanup_verified"])
        self.assertIn("eight-second cleanup deadline", result["error_private"])
        self.assertEqual(result["elapsed_seconds"], 9)
        self.assertEqual(len(result["removed_files_private"]), 5)
        self.assertEqual(len(result["attempted_files_private"]), 5)
        self.assertEqual(len(result["removed_directories_private"]), 2)
        self.assertEqual(len(result["attempted_directories_private"]), 2)


if __name__ == "__main__":
    unittest.main()
