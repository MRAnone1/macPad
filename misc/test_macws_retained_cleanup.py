"""Synthetic host filesystem only; fixed scope/owner patched together per test.

The fake observation backend is invented, not native authority. These tests
exercise real no-follow FD reads and exact unlink/rmdir of self-owned temp files.
"""
import builtins
from contextlib import ExitStack, redirect_stdout
import copy
import ctypes
import errno
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from macws_swap_pair import retained_cleanup as c
from macws_swap_pair import retained_archive as a


def forbidden(*args, **kwargs):
    raise AssertionError("unexpected capability")


class Backend:
    def __init__(self, context):
        self.context = copy.deepcopy(context)
        self.time = 100.0
        self.calls = 0
        self.hook = lambda value: None

    def now(self): return self.time

    def observe(self, selection, provenance, deadline):
        self.calls += 1
        ctx = self.context
        value = {"schema": "macws.retained-artifact.gates.v1", "selection_sha256": selection,
                 "provenance_sha256": provenance, "boot_private": ctx["boot_private"],
                 "config_sha256": ctx["config_sha256"], "source_sha256": dict(c.SOURCES),
                 "UI_private": copy.deepcopy(ctx["UI_private"]), "exclusive_operator": True,
                 "observed_monotonic": self.time, "jobs_absent": dict.fromkeys(c.SERVICES, True),
                 "no_candidate_or_test_workloads": True, "other_scratch_absent": True,
                 "artifacts_unchanged": True, "thermal": 0,
                 "generation_absence": {"api": "proc_pidinfo", "flavor": 3, "requested_bytes": 136,
                     "returned": 0, "errno": errno.ESRCH, "outcome": "ESRCH",
                     "pid_private": ctx["retired_birth_private"][0],
                     "expected_birth_private": list(ctx["retired_birth_private"])}}
        self.hook(value)
        return value


class RetainedCleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="synthetic-retained-artifacts-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / "selection"
        self.path.mkdir(mode=0o700)
        self.files = {"job.plist": b"invented canonical effective control plist\n",
                      "probe.log": b"invented retained log\n"}
        for name, raw in self.files.items():
            path = self.path/name; path.write_bytes(raw); path.chmod(0o600)
        stack = ExitStack(); self.addCleanup(stack.close)
        stack.enter_context(patch.object(c, "TARGET", str(self.path)))
        stack.enter_context(patch.object(c, "OWNER", (os.geteuid(), os.getegid())))
        self.context = {"boot_private": "11111111-2222-3333-4444-555555555555",
                        "config_sha256": "a" * 64, "source_sha256": dict(c.SOURCES),
                        "retired_birth_private": [401, 1000, 5],
                        "UI_private": {"SpringBoard": [101, 1000, 1], "backboardd": [102, 1000, 2]},
                        "expected_file_sha256": {name: c.digest(raw) for name, raw in self.files.items()},
                        "exclusive_operator": True}
        self.manifest = c.capture_selection(self.context)["manifest"]
        self.wire = b'{"synthetic_fresh_capture":true}\n'
        self.provenance = {name: c.digest(name.encode()) for name in c.PROVENANCE_KEYS}
        self.provenance["effective_config_sha256"] = self.context["config_sha256"]
        self.provenance["current_wire_sha256"] = c.digest(self.wire)
        self.receipt = {"schema": "macws.retained-artifact.archive.v1",
                        "manifest_sha256": c.digest(c.canonical(self.manifest)),
                        "provenance_sha256": c.digest(c.canonical(self.provenance)),
                        "wire_sha256": c.digest(self.wire),
                        "file_sha256": {name: c.digest(raw) for name, raw in self.files.items()},
                        "durable_archive_verified": True, "native_evidence_authenticity_verified": False,
                        "device_acceptance": False}
        self.backend = Backend(self.context)

    def cleaner(self, **changes):
        values = {"manifest": self.manifest, "provenance": self.provenance,
                  "archive_receipt": self.receipt, "context": self.context, "expected_files": self.files}
        values.update(changes)
        return c.Cleaner(**values)

    def assert_no_effect(self, report):
        self.assertEqual(report["attempted"], [])
        self.assertEqual(report["completed"], [])
        self.assertFalse(report["cleanup_verified"])
        self.assertEqual(report["outcome"], "refused_before_effect")

    def test_real_temp_selection_hashes_and_all_stat_fields(self):
        captured = c.capture_selection(self.context)
        self.assertEqual(captured["files"], self.files)
        self.assertEqual(captured["manifest"], self.manifest)
        self.assertFalse(captured["native_evidence_authenticity_verified"])
        for name in c.NAMES:
            self.assertEqual(set(self.manifest["files"][name]["stat"]), c.STAT_FIELDS)
            self.assertEqual(self.manifest["files"][name]["stat"]["nlink"], 1)

    def test_actual_archive_creation_verification_and_cleanup_interoperate(self):
        parent = self.root / "archives"; parent.mkdir(mode=0o700)
        receipt = a.archive_bytes(parent, "attempt", wire=self.wire, manifest=self.manifest,
                                  provenance=self.provenance, files=self.files)
        # The direct successful creation return is the trusted caller prerequisite.
        self.assertEqual(receipt, self.receipt)
        verified = a.verify_archive(parent/"attempt", expected_manifest=self.manifest,
                                    expected_provenance=self.provenance,
                                    expected_wire_sha256=c.digest(self.wire),
                                    expected_file_sha256=self.context["expected_file_sha256"])
        self.assertEqual(verified["receipt"], receipt)
        result = self.cleaner(archive_receipt=receipt).execute_once(self.backend)
        self.assertEqual(result["completed"], ["unlink:job.plist", "unlink:probe.log", "rmdir:selection"])
        self.assertTrue(result["cleanup_verified"])
        self.assertFalse(result["device_acceptance"])
        self.assertFalse(self.path.exists())
        self.assertTrue((parent/"attempt"/"job.plist.private.bin").is_file())

    def test_success_exact_three_effects_and_no_native_or_job_operations(self):
        with patch.object(ctypes, "CDLL", forbidden), patch.object(subprocess, "Popen", forbidden), \
             patch.object(subprocess, "run", forbidden), patch.object(os, "kill", forbidden), \
             patch.object(socket, "socket", forbidden):
            result = self.cleaner().execute_once(self.backend)
        self.assertEqual(result["attempted"], result["completed"])
        self.assertEqual(len(result["completed"]), 3)
        self.assertTrue(result["cleanup_verified"])
        self.assertEqual(self.backend.calls, 5)
        self.assertFalse(result["original_ownership_recovered"])

    def test_one_use_even_after_refusal(self):
        cleaner = self.cleaner()
        self.backend.hook = lambda v: v.update(thermal=1)
        self.assert_no_effect(cleaner.execute_once(self.backend))
        with self.assertRaises(c.Refused): cleaner.execute_once(self.backend)

    def test_constructor_freezes_input_and_refuses_changed_selected_content(self):
        cleaner = self.cleaner()
        self.manifest["files"]["job.plist"]["stat"]["ino"] += 1
        self.context["boot_private"] = "00000000-1111-2222-3333-444444444444"
        self.provenance["original_wire_sha256"] = "0" * 64
        self.receipt["manifest_sha256"] = "0" * 64
        self.assertTrue(cleaner.execute_once(self.backend)["cleanup_verified"])

    def test_rehashed_manifest_foreign_fields_wrong_path_boot_config_source_refuse(self):
        mutations = [lambda m: m.update(path="/private/var/tmp/foreign"), lambda m: m.update(extra=True),
                     lambda m: m.update(boot_private="00000000-1111-2222-3333-444444444444"),
                     lambda m: m.update(config_sha256="0"*64), lambda m: m["source_sha256"].update(controller_py="0"*64)]
        for change in mutations:
            value=copy.deepcopy(self.manifest); change(value)
            receipt=copy.deepcopy(self.receipt);receipt["manifest_sha256"]=c.digest(c.canonical(value))
            with self.assertRaises(c.Refused): self.cleaner(manifest=value,archive_receipt=receipt)

    def test_missing_extra_false_or_mismatched_archive_receipt_refuses(self):
        for key in self.receipt:
            bad=copy.deepcopy(self.receipt);bad.pop(key)
            with self.subTest(key=key), self.assertRaises(c.Refused): self.cleaner(archive_receipt=bad)
        for key,value in (("durable_archive_verified",False),("durable_archive_verified",1),
                          ("device_acceptance",0),("native_evidence_authenticity_verified",0),
                          ("wire_sha256","0"*64),("manifest_sha256","0"*64),("extra",True)):
            bad=copy.deepcopy(self.receipt);bad[key]=value
            with self.subTest(key=key),self.assertRaises(c.Refused): self.cleaner(archive_receipt=bad)

    def test_wrong_content_hash_and_mutated_expected_log_cannot_be_refreshed(self):
        changed=dict(self.files);changed["probe.log"]=b"different current bytes\n"
        (self.path/"probe.log").write_bytes(changed["probe.log"])
        with self.assertRaises(c.Refused): c.capture_selection(self.context)
        with self.assertRaises(c.Refused): self.cleaner(expected_files=changed)

    def test_strict_stat_type_owner_mode_kind_size_nlink_refuse(self):
        for key,value in (("ino",True),("dev",1.0),("size",-1),("uid",os.geteuid()+1),
                          ("mode",0o644),("kind","directory"),("nlink",2),("mtime_ns",1<<63)):
            bad=copy.deepcopy(self.manifest);bad["files"]["probe.log"]["stat"][key]=value
            with self.subTest(key=key),self.assertRaises(c.Refused):self.cleaner(manifest=bad)

    def test_file_replacement_before_execution_refuses_no_adoption(self):
        cleaner=self.cleaner(); path=self.path/"probe.log"
        path.rename(self.root/"old-log");path.write_bytes(self.files["probe.log"]);path.chmod(0o600)
        self.assert_no_effect(cleaner.execute_once(self.backend))
        self.assertTrue(path.exists())

    def test_directory_replacement_before_execution_refuses(self):
        cleaner=self.cleaner();self.path.rename(self.root/"old-selection");self.path.mkdir(mode=0o700)
        for name,raw in self.files.items():p=self.path/name;p.write_bytes(raw);p.chmod(0o600)
        self.assert_no_effect(cleaner.execute_once(self.backend))
        self.assertTrue((self.root/"old-selection"/"probe.log").exists())

    def test_directory_or_parent_symlink_refuses(self):
        cleaner=self.cleaner();park=self.root/"park";self.path.rename(park);self.path.symlink_to(park,target_is_directory=True)
        self.assert_no_effect(cleaner.execute_once(self.backend))

    def test_file_symlink_refuses(self):
        cleaner=self.cleaner();path=self.path/"probe.log";park=self.root/"park-log";path.rename(park);path.symlink_to(park)
        self.assert_no_effect(cleaner.execute_once(self.backend))

    def test_hardlink_same_inode_content_refuses(self):
        cleaner=self.cleaner();os.link(self.path/"probe.log",self.root/"second-link")
        self.assert_no_effect(cleaner.execute_once(self.backend))

    def test_extra_or_missing_entry_refuses(self):
        cleaner=self.cleaner();(self.path/"foreign").write_bytes(b"untouched")
        self.assert_no_effect(cleaner.execute_once(self.backend))
        self.assertEqual((self.path/"foreign").read_bytes(),b"untouched")

    def test_missing_file_refuses(self):
        cleaner=self.cleaner();(self.path/"probe.log").rename(self.root/"park-log")
        self.assert_no_effect(cleaner.execute_once(self.backend))

    def test_fifo_substituted_before_open_cannot_wait_for_a_writer(self):
        cleaner=self.cleaner();path=self.path/"probe.log";path.unlink();os.mkfifo(path)
        actual=os.open
        def guarded_open(path,flags,*args,**kwargs):
            if path=="probe.log": self.assertTrue(flags&os.O_NONBLOCK)
            return actual(path,flags,*args,**kwargs)
        with patch.object(os,"open",guarded_open): self.assert_no_effect(cleaner.execute_once(self.backend))

    def test_frozen_log_modified_on_original_inode_refuses(self):
        cleaner=self.cleaner();(self.path/"probe.log").write_bytes(b"changed\n")
        self.assert_no_effect(cleaner.execute_once(self.backend))

    def test_wrong_fresh_boot_source_config_UI_jobs_thermal_and_workloads_refuse(self):
        mutations=[lambda v:v.update(boot_private="00000000-1111-2222-3333-444444444444"),
                   lambda v:v.update(config_sha256="0"*64),lambda v:v.update(selection_sha256="0"*64),
                   lambda v:v.update(provenance_sha256="0"*64),lambda v:v["source_sha256"].update({"controller.py":"0"*64}),
                   lambda v:v["UI_private"]["SpringBoard"].__setitem__(0,999),
                   lambda v:v["jobs_absent"].update({c.SERVICES[0]:False}),lambda v:v.update(thermal=1),
                   lambda v:v.update(thermal=False),lambda v:v.update(no_candidate_or_test_workloads=False),
                   lambda v:v.update(other_scratch_absent=False),lambda v:v.update(artifacts_unchanged=False),
                   lambda v:v.update(exclusive_operator=False),lambda v:v.update(extra=True)]
        for mutate in mutations:
            self.backend.hook=mutate
            with self.subTest(mutate=mutate): self.assert_no_effect(self.cleaner().execute_once(self.backend))

    def test_native_absence_short_error_PID_reuse_and_float_birth_refuse(self):
        for key,value in (("returned",136),("errno",errno.EIO),("errno",True),("pid_private",402),
                          ("outcome","alive"),("expected_birth_private",[401,1000.0,5])):
            self.backend.hook=lambda v,key=key,value=value:v["generation_absence"].update({key:value})
            with self.subTest(key=key):
                self.assert_no_effect(self.cleaner().execute_once(self.backend))

    def test_nonfinite_stale_future_and_bool_gate_times_refuse(self):
        for value in (float("nan"),float("inf"),True,99.0,101.0):
            self.backend.hook=lambda v,value=value:v.update(observed_monotonic=value)
            with self.subTest(value=value): self.assert_no_effect(self.cleaner().execute_once(self.backend))

    def test_nonfinite_or_bool_backend_clock_refuses(self):
        for value in (float("nan"),float("inf"),True,-1):
            self.backend.time=value
            with self.subTest(value=value):self.assert_no_effect(self.cleaner().execute_once(self.backend))

    def test_regressing_clock_refuses(self):
        self.backend.hook=lambda v:setattr(self.backend,"time",99.0)
        self.assert_no_effect(self.cleaner().execute_once(self.backend))

    def test_gate_becomes_stale_during_file_read_refuses_before_unlink(self):
        actual=c._Held.checked
        def delayed(held,*args,**kwargs):
            result=actual(held,*args,**kwargs)
            if self.backend.calls==2:self.backend.time+=1.1
            return result
        with patch.object(c._Held,"checked",delayed):self.assert_no_effect(self.cleaner().execute_once(self.backend))

    def test_deadline_expired_during_observation_refuses(self):
        self.backend.hook=lambda v:setattr(self.backend,"time",108.0)
        self.assert_no_effect(self.cleaner().execute_once(self.backend))

    def test_second_file_replacement_after_first_unlink_is_partial_no_retry(self):
        def hook(value):
            if self.backend.calls==3:
                path=self.path/"probe.log";path.rename(self.root/"retained-log")
                path.write_bytes(self.files["probe.log"]);path.chmod(0o600)
        self.backend.hook=hook;cleaner=self.cleaner();report=cleaner.execute_once(self.backend)
        self.assertEqual(report["completed"],["unlink:job.plist"])
        self.assertEqual(report["outcome"],"partial_or_unknown")
        self.assertFalse(report["cleanup_verified"])
        self.assertTrue((self.path/"probe.log").exists())
        with self.assertRaises(c.Refused):cleaner.execute_once(self.backend)

    def test_job_reappears_after_first_effect_preserves_second(self):
        self.backend.hook=lambda v:v["jobs_absent"].update({c.SERVICES[1]:self.backend.calls!=3})
        report=self.cleaner().execute_once(self.backend)
        self.assertEqual(report["completed"],["unlink:job.plist"])
        self.assertTrue((self.path/"probe.log").exists())
        self.assertFalse(report["cleanup_verified"])

    def test_unlink_performed_then_raises_is_unknown_attempt_not_zero(self):
        actual=os.unlink
        def uncertain(name,*args,**kwargs):
            actual(name,*args,**kwargs)
            raise OSError("synthetic lost return")
        with patch.object(os,"unlink",uncertain):report=self.cleaner().execute_once(self.backend)
        self.assertEqual(report["attempted"],["unlink:job.plist"])
        self.assertEqual(report["completed"],[])
        self.assertEqual(report["outcome"],"partial_or_unknown")
        self.assertTrue((self.path/"probe.log").exists())

    def test_unlink_failure_preserves_files_and_unknown_attempt(self):
        with patch.object(os,"unlink",side_effect=PermissionError("synthetic")):
            report=self.cleaner().execute_once(self.backend)
        self.assertEqual(len(report["attempted"]),1)
        self.assertEqual(report["completed"],[])
        self.assertTrue((self.path/"job.plist").exists())
        self.assertEqual(report["outcome"],"partial_or_unknown")

    def test_rmdir_performed_then_raises_does_not_claim_cleanup(self):
        actual=os.rmdir
        def uncertain(name,*args,**kwargs):
            actual(name,*args,**kwargs);raise OSError("synthetic lost return")
        with patch.object(os,"rmdir",uncertain):report=self.cleaner().execute_once(self.backend)
        self.assertEqual(len(report["attempted"]),3)
        self.assertEqual(len(report["completed"]),2)
        self.assertFalse(report["cleanup_verified"])
        self.assertFalse(self.path.exists())

    def test_post_removal_gate_failure_keeps_result_unknown(self):
        self.backend.hook=lambda v:v.update(thermal=1 if self.backend.calls==5 else 0)
        report=self.cleaner().execute_once(self.backend)
        self.assertEqual(len(report["completed"]),3)
        self.assertFalse(report["cleanup_verified"])
        self.assertEqual(report["outcome"],"partial_or_unknown")

    def test_new_object_after_rmdir_is_preserved_and_refuses_absence(self):
        def hook(value):
            if self.backend.calls==5:self.path.mkdir(mode=0o700)
        self.backend.hook=hook;report=self.cleaner().execute_once(self.backend)
        self.assertFalse(report["cleanup_verified"])
        self.assertTrue(self.path.is_dir())

    def test_replacement_parent_during_post_gate_refuses_actual_path_absence(self):
        def hook(value):
            if self.backend.calls==5:
                self.root.rename(self.root.with_name(self.root.name+"-moved"))
                self.root.mkdir(mode=0o700);self.path.mkdir(mode=0o700)
                self.addCleanup(lambda: __import__("shutil").rmtree(self.root.with_name(self.root.name+"-moved")))
        self.backend.hook=hook;report=self.cleaner().execute_once(self.backend)
        self.assertFalse(report["cleanup_verified"])
        self.assertTrue(self.path.exists())

    def test_decoder_duplicate_nonfinite_overflow_oversize_and_deep_values_refuse(self):
        for raw in (b'{"a":1,"a":2}',b'{"x":NaN}',b'{"x":1e999}',b'\xff',b'[',b' '*65537):
            with self.subTest(raw=raw[:20]),self.assertRaises(c.Refused):c.decode(raw)
        value=None
        for _ in range(14):value=[value]
        with self.assertRaises(c.Refused):c.canonical(value)

    def final_anchor_delay(self, seconds):
        actual=c._Held.anchor_checked
        final_checks=0
        def delayed(held,include_selection=True):
            nonlocal final_checks
            value=actual(held,include_selection=include_selection)
            if not include_selection:
                final_checks+=1
                if final_checks==4:self.backend.time+=seconds
            return value
        with patch.object(c._Held,"anchor_checked",delayed):report=self.cleaner().execute_once(self.backend)
        self.assertEqual(len(report["completed"]),3)
        self.assertFalse(report["cleanup_verified"])
        self.assertEqual(report["outcome"],"partial_or_unknown")

    def test_deadline_after_final_parent_check_cannot_claim_cleanup(self):
        self.final_anchor_delay(9)

    def test_stale_postgate_after_final_parent_check_cannot_claim_cleanup(self):
        self.final_anchor_delay(1.1)

    def test_opened_directory_fd_is_closed_when_its_first_stat_fails(self):
        actual_open, actual_close = os.open, os.close
        opened, closed = [], []
        def opening(*args, **kwargs):
            fd=actual_open(*args, **kwargs);opened.append(fd);return fd
        def closing(fd):
            closed.append(fd);return actual_close(fd)
        with patch.object(os,"open",opening),patch.object(os,"close",closing), \
             patch.object(os,"fstat",side_effect=OSError("synthetic first-stat failure")):
            self.assert_no_effect(self.cleaner().execute_once(self.backend))
        self.assertEqual(opened,closed)
        self.assertEqual(len(opened),1)

    def test_private_gate_evidence_and_first_failed_stage_are_retained(self):
        self.backend.hook=lambda v:v.update(thermal=1 if self.backend.calls==3 else 0)
        cleaner=self.cleaner();report=cleaner.execute_once(self.backend)
        self.assertEqual(report["stage"],"before_unlink:probe.log")
        self.assertEqual(len(report["gate_observations_private"]),3)
        self.assertEqual(report["gate_observations_private"][-1]["thermal"],1)
        self.assertEqual(report["refusal"],"fresh jobs/thermal refusal")
        self.assertEqual(report["selection_sha256"],self.receipt["manifest_sha256"])
        self.assertEqual(report["archive_receipt_sha256"],c.digest(c.canonical(self.receipt)))
        self.backend.context["retired_birth_private"][0]=999
        self.assertEqual(report["gate_observations_private"][0]["generation_absence"]["pid_private"],401)

    def test_default_import_and_CLI_metadata_have_zero_io(self):
        source=(Path(__file__).parent/"macws_swap_pair/retained_cleanup.py").read_bytes()
        for name in ("synthetic_import","__main__"):
            output=io.StringIO()
            with ExitStack() as stack:
                for owner,attr in ((os,"open"),(os,"unlink"),(os,"rmdir"),(os,"mkdir"),(os,"kill"),
                                   (socket,"socket"),(subprocess,"run"),(subprocess,"Popen"),(ctypes,"CDLL"),
                                   (signal,"signal"),(builtins,"open")):
                    stack.enter_context(patch.object(owner,attr,forbidden))
                stack.enter_context(redirect_stdout(output))
                exec(compile(source,"<inert-default>","exec"),{"__name__":name})
            self.assertEqual(json.loads(output.getvalue()),c.metadata()) if name=="__main__" else self.assertEqual(output.getvalue(),"")


if __name__=="__main__":unittest.main()
