"""Invented synthetic fixtures only: no device/native/transport dispatch."""
import copy
import ast
import errno
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("private_retirement_core", HERE / "macws_swap_pair/process_retirement.py")
c = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = c
spec.loader.exec_module(c)
SOURCES = HERE / "macws_swap_pair"


def witness(birth, path):
    raw = bytearray(136)
    struct.pack_into("<I", raw, 4, 4)
    struct.pack_into("<I", raw, 12, birth[0])
    struct.pack_into("<QQ", raw, 120, *birth[1:])
    return {"path": path, "birth_private": birth.copy(), "stopped": True,
            "native_status_private": 4, "native_status_name": "SSTOP",
            "state_source": "proc_bsdinfo.pbi_status", "raw_bsdinfo_private_hex": raw.hex(),
            "raw_bsdinfo_sha256": hashlib.sha256(raw).hexdigest(),
            "returned_bsdinfo_bytes": 136, "bsdinfo_errno": 0}


def fixture():
    rs = c.load_runtime(SOURCES)
    config = {"schema": "macws.swap-pair.live-config.v7", "operation": "run", "arch": "arm64",
              "run_nonce": "a" * 32, "profile_sha256": rs.PROBE_PROFILE_SHA256,
              "loaded_hook_profile_sha256": rs.PROBE_PROFILE_SHA256,
              "signed_probe_sha256": c.PROBE_SHA, "signed_probe_uuid": c.PROBE_UUID,
              "signed_probe_cdhash": c.PROBE_CDHASH, "installed_probe_token": [7, 123, 70000, 1111, 2222],
              "boot_private": "11111111-2222-3333-4444-555555555555",
              "UI_private": {"SpringBoard": [101, 1000, 1], "backboardd": [102, 1000, 2]},
              "source_sha256": dict(c.SOURCE_PINS), "active_seconds": 10, "cleanup_seconds": 8,
              "candidate_limits": dict(rs.PROBE_LIMITS), "offline_QA_sha256": c.QA_SHA,
              "clock_info": {"domain": "mach_absolute_time.absolute_seconds.v1", "numer": 125, "denom": 3}}
    initial = witness([401, 1234, 500], rs.ROOTFS + rs.executable(config))
    run = {"schema": "macws.swap-pair.controller-protocol.v7", "bootstrap_attempted": True,
           "bootstraps": 1, "debug_admission_calls": 0, "resumes": 0, "second_resumes": 0,
           "C_ready_verified": False, "pair_result_private": None,
           "birth_private": initial["birth_private"].copy(), "initial_process_private": initial}
    full = {"schema": "macws.swap-pair.live-controller.v7", "operation": "control_normal",
            "source_sha256": dict(c.SOURCE_PINS), "clock_info": config["clock_info"].copy(),
            "cleanup_verified": False, "pair_capture_accepted": False,
            "control_capture_accepted": False, "run_private": run}
    report = {"schema": "macws.swap-pair.explicit-device-call.v7", "operation": "control_normal",
              "control": "normal_ready_stop", "source_sha256": dict(c.SOURCE_PINS),
              "clock_info": config["clock_info"].copy(), "full_report_returned": True,
              "device_acceptance": False, "freeze_fix": False, "full_private_report": full}
    paths = {"probe.arm64": (rs.ROOTFS + rs.executable(config), c.PROBE_SHA, 0o755),
             **{name: (c.CONTROLLER_DIR + "/" + name, value, 0o600) for name, value in c.SOURCE_PINS.items()},
             "offline-QA.canonical.private.json": (c.CONTROLLER_DIR + "/offline-QA.canonical.private.json", c.QA_SHA, 0o600)}
    rows = []
    for index, (name, (path, sha, mode)) in enumerate(paths.items()):
        token = {"dev": 7, "ino": 123 + index, "size": 70000, "mtime_ns": 1111,
                 "ctime_ns": 2222, "mode": mode, "uid": 0, "gid": 0, "nlink": 1}
        rows.append({"name": name, "path": path, "sha256": sha, "stat": token,
                     "previously_absent": True, "new_vnode_created_exclusively": True})
    delivery = {"schema": "macws.diagnostic-probe.delivery.private.v1", "installation_verified": True,
                "receiver_sha256": c.RECEIVER_SHA, "bundle_manifest_sha256": c.MANIFEST_SHA,
                "candidate_executions": 0, "controller_executions": 0, "trust_mutations": 0,
                "installed_files_private": rows,
                "probe_signature": {"architecture": "arm64", "cdhash": c.PROBE_CDHASH,
                    "code_limit": 69584, "hash_type": 2, "page_hashes_valid": True,
                    "signed_pages_checked": 5, "uuid": c.PROBE_UUID}}
    return config, report, delivery


class FakeBackend:
    """Read/effect simulator, never an OwnedFiles substitute."""
    def __init__(self, original):
        self.config = copy.deepcopy(original.config)
        self.clock = SimpleNamespace(profile=copy.deepcopy(original.config["clock_info"]))
        self.original = original
        self.time = 100
        self.build = "20E252"
        self.boot = self.config["boot_private"]
        self.ui = copy.deepcopy(self.config["UI_private"])
        self.thermal = 0
        self.installed_token = self.config["installed_probe_token"].copy()
        self.installed_sha = self.config["signed_probe_sha256"]
        self.installed_uuid = self.config["signed_probe_uuid"]
        self.trusted = True
        self.current = copy.deepcopy(original.initial)
        self.pid = original.birth[0]
        self.redirect = False
        self.exists = True
        self.calls = []
        self.killed = False
        self.booted_out = False
        self.kill_partial = False
        self.bootout_partial = False
        self.kill_result = (0, "", "")
        self.bootout_result = (0, "", "")
        self.esrch = True
        self.esrch_uncertain = False
        self.reused = False
        self.after_kill_redirect = False
        self.after_kill_deadline = False
        self.final_job_survives = False
        self.plist_redirect = False
        self.other_label_exists = False
        self.binding_refusal = False
        self.invalid_alive_evidence = False
        self.process_after_kill_forbidden = False
        self.delay_final_ESRCH_samples = 0

    def now(self):
        return self.time

    def health(self, deadline, initial=False):
        self.calls.append("health")
        c.need(initial is True and self.build == "20E252" and self.boot == self.config["boot_private"]
               and self.ui == self.config["UI_private"] and self.thermal == 0, "synthetic_health")

    def installed(self, deadline):
        self.calls.append("installed")
        c.need(self.installed_token == self.config["installed_probe_token"] and
               self.installed_sha == self.config["signed_probe_sha256"] and
               self.installed_uuid == self.config["signed_probe_uuid"] and self.trusted is True,
               "synthetic_installed")

    def other_label_absent(self, deadline):
        self.calls.append("other_label")
        return not self.other_label_exists

    def read_regular(self, path, limit):
        self.calls.append("read_plist")
        rs = self.original.runtime
        if path != rs.scratch_path(self.config) + "/job.plist" or limit != 16384:
            raise AssertionError("unexpected file read")
        raw = b"foreign" if self.plist_redirect else rs.plist_bytes(self.config)
        return raw, [1, 2, len(raw), 3, 4]

    def process(self, pid, deadline):
        self.calls.append("process")
        if self.killed and self.process_after_kill_forbidden:
            raise AssertionError('must use known-generation query after SIGKILL')
        return copy.deepcopy(self.current)

    def bind(self, deadline, birth=None, stopped=False, allow_wrapper=False):
        self.calls.append(('bind', stopped, allow_wrapper))
        c.need(not self.binding_refusal and birth == self.original.birth and
               stopped is True and allow_wrapper is False and
               self.installed_token == self.config['installed_probe_token'],
               'synthetic_exact_runtime_bind')
        return birth.copy()

    def pause(self, seconds):
        self.calls.append('pause')
        self.time += seconds

    def generation_absent(self, birth, deadline):
        self.calls.append("generation")
        if self.reused:
            raise RuntimeError("synthetic reused birth")
        absent = self.esrch
        if self.booted_out and self.delay_final_ESRCH_samples > 0:
            self.delay_final_ESRCH_samples -= 1
            absent = False
        self.last_generation_query = {"api": "proc_pidinfo", "flavor": 3, "requested_bytes": 136,
            "returned": 0 if absent else 136,
            "errno": (errno.ESRCH if absent else 0) if not self.esrch_uncertain else errno.EPERM,
            "pid_private": birth[0], "expected_birth_private": birth.copy(),
            "outcome": "ESRCH" if absent else 'same_generation_alive'}
        if not absent:
            self.last_generation_query['observed_birth_private'] = birth.copy()
            if self.invalid_alive_evidence:
                self.last_generation_query['observed_birth_private'][1] += 1
        return absent

    def command(self, argv, deadline):
        self.calls.append(tuple(argv))
        rs = self.original.runtime
        service = rs.service_identifier(self.config)
        if argv == [rs.LAUNCHCTL, "print", service]:
            if not self.exists:
                return 113, "", 'Could not find service "' + rs.job_label(self.config) + '" in domain for uid: 501\n'
            program = rs.WRAPPER + (".foreign" if self.redirect else "")
            raw = service + " = {\n"
            for key, value in (("program", program), ("domain", rs.LAUNCHD_DOMAIN),
                               ("path", rs.scratch_path(self.config) + "/job.plist"),
                               ("stdout path", rs.scratch_path(self.config) + "/probe.log"),
                               ("stderr path", rs.scratch_path(self.config) + "/probe.log")):
                raw += "\t" + key + " = " + value + "\n"
            raw += "\targuments = {\n" + "".join("\t\t" + x + "\n" for x in rs.arguments(self.config)) + "\t}\n"
            if self.pid is not None:
                raw += "\tpid = " + str(self.pid) + "\n"
            return 0, raw + "}\n", ""
        if argv == [rs.LAUNCHCTL, "kill", "SIGKILL", service]:
            self.killed = True
            if self.after_kill_redirect:
                self.pid += 1
            if self.after_kill_deadline:
                self.time = 109
            if self.kill_partial:
                raise TimeoutError("synthetic partial kill")
            return self.kill_result
        if argv == [rs.LAUNCHCTL, "bootout", service]:
            self.booted_out = True
            self.exists = self.final_job_survives
            if self.bootout_partial:
                raise TimeoutError("synthetic partial bootout")
            return self.bootout_result
        raise AssertionError("unapproved command")


class Controls(unittest.TestCase):
    def setUp(self):
        self.inputs = fixture()
        self.original = c.validate_original(*self.inputs, source_directory=SOURCES)
        self.backend = FakeBackend(self.original)

    def run_effect(self):
        return c.observe_or_retire(self.original, self.backend, deadline=108, execute=True,
                                   read_regular=self.backend.read_regular)

    def no_effect(self, result):
        self.assertFalse(result["process_retired"])
        self.assertEqual(result["kill_attempts"], 0)
        self.assertFalse(self.backend.killed)
        self.assertFalse(self.backend.booted_out)

    def test_default_inert_without_backend(self):
        result = c.observe_or_retire()
        self.assertEqual(result["device_mutations_attempted"], 0)
        self.assertFalse(result["observed"])

    def test_default_does_not_touch_supplied_backend(self):
        c.observe_or_retire(self.original, self.backend)
        self.assertEqual(self.backend.calls, [])

    def test_observe_read_only(self):
        result = c.observe_or_retire(self.original, self.backend, deadline=108, observe=True,
                                     read_regular=self.backend.read_regular)
        self.assertTrue(result["exact_stopped_target_observed"])
        self.no_effect(result)

    def test_exact_retirement_preserves_scratch_limit(self):
        result = self.run_effect()
        self.assertTrue(result["process_retired"])
        self.assertEqual((result["kill_completed"], result["bootout_completed"]), (1, 1))
        self.assertEqual(result["device_mutations"], 2)
        for key in ("cleanup_verified", "device_acceptance", "freeze_fix", "scratch_ownership_recovered"):
            self.assertIs(result[key], False)

    def test_foreign_pid_before_first_effect(self):
        self.backend.pid += 1
        self.no_effect(self.run_effect())

    def test_job_program_redirect_before_first_effect(self):
        self.backend.redirect = True
        self.no_effect(self.run_effect())

    def test_current_plist_redirect_refuses(self):
        self.backend.plist_redirect = True
        self.no_effect(self.run_effect())

    def test_missing_current_plist_reader_refuses(self):
        self.no_effect(c.observe_or_retire(self.original, self.backend, deadline=108, execute=True))

    def test_other_fixed_label_present_refuses(self):
        self.backend.other_label_exists = True
        self.no_effect(self.run_effect())

    def test_wrapper_path_never_falls_back(self):
        self.backend.current["path"] = self.original.runtime.WRAPPER
        self.no_effect(self.run_effect())

    def test_logical_alias_never_falls_back(self):
        self.backend.current["path"] = self.backend.current["path"].replace("/private/var/", "/var/", 1)
        self.no_effect(self.run_effect())

    def test_changed_current_birth_is_refused(self):
        self.backend.current = witness([401, 2222, 123], self.original.initial["path"])
        self.no_effect(self.run_effect())

    def test_nonstopped_target_is_refused(self):
        self.backend.current["stopped"] = False
        self.no_effect(self.run_effect())

    def test_changed_raw_status_is_refused(self):
        self.backend.current["raw_bsdinfo_sha256"] = "0" * 64
        self.no_effect(self.run_effect())

    def test_unchanged_runtime_bind_refusal_prevents_effect(self):
        self.backend.binding_refusal = True
        self.no_effect(self.run_effect())

    def test_original_birth_and_raw_witness_mutation_is_refused(self):
        replacement = witness([401, 9999, 1], self.original.initial['path'])
        self.original.birth[:] = replacement['birth_private']
        self.original.initial.update(replacement)
        self.no_effect(self.run_effect())

    def test_build_boot_ui_thermal_refuse(self):
        for field, value in (("build", "20F75"), ("boot", "changed"), ("ui", {}), ("thermal", 1)):
            with self.subTest(field=field):
                self.backend = FakeBackend(self.original)
                setattr(self.backend, field, value)
                self.no_effect(self.run_effect())

    def test_installed_stat_hash_uuid_trust_refuse(self):
        for field, value in (("installed_token", [7, 999, 70000, 1111, 2222]),
                             ("installed_sha", "0" * 64), ("installed_uuid", "changed"), ("trusted", False)):
            with self.subTest(field=field):
                self.backend = FakeBackend(self.original)
                setattr(self.backend, field, value)
                self.no_effect(self.run_effect())

    def test_after_kill_redirect_prevents_bootout(self):
        self.backend.after_kill_redirect = True
        result = self.run_effect()
        self.assertEqual(result["kill_completed"], 1)
        self.assertEqual(result["bootout_attempts"], 0)
        self.assertFalse(result["process_retired"])

    def test_partial_kill_unknown_completion_and_no_bootout(self):
        self.backend.kill_partial = True
        result = self.run_effect()
        self.assertEqual(result["kill_attempts"], 1)
        self.assertIsNone(result["kill_completed"])
        self.assertIsNone(result["device_mutations"])
        self.assertEqual(result["bootout_attempts"], 0)

    def test_noisy_kill_refuses_without_success_count(self):
        self.backend.kill_result = (0, "warning\n", "")
        result = self.run_effect()
        self.assertIsNone(result["kill_completed"])
        self.assertEqual(result["bootout_attempts"], 0)

    def test_partial_bootout_unknown_completion(self):
        self.backend.bootout_partial = True
        result = self.run_effect()
        self.assertEqual(result["kill_completed"], 1)
        self.assertEqual(result["bootout_attempts"], 1)
        self.assertIsNone(result["bootout_completed"])
        self.assertFalse(result["process_retired"])

    def test_uncertain_ESRCH_blocks_bootout(self):
        self.backend.esrch_uncertain = True
        result = self.run_effect()
        self.assertEqual(result["bootout_attempts"], 0)
        self.assertFalse(result["process_retired"])

    def test_reused_birth_after_kill_blocks_bootout(self):
        self.backend.reused = True
        result = self.run_effect()
        self.assertEqual(result["bootout_attempts"], 0)
        self.assertFalse(result["process_retired"])

    def test_no_final_ESRCH_never_claims_retired(self):
        self.backend.esrch = False
        result = self.run_effect()
        self.assertEqual(result["bootout_completed"], 1)
        self.assertFalse(result["process_retired"])
        self.assertFalse(result["original_generation_ESRCH"])

    def test_false_generation_result_needs_copied_same_birth(self):
        self.backend.esrch = False
        self.backend.invalid_alive_evidence = True
        result = self.run_effect()
        self.assertEqual(result['kill_completed'], 1)
        self.assertEqual(result['bootout_attempts'], 0)
        self.assertFalse(result['process_retired'])
        self.assertTrue(result['generation_queries_private'])

    def test_post_kill_binding_does_not_invent_a_stopped_state(self):
        self.backend.esrch = False
        self.backend.process_after_kill_forbidden = True
        result = self.run_effect()
        self.assertEqual(result['bootout_completed'], 1)
        self.assertFalse(result['process_retired'])

    def test_delayed_native_reaping_uses_reads_only(self):
        self.backend.delay_final_ESRCH_samples = 2
        result = self.run_effect()
        self.assertTrue(result['process_retired'])
        self.assertEqual(result['kill_attempts'], 1)
        self.assertEqual(result['bootout_attempts'], 1)
        self.assertEqual(result['generation_queries_private'][-1]['outcome'], 'ESRCH')
        self.assertIn('pause', self.backend.calls)

    def test_success_retains_native_witnesses(self):
        result = self.run_effect()
        self.assertEqual(result['observed_process_private'], self.original.initial)
        self.assertEqual(result['pre_kill_process_private'], self.original.initial)
        self.assertTrue(result['job_observations_private'])
        self.assertEqual(result['generation_queries_private'][-1]['expected_birth_private'], self.original.birth)

    def test_final_job_survival_never_claims_retired(self):
        self.backend.final_job_survives = True
        result = self.run_effect()
        self.assertFalse(result["process_retired"])

    def test_deadline_after_kill_prevents_second_effect(self):
        self.backend.after_kill_deadline = True
        result = self.run_effect()
        self.assertEqual(result["kill_completed"], 1)
        self.assertEqual(result["bootout_attempts"], 0)

    def test_invalid_deadline_and_clock_refuse(self):
        for deadline in (100, 109, float("nan"), None):
            self.no_effect(c.observe_or_retire(self.original, self.backend, deadline=deadline, execute=True))
        self.backend.clock.profile = {}
        self.no_effect(self.run_effect())

    def test_mutated_context_refuses(self):
        self.original.config["installed_probe_token"][1] += 1
        self.no_effect(self.run_effect())

    def test_missing_original_authority_refuses(self):
        self.no_effect(c.observe_or_retire(None, self.backend, deadline=108, execute=True))

    def test_ambiguous_modes_refuse_without_effect(self):
        self.no_effect(c.observe_or_retire(self.original, self.backend, deadline=108,
                                          observe=True, execute=True,
                                          read_regular=self.backend.read_regular))

    def test_original_counter_and_phase_adversaries(self):
        for key, value in (("bootstraps", 0), ("bootstraps", True), ("debug_admission_calls", 1),
                           ("resumes", 1), ("second_resumes", 1), ("C_ready_verified", True),
                           ("pair_result_private", {})):
            cfg, rep, delivery = fixture()
            rep["full_private_report"]["run_private"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(c.Refused):
                c.validate_original(cfg, rep, delivery, source_directory=SOURCES)

    def test_original_source_build_boot_and_delivery_adversaries(self):
        cfg, rep, delivery = fixture()
        changes = [("source_sha256", {}), ("signed_probe_sha256", "0" * 64),
                   ("signed_probe_cdhash", "0" * 40), ("boot_private", "not-a-uuid")]
        for key, value in changes:
            altered = copy.deepcopy(cfg); altered[key] = value
            with self.subTest(key=key), self.assertRaises(c.Refused):
                c.validate_original(altered, rep, delivery, source_directory=SOURCES)
        delivery["installed_files_private"][0]["stat"]["ino"] += 1
        with self.assertRaises(c.Refused):
            c.validate_original(cfg, rep, delivery, source_directory=SOURCES)

    def test_original_delivery_wrong_owner_or_nonexclusive_refuses(self):
        for key, value in (("gid", 501), ("mode", 0o100777), ("mode", 0o100755), ("nlink", 2)):
            cfg, rep, delivery = fixture()
            delivery["installed_files_private"][0]["stat"][key] = value
            with self.subTest(key=key), self.assertRaises(c.Refused):
                c.validate_original(cfg, rep, delivery, source_directory=SOURCES)

    def test_fixture_modes_use_exact_pinned_receiver_token_projection(self):
        source = (SOURCES.parent / 'macws_diagnostic_probe_receiver.py').read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), c.RECEIVER_SHA)
        functions = [node for node in ast.parse(source).body
                     if isinstance(node, ast.FunctionDef) and node.name == 'token']
        self.assertEqual(len(functions), 1)
        namespace = {'stat': stat}
        exec(compile(ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[])),
                     '<pinned-receiver-token-projection>', 'exec'), namespace)
        for row in self.inputs[2]['installed_files_private']:
            expected = row['stat']
            invented = SimpleNamespace(**{'st_' + key: value for key, value in expected.items()})
            invented.st_mode |= stat.S_IFREG
            self.assertEqual(namespace['token'](invented), expected)

    def test_source_bytes_pin_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in c.SOURCE_PINS:
                (Path(directory) / name).write_bytes((SOURCES / name).read_bytes())
            path = Path(directory) / "runtime_support.py"
            path.write_text("raise AssertionError('must not execute unpinned source')\n")
            with self.assertRaises(c.Refused):
                c.load_runtime(directory)

    def test_public_summary_contains_no_raw_identity(self):
        result = self.run_effect()
        text = json.dumps(c.public_summary(result))
        for value in (self.original.config["boot_private"], self.original.initial["raw_bsdinfo_private_hex"],
                      self.original.initial["path"], str(self.original.birth)):
            self.assertNotIn(value, text)

    def test_public_summary_rejects_untyped_counters_and_hides_unknown_reason(self):
        result = self.run_effect()
        result['refusal'] = self.original.config['boot_private']
        self.assertEqual(c.public_summary(result)['refusal'], 'unrecognized_refusal')
        result['kill_completed'] = True
        with self.assertRaises(c.Refused):
            c.public_summary(result)

    def test_source_symlink_and_oversized_source_refuse_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            for name in c.SOURCE_PINS:
                (target / name).write_bytes((SOURCES / name).read_bytes())
            runtime = target / 'runtime_support.py'
            runtime.write_bytes(b'x' * (128 * 1024 + 1))
            with self.assertRaises(c.Refused):
                c.load_runtime(target)
            runtime.unlink()
            runtime.symlink_to(SOURCES / 'runtime_support.py')
            with self.assertRaises(OSError):
                c.load_runtime(target)

    def test_no_native_dispatch_file_mutation_resume_or_bare_pid_signal(self):
        def forbidden(*args, **kwargs):
            raise AssertionError("forbidden offline dispatch")
        with patch("ctypes.CDLL", forbidden), patch("subprocess.run", forbidden), \
             patch("os.kill", forbidden), patch("os.unlink", forbidden), patch("os.rmdir", forbidden):
            cfg, rep, delivery = fixture()
            original = c.validate_original(cfg, rep, delivery, source_directory=SOURCES)
            backend = FakeBackend(original)
            result = c.observe_or_retire(original, backend, deadline=108, execute=True,
                                         read_regular=backend.read_regular)
        self.assertTrue(result["process_retired"])
        rs = original.runtime
        effects = [call for call in backend.calls if type(call) is tuple and
                   call[0] == rs.LAUNCHCTL and call[1] != 'print']
        self.assertEqual([call for call in backend.calls if type(call) is tuple and call[0] == 'bind'],
                         [('bind', True, False), ('bind', True, False)])
        service = rs.service_identifier(original.config)
        self.assertEqual(effects, [(rs.LAUNCHCTL, "kill", "SIGKILL", service),
                                   (rs.LAUNCHCTL, "bootout", service)])


if __name__ == "__main__":
    unittest.main()
