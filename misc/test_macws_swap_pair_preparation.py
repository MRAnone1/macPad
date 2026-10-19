"""Synthetic host controls only. No device, transport, native API or job.

All purported device identities/tokens in fixture() are invented in memory
for adversarial parser tests. No session/config/receipt file is generated.
"""
from contextlib import redirect_stdout
import base64
import builtins
import copy
import ctypes
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import signal
import shutil
import struct
import tempfile
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

RUNTIME_DIR = Path(__file__).resolve().parent / "macws_swap_pair"
QA_PATH = RUNTIME_DIR / "offline_qa.json"
spec = importlib.util.spec_from_file_location("macws_control_preparation_portable", RUNTIME_DIR / "prepare_control_payload.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def raw(value):
    return json.dumps(value, separators=(",", ":")).encode()


def fixture():
    sizes = {name: (RUNTIME_DIR / name).stat().st_size for name in p.SOURCES}
    tokens = {name: {"dev": 1, "ino": 2 + i, "size": size, "mtime_ns": 1000, "ctime_ns": 1000}
              for i, (name, size) in enumerate(sizes.items())}
    support, _ = p.pinned_support(source_directory=RUNTIME_DIR, qa_path=QA_PATH, tokens=tokens)
    qa = json.loads(QA_PATH.read_bytes())
    config = {"schema": "macws.swap-pair.live-config.v7", "operation": "run", "arch": "arm64", "run_nonce": "a" * 32,
              "profile_sha256": support.PROBE_PROFILE_SHA256, "loaded_hook_profile_sha256": support.PROBE_PROFILE_SHA256,
              "signed_probe_sha256": "3" * 64, "signed_probe_uuid": support.PROBE_BUILDS["arm64"][1],
              "signed_probe_cdhash": "4" * 40, "installed_probe_token": [1, 2, 50000, 1000, 1000],
              "boot_private": "11111111-2222-3333-4444-555555555555",
              "UI_private": {"SpringBoard": [101, 1000, 1], "backboardd": [102, 1000, 2]}, "source_sha256": dict(p.SOURCES),
              "active_seconds": 10, "cleanup_seconds": 8, "offline_QA_sha256": p.QA_SHA256,
              "candidate_limits": dict(support.PROBE_LIMITS),
              "clock_info": {"domain": "mach_absolute_time.absolute_seconds.v1", "numer": 125, "denom": 3}}
    common = {"run_nonce": config["run_nonce"], "admission_sha256": support.admission_sha(config),
              "source_sha256": dict(p.SOURCES), "boot_private": config["boot_private"], "observed_monotonic": 99,
              "raw_sha256": "5" * 64, "evidence_kind": "copied-native-runtime", "clock_info": config["clock_info"]}
    pre = dict(common, schema="macws.swap-pair.native-preflight.v1", UI_private=copy.deepcopy(config["UI_private"]),
               thermal="nominal", label_absent=True, scratch_absent=True)
    artifact = dict(common, schema="macws.swap-pair.installed-signed-artifact.v1", path=support.executable(config),
                    sha256=config["signed_probe_sha256"], uuid=config["signed_probe_uuid"], cdhash=config["signed_probe_cdhash"],
                    stat_token=config["installed_probe_token"], new_vnode=True, trust_member=True,
                    source_profile_sha256=config["profile_sha256"], unsigned_sha256=support.PROBE_BUILDS["arm64"][0],
                    probe_source_sha256=support.PROBE_SOURCE_SHA256, build_receipt_sha256=support.PROBE_BUILD_RECEIPT_SHA256)
    hook = dict(common, schema="macws.swap-pair.loaded-hook-profile-preparation.v1", profile_sha256=config["profile_sha256"],
                architecture="arm64", hook_path=support.HOOKS["arm64"][0], hook_sha256=support.HOOKS["arm64"][1])
    receipts = {"schema": "macws.swap-pair.live-prerequisites.v7", "preflight": pre, "signed_artifact": artifact,
                "loaded_hook_profile": hook, "offline_QA": {"receipt": qa, "raw_sha256": p.QA_SHA256}, "native_controls": {}}
    return config, receipts, tokens


def build(config=None, receipts=None, tokens=None, control="normal_ready_stop"):
    cfg, rec, tok = fixture()
    return p.build_control_payload(config_raw=raw(cfg if config is None else config),
                                   receipts_raw=raw(rec if receipts is None else receipts),
                                   tokens_raw=raw(tok if tokens is None else tokens), control=control, source_directory=RUNTIME_DIR, qa_path=QA_PATH)


def forbidden(*args, **kwargs):
    raise AssertionError("native/transport/signal operation forbidden in offline test")


def canonical_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def synthetic_capture(control="normal_ready_stop"):
    """Internally consistent invented data, never a copied native witness."""
    config = fixture()[0]
    birth = [401, 1234, 500]
    bsd = bytearray(136)
    struct.pack_into("<I", bsd, 4, 4)
    struct.pack_into("<I", bsd, 12, birth[0])
    struct.pack_into("<QQ", bsd, 120, *birth[1:])
    process = {"path": "/private/var/mnt/rootfs/usr/local/libexec/macws-swap-pair-probe-20261017/probe.arm64",
               "birth_private": list(birth), "stopped": True, "native_status_private": 4, "native_status_name": "SSTOP",
               "state_source": "proc_bsdinfo.pbi_status", "raw_bsdinfo_private_hex": bytes(bsd).hex(),
               "raw_bsdinfo_sha256": hashlib.sha256(bsd).hexdigest(), "returned_bsdinfo_bytes": 136, "bsdinfo_errno": 0}
    ready = {"schema": "macws.own-swap-pair.ready.v2", "phase": "before_GetMainDisplay", "profile_sha256": config["profile_sha256"],
             "loaded_hook_profile_architecture": "arm64", "loaded_hook_profile_uuid": "2552c7f2-0946-3525-9771-d6d48b44c0e9",
             "hook_uuid_code_gates_passed": True, "pair_invoked": False, "runtime_accepted": False}
    trigger = {"normal_ready_stop": "controller_done", "parent_pipe_EOF": "parent_loss_or_invalid_control", "active_deadline": "active_deadline"}[control]
    run = {"bootstraps": 1, "resumes": 1, "second_resumes": 0, "C_ready_verified": True, "C_ready_private": ready,
           "birth_private": birth, "initial_process_private": copy.deepcopy(process), "C_ready_process_private": copy.deepcopy(process)}
    cleanup = {"own_job_absent": True, "bootout_calls": 1, "known_generation_absent": True,
               "generation_absence_evidence_private": {"api": "proc_pidinfo", "flavor": 3, "requested_bytes": 136, "returned": 0,
                                                       "errno": 3, "outcome": "ESRCH", "pid_private": birth[0], "expected_birth_private": list(birth)}}
    watch = {"ready": True, "trigger": trigger, "cleanup_verified": True, "cleanup": cleanup, "samples": 1,
             "seconds": 10 if control == "active_deadline" else .5, "active_alarm_fired": control == "active_deadline",
             "deadline_mechanism": "SIGALRM" if control == "active_deadline" else None,
             "owned_log_private": json.dumps(ready) + "\n"}
    full = {"schema": "macws.swap-pair.live-controller.v7", "operation": p.CONTROLS[control], "source_sha256": dict(p.SOURCES),
            "clock_info": dict(config["clock_info"]), "device_acceptance": False, "driver_state_cancelled": False,
            "cleanup_verified": True, "pair_capture_accepted": False, "control_capture_accepted": True, "freeze_fix": False,
            "independent_watchdog_ready_before_bootstrap": True, "run_private": run, "watchdog_private": watch, "completed_monotonic_private": 110}
    outer = {"schema": "macws.swap-pair.explicit-device-call.v7", "control": control, "operation": p.CONTROLS[control],
             "source_sha256": dict(p.SOURCES), "device_acceptance": False, "freeze_fix": False, "full_report_returned": True,
             "accepted_scoped_capture": True, "clock_info": dict(config["clock_info"]), "full_private_report": full,
             "completed_monotonic_private": 111}
    refresh_synthetic_receipt(outer, config)
    return config, outer


def refresh_synthetic_receipt(outer, config):
    """Re-encode a tampered fixture, so tests do not rely on hash mismatch alone."""
    full = outer["full_private_report"]; run = full["run_private"]; watch = full["watchdog_private"]
    projection = {"schema": "macws.swap-pair.stopped-control-witness.v7", "operation": outer["operation"],
                  "source_sha256": dict(p.SOURCES), "full_private_report_sha256": canonical_sha(full),
                  "independent_watchdog_ready_before_bootstrap": full["independent_watchdog_ready_before_bootstrap"],
                  "control_capture_accepted": full["control_capture_accepted"], "pair_capture_accepted": full["pair_capture_accepted"],
                  "device_acceptance": full["device_acceptance"], "cleanup_verified": full["cleanup_verified"],
                  "run": copy.deepcopy(run),
                  "watchdog": {key: copy.deepcopy(watch[key]) for key in ("ready", "trigger", "cleanup_verified", "cleanup", "samples", "seconds", "active_alarm_fired", "deadline_mechanism")},
                  "final_C_result_observed": False}
    outer["native_control_receipt"] = {"schema": "macws.swap-pair.native-stopped-control.v7", "control": outer["control"],
                                       "operation": outer["operation"], "accepted": True, "native_job_used": True, "simulation_only": False,
                                       "raw_sha256": canonical_sha(projection), "raw_witness": projection, "source_sha256": dict(p.SOURCES),
                                       "admission_sha256": canonical_sha({key: value for key, value in config.items() if key != "operation"}),
                                       "run_nonce": config["run_nonce"], "boot_private": config["boot_private"], "observed_monotonic": 112,
                                       "first_resumes": run["resumes"], "second_resumes": run["second_resumes"], "C_ready_verified": run["C_ready_verified"],
                                       "cleanup_verified": full["cleanup_verified"], "trigger": watch["trigger"]}


def decode_capture(config, outer, **overrides):
    args = dict(stdout=raw(outer), stderr=b"", returncode=0, timed_out=False, control=outer["control"], expected_config_raw=raw(config))
    args.update(overrides)
    return p.decode_transport_result(**args)




class FakeClock:
    def __init__(self):
        self.profile = {"domain": "mach_absolute_time.absolute_seconds.v1", "numer": 125, "denom": 3}
    def now(self):
        return 10000


def run_synthetic_payload(source, tokens, *, execute_error=False, mutate_source=False, wrong_token=False):
    """Compile the actual payload; redirect only fixed source reads to local files.

    Native imports remain prohibited. The optional execute replacement is an
    explicit in-memory synthetic failure seam installed after source compile.
    """
    real_open, real_fstat, real_read = os.open, os.fstat, os.read
    names, executed = {}, []
    original_tokens = copy.deepcopy(tokens)
    def open_local(path, flags, *args):
        if not str(path).startswith(p.DIRECTORY + "/"):
            raise AssertionError("unexpected payload source path")
        name = str(path).split("/")[-1]
        fd = real_open(RUNTIME_DIR / name, flags, *args)
        names[fd] = name
        return fd
    def stat_local(fd):
        info = real_fstat(fd)
        token = original_tokens[names[fd]]
        return SimpleNamespace(st_dev=token["dev"], st_ino=token["ino"] + int(wrong_token), st_size=token["size"],
                               st_mtime_ns=token["mtime_ns"], st_ctime_ns=token["ctime_ns"],
                               st_uid=0, st_nlink=1, st_mode=stat_mode(info.st_mode))
    def read_local(fd, count):
        data = real_read(fd, count)
        return (bytes([data[0] ^ 1]) + data[1:]) if mutate_source and data else data
    def module_exec(code, globals):
        executed.append(code.co_filename)
        builtins.exec(code, globals)
        if code.co_filename.endswith("/runtime_support.py"):
            globals["NativeSharedClock"] = FakeClock
            globals["source_binding"] = lambda: dict(p.SOURCES)
        if code.co_filename.endswith("/controller.py") and execute_error:
            fake = """def execute(config, receipts, *, native_clock_factory):
 report={"schema":"macws.swap-pair.live-controller.v7","source_sha256":dict(EXPECTED),"operation":config["operation"],"run_private":{"bootstraps":1}}
 assert native_clock_factory().now()==10000
 raise OSError(9,"synthetic execute failure after partial report")
"""
            space = {"EXPECTED": p.SOURCES}
            builtins.exec(compile(fake, code.co_filename, "exec"), space)
            globals["execute"] = space["execute"]
    output = io.StringIO()
    with patch.dict(sys.modules), patch.dict(os.environ), \
            patch.object(os, "open", open_local), patch.object(os, "fstat", stat_local), patch.object(os, "read", read_local), \
            patch.object(ctypes, "CDLL", forbidden), patch.object(subprocess, "Popen", forbidden), \
            patch.object(subprocess, "run", forbidden), patch.object(os, "kill", forbidden), \
            patch.object(signal, "signal", forbidden), patch.object(signal, "alarm", forbidden), patch.object(signal, "setitimer", forbidden), redirect_stdout(output):
        builtins.exec(compile(source, "<synthetic-prepared-v7-payload>", "exec"), {"exec": module_exec})
    return json.loads(output.getvalue()), executed


def stat_mode(mode):
    return (mode & ~0o777) | 0o600


class BuilderTests(unittest.TestCase):
    def test_default_has_no_transport_native_or_file_loading(self):
        capture = io.StringIO()
        with patch.object(p, "pinned_support", forbidden), patch.object(p, "bounded_regular", forbidden), \
                patch.object(ctypes, "CDLL", forbidden), patch.object(subprocess, "Popen", forbidden), \
                patch.object(subprocess, "run", forbidden), patch.object(os, "kill", forbidden), \
                patch.object(signal, "signal", forbidden), patch.object(signal, "alarm", forbidden), patch.object(signal, "setitimer", forbidden), redirect_stdout(capture):
            self.assertEqual(p.main([]), 0)
        meta = json.loads(capture.getvalue())
        self.assertIs(meta["current_device_freshness_claimed"], False)
        self.assertIs(meta["transport_provided"], False)
        self.assertIs(meta["active_pair_payload_supported"], False)
        self.assertEqual(meta["device_commands"], 0)

    def test_all_three_payloads_compile_and_preserve_inputs_without_age_claim(self):
        cfg, rec, tok = fixture()
        before = copy.deepcopy((cfg, rec, tok))
        for control, operation in p.CONTROLS.items():
            source, report = build(cfg, rec, tok, control)
            compile(source, "<compile-only-test>", "exec")
            self.assertLessEqual(len(source), p.MAX_SOURCE_BYTES)
            self.assertEqual(report["operation"], operation)
            self.assertEqual(report["stdin_source_sha256"], hashlib.sha256(source).hexdigest())
            self.assertIs(report["receipt_freshness_checked"], False)
            self.assertIs(report["requires_live_native_revalidation"], True)
            self.assertNotIn(b".v6", source)
        self.assertEqual((cfg, rec, tok), before)

    def test_inputs_or_output_without_explicit_build_refuse(self):
        for flag in ("--config", "--receipts", "--tokens", "--output", "--source-directory", "--qa-path"):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                p.main([flag, "not-read"])

    def test_explicit_alternate_pinned_directory_and_qa_path_produce_identical_payload(self):
        cfg, rec, tok = fixture(); expected, _ = build(cfg, rec, tok)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); sources = root / "explicit-sources"; sources.mkdir()
            for name in p.SOURCES: shutil.copyfile(RUNTIME_DIR / name, sources / name)
            qa = root / "explicit-canonical-qa.json"; shutil.copyfile(QA_PATH, qa)
            source, report = p.build_control_payload(config_raw=raw(cfg), receipts_raw=raw(rec), tokens_raw=raw(tok),
                                                    control="normal_ready_stop", source_directory=sources, qa_path=qa)
            self.assertEqual(source, expected)
            self.assertIs(report["current_device_freshness_claimed"], False)

    def test_explicit_modified_source_or_qa_refuses_before_module_execution(self):
        cfg, rec, tok = fixture()
        for target in ("controller.py", "QA"):
            with tempfile.TemporaryDirectory() as directory:
                sources = Path(directory) / "sources"; sources.mkdir()
                for name in p.SOURCES: shutil.copyfile(RUNTIME_DIR / name, sources / name)
                qa = Path(directory) / "qa.json"; shutil.copyfile(QA_PATH, qa)
                changed = qa if target == "QA" else sources / target
                changed.write_bytes(changed.read_bytes() + b"\n")
                with self.subTest(target=target), patch.object(builtins, "exec", forbidden), self.assertRaises(ValueError):
                    p.build_control_payload(config_raw=raw(cfg), receipts_raw=raw(rec), tokens_raw=raw(tok),
                                            control="normal_ready_stop", source_directory=sources, qa_path=qa)

    def test_missing_explicit_paths_never_fall_back_to_private_sources(self):
        cfg, rec, tok = fixture()
        for source_directory, qa_path in ((None, QA_PATH), (RUNTIME_DIR, None), (None, None)):
            with self.subTest(source_directory=source_directory, qa_path=qa_path), patch.object(p, "bounded_regular", forbidden), self.assertRaises(ValueError):
                p.build_control_payload(config_raw=raw(cfg), receipts_raw=raw(rec), tokens_raw=raw(tok), control="normal_ready_stop",
                                        source_directory=source_directory, qa_path=qa_path)

    def test_active_and_unknown_controls_are_impossible(self):
        for control in (None, "run", "active_pair", "", True):
            with self.subTest(control=control), self.assertRaises(ValueError):
                build(control=control)

    def test_v6_config_and_receipts_refuse(self):
        config, receipts, tokens = fixture()
        config["schema"] = "macws.swap-pair.live-config.v6"
        with self.assertRaises(ValueError): build(config, receipts, tokens)
        config, receipts, tokens = fixture()
        receipts["schema"] = "macws.swap-pair.live-prerequisites.v6"
        with self.assertRaises(RuntimeError): build(config, receipts, tokens)

    def test_old_control_receipts_and_source_drift_refuse(self):
        cfg, rec, tok = fixture()
        rec["native_controls"] = {"normal_ready_stop": {"accepted": True}}
        with self.assertRaises(RuntimeError): build(cfg, rec, tok)
        cfg, rec, tok = fixture()
        rec["preflight"]["source_sha256"] = dict(p.SOURCES, **{"controller.py": "0" * 64})
        with self.assertRaises(ValueError): build(cfg, rec, tok)

    def test_config_or_receipt_source_mismatch_refuses_before_module_execution(self):
        for target in ("config", "preflight", "signed_artifact", "loaded_hook_profile"):
            cfg, rec, tok = fixture()
            if target == "config": cfg["source_sha256"] = {}
            else: rec[target]["source_sha256"] = {}
            with self.subTest(target=target), patch.object(builtins, "exec", forbidden), self.assertRaises(ValueError):
                p.build_control_payload(config_raw=raw(cfg), receipts_raw=raw(rec), tokens_raw=raw(tok), control="normal_ready_stop", source_directory=RUNTIME_DIR, qa_path=QA_PATH)

    def test_token_mismatch_refuses_before_support_module_execution(self):
        cfg, rec, tok = fixture()
        for changed in ({}, dict(tok, extra={}), dict(tok, **{"controller.py": dict(tok["controller.py"], size=1)}),
                        dict(tok, **{"controller.py": dict(tok["controller.py"], ino=True)})):
            with self.subTest(tokens=changed), patch.object(builtins, "exec", forbidden), self.assertRaises(ValueError):
                p.build_control_payload(config_raw=raw(cfg), receipts_raw=raw(rec), tokens_raw=raw(changed), control="normal_ready_stop", source_directory=RUNTIME_DIR, qa_path=QA_PATH)

    def test_frozen_source_mismatch_refuses_before_module_execution(self):
        cfg, rec, tok = fixture()
        reader = p.bounded_regular
        def changed(path, limit):
            data = reader(path, limit)
            return data + b"\n" if str(path).endswith("controller.py") else data
        with patch.object(p, "bounded_regular", changed), patch.object(builtins, "exec", forbidden), self.assertRaisesRegex(ValueError, "source mismatch"):
            p.build_control_payload(config_raw=raw(cfg), receipts_raw=raw(rec), tokens_raw=raw(tok), control="normal_ready_stop", source_directory=RUNTIME_DIR, qa_path=QA_PATH)

    def test_json_duplicate_nonfinite_and_oversize_refuse(self):
        for value in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}', b'[]', b'', b' ' * (p.MAX_INPUT_BYTES + 1)):
            with self.subTest(value=value[:30]), self.assertRaises(ValueError): p.strict_json(value)

    def test_qa_artifact_admission_and_clock_bindings_refuse(self):
        for section, field, value in (("offline_QA", "raw_sha256", "0" * 64),
                                      ("signed_artifact", "new_vnode", False),
                                      ("preflight", "admission_sha256", "0" * 64),
                                      ("loaded_hook_profile", "clock_info", {"domain": "wrong", "numer": 1, "denom": 1})):
            cfg, rec, tok = fixture(); rec[section][field] = value
            with self.subTest(section=section, field=field), self.assertRaises(RuntimeError): build(cfg, rec, tok)


class CompiledPayloadTests(unittest.TestCase):
    def test_execute_error_retains_exact_source_bound_partial_traceback_and_null_unknowns(self):
        source, _ = build(); tokens = fixture()[2]
        observed, executed = run_synthetic_payload(source, tokens, execute_error=True)
        self.assertEqual(len(executed), 2)
        self.assertIs(observed["accepted_scoped_capture"], False)
        self.assertIs(observed["full_report_returned"], False)
        self.assertEqual(observed["partial_private_report"]["run_private"]["bootstraps"], 1)
        self.assertIn("synthetic execute failure", observed["traceback_private"])
        summary = p.report_summary(observed)
        self.assertEqual(summary["bootstraps"], 1)
        self.assertIsNone(summary["resumes"])
        self.assertIsNone(summary["second_resumes"])
        self.assertIsNone(summary["cleanup_verified"])

    def test_source_hash_failure_precedes_every_module_and_clock_execution(self):
        source, _ = build()
        observed, executed = run_synthetic_payload(source, fixture()[2], mutate_source=True)
        self.assertEqual(executed, [])
        self.assertIn("source hash changed", observed["caller_error_private"])
        self.assertNotIn("clock_info", observed)
        self.assertIsNone(p.report_summary(observed)["bootstraps"])

    def test_delivery_token_failure_precedes_every_module_and_clock_execution(self):
        source, _ = build()
        observed, executed = run_synthetic_payload(source, fixture()[2], wrong_token=True)
        self.assertEqual(executed, [])
        self.assertIn("delivery token changed", observed["caller_error_private"])
        self.assertNotIn("clock_info", observed)

    def test_actual_v7_execute_refuses_stale_receipt_with_synthetic_live_clock_before_jobs(self):
        source, _ = build()
        observed, executed = run_synthetic_payload(source, fixture()[2])
        self.assertEqual(len(executed), 2)
        self.assertIn("stale/future receipt", observed["caller_error_private"])
        self.assertIn("validate_prerequisites", observed["traceback_private"])
        self.assertNotIn("partial_private_report", observed)
        self.assertIsNone(p.report_summary(observed)["bootstraps"])

    def test_partial_report_from_different_function_or_source_is_not_promoted(self):
        def execute():
            report = {"schema": "macws.swap-pair.live-controller.v7", "operation": "control_normal", "source_sha256": dict(p.SOURCES)}
            raise RuntimeError("synthetic unrelated execute")
        try:
            execute()
        except RuntimeError as error:
            for expected_code, expected_sources, operation in ((None, p.SOURCES, "control_normal"),
                                                              (execute.__code__, {}, "control_normal"),
                                                              (execute.__code__, p.SOURCES, "control_deadline")):
                captured = p.preserve_execute_failure(error, expected_sources, operation, expected_code)
                self.assertNotIn("partial_private_report", captured)


class TransportEnvelopeTests(unittest.TestCase):
    def negative(self):
        source, _ = build()
        return run_synthetic_payload(source, fixture()[2], execute_error=True)[0]

    def test_negative_nonzero_exit_retains_complete_private_partial_report(self):
        observed = self.negative()
        result = p.decode_transport_result(stdout=raw(observed), stderr=b"warning\n", returncode=1, timed_out=False, control="normal_ready_stop")
        self.assertEqual(json.loads(base64.b64decode(result["stdout_private_b64"])), observed)
        self.assertEqual(base64.b64decode(result["stderr_private_b64"]), b"warning\n")
        self.assertEqual(result["summary"]["bootstraps"], 1)
        self.assertIsNone(result["summary"]["resumes"])
        self.assertIs(result["accepted_scoped_capture"], False)

    def test_timeout_keeps_partial_output_and_never_asserts_zero_effect_or_cleanup(self):
        result = p.decode_transport_result(stdout=b'{"schema":', stderr=b"", returncode=None, timed_out=True, control="normal_ready_stop")
        self.assertEqual(base64.b64decode(result["stdout_private_b64"]), b'{"schema":')
        self.assertTrue(result["parse_error_private"])
        for key in ("bootstraps", "resumes", "second_resumes", "cleanup_verified"):
            self.assertIsNone(result["summary"][key])
        self.assertIs(result["accepted_scoped_capture"], False)

    def test_timeout_overrides_complete_claimed_success_without_discarding_report(self):
        observed = self.negative(); observed["accepted_scoped_capture"] = True; observed["full_report_returned"] = True
        result = p.decode_transport_result(stdout=raw(observed), stderr=b"", returncode=0, timed_out=True, control="normal_ready_stop")
        self.assertIn("private_caller_report", result)
        self.assertIs(result["accepted_scoped_capture"], False)

    def test_v6_wrong_operation_or_source_never_promotes_counters(self):
        for key, value in (("schema", "macws.swap-pair.explicit-device-call.v6"), ("operation", "run"), ("source_sha256", {})):
            observed = self.negative(); observed[key] = value
            result = p.decode_transport_result(stdout=raw(observed), stderr=b"", returncode=0, timed_out=False, control="normal_ready_stop")
            self.assertIn("parse_error_private", result)
            self.assertIsNone(result["summary"]["bootstraps"])

    def test_nested_partial_source_mismatch_does_not_promote_counters(self):
        observed = self.negative(); observed["partial_private_report"]["source_sha256"] = {}
        result = p.decode_transport_result(stdout=raw(observed), stderr=b"", returncode=0, timed_out=False, control="normal_ready_stop")
        self.assertIn("parse_error_private", result)
        self.assertIsNone(result["summary"]["bootstraps"])

    def test_oversize_transport_and_untyped_timeout_refuse(self):
        for kwargs in ({"stdout": b"x" * (p.MAX_STDOUT_BYTES + 1)}, {"stderr": b"x" * (p.MAX_STDERR_BYTES + 1)}, {"timed_out": 0}):
            defaults = dict(stdout=b"", stderr=b"", returncode=0, timed_out=False, control="normal_ready_stop")
            defaults.update(kwargs)
            with self.assertRaises(ValueError): p.decode_transport_result(**defaults)

    def test_duplicate_or_nonfinite_output_is_preserved_but_not_interpreted(self):
        for stdout in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}'):
            result = p.decode_transport_result(stdout=stdout, stderr=b"", returncode=0, timed_out=False, control="normal_ready_stop")
            self.assertEqual(base64.b64decode(result["stdout_private_b64"]), stdout)
            self.assertIn("parse_error_private", result)
            self.assertIsNone(result["summary"]["bootstraps"])


class CaptureConsistencyTests(unittest.TestCase):
    def assert_refuses(self, config, outer):
        result = decode_capture(config, outer)
        self.assertIs(result["accepted_scoped_capture"], False)
        self.assertIs(result["internally_consistent_capture"], False)
        self.assertIn("capture_consistency_error_private", result)
        self.assertIn("private_caller_report", result)
        return result

    def test_all_controls_can_be_internally_consistent_without_freshness_or_authenticity_claims(self):
        for control in p.CONTROLS:
            config, outer = synthetic_capture(control)
            with self.subTest(control=control), patch.object(ctypes, "CDLL", forbidden), patch.object(subprocess, "Popen", forbidden), \
                    patch.object(subprocess, "run", forbidden), patch.object(os, "kill", forbidden), patch.object(signal, "alarm", forbidden), patch.object(signal, "setitimer", forbidden):
                result = decode_capture(config, outer)
            self.assertIs(result["accepted_scoped_capture"], True)
            self.assertIs(result["internally_consistent_capture"], True)
            self.assertIs(result["current_device_freshness_claimed"], False)
            self.assertIs(result["native_evidence_authenticity_verified"], False)
            self.assertIs(result["device_acceptance"], False)


    def test_positive_without_explicit_context_refuses(self):
        config, outer = synthetic_capture()
        result = decode_capture(config, outer, expected_config_raw=None)
        self.assertIs(result["accepted_scoped_capture"], False)
        self.assertIn("expected admission context", result["capture_consistency_error_private"])

    def test_full_boolean_integer_aliases_refuse_even_with_recomputed_receipt(self):
        for key, value in (("control_capture_accepted", 1), ("pair_capture_accepted", 0), ("device_acceptance", 0),
                           ("freeze_fix", 0), ("driver_state_cancelled", 0), ("cleanup_verified", 1),
                           ("independent_watchdog_ready_before_bootstrap", 1)):
            config, outer = synthetic_capture(); outer["full_private_report"][key] = value; refresh_synthetic_receipt(outer, config)
            with self.subTest(key=key): self.assert_refuses(config, outer)

    def test_run_boolean_integer_aliases_or_second_resume_refuse(self):
        for key, value in (("bootstraps", True), ("resumes", True), ("second_resumes", False), ("second_resumes", 1), ("C_ready_verified", 1)):
            config, outer = synthetic_capture(); outer["full_private_report"]["run_private"][key] = value; refresh_synthetic_receipt(outer, config)
            with self.subTest(key=key, value=value): self.assert_refuses(config, outer)

    def test_missing_receipt_or_changed_session_source_control_operation_refuses(self):
        config, outer = synthetic_capture(); del outer["native_control_receipt"]; self.assert_refuses(config, outer)
        for key, value in (("schema", "macws.swap-pair.native-stopped-control.v6"), ("source_sha256", {}), ("control", "active_deadline"),
                           ("operation", "run"), ("run_nonce", "b" * 32), ("boot_private", "99999999-2222-3333-4444-555555555555"),
                           ("admission_sha256", "0" * 64), ("accepted", 1), ("native_job_used", 1), ("simulation_only", 0)):
            config, outer = synthetic_capture(); outer["native_control_receipt"][key] = value
            with self.subTest(key=key): self.assert_refuses(config, outer)

    def test_raw_digest_projection_and_full_report_hash_must_all_agree(self):
        for mutation in ("raw_digest", "full_digest", "projection", "full_report"):
            config, outer = synthetic_capture(); item = outer["native_control_receipt"]
            if mutation == "raw_digest": item["raw_sha256"] = "0" * 64
            elif mutation == "full_digest":
                item["raw_witness"]["full_private_report_sha256"] = "0" * 64
                item["raw_sha256"] = canonical_sha(item["raw_witness"])
            elif mutation == "projection":
                item["raw_witness"]["run"]["bootstraps"] = 99
                item["raw_sha256"] = canonical_sha(item["raw_witness"])
            else: outer["full_private_report"]["extra_private_note"] = "different exact report"
            with self.subTest(mutation=mutation): self.assert_refuses(config, outer)

    def test_projection_bool_alias_with_unchanged_digest_refuses(self):
        config, outer = synthetic_capture()
        # Python compares True == 1; canonical JSON bytes must still differ.
        outer["native_control_receipt"]["raw_witness"]["run"]["resumes"] = True
        self.assert_refuses(config, outer)

    def test_unrepresentable_capture_time_refuses_without_losing_private_report(self):
        config, outer = synthetic_capture()
        outer["native_control_receipt"]["observed_monotonic"] = 10**1000
        self.assert_refuses(config, outer)

    def test_native_bsd_status_birth_path_and_digest_are_checked_after_hash_refresh(self):
        for field, value in (("path", "/wrong/probe"), ("native_status_private", 2), ("stopped", 1),
                             ("returned_bsdinfo_bytes", True), ("raw_bsdinfo_sha256", "0" * 64)):
            config, outer = synthetic_capture(); outer["full_private_report"]["run_private"]["C_ready_process_private"][field] = value
            refresh_synthetic_receipt(outer, config)
            with self.subTest(field=field): self.assert_refuses(config, outer)
        config, outer = synthetic_capture(); proc = outer["full_private_report"]["run_private"]["C_ready_process_private"]
        bsd = bytearray.fromhex(proc["raw_bsdinfo_private_hex"]); struct.pack_into("<I", bsd, 4, 2)
        proc["raw_bsdinfo_private_hex"] = bytes(bsd).hex(); proc["raw_bsdinfo_sha256"] = hashlib.sha256(bsd).hexdigest()
        refresh_synthetic_receipt(outer, config); self.assert_refuses(config, outer)

    def test_cleanup_and_watchdog_boolean_aliases_or_wrong_esrch_refuse(self):
        for target, key, value in (("watch", "ready", 1), ("watch", "samples", True), ("watch", "active_alarm_fired", 0),
                                   ("cleanup", "own_job_absent", 1), ("cleanup", "known_generation_absent", 1), ("cleanup", "bootout_calls", True),
                                   ("absence", "errno", 1), ("absence", "returned", False), ("absence", "pid_private", 999)):
            config, outer = synthetic_capture(); watch = outer["full_private_report"]["watchdog_private"]
            obj = watch if target == "watch" else watch["cleanup"] if target == "cleanup" else watch["cleanup"]["generation_absence_evidence_private"]
            obj[key] = value; refresh_synthetic_receipt(outer, config)
            with self.subTest(target=target, key=key): self.assert_refuses(config, outer)

    def test_active_deadline_requires_consistent_mechanism_and_duration(self):
        config, outer = synthetic_capture("active_deadline"); watch = outer["full_private_report"]["watchdog_private"]
        watch["active_alarm_fired"] = False; watch["deadline_mechanism"] = "monotonic_deadline"; refresh_synthetic_receipt(outer, config)
        self.assertIs(decode_capture(config, outer)["accepted_scoped_capture"], True)
        for key, value in (("seconds", 9.5), ("trigger", "controller_done"), ("deadline_mechanism", "unknown")):
            config, outer = synthetic_capture("active_deadline"); outer["full_private_report"]["watchdog_private"][key] = value
            refresh_synthetic_receipt(outer, config)
            with self.subTest(key=key): self.assert_refuses(config, outer)

    def test_duplicate_ready_or_final_c_result_in_log_refuses(self):
        for extra in ("ready", "final"):
            config, outer = synthetic_capture(); watch = outer["full_private_report"]["watchdog_private"]
            watch["owned_log_private"] += watch["owned_log_private"] if extra == "ready" else '{"get_main_status":0}\n'
            refresh_synthetic_receipt(outer, config)
            with self.subTest(extra=extra): self.assert_refuses(config, outer)

    def test_capture_time_order_is_internal_only_and_never_uses_current_clock(self):
        import time
        config, outer = synthetic_capture()
        outer["full_private_report"]["completed_monotonic_private"] = 10**12
        outer["completed_monotonic_private"] = 10**12 + 1
        refresh_synthetic_receipt(outer, config); outer["native_control_receipt"]["observed_monotonic"] = 10**12 + 2
        with patch.object(time, "time", forbidden), patch.object(time, "monotonic", forbidden), patch.object(time, "perf_counter", forbidden):
            result = decode_capture(config, outer)
        self.assertIs(result["internally_consistent_capture"], True)
        self.assertIs(result["current_device_freshness_claimed"], False)
        outer["native_control_receipt"]["observed_monotonic"] = 0
        self.assert_refuses(config, outer)

    def test_transport_timeout_stderr_or_nonzero_exit_overrides_consistent_capture(self):
        for changes in ({"timed_out": True}, {"stderr": b"warning\n"}, {"returncode": 1}, {"returncode": None}):
            config, outer = synthetic_capture()
            with self.subTest(changes=changes): result = decode_capture(config, outer, **changes)
            self.assertIs(result["internally_consistent_capture"], True)
            self.assertIs(result["accepted_scoped_capture"], False)
            self.assertEqual(result["summary"]["bootstraps"], 1)

    def test_incomplete_wrong_source_or_bool_clock_context_refuses(self):
        for mutation in ("missing", "source", "clock"):
            config, outer = synthetic_capture()
            if mutation == "missing": del config["signed_probe_uuid"]
            elif mutation == "source": config["source_sha256"] = {}
            else: config["clock_info"]["numer"] = True
            with self.subTest(mutation=mutation): self.assert_refuses(config, outer)


if __name__ == "__main__":
    unittest.main()
