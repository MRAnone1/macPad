"""Invented coherent historical fixtures; no device or network dispatch."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
MISC = HERE
SOURCES = MISC / "macws_swap_pair"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


c = load("synthetic_retained_inputs", SOURCES / "retained_inputs.py")
f = load("synthetic_retained_historical_fixture", MISC / "test_macws_process_retirement.py")


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def encoded(values):
    return {name: c.canonical(value) for name, value in values.items()}


def fixture():
    """All boot/birth/content objects below are invented, never native receipts."""
    config, report, delivery = f.fixture()
    original = f.c.validate_original(config, report, delivery, source_directory=SOURCES)
    backend = f.FakeBackend(original)
    core = f.c.observe_or_retire(original, backend, deadline=108, execute=True,
                                read_regular=backend.read_regular)
    assert core["process_retired"] is True
    # Complete the invented five-file delivery with distinct invented directories.
    cleanup = c._load_module(SOURCES, "cleanup_payload.py", c.CLEANUP_SHA256)
    delivery.update({key: False for key in ("automatic_cleanup_attempted", "current_trust_verified",
        "native_dependency_closure_currently_verified", "device_acceptance", "runtime_accepted",
        "freeze_cause_or_fix_proven")})
    delivery["created_directories_private"] = []
    delivery["parents_private"] = []
    for index, directory in enumerate(cleanup.DIRECTORIES):
        token = {"dev": 7, "ino": 800 + index, "size": 64, "mtime_ns": 3000,
                 "ctime_ns": 4000, "mode": 0o700, "uid": 0, "gid": 0, "nlink": 2}
        delivery["created_directories_private"].append({"path": directory, "stat": token})
        parent = directory.rsplit("/", 1)[0]
        delivery["parents_private"].append({"logical": parent,
            "resolved": "/private/synthetic-root/usr/libexec" if parent.startswith("/var/jb/") else parent,
            "stat": dict(token, ino=850 + index), "target_previously_absent": True})
    rs = original.runtime
    service = rs.service_identifier(original.config)
    run = dict(original.config, operation="run")
    other = rs.service_identifier(run)
    absent = [113, "", 'Could not find service "' + rs.job_label(run) + '" in domain for uid: 501\n']
    jobs = core["job_observations_private"]
    reads = (["/bin/ps", "-eo", "pid,comm"], [rs.JBCTL, "trustcache", "info"],
             [rs.LAUNCHCTL, "print", other], [rs.LAUNCHCTL, "print", service])
    commands = []
    def add(argv, result=(0, "", "")):
        commands.append({"argv_private": argv, "attempted": True, "result_known": True,
            "returncode": result[0], "stdout_private_b64": b64(result[1].encode()),
            "stderr_private_b64": b64(result[2].encode())})
    def phase(job):
        for index, argv in enumerate(reads):
            add(argv, absent if index == 2 else job if index == 3 else (0, "synthetic\n", ""))
    phase(jobs[0]); add(reads[3], jobs[0])
    phase(jobs[1]); add(reads[3], jobs[1])
    add([rs.LAUNCHCTL, "kill", "SIGKILL", service])
    phase(jobs[2]); add([rs.LAUNCHCTL, "bootout", service])
    phase(jobs[3])
    worker = {"schema": "macws.process-retirement.worker.private.v1", "core_sha256": c.CORE_SHA256,
        "execute_requested": True, "process_retired": True, "exclusive_writer_assumed": True,
        "native_backend_constructed": True, "service_check_and_action_atomic": False,
        "clock_info": config["clock_info"].copy(), "cleanup_verified": False,
        "device_acceptance": False, "freeze_fix": False, "started_monotonic_private": 100.0,
        "finished_monotonic_private": 100.5, "core_result_private": core,
        "summary": f.c.public_summary(core), "commands_private": commands}
    expected = {"job.plist": rs.plist_bytes(original.config), "probe.log": b"synthetic retained log\n"}
    rows = {}
    for index, (name, raw) in enumerate(expected.items()):
        rows[name] = {"path_private": rs.scratch_path(original.config) + "/" + name,
            "mode": 0o600, "uid": 0, "gid": 0, "bytes": len(raw), "sha256": c.digest(raw),
            "raw_private_b64": b64(raw), "token_private": [7, 910 + index, len(raw), 3000, 4000]}
    rows["job.plist"]["matches_config_derived_plist"] = True
    obs = {key: True for key in ("UI_matches_session", "boot_matches_session",
        "candidate_token_matches_delivery", "same_initial_birth", "same_initial_path")}
    obs.update(thermal=0, process_private=copy.deepcopy(original.initial))
    snapshot = {"schema": "macws.swap-pair.readonly-owned-state.private.v7", "observation_completed": True,
        "installed_source_sha256": config["source_sha256"].copy(), "cleanup_authorized": False,
        "device_acceptance": False, "freeze_fix": False, "original_file_ownership_recovered": False,
        "candidate_executions": 0, "mutations": 0, "signals_to_other_processes": 0, "trust_mutations": 0,
        "before_private": copy.deepcopy(obs), "after_private": copy.deepcopy(obs),
        "scratch_private": {rs.scratch_path(run): {"present": False}, rs.scratch_path(original.config): {
            "present": True, "current_observation_only_not_original_ownership": True,
            "mode": 0o700, "uid": 0, "gid": 0, "current_token_private": [7, 900, 64, 3000, 4000],
            "files_private": rows}}}
    config_raw, wire_raw = c.canonical(config), c.canonical(report)
    nested = {"schema": "macws.swap-pair.control-transport-envelope.v7", "timed_out": False,
        "returncode": 0, "output_structure_checked": True, "private_caller_report": copy.deepcopy(report),
        "stdout_private_b64": b64(wire_raw), "stdout_sha256": c.digest(wire_raw),
        "stderr_private_b64": "", "stderr_sha256": c.digest(b"")}
    host = {"schema": "macws.swap-pair.normal-control-transport.private.v7", "operation": "control_normal",
        "control": "normal_ready_stop", "decoded_private": nested,
        "transport_private": {"capture_complete": True, "stdin_complete": True, "timed_out": False,
            "output_limit_exceeded": False, "returncode": 0, "local_cleanup_errors_private": []},
        "stdout_private_b64": b64(wire_raw), "stdout_sha256": c.digest(wire_raw),
        "stderr_private_b64": "", "stderr_sha256": c.digest(b""),
        "stdout_bytes_captured": len(wire_raw), "stderr_bytes_captured": 0,
        "input_sha256": {"config_sha256": c.digest(config_raw)}}
    host.update({key: False for key in ("accepted_scoped_capture", "active_pair_route", "automatic_retry",
        "current_device_freshness_claimed", "device_acceptance", "freeze_fix",
        "native_evidence_authenticity_verified", "remote_cleanup_inferred_from_transport")})
    values = {"config": config, "control_wire": report, "host": host, "delivery": delivery,
              "retirement_wire": worker, "snapshot": snapshot}
    # Native report serialization projects command tuples to JSON arrays.
    return json.loads(json.dumps(values)), expected


class InputsTests(unittest.TestCase):
    def setUp(self):
        self.values, self.expected = fixture()

    def build(self, values=None, raw_override=None, patch_pins=True, sources=SOURCES):
        raw = encoded(self.values if values is None else values)
        if raw_override:
            raw.update(raw_override)
        pins = {name: c.digest(value) for name, value in raw.items()} if patch_pins else c.INPUT_PINS
        with patch.object(c, "INPUT_PINS", pins):
            return c.build_inputs(*(raw[name] for name in c.INPUT_PINS), source_directory=sources)

    def rejects(self, mutate):
        mutate(self.values)
        with self.assertRaises((c.Refused, f.c.Refused, ValueError)):
            self.build()

    def test_complete_invented_consistency_uses_real_v7_validator(self):
        result = self.build()
        self.assertTrue(result.intact())
        self.assertIs(type(result.original), result.retirement_core.Original)
        self.assertEqual(result.original.config["operation"], "control_normal")
        self.assertEqual(c.decode(result.original_bytes["config"])["operation"], "run")
        self.assertEqual(result.expected_files, self.expected)
        self.assertEqual(len(result.provenance_base), 7)
        self.assertNotIn("current_wire_sha256", result.provenance_base)
        self.assertEqual(len(result.delivery["created_directories_private"]), 2)

    def test_default_cli_inert(self):
        run = subprocess.run([sys.executable, "-B", str(SOURCES / "retained_inputs.py")],
                             capture_output=True, check=True, timeout=5)
        value = json.loads(run.stdout)
        self.assertEqual(value, c.metadata())
        self.assertEqual(value["native_backends_constructed"], 0)
        self.assertEqual(run.stderr, b"")

    def test_unpatched_real_pins_refuse_invented_data(self):
        with self.assertRaises(c.Refused):
            self.build(patch_pins=False)

    def test_mutating_original_is_detected(self):
        result = self.build()
        result.original.config["run_nonce"] = "b" * 32
        with self.assertRaises(result.retirement_core.Refused):
            result.intact()

    def test_mutating_original_birth_is_detected(self):
        result = self.build()
        result.original.birth[0] += 1
        with self.assertRaises(result.retirement_core.Refused):
            result.intact()

    def test_returned_values_are_copies(self):
        result = self.build()
        context = result.context; context["UI_private"]["SpringBoard"][0] += 1
        context["expected_file_sha256"]["probe.log"] = "a" * 64
        files = result.expected_files; files["probe.log"] = b"changed"
        provenance = result.provenance_base; provenance["original_config_sha256"] = "a" * 64
        delivery = result.delivery; delivery["created_directories_private"] = []
        self.assertTrue(result.intact())
        self.assertEqual(result.expected_files, self.expected)
        self.assertNotEqual(context, result.context)
        self.assertNotEqual(provenance, result.provenance_base)
        self.assertEqual(len(result.delivery["created_directories_private"]), 2)

    def test_no_old_scratch_stat_authority_returned(self):
        result = self.build()
        self.assertEqual(set(result.context), {"boot_private", "config_sha256", "source_sha256",
            "retired_birth_private", "UI_private", "expected_file_sha256", "exclusive_operator"})
        self.assertNotIn("current_token_private", repr(result.context))

    def test_v7_invalid_native_witness_refuses(self):
        def mutate(v):
            v["control_wire"]["full_private_report"]["run_private"]["initial_process_private"]["stopped"] = False
            wire = c.canonical(v["control_wire"])
            for scope in (v["host"], v["host"]["decoded_private"]):
                scope["stdout_private_b64"], scope["stdout_sha256"] = b64(wire), c.digest(wire)
            v["host"]["stdout_bytes_captured"] = len(wire)
            v["host"]["decoded_private"]["private_caller_report"] = copy.deepcopy(v["control_wire"])
        self.rejects(mutate)

    def test_host_wire_replacement_refuses(self):
        self.rejects(lambda v: v["host"].update(stdout_private_b64=b64(b"{}")))

    def test_host_decoded_replacement_refuses(self):
        self.rejects(lambda v: v["host"]["decoded_private"]["private_caller_report"].update(device_acceptance=True))

    def test_host_partial_transport_refuses(self):
        self.rejects(lambda v: v["host"]["transport_private"].update(stdin_complete=False))

    def test_host_returncode_boolean_refuses(self):
        self.rejects(lambda v: v["host"]["transport_private"].update(returncode=False))

    def test_host_size_boolean_refuses(self):
        self.rejects(lambda v: v["host"].update(stderr_bytes_captured=False))

    def test_wrong_original_config_hash_refuses(self):
        self.rejects(lambda v: v["host"]["input_sha256"].update(config_sha256="0" * 64))

    def test_missing_original_delivery_directory_refuses(self):
        self.rejects(lambda v: v["delivery"]["created_directories_private"].pop())

    def test_delivery_file_stat_boolean_refuses(self):
        self.rejects(lambda v: v["delivery"]["installed_files_private"][0]["stat"].update(nlink=True))

    def test_delivery_directory_reused_inode_refuses(self):
        self.rejects(lambda v: v["delivery"]["created_directories_private"][0]["stat"].update(ino=123))

    def test_retirement_edited_success_counter_refuses(self):
        self.rejects(lambda v: v["retirement_wire"]["core_result_private"].update(kill_completed=True))

    def test_retirement_generation_reuse_refuses(self):
        self.rejects(lambda v: v["retirement_wire"]["core_result_private"]["generation_queries_private"][0].update(outcome="reused"))

    def test_retirement_final_job_not_absent_refuses(self):
        self.rejects(lambda v: v["retirement_wire"]["core_result_private"]["job_observations_private"].__setitem__(
            -1, copy.deepcopy(v["retirement_wire"]["core_result_private"]["job_observations_private"][0])))

    def test_retirement_extra_effect_refuses(self):
        self.rejects(lambda v: v["retirement_wire"]["commands_private"][0].update(
            argv_private=["/var/jb/usr/bin/launchctl", "kickstart", "foreign"]))

    def test_retirement_command_noise_refuses(self):
        self.rejects(lambda v: v["retirement_wire"]["commands_private"][10].update(stderr_private_b64=b64(b"noise")))

    def test_retirement_permitted_commands_reordered_refuses(self):
        def mutate(v):
            commands = v["retirement_wire"]["commands_private"]
            commands[0], commands[1] = commands[1], commands[0]
        self.rejects(mutate)

    def test_retirement_native_job_and_core_result_diverge_refuses(self):
        def mutate(v):
            worker = v["retirement_wire"]
            worker["commands_private"][4]["stdout_private_b64"] = b64(
                worker["core_result_private"]["job_observations_private"][0][1].replace(
                    "\tpid = 401\n", "\tpid = 402\n").encode())
        self.rejects(mutate)

    def test_retirement_read_returncode_boolean_refuses(self):
        self.rejects(lambda v: v["retirement_wire"]["commands_private"][0].update(returncode=False))

    def test_retirement_summary_replacement_refuses(self):
        self.rejects(lambda v: v["retirement_wire"]["summary"].update(cleanup_verified=True))

    def test_retirement_clock_bool_refuses(self):
        self.rejects(lambda v: v["retirement_wire"].update(started_monotonic_private=True))

    def test_snapshot_file_changed_refuses(self):
        target = f.c.load_runtime(SOURCES).CONTROL_SCRATCH
        self.rejects(lambda v: v["snapshot"]["scratch_private"][target]["files_private"]["probe.log"].update(raw_private_b64=b64(b"foreign")))

    def test_snapshot_plist_not_effective_control_refuses(self):
        target = f.c.load_runtime(SOURCES).CONTROL_SCRATCH
        def mutate(v):
            raw = b"foreign plist"
            row = v["snapshot"]["scratch_private"][target]["files_private"]["job.plist"]
            row.update(raw_private_b64=b64(raw), bytes=len(raw), sha256=c.digest(raw))
            row["token_private"][2] = len(raw)
        self.rejects(mutate)

    def test_snapshot_foreign_child_refuses(self):
        target = f.c.load_runtime(SOURCES).CONTROL_SCRATCH
        self.rejects(lambda v: v["snapshot"]["scratch_private"][target]["files_private"].update(foreign={}))

    def test_snapshot_promoted_ownership_refuses(self):
        self.rejects(lambda v: v["snapshot"].update(original_file_ownership_recovered=True))

    def test_snapshot_other_absence_boolean_only(self):
        path = f.c.load_runtime(SOURCES).SCRATCH
        self.rejects(lambda v: v["snapshot"]["scratch_private"][path].update(present=0))

    def test_noncanonical_base64_refuses(self):
        self.rejects(lambda v: v["host"].update(stderr_private_b64="===="))

    def test_json_duplicates_refuse(self):
        with self.assertRaises(c.Refused):
            self.build(raw_override={"config": b'{"x":1,"x":2}'})

    def test_bytearray_is_not_original_immutable_bytes(self):
        raw = encoded(self.values)
        pins = {name: c.digest(value) for name, value in raw.items()}
        raw["config"] = bytearray(raw["config"])
        with patch.object(c, "INPUT_PINS", pins), self.assertRaises(c.Refused):
            c.build_inputs(*(raw[name] for name in c.INPUT_PINS), source_directory=SOURCES)

    def test_json_nonfinite_constants_and_overflow_refuse(self):
        for value in (b"NaN", b"Infinity", b"-Infinity", b"1e999", b"-1e999"):
            with self.subTest(value=value), self.assertRaises(c.Refused):
                c.decode(b'{"x":' + value + b'}')

    def test_json_nonfinite_hidden_nested_refuses(self):
        with self.assertRaises(c.Refused):
            c.decode(b'{"safe": true,"unused":{"x":[1e999]}}')

    def test_json_depth_integer_surrogate_and_size_refuse(self):
        for raw in (b'{"x":' + b'[' * 20 + b'0' + b']' * 20 + b'}',
                    b'{"x":9223372036854775808}', b'{"x":"\\ud800"}', b' ' * (c.MAX_RAW + 1)):
            with self.subTest(raw_kind=len(raw)), self.assertRaises(c.Refused):
                c.decode(raw)

    def test_canonical_repeated_strings_share_aggregate_byte_budget(self):
        with patch.object(c, "MAX_RAW", 64), patch.object(c.json, "dumps") as dumps:
            with self.assertRaisesRegex(c.Refused, "bounded_aggregate_json_strings"):
                c.canonical({"x": ["a" * 32] * 3})
            dumps.assert_not_called()

    def test_canonical_ascii_expansion_obeys_complete_byte_budget(self):
        with patch.object(c, "MAX_RAW", 64):
            with self.assertRaisesRegex(c.Refused, "bounded_complete_canonical_json"):
                c.canonical({"x": "\u2603" * 12})

    def test_source_symlink_refuses_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "cleanup_payload.py").symlink_to(SOURCES / "cleanup_payload.py")
            with self.assertRaises(OSError):
                self.build(sources=directory)

    def test_changed_cleanup_source_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "cleanup_payload.py").write_bytes(b"raise RuntimeError('must not execute')\n")
            with self.assertRaisesRegex(c.Refused, "frozen_validation_source"):
                self.build(sources=directory)

    def test_replaced_logical_source_path_refuses_even_same_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            path = directory / "source.py"
            raw = b"reviewed synthetic source\n"
            path.write_bytes(raw)
            replacement = directory / "replacement.py"
            replacement.write_bytes(raw)
            actual_read = c.os.read
            changed = False
            def read_and_replace(fd, amount):
                nonlocal changed
                block = actual_read(fd, amount)
                if not changed:
                    changed = True
                    path.rename(directory / "original-held.py")
                    replacement.rename(path)
                return block
            with patch.object(c.os, "read", side_effect=read_and_replace):
                with self.assertRaisesRegex(c.Refused, "retirement_source_changed_during_read"):
                    c._source_raw(directory, "source.py", c.digest(raw))


if __name__ == "__main__":
    unittest.main()
