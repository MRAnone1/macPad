"""Invented in-memory data only; no current device or session is represented."""
import base64
from contextlib import redirect_stdout
import copy
import ctypes
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from macws_swap_pair import project_session as p

# Local test harness paths only. The projector API has no source-path fallback.
MISC = Path(__file__).resolve().parent
RUNTIME = MISC / "macws_swap_pair"
QA_PATH = RUNTIME / "offline_qa.json"
PREPARER = RUNTIME / "prepare_control_payload.py"
PIPELINE = MISC / "macws_diagnostic_probe_pipeline.py"


def raw(value): return json.dumps(value, separators=(",", ":")).encode()


def forbidden(*args, **kwargs):
    raise AssertionError("native/network/process/clock/nonce operation forbidden")


def fixture():
    """Never serialize this invented device data to a session/receipt file."""
    qa_raw = QA_PATH.read_bytes()
    selected = {"probe.arm64": (p.CANDIDATE["path"], p.CANDIDATE["sha256"], 0o755, 22000),
                "offline-QA.canonical.private.json": (p.CONTROLLER_DIRECTORY + "/offline-QA.canonical.private.json", p.QA_SHA, 0o600, len(qa_raw))}
    selected.update({name: (p.CONTROLLER_DIRECTORY + "/" + name, digest, 0o600, (RUNTIME / name).stat().st_size) for name, digest in p.SOURCES.items()})
    rows = []
    for i, (name, (path, digest, mode, size)) in enumerate(selected.items()):
        rows.append({"name": name, "path": path, "sha256": digest, "previously_absent": True, "new_vnode_created_exclusively": True,
                     "stat": {"dev": 1, "ino": 100 + i, "size": size, "mtime_ns": 1000, "ctime_ns": 1000,
                              "mode": mode, "uid": 0, "gid": 0, "nlink": 1}})
    signature = {"architecture": "arm64", "uuid": p.CANDIDATE["uuid"], "cdhash": p.CANDIDATE["cdhash"],
                 "hash_type": 2, "signed_pages_checked": 5, "code_limit": 20000, "page_hashes_valid": True}
    plan = {"schema": "macws.diagnostic-probe.delivery-plan.v1", "bundle_manifest_sha256": p.MANIFEST_SHA,
            "pipeline_source_sha256": p.PIPELINE_SHA, "receiver_source_sha256": p.RECEIVER_SHA, "envelope_sha256": "1" * 64,
            "architecture": "arm64", "provenance_files_verified": 41,
            "payload_files": [{"name": row["name"], "path": row["path"], "sha256": row["sha256"], "mode": format(row["stat"]["mode"], "04o")} for row in rows],
            "probe_signature_host_verified": signature}
    delivery = {"schema": "macws.diagnostic-probe.delivery.private.v1", "receiver_sha256": p.RECEIVER_SHA,
                "bundle_manifest_sha256": p.MANIFEST_SHA, "installation_verified": True, "installed_files_private": rows,
                "parents_private": [{"logical": parent, "target_previously_absent": True} for parent in (p.ROOTFS + "/usr/local/libexec", "/var/jb/usr/libexec")],
                "created_directories_private": [], "probe_signature": signature,
                "candidate_executions": 0, "controller_executions": 0, "trust_mutations": 0,
                "native_dependency_closure_currently_verified": False, "current_trust_verified": False,
                "device_acceptance": False, "runtime_accepted": False, "freeze_cause_or_fix_proven": False, "automatic_cleanup_attempted": False}
    metadata = {"hw.machine": "iPad13,6", "kern.osversion": "20E252", "kern.uuid": "d6b9e234-64f1-30ea-ae62-ed8f2dc6efdb",
                "kern.bootsessionuuid": "11111111-2222-3333-4444-555555555555", "rootfs_product_version": "13.4", "rootfs_product_build": "22F66"}
    process = {"UI_private": {"SpringBoard": [101, 1000, 1], "backboardd": [102, 1000, 2]}, "blocked_private": []}
    files = {}
    for i, (name, expected) in enumerate({**p.DEPENDENCIES, "candidate": p.CANDIDATE}.items()):
        files[name] = dict(expected, present=True, identity_verified=True, page_hashes_valid=True, trust_member=True,
                           cdhash=expected.get("cdhash", format(i + 1, "040x")), hash_type=2, signed_pages_checked=5, code_limit=20000,
                           stat_token_private=[1, 20 + i, 10000, 1000, 1000])
    files["candidate"]["stat_token_private"] = [rows[0]["stat"][key] for key in p.STAT_FIELDS]
    trust = sorted(item["cdhash"] for item in files.values())
    names = {"exact_device_build", "same_boot", "same_UI_generations", "nominal_thermal", "no_blocked_workloads", "both_scratch_absent",
             "both_job_labels_absent", "same_trust_membership_set", "stable_file_observations", "candidate_present_identity_trusted", "frozen_dependencies_present_identity_trusted"}
    jobs = {label: [113, "", 'Could not find service "' + label + '" in domain for uid: 501\n'] for label in p.LABELS}
    observed = {"schema": "macws.swap-pair.read-only-admission-observations.v4", "observer_source_sha256": p.OBSERVER_SHA,
                "inputs_sha256": p.OBSERVER_INPUT_SHA, "controller_source_sha256": dict(p.SOURCES), "signed_artifact_manifest_sha256": p.SIGNED_MANIFEST_SHA,
                "launchd_domain": "user/501", "mutations": 0, "candidate_executions": 0, "launchd_mutations": 0, "trust_mutations": 0,
                "fully_admitted": False, "runtime_accepted": False, "device_acceptance": False, "runtime_controls_verified": False, "freshness_verified": False,
                "new_vnode": None, "observation_completed": True, "observed_baseline_checks_passed": True, "refusals": [], "finalization_refusals": [],
                "checks": {name: True for name in names}, "metadata_before_private": copy.deepcopy(metadata), "metadata_after_private": copy.deepcopy(metadata),
                "process_before_private": copy.deepcopy(process), "process_after_private": copy.deepcopy(process), "thermal_before": 0, "thermal_after": 0,
                "jobs_before_private": copy.deepcopy(jobs), "jobs_after_private": copy.deepcopy(jobs),
                "scratch_before": {path: True for path in p.SCRATCH}, "scratch_after": {path: True for path in p.SCRATCH},
                "trust_before_private": list(trust), "trust_after_private": list(trust), "files_before_private": copy.deepcopy(files), "files_after_private": copy.deepcopy(files),
                "candidate_observation": "candidate-identity-and-current-trust-poststage", "started_monotonic": 99,
                "finished_monotonic_private": 100, "clock_info": {"domain": "mach_absolute_time.absolute_seconds.v1", "numer": 125, "denom": 3},
                "budget": {"elapsed_seconds": .1}}
    return observed, delivery, plan, qa_raw


def project(observed=None, delivery=None, plan=None, qa_raw=None, **overrides):
    obs, delivered, planned, qa = fixture()
    arguments = dict(observer_raw=raw(obs if observed is None else observed), delivery_raw=raw(delivered if delivery is None else delivery),
                     delivery_plan_raw=raw(planned if plan is None else plan), qa_raw=qa if qa_raw is None else qa_raw, delivery_exit=0, run_nonce="a" * 32,
                     source_directory=RUNTIME, qa_path=QA_PATH, preparer_path=PREPARER, pipeline_path=PIPELINE)
    arguments.update(overrides)
    return p.project_session(**arguments)


class SessionProjectionTests(unittest.TestCase):
    def test_default_metadata_no_io_native_transport_or_nonce(self):
        capture = io.StringIO()
        with patch.object(p, "read_pin", forbidden), patch.object(ctypes, "CDLL", forbidden), patch.object(subprocess, "Popen", forbidden), \
                patch.object(subprocess, "run", forbidden), patch.object(os, "kill", forbidden), patch.object(secrets, "token_hex", forbidden), redirect_stdout(capture):
            self.assertEqual(p.main([]), 0)
        result = json.loads(capture.getvalue())
        self.assertIs(result["session_created"], False)
        self.assertIs(result["nonce_generated"], False)
        self.assertIs(result["current_device_freshness_claimed"], False)

    def test_positive_projection_is_pure_and_contains_exact_v7_structures(self):
        with patch.object(ctypes, "CDLL", forbidden), patch.object(subprocess, "Popen", forbidden), patch.object(subprocess, "run", forbidden), \
                patch.object(os, "kill", forbidden), patch.object(signal, "setitimer", forbidden), patch.object(signal, "alarm", forbidden), \
                patch.object(secrets, "token_hex", forbidden), patch.object(time, "time", forbidden), patch.object(time, "monotonic", forbidden), patch.object(time, "perf_counter", forbidden):
            result = project()
        self.assertEqual(result["config"]["schema"], "macws.swap-pair.live-config.v7")
        self.assertEqual(result["prerequisites"]["schema"], "macws.swap-pair.live-prerequisites.v7")
        self.assertEqual(result["prerequisites"]["native_controls"], {})
        self.assertEqual(result["config"]["run_nonce"], "a" * 32)
        self.assertIs(result["session_files_created"], False)
        self.assertIs(result["current_device_freshness_claimed"], False)
        self.assertIs(result["evidence_authenticity_proven"], False)
        self.assertEqual(result["trust_basis"], "current-observed-membership; no admission mutation")

    def test_original_bytes_are_retained_losslessly_and_receipt_time_is_not_refreshed(self):
        obs, delivery, plan, qa = fixture(); original = b" \n" + raw(obs) + b"\n"
        result = project(obs, delivery, plan, qa, observer_raw=original)
        self.assertEqual(base64.b64decode(result["original_inputs_private_b64"]["observer"]), original)
        self.assertEqual(result["prerequisites"]["preflight"]["raw_sha256"], hashlib.sha256(original).hexdigest())
        for kind in ("preflight", "signed_artifact", "loaded_hook_profile"):
            self.assertEqual(result["prerequisites"][kind]["observed_monotonic"], obs["finished_monotonic_private"])
        for name, data in (("delivery", raw(delivery)), ("delivery_plan", raw(plan)), ("canonical_QA", qa)):
            self.assertEqual(base64.b64decode(result["original_inputs_private_b64"][name]), data)

    def test_delivery_stats_are_projected_to_exact_five_source_token_fields(self):
        result = project()
        self.assertEqual(set(result["tokens"]), set(p.SOURCES))
        for token in result["tokens"].values():
            self.assertEqual(set(token), set(p.STAT_FIELDS))
            self.assertNotIn("mode", token)
            self.assertNotIn("uid", token)

    def test_generated_projection_builds_one_control_payload_without_execution(self):
        result = project()
        spec = importlib.util.spec_from_file_location("_test_pinned_preparer", PREPARER)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        source, report = module.build_control_payload(config_raw=raw(result["config"]), receipts_raw=raw(result["prerequisites"]), tokens_raw=raw(result["tokens"]),
                                                      source_directory=RUNTIME, qa_path=QA_PATH, control="normal_ready_stop")
        compile(source, "<compile-only-session-projection>", "exec")
        self.assertEqual(report["operation"], "control_normal")
        self.assertIs(report["current_device_freshness_claimed"], False)

    def test_external_nonce_is_required_and_not_generated(self):
        for nonce in (None, "", "a" * 31, "g" * 32, True):
            with self.subTest(nonce=nonce), patch.object(secrets, "token_hex", forbidden), self.assertRaises(ValueError): project(run_nonce=nonce)
        self.assertNotIn("trust", inspect.signature(p.project_session).parameters)

    def test_qa_raw_mismatch_refuses_before_source_io_or_module_execution(self):
        with patch.object(p, "read_pin", forbidden), self.assertRaises(ValueError): project(qa_raw=fixture()[3] + b"\n")

    def test_source_qa_preparer_and_pipeline_pins_precede_module_execution(self):
        for changed in ("controller.py", "QA", "preparer", "pipeline"):
            original = p.read_pin
            def bad(path, expected):
                name = Path(path).name
                if ((changed == "controller.py" and name == changed) or (changed == "QA" and name == "offline_qa.json") or
                        (changed == "preparer" and name == "prepare_control_payload.py") or (changed == "pipeline" and name == "macws_diagnostic_probe_pipeline.py")):
                    raise ValueError("synthetic source pin mismatch")
                return original(path, expected)
            with self.subTest(changed=changed), patch.object(p, "read_pin", bad), patch("builtins.exec", forbidden), self.assertRaises(ValueError): project()

    def test_no_private_source_or_qa_path_fallback(self):
        for key in ("source_directory", "qa_path", "preparer_path", "pipeline_path"):
            with self.subTest(key=key), self.assertRaises(ValueError): project(**{key: None})

    def test_old_observer_schema_or_source_inputs_bindings_refuse(self):
        for key, value in (("schema", "macws.swap-pair.read-only-admission-observations.v3"), ("observer_source_sha256", "0" * 64),
                           ("inputs_sha256", "0" * 64), ("controller_source_sha256", {}), ("signed_artifact_manifest_sha256", "0" * 64), ("launchd_domain", "system")):
            obs = fixture()[0]; obs[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): project(observed=obs)

    def test_incomplete_observer_finalization_or_claimed_admission_refuses(self):
        for key, value in (("observation_completed", False), ("observed_baseline_checks_passed", False), ("finalization_refusals", ["clock failure"]),
                           ("refusals", ["hot"]), ("finished_monotonic_private", None), ("freshness_verified", True), ("device_acceptance", True),
                           ("mutations", False), ("trust_mutations", 1), ("new_vnode", True)):
            obs = fixture()[0]; obs[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): project(observed=obs)

    def test_baseline_check_false_missing_extra_or_boolean_alias_refuses(self):
        for mutation in ("false", "missing", "extra", "alias"):
            obs = fixture()[0]
            if mutation == "missing": del obs["checks"]["same_boot"]
            elif mutation == "extra": obs["checks"]["unknown"] = True
            else: obs["checks"]["same_boot"] = False if mutation == "false" else 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): project(observed=obs)

    def test_boot_ui_or_rootfs_drift_refuses_without_new_identity_generation(self):
        for mutation in ("boot", "UI", "rootfs", "device", "thermal", "workload"):
            obs = fixture()[0]
            if mutation == "boot": obs["metadata_after_private"]["kern.bootsessionuuid"] = "99999999-2222-3333-4444-555555555555"
            elif mutation == "UI": obs["process_after_private"]["UI_private"]["SpringBoard"][1] += 1
            elif mutation == "rootfs": obs["metadata_after_private"]["rootfs_product_build"] = "unknown"
            elif mutation == "device": obs["metadata_before_private"]["hw.machine"] = "unknown"
            elif mutation == "thermal": obs["thermal_after"] = 1
            else: obs["process_after_private"]["blocked_private"] = [{"basename": "WindowServer"}]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): project(observed=obs)

    def test_absent_label_and_scratch_evidence_must_be_exact_uid501(self):
        for mutation in ("system", "wrong_uid", "stderr_suffix", "code", "missing_label", "scratch"):
            obs = fixture()[0]; label = p.LABELS[0]
            if mutation == "scratch": obs["scratch_after"][p.SCRATCH[0]] = False
            elif mutation == "missing_label": del obs["jobs_after_private"][label]
            elif mutation == "code": obs["jobs_after_private"][label][0] = 1
            elif mutation == "system": obs["jobs_after_private"][label][2] = "Could not find service in system\n"
            elif mutation == "wrong_uid": obs["jobs_after_private"][label][2] = obs["jobs_after_private"][label][2].replace("501", "502")
            else: obs["jobs_after_private"][label][2] += "warning\n"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): project(observed=obs)

    def test_current_trust_membership_pages_or_exact_candidate_identity_are_required(self):
        for mutation in ("trust", "pages", "UUID", "SHA", "unstable", "token", "bool_token"):
            obs = fixture()[0]
            if mutation == "trust":
                obs["trust_before_private"].remove(p.CANDIDATE["cdhash"]); obs["trust_after_private"].remove(p.CANDIDATE["cdhash"])
            else:
                for group in ("files_before_private", "files_after_private"):
                    item = obs[group]["candidate"]
                    if mutation == "pages": item["page_hashes_valid"] = False
                    elif mutation == "UUID": item["uuid"] = "unknown"
                    elif mutation == "SHA": item["sha256"] = "0" * 64
                    elif mutation == "token": item["stat_token_private"][1] += 1
                    elif mutation == "bool_token": item["stat_token_private"][0] = True
                if mutation == "unstable": obs["files_after_private"]["candidate"]["stat_token_private"][4] += 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): project(observed=obs)

    def test_delivery_versions_hashes_exit_and_execution_claims_refuse(self):
        with self.assertRaises(ValueError): project(delivery_exit=1)
        for key, value in (("schema", "unknown"), ("receiver_sha256", "0" * 64), ("bundle_manifest_sha256", "0" * 64),
                           ("installation_verified", False), ("candidate_executions", 1), ("trust_mutations", True), ("current_trust_verified", True)):
            delivery = fixture()[1]; delivery[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): project(delivery=delivery)
        for key, value in (("pipeline_source_sha256", "0" * 64), ("receiver_source_sha256", "0" * 64), ("bundle_manifest_sha256", "0" * 64),
                           ("architecture", "arm64e"), ("provenance_files_verified", True)):
            plan = fixture()[2]; plan[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): project(plan=plan)

    def test_delivery_duplicate_missing_unknown_rows_or_substituted_stat_refuse(self):
        for mutation in ("duplicate", "missing", "unknown", "inode", "mode", "uid", "bool_stat", "source_size"):
            obs, delivery, plan, _ = fixture(); rows = delivery["installed_files_private"]
            if mutation == "duplicate": rows[-1] = copy.deepcopy(rows[0])
            elif mutation == "missing": rows.pop()
            elif mutation == "unknown": rows[-1]["name"] = "unknown.py"
            elif mutation == "inode": rows[0]["stat"]["ino"] += 1
            elif mutation == "mode": rows[-1]["stat"]["mode"] = 0o777
            elif mutation == "uid": rows[-1]["stat"]["uid"] = 501
            elif mutation == "bool_stat": rows[-1]["stat"]["dev"] = True
            else: rows[-1]["stat"]["size"] += 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): project(obs, delivery, plan)

    def test_observed_timestamp_is_not_checked_against_host_time_and_nulls_refuse(self):
        obs = fixture()[0]; obs["started_monotonic"] = 10**12; obs["finished_monotonic_private"] = 10**12 + 1
        with patch.object(time, "time", forbidden), patch.object(time, "monotonic", forbidden), patch.object(time, "perf_counter", forbidden):
            result = project(observed=obs)
        self.assertEqual(result["prerequisites"]["preflight"]["observed_monotonic"], 10**12 + 1)
        self.assertIs(result["current_device_freshness_claimed"], False)
        for value in (None, True, -1, float("inf")):
            obs = fixture()[0]; obs["finished_monotonic_private"] = value
            with self.subTest(value=value), self.assertRaises(ValueError): project(observed=obs)

    def test_raw_json_duplicates_nonfinite_and_input_bounds_refuse(self):
        for data in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'[]', b' ' * (512 * 1024 + 1)):
            with self.subTest(data=data[:20]), self.assertRaises(ValueError): project(observer_raw=data)

    def test_projector_never_calls_validate_prerequisites_with_copied_time(self):
        original_exec = exec
        def instrument(code, namespace):
            original_exec(code, namespace)
            if str(getattr(code, "co_filename", "")).endswith("runtime_support.py"):
                namespace["validate_prerequisites"] = forbidden
        with patch("builtins.exec", instrument):
            result = project()
        self.assertEqual(result["prerequisites"]["native_controls"], {})


if __name__ == "__main__":
    unittest.main()
