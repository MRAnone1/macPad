"""Portable synthetic read-only observer controls; no device/native calls.

No copied native command output, process IDs, boot identifiers or addresses
are fixtures here. Minimal signed bytes and process generations are synthetic.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid


ROOT = Path(__file__).resolve().parent / "macws_swap_pair"
SOURCE = (ROOT / "readonly_observer.py").read_bytes()
INPUTS = (ROOT / "observer_inputs.json").read_bytes()
spec = importlib.util.spec_from_file_location("macws_readonly_observer_portable", ROOT / "readonly_observer.py")
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)


def synthetic_signed_thin():
    identity = uuid.UUID("11111111-2222-3333-4444-555555555555")
    commands = struct.pack("<II", 0x1b, 24) + identity.bytes + struct.pack("<IIII", 0x1d, 16, 128, 96)
    code = struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 2, 2, len(commands), 0, 0) + commands
    code += b"\0" * (128 - len(code))
    directory = struct.pack(">9I4BI", 0xfade0c02, 76, 0x20001, 0, 44, 0, 0, 1, 128, 32, 2, 0, 7, 0)
    directory += hashlib.sha256(code).digest()
    return code + struct.pack(">5I", 0xfade0cc0, 96, 1, 0, 20) + directory


SYNTHETIC_BINARY = synthetic_signed_thin()
SIGNATURE = o.code_signature(SYNTHETIC_BINARY)


def absent(label):
    # Synthetic string matching the published, exact source-bound contract.
    return (113, "", 'Could not find service "' + label + '" in domain for uid: 501\n')


class FakeObserver:
    simulation_only = True

    def __init__(self):
        self.commands = []
        self.candidate_missing = False
        self.candidate_bad_identity = False
        self.untrusted = False
        self.final_time_failure = False
        self.final_budget_failure = False
        self.final_clock_failure = False
        self.primary_failure = False
        self.wrong_domain = False
        self.counts = {"now": 0, "budget": 0, "clock": 0}

    def now(self):
        self.counts["now"] += 1
        if self.final_time_failure and self.counts["now"] > 1:
            raise o.Refused("observer total deadline")
        return 100.0

    def clock_info(self):
        self.counts["clock"] += 1
        if self.final_clock_failure:
            raise o.Refused("clock profile unavailable")
        return {"domain": "mach_absolute_time.absolute_seconds.v1", "numer": 125, "denom": 3}

    def metadata(self):
        return {"hw.machine": "iPad13,6", "kern.osversion": "20E252", "kern.uuid": "d6b9e234-64f1-30ea-ae62-ed8f2dc6efdb",
                "kern.bootsessionuuid": "11111111-1111-1111-1111-111111111111",
                "rootfs_product_version": "13.4", "rootfs_product_build": "22F66"}

    def process_snapshot(self):
        return {"UI_private": {"SpringBoard": [5, 122, 456], "backboardd": [6, 123, 456]},
                "rows_private": [], "UI_details_private": {}, "blocked_private": []}

    def thermal(self):
        if self.primary_failure:
            raise o.Refused("synthetic primary thermal refusal")
        return 0

    def job(self, label):
        result = absent(label)
        if self.wrong_domain:
            return result[:2] + (result[2].replace("uid: 501", "system"),)
        return result

    def path_absent(self, path):
        return True

    def read(self, path, limit):
        if self.candidate_missing and path == "/synthetic/probe.arm64":
            raise FileNotFoundError(path)
        return SYNTHETIC_BINARY, [1, 2, len(SYNTHETIC_BINARY), 3, 4]

    def trust(self):
        return set() if self.untrusted else {SIGNATURE["cdhash"]}

    def budget(self):
        self.counts["budget"] += 1
        if self.final_budget_failure:
            raise o.Refused("shared native clock read budget")
        return {"file_read_bytes": 0, "commands": 0, "elapsed_seconds": .01}


class ReadOnlyObserverTests(unittest.TestCase):
    def setUp(self):
        for target, name, message in ((o.ctypes, "CDLL", "native API"), (o.subprocess, "Popen", "subprocess"),
                                      (os, "kill", "signal"), (signal, "alarm", "alarm"), (signal, "setitimer", "timer")):
            guard = patch.object(target, name, side_effect=AssertionError(message + " forbidden in portable test"))
            guard.start(); self.addCleanup(guard.stop)

    def parser(self):
        return o.extracted_absence_parser(o.checked_inputs(INPUTS))

    def observe(self, fake):
        inputs = o.checked_inputs(INPUTS)
        expected = {"path": "/synthetic/probe.arm64", "sha256": o.sha(SYNTHETIC_BINARY), "architecture": "arm64",
                    "uuid": SIGNATURE["uuid"], "cdhash": SIGNATURE["cdhash"]}
        if fake.candidate_bad_identity:
            expected["uuid"] = str(uuid.UUID(int=0))
        inputs["candidate"] = expected
        dependencies = {name: {**expected, "uuid": SIGNATURE["uuid"], "path": "/synthetic/" + name} for name in o.DEPENDENCIES}
        with patch.object(o, "DEPENDENCIES", dependencies):
            return o.observe(fake, inputs, o.sha(SOURCE))

    def test_frozen_public_copies_have_exact_original_hashes(self):
        self.assertEqual(o.sha(SOURCE), "717de31eb1d7a05ed363eca7c3dce0dbd7f4ff500bb8cb65377bd340babf1c7a")
        self.assertEqual(o.sha(INPUTS), "f7261fcf3e6c47493e92f8b04396316acf9d3f66b229d77a85cc0f95ffa6f280")
        self.assertEqual(o.checked_inputs(INPUTS)["controller_source_sha256"]["runtime_support.py"],
                         o.sha((ROOT / "runtime_support.py").read_bytes()))

    def test_import_and_default_CLI_have_no_native_or_adapter_effects(self):
        spec = importlib.util.spec_from_file_location("macws_observer_default_import_test", ROOT / "readonly_observer.py")
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with patch.object(module, "NativeObserver", side_effect=AssertionError("adapter forbidden")), contextlib.redirect_stdout(io.StringIO()) as captured:
            self.assertEqual(module.main([]), 0)
        result = json.loads(captured.getvalue())
        self.assertFalse(result["native_execution"]); self.assertEqual(result["launchd_domain"], "user/501")

    def test_changed_source_or_input_refused_before_adapter(self):
        def forbidden(_):
            self.fail("native adapter constructed")
        with self.assertRaises(o.Refused): o.execute(SOURCE + b"\n", o.sha(SOURCE), INPUTS, forbidden)
        with self.assertRaises(o.Refused): o.execute(SOURCE, o.sha(SOURCE), INPUTS + b" ", forbidden)

    def test_explicit_native_execution_requires_digest_before_adapter(self):
        with self.assertRaises(o.Refused): o.main(["--observe"])

    def test_exact_source_bound_parser_accepts_both_fixed_labels(self):
        parser = self.parser()
        for label in o.LABELS:
            self.assertTrue(o.job_absent(absent(label), label, parser))

    def test_changed_runtime_support_refused_before_parser_extraction(self):
        inputs = o.checked_inputs(INPUTS); inputs["runtime_support_source"] += "\n"
        with self.assertRaises(o.Refused): o.extracted_absence_parser(inputs)

    def test_copied_native_primitives_expose_only_three_read_methods(self):
        cls = o.extracted_primitives(o.checked_inputs(INPUTS))
        self.assertEqual({name for name in cls.__dict__ if not name.startswith("__")}, {"metadata", "process", "thermal"})

    def test_copied_shared_clock_accepts_only_injected_synthetic_functions(self):
        class Function:
            def __init__(self, function): self.function = function
            def __call__(self, *args): return self.function(*args)
        def timebase(pointer):
            pointer._obj.numer = 125; pointer._obj.denom = 3
            return 0
        library = SimpleNamespace(mach_timebase_info=Function(timebase), mach_absolute_time=Function(lambda: 24000000))
        cls = o.extracted_shared_clock(o.checked_inputs(INPUTS))
        clock = cls(library)
        self.assertEqual(clock.now(), 1.0)
        self.assertEqual(clock.profile, {"domain": "mach_absolute_time.absolute_seconds.v1", "numer": 125, "denom": 3})

    def test_absence_requires_exact_integer_status113(self):
        for code in (0, 1, 3, 112, 114, 255, -1, True, 113.0):
            result = (code,) + absent(o.LABELS[0])[1:]
            with self.subTest(code=code), self.assertRaises(o.Refused): o.job_absent(result, o.LABELS[0], self.parser())

    def test_absence_rejects_wrong_domain_and_warning_stderr(self):
        valid = absent(o.LABELS[0])[2]
        for stderr in (valid.replace("uid: 501", "system"), valid.replace("uid: 501", "uid: 502"),
                       "Bad request.\n" + valid, valid + "warning\n", valid.rstrip(), valid + "\n", valid.replace("\n", "\r\n")):
            with self.subTest(stderr=stderr), self.assertRaises(o.Refused):
                o.job_absent((113, "", stderr), o.LABELS[0], self.parser())

    def test_absence_never_ignores_stdout_or_wrong_label(self):
        for stdout in (" ", "\n", "warning"):
            with self.subTest(stdout=stdout), self.assertRaises(o.Refused):
                o.job_absent((113, stdout, absent(o.LABELS[0])[2]), o.LABELS[0], self.parser())
        with self.assertRaises(o.Refused): o.job_absent(absent(o.LABELS[1]), o.LABELS[0], self.parser())
        with self.assertRaises(o.Refused): o.job_absent(absent("other"), "other", self.parser())

    def test_absence_malformed_result_schema_refused(self):
        for result in (None, (), (113, ""), (113, "", None), (113, b"", absent(o.LABELS[0])[2]), "113"):
            with self.subTest(result=result), self.assertRaises(o.Refused): o.job_absent(result, o.LABELS[0], self.parser())

    def test_command_guard_allows_only_exact_read_queries(self):
        for label in o.LABELS:
            self.assertTrue(o.readonly_command_allowed([o.LAUNCHCTL, "print", "user/501/" + label]))
        self.assertTrue(o.readonly_command_allowed([o.JBCTL, "trustcache", "info"]))
        self.assertTrue(o.readonly_command_allowed(["/bin/ps", "-eo", "pid,comm"]))

    def test_command_guard_refuses_domains_aliases_mutations_and_unknown_labels(self):
        commands = [[o.LAUNCHCTL, "print", domain + o.LABELS[0]] for domain in ("system/", "gui/501/", "user/foreground/", "user/0/", "user/502/", "")]
        commands += [[o.LAUNCHCTL, "bootstrap", "user/501"], [o.LAUNCHCTL, "print", "user/501/other"], [o.JBCTL, "trustcache", "add"]]
        for command in commands:
            with self.subTest(command=command), self.assertRaises(o.Refused): o.readonly_command_allowed(command)

    def test_native_job_method_constructs_exact_command_without_instantiation(self):
        calls = []
        fake = SimpleNamespace(command=lambda argv: calls.append(argv) or absent(o.LABELS[0]))
        for label in o.LABELS: o.NativeObserver.job(fake, label)
        self.assertEqual(calls, [[o.LAUNCHCTL, "print", "user/501/" + label] for label in o.LABELS])
        with self.assertRaises(o.Refused): o.NativeObserver.job(fake, "other")
        self.assertEqual(len(calls), 2)

    def test_prestage_missing_candidate_is_explicit_without_token_or_trust(self):
        fake = FakeObserver(); fake.candidate_missing = True
        result = self.observe(fake)
        self.assertTrue(result["observation_completed"]); self.assertFalse(result["observed_baseline_checks_passed"])
        self.assertEqual(result["candidate_observation"], "candidate-missing-prestage")
        candidate = result["files_after_private"]["candidate"]
        self.assertFalse(candidate["present"]); self.assertIsNone(candidate["trust_member"])
        self.assertNotIn("stat_token_private", candidate)

    def test_poststage_identity_and_current_trust_remain_observation_only(self):
        result = self.observe(FakeObserver())
        self.assertTrue(result["observation_completed"]); self.assertTrue(result["observed_baseline_checks_passed"])
        self.assertEqual(result["candidate_observation"], "candidate-identity-and-current-trust-poststage")
        for key in ("fully_admitted", "runtime_accepted", "device_acceptance", "freshness_verified", "runtime_controls_verified"):
            self.assertFalse(result[key])
        self.assertIsNone(result["new_vnode"])
        for key in ("candidate_executions", "launchd_mutations", "trust_mutations", "mutations"): self.assertEqual(result[key], 0)

    def test_poststage_untrusted_and_identity_mismatch_are_distinct(self):
        fake = FakeObserver(); fake.untrusted = True
        result = self.observe(fake)
        self.assertEqual(result["candidate_observation"], "candidate-present-untrusted")
        self.assertFalse(result["observed_baseline_checks_passed"])
        fake = FakeObserver(); fake.candidate_bad_identity = True
        result = self.observe(fake)
        self.assertEqual(result["candidate_observation"], "candidate-present-identity-mismatch")
        self.assertFalse(result["observed_baseline_checks_passed"])

    def test_wrong_domain_observation_refused_without_dropping_copied_report(self):
        fake = FakeObserver(); fake.wrong_domain = True
        result = self.observe(fake)
        self.assertFalse(result["observation_completed"])
        self.assertIn("jobs_before_private", result); self.assertIn("files_after_private", result)
        self.assertTrue(any("launchctl absence" in value for value in result["refusals"]))

    def test_expired_final_timestamp_preserves_report_and_unknown_null(self):
        fake = FakeObserver(); fake.final_time_failure = True
        result = self.observe(fake)
        self.assertIn("metadata_before_private", result); self.assertIn("files_after_private", result)
        self.assertIsNone(result["finished_monotonic_private"])
        self.assertFalse(result["observation_completed"]); self.assertFalse(result["observed_baseline_checks_passed"])
        self.assertEqual(result["finalization_refusals"], ["finished_monotonic_private: Refused: observer total deadline"])
        self.assertEqual(fake.counts["now"], 2)

    def test_primary_and_finalization_refusals_both_survive(self):
        fake = FakeObserver(); fake.primary_failure = True; fake.final_time_failure = True
        result = self.observe(fake)
        self.assertIn("metadata_before_private", result)
        self.assertIn("Refused: synthetic primary thermal refusal", result["refusals"])
        self.assertIn("finished_monotonic_private: Refused: observer total deadline", result["refusals"])
        self.assertIsNone(result["finished_monotonic_private"])

    def test_final_budget_refusal_has_null_unknown_budget_and_negative_result(self):
        fake = FakeObserver(); fake.final_budget_failure = True
        result = self.observe(fake)
        self.assertIsNone(result["budget"]); self.assertIn("commands_private", result)
        self.assertFalse(result["observation_completed"]); self.assertFalse(result["observed_baseline_checks_passed"])
        self.assertEqual(fake.counts["budget"], 1)

    def test_all_finalization_failures_do_not_reset_or_retry_queries(self):
        fake = FakeObserver(); fake.final_time_failure = fake.final_clock_failure = fake.final_budget_failure = True
        result = self.observe(fake)
        for key in ("clock_info", "finished_monotonic_private", "budget"): self.assertIsNone(result[key])
        self.assertEqual(fake.counts, {"now": 2, "clock": 1, "budget": 1})
        self.assertEqual(len(result["finalization_refusals"]), 3)
        self.assertFalse(result["observation_completed"]); self.assertFalse(result["observed_baseline_checks_passed"])

    def test_signed_code_page_mutation_is_refused(self):
        changed = bytearray(SYNTHETIC_BINARY); changed[100] ^= 1
        with self.assertRaises(o.Refused): o.code_signature(bytes(changed))

    def test_native_budget_limits_remain_bounded(self):
        self.assertEqual(o.LIMITS["deadline_seconds"], 8)
        self.assertEqual(o.LIMITS["device_alarm_seconds"], 12)
        self.assertEqual(o.LIMITS["read_bytes"], 16 * 1024 * 1024)
        self.assertEqual(o.LIMITS["command_seconds"], 1)
        self.assertEqual(o.LIMITS["command_count"], 16)


if __name__ == "__main__":
    unittest.main()
