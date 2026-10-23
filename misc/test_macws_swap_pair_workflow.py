"""One shared invented workflow; compile payloads, never execute them.

The fixture contains synthetic process/file tokens and an invented nonce only
in memory. Static source/artifact identities come from the reviewed plan. An
internally consistent invented report is not authentic or fresh device evidence.
"""
import base64
import copy
from contextlib import ExitStack
import ctypes
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import unittest
from unittest.mock import patch

from macws_swap_pair import cleanup_payload as cleanup
from macws_swap_pair import prepare_control_payload as preparer
from macws_swap_pair import project_session as projector
import test_macws_swap_pair_preparation as capture_fixtures
import test_macws_swap_pair_session as session_fixtures

MISC = Path(__file__).resolve().parent
RUNTIME = MISC / "macws_swap_pair"
PLAN_RAW = (RUNTIME / "reviewed_delivery_plan.json").read_bytes()
PLAN = json.loads(PLAN_RAW)


def encoded(value):
    return json.dumps(value, sort_keys=True, allow_nan=False, separators=(",", ":")).encode()


def forbidden(*args, **kwargs):
    raise AssertionError("native/transport/mutation/nonce generation forbidden in rehearsal")


def shared_fixture():
    """Complete invented records with the exact, byte-pinned static plan."""
    observed, delivery, _, qa_raw = session_fixtures.fixture()
    delivery["probe_signature"] = copy.deepcopy(PLAN["probe_signature_host_verified"])
    row = next(row for row in delivery["installed_files_private"] if row["name"] == "probe.arm64")
    # Invented length, large enough for this plan's code limit; no binary read.
    row["stat"]["size"] = delivery["probe_signature"]["code_limit"] + 1024
    delivery["created_directories_private"] = [
        {"path": path, "stat": {
            "dev": 1, "ino": 500 + i, "size": 128, "mtime_ns": 1000, "ctime_ns": 1000,
            "mode": 0o700, "uid": 0, "gid": 0, "nlink": 2,
        }}
        for i, path in enumerate(cleanup.DIRECTORIES)
    ]
    for stage in ("files_before_private", "files_after_private"):
        observed[stage]["candidate"].update(PLAN["probe_signature_host_verified"])
        observed[stage]["candidate"]["stat_token_private"] = [row["stat"][key] for key in projector.STAT_FIELDS]
    return observed, delivery, qa_raw


def project(observed, delivery, qa_raw):
    return projector.project_session(
        observer_raw=encoded(observed), delivery_raw=encoded(delivery), delivery_plan_raw=PLAN_RAW,
        delivery_exit=0, qa_raw=qa_raw, run_nonce="a" * 32, source_directory=RUNTIME,
        qa_path=RUNTIME / "offline_qa.json", preparer_path=RUNTIME / "prepare_control_payload.py",
        pipeline_path=MISC / "macws_diagnostic_probe_pipeline.py",
    )


def build_control(projected):
    return preparer.build_control_payload(
        config_raw=encoded(projected["config"]), receipts_raw=encoded(projected["prerequisites"]),
        tokens_raw=encoded(projected["tokens"]), source_directory=RUNTIME,
        qa_path=RUNTIME / "offline_qa.json", control="normal_ready_stop",
    )


def build_cleanup(delivery):
    return cleanup.build_cleanup_payload(
        observer_source=(RUNTIME / "readonly_observer.py").read_bytes(),
        observer_inputs=(RUNTIME / "observer_inputs.json").read_bytes(),
        plan_raw=PLAN_RAW, delivery_raw=encoded(delivery),
    )


def consistent_fake_capture(config):
    # This is an invented protocol report, including its internal native flags.
    # Rebind the entire projection/receipt to THIS session, not the helper's.
    _, outer = capture_fixtures.synthetic_capture()
    outer["clock_info"] = copy.deepcopy(config["clock_info"])
    outer["full_private_report"]["clock_info"] = copy.deepcopy(config["clock_info"])
    capture_fixtures.refresh_synthetic_receipt(outer, config)
    return outer


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        guards = ExitStack()
        self.addCleanup(guards.close)
        for owner, name in (
            (ctypes, "CDLL"), (subprocess, "Popen"), (subprocess, "run"),
            (os, "kill"), (os, "unlink"), (os, "rmdir"), (os, "mkdir"),
            (signal, "signal"), (signal, "alarm"), (signal, "setitimer"),
            (secrets, "token_hex"), (Path, "write_bytes"), (Path, "write_text"),
        ):
            guards.enter_context(patch.object(owner, name, forbidden))

    def test_shared_pinned_fixture_composes_projection_control_decode_and_cleanup(self):
        observed, delivery, qa_raw = shared_fixture()
        before = copy.deepcopy((observed, delivery, qa_raw))
        projected = project(observed, delivery, qa_raw)
        source, control_metadata = build_control(projected)
        fake = consistent_fake_capture(projected["config"])
        decoded = preparer.decode_transport_result(
            stdout=encoded(fake), stderr=b"", returncode=0, timed_out=False,
            control="normal_ready_stop", expected_config_raw=encoded(projected["config"]),
        )
        cleanup_source, cleanup_metadata = build_cleanup(delivery)
        compile(source, "<compile-only-shared-control>", "exec")
        compile(cleanup_source, "<compile-only-shared-cleanup>", "exec")

        self.assertIs(decoded["internally_consistent_capture"], True)
        self.assertIs(decoded["accepted_scoped_capture"], True)
        for key in ("native_evidence_authenticity_verified", "current_device_freshness_claimed", "device_acceptance"):
            self.assertIs(decoded[key], False)
        for key in ("session_files_created", "nonce_generated", "current_device_freshness_claimed", "evidence_authenticity_proven", "device_acceptance"):
            self.assertIs(projected[key], False)
        for key in ("current_freshness_verified", "evidence_authenticity_verified", "device_acceptance"):
            self.assertIs(cleanup_metadata[key], False)
        self.assertEqual(control_metadata["operation"], "control_normal")
        self.assertIs(control_metadata["requires_live_native_revalidation"], True)
        self.assertIs(cleanup_metadata["requires_live_readonly_baseline"], True)
        self.assertEqual((observed, delivery, qa_raw), before)
        self.assertEqual(hashlib.sha256(PLAN_RAW).hexdigest(), cleanup.PLAN_SHA)
        self.assertEqual(cleanup_metadata["raw_delivery_sha256"], projected["original_inputs_sha256"]["delivery"])
        self.assertEqual(cleanup_metadata["raw_plan_sha256"], projected["original_inputs_sha256"]["delivery_plan"])
        delivered = {row["name"]: row for row in delivery["installed_files_private"]}
        self.assertEqual(projected["config"]["installed_probe_token"],
                         [delivered["probe.arm64"]["stat"][key] for key in projector.STAT_FIELDS])
        self.assertEqual(projected["tokens"], {
            name: {key: delivered[name]["stat"][key] for key in projector.STAT_FIELDS}
            for name in projector.SOURCES
        })
        self.assertEqual(projected["prerequisites"]["native_controls"], {})
        for name, raw in (("observer", encoded(observed)), ("delivery", encoded(delivery)), ("delivery_plan", PLAN_RAW)):
            self.assertEqual(base64.b64decode(projected["original_inputs_private_b64"][name]), raw)

    def test_incomplete_directory_records_prevent_cleanup_construction(self):
        observed, delivery, qa_raw = shared_fixture()
        delivery["created_directories_private"] = []
        projected = project(observed, delivery, qa_raw)
        build_control(projected)
        with self.assertRaisesRegex(ValueError, "exact two delivery directories"):
            build_cleanup(delivery)

    def test_cleanup_requires_group_zero_even_when_projection_accepts_root_uid(self):
        observed, delivery, qa_raw = shared_fixture()
        for row in delivery["installed_files_private"] + delivery["created_directories_private"]:
            row["stat"]["gid"] = 501
        # Projector first invokes the pinned pipeline's pure receipt validator.
        # Both require root UID, whereas cleanup additionally requires GID zero.
        projected = project(observed, delivery, qa_raw)
        build_control(projected)
        with self.assertRaisesRegex(ValueError, "root-owned delivery stat"):
            build_cleanup(delivery)

    def test_reviewed_signature_must_match_the_same_observer_candidate(self):
        observed, delivery, qa_raw = shared_fixture()
        for stage in ("files_before_private", "files_after_private"):
            observed[stage]["candidate"]["code_limit"] = 20000
        with self.assertRaisesRegex(ValueError, "observed candidate signature differs"):
            project(observed, delivery, qa_raw)

    def test_delivered_candidate_token_must_match_the_same_observation(self):
        observed, delivery, qa_raw = shared_fixture()
        row = next(row for row in delivery["installed_files_private"] if row["name"] == "probe.arm64")
        row["stat"]["ino"] += 1
        with self.assertRaisesRegex(ValueError, "delivery/current candidate token differs"):
            project(observed, delivery, qa_raw)

    def test_decoder_refuses_an_otherwise_consistent_report_from_another_session(self):
        observed, delivery, qa_raw = shared_fixture()
        projected = project(observed, delivery, qa_raw)
        fake = consistent_fake_capture(projected["config"])
        foreign = copy.deepcopy(projected["config"])
        foreign["run_nonce"] = "b" * 32
        decoded = preparer.decode_transport_result(
            stdout=encoded(fake), stderr=b"", returncode=0, timed_out=False,
            control="normal_ready_stop", expected_config_raw=encoded(foreign),
        )
        self.assertIs(decoded["accepted_scoped_capture"], False)
        self.assertIs(decoded["internally_consistent_capture"], False)
        self.assertIn("receipt consistency", decoded["capture_consistency_error_private"])


if __name__ == "__main__":
    unittest.main()
