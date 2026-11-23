"""Synthetic host-only report contracts; these fixtures are not device evidence.

The event streams below describe the published producer's report format. They
do not execute UIKit or Metal, attest report origin, or demonstrate a freeze fix.
"""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HELPER = Path(__file__).resolve().parent / "presentation_lifecycle_preview" / "check_report.py"
SPEC = importlib.util.spec_from_file_location("presentation_report_under_test", HELPER)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)

RUN_UI = "11111111-2222-4333-8444-555555555555"
RUN_METAL = "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE"
WILL_RESIGN = "UIApplicationWillResignActiveNotification"
DID_BACKGROUND = "UIApplicationDidEnterBackgroundNotification"
WILL_FOREGROUND = "UIApplicationWillEnterForegroundNotification"
DID_ACTIVE = "UIApplicationDidBecomeActiveNotification"
BGRA = [[0, 0, 255, 255], [0, 255, 0, 255],
        [255, 0, 0, 255], [0, 255, 255, 255]]


def fixture(mode="UIKit", target="device", *, presented_first=False,
            extra_lifecycle=False):
    """Construct invented observations, never a recording from an iPad."""
    run = RUN_UI if mode == "UIKit" else RUN_METAL
    events = []

    def add(name, frame=0, fields=None, identifier=run):
        tick = len(events) + 1
        event = {"event": name, "run": identifier, "frame": frame,
                 "wall_seconds": 1700000000.0 + tick,
                 "uptime_seconds": 100.0 + tick}
        event.update(fields or {})
        events.append(event)

    add("app_ready", fields={"machine": "iPad13,6", "os": "16.4.1",
        "os_build": "Version 16.4.1 (Build 20E252)", "bundle_version": "1",
        # @(!TARGET_OS_SIMULATOR) boxes the C int expression as JSON 0/1.
        "target": target, "presentation_callback_supported": int(target == "device")},
        identifier="")
    if extra_lifecycle:
        add(WILL_RESIGN, fields={"application_state": 1}, identifier="")
        add(DID_BACKGROUND, fields={"application_state": 2}, identifier="")
        add(WILL_FOREGROUND, fields={"application_state": 1}, identifier="")
        add(DID_ACTIVE, fields={"application_state": 0}, identifier="")
    add("run_started", fields={"mode": mode, "thermal": 0, "low_power": False})
    if mode == "Metal":
        add("metal_setup_started")
        add("drawable_size_changed", fields={"width": 640, "height": 480})
        add("metal_setup_finished", fields={"pipeline_ready": 1, "error": ""})
    for frame in (1, 2):
        add("frame_requested", frame)
        if mode == "UIKit":
            add("uikit_draw", frame)
        else:
            if target == "simulator":
                # The real producer emits this synchronous marker BEFORE commit.
                add("presentation_callback_unavailable", frame, {"target": target})
            add("command_commit", frame, {"drawable_width": 640, "drawable_height": 480})

            def completed():
                add("command_completed", frame, {"status": 4, "error": "",
                    "sample_bgra": deepcopy(BGRA), "four_samples_match": True})

            def presented():
                add("drawable_presented", frame, {"presented_time": 150.0 + frame,
                    "positive_presented_time": 1, "drawable_id": frame - 1})

            if target == "device" and presented_first:
                presented()
            completed()
            if target == "device" and not presented_first:
                presented()
        add("human_colors_visible", frame)
        if frame == 1:
            add(WILL_RESIGN, frame, {"application_state": 1})
            add(DID_BACKGROUND, frame, {"application_state": 2})
            add(WILL_FOREGROUND, frame, {"application_state": 1})
            add(DID_ACTIVE, frame, {"application_state": 0})
    if extra_lifecycle:
        add(WILL_RESIGN, 2, {"application_state": 1})
        add(DID_BACKGROUND, 2, {"application_state": 2})
        add(WILL_FOREGROUND, 2, {"application_state": 1})
        add(DID_ACTIVE, 2, {"application_state": 0})
        if mode == "Metal":
            add("drawable_size_changed", 2, {"width": 640, "height": 480})
    return {"schema": "macws.presentation-comparison.v1", "events": events,
            "mode": mode, "finished": True,
            "outcome": "two_frames_observed_and_confirmed", "target": target,
            "presentation_callback_supported": int(target == "device"),
            "dropped_events": 0, "human_review_required": True}


def raw(report):
    return json.dumps(report, separators=(",", ":")).encode("utf-8")


def event(report, name, frame=None):
    return next(row for row in report["events"] if row["event"] == name
                and (frame is None or row["frame"] == frame))


class PresentationReportTests(unittest.TestCase):
    def assertConservative(self, result):
        self.assertIs(result["device_acceptance"], False)
        self.assertIs(result["authenticity_verified"], False)
        self.assertIs(result["human_review_required"], True)
        self.assertIs(result["original_freeze_fixed"], False)

    def refuse(self, report, **options):
        with self.assertRaises(checker.Refused):
            checker.assess(raw(report), **options)

    def test_device_modes_have_only_structural_success(self):
        for mode in ("UIKit", "Metal"):
            with self.subTest(mode=mode):
                self.assertConservative(checker.assess(raw(fixture(mode))))

    def test_objc_c_int_boxing_and_typed_bool_fields_are_not_interchangeable(self):
        for target in ("device", "simulator"):
            report = fixture("Metal", target)
            derived = [(report, "presentation_callback_supported"),
                       (event(report, "app_ready"), "presentation_callback_supported"),
                       (event(report, "metal_setup_finished"), "pipeline_ready")]
            if target == "device":
                derived.extend((event(report, "drawable_presented", frame),
                                "positive_presented_time") for frame in (1, 2))
            for destination, key in derived:
                original = destination[key]
                self.assertIs(type(original), int)
                for replacement in (False, True, 0.0, 1.0):
                    with self.subTest(target=target, derived_field=key, value=replacement):
                        destination[key] = replacement
                        self.refuse(report, allow_simulator=target == "simulator")
                destination[key] = original
            self.assertConservative(checker.assess(raw(report),
                                    allow_simulator=target == "simulator"))

        report = fixture("Metal")
        typed_bool = [(report, "finished"), (report, "human_review_required"),
                      (event(report, "run_started"), "low_power")]
        typed_bool.extend((event(report, "command_completed", frame),
                           "four_samples_match") for frame in (1, 2))
        for destination, key in typed_bool:
            original = destination[key]
            self.assertIs(type(original), bool)
            for replacement in (int(original), float(original)):
                with self.subTest(bool_field=key, value=replacement):
                    destination[key] = replacement
                    self.refuse(report)
            destination[key] = original

    def test_both_device_callback_orders_are_valid(self):
        for first in (False, True):
            with self.subTest(presented_first=first):
                self.assertConservative(checker.assess(raw(fixture("Metal", presented_first=first))))

    def test_callback_timestamp_recording_can_be_out_of_order(self):
        report = fixture("Metal", presented_first=True)
        for frame in (1, 2):
            commit = event(report, "command_commit", frame)
            presented = event(report, "drawable_presented", frame)
            completed = event(report, "command_completed", frame)
            # Both are captured after commit, but callback threads enqueue in
            # the opposite order to their timestamp creation. Do not sort them.
            presented["uptime_seconds"] = commit["uptime_seconds"] + 1.5
            completed["uptime_seconds"] = commit["uptime_seconds"] + 1.0
            presented["wall_seconds"] = commit["wall_seconds"] + 1.5
            completed["wall_seconds"] = commit["wall_seconds"] + 1.0
        self.assertConservative(checker.assess(raw(report)))

    def test_pre_run_and_post_success_lifecycle_are_retained(self):
        for mode in ("UIKit", "Metal"):
            with self.subTest(mode=mode):
                self.assertConservative(checker.assess(raw(fixture(mode, extra_lifecycle=True))))

    def test_wall_clock_adjustment_is_not_event_reordering(self):
        report = fixture()
        for row in report["events"][5:]:
            row["wall_seconds"] -= 3600
        self.assertConservative(checker.assess(raw(report)))

    def test_simulator_is_refused_by_default_for_both_modes(self):
        for mode in ("UIKit", "Metal"):
            with self.subTest(mode=mode):
                self.refuse(fixture(mode, "simulator"))

    def test_explicit_simulator_opt_in_preserves_lower_capability(self):
        for mode in ("UIKit", "Metal"):
            with self.subTest(mode=mode):
                report = fixture(mode, "simulator")
                self.assertConservative(checker.assess(raw(report), allow_simulator=True))

    def test_missing_required_endpoints(self):
        requirements = {"UIKit": [("app_ready", 0), ("run_started", 0),
            ("frame_requested", 1), ("frame_requested", 2), ("uikit_draw", 1),
            ("uikit_draw", 2), ("human_colors_visible", 1), ("human_colors_visible", 2),
            (DID_BACKGROUND, 1), (DID_ACTIVE, 1)],
            "Metal": [("metal_setup_started", 0), ("metal_setup_finished", 0),
            ("command_commit", 1), ("command_commit", 2), ("command_completed", 1),
            ("command_completed", 2), ("drawable_presented", 1), ("drawable_presented", 2)]}
        for mode, required in requirements.items():
            for name, frame in required:
                with self.subTest(mode=mode, event=name, frame=frame):
                    report = fixture(mode)
                    report["events"].remove(event(report, name, frame))
                    self.refuse(report)

    def test_duplicate_mandatory_events_are_not_additional_evidence(self):
        for mode, name, frame in [("UIKit", "app_ready", 0), ("UIKit", "run_started", 0),
                ("UIKit", "frame_requested", 1), ("UIKit", "human_colors_visible", 2),
                ("UIKit", "uikit_draw", 1), ("Metal", "metal_setup_finished", 0),
                ("Metal", "command_commit", 1), ("Metal", "command_completed", 1),
                ("Metal", "drawable_presented", 2)]:
            with self.subTest(mode=mode, event=name):
                report = fixture(mode)
                row = event(report, name, frame)
                report["events"].insert(report["events"].index(row), deepcopy(row))
                self.refuse(report)

    def test_frame_one_needs_endpoints_before_human_confirmation(self):
        for mode, name in [("UIKit", "uikit_draw"), ("Metal", "command_completed"),
                           ("Metal", "drawable_presented")]:
            with self.subTest(mode=mode, event=name):
                report = fixture(mode)
                row = event(report, name, 1)
                report["events"].remove(row)
                index = report["events"].index(event(report, "human_colors_visible", 1))
                report["events"].insert(index + 1, row)
                self.refuse(report)

    def test_frame_two_needs_its_own_observation_before_confirmation(self):
        report = fixture("Metal")
        row = event(report, "drawable_presented", 2)
        report["events"].remove(row)
        report["events"].append(row)
        self.refuse(report)

    def test_background_cannot_precede_first_human_confirmation(self):
        report = fixture()
        row = event(report, DID_BACKGROUND, 1)
        report["events"].remove(row)
        report["events"].insert(report["events"].index(event(report, "human_colors_visible", 1)), row)
        self.refuse(report)

    def test_frame_two_cannot_precede_return_to_active(self):
        report = fixture()
        row = event(report, "frame_requested", 2)
        report["events"].remove(row)
        report["events"].insert(report["events"].index(event(report, DID_ACTIVE, 1)), row)
        self.refuse(report)

    def test_returned_active_flag_cannot_survive_another_departure(self):
        for name, state in ((WILL_RESIGN, 1), (DID_BACKGROUND, 2)):
            with self.subTest(lifecycle=name):
                report = fixture()
                row = deepcopy(event(report, name, 1))
                row["application_state"] = state
                index = report["events"].index(event(report, "frame_requested", 2))
                report["events"].insert(index, row)
                self.refuse(report)

    def test_inactive_interruption_alone_is_not_background_transition(self):
        report = fixture()
        report["events"].remove(event(report, DID_BACKGROUND, 1))
        report["events"].remove(event(report, WILL_FOREGROUND, 1))
        self.refuse(report)

    def test_metal_completion_cannot_precede_commit(self):
        for name in ("command_completed", "drawable_presented"):
            with self.subTest(event=name):
                report = fixture("Metal")
                row = event(report, name, 1)
                report["events"].remove(row)
                report["events"].insert(report["events"].index(event(report, "command_commit", 1)), row)
                self.refuse(report)

    def test_run_uuid_mixing_and_invalid_run_ids(self):
        for value in (RUN_METAL, "", "not-a-uuid", True, 1):
            with self.subTest(value=value):
                report = fixture()
                event(report, "uikit_draw", 1)["run"] = value
                self.refuse(report)

    def test_unknown_or_boolean_frame_numbers(self):
        for value in (0, 3, -1, True, False, 1.0, "1"):
            with self.subTest(value=value):
                report = fixture()
                event(report, "uikit_draw", 1)["frame"] = value
                self.refuse(report)

    def test_failed_or_stopped_history_cannot_be_relabelled_successful(self):
        report = fixture()
        row = deepcopy(event(report, "human_colors_visible", 1))
        row.update(event="run_failed", reason="Stopped by user")
        report["events"].insert(report["events"].index(event(report, DID_BACKGROUND, 1)), row)
        self.refuse(report)

    def test_top_level_flags_and_enum_types(self):
        for field, value in [("schema", "macws.presentation-comparison.v2"),
                ("finished", False), ("finished", 1), ("outcome", "running"),
                ("outcome", "failed_or_stopped"), ("human_review_required", False),
                ("human_review_required", 1), ("dropped_events", 1),
                ("dropped_events", False), ("dropped_events", 0.0),
                ("target", "unknown"), ("presentation_callback_supported", False),
                ("presentation_callback_supported", True),
                ("presentation_callback_supported", 0),
                ("presentation_callback_supported", 1.0), ("mode", "metal")]:
            with self.subTest(field=field, value=value):
                report = fixture()
                report[field] = value
                self.refuse(report)

    def test_app_ready_target_or_capability_must_agree(self):
        for field, value in [("target", "simulator"), ("presentation_callback_supported", False),
                             ("presentation_callback_supported", True),
                             ("presentation_callback_supported", 0),
                             ("bundle_version", ""), ("machine", ""), ("os_build", "")]:
            with self.subTest(field=field):
                report = fixture()
                event(report, "app_ready")[field] = value
                self.refuse(report)

    def test_started_mode_must_agree(self):
        report = fixture()
        event(report, "run_started")["mode"] = "Metal"
        self.refuse(report)

    def test_unknown_event_is_refused(self):
        report = fixture()
        event(report, "uikit_draw", 1)["event"] = "future_unreviewed_draw"
        self.refuse(report)

    def test_unrecognized_top_level_or_event_fields_are_refused(self):
        for top_level in (True, False):
            with self.subTest(top_level=top_level):
                report = fixture()
                destination = report if top_level else event(report, "uikit_draw", 1)
                destination["unsupported_revision_field"] = "new contract"
                self.refuse(report)

    def test_metal_events_in_uikit_control_are_refused(self):
        metal = fixture("Metal")
        for name in ("metal_setup_started", "metal_setup_finished", "command_commit",
                     "command_completed", "drawable_presented", "drawable_size_changed"):
            with self.subTest(event=name):
                report = fixture()
                row = deepcopy(event(metal, name))
                row["run"] = RUN_UI
                report["events"].insert(2, row)
                self.refuse(report)

    def test_metal_setup_must_be_ready_without_error(self):
        for field, value in [("pipeline_ready", False), ("pipeline_ready", True),
                             ("pipeline_ready", 0), ("pipeline_ready", 1.0), ("error", "failure")]:
            with self.subTest(field=field):
                report = fixture("Metal")
                event(report, "metal_setup_finished")[field] = value
                self.refuse(report)

    def test_gpu_status_samples_and_error_are_independent_requirements(self):
        changes = [("status", 5), ("status", 4.0), ("status", True),
                   ("four_samples_match", False), ("four_samples_match", 1),
                   ("error", "GPU fault"), ("sample_bgra", BGRA[:3]),
                   ("sample_bgra", [[False, 0, 255, 255]] + deepcopy(BGRA[1:]))]
        wrong_color = deepcopy(BGRA)
        wrong_color[2][0] = 254
        changes.append(("sample_bgra", wrong_color))
        for field, value in changes:
            with self.subTest(field=field, value=value):
                report = fixture("Metal")
                event(report, "command_completed", 1)[field] = value
                self.refuse(report)

    def test_device_presentation_timestamp_and_id(self):
        for field, value in [("presented_time", 0), ("presented_time", -1),
                ("presented_time", None), ("presented_time", True),
                ("presented_time", float("nan")), ("presented_time", float("inf")),
                ("positive_presented_time", False), ("positive_presented_time", True),
                ("positive_presented_time", 0), ("positive_presented_time", 1.0),
                ("drawable_id", -1), ("drawable_id", True)]:
            with self.subTest(field=field, value=value):
                report = fixture("Metal")
                event(report, "drawable_presented", 1)[field] = value
                self.refuse(report)

    def test_second_presentation_must_advance_without_requiring_adjacent_ids(self):
        for field in ("presented_time", "drawable_id"):
            report = fixture("Metal")
            event(report, "drawable_presented", 2)[field] = event(report, "drawable_presented", 1)[field]
            with self.subTest(field=field):
                self.refuse(report)
        report = fixture("Metal")
        event(report, "drawable_presented", 2)["drawable_id"] = 12345
        self.assertConservative(checker.assess(raw(report)))

    def test_too_small_drawable_geometry_is_refused(self):
        for field in ("drawable_width", "drawable_height"):
            for value in (0, 3, True, 4.0):
                with self.subTest(field=field, value=value):
                    report = fixture("Metal")
                    event(report, "command_commit", 1)[field] = value
                    self.refuse(report)

    def test_device_report_cannot_substitute_simulator_marker(self):
        report = fixture("Metal")
        row = event(report, "drawable_presented", 1)
        row.clear()
        row.update(deepcopy(event(fixture("Metal", "simulator"), "presentation_callback_unavailable", 1)))
        self.refuse(report)

    def test_simulator_cannot_include_device_presentation(self):
        report = fixture("Metal", "simulator")
        row = deepcopy(event(fixture("Metal"), "drawable_presented", 1))
        report["events"].insert(report["events"].index(event(report, "human_colors_visible", 1)), row)
        self.refuse(report, allow_simulator=True)

    def test_simulator_markers_are_required_and_unique(self):
        for mutation in ("missing", "duplicate"):
            with self.subTest(mutation=mutation):
                report = fixture("Metal", "simulator")
                row = event(report, "presentation_callback_unavailable", 1)
                if mutation == "missing":
                    report["events"].remove(row)
                else:
                    report["events"].insert(report["events"].index(row), deepcopy(row))
                self.refuse(report, allow_simulator=True)

    def test_event_timestamps_need_finite_numeric_types(self):
        for field, value in [("wall_seconds", float("nan")), ("wall_seconds", float("inf")),
                ("wall_seconds", True), ("wall_seconds", "100"),
                ("uptime_seconds", -1), ("uptime_seconds", float("inf")),
                ("uptime_seconds", False)]:
            with self.subTest(field=field, value=value):
                report = fixture()
                event(report, "uikit_draw", 1)[field] = value
                self.refuse(report)

    def test_excess_events_and_raw_size_are_refused(self):
        report = fixture()
        report["events"].extend(deepcopy(report["events"][-1]) for _ in range(257))
        self.refuse(report)
        with self.assertRaises(checker.Refused):
            checker.assess(b" " * (1024 * 1024 + 1))

    def test_parser_rejects_duplicate_keys_truncation_trailing_and_deep_json(self):
        normal = raw(fixture())
        duplicate = b'{"schema":"bad",' + normal[1:]
        for data in (duplicate, normal[:-1], normal + b" {}", b"[" * 40 + b"0" + b"]" * 40,
                     b"\xff", b"null", b"[]"):
            with self.subTest(prefix=data[:30]):
                with self.assertRaises(checker.Refused):
                    checker.assess(data)

    def test_brackets_and_escaped_quotes_in_strings_are_not_json_nesting(self):
        report = fixture()
        event(report, "app_ready")["os_build"] = '["' * 100 + '\\"' + "]" * 100
        self.assertConservative(checker.assess(raw(report)))

    def test_raw_input_type_and_overflowed_exponent_are_refused(self):
        for value in (None, "{}", bytearray(raw(fixture())), b""):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(checker.Refused):
                    checker.assess(value)
        report = fixture("Metal")
        data = raw(report).replace(b'"presented_time":151.0', b'"presented_time":1e999')
        self.assertNotEqual(data, raw(report))
        with self.assertRaises(checker.Refused):
            checker.assess(data)

    def test_device_pair_is_only_a_consistent_unattested_candidate(self):
        self.assertConservative(checker.assess_pair(raw(fixture()), raw(fixture("Metal"))))

    def test_pair_mode_order_and_distinct_run_ids(self):
        ui, metal = fixture(), fixture("Metal")
        for first, second in ((metal, ui), (ui, ui), (metal, metal)):
            with self.subTest(modes=(first["mode"], second["mode"])):
                with self.assertRaises(checker.Refused):
                    checker.assess_pair(raw(first), raw(second))
        for row in metal["events"]:
            if row["run"]:
                row["run"] = RUN_UI
        with self.assertRaises(checker.Refused):
            checker.assess_pair(raw(ui), raw(metal))

    def test_pair_run_distinctness_is_case_insensitive(self):
        ui, metal = fixture(), fixture("Metal")
        for row in ui["events"]:
            if row["run"]:
                row["run"] = RUN_METAL
        for row in metal["events"]:
            if row["run"]:
                row["run"] = RUN_METAL.lower()
        with self.assertRaises(checker.Refused):
            checker.assess_pair(raw(ui), raw(metal))

    def test_pair_metadata_and_start_conditions_must_match(self):
        for name, value in [("machine", "iPad14,5"), ("os", "16.5.1"),
                            ("os_build", "Different build"), ("bundle_version", "2")]:
            with self.subTest(metadata=name):
                metal = fixture("Metal")
                event(metal, "app_ready")[name] = value
                with self.assertRaises(checker.Refused):
                    checker.assess_pair(raw(fixture()), raw(metal))
        for name, value in (("thermal", 1), ("low_power", True)):
            with self.subTest(start_condition=name):
                metal = fixture("Metal")
                event(metal, "run_started")[name] = value
                with self.assertRaises(checker.Refused):
                    checker.assess_pair(raw(fixture()), raw(metal))

    def test_pair_targets_cannot_be_mixed_even_with_simulator_opt_in(self):
        with self.assertRaises(checker.Refused):
            checker.assess_pair(raw(fixture()), raw(fixture("Metal", "simulator")), allow_simulator=True)

    def test_simulator_pair_needs_explicit_opt_in_and_remains_unaccepted(self):
        ui, metal = raw(fixture(target="simulator")), raw(fixture("Metal", "simulator"))
        with self.assertRaises(checker.Refused):
            checker.assess_pair(ui, metal)
        self.assertConservative(checker.assess_pair(ui, metal, allow_simulator=True))

    def test_cli_valid_pair_emits_only_conservative_structural_success(self):
        with tempfile.TemporaryDirectory(prefix="presentation-report-host-test-") as directory:
            ui = Path(directory) / "synthetic-uikit.json"
            metal = Path(directory) / "synthetic-metal.json"
            ui.write_bytes(raw(fixture()))
            metal.write_bytes(raw(fixture("Metal")))
            completed = subprocess.run([sys.executable, str(HELPER), str(ui), str(metal)],
                capture_output=True, text=True, timeout=5, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertIs(result["completed_record_consistent"], True)
        self.assertConservative(result)

    def test_cli_bad_or_missing_input_has_machine_readable_refusal(self):
        with tempfile.TemporaryDirectory(prefix="presentation-report-host-test-") as directory:
            bad = Path(directory) / "synthetic-invalid.json"
            missing = Path(directory) / "never-created.json"
            bad.write_bytes(b"{")
            for path in (bad, missing):
                with self.subTest(input=path.name):
                    completed = subprocess.run([sys.executable, str(HELPER), str(path)],
                        capture_output=True, text=True, timeout=5, check=False)
                    self.assertEqual(completed.returncode, 2, completed.stderr)
                    result = json.loads(completed.stdout)
                    self.assertIs(result["completed_record_consistent"], False)
                    self.assertConservative(result)


if __name__ == "__main__":
    unittest.main()
