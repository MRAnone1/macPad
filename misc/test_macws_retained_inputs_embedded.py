"""Offline embedded-validator tests; every boot and native receipt is invented."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PUBLIC = HERE
SOURCES = PUBLIC / "macws_swap_pair"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


c = load("synthetic_retained_inputs_embedded", SOURCES / "retained_inputs.py")
fixture_module = load("synthetic_embedded_fixture", PUBLIC / "test_macws_retained_inputs.py")


def sources():
    return {name: (SOURCES / name).read_bytes() for name in
            ("process_retirement.py", "cleanup_payload.py", "reviewed_delivery_plan.json")}


class EmbeddedInputsTests(unittest.TestCase):
    def setUp(self):
        values, self.expected = fixture_module.fixture()
        self.raw = {name: c.canonical(value) for name, value in values.items()}
        self.pins = {name: c.digest(raw) for name, raw in self.raw.items()}

    def build(self, bundle, source_directory=SOURCES):
        with patch.object(c, "INPUT_PINS", self.pins):
            return c.build_inputs(*(self.raw[name] for name in c.INPUT_PINS),
                source_directory=source_directory, validator_sources=bundle)

    def refuse_before_load(self, bundle, reason=None):
        with patch.object(c, "_load_module") as disk, \
             patch.object(c, "_load_embedded_module") as embedded:
            if reason:
                with self.assertRaisesRegex(c.Refused, reason):
                    self.build(bundle)
            else:
                with self.assertRaises(c.Refused):
                    self.build(bundle)
            disk.assert_not_called()
            embedded.assert_not_called()

    def test_complete_embedded_path_preserves_original_validation(self):
        result = self.build(sources())
        self.assertTrue(result.intact())
        self.assertIs(type(result.original), result.retirement_core.Original)
        self.assertEqual(result.expected_files, self.expected)
        self.assertEqual(result.original.config["operation"], "control_normal")
        self.assertEqual(c.decode(result.original_bytes["config"])["operation"], "run")
        self.assertEqual(set(result.provenance_base), {
            "original_wire_sha256", "original_host_sha256", "original_delivery_sha256",
            "original_config_sha256", "effective_config_sha256", "retirement_wire_sha256",
            "retained_snapshot_sha256"})

    def test_legacy_file_path_keeps_same_result(self):
        legacy = self.build(None)
        embedded = self.build(sources())
        self.assertEqual(legacy.context, embedded.context)
        self.assertEqual(legacy.provenance_base, embedded.provenance_base)
        self.assertEqual(legacy.original_bytes, embedded.original_bytes)
        self.assertEqual(legacy.delivery_plan, embedded.delivery_plan)
        self.assertEqual(legacy.expected_files, embedded.expected_files)

    def test_embedded_entries_never_use_file_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in fixture_module.f.c.SOURCE_PINS:
                (directory / name).write_bytes((SOURCES / name).read_bytes())
            # Only installed original runtime files exist. The three embedded
            # entries are never staged or read through either file helper.
            with patch.object(c, "_source_raw", side_effect=AssertionError("disk entry")), \
                 patch.object(c, "_load_module", side_effect=AssertionError("disk module")):
                result = self.build(sources(), directory)
            self.assertTrue(result.intact())
            self.assertEqual(set(path.name for path in directory.iterdir()),
                             set(fixture_module.f.c.SOURCE_PINS))

    def test_original_runtime_files_remain_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                self.build(sources(), Path(tmp))

    def test_original_runtime_changed_source_still_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in fixture_module.f.c.SOURCE_PINS:
                (directory / name).write_bytes((SOURCES / name).read_bytes())
            (directory / "runtime_support.py").write_bytes(b"raise AssertionError('never run')\n")
            with self.assertRaisesRegex(c.Refused, "original_pinned_validation_refused"):
                self.build(sources(), directory)

    def test_every_source_sha_checked_before_first_exec(self):
        for name in sources():
            with self.subTest(name=name):
                value = sources()
                value[name] = b"raise AssertionError('must not execute')\n"
                self.refuse_before_load(value, "frozen_embedded_validation_sources")

    def test_all_three_hashes_computed_before_first_exec(self):
        bundle = sources()
        called = []
        original_digest = c.digest
        def record(raw):
            called.append(raw)
            return original_digest(raw)
        original_load = c._load_embedded_module
        def checked_load(name, raw):
            self.assertTrue(all(item in called for item in bundle.values()))
            return original_load(name, raw)
        with patch.object(c, "digest", side_effect=record), \
             patch.object(c, "_load_embedded_module", side_effect=checked_load):
            self.assertTrue(self.build(bundle).intact())

    def test_missing_and_extra_keys_refuse_before_exec(self):
        for name in sources():
            bundle = sources()
            bundle.pop(name)
            with self.subTest(missing=name):
                self.refuse_before_load(bundle, "exact_embedded_validator_source_set")
        bundle = sources()
        bundle["extra.py"] = b"pass\n"
        self.refuse_before_load(bundle, "exact_embedded_validator_source_set")

    def test_alternative_filename_and_wrong_key_type_refuse(self):
        for bad in ("../process_retirement.py", 3, b"process_retirement.py"):
            bundle = sources()
            bundle[bad] = bundle.pop("process_retirement.py")
            with self.subTest(bad=bad):
                self.refuse_before_load(bundle, "exact_embedded_validator_source_set")

    def test_only_plain_dict_admitted(self):
        class DictSubclass(dict):
            pass
        for bundle in ([], (), "sources", DictSubclass(sources()), 0, False):
            with self.subTest(type=type(bundle)):
                self.refuse_before_load(bundle, "exact_embedded_validator_source_set")

    def test_only_plain_immutable_source_bytes_admitted(self):
        class BytesSubclass(bytes):
            pass
        original = sources()["process_retirement.py"]
        for item in (original.decode(), bytearray(original), memoryview(original),
                     BytesSubclass(original), False, None, 3):
            bundle = sources()
            bundle["process_retirement.py"] = item
            with self.subTest(type=type(item)):
                self.refuse_before_load(bundle, "bounded_immutable_embedded_validator_sources")

    def test_empty_and_oversized_sources_refuse_before_exec(self):
        for item in (b"", b"x" * (c.MAX_VALIDATOR_SOURCE + 1)):
            bundle = sources()
            bundle["reviewed_delivery_plan.json"] = item
            self.refuse_before_load(bundle, "bounded_immutable_embedded_validator_sources")

    def test_aggregate_source_cap_refuses_before_exec(self):
        bundle = sources()
        with patch.object(c, "MAX_VALIDATOR_SOURCES", sum(map(len, bundle.values())) - 1):
            self.refuse_before_load(bundle, "bounded_immutable_embedded_validator_sources")

    def test_caller_container_mutation_after_snapshot_cannot_change_execution(self):
        bundle = sources()
        retained = dict(bundle)
        original_load = c._load_embedded_module
        seen = []
        def mutate_then_load(name, raw):
            bundle.clear()
            bundle["process_retirement.py"] = b"raise AssertionError('never execute')\n"
            seen.append((name, raw))
            return original_load(name, raw)
        with patch.object(c, "_load_embedded_module", side_effect=mutate_then_load):
            result = self.build(bundle)
        self.assertTrue(result.intact())
        self.assertEqual(seen, [(name, retained[name]) for name in
                               ("cleanup_payload.py", "process_retirement.py")])
        self.assertEqual(result.delivery_plan, c.decode(retained["reviewed_delivery_plan.json"]))

    def test_frozen_source_snapshot_is_not_mutable(self):
        checked = c._validator_sources_checked(sources())
        with self.assertRaises(TypeError):
            checked["process_retirement.py"] = b"changed"

    def test_embedded_validator_instances_use_distinct_namespaces(self):
        first = self.build(sources())
        second = self.build(sources())
        self.assertIsNot(first.retirement_core, second.retirement_core)
        self.assertIsNot(first.cleanup_core, second.cleanup_core)
        self.assertNotEqual(first.retirement_core.__name__, second.retirement_core.__name__)
        self.assertIs(sys.modules[first.retirement_core.__name__], first.retirement_core)
        self.assertIs(sys.modules[second.retirement_core.__name__], second.retirement_core)
        first.original.config["run_nonce"] = "b" * 32
        with self.assertRaises(first.retirement_core.Refused):
            first.intact()
        self.assertTrue(second.intact())

    def test_default_cli_remains_inert(self):
        result = subprocess.run([sys.executable, "-B", str(SOURCES / "retained_inputs.py")],
            capture_output=True, check=True, timeout=5)
        self.assertEqual(json.loads(result.stdout), c.metadata())
        self.assertEqual(result.stderr, b"")
        self.assertEqual(c.metadata()["native_backends_constructed"], 0)


if __name__ == "__main__":
    unittest.main()
