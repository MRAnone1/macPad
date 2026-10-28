"""Synthetic source-bound factory checks; no native backend is constructed."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SOURCES = HERE / "macws_swap_pair"
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("embedded_observer_under_test", SOURCES / "retained_observer.py")
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)


class FactoryTests(unittest.TestCase):
    def setUp(self):
        self.sources = {name: (SOURCES / name).read_bytes() for name in o.PINS}
        self.inputs = types.SimpleNamespace(original=object(), intact=lambda: True)

    def factory(self, **kwargs):
        backend, result = object(), object()
        with patch.object(o, "NativeReadOnlyBackend", return_value=backend) as native, \
             patch.object(o, "Observer", return_value=result) as observer:
            self.assertIs(o.native_observer(self.inputs, **kwargs), result)
            native.assert_called_once_with(self.inputs.original)
            observer.assert_called_once_with(self.inputs, backend)

    def test_embedded_sources_do_not_read_virtual_paths(self):
        with patch.object(o, "nofollow_read", side_effect=AssertionError("unexpected file read")):
            self.factory(dependency_sources=self.sources)

    def test_default_still_reads_both_exact_physical_sources(self):
        def read(path, limit):
            self.assertEqual(limit, 256*1024)
            return self.sources[Path(path).name], None
        with patch.object(o, "nofollow_read", side_effect=read) as read_mock:
            self.factory()
            self.assertEqual(read_mock.call_count, 2)

    def test_all_bad_source_variants_refuse_before_intact_or_native(self):
        class Key(str):
            pass
        invalid = [[], {}, {**self.sources, "foreign.py": b"x"},
                   {Key(name): raw for name, raw in self.sources.items()},
                   {name: raw for name, raw in self.sources.items() if name != "readonly_observer.py"}]
        for name in o.PINS:
            for raw in (b"", bytearray(self.sources[name]), "text", b"x"*(256*1024+1), self.sources[name]+b"\n"):
                invalid.append({**self.sources, name: raw})
        for value in invalid:
            with self.subTest(names=type(value).__name__), \
                 patch.object(o, "NativeReadOnlyBackend", side_effect=AssertionError("native construction")), \
                 patch.object(self.inputs, "intact", side_effect=AssertionError("validation too early")), \
                 self.assertRaises(o.cleanup.Refused):
                o.native_observer(self.inputs, dependency_sources=value)

    def test_false_intact_is_refused_before_native(self):
        with patch.object(self.inputs, "intact", return_value=False), \
             patch.object(o, "NativeReadOnlyBackend", side_effect=AssertionError("native construction")), \
             self.assertRaises(o.cleanup.Refused):
            o.native_observer(self.inputs, dependency_sources=self.sources)

    def test_lineage_exception_prevents_native_construction(self):
        with patch.object(self.inputs, "intact", side_effect=o.cleanup.Refused("changed inputs")), \
             patch.object(o, "NativeReadOnlyBackend", side_effect=AssertionError("native construction")), \
             self.assertRaises(o.cleanup.Refused):
            o.native_observer(self.inputs, dependency_sources=self.sources)


if __name__ == "__main__":
    unittest.main()
