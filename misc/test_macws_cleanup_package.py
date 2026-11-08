"""Offline byte-contract adversaries; never a device acceptance simulation."""

import ast
import base64
import builtins
import contextlib
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest import mock
import zlib

from macws_swap_pair import cleanup_package as package
from macws_swap_pair import cleanup_decode_payload as payload


PUBLIC = Path(__file__).resolve().parent / "macws_swap_pair"
CODEC_RAW = (PUBLIC / "retained_frame.py").read_bytes()
assert hashlib.sha256(CODEC_RAW).hexdigest() == payload.CODEC_SHA256
CODEC = types.ModuleType("pinned_test_codec")
exec(compile(CODEC_RAW, "retained_frame.pinned-test.py", "exec"), CODEC.__dict__)
PACKAGE_RAW = Path(package.__file__).read_bytes()
PACKAGE_PIN = hashlib.sha256(PACKAGE_RAW).hexdigest()
UNSET = object()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixture():
    # Every framed source is poison: any execution would fail the test.
    sources = {name: b"raise AssertionError('FRAMED_SOURCE_MUST_NEVER_EXECUTE')\n" + name.encode()
               for name in package.SOURCE_NAMES}
    source_pins = {name: sha(raw) for name, raw in sources.items()}
    context = {"binding": {"hw.machine": "invented-offline-profile", "kern.osversion": "invented",
                "kern.uuid": "historical-invented", "kern.bootsessionuuid": "historical-invented",
                "rootfs_product_version": "invented", "rootfs_product_build": "invented"},
               "UI_private": {"SpringBoard": [10, 100, 0], "backboardd": [11, 100, 0]},
               "attempt_nonce": "a" * 32,
               "clock_info": {"domain": "mach_absolute_time.absolute_seconds.v1", "numer": 1, "denom": 1},
               "source_sha256": {role: source_pins[name] for role, name in package.SOURCE_ROLES.items()}}
    entries = package.named_entries(sources=sources, delivery_raw=b'ORIGINAL \x00 IMMUTABLE\xff\n',
        archived_files={name: b"ORIGINAL FILE " + name.encode() for name in package.FILE_ALIASES},
        context_raw=package._canonical(context))
    data_pins = {name: sha(entries[name]) for name in package.DATA_NAMES}
    return entries, source_pins, data_pins


def make_frame(entries, source_pins, data_pins):
    return package.build(entries=entries, trusted_source_sha256=source_pins,
                         trusted_data_sha256=data_pins, codec=CODEC)


def wrapper(frame_raw, source_pins, data_pins):
    return payload.build(frame_raw=frame_raw, trusted_frame_sha256=sha(frame_raw),
        codec_source_raw=CODEC_RAW, trusted_codec_sha256=payload.CODEC_SHA256,
        package_source_raw=PACKAGE_RAW, trusted_package_sha256=PACKAGE_PIN,
        trusted_source_sha256=source_pins, trusted_data_sha256=data_pins)


def manifest_frame(frame_raw, alter):
    expanded = zlib.decompress(frame_raw[len(CODEC.MAGIC):])
    size = int.from_bytes(expanded[:4], "big")
    manifest = json.loads(expanded[4:4 + size])
    alter(manifest)
    meta = CODEC._canonical(manifest)
    return CODEC.MAGIC + zlib.compress(len(meta).to_bytes(4, "big") + meta + expanded[4 + size:], 9)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.entries, self.source_pins, self.data_pins = fixture()
        self.frame = make_frame(self.entries, self.source_pins, self.data_pins)

    def decode(self, raw=UNSET, sources=UNSET, data=UNSET):
        return package.decode(frame_raw=self.frame if raw is UNSET else raw,
            trusted_source_sha256=self.source_pins if sources is UNSET else sources,
            trusted_data_sha256=self.data_pins if data is UNSET else data, codec=CODEC)

    def changed_context(self, mutate):
        context = json.loads(self.entries["context.private.json"]); mutate(context)
        raw = package._canonical(context)
        entries = dict(self.entries, **{"context.private.json": raw})
        return entries, dict(self.data_pins, **{"context.private.json": sha(raw)})

    def test_exact_twelve_lossless_roundtrip_with_poison_sources(self):
        result = self.decode()
        self.assertEqual(result.entries(), self.entries)
        self.assertEqual(len(result.sources()), 5)
        self.assertEqual(result.delivery_raw(), self.entries["delivery.private.json"])
        self.assertEqual(result.archived_files()["offline-QA.canonical.private.json"], self.entries["offline_qa.private.json"])
        self.assertEqual(result.context_raw(), self.entries["context.private.json"])
        self.assertEqual(result.summary()["entry_count"], 12)
        self.assertFalse(result.summary()["current_device_freshness"])
        self.assertFalse(result.summary()["device_acceptance"])

    def test_deterministic_and_owned_maps(self):
        before = dict(self.entries)
        self.assertEqual(make_frame(dict(reversed(list(self.entries.items()))), self.source_pins, self.data_pins), self.frame)
        result = self.decode(); result.entries().clear(); result.sources().clear(); result.archived_files().clear()
        result.context()["UI_private"]["SpringBoard"][0] = 99
        self.assertEqual(result.entries(), before)
        self.assertEqual(result.context()["UI_private"]["SpringBoard"][0], 10)
        self.assertEqual(self.entries, before)

    def test_every_source_and_data_tamper_refused(self):
        for name in self.entries:
            with self.subTest(name=name), self.assertRaises((package.Refused, CODEC.Refused)):
                make_frame(dict(self.entries, **{name: self.entries[name] + b"changed"}), self.source_pins, self.data_pins)

    def test_all_twelve_pins_before_any_context_parse_in_build_and_decode(self):
        for name in self.entries:
            changed = dict(self.entries, **{name: b"changed"})
            coherent = dict(self.source_pins, **self.data_pins); coherent[name] = sha(b"changed")
            altered_frame = CODEC.encode(changed, coherent)
            with self.subTest(name=name), mock.patch.object(package, "_context_json", side_effect=AssertionError("parsed early")):
                with self.assertRaises((package.Refused, CODEC.Refused)):
                    make_frame(changed, self.source_pins, self.data_pins)
                with self.assertRaises((package.Refused, CODEC.Refused)):
                    self.decode(altered_frame)

    def test_each_independent_pin_not_replaced_by_coherent_manifest(self):
        for name in self.entries:
            wrong_sources, wrong_data = dict(self.source_pins), dict(self.data_pins)
            (wrong_sources if name in package.SOURCE_NAMES else wrong_data)[name] = "0" * 64
            with self.subTest(name=name), self.assertRaises((package.Refused, CODEC.Refused)):
                self.decode(sources=wrong_sources, data=wrong_data)

    def test_pin_maps_are_exact_typed_independent_inputs(self):
        class SubDict(dict): pass
        for bad in (None, [], SubDict(self.source_pins), dict(self.source_pins, foreign="0" * 64), {}):
            with self.subTest(bad=type(bad).__name__), self.assertRaises(package.Refused): self.decode(sources=bad)
        for digest in (True, None, "F" * 64, "0" * 63, b"0" * 64):
            changed = dict(self.source_pins); changed[package.SOURCE_NAMES[0]] = digest
            with self.subTest(digest=digest), self.assertRaises(package.Refused): self.decode(sources=changed)

    def test_fixed_allowlist_missing_extra_alias_and_path_names(self):
        for name in ("../probe.arm64", "Probe.arm64", "unknown", "a/b", "offline-QA.canonical.private.json"):
            changed = dict(self.entries); changed[name] = changed.pop("probe.arm64")
            pins = {key: sha(value) for key, value in changed.items()}
            with self.subTest(name=name), self.assertRaises(package.Refused):
                package.build(entries=changed, trusted_source_sha256=self.source_pins,
                              trusted_data_sha256={key: value for key, value in pins.items() if key not in package.SOURCE_NAMES}, codec=CODEC)
        for changed in ({}, dict(self.entries, extra=b"extra")):
            with self.assertRaises(package.Refused): make_frame(changed, self.source_pins, self.data_pins)

    def test_named_entry_mapping_refuses_any_foreign_source_or_file(self):
        sources = {name: self.entries[name] for name in package.SOURCE_NAMES}
        blobs = self.decode().archived_files()
        for bad_sources, bad_blobs in ((dict(sources, sixth=b"x"), blobs), (sources, dict(blobs, unknown=b"x")), ({}, blobs)):
            with self.assertRaises(package.Refused):
                package.named_entries(sources=bad_sources, delivery_raw=b"x", archived_files=bad_blobs, context_raw=b"x")

    def test_every_per_name_cap_and_mutability_refused(self):
        for name in self.entries:
            cap = package.MAX_CONTEXT_BYTES if name == "context.private.json" else package.MAX_DELIVERY_BYTES if name == "delivery.private.json" else 128 * 1024
            for value in (b"x" * (cap + 1), b"", bytearray(self.entries[name]), memoryview(self.entries[name])):
                changed = dict(self.entries, **{name: value})
                pins = {key: sha(bytes(raw)) for key, raw in changed.items()}
                with self.subTest(name=name, kind=type(value).__name__), self.assertRaises(package.Refused):
                    package.build(entries=changed,
                        trusted_source_sha256={key: pins[key] for key in package.SOURCE_NAMES},
                        trusted_data_sha256={key: pins[key] for key in package.DATA_NAMES}, codec=CODEC)

    def test_compressed_cap_and_decompression_bomb(self):
        for raw in (b"x" * (CODEC.MAX_FRAME_BYTES + 1),
                    CODEC.MAGIC + zlib.compress(b"x" * (CODEC.MAX_PAYLOAD_BYTES + 1), 9)):
            with mock.patch.object(json, "loads", side_effect=AssertionError("parser reached")):
                with self.assertRaises(CODEC.Refused): self.decode(raw)

    def test_actual_incompressible_named_file_fails_fixed_compressed_budget(self):
        entries = dict(self.entries)
        entries["probe.arm64"] = b"".join(hashlib.sha256(str(n).encode()).digest() for n in range(4096))
        entries["runtime_support.py"] = entries["probe.arm64"][::-1]
        pins = dict(self.data_pins, **{name: sha(entries[name]) for name in ("probe.arm64", "runtime_support.py")})
        with self.assertRaisesRegex(CODEC.Refused, "compressed byte budget"):
            make_frame(entries, self.source_pins, pins)

    def test_frame_truncation_trailing_checksum_and_magic(self):
        for raw in (self.frame[:-1], self.frame + b"\x00", b"x" + self.frame[1:], self.frame[:-1] + bytes([self.frame[-1] ^ 1])):
            with self.subTest(size=len(raw)), self.assertRaises(CODEC.Refused): self.decode(raw)

    def test_manifest_order_name_offset_hash_and_boolean_size(self):
        mutations = [lambda m: m["entries"].reverse(), lambda m: m["entries"][0].update(name="foreign"),
                     lambda m: m["entries"][0].update(offset=1), lambda m: m["entries"][0].update(size=True),
                     lambda m: m["entries"][0].update(sha256="0" * 64)]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(CODEC.Refused):
                self.decode(manifest_frame(self.frame, mutation))

    def test_context_source_roles_cannot_override_external_five_source_pins(self):
        for role in package.SOURCE_ROLES:
            entries, data = self.changed_context(lambda context: context["source_sha256"].update({role: "0" * 64}))
            coherent = CODEC.encode(entries, dict(self.source_pins, **data))
            with self.subTest(role=role), self.assertRaisesRegex(package.Refused, "context_sources_match"):
                self.decode(coherent, data=data)
        self.assertNotIn("readonly_observer", package.SOURCE_ROLES)
        changed = dict(self.source_pins, **{"readonly_observer.py": "0" * 64})
        with self.assertRaises(CODEC.Refused): self.decode(sources=changed)

    def test_context_extra_missing_authority_flags_bool_alias_and_float_refused(self):
        mutations = [lambda c: c.update(execution_authorized=True), lambda c: c.pop("attempt_nonce"),
                     lambda c: c["clock_info"].update(numer=True), lambda c: c["clock_info"].update(denom=1.0),
                     lambda c: c["UI_private"]["SpringBoard"].__setitem__(2, False),
                     lambda c: c["UI_private"].update(backboardd=c["UI_private"]["SpringBoard"]),
                     lambda c: c.update(attempt_nonce="A" * 32)]
        for mutate in mutations:
            entries, data = self.changed_context(mutate)
            with self.subTest(mutate=mutate), self.assertRaises(package.Refused): make_frame(entries, self.source_pins, data)

    def test_context_malformed_noncanonical_duplicate_deep_flood_refused(self):
        bad_values = [b"{}", b"{", b"{\"x\":1,\"x\":2}", b"[" * 100 + b"0" + b"]" * 100,
                      b"[" + b"0," * 200 + b"0]", self.entries["context.private.json"] + b"\n",
                      b'{"x":NaN}', b'{"x":' + b"9" * 100 + b"}", b"\xff"]
        for raw in bad_values:
            entries = dict(self.entries, **{"context.private.json": raw})
            data = dict(self.data_pins, **{"context.private.json": sha(raw)})
            with self.subTest(raw=raw[:20]), self.assertRaises(package.Refused): make_frame(entries, self.source_pins, data)

    def test_package_has_no_exec_native_source_import_or_io(self):
        with mock.patch.object(builtins, "open", side_effect=AssertionError("open")), \
             mock.patch.object(builtins, "exec", side_effect=AssertionError("exec")), \
             mock.patch.object(builtins, "eval", side_effect=AssertionError("eval")), \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError("Popen")), \
             mock.patch.object(ctypes, "CDLL", side_effect=AssertionError("CDLL")), \
             mock.patch.object(os, "unlink", side_effect=AssertionError("unlink")), \
             mock.patch.object(os, "rmdir", side_effect=AssertionError("rmdir")):
            raw = make_frame(self.entries, self.source_pins, self.data_pins)
            self.assertEqual(self.decode(raw).entries(), self.entries)
            out = io.StringIO()
            with contextlib.redirect_stdout(out): package.main()
            self.assertTrue(json.loads(out.getvalue())["default_inert"])


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.entries, self.sources, self.data = fixture()
        self.frame = make_frame(self.entries, self.sources, self.data)
        self.payload = wrapper(self.frame, self.sources, self.data)

    def run_payload(self, raw=None, args=(), alter=None):
        source = self.payload if raw is None else raw
        tree = ast.parse(source)
        if alter:
            frozen_node = next(node for node in tree.body if isinstance(node, ast.Assign) and
                               isinstance(node.targets[0], ast.Name) and node.targets[0].id == "FROZEN")
            frozen = ast.literal_eval(frozen_node.value); alter(frozen)
            frozen_node.value = ast.parse(repr(frozen), mode="eval").body
            ast.fix_missing_locations(tree)
        compiled = compile(tree, "private.decode-only-payload.py", "exec")
        original_exec = builtins.exec
        out, calls = io.StringIO(), []
        def record(code, globals=None, locals=None):
            calls.append(code.co_filename)
            return original_exec(code, globals, locals)
        with mock.patch.object(sys, "argv", ["private.decode-only-payload.py", *args]), \
             mock.patch.object(builtins, "exec", side_effect=record), \
             mock.patch.object(builtins, "open", side_effect=AssertionError("open")), \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError("Popen")), \
             mock.patch.object(ctypes, "CDLL", side_effect=AssertionError("CDLL")), \
             mock.patch.object(os, "unlink", side_effect=AssertionError("unlink")), \
             mock.patch.object(os, "rmdir", side_effect=AssertionError("rmdir")), \
             contextlib.redirect_stdout(out):
            self.last_calls = calls
            original_exec(compiled, {"__name__": "__main__"})
        return json.loads(out.getvalue()), calls

    def test_default_does_not_exec_bootstrap_or_decode_poison_frame(self):
        result, calls = self.run_payload(alter=lambda frozen: frozen.update(frame_b64="INVALID BASE64"))
        self.assertEqual(calls, [])
        self.assertEqual(result, package.metadata())

    def test_explicit_decode_executes_only_two_checked_bootstraps_never_framed_sources(self):
        result, calls = self.run_payload(args=("--decode",))
        self.assertEqual(calls, ["retained_frame.pinned.py", "cleanup_package.pinned.py"])
        self.assertEqual(result["entry_count"], 12)
        self.assertEqual(result["source_executions"], 0)
        self.assertFalse(result["execution_authority"])

    def test_every_bootstrap_and_frame_integrity_pin_checked_before_first_exec(self):
        for name in ("codec", "package", "frame"):
            def alter(frozen): frozen[name + "_b64"] = base64.b64encode(b"raise AssertionError('poison')").decode()
            with self.subTest(name=name), self.assertRaises(ValueError): self.run_payload(args=("--decode",), alter=alter)
            self.assertEqual(self.last_calls, [])

    def test_coherent_repacked_source_still_refused_by_external_entry_pin(self):
        changed = dict(self.entries, **{"retained_observer.py": b"raise AssertionError('NEW_POISON')"})
        coherent_pins = dict(self.sources, **self.data); coherent_pins["retained_observer.py"] = sha(changed["retained_observer.py"])
        coherent_frame = CODEC.encode(changed, coherent_pins)
        def alter(frozen):
            frozen["frame_b64"] = base64.b64encode(coherent_frame).decode(); frozen["frame_sha256"] = sha(coherent_frame)
        with self.assertRaises(ValueError): self.run_payload(args=("--decode",), alter=alter)
        self.assertEqual(self.last_calls, ["retained_frame.pinned.py", "cleanup_package.pinned.py"])

    def test_unknown_action_or_extra_args_refused_before_bootstrap(self):
        for args in (("--cleanup",), ("--observe",), ("--decode", "--cleanup"), ("--decode", "true"), ("--help",)):
            with self.subTest(args=args), self.assertRaises(ValueError): self.run_payload(args=args)
            self.assertEqual(self.last_calls, [])

    def test_builder_rejects_changed_codec_even_when_attacker_updates_pin(self):
        with self.assertRaisesRegex(package.Refused, "unchanged_retained_frame_pin"):
            payload.build(frame_raw=self.frame, trusted_frame_sha256=sha(self.frame), codec_source_raw=b"poison",
                trusted_codec_sha256=sha(b"poison"), package_source_raw=PACKAGE_RAW, trusted_package_sha256=PACKAGE_PIN,
                trusted_source_sha256=self.sources, trusted_data_sha256=self.data)

    def test_default_and_decode_actual_subprocess(self):
        for args in ([], ["--decode"]):
            result = subprocess.run([sys.executable, "-B", "-c", self.payload.decode("ascii"), *args],
                                    input=b"ignored", capture_output=True, timeout=5, check=True)
            self.assertEqual(result.stderr, b"")
            self.assertEqual(json.loads(result.stdout)["source_executions"], 0)

    def test_unchanged_r3_stdin_cap_not_host_argv_assumption(self):
        self.assertLessEqual(len(self.payload), 256 * 1024)
        self.assertEqual(payload.R3_STDIN_MAX_BYTES, 256 * 1024)
        self.assertEqual(CODEC.MAX_FRAME_BYTES, 128 * 1024)
        self.assertEqual(CODEC.MAX_TOTAL_BYTES, 2 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
