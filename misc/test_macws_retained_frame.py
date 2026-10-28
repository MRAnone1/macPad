"""Synthetic offline tests; framed bytes are never executable source."""
import builtins
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock
import zlib
from macws_swap_pair import retained_frame as frame


def pins(entries):
    return {name: hashlib.sha256(raw).hexdigest() for name, raw in entries.items()}


def document(entries):
    rows, offset = [], 0
    for name in sorted(entries):
        raw = entries[name]
        rows.append({'name': name, 'size': len(raw), 'offset': offset,
                     'sha256': hashlib.sha256(raw).hexdigest()})
        offset += len(raw)
    return {'schema': frame.SCHEMA, 'entries': rows}


def compressed(expanded):
    return frame.MAGIC + zlib.compress(expanded, 9)


def meta_packed(meta, payload=b''):
    return compressed(len(meta).to_bytes(4, 'big') + meta + payload)


def packed(value, payload=b''):
    return meta_packed(frame._canonical(value), payload)


class RetainedFrameTests(unittest.TestCase):
    def setUp(self):
        self.entries = {'config.json': b'{"sample":true}\n',
                        'retained_inputs.py': b"raise AssertionError('never execute')\n",
                        'empty.bin': b''}
        self.pins = pins(self.entries)
        self.value = document(self.entries)
        self.payload = b''.join(self.entries[name] for name in sorted(self.entries))
        self.raw = frame.encode(self.entries, self.pins)

    def refuse_value(self, mutation):
        value = document(self.entries)
        mutation(value)
        with self.assertRaises(frame.Refused):
            frame.decode(packed(value, self.payload), self.pins)

    def test_roundtrip_lossless(self):
        self.assertEqual(frame.decode(self.raw, self.pins), self.entries)

    def test_deterministic_order(self):
        self.assertEqual(frame.encode(dict(reversed(list(self.entries.items()))), self.pins), self.raw)

    def test_all_byte_values_roundtrip(self):
        entries = {'all.bin': bytes(range(256)) * 100}
        self.assertEqual(frame.decode(frame.encode(entries, pins(entries)), pins(entries)), entries)

    def test_result_and_pins_ownership(self):
        before = self.pins.copy()
        frame.decode(self.raw, self.pins).clear()
        self.assertEqual(frame.decode(self.raw, self.pins), self.entries)
        self.assertEqual(self.pins, before)

    def test_empty_or_non_dict_pins(self):
        for bad in ({}, [], None, (), True):
            with self.subTest(bad=bad), self.assertRaises(frame.Refused):
                frame.decode(self.raw, bad)

    def test_too_many_pins(self):
        many = {'a' + str(n): '0' * 64 for n in range(frame.MAX_ENTRIES + 1)}
        with self.assertRaises(frame.Refused):
            frame.decode(self.raw, many)

    def test_bad_pin_names(self):
        for name in (1, '', '../x', 'a/b', 'A', 'a\n', 'a' * 97, 'ä', '.a', 'a\x00'):
            with self.subTest(name=name), self.assertRaises(frame.Refused):
                frame.decode(self.raw, {name: '0' * 64})

    def test_bad_pin_values(self):
        for digest in (True, None, b'0' * 64, 'F' * 64, 'g' * 64, '0' * 63, '0' * 65):
            with self.subTest(digest=digest), self.assertRaises(frame.Refused):
                frame.decode(self.raw, {'x': digest})

    def test_pin_subclass_rejected(self):
        class Mapping(dict): pass
        with self.assertRaises(frame.Refused):
            frame.decode(self.raw, Mapping(self.pins))

    def test_encode_exact_names(self):
        for entries in ({}, {'unknown': b'x'}, []):
            with self.subTest(entries=entries), self.assertRaises(frame.Refused):
                frame.encode(entries, self.pins)

    def test_encode_bytes_exact_type(self):
        for value in (bytearray(b'x'), memoryview(b'x'), 'x', True):
            with self.subTest(value=type(value).__name__), self.assertRaises(frame.Refused):
                frame.encode({'x': value}, {'x': '0' * 64})

    def test_encode_pin_mismatch(self):
        with self.assertRaises(frame.Refused):
            frame.encode(self.entries, dict(self.pins, **{'config.json': '0' * 64}))

    def test_encode_entry_cap(self):
        entries = {'x': b'x' * (frame.MAX_ENTRY_BYTES + 1)}
        with self.assertRaises(frame.Refused): frame.encode(entries, pins(entries))

    def test_total_cap_encode(self):
        entries = {'x' + str(n): b'x' * frame.MAX_ENTRY_BYTES for n in range(5)}
        with self.assertRaises(frame.Refused): frame.encode(entries, pins(entries))

    def test_exact_total_and_entry_caps(self):
        entries = {'x' + str(n): b'x' * frame.MAX_ENTRY_BYTES for n in range(4)}
        self.assertEqual(frame.decode(frame.encode(entries, pins(entries)), pins(entries)), entries)

    def test_max_entries_and_names_roundtrip(self):
        entries = {'x' + str(n).zfill(2) + 'a' * 93: b'' for n in range(frame.MAX_ENTRIES)}
        self.assertEqual(frame.decode(frame.encode(entries, pins(entries)), pins(entries)), entries)

    def test_compressed_cap_encode(self):
        raw = b''.join(hashlib.sha256(str(n).encode()).digest() for n in range(5000))
        entries = {'noise': raw}
        with self.assertRaisesRegex(frame.Refused, 'compressed byte budget'):
            frame.encode(entries, pins(entries))

    def test_raw_type_size(self):
        for raw in ('x', None, bytearray(self.raw), b'', frame.MAGIC,
                    b'x' * (frame.MAX_FRAME_BYTES + 1)):
            with self.subTest(raw=type(raw).__name__), self.assertRaises(frame.Refused):
                frame.decode(raw, self.pins)

    def test_magic_version(self):
        for raw in (b'X' + self.raw[1:], self.raw[:len(frame.MAGIC) - 1] + b'\x02' + self.raw[len(frame.MAGIC):]):
            with self.subTest(), self.assertRaises(frame.Refused): frame.decode(raw, self.pins)

    def test_every_truncation_refused(self):
        for length in range(len(self.raw)):
            with self.subTest(length=length), self.assertRaises(frame.Refused):
                frame.decode(self.raw[:length], self.pins)

    def test_trailing_byte_and_concatenated_stream_refused(self):
        for trailing in (b'\x00', b'\n', zlib.compress(b'{}'), self.raw):
            with self.subTest(), self.assertRaises(frame.Refused):
                frame.decode(self.raw + trailing, self.pins)

    def test_checksum_mutation_refused(self):
        with self.assertRaises(frame.Refused):
            frame.decode(self.raw[:-1] + bytes([self.raw[-1] ^ 1]), self.pins)

    def test_other_compression_formats_refused(self):
        expanded = zlib.decompress(self.raw[len(frame.MAGIC):])
        for bits in (-zlib.MAX_WBITS, zlib.MAX_WBITS + 16):
            compressor = zlib.compressobj(wbits=bits)
            raw = frame.MAGIC + compressor.compress(expanded) + compressor.flush()
            with self.subTest(bits=bits), self.assertRaises(frame.Refused): frame.decode(raw, self.pins)

    def test_expansion_bomb_refused_before_json(self):
        raw = compressed(b'0' * (frame.MAX_PAYLOAD_BYTES + 1))
        with mock.patch.object(json, 'loads', side_effect=AssertionError('parser reached')):
            with self.assertRaisesRegex(frame.Refused, 'expanded byte budget'): frame.decode(raw, self.pins)

    def test_no_unbounded_flush_and_bounded_decompress(self):
        original, calls = zlib.decompressobj, []
        class Recorder:
            def __init__(self, *args): self.inner = original(*args)
            def decompress(self, data, max_length=0):
                calls.append(max_length)
                return self.inner.decompress(data, max_length)
            def flush(self, *_args): raise AssertionError('unbounded flush forbidden')
            def __getattr__(self, name): return getattr(self.inner, name)
        with mock.patch.object(zlib, 'decompressobj', Recorder):
            self.assertEqual(frame.decode(self.raw, self.pins), self.entries)
        self.assertEqual(calls, [frame.MAX_PAYLOAD_BYTES + 1])

    def test_header_length_boundaries(self):
        for expanded in (b'', b'\x00', b'\x00' * 3, b'\x00' * 4,
                         (frame.MAX_JSON_BYTES + 1).to_bytes(4, 'big') + b'{}',
                         (10).to_bytes(4, 'big') + b'{}', b'\xff' * 4):
            with self.subTest(expanded=expanded), self.assertRaises(frame.Refused):
                frame.decode(compressed(expanded), self.pins)

    def test_short_and_extra_payload_refused(self):
        for payload in (self.payload[:-1], self.payload + b'\x00', self.payload + b'extra'):
            with self.subTest(), self.assertRaises(frame.Refused):
                frame.decode(packed(self.value, payload), self.pins)

    def test_top_level_shape(self):
        for value in ([], True, None, 1, 'x', {}, dict(self.value, extra=True)):
            with self.subTest(value=type(value).__name__), self.assertRaises(frame.Refused):
                frame.decode(packed(value, self.payload), self.pins)

    def test_schema_changed(self):
        for schema in (1, True, None, 'macws-retained-frame-v2'):
            with self.subTest(schema=schema): self.refuse_value(lambda value: value.update(schema=schema))

    def test_entry_names_order_exact(self):
        for change in (lambda value: value['entries'].pop(),
                       lambda value: value['entries'].reverse(),
                       lambda value: value['entries'][0].update(name='foreign'),
                       lambda value: value['entries'][1].update(name='config.json')):
            self.refuse_value(change)

    def test_entries_list_only(self):
        for entries in ({}, True, None, 'x'):
            with self.subTest(entries=entries): self.refuse_value(lambda value: value.update(entries=entries))

    def test_entry_wrong_shapes(self):
        for entry in ([], True, None, {}, {'size': 0}, dict(self.value['entries'][0], extra=1)):
            with self.subTest(entry=entry): self.refuse_value(lambda value: value['entries'].__setitem__(0, entry))

    def test_bad_declared_sizes(self):
        for size in (True, None, '1', -1, frame.MAX_ENTRY_BYTES + 1):
            with self.subTest(size=size): self.refuse_value(lambda value: value['entries'][0].update(size=size))

    def test_declared_size_mismatch(self):
        self.refuse_value(lambda value: value['entries'][0].update(size=1))

    def test_offsets_gaps_overlaps_and_types(self):
        for offset in (True, None, '0', -1, 1, frame.MAX_TOTAL_BYTES + 1):
            with self.subTest(offset=offset): self.refuse_value(lambda value: value['entries'][0].update(offset=offset))
        for offset in (0, len(self.entries['config.json']) + 1):
            with self.subTest(offset=offset): self.refuse_value(lambda value: value['entries'][1].update(offset=offset))

    def test_total_cap_decode(self):
        entries = {'x' + str(n): b'x' * frame.MAX_ENTRY_BYTES for n in range(4)}
        entries['x4'] = b'x'
        with self.assertRaisesRegex(frame.Refused, 'decoded byte budget'):
            frame.decode(packed(document(entries), b''.join(entries[n] for n in sorted(entries))), pins(entries))

    def test_coherent_in_frame_hash_rewrite_does_not_replace_caller_pin(self):
        changed = dict(self.entries, **{'config.json': b'malicious'})
        with self.assertRaisesRegex(frame.Refused, 'trusted SHA-256 mismatch'):
            frame.decode(packed(document(changed), b''.join(changed[n] for n in sorted(changed))), self.pins)

    def test_content_change_preserving_declared_hash_refused(self):
        with self.assertRaisesRegex(frame.Refused, 'byte SHA-256 mismatch'):
            frame.decode(packed(self.value, b'x' * len(self.payload)), self.pins)

    def test_duplicate_keys(self):
        with self.assertRaisesRegex(frame.Refused, 'duplicate key'):
            frame.decode(meta_packed(b'{"entries":[],"schema":"x","schema":"x"}\n'), self.pins)

    def test_noncanonical_json(self):
        raw = frame._canonical(self.value)
        for meta in (raw[:-1], b' ' + raw, raw.replace(b'"schema":', b'"schema" :'), raw + b'\n'):
            with self.subTest(), self.assertRaisesRegex(frame.Refused, 'noncanonical'):
                frame.decode(meta_packed(meta, self.payload), self.pins)

    def test_nonfinite_float_overflow_and_large_integer(self):
        for token in (b'NaN', b'Infinity', b'-Infinity', b'1e99999', b'1.0', b'9' * 100):
            with self.subTest(token=token[:20]), self.assertRaises(frame.Refused):
                frame.decode(meta_packed(b'{"entries":[],"schema":' + token + b'}\n'), self.pins)

    def test_depth_rejected_before_parser(self):
        meta = b'[' * 500 + b'0' + b']' * 500
        with mock.patch.object(json, 'loads', side_effect=AssertionError('parser reached')):
            with self.assertRaisesRegex(frame.Refused, 'nesting/container'): frame.decode(meta_packed(meta), self.pins)

    def test_flat_node_budget_rejected_before_parser(self):
        meta = b'[' + b'0,' * 1000 + b'0]'
        with mock.patch.object(json, 'loads', side_effect=AssertionError('parser reached')):
            with self.assertRaisesRegex(frame.Refused, 'value budget'): frame.decode(meta_packed(meta), self.pins)

    def test_container_budget_rejected_before_parser(self):
        meta = b'[' + b'{},' * 45 + b'{}]'
        with mock.patch.object(json, 'loads', side_effect=AssertionError('parser reached')):
            with self.assertRaisesRegex(frame.Refused, 'nesting/container'): frame.decode(meta_packed(meta), self.pins)

    def test_invalid_ascii_and_json(self):
        for meta in (b'\xff', b'{"x":"\xc3\xa4"}\n', b'{', b'}', b'"unterminated', b'{}{}', b'{"x":}'):
            with self.subTest(meta=meta), self.assertRaises(frame.Refused): frame.decode(meta_packed(meta), self.pins)

    def test_brackets_and_escaped_quotes_in_strings_do_not_affect_depth(self):
        with self.assertRaisesRegex(frame.Refused, 'exact shape'):
            frame.decode(packed({'strange': '\\"[{}]"' * 200}), self.pins)

    def test_encoder_decoder_no_io_or_exec(self):
        with mock.patch.object(builtins, 'open', side_effect=AssertionError('open')), \
             mock.patch.object(builtins, 'exec', side_effect=AssertionError('exec')), \
             mock.patch.object(builtins, 'eval', side_effect=AssertionError('eval')), \
             mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('Popen')):
            self.assertEqual(frame.decode(frame.encode(self.entries, self.pins), self.pins), self.entries)

    def test_default_main_metadata_only(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), \
             mock.patch.object(builtins, 'open', side_effect=AssertionError('open')), \
             mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('Popen')):
            frame.main()
        self.assertEqual(json.loads(out.getvalue())['mode'], 'metadata-only')

    def test_default_cli_actual_process_metadata(self):
        result = subprocess.run([sys.executable, '-B', str(Path(frame.__file__))],
                                input=b'ignored stdin', capture_output=True, timeout=5, check=True)
        self.assertEqual(result.stderr, b'')
        self.assertEqual(json.loads(result.stdout), frame.metadata())


if __name__ == '__main__':
    unittest.main()
