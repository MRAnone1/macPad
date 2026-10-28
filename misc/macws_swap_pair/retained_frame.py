"""Bounded lossless frame codec; metadata-only import and default CLI.

Trusted callers supply the exact name -> SHA-256 mapping. The frame contains
no authority to choose a source pin, import a module, or operate on a device.
"""

import hashlib
import json
import re
import zlib


MAGIC = b"MACWS-RETAINED-FRAME\x00\x01"
SCHEMA = "macws-retained-frame-v1"
MAX_FRAME_BYTES = 128 * 1024
MAX_JSON_BYTES = 8 * 1024
MAX_ENTRY_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_PAYLOAD_BYTES = 4 + MAX_JSON_BYTES + MAX_TOTAL_BYTES
MAX_ENTRIES = 32
MAX_DEPTH = 4
MAX_CONTAINERS = 40
MAX_JSON_KEYS = 140
MAX_SEPARATORS = 384
NAME = re.compile(r"[a-z][a-z0-9_.-]{0,95}\Z", re.ASCII)
SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class Refused(ValueError):
    """Malformed, changed, incomplete, or over-budget frame."""


def _pins(pins):
    if type(pins) is not dict or not 1 <= len(pins) <= MAX_ENTRIES:
        raise Refused("pins: exact nonempty bounded dictionary required")
    checked = {}
    for name, digest in pins.items():
        if type(name) is not str or NAME.fullmatch(name) is None:
            raise Refused("pins: entry name")
        if type(digest) is not str or SHA256.fullmatch(digest) is None:
            raise Refused("pins: lowercase SHA-256 required")
        checked[name] = digest
    return checked


def _canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")


def _syntax_budget(raw):
    """Limit nesting before json's recursive parser sees untrusted text."""
    depth = containers = separators = 0
    quoted = escaped = False
    for byte in raw:
        if byte > 127:
            raise Refused("JSON: canonical ASCII required")
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            containers += 1
            if depth > MAX_DEPTH or containers > MAX_CONTAINERS:
                raise Refused("JSON: nesting/container budget")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise Refused("JSON: nesting")
        elif byte in (44, 58):
            separators += 1
            if separators > MAX_SEPARATORS:
                raise Refused("JSON: value budget")
    if depth or quoted:
        raise Refused("JSON: incomplete structure")


def _json(raw):
    _syntax_budget(raw)
    key_count = 0

    def pairs(items):
        nonlocal key_count
        key_count += len(items)
        if key_count > MAX_JSON_KEYS:
            raise Refused("JSON: key budget")
        value = {}
        for key, item in items:
            if key in value:
                raise Refused("JSON: duplicate key")
            value[key] = item
        return value

    def integer(value):
        if len(value) > 8:
            raise Refused("JSON: integer budget")
        return int(value)

    def no_number(_value):
        raise Refused("JSON: floats/constants forbidden")

    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
                           parse_int=integer, parse_float=no_number,
                           parse_constant=no_number)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, Refused):
            raise
        raise Refused("JSON: invalid") from exc
    if _canonical(value) != raw:
        raise Refused("JSON: noncanonical encoding")
    return value


def encode(entries, pins):
    """Return one compressed frame, after checking every exact caller pin."""
    checked = _pins(pins)
    if type(entries) is not dict or entries.keys() != checked.keys():
        raise Refused("entries: exact pinned names required")
    rows = []
    contents = []
    total = 0
    for name in sorted(checked):
        value = entries[name]
        if type(value) is not bytes or len(value) > MAX_ENTRY_BYTES:
            raise Refused("entry: byte type/size")
        if total + len(value) > MAX_TOTAL_BYTES:
            raise Refused("entries: decoded byte budget")
        if hashlib.sha256(value).hexdigest() != checked[name]:
            raise Refused("entry: trusted SHA-256 mismatch")
        rows.append({"name": name, "offset": total, "sha256": checked[name],
                     "size": len(value)})
        contents.append(value)
        total += len(value)
    meta = _canonical({"entries": rows, "schema": SCHEMA})
    if len(meta) > MAX_JSON_BYTES:
        raise Refused("JSON: byte budget")
    raw = len(meta).to_bytes(4, "big") + meta + b"".join(contents)
    frame = MAGIC + zlib.compress(raw, level=9)
    if len(frame) > MAX_FRAME_BYTES:
        raise Refused("frame: compressed byte budget")
    return frame


def decode(raw, pins):
    """Decode all exact pinned bytes or refuse; never execute frame contents."""
    checked = _pins(pins)
    if type(raw) is not bytes or not len(MAGIC) < len(raw) <= MAX_FRAME_BYTES:
        raise Refused("frame: byte type/size")
    if not raw.startswith(MAGIC):
        raise Refused("frame: magic/version")
    compressed = raw[len(MAGIC):]
    try:
        decompressor = zlib.decompressobj(zlib.MAX_WBITS)
        expanded = decompressor.decompress(compressed, MAX_PAYLOAD_BYTES + 1)
    except zlib.error as exc:
        raise Refused("frame: invalid zlib stream") from exc
    if len(expanded) > MAX_PAYLOAD_BYTES:
        raise Refused("frame: expanded byte budget")
    if not decompressor.eof or decompressor.unconsumed_tail or decompressor.unused_data:
        raise Refused("frame: incomplete/extra/over-budget zlib stream")
    if len(expanded) < 4:
        raise Refused("frame: missing metadata length")
    meta_size = int.from_bytes(expanded[:4], "big")
    if not 1 <= meta_size <= MAX_JSON_BYTES or len(expanded) < 4 + meta_size:
        raise Refused("frame: metadata byte boundary")
    value = _json(expanded[4:4 + meta_size])
    if type(value) is not dict or set(value) != {"entries", "schema"}:
        raise Refused("frame: exact shape")
    if type(value["schema"]) is not str or value["schema"] != SCHEMA:
        raise Refused("frame: schema")
    entries = value["entries"]
    if type(entries) is not list or len(entries) != len(checked):
        raise Refused("entries: exact pinned row count required")
    decoded = {}
    total = 0
    payload_start = 4 + meta_size
    for name, entry in zip(sorted(checked), entries):
        if type(entry) is not dict or set(entry) != {"name", "offset", "sha256", "size"}:
            raise Refused("entry: exact shape")
        if type(entry["name"]) is not str or entry["name"] != name:
            raise Refused("entry: exact pinned order/names required")
        if type(entry["offset"]) is not int or entry["offset"] != total:
            raise Refused("entry: contiguous byte offset required")
        size = entry["size"]
        if type(size) is not int or not 0 <= size <= MAX_ENTRY_BYTES:
            raise Refused("entry: byte size")
        digest = entry["sha256"]
        if type(digest) is not str or digest != checked[name]:
            raise Refused("entry: trusted SHA-256 mismatch")
        # Validate every boundary before slicing copied entry contents.
        if total + size > MAX_TOTAL_BYTES:
            raise Refused("entries: decoded byte budget")
        start = payload_start + total
        end = start + size
        if end > len(expanded):
            raise Refused("entry: byte boundary")
        data = expanded[start:end]
        if hashlib.sha256(data).hexdigest() != digest:
            raise Refused("entry: byte SHA-256 mismatch")
        decoded[name] = data
        total += size
    if payload_start + total != len(expanded):
        raise Refused("frame: unaccounted payload bytes")
    return decoded


def metadata():
    return {"schema": SCHEMA, "mode": "metadata-only", "native_io": False,
            "execution_authority": False, "max_frame_bytes": MAX_FRAME_BYTES,
            "max_json_bytes": MAX_JSON_BYTES, "max_entry_bytes": MAX_ENTRY_BYTES,
            "max_total_bytes": MAX_TOTAL_BYTES, "max_entries": MAX_ENTRIES,
            "max_payload_bytes": MAX_PAYLOAD_BYTES}


def main():
    print(json.dumps(metadata(), sort_keys=True))


if __name__ == "__main__":
    main()
