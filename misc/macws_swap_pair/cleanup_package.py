"""Pure fixed-name cleanup package; no loader, native factory, or action.

The caller supplies independently selected trusted source and data pins and an
already trusted retained_frame codec. Matching hashes are byte identity only:
they provide no current device freshness, archive acknowledgement, authority,
or native witness. The five source entries are returned as bytes, never run.
"""

import hashlib
import json
import re


SCHEMA = "macws.current-installation-cleanup.package.v1"
SOURCE_NAMES = (
    "current_installation_cleanup.py", "installation_revalidation.py",
    "retained_cleanup.py", "retained_observer.py", "readonly_observer.py",
)
FILE_ALIASES = {
    "probe.arm64": "probe.arm64",
    "controller.py": "controller.py",
    "runtime_support.py": "runtime_support.py",
    "watchdog.py": "watchdog.py",
    "offline-QA.canonical.private.json": "offline_qa.private.json",
}
DATA_NAMES = ("delivery.private.json", "context.private.json", *FILE_ALIASES.values())
ENTRY_NAMES = frozenset((*SOURCE_NAMES, *DATA_NAMES))
SOURCE_ROLES = {
    "cleanup": "current_installation_cleanup.py",
    "provenance": "installation_revalidation.py",
    "stat_record": "retained_cleanup.py",
    "physical_directory": "retained_observer.py",
}
SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
MAX_CONTEXT_BYTES = 8192
MAX_DELIVERY_BYTES = 65536
MAX_SOURCE_BYTES = 128 * 1024
MAX_FILE_BYTES = 128 * 1024


class Refused(ValueError):
    """Categorical malformed, changed, or over-budget package refusal."""


def need(condition, reason):
    if condition is not True:
        raise Refused(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _keys(value, names):
    need(type(value) is dict and set(value) == set(names), "exact_dictionary_names")


def _pins(value, names):
    _keys(value, names)
    need(all(type(digest) is str and SHA256.fullmatch(digest) is not None
             for digest in value.values()), "trusted_lowercase_sha256")
    return dict(value)


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(",", ":")).encode("ascii")


def _context_json(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_CONTEXT_BYTES,
         "bounded_immutable_context")
    # Reject nesting and node floods before handing untrusted text to json.
    depth = containers = separators = 0
    quoted = escaped = False
    for byte in raw:
        need(byte < 128, "canonical_context_ascii")
        if quoted:
            if escaped: escaped = False
            elif byte == 92: escaped = True
            elif byte == 34: quoted = False
        elif byte == 34: quoted = True
        elif byte in (91, 123):
            depth += 1; containers += 1
            need(depth <= 4 and containers <= 16, "context_nesting_budget")
        elif byte in (93, 125):
            depth -= 1; need(depth >= 0, "context_nesting")
        elif byte in (44, 58):
            separators += 1; need(separators <= 128, "context_value_budget")
    need(depth == 0 and not quoted, "complete_context_structure")

    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate_context_key")
            result[key] = value
        return result

    def integer(word):
        need(len(word) <= 20, "context_integer_budget")
        return int(word)

    def no_number(_word):
        raise Refused("context_float_or_constant")

    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
                           parse_int=integer, parse_float=no_number,
                           parse_constant=no_number)
        need(_canonical(value) == raw, "canonical_context_encoding")
        return value
    except Refused:
        raise
    except (ValueError, UnicodeError, RecursionError, OverflowError) as error:
        raise Refused("invalid_context_json") from error


def checked_context(raw, source_pins):
    """Check only the explicit package contract; this grants no freshness."""
    value = _context_json(raw)
    _keys(value, ("binding", "UI_private", "attempt_nonce", "clock_info", "source_sha256"))
    binding = value["binding"]
    _keys(binding, ("hw.machine", "kern.osversion", "kern.uuid", "kern.bootsessionuuid",
                    "rootfs_product_version", "rootfs_product_build"))
    need(all(type(word) is str and 0 < len(word) <= 128 and word.isascii() and
             all(32 <= ord(char) < 127 for char in word) for word in binding.values()),
         "explicit_binding_words")
    need(type(value["attempt_nonce"]) is str and
         re.fullmatch(r"[0-9a-f]{32}", value["attempt_nonce"], re.ASCII) is not None,
         "explicit_attempt_nonce")
    ui = value["UI_private"]; _keys(ui, ("SpringBoard", "backboardd"))
    for birth in ui.values():
        need(type(birth) is list and len(birth) == 3 and all(type(item) is int for item in birth) and
             1 < birth[0] <= 0x7fffffff and 0 < birth[1] < 1 << 63 and 0 <= birth[2] < 1000000,
             "explicit_ui_birth")
    need(ui["SpringBoard"][0] != ui["backboardd"][0], "distinct_ui_births")
    profile = value["clock_info"]; _keys(profile, ("domain", "numer", "denom"))
    need(profile["domain"] == "mach_absolute_time.absolute_seconds.v1" and
         all(type(profile[key]) is int and 0 < profile[key] <= 1000000000
             for key in ("numer", "denom")), "explicit_clock_profile")
    _keys(value["source_sha256"], SOURCE_ROLES)
    need(value["source_sha256"] == {role: source_pins[name] for role, name in SOURCE_ROLES.items()},
         "context_sources_match_independent_trusted_pins")
    return value


def _checked_entries(entries, source_pins, data_pins):
    source_pins = _pins(source_pins, SOURCE_NAMES)
    data_pins = _pins(data_pins, DATA_NAMES)
    _keys(entries, ENTRY_NAMES)
    pins = dict(source_pins, **data_pins)
    checked = {}
    # Every source/data pin is checked before parsing any entry as JSON.
    for name in sorted(ENTRY_NAMES):
        raw = entries[name]
        limit = (MAX_CONTEXT_BYTES if name == "context.private.json" else
                 MAX_DELIVERY_BYTES if name == "delivery.private.json" else
                 MAX_SOURCE_BYTES if name in SOURCE_NAMES else MAX_FILE_BYTES)
        need(type(raw) is bytes and 0 < len(raw) <= limit, "bounded_immutable_entry")
        need(sha(raw) == pins[name], "independent_trusted_entry_pin")
        checked[name] = raw
    checked_context(checked["context.private.json"], source_pins)
    return checked, source_pins, data_pins


def named_entries(*, sources, delivery_raw, archived_files, context_raw):
    """Map only the five-source closure, original receipt, five blobs, context."""
    _keys(sources, SOURCE_NAMES); _keys(archived_files, FILE_ALIASES)
    return dict(sources, **{"delivery.private.json": delivery_raw,
                           "context.private.json": context_raw},
                **{alias: archived_files[name] for name, alias in FILE_ALIASES.items()})


class VerifiedPackage:
    """Owned immutable bytes only; no operation/callback/native constructors."""
    def __init__(self, entries, source_pins, data_pins):
        self._entries, self._source_pins, self._data_pins = _checked_entries(entries, source_pins, data_pins)

    def entries(self):
        return dict(self._entries)

    def sources(self):
        return {name: self._entries[name] for name in SOURCE_NAMES}

    def delivery_raw(self):
        return self._entries["delivery.private.json"]

    def archived_files(self):
        return {name: self._entries[alias] for name, alias in FILE_ALIASES.items()}

    def context_raw(self):
        return self._entries["context.private.json"]

    def context(self):
        return checked_context(self.context_raw(), self._source_pins)

    def summary(self):
        return dict(metadata(), mode="verified-bytes-only", entry_count=len(self._entries),
                    decoded_bytes=sum(len(raw) for raw in self._entries.values()),
                    all_independent_pins_verified=True, required_source_entries_present=True)


def build(*, entries, trusted_source_sha256, trusted_data_sha256, codec):
    """Use an already trusted unchanged codec; execute no packaged source."""
    checked, source_pins, data_pins = _checked_entries(entries, trusted_source_sha256, trusted_data_sha256)
    return codec.encode(checked, dict(source_pins, **data_pins))


def decode(*, frame_raw, trusted_source_sha256, trusted_data_sha256, codec):
    """Verify every externally pinned entry before returning any source bytes."""
    source_pins = _pins(trusted_source_sha256, SOURCE_NAMES)
    data_pins = _pins(trusted_data_sha256, DATA_NAMES)
    entries = codec.decode(frame_raw, dict(source_pins, **data_pins))
    return VerifiedPackage(entries, source_pins, data_pins)


def metadata():
    return {"schema": SCHEMA, "mode": "metadata-only", "default_inert": True,
            "native_calls": 0, "source_executions": 0, "unlink_calls": 0, "rmdir_calls": 0,
            "execution_authority": False, "archive_acknowledgement": False,
            "current_device_freshness": False, "device_acceptance": False,
            "required_source_modules": 5, "source_closure_executable": False}


def main():
    print(json.dumps(metadata(), sort_keys=True))


if __name__ == "__main__":
    main()
