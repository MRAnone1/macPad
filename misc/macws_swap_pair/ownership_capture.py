"""Offline/private original OwnedFiles capture; never a recovery authority.

The caller must hold the unchanged pinned runtime's original OwnedFiles object
immediately after create(), before watchdog/bootstrap. This module cannot prove
that timing or caller provenance, and deliberately makes no such JSON claim.
It offers only bounded source reads and the existing read-only checked() call.
No native construction, creation, writing, deletion, signal, job or transport
route exists. Import/default CLI is metadata-only.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import types

SOURCES = {
    "controller.py": "955c50b5cb2b30b8f0aefd69720675d04c91126dec17c802fb09be8c42197977",
    "runtime_support.py": "5d09cf9380afaa2409661a58909d1bfee41d81943f1b2306facb0cd94ee10fe0",
    "watchdog.py": "c28ec9edd30bf86613c7cb29693697901228b579100b8b181a4dc47915f00e0a",
}
SCRATCH_BY_OPERATION = {
    "run": "/private/var/tmp/macws-swap-pair-20261017",
    "control_normal": "/private/var/tmp/macws-swap-pair-control-20261018",
    "control_parent_EOF": "/private/var/tmp/macws-swap-pair-control-20261018",
    "control_deadline": "/private/var/tmp/macws-swap-pair-control-20261018",
}
SCHEMA = "macws.swap-pair.original-owned-files.witness.v1"
LIMIT = 16384
FALSE_FLAGS = (
    "creation_timing_verified", "caller_provenance_authenticated",
    "native_evidence_authenticity_verified", "device_acceptance",
    "control_authorized", "durable_host_preservation_verified",
)


class Refused(ValueError):
    pass


def need(condition, message):
    if condition is not True:
        raise Refused(message)


def _copy(value, depth=0, budget=None):
    """Typed bounded JSON copy, before hashing or calling runtime validators."""
    budget = [1024] if budget is None else budget
    budget[0] -= 1
    need(budget[0] >= 0 and depth <= 10, "JSON structural bound")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        need(0 <= value < 1 << 64, "bounded unsigned integer")
        return value
    if type(value) is float:
        # v7 accepts finite positive fractional deadlines. Reject NaN/inf.
        need(0 <= value <= 1e18, "bounded finite number")
        return value
    if type(value) is str:
        need(len(value) <= 4096 and len(value.encode("utf-8")) <= 4096,
             "bounded UTF-8 string")
        return value
    if type(value) is list:
        need(len(value) <= 64, "bounded array")
        return [_copy(item, depth + 1, budget) for item in value]
    need(type(value) is dict and len(value) <= 64 and
         all(type(key) is str and len(key) <= 128 for key in value),
         "plain bounded object")
    return {key: _copy(item, depth + 1, budget) for key, item in value.items()}


def canonical(value):
    raw = json.dumps(_copy(value), sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    need(len(raw) <= LIMIT, "complete JSON byte bound")
    return raw


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _source_bytes(path):
    # Refuse a substituted FIFO/device after opening without waiting for a peer.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 512 * 1024,
             "bounded regular pinned source")
        raw = bytearray()
        while len(raw) <= before.st_size:
            block = os.read(fd, min(65536, before.st_size + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(fd)
        fields = lambda info: (info.st_dev, info.st_ino, info.st_size,
                               info.st_mtime_ns, info.st_ctime_ns, info.st_mode,
                               info.st_uid, info.st_gid, info.st_nlink)
        need(len(raw) == before.st_size and fields(before) == fields(after) ==
             fields(os.lstat(path)), "pinned source changed during read")
        return bytes(raw)
    finally:
        os.close(fd)


def _bindings(runtime, config, current_sources):
    config = _copy(config)
    current_sources = _copy(current_sources)
    canonical(config)
    need(current_sources == SOURCES, "exact original v7 source map")
    need(type(runtime) is types.ModuleType and type(runtime.__file__) is str,
         "caller-held pinned runtime module")
    directory = Path(runtime.__file__).parent
    need(Path(runtime.__file__).name == "runtime_support.py", "runtime source name")
    for name, digest in SOURCES.items():
        need(_sha(_source_bytes(directory / name)) == digest, "pinned source bytes: " + name)
    # These are the existing v7 gates, not a substitute permissive config parser.
    runtime.config_checked(config)
    need(config["source_sha256"] == current_sources, "config source map differs")
    need(runtime.scratch_path(config) == SCRATCH_BY_OPERATION[config["operation"]],
         "fixed operation scratch")
    return config


def _identity(value):
    need(type(value) is list and len(value) == 2 and
         all(type(item) is int and 0 <= item < 1 << 64 for item in value) and
         value[1] > 0, "original bounded device/inode identity")


def _payload(config, runtime, directory_token, files):
    return {
        "schema": SCHEMA,
        "evidence_kind": "caller-held-original-OwnedFiles-unverified-provenance",
        "operation": config["operation"],
        "scratch_path": SCRATCH_BY_OPERATION[config["operation"]],
        "launchd_domain": "user/501",
        "job_label": runtime.job_label(config),
        "run_nonce": config["run_nonce"],
        "boot_private": config["boot_private"],
        "config_sha256": runtime.config_sha(config),
        "admission_sha256": runtime.admission_sha(config),
        "source_sha256": _copy(config["source_sha256"]),
        "directory_token_private": _copy(directory_token),
        "files_private": _copy(files),
        **{key: False for key in FALSE_FLAGS},
    }


def validate_witness(value, *, runtime, config, current_sources):
    """Return an independent typed copy. Validation grants no action authority."""
    config = _bindings(runtime, config, current_sources)
    result = _copy(value)
    need(type(result) is dict and set(result) == {"witness", "witness_sha256"},
         "fixed capture envelope")
    witness = result["witness"]
    need(type(witness) is dict and "directory_token_private" in witness and
         "files_private" in witness, "ownership fields present")
    _identity(witness["directory_token_private"])
    files = witness["files_private"]
    need(type(files) is dict and set(files) == {"job.plist", "probe.log"}, "two original files")
    for name, item in files.items():
        need(type(item) is dict and set(item) == {"identity", "sha256"}, "fixed original file schema")
        _identity(item["identity"])
        if name == "job.plist":
            need(item["sha256"] == _sha(runtime.plist_bytes(config)), "original immutable plist hash")
        else:
            need(item["sha256"] is None, "unknown mutable log hash must remain null")
    need(files["job.plist"]["identity"] != files["probe.log"]["identity"] and
         all(item["identity"] != witness["directory_token_private"] for item in files.values()) and
         all(item["identity"][0] == witness["directory_token_private"][0] for item in files.values()),
         "distinct same-directory file identities")
    expected = _payload(config, runtime, witness["directory_token_private"], files)
    need(witness == expected and all(witness[key] is False for key in FALSE_FLAGS),
         "exact operation/session/source/boot/config bindings and false authority flags")
    need(type(result["witness_sha256"]) is str and
         result["witness_sha256"] == _sha(canonical(witness)), "capture digest")
    canonical(result)
    return result


def capture_owned_files(files, *, runtime, config, current_sources):
    """Freeze ORIGINAL stored identities after the original checked() succeeds.

    Caller must invoke this immediately after its original create(). No fresh
    stat result is used as a replacement ownership token. An object/class and
    matching source files cannot authenticate call history or process integrity.
    """
    config = _bindings(runtime, config, current_sources)
    need(type(files) is runtime.OwnedFiles and type(files.fd) is int and files.fd >= 3,
         "caller-held exact OwnedFiles instance")
    need(files.path == SCRATCH_BY_OPERATION[config["operation"]], "owned operation scratch")
    # Freeze stored values before checked(); a rejected object is never adopted.
    directory_token, original_files = _copy(files.directory_token), _copy(files.files)
    witness = _payload(config, runtime, directory_token, original_files)
    result = {"witness": witness, "witness_sha256": _sha(canonical(witness))}
    validate_witness(result, runtime=runtime, config=config, current_sources=current_sources)
    need(files.checked() is True, "original OwnedFiles check refused")
    need(canonical(files.directory_token) == canonical(directory_token) and
         canonical(files.files) == canonical(original_files),
         "stored original ownership changed during check")
    return validate_witness(result, runtime=runtime, config=config, current_sources=current_sources)


def decode_witness(raw, *, runtime, config, current_sources):
    """Strict bounded JSON, including duplicate-key refusal, no native actions."""
    need(type(raw) is bytes and 0 < len(raw) <= LIMIT, "original bounded witness bytes")
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda value: (_ for _ in ()).throw(Refused("nonfinite JSON")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Refused("invalid bounded witness JSON") from error
    return validate_witness(value, runtime=runtime, config=config, current_sources=current_sources)


def metadata():
    return {"schema": "macws.swap-pair.ownership-capture.offline-preparation.v1",
            "device_commands": 0, "filesystem_mutations": 0,
            "native_calls": 0, "device_acceptance": False,
            "existing_scratch_adoption_authorized": False,
            "new_control_authorized": False}


if __name__ == "__main__":
    print(json.dumps(metadata(), sort_keys=True))
