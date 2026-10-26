"""Private, host-only preservation of exactly one retained diagnostic capture.

No native authority follows from this module or its receipts.  Only a successful
direct archive_bytes return attests that this process completed its fsync steps.
A later verifier can check bytes/identities, not reconstruct past fsync events.
Failures preserve partial artifacts and are never rolled back or retried here.
"""

import hashlib
import json
import math
import os
import re
import stat


SCHEMA = "macws.retained-artifact.archive.v1"
WIRE_LIMIT = 2 * 1024 * 1024
JSON_LIMIT = 256 * 1024
FILE_LIMITS = {"job.plist": 65536, "probe.log": 262144}
FILE_NAMES = {name: name + ".private.bin" for name in FILE_LIMITS}
ENTRY_NAMES = frozenset({"wire.private.bin", "manifest.private.json",
                         "provenance.private.json", "receipt.private.json",
                         *FILE_NAMES.values()})
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_CREATE_FLAGS = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class ArchiveRefused(ValueError):
    """The bounded preservation contract did not hold."""


def _require(condition, message):
    if not condition:
        raise ArchiveRefused(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical_json(value):
    """Freeze bounded plain JSON; reject implicit conversions and nonfinite data."""
    _require(type(value) is dict, "JSON root must be a plain dictionary")
    nodes = [0]
    characters = [0]
    active = set()

    def visit(item, depth):
        nodes[0] += 1
        _require(nodes[0] <= 20000 and depth <= 32, "JSON structure exceeds bound")
        kind = type(item)
        if item is None or kind is bool:
            return
        if kind is int:
            _require(-(2**63) <= item < 2**63, "JSON integer exceeds bound")
            return
        if kind is float:
            _require(math.isfinite(item), "JSON number is not finite")
            return
        if kind is str:
            _require(len(item) <= 65536, "JSON string exceeds bound")
            characters[0] += len(item)
            _require(characters[0] <= JSON_LIMIT, "JSON character budget exceeded")
            _require(not any(0xD800 <= ord(c) <= 0xDFFF for c in item),
                     "JSON string contains surrogate")
            return
        _require(kind in (dict, list), "JSON contains non-plain value")
        _require(id(item) not in active, "JSON contains cycle")
        active.add(id(item))
        if kind is dict:
            for key, child in item.items():
                _require(type(key) is str, "JSON key must be a plain string")
                visit(key, depth + 1)
                visit(child, depth + 1)
        else:
            for child in item:
                visit(child, depth + 1)
        active.remove(id(item))

    visit(value, 0)
    frozen = json.dumps(value, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    _require(len(frozen) <= JSON_LIMIT, "JSON bytes exceed bound")
    return frozen


def _decode_canonical(data):
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def bad_constant(_):
        raise ArchiveRefused("nonfinite JSON constant")

    try:
        value = json.loads(data.decode("ascii"), object_pairs_hook=pairs,
                           parse_constant=bad_constant)
        _require(canonical_json(value) == data, "archive JSON is not canonical")
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ArchiveRefused("archive JSON is invalid") from exc
    return value


def _absolute_path(path):
    path = os.fspath(path)
    _require(type(path) is str and len(path) <= 4096 and path.startswith("/") and "\0" not in path,
             "parent path must be an absolute string")
    parts = path.split("/")[1:]
    _require(bool(parts) and all(part not in ("", ".", "..") for part in parts),
             "path has unsafe components")
    return path, parts


def _open_directory_path(path):
    """No component is allowed to be a symlink, including a parent anchor."""
    _, parts = _absolute_path(path)
    fd = os.open("/", _DIR_FLAGS)
    try:
        for part in parts:
            next_fd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _stat_tuple(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink)


def _directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _check_directory(fd, *, private):
    info = os.fstat(fd)
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid(),
             "directory type or owner mismatch")
    mode = stat.S_IMODE(info.st_mode)
    _require(mode == 0o700 if private else mode & 0o7022 == 0,
             "directory permissions mismatch")
    return info


def _parent_path_checked(fd, path, identity):
    check_fd = _open_directory_path(path)
    try:
        _require(_directory_identity(_check_directory(fd, private=False)) == identity
                 == _directory_identity(_check_directory(check_fd, private=False)),
                 "held parent/path identity mismatch")
    finally:
        os.close(check_fd)


def _read_fd(fd, limit):
    os.lseek(fd, 0, os.SEEK_SET)
    parts = []
    count = 0
    while True:
        chunk = os.read(fd, min(65536, limit + 1 - count))
        if not chunk:
            return b"".join(parts)
        count += len(chunk)
        _require(count <= limit, "archive file exceeds bound")
        parts.append(chunk)


def _read_checked(fd, limit):
    before = os.fstat(fd)
    _require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600
             and before.st_uid == os.geteuid() and before.st_nlink == 1,
             "archive file type/mode/owner/link mismatch")
    _require(0 <= before.st_size <= limit, "archive file size exceeds bound")
    data = _read_fd(fd, limit)
    after = os.fstat(fd)
    _require(_stat_tuple(before) == _stat_tuple(after) and len(data) == before.st_size,
             "archive file changed during read")
    return data, _stat_tuple(after)


def _path_checked(archive_fd, name, fd, token):
    _require(_stat_tuple(os.fstat(fd)) == token
             == _stat_tuple(os.stat(name, dir_fd=archive_fd, follow_symlinks=False)),
             "archive file descriptor/path mismatch")


def _write_checked(archive_fd, name, data):
    fd = os.open(name, _CREATE_FLAGS, 0o600, dir_fd=archive_fd)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            _require(type(written) is int and 0 < written <= len(data) - offset,
                     "archive write made no valid progress")
            offset += written
        os.fsync(fd)
        actual, token = _read_checked(fd, max(len(data), 1))
        _require(actual == data, "archive readback mismatch")
        _path_checked(archive_fd, name, fd, token)
        return fd, token
    except BaseException:
        os.close(fd)
        raise


def _receipt(manifest_bytes, provenance_bytes, wire, files):
    return {"schema": SCHEMA, "manifest_sha256": sha256(manifest_bytes),
            "provenance_sha256": sha256(provenance_bytes),
            "wire_sha256": sha256(wire),
            "file_sha256": {name: sha256(files[name]) for name in FILE_LIMITS},
            "durable_archive_verified": True,
            "native_evidence_authenticity_verified": False,
            "device_acceptance": False}


def archive_bytes(parent_directory, archive_name, *, wire, manifest, provenance, files):
    """Exclusively preserve a capture; return only after complete durable readback.

    The caller must retain this direct successful return.  A persisted receipt
    alone cannot establish that its final fsync completed.  On any exception,
    keep the named partial archive for investigation; never reuse its name.
    """
    _require(type(archive_name) is str and _NAME.fullmatch(archive_name)
             and archive_name not in (".", ".."), "unsafe archive name")
    _require(type(wire) is bytes and 0 < len(wire) <= WIRE_LIMIT,
             "wire bytes must be nonempty and bounded")
    _require(type(files) is dict and set(files) == set(FILE_LIMITS),
             "archive requires exactly job.plist and probe.log")
    frozen_files = {}
    for name, limit in FILE_LIMITS.items():
        _require(type(files[name]) is bytes and len(files[name]) <= limit,
                 "diagnostic bytes exceed bound")
        frozen_files[name] = files[name]
    manifest_bytes = canonical_json(manifest)
    provenance_bytes = canonical_json(provenance)
    parent_path, _ = _absolute_path(parent_directory)
    payloads = {"wire.private.bin": wire, "manifest.private.json": manifest_bytes,
                "provenance.private.json": provenance_bytes,
                **{FILE_NAMES[name]: data for name, data in frozen_files.items()}}
    parent_fd = _open_directory_path(parent_path)
    archive_fd = None
    held = {}
    try:
        parent_identity = _directory_identity(_check_directory(parent_fd, private=False))
        _parent_path_checked(parent_fd, parent_path, parent_identity)
        os.mkdir(archive_name, 0o700, dir_fd=parent_fd)
        archive_fd = os.open(archive_name, _DIR_FLAGS, dir_fd=parent_fd)
        archive_identity = _directory_identity(_check_directory(archive_fd, private=True))
        _require(archive_identity == _directory_identity(os.stat(
            archive_name, dir_fd=parent_fd, follow_symlinks=False)),
            "new archive directory identity mismatch")
        for name, data in payloads.items():
            held[name] = _write_checked(archive_fd, name, data)
        os.fsync(archive_fd)
        result = _receipt(manifest_bytes, provenance_bytes, wire, frozen_files)
        # Its true bit is not trusted until this function returns successfully.
        payloads["receipt.private.json"] = canonical_json(result)
        held["receipt.private.json"] = _write_checked(
            archive_fd, "receipt.private.json", payloads["receipt.private.json"])
        os.fsync(archive_fd)
        os.fsync(parent_fd)
        _require(set(os.listdir(archive_fd)) == ENTRY_NAMES, "archive entries mismatch")
        directory_token = _stat_tuple(_check_directory(archive_fd, private=True))
        for name, (fd, token) in held.items():
            actual, current = _read_checked(fd, max(len(payloads[name]), 1))
            _require(actual == payloads[name] and current == token,
                     "archive final readback mismatch")
            _path_checked(archive_fd, name, fd, token)
        _require(directory_token == _stat_tuple(os.fstat(archive_fd))
                 == _stat_tuple(os.stat(archive_name, dir_fd=parent_fd, follow_symlinks=False))
                 and set(os.listdir(archive_fd)) == ENTRY_NAMES,
                 "archive directory changed during final readback")
        _parent_path_checked(parent_fd, parent_path, parent_identity)
        return result
    finally:
        for fd, _ in held.values():
            os.close(fd)
        if archive_fd is not None:
            os.close(archive_fd)
        os.close(parent_fd)


def verify_archive(archive_directory, *, expected_manifest, expected_provenance,
                   expected_wire_sha256, expected_file_sha256):
    """Verify current archive bytes, never historical durability or native truth."""
    expected_manifest_bytes = canonical_json(expected_manifest)
    expected_provenance_bytes = canonical_json(expected_provenance)
    _require(type(expected_wire_sha256) is str and _HASH.fullmatch(expected_wire_sha256),
             "expected wire hash is invalid")
    _require(type(expected_file_sha256) is dict
             and set(expected_file_sha256) == set(FILE_LIMITS),
             "expected file hashes require exactly job.plist and probe.log")
    frozen_expected_files = {}
    for name in FILE_LIMITS:
        value = expected_file_sha256[name]
        _require(type(value) is str and _HASH.fullmatch(value), "expected file hash is invalid")
        frozen_expected_files[name] = value
    path, parts = _absolute_path(archive_directory)
    archive_name = parts[-1]
    _require(_NAME.fullmatch(archive_name), "unsafe archive name")
    parent_path = path.rsplit("/", 1)[0]
    parent_fd = _open_directory_path(parent_path)
    archive_fd = None
    held = {}
    try:
        parent_identity = _directory_identity(_check_directory(parent_fd, private=False))
        archive_fd = os.open(archive_name, _DIR_FLAGS, dir_fd=parent_fd)
        directory_token = _stat_tuple(_check_directory(archive_fd, private=True))
        _require(set(os.listdir(archive_fd)) == ENTRY_NAMES, "archive entries mismatch")
        limits = {"wire.private.bin": WIRE_LIMIT, "manifest.private.json": JSON_LIMIT,
                  "provenance.private.json": JSON_LIMIT, "receipt.private.json": JSON_LIMIT,
                  **{FILE_NAMES[name]: limit for name, limit in FILE_LIMITS.items()}}
        data = {}
        for name, limit in limits.items():
            fd = os.open(name, _READ_FLAGS, dir_fd=archive_fd)
            held[name] = (fd, None)
            data[name], token = _read_checked(fd, limit)
            held[name] = (fd, token)
            _path_checked(archive_fd, name, fd, token)
        _require(data["manifest.private.json"] == expected_manifest_bytes
                 and data["provenance.private.json"] == expected_provenance_bytes,
                 "archive manifest/provenance expectation mismatch")
        _decode_canonical(data["manifest.private.json"])
        _decode_canonical(data["provenance.private.json"])
        _require(0 < len(data["wire.private.bin"]) <= WIRE_LIMIT
                 and sha256(data["wire.private.bin"]) == expected_wire_sha256,
                 "archive wire expectation mismatch")
        _require({name: sha256(data[FILE_NAMES[name]]) for name in FILE_LIMITS}
                 == frozen_expected_files, "archive file hash expectation mismatch")
        expected_receipt = _receipt(expected_manifest_bytes, expected_provenance_bytes,
                                    data["wire.private.bin"],
                                    {name: data[FILE_NAMES[name]] for name in FILE_LIMITS})
        receipt = _decode_canonical(data["receipt.private.json"])
        _require(data["receipt.private.json"] == canonical_json(expected_receipt),
                 "archive receipt mismatch")
        for name, (fd, token) in held.items():
            actual, current = _read_checked(fd, limits[name])
            _require(actual == data[name] and current == token, "archive changed during verification")
            _path_checked(archive_fd, name, fd, token)
        _require(directory_token == _stat_tuple(os.fstat(archive_fd))
                 == _stat_tuple(os.stat(archive_name, dir_fd=parent_fd, follow_symlinks=False))
                 and set(os.listdir(archive_fd)) == ENTRY_NAMES,
                 "archive directory changed during verification")
        _parent_path_checked(parent_fd, parent_path, parent_identity)
        return {"receipt": receipt, "verification": {
            "current_bytes_verified": True,
            "past_fsync_independently_verified": False,
            "native_evidence_authenticity_verified": False,
            "device_acceptance": False}}
    finally:
        for fd, _ in held.values():
            os.close(fd)
        if archive_fd is not None:
            os.close(archive_fd)
        os.close(parent_fd)


def main():
    """Metadata only.  No CLI archive, device or cleanup route exists."""
    print(json.dumps({"schema": SCHEMA, "host_persistence_only": True,
                      "native_actions_available": False,
                      "device_acceptance": False}, sort_keys=True))


if __name__ == "__main__":
    main()
