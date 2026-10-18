"""Exclusive, bounded delivery only. This module never launches or trusts a probe.

The CLI is deliberately absent: the host pipeline sends this exact source over
finite SSH stdin. Temporary host tests call install() with explicit fake roots.
"""
import base64
import ctypes
import hashlib
import json
import os
import pathlib
import plistlib
import re
import signal
import stat
import struct
import time
import uuid

MANIFEST_SHA256 = "a4c52d5f9d01ac07e516f99f297444a0a7dfabf0dd0e496d8e6b8f7ad2c1283a"
MAX_PAYLOAD = 1024 * 1024
DEADLINE_SECONDS = 8.0
PROBE_PARENT = "/private/var/mnt/rootfs/usr/local/libexec"
CONTROLLER_PARENT = "/var/jb/usr/libexec"
PROBE_DIR = "macws-swap-pair-probe-20261017"
CONTROLLER_DIR = "macws-swap-pair-controller-20261018"
SELECTED = {
    "probe.arm64": (PROBE_PARENT, PROBE_DIR, 0o755),
    "controller.py": (CONTROLLER_PARENT, CONTROLLER_DIR, 0o600),
    "runtime_support.py": (CONTROLLER_PARENT, CONTROLLER_DIR, 0o600),
    "watchdog.py": (CONTROLLER_PARENT, CONTROLLER_DIR, 0o600),
    "offline-QA.canonical.private.json": (CONTROLLER_PARENT, CONTROLLER_DIR, 0o600),
}


class Refused(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode_json(raw):
    require(len(raw) <= MAX_PAYLOAD, "JSON exceeds payload bound")
    return json.loads(raw, object_pairs_hook=unique_object)


def token(value):
    return {"dev": value.st_dev, "ino": value.st_ino,
            "mode": stat.S_IMODE(value.st_mode), "uid": value.st_uid,
            "gid": value.st_gid, "nlink": value.st_nlink, "size": value.st_size,
            "mtime_ns": value.st_mtime_ns, "ctime_ns": value.st_ctime_ns}


def dir_identity(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid,
            stat.S_IMODE(value.st_mode))


def read_fd(fd, length, check):
    require(0 <= length <= MAX_PAYLOAD, "file size exceeds bound")
    result = bytearray()
    os.lseek(fd, 0, os.SEEK_SET)
    while len(result) < length:
        check()
        part = os.read(fd, min(65536, length - len(result)))
        require(bool(part), "short file read")
        result.extend(part)
    require(os.read(fd, 1) == b"", "file grew while reading")
    return bytes(result)


def probe_signature(data):
    """Own thin Mach-O CodeDirectory page hashes, not AMFI/trust acceptance."""
    require(len(data) >= 32, "short Mach-O")
    magic, cpu, sub, kind, count, size, flags, reserved = struct.unpack_from("<8I", data)
    require(magic == 0xfeedfacf and cpu == 0x100000c and sub == 0,
            "probe is not the selected thin arm64")
    require(0 < count <= 128 and 0 < size <= 65536 and 32 + size <= len(data),
            "invalid Mach-O commands")
    cursor, identity, signature = 32, None, None
    for _ in range(count):
        require(cursor + 8 <= 32 + size, "truncated load command")
        command, length = struct.unpack_from("<II", data, cursor)
        require(length >= 8 and cursor + length <= 32 + size, "invalid load command")
        if command == 0x1b:
            require(identity is None and length == 24, "invalid UUID command")
            identity = str(uuid.UUID(bytes=bytes(data[cursor + 8:cursor + 24])))
        if command == 0x1d:
            require(signature is None and length == 16, "invalid signature command")
            signature = struct.unpack_from("<II", data, cursor + 8)
        cursor += length
    require(cursor == 32 + size and identity is not None and signature is not None,
            "missing Mach-O identity/signature")
    offset, length = signature
    require(12 <= length <= MAX_PAYLOAD and offset + length == len(data),
            "signature bounds differ")
    blob = data[offset:offset + length]
    magic, declared, count = struct.unpack_from(">III", blob)
    require(magic == 0xfade0cc0 and 12 <= declared <= len(blob) and count <= 32
            and 12 + count * 8 <= declared, "invalid signature superblob")
    results = []
    for index in range(count):
        slot, where = struct.unpack_from(">II", blob, 12 + 8 * index)
        require(where + 8 <= declared, "invalid signature slot")
        magic, length = struct.unpack_from(">II", blob, where)
        require(length >= 8 and where + length <= declared, "invalid signature blob")
        if magic != 0xfade0c02:
            continue
        directory = blob[where:where + length]
        require(length >= 64, "short CodeDirectory")
        version, flags, hashes, ident, special, pages, limit = struct.unpack_from(">7I", directory, 8)
        hash_size, hash_type, platform, page_shift = struct.unpack_from("4B", directory, 36)
        require(hash_size == 32 and hash_type == 2 and 12 <= page_shift <= 16
                and 0 < pages <= 128 and hashes + pages * 32 <= length,
                "unsupported CodeDirectory shape")
        require(version < 0x20100 or struct.unpack_from(">I", directory, 44)[0] == 0,
                "scatter signature refused")
        if version >= 0x20300:
            limit = struct.unpack_from(">Q", directory, 56)[0] or limit
        page_size = 1 << page_shift
        require(0 < limit <= offset and pages == (limit + page_size - 1) // page_size,
                "CodeDirectory code limit differs")
        for page in range(pages):
            part = data[page * page_size:min((page + 1) * page_size, limit)]
            require(hashlib.sha256(part).digest() == directory[hashes + page * 32:hashes + (page + 1) * 32],
                    "signed code page mismatch")
        results.append({"architecture": "arm64", "uuid": identity,
                        "cdhash": hashlib.sha256(directory).hexdigest()[:40],
                        "hash_type": 2, "signed_pages_checked": pages,
                        "code_limit": limit, "page_hashes_valid": True})
    require(len(results) == 1, "expected exactly one CodeDirectory")
    return results[0]


def parse_payload(payload):
    require(type(payload) is dict and set(payload) == {"manifest_b64", "files_b64"},
            "unexpected delivery payload fields")
    raw = base64.b64decode(payload["manifest_b64"], validate=True)
    require(sha(raw) == MANIFEST_SHA256, "unreviewed bundle manifest")
    manifest = decode_json(raw)
    require(manifest["schema"] == "macws.swap-pair.local-delivery-bundle.v1",
            "wrong bundle schema")
    rows = {row["name"]: row for row in manifest["files"]}
    require(len(rows) == len(manifest["files"]), "duplicate manifest file")
    require(sha(canonical(manifest["files"])) == manifest["content_rows_sha256"],
            "manifest content rows differ")
    require(set(payload["files_b64"]) == set(SELECTED), "payload is not the five selected files")
    files = {}
    for name, (parent, directory, mode) in SELECTED.items():
        row = rows[name]
        require(row["intended_device_path"] == parent + "/" + directory + "/" + name
                and row["intended_device_mode"] == format(mode, "04o"), "target metadata differs")
        content = base64.b64decode(payload["files_b64"][name], validate=True)
        require(len(content) == row["bytes"] and sha(content) == row["sha256"],
                "selected file content differs")
        files[name] = content
    signature = probe_signature(files["probe.arm64"])
    require(signature == manifest["host_signature_results"]["arm64"],
            "probe signature differs from host metadata")
    return files, signature


def sysctl_text(name):
    libc = ctypes.CDLL(None, use_errno=True)
    fn = libc.sysctlbyname
    fn.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
    fn.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(512)
    length = ctypes.c_size_t(len(buffer))
    require(fn(name.encode(), buffer, ctypes.byref(length), None, 0) == 0
            and 0 < length.value <= len(buffer), "sysctl identity unavailable")
    return buffer.raw[:length.value].rstrip(b"\0").decode("ascii")


def device_gate():
    require(os.getuid() == os.geteuid() == 0, "root context required")
    require(sysctl_text("hw.machine") == "iPad13,6", "device model differs")
    require(sysctl_text("kern.osversion") == "20E252", "kernel build differs")
    require(sysctl_text("kern.uuid").lower() == "d6b9e234-64f1-30ea-ae62-ed8f2dc6efdb",
            "kernel UUID differs")
    for path, version, build in (
        ("/System/Library/CoreServices/SystemVersion.plist", "16.4.1", "20E252"),
        ("/private/var/mnt/rootfs/System/Library/CoreServices/SystemVersion.plist", "13.4", "22F66"),
    ):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            observed = os.fstat(fd)
            require(stat.S_ISREG(observed.st_mode) and 0 < observed.st_size <= 65536,
                    "system version file shape differs")
            raw = read_fd(fd, observed.st_size, lambda: None)
            require(token(observed) == token(os.fstat(fd)), "system version changed")
        finally:
            os.close(fd)
        value = plistlib.loads(raw)
        require(value["ProductVersion"] == version and value["ProductBuildVersion"] == build,
                "OS version differs")


def open_parent(logical, check):
    """Follow only the known rootless prefix, then walk canonical dirs by FD."""
    resolved = os.path.realpath(logical)
    if logical == CONTROLLER_PARENT:
        rootless = os.path.realpath("/var/jb")
        require(stat.S_ISLNK(os.lstat("/var/jb").st_mode), "rootless prefix is not a symlink")
        require(re.fullmatch(r"/private/preboot/[0-9A-Fa-f]+/dopamine-[A-Za-z0-9_-]+/procursus", rootless)
                is not None and resolved == rootless + "/usr/libexec", "unexpected rootless resolution")
    else:
        require(logical == PROBE_PARENT and resolved == logical, "unexpected rootfs parent resolution")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for piece in pathlib.PurePosixPath(resolved).parts[1:]:
            check()
            child = os.open(piece, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            observed = os.fstat(fd)
            require(observed.st_uid == 0 and stat.S_IMODE(observed.st_mode) & 0o022 == 0,
                    "untrusted canonical parent component")
        value = os.fstat(fd)
        require(stat.S_ISDIR(value.st_mode) and value.st_uid == 0
                and stat.S_IMODE(value.st_mode) & 0o022 == 0, "untrusted destination parent")
        require(dir_identity(value) == dir_identity(os.stat(logical)), "parent resolution changed")
        return fd, resolved, value
    except BaseException:
        os.close(fd)
        raise


def recheck_parent(logical, resolved, value):
    require(os.path.realpath(logical) == resolved
            and dir_identity(os.stat(logical)) == dir_identity(value), "logical parent changed")


def install(files, signature, report, *, gate=device_gate, parent_opener=open_parent,
            parent_recheck=recheck_parent, owner_uid=0,
            clock=time.monotonic, deadline_seconds=DEADLINE_SECONDS):
    """Install the five verified bytes; injection is for temporary tests only."""
    started = clock()

    def check():
        require(clock() - started < deadline_seconds, "delivery deadline exceeded")

    check()
    gate()
    check()
    parents, directories, owned = {}, {}, {}
    try:
        # Observe BOTH targets before any creation; races still fail via mkdir.
        for logical, directory in ((PROBE_PARENT, PROBE_DIR), (CONTROLLER_PARENT, CONTROLLER_DIR)):
            check()
            fd, resolved, value = parent_opener(logical, check)
            parents[logical] = (fd, value, resolved)
            try:
                os.stat(directory, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise Refused("destination already exists; preserved")
            report["parents_private"].append({"logical": logical, "resolved": resolved,
                                               "stat": token(value), "target_previously_absent": True})
        for logical, directory in ((PROBE_PARENT, PROBE_DIR), (CONTROLLER_PARENT, CONTROLLER_DIR)):
            check()
            pfd, before, resolved = parents[logical]
            require(dir_identity(before) == dir_identity(os.fstat(pfd)), "parent changed")
            parent_recheck(logical, resolved, before)
            os.mkdir(directory, 0o700, dir_fd=pfd)  # EEXIST never overwritten or cleaned.
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pfd)
            directories[logical] = fd
            os.fchmod(fd, 0o700)
            value = os.fstat(fd)
            require(value.st_uid == owner_uid and stat.S_IMODE(value.st_mode) == 0o700,
                    "new directory ownership/mode differs")
            report["created_directories_private"].append({"path": logical + "/" + directory,
                                                         "stat": token(value)})
        for name, (logical, directory, mode) in SELECTED.items():
            check()
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directories[logical])
            try:
                data = files[name]
                cursor = 0
                while cursor < len(data):
                    check()
                    written = os.write(fd, data[cursor:cursor + 65536])
                    require(written > 0, "short file write")
                    cursor += written
                os.fchmod(fd, mode)  # Settle final mode before any accepted stat token.
                os.fsync(fd)
                value = os.fstat(fd)
                require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == owner_uid
                        and stat.S_IMODE(value.st_mode) == mode, "new file identity differs")
                expected = token(value)
                require(read_fd(fd, len(data), check) == data and token(os.fstat(fd)) == expected,
                        "new file readback differs")
                owned[name] = expected
                report["installed_files_private"].append({"name": name, "path": logical + "/" + directory + "/" + name,
                                                          "stat": expected, "sha256": sha(data),
                                                          "previously_absent": True, "new_vnode_created_exclusively": True})
            finally:
                os.close(fd)
        # Reopen each exact name, verify tokens/content and no additional files.
        for logical, directory in ((PROBE_PARENT, PROBE_DIR), (CONTROLLER_PARENT, CONTROLLER_DIR)):
            check()
            fd = directories[logical]
            expected_names = {name for name, row in SELECTED.items() if row[0] == logical}
            require(set(os.listdir(fd)) == expected_names, "unexpected file in owned directory")
            pfd, before, resolved = parents[logical]
            require(dir_identity(before) == dir_identity(os.fstat(pfd)), "destination parent changed")
            parent_recheck(logical, resolved, before)
            require(dir_identity(os.fstat(fd)) == dir_identity(os.stat(directory, dir_fd=pfd, follow_symlinks=False)),
                    "owned directory path changed")
            for name in sorted(expected_names):
                check()
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    require(token(os.fstat(child)) == owned[name], "installed token changed")
                    require(read_fd(child, len(files[name]), check) == files[name], "installed content changed")
                    require(token(os.fstat(child)) == owned[name], "installed token changed during read")
                finally:
                    os.close(child)
            for row in report["created_directories_private"]:
                if row["path"] == logical + "/" + directory:
                    row["stat"] = token(os.fstat(fd))
        check()
        gate()
        check()
        report.update(installation_verified=True, probe_signature=signature,
                      duration_seconds=clock() - started)
    finally:
        for fd in list(directories.values()) + [row[0] for row in parents.values()]:
            os.close(fd)


def receive(payload, receiver_sha256):
    report = {"schema": "macws.diagnostic-probe.delivery.private.v1",
              "receiver_sha256": receiver_sha256, "bundle_manifest_sha256": MANIFEST_SHA256,
              "installation_verified": False, "parents_private": [],
              "created_directories_private": [], "installed_files_private": [],
              "candidate_executions": 0, "controller_executions": 0, "trust_mutations": 0,
              "native_dependency_closure_currently_verified": False, "current_trust_verified": False,
              "device_acceptance": False, "runtime_accepted": False,
              "freeze_cause_or_fix_proven": False, "automatic_cleanup_attempted": False}
    try:
        signal.signal(signal.SIGALRM, lambda signum, frame: (_ for _ in ()).throw(TimeoutError("delivery alarm")))
        signal.alarm(12)
        started = time.monotonic()
        files, signature = parse_payload(payload)
        install(files, signature, report, deadline_seconds=DEADLINE_SECONDS - (time.monotonic() - started))
    except BaseException as error:
        report["refusal"] = type(error).__name__ + ": " + str(error)
    finally:
        signal.alarm(0)
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report["installation_verified"] else 1
