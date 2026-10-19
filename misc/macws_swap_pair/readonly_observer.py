"""Private, default-off read-only observations; never an admission authority.

Import/default CLI performs no native APIs. Native execution needs --observe,
an independently frozen source digest, and the exact copied input bytes.
"""
from __future__ import annotations
import argparse
import ast
import ctypes
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
import uuid

INPUT_SHA256 = "f7261fcf3e6c47493e92f8b04396316acf9d3f66b229d77a85cc0f95ffa6f280"
EXPECTED_SUPPORT_SHA256 = "5d09cf9380afaa2409661a58909d1bfee41d81943f1b2306facb0cd94ee10fe0"
LAUNCHD_DOMAIN = "user/501"
ABSENCE_FUNCTION_SHA256 = {
    "job_label": "1dc9382640b4c81f55f3303b22e7a647d0abb87b41b56b3a9476a7bbc1b6c1d1",
    "parsed_job": "8f129ae75ad8595286be19fc2a11a0113f9319bd2bf6a346094c28c93cf498db",
}
METHOD_SHA256 = {
    "metadata": "fb0295a183e82c35bba2143d8045dd2b36af53a3c336a10cc583499aafa51c3f",
    "process": "6ea5182cee17896c53cf2840e75aa4fe9308d21907b3e143dfc24b26c10b7b1b",
    "thermal": "b6dda26c769d48fcfbfff0a84d8b00fca0263adaac9396e4165c11296e94486d",
}
LABELS = ("com.macws.preflight.swap-pair.20261017", "com.macws.preflight.swap-pair-control.20261018")
SCRATCH = ("/private/var/tmp/macws-swap-pair-20261017", "/private/var/tmp/macws-swap-pair-control-20261018")
LAUNCHCTL = "/var/jb/usr/bin/launchctl"
JBCTL = "/var/jb/usr/bin/jbctl"
ROOTFS = "/private/var/mnt/rootfs"
DEPENDENCIES = {
    "wrapper": {"path": "/var/jb/usr/libexec/macws-windowserver-preflight-20261007/launchdchrootexec_fullframe_streamgate_20261009", "sha256": "e7f1d9e9966826022372248a308c2e28126758a97057ada43551c1a206549d20", "architecture": "arm64", "uuid": "bf207849-42b2-3a26-b431-a04b0f42818d"},
    "hook_arm64": {"path": ROOTFS + "/usr/local/lib/libmachook_fullframe_streamgate_20261009_arm64.dylib", "sha256": "bcd544a537fc81cbc16ec3fb8de2c7677708d35ada10c0caf044ba83f005340b", "architecture": "arm64", "uuid": "2552c7f2-0946-3525-9771-d6d48b44c0e9"},
    "hook_arm64e": {"path": ROOTFS + "/usr/local/lib/libmachook_fullframe_streamgate_20261009.dylib", "sha256": "803bcccf8cb9afd8d3b96bdbe88ca13d79463e6a09f2c192d346bc5300541008", "architecture": "arm64e", "uuid": "8d9d059f-f308-3a07-be9e-bb23123ba997"},
}
LIMITS = {"device_alarm_seconds": 12, "deadline_seconds": 8, "read_bytes": 16 * 1024 * 1024,
          "command_seconds": 1, "command_stdout_bytes": 256 * 1024, "command_stderr_bytes": 16 * 1024,
          "command_count": 16, "process_count": 4096, "source_bytes": 256 * 1024, "input_bytes": 128 * 1024}
BLOCKED_BASENAMES = {"probe.arm64", "probe.arm64e", "WindowServer", "macws-hostd", "macws-displayd",
                     "macws-autosignd", "macwsdisplayd", "macwshostd", "autosignd", "oslog",
                     "debugserver", "lldb", "sample", "spindump", "tail", "grep"}


class Refused(RuntimeError):
    pass


def need(condition, message):
    if condition is not True:
        raise Refused(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def birth_checked(value):
    need(type(value) is list and len(value) == 3 and all(type(x) is int for x in value), "private birth tuple")
    need(value[0] > 1 and value[1] > 0 and 0 <= value[2] < 1_000_000, "private birth fields")
    return value


def token(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def checked_inputs(raw):
    need(type(raw) is bytes and len(raw) <= LIMITS["input_bytes"] and sha(raw) == INPUT_SHA256, "copied inputs digest changed")
    value = json.loads(raw)
    need(value["schema"] == "macws.swap-pair.admission-observer-inputs.v4", "input schema")
    source = value["runtime_support_source"]
    need(sha(source.encode()) == EXPECTED_SUPPORT_SHA256 == value["controller_source_sha256"]["runtime_support.py"], "frozen controller source changed")
    need(value["baseline_private"] is None, "this input is baseline collection, no invented baseline")
    need(value["launchd_domain"] == LAUNCHD_DOMAIN, "pinned launchd domain changed")
    return value


def extracted_primitives(inputs):
    """Compile only three exact frozen methods into a new read-only class.

    Never instantiate or bypass RealBackend, and never execute its module body.
    """
    source = inputs["runtime_support_source"]
    need(sha(source.encode()) == EXPECTED_SUPPORT_SHA256, "source changed before method extraction")
    module = ast.parse(source)
    classes = [x for x in module.body if isinstance(x, ast.ClassDef) and x.name == "RealBackend"]
    need(len(classes) == 1, "one frozen backend declaration")
    methods = [x for x in classes[0].body if isinstance(x, ast.FunctionDef) and x.name in METHOD_SHA256]
    need(len(methods) == 3 and {x.name for x in methods} == set(METHOD_SHA256), "three exact primitive methods")
    for method in methods:
        need(sha(ast.get_source_segment(source, method).encode()) == METHOD_SHA256[method.name], "primitive method changed")
    cls = ast.ClassDef(name="CopiedReadOnlyPrimitives", bases=[], keywords=[], body=methods, decorator_list=[])
    ns = {"ctypes": ctypes, "need": need, "birth_checked": birth_checked, "struct": struct, "re": re, "sha": sha}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])), "copied-read-only-primitives", "exec"), ns)
    return ns["CopiedReadOnlyPrimitives"]


def extracted_shared_clock(inputs):
    source = inputs["runtime_support_source"]
    need(sha(source.encode()) == EXPECTED_SUPPORT_SHA256, "clock source binding changed")
    nodes = [x for x in ast.parse(source).body if isinstance(x, ast.ClassDef) and x.name == "NativeSharedClock"]
    need(len(nodes) == 1 and sha(ast.get_source_segment(source, nodes[0]).encode()) == '96f6d71dbbdad7f80ab012f05564791853f6e2ec3c23f89beccc583a207f15dd', "exact shared native clock class changed")
    namespace = {"ctypes": ctypes, "need": need}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), "copied-shared-native-clock", "exec"), namespace)
    return namespace["NativeSharedClock"]


def code_signature(raw):
    """Strict thin ARM64 CodeDirectory code-page validation, no native call."""
    need(len(raw) >= 32, "short thin header")
    magic, cpu, subtype, filetype, count, size, _, _ = struct.unpack_from("<8I", raw)
    need(magic == 0xfeedfacf and cpu == 0x100000c and (subtype & 0xffffff) in (0, 2), "thin ARM64 identity")
    need(filetype in (2, 6) and 0 < count <= 1024 and 0 < size <= 65536 and 32 + size <= len(raw), "thin command bounds")
    end = 32 + size; at = 32; identities = []; signatures = []
    for _ in range(count):
        need(at + 8 <= end, "command header bound")
        command, length = struct.unpack_from("<II", raw, at)
        need(length >= 8 and length % 8 == 0 and at + length <= end, "command extent")
        if command == 0x1b:
            need(length == 24, "UUID command length")
            identities.append(str(uuid.UUID(bytes=raw[at + 8:at + 24])))
        if command == 0x1d:
            need(length == 16, "signature command length")
            signatures.append(struct.unpack_from("<II", raw, at + 8))
        at += length
    need(at == end and len(identities) == 1 and len(signatures) == 1, "unique UUID and signature commands")
    offset, extent = signatures[0]
    need(end <= offset < len(raw) and 12 <= extent <= len(raw) - offset, "signature data range")
    blob = raw[offset:offset + extent]
    magic, length, count = struct.unpack_from(">III", blob)
    need(magic == 0xfade0cc0 and 12 <= length <= extent and 0 < count <= 16 and 12 + count * 8 <= length, "signature superblob bounds")
    results = []; seen_slots = set()
    for index in range(count):
        slot, start = struct.unpack_from(">II", blob, 12 + index * 8)
        need(slot not in seen_slots and 12 + count * 8 <= start and start + 8 <= length, "signature slot bounds/uniqueness")
        seen_slots.add(slot)
        kind, directory_size = struct.unpack_from(">II", blob, start)
        need(8 <= directory_size <= length - start, "signature child bounds")
        if kind != 0xfade0c02:
            continue
        directory = blob[start:start + directory_size]
        need(len(directory) >= 44, "CodeDirectory minimum")
        version, _, hash_offset, _, special, slots, code_limit = struct.unpack_from(">7I", directory, 8)
        hash_size, hash_type, _, shift = struct.unpack_from("4B", directory, 36)
        constructor = {1: hashlib.sha1, 2: hashlib.sha256, 3: hashlib.sha256, 4: hashlib.sha384}.get(hash_type)
        need(constructor is not None and hash_size == (20 if hash_type in (1, 3) else 32 if hash_type == 2 else 48), "CodeDirectory hash ABI")
        need(0 <= shift <= 20 and 0 < slots <= 4096 and hash_offset >= 44 and special <= 64 and hash_offset >= special * hash_size, "CodeDirectory slots/page bound")
        need(hash_offset + slots * hash_size <= len(directory), "CodeDirectory hash extent")
        if version >= 0x20100:
            need(len(directory) >= 48 and struct.unpack_from(">I", directory, 44)[0] == 0, "scatter CodeDirectory unsupported")
        if version >= 0x20300:
            need(len(directory) >= 64, "64-bit CodeDirectory minimum")
            limit64 = struct.unpack_from(">Q", directory, 56)[0]
            if limit64:
                code_limit = limit64
        page = 1 << shift if shift else code_limit
        need(0 < code_limit <= offset and 0 < page and slots == (code_limit + page - 1) // page, "CodeDirectory code coverage")
        for index in range(slots):
            begin = index * page; data = raw[begin:min(begin + page, code_limit)]
            need(bool(data) and constructor(data).digest()[:hash_size] == directory[hash_offset + index * hash_size:hash_offset + (index + 1) * hash_size], "signed code page mismatch")
        results.append({"cdhash": constructor(directory).hexdigest()[:40], "hash_type": hash_type,
                        "signed_pages_checked": slots, "code_limit": code_limit, "page_hashes_valid": True})
    need(len(results) == 1, "exactly one CodeDirectory required")
    return {"architecture": "arm64e" if subtype & 0xffffff == 2 else "arm64", "uuid": identities[0], **results[0]}


def process_rows(text):
    need(type(text) is str and len(text.encode()) <= LIMITS["command_stdout_bytes"], "process list bound")
    lines = text.splitlines()
    need(bool(lines) and lines[0].split() == ["PID", "COMM"] and len(lines) <= LIMITS["process_count"] + 1, "exact process list header/count")
    rows = []; seen = set()
    for line in lines[1:]:
        fields = line.strip().split(maxsplit=1)
        need(len(fields) == 2 and re.fullmatch(r"[0-9]+", fields[0]) is not None and "\x00" not in fields[1], "process row syntax")
        pid = int(fields[0]); name = fields[1]
        need(pid > 0 and pid not in seen and name and len(name.encode()) <= 4096, "process row identity")
        seen.add(pid); rows.append({"pid_private": pid, "comm_private": name, "basename": name.rsplit("/", 1)[-1]})
    return rows


def trust_rows(text):
    """Keep the original text; refuse unknown lines rather than infer emptiness."""
    lines = text.splitlines(); hashes = []; expected_count = None; group_count = 0
    for line in lines:
        if not line.strip():
            continue
        header = re.fullmatch(r"Jailbreak Trustcache ([0-9]+) <UUID: ([0-9A-Fa-f]{32})> \(length: ([0-9]+)\)", line)
        if header:
            need(expected_count is None or group_count == expected_count, "trustcache previous count")
            expected_count = int(header.group(3)); group_count = 0
            need(expected_count <= 4096, "trustcache count bound")
            continue
        item = re.fullmatch(r"\|\s*([0-9]+):\s*([0-9A-Fa-f]{40})\s*", line)
        need(item is not None and expected_count is not None and int(item.group(1)) == group_count + 1, "unknown trustcache output")
        hashes.append(item.group(2).lower()); group_count += 1
    need(expected_count is not None and group_count == expected_count, "trustcache complete group")
    return set(hashes)


def extracted_absence_parser(inputs):
    """Copy v7's exact schema/absence branch, omitting all presence handling.

    Both full source functions are hash-bound before AST extraction. The
    copied prefix contains only schema checks, tuple unpacking, label choice,
    and the exact native-copied uid:501/status113 diagnostic. A present query
    then fails closed; no PID, owned-job, or admission claim is made.
    """
    source = inputs["runtime_support_source"]
    need(sha(source.encode()) == EXPECTED_SUPPORT_SHA256, "launchd parser source changed")
    nodes = [node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name in ABSENCE_FUNCTION_SHA256]
    need(len(nodes) == 2 and {node.name for node in nodes} == set(ABSENCE_FUNCTION_SHA256), "two exact launchd source functions")
    for node in nodes:
        need(sha(ast.get_source_segment(source, node).encode()) == ABSENCE_FUNCTION_SHA256[node.name], "launchd source function changed")
    parsed = next(node for node in nodes if node.name == "parsed_job")
    need(len(parsed.body) >= 5 and isinstance(parsed.body[4], ast.If), "exact launchd absence branch position")
    parsed.body = parsed.body[:5] + ast.parse('need(False, "job present or uncertain query")').body
    namespace = {"need": need, "LABEL": LABELS[0], "CONTROL_LABEL": LABELS[1]}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), "copied-launchd-absence-only", "exec"), namespace)
    return namespace["parsed_job"]


def job_absent(result, label, parser):
    need(label in LABELS, "unknown launchd absence label")
    config = {"operation": "run" if label == LABELS[0] else "control_normal"}
    need(parser(config, result) is None, "job absence parser result")
    return True


def readonly_command_allowed(argv):
    """Only fixed read-only commands; no system/gui/foreground alias fallback."""
    need(type(argv) is list and all(type(word) is str for word in argv), "read-only command schema")
    allowed = (["/bin/ps", "-eo", "pid,comm"], [JBCTL, "trustcache", "info"])
    valid = argv in allowed or (len(argv) == 3 and argv[:2] == [LAUNCHCTL, "print"] and argv[2] in [LAUNCHD_DOMAIN + "/" + label for label in LABELS])
    need(valid, "non-read-only or unexpected command")
    return True


class NativeObserver:
    """No constructor operation besides Python memory/clock; no write APIs."""
    def __init__(self, inputs):
        # Reserve the full capacity of two metadata snapshots, four exact
        # libproc path/birth queries and four thermal encoding observations.
        # Command pipe bytes and file bytes share the remaining total budget.
        self.native_reserved_read_bytes = 20480
        self.bytes_read = self.native_reserved_read_bytes; self.file_bytes_read = 0
        self.commands = []; self.proc = None
        self.native_clock_reads = 0
        self.clock = extracted_shared_clock(inputs)()
        self.start = self._clock_now(); self.deadline = self.start + LIMITS["deadline_seconds"]
        primitive = extracted_primitives(inputs)
        self.primitive = primitive(); self.primitive.proc = None
        self.primitive.command = self.command

    def _clock_now(self):
        self.native_clock_reads += 1
        self.bytes_read += 8
        need(self.bytes_read <= LIMITS["read_bytes"], "shared native clock read budget")
        return self.clock.now()

    def clock_info(self):
        return dict(self.clock.profile)

    def check(self):
        need(self._clock_now() < self.deadline, "observer total deadline")

    def now(self):
        self.check(); return self._clock_now()

    def command(self, argv, deadline=None):
        self.check(); need(len(self.commands) < LIMITS["command_count"], "command count bound")
        readonly_command_allowed(argv)
        stop = min(self.deadline, self._clock_now() + LIMITS["command_seconds"])
        if deadline is not None:
            stop = min(stop, deadline)
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = {"stdout": bytearray(), "stderr": bytearray()}; selector = selectors.DefaultSelector()
        try:
            for name in output:
                stream = getattr(proc, name); os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                left = stop - self._clock_now(); need(left > 0, "read-only command deadline")
                for key, _ in selector.select(min(left, .05)):
                    name = key.data; block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj); continue
                    output[name].extend(block)
                    self.bytes_read += len(block)
                    need(self.bytes_read <= LIMITS["read_bytes"], "shared read byte budget")
                    need(len(output[name]) <= LIMITS["command_" + name + "_bytes"], "read-only command output bound")
            code = proc.wait(timeout=max(.001, stop - self._clock_now()))
            self.check()
            result = (code, bytes(output["stdout"]).decode("utf-8", "strict"), bytes(output["stderr"]).decode("utf-8", "strict"))
            self.commands.append({"argv": argv, "returncode": code, "stdout_private": result[1], "stderr_private": result[2]})
            return result
        finally:
            selector.close()
            if proc.poll() is None:
                proc.kill(); proc.wait(timeout=.25)
            proc.stdout.close(); proc.stderr.close()

    def metadata(self):
        self.check()
        values = {name: self.primitive.metadata(name) for name in ("hw.machine", "kern.osversion", "kern.uuid", "kern.bootsessionuuid")}
        for value in values.values():
            need(type(value) is str and 0 < len(value) < 128, "metadata string bound")
        need(re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", values["kern.bootsessionuuid"]) is not None, "boot UUID syntax")
        raw, _ = self.read(ROOTFS + "/System/Library/CoreServices/SystemVersion.plist", 65536)
        version = plistlib.loads(raw)
        need(type(version) is dict and all(type(version.get(x)) is str and len(version[x]) <= 64 for x in ("ProductVersion", "ProductBuildVersion")), "rootfs version plist fields")
        values["rootfs_product_version"] = version["ProductVersion"]
        values["rootfs_product_build"] = version["ProductBuildVersion"]
        self.check(); return values

    def process_snapshot(self):
        result = self.command(["/bin/ps", "-eo", "pid,comm"])
        need(result[0] == 0 and result[2] == "", "process list query")
        rows = process_rows(result[1]); ui = {}; details = {}
        for row in rows:
            name = row["basename"]
            if name in ("SpringBoard", "backboardd"):
                need(name not in ui, "duplicate UI name")
                state = self.primitive.process(row["pid_private"], self.deadline)
                need(state["path"].rsplit("/", 1)[-1] == name and state["stopped"] is False, "UI path or stopped state uncertain")
                ui[name] = state["birth_private"]; details[name] = state
        need(set(ui) == {"SpringBoard", "backboardd"} and ui["SpringBoard"][0] != ui["backboardd"][0], "both unique UI generations")
        self.check()
        return {"rows_private": rows, "UI_private": ui, "UI_details_private": details,
                "blocked_private": [x for x in rows if x["basename"] in BLOCKED_BASENAMES or ("macws" in x["basename"].lower() and any(word in x["basename"].lower() for word in ("windowserver", "debug", "producer", "observer", "swap-pair")))]}

    def thermal(self):
        self.check(); value = self.primitive.thermal(); self.check(); return value

    def path_absent(self, path):
        self.check()
        try:
            os.lstat(path)
        except FileNotFoundError:
            return True
        return False

    def job(self, label):
        need(label in LABELS, "unknown launchd observation label")
        return self.command([LAUNCHCTL, "print", LAUNCHD_DOMAIN + "/" + label])

    def read(self, path, limit):
        self.check()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit and info.st_size <= LIMITS["read_bytes"] - self.bytes_read, "regular file size/read budget")
            before = token(info); chunks = []; total = 0
            while total < info.st_size:
                self.check(); block = os.read(fd, min(65536, info.st_size - total))
                need(bool(block), "short regular file")
                self.bytes_read += len(block); self.file_bytes_read += len(block); total += len(block); chunks.append(block)
            need(os.read(fd, 1) == b"" and token(os.fstat(fd)) == before and token(os.lstat(path)) == before, "regular file changed during read")
            self.check(); return b"".join(chunks), before
        finally:
            os.close(fd)

    def trust(self):
        result = self.command([JBCTL, "trustcache", "info"])
        need(result[0] == 0 and result[2] == "", "trustcache read query")
        return trust_rows(result[1])

    def budget(self):
        return {"file_read_bytes": self.file_bytes_read, "total_read_bytes_charged": self.bytes_read,
                "native_primitive_reserved_read_bytes": self.native_reserved_read_bytes,
                "commands": len(self.commands), "native_clock_reads": self.native_clock_reads, "elapsed_seconds": self._clock_now() - self.start}


def identity_observation(adapter, expected, trusted):
    path = expected["path"]
    try:
        raw, observed_token = adapter.read(path, 2 * 1024 * 1024 if "probe." in path else 4 * 1024 * 1024)
    except FileNotFoundError:
        return {"path": path, "present": False, "identity_verified": False, "trust_member": None,
                "refusal": "candidate missing" if "probe." in path else "frozen dependency missing"}
    signature = code_signature(raw)
    observed = {"path": path, "present": True, "sha256": sha(raw), "stat_token_private": observed_token,
                **signature, "trust_member": signature["cdhash"] in trusted}
    observed["identity_verified"] = all(observed[key] == expected[key] for key in ("sha256", "architecture", "uuid")) and ("cdhash" not in expected or observed["cdhash"] == expected["cdhash"])
    return observed


def observe(adapter, inputs, source_sha256):
    """All identifiers/command outputs remain in this private raw witness."""
    receipt = {"schema": "macws.swap-pair.read-only-admission-observations.v4", "observer_source_sha256": source_sha256,
               "inputs_sha256": INPUT_SHA256, "controller_source_sha256": inputs["controller_source_sha256"],
               "signed_artifact_manifest_sha256": inputs["signed_artifact_manifest_sha256"],
               "limits": LIMITS.copy(), "mutations": 0, "candidate_executions": 0, "launchd_mutations": 0,
               "trust_mutations": 0, "new_vnode": None, "fully_admitted": False, "runtime_accepted": False,
               "device_acceptance": False, "runtime_controls_verified": False, "freshness_verified": False,
               "launchd_domain": LAUNCHD_DOMAIN, "refusals": []}
    try:
        absence_parser = extracted_absence_parser(inputs)
        receipt["started_monotonic"] = adapter.now()
        receipt["metadata_before_private"] = adapter.metadata()
        receipt["process_before_private"] = adapter.process_snapshot()
        receipt["thermal_before"] = adapter.thermal()
        receipt["jobs_before_private"] = {label: adapter.job(label) for label in LABELS}
        receipt["scratch_before"] = {path: adapter.path_absent(path) for path in SCRATCH}
        trusted = adapter.trust(); receipt["trust_before_private"] = sorted(trusted)
        expected = {**DEPENDENCIES, "candidate": inputs["candidate"]}
        receipt["files_before_private"] = {name: identity_observation(adapter, entry, trusted) for name, entry in expected.items()}
        # Re-copy bytes rather than rely only on size/mtime equality.
        trusted_after = adapter.trust(); receipt["trust_after_private"] = sorted(trusted_after)
        receipt["files_after_private"] = {name: identity_observation(adapter, entry, trusted_after) for name, entry in expected.items()}
        candidate = receipt["files_after_private"]["candidate"]
        receipt["candidate_observation"] = ("candidate-missing-prestage" if candidate["present"] is False else
            "candidate-identity-and-current-trust-poststage" if candidate["identity_verified"] is True and candidate["trust_member"] is True else
            "candidate-present-untrusted" if candidate["identity_verified"] is True else "candidate-present-identity-mismatch")
        receipt["jobs_after_private"] = {label: adapter.job(label) for label in LABELS}
        receipt["scratch_after"] = {path: adapter.path_absent(path) for path in SCRATCH}
        receipt["thermal_after"] = adapter.thermal()
        receipt["process_after_private"] = adapter.process_snapshot()
        receipt["metadata_after_private"] = adapter.metadata()
        before = receipt["metadata_before_private"]; after = receipt["metadata_after_private"]
        checks = {
            "exact_device_build": all(x["hw.machine"] == "iPad13,6" and x["kern.osversion"] == "20E252" and x["kern.uuid"].lower() == "d6b9e234-64f1-30ea-ae62-ed8f2dc6efdb" and x["rootfs_product_version"] == "13.4" and x["rootfs_product_build"] == "22F66" for x in (before, after)),
            "same_boot": before == after,
            "same_UI_generations": receipt["process_before_private"]["UI_private"] == receipt["process_after_private"]["UI_private"],
            "nominal_thermal": receipt["thermal_before"] == receipt["thermal_after"] == 0,
            "no_blocked_workloads": receipt["process_before_private"]["blocked_private"] == receipt["process_after_private"]["blocked_private"] == [],
            "both_scratch_absent": all(x is True for group in (receipt["scratch_before"], receipt["scratch_after"]) for x in group.values()),
            "both_job_labels_absent": all(job_absent(result, label, absence_parser) for group in (receipt["jobs_before_private"], receipt["jobs_after_private"]) for label, result in group.items()),
            "same_trust_membership_set": trusted == trusted_after,
            "stable_file_observations": receipt["files_before_private"] == receipt["files_after_private"],
            "candidate_present_identity_trusted": all(receipt["files_after_private"]["candidate"].get(key) is True for key in ("present", "identity_verified", "trust_member")),
            "frozen_dependencies_present_identity_trusted": all(all(receipt["files_after_private"][name].get(key) is True for key in ("present", "identity_verified", "trust_member")) for name in DEPENDENCIES),
        }
        receipt["checks"] = checks
        receipt["refusals"] = [key for key, value in checks.items() if value is not True]
        receipt["observation_completed"] = True
        receipt["observed_baseline_checks_passed"] = all(checks.values())
    except (Refused, OSError, ValueError, KeyError, TypeError, struct.error, TimeoutError, subprocess.SubprocessError) as error:
        receipt["observation_completed"] = False; receipt["observed_baseline_checks_passed"] = False
        receipt["refusals"].append(type(error).__name__ + ": " + str(error)[:240])
    # Final clock/budget queries remain within their original guards. A guard
    # refusal must preserve copied observations, never reset/relax a budget or
    # replace an unavailable final timestamp/counter with an invented value.
    receipt["finalization_refusals"] = []
    for field, query in (("clock_info", adapter.clock_info), ("finished_monotonic_private", adapter.now), ("budget", adapter.budget)):
        receipt[field] = None
        try:
            receipt[field] = query()
        except (Refused, OSError, ValueError, KeyError, TypeError, struct.error, TimeoutError, subprocess.SubprocessError) as error:
            refusal = field + ": " + type(error).__name__ + ": " + str(error)[:240]
            receipt["finalization_refusals"].append(refusal)
            receipt["refusals"].append(refusal)
            receipt["observation_completed"] = False
            receipt["observed_baseline_checks_passed"] = False
    receipt["commands_private"] = adapter.commands
    receipt["existing_native_support"] = {"python_executable_path_private": sys.executable,
                                          "copied_native_primitive_paths": ["/usr/lib/libproc.dylib", "/System/Library/Frameworks/Foundation.framework/Foundation", "/usr/lib/libobjc.A.dylib"],
                                          "support_binary_identities_validated": False,
                                          "candidate_dependency_closure_proved": False,
                                          "scope": "existing native Python and system API support; no candidate image was executed or loaded"}
    return receipt


def execute(source_bytes, expected_source_sha256, inputs_bytes, adapter_factory=NativeObserver):
    need(type(source_bytes) is bytes and 0 < len(source_bytes) <= LIMITS["source_bytes"] and sha(source_bytes) == expected_source_sha256, "observer source binding changed")
    inputs = checked_inputs(inputs_bytes)
    return observe(adapter_factory(inputs), inputs, expected_source_sha256)


def main(argv=None, *, source_bytes=None, inputs_bytes=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observe", action="store_true")
    parser.add_argument("--source-sha256")
    parser.add_argument("--inputs")
    args = parser.parse_args(argv)
    if not args.observe:
        print(json.dumps({"schema": "macws.swap-pair.observer-default-off.v4", "native_execution": False, "launchd_domain": LAUNCHD_DOMAIN, "limits": LIMITS}))
        return 0
    need(type(args.source_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", args.source_sha256) is not None, "explicit frozen observer source digest required")
    if source_bytes is None:
        source_bytes = Path(__file__).read_bytes()
    if inputs_bytes is None:
        need(args.inputs is not None, "exact copied inputs required")
        inputs_bytes = Path(args.inputs).read_bytes()
    previous = signal.getsignal(signal.SIGALRM)
    def timed_out(signum, frame):
        raise TimeoutError("observer independent 12-second alarm")
    signal.signal(signal.SIGALRM, timed_out); signal.alarm(LIMITS["device_alarm_seconds"])
    try:
        receipt = execute(source_bytes, args.source_sha256, inputs_bytes)
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")), flush=True)
        return 0 if receipt["observation_completed"] else 1
    finally:
        signal.alarm(0); signal.signal(signal.SIGALRM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
