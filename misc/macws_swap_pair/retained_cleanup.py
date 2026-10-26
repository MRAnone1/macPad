"""Explicit fixed retained-artifact selection; import/default CLI is inert.

This is a trusted-caller reference core, not a live device adapter. Its caller
must authenticate original evidence, expected content, actual fresh observations
and the direct successful durable host-archive return before using Cleaner.
JSON consistency alone proves none of those facts. No native backend or
transport is constructed. Original OwnedFiles authority is never recreated.
"""
from __future__ import annotations

import errno
import hashlib
import json
import math
import os
from pathlib import PurePosixPath
import re
import stat

TARGET = "/private/var/tmp/macws-swap-pair-control-20261018"
NAMES = ("job.plist", "probe.log")
LIMITS = {"job.plist": 65536, "probe.log": 262144}
OWNER = (0, 0)
SERVICES = ("user/501/com.macws.preflight.swap-pair.20261017",
            "user/501/com.macws.preflight.swap-pair-control.20261018")
SOURCES = {
    "controller.py": "955c50b5cb2b30b8f0aefd69720675d04c91126dec17c802fb09be8c42197977",
    "runtime_support.py": "5d09cf9380afaa2409661a58909d1bfee41d81943f1b2306facb0cd94ee10fe0",
    "watchdog.py": "c28ec9edd30bf86613c7cb29693697901228b579100b8b181a4dc47915f00e0a",
}
PROVENANCE_KEYS = (
    "original_wire_sha256", "original_host_sha256", "original_delivery_sha256",
    "original_config_sha256", "effective_config_sha256", "retirement_wire_sha256",
    "retained_snapshot_sha256", "current_wire_sha256",
)
STAT_FIELDS = {"dev", "ino", "size", "mtime_ns", "ctime_ns", "mode", "uid", "gid", "nlink", "kind"}


class Refused(ValueError):
    pass


def need(condition, message):
    if condition is not True:
        raise Refused(message)


def _copy(value, depth=0, budget=None):
    budget = [2048] if budget is None else budget
    budget[0] -= 1
    need(depth <= 12 and budget[0] >= 0, "JSON structure bound")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        need(-(1 << 63) <= value < 1 << 63, "JSON integer bound")
        return value
    if type(value) is float:
        need(math.isfinite(value), "nonfinite JSON number")
        return value
    if type(value) is str:
        need(len(value) <= 4096 and len(value.encode("utf-8")) <= 4096, "JSON string bound")
        return value
    if type(value) is list:
        need(len(value) <= 64, "JSON array bound")
        return [_copy(item, depth + 1, budget) for item in value]
    need(type(value) is dict and len(value) <= 64 and
         all(type(key) is str and len(key) <= 128 for key in value), "JSON object bound")
    return {key: _copy(item, depth + 1, budget) for key, item in value.items()}


def canonical(value):
    raw = json.dumps(_copy(value), sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    need(len(raw) <= 65536, "complete JSON bound")
    return raw


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 65536, "bounded original JSON")
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    try:
        result = json.loads(raw, object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(Refused("nonfinite JSON")))
        canonical(result)
        return result
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Refused("invalid JSON") from error


def keys(value, fields):
    need(type(value) is dict and set(value) == set(fields), "fixed object fields")


def sha_word(value):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "SHA256 shape")


def birth(value):
    need(type(value) is list and len(value) == 3 and all(type(x) is int for x in value) and
         1 < value[0] <= 0x7fffffff and 0 < value[1] < 1 << 63 and
         0 <= value[2] < 1000000, "native process birth")


def context_checked(value):
    result = decode(canonical(value))
    keys(result, ("boot_private", "config_sha256", "source_sha256", "retired_birth_private",
                  "UI_private", "expected_file_sha256", "exclusive_operator"))
    need(type(result["boot_private"]) is str and re.fullmatch(
        r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", result["boot_private"]) is not None,
        "original boot binding")
    sha_word(result["config_sha256"])
    keys(result["expected_file_sha256"], NAMES)
    for value in result["expected_file_sha256"].values(): sha_word(value)
    need(result["source_sha256"] == SOURCES and result["exclusive_operator"] is True,
         "frozen source and exclusive caller")
    birth(result["retired_birth_private"])
    keys(result["UI_private"], ("SpringBoard", "backboardd"))
    for value in result["UI_private"].values():
        birth(value)
    need(len({result["retired_birth_private"][0], *(x[0] for x in result["UI_private"].values())}) == 3,
         "distinct native process identities")
    return result


def stat_record(info):
    kind = "directory" if stat.S_ISDIR(info.st_mode) else "regular" if stat.S_ISREG(info.st_mode) else "other"
    return {"dev": info.st_dev, "ino": info.st_ino, "size": info.st_size,
            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
            "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
            "gid": info.st_gid, "nlink": info.st_nlink, "kind": kind}


def stat_checked(value, kind):
    keys(value, STAT_FIELDS)
    need(all(type(item) is int and 0 <= item < 1 << 63 for key, item in value.items() if key != "kind"),
         "strict stat integers")
    need(value["kind"] == kind and value["ino"] > 0 and value["nlink"] > 0 and
         (value["uid"], value["gid"]) == OWNER and
         value["mode"] == (0o700 if kind == "directory" else 0o600), "selected object type/owner/mode")
    if kind == "regular":
        need(value["nlink"] == 1, "selected regular file hardlink")


def selection_checked(value, context, expected_files):
    result = decode(canonical(value))
    keys(result, ("schema", "path", "boot_private", "config_sha256", "source_sha256", "directory", "files"))
    need(result["schema"] == "macws.retained-artifact.selection.v1" and result["path"] == TARGET and
         result["boot_private"] == context["boot_private"] and
         result["config_sha256"] == context["config_sha256"] and result["source_sha256"] == SOURCES,
         "fixed current selection context")
    stat_checked(result["directory"], "directory")
    keys(result["files"], NAMES); keys(expected_files, NAMES)
    for name in NAMES:
        row = result["files"][name]
        keys(row, ("stat", "sha256")); stat_checked(row["stat"], "regular"); sha_word(row["sha256"])
        raw = expected_files[name]
        need(type(raw) is bytes and len(raw) <= LIMITS[name] and (name != "job.plist" or len(raw) > 0),
             "bounded retained original copied content")
        need(row["sha256"] == digest(raw) == context["expected_file_sha256"][name] and
             row["stat"]["size"] == len(raw), "selected original effective plist/retained log content lineage")
        need(row["stat"]["dev"] == result["directory"]["dev"], "selected same filesystem")
    need(result["files"][NAMES[0]]["stat"]["ino"] != result["files"][NAMES[1]]["stat"]["ino"], "distinct selected files")
    return result


def provenance_checked(value, context):
    value = decode(canonical(value)); keys(value, PROVENANCE_KEYS)
    for item in value.values(): sha_word(item)
    need(value["effective_config_sha256"] == context["config_sha256"], "effective configuration provenance")
    return value


def archive_checked(receipt, selection, provenance):
    result = decode(canonical(receipt))
    keys(result, ("schema", "manifest_sha256", "provenance_sha256", "wire_sha256", "file_sha256",
                  "durable_archive_verified", "native_evidence_authenticity_verified", "device_acceptance"))
    need(result == {
        "schema": "macws.retained-artifact.archive.v1", "manifest_sha256": digest(canonical(selection)),
        "provenance_sha256": digest(canonical(provenance)), "wire_sha256": provenance["current_wire_sha256"],
        "file_sha256": {name: selection["files"][name]["sha256"] for name in NAMES},
        "durable_archive_verified": True, "native_evidence_authenticity_verified": False,
        "device_acceptance": False,
    } and result["durable_archive_verified"] is True and
         result["native_evidence_authenticity_verified"] is False and result["device_acceptance"] is False,
         "matching successful host archive receipt required")
    return result


def _anchor_identity(record):
    return {key: record[key] for key in ("dev", "ino", "kind", "mode", "uid", "gid")}


class _Held:
    """No-follow chain and selected file FDs, never path discovery or recursion."""
    def __init__(self):
        self.chain = []
        self.files = {}
        try:
            parts = PurePosixPath(TARGET).parts
            need(parts[0] == "/" and all(part not in (".", "..", "") for part in parts[1:]), "fixed absolute path")
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
            self.add_directory(None, fd)
            for name in parts[1:]:
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=self.chain[-1][1])
                self.add_directory(name, fd)
            self.fd = self.chain[-1][1]
            for name in NAMES:
                self.files[name] = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
            self.anchor_checked()
        except BaseException:
            self.close()
            raise

    def add_directory(self, name, fd):
        try:
            record = stat_record(os.fstat(fd))
        except BaseException:
            os.close(fd)
            raise
        self.chain.append((name, fd, record))

    def close(self):
        for fd in self.files.values(): os.close(fd)
        self.files = {}
        for _, fd, _ in reversed(self.chain): os.close(fd)
        self.chain = []

    def anchor_checked(self, include_selection=True):
        chain = self.chain if include_selection else self.chain[:-1]
        for index, (name, fd, original) in enumerate(chain):
            current = stat_record(os.fstat(fd))
            need(current["kind"] == "directory" and _anchor_identity(current) == _anchor_identity(original),
                 "held directory anchor changed")
            if index:
                entry = stat_record(os.stat(name, dir_fd=self.chain[index-1][1], follow_symlinks=False))
                need(_anchor_identity(entry) == _anchor_identity(current), "fixed directory path substituted")
            else:
                need(_anchor_identity(stat_record(os.lstat("/"))) == _anchor_identity(current), "root anchor changed")

    def read_file(self, name):
        fd = self.files[name]
        before = stat_record(os.fstat(fd)); stat_checked(before, "regular")
        need(before["size"] <= LIMITS[name], "selected file read bound")
        raw = bytearray(); os.lseek(fd, 0, os.SEEK_SET)
        while len(raw) <= before["size"]:
            block = os.read(fd, min(65536, before["size"] + 1 - len(raw)))
            if not block: break
            raw.extend(block)
        after = stat_record(os.fstat(fd))
        entry = stat_record(os.stat(name, dir_fd=self.fd, follow_symlinks=False))
        need(before == after == entry and len(raw) == before["size"], "selected file changed during held read")
        return bytes(raw), before

    def checked(self, manifest=None, remaining=NAMES):
        self.anchor_checked()
        directory = stat_record(os.fstat(self.fd)); stat_checked(directory, "directory")
        need(set(os.listdir(self.fd)) == set(remaining), "exact remaining selected entries")
        files, content = {}, {}
        for name in remaining:
            raw, record = self.read_file(name)
            content[name] = raw; files[name] = {"stat": record, "sha256": digest(raw)}
        self.anchor_checked()
        need(stat_record(os.fstat(self.fd)) == directory and set(os.listdir(self.fd)) == set(remaining),
             "directory changed during selection read")
        if manifest is not None:
            need(_anchor_identity(directory) == _anchor_identity(manifest["directory"]), "selected directory replaced")
            if tuple(remaining) == NAMES:
                need(directory == manifest["directory"], "original selected directory metadata changed")
            need(all(files[name] == manifest["files"][name] for name in remaining), "selected full file manifest mismatch")
        return directory, files, content


def capture_selection(context):
    """Read-only local selection; no native evidence or action is authorized."""
    context = context_checked(context)
    held = _Held()
    try:
        directory, files, content = held.checked()
        manifest = {"schema": "macws.retained-artifact.selection.v1", "path": TARGET,
                    "boot_private": context["boot_private"], "config_sha256": context["config_sha256"],
                    "source_sha256": dict(SOURCES), "directory": directory, "files": files}
        selection_checked(manifest, context, content)
        return {"manifest": manifest, "files": content, "native_evidence_authenticity_verified": False}
    finally:
        held.close()


def _absence(value, expected_birth):
    keys(value, ("api", "flavor", "requested_bytes", "returned", "errno", "outcome", "pid_private", "expected_birth_private"))
    need(value["api"] == "proc_pidinfo" and value["outcome"] == "ESRCH" and
         value["expected_birth_private"] == expected_birth and
         all(type(value[key]) is int and value[key] == expected for key, expected in (
             ("flavor", 3), ("requested_bytes", 136), ("returned", 0), ("errno", errno.ESRCH),
             ("pid_private", expected_birth[0]))), "copied native retired-generation absence")
    birth(value["expected_birth_private"])


class Cleaner:
    """One-use explicit syscall route; requires trusted real caller integration.

    Caller JSON cannot prove archive durability or fresh native observations.
    This class supplies no such backend, transport, authentication or watchdog.
    """
    def __init__(self, manifest, provenance, archive_receipt, context, expected_files):
        self.context_raw = canonical(context_checked(context))
        context = decode(self.context_raw)
        self.manifest_raw = canonical(selection_checked(manifest, context, expected_files))
        self.provenance_raw = canonical(provenance_checked(provenance, context))
        self.archive_receipt_raw = canonical(archive_checked(archive_receipt, decode(self.manifest_raw), decode(self.provenance_raw)))
        self.used = False
        self.last_clock = None
        self.observations = []

    def _clock(self, backend, deadline=None):
        value = backend.now()
        need(type(value) in (int, float) and math.isfinite(value) and value >= 0 and
             (self.last_clock is None or value >= self.last_clock) and
             (deadline is None or value < deadline), "bounded nonregressing cleanup clock")
        self.last_clock = value
        return value

    def _gates(self, backend, manifest, provenance, context, deadline):
        before = self._clock(backend, deadline)
        value = decode(canonical(backend.observe(digest(self.manifest_raw), digest(self.provenance_raw), deadline)))
        self.observations.append(value)
        need(len(self.observations) <= 5, "bounded gate observation count")
        after = self._clock(backend, deadline)
        keys(value, ("schema", "selection_sha256", "provenance_sha256", "boot_private", "config_sha256",
                     "source_sha256", "UI_private", "exclusive_operator", "observed_monotonic", "jobs_absent",
                     "no_candidate_or_test_workloads", "other_scratch_absent", "artifacts_unchanged", "thermal", "generation_absence"))
        observed = value["observed_monotonic"]
        need(type(observed) in (int, float) and math.isfinite(observed) and before <= observed <= after and
             after - observed <= 1, "fresh bounded gate evidence")
        need(value["schema"] == "macws.retained-artifact.gates.v1" and
             value["selection_sha256"] == digest(self.manifest_raw) and
             value["provenance_sha256"] == digest(self.provenance_raw) and
             value["boot_private"] == context["boot_private"] and value["config_sha256"] == context["config_sha256"] and
             value["source_sha256"] == SOURCES and canonical(value["UI_private"]) == canonical(context["UI_private"]),
             "fresh context/source/UI bindings")
        need(all(value[key] is True for key in ("exclusive_operator", "no_candidate_or_test_workloads", "other_scratch_absent", "artifacts_unchanged")),
             "fresh independent baseline refusal")
        keys(value["jobs_absent"], SERVICES)
        need(all(value["jobs_absent"][name] is True for name in SERVICES) and
             type(value["thermal"]) is int and value["thermal"] == 0, "fresh jobs/thermal refusal")
        _absence(value["generation_absence"], context["retired_birth_private"])
        return observed

    def execute_once(self, backend):
        need(self.used is False, "cleanup object is one-use; no automatic retry")
        self.used = True
        report = {"schema": "macws.retained-artifact.cleanup-result.v1", "attempted": [], "completed": [],
                  "outcome": "refused_before_effect", "cleanup_verified": False,
                  "native_evidence_authenticity_verified": False, "device_acceptance": False,
                  "original_ownership_recovered": False, "freeze_fix": False, "error": None,
                  "refusal": None, "stage": "before_observation",
                  "selection_sha256": digest(self.manifest_raw),
                  "provenance_sha256": digest(self.provenance_raw),
                  "archive_receipt_sha256": digest(self.archive_receipt_raw),
                  "gate_observations_private": self.observations}
        held = None
        try:
            manifest, provenance, context = decode(self.manifest_raw), decode(self.provenance_raw), decode(self.context_raw)
            start = self._clock(backend)
            deadline = start + 8
            self._gates(backend, manifest, provenance, context, deadline)
            report["stage"] = "open_and_validate_selection"
            held = _Held(); held.checked(manifest)
            remaining = list(NAMES)
            for name in NAMES:
                report["stage"] = "before_unlink:" + name
                observed = self._gates(backend, manifest, provenance, context, deadline)
                held.checked(manifest, remaining)
                need(self._clock(backend, deadline) - observed <= 1, "gate stale immediately before unlink")
                report["attempted"].append("unlink:" + name)
                os.unlink(name, dir_fd=held.fd)
                report["completed"].append("unlink:" + name)
                remaining.remove(name)
            report["stage"] = "before_rmdir"
            observed = self._gates(backend, manifest, provenance, context, deadline)
            held.checked(manifest, remaining)
            need(self._clock(backend, deadline) - observed <= 1, "gate stale immediately before rmdir")
            report["attempted"].append("rmdir:selection")
            os.rmdir(self.chain_name(held), dir_fd=held.chain[-2][1])
            report["completed"].append("rmdir:selection")
            report["stage"] = "after_rmdir"
            post_observed = self._gates(backend, manifest, provenance, context, deadline)
            # Parent remains held. Any unexpected object, even a replacement,
            # means absence is unverified; never delete or re-adopt it.
            for _ in range(2):
                held.anchor_checked(include_selection=False)
                self._clock(backend, deadline)
                try:
                    os.stat(self.chain_name(held), dir_fd=held.chain[-2][1], follow_symlinks=False)
                except FileNotFoundError:
                    held.anchor_checked(include_selection=False)
                    continue
                raise Refused("selection path reappeared")
            need(self._clock(backend, deadline) - post_observed <= 1, "post-removal gate stale at final verification")
            report["outcome"] = "selection_absent_after_effects"
            report["cleanup_verified"] = True
            report["stage"] = "finished"
        except Exception as error:
            report["outcome"] = "partial_or_unknown" if report["attempted"] else "refused_before_effect"
            report["error"] = type(error).__name__
            report["refusal"] = str(error) if type(error) is Refused else None
        finally:
            if held is not None: held.close()
        return report

    @staticmethod
    def chain_name(held):
        return held.chain[-1][0]


def metadata():
    return {"schema": "macws.retained-artifact.cleanup-metadata.v1", "default_inert": True,
            "native_backend_provided": False, "transport_provided": False,
            "default_filesystem_operations": 0, "original_ownership_recovered": False,
            "device_acceptance": False, "new_control_authorized": False}


if __name__ == "__main__":
    print(json.dumps(metadata(), sort_keys=True))
