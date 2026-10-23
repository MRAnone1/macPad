"""Default-off preparation of one fixed, owned five-file diagnostic cleanup.

No transport is provided. All source/input/plan/delivery bytes are explicit.
Construction checks structure and immutable bindings, never current freshness
or native authenticity. The payload repeats a live exact-v4 observation first.
"""
import argparse
import base64
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import signal
import stat
import time

OBSERVER_SHA = "717de31eb1d7a05ed363eca7c3dce0dbd7f4ff500bb8cb65377bd340babf1c7a"
INPUT_SHA = "f7261fcf3e6c47493e92f8b04396316acf9d3f66b229d77a85cc0f95ffa6f280"
PLAN_SHA = "d287798e366823c1394b7c6e57f0902daf6881fd9c198f116a8400464177bd76"
MANIFEST_SHA = "d2c843dc9930b28342c9b57d11bbee2bbe12202b1147dec11137106646d13263"
RECEIVER_SHA = "1d4a9f515b7884ead3326f39d35cc639e1e2972048e2f26a1f73033af3100463"
PIPELINE_SHA = "0d310c1c733807c810d867ccb04def8467f26fada6fcdf27b299f1ea6df9848e"
PROBE_DIR = "/private/var/mnt/rootfs/usr/local/libexec/macws-swap-pair-probe-20261017"
CONTROL_DIR = "/var/jb/usr/libexec/macws-swap-pair-controller-20261018"
DIRECTORIES = (PROBE_DIR, CONTROL_DIR)
FILES = {
    PROBE_DIR + "/probe.arm64": (0o755, "7e60e45736d93386f667b9009d0b2e8ea81ab38c0479294ec98019fd655af886"),
    CONTROL_DIR + "/controller.py": (0o600, "955c50b5cb2b30b8f0aefd69720675d04c91126dec17c802fb09be8c42197977"),
    CONTROL_DIR + "/runtime_support.py": (0o600, "5d09cf9380afaa2409661a58909d1bfee41d81943f1b2306facb0cd94ee10fe0"),
    CONTROL_DIR + "/watchdog.py": (0o600, "c28ec9edd30bf86613c7cb29693697901228b579100b8b181a4dc47915f00e0a"),
    CONTROL_DIR + "/offline-QA.canonical.private.json": (0o600, "ebee0b881b5f589c4ca100c5dbcd4c72faa946b0bf741511a7396138139ae29c"),
}
STAT_KEYS = ("dev", "ino", "size", "mtime_ns", "ctime_ns", "mode", "uid", "gid", "nlink")
CHECKS = {"exact_device_build", "same_boot", "same_UI_generations", "nominal_thermal", "no_blocked_workloads",
          "both_scratch_absent", "both_job_labels_absent", "same_trust_membership_set", "stable_file_observations",
          "candidate_present_identity_trusted", "frozen_dependencies_present_identity_trusted"}
MAX_DELIVERY_BYTES = 128 * 1024
MAX_FILE_BYTES = 128 * 1024
DEADLINE_SECONDS = 8
ALARM_SECONDS = 12


def require(condition, message):
    if condition is not True:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_object(raw, limit):
    require(type(raw) is bytes and 0 < len(raw) <= limit, "explicit bounded JSON bytes required")
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, "duplicate JSON key")
            out[key] = value
        return out
    def invalid(_):
        raise ValueError("nonfinite JSON value")
    def number(word):
        value = float(word)
        require(math.isfinite(value), "nonfinite JSON value")
        return value
    try:
        out = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid, parse_float=number)
    except (RecursionError, UnicodeError) as error:
        raise ValueError("unparseable bounded JSON") from error
    require(type(out) is dict, "JSON object required")
    return out


def metadata():
    return {"schema": "macws.fixed-owned-cleanup.preparation.v1", "cleanup_requested": False,
            "fixed_files": 5, "fixed_directories": 2, "device_commands": 0, "transport_provided": False,
            "current_freshness_verified": False, "evidence_authenticity_verified": False,
            "device_acceptance": False, "observer_sha256": OBSERVER_SHA, "inputs_sha256": INPUT_SHA,
            "plan_sha256": PLAN_SHA, "manifest_sha256": MANIFEST_SHA,
            "deadline_seconds": DEADLINE_SECONDS, "alarm_seconds": ALARM_SECONDS}


def validate_plan(raw):
    require(sha(raw) == PLAN_SHA, "exact reviewed delivery plan bytes required")
    plan = strict_object(raw, 64 * 1024)
    require(plan["schema"] == "macws.diagnostic-probe.delivery-plan.v1" and
            plan["bundle_manifest_sha256"] == MANIFEST_SHA and plan["receiver_source_sha256"] == RECEIVER_SHA and
            plan["pipeline_source_sha256"] == PIPELINE_SHA and plan["architecture"] == "arm64", "fixed plan bindings")
    rows = plan["payload_files"]
    require(type(rows) is list and len(rows) == 5 and {row["path"] for row in rows} == set(FILES), "fixed plan file set")
    for row in rows:
        mode, digest = FILES[row["path"]]
        require(row == {"name": row["path"].rsplit("/", 1)[1], "path": row["path"],
                        "mode": format(mode, "04o"), "sha256": digest}, "fixed plan row")
    return plan


def validate_stat(value, *, directory=False, mode=None):
    require(type(value) is dict and set(value) == set(STAT_KEYS) and
            all(type(x) is int and x >= 0 for x in value.values()) and value["ino"] > 0, "typed complete delivery stat")
    require(value["uid"] == value["gid"] == 0 and value["nlink"] > 0, "root-owned delivery stat")
    require(value["mode"] == (0o700 if directory else mode), "fixed delivery mode")
    if not directory:
        require(value["nlink"] == 1 and 0 < value["size"] <= MAX_FILE_BYTES, "fixed bounded single-link payload")


def validate_delivery(delivery, plan):
    require(type(delivery) is dict and delivery["schema"] == "macws.diagnostic-probe.delivery.private.v1" and
            delivery["receiver_sha256"] == RECEIVER_SHA == plan["receiver_source_sha256"] and
            delivery["bundle_manifest_sha256"] == MANIFEST_SHA == plan["bundle_manifest_sha256"] and
            delivery["installation_verified"] is True and "refusal" not in delivery, "verified fixed delivery binding")
    for key in ("candidate_executions", "controller_executions", "trust_mutations"):
        require(type(delivery[key]) is int and delivery[key] == 0, "unexpected delivery effects")
    for key in ("automatic_cleanup_attempted", "native_dependency_closure_currently_verified", "current_trust_verified",
                "device_acceptance", "runtime_accepted", "freeze_cause_or_fix_proven"):
        require(delivery[key] is False, "unexpected delivery authority")
    rows, dirs = delivery["installed_files_private"], delivery["created_directories_private"]
    require(type(rows) is list and len(rows) == 5 and {row["path"] for row in rows} == set(FILES), "exact five delivery files")
    require(type(dirs) is list and len(dirs) == 2 and {row["path"] for row in dirs} == set(DIRECTORIES), "exact two delivery directories")
    inode_ids = set()
    for row in rows:
        require(type(row) is dict and set(row) == {"name", "path", "sha256", "stat", "previously_absent", "new_vnode_created_exclusively"}, "fixed delivery row schema")
        mode, digest = FILES[row["path"]]
        require(row["name"] == row["path"].rsplit("/", 1)[1] and row["sha256"] == digest and
                row["previously_absent"] is True and row["new_vnode_created_exclusively"] is True, "new exclusive fixed delivery file")
        validate_stat(row["stat"], mode=mode)
        identity = (row["stat"]["dev"], row["stat"]["ino"])
        require(identity not in inode_ids, "duplicate delivery vnode")
        inode_ids.add(identity)
    for row in dirs:
        require(type(row) is dict and set(row) == {"path", "stat"}, "fixed directory row schema")
        validate_stat(row["stat"], directory=True)
        identity = (row["stat"]["dev"], row["stat"]["ino"])
        require(identity not in inode_ids, "duplicate directory vnode")
        inode_ids.add(identity)
    parents = delivery["parents_private"]
    require(type(parents) is list and len(parents) == 2 and
            {row["logical"] for row in parents} == {path.rsplit("/", 1)[0] for path in DIRECTORIES} and
            all(row["target_previously_absent"] is True for row in parents), "exclusive two-parent delivery receipt")
    require(delivery["probe_signature"] == plan["probe_signature_host_verified"], "delivered signature differs from reviewed plan")
    return rows, dirs


def validate_baseline(value, candidate):
    require(type(value) is dict and value["schema"] == "macws.swap-pair.read-only-admission-observations.v4" and
            value["observer_source_sha256"] == OBSERVER_SHA and value["inputs_sha256"] == INPUT_SHA and
            value["launchd_domain"] == "user/501", "exact current v4 observation binding")
    require(value["observation_completed"] is True and value["observed_baseline_checks_passed"] is True and
            value["refusals"] == [] and value["finalization_refusals"] == [], "completed positive baseline required")
    require(type(value["checks"]) is dict and set(value["checks"]) == CHECKS and
            all(x is True for x in value["checks"].values()), "all exact baseline checks required")
    for key in ("fully_admitted", "runtime_accepted", "device_acceptance", "runtime_controls_verified", "freshness_verified"):
        require(value[key] is False, "unexpected observer authority")
    require(value["new_vnode"] is None, "observer must not invent vnode receipt")
    for key in ("mutations", "candidate_executions", "launchd_mutations", "trust_mutations"):
        require(type(value[key]) is int and value[key] == 0, "unexpected observer effects")
    observed = value["files_after_private"]["candidate"]
    require(observed["path"] == candidate["path"] and observed["sha256"] == candidate["sha256"] and
            observed["stat_token_private"] == [candidate["stat"][key] for key in STAT_KEYS[:5]] and
            all(observed[key] is True for key in ("present", "identity_verified", "trust_member")), "observed candidate differs from exact delivery")


class NativeFS:
    open = staticmethod(os.open)
    close = staticmethod(os.close)
    fstat = staticmethod(os.fstat)
    stat = staticmethod(os.stat)
    read = staticmethod(os.read)
    listdir = staticmethod(os.listdir)
    unlink = staticmethod(os.unlink)
    rmdir = staticmethod(os.rmdir)


def stat_values(info):
    return {key: (stat.S_IMODE(info.st_mode) if key == "mode" else getattr(info, "st_" + key)) for key in STAT_KEYS}


def check_directory(fs, fd, parent_fd, name, expected, *, pristine):
    held = fs.fstat(fd)
    linked = fs.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    require(stat.S_ISDIR(held.st_mode) and stat.S_ISDIR(linked.st_mode), "owned directory kind changed")
    a, b = stat_values(held), stat_values(linked)
    require(a == b and all(a[key] == expected[key] for key in ("dev", "ino", "mode", "uid", "gid")) and
            a["nlink"] > 0, "owned directory path/vnode/mode/owner changed")
    if pristine:
        require(a == expected, "owned directory complete delivery token changed")


def checked_file(fs, directory_fd, row, check):
    check()
    fd = fs.open(row["name"], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        before = fs.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and stat_values(before) == row["stat"], "owned file complete token/mode/owner/link changed")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            check()
            block = fs.read(fd, min(65536, remaining))
            require(type(block) is bytes and 0 < len(block) <= remaining, "short/invalid owned file read")
            digest.update(block)
            remaining -= len(block)
        require(fs.read(fd, 1) == b"", "owned file grew during bounded read")
        after, linked = fs.fstat(fd), fs.stat(row["name"], dir_fd=directory_fd, follow_symlinks=False)
        require(stat.S_ISREG(linked.st_mode) and stat_values(after) == row["stat"] == stat_values(linked) and
                digest.hexdigest() == row["sha256"], "owned file bytes/path/token changed")
        check()
        return fd
    except BaseException:
        fs.close(fd)
        raise


def cleanup_scoped(delivery, plan, baseline, *, fs=None, clock=time.monotonic, started=None):
    """Scope is fixed; injected FS/clock are synthetic-test seams only.

    The generated native payload supplies neither override. Full ownership is
    rechecked before each unlink; this is not an atomic namespace snapshot.
    """
    simulation = fs is not None
    fs = NativeFS() if fs is None else fs
    report = {"schema": "macws.fixed-owned-cleanup.private.v1", "removed_files_private": [],
              "attempted_files_private": [], "removed_directories_private": [], "attempted_directories_private": [], "cleanup_verified": False,
              "device_acceptance": False, "current_freshness_verified_by_preparation": False,
              "atomic_namespace_ownership_claimed": False, "trust_mutations": 0, "job_mutations": 0,
              "signals_to_jobs": 0, "candidate_executions": 0, "trustcache_entry_removal_attempted": False,
              "simulation_only": simulation}
    fds, held = [], {}
    beginning = None
    def check():
        require(0 <= clock() - beginning < DEADLINE_SECONDS, "eight-second cleanup deadline")
    try:
        beginning = clock() if started is None else started
        check()
        # Preserve a negative/partial observation as copied evidence too.
        report["copied_readonly_before_private"] = baseline
        rows, dirs = validate_delivery(delivery, plan)
        validate_baseline(baseline, next(row for row in rows if row["path"] == PROBE_DIR + "/probe.arm64"))
        # Open and validate ALL directories and ALL five children before ANY unlink.
        for directory in dirs:
            check()
            path = directory["path"]
            parent, name = path.rsplit("/", 1)
            pfd = fs.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fds.append(pfd)
            fd = fs.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pfd)
            fds.append(fd)
            check_directory(fs, fd, pfd, name, directory["stat"], pristine=True)
            owned = [row for row in rows if row["path"].rsplit("/", 1)[0] == path]
            require(set(fs.listdir(fd)) == {row["name"] for row in owned}, "foreign/missing directory child")
            for row in owned:
                child = checked_file(fs, fd, row, check)
                fs.close(child)
            held[path] = (pfd, fd, name, directory["stat"], owned)
        report["all_objects_prevalidated"] = True
        for path in DIRECTORIES:
            pfd, fd, name, expected, owned = held[path]
            remaining = {row["name"] for row in owned}
            for row in owned:
                check()
                check_directory(fs, fd, pfd, name, expected, pristine=False)
                require(set(fs.listdir(fd)) == remaining, "directory child set changed before unlink")
                child = checked_file(fs, fd, row, check)
                try:
                    # Held child FD prevents reuse of the just-verified vnode.
                    report["attempted_files_private"].append(row["path"])
                    fs.unlink(row["name"], dir_fd=fd)
                    report["removed_files_private"].append(row["path"])
                    remaining.remove(row["name"])
                finally:
                    fs.close(child)
            check()
            check_directory(fs, fd, pfd, name, expected, pristine=False)
            require(fs.listdir(fd) == [], "owned directory not empty")
            report["attempted_directories_private"].append(path)
            fs.rmdir(name, dir_fd=pfd)
            report["removed_directories_private"].append(path)
        check()
        for path in list(FILES) + list(DIRECTORIES):
            check()
            try:
                fs.stat(path, dir_fd=None, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("scoped pathname still present")
        check()
        report["cleanup_verified"] = True
    except BaseException as error:
        report["error_private"] = type(error).__name__ + ": " + str(error)[:400]
        report["cleanup_verified"] = False
    finally:
        for fd in reversed(fds):
            try:
                fs.close(fd)
            except BaseException as error:
                report.setdefault("finalization_errors_private", []).append(type(error).__name__ + ": " + str(error)[:200])
                report["cleanup_verified"] = False
        try:
            report["elapsed_seconds"] = None if beginning is None else clock() - beginning
        except BaseException as error:
            report["elapsed_seconds"] = None
            report.setdefault("finalization_errors_private", []).append(type(error).__name__ + ": " + str(error)[:200])
            report["cleanup_verified"] = False
    return report


def build_cleanup_payload(*, observer_source, observer_inputs, plan_raw, delivery_raw):
    require(type(observer_source) is bytes and len(observer_source) <= 256 * 1024 and sha(observer_source) == OBSERVER_SHA, "exact v4 observer source required")
    require(type(observer_inputs) is bytes and len(observer_inputs) <= 128 * 1024 and sha(observer_inputs) == INPUT_SHA, "exact v4 observer inputs required")
    plan = validate_plan(plan_raw)
    delivery = strict_object(delivery_raw, MAX_DELIVERY_BYTES)
    validate_delivery(delivery, plan)
    constants = ("OBSERVER_SHA", "INPUT_SHA", "PLAN_SHA", "MANIFEST_SHA", "RECEIVER_SHA", "PIPELINE_SHA", "PROBE_DIR",
                 "CONTROL_DIR", "DIRECTORIES", "FILES", "STAT_KEYS", "CHECKS", "MAX_DELIVERY_BYTES", "MAX_FILE_BYTES", "DEADLINE_SECONDS", "ALARM_SECONDS")
    source = "import base64,hashlib,json,math,os,signal,stat,time,sys\nsys.dont_write_bytecode=True\n"
    source += "\n".join(name + "=" + ("{" + ",".join(repr(key) for key in sorted(CHECKS)) + "}"
                        if name == "CHECKS" else repr(globals()[name])) for name in constants) + "\n"
    for item in (require, sha, strict_object, validate_plan, validate_stat, validate_delivery, validate_baseline,
                 NativeFS, stat_values, check_directory, checked_file, cleanup_scoped):
        source += inspect.getsource(item) + "\n"
    body = {"source": base64.b64encode(observer_source).decode(), "inputs": base64.b64encode(observer_inputs).decode(),
            "plan": base64.b64encode(plan_raw).decode(), "delivery": base64.b64encode(delivery_raw).decode()}
    source += "BODY=" + repr(body) + "\n"
    source += '''
report={"schema":"macws.fixed-owned-cleanup.private.v1","cleanup_verified":False,"removed_files_private":[],"removed_directories_private":[],"device_acceptance":False}
previous=None
try:
 def expired(signum,frame):raise TimeoutError("independent twelve-second cleanup alarm")
 previous=signal.signal(signal.SIGALRM,expired);signal.alarm(ALARM_SECONDS)
 started=time.monotonic()
 copied={key:base64.b64decode(value,validate=True) for key,value in BODY.items()}
 require(sha(copied["source"])==OBSERVER_SHA and sha(copied["inputs"])==INPUT_SHA,"v4 source/input changed")
 plan=validate_plan(copied["plan"]);delivery=strict_object(copied["delivery"],MAX_DELIVERY_BYTES);validate_delivery(delivery,plan)
 namespace={"__name__":"hash_bound_cleanup_readonly_observer_v4"}
 exec(compile(copied["source"],"<hash-bound-cleanup-observer-v4>","exec"),namespace)
 baseline=namespace["execute"](copied["source"],OBSERVER_SHA,copied["inputs"])
 report=cleanup_scoped(delivery,plan,baseline,started=started)
 report.update(raw_delivery_sha256=sha(copied["delivery"]),raw_plan_sha256=sha(copied["plan"]),observer_sha256=OBSERVER_SHA,inputs_sha256=INPUT_SHA)
except BaseException as error:
 report["error_private"]=type(error).__name__+": "+str(error)[:400];report["cleanup_verified"]=False
finally:
 try:
  signal.alarm(0)
  if previous is not None:signal.signal(signal.SIGALRM,previous)
 except BaseException as error:
  report.setdefault("finalization_errors_private",[]).append(type(error).__name__+": "+str(error)[:200]);report["cleanup_verified"]=False
 print(json.dumps(report,allow_nan=False,separators=(",",":")),flush=True)
'''
    raw = source.encode()
    require(len(raw) <= 256 * 1024, "bounded cleanup payload exceeded")
    compile(raw, "<prepared-fixed-owned-cleanup>", "exec")
    return raw, dict(metadata(), cleanup_requested=True, source_sha256=sha(raw), source_bytes=len(raw),
                     raw_delivery_sha256=sha(delivery_raw), raw_plan_sha256=sha(plan_raw),
                     structurally_bound=True, requires_live_readonly_baseline=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    print(json.dumps(metadata(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
