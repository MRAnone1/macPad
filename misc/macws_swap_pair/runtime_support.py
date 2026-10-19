"""Private standalone device backend. Importing performs no native operation.

Execution is gated by source-bound live prerequisites. No transport, signing,
deployment, task-port extraction, GPU selector or global cleanup is provided.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import plistlib
import re
import signal
import stat
import struct
import subprocess
import time

LABEL = "com.macws.preflight.swap-pair.20261017"
SCRATCH = "/private/var/tmp/macws-swap-pair-20261017"
CONTROL_LABEL = "com.macws.preflight.swap-pair-control.20261018"
CONTROL_SCRATCH = "/private/var/tmp/macws-swap-pair-control-20261018"
ROOTFS = "/private/var/mnt/rootfs"
WRAPPER = "/var/jb/usr/libexec/macws-windowserver-preflight-20261007/launchdchrootexec_fullframe_streamgate_20261009"
WRAPPER_SHA256 = "e7f1d9e9966826022372248a308c2e28126758a97057ada43551c1a206549d20"
HOOKS = {
    "arm64": ("/usr/local/lib/libmachook_fullframe_streamgate_20261009_arm64.dylib", "bcd544a537fc81cbc16ec3fb8de2c7677708d35ada10c0caf044ba83f005340b"),
    "arm64e": ("/usr/local/lib/libmachook_fullframe_streamgate_20261009.dylib", "803bcccf8cb9afd8d3b96bdbe88ca13d79463e6a09f2c192d346bc5300541008"),
}
LAUNCHCTL = "/var/jb/usr/bin/launchctl"
# Runtime-copied native witnesses pin this port to one explicit launchd domain.
# Do not follow redirects, foreground aliases, or caller-selected domains.
LAUNCHD_DOMAIN = "user/501"
JBCTL = "/var/jb/usr/bin/jbctl"
SOURCE_FILES = ("runtime_support.py", "watchdog.py", "controller.py")
PROBE_PROFILE_SHA256 = "c49855470070de0efe28bd16c05084eee16db268e450285c906158d67d1cdaae"
PROBE_SOURCE_SHA256 = "2a4e1eb2ddc36fb903c5e495095a1daade11c0f14ae8a96dc376a062df491d73"
PROBE_BUILD_RECEIPT_SHA256 = "68875295a822e3e788a6e2baaadd318075c566bcf4da0cab2430b2db79ecbfc9"
PROBE_BUILDS = {
    "arm64": ("7c2ec62be076eda3e14e51e8ef2118fa9b85f59cca4a028c8d77f9d58958ae5d", "9b8378ef-aab0-3e72-b8e3-8e1b56c9a647"),
    "arm64e": ("259ff0262f47eb7408839cba0d58cb75d07dadd82a7d85189b96be59b27ae815", "a1d8575a-aea8-3429-9361-77a0da8835ec"),
}
PROBE_LIMITS = {"read_call_limit": 20736, "read_byte_limit": 2883584, "dyld_image_limit": 1024,
                "total_deadline_seconds": 8, "loaded_hook_observations": 5}
REQUIRED_CONTROLS = ("normal_ready_stop", "parent_pipe_EOF", "active_deadline")
OPERATIONS = ("run", "control_normal", "control_parent_EOF", "control_deadline")
CONTROL_OPERATIONS = dict(zip(REQUIRED_CONTROLS, OPERATIONS[1:]))


def job_label(config):
    return LABEL if config["operation"] == "run" else CONTROL_LABEL


def scratch_path(config):
    return SCRATCH if config["operation"] == "run" else CONTROL_SCRATCH


def service_identifier(config):
    return LAUNCHD_DOMAIN + "/" + job_label(config)


def launchctl_success(result, message):
    """Exact observed quiet mutation result; warnings never imply success."""
    need(type(result) in (tuple, list) and len(result) == 3 and
         type(result[0]) is int and result[0] == 0 and result[1] == "" and result[2] == "", message)


def parsed_job(config, result):
    """Parse only the pinned domain and exact owned service's copied format.

    This is identity validation, not authentication of arbitrary command text.
    Caller must invoke the fixed launchctl command, retain owned-file checks,
    and bind the returned PID to exact native process/birth/inode witnesses.
    """
    need(type(result) in (tuple, list) and len(result) == 3 and
         type(result[0]) is int and all(type(x) is str for x in result[1:]), "launchctl result schema")
    code, stdout, stderr = result
    label = job_label(config)
    if code != 0:
        expected = 'Could not find service "' + label + '" in domain for uid: 501\n'
        need(code == 113 and stdout == "" and stderr == expected, "unrecognized launchctl absence result")
        return None
    need(stderr == "", "job query stderr")
    need(stdout.startswith(service_identifier(config) + " = {\n") and stdout.endswith("}\n"), "exact owned launchd domain/header")
    need(all(not line or line.startswith("\t") for line in stdout.splitlines()[1:-1]),
         "unexpected outer launchd block/header")
    def field(name):
        found = re.findall(r"^\t" + re.escape(name) + r" = ([^\n]*)$", stdout, re.M)
        need(len(found) == 1, "missing/duplicate owned job field: " + name)
        return found[0]
    for name, expected in (("program", WRAPPER), ("domain", LAUNCHD_DOMAIN),
                           ("path", scratch_path(config) + "/job.plist"),
                           ("stdout path", scratch_path(config) + "/probe.log"),
                           ("stderr path", scratch_path(config) + "/probe.log")):
        need(field(name) == expected, "exact owned launchd job field: " + name)
    blocks = re.findall(r"^\targuments = \{\n(.*?)^\t\}\n", stdout, re.M | re.S)
    expected_args = arguments(config)
    need(len(blocks) == 1 and blocks[0] == "".join("\t\t" + word + "\n" for word in expected_args),
         "exact owned launchd job arguments")
    pid_fields = re.findall(r"^\tpid = ([^\n]*)$", stdout, re.M)
    need(len(pid_fields) <= 1, "duplicate owned job PID")
    pid = None
    if pid_fields:
        need(re.fullmatch(r"[1-9][0-9]{0,9}", pid_fields[0]) is not None, "owned job PID shape")
        pid = int(pid_fields[0])
        need(1 < pid <= 0x7fffffff, "owned job PID range")
    return {"pid": pid, "arguments": expected_args}


def admission_sha(config):
    """One reviewed session/build/QA binding shared by disjoint operations."""
    return config_sha({key: value for key, value in config.items() if key != "operation"})


class Refused(RuntimeError):
    pass


class NativeSharedClock:
    """Public Mach absolute counter; no per-process epoch subtraction.

    Construction is explicit. Importing this module performs no native call.
    library injection is for synthetic host controls only.
    """
    def __init__(self, library=None):
        class Timebase(ctypes.Structure):
            _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]
        need(ctypes.sizeof(Timebase) == 8 and Timebase.numer.offset == 0 and Timebase.denom.offset == 4,
             "public Mach timebase layout")
        library = ctypes.CDLL(None) if library is None else library
        query = library.mach_timebase_info
        query.argtypes = [ctypes.POINTER(Timebase)]; query.restype = ctypes.c_int
        info = Timebase()
        need(query(ctypes.byref(info)) == 0 and 0 < info.numer <= 1_000_000_000 and
             0 < info.denom <= 1_000_000_000, "public Mach timebase result")
        self.numer, self.denom = info.numer, info.denom
        self.absolute = library.mach_absolute_time
        self.absolute.argtypes = []; self.absolute.restype = ctypes.c_uint64
        self.last_ticks = 0
        self.profile = {"domain": "mach_absolute_time.absolute_seconds.v1", "numer": self.numer, "denom": self.denom}

    def now(self):
        ticks = self.absolute()
        need(type(ticks) is int and 0 < ticks < (1 << 64) and ticks >= self.last_ticks,
             "shared Mach counter regressed/invalid")
        self.last_ticks = ticks
        return ((ticks * self.numer) // self.denom) / 1_000_000_000


def need(condition, message):
    if condition is not True:
        raise Refused(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def sha_word(value):
    need(type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None, "SHA256 shape")
    return value


def clock_value(value):
    need(type(value) in (int, float) and math.isfinite(value) and value >= 0, "monotonic time shape")
    return float(value)


def keys(value, expected):
    need(type(value) is dict and set(value) == set(expected), "fixed object schema")


def source_binding(directory=None):
    directory = Path(__file__).resolve().parent if directory is None else Path(directory)
    return {name: sha((directory / name).read_bytes()) for name in SOURCE_FILES}


def config_checked(config):
    keys(config, ("schema", "operation", "arch", "run_nonce", "profile_sha256", "loaded_hook_profile_sha256",
                  "signed_probe_sha256", "signed_probe_uuid", "signed_probe_cdhash", "installed_probe_token",
                  "boot_private", "UI_private", "source_sha256", "active_seconds", "cleanup_seconds", "candidate_limits", "offline_QA_sha256", "clock_info"))
    need(config["schema"] == "macws.swap-pair.live-config.v7", "config version")
    keys(config["clock_info"], ("domain", "numer", "denom"))
    need(config["clock_info"]["domain"] == "mach_absolute_time.absolute_seconds.v1" and
         all(type(config["clock_info"][key]) is int and 0 < config["clock_info"][key] <= 1_000_000_000
             for key in ("numer", "denom")), "shared native clock domain/timebase")
    need(type(config["operation"]) is str and config["operation"] in OPERATIONS, "fixed run/control operation")
    sha_word(config["offline_QA_sha256"])
    need(type(config["arch"]) is str and config["arch"] in HOOKS, "thin architecture")
    need(type(config["run_nonce"]) is str and re.fullmatch("[0-9a-f]{32}", config["run_nonce"]) is not None, "fresh private run nonce")
    for name in ("profile_sha256", "loaded_hook_profile_sha256", "signed_probe_sha256"):
        sha_word(config[name])
    need(config["loaded_hook_profile_sha256"] == config["profile_sha256"], "v2 complete profile covers loaded hook gates")
    need(config["profile_sha256"] == PROBE_PROFILE_SHA256, "unknown compiled v2 profile")
    need(type(config["signed_probe_uuid"]) is str and re.fullmatch("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", config["signed_probe_uuid"]) is not None, "signed probe UUID")
    need(config["signed_probe_uuid"] == PROBE_BUILDS[config["arch"]][1], "signed probe UUID differs from reviewed thin build")
    need(type(config["signed_probe_cdhash"]) is str and re.fullmatch("[0-9a-f]{40}", config["signed_probe_cdhash"]) is not None, "signed probe CodeDirectory")
    token = config["installed_probe_token"]
    need(type(token) is list and len(token) == 5 and all(type(x) is int and x >= 0 for x in token), "installed probe stat token")
    need(token[1] > 0 and 0 < token[2] <= 2 * 1024 * 1024, "installed probe inode/size")
    need(type(config["boot_private"]) is str and re.fullmatch("[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", config["boot_private"]) is not None, "private boot UUID")
    keys(config["UI_private"], ("SpringBoard", "backboardd"))
    for value in config["UI_private"].values():
        birth_checked(value)
    need(config["UI_private"]["SpringBoard"][0] != config["UI_private"]["backboardd"][0], "unique UI process identities")
    keys(config["source_sha256"], SOURCE_FILES)
    for value in config["source_sha256"].values():
        sha_word(value)
    need(type(config["active_seconds"]) in (int, float) and 0 < clock_value(config["active_seconds"]) <= 10, "active bound <=10 seconds")
    need(type(config["cleanup_seconds"]) in (int, float) and 0 < clock_value(config["cleanup_seconds"]) <= 8, "cleanup bound <=8 seconds")
    limits = config["candidate_limits"]
    keys(limits, ("read_call_limit", "read_byte_limit", "dyld_image_limit", "total_deadline_seconds", "loaded_hook_observations"))
    for name, maximum in (("read_call_limit", 32768), ("read_byte_limit", 4 * 1024 * 1024),
                          ("dyld_image_limit", 1024), ("total_deadline_seconds", 8), ("loaded_hook_observations", 5)):
        need(type(limits[name]) is int and 0 < limits[name] <= maximum, "candidate limit manifest bound")
    need(limits["loaded_hook_observations"] == 5, "five loaded hook gates")
    need(limits == PROBE_LIMITS, "reviewed candidate manifest limits changed")
    return config


def birth_checked(value):
    need(type(value) is list and len(value) == 3 and all(type(x) is int for x in value), "private birth tuple")
    need(value[0] > 1 and value[1] > 0 and 0 <= value[2] < 1_000_000, "private birth fields")
    return value


def stopped_process_witness_checked(value, birth, path):
    """Validate the copied native stop observation, without issuing queries."""
    keys(value, ("path", "birth_private", "stopped", "native_status_private", "native_status_name",
                 "state_source", "raw_bsdinfo_private_hex", "raw_bsdinfo_sha256", "returned_bsdinfo_bytes", "bsdinfo_errno"))
    need(value["path"] == path and value["birth_private"] == birth and value["stopped"] is True and
         type(value["native_status_private"]) is int and value["native_status_private"] == 4 and
         value["native_status_name"] == "SSTOP" and value["state_source"] == "proc_bsdinfo.pbi_status" and
         type(value["returned_bsdinfo_bytes"]) is int and value["returned_bsdinfo_bytes"] == 136 and
         type(value["bsdinfo_errno"]) is int and value["bsdinfo_errno"] == 0, "copied native stopped state")
    raw_hex = value["raw_bsdinfo_private_hex"]
    need(type(raw_hex) is str and re.fullmatch("[0-9a-f]{272}", raw_hex) is not None, "exact copied BSD-info hex")
    raw = bytes.fromhex(raw_hex)
    need(sha(raw) == value["raw_bsdinfo_sha256"] and struct.unpack_from("<I", raw, 4)[0] == 4 and
         struct.unpack_from("<I", raw, 12)[0] == birth[0] and list(struct.unpack_from("<QQ", raw, 120)) == birth[1:],
         "raw native stop/birth evidence differs")
    return value


def executable(config):
    return "/usr/local/libexec/macws-swap-pair-probe-20261017/probe." + config["arch"]


def arguments(config):
    return [WRAPPER, "0", "0", ROOTFS, executable(config), "--one-pair", "--profile-sha256", config["profile_sha256"]]


def config_sha(config):
    return sha(json.dumps(config, sort_keys=True, separators=(",", ":")).encode())


def validate_prerequisites(config, receipts, *, now, current_sources):
    """Source/freshness validation, not authentication of arbitrary JSON claims.

    Caller must preserve the copied original receipt bytes. Active-pair
    admission requires three actual stopped-job controls from the collector.
    Fake QA stays explicitly offline; arbitrary self-reported JSON is not
    authenticated merely by passing structural validation.
    """
    config_checked(config)
    need(config["source_sha256"] == current_sources, "current controller/watchdog/backend sources changed")
    keys(receipts, ("schema", "preflight", "signed_artifact", "loaded_hook_profile", "offline_QA", "native_controls"))
    need(receipts["schema"] == "macws.swap-pair.live-prerequisites.v7", "receipt version")
    now = clock_value(now)
    common = {"schema", "run_nonce", "admission_sha256", "source_sha256", "boot_private", "observed_monotonic", "raw_sha256", "evidence_kind", "clock_info"}
    schemas = {"preflight": ("macws.swap-pair.native-preflight.v1", {"UI_private", "thermal", "label_absent", "scratch_absent"}),
               "signed_artifact": ("macws.swap-pair.installed-signed-artifact.v1", {"path", "sha256", "uuid", "cdhash", "stat_token", "new_vnode", "trust_member", "source_profile_sha256",
                                                                                         "unsigned_sha256", "probe_source_sha256", "build_receipt_sha256"}),
               "loaded_hook_profile": ("macws.swap-pair.loaded-hook-profile-preparation.v1", {"profile_sha256", "architecture", "hook_path", "hook_sha256"})}
    for name, (schema, extra) in schemas.items():
        item = receipts[name]
        keys(item, common | extra)
        need(item["schema"] == schema and item["evidence_kind"] == "copied-native-runtime", "fake or unknown prerequisite evidence")
        need(item["run_nonce"] == config["run_nonce"] and item["admission_sha256"] == admission_sha(config), "another admission-session receipt")
        need(item["source_sha256"] == current_sources and item["boot_private"] == config["boot_private"], "receipt source/boot mismatch")
        need(item["clock_info"] == config["clock_info"], "receipt shared-clock domain differs")
        observed = clock_value(item["observed_monotonic"])
        need(0 <= now - observed <= 300, "stale/future receipt")
        sha_word(item["raw_sha256"])
    pre = receipts["preflight"]
    need(pre["UI_private"] == config["UI_private"] and pre["thermal"] == "nominal" and pre["label_absent"] is True and pre["scratch_absent"] is True, "preflight baseline/exclusivity")
    artifact = receipts["signed_artifact"]
    need(artifact["path"] == executable(config) and artifact["sha256"] == config["signed_probe_sha256"] and
         artifact["uuid"] == config["signed_probe_uuid"] and artifact["cdhash"] == config["signed_probe_cdhash"] and
         artifact["stat_token"] == config["installed_probe_token"] and artifact["new_vnode"] is True and artifact["trust_member"] is True and
         artifact["source_profile_sha256"] == config["profile_sha256"] and artifact["unsigned_sha256"] == PROBE_BUILDS[config["arch"]][0] and
         artifact["probe_source_sha256"] == PROBE_SOURCE_SHA256 and artifact["build_receipt_sha256"] == PROBE_BUILD_RECEIPT_SHA256,
         "exact reviewed source/build and signed installed artifact")
    hook = receipts["loaded_hook_profile"]
    need(hook["profile_sha256"] == config["loaded_hook_profile_sha256"] and hook["architecture"] == config["arch"] and
         (hook["hook_path"], hook["hook_sha256"]) == HOOKS[config["arch"]], "loaded hook preparation binding")
    offline = receipts["offline_QA"]
    keys(offline, ("receipt", "raw_sha256"))
    qa = offline["receipt"]
    need(type(qa) is dict and qa.get("schema") == "macws.swap-pair.live-controller-offline-QA.v7" and
         qa.get("accepted_offline_controls") is True and qa.get("simulation_only") is True and
         qa.get("genuine_native_watchdog_controls") is False and qa.get("device_commands") == 0 and
         qa.get("exit") == 0 and qa.get("runtime_source_sha256") == current_sources,
         "source-bound offline fake QA absent or mislabeled")
    need(offline["raw_sha256"] == config["offline_QA_sha256"] == config_sha(qa), "exact canonical offline QA receipt SHA")
    need(type(qa.get("retained_v1_guard_tests")) is int and qa["retained_v1_guard_tests"] >= 31, "retained offline guard tests")
    need(type(qa.get("retained_v2_guard_tests")) is int and qa["retained_v2_guard_tests"] >= 44, "retained v2 offline guard tests")
    if config["operation"] != "run":
        need(receipts["native_controls"] == {}, "control collection does not consume old/native admission receipts")
        return True
    keys(receipts["native_controls"], REQUIRED_CONTROLS)
    expected_triggers = {"normal_ready_stop": "controller_done", "parent_pipe_EOF": "parent_loss_or_invalid_control", "active_deadline": "active_deadline"}
    for name, item in receipts["native_controls"].items():
        keys(item, ("schema", "control", "operation", "accepted", "raw_sha256", "raw_witness", "native_job_used", "simulation_only",
                    "source_sha256", "admission_sha256", "run_nonce", "boot_private", "observed_monotonic", "first_resumes", "second_resumes",
                    "C_ready_verified", "cleanup_verified", "trigger"))
        need(item["schema"] == "macws.swap-pair.native-stopped-control.v7" and item["control"] == name and
             item["operation"] == CONTROL_OPERATIONS[name] and item["accepted"] is True and
             item["native_job_used"] is True and item["simulation_only"] is False, "three actual stopped-probe controls required")
        need(item["source_sha256"] == current_sources and item["admission_sha256"] == admission_sha(config) and
             item["run_nonce"] == config["run_nonce"] and item["boot_private"] == config["boot_private"], "native control source/session binding")
        observed = clock_value(item["observed_monotonic"])
        need(0 <= now - observed <= 300, "native control stale/future")
        need(type(item["first_resumes"]) is int and item["first_resumes"] == 1 and type(item["second_resumes"]) is int and
             item["second_resumes"] == 0 and item["C_ready_verified"] is True and item["cleanup_verified"] is True and
             item["trigger"] == expected_triggers[name], "native stopped-control protocol/cleanup result")
        need(type(item["raw_witness"]) is dict and item["raw_sha256"] == config_sha(item["raw_witness"]), "copied actual native control witness digest")
        witness = item["raw_witness"]
        keys(witness, ("schema", "operation", "source_sha256", "full_private_report_sha256", "independent_watchdog_ready_before_bootstrap",
                       "control_capture_accepted", "pair_capture_accepted", "device_acceptance", "cleanup_verified", "run", "watchdog", "final_C_result_observed"))
        sha_word(witness["full_private_report_sha256"])
        need(witness["schema"] == "macws.swap-pair.stopped-control-witness.v7" and witness["operation"] == item["operation"] and
             witness["source_sha256"] == current_sources and witness["independent_watchdog_ready_before_bootstrap"] is True and
             witness["control_capture_accepted"] is True and witness["pair_capture_accepted"] is False and
             witness["device_acceptance"] is False and witness["cleanup_verified"] is True and witness["final_C_result_observed"] is False,
             "actual control projection contradicts admission")
        run = witness["run"]; watch = witness["watchdog"]
        keys(run, ("bootstraps", "resumes", "second_resumes", "C_ready_verified", "C_ready_private", "birth_private",
                   "initial_process_private", "C_ready_process_private"))
        need(type(run["bootstraps"]) is int and run["bootstraps"] == 1 and type(run["resumes"]) is int and run["resumes"] == 1 and
             type(run["second_resumes"]) is int and run["second_resumes"] == 0 and run["C_ready_verified"] is True,
             "copied control executed a second resume or lacks ready stop")
        birth_checked(run["birth_private"])
        for phase in ("initial_process_private", "C_ready_process_private"):
            stopped_process_witness_checked(run[phase], run["birth_private"], ROOTFS + executable(config))
        ready = run["C_ready_private"]
        keys(ready, ("schema", "phase", "profile_sha256", "loaded_hook_profile_architecture", "loaded_hook_profile_uuid",
                     "hook_uuid_code_gates_passed", "pair_invoked", "runtime_accepted"))
        expected_hook_uuid = "2552c7f2-0946-3525-9771-d6d48b44c0e9" if config["arch"] == "arm64" else "8d9d059f-f308-3a07-be9e-bb23123ba997"
        need(ready["schema"] == "macws.own-swap-pair.ready.v2" and ready["phase"] == "before_GetMainDisplay" and
             ready["profile_sha256"] == config["profile_sha256"] and ready["loaded_hook_profile_architecture"] == config["arch"] and
             ready["loaded_hook_profile_uuid"] == expected_hook_uuid and ready["hook_uuid_code_gates_passed"] is True and
             ready["pair_invoked"] is False and ready["runtime_accepted"] is False, "copied exact C control ready phase")
        keys(watch, ("ready", "trigger", "cleanup_verified", "cleanup", "samples", "seconds", "active_alarm_fired", "deadline_mechanism"))
        need(watch["ready"] is True and watch["trigger"] == expected_triggers[name] and watch["cleanup_verified"] is True and
             type(watch["samples"]) is int and watch["samples"] >= 0 and 0 <= clock_value(watch["seconds"]) <= 18,
             "copied watchdog result/deadline")
        need(type(watch["active_alarm_fired"]) is bool, "typed active alarm observation")
        if name == "active_deadline":
            need(watch["seconds"] >= config["active_seconds"] and
                 ((watch["active_alarm_fired"] is True and watch["deadline_mechanism"] == "SIGALRM") or
                  (watch["active_alarm_fired"] is False and watch["deadline_mechanism"] == "monotonic_deadline")),
                 "actual independent active-deadline witness")
        else:
            need(watch["active_alarm_fired"] is False and watch["deadline_mechanism"] is None, "normal/EOF control substituted deadline")
        need(type(watch["cleanup"]) is dict and watch["cleanup"].get("own_job_absent") is True and
             type(watch["cleanup"].get("bootout_calls")) is int and watch["cleanup"]["bootout_calls"] in (0, 1),
             "copied exact job cleanup result")
        need(watch["cleanup"].get("known_generation_absent") is True, "copied known owned generation absence")
        absence = watch["cleanup"].get("generation_absence_evidence_private")
        keys(absence, ("api", "flavor", "requested_bytes", "returned", "errno", "outcome", "pid_private", "expected_birth_private"))
        need(absence["api"] == "proc_pidinfo" and type(absence["flavor"]) is int and absence["flavor"] == 3 and
             type(absence["requested_bytes"]) is int and absence["requested_bytes"] == 136 and
             type(absence["returned"]) is int and absence["returned"] == 0 and type(absence["errno"]) is int and absence["errno"] == errno.ESRCH and
             absence["outcome"] == "ESRCH" and absence["expected_birth_private"] == run["birth_private"] and
             type(absence["pid_private"]) is int and absence["pid_private"] == run["birth_private"][0],
             "copied exact known-generation ESRCH witness")
    return True


def stat_token(value):
    return [value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def read_regular(path, limit):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit, "bounded regular file")
        raw = os.read(fd, limit + 1)
        need(len(raw) == before.st_size and len(raw) <= limit, "complete bounded file")
        after = os.fstat(fd)
        need(stat_token(before) == stat_token(after) == stat_token(path.lstat()), "file changed during read")
        return raw, stat_token(before)
    finally:
        os.close(fd)


class RealBackend:
    """Actual local-device operations, instantiated only after prerequisite gates."""
    def __init__(self, config, clock=None):
        self.config = config_checked(config)
        self.clock = NativeSharedClock() if clock is None else clock
        need(self.clock.profile == self.config["clock_info"], "actual native clock differs from admission")
        self.proc = None

    def now(self):
        return self.clock.now()

    def pause(self, seconds):
        time.sleep(min(.02, seconds))

    def command(self, argv, deadline):
        remaining = deadline - self.now()
        need(remaining > 0, "command deadline")
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(1, remaining))
        need(len(result.stdout) <= 256 * 1024 and len(result.stderr) <= 16 * 1024, "command output bound")
        return result.returncode, result.stdout.decode("utf-8", "strict"), result.stderr.decode("utf-8", "strict")

    def metadata(self, name):
        library = ctypes.CDLL(None)
        query = library.sysctlbyname
        query.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
        query.restype = ctypes.c_int
        raw = ctypes.create_string_buffer(128); length = ctypes.c_size_t(128)
        need(query(name.encode("ascii"), raw, ctypes.byref(length), None, 0) == 0 and 0 < length.value < 128, "metadata query")
        return bytes(raw)[:length.value].rstrip(b"\0").decode("ascii")

    def process(self, pid, deadline):
        need(type(pid) is int and pid > 1, "PID shape")
        if self.proc is None:
            self.proc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        path_query = self.proc.proc_pidpath
        path_query.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        path_query.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(4096)
        length = path_query(pid, buffer, len(buffer))
        need(0 < length < len(buffer), "process path query")
        path = buffer.value.decode("utf-8", "strict")
        query = self.proc.proc_pidinfo
        query.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        query.restype = ctypes.c_int
        raw = ctypes.create_string_buffer(136)
        ctypes.set_errno(0)
        returned = query(pid, 3, 0, raw, len(raw))
        need(returned == 136 and ctypes.get_errno() == 0, "exact proc_bsdinfo birth metadata")
        data = bytes(raw)
        need(struct.unpack_from("<I", data, 12)[0] == pid, "birth metadata PID")
        seconds, micros = struct.unpack_from("<QQ", data, 120)
        birth = birth_checked([pid, seconds, micros])
        # Public proc_bsdinfo.pbi_status is copied from the SAME complete block
        # as PID/birth. This port's ps emitted '?s'; it cannot establish state.
        # SDK layout/constants are compiled for both architectures. Native
        # status 2 is copied on this build; actual stop4 still needs a control.
        native_status = struct.unpack_from("<I", data, 4)[0]
        need(native_status in (2, 3, 4), "unknown/creating/zombie native process state")
        return {"path": path, "birth_private": birth, "stopped": native_status == 4,
                "native_status_private": native_status,
                "native_status_name": {2: "SRUN", 3: "SSLEEP", 4: "SSTOP"}[native_status],
                "state_source": "proc_bsdinfo.pbi_status", "raw_bsdinfo_private_hex": data.hex(),
                "raw_bsdinfo_sha256": sha(data), "returned_bsdinfo_bytes": returned, "bsdinfo_errno": 0}

    def generation_absent(self, birth, deadline):
        """Known PID/start tuple, including wrapper; ESRCH alone proves absence.

        An alive matching tuple or a reused PID never authorizes a signal after
        launchd job absence. Unexpected libproc results remain uncertain.
        """
        birth_checked(birth)
        need(self.now() < deadline, "known-generation absence deadline")
        if self.proc is None:
            self.proc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        query = self.proc.proc_pidinfo
        query.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
        query.restype = ctypes.c_int
        raw = ctypes.create_string_buffer(136)
        ctypes.set_errno(0)
        returned = query(birth[0], 3, 0, raw, len(raw))
        error = ctypes.get_errno()
        self.last_generation_query = {"api": "proc_pidinfo", "flavor": 3, "requested_bytes": 136,
                                      "returned": returned, "errno": error, "pid_private": birth[0],
                                      "expected_birth_private": birth.copy(), "outcome": "uncertain"}
        need(self.now() < deadline, "known-generation absence result deadline")
        if returned == 0 and error == errno.ESRCH:
            self.last_generation_query["outcome"] = "ESRCH"
            return True
        need(returned == 136 and error == 0, "known-generation query failed without ESRCH")
        data = bytes(raw)
        need(struct.unpack_from("<I", data, 12)[0] == birth[0], "known-generation metadata PID")
        seconds, micros = struct.unpack_from("<QQ", data, 120)
        observed = birth_checked([birth[0], seconds, micros])
        self.last_generation_query["observed_birth_private"] = observed
        need(observed == birth, "known PID reused; preserve replacement and refuse cleanup")
        self.last_generation_query["outcome"] = "same_generation_alive"
        return False

    def UI(self, deadline):
        result = self.command(["/bin/ps", "-eo", "pid,comm"], deadline)
        need(result[0] == 0 and not result[2], "UI process list")
        ui = {}
        for line in result[1].splitlines()[1:]:
            fields = line.split()
            if len(fields) != 2:
                continue
            name = fields[1].rsplit("/", 1)[-1]
            if name in ("SpringBoard", "backboardd"):
                need(name not in ui, "duplicate UI process")
                ui[name] = self.process(int(fields[0]), deadline)["birth_private"]
        need(set(ui) == {"SpringBoard", "backboardd"}, "both UI processes present")
        return ui

    def thermal(self):
        ctypes.CDLL("/System/Library/Frameworks/Foundation.framework/Foundation", mode=ctypes.RTLD_GLOBAL)
        objc = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
        objc.objc_getClass.argtypes = [ctypes.c_char_p]; objc.objc_getClass.restype = ctypes.c_void_p
        objc.sel_registerName.argtypes = [ctypes.c_char_p]; objc.sel_registerName.restype = ctypes.c_void_p
        klass = objc.objc_getClass(b"NSProcessInfo")
        proc_sel = objc.sel_registerName(b"processInfo"); thermal_sel = objc.sel_registerName(b"thermalState")
        need(bool(klass and proc_sel and thermal_sel), "public thermal selectors")
        for name in ("class_getClassMethod", "class_getInstanceMethod"):
            func = getattr(objc, name); func.argtypes = [ctypes.c_void_p, ctypes.c_void_p]; func.restype = ctypes.c_void_p
        objc.method_getNumberOfArguments.argtypes = [ctypes.c_void_p]; objc.method_getNumberOfArguments.restype = ctypes.c_uint
        objc.method_getTypeEncoding.argtypes = [ctypes.c_void_p]; objc.method_getTypeEncoding.restype = ctypes.c_char_p
        for method, encoding in ((objc.class_getClassMethod(klass, proc_sel), "@@:"),
                                 (objc.class_getInstanceMethod(klass, thermal_sel), "q@:")):
            need(bool(method) and objc.method_getNumberOfArguments(method) == 2, "public thermal method ABI")
            raw = objc.method_getTypeEncoding(method)
            need(bool(raw) and len(raw) < 80 and re.sub("[0-9]", "", raw.decode("ascii")) == encoding, "public thermal encoding")
        entry = ctypes.cast(objc.objc_msgSend, ctypes.c_void_p).value
        obj_msg = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p)(entry)
        int_msg = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p)(entry)
        process_info = obj_msg(klass, proc_sel)
        need(bool(process_info) and ctypes.sizeof(ctypes.c_long) == 8, "public thermal object ABI")
        value = int_msg(process_info, thermal_sel)
        need(value in (0, 1, 2, 3), "thermal value")
        return value

    def health(self, deadline, initial=False):
        need(self.metadata("hw.machine") == "iPad13,6" and self.metadata("kern.osversion") == "20E252" and
             self.metadata("kern.uuid").lower() == "d6b9e234-64f1-30ea-ae62-ed8f2dc6efdb", "unverified/changed device build")
        need(self.metadata("kern.bootsessionuuid") == self.config["boot_private"], "boot changed")
        need(self.UI(deadline) == self.config["UI_private"], "UI generation changed")
        value = self.thermal()
        need(value == 0 if initial else value <= 1, "thermal stop")

    def job(self, deadline):
        result = self.command([LAUNCHCTL, "print", service_identifier(self.config)], deadline)
        return parsed_job(self.config, result)

    def other_label_absent(self, deadline):
        other_config = dict(self.config, operation="control_normal" if self.config["operation"] == "run" else "run")
        result = self.command([LAUNCHCTL, "print", service_identifier(other_config)], deadline)
        return parsed_job(other_config, result) is None

    def installed(self, deadline):
        probe = ROOTFS + executable(self.config)
        raw, token = read_regular(probe, 2 * 1024 * 1024)
        need(token == self.config["installed_probe_token"] and sha(raw) == self.config["signed_probe_sha256"], "installed probe content/token changed")
        need(len(raw) >= 32 and struct.unpack_from("<I", raw)[0] == 0xfeedfacf, "thin signed Mach-O")
        cpu, subtype, filetype, count, size = struct.unpack_from("<IIIII", raw, 4)
        need(cpu == 0x100000c and (subtype & 0xff) == (0 if self.config["arch"] == "arm64" else 2) and
             filetype == 2 and 0 < count <= 1024 and 0 < size <= 65536 and size <= len(raw) - 32,
             "probe architecture/type/command bound")
        at = 32; uuids = []
        for _ in range(count):
            need(at + 8 <= 32 + size, "load-command bounds")
            cmd, length = struct.unpack_from("<II", raw, at)
            need(length >= 8 and length % 8 == 0 and at + length <= 32 + size, "load-command size")
            if cmd == 0x1b:
                need(length == 24, "UUID command extent")
                value = raw[at + 8:at + 24].hex()
                uuids.append(value[:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:])
            at += length
        need(at == 32 + size and uuids == [self.config["signed_probe_uuid"]], "probe UUID")
        for path, expected in ((WRAPPER, WRAPPER_SHA256), (ROOTFS + HOOKS[self.config["arch"]][0], HOOKS[self.config["arch"]][1])):
            content, _ = read_regular(path, 4 * 1024 * 1024)
            need(sha(content) == expected, "frozen wrapper/hook content changed")
        result = self.command([JBCTL, "trustcache", "info"], deadline)
        need(result[0] == 0 and not result[2], "trust membership query")
        hashes = set(x.lower() for x in re.findall(r"^\|\s*\d+:\s*([0-9A-Fa-f]{40})\s*$", result[1], re.M))
        need(self.config["signed_probe_cdhash"] in hashes, "signed probe CDHash not currently trusted")

    def bind(self, deadline, birth=None, stopped=False, allow_wrapper=False):
        state = self.job(deadline)
        need(state is not None and state["pid"] is not None, "owned target PID unavailable")
        current = self.process(state["pid"], deadline)
        expected = ROOTFS + executable(self.config)
        if allow_wrapper and current["path"] == WRAPPER:
            content, _ = read_regular(WRAPPER, 2 * 1024 * 1024)
            need(sha(content) == WRAPPER_SHA256, "own startup wrapper changed")
        else:
            need(current["path"] == expected and os.path.samefile(current["path"], expected), "exact target path/inode")
            need(stat_token(Path(expected).stat()) == self.config["installed_probe_token"], "target executable stat changed")
        if birth is not None:
            need(current["birth_private"] == birth, "owned target process generation changed")
        if stopped:
            need(current["stopped"] is True, "owned target is not stopped")
        return current["birth_private"]

    def no_candidate_process(self, deadline):
        result = self.command(["/bin/ps", "-eo", "pid,comm"], deadline)
        need(result[0] == 0 and not result[2], "final process inventory")
        for line in result[1].splitlines()[1:]:
            fields = line.split()
            if len(fields) == 2 and fields[1].rsplit("/", 1)[-1] in ("probe.arm64", "probe.arm64e"):
                return False
        return True

    def debug_admit(self, birth, deadline):
        self.bind(deadline, birth, stopped=True)
        result = self.command([JBCTL, "proc_set_debugged", str(birth[0])], deadline)
        need(result[0] == 0 and not result[2], "owned target debug admission")

    def resume(self, birth, deadline):
        self.bind(deadline, birth, stopped=True)
        os.kill(birth[0], signal.SIGCONT)


def plist_bytes(config):
    return plistlib.dumps({"Label": job_label(config), "ProgramArguments": arguments(config), "RunAtLoad": False,
                          "KeepAlive": False, "POSIXSpawnType": "Interactive",
                          "StandardOutPath": scratch_path(config) + "/probe.log", "StandardErrorPath": scratch_path(config) + "/probe.log",
                          "EnvironmentVariables": {"MACWS_SUSPEND_AT_EXEC": "1", "MACWS_SUSPEND_TARGET": "probe." + config["arch"],
                                                   "MACWS_AGX_NATIVE": "1", "MACWS_AGX_REGISTER_CLASSES": "1",
                                                   "DYLD_SHARED_CACHE_DIR": "/System/Cryptexes/OS/System/Library/dyld",
                                                   "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}}, sort_keys=True)


class OwnedFiles:
    """Directory-FD ownership; never follows a replacement directory or file."""
    def __init__(self, directory_fd, directory_token, files, scratch):
        need(type(directory_fd) is int and directory_fd >= 3, "owned directory descriptor")
        need(type(directory_token) is list and len(directory_token) == 2 and all(type(x) is int and x >= 0 for x in directory_token), "owned directory token")
        keys(files, ("job.plist", "probe.log"))
        for name, item in files.items():
            keys(item, ("identity", "sha256"))
            need(type(item["identity"]) is list and len(item["identity"]) == 2 and all(type(x) is int and x >= 0 for x in item["identity"]), "owned file token")
            if name == "job.plist":
                sha_word(item["sha256"])
            else:
                need(item["sha256"] is None, "log hash is not immutable")
        self.fd = directory_fd; self.directory_token = directory_token; self.files = files
        need(scratch in (SCRATCH, CONTROL_SCRATCH), "fixed run/control scratch")
        self.path = scratch

    @classmethod
    def create(cls, config):
        scratch = scratch_path(config)
        need(not os.path.lexists(scratch), "own scratch already exists")
        os.mkdir(scratch, 0o700)
        fd = os.open(scratch, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        token = stat_token(os.fstat(fd))[:2]
        files = {}
        try:
            for name, raw in (("job.plist", plist_bytes(config)), ("probe.log", b"")):
                owned = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                try:
                    need(os.write(owned, raw) == len(raw), "complete owned file write")
                    info = os.fstat(owned)
                    files[name] = {"identity": [info.st_dev, info.st_ino], "sha256": sha(raw) if name == "job.plist" else None}
                finally:
                    os.close(owned)
            return cls(fd, token, files, scratch)
        except BaseException:
            os.close(fd)
            # Partial creation is not silently deleted without full ownership proof.
            raise

    def checked(self, check_log_size=True):
        need(stat_token(os.fstat(self.fd))[:2] == self.directory_token and
             stat_token(os.lstat(self.path))[:2] == self.directory_token and not stat.S_ISLNK(os.lstat(self.path).st_mode), "owned directory substituted")
        need(set(os.listdir(self.fd)) == set(self.files), "owned directory entries changed")
        for name, item in self.files.items():
            info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            need(stat.S_ISREG(info.st_mode) and [info.st_dev, info.st_ino] == item["identity"], "owned file substituted")
            if item["sha256"] is not None:
                raw, token = read_regular(self.path + "/" + name, 65536)
                need(sha(raw) == item["sha256"] and token[:2] == item["identity"], "immutable own plist changed")
            elif check_log_size:
                need(info.st_size <= 256 * 1024, "owned log exceeded bound")
        return True

    def log(self):
        self.checked(check_log_size=False)
        raw, _ = read_regular(self.path + "/probe.log", 256 * 1024)
        return raw

    def cleanup_files(self, backend, deadline):
        need(backend.job(deadline) is None, "job not absent before owned file cleanup")
        self.checked(check_log_size=False)
        for name in ("job.plist", "probe.log"):
            # Directory FD remains held; verify the exact inode again before unlink.
            info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            need([info.st_dev, info.st_ino] == self.files[name]["identity"] and stat.S_ISREG(info.st_mode), "file substituted before unlink")
            os.unlink(name, dir_fd=self.fd)
        need(os.listdir(self.fd) == [] and stat_token(os.lstat(self.path))[:2] == self.directory_token, "own directory changed before rmdir")
        os.rmdir(self.path)


def stop_owned(backend, files, config, deadline, birth=None):
    """Stop only our exact job. PID/name-wide kill is intentionally absent."""
    files.checked(check_log_size=False)
    need(backend.metadata("kern.bootsessionuuid") == config["boot_private"], "boot changed before cleanup")
    state = backend.job(deadline)
    def absence_result(**result):
        if birth is None:
            result["known_generation_absent"] = None
        else:
            queries = 0
            while backend.now() < deadline:
                queries += 1
                if backend.generation_absent(birth, deadline) is True:
                    result["known_generation_absent"] = True
                    result["generation_absence_evidence_private"] = dict(backend.last_generation_query)
                    result["known_generation_absence_queries"] = queries
                    return result
                # Launchd may remove its job before the exact old process is
                # reaped. Wait only within the original cleanup deadline.
                backend.pause(min(.02, max(0, deadline - backend.now())))
            raise TimeoutError("known owned generation remains alive at cleanup deadline")
        return result
    if state is None:
        return absence_result(own_job_absent=True, bootout_calls=0)
    if state["pid"] is not None:
        current = backend.bind(deadline, birth, allow_wrapper=True)
        if birth is not None:
            need(current == birth, "cleanup PID reuse")
        else:
            birth = current
    owned_kills = 0
    if state["pid"] is not None:
        # A SIGSTOP-held owned job must never resume merely to receive SIGTERM.
        # Signal the exact verified launchd job, not a bare/reusable PID.
        killed = backend.command([LAUNCHCTL, "kill", "SIGKILL", service_identifier(config)], deadline)
        launchctl_success(killed, "exact owned job termination")
        owned_kills = 1
    result = backend.command([LAUNCHCTL, "bootout", service_identifier(config)], deadline)
    launchctl_success(result, "exact owned job bootout")
    while backend.now() < deadline:
        state = backend.job(deadline)
        if state is None:
            return absence_result(own_job_absent=True, bootout_calls=1, bootout_exit=result[0], owned_job_kill_calls=owned_kills)
        if state["pid"] is not None:
            backend.bind(deadline, birth, allow_wrapper=True)
        backend.pause(.02)
    raise TimeoutError("exact owned job cleanup deadline")
