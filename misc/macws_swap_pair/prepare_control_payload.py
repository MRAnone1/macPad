"""Offline-only v7 one-control payload preparation. No transport is provided.

No inputs or receipt timestamps are invented, refreshed, or rewritten. Host
checks establish structure and source binding only. Native execute() must
evaluate supplied receipt ages against a live NativeSharedClock before jobs.
"""
from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import traceback
import types

DIRECTORY = "/var/jb/usr/libexec/macws-swap-pair-controller-20261018"
SOURCES = {
    "runtime_support.py": "5d09cf9380afaa2409661a58909d1bfee41d81943f1b2306facb0cd94ee10fe0",
    "watchdog.py": "c28ec9edd30bf86613c7cb29693697901228b579100b8b181a4dc47915f00e0a",
    "controller.py": "955c50b5cb2b30b8f0aefd69720675d04c91126dec17c802fb09be8c42197977",
}
QA_SHA256 = "ebee0b881b5f589c4ca100c5dbcd4c72faa946b0bf741511a7396138139ae29c"
CONTROLS = {"normal_ready_stop": "control_normal", "parent_pipe_EOF": "control_parent_EOF", "active_deadline": "control_deadline"}
MAX_INPUT_BYTES = 65536
MAX_SOURCE_BYTES = 256 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_STDOUT_BYTES = 4 * 1024 * 1024
MAX_STDERR_BYTES = 16384


def metadata():
    return {"schema": "macws.swap-pair.call-preparation.v7", "source_sha256": dict(SOURCES),
            "offline_QA_sha256": QA_SHA256, "controls": list(CONTROLS),
            "transport_provided": False, "device_commands": 0, "device_acceptance": False,
            "fresh_device_state_asserted": False, "receipt_freshness_checked": False,
            "current_device_freshness_claimed": False,
            "active_pair_payload_supported": False}


def strict_json(raw, limit=MAX_INPUT_BYTES):
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise ValueError("explicit bounded JSON bytes required")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("finite JSON numbers required")
    def finite_float(word):
        value = float(word)
        if not math.isfinite(value):
            raise ValueError("finite JSON numbers required")
        return value
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite_float)
    except RecursionError as error:
        raise ValueError("JSON nesting exceeded parser bound") from error
    if type(value) is not dict:
        raise ValueError("JSON object required")
    return value


def bounded_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= limit:
            raise ValueError("bounded regular single-link file required")
        raw = bytearray()
        while len(raw) <= before.st_size:
            part = os.read(fd, min(65536, before.st_size + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or any(getattr(before, k) != getattr(after, k) for k in fields):
            raise ValueError("file changed during bounded read")
        return bytes(raw)
    finally:
        os.close(fd)


def tokens_checked(tokens, blobs):
    if type(tokens) is not dict or set(tokens) != set(SOURCES):
        raise ValueError("all fixed explicit source tokens required")
    for name, token in tokens.items():
        if (type(token) is not dict or set(token) != {"dev", "ino", "size", "mtime_ns", "ctime_ns"} or
                not all(type(v) is int and v >= 0 for v in token.values()) or token["ino"] <= 0 or
                token["size"] != len(blobs[name])):
            raise ValueError("explicit source delivery stat token")


def pinned_support(*, source_directory, qa_path, tokens):
    """Load only exact frozen own source; imports construct no native backend."""
    if source_directory is None or qa_path is None:
        raise ValueError("explicit source directory and canonical QA path required")
    source_directory = Path(source_directory)
    qa_path = Path(qa_path)
    blobs = {}
    for name, expected in SOURCES.items():
        raw = bounded_regular(source_directory / name, 128 * 1024)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("frozen v7 source mismatch: " + name)
        blobs[name] = raw
    qa = bounded_regular(qa_path, MAX_INPUT_BYTES)
    if hashlib.sha256(qa).hexdigest() != QA_SHA256:
        raise ValueError("frozen v7 QA mismatch")
    # Reject malformed delivery inputs before executing even own module code.
    tokens_checked(tokens, blobs)
    support = types.ModuleType("_offline_pinned_v7_support")
    support.__file__ = str(source_directory / "runtime_support.py")
    exec(compile(blobs["runtime_support.py"], support.__file__, "exec"), support.__dict__)
    return support, blobs


def structural_inputs(config, receipts, tokens, support, blobs):
    """Check immutable bindings without reading any clock or evaluating age.

    This deliberately does not call validate_prerequisites(now=<old receipt>)
    or fabricate current time. Real execution repeats all validation with the
    live native clock; arbitrary JSON is not authenticated by this checker.
    """
    s = support
    s.config_checked(config)
    s.need(config["operation"] == "run" and config["source_sha256"] == SOURCES, "explicit v7 run-admission config required")
    s.keys(receipts, ("schema", "preflight", "signed_artifact", "loaded_hook_profile", "offline_QA", "native_controls"))
    s.need(receipts["schema"] == "macws.swap-pair.live-prerequisites.v7" and receipts["native_controls"] == {},
           "v7 control preparation refuses old control admission")
    common = {"schema", "run_nonce", "admission_sha256", "source_sha256", "boot_private", "observed_monotonic", "raw_sha256", "evidence_kind", "clock_info"}
    sections = {
        "preflight": ("macws.swap-pair.native-preflight.v1", {"UI_private", "thermal", "label_absent", "scratch_absent"}),
        "signed_artifact": ("macws.swap-pair.installed-signed-artifact.v1", {"path", "sha256", "uuid", "cdhash", "stat_token", "new_vnode", "trust_member", "source_profile_sha256", "unsigned_sha256", "probe_source_sha256", "build_receipt_sha256"}),
        "loaded_hook_profile": ("macws.swap-pair.loaded-hook-profile-preparation.v1", {"profile_sha256", "architecture", "hook_path", "hook_sha256"}),
    }
    for name, (schema, extra) in sections.items():
        item = receipts[name]
        s.keys(item, common | extra)
        s.need(item["schema"] == schema and item["evidence_kind"] == "copied-native-runtime", "explicit native receipt structure required")
        s.need(item["source_sha256"] == SOURCES and item["run_nonce"] == config["run_nonce"] and
               item["admission_sha256"] == s.admission_sha(config) and item["boot_private"] == config["boot_private"] and
               item["clock_info"] == config["clock_info"], "receipt admission/source/clock binding")
        s.clock_value(item["observed_monotonic"])
        s.sha_word(item["raw_sha256"])
    pre = receipts["preflight"]
    s.need(pre["UI_private"] == config["UI_private"] and pre["thermal"] == "nominal" and
           pre["label_absent"] is True and pre["scratch_absent"] is True, "preflight shape/bindings")
    artifact = receipts["signed_artifact"]
    expected_artifact = {"path": s.executable(config), "sha256": config["signed_probe_sha256"], "uuid": config["signed_probe_uuid"],
                         "cdhash": config["signed_probe_cdhash"], "stat_token": config["installed_probe_token"],
                         "new_vnode": True, "trust_member": True, "source_profile_sha256": config["profile_sha256"],
                         "unsigned_sha256": s.PROBE_BUILDS[config["arch"]][0], "probe_source_sha256": s.PROBE_SOURCE_SHA256,
                         "build_receipt_sha256": s.PROBE_BUILD_RECEIPT_SHA256}
    s.need(all(artifact[k] == v for k, v in expected_artifact.items()) and artifact["new_vnode"] is True and artifact["trust_member"] is True,
           "artifact source/build/stat bindings")
    hook = receipts["loaded_hook_profile"]
    s.need(hook["profile_sha256"] == config["loaded_hook_profile_sha256"] and hook["architecture"] == config["arch"] and
           (hook["hook_path"], hook["hook_sha256"]) == s.HOOKS[config["arch"]], "hook profile bindings")
    offline = receipts["offline_QA"]
    s.keys(offline, ("receipt", "raw_sha256"))
    s.need(offline["raw_sha256"] == config["offline_QA_sha256"] == QA_SHA256 == s.config_sha(offline["receipt"]), "exact fixed v7 offline QA receipt")
    s.need(offline["receipt"]["schema"] == "macws.swap-pair.live-controller-offline-QA.v7" and
           offline["receipt"]["runtime_source_sha256"] == SOURCES, "v7 QA source/schema")
    tokens_checked(tokens, blobs)


def preserve_execute_failure(error, expected_sources, operation, execute_code):
    """Retain only the exact executing function's source-bound partial report."""
    trace_text = "".join(traceback.format_exception(type(error), error, error.__traceback__))
    result = {"caller_error_private": type(error).__name__ + ": " + str(error),
              "traceback_private": trace_text[:65536], "traceback_truncated": len(trace_text) > 65536,
              "full_report_returned": False}
    trace = error.__traceback__
    while trace is not None:
        frame = trace.tb_frame
        candidate = frame.f_locals.get("report")
        if (execute_code is not None and frame.f_code is execute_code and type(candidate) is dict and
                candidate.get("schema") == "macws.swap-pair.live-controller.v7" and
                candidate.get("source_sha256") == expected_sources and candidate.get("operation") == operation):
            try:
                raw = json.dumps(candidate, allow_nan=False, separators=(",", ":")).encode()
                if len(raw) > 2 * 1024 * 1024:
                    raise ValueError("bounded partial controller report exceeded")
                result["partial_private_report"] = json.loads(raw)
            except BaseException as copy_error:
                result["partial_report_copy_error_private"] = type(copy_error).__name__ + ": " + str(copy_error)
        trace = trace.tb_next
    return result


def report_summary(outer):
    """Unknown values stay null, including absent or unparseable reports."""
    witness = outer.get("full_private_report", outer.get("partial_private_report", {}))
    witness = witness if type(witness) is dict else {}
    run = witness.get("run_private", {})
    run = run if type(run) is dict else {}
    watch = witness.get("watchdog_private", {})
    watch = watch if type(watch) is dict else {}
    return {"full_report_returned": outer.get("full_report_returned") is True,
            "accepted_scoped_capture": outer.get("accepted_scoped_capture") is True,
            "bootstraps": run.get("bootstraps"), "resumes": run.get("resumes"),
            "second_resumes": run.get("second_resumes"), "C_ready_verified": run.get("C_ready_verified"),
            "cleanup_verified": witness.get("cleanup_verified"), "watchdog_trigger": watch.get("trigger")}


def build_control_payload(*, config_raw, receipts_raw, tokens_raw, control, source_directory, qa_path):
    if type(control) is not str or control not in CONTROLS:
        raise ValueError("one explicit fixed stopped control required")
    config, receipts, tokens = (strict_json(raw) for raw in (config_raw, receipts_raw, tokens_raw))
    if config.get("schema") != "macws.swap-pair.live-config.v7" or config.get("source_sha256") != SOURCES:
        raise ValueError("fixed v7 config/source binding before module execution")
    for name in ("preflight", "signed_artifact", "loaded_hook_profile"):
        if type(receipts.get(name)) is not dict or receipts[name].get("source_sha256") != SOURCES:
            raise ValueError("fixed v7 prerequisite sources before module execution")
    offline = receipts.get("offline_QA")
    if (type(offline) is not dict or type(offline.get("receipt")) is not dict or
            offline["receipt"].get("runtime_source_sha256") != SOURCES):
        raise ValueError("fixed v7 QA sources before module execution")
    support, blobs = pinned_support(source_directory=source_directory, qa_path=qa_path, tokens=tokens)
    structural_inputs(config, receipts, tokens, support, blobs)
    body = {"config": config, "receipts": receipts, "tokens": tokens, "control": control}
    body_raw = json.dumps(body, allow_nan=False, separators=(",", ":")).encode()
    if len(body_raw) > MAX_INPUT_BYTES:
        raise ValueError("combined execution inputs exceed bound")
    prefix = "import base64,hashlib,json,os,stat,sys,traceback,types\n" + inspect.getsource(preserve_execute_failure)
    prefix += "\nbody=json.loads(base64.b64decode(" + repr(base64.b64encode(body_raw).decode()) + ",validate=True))\n"
    prefix += "EXPECTED_SOURCES=" + repr(SOURCES) + "\nDIRECTORY=" + repr(DIRECTORY) + "\n"
    program = r'''
sys.dont_write_bytecode=True
os.environ["PYTHONDONTWRITEBYTECODE"]="1"
config=body["config"];receipts=body["receipts"]
operation={"normal_ready_stop":"control_normal","parent_pipe_EOF":"control_parent_EOF","active_deadline":"control_deadline"}[body["control"]]
outer={"schema":"macws.swap-pair.explicit-device-call.v7","control":body["control"],"operation":operation,
       "source_sha256":EXPECTED_SOURCES,"device_acceptance":False,"freeze_fix":False,
       "full_report_returned":False,"accepted_scoped_capture":False}
execute_code=None
try:
 if config.get("schema")!="macws.swap-pair.live-config.v7" or config.get("source_sha256")!=EXPECTED_SOURCES:
  raise ValueError("fixed v7 config/source binding before module execution")
 if set(body["tokens"])!=set(EXPECTED_SOURCES):raise ValueError("all fixed delivery tokens required")
 blobs={}
 for name,expected in EXPECTED_SOURCES.items():
  fd=os.open(DIRECTORY+"/"+name,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   before=os.fstat(fd);wanted=body["tokens"][name]
   if set(wanted)!={"dev","ino","size","mtime_ns","ctime_ns"}:raise ValueError("exact delivery token fields")
   if not all(type(v) is int and v>=0 for v in wanted.values()):raise ValueError("typed delivery token")
   token=lambda info:[info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
   if not (stat.S_ISREG(before.st_mode) and before.st_uid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o600):
    raise ValueError("source owner/type/link/mode")
   if token(before)!=[wanted[k] for k in ("dev","ino","size","mtime_ns","ctime_ns")]:raise ValueError("source delivery token changed")
   if not 0<before.st_size<=128*1024:raise ValueError("bounded source size")
   chunks=[];length=0
   while length<=before.st_size:
    raw=os.read(fd,min(65536,before.st_size+1-length))
    if not raw:break
    chunks.append(raw);length+=len(raw)
   raw=b"".join(chunks);after=os.fstat(fd)
   if token(before)!=token(after) or [before.st_mode,before.st_uid,before.st_nlink]!=[after.st_mode,after.st_uid,after.st_nlink]:
    raise ValueError("source changed during bounded read")
   if len(raw)!=before.st_size or hashlib.sha256(raw).hexdigest()!=expected:raise ValueError("fixed v7 source hash changed")
   blobs[name]=raw
  finally:os.close(fd)
 for module_name in ("runtime_support","controller"):
  module=types.ModuleType(module_name);module.__file__=DIRECTORY+"/"+module_name+".py"
  sys.modules[module_name]=module
  exec(compile(blobs[module_name+".py"],module.__file__,"exec"),module.__dict__)
 support=sys.modules["runtime_support"];controller=sys.modules["controller"]
 if support.source_binding()!=EXPECTED_SOURCES:raise ValueError("live source path binding changed")
 support.config_checked(config)
 if config["operation"]!="run" or receipts.get("schema")!="macws.swap-pair.live-prerequisites.v7" or receipts.get("native_controls")!={}:
  raise ValueError("fixed v7 stopped-control admission only")
 selected=dict(config,operation=operation)
 execute_code=controller.execute.__code__
 clock=support.NativeSharedClock()
 outer["clock_info"]=clock.profile
 # v7 execute validates every prerequisite age against this live native clock
 # and repeats current backend exclusivity/identity/thermal gates before jobs.
 witness=controller.execute(selected,receipts,native_clock_factory=lambda:clock)
 raw=json.dumps(witness,allow_nan=False,separators=(",",":")).encode()
 if len(raw)>2*1024*1024:raise ValueError("bounded full controller report exceeded")
 if type(witness) is not dict or witness.get("schema")!="macws.swap-pair.live-controller.v7" or witness.get("source_sha256")!=EXPECTED_SOURCES or witness.get("operation")!=operation:
  raise ValueError("full v7 controller report binding")
 outer["full_private_report"]=witness
 outer["full_report_returned"]=True
 outer["completed_monotonic_private"]=clock.now()
 if witness.get("control_capture_accepted") is True:
  copied=controller.stopped_control_projection(witness);run=witness["run_private"];watch=witness["watchdog_private"]
  outer["native_control_receipt"]={"schema":"macws.swap-pair.native-stopped-control.v7","control":body["control"],"operation":operation,
   "accepted":True,"native_job_used":True,"simulation_only":False,"raw_sha256":support.config_sha(copied),"raw_witness":copied,
   "source_sha256":EXPECTED_SOURCES,"admission_sha256":support.admission_sha(config),"run_nonce":config["run_nonce"],
   "boot_private":config["boot_private"],"observed_monotonic":clock.now(),"first_resumes":run["resumes"],"second_resumes":run["second_resumes"],
   "C_ready_verified":run["C_ready_verified"],"cleanup_verified":witness["cleanup_verified"],"trigger":watch["trigger"]}
  outer["accepted_scoped_capture"]=True
except BaseException as error:
 outer["accepted_scoped_capture"]=False
 full_returned=outer["full_report_returned"]
 outer.update(preserve_execute_failure(error,EXPECTED_SOURCES,operation,execute_code))
 outer["full_report_returned"]=full_returned
finally:
 print(json.dumps(outer,allow_nan=False,separators=(",",":")),flush=True)
'''
    source = (prefix + program).encode()
    if len(source) > MAX_SOURCE_BYTES:
        raise ValueError("bounded generated source exceeded")
    compile(source, "<prepared-v7-control-payload>", "exec")
    return source, dict(metadata(), control=control, operation=CONTROLS[control],
                        stdin_source_sha256=hashlib.sha256(source).hexdigest(), stdin_source_bytes=len(source),
                        input_sha256=hashlib.sha256(body_raw).hexdigest(), structural_bindings_checked=True,
                        requires_live_native_revalidation=True)


def _require(condition, message):
    if condition is not True:
        raise ValueError(message)


def _canonical_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False, separators=(",", ":")).encode()).hexdigest()


def _time_value(value):
    try:
        finite = type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError:
        finite = False
    _require(finite, "typed finite capture time")
    return value


def _stopped_process_consistent(value, birth, path):
    keys = {"path", "birth_private", "stopped", "native_status_private", "native_status_name", "state_source",
            "raw_bsdinfo_private_hex", "raw_bsdinfo_sha256", "returned_bsdinfo_bytes", "bsdinfo_errno"}
    _require(type(value) is dict and set(value) == keys, "exact copied stopped-process fields")
    _require(value["path"] == path and value["birth_private"] == birth and value["stopped"] is True and
             type(value["native_status_private"]) is int and value["native_status_private"] == 4 and
             value["native_status_name"] == "SSTOP" and value["state_source"] == "proc_bsdinfo.pbi_status" and
             type(value["returned_bsdinfo_bytes"]) is int and value["returned_bsdinfo_bytes"] == 136 and
             type(value["bsdinfo_errno"]) is int and value["bsdinfo_errno"] == 0, "copied stopped-process consistency")
    raw_hex = value["raw_bsdinfo_private_hex"]
    _require(type(raw_hex) is str and re.fullmatch("[0-9a-f]{272}", raw_hex) is not None, "bounded copied BSD-info hex")
    raw = bytes.fromhex(raw_hex)
    _require(hashlib.sha256(raw).hexdigest() == value["raw_bsdinfo_sha256"] and
             struct.unpack_from("<I", raw, 4)[0] == 4 and struct.unpack_from("<I", raw, 12)[0] == birth[0] and
             list(struct.unpack_from("<QQ", raw, 120)) == birth[1:], "copied BSD-info status/birth/hash differs")


def capture_consistency(outer, expected_config):
    """Pure internal consistency only; no clock read, freshness, or authenticity.

    The complete report, projection and receipt must agree with the explicit
    caller-supplied admission context. This does not authenticate arbitrary
    JSON and cannot replace execute()'s live prerequisite/backend validation.
    """
    config_keys = {"schema", "operation", "arch", "run_nonce", "profile_sha256", "loaded_hook_profile_sha256",
                   "signed_probe_sha256", "signed_probe_uuid", "signed_probe_cdhash", "installed_probe_token",
                   "boot_private", "UI_private", "source_sha256", "active_seconds", "cleanup_seconds",
                   "candidate_limits", "offline_QA_sha256", "clock_info"}
    _require(type(expected_config) is dict and set(expected_config) == config_keys, "explicit complete v7 admission context required")
    cfg = expected_config
    _require(cfg["schema"] == "macws.swap-pair.live-config.v7" and cfg["operation"] == "run" and
             cfg["source_sha256"] == SOURCES and cfg["arch"] in ("arm64", "arm64e"), "fixed v7 capture context")
    _require(type(cfg["run_nonce"]) is str and re.fullmatch("[0-9a-f]{32}", cfg["run_nonce"]) is not None and
             type(cfg["boot_private"]) is str and re.fullmatch("[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", cfg["boot_private"]) is not None,
             "capture context session identities")
    clock = cfg["clock_info"]
    _require(type(clock) is dict and set(clock) == {"domain", "numer", "denom"} and
             clock["domain"] == "mach_absolute_time.absolute_seconds.v1" and
             all(type(clock[k]) is int and 0 < clock[k] <= 1_000_000_000 for k in ("numer", "denom")), "capture clock domain/timebase")
    _require(0 < _time_value(cfg["active_seconds"]) <= 10 and 0 < _time_value(cfg["cleanup_seconds"]) <= 8, "bounded capture context")
    control = outer["control"]
    operation = CONTROLS[control]
    _require(outer.get("accepted_scoped_capture") is True and outer.get("full_report_returned") is True and
             outer.get("device_acceptance") is False and outer.get("freeze_fix") is False and
             "partial_private_report" not in outer and outer.get("clock_info") == clock,
             "exact typed outer capture flags")
    _require(not any("error_private" in key for key in outer), "outer capture contains error")
    full = outer.get("full_private_report")
    _require(type(full) is dict and full.get("schema") == "macws.swap-pair.live-controller.v7" and
             full.get("source_sha256") == SOURCES and full.get("operation") == operation and full.get("clock_info") == clock,
             "complete source/operation/clock-bound v7 report")
    for key, expected in (("control_capture_accepted", True), ("pair_capture_accepted", False), ("device_acceptance", False),
                          ("freeze_fix", False), ("driver_state_cancelled", False), ("cleanup_verified", True),
                          ("independent_watchdog_ready_before_bootstrap", True)):
        _require(full.get(key) is expected, "typed full capture flag: " + key)
    _require(not any("error_private" in key for key in full), "full controller capture contains error")
    run, watch = full.get("run_private"), full.get("watchdog_private")
    _require(type(run) is dict and type(watch) is dict, "full run/watchdog objects required")
    _require(not any("error_private" in key for key in run) and not any("error_private" in key for key in watch) and
             "pair_result_private" not in run, "control report contains error or active-pair result")
    for key, expected in (("bootstraps", 1), ("resumes", 1), ("second_resumes", 0)):
        _require(type(run.get(key)) is int and run[key] == expected, "typed stopped-control counter: " + key)
    _require(run.get("C_ready_verified") is True, "verified C-ready stop required")
    birth = run.get("birth_private")
    _require(type(birth) is list and len(birth) == 3 and all(type(x) is int for x in birth) and
             birth[0] > 1 and birth[1] > 0 and 0 <= birth[2] < 1_000_000, "typed owned birth tuple")
    probe_path = "/private/var/mnt/rootfs/usr/local/libexec/macws-swap-pair-probe-20261017/probe." + cfg["arch"]
    for key in ("initial_process_private", "C_ready_process_private"):
        _stopped_process_consistent(run.get(key), birth, probe_path)
    ready = run.get("C_ready_private")
    ready_keys = {"schema", "phase", "profile_sha256", "loaded_hook_profile_architecture", "loaded_hook_profile_uuid",
                  "hook_uuid_code_gates_passed", "pair_invoked", "runtime_accepted"}
    hook_uuid = "2552c7f2-0946-3525-9771-d6d48b44c0e9" if cfg["arch"] == "arm64" else "8d9d059f-f308-3a07-be9e-bb23123ba997"
    _require(type(ready) is dict and set(ready) == ready_keys and ready["schema"] == "macws.own-swap-pair.ready.v2" and
             ready["phase"] == "before_GetMainDisplay" and ready["profile_sha256"] == cfg["profile_sha256"] and
             ready["loaded_hook_profile_architecture"] == cfg["arch"] and ready["loaded_hook_profile_uuid"] == hook_uuid and
             ready["hook_uuid_code_gates_passed"] is True and ready["pair_invoked"] is False and ready["runtime_accepted"] is False,
             "exact ready-only control phase")
    trigger = {"normal_ready_stop": "controller_done", "parent_pipe_EOF": "parent_loss_or_invalid_control", "active_deadline": "active_deadline"}[control]
    _require(watch.get("ready") is True and watch.get("cleanup_verified") is True and watch.get("trigger") == trigger and
             type(watch.get("samples")) is int and watch["samples"] >= 0 and 0 <= _time_value(watch.get("seconds")) <= 18 and
             type(watch.get("active_alarm_fired")) is bool, "typed watchdog flags/trigger/bounds")
    if control == "active_deadline":
        _require(watch["seconds"] >= cfg["active_seconds"] and
                 ((watch["active_alarm_fired"] is True and watch.get("deadline_mechanism") == "SIGALRM") or
                  (watch["active_alarm_fired"] is False and watch.get("deadline_mechanism") == "monotonic_deadline")),
                 "internal active-deadline consistency")
    else:
        _require(watch["active_alarm_fired"] is False and watch.get("deadline_mechanism") is None, "unexpected substituted deadline")
    cleanup = watch.get("cleanup")
    _require(type(cleanup) is dict and cleanup.get("own_job_absent") is True and cleanup.get("known_generation_absent") is True and
             type(cleanup.get("bootout_calls")) is int and cleanup["bootout_calls"] in (0, 1), "typed exact cleanup flags")
    absence = cleanup.get("generation_absence_evidence_private")
    absence_keys = {"api", "flavor", "requested_bytes", "returned", "errno", "outcome", "pid_private", "expected_birth_private"}
    _require(type(absence) is dict and set(absence) == absence_keys and absence["api"] == "proc_pidinfo" and absence["outcome"] == "ESRCH" and
             absence["expected_birth_private"] == birth, "copied generation-absence structure")
    for key, expected in (("flavor", 3), ("requested_bytes", 136), ("returned", 0), ("errno", errno.ESRCH), ("pid_private", birth[0])):
        _require(type(absence[key]) is int and absence[key] == expected, "copied generation-absence field: " + key)
    log = watch.get("owned_log_private")
    _require(type(log) is str and len(log.encode()) <= 256 * 1024, "bounded owned C log required")
    readies = []
    for line in log.splitlines():
        if not line.startswith("{"):
            continue
        try:
            record = strict_json(line.encode(), 256 * 1024)
        except ValueError:
            continue
        _require("get_main_status" not in record, "final C result present in stopped control log")
        if record.get("schema") == "macws.own-swap-pair.ready.v2": readies.append(record)
    _require(readies == [ready], "exact one matching ready-only C log record")
    run_keys = ("bootstraps", "resumes", "second_resumes", "C_ready_verified", "C_ready_private", "birth_private", "initial_process_private", "C_ready_process_private")
    watch_keys = ("ready", "trigger", "cleanup_verified", "cleanup", "samples", "seconds", "active_alarm_fired", "deadline_mechanism")
    projection = {"schema": "macws.swap-pair.stopped-control-witness.v7", "operation": operation, "source_sha256": SOURCES,
                  "full_private_report_sha256": _canonical_sha(full),
                  "independent_watchdog_ready_before_bootstrap": True, "control_capture_accepted": True, "pair_capture_accepted": False,
                  "device_acceptance": False, "cleanup_verified": True, "run": {key: run[key] for key in run_keys},
                  "watchdog": {key: watch[key] for key in watch_keys}, "final_C_result_observed": False}
    item = outer.get("native_control_receipt")
    item_keys = {"schema", "control", "operation", "accepted", "raw_sha256", "raw_witness", "native_job_used", "simulation_only",
                 "source_sha256", "admission_sha256", "run_nonce", "boot_private", "observed_monotonic", "first_resumes", "second_resumes",
                 "C_ready_verified", "cleanup_verified", "trigger"}
    _require(type(item) is dict and set(item) == item_keys, "complete exact native-control receipt required")
    _require(item["schema"] == "macws.swap-pair.native-stopped-control.v7" and item["control"] == control and
             item["operation"] == operation and item["accepted"] is True and item["native_job_used"] is True and
             item["simulation_only"] is False and item["source_sha256"] == SOURCES and item["run_nonce"] == cfg["run_nonce"] and
             item["boot_private"] == cfg["boot_private"] and
             item["admission_sha256"] == _canonical_sha({key: value for key, value in cfg.items() if key != "operation"}),
             "source/operation/control/session/admission receipt consistency")
    _require(item["raw_witness"] == projection and item["raw_sha256"] == _canonical_sha(projection) == _canonical_sha(item["raw_witness"]),
             "full report/projection/receipt digests differ")
    _require(type(item["first_resumes"]) is int and item["first_resumes"] == 1 and type(item["second_resumes"]) is int and
             item["second_resumes"] == 0 and item["C_ready_verified"] is True and item["cleanup_verified"] is True and
             item["trigger"] == trigger, "typed receipt protocol result")
    _require(_time_value(item["observed_monotonic"]) >= _time_value(outer.get("completed_monotonic_private")) >=
             _time_value(full.get("completed_monotonic_private")), "internal same-domain capture time order")
    return True


def decode_transport_result(*, stdout, stderr, returncode, timed_out, control, expected_config_raw=None):
    """Pure lossless private envelope for future bounded transport results.

    Negative/timeout output is retained and parsed when complete. Timeout,
    stderr, nonzero exit, invalid binding, or missing output forbids acceptance.
    No device cleanup or zero job count is inferred from transport failure.
    """
    if type(stdout) is not bytes or len(stdout) > MAX_STDOUT_BYTES or type(stderr) is not bytes or len(stderr) > MAX_STDERR_BYTES:
        raise ValueError("transport must supply bounded captured bytes")
    if type(timed_out) is not bool or (returncode is not None and type(returncode) is not int) or control not in CONTROLS:
        raise ValueError("typed explicit transport outcome required")
    result = {"schema": "macws.swap-pair.control-transport-envelope.v7", "control": control,
              "timed_out": timed_out, "returncode": returncode, "stdout_private_b64": base64.b64encode(stdout).decode(),
              "stderr_private_b64": base64.b64encode(stderr).decode(), "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
              "stderr_sha256": hashlib.sha256(stderr).hexdigest(), "accepted_scoped_capture": False,
              "device_acceptance": False, "fresh_device_state_asserted": False, "current_device_freshness_claimed": False,
              "native_evidence_authenticity_verified": False, "internally_consistent_capture": False}
    observed = {}
    try:
        observed = strict_json(stdout, MAX_STDOUT_BYTES)
        if (type(observed) is not dict or observed.get("schema") != "macws.swap-pair.explicit-device-call.v7" or
                observed.get("source_sha256") != SOURCES or observed.get("control") != control or observed.get("operation") != CONTROLS[control]):
            raise ValueError("exact source-bound v7 caller output required")
        for key in ("full_private_report", "partial_private_report"):
            if key in observed:
                witness = observed[key]
                if (type(witness) is not dict or witness.get("schema") != "macws.swap-pair.live-controller.v7" or
                        witness.get("source_sha256") != SOURCES or witness.get("operation") != CONTROLS[control]):
                    raise ValueError("nested v7 controller report binding")
        result["private_caller_report"] = observed
        # This is a structural interpretation of supplied bytes. A transport
        # implementation must preserve original bytes and provenance; this
        # helper does not authenticate arbitrary JSON as native evidence.
        result["output_structure_checked"] = True
        if observed.get("accepted_scoped_capture") is True:
            try:
                _require(expected_config_raw is not None, "explicit expected admission context required for positive interpretation")
                result["internally_consistent_capture"] = capture_consistency(observed, strict_json(expected_config_raw))
            except (ValueError, TypeError, KeyError, RecursionError) as error:
                result["capture_consistency_error_private"] = type(error).__name__ + ": " + str(error)
        result["accepted_scoped_capture"] = bool(not timed_out and returncode == 0 and stderr == b"" and
                                                  result["internally_consistent_capture"] is True)
    except (ValueError, TypeError, UnicodeError) as error:
        result["parse_error_private"] = type(error).__name__ + ": " + str(error)
        observed = {}
    result["summary"] = report_summary(observed)
    result["summary"]["accepted_scoped_capture"] = result["accepted_scoped_capture"]
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-control", choices=tuple(CONTROLS))
    parser.add_argument("--config")
    parser.add_argument("--receipts")
    parser.add_argument("--tokens")
    parser.add_argument("--output")
    parser.add_argument("--source-directory")
    parser.add_argument("--qa-path")
    args = parser.parse_args(argv)
    paths = (args.config, args.receipts, args.tokens, args.output, args.source_directory, args.qa_path)
    if args.build_control is None:
        if any(p is not None for p in paths):
            raise ValueError("explicit --build-control required for local preparation")
        print(json.dumps(metadata(), sort_keys=True))
        return 0
    if any(p is None for p in paths):
        raise ValueError("explicit config, receipts, source tokens, source directory, QA path and exclusive output required")
    source, report = build_control_payload(config_raw=bounded_regular(args.config, MAX_INPUT_BYTES),
                                          receipts_raw=bounded_regular(args.receipts, MAX_INPUT_BYTES),
                                          tokens_raw=bounded_regular(args.tokens, MAX_INPUT_BYTES), control=args.build_control,
                                          source_directory=args.source_directory, qa_path=args.qa_path)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(source)
    except BaseException:
        # Preserve a partial owned output for inspection; never remove an
        # uncertain pathname or silently replace an earlier prepared artifact.
        raise
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
