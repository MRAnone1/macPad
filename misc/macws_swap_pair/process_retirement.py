"""Private, dependency-injected process/service retirement; default is inert.

No transport, native construction, file retirement, bootstrap, debug admission,
resume, trust mutation, PID signal, or recovery retry is implemented here.
The caller owns copying/authenticating original evidence and the bounded backend.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types


SOURCE_PINS = {
    "runtime_support.py": "5d09cf9380afaa2409661a58909d1bfee41d81943f1b2306facb0cd94ee10fe0",
    "controller.py": "955c50b5cb2b30b8f0aefd69720675d04c91126dec17c802fb09be8c42197977",
    "watchdog.py": "c28ec9edd30bf86613c7cb29693697901228b579100b8b181a4dc47915f00e0a",
}
QA_SHA = "ebee0b881b5f589c4ca100c5dbcd4c72faa946b0bf741511a7396138139ae29c"
PROBE_SHA = "7e60e45736d93386f667b9009d0b2e8ea81ab38c0479294ec98019fd655af886"
PROBE_UUID = "9b8378ef-aab0-3e72-b8e3-8e1b56c9a647"
PROBE_CDHASH = "6665b5a54da06153a5940368788cdb9b6e9be3dc"
RECEIVER_SHA = "1d4a9f515b7884ead3326f39d35cc639e1e2972048e2f26a1f73033af3100463"
MANIFEST_SHA = "d2c843dc9930b28342c9b57d11bbee2bbe12202b1147dec11137106646d13263"
CONTROLLER_DIR = "/var/jb/usr/libexec/macws-swap-pair-controller-20261018"


class Refused(RuntimeError):
    """A categorical failure; never includes raw identifiers or command output."""


def need(condition, reason):
    if condition is not True:
        raise Refused(reason)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def metadata():
    return {"schema": "macws.process-retirement.metadata.private.v1",
            "default_inert": True, "transport_provided": False,
            "core_constructs_native_backend": False, "device_mutations": 0,
            "filesystem_mutations": 0, "resume_calls": 0, "bootstrap_calls": 0,
            "debug_admission_calls": 0, "trust_mutations": 0,
            "cleanup_verified": False, "device_acceptance": False,
            "freeze_fix": False, "scratch_ownership_recovered": False}


def load_runtime(source_directory):
    """Hash all bytes before executing the inert, unchanged runtime module."""
    directory = Path(source_directory)
    raw = {}
    for name in SOURCE_PINS:
        fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 0 < before.st_size <= 128 * 1024, "bounded_regular_source")
            value = bytearray()
            while len(value) <= before.st_size:
                block = os.read(fd, min(65536, before.st_size + 1 - len(value)))
                if not block:
                    break
                value.extend(block)
            after = os.fstat(fd)
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
            need(len(value) == before.st_size and
                 all(getattr(before, key) == getattr(after, key) for key in fields),
                 "source_changed_during_read")
            raw[name] = bytes(value)
        finally:
            os.close(fd)
    need({name: digest(value) for name, value in raw.items()} == SOURCE_PINS,
         "frozen_source_mismatch")
    module = types.ModuleType("private_retirement_frozen_runtime")
    module.__file__ = str(directory / "runtime_support.py")
    exec(compile(raw["runtime_support.py"], module.__file__, "exec"), module.__dict__)
    return module


@dataclass(frozen=True)
class Original:
    runtime: object
    config: dict
    birth: list
    initial: dict
    config_digest: str
    process_witness_digest: str


def _delivery_checked(rs, delivery, config):
    need(type(delivery) is dict and
         delivery.get("schema") == "macws.diagnostic-probe.delivery.private.v1" and
         delivery.get("installation_verified") is True and
         delivery.get("receiver_sha256") == RECEIVER_SHA and
         delivery.get("bundle_manifest_sha256") == MANIFEST_SHA,
         "original_delivery_binding")
    need(all(type(delivery.get(key)) is int and delivery[key] == 0
             for key in ("candidate_executions", "controller_executions", "trust_mutations")),
         "delivery_was_not_copy_only")
    rows = delivery.get("installed_files_private")
    need(type(rows) is list and len(rows) == 5, "original_delivery_files")
    # The pinned receiver serializes stat.S_IMODE, not the file-type bits.
    expected = {"probe.arm64": (rs.ROOTFS + rs.executable(config), PROBE_SHA, 0o755),
                **{name: (CONTROLLER_DIR + "/" + name, value, 0o600)
                   for name, value in SOURCE_PINS.items()},
                "offline-QA.canonical.private.json":
                    (CONTROLLER_DIR + "/offline-QA.canonical.private.json", QA_SHA, 0o600)}
    need({row.get("name") for row in rows if type(row) is dict} == set(expected),
         "original_delivery_file_set")
    for row in rows:
        path, expected_sha, mode = expected[row["name"]]
        token = row.get("stat")
        need(row.get("path") == path and row.get("sha256") == expected_sha and
             row.get("previously_absent") is True and
             row.get("new_vnode_created_exclusively") is True and type(token) is dict,
             "original_delivery_file_identity")
        need(set(token) == {"dev", "ino", "size", "mtime_ns", "ctime_ns", "mode", "uid", "gid", "nlink"}
             and all(type(value) is int and value >= 0 for value in token.values()) and
             token["mode"] == mode and token["uid"] == 0 and token["gid"] == 0 and
             token["nlink"] == 1 and token["ino"] > 0, "original_delivery_stat")
        if row["name"] == "probe.arm64":
            need([token[key] for key in ("dev", "ino", "size", "mtime_ns", "ctime_ns")]
                 == config["installed_probe_token"], "original_delivery_candidate_token")
    need(delivery.get("probe_signature") == {
        "architecture": "arm64", "cdhash": PROBE_CDHASH, "code_limit": 69584,
        "hash_type": 2, "page_hashes_valid": True, "signed_pages_checked": 5,
        "uuid": PROBE_UUID}, "original_signed_build")


def validate_original(config, original_report, delivery, *, source_directory):
    """Pure evidence validation; never interprets current scratch as ownership.

    Inputs must be the caller's retained original bytes, decoded without editing.
    The base session operation may be run; the actual retained caller operation
    MUST be control_normal. Only its effective control configuration is bound.
    This validates consistency, not provenance/authenticity of arbitrary JSON.
    """
    rs = load_runtime(source_directory)
    config = copy.deepcopy(config)
    try:
        rs.config_checked(config)
        need(config["operation"] in ("run", "control_normal"), "original_session_operation")
        config["operation"] = "control_normal"
        rs.config_checked(config)
        need(config["arch"] == "arm64" and config["signed_probe_sha256"] == PROBE_SHA and
             config["signed_probe_uuid"] == PROBE_UUID and
             config["signed_probe_cdhash"] == PROBE_CDHASH and
             config["source_sha256"] == SOURCE_PINS and config["offline_QA_sha256"] == QA_SHA,
             "original_fixed_build_or_source")
        report = copy.deepcopy(original_report)
        need(type(report) is dict and report.get("schema") == "macws.swap-pair.explicit-device-call.v7"
             and report.get("operation") == "control_normal" and
             report.get("control") == "normal_ready_stop" and
             report.get("source_sha256") == SOURCE_PINS and
             report.get("clock_info") == config["clock_info"] and
             report.get("full_report_returned") is True and
             report.get("device_acceptance") is False and report.get("freeze_fix") is False,
             "original_caller_report")
        full = report.get("full_private_report")
        need(type(full) is dict and full.get("schema") == "macws.swap-pair.live-controller.v7"
             and full.get("operation") == "control_normal" and full.get("source_sha256") == SOURCE_PINS
             and full.get("clock_info") == config["clock_info"] and
             full.get("cleanup_verified") is False and full.get("pair_capture_accepted") is False and
             full.get("control_capture_accepted") is False, "original_full_report")
        run = full.get("run_private")
        need(type(run) is dict and run.get("schema") == "macws.swap-pair.controller-protocol.v7"
             and run.get("bootstrap_attempted") is True and run.get("C_ready_verified") is False
             and run.get("pair_result_private") is None and "C_ready_process_private" not in run,
             "original_pre_resume_phase")
        for key, expected in (("bootstraps", 1), ("debug_admission_calls", 0),
                              ("resumes", 0), ("second_resumes", 0)):
            need(type(run.get(key)) is int and run[key] == expected, "original_pre_resume_counters")
        birth = rs.birth_checked(run.get("birth_private"))
        initial = rs.stopped_process_witness_checked(run.get("initial_process_private"), birth,
                                                    rs.ROOTFS + rs.executable(config))
        _delivery_checked(rs, delivery, config)
    except rs.Refused as error:
        raise Refused("original_v7_validation_failed") from error
    return Original(rs, config, copy.deepcopy(birth), copy.deepcopy(initial), rs.config_sha(config),
                    rs.config_sha({'birth': birth, 'initial': initial}))


def _intact(original):
    rs = original.runtime
    need(rs.config_sha(original.config) == original.config_digest, "validated_context_modified")
    need(rs.config_sha({'birth': original.birth, 'initial': original.initial}) ==
         original.process_witness_digest, "validated_original_process_witness_modified")
    rs.config_checked(original.config)
    rs.stopped_process_witness_checked(original.initial, original.birth,
                                      rs.ROOTFS + rs.executable(original.config))


def _gate(original, backend, deadline, read_regular):
    _intact(original)
    rs = original.runtime
    need(backend.config == original.config and backend.clock.profile == original.config["clock_info"],
         "backend_configuration_mismatch")
    now = rs.clock_value(backend.now())
    need(now < deadline, "absolute_deadline")
    backend.health(deadline, initial=True)  # Fixed build, boot, UI; thermal nominal.
    backend.installed(deadline)  # Exact current stat/hash/UUID/wrapper/hook and trust membership.
    need(backend.other_label_absent(deadline) is True, "other_label_present")
    # This is a new read-only content observation, NOT original file authority.
    # The caller supplies the unchanged pinned runtime.read_regular (O_NOFOLLOW).
    need(callable(read_regular), "pinned_current_plist_reader_required")
    raw, token = read_regular(rs.scratch_path(original.config) + "/job.plist", 16384)
    need(type(raw) is bytes and raw == rs.plist_bytes(original.config) and
         type(token) is list and len(token) == 5 and all(type(x) is int and x >= 0 for x in token),
         "current_exact_plist_content_required")
    need(backend.now() < deadline, "absolute_deadline")


def _job(original, backend, deadline, report):
    rs = original.runtime
    result = backend.command([rs.LAUNCHCTL, "print", rs.service_identifier(original.config)], deadline)
    report['job_observations_private'].append(copy.deepcopy(result))
    need(backend.now() < deadline, "absolute_deadline")
    return rs.parsed_job(original.config, result)


def _stopped(original, backend, job, deadline):
    rs = original.runtime
    need(job is not None and job["pid"] == original.birth[0], "original_job_generation_missing")
    # Preserve the unchanged runtime path/inode/stat gate, without wrapper fallback.
    need(backend.bind(deadline, original.birth, stopped=True, allow_wrapper=False) ==
         original.birth, "exact_runtime_binding_required")
    current = backend.process(job["pid"], deadline)
    rs.stopped_process_witness_checked(current, original.birth, rs.ROOTFS + rs.executable(original.config))
    need(backend.now() < deadline, "absolute_deadline")
    return copy.deepcopy(current)


def _absent(original, backend, deadline, report):
    rs = original.runtime
    try:
        absent = backend.generation_absent(original.birth, deadline)
    finally:
        evidence = getattr(backend, 'last_generation_query', None)
        if type(evidence) is dict:
            report['generation_queries_private'].append(copy.deepcopy(evidence))
    need(type(absent) is bool, "generation_absence_result")
    evidence = backend.last_generation_query
    need(type(evidence) is dict and evidence.get('api') == 'proc_pidinfo' and
         type(evidence.get('flavor')) is int and evidence['flavor'] == 3 and
         type(evidence.get('requested_bytes')) is int and evidence['requested_bytes'] == 136 and
         evidence.get('pid_private') == original.birth[0] and
         evidence.get('expected_birth_private') == original.birth,
         'copied_original_generation_query_required')
    if absent:
        evidence = backend.last_generation_query
        need(type(evidence) is dict and evidence.get("api") == "proc_pidinfo" and
             evidence.get("flavor") == 3 and evidence.get("requested_bytes") == 136 and
             type(evidence.get("returned")) is int and evidence["returned"] == 0 and
             type(evidence.get("errno")) is int and evidence["errno"] == errno.ESRCH and
             evidence.get("pid_private") == original.birth[0] and
             evidence.get("expected_birth_private") == original.birth and
             evidence.get("outcome") == "ESRCH", "copied_original_generation_ESRCH_required")
    else:
        need(type(evidence.get('returned')) is int and evidence['returned'] == 136 and
             type(evidence.get('errno')) is int and evidence['errno'] == 0 and
             evidence.get('observed_birth_private') == original.birth and
             evidence.get('outcome') == 'same_generation_alive',
             'copied_same_original_generation_required')
    need(backend.now() < deadline, "absolute_deadline")
    return absent


def _report():
    return {**metadata(), "schema": "macws.process-retirement.result.private.v1",
            "observed": False, "exact_stopped_target_observed": False,
            "kill_attempts": 0, "kill_completed": 0, "bootout_attempts": 0,
            "bootout_completed": 0, "device_mutations_attempted": 0,
            "device_mutations_completed": 0, "original_generation_ESRCH": False,
            "exact_job_absent": False, "process_retired": False, "refusal": None,
            'job_observations_private': [], 'generation_queries_private': []}


def public_summary(report):
    """Explicit typed allowlist; full native witnesses remain in private report."""
    need(type(report) is dict and report.get('schema') == 'macws.process-retirement.result.private.v1',
         'private_retirement_report_required')
    result = {'schema': 'macws.process-retirement.summary.v1'}
    for key in ('observed', 'exact_stopped_target_observed', 'original_generation_ESRCH',
                'exact_job_absent', 'process_retired', 'cleanup_verified', 'device_acceptance',
                'freeze_fix', 'scratch_ownership_recovered'):
        need(type(report.get(key)) is bool, 'typed_summary_boolean_required')
        result[key] = report[key]
    for key in ('kill_attempts', 'kill_completed', 'bootout_attempts', 'bootout_completed',
                'device_mutations_attempted', 'device_mutations_completed'):
        value = report.get(key)
        need(value is None or (type(value) is int and 0 <= value <= 2),
             'typed_summary_counter_required')
        result[key] = value
    refusal = report.get('refusal')
    result['refusal'] = refusal if refusal is None or (
        type(refusal) is str and re.fullmatch(r'[a-z][a-z0-9_]{0,79}', refusal)) else 'unrecognized_refusal'
    return result


def observe_or_retire(original=None, backend=None, *, deadline=None, observe=False, execute=False,
                      read_regular=None):
    """At most one kill + one bootout, each gated; no retry or file authority.

    An injected backend is required. This module never instantiates RealBackend.
    Root transport must bind it to load_runtime's unchanged RealBackend and source
    pins, and read_regular to that same pinned runtime's read_regular function.
    A user-supplied arbitrary Python backend is not an authentication layer.
    Command exceptions leave completion counters unknown, including TimeoutError.
    An observed or retired process never implies scratch cleanup or acceptance.
    """
    report = _report()
    if not observe and not execute:
        return report
    try:
        need(type(observe) is bool and type(execute) is bool, "explicit_boolean_mode")
        need(not (observe and execute), 'ambiguous_observe_and_execute_mode')
        need(type(original) is Original and backend is not None, "validated_original_required")
        rs = original.runtime
        now = rs.clock_value(backend.now())
        deadline = rs.clock_value(deadline)
        need(0 < deadline - now <= 8, "retirement_bound_eight_seconds")
        _gate(original, backend, deadline, read_regular)
        job = _job(original, backend, deadline, report)
        report['observed_process_private'] = _stopped(original, backend, job, deadline)
        report["observed"] = True
        report["exact_stopped_target_observed"] = True
        if not execute:
            return report
        # Final revalidation immediately before the only permitted first effect.
        _gate(original, backend, deadline, read_regular)
        report['pre_kill_process_private'] = _stopped(
            original, backend, _job(original, backend, deadline, report), deadline)
        report["kill_attempts"] = 1
        report["kill_completed"] = None
        report["device_mutations_attempted"] = 1
        report["device_mutations_completed"] = None
        report["device_mutations"] = None
        result = backend.command([rs.LAUNCHCTL, "kill", "SIGKILL", rs.service_identifier(original.config)], deadline)
        rs.launchctl_success(result, "retirement kill command incomplete")
        report["kill_completed"] = 1
        report["device_mutations_completed"] = 1
        report["device_mutations"] = 1
        _gate(original, backend, deadline, read_regular)
        job = _job(original, backend, deadline, report)
        absent = _absent(original, backend, deadline, report)
        if job is not None:
            if not absent:
                # SIGKILL may already have changed the original process state.
                # The pinned native generation query, not a fabricated SSTOP,
                # binds the still-known generation immediately before bootout.
                need(job['pid'] == original.birth[0], 'job_redirect_after_kill')
            else:
                need(job["pid"] in (None, original.birth[0]), "job_redirect_after_kill")
            # The immediately copied job plus ESRCH or same stopped generation
            # is required even though the original configured label is fixed.
            report["bootout_attempts"] = 1
            report["bootout_completed"] = None
            report["device_mutations_attempted"] = 2
            report["device_mutations_completed"] = None
            report["device_mutations"] = None
            result = backend.command([rs.LAUNCHCTL, "bootout", rs.service_identifier(original.config)], deadline)
            rs.launchctl_success(result, "retirement bootout command incomplete")
            report["bootout_completed"] = 1
            report["device_mutations_completed"] = 2
            report["device_mutations"] = 2
        _gate(original, backend, deadline, read_regular)
        # Read-only reaping observations are finite and never repeat a mutation.
        for sample in range(32):
            remaining = rs.clock_value(deadline) - rs.clock_value(backend.now())
            need(remaining > 0, 'absolute_deadline')
            final_job = _job(original, backend, deadline, report)
            need(final_job is None or final_job['pid'] in (None, original.birth[0]),
                 'replacement_job_during_final_observation')
            report['exact_job_absent'] = final_job is None
            report['original_generation_ESRCH'] = _absent(original, backend, deadline, report)
            report['process_retired'] = report['exact_job_absent'] and report['original_generation_ESRCH']
            if report['process_retired']:
                break
            if sample < 31:
                backend.pause(min(.02, remaining))
        if not report["process_retired"]:
            report["refusal"] = "final_retirement_not_proven"
    except Refused as error:
        report["refusal"] = str(error)
    except Exception:
        # Never serialize exception text (which can include PID/path/native raw).
        report["refusal"] = "backend_or_frozen_validation_failed"
    return report


if __name__ == "__main__":
    print(json.dumps(metadata(), sort_keys=True))
