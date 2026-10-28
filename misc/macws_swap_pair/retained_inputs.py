"""Pinned historical bytes for a future read-only retained-artifact observer.

Import/default CLI performs no input reads, native construction or effects.
Exact SHA pins authenticate the caller-selected historical bytes only under the
trusted-host/source-review assumption. JSON consistency is not native authority.
Old scratch stat values are never returned as selection or deletion authority.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import sys
import types

INPUT_PINS = {
    "config": "34084489495810c30b5180d6dc70e08cc388b25a70587d9068b6c254a48e5ac8",
    "control_wire": "3d90ab04efd4d1a848f46b559309654478dbfe67b000a1866b0a8d6f564c330e",
    "host": "9b1cb48e6098a27c7fc7d481cfa0a8408fe5e910313994591b4b55af50b286af",
    "delivery": "bd7d13afb89c48006737ccbab4c564e93fdb7304bb680241a979f350f20cc940",
    "retirement_wire": "7c87719fec3bb00837861c9ab745f59fe64c81f7de3e55614b50fceff99b7b06",
    "snapshot": "4ed4f616220d65d2a86de344e4a9d19d84e6441731a9d26eefad30d1320672ef",
}
CORE_SHA256 = "259d817eb942a251a07407751bce4785d0495cf252bd98aebdfc5176bebf0ee5"
CLEANUP_SHA256 = "163a222759d985c1ada68366584a003b95578e877a60ec3a4f51437e62fb7e90"
PLAN_SHA256 = "d287798e366823c1394b7c6e57f0902daf6881fd9c198f116a8400464177bd76"
MAX_VALIDATOR_SOURCE = 128 * 1024
MAX_VALIDATOR_SOURCES = 3 * MAX_VALIDATOR_SOURCE
MAX_RAW = 512 * 1024
NAMES = ("job.plist", "probe.log")
FILE_LIMITS = {"job.plist": 65536, "probe.log": 262144}


class Refused(ValueError):
    """Fixed categorical error; raw identifiers/bytes are never interpolated."""


def need(condition, reason):
    if condition is not True:
        raise Refused(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _tree(value, depth=0, budget=None):
    # Bound both nodes and aggregate string bytes before canonical encoding.
    # Repeating one individually bounded large string cannot multiply memory.
    budget = [30000, MAX_RAW] if budget is None else budget
    budget[0] -= 1
    need(depth <= 18 and budget[0] >= 0, "bounded_json_structure")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        need(-(1 << 63) <= value < 1 << 63, "bounded_json_integer")
        return
    if type(value) is float:
        need(math.isfinite(value), "finite_json_number")
        return
    if type(value) is str:
        try:
            need(len(value) <= MAX_RAW, "bounded_json_string")
            length = len(value.encode("utf-8"))
            need(length <= MAX_RAW, "bounded_json_string")
            budget[1] -= length
            need(budget[1] >= 0, "bounded_aggregate_json_strings")
        except UnicodeError as error:
            raise Refused("valid_json_unicode") from error
        return
    if type(value) is list:
        need(len(value) <= 1024, "bounded_json_array")
        for item in value:
            _tree(item, depth + 1, budget)
        return
    need(type(value) is dict and len(value) <= 256 and all(
        type(key) is str and len(key) <= 128 for key in value), "bounded_json_object")
    for key, item in value.items():
        _tree(key, depth + 1, budget)
        _tree(item, depth + 1, budget)


def canonical(value):
    _tree(value)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    need(len(raw) <= MAX_RAW, "bounded_complete_canonical_json")
    return raw


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_RAW, "bounded_json_bytes")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    def constant(_):
        raise Refused("finite_json_number")
    try:
        result = json.loads(raw, object_pairs_hook=unique, parse_constant=constant)
        _tree(result)  # Also rejects ordinary exponent overflow (1e999).
        need(type(result) is dict, "one_json_object")
        return result
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError) as error:
        raise Refused("valid_bounded_json") from error


def _b64(value, limit):
    need(type(value) is str and len(value) <= ((limit + 2) // 3) * 4,
         "bounded_base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise Refused("valid_base64") from error
    need(len(raw) <= limit and base64.b64encode(raw).decode("ascii") == value,
         "canonical_bounded_base64")
    return raw


def _integer(value, expected):
    return type(value) is int and value == expected


def _same(left, right):
    return canonical(left) == canonical(right)


def _source_raw(source_directory, filename, expected_sha):
    path = Path(source_directory) / filename
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 < before.st_size <= 128 * 1024, "bounded_regular_retirement_source")
        raw = bytearray()
        while len(raw) <= before.st_size:
            block = os.read(fd, min(65536, before.st_size + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(fd)
        linked = os.lstat(path)
        fields = ("st_dev", "st_ino", "st_size", "st_mode", "st_mtime_ns", "st_ctime_ns",
                  "st_nlink", "st_uid", "st_gid")
        need(len(raw) == before.st_size and all(
            getattr(before, key) == getattr(after, key) == getattr(linked, key) for key in fields),
            "retirement_source_changed_during_read")
        raw = bytes(raw)
        need(digest(raw) == expected_sha, "frozen_validation_source")
    finally:
        os.close(fd)
    return raw


def _load_module(source_directory, filename, expected_sha):
    path = Path(source_directory) / filename
    raw = _source_raw(source_directory, filename, expected_sha)
    # A fresh isolated inert module; callers use the returned module's Original.
    name = "_retained_inputs_" + filename.replace(".", "_") + str(id(raw))
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def _validator_sources_checked(value):
    """Freeze all three exact source bytes before any embedded source executes.

    Only a plain dictionary of plain immutable bytes is admitted. This is not a
    plugin interface: the source identities remain the existing fixed pins.
    """
    expected = {"process_retirement.py": CORE_SHA256,
                "cleanup_payload.py": CLEANUP_SHA256,
                "reviewed_delivery_plan.json": PLAN_SHA256}
    need(type(value) is dict and len(value) == len(expected) and
         all(type(key) is str for key in value) and set(value) == set(expected),
         "exact_embedded_validator_source_set")
    # Copy only the fixed keys. The caller's mutable container is not consulted
    # after this snapshot; bytes subclasses and mutable buffers are rejected.
    raw = {name: value[name] for name in expected}
    need(all(type(item) is bytes and 0 < len(item) <= MAX_VALIDATOR_SOURCE
             for item in raw.values()) and
         sum(len(item) for item in raw.values()) <= MAX_VALIDATOR_SOURCES,
         "bounded_immutable_embedded_validator_sources")
    need({name: digest(item) for name, item in raw.items()} == expected,
         "frozen_embedded_validation_sources")
    return types.MappingProxyType(raw)


def _load_embedded_module(filename, raw):
    # Each instance owns a fresh name so dataclasses can resolve only this
    # instance's globals. This relies on a trusted, single-process interpreter;
    # it is not a sandbox against concurrent sys.modules or stdlib mutation.
    module = types.ModuleType("_retained_inputs_embedded_pending")
    name = "_retained_inputs_embedded_" + filename.replace(".", "_") + str(id(module))
    need(name not in sys.modules, "fresh_embedded_validator_namespace")
    module.__name__ = name
    module.__file__ = "<retained-inputs-embedded/" + filename + ">"
    sys.modules[name] = module
    try:
        exec(compile(raw, module.__file__, "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def _delivery_checked(source_directory, delivery, validator_sources=None):
    if validator_sources is None:
        cleanup = _load_module(source_directory, "cleanup_payload.py", CLEANUP_SHA256)
        raw_plan = _source_raw(source_directory, "reviewed_delivery_plan.json", PLAN_SHA256)
    else:
        cleanup = _load_embedded_module("cleanup_payload.py", validator_sources["cleanup_payload.py"])
        raw_plan = validator_sources["reviewed_delivery_plan.json"]
    decode(raw_plan)
    try:
        plan = cleanup.validate_plan(raw_plan)
        cleanup.validate_delivery(delivery, plan)
    except (ValueError, KeyError, TypeError) as error:
        raise Refused("original_full_delivery_validation_refused") from error
    return cleanup, raw_plan


def _host_checked(host, report, wire, config_raw):
    need(host.get("schema") == "macws.swap-pair.normal-control-transport.private.v7" and
         host.get("operation") == "control_normal" and host.get("control") == "normal_ready_stop",
         "historical_host_mode")
    for key in ("accepted_scoped_capture", "active_pair_route", "automatic_retry",
                "current_device_freshness_claimed", "device_acceptance", "freeze_fix",
                "native_evidence_authenticity_verified", "remote_cleanup_inferred_from_transport"):
        need(host.get(key) is False, "historical_host_limits")
    transport = host.get("transport_private")
    need(type(transport) is dict and transport.get("capture_complete") is True and
         transport.get("stdin_complete") is True and transport.get("timed_out") is False and
         transport.get("output_limit_exceeded") is False and
         _integer(transport.get("returncode"), 0) and
         transport.get("local_cleanup_errors_private") == [] and
         "transport_error_private" not in transport, "complete_original_transport")
    nested = host.get("decoded_private")
    need(type(nested) is dict and nested.get("schema") == "macws.swap-pair.control-transport-envelope.v7" and
         nested.get("timed_out") is False and _integer(nested.get("returncode"), 0) and
         nested.get("output_structure_checked") is True and
         _same(nested.get("private_caller_report"), report), "unaltered_decoded_original_report")
    for scope in (host, nested):
        need(_b64(scope.get("stdout_private_b64"), MAX_RAW) == wire and
             scope.get("stdout_sha256") == digest(wire) and
             _b64(scope.get("stderr_private_b64"), 16384) == b"" and
             scope.get("stderr_sha256") == digest(b""), "original_complete_wire_binding")
    need(_integer(host.get("stdout_bytes_captured"), len(wire)) and
         _integer(host.get("stderr_bytes_captured"), 0) and
         type(host.get("input_sha256")) is dict and
         host["input_sha256"].get("config_sha256") == digest(config_raw), "original_config_byte_binding")


def _job_tuple(value):
    need(type(value) is list and len(value) == 3 and type(value[0]) is int and
         type(value[1]) is str and type(value[2]) is str, "typed_native_command_tuple")
    return tuple(value)


def _retirement_checked(pr, original, worker):
    rs = original.runtime
    need(worker.get("schema") == "macws.process-retirement.worker.private.v1" and
         worker.get("core_sha256") == CORE_SHA256 and worker.get("execute_requested") is True and
         worker.get("process_retired") is True and worker.get("exclusive_writer_assumed") is True and
         worker.get("native_backend_constructed") is True and
         worker.get("service_check_and_action_atomic") is False and
         _same(worker.get("clock_info"), original.config["clock_info"]) and
         "worker_error_category" not in worker, "original_retirement_worker")
    for key in ("cleanup_verified", "device_acceptance", "freeze_fix"):
        need(worker.get(key) is False, "original_retirement_limits")
    started, finished = worker.get("started_monotonic_private"), worker.get("finished_monotonic_private")
    need(type(started) in (int, float) and type(finished) in (int, float) and
         math.isfinite(started) and math.isfinite(finished) and 0 <= started < finished and
         finished - started <= 8, "bounded_historical_retirement_clock")
    core = worker.get("core_result_private")
    need(type(core) is dict and core.get("refusal") is None and
         core.get("schema") == "macws.process-retirement.result.private.v1", "complete_retirement_core")
    for key in ("observed", "exact_stopped_target_observed", "original_generation_ESRCH",
                "exact_job_absent", "process_retired"):
        need(core.get(key) is True, "successful_historical_process_retirement")
    for key in ("cleanup_verified", "device_acceptance", "freeze_fix", "scratch_ownership_recovered"):
        need(core.get(key) is False, "historical_process_only_limits")
    for key, expected in (("kill_attempts", 1), ("kill_completed", 1), ("bootout_attempts", 1),
                          ("bootout_completed", 1), ("device_mutations", 2),
                          ("device_mutations_attempted", 2), ("device_mutations_completed", 2),
                          ("bootstrap_calls", 0), ("debug_admission_calls", 0),
                          ("resume_calls", 0), ("trust_mutations", 0), ("filesystem_mutations", 0)):
        need(_integer(core.get(key), expected), "typed_retirement_effect_counters")
    need(_same(pr.public_summary(core), worker.get("summary")), "retirement_summary_projection")
    for name in ("observed_process_private", "pre_kill_process_private"):
        rs.stopped_process_witness_checked(core.get(name), original.birth,
                                          rs.ROOTFS + rs.executable(original.config))
    queries = core.get("generation_queries_private")
    need(type(queries) is list and len(queries) == 2, "two_retained_generation_queries")
    for query in queries:
        need(type(query) is dict and query.get("api") == "proc_pidinfo" and
             _integer(query.get("flavor"), 3) and _integer(query.get("requested_bytes"), 136) and
             _integer(query.get("returned"), 0) and _integer(query.get("errno"), errno.ESRCH) and
             _integer(query.get("pid_private"), original.birth[0]) and
             _same(query.get("expected_birth_private"), original.birth) and query.get("outcome") == "ESRCH",
             "retained_native_generation_esrch")
    jobs = core.get("job_observations_private")
    need(type(jobs) is list and len(jobs) == 4, "retained_job_observations")
    for row in jobs[:-1]:
        parsed = rs.parsed_job(original.config, _job_tuple(row))
        need(parsed is not None and parsed["pid"] in (None, original.birth[0]), "retired_job_generation")
    need(rs.parsed_job(original.config, _job_tuple(jobs[-1])) is None, "retained_exact_job_absence")
    commands = worker.get("commands_private")
    need(type(commands) is list and len(commands) == 20, "retained_bounded_command_trace")
    normal = dict(original.config, operation="run")
    service, other = rs.service_identifier(original.config), rs.service_identifier(normal)
    phase = [["/bin/ps", "-eo", "pid,comm"], [rs.JBCTL, "trustcache", "info"],
             [rs.LAUNCHCTL, "print", other], [rs.LAUNCHCTL, "print", service]]
    expected_argv = (phase + [phase[-1]] + phase + [phase[-1]] +
        [[rs.LAUNCHCTL, "kill", "SIGKILL", service]] + phase +
        [[rs.LAUNCHCTL, "bootout", service]] + phase)
    need([row.get("argv_private") if type(row) is dict else None for row in commands] == expected_argv,
         "exact_retirement_command_sequence")
    command_modes = []
    for row in commands:
        need(type(row) is dict and row.get("attempted") is True and row.get("result_known") is True and
             type(row.get("returncode")) is int, "complete_retirement_command_trace")
        argv = row.get("argv_private")
        need(type(argv) is list and all(type(x) is str for x in argv), "typed_retirement_argv")
        stdout = _b64(row.get("stdout_private_b64"), 262144)
        stderr = _b64(row.get("stderr_private_b64"), 16384)
        if argv in ([rs.LAUNCHCTL, "kill", "SIGKILL", service], [rs.LAUNCHCTL, "bootout", service]):
            need(row["returncode"] == 0 and stdout == stderr == b"", "quiet_completed_retirement_effect")
            command_modes.append("kill" if argv[1] == "kill" else "bootout")
        else:
            need(argv in (["/bin/ps", "-eo", "pid,comm"], [rs.JBCTL, "trustcache", "info"],
                          [rs.LAUNCHCTL, "print", other], [rs.LAUNCHCTL, "print", service]),
                 "retirement_read_command_allowlist")
            if argv[1] == "print":
                try:
                    result = (row["returncode"], stdout.decode("utf-8"), stderr.decode("utf-8"))
                except UnicodeError as error:
                    raise Refused("utf8_retirement_job_trace") from error
                if argv[-1] == other:
                    need(rs.parsed_job(normal, result) is None, "retirement_other_service_absent")
                else:
                    parsed = rs.parsed_job(original.config, result)
                    need(parsed is None or parsed["pid"] in (None, original.birth[0]),
                         "retirement_trace_original_job_generation")
            else:
                need(row["returncode"] == 0 and stderr == b"", "quiet_complete_retirement_read")
    need(command_modes == ["kill", "bootout"], "one_ordered_retirement_effect_each")
    for index, job in zip((4, 9, 14, 19), jobs):
        row = commands[index]
        copied = [row["returncode"], _b64(row["stdout_private_b64"], 262144).decode("utf-8"),
                  _b64(row["stderr_private_b64"], 16384).decode("utf-8")]
        need(_same(copied, job), "core_job_and_native_command_wire_agree")
    last = commands[-1]
    need(last["argv_private"] == [rs.LAUNCHCTL, "print", service] and
         rs.parsed_job(original.config, (last["returncode"],
             _b64(last["stdout_private_b64"], 262144).decode("utf-8"),
             _b64(last["stderr_private_b64"], 16384).decode("utf-8"))) is None,
         "trace_final_exact_job_absence")


def _snapshot_checked(original, snapshot):
    rs = original.runtime
    need(snapshot.get("schema") == "macws.swap-pair.readonly-owned-state.private.v7" and
         snapshot.get("observation_completed") is True and
         snapshot.get("installed_source_sha256") == original.config["source_sha256"],
         "historical_retained_snapshot")
    for key in ("cleanup_authorized", "device_acceptance", "freeze_fix", "original_file_ownership_recovered"):
        need(snapshot.get(key) is False, "historical_snapshot_limits")
    for key in ("candidate_executions", "mutations", "signals_to_other_processes", "trust_mutations"):
        need(_integer(snapshot.get(key), 0), "historical_snapshot_readonly")
    for name in ("before_private", "after_private"):
        observation = snapshot.get(name)
        need(type(observation) is dict and all(observation.get(key) is True for key in (
            "UI_matches_session", "boot_matches_session", "candidate_token_matches_delivery",
            "same_initial_birth", "same_initial_path")) and _integer(observation.get("thermal"), 0),
            "historical_snapshot_health")
        rs.stopped_process_witness_checked(observation.get("process_private"), original.birth,
                                          rs.ROOTFS + rs.executable(original.config))
    scratch = snapshot.get("scratch_private")
    target = rs.scratch_path(original.config)
    other = rs.scratch_path(dict(original.config, operation="run"))
    need(type(scratch) is dict and set(scratch) == {target, other} and
         type(scratch[other]) is dict and set(scratch[other]) == {"present"} and
         scratch[other]["present"] is False, "historical_fixed_scratch_scope")
    selected = scratch[target]
    need(type(selected) is dict and selected.get("present") is True and
         selected.get("current_observation_only_not_original_ownership") is True and
         _integer(selected.get("mode"), 0o700) and _integer(selected.get("uid"), 0) and
         _integer(selected.get("gid"), 0), "historical_current_observation_only")
    rows = selected.get("files_private")
    need(type(rows) is dict and set(rows) == set(NAMES), "historical_exact_two_files")
    result = {}
    for name in NAMES:
        row = rows[name]
        need(type(row) is dict and row.get("path_private") == target + "/" + name and
             _integer(row.get("mode"), 0o600) and _integer(row.get("uid"), 0) and
             _integer(row.get("gid"), 0), "historical_file_scope_owner_mode")
        raw = _b64(row.get("raw_private_b64"), FILE_LIMITS[name])
        token = row.get("token_private")
        need(_integer(row.get("bytes"), len(raw)) and row.get("sha256") == digest(raw) and
             type(token) is list and len(token) == 5 and all(type(x) is int and x >= 0 for x in token) and
             token[1] > 0 and token[2] == len(raw), "historical_complete_file_bytes")
        result[name] = raw
    need(result["job.plist"] == rs.plist_bytes(original.config) and
         rows["job.plist"].get("matches_config_derived_plist") is True,
         "historical_effective_control_plist")
    return result


@dataclass(frozen=True)
class Inputs:
    retirement_core: object = field(repr=False)
    cleanup_core: object = field(repr=False)
    original: object = field(repr=False)
    _plan: bytes = field(repr=False)
    _context: bytes = field(repr=False)
    _expected: tuple = field(repr=False)
    _provenance: bytes = field(repr=False)
    _raw: tuple = field(repr=False)

    def intact(self):
        self.retirement_core._intact(self.original)
        need(self.original.config_digest == self.context["config_sha256"], "original_input_modified")
        return True

    @property
    def context(self):
        return decode(self._context)

    @property
    def expected_files(self):
        return dict(self._expected)

    @property
    def provenance_base(self):
        return decode(self._provenance)

    @property
    def original_bytes(self):
        return dict(self._raw)

    @property
    def delivery(self):
        return decode(self.original_bytes["delivery"])

    @property
    def delivery_plan(self):
        return decode(self._plan)


def build_inputs(config_raw, control_wire_raw, host_raw, delivery_raw, retirement_wire_raw,
                 snapshot_raw, *, source_directory, validator_sources=None):
    """Explicit offline validation; no backend, command, archive or device action.

    Only the effective operation is derived by the unchanged v7 validator. Base
    config/wire bytes and times are preserved. Old snapshot tokens are checked
    only for content consistency and are excluded from every returned context.
    Optional validator_sources supplies the exact three pinned validator bytes
    without staging files. All are frozen and verified before first execution.
    source_directory still selects the installed, unchanged three runtime files
    read and verified by the unchanged original validator.
    """
    sources = (None if validator_sources is None else
               _validator_sources_checked(validator_sources))
    raw = dict(zip(INPUT_PINS, (config_raw, control_wire_raw, host_raw, delivery_raw,
                              retirement_wire_raw, snapshot_raw)))
    need(all(type(value) is bytes and 0 < len(value) <= MAX_RAW for value in raw.values()),
         "six_bounded_original_inputs")
    need({name: digest(value) for name, value in raw.items()} == INPUT_PINS, "exact_historical_input_bytes")
    data = {name: decode(value) for name, value in raw.items()}
    _host_checked(data["host"], data["control_wire"], control_wire_raw, config_raw)
    cleanup, raw_plan = _delivery_checked(source_directory, data["delivery"], sources)
    pr = (_load_module(source_directory, "process_retirement.py", CORE_SHA256)
          if sources is None else
          _load_embedded_module("process_retirement.py", sources["process_retirement.py"]))
    try:
        original = pr.validate_original(data["config"], data["control_wire"], data["delivery"],
                                        source_directory=source_directory)
    except pr.Refused as error:
        raise Refused("original_pinned_validation_refused") from error
    try:
        _retirement_checked(pr, original, data["retirement_wire"])
        expected = _snapshot_checked(original, data["snapshot"])
    except pr.Refused as error:
        raise Refused("original_pinned_validation_refused") from error
    except original.runtime.Refused as error:
        raise Refused("original_runtime_validation_refused") from error
    context = {"boot_private": original.config["boot_private"], "config_sha256": original.config_digest,
        "source_sha256": original.config["source_sha256"], "retired_birth_private": original.birth,
        "UI_private": original.config["UI_private"],
        "expected_file_sha256": {name: digest(expected[name]) for name in NAMES},
        "exclusive_operator": True}
    provenance = {"original_wire_sha256": digest(control_wire_raw), "original_host_sha256": digest(host_raw),
        "original_delivery_sha256": digest(delivery_raw), "original_config_sha256": digest(config_raw),
        "effective_config_sha256": original.config_digest, "retirement_wire_sha256": digest(retirement_wire_raw),
        "retained_snapshot_sha256": digest(snapshot_raw)}
    return Inputs(pr, cleanup, original, raw_plan, canonical(context), tuple(expected.items()),
                  canonical(provenance), tuple(raw.items()))


def metadata():
    return {"schema": "macws.retained-inputs.metadata.private.v1", "default_inert": True,
        "native_backends_constructed": 0, "device_commands": 0, "filesystem_mutations": 0,
        "scratch_ownership_recovered": False, "device_acceptance": False, "freeze_fix": False}


if __name__ == "__main__":
    print(json.dumps(metadata(), sort_keys=True))
