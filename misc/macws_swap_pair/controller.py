"""Explicit, private device-local controller source. Default is preparation.

No SSH, network, signing, trust mutation or deployment code is present. The
active-pair path is unusable until three genuine stopped-control receipts and
the exact signed installed candidate manifest have been prepared and reviewed.
The separate collector stops before the second resume and needs the signed
artifact, fresh baseline and offline QA, without circular control prerequisites.
"""
import argparse
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

from runtime_support import (CONTROL_OPERATIONS, REQUIRED_CONTROLS, LAUNCHCTL, LAUNCHD_DOMAIN, service_identifier, launchctl_success,
                             OwnedFiles, RealBackend, Refused, config_checked,
                             admission_sha, config_sha, job_label, need, read_regular,
                             scratch_path, source_binding, stopped_process_witness_checked, validate_prerequisites, ROOTFS, executable, NativeSharedClock)


def ready_record(raw, config):
    """Accept exactly one complete C v2 ready record, never a final result."""
    need(type(raw) is bytes and len(raw) <= 256 * 1024, "bounded owned C ready log")
    records = []
    for line in raw.splitlines():
        if not line.startswith(b"{"):
            continue
        try:
            value = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if type(value) is dict and value.get("schema") == "macws.own-swap-pair.ready.v2":
            records.append(value)
    if not records:
        return None
    need(len(records) == 1, "duplicate C ready phases")
    value = records[0]
    expected = {"schema", "phase", "profile_sha256", "loaded_hook_profile_architecture", "loaded_hook_profile_uuid",
                "hook_uuid_code_gates_passed", "pair_invoked", "runtime_accepted"}
    need(set(value) == expected, "C ready schema changed")
    need(value["phase"] == "before_GetMainDisplay" and value["profile_sha256"] == config["profile_sha256"] and
         value["loaded_hook_profile_architecture"] == config["arch"] and
         value["loaded_hook_profile_uuid"] == ("2552c7f2-0946-3525-9771-d6d48b44c0e9" if config["arch"] == "arm64" else "8d9d059f-f308-3a07-be9e-bb23123ba997") and
         value["hook_uuid_code_gates_passed"] is True and value["pair_invoked"] is False and value["runtime_accepted"] is False,
         "wrong C phase/profile/loaded hook or pair already invoked")
    return value


def final_record(raw, config):
    need(type(raw) is bytes and len(raw) <= 256 * 1024, "bounded final log")
    results = []
    for line in raw.splitlines():
        if not line.startswith(b"{"):
            continue
        try:
            value = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if type(value) is dict and "get_main_status" in value:
            results.append(value)
    if not results:
        return None
    need(len(results) == 1, "exact one final C result required")
    result = results[0]
    expected = {"schema", "requested", "profile_sha256", "refusal", "get_main_status", "pair_invoked", "begin_calls", "cancel_calls",
                "begin_status", "cancel_status", "returned_id_private", "active_id_after_private", "begin_errno", "cancel_errno", "post_verified",
                "service_registry_id_private", "client_registry_id_private", "provider_ownership_uncertain", "provider_cleanup_uncertain",
                "own_memory_reads", "own_memory_bytes", "accepted_probe_pair", "loaded_hook_observations", "loaded_hook_profile_architecture",
                "read_call_limit", "read_byte_limit", "dyld_image_limit", "total_deadline_seconds", "ready_announced", "ready_pause_returned",
                "dyld_binding_or_PAC_callability_proven", "WindowServer_status_witness", "physical_presentation_proven", "freeze_cause_or_fix_confirmed", "runtime_accepted"}
    need(set(result) == expected and result["schema"] == "macws.own-swap-pair.private.v2", "exact v2 final schema")
    need(result["profile_sha256"] == config["profile_sha256"] and result["loaded_hook_profile_architecture"] == config["arch"], "final compiled profile/architecture")
    for name in ("requested", "pair_invoked", "post_verified", "provider_ownership_uncertain", "provider_cleanup_uncertain",
                 "accepted_probe_pair", "ready_announced", "ready_pause_returned", "dyld_binding_or_PAC_callability_proven",
                 "WindowServer_status_witness", "physical_presentation_proven", "freeze_cause_or_fix_confirmed", "runtime_accepted"):
        need(type(result[name]) is bool, "typed final boolean")
    for name in ("get_main_status", "begin_status", "cancel_status", "begin_errno", "cancel_errno"):
        need(type(result[name]) is int and -(1 << 31) <= result[name] < (1 << 31), "typed signed final status")
    for name in ("returned_id_private", "active_id_after_private", "begin_calls", "cancel_calls"):
        need(type(result[name]) is int and 0 <= result[name] < (1 << 32), "typed u32 final field")
    for name in ("service_registry_id_private", "client_registry_id_private"):
        need(type(result[name]) is int and 0 <= result[name] < (1 << 64), "typed u64 final field")
    for name, expected_limit in config["candidate_limits"].items():
        if name == "loaded_hook_observations":
            need(type(result[name]) is int and 0 <= result[name] <= expected_limit,
                 "bounded runtime loaded-hook observation count")
        else:
            need(type(result[name]) is int and result[name] == expected_limit, "exact candidate limit manifest")
    need(type(result["own_memory_reads"]) is int and 0 <= result["own_memory_reads"] <= result["read_call_limit"] and
         type(result["own_memory_bytes"]) is int and 0 <= result["own_memory_bytes"] <= result["read_byte_limit"], "reported shared read bounds")
    need(type(result["refusal"]) is str and 0 < len(result["refusal"]) <= 128, "bounded C refusal label")
    for name in ("dyld_binding_or_PAC_callability_proven", "WindowServer_status_witness", "physical_presentation_proven", "freeze_cause_or_fix_confirmed", "runtime_accepted"):
        need(result[name] is False, "diagnostic scope disclaimer changed")
    return result


def accepted_pair(result):
    return bool(result and result["accepted_probe_pair"] is True and result["requested"] is True and result["pair_invoked"] is True and
                result["get_main_status"] == 0 and result["begin_calls"] == 1 and result["cancel_calls"] == 1 and
                result["begin_status"] == 0 and result["cancel_status"] == 0 and result["post_verified"] is True and
                result["provider_ownership_uncertain"] is False and result["provider_cleanup_uncertain"] is False and
                result["returned_id_private"] == result["active_id_after_private"] and result["refusal"] == "none" and
                result["ready_announced"] is True and result["ready_pause_returned"] is True and
                result["loaded_hook_observations"] == 5 and result["service_registry_id_private"] > 0 and
                result["client_registry_id_private"] > 0 and result["service_registry_id_private"] != result["client_registry_id_private"])


def reach_C_ready(config, backend, files, watch_ready, watch_alive, report):
    """Shared startup stops after exactly the first resume. No pair call."""
    deadline = min(backend.now() + config["active_seconds"], watch_ready["active_deadline_private"])
    report.update({"schema": "macws.swap-pair.controller-protocol.v7", "bootstrap_attempted": False, "bootstraps": 0, "resumes": 0, "second_resumes": 0,
                   "debug_admission_calls": 0, "C_ready_verified": False, "pair_result_private": None})
    birth = None

    def gate():
        need(backend.now() < deadline and watch_alive() is True, "watchdog/deadline gate")
        files.checked()
        backend.health(deadline)
        need(backend.other_label_absent(deadline), "other run/control job exists")

    def wait_stopped(require_ready):
        while backend.now() < deadline:
            gate()
            state = backend.job(deadline)
            need(state is not None, "own job disappeared during startup")
            if state["pid"] is not None:
                try:
                    current = backend.bind(deadline, birth)
                except Refused:
                    # A known wrapper may briefly exist before SETEXEC, but a
                    # changed identity after binding is never an excuse to wait.
                    if birth is not None:
                        raise
                    backend.bind(deadline, allow_wrapper=True)
                    backend.pause(.02)
                    continue
                copied_state = backend.process(state["pid"], deadline)
                if copied_state["stopped"] is not True:
                    backend.pause(.02)
                    continue
                stopped_process_witness_checked(copied_state, current, ROOTFS + executable(config))
                report["C_ready_process_private" if require_ready else "initial_process_private"] = copied_state
                phase = ready_record(files.log(), config)
                if require_ready:
                    if phase is not None:
                        return current, phase
                else:
                    need(phase is None, "C ready phase appeared before initial admission/resume")
                    return current, None
            backend.pause(.02)
        raise TimeoutError("own stopped target phase deadline")

    gate()
    need(backend.job(deadline) is None, "exclusive absent own label before bootstrap")
    report["bootstrap_attempted"] = True
    result = backend.command([LAUNCHCTL, "bootstrap", LAUNCHD_DOMAIN, scratch_path(config) + "/job.plist"], deadline)
    launchctl_success(result, "own bootstrap failed")
    report["bootstraps"] = 1
    result = backend.command([LAUNCHCTL, "kickstart", service_identifier(config)], deadline)
    launchctl_success(result, "own kickstart failed")
    birth, _ = wait_stopped(False)
    report["birth_private"] = birth
    gate()
    backend.debug_admit(birth, deadline)
    report["debug_admission_calls"] = 1
    gate()
    backend.resume(birth, deadline)
    report["resumes"] = 1
    current, phase = wait_stopped(True)
    need(current == birth, "C ready belongs to another generation")
    report["C_ready_private"] = phase
    report["C_ready_verified"] = True
    return birth, deadline, gate


def run_protocol(config, backend, files, watch_ready, watch_alive, report=None):
    """The second-resume site is inaccessible to every control operation."""
    need(config["operation"] == "run", "second-resume protocol is run-only")
    report = {} if report is None else report
    birth, deadline, gate = reach_C_ready(config, backend, files, watch_ready, watch_alive, report)
    gate()
    # The only resume that can pass the C GetMainDisplay guard is this second
    # site, after the exact ready JSON + same stopped process have been copied.
    backend.bind(deadline, birth, stopped=True)
    backend.resume(birth, deadline)
    report["resumes"] = 2
    report["second_resumes"] = 1
    while backend.now() < deadline:
        gate()
        raw = files.log()
        result = final_record(raw, config)
        if result is None:
            state = backend.job(deadline)
            if state is None or state["pid"] is None:
                raise Refused("own probe exited without a final result")
            backend.bind(deadline, birth)
            backend.pause(.02)
            continue
        report["pair_result_private"] = result
        report["owned_log_private"] = raw.decode("utf-8", "replace")
        return report
    raise TimeoutError("one-pair final result deadline")


def control_protocol(config, backend, files, watch_ready, watch_alive, report, parent_pipe_EOF):
    """Real stopped-probe controls: this path never calls the run protocol."""
    need(config["operation"] in CONTROL_OPERATIONS.values(), "control-only protocol")
    birth, deadline, _ = reach_C_ready(config, backend, files, watch_ready, watch_alive, report)
    need(report["resumes"] == 1 and report["second_resumes"] == 0, "control startup resume count")
    backend.bind(deadline, birth, stopped=True)
    need(final_record(files.log(), config) is None, "control observed unexpected final probe result")
    if config["operation"] == "control_parent_EOF":
        parent_pipe_EOF()
        report["control_pipe_EOF_requested"] = True
    elif config["operation"] == "control_deadline":
        report["control_hold_for_deadline"] = True
        # The independent child continues health checks while this parent holds
        # an authenticated stopped generation. No second resume is in this path.
        while backend.now() < deadline - .25 and watch_alive():
            files.checked()
            backend.bind(deadline, birth, stopped=True)
            backend.pause(.02)
    return report


def finite_ready_line(stream, deadline, *, now=time.monotonic, select_call=select.select):
    """Read one bounded newline frame without a buffered-readline hang gap."""
    fd = stream.fileno()
    prior = os.get_blocking(fd)
    os.set_blocking(fd, False)
    raw = bytearray()
    try:
        while now() < deadline:
            ready, _, _ = select_call([fd], [], [], max(0, deadline - now()))
            need(bool(ready), "watchdog readiness deadline")
            try:
                byte = os.read(fd, 1)
            except BlockingIOError:
                continue
            need(bool(byte), "watchdog readiness pipe closed before newline")
            raw.extend(byte)
            need(len(raw) <= 4096, "bounded watchdog readiness line")
            if byte == b"\n":
                return bytes(raw)
        raise TimeoutError("watchdog readiness partial-line deadline")
    finally:
        os.set_blocking(fd, prior)


def finite_pipe_write(stream, payload, deadline, *, now=time.monotonic):
    fd = stream.fileno()
    prior = os.get_blocking(fd)
    os.set_blocking(fd, False)
    at = 0
    try:
        while at < len(payload) and now() < deadline:
            _, ready, _ = select.select([], [fd], [], max(0, deadline - now()))
            need(bool(ready), "watchdog config write deadline")
            try:
                written = os.write(fd, payload[at:at + 4096])
            except BlockingIOError:
                continue
            need(written > 0, "watchdog config pipe closed")
            at += written
        need(at == len(payload), "incomplete watchdog config write")
    finally:
        os.set_blocking(fd, prior)


def execute(config, receipts, *, native_clock_factory=NativeSharedClock):
    # Pure config/source gates precede the read-only shared-clock query.
    # Backend effects and jobs require all freshness/manifest/control guards.
    sources = source_binding()
    config_checked(config)
    need(config["source_sha256"] == sources, "current sources differ before clock observation")
    clock = native_clock_factory()
    need(clock.profile == config["clock_info"], "shared native clock differs from admission")
    validate_prerequisites(config, receipts, now=clock.now(), current_sources=sources)
    backend = RealBackend(config, clock=clock)
    initial_deadline = backend.now() + 10
    backend.health(initial_deadline, initial=True)
    backend.installed(initial_deadline)
    need(backend.job(initial_deadline) is None and backend.other_label_absent(initial_deadline) and
         backend.no_candidate_process(initial_deadline), "exclusive run/control baseline")
    need(not os.path.lexists(scratch_path(config)), "preserve pre-existing scratch")
    files = None; watch = None; read_fd = write_fd = None; watch_started = None
    report = {"schema": "macws.swap-pair.live-controller.v7", "operation": config["operation"], "source_sha256": sources, "clock_info": clock.profile,
              "device_acceptance": False, "driver_state_cancelled": False, "cleanup_verified": False,
              "pair_capture_accepted": False, "control_capture_accepted": False, "freeze_fix": False}

    def close_pipe(which):
        # Relinquish ownership before close: even an uncertain/failed close must
        # never cause a retry against a descriptor number that could be reused.
        nonlocal read_fd, write_fd
        if which == "read":
            owned, read_fd = read_fd, None
        else:
            need(which == "write", "known controller pipe end")
            owned, write_fd = write_fd, None
        if owned is not None:
            os.close(owned)

    def finalization_step(phase, action):
        try:
            return action()
        except BaseException as error:
            report.setdefault("finalization_error_private", []).append(
                {"phase": phase, "error": type(error).__name__ + ": " + str(error)})
            return None

    def soft_timeout(signum, frame):
        raise TimeoutError("controller ten-second active deadline")

    old_handler = signal.signal(signal.SIGALRM, soft_timeout)
    try:
        files = OwnedFiles.create(config)
        read_fd, write_fd = os.pipe()
        body = {"config": config, "receipts": receipts, "directory_token": files.directory_token, "files": files.files}
        watch = subprocess.Popen([sys.executable, str(Path(__file__).with_name("watchdog.py")),
                                  "--control-fd", str(read_fd), "--owned-directory-fd", str(files.fd)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 pass_fds=(read_fd, files.fd))
        watch_started = backend.now()
        close_pipe("read")
        payload = json.dumps(body, separators=(",", ":")).encode()
        need(len(payload) <= 65536, "bounded independent watchdog input")
        finite_pipe_write(watch.stdin, payload, backend.now() + 3, now=backend.now)
        watch.stdin.close(); watch.stdin = None
        line = finite_ready_line(watch.stdout, backend.now() + 3, now=backend.now)
        need(0 < len(line) <= 4096 and line.endswith(b"\n"), "bounded watchdog readiness line")
        value = json.loads(line)
        need(type(value) is dict and set(value) == {"schema", "ready", "run_nonce", "active_deadline_private"} and
             value["schema"] == "macws.swap-pair.watchdog-ready.v7" and value["ready"] is True and
             value["run_nonce"] == config["run_nonce"] and watch.poll() is None, "exact independent watchdog ready")
        now = backend.now()
        need(type(value["active_deadline_private"]) in (int, float) and now < value["active_deadline_private"] <= now + 10,
             "watchdog active deadline binding")
        report["independent_watchdog_ready_before_bootstrap"] = True
        signal.setitimer(signal.ITIMER_REAL, min(10, value["active_deadline_private"] - now))
        report["run_private"] = {}
        if config["operation"] == "run":
            run_protocol(config, backend, files, value, lambda: watch.poll() is None, report["run_private"])
        else:
            def parent_pipe_EOF():
                nonlocal write_fd
                need(write_fd is not None, "control pipe already closed")
                close_pipe("write")
            control_protocol(config, backend, files, value, lambda: watch.poll() is None,
                             report["run_private"], parent_pipe_EOF)
    except BaseException as error:
        report["error_private"] = type(error).__name__ + ": " + str(error)
    finally:
        finalization_step("cancel_active_alarm", lambda: signal.setitimer(signal.ITIMER_REAL, 0))
        finalization_step("close_read_pipe", lambda: close_pipe("read"))
        hold_pipe = config["operation"] == "control_deadline" and report.get("run_private", {}).get("control_hold_for_deadline") is True
        if write_fd is not None and not hold_pipe:
            try:
                need(os.write(write_fd, b"D") == 1, "complete controller-done token")
            except BaseException as error:
                report["controller_done_write_error_private"] = type(error).__name__ + ": " + str(error)
            finalization_step("close_done_pipe", lambda: close_pipe("write"))
        if watch is not None:
            try:
                stdout, stderr = watch.communicate(timeout=max(.1, watch_started + 18.5 - backend.now()))
                need(len(stdout) <= 512 * 1024 and len(stderr) <= 16 * 1024, "bounded independent watchdog final result")
                lines = stdout.splitlines()
                need(len(lines) == 1, "one final independent watchdog report")
                result = json.loads(lines[0])
                need(type(result) is dict, "independent watchdog report object")
                report["watchdog_private"] = result
                report["cleanup_verified"] = result.get("cleanup_verified") is True
                if stderr:
                    report["watchdog_stderr_private"] = stderr.decode("utf-8", "replace")
                need(not stderr, "independent watchdog final stderr")
                need(watch.returncode == 0, "independent watchdog reported uncertain cleanup")
            except BaseException as error:
                report["watchdog_error_private"] = type(error).__name__ + ": " + str(error)
                # Do not kill the independent watchdog while it may be cleaning
                # the probe. Its own hard timer ends it by active+cleanup bound.
        finalization_step("close_remaining_write_pipe", lambda: close_pipe("write"))
        if files is not None and report["cleanup_verified"] is not True:
            try:
                need(watch is None or watch.poll() is not None, "independent watchdog may still be cleaning")
                deadline = backend.now() + 2
                attempted = report.get("run_private", {}).get("bootstrap_attempted") is True
                known_absent = report.get("watchdog_private", {}).get("cleanup", {}).get("known_generation_absent") is True
                need(not attempted or known_absent, "preserve files after unbound/uncertain started generation")
                need(backend.metadata("kern.bootsessionuuid") == config["boot_private"] and backend.job(deadline) is None and
                     backend.no_candidate_process(deadline), "parent fallback preserves uncertain ownership")
                files.cleanup_files(backend, deadline)
                report["prebootstrap_or_absent_owned_file_cleanup"] = True
            except BaseException as error:
                report["cleanup_error_private"] = type(error).__name__ + ": " + str(error)
        if files is not None:
            finalization_step("close_owned_directory", lambda: os.close(files.fd))
        finalization_step("restore_alarm_handler", lambda: signal.signal(signal.SIGALRM, old_handler))
    try:
        run = report.get("run_private", {})
        final = run.get("pair_result_private", {})
        report["pair_capture_accepted"] = bool(config["operation"] == "run" and report["cleanup_verified"] and not any("error_private" in k for k in report) and
                                           run.get("resumes") == 2 and run.get("C_ready_verified") is True and
                                           accepted_pair(final) and
                                           report.get("watchdog_private", {}).get("cleanup", {}).get("known_generation_absent") is True and
                                           not any("error_private" in k for k in report.get("watchdog_private", {})) and
                                           report.get("watchdog_private", {}).get("trigger") == "controller_done")
        if config["operation"] != "run":
            expected_trigger = {"control_normal": "controller_done", "control_parent_EOF": "parent_loss_or_invalid_control",
                            "control_deadline": "active_deadline"}[config["operation"]]
            watch_result = report.get("watchdog_private", {})
            raw = watch_result.get("owned_log_private", "").encode("utf-8")
            try:
                only_ready = ready_record(raw, config) is not None and final_record(raw, config) is None
            except Refused:
                only_ready = False
            report["control_capture_accepted"] = bool(report["cleanup_verified"] and only_ready and run.get("resumes") == 1 and
                                                  run.get("second_resumes") == 0 and run.get("C_ready_verified") is True and
                                                  watch_result.get("trigger") == expected_trigger and
                                                  watch_result.get("cleanup", {}).get("known_generation_absent") is True and
                                                  not any("error_private" in k for k in report) and
                                                  not any("error_private" in k for k in watch_result))
        report["completed_monotonic_private"] = clock.now()
    except BaseException as error:
        report["report_error_private"] = type(error).__name__ + ": " + str(error)
        report["pair_capture_accepted"] = report["control_capture_accepted"] = False
    return report


def stopped_control_projection(witness):
    """Copied allowlisted runtime fields; full private report stays separate."""
    run = witness["run_private"]; watch = witness["watchdog_private"]
    return {"schema": "macws.swap-pair.stopped-control-witness.v7", "operation": witness["operation"],
            "source_sha256": witness["source_sha256"], "full_private_report_sha256": config_sha(witness),
            "independent_watchdog_ready_before_bootstrap": witness["independent_watchdog_ready_before_bootstrap"],
            "control_capture_accepted": witness["control_capture_accepted"], "pair_capture_accepted": witness["pair_capture_accepted"],
            "device_acceptance": witness["device_acceptance"], "cleanup_verified": witness["cleanup_verified"],
            "run": {key: run[key] for key in ("bootstraps", "resumes", "second_resumes", "C_ready_verified", "C_ready_private", "birth_private",
                                              "initial_process_private", "C_ready_process_private")},
            "watchdog": {key: watch[key] for key in ("ready", "trigger", "cleanup_verified", "cleanup", "samples", "seconds", "active_alarm_fired", "deadline_mechanism")},
            "final_C_result_observed": False}


def collect_controls(config, receipts, *, native_clock_factory=NativeSharedClock):
    """Three sequential real stopped-probe controls; no active-pair dispatch."""
    need(config["operation"] == "run", "collector input must name the final run admission")
    need(receipts["native_controls"] == {}, "collector refuses stale/reused native controls")
    controls = {}
    private_reports = {}
    clock = native_clock_factory()
    for name in REQUIRED_CONTROLS:
        selected = dict(config, operation=CONTROL_OPERATIONS[name])
        # execute() revalidates every prerequisite and independently rechecks
        # absent labels/processes/scratch and current UI/thermal/artifacts.
        witness = execute(selected, receipts, native_clock_factory=lambda: clock)
        need(witness.get("control_capture_accepted") is True and witness.get("pair_capture_accepted") is False,
             "native stopped control refused; do not continue to another job")
        run = witness["run_private"]; watchdog = witness["watchdog_private"]
        copied = stopped_control_projection(witness)
        controls[name] = {"schema": "macws.swap-pair.native-stopped-control.v7", "control": name,
                          "operation": selected["operation"], "accepted": True, "native_job_used": True, "simulation_only": False,
                          "raw_sha256": config_sha(copied), "raw_witness": copied, "source_sha256": config["source_sha256"],
                          "admission_sha256": admission_sha(config), "run_nonce": config["run_nonce"], "boot_private": config["boot_private"],
                          "observed_monotonic": clock.now(), "first_resumes": run["resumes"], "second_resumes": run["second_resumes"],
                          "C_ready_verified": run["C_ready_verified"], "cleanup_verified": witness["cleanup_verified"], "trigger": watchdog["trigger"]}
        private_reports[name] = witness
    return {"schema": "macws.swap-pair.native-stopped-controls-collection.v7", "native_controls": controls,
            "private_raw_reports": private_reports,
            "active_pair_runs": 0, "second_resumes": 0, "device_acceptance": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Private controller source; preparation only by default. No transport exists.")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--collect-native-controls", action="store_true")
    parser.add_argument("--config")
    parser.add_argument("--receipts")
    args = parser.parse_args(argv)
    need(not (args.execute and args.collect_native_controls), "choose run or stopped native controls")
    if not args.execute and not args.collect_native_controls:
        need(args.config is None and args.receipts is None, "execution inputs need explicit --execute")
        print(json.dumps({"schema": "macws.swap-pair.controller-source-preparation.v7", "source_sha256": source_binding(),
                          "device_commands": 0, "device_acceptance": False, "genuine_native_watchdog_controls_collected": False,
                          "execution_blocker": "Exact signed deployment, same-run live receipts and genuine native watchdog controls are absent."}))
        return 0
    need(args.config is not None and args.receipts is not None, "all execution prerequisites required")
    config_raw, _ = read_regular(args.config, 65536)
    receipt_raw, _ = read_regular(args.receipts, 65536)
    if args.collect_native_controls:
        result = collect_controls(json.loads(config_raw), json.loads(receipt_raw))
        print(json.dumps(result, separators=(",", ":")))
        return 0
    config = json.loads(config_raw)
    need(config.get("operation") == "run", "explicit execution CLI is active run-only; controls use their collector")
    result = execute(config, json.loads(receipt_raw))
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["pair_capture_accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
