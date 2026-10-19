"""Independent local-device watchdog source. No transport or implicit launch.

The standalone entry is only for the source-bound controller's child process.
Actual native watchdog control receipts have not been collected by this code.
"""
import argparse
import json
import os
import select
import signal
import stat
import time

from runtime_support import (OwnedFiles, RealBackend, config_checked, need,
                             plist_bytes, scratch_path, sha, source_binding, stop_owned, validate_prerequisites, NativeSharedClock)


class ActiveDeadline(TimeoutError):
    """Expected independent active timer, distinct from other timeouts."""


def watchdog_loop(config, backend, files, control, emit, cleanup_alarm=lambda deadline: None):
    """Use actual backend operations, or explicit fakes in unit controls."""
    started = backend.now()
    active_deadline = started + config["active_seconds"]
    hard_deadline = active_deadline + config["cleanup_seconds"]
    event = {"schema": "macws.swap-pair.watchdog.v7", "ready": False, "trigger": None,
             "cleanup_verified": False, "driver_state_cancelled": False, "samples": 0,
             "active_alarm_fired": False, "deadline_mechanism": None}
    birth = None
    try:
        backend.health(active_deadline, initial=True)
        files.checked()
        need(backend.job(active_deadline) is None, "watchdog refuses pre-existing label")
        need(backend.other_label_absent(active_deadline), "watchdog refuses occupied other run/control label")
        need(backend.no_candidate_process(active_deadline), "watchdog refuses pre-existing probe")
        emit({"schema": "macws.swap-pair.watchdog-ready.v7", "ready": True,
              "run_nonce": config["run_nonce"], "active_deadline_private": active_deadline})
        event["ready"] = True
        next_health = started
        while True:
            now = backend.now()
            if now >= active_deadline:
                event["trigger"] = "active_deadline"
                event["deadline_mechanism"] = "monotonic_deadline"
                break
            token = control(min(.05, active_deadline - now))
            if token is not None:
                event["trigger"] = "controller_done" if token == b"D" else "parent_loss_or_invalid_control"
                break
            if backend.now() >= next_health:
                backend.health(active_deadline)
                files.checked()
                need(backend.other_label_absent(active_deadline), "another run/control job appeared")
                state = backend.job(active_deadline)
                if state is not None and state["pid"] is not None:
                    observed = backend.bind(active_deadline, birth, allow_wrapper=True)
                    birth = observed if birth is None else birth
                    need(observed == birth, "watchdog target process generation changed")
                event["samples"] += 1
                next_health = backend.now() + .2
    except BaseException as error:
        if isinstance(error, ActiveDeadline):
            event["trigger"] = "active_deadline"
            event["active_alarm_fired"] = True
            event["deadline_mechanism"] = "SIGALRM"
        else:
            event["trigger"] = "health_or_source_exception"
            event["error_private"] = type(error).__name__ + ": " + str(error)
    finally:
        # Parent loss or health failure starts cleanup immediately; a late tick
        # cannot extend the original 10+8-second absolute userspace deadline.
        cleanup_deadline = min(hard_deadline, backend.now() + config["cleanup_seconds"])
        cleanup_alarm(cleanup_deadline)
        try:
            event["owned_log_private"] = files.log().decode("utf-8", "replace")
        except BaseException as error:
            event["log_capture_error_private"] = type(error).__name__ + ": " + str(error)
        try:
            need(backend.now() < cleanup_deadline, "watchdog cleanup reserve exhausted")
            event["cleanup"] = stop_owned(backend, files, config, cleanup_deadline, birth)
            need(event["cleanup"]["own_job_absent"] is True and backend.no_candidate_process(cleanup_deadline),
                 "own job/process cleanup incomplete")
            need(event["cleanup"].get("known_generation_absent") is True,
                 "owned generation never bound; job absence is not all-process absence")
            backend.health(cleanup_deadline)
            files.cleanup_files(backend, cleanup_deadline)
            event["cleanup_verified"] = True
        except BaseException as error:
            event["cleanup_error_private"] = type(error).__name__ + ": " + str(error)
            if getattr(backend, "last_generation_query", None) is not None:
                event["known_generation_query_private"] = backend.last_generation_query
        event["seconds"] = backend.now() - started
        emit(event)
    return event


def main(argv=None):
    parser = argparse.ArgumentParser(description="Private independent watchdog child entry; not a host launcher.")
    parser.add_argument("--control-fd", type=int, required=True)
    parser.add_argument("--owned-directory-fd", type=int, required=True)
    args = parser.parse_args(argv)
    need(args.control_fd >= 3 and args.owned_directory_fd >= 3 and args.control_fd != args.owned_directory_fd, "distinct inherited watchdog descriptors")
    need(stat.S_ISFIFO(os.fstat(args.control_fd).st_mode) and stat.S_ISDIR(os.fstat(args.owned_directory_fd).st_mode), "watchdog inherited descriptor kinds")
    raw = bytearray()
    until = time.monotonic() + 3
    prior = os.get_blocking(0)
    os.set_blocking(0, False)
    try:
        while time.monotonic() < until:
            ready, _, _ = select.select([0], [], [], max(0, until - time.monotonic()))
            need(bool(ready), "watchdog bounded input deadline")
            chunk = os.read(0, 8192)
            if not chunk:
                break
            raw.extend(chunk)
            need(len(raw) <= 65536, "bounded watchdog input")
        else:
            raise TimeoutError("watchdog input did not close")
    finally:
        os.set_blocking(0, prior)
    need(bool(raw), "nonempty watchdog input")
    body = json.loads(raw)
    need(type(body) is dict and set(body) == {"config", "receipts", "directory_token", "files"}, "watchdog input schema")
    config = config_checked(body["config"])
    need(config["source_sha256"] == source_binding(), "standalone watchdog source binding")
    clock = NativeSharedClock()
    need(clock.profile == config["clock_info"], "watchdog shared native clock differs")
    validate_prerequisites(config, body["receipts"], now=clock.now(), current_sources=source_binding())
    files = OwnedFiles(args.owned_directory_fd, body["directory_token"], body["files"], scratch_path(config))
    need(files.files["job.plist"]["sha256"] == sha(plist_bytes(config)), "watchdog exact computed launch plist")
    backend = RealBackend(config, clock=clock)
    hard_deadline = backend.now() + config["active_seconds"] + config["cleanup_seconds"]

    def hard_exit(signum, frame):
        # Never block on a full parent-output pipe in the hard-timeout handler.
        os._exit(124)

    def active_timeout(signum, frame):
        raise ActiveDeadline("independent watchdog active deadline")

    def cleanup_alarm(deadline):
        signal.signal(signal.SIGALRM, hard_exit)
        remaining = min(deadline, hard_deadline) - backend.now()
        if remaining <= 0:
            hard_exit(signal.SIGALRM, None)
        signal.setitimer(signal.ITIMER_REAL, remaining)

    signal.signal(signal.SIGALRM, active_timeout)
    signal.setitimer(signal.ITIMER_REAL, config["active_seconds"])

    def control(seconds):
        ready, _, _ = select.select([args.control_fd], [], [], seconds)
        return os.read(args.control_fd, 2) if ready else None

    def emit(value):
        raw = json.dumps(value, separators=(",", ":")).encode() + b"\n"
        need(len(raw) <= 512 * 1024, "watchdog report bound")
        need(os.write(1, raw) == len(raw), "complete watchdog report write")

    try:
        event = watchdog_loop(config, backend, files, control, emit, cleanup_alarm)
        return 0 if event["cleanup_verified"] else 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        os.close(args.control_fd)
        os.close(args.owned_directory_fd)


if __name__ == "__main__":
    raise SystemExit(main())
