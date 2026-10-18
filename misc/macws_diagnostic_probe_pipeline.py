"""Pinned own-probe delivery through device_pipeline.sh; dry metadata by default.

--install only copies five files into absent, exclusive diagnostic directories.
It performs no signing, trust admission, launch, debug admission or resume.
Raw installation stdout is PRIVATE and must be captured by the caller.
"""
import argparse
import base64
import hashlib
import json
import os
import re
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import time

import macws_diagnostic_probe_receiver as receiver

MAX_PAYLOAD = receiver.MAX_PAYLOAD
MANIFEST_SHA256 = receiver.MANIFEST_SHA256
RECEIVER_PATH = Path(__file__).with_name("macws_diagnostic_probe_receiver.py")
SSH_BOOTSTRAP = """import base64,hashlib,json,signal,sys
def alarm(signum,frame):
    raise TimeoutError('delivery bootstrap alarm')
signal.signal(signal.SIGALRM,alarm)
signal.alarm(12)
raw=sys.stdin.buffer.read(1048577)
if len(raw)>1048576 or hashlib.sha256(raw).hexdigest()!=sys.argv[2]:
    raise RuntimeError('delivery envelope bound/hash differs')
envelope=json.loads(raw)
source=base64.b64decode(envelope['receiver_source_b64'],validate=True)
if hashlib.sha256(source).hexdigest()!=sys.argv[1]:
    raise RuntimeError('receiver source differs')
namespace={'__name__':'macws_pinned_receiver','__file__':'ssh-stdin-pinned-receiver'}
exec(compile(source,'ssh-stdin-pinned-receiver','exec'),namespace)
raise SystemExit(namespace['receive'](envelope['payload'],sys.argv[1]))
"""


def read_regular(path, maximum=MAX_PAYLOAD):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        receiver.require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum,
                         "local source is not a bounded regular file")
        data = receiver.read_fd(fd, before.st_size, lambda: None)
        receiver.require(receiver.token(before) == receiver.token(os.fstat(fd)), "local source changed")
        return data
    finally:
        os.close(fd)


def prepare_bundle(bundle):
    bundle = Path(bundle)
    if bundle.name == "manifest.private.json":
        bundle = bundle.parent
    before = bundle.lstat()
    receiver.require(stat.S_ISDIR(before.st_mode) and not bundle.is_symlink(),
                     "bundle is not an ordinary directory")
    raw = read_regular(bundle / "manifest.private.json", 65536)
    receiver.require(receiver.sha(raw) == MANIFEST_SHA256, "unreviewed bundle manifest")
    manifest = receiver.decode_json(raw)
    rows = manifest["files"]
    receiver.require(len(rows) == 34 and len({row["name"] for row in rows}) == len(rows),
                     "bundle file inventory differs")
    receiver.require(set(os.listdir(bundle)) == {"manifest.private.json"} | {row["name"] for row in rows},
                     "bundle has missing or unexpected files")
    files = {}
    total = 0
    for row in rows:
        name = row["name"]
        receiver.require(type(name) is str and name not in {"", ".", ".."}
                         and "/" not in name and "\\" not in name, "invalid bundle filename")
        data = read_regular(bundle / name)
        total += len(data)
        receiver.require(total <= MAX_PAYLOAD, "bundle bytes exceed bound")
        receiver.require(len(data) == row["bytes"] and receiver.sha(data) == row["sha256"],
                         "bundle provenance content differs: " + name)
        if name in receiver.SELECTED:
            files[name] = base64.b64encode(data).decode("ascii")
    receiver.require(receiver.dir_identity(before) == receiver.dir_identity(bundle.lstat()),
                     "bundle directory changed")
    payload = {"manifest_b64": base64.b64encode(raw).decode("ascii"), "files_b64": files}
    _, signature = receiver.parse_payload(payload)
    source = read_regular(RECEIVER_PATH, 128 * 1024)
    source_sha = receiver.sha(source)
    envelope = receiver.canonical({"receiver_source_b64": base64.b64encode(source).decode("ascii"),
                                   "payload": payload})
    receiver.require(len(envelope) <= MAX_PAYLOAD, "transport exceeds payload bound")
    plan = {"schema": "macws.diagnostic-probe.delivery-plan.v1", "bundle_manifest_sha256": MANIFEST_SHA256,
            "pipeline_source_sha256": receiver.sha(read_regular(Path(__file__))),
            "receiver_source_sha256": source_sha, "envelope_sha256": receiver.sha(envelope),
            "architecture": "arm64", "provenance_files_verified": len(rows),
            "payload_files": [{"name": name, "path": parent + "/" + directory + "/" + name,
                               "mode": format(mode, "04o"), "sha256": next(row["sha256"] for row in rows if row["name"] == name)}
                              for name, (parent, directory, mode) in receiver.SELECTED.items()],
            "probe_signature_host_verified": signature,
            "transport_bytes": len(envelope), "host_timeout_seconds": 20,
            "receiver_alarm_seconds": 12, "receiver_deadline_seconds": 8,
            "device_commands": 0, "deployments": 0, "trust_mutations": 0,
            "candidate_executions": 0, "controller_executions": 0,
            "native_dependency_closure_currently_verified": False, "current_trust_verified": False,
            "device_acceptance": False, "runtime_accepted": False, "freeze_cause_or_fix_proven": False}
    return plan, envelope


def ssh_options(raw):
    options = json.loads(raw)
    receiver.require(type(options) is list and len(options) <= 64 and all(
        type(part) is str and 0 < len(part) <= 4096 and not any(character in part for character in "\0\r\n")
        for part in options), "SSH options must be a bounded JSON string array")
    at = 0
    while at < len(options):
        option = options[at]
        receiver.require(option in ("-i", "-c", "-o") and at + 1 < len(options),
                         "SSH option can change finite stdin/session contract")
        value = options[at + 1]
        if option == "-i":
            receiver.require(os.path.isabs(value) and not value.startswith("-"), "absolute SSH identity path required")
        elif option == "-c":
            receiver.require(re.fullmatch(r"[A-Za-z0-9@._,+-]+", value) is not None,
                             "invalid explicit SSH cipher list")
        else:
            key, separator, setting = value.partition("=")
            valid = bool(separator) and (
                (key == "ConnectTimeout" and setting.isdigit() and 1 <= int(setting) <= 8) or
                (key == "ServerAliveInterval" and setting.isdigit() and 1 <= int(setting) <= 15) or
                (key == "ServerAliveCountMax" and setting.isdigit() and 1 <= int(setting) <= 3) or
                (key in ("IdentitiesOnly", "BatchMode") and setting == "yes") or
                (key == "StrictHostKeyChecking" and setting in ("yes", "accept-new")) or
                (key == "UserKnownHostsFile" and os.path.isabs(setting)))
            receiver.require(valid, "SSH setting can change finite stdin/session contract")
        at += 2
    return options


def validate_receipt(report, plan, exit_code):
    receiver.require(report["schema"] == "macws.diagnostic-probe.delivery.private.v1"
                     and report["receiver_sha256"] == plan["receiver_source_sha256"]
                     and report["bundle_manifest_sha256"] == MANIFEST_SHA256,
                     "receiver receipt identity differs")
    for field in ("candidate_executions", "controller_executions", "trust_mutations"):
        receiver.require(type(report.get(field)) is int and report[field] == 0,
                         "unexpected execution/trust receipt")
    for field in ("native_dependency_closure_currently_verified", "current_trust_verified",
                  "device_acceptance", "runtime_accepted", "freeze_cause_or_fix_proven",
                  "automatic_cleanup_attempted"):
        receiver.require(report.get(field) is False, "unexpected acceptance/cleanup claim")
    receiver.require(type(report.get("installation_verified")) is bool, "invalid installation receipt")
    if not report["installation_verified"]:
        receiver.require(exit_code != 0, "successful SSH without verified installation")
        return
    receiver.require(exit_code == 0 and "refusal" not in report, "installation exit/refusal differs")
    expected = {row["name"]: row for row in plan["payload_files"]}
    rows = report["installed_files_private"]
    receiver.require(len(rows) == len(expected) and {row["name"] for row in rows} == set(expected),
                     "installed receipt file set differs")
    for row in rows:
        wanted = expected[row["name"]]
        observed = row["stat"]
        receiver.require(row["path"] == wanted["path"] and row["sha256"] == wanted["sha256"]
                         and row["previously_absent"] is True
                         and row["new_vnode_created_exclusively"] is True
                         and observed["mode"] == int(wanted["mode"], 8)
                         and observed["uid"] == 0 and observed["nlink"] == 1
                         and type(observed["dev"]) is int and type(observed["ino"]) is int
                         and observed["ino"] > 0, "installed receipt metadata differs")
    parents = report["parents_private"]
    receiver.require(len(parents) == 2 and {row["logical"] for row in parents}
                     == {receiver.PROBE_PARENT, receiver.CONTROLLER_PARENT}
                     and all(row["target_previously_absent"] is True for row in parents),
                     "destination absence receipt differs")
    receiver.require(report["probe_signature"] == plan["probe_signature_host_verified"],
                     "installed probe signature receipt differs")


def install(plan, envelope, *, device, port, options, timeout=20, run=subprocess.run):
    options = ssh_options(json.dumps(options))
    receiver.require(type(device) is str and 0 < len(device) <= 255 and not device.startswith("-")
                     and not any(character.isspace() or character == "\0" for character in device),
                     "explicit SSH device required")
    receiver.require(type(port) is int and 1 <= port <= 65535, "invalid SSH port")
    receiver.require(type(timeout) in (int, float) and 0 < timeout <= 20, "host timeout must be <=20 seconds")
    receiver.require(receiver.sha(envelope) == plan["envelope_sha256"], "prepared envelope changed")
    command = shlex.join(["/var/jb/usr/bin/python3", "-c", SSH_BOOTSTRAP,
                          plan["receiver_source_sha256"], plan["envelope_sha256"]])
    arguments = ["ssh", "-F", "/dev/null", "-T", *options, "-p", str(port), "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                 "-o", "ClearAllForwardings=yes", "-o", "ControlMaster=no", "-o", "RequestTTY=no",
                 "-o", "StdinNull=no", "-o", "ForkAfterAuthentication=no", "-o", "RemoteCommand=none",
                 "-o", "ServerAliveInterval=3", "-o", "ServerAliveCountMax=1", device, command]
    started = time.monotonic()
    result = run(arguments, input=envelope, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                 timeout=timeout, check=False)
    receiver.require(len(result.stdout) <= MAX_PAYLOAD and len(result.stderr) <= 65536,
                     "transport output exceeds bound")
    report = receiver.decode_json(result.stdout)
    validate_receipt(report, plan, result.returncode)
    report["host_private"] = {"pipeline_source_sha256": plan["pipeline_source_sha256"],
                              "envelope_sha256": plan["envelope_sha256"],
                              "host_timeout_seconds": timeout, "duration_seconds": time.monotonic() - started,
                              "ssh_exit": result.returncode, "stderr_sha256": receiver.sha(result.stderr),
                              "stderr_bytes": len(result.stderr)}
    return report, result.returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-bundle", required=True)
    parser.add_argument("--architecture", choices=["arm64"], default="arm64")
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--device", default=os.environ.get("MACWS_DEVICE"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("MACWS_DEVICE_PORT", "22")))
    parser.add_argument("--ssh-options-json", default=os.environ.get("MACWS_DIAGNOSTIC_SSH_OPTIONS_JSON", "[]"),
                        help="Explicit JSON SSH argument array; existing identity/known-host options belong here")
    parser.add_argument("--host-timeout", type=float, default=20)
    args = parser.parse_args(argv)
    try:
        plan, envelope = prepare_bundle(args.probe_bundle)
        if not args.install:
            print(json.dumps(plan, sort_keys=True))
            return 0
        report, code = install(plan, envelope, device=args.device, port=args.port,
                               options=ssh_options(args.ssh_options_json), timeout=args.host_timeout)
        print(json.dumps(report, sort_keys=True))  # PRIVATE: caller captures stdout.
        return 0 if code == 0 and report.get("installation_verified") is True else 1
    except (OSError, ValueError, KeyError, receiver.Refused, subprocess.SubprocessError) as error:
        print(json.dumps({"schema": "macws.diagnostic-probe.delivery-host-refusal.v1",
                          "refusal": type(error).__name__ + ": " + str(error),
                          "installation_verified": False, "device_acceptance": False,
                          "runtime_accepted": False, "automatic_cleanup_attempted": False}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
