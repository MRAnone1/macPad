"""Explicit-input, offline v7 session projection. Default prints metadata only.

No nonce, time, native witness or transport is generated. The result preserves
the original supplied bytes; native execute must establish current freshness.
"""
import ast
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import types

SOURCES = {
    "runtime_support.py": "5d09cf9380afaa2409661a58909d1bfee41d81943f1b2306facb0cd94ee10fe0",
    "watchdog.py": "c28ec9edd30bf86613c7cb29693697901228b579100b8b181a4dc47915f00e0a",
    "controller.py": "955c50b5cb2b30b8f0aefd69720675d04c91126dec17c802fb09be8c42197977",
}
QA_SHA = "ebee0b881b5f589c4ca100c5dbcd4c72faa946b0bf741511a7396138139ae29c"
PREPARER_SHA = "e62d029d18db87cd83cd77dca10300fe9c99f9ac2d48b7e1a977423cf85b51dd"
PIPELINE_SHA = "0d310c1c733807c810d867ccb04def8467f26fada6fcdf27b299f1ea6df9848e"
RECEIVER_SHA = "1d4a9f515b7884ead3326f39d35cc639e1e2972048e2f26a1f73033af3100463"
MANIFEST_SHA = "d2c843dc9930b28342c9b57d11bbee2bbe12202b1147dec11137106646d13263"
OBSERVER_SHA = "717de31eb1d7a05ed363eca7c3dce0dbd7f4ff500bb8cb65377bd340babf1c7a"
OBSERVER_INPUT_SHA = "f7261fcf3e6c47493e92f8b04396316acf9d3f66b229d77a85cc0f95ffa6f280"
SIGNED_MANIFEST_SHA = "a49c6c33f585e591d894046c5c76c314bd14aa506dca6f6e89366a8eda56fb71"
ROOTFS = "/private/var/mnt/rootfs"
CONTROLLER_DIRECTORY = "/var/jb/usr/libexec/macws-swap-pair-controller-20261018"
CANDIDATE = {"path": ROOTFS + "/usr/local/libexec/macws-swap-pair-probe-20261017/probe.arm64",
             "sha256": "7e60e45736d93386f667b9009d0b2e8ea81ab38c0479294ec98019fd655af886",
             "architecture": "arm64", "uuid": "9b8378ef-aab0-3e72-b8e3-8e1b56c9a647",
             "cdhash": "6665b5a54da06153a5940368788cdb9b6e9be3dc"}
DEPENDENCIES = {
    "wrapper": {"path": "/var/jb/usr/libexec/macws-windowserver-preflight-20261007/launchdchrootexec_fullframe_streamgate_20261009",
                "sha256": "e7f1d9e9966826022372248a308c2e28126758a97057ada43551c1a206549d20", "architecture": "arm64", "uuid": "bf207849-42b2-3a26-b431-a04b0f42818d"},
    "hook_arm64": {"path": ROOTFS + "/usr/local/lib/libmachook_fullframe_streamgate_20261009_arm64.dylib",
                   "sha256": "bcd544a537fc81cbc16ec3fb8de2c7677708d35ada10c0caf044ba83f005340b", "architecture": "arm64", "uuid": "2552c7f2-0946-3525-9771-d6d48b44c0e9"},
    "hook_arm64e": {"path": ROOTFS + "/usr/local/lib/libmachook_fullframe_streamgate_20261009.dylib",
                    "sha256": "803bcccf8cb9afd8d3b96bdbe88ca13d79463e6a09f2c192d346bc5300541008", "architecture": "arm64e", "uuid": "8d9d059f-f308-3a07-be9e-bb23123ba997"},
}
LABELS = ("com.macws.preflight.swap-pair.20261017", "com.macws.preflight.swap-pair-control.20261018")
SCRATCH = ("/private/var/tmp/macws-swap-pair-20261017", "/private/var/tmp/macws-swap-pair-control-20261018")
STAT_FIELDS = ("dev", "ino", "size", "mtime_ns", "ctime_ns")


def need(condition, message):
    if condition is not True:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, allow_nan=False, separators=(",", ":")).encode()


def finite(value):
    try:
        need(type(value) in (int, float) and math.isfinite(value) and value >= 0, "finite observed time required")
    except OverflowError as error:
        raise ValueError("unrepresentable observed time") from error
    return value


def decode(raw, limit):
    need(type(raw) is bytes and 0 < len(raw) <= limit, "explicit bounded raw JSON required")
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    def constant(_): raise ValueError("nonfinite JSON constant")
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except RecursionError as error:
        raise ValueError("JSON nesting bound") from error
    need(type(value) is dict, "JSON object required")
    # Also reject overflowed JSON floats anywhere in the supplied object.
    canonical(value)
    return value


def read_pin(path, expected):
    need(path is not None, "explicit pinned source path required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 128 * 1024, "bounded single-link source")
        data = bytearray()
        while len(data) <= before.st_size:
            block = os.read(fd, min(65536, before.st_size + 1 - len(data)))
            if not block: break
            data.extend(block)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        need(len(data) == before.st_size and all(getattr(before, k) == getattr(after, k) for k in fields) and sha(data) == expected,
             "pinned source bytes/token changed")
        return bytes(data)
    finally:
        os.close(fd)


def metadata():
    return {"schema": "macws.swap-pair.session-projector-default.v7", "device_commands": 0,
            "native_calls": 0, "network_calls": 0, "session_created": False,
            "nonce_generated": False, "current_device_freshness_claimed": False, "device_acceptance": False}


def project_session(*, observer_raw, delivery_raw, delivery_plan_raw, delivery_exit, qa_raw, run_nonce,
                    source_directory, qa_path, preparer_path, pipeline_path):
    """Return projected values and original bytes; perform no native/clock/write.

    Input provenance remains the caller's responsibility. Structural consistency
    never authenticates JSON or establishes its age relative to a current clock.
    """
    need(type(run_nonce) is str and re.fullmatch("[0-9a-f]{32}", run_nonce) is not None, "explicit external nonce required")
    need(type(delivery_exit) is int and delivery_exit == 0, "validated successful delivery exit required")
    observed, delivery, plan, qa = (decode(raw, limit) for raw, limit in ((observer_raw, 512 * 1024), (delivery_raw, 65536), (delivery_plan_raw, 65536), (qa_raw, 65536)))
    need(sha(qa_raw) == QA_SHA and canonical(qa) == qa_raw, "exact canonical v7 QA bytes required")
    need(source_directory is not None and qa_path is not None, "explicit runtime/QA paths required")
    source_directory = Path(source_directory)
    # Every own-source and QA pin is checked before executing module code.
    source_blobs = {name: read_pin(source_directory / name, digest) for name, digest in SOURCES.items()}
    need(read_pin(qa_path, QA_SHA) == qa_raw, "canonical QA path/raw mismatch")
    preparer_blob = read_pin(preparer_path, PREPARER_SHA)
    pipeline_blob = read_pin(pipeline_path, PIPELINE_SHA)
    need(plan.get("schema") == "macws.diagnostic-probe.delivery-plan.v1" and
         plan.get("bundle_manifest_sha256") == MANIFEST_SHA and plan.get("pipeline_source_sha256") == PIPELINE_SHA and
         plan.get("receiver_source_sha256") == RECEIVER_SHA and plan.get("architecture") == "arm64" and
         type(plan.get("provenance_files_verified")) is int and plan["provenance_files_verified"] == 41,
         "exact validated pipeline plan required")
    function_nodes = [node for node in ast.parse(pipeline_blob).body if isinstance(node, ast.FunctionDef) and node.name == "validate_receipt"]
    need(len(function_nodes) == 1, "one pinned pure delivery validator required")
    receiver = types.SimpleNamespace(require=need, PROBE_PARENT=ROOTFS + "/usr/local/libexec", CONTROLLER_PARENT="/var/jb/usr/libexec")
    namespace = {"receiver": receiver, "MANIFEST_SHA256": MANIFEST_SHA}
    exec(compile(ast.fix_missing_locations(ast.Module(body=function_nodes, type_ignores=[])), "<pinned-pure-delivery-validator>", "exec"), namespace)
    namespace["validate_receipt"](delivery, plan, delivery_exit)
    need(delivery.get("installation_verified") is True, "verified installation required")
    expected = {"probe.arm64": (CANDIDATE["path"], CANDIDATE["sha256"], 0o755),
                "offline-QA.canonical.private.json": (CONTROLLER_DIRECTORY + "/offline-QA.canonical.private.json", QA_SHA, 0o600)}
    expected.update({name: (CONTROLLER_DIRECTORY + "/" + name, digest, 0o600) for name, digest in SOURCES.items()})
    rows = delivery["installed_files_private"]
    need(type(rows) is list and len(rows) == 5 and len({row["name"] for row in rows}) == 5 and {row["name"] for row in rows} == set(expected), "exact five delivered files")
    indexed = {row["name"]: row for row in rows}
    for name, (path, digest, mode) in expected.items():
        row = indexed[name]; info = row["stat"]
        need(row["path"] == path and row["sha256"] == digest and row["previously_absent"] is True and row["new_vnode_created_exclusively"] is True, "exclusive delivered file binding")
        need(all(type(info.get(k)) is int and info[k] >= 0 for k in (*STAT_FIELDS, "mode", "uid", "gid", "nlink")) and
             info["ino"] > 0 and info["size"] > 0 and info["uid"] == 0 and info["nlink"] == 1 and info["mode"] == mode,
             "typed delivered stat token/mode/owner")
        if name in source_blobs: need(info["size"] == len(source_blobs[name]), "delivered source size differs")
    need(observed.get("schema") == "macws.swap-pair.read-only-admission-observations.v4" and
         observed.get("observer_source_sha256") == OBSERVER_SHA and observed.get("inputs_sha256") == OBSERVER_INPUT_SHA and
         observed.get("controller_source_sha256") == SOURCES and observed.get("signed_artifact_manifest_sha256") == SIGNED_MANIFEST_SHA and
         observed.get("launchd_domain") == "user/501", "exact v4 source-bound observer required")
    for field in ("mutations", "candidate_executions", "launchd_mutations", "trust_mutations"):
        need(type(observed.get(field)) is int and observed[field] == 0, "observer mutation/execution report")
    for field in ("fully_admitted", "runtime_accepted", "device_acceptance", "runtime_controls_verified", "freshness_verified"):
        need(observed.get(field) is False, "observer must remain non-authoritative")
    need(observed.get("new_vnode") is None and observed.get("observation_completed") is True and
         observed.get("observed_baseline_checks_passed") is True and observed.get("refusals") == [] and observed.get("finalization_refusals") == [],
         "complete clean observer witness required")
    checks = observed.get("checks")
    check_names = {"exact_device_build", "same_boot", "same_UI_generations", "nominal_thermal", "no_blocked_workloads", "both_scratch_absent",
                   "both_job_labels_absent", "same_trust_membership_set", "stable_file_observations", "candidate_present_identity_trusted", "frozen_dependencies_present_identity_trusted"}
    need(type(checks) is dict and set(checks) == check_names and all(x is True for x in checks.values()), "all exact observer baseline checks required")
    before, after = observed["metadata_before_private"], observed["metadata_after_private"]
    need(type(before) is dict and before == after and before.get("hw.machine") == "iPad13,6" and before.get("kern.osversion") == "20E252" and
         before.get("kern.uuid", "").lower() == "d6b9e234-64f1-30ea-ae62-ed8f2dc6efdb" and before.get("rootfs_product_version") == "13.4" and before.get("rootfs_product_build") == "22F66",
         "stable exact device/rootfs/boot metadata")
    proc_before, proc_after = observed["process_before_private"], observed["process_after_private"]
    need(canonical(proc_before["UI_private"]) == canonical(proc_after["UI_private"]) and proc_before["blocked_private"] == proc_after["blocked_private"] == [] and
         type(observed["thermal_before"]) is int and type(observed["thermal_after"]) is int and observed["thermal_before"] == observed["thermal_after"] == 0,
         "stable UI/no workloads/nominal thermal")
    for group in ("jobs_before_private", "jobs_after_private"):
        jobs = observed[group]; need(type(jobs) is dict and set(jobs) == set(LABELS), "both fixed labels required")
        for label, result in jobs.items():
            need(type(result) is list and len(result) == 3 and type(result[0]) is int and result[0] == 113 and result[1] == "" and
                 result[2] == 'Could not find service "' + label + '" in domain for uid: 501\n', "exact user/501 absence result required")
    for group in ("scratch_before", "scratch_after"):
        need(type(observed[group]) is dict and set(observed[group]) == set(SCRATCH) and all(x is True for x in observed[group].values()), "both scratch directories absent")
    trusted = observed["trust_after_private"]
    need(type(trusted) is list and trusted == observed["trust_before_private"] and len(trusted) == len(set(trusted)) and
         all(type(x) is str and re.fullmatch("[0-9a-f]{40}", x) is not None for x in trusted), "stable current trust set")
    files = observed["files_after_private"]
    need(type(files) is dict and canonical(files) == canonical(observed["files_before_private"]) and set(files) == set(DEPENDENCIES) | {"candidate"}, "stable exact observed file set")
    for name, identity in {**DEPENDENCIES, "candidate": CANDIDATE}.items():
        item = files[name]
        need(all(item.get(k) == v for k, v in identity.items()) and all(item.get(k) is True for k in ("present", "identity_verified", "trust_member", "page_hashes_valid")) and
             item.get("cdhash") in trusted and type(item.get("signed_pages_checked")) is int and item["signed_pages_checked"] > 0 and
             type(item.get("code_limit")) is int and item["code_limit"] > 0 and type(item.get("hash_type")) is int and item["hash_type"] == 2,
             "current exact identity/pages/trust required")
    candidate = files["candidate"]
    probe_token = [indexed["probe.arm64"]["stat"][k] for k in STAT_FIELDS]
    need(type(candidate.get("stat_token_private")) is list and len(candidate["stat_token_private"]) == 5 and
         all(type(x) is int and x >= 0 for x in candidate["stat_token_private"]) and candidate["stat_token_private"] == probe_token and
         observed.get("candidate_observation") == "candidate-identity-and-current-trust-poststage",
         "fresh exclusive delivery/current candidate token differs")
    signature = delivery["probe_signature"]
    need(all(signature.get(k) == candidate.get(k) for k in ("architecture", "uuid", "cdhash", "hash_type", "signed_pages_checked", "code_limit", "page_hashes_valid")),
         "observed candidate signature differs from validated delivery")
    need(signature.get("page_hashes_valid") is True and all(type(signature.get(k)) is int and signature[k] > 0 for k in ("hash_type", "signed_pages_checked", "code_limit")),
         "typed validated delivery signature required")
    observed_time = finite(observed.get("finished_monotonic_private"))
    need(finite(observed["started_monotonic"]) <= observed_time, "observer time order")
    need(type(observed.get("budget")) is dict and 0 <= finite(observed["budget"].get("elapsed_seconds")) <= 8, "complete bounded observer budget")
    tokens = {name: {key: indexed[name]["stat"][key] for key in STAT_FIELDS} for name in SOURCES}
    module = types.ModuleType("_source_pinned_v7r2_preparation"); module.__file__ = str(preparer_path)
    exec(compile(preparer_blob, str(preparer_path), "exec"), module.__dict__)
    support, blobs = module.pinned_support(source_directory=source_directory, qa_path=qa_path, tokens=tokens)
    config = {"schema": "macws.swap-pair.live-config.v7", "operation": "run", "arch": "arm64", "run_nonce": run_nonce,
              "profile_sha256": support.PROBE_PROFILE_SHA256, "loaded_hook_profile_sha256": support.PROBE_PROFILE_SHA256,
              "signed_probe_sha256": candidate["sha256"], "signed_probe_uuid": candidate["uuid"], "signed_probe_cdhash": candidate["cdhash"],
              "installed_probe_token": probe_token, "boot_private": after["kern.bootsessionuuid"], "UI_private": proc_after["UI_private"],
              "source_sha256": dict(SOURCES), "active_seconds": 10, "cleanup_seconds": 8, "candidate_limits": dict(support.PROBE_LIMITS),
              "offline_QA_sha256": QA_SHA, "clock_info": observed["clock_info"]}
    witnesses = {"signed_artifact": {"delivery_raw_sha256": sha(delivery_raw), "delivery_plan_raw_sha256": sha(delivery_plan_raw),
                                     "observer_raw_sha256": sha(observer_raw), "exclusive_delivery_row": indexed["probe.arm64"],
                                     "current_candidate_observation": candidate, "trust_basis": "current-observed-membership; no admission mutation"},
                 "loaded_hook_profile": {"observer_raw_sha256": sha(observer_raw), "before": observed["files_before_private"]["hook_arm64"], "after": files["hook_arm64"]}}
    common = {"run_nonce": run_nonce, "admission_sha256": support.admission_sha(config), "source_sha256": dict(SOURCES), "boot_private": config["boot_private"],
              "observed_monotonic": observed_time, "clock_info": config["clock_info"], "evidence_kind": "copied-native-runtime"}
    preflight = dict(common, schema="macws.swap-pair.native-preflight.v1", UI_private=config["UI_private"], thermal="nominal", label_absent=True, scratch_absent=True,
                     raw_sha256=sha(observer_raw))
    artifact = dict(common, schema="macws.swap-pair.installed-signed-artifact.v1", path=support.executable(config), sha256=candidate["sha256"], uuid=candidate["uuid"], cdhash=candidate["cdhash"],
                    stat_token=probe_token, new_vnode=True, trust_member=True, source_profile_sha256=support.PROBE_PROFILE_SHA256,
                    unsigned_sha256=support.PROBE_BUILDS["arm64"][0], probe_source_sha256=support.PROBE_SOURCE_SHA256, build_receipt_sha256=support.PROBE_BUILD_RECEIPT_SHA256,
                    raw_sha256=sha(canonical(witnesses["signed_artifact"])))
    hook = dict(common, schema="macws.swap-pair.loaded-hook-profile-preparation.v1", profile_sha256=support.PROBE_PROFILE_SHA256, architecture="arm64",
                hook_path=support.HOOKS["arm64"][0], hook_sha256=files["hook_arm64"]["sha256"], raw_sha256=sha(canonical(witnesses["loaded_hook_profile"])))
    receipts = {"schema": "macws.swap-pair.live-prerequisites.v7", "preflight": preflight, "signed_artifact": artifact, "loaded_hook_profile": hook,
                "offline_QA": {"receipt": qa, "raw_sha256": QA_SHA}, "native_controls": {}}
    module.structural_inputs(config, receipts, tokens, support, blobs)
    originals = {"observer": observer_raw, "delivery": delivery_raw, "delivery_plan": delivery_plan_raw, "canonical_QA": qa_raw}
    return {"schema": "macws.swap-pair.session-projection.v7", "config": config, "prerequisites": receipts, "tokens": tokens,
            "copied_witnesses": witnesses, "original_inputs_private_b64": {name: base64.b64encode(raw).decode() for name, raw in originals.items()},
            "original_inputs_sha256": {name: sha(raw) for name, raw in originals.items()}, "device_commands": 0, "native_calls": 0, "network_calls": 0,
            "nonce_generated": False, "session_files_created": False, "current_device_freshness_claimed": False, "evidence_authenticity_proven": False,
            "device_acceptance": False, "trust_basis": "current-observed-membership; no admission mutation"}


def main(argv=None):
    need(argv is None or argv == [], "default metadata only; explicit project_session API required")
    print(json.dumps(metadata(), sort_keys=True))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
