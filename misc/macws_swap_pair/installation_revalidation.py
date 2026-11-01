"""Offline evidence for a copied dev-only installation-token change.

Only the explicit revalidate() API consumes bytes. It neither reads paths nor
provides a session, trust, cleanup, execution, or ownership capability. External
hash pins belong to the trusted caller; matching JSON/hashes does not authenticate
a native witness or establish freshness. The original negative audit is retained.
"""
import base64
import binascii
import hashlib
import json
import math
import re


STAT_FIELDS = ("dev", "ino", "size", "mtime_ns", "ctime_ns", "mode", "uid", "gid", "nlink")
PARENT_FIELDS = ("dev", "ino", "mode", "uid", "gid")
META_FIELDS = ("hw.machine", "kern.osversion", "kern.uuid", "kern.bootsessionuuid")
SOURCE_NAMES = {"audit_worker", "readonly_observer", "retained_cleanup", "retained_observer"}
ROOTFS_PARENT = "/private/var/mnt/rootfs/usr/local/libexec"
ROOTLESS_PARENT = "/var/jb/usr/libexec"
PROBE_DIRECTORY = "macws-swap-pair-probe-20261017"
CONTROLLER_DIRECTORY = "macws-swap-pair-controller-20261018"
FILE_NAMES = ("probe.arm64", "controller.py", "runtime_support.py", "watchdog.py", "offline-QA.canonical.private.json")
MANIFEST_SHA = "d2c843dc9930b28342c9b57d11bbee2bbe12202b1147dec11137106646d13263"
RECEIVER_SHA = "1d4a9f515b7884ead3326f39d35cc639e1e2972048e2f26a1f73033af3100463"
PIPELINE_SHA = "0d310c1c733807c810d867ccb04def8467f26fada6fcdf27b299f1ea6df9848e"
KERNEL_UUID = "d6b9e234-64f1-30ea-ae62-ed8f2dc6efdb"
PROBE_SIGNATURE = {"architecture": "arm64", "uuid": "9b8378ef-aab0-3e72-b8e3-8e1b56c9a647",
                   "cdhash": "6665b5a54da06153a5940368788cdb9b6e9be3dc", "hash_type": 2,
                   "signed_pages_checked": 5, "code_limit": 69584, "page_hashes_valid": True}
EFFECTS = {"file_writes", "file_unlinks", "directory_creations", "directory_removals", "trust_changes",
           "job_changes", "process_execution", "configuration_changes", "cleanup", "new_session"}
MAX_AUDIT_BYTES = 512 * 1024
MAX_FILE_BYTES = 128 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 512 * 1024


class Refused(ValueError):
    """Categorical refusal; copied identifiers are not interpolated."""


def need(value, reason):
    if value is not True:
        raise Refused(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    need(type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None, "sha256_word")
    return value


def exact_keys(value, fields):
    need(type(value) is dict and set(value) == set(fields), "exact_object_fields")


def integer(value, *, minimum=0, maximum=(1 << 63) - 1):
    need(type(value) is int and minimum <= value <= maximum, "strict_bounded_integer")
    return value


def _tree(value, depth=0, budget=None):
    budget = [10000, MAX_AUDIT_BYTES] if budget is None else budget
    budget[0] -= 1
    need(depth <= 16 and budget[0] >= 0, "bounded_json_tree")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        need(-(1 << 63) <= value < (1 << 63), "bounded_json_integer")
        return
    if type(value) is float:
        need(math.isfinite(value), "finite_json_number")
        return
    if type(value) is str:
        try:
            length = len(value.encode("utf-8"))
        except UnicodeError as error:
            raise Refused("valid_json_unicode") from error
        budget[1] -= length
        need(length <= MAX_AUDIT_BYTES and budget[1] >= 0, "bounded_json_strings")
        return
    if type(value) is list:
        need(len(value) <= 4096, "bounded_json_array")
        for item in value:
            _tree(item, depth + 1, budget)
        return
    need(type(value) is dict and len(value) <= 128 and all(type(k) is str and len(k) <= 128 for k in value),
         "bounded_json_object")
    for key, item in value.items():
        _tree(key, depth + 1, budget)
        _tree(item, depth + 1, budget)


def canonical(value):
    _tree(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def decode(raw, limit):
    need(type(raw) is bytes and 0 < len(raw) <= limit, "explicit_bounded_immutable_json_bytes")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def constant(_):
        raise Refused("finite_json_number")

    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=constant)
        _tree(value)
        need(type(value) is dict, "one_json_object")
        return value
    except Refused:
        raise
    except (ValueError, UnicodeError, RecursionError, OverflowError) as error:
        raise Refused("valid_bounded_json") from error


def physical_path(value):
    need(type(value) is str and 1 < len(value) <= 1024 and value.startswith("/") and
         value.isascii() and all(32 < ord(c) < 127 for c in value), "literal_physical_path")
    need(all(part not in ("", ".", "..") for part in value[1:].split("/")) and
         not (value == "/var" or value.startswith("/var/") or value == "/private/var/jb" or
              value.startswith("/private/var/jb/")), "no_implicit_path_alias")
    return value


def stat9(value):
    exact_keys(value, STAT_FIELDS)
    for field in STAT_FIELDS:
        integer(value[field])
    need(value["ino"] > 0 and value["nlink"] > 0 and value["mode"] <= 0o7777, "stat9_identity_and_mode")
    return value


def names(value):
    need(type(value) is list and len(value) <= 4096 and all(type(n) is str for n in value), "bounded_name_list")
    need(value == sorted(set(value)), "sorted_unique_names")
    for name in value:
        need(name not in ("", ".", "..") and "/" not in name and "\0" not in name and
             len(name.encode("utf-8")) <= 255, "literal_child_name")
    need(len(canonical(value)) <= 32 * 1024, "bounded_name_bytes")
    return value


def binding(value):
    exact_keys(value, META_FIELDS)
    need(all(type(v) is str and 0 < len(v) <= 128 and v.isascii() and
             all(32 <= ord(c) < 127 for c in v) for v in value.values()), "copied_metadata_strings")
    need(value["hw.machine"] == "iPad13,6" and value["kern.osversion"] == "20E252" and
         value["kern.uuid"].lower() == KERNEL_UUID and
         re.fullmatch("[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value["kern.bootsessionuuid"]) is not None,
         "exact_device_profile_and_copied_boot")
    return dict(value)


def no_effects(value, counters, false_fields, true_fields=()):
    for key in counters:
        need(type(value.get(key)) is int and value[key] == 0, "zero_effect_counter")
    for key in false_fields:
        need(value.get(key) is False, "false_authority_or_effect_flag")
    for key in true_fields:
        need(value.get(key) is True, "complete_read_only_flag")


def _delivery(value):
    exact_keys(value, {"automatic_cleanup_attempted", "bundle_manifest_sha256", "candidate_executions", "controller_executions",
        "created_directories_private", "current_trust_verified", "device_acceptance", "duration_seconds", "freeze_cause_or_fix_proven",
        "host_private", "installation_verified", "installed_files_private", "native_dependency_closure_currently_verified",
        "parents_private", "probe_signature", "receiver_sha256", "runtime_accepted", "schema", "trust_mutations"})
    need(value["schema"] == "macws.diagnostic-probe.delivery.private.v1" and value["bundle_manifest_sha256"] == MANIFEST_SHA and
         value["receiver_sha256"] == RECEIVER_SHA, "original_delivery_schema_and_pipeline")
    no_effects(value, ("candidate_executions", "controller_executions", "trust_mutations"),
        ("automatic_cleanup_attempted", "current_trust_verified", "device_acceptance", "freeze_cause_or_fix_proven",
         "native_dependency_closure_currently_verified", "runtime_accepted"), ("installation_verified",))
    need(type(value["duration_seconds"]) in (int, float) and 0 <= value["duration_seconds"] <= 20, "original_delivery_duration")
    host = value["host_private"]
    exact_keys(host, ("duration_seconds", "envelope_sha256", "host_timeout_seconds", "pipeline_source_sha256", "ssh_exit", "stderr_bytes", "stderr_sha256"))
    digest(host["envelope_sha256"])
    need(host["pipeline_source_sha256"] == PIPELINE_SHA and type(host["duration_seconds"]) in (int, float) and
         0 <= host["duration_seconds"] <= 20 and type(host["host_timeout_seconds"]) is int and host["host_timeout_seconds"] == 20,
         "original_delivery_host_binding")
    need(type(host["ssh_exit"]) is int and host["ssh_exit"] == 0 and type(host["stderr_bytes"]) is int and host["stderr_bytes"] == 0 and
         host["stderr_sha256"] == sha(b""), "successful_quiet_original_delivery")
    signature = value["probe_signature"]
    exact_keys(signature, PROBE_SIGNATURE)
    need(all(type(signature[k]) is type(v) and signature[k] == v for k, v in PROBE_SIGNATURE.items()), "original_probe_signature_profile")

    parents = value["parents_private"]
    need(type(parents) is list and len(parents) == 2, "two_original_parents")
    indexed = {}
    for row in parents:
        exact_keys(row, ("logical", "resolved", "stat", "target_previously_absent"))
        need(type(row["logical"]) is str and row["logical"] in (ROOTFS_PARENT, ROOTLESS_PARENT) and row["logical"] not in indexed,
             "distinct_original_parent_scope")
        physical_path(row["resolved"])
        stat9(row["stat"])
        need(row["target_previously_absent"] is True and row["stat"]["mode"] == 0o755 and
             row["stat"]["uid"] == row["stat"]["gid"] == 0, "original_parent_owner_mode_absence")
        indexed[row["logical"]] = row
    need(indexed[ROOTFS_PARENT]["resolved"] == ROOTFS_PARENT and indexed[ROOTLESS_PARENT]["resolved"].endswith("/usr/libexec"),
         "original_resolved_parent_scope")
    rootless = indexed[ROOTLESS_PARENT]["resolved"][:-len("/usr/libexec")]
    need(rootless.startswith("/private/preboot/") and rootless.endswith("/procursus"), "original_physical_rootless_root")
    directory_paths = (ROOTFS_PARENT + "/" + PROBE_DIRECTORY, ROOTLESS_PARENT + "/" + CONTROLLER_DIRECTORY)

    def physical(path):
        if path.startswith("/var/jb/"):
            return rootless + path[len("/var/jb"):]
        return physical_path(path)

    directories = value["created_directories_private"]
    need(type(directories) is list and len(directories) == 2, "two_original_created_directories")
    seen = set()
    for row in directories:
        exact_keys(row, ("path", "stat"))
        need(type(row["path"]) is str and row["path"] in directory_paths and row["path"] not in seen, "distinct_original_directories")
        stat9(row["stat"])
        need(row["stat"]["mode"] == 0o700 and row["stat"]["uid"] == row["stat"]["gid"] == 0, "original_directory_owner_mode")
        seen.add(row["path"])
    files = value["installed_files_private"]
    need(type(files) is list and len(files) == 5, "five_original_delivered_files")
    seen = set()
    for row in files:
        exact_keys(row, ("name", "path", "sha256", "stat", "previously_absent", "new_vnode_created_exclusively"))
        name = row["name"]
        need(type(name) is str and name in FILE_NAMES and name not in seen, "distinct_fixed_original_file_names")
        need(row["path"] == directory_paths[0 if name == "probe.arm64" else 1] + "/" + name and
             row["previously_absent"] is True and row["new_vnode_created_exclusively"] is True, "original_exclusive_file_row")
        stat9(row["stat"])
        need(row["stat"]["mode"] == (0o755 if name == "probe.arm64" else 0o600) and
             row["stat"]["uid"] == row["stat"]["gid"] == 0 and row["stat"]["nlink"] == 1 and
             0 < row["stat"]["size"] <= MAX_FILE_BYTES, "original_file_owner_mode_size_links")
        digest(row["sha256"])
        seen.add(name)
    return rootless, physical


def _transport(value, audit_raw):
    exact_keys(value, ("capture_complete", "local_cleanup_errors_private", "output_limit_exceeded", "remote_effects_known_from_transport",
        "returncode", "schema", "stderr_bytes_captured", "stderr_sha256", "stdin_complete", "stdout_bytes_captured", "stdout_sha256",
        "timed_out", "trusted_transport_contract_checked"))
    need(value["schema"] == "macws.retained-capturer.transport.v1", "transport_schema")
    no_effects(value, (), ("output_limit_exceeded", "remote_effects_known_from_transport", "timed_out"),
               ("capture_complete", "stdin_complete", "trusted_transport_contract_checked"))
    need(type(value["returncode"]) is int and value["returncode"] == 1 and value["local_cleanup_errors_private"] == [],
         "complete_negative_transport")
    need(type(value["stderr_bytes_captured"]) is int and value["stderr_bytes_captured"] == 0 and value["stderr_sha256"] == sha(b"") and
         type(value["stdout_bytes_captured"]) is int and value["stdout_bytes_captured"] == len(audit_raw) and value["stdout_sha256"] == sha(audit_raw),
         "quiet_exact_audit_stdout_binding")


def metadata():
    return {"schema": "macws.installation-revalidation.default.v1", "default_inert": True,
            "input_bytes_consumed": 0, "device_commands": 0, "native_calls": 0, "network_calls": 0,
            "session_authorized": False, "cleanup_authorized": False, "trust_authorized": False,
            "execution_authorized": False, "installation_ownership_authorized": False,
            "evidence_authenticity_proven": False, "current_device_freshness_claimed": False,
            "historical_volume_continuity_proven": False, "device_acceptance": False}


def revalidate(*, delivery_raw, audit_raw, transport_raw, expected_input_sha256, expected_source_sha256,
               expected_expectation_sha256, expected_current_binding):
    """Describe dev-only changes in externally pinned copied bytes, offline.

    The caller supplies independently selected input/source pins and the copied
    boot/profile binding. The function does not discover or authenticate them.
    No original token is substituted, and no selected token conveys authority.
    """
    exact_keys(expected_input_sha256, ("delivery", "audit", "transport"))
    input_pins = {key: digest(value) for key, value in expected_input_sha256.items()}
    exact_keys(expected_source_sha256, SOURCE_NAMES)
    source_pins = {key: digest(value) for key, value in expected_source_sha256.items()}
    expectation_pin = digest(expected_expectation_sha256)
    current_binding = binding(expected_current_binding)
    original_inputs = {"delivery": delivery_raw, "audit": audit_raw, "transport": transport_raw}
    limits = {"delivery": 65536, "audit": MAX_AUDIT_BYTES, "transport": 16384}
    for key, raw in original_inputs.items():
        need(type(raw) is bytes and 0 < len(raw) <= limits[key] and sha(raw) == input_pins[key], "external_input_hash_pin")
    original, worker, transport = (decode(original_inputs[key], limits[key]) for key in ("delivery", "audit", "transport"))
    rootless, physical = _delivery(original)
    _transport(transport, audit_raw)
    exact_keys(worker, ("audit_completed", "audit_private", "candidate_executions", "cleanup_authorized", "default_inert", "device_acceptance",
        "device_mutations", "error_category", "expectation_sha256", "hard_seconds", "historical_session_admission", "observation_requested",
        "original_delivery_consistent", "schema", "source_sha256", "trust_mutation_commands"))
    need(worker["schema"] == "macws.delivery-readonly-audit.worker.v1" and worker["source_sha256"] == source_pins and
         worker["expectation_sha256"] == expectation_pin and worker["error_category"] is None and
         type(worker["hard_seconds"]) is int and worker["hard_seconds"] == 12, "source_bound_completed_audit_worker")
    no_effects(worker, ("candidate_executions", "device_mutations", "trust_mutation_commands"),
        ("cleanup_authorized", "default_inert", "device_acceptance", "historical_session_admission", "original_delivery_consistent"),
        ("audit_completed", "observation_requested"))
    audit = worker["audit_private"]
    exact_keys(audit, ("anchor_after", "anchor_before", "audit_binding", "audit_completed", "automatic_retry", "candidate_executions",
        "cleanup_authorized", "complete", "controller_executions", "device_acceptance", "device_file_removals", "device_mutations",
        "directories", "effects", "files", "metadata_after", "metadata_before", "new_session_authorized", "old_controller_configuration_modified",
        "old_ownedfiles_authority_reconstructed", "original_delivery_consistent", "original_lineage_matches", "parents", "read_only", "receipt_sha256",
        "refusals", "schema", "source_bytes_copied", "trust_authorized", "trust_mutations"))
    need(audit["schema"] == "macws.delivery-readonly-audit.private.v1" and audit["receipt_sha256"] == input_pins["delivery"], "original_receipt_binding")
    no_effects(audit, ("candidate_executions", "controller_executions", "device_file_removals", "device_mutations", "trust_mutations"),
        ("automatic_retry", "cleanup_authorized", "device_acceptance", "new_session_authorized", "old_controller_configuration_modified",
         "old_ownedfiles_authority_reconstructed", "original_delivery_consistent", "original_lineage_matches", "trust_authorized"),
        ("audit_completed", "complete", "read_only"))
    exact_keys(audit["effects"], EFFECTS)
    need(all(v is False for v in audit["effects"].values()), "all_audit_effects_false")
    need(all(binding(audit[k]) == current_binding for k in ("audit_binding", "metadata_before", "metadata_after")), "stable_copied_current_profile_binding")
    expectation = {"schema": "delivery-readonly-audit-expectation-v1", "receipt_sha256": input_pins["delivery"],
        "audit_binding": current_binding, "rootless": {"path": "/private/var/jb", "target": rootless},
        "parents": [{"path": r["resolved"], "stat": r["stat"]} for r in original["parents_private"]],
        "files": [{"path": physical(r["path"]), "stat": r["stat"], "sha256": r["sha256"]} for r in original["installed_files_private"]],
        "directories": [{"path": physical(r["path"]), "stat": r["stat"]} for r in original["created_directories_private"]]}
    need(sha(canonical(expectation) + b"\n") == expectation_pin, "reconstructed_original_audit_expectation_pin")

    anchor = audit["anchor_before"]
    for phase in ("anchor_before", "anchor_after"):
        exact_keys(audit[phase], ("stat", "target"))
        stat9(audit[phase]["stat"])
    need(anchor == audit["anchor_after"] and anchor["stat"]["uid"] == anchor["stat"]["gid"] == 0 and anchor["stat"]["nlink"] == 1 and
         type(anchor["target"]) is str and anchor["target"] in (rootless, rootless + "/"), "stable_exact_current_rootless_anchor")
    selected = {"parents": [], "directories": [], "files": []}
    refusals = []
    for group, originals_key, compared in (("parents", "parents_private", PARENT_FIELDS),
                                           ("directories", "created_directories_private", STAT_FIELDS)):
        rows = audit[group]
        originals = original[originals_key]
        need(type(rows) is list and len(rows) == 2, "exact_current_directory_count")
        for row, old in zip(rows, originals):
            exact_keys(row, ("path", "before", "after"))
            path = old["resolved"] if group == "parents" else physical(old["path"])
            need(row["path"] == path, "ordered_original_directory_scope")
            physical_path(row["path"])
            for phase in ("before", "after"):
                exact_keys(row[phase], ("stat", "names"))
                stat9(row[phase]["stat"])
                names(row[phase]["names"])
            need(row["before"] == row["after"], "stable_current_directory_token_and_names")
            changed = [key for key in compared if old["stat"][key] != row["before"]["stat"][key]]
            need(changed == ["dev"], "only_recorded_directory_dev_may_differ")
            if group == "directories":
                wanted_names = sorted(r["name"] for r in original["installed_files_private"] if physical(r["path"]).rsplit("/", 1)[0] == path)
                need(row["before"]["names"] == wanted_names, "only_exact_delivered_directory_children")
            refusals.append({"phase": "original_lineage", "reason": "original_" + group + "_token_mismatch", "path": path})
            selected[group].append({"path": path, "original_stat_private": old["stat"], "current_stat_private": row["before"]["stat"],
                "current_names_private": row["before"]["names"], "compared_fields": list(compared), "changed_compared_fields": changed})

    rows = audit["files"]
    need(type(rows) is list and len(rows) == 5, "five_current_copied_files")
    copied = 0
    for row, old in zip(rows, original["installed_files_private"]):
        exact_keys(row, ("bytes_private_b64", "copied_bytes", "copy_complete", "linked_stat", "path", "refusals", "sha256", "stable", "stat", "stat_after"))
        need(row["path"] == physical(old["path"]), "ordered_fixed_current_file_scope")
        for phase in ("stat", "stat_after", "linked_stat"):
            stat9(row[phase])
        need(row["copy_complete"] is True and row["stable"] is True and row["refusals"] == [] and
             row["stat"] == row["stat_after"] == row["linked_stat"], "complete_stable_current_file_and_link")
        need([key for key in STAT_FIELDS if old["stat"][key] != row["stat"][key]] == ["dev"], "only_recorded_file_dev_may_differ")
        count = integer(row["copied_bytes"], minimum=1, maximum=MAX_FILE_BYTES)
        encoded = row["bytes_private_b64"]
        need(type(encoded) is str and len(encoded) <= ((MAX_FILE_BYTES + 2) // 3) * 4, "bounded_copied_base64")
        try:
            blob = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise Refused("valid_copied_base64") from error
        need(base64.b64encode(blob).decode("ascii") == encoded and len(blob) == count == row["stat"]["size"] and
             sha(blob) == digest(row["sha256"]) == old["sha256"], "full_copied_file_bytes_match_original_hash")
        copied += count
        need(copied <= MAX_SOURCE_BYTES, "total_copied_source_byte_bound")
        refusals.append({"phase": "original_lineage", "reason": "original_file_token_or_hash_mismatch", "path": row["path"]})
        selected["files"].append({"name": old["name"], "path": row["path"], "original_stat_private": old["stat"],
            "current_stat_private": row["stat"], "sha256": row["sha256"], "copied_bytes": count,
            "copied_bytes_private_b64": encoded, "changed_stat_fields": ["dev"]})
    need(type(audit["source_bytes_copied"]) is int and audit["source_bytes_copied"] == copied, "exact_copied_source_byte_total")
    need(audit["refusals"] == refusals and len(refusals) == 9, "exact_nine_original_lineage_refusals")
    result = dict(metadata(), schema="macws.installation-revalidation.evidence.v1", default_inert=False,
        input_bytes_consumed=sum(len(v) for v in original_inputs.values()), revalidation_completed=True,
        external_input_pins_match=True, original_audit_remains_negative=True, all_five_copied_hashes_match_original=True,
        current_stat_brackets_stable=True, observed_compared_changes_only_dev=True,
        input_sha256=input_pins, input_bytes={key: len(value) for key, value in original_inputs.items()},
        source_sha256=source_pins, expectation_sha256=expectation_pin, copied_current_binding_private=current_binding,
        current_rootless_anchor_private=anchor, selected_current_evidence_private=selected,
        original_lineage_refusals_private=refusals, source_bytes_copied=copied,
        historical_session_admitted=False, old_ownedfiles_authority_reconstructed=False,
        original_receipt_modified=False, timestamp_refreshed=False)
    need(len(canonical(result)) <= MAX_RESULT_BYTES, "bounded_complete_evidence_result")
    return result


def main(argv=None):
    need(argv is None or argv == [], "default_metadata_only_explicit_api_required")
    print(json.dumps(metadata(), sort_keys=True))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
