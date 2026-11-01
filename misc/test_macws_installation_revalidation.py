"""Invented in-memory evidence only. Fixtures are never native acceptance."""
import ast
import base64
from contextlib import redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent / "macws_swap_pair"
SPEC = importlib.util.spec_from_file_location("installation_revalidation", HERE / "installation_revalidation.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def token(dev, ino, size=96, mode=0o755, nlink=2):
    return {"dev": dev, "ino": ino, "size": size, "mtime_ns": 1000, "ctime_ns": 1100,
            "mode": mode, "uid": 0, "gid": 0, "nlink": nlink}


def fixture():
    """Invented provenance: hashes are explicit fixture pins, never real pins."""
    rootless = "/private/preboot/INVENTED/dopamine-FAKE/procursus"
    binding = {"hw.machine": "iPad13,6", "kern.osversion": "20E252", "kern.uuid": m.KERNEL_UUID.upper(),
               "kern.bootsessionuuid": "12345678-1234-1234-1234-123456789ABC"}
    parents = [{"logical": m.ROOTFS_PARENT, "resolved": m.ROOTFS_PARENT, "stat": token(10, 1), "target_previously_absent": True},
               {"logical": m.ROOTLESS_PARENT, "resolved": rootless + "/usr/libexec", "stat": token(20, 2), "target_previously_absent": True}]
    directory_paths = [m.ROOTFS_PARENT + "/" + m.PROBE_DIRECTORY, m.ROOTLESS_PARENT + "/" + m.CONTROLLER_DIRECTORY]
    directories = [{"path": path, "stat": token(10 + i * 10, 3 + i, mode=0o700)} for i, path in enumerate(directory_paths)]
    originals = []
    blobs = {}
    for i, name in enumerate(m.FILE_NAMES):
        blobs[name] = b"INVENTED fixture bytes " + name.encode()
        originals.append({"name": name, "path": directory_paths[0 if i == 0 else 1] + "/" + name,
            "sha256": m.sha(blobs[name]), "stat": token(10 if i == 0 else 20, 10 + i, len(blobs[name]), 0o755 if i == 0 else 0o600, 1),
            "previously_absent": True, "new_vnode_created_exclusively": True})
    delivery = {"schema": "macws.diagnostic-probe.delivery.private.v1", "bundle_manifest_sha256": m.MANIFEST_SHA,
        "receiver_sha256": m.RECEIVER_SHA, "duration_seconds": 0.01, "installation_verified": True,
        "candidate_executions": 0, "controller_executions": 0, "trust_mutations": 0,
        "automatic_cleanup_attempted": False, "current_trust_verified": False, "device_acceptance": False,
        "freeze_cause_or_fix_proven": False, "native_dependency_closure_currently_verified": False, "runtime_accepted": False,
        "host_private": {"duration_seconds": 0.1, "envelope_sha256": "c" * 64, "host_timeout_seconds": 20,
            "pipeline_source_sha256": m.PIPELINE_SHA, "ssh_exit": 0, "stderr_bytes": 0, "stderr_sha256": m.sha(b"")},
        "probe_signature": dict(m.PROBE_SIGNATURE), "installed_files_private": originals,
        "parents_private": parents, "created_directories_private": directories}

    def physical(path):
        return rootless + path[len("/var/jb"):] if path.startswith("/var/jb/") else path

    original_sha = m.sha(raw(delivery))
    expectation = {"schema": "delivery-readonly-audit-expectation-v1", "receipt_sha256": original_sha,
        "audit_binding": binding, "rootless": {"path": "/private/var/jb", "target": rootless},
        "parents": [{"path": r["resolved"], "stat": r["stat"]} for r in parents],
        "files": [{"path": physical(r["path"]), "stat": r["stat"], "sha256": r["sha256"]} for r in originals],
        "directories": [{"path": physical(r["path"]), "stat": r["stat"]} for r in directories]}
    expectation_sha = m.sha(m.canonical(expectation) + b"\n")
    anchor = {"target": rootless + "/", "stat": token(12, 8, len(rootless) + 1, 0o777, 1)}
    audit = {"schema": "macws.delivery-readonly-audit.private.v1", "receipt_sha256": original_sha,
        "audit_binding": copy.deepcopy(binding), "metadata_before": copy.deepcopy(binding), "metadata_after": copy.deepcopy(binding),
        "anchor_before": anchor, "anchor_after": copy.deepcopy(anchor), "parents": [], "directories": [], "files": [], "refusals": [],
        "source_bytes_copied": 0, "device_mutations": 0, "candidate_executions": 0, "controller_executions": 0,
        "device_file_removals": 0, "trust_mutations": 0,
        "read_only": True, "complete": True, "audit_completed": True,
        "automatic_retry": False, "cleanup_authorized": False, "device_acceptance": False, "new_session_authorized": False,
        "old_controller_configuration_modified": False, "old_ownedfiles_authority_reconstructed": False,
        "original_delivery_consistent": False, "original_lineage_matches": False, "trust_authorized": False,
        "effects": {key: False for key in m.EFFECTS}}
    for group, originals_group in (("parents", parents), ("directories", directories)):
        for old in originals_group:
            path = old["resolved"] if group == "parents" else physical(old["path"])
            current = dict(old["stat"], dev=old["stat"]["dev"] + 2)
            children = sorted(r["name"] for r in originals if physical(r["path"]).rsplit("/", 1)[0] == path)
            if group == "parents":
                # Parent timestamps/size/link counts are not historical identity
                # fields. They must still remain stable across the current copy.
                current.update(mtime_ns=9999, ctime_ns=9999, size=777, nlink=30)
                children = [m.PROBE_DIRECTORY if path == m.ROOTFS_PARENT else m.CONTROLLER_DIRECTORY]
            before = {"stat": current, "names": children}
            audit[group].append({"path": path, "before": before, "after": copy.deepcopy(before)})
            audit["refusals"].append({"phase": "original_lineage", "reason": "original_" + group + "_token_mismatch", "path": path})
    for old in originals:
        current = dict(old["stat"], dev=old["stat"]["dev"] + 2)
        blob = blobs[old["name"]]
        path = physical(old["path"])
        audit["files"].append({"path": path, "stat": current, "stat_after": copy.deepcopy(current), "linked_stat": copy.deepcopy(current),
            "bytes_private_b64": base64.b64encode(blob).decode(), "copied_bytes": len(blob), "sha256": old["sha256"],
            "copy_complete": True, "stable": True, "refusals": []})
        audit["source_bytes_copied"] += len(blob)
        audit["refusals"].append({"phase": "original_lineage", "reason": "original_file_token_or_hash_mismatch", "path": path})
    sources = {key: m.sha(("INVENTED source " + key).encode()) for key in m.SOURCE_NAMES}
    worker = {"schema": "macws.delivery-readonly-audit.worker.v1", "audit_private": audit, "source_sha256": sources,
        "expectation_sha256": expectation_sha, "audit_completed": True, "observation_requested": True,
        "cleanup_authorized": False, "default_inert": False, "device_acceptance": False, "historical_session_admission": False,
        "original_delivery_consistent": False, "error_category": None, "hard_seconds": 12,
        "candidate_executions": 0, "device_mutations": 0, "trust_mutation_commands": 0}
    transport = {"schema": "macws.retained-capturer.transport.v1", "capture_complete": True, "stdin_complete": True,
        "trusted_transport_contract_checked": True, "local_cleanup_errors_private": [], "output_limit_exceeded": False,
        "remote_effects_known_from_transport": False, "returncode": 1, "timed_out": False, "stderr_bytes_captured": 0,
        "stderr_sha256": m.sha(b""), "stdout_bytes_captured": len(raw(worker)), "stdout_sha256": m.sha(raw(worker))}
    return delivery, worker, transport, sources, expectation_sha, binding


def arguments(values=None):
    delivery, worker, transport, sources, expectation_sha, binding = fixture() if values is None else values
    delivery_raw, audit_raw = raw(delivery), raw(worker)
    transport = copy.deepcopy(transport)
    # For semantic mutation tests, deliberately re-pin the changed invented input.
    # The validator must reject its structure as well as enforce external pins.
    transport.update(stdout_bytes_captured=len(audit_raw), stdout_sha256=m.sha(audit_raw))
    transport_raw = raw(transport)
    return dict(delivery_raw=delivery_raw, audit_raw=audit_raw, transport_raw=transport_raw,
        expected_input_sha256={"delivery": m.sha(delivery_raw), "audit": m.sha(audit_raw), "transport": m.sha(transport_raw)},
        expected_source_sha256=copy.deepcopy(sources), expected_expectation_sha256=expectation_sha,
        expected_current_binding=copy.deepcopy(binding))


class InstallationRevalidationTests(unittest.TestCase):
    def refused(self, values):
        with self.assertRaises(m.Refused):
            m.revalidate(**arguments(values))

    def test_default_import_and_cli_are_inert_and_have_no_effect_imports(self):
        tree = ast.parse((HERE / "installation_revalidation.py").read_text())
        imports = {name.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for name in node.names}
        self.assertEqual(imports, {"base64", "binascii", "hashlib", "json", "math", "re", "sys"})
        self.assertFalse(any(isinstance(n, ast.ImportFrom) for n in ast.walk(tree)))
        capture = io.StringIO()
        with patch.object(m, "decode", side_effect=AssertionError("input read")), redirect_stdout(capture):
            self.assertEqual(m.main([]), 0)
        self.assertEqual(json.loads(capture.getvalue()), m.metadata())
        with self.assertRaises(m.Refused):
            m.main(["--execute"])

    def test_positive_fixture_is_evidence_with_no_authority_or_freshness(self):
        result = m.revalidate(**arguments())
        self.assertTrue(result["revalidation_completed"])
        self.assertTrue(result["original_audit_remains_negative"])
        self.assertEqual(len(result["selected_current_evidence_private"]["files"]), 5)
        for key in ("session_authorized", "cleanup_authorized", "trust_authorized", "execution_authorized", "installation_ownership_authorized",
                    "evidence_authenticity_proven", "current_device_freshness_claimed", "historical_volume_continuity_proven", "device_acceptance",
                    "historical_session_admitted", "old_ownedfiles_authority_reconstructed", "original_receipt_modified", "timestamp_refreshed"):
            self.assertIs(result[key], False)
        for key in ("device_commands", "native_calls", "network_calls"):
            self.assertEqual(result[key], 0)
        self.assertNotIn("new_vnode", result)
        self.assertNotIn("config", result)
        self.assertNotIn("prerequisites", result)

    def test_original_inputs_and_external_mappings_are_not_modified_or_aliased(self):
        args = arguments()
        original = copy.deepcopy(args)
        result = m.revalidate(**args)
        self.assertEqual(args, original)
        result["source_sha256"].clear()
        result["copied_current_binding_private"].clear()
        result["input_sha256"].clear()
        self.assertEqual(args, original)

    def test_external_pins_must_match_each_exact_input_before_decode(self):
        for key in ("delivery", "audit", "transport"):
            args = arguments(); args["expected_input_sha256"][key] = "0" * 64
            with self.subTest(key=key), patch.object(m, "decode", side_effect=AssertionError("decoded before pins")), self.assertRaises(m.Refused):
                m.revalidate(**args)
        for pins in ({}, {"delivery": "0" * 64}, {"delivery": "g" * 64, "audit": "0" * 64, "transport": "0" * 64}):
            args = arguments(); args["expected_input_sha256"] = pins
            with self.subTest(pins=pins), self.assertRaises(m.Refused):
                m.revalidate(**args)

    def test_nonimmutable_empty_or_oversized_input_refuses(self):
        for field, value in (("audit_raw", bytearray(b"{}")), ("delivery_raw", b""), ("audit_raw", b"x" * (m.MAX_AUDIT_BYTES + 1))):
            args = arguments(); args[field] = value
            with self.subTest(field=field, kind=type(value).__name__), self.assertRaises(m.Refused):
                m.revalidate(**args)

    def test_duplicate_nonfinite_overflowed_and_deep_json_refuse(self):
        for bad in (b'{"schema":1,"schema":2}', b'{"x":NaN}', b'{"x":1e999}', b'{"x":9223372036854775808}',
                    b'{"x":' + b'[' * 25 + b'0' + b']' * 25 + b'}', b'{"x":"\\ud800"}', b'[]'):
            args = arguments(); args["audit_raw"] = bad; args["expected_input_sha256"]["audit"] = m.sha(bad)
            with self.subTest(bad=bad[:60]), self.assertRaises(m.Refused):
                m.revalidate(**args)

    def test_partial_or_ambiguous_transport_refuses(self):
        changes = (("capture_complete", False), ("stdin_complete", False), ("trusted_transport_contract_checked", False),
            ("output_limit_exceeded", True), ("timed_out", True), ("returncode", 0), ("returncode", True),
            ("stderr_bytes_captured", 1), ("stderr_sha256", "0" * 64), ("local_cleanup_errors_private", ["failure"]),
            ("remote_effects_known_from_transport", True))
        for key, value in changes:
            values = fixture(); values[2][key] = value
            with self.subTest(key=key): self.refused(values)
        args = arguments(); transport = json.loads(args["transport_raw"]); transport["stdout_sha256"] = "0" * 64
        args["transport_raw"] = raw(transport); args["expected_input_sha256"]["transport"] = m.sha(args["transport_raw"])
        with self.assertRaises(m.Refused): m.revalidate(**args)

    def test_unknown_fields_or_versions_refuse_at_each_envelope(self):
        for target in (0, 1, 2, "audit"):
            for kind in ("schema", "extra"):
                values = fixture(); row = values[1]["audit_private"] if target == "audit" else values[target]
                row["schema" if kind == "schema" else "unknown"] = "unknown"
                with self.subTest(target=target, kind=kind): self.refused(values)

    def test_worker_source_expectation_or_receipt_binding_substitution_refuses(self):
        for target in ("source", "expectation", "receipt", "reconstructed"):
            values = fixture()
            if target == "source": values[1]["source_sha256"] = dict(values[3], audit_worker="0" * 64)
            elif target == "expectation": values[1]["expectation_sha256"] = "0" * 64
            elif target == "receipt": values[1]["audit_private"]["receipt_sha256"] = "0" * 64
            else: values[0]["parents_private"][0]["stat"]["ino"] += 1
            with self.subTest(target=target): self.refused(values)

    def test_any_claimed_effect_authority_or_incompleteness_refuses(self):
        for target, key, value in (("worker", "audit_completed", False), ("worker", "device_acceptance", True),
            ("worker", "historical_session_admission", True), ("worker", "candidate_executions", False),
            ("worker", "device_mutations", 1), ("worker", "trust_mutation_commands", 1), ("worker", "hard_seconds", True),
            ("worker", "original_delivery_consistent", True), ("audit", "complete", False),
            ("audit", "new_session_authorized", True), ("audit", "old_ownedfiles_authority_reconstructed", True),
            ("audit", "cleanup_authorized", True), ("audit", "trust_authorized", True), ("audit", "trust_mutations", False),
            ("audit", "original_lineage_matches", True), ("audit", "read_only", False)):
            values = fixture(); (values[1] if target == "worker" else values[1]["audit_private"])[key] = value
            with self.subTest(target=target, key=key): self.refused(values)
        for key in m.EFFECTS:
            values = fixture(); values[1]["audit_private"]["effects"][key] = True
            with self.subTest(effect=key): self.refused(values)

    def test_changed_boot_profile_or_metadata_bracket_refuses(self):
        for phase in ("audit_binding", "metadata_before", "metadata_after"):
            for key, value in (("hw.machine", "iPad14,5"), ("kern.osversion", "20F75"), ("kern.uuid", "0" * 36),
                ("kern.bootsessionuuid", "87654321-1234-1234-1234-123456789ABC")):
                values = fixture(); values[1]["audit_private"][phase][key] = value
                with self.subTest(phase=phase, key=key): self.refused(values)

    def test_rootless_literal_token_or_owner_bracket_refuses(self):
        for change in ("other_target", "double_slash", "after", "owner", "links", "extra", "after_bool"):
            values = fixture(); audit = values[1]["audit_private"]
            if change == "other_target": audit["anchor_before"]["target"] += "other"
            elif change == "double_slash": audit["anchor_before"]["target"] += "/"
            elif change == "after": audit["anchor_after"]["stat"]["ino"] += 1
            elif change == "owner": audit["anchor_before"]["stat"]["uid"] = 501
            elif change == "links": audit["anchor_before"]["stat"]["nlink"] = 2
            elif change == "after_bool": audit["anchor_after"]["stat"]["uid"] = False
            else: audit["anchor_before"]["extra"] = 1
            with self.subTest(change=change): self.refused(values)

    def test_parent_comparison_uses_only_documented_identity_subset(self):
        result = m.revalidate(**arguments())
        for parent in result["selected_current_evidence_private"]["parents"]:
            self.assertEqual(parent["compared_fields"], list(m.PARENT_FIELDS))
            self.assertEqual(parent["changed_compared_fields"], ["dev"])
            self.assertNotEqual(parent["original_stat_private"]["mtime_ns"], parent["current_stat_private"]["mtime_ns"])

    def test_any_compared_drift_other_than_dev_and_unchanged_dev_refuse(self):
        for group, keys in (("parents", m.PARENT_FIELDS), ("directories", m.STAT_FIELDS), ("files", m.STAT_FIELDS)):
            for key in keys:
                values = fixture(); row = values[1]["audit_private"][group][0]
                if group == "files":
                    phases = ("stat", "stat_after", "linked_stat")
                    for phase in phases: row[phase][key] += -2 if key == "dev" else 1
                else:
                    for phase in ("before", "after"): row[phase]["stat"][key] += -2 if key == "dev" else 1
                with self.subTest(group=group, key=key): self.refused(values)

    def test_current_directory_token_names_or_exact_children_must_be_stable(self):
        for group in ("parents", "directories"):
            for change in ("token", "names", "extra", "duplicate", "alias", "foreign_child", "reorder"):
                values = fixture(); row = values[1]["audit_private"][group][0]
                if change == "token": row["after"]["stat"]["ctime_ns"] += 1
                elif change == "names": row["after"]["names"].append("new")
                elif change == "extra": row["before"]["extra"] = 1
                elif change == "duplicate": row["before"]["names"] *= 2
                elif change == "alias": row["path"] = "/var" + row["path"][len("/private/var"):]
                elif change == "foreign_child":
                    row["before"]["names"].append("FOREIGN"); row["before"]["names"].sort()
                    row["after"] = copy.deepcopy(row["before"])
                    if group == "parents": continue  # Unrelated parent children are allowed.
                else: values[1]["audit_private"][group].reverse()
                with self.subTest(group=group, change=change): self.refused(values)

    def test_partial_changed_or_invalid_current_file_copy_refuses(self):
        for change in ("partial", "unstable", "refusal", "link", "missing", "duplicate", "path", "hash", "bytes", "base64", "count", "extra"):
            values = fixture(); audit = values[1]["audit_private"]; row = audit["files"][0]
            if change == "partial": row["copy_complete"] = False
            elif change == "unstable": row["stable"] = False
            elif change == "refusal": row["refusals"] = ["read_changed"]
            elif change == "link": row["linked_stat"]["ino"] += 1
            elif change == "missing": audit["files"].pop()
            elif change == "duplicate": audit["files"][-1] = copy.deepcopy(row)
            elif change == "path": row["path"] += "/../other"
            elif change == "hash": row["sha256"] = "0" * 64
            elif change == "bytes": row["bytes_private_b64"] = base64.b64encode(b"changed").decode()
            elif change == "base64": row["bytes_private_b64"] += "\n"
            elif change == "count": row["copied_bytes"] = True
            else: row["unknown"] = 1
            with self.subTest(change=change): self.refused(values)

    def test_false_boolean_or_out_of_range_stat_fields_refuse(self):
        for value in (True, -1, 1 << 63, 1.0, "1"):
            values = fixture(); values[1]["audit_private"]["files"][0]["stat"]["dev"] = value
            with self.subTest(value=value): self.refused(values)
        for key, value in (("mode", 0o100755), ("ino", 0), ("nlink", 0)):
            values = fixture(); values[1]["audit_private"]["directories"][0]["before"]["stat"][key] = value
            with self.subTest(key=key): self.refused(values)

    def test_complete_exact_original_lineage_refusals_and_byte_total_required(self):
        for change in ("missing", "extra", "duplicate", "phase", "reason", "path", "reorder", "total"):
            values = fixture(); audit = values[1]["audit_private"]
            if change == "missing": audit["refusals"].pop()
            elif change == "extra": audit["refusals"].append({"phase": "copy", "reason": "error"})
            elif change == "duplicate": audit["refusals"][-1] = copy.deepcopy(audit["refusals"][0])
            elif change == "phase": audit["refusals"][0]["phase"] = "audit"
            elif change == "reason": audit["refusals"][0]["reason"] = "ignored"
            elif change == "path": audit["refusals"][0]["path"] += "other"
            elif change == "reorder": audit["refusals"].reverse()
            else: audit["source_bytes_copied"] += 1
            with self.subTest(change=change): self.refused(values)


if __name__ == "__main__":
    unittest.main()
