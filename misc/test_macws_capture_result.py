"""Invented coherent report bytes only. No device query or filesystem mutation."""
import base64
from contextlib import ExitStack
import copy
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from macws_swap_pair import capture_result as result_core
from macws_swap_pair import runtime_support as rs
c = result_core.cleanup
o = result_core.observer


def encoded(raw):
    return base64.b64encode(raw).decode('ascii')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                       allow_nan=False) + '\n').encode('ascii')


def record(ino, size=64, mode=0o700, kind='directory'):
    return {'dev': 7, 'ino': ino, 'size': size, 'mtime_ns': 1000, 'ctime_ns': 2000,
            'mode': mode, 'uid': 0, 'gid': 0, 'nlink': 2 if kind == 'directory' else 1, 'kind': kind}


def token(info):
    return {k: v for k, v in info.items() if k != 'kind'}


def signature(index=0):
    return {'architecture': 'arm64', 'uuid': '11111111-2222-3333-4444-555555555555',
            'cdhash': str(index + 1) * 40, 'hash_type': 2, 'signed_pages_checked': 5,
            'code_limit': 69584, 'page_hashes_valid': True}


class InventedInputs:
    """Deliberately invented caller fixture, never historical/native authority."""
    def __init__(self):
        self.expected_files = {'job.plist': b'invented plist', 'probe.log': b'invented log'}
        self.context = {'boot_private': '11111111-2222-3333-4444-555555555555', 'config_sha256': 'a' * 64,
            'source_sha256': dict(c.SOURCES), 'retired_birth_private': [401, 1000, 5],
            'UI_private': {'SpringBoard': [101, 1000, 1], 'backboardd': [102, 1000, 2]},
            'expected_file_sha256': {name: c.digest(raw) for name, raw in self.expected_files.items()},
            'exclusive_operator': True}
        self.original_bytes = {name: ('invented ' + name).encode() for name in result_core.EVIDENCE}
        self.provenance_base = {k: 'b' * 64 for k in c.PROVENANCE_KEYS if k != 'current_wire_sha256'}
        self.provenance_base['effective_config_sha256'] = self.context['config_sha256']
        self.original = SimpleNamespace(runtime=rs, config={'operation': 'control_normal'})
        self.delivery = {'probe_signature': signature(),
            'parents_private': [{'logical': '/var/jb/usr/libexec', 'resolved': '/private/preboot/invented/procursus/usr/libexec',
                'stat': token(record(10))}],
            'created_directories_private': [{'path': o.CONTROLLER_DIR, 'stat': token(record(20))},
                {'path': rs.ROOTFS + '/usr/local/libexec/macws-swap-pair-probe-20261017', 'stat': token(record(21))}],
            'installed_files_private': []}
        for index, name in enumerate(('controller.py', 'runtime_support.py', 'watchdog.py',
                                      'offline-QA.canonical.private.json', 'probe.arm64')):
            directory = self.delivery['created_directories_private'][name == 'probe.arm64']['path']
            self.delivery['installed_files_private'].append({'name': name, 'path': directory + '/' + name,
                'stat': token(record(30 + index, 50, 0o755 if name == 'probe.arm64' else 0o600, 'regular')),
                'sha256': c.digest(('invented artifact ' + name).encode())})
    def intact(self):
        return True


def fixture():
    inputs = InventedInputs()
    expected = {'payload_sha256': 'c' * 64, 'codec_sha256': 'd' * 64, 'frame_sha256': 'e' * 64,
                'entry_sha256': {name: 'f' * 64 for name in result_core.ENTRY_NAMES}}
    expected['entry_sha256'].update({'evidence.' + name: c.digest(raw)
                                    for name, raw in inputs.original_bytes.items()})
    manifest = {'schema': 'macws.retained-artifact.selection.v1', 'path': c.TARGET,
        'boot_private': inputs.context['boot_private'], 'config_sha256': inputs.context['config_sha256'],
        'source_sha256': dict(c.SOURCES), 'directory': record(60), 'files': {
            name: {'stat': record(61 + at, len(raw), 0o600, 'regular'), 'sha256': c.digest(raw)}
            for at, (name, raw) in enumerate(inputs.expected_files.items())}}
    files = {name: encoded(raw) for name, raw in inputs.expected_files.items()}
    absence = {'api': 'proc_pidinfo', 'flavor': 3, 'requested_bytes': 136, 'returned': 0,
        'errno': 3, 'outcome': 'ESRCH', 'pid_private': 401, 'expected_birth_private': [401, 1000, 5]}
    gates = []
    for index in range(2):
        gates.append({'schema': 'macws.retained-artifact.gates.v1',
            'selection_sha256': c.digest(c.canonical(manifest)) if index else '0' * 64,
            'provenance_sha256': c.digest(c.canonical(inputs.provenance_base)),
            'boot_private': inputs.context['boot_private'], 'config_sha256': inputs.context['config_sha256'],
            'source_sha256': dict(c.SOURCES), 'UI_private': copy.deepcopy(inputs.context['UI_private']),
            'exclusive_operator': True, 'observed_monotonic': 100.0 + index * .25,
            'jobs_absent': dict.fromkeys(c.SERVICES, True), 'no_candidate_or_test_workloads': True,
            'other_scratch_absent': True, 'artifacts_unchanged': True, 'thermal': 0,
            'generation_absence': copy.deepcopy(absence)})
    commands, observations, queries = [], [], []
    byte_count = 0
    trust = [signature()['cdhash']] + [signature(at + 1)['cdhash'] for at in range(3)]
    for phase in range(2):
        trust_text = 'Jailbreak Trustcache 0 <UUID: ' + '1' * 32 + '> (length: 4)\n' + ''.join(
            '| ' + str(at + 1) + ': ' + value + '\n' for at, value in enumerate(trust))
        phase_results = [[0, '  PID COMM\n101 /System/SpringBoard\n102 /System/backboardd\n', ''],
            *[[113, '', 'Could not find service "' + service.rsplit('/', 1)[-1] + '" in domain for uid: 501\n']
              for service in c.SERVICES], [0, trust_text, '']]
        argv = [['/bin/ps', '-eo', 'pid,comm'], [rs.LAUNCHCTL, 'print', c.SERVICES[0]],
                [rs.LAUNCHCTL, 'print', c.SERVICES[1]], [rs.JBCTL, 'trustcache', 'info']]
        for args, value in zip(argv, phase_results):
            commands.append({'argv_private': args, 'attempted': True, 'result_known': True,
                'stdout_private_b64': encoded(value[1].encode()), 'stderr_private_b64': encoded(value[2].encode()),
                'child_cleanup_attempted': False, 'returncode': value[0]})
            byte_count += len(value[1].encode()) + len(value[2].encode())
        ui = {}
        for name, birth in inputs.context['UI_private'].items():
            raw = bytearray(136)
            struct.pack_into('<I', raw, 4, 2)
            struct.pack_into('<I', raw, 12, birth[0])
            struct.pack_into('<QQ', raw, 120, *birth[1:])
            ui[name] = {'path': '/System/' + name, 'birth_private': birth, 'stopped': False,
                'native_status_private': 2, 'native_status_name': 'SRUN', 'raw_bsdinfo_private_hex': bytes(raw).hex(),
                'raw_bsdinfo_sha256': c.digest(raw), 'returned_bsdinfo_bytes': 136, 'bsdinfo_errno': 0,
                'state_source': 'proc_bsdinfo.pbi_status'}
            path = ('/System/' + name + '\0').encode()
            queries.append({'api': 'proc_pidinfo', 'flavor': 3, 'requested_bytes': 136, 'returned': 136,
                'errno': 0, 'pid_private': birth[0], 'expected_birth_private': None,
                'raw_bsdinfo_private_hex': bytes(raw).hex(), 'raw_bsdinfo_sha256': c.digest(raw),
                'path_returned': len(path), 'path_private_b64': encoded(path)})
        queries.append(dict(absence, raw_bsdinfo_private_hex='', raw_bsdinfo_sha256=c.digest(b'')))
        artifacts = {}
        for item in inputs.delivery['installed_files_private']:
            artifacts[item['path']] = {'stat': dict(item['stat'], kind='regular'), 'sha256': item['sha256']}
            if item['name'] == 'probe.arm64':
                artifacts[item['path']]['signature'] = signature()
        for at, (name, dependency) in enumerate(result_core.readonly.DEPENDENCIES.items()):
            artifacts[name] = {'stat': record(80 + at, 100000, 0o755, 'regular'), 'sha256': dependency['sha256'],
                'signature': dict(signature(at + 1), architecture=dependency['architecture'], uuid=dependency['uuid'])}
        root = {'stat_private': record(99, mode=0o777, kind='other'),
                'link_private': '/private/preboot/invented/procursus/'}
        observations.append({'started_monotonic_private': gates[phase]['observed_monotonic'], 'completed': True,
            'stage': 'complete', 'rootless_anchor_private': [copy.deepcopy(root), copy.deepcopy(root)],
            'rootless_parent_observations_private': [record(10), record(10)],
            'metadata_private': {'hw.machine': 'iPad13,6', 'kern.osversion': '20E252',
                'kern.uuid': 'd6b9e234-64f1-30ea-ae62-ed8f2dc6efdb', 'kern.bootsessionuuid': inputs.context['boot_private']},
            'rootfs_version_private': {'ProductVersion': '13.4', 'ProductBuildVersion': '22F66'},
            'process_command_private': phase_results[0],
            'process_rows_private': result_core.readonly.process_rows(phase_results[0][1]),
            'UI_details_private': ui, 'jobs_private': dict(zip(c.SERVICES, phase_results[1:3])),
            'generation_absence_private': copy.deepcopy(absence), 'thermal': 0,
            'trust_command_private': phase_results[3], 'trust_members_private': sorted(trust),
            'artifacts_private': artifacts, 'delivery_directories_private': [
                {'path_private': item['path'], 'stat_private': dict(item['stat'], kind='directory'),
                 'entries_private': sorted(x['name'] for x in inputs.delivery['installed_files_private']
                                          if x['path'].rsplit('/', 1)[0] == item['path'])}
                for item in inputs.delivery['created_directories_private']],
            'finished_monotonic_private': gates[phase]['observed_monotonic'] + .1,
            'gate_private': copy.deepcopy(gates[phase])})
    report = {'schema': 'macws.retained-artifact.observer-report.v1', 'observations_private': observations,
        'commands_private': commands, 'native_queries_private': queries, 'copied_command_bytes': byte_count,
        'native_query_count': 20, 'native_clock_read_count': 100, 'copied_file_bytes': 700000,
        'clock_reads': 50, 'limits': dict(o.LIMITS), 'existing_workload_or_file_mutations': 0,
        'candidate_executions': 0, 'existing_job_signals': 0, 'managed_read_child_cleanup_attempts': 0,
        'cleanup_authorized': False, 'device_acceptance': False, 'original_ownership_recovered': False}
    capture = {'schema': 'macws.retained-artifact.read-only-capture.v1', 'capture_completed': True,
        'capture_only_not_cleanup_admission': True, 'cleanup_authorized': False, 'device_acceptance': False,
        'existing_workload_or_file_mutations': 0, 'files_private': files, 'manifest_private': manifest,
        'selection_copies_private': [{'manifest_private': copy.deepcopy(manifest), 'files_private': dict(files)} for _ in range(2)],
        'error_category': None, 'refusal': None, 'pre_capture_gate_private': gates[0],
        'post_capture_gate_private': gates[1], 'observer_private': report}
    worker = {'schema': 'macws.retained-artifact.worker.private.v1', 'capture_requested': True,
        'default_inert': False, 'capture_completed': True, 'capture_only_not_cleanup_admission': True,
        'cleanup_authorized': False, 'device_acceptance': False, 'freeze_fix': False,
        'original_ownership_recovered': False, 'native_backend_construction_attempted': True,
        'native_backend_constructed': True, 'helper_modules_executed': list(result_core.LOAD_ORDER),
        'capture_report_private': capture, 'capture_report_omitted': False, 'worker_error_category': None,
        'worker_refusal_category': None, 'stage': 'capture_complete', 'hard_seconds': 12,
        'output_limit_bytes': result_core.MAX_STDOUT, 'output_limit_exceeded': False,
        'codec_sha256': expected['codec_sha256'], 'frame_sha256': expected['frame_sha256'],
        'entry_sha256': dict(expected['entry_sha256'])}
    transport = {'returncode': 0, 'stdout': canonical(worker), 'stderr': b'', 'timed_out': False,
        'output_limit_exceeded': False, 'stdin_complete': True, 'capture_complete': True,
        'local_cleanup_errors_private': []}
    return inputs, expected, worker, transport


class ResultTests(unittest.TestCase):
    def setUp(self):
        self.inputs, self.expected, self.worker, self.transport = fixture()
        self.capture = self.worker['capture_report_private']
        self.report = self.capture['observer_private']
    def assess(self):
        return result_core.assess(self.transport, expected=self.expected, inputs=self.inputs)
    def rewrite(self):
        self.transport['stdout'] = canonical(self.worker)
    def refused(self):
        value = self.assess()
        self.assertFalse(value['source_bound_capture_received'], value)
        self.assertFalse(value['reported_capture_completed'])
        self.assertFalse(value['archive_size_eligible'])
        self.assertIsNotNone(value['refusal_category'])
        for name in ('cleanup_authorized', 'native_evidence_authenticity_verified', 'fresh_cleanup_gates_verified',
                     'device_acceptance', 'freeze_fix', 'original_ownership_recovered', 'automatic_retry'):
            self.assertIs(value[name], False)
        return value
    def test_complete_invented_trace_is_report_only(self):
        with ExitStack() as stack:
            for owner, name in ((os, 'open'), (os, 'unlink'), (os, 'kill'), (subprocess, 'Popen'),
                                (ctypes, 'CDLL'), (signal, 'setitimer')):
                stack.enter_context(patch.object(owner, name, side_effect=AssertionError('unexpected capability')))
            value = self.assess()
        self.assertTrue(value['source_bound_capture_received'], value)
        self.assertTrue(value['reported_capture_completed'])
        self.assertTrue(value['archive_size_eligible'])
        self.assertEqual(value['current_wire_sha256'], c.digest(self.transport['stdout']))
        self.assertFalse(value['cleanup_authorized'])
        self.assertFalse(value['native_evidence_authenticity_verified'])
        self.assertLess(len(canonical(value)), 2000)
        self.assertNotIn('private', json.dumps(value))
    def test_transport_negative_states(self):
        for key, value in (('returncode', 1), ('returncode', 124), ('returncode', 255), ('returncode', None),
            ('returncode', False), ('timed_out', True), ('timed_out', 0), ('output_limit_exceeded', True),
            ('stdin_complete', False), ('stdin_complete', None), ('stdin_complete', 1), ('capture_complete', False),
            ('capture_complete', 1), ('stderr', b'noise'), ('transport_error_private', 'OSError: invented'),
            ('local_cleanup_errors_private', ['invented cleanup failure'])):
            original = copy.deepcopy(self.transport)
            with self.subTest(key=key, value=value):
                self.transport[key] = value
                self.refused()
            self.transport = original
    def test_transport_extra_missing_and_wrong_bytes(self):
        for transform in (lambda v: v.update(extra=True), lambda v: v.pop('stdin_complete'),
                           lambda v: v.update(stdout=bytearray(v['stdout'])),
                           lambda v: v.update(stderr=b'x' * (result_core.MAX_STDERR + 2))):
            original = copy.deepcopy(self.transport)
            transform(self.transport)
            self.refused()
            self.transport = original
    def test_noisy_partial_empty_and_oversized_wire(self):
        for raw in (b'', b'noise\n' + self.transport['stdout'], self.transport['stdout'][:-7],
                    b'\xff', self.transport['stdout'] + b'{}', b'x' * (result_core.MAX_STDOUT + 1)):
            self.transport['stdout'] = raw
            self.refused()
    def test_wrong_worker_identity_or_order(self):
        for name, value in (('schema', 'old'), ('codec_sha256', 'a' * 64), ('frame_sha256', 'b' * 64),
            ('helper_modules_executed', list(reversed(result_core.LOAD_ORDER))), ('entry_sha256', {})):
            before = copy.deepcopy(self.worker)
            self.worker[name] = value
            self.rewrite()
            self.refused()
            self.worker = before
    def test_worker_flags_types_and_claims(self):
        for name, value in (('capture_requested', 1), ('capture_completed', 1), ('default_inert', 0),
            ('cleanup_authorized', True), ('device_acceptance', True), ('freeze_fix', True),
            ('capture_report_omitted', True), ('native_backend_constructed', False), ('stage', 'capture_refused'),
            ('hard_seconds', 12.0), ('output_limit_bytes', 100), ('worker_error_category', 'Refused')):
            before = copy.deepcopy(self.worker)
            self.worker[name] = value
            self.rewrite()
            self.refused()
            self.worker = before
    def test_nested_capture_flags_and_omitted(self):
        for name, value in (('schema', 'old'), ('capture_completed', False), ('capture_completed', 1),
            ('capture_only_not_cleanup_admission', False), ('cleanup_authorized', True),
            ('device_acceptance', True), ('existing_workload_or_file_mutations', False),
            ('error_category', 'Refused'), ('refusal', 'invented')):
            before = copy.deepcopy(self.capture)
            self.capture[name] = value
            self.rewrite()
            self.refused()
            self.worker['capture_report_private'] = self.capture = before
    def test_wrong_expected_entry_or_historical_input(self):
        self.expected['entry_sha256']['evidence.config'] = '1' * 64
        self.refused()
    def test_expected_fields_or_pin_wrong(self):
        self.expected['payload_sha256'] = 'A' * 64
        self.refused()
    def test_input_integrity_must_be_exacttrue(self):
        self.inputs.intact = lambda: 1
        self.refused()
    def test_private_exception_is_not_echoed(self):
        def fail():
            raise ValueError('/private/secret/invented')
        self.inputs.intact = fail
        value = self.refused()
        self.assertNotIn('secret', json.dumps(value))
    def test_changed_file_copy_even_same_size(self):
        self.capture['selection_copies_private'][0]['files_private']['probe.log'] = encoded(b'x' * len(b'invented log'))
        self.rewrite()
        self.refused()
    def test_copy_b64_noncanonical_or_malformed(self):
        for value in ('a===', 'a A==', encoded(b'invented log') + '=', 'a' * 400000):
            self.capture['selection_copies_private'][0]['files_private']['probe.log'] = value
            self.rewrite()
            self.refused()
    def test_second_manifest_stat_changed(self):
        self.capture['selection_copies_private'][1]['manifest_private']['files']['probe.log']['stat']['ino'] += 10
        self.rewrite()
        self.refused()
    def test_manifest_current_inode_not_old_snapshot_authority(self):
        for item in [self.capture['manifest_private']] + [x['manifest_private'] for x in self.capture['selection_copies_private']]:
            item['directory']['ino'] = 500
            for row in item['files'].values():
                row['stat']['ino'] += 500
        manifest_sha = c.digest(c.canonical(self.capture['manifest_private']))
        self.capture['post_capture_gate_private']['selection_sha256'] = manifest_sha
        self.report['observations_private'][1]['gate_private']['selection_sha256'] = manifest_sha
        self.rewrite()
        self.assertTrue(self.assess()['reported_capture_completed'])
    def test_unsafe_stat_types_or_links(self):
        for field, value in (('nlink', 2), ('mode', 0o644), ('size', 12.0), ('ino', True)):
            before = copy.deepcopy(self.capture['selection_copies_private'][0])
            self.capture['selection_copies_private'][0]['manifest_private']['files']['probe.log']['stat'][field] = value
            self.rewrite()
            self.refused()
            self.capture['selection_copies_private'][0] = before
    def test_gate_wrong_context_provenance_or_preselection(self):
        for key, value in (('selection_sha256', '1' * 64), ('provenance_sha256', '2' * 64),
            ('boot_private', '22222222-2222-3333-4444-555555555555'), ('thermal', False),
            ('exclusive_operator', 1), ('other_scratch_absent', False), ('UI_private', {})):
            before = copy.deepcopy(self.capture['pre_capture_gate_private'])
            self.capture['pre_capture_gate_private'][key] = value
            self.rewrite()
            self.refused()
            self.capture['pre_capture_gate_private'] = before
    def test_capture_provenance_cannot_contain_current_wire(self):
        self.inputs.provenance_base['current_wire_sha256'] = 'a' * 64
        self.refused()
    def test_absence_uncertainty_or_wrong_birth(self):
        self.capture['post_capture_gate_private']['generation_absence']['errno'] = 5
        self.rewrite()
        self.refused()
    def test_observer_count_and_effects(self):
        for key, value in (('observations_private', self.report['observations_private'][:1]),
            ('commands_private', self.report['commands_private'][:7]), ('native_queries_private', []),
            ('candidate_executions', False), ('existing_job_signals', 1), ('managed_read_child_cleanup_attempts', 1),
            ('cleanup_authorized', True), ('native_query_count', 19), ('native_clock_read_count', 8193),
            ('copied_command_bytes', 10), ('copied_file_bytes', 1), ('clock_reads', 0)):
            before = copy.deepcopy(self.report[key])
            self.report[key] = value
            self.rewrite()
            self.refused()
            self.report[key] = before
    def test_observer_limits_exact(self):
        self.report['limits']['seconds'] = 9
        self.rewrite()
        self.refused()
    def test_missing_nested_field(self):
        del self.report['observations_private'][0]['rootless_anchor_private']
        self.rewrite()
        self.refused()
    def test_observer_timing_stale_or_regressed(self):
        for key, value in (('finished_monotonic_private', 102.0), ('started_monotonic_private', 100.5),
                           ('completed', 1), ('stage', 'processes')):
            original = self.report['observations_private'][0][key]
            self.report['observations_private'][0][key] = value
            self.rewrite()
            self.refused()
            self.report['observations_private'][0][key] = original
    def test_rootless_current_literal_changes(self):
        self.report['observations_private'][1]['rootless_anchor_private'][1]['link_private'] += '/'
        self.rewrite()
        self.refused()
    def test_device_identity_changed(self):
        self.report['observations_private'][0]['metadata_private']['hw.machine'] = 'iPad14,3'
        self.rewrite()
        self.refused()
    def test_rootfs_changed(self):
        self.report['observations_private'][0]['rootfs_version_private']['ProductBuildVersion'] = '22F67'
        self.rewrite()
        self.refused()
    def test_UI_raw_block_changed(self):
        self.report['observations_private'][0]['UI_details_private']['SpringBoard']['raw_bsdinfo_private_hex'] = '00' * 136
        self.rewrite()
        self.refused()
    def test_native_path_query_changed(self):
        self.report['native_queries_private'][0]['path_private_b64'] = encoded(b'/System/foreign')
        self.rewrite()
        self.refused()
    def test_native_absence_fake_raw(self):
        self.report['native_queries_private'][2]['raw_bsdinfo_private_hex'] = '00'
        self.rewrite()
        self.refused()
    def test_effect_command_cannot_substitute(self):
        self.report['commands_private'][0]['argv_private'] = [rs.LAUNCHCTL, 'kill', 'SIGKILL', c.SERVICES[0]]
        self.rewrite()
        self.refused()
    def test_command_boolean_exit_code(self):
        self.report['commands_private'][0]['returncode'] = False
        self.rewrite()
        self.refused()
    def test_command_raw_and_gate_disagree(self):
        self.report['commands_private'][0]['stdout_private_b64'] = encoded(b'  PID COMM\n')
        self.rewrite()
        self.refused()
    def test_nonempty_unrecognized_job_query(self):
        self.report['commands_private'][1]['stderr_private_b64'] = encoded(b'unknown failure')
        self.report['copied_command_bytes'] += len(b'unknown failure') - len(self.report['observations_private'][0]['jobs_private'][c.SERVICES[0]][2])
        self.report['observations_private'][0]['jobs_private'][c.SERVICES[0]][2] = 'unknown failure'
        self.rewrite()
        self.refused()
    def test_dependency_or_delivery_hash_changed(self):
        self.report['observations_private'][0]['artifacts_private']['wrapper']['sha256'] = '0' * 64
        self.rewrite()
        self.refused()
    def test_delivery_directory_extra_entry(self):
        self.report['observations_private'][0]['delivery_directories_private'][0]['entries_private'].append('foreign')
        self.rewrite()
        self.refused()
    def test_duplicate_key_and_nonfinite(self):
        for raw in (b'{"schema":1,"schema":2}\n', b'{"value":NaN}\n', b'{"value":1e999}\n',
                    b'{"value":9223372036854775808}\n', b'{"value":"\\ud800"}\n'):
            self.transport['stdout'] = raw
            self.refused()
    def test_nesting_before_json(self):
        self.transport['stdout'] = b'[' * 2000 + b'0' + b']' * 2000
        self.assertEqual(self.refused()['refusal_category'], 'json_structure_limit')
    def test_noncanonical_wire(self):
        self.transport['stdout'] = json.dumps(self.worker, indent=2).encode()
        self.assertEqual(self.refused()['refusal_category'], 'json_canonical_wire')
    def test_JSON_node_and_string_aggregate_bounds(self):
        with patch.object(result_core, 'MAX_NODES', 4):
            self.refused()
        with patch.object(result_core, 'MAX_STRINGS', 100):
            self.refused()
    def test_archival_size_is_separate_from_R3_capture(self):
        # A valid complete worker can repeat otherwise irrelevant real plist
        # metadata. It remains source-bound JSON but exceeds archive capacity.
        value = 'x' * 1100000
        for row in self.report['observations_private']:
            row['rootfs_version_private']['ProductCopyright'] = value
        self.rewrite()
        self.assertGreater(len(self.transport['stdout']), result_core.archive.WIRE_LIMIT)
        value = self.assess()
        self.assertTrue(value['reported_capture_completed'], value)
        self.assertFalse(value['archive_size_eligible'])
        self.assertFalse(value['cleanup_authorized'])


if __name__ == '__main__':
    unittest.main()
