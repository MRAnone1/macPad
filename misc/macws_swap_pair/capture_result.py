"""Pure host interpretation of a source-bound retained read-only capture.

The trusted caller has already selected reviewed source pins and historical
Inputs. This module does no I/O. Even a coherent positive JSON report establishes
only what the selected worker reported, never fresh native or cleanup authority.
The caller must persist every original transport byte before calling assess.
"""
import base64
import hashlib
import json
import math
import re
import struct

from macws_swap_pair import retained_cleanup as cleanup
from macws_swap_pair import retained_archive as archive
from macws_swap_pair import readonly_observer as readonly
from macws_swap_pair import retained_observer as observer

MAX_STDOUT = 4 * 1024 * 1024
MAX_STDERR = 16 * 1024
MAX_DEPTH = 24
MAX_NODES = 100000
MAX_STRINGS = MAX_STDOUT
EVIDENCE = ('config', 'control_wire', 'host', 'delivery', 'retirement_wire', 'snapshot')
SOURCES = ('process_retirement.py', 'cleanup_payload.py', 'reviewed_delivery_plan.json',
           'retained_inputs.py', 'retained_cleanup.py', 'readonly_observer.py', 'retained_observer.py')
ENTRY_NAMES = frozenset(['evidence.' + x for x in EVIDENCE] + ['source.' + x for x in SOURCES])
LOAD_ORDER = ['retained_cleanup', 'readonly_observer', 'retained_inputs', 'retained_observer']
TRANSPORT_KEYS = frozenset(('returncode', 'stdout', 'stderr', 'timed_out', 'output_limit_exceeded',
                            'stdin_complete', 'capture_complete', 'local_cleanup_errors_private'))
WORKER_KEYS = frozenset(('schema', 'capture_requested', 'default_inert', 'capture_completed',
    'capture_only_not_cleanup_admission', 'cleanup_authorized', 'device_acceptance', 'freeze_fix',
    'original_ownership_recovered', 'native_backend_construction_attempted', 'native_backend_constructed',
    'helper_modules_executed', 'capture_report_private', 'capture_report_omitted',
    'worker_error_category', 'worker_refusal_category', 'stage', 'hard_seconds', 'output_limit_bytes',
    'output_limit_exceeded', 'codec_sha256', 'frame_sha256', 'entry_sha256'))
GATE_KEYS = frozenset(('schema', 'selection_sha256', 'provenance_sha256', 'boot_private',
    'config_sha256', 'source_sha256', 'UI_private', 'exclusive_operator', 'observed_monotonic',
    'jobs_absent', 'no_candidate_or_test_workloads', 'other_scratch_absent', 'artifacts_unchanged',
    'thermal', 'generation_absence'))


class Refused(ValueError):
    pass


def need(value, category):
    if value is not True:
        raise Refused(category)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def keys(value, names, category):
    need(type(value) is dict and set(value) == set(names), category)


def same(a, b):
    # JSON canonical comparison avoids Python's True == 1 and 1 == 1.0 aliases.
    return json.dumps(a, sort_keys=True, separators=(',', ':'), allow_nan=False) == json.dumps(
        b, sort_keys=True, separators=(',', ':'), allow_nan=False)


def integer(value, low=0, high=(1 << 63) - 1):
    return type(value) is int and low <= value <= high


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def pin(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _tree(value, depth=0, budget=None):
    budget = [MAX_NODES, MAX_STRINGS] if budget is None else budget
    budget[0] -= 1
    need(depth <= MAX_DEPTH and budget[0] >= 0, 'json_structure_limit')
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        need(-(1 << 63) <= value < 1 << 63, 'json_integer_limit')
        return
    if type(value) is float:
        need(math.isfinite(value), 'json_finite_number')
        return
    if type(value) is str:
        need(len(value) <= MAX_STRINGS, 'json_string_limit')
        budget[1] -= len(value.encode('utf-8'))
        need(budget[1] >= 0, 'json_string_aggregate_limit')
        return
    if type(value) is list:
        need(len(value) <= 8192, 'json_array_limit')
        for item in value:
            _tree(item, depth + 1, budget)
        return
    need(type(value) is dict and len(value) <= 256 and all(type(k) is str and len(k) <= 256
        for k in value), 'json_object_limit')
    for key, item in value.items():
        _tree(key, depth + 1, budget)
        _tree(item, depth + 1, budget)


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_STDOUT, 'json_bytes_limit')
    # Bound nesting and separators before invoking json's recursive parser.
    depth = separators = 0
    quoted = escaped = False
    for byte in raw:
        need(byte < 128, 'json_canonical_ascii')
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            need(depth <= MAX_DEPTH, 'json_structure_limit')
        elif byte in (93, 125):
            depth -= 1
            need(depth >= 0, 'json_structure_limit')
        elif byte in (44, 58):
            separators += 1
            need(separators <= MAX_NODES, 'json_structure_limit')
    need(depth == 0 and not quoted, 'json_incomplete')
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'json_duplicate_key')
            value[key] = item
        return value
    def reject(_):
        raise Refused('json_finite_number')
    def parse_int(word):
        need(len(word) <= 20, 'json_integer_limit')
        return int(word)
    value = json.loads(raw, object_pairs_hook=pairs, parse_int=parse_int, parse_constant=reject)
    _tree(value)
    need(type(value) is dict, 'json_one_object')
    need((json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                     allow_nan=False) + '\n').encode('ascii') == raw, 'json_canonical_wire')
    return value


def b64(value, limit):
    need(type(value) is str and len(value) <= 4 * ((limit + 2) // 3), 'base64_limit')
    raw = base64.b64decode(value, validate=True)
    need(len(raw) <= limit and base64.b64encode(raw).decode('ascii') == value, 'base64_canonical')
    return raw


def gate_checked(gate, context, selection_sha, provenance_sha):
    keys(gate, GATE_KEYS, 'capture_gate_fields')
    need(gate['schema'] == 'macws.retained-artifact.gates.v1' and
         gate['selection_sha256'] == selection_sha and gate['provenance_sha256'] == provenance_sha and
         gate['boot_private'] == context['boot_private'] and
         gate['config_sha256'] == context['config_sha256'] and
         same(gate['source_sha256'], context['source_sha256']) and
         same(gate['UI_private'], context['UI_private']), 'capture_gate_binding')
    need(all(gate[x] is True for x in ('exclusive_operator', 'no_candidate_or_test_workloads',
        'other_scratch_absent', 'artifacts_unchanged')), 'capture_gate_refused')
    keys(gate['jobs_absent'], cleanup.SERVICES, 'capture_gate_jobs')
    need(all(x is True for x in gate['jobs_absent'].values()) and
         type(gate['thermal']) is int and gate['thermal'] == 0 and
         number(gate['observed_monotonic']), 'capture_gate_health')
    cleanup._absence(gate['generation_absence'], context['retired_birth_private'])


def selected_copy(value, context, expected_files):
    keys(value, ('manifest_private', 'files_private'), 'capture_copy_fields')
    manifest = cleanup.selection_checked(value['manifest_private'], context, expected_files)
    keys(value['files_private'], cleanup.NAMES, 'capture_copy_file_names')
    files = {name: b64(value['files_private'][name], cleanup.LIMITS[name]) for name in cleanup.NAMES}
    need(files == expected_files, 'capture_copy_old_content_binding')
    return manifest, files


def _command(row):
    keys(row, ('argv_private', 'attempted', 'result_known', 'stdout_private_b64',
               'stderr_private_b64', 'child_cleanup_attempted', 'returncode'), 'command_fields')
    need(row['attempted'] is True and row['result_known'] is True and
         row['child_cleanup_attempted'] is False and integer(row['returncode'], -(1 << 31), (1 << 31) - 1),
         'command_completion')
    readonly.readonly_command_allowed(row['argv_private'])
    out = b64(row['stdout_private_b64'], observer.LIMITS['command_stdout'])
    err = b64(row['stderr_private_b64'], observer.LIMITS['command_stderr'])
    return [row['returncode'], out.decode('utf-8'), err.decode('utf-8')], len(out) + len(err)


def _ui(value, name, birth):
    keys(value, ('path', 'birth_private', 'stopped', 'native_status_private', 'native_status_name',
        'raw_bsdinfo_private_hex', 'raw_bsdinfo_sha256', 'returned_bsdinfo_bytes', 'bsdinfo_errno',
        'state_source'), 'UI_fields')
    need(type(value['path']) is str and value['path'].rsplit('/', 1)[-1] == name and
         same(value['birth_private'], birth) and value['stopped'] is False and
         type(value['native_status_private']) is int and value['native_status_private'] in (2, 3) and
         value['native_status_name'] == {2: 'SRUN', 3: 'SSLEEP'}[value['native_status_private']] and
         type(value['returned_bsdinfo_bytes']) is int and value['returned_bsdinfo_bytes'] == 136 and
         type(value['bsdinfo_errno']) is int and value['bsdinfo_errno'] == 0 and
         value['state_source'] == 'proc_bsdinfo.pbi_status', 'UI_context')
    rawhex = value['raw_bsdinfo_private_hex']
    need(type(rawhex) is str and re.fullmatch('[0-9a-f]{272}', rawhex) is not None, 'UI_raw_block')
    raw = bytes.fromhex(rawhex)
    need(sha(raw) == value['raw_bsdinfo_sha256'] and struct.unpack_from('<I', raw, 4)[0] == value['native_status_private'] and
         [struct.unpack_from('<I', raw, 12)[0], *struct.unpack_from('<QQ', raw, 120)] == birth,
         'UI_raw_binding')


def _native_queries(rows, observations, context):
    need(type(rows) is list and len(rows) == 6, 'native_query_trace_count')
    for phase in range(2):
        for offset, name in enumerate(('SpringBoard', 'backboardd')):
            row = rows[phase * 3 + offset]
            keys(row, ('api', 'flavor', 'requested_bytes', 'returned', 'errno', 'pid_private',
                'expected_birth_private', 'raw_bsdinfo_private_hex', 'raw_bsdinfo_sha256',
                'path_returned', 'path_private_b64'), 'native_UI_query_fields')
            state = observations[phase]['UI_details_private'][name]
            need(row['api'] == 'proc_pidinfo' and all(type(row[k]) is int and row[k] == v for k, v in (
                ('flavor', 3), ('requested_bytes', 136), ('returned', 136), ('errno', 0),
                ('pid_private', context['UI_private'][name][0]))) and row['expected_birth_private'] is None and
                row['raw_bsdinfo_private_hex'] == state['raw_bsdinfo_private_hex'] and
                row['raw_bsdinfo_sha256'] == state['raw_bsdinfo_sha256'], 'native_UI_query_binding')
            path = b64(row['path_private_b64'], 4096)
            need(integer(row['path_returned'], 1, 4095) and len(path) == row['path_returned'] and
                 path.split(b'\0', 1)[0].decode('utf-8') == state['path'], 'native_UI_path_binding')
        row = rows[phase * 3 + 2]
        keys(row, ('api', 'flavor', 'requested_bytes', 'returned', 'errno', 'pid_private',
            'expected_birth_private', 'raw_bsdinfo_private_hex', 'raw_bsdinfo_sha256', 'outcome'),
            'native_absence_query_fields')
        need(row['raw_bsdinfo_private_hex'] == '' and row['raw_bsdinfo_sha256'] == sha(b''),
             'native_absence_query_raw')
        cleanup._absence({k: row[k] for k in ('api', 'flavor', 'requested_bytes', 'returned', 'errno',
            'outcome', 'pid_private', 'expected_birth_private')}, context['retired_birth_private'])
        need(same(observations[phase]['generation_absence_private'],
            {k: row[k] for k in observations[phase]['generation_absence_private']}), 'native_absence_gate_binding')


def _artifacts(row, inputs, trust):
    delivery = inputs.delivery
    keys(row['artifacts_private'], [x['path'] for x in delivery['installed_files_private']] +
         list(readonly.DEPENDENCIES), 'artifact_set')
    copied = 0
    for item in delivery['installed_files_private']:
        artifact = row['artifacts_private'][item['path']]
        keys(artifact, ('stat', 'sha256', 'signature') if item['name'] == 'probe.arm64' else
             ('stat', 'sha256'), 'artifact_fields')
        observer.typed_record(artifact['stat'], 'regular')
        need(all(same(artifact['stat'][k], value) for k, value in item['stat'].items()) and
             artifact['stat']['nlink'] == 1 and artifact['sha256'] == item['sha256'], 'delivered_artifact_binding')
        if item['name'] == 'probe.arm64':
            need(same(artifact['signature'], delivery['probe_signature']) and
                 artifact['signature']['cdhash'] in trust, 'delivered_probe_signature')
        copied += artifact['stat']['size']
    for name, expected in readonly.DEPENDENCIES.items():
        artifact = row['artifacts_private'][name]
        keys(artifact, ('stat', 'sha256', 'signature'), 'dependency_artifact_fields')
        observer.typed_record(artifact['stat'], 'regular')
        signature = artifact['signature']
        keys(signature, ('architecture', 'uuid', 'cdhash', 'hash_type', 'signed_pages_checked',
                         'code_limit', 'page_hashes_valid'), 'dependency_signature_fields')
        need(artifact['stat']['nlink'] == 1 and artifact['sha256'] == expected['sha256'] and
             all(signature[k] == expected[k] for k in ('architecture', 'uuid')) and
             signature['cdhash'] in trust and type(signature['hash_type']) is int and
             signature['hash_type'] in (1, 2, 3, 4) and integer(signature['signed_pages_checked'], 1) and
             integer(signature['code_limit'], 1, artifact['stat']['size'] - 1) and signature['page_hashes_valid'] is True,
             'dependency_signature_binding')
        copied += artifact['stat']['size']
    directories = row['delivery_directories_private']
    need(type(directories) is list and len(directories) == len(delivery['created_directories_private']) == 2,
         'delivery_directory_count')
    for actual, expected in zip(directories, delivery['created_directories_private']):
        keys(actual, ('path_private', 'stat_private', 'entries_private'), 'delivery_directory_fields')
        observer.typed_record(actual['stat_private'], 'directory')
        names = sorted(x['name'] for x in delivery['installed_files_private']
                       if x['path'].rsplit('/', 1)[0] == expected['path'])
        need(actual['path_private'] == expected['path'] and actual['entries_private'] == names and
             all(same(actual['stat_private'][k], v) for k, v in expected['stat'].items()),
             'delivery_directory_binding')
    return copied


def observer_checked(report, gates, inputs, context):
    keys(report, ('schema', 'observations_private', 'commands_private', 'native_queries_private',
        'copied_command_bytes', 'native_query_count', 'native_clock_read_count', 'copied_file_bytes',
        'clock_reads', 'limits', 'existing_workload_or_file_mutations', 'candidate_executions',
        'existing_job_signals', 'managed_read_child_cleanup_attempts', 'cleanup_authorized',
        'device_acceptance', 'original_ownership_recovered'), 'observer_report_fields')
    need(report['schema'] == 'macws.retained-artifact.observer-report.v1' and
         same(report['limits'], observer.LIMITS), 'observer_report_identity')
    need(all(type(report[x]) is int and report[x] == 0 for x in ('existing_workload_or_file_mutations',
        'candidate_executions', 'existing_job_signals', 'managed_read_child_cleanup_attempts')) and
         all(report[x] is False for x in ('cleanup_authorized', 'device_acceptance', 'original_ownership_recovered')),
         'observer_report_effects')
    for key, limit in (('copied_command_bytes', 'all_command_bytes'), ('copied_file_bytes', 'read_bytes'),
                       ('native_query_count', 'native_queries'), ('native_clock_read_count', 'clock_reads'),
                       ('clock_reads', 'clock_reads')):
        need(integer(report[key], 1, observer.LIMITS[limit]), 'observer_counter_limit')
    need(report['native_query_count'] == 20, 'observer_native_query_count')
    observations = report['observations_private']
    need(type(observations) is list and len(observations) == 2, 'observer_observation_count')
    commands = report['commands_private']
    need(type(commands) is list and len(commands) == 8, 'observer_command_count')
    copies = [_command(x) for x in commands]
    need(sum(x[1] for x in copies) == report['copied_command_bytes'], 'observer_copied_command_bytes')
    rs = inputs.original.runtime
    previous_finish = None
    anchors = []
    trust_initial = None
    copied_files = 2 * sum(len(x) for x in inputs.expected_files.values())
    for index, (row, gate) in enumerate(zip(observations, gates)):
        keys(row, ('started_monotonic_private', 'completed', 'stage', 'rootless_anchor_private',
            'rootless_parent_observations_private', 'metadata_private', 'rootfs_version_private',
            'process_command_private', 'process_rows_private', 'UI_details_private', 'jobs_private',
            'generation_absence_private', 'thermal', 'trust_command_private', 'trust_members_private',
            'artifacts_private', 'delivery_directories_private', 'finished_monotonic_private', 'gate_private'),
            'observer_observation_fields')
        start, finish = row['started_monotonic_private'], row['finished_monotonic_private']
        need(row['completed'] is True and row['stage'] == 'complete' and number(start) and number(finish) and
             start <= finish and finish - start <= observer.LIMITS['max_gate_age'] and
             (previous_finish is None or previous_finish <= start) and
             gate['observed_monotonic'] == start and same(row['gate_private'], gate), 'observer_gate_timing')
        previous_finish = finish
        need(finish - observations[0]['started_monotonic_private'] < observer.LIMITS['seconds'], 'observer_global_time')
        need(row['metadata_private'] == {'hw.machine': 'iPad13,6', 'kern.osversion': '20E252',
             'kern.uuid': row['metadata_private'].get('kern.uuid'), 'kern.bootsessionuuid': context['boot_private']} and
             type(row['metadata_private']['kern.uuid']) is str and
             row['metadata_private']['kern.uuid'].lower() == 'd6b9e234-64f1-30ea-ae62-ed8f2dc6efdb', 'observer_device_identity')
        version = row['rootfs_version_private']
        need(type(version) is dict and version.get('ProductVersion') == '13.4' and
             version.get('ProductBuildVersion') == '22F66', 'observer_rootfs_identity')
        roots = row['rootless_anchor_private']; parents = row['rootless_parent_observations_private']
        need(type(roots) is list and len(roots) == 2 and same(roots[0], roots[1]) and
             type(parents) is list and len(parents) == 2 and same(parents[0], parents[1]), 'observer_anchor_stability')
        keys(roots[0], ('stat_private', 'link_private'), 'observer_anchor_fields')
        observer.typed_record(roots[0]['stat_private'], 'other')
        need(roots[0]['stat_private']['uid'] == roots[0]['stat_private']['gid'] == 0, 'observer_anchor_owner')
        parent = next(x for x in inputs.delivery['parents_private'] if x['logical'] == '/var/jb/usr/libexec')
        root = parent['resolved'][:-len('/usr/libexec')]
        need(parent['resolved'].endswith('/usr/libexec') and root.startswith('/private/preboot/') and
             roots[0]['link_private'] in (root, root + '/'), 'observer_anchor_original_target')
        observer.typed_record(parents[0], 'directory')
        need(all(same(parents[0][k], parent['stat'][k]) for k in ('dev', 'ino', 'mode', 'uid', 'gid')),
             'observer_anchor_original_parent')
        anchors.append(roots[0])
        phase = copies[index * 4:(index + 1) * 4]
        argv = [commands[index * 4 + at]['argv_private'] for at in range(4)]
        need(argv == [['/bin/ps', '-eo', 'pid,comm'], [rs.LAUNCHCTL, 'print', cleanup.SERVICES[0]],
                      [rs.LAUNCHCTL, 'print', cleanup.SERVICES[1]], [rs.JBCTL, 'trustcache', 'info']],
             'observer_command_sequence')
        ps = phase[0][0]
        need(ps[0] == 0 and ps[2] == '' and same(ps, row['process_command_private']), 'observer_process_command_binding')
        process_rows = readonly.process_rows(ps[1])
        need(same(process_rows, row['process_rows_private']), 'observer_process_rows_binding')
        need(not any(x['basename'] in readonly.BLOCKED_BASENAMES or ('macws' in x['basename'].lower() and
             any(w in x['basename'].lower() for w in ('windowserver', 'debug', 'producer', 'observer', 'swap-pair')))
             for x in process_rows), 'observer_blocked_workload')
        keys(row['UI_details_private'], ('SpringBoard', 'backboardd'), 'observer_UI_fields')
        for name, birth in context['UI_private'].items():
            matches = [x for x in process_rows if x['basename'] == name]
            need(len(matches) == 1 and matches[0]['pid_private'] == birth[0], 'observer_UI_unique_process')
            _ui(row['UI_details_private'][name], name, birth)
        keys(row['jobs_private'], cleanup.SERVICES, 'observer_job_fields')
        for at, service in enumerate(cleanup.SERVICES):
            command = phase[at + 1][0]
            config = dict(inputs.original.config, operation='run' if at == 0 else 'control_normal')
            need(same(command, row['jobs_private'][service]) and rs.parsed_job(config, command) is None,
                 'observer_exact_job_absence')
        cleanup._absence(row['generation_absence_private'], context['retired_birth_private'])
        need(same(row['generation_absence_private'], gate['generation_absence']) and
             type(row['thermal']) is int and row['thermal'] == 0, 'observer_generation_thermal_binding')
        trust_command = phase[3][0]
        need(trust_command[0] == 0 and trust_command[2] == '' and
             same(trust_command, row['trust_command_private']), 'observer_trust_command_binding')
        trust = readonly.trust_rows(trust_command[1])
        need(sorted(trust) == row['trust_members_private'] and
             (trust_initial is None or trust_initial == trust), 'observer_trust_stability')
        trust_initial = trust
        copied_files += _artifacts(row, inputs, trust)
    need(same(anchors[0], anchors[1]), 'observer_session_anchor_stability')
    need(report['copied_file_bytes'] > copied_files, 'observer_file_byte_lower_bound')
    _native_queries(report['native_queries_private'], observations, context)


def assess(result, *, expected, inputs):
    """Return bounded summary only; this never archives, retries or grants actions."""
    summary = {'schema': 'macws.retained-artifact.host-assessment.v1',
        'source_bound_capture_received': False, 'reported_capture_completed': False,
        'archive_size_eligible': False, 'current_wire_sha256': None, 'manifest_sha256': None,
        'file_sha256': None, 'provenance_base_sha256': None, 'refusal_category': None,
        'cleanup_authorized': False, 'native_evidence_authenticity_verified': False,
        'fresh_cleanup_gates_verified': False, 'device_acceptance': False, 'freeze_fix': False,
        'original_ownership_recovered': False, 'automatic_retry': False}
    try:
        keys(expected, ('payload_sha256', 'codec_sha256', 'frame_sha256', 'entry_sha256'), 'expected_pin_fields')
        need(all(pin(expected[k]) for k in ('payload_sha256', 'codec_sha256', 'frame_sha256')), 'expected_pin_shape')
        keys(expected['entry_sha256'], ENTRY_NAMES, 'expected_entry_names')
        need(all(pin(x) for x in expected['entry_sha256'].values()), 'expected_entry_pins')
        need(inputs.intact() is True, 'historical_inputs_intact')
        context = cleanup.context_checked(inputs.context)
        expected_files = inputs.expected_files
        original_bytes = inputs.original_bytes
        need(type(original_bytes) is dict and set(original_bytes) == set(EVIDENCE) and
             all(type(raw) is bytes and 0 < len(raw) <= 512 * 1024 and
                 expected['entry_sha256']['evidence.' + name] == sha(raw)
                 for name, raw in original_bytes.items()), 'historical_input_entry_binding')
        keys(result, TRANSPORT_KEYS if 'transport_error_private' not in result else
             TRANSPORT_KEYS | {'transport_error_private'}, 'transport_fields')
        need(type(result['stdout']) is bytes and len(result['stdout']) <= MAX_STDOUT + 1 and
             type(result['stderr']) is bytes and len(result['stderr']) <= MAX_STDERR + 1 and
             (type(result['returncode']) is int or result['returncode'] is None) and
             all(type(result[k]) is bool for k in ('timed_out', 'output_limit_exceeded', 'capture_complete')) and
             (type(result['stdin_complete']) is bool or result['stdin_complete'] is None) and
             type(result['local_cleanup_errors_private']) is list, 'transport_types')
        need(result['capture_complete'] is True and result['stdin_complete'] is True and
             result['timed_out'] is False and result['output_limit_exceeded'] is False and
             type(result['returncode']) is int and result['returncode'] == 0 and
             result['stderr'] == b'' and result['local_cleanup_errors_private'] == [] and
             'transport_error_private' not in result, 'transport_incomplete_or_negative')
        wire = result['stdout']
        worker = decode(wire)
        keys(worker, WORKER_KEYS, 'worker_fields')
        need(worker['schema'] == 'macws.retained-artifact.worker.private.v1' and
             worker['codec_sha256'] == expected['codec_sha256'] and
             worker['frame_sha256'] == expected['frame_sha256'] and
             same(worker['entry_sha256'], expected['entry_sha256']) and
             same(worker['helper_modules_executed'], LOAD_ORDER), 'worker_identity')
        need(all(worker[x] is True for x in ('capture_requested', 'capture_completed',
             'capture_only_not_cleanup_admission', 'native_backend_construction_attempted', 'native_backend_constructed')) and
             all(worker[x] is False for x in ('default_inert', 'cleanup_authorized', 'device_acceptance',
             'freeze_fix', 'original_ownership_recovered', 'capture_report_omitted', 'output_limit_exceeded')) and
             worker['worker_error_category'] is None and worker['worker_refusal_category'] is None and
             worker['stage'] == 'capture_complete' and type(worker['hard_seconds']) is int and
             worker['hard_seconds'] == 12 and type(worker['output_limit_bytes']) is int and
             worker['output_limit_bytes'] == MAX_STDOUT, 'worker_completion')
        capture = worker['capture_report_private']
        keys(capture, ('schema', 'capture_completed', 'capture_only_not_cleanup_admission',
             'cleanup_authorized', 'device_acceptance', 'existing_workload_or_file_mutations',
             'files_private', 'manifest_private', 'selection_copies_private', 'error_category',
             'refusal', 'pre_capture_gate_private', 'post_capture_gate_private', 'observer_private'), 'capture_fields')
        need(capture['schema'] == 'macws.retained-artifact.read-only-capture.v1' and
             capture['capture_completed'] is True and capture['capture_only_not_cleanup_admission'] is True and
             capture['cleanup_authorized'] is False and capture['device_acceptance'] is False and
             type(capture['existing_workload_or_file_mutations']) is int and
             capture['existing_workload_or_file_mutations'] == 0 and capture['error_category'] is None and
             capture['refusal'] is None, 'capture_completion')
        copies = capture['selection_copies_private']
        need(type(copies) is list and len(copies) == 2, 'capture_selection_copy_count')
        first, first_files = selected_copy(copies[0], context, expected_files)
        second, second_files = selected_copy(copies[1], context, expected_files)
        need(same(first, second) and first_files == second_files and same(capture['manifest_private'], second) and
             same(capture['files_private'], copies[1]['files_private']), 'capture_selection_stability')
        provenance = inputs.provenance_base
        keys(provenance, set(cleanup.PROVENANCE_KEYS) - {'current_wire_sha256'}, 'capture_provenance_fields')
        need(all(pin(x) for x in provenance.values()) and provenance['effective_config_sha256'] == context['config_sha256'],
             'capture_provenance_binding')
        provenance_sha = sha(cleanup.canonical(provenance))
        manifest_sha = sha(cleanup.canonical(second))
        gates = [capture['pre_capture_gate_private'], capture['post_capture_gate_private']]
        for gate, selection_sha in zip(gates, ('0' * 64, manifest_sha)):
            gate_checked(gate, context, selection_sha, provenance_sha)
        observer_checked(capture['observer_private'], gates, inputs, context)
        summary.update(source_bound_capture_received=True, reported_capture_completed=True,
             archive_size_eligible=len(wire) <= archive.WIRE_LIMIT, current_wire_sha256=sha(wire),
             manifest_sha256=manifest_sha, file_sha256={name: sha(raw) for name, raw in second_files.items()},
             provenance_base_sha256=provenance_sha)
    except Refused as error:
        summary['refusal_category'] = str(error)
    except Exception:
        # Pinned helper validators intentionally use different exception types.
        # Unknown shapes and helper refusals never escape as apparent success or
        # echo their potentially private exception text into this summary.
        summary['refusal_category'] = 'invalid_bounded_capture'
    return summary
