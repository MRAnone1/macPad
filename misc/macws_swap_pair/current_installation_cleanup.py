"""Explicit current selection of the fixed diagnostic installation, one use.

Default/import does nothing. There is no native gate/clock/archive factory or
transport here. The explicit action requires trusted, nonserialized callbacks.
Old delivery is immutable provenance; every deletion token is acquired afresh.
Other privileged writers must be excluded: unlinkat is not conditional on inode.
"""
import base64
import hashlib
import math
import os
import re
import stat

from macws_swap_pair import installation_revalidation as provenance
from macws_swap_pair import retained_cleanup as records
from macws_swap_pair import retained_observer as physical

EXPECTED_FILES = {
    'probe.arm64': '7e60e45736d93386f667b9009d0b2e8ea81ab38c0479294ec98019fd655af886',
    'controller.py': '955c50b5cb2b30b8f0aefd69720675d04c91126dec17c802fb09be8c42197977',
    'runtime_support.py': '5d09cf9380afaa2409661a58909d1bfee41d81943f1b2306facb0cd94ee10fe0',
    'watchdog.py': 'c28ec9edd30bf86613c7cb29693697901228b579100b8b181a4dc47915f00e0a',
    'offline-QA.canonical.private.json': 'ebee0b881b5f589c4ca100c5dbcd4c72faa946b0bf741511a7396138139ae29c',
}
OWNER = (0, 0)
LABELS = ('com.macws.preflight.swap-pair.20261017', 'com.macws.preflight.swap-pair-control.20261018')
SCRATCH = ('/private/var/tmp/macws-swap-pair-20261017', '/private/var/tmp/macws-swap-pair-control-20261018')
IDENTITY = ('dev', 'ino', 'kind', 'mode', 'uid', 'gid')
MAX_FILE = 128 * 1024
MAX_NAMES = 4096
MAX_NAMES_BYTES = 32 * 1024
MAX_READ_BYTES = 4 * 1024 * 1024
SECONDS = 8

class Refused(ValueError):
    pass

def need(value, reason):
    if value is not True:
        raise Refused(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def ident(value):
    return {key: value[key] for key in IDENTITY}

def copied(value):
    return provenance.decode(provenance.canonical(value), 1024 * 1024)

def number(value):
    need(type(value) in (int, float) and math.isfinite(value) and value >= 0, 'finite_clock')
    return value

def checked_record(value):
    provenance.exact_keys(value, (*provenance.STAT_FIELDS, 'kind'))
    need(value['kind'] in ('regular', 'directory', 'other') and
         all(type(value[key]) is int and 0 <= value[key] < 1 << 63 for key in provenance.STAT_FIELDS) and
         value['ino'] > 0 and value['mode'] <= 0o7777, 'strict_current_stat')
    return copied(value)

def checked_context(value):
    provenance.exact_keys(value, ('binding', 'UI_private', 'attempt_nonce', 'clock_info', 'source_sha256'))
    meta = value['binding']
    provenance.exact_keys(meta, (*provenance.META_FIELDS, 'rootfs_product_version', 'rootfs_product_build'))
    provenance.binding({key: meta[key] for key in provenance.META_FIELDS})
    need(meta['rootfs_product_version'] == '13.4' and meta['rootfs_product_build'] == '22F66', 'rootfs_profile')
    need(type(value['attempt_nonce']) is str and re.fullmatch('[0-9a-f]{32}', value['attempt_nonce']) is not None, 'explicit_new_nonce')
    provenance.exact_keys(value['UI_private'], ('SpringBoard', 'backboardd'))
    for birth in value['UI_private'].values():
        need(type(birth) is list and len(birth) == 3 and all(type(v) is int for v in birth) and
             birth[0] > 1 and birth[1] > 0 and 0 <= birth[2] < 1000000, 'UI_birth_tuple')
    need(value['UI_private']['SpringBoard'][0] != value['UI_private']['backboardd'][0], 'distinct_UI')
    profile = value['clock_info']
    provenance.exact_keys(profile, ('domain', 'numer', 'denom'))
    need(profile['domain'] == 'mach_absolute_time.absolute_seconds.v1' and
         all(type(profile[k]) is int and 0 < profile[k] <= 1000000000 for k in ('numer', 'denom')), 'shared_clock_profile')
    provenance.exact_keys(value['source_sha256'], ('cleanup', 'physical_directory', 'stat_record', 'provenance'))
    for digest in value['source_sha256'].values(): provenance.digest(digest)
    return copied(value)

class PhysicalFS:
    """Real held-FD operations. Construction opens nothing; paths are core-owned."""
    def open_parent(self, path):
        return physical.PhysicalDirectory(path)

    def anchor(self):
        before = os.lstat('/private/var/jb')
        need(stat.S_ISLNK(before.st_mode), 'rootless_anchor_kind')
        target = os.readlink('/private/var/jb')
        need(records.stat_record(before) == records.stat_record(os.lstat('/private/var/jb')), 'rootless_anchor_race')
        return {'stat': records.stat_record(before), 'target': target}

    def open_directory(self, parent, name):
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent.fd)

    def open_file(self, directory, name):
        return os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)

    def record(self, fd):
        return records.stat_record(os.fstat(fd))

    def linked(self, parent, name):
        return records.stat_record(os.stat(name, dir_fd=parent, follow_symlinks=False))

    def snapshot(self, fd, check):
        check(); before = self.record(fd); names = []; size = 0
        with os.scandir(fd) as entries:
            for entry in entries:
                check(); word = entry.name
                need(type(word) is str and word not in ('', '.', '..') and '/' not in word and '\0' not in word, 'literal_child_name')
                size += len(word.encode('utf-8', 'strict')) + 4
                need(len(names) < MAX_NAMES and size <= MAX_NAMES_BYTES, 'bounded_directory_names')
                names.append(word)
        check(); need(before == self.record(fd), 'directory_changed_during_snapshot')
        return {'stat': before, 'names': sorted(names)}

    def read(self, fd, limit, check):
        # The bytes returned on failure remain available to the action's report.
        data = bytearray(); error = None
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            while len(data) <= limit:
                check(); block = os.read(fd, min(65536, limit + 1 - len(data)))
                if not block: break
                data.extend(block)
            need(len(data) <= limit, 'file_grew_during_read')
        except Exception as caught:
            error = type(caught).__name__
        return bytes(data), error

    def unlink(self, directory, name): os.unlink(name, dir_fd=directory)
    def rmdir(self, parent, name): os.rmdir(name, dir_fd=parent.fd)
    def close_file(self, fd): os.close(fd)
    def close_parent(self, parent):
        chain, parent.chain = parent.chain, []
        error = None
        for _, fd, _ in reversed(chain):
            try: os.close(fd)
            except OSError as caught:
                if error is None: error = caught
        if error is not None: raise error

def metadata():
    return {'schema': 'macws.current-installation-cleanup.default.v1', 'default_inert': True,
            'native_calls': 0, 'unlink_calls': 0, 'rmdir_calls': 0, 'device_acceptance': False}

class CurrentInstallationCleanup:
    """A new scoped action, not recovery of any historical OwnedFiles object."""
    def __init__(self, *, delivery_raw, delivery_sha256, archived_files, context):
        provenance.digest(delivery_sha256)
        need(type(delivery_raw) is bytes and sha(delivery_raw) == delivery_sha256, 'immutable_original_delivery_pin')
        delivery = provenance.decode(delivery_raw, 65536)
        self.rootless, to_physical = provenance._delivery(delivery)
        need(type(archived_files) is dict and set(archived_files) == set(EXPECTED_FILES), 'five_archived_files')
        self.files = []
        for row in delivery['installed_files_private']:
            name = row['name']; blob = archived_files[name]
            need(type(blob) is bytes and 0 < len(blob) <= MAX_FILE and sha(blob) == EXPECTED_FILES[name] == row['sha256'] and
                 len(blob) == row['stat']['size'], 'fixed_complete_archive_content')
            self.files.append({'name': name, 'path': to_physical(row['path']), 'sha256': row['sha256'],
                               'size': len(blob), 'mode': 0o755 if name == 'probe.arm64' else 0o600})
        self.paths = [to_physical(row['path']) for row in delivery['created_directories_private']]
        self.context = checked_context(context)
        self.delivery_sha256 = delivery_sha256
        self.archive_raw = provenance.canonical({'schema': 'macws.current-installation-cleanup.archive.v1',
            'delivery_private_b64': base64.b64encode(delivery_raw).decode('ascii'),
            'files_private_b64': {name: base64.b64encode(blob).decode('ascii') for name, blob in archived_files.items()}})
        need(len(self.archive_raw) <= 1024 * 1024, 'bounded_archive')
        self.used = False

    def run(self, *, cleanup=False, fs=None, gate=None, clock=None, verify_archive=None):
        need(type(cleanup) is bool, 'explicit_boolean_action')
        if not cleanup: return metadata()
        need(self.used is False, 'one_use_action_no_retry')
        self.used = True
        report = {'schema': 'macws.current-installation-cleanup.result.v1', 'attempted': [], 'completed': [],
            'outcome': 'refused_before_effect', 'cleanup_verified': False, 'selection_private': None,
            'gate_observations_private': [], 'file_observations_private': [], 'offending_file_copies_private': [], 'finalization_errors': [],
            'original_ownership_recovered': False, 'atomic_namespace_ownership_claimed': False,
            'native_evidence_authenticity_verified': False, 'execution_authorized': False,
            'trust_mutations': 0, 'job_mutations': 0, 'candidate_executions': 0, 'device_acceptance': False,
            'archive_sha256': sha(self.archive_raw), 'delivery_sha256': self.delivery_sha256,
            'expected_context_private': copied(self.context), 'intended_scope_private': [item['path'] for item in self.files] + list(self.paths),
            'refusal': None}
        parents, directories, handles = {}, {}, []
        last, start, charged = None, None, 0
        def tick():
            nonlocal last
            now = number(clock.now())
            need(last is None or now >= last, 'clock_regressed')
            need(start is None or 0 <= now - start < SECONDS, 'eight_second_action_deadline')
            last = now; return now
        def gates():
            before = tick(); value = copied(gate.observe(start + SECONDS)); after = tick()
            report['gate_observations_private'].append(value)
            need(len(report['gate_observations_private']) <= 9 and len(provenance.canonical(value)) <= 16384, 'gate_bounds')
            provenance.exact_keys(value, ('schema', 'attempt_nonce', 'binding', 'UI_private', 'source_sha256', 'clock_info',
                'observed_monotonic', 'thermal', 'jobs_absent', 'scratch_absent', 'no_candidate_or_test_workloads', 'exclusive_operator'))
            current_context = checked_context({key: value[key] for key in self.context})
            need(value['schema'] == 'macws.current-installation-cleanup.gates.v1' and
                 current_context == self.context, 'fresh_context_source_clock_UI')
            observed = number(value['observed_monotonic'])
            need(before <= observed <= after and after - observed <= 1, 'fresh_gate_timestamp')
            need(type(value['thermal']) is int and value['thermal'] == 0 and value['exclusive_operator'] is True and
                 value['no_candidate_or_test_workloads'] is True, 'health_or_exclusivity_refusal')
            provenance.exact_keys(value['jobs_absent'], LABELS); provenance.exact_keys(value['scratch_absent'], SCRATCH)
            need(all(v is True for group in ('jobs_absent', 'scratch_absent') for v in value[group].values()), 'job_or_scratch_present')
            need(clock.profile == self.context['clock_info'], 'shared_clock_changed')
            return observed
        def anchor():
            value = copied(fs.anchor()); record = value['stat']
            provenance.exact_keys(value, ('stat', 'target')); checked_record(record)
            need(value['target'] in (self.rootless, self.rootless + '/') and
                 (record['uid'], record['gid']) == OWNER and record['nlink'] == 1, 'rootless_anchor_scope')
            return value
        def safe_record(record, kind, mode):
            checked_record(record)
            need(record['kind'] == kind and (record['uid'], record['gid']) == OWNER and record['mode'] == mode and
                 record['ino'] > 0 and record['nlink'] > 0, 'current_kind_owner_mode')
            if kind == 'regular': need(record['nlink'] == 1 and 0 < record['size'] <= MAX_FILE, 'current_file_size_links')
        def read_file(item):
            nonlocal charged
            tick(); fd = item['fd']; before = checked_record(fs.record(fd))
            observation = {'path': item['path'], 'stat_before': before}
            report['file_observations_private'].append(observation)
            safe_record(before, 'regular', item['mode'])
            raw, error = fs.read(fd, before['size'], tick)
            need(type(raw) is bytes and len(raw) <= MAX_FILE + 1 and
                 (error is None or type(error) is str and len(error) <= 64), 'bounded_read_callback_result')
            charged += len(raw); need(charged <= MAX_READ_BYTES, 'total_file_read_budget')
            after = checked_record(fs.record(fd)); linked = checked_record(fs.linked(item['directory']['fd'], item['name']))
            observation.update(stat_after=after, linked_stat=linked, copied_bytes=len(raw), sha256=sha(raw), read_error=error)
            good = (error is None and before == after == linked and len(raw) == item['size'] == before['size'] and sha(raw) == item['sha256'])
            if not good:
                report['offending_file_copies_private'].append({'path': item['path'], 'bytes_private_b64': base64.b64encode(raw).decode('ascii'),
                    'before': before, 'after': after, 'linked': linked, 'read_error': error})
            need(good, 'current_file_bytes_or_link_changed')
            if 'selected' in item: need(before == item['selected'], 'current_selected_full_file_token_changed')
            return before
        def snapshot(fd):
            value = copied(fs.snapshot(fd, tick)); provenance.exact_keys(value, ('stat', 'names'))
            checked_record(value['stat']); provenance.names(value['names'])
            return value
        def checked_namespace(update=None):
            tick(); need(anchor() == selected_anchor, 'rootless_anchor_changed')
            for parent in parents.values():
                parent['handle'].checked(); snap = snapshot(parent['handle'].fd)
                if update is parent:
                    need(ident(snap['stat']) == ident(parent['snapshot']['stat']) and snap['names'] == sorted(parent['remaining']), 'parent_after_own_removal')
                    parent['snapshot'] = snap
                else: need(snap == parent['snapshot'], 'parent_namespace_or_token_changed')
            for directory in directories.values():
                parent = directory['parent']; name = directory['name']
                if directory['removed']:
                    try: fs.linked(parent['handle'].fd, name)
                    except FileNotFoundError: continue
                    raise Refused('removed_directory_reappeared')
                snap = snapshot(directory['fd'])
                need(snap['stat'] == checked_record(fs.linked(parent['handle'].fd, name)), 'directory_link_changed')
                if update is directory:
                    need(ident(snap['stat']) == ident(directory['snapshot']['stat']) and snap['names'] == sorted(directory['remaining']), 'directory_after_own_unlink')
                    directory['snapshot'] = snap
                else: need(snap == directory['snapshot'], 'directory_namespace_or_full_token_changed')
                for item in directory['files']:
                    if item['name'] in directory['remaining']: read_file(item)
            tick()
        try:
            need(all(value is not None for value in (fs, gate, clock, verify_archive)), 'explicit_trusted_callbacks_required')
            # A direct callback return, not a serialized receipt bit, is required.
            need(verify_archive(self.archive_raw, sha(self.archive_raw)) is None, 'archive_callback_contract')
            report['archive_callback_completed'] = True
            start = tick(); gates(); selected_anchor = anchor()
            report['selection_private'] = {'anchor': selected_anchor, 'parents': {}, 'directories': {}, 'files': {}}
            for path in self.paths:
                parent_path, name = path.rsplit('/', 1)
                parent = parents.get(parent_path)
                if parent is None:
                    handle = fs.open_parent(parent_path); handles.append(('parent', handle))
                    parent = {'handle': handle, 'snapshot': snapshot(handle.fd)}
                    report['selection_private']['parents'][parent_path] = parent['snapshot']
                    safe_record(parent['snapshot']['stat'], 'directory', 0o755)
                    parent['remaining'] = set(parent['snapshot']['names']); parents[parent_path] = parent
                fd = fs.open_directory(parent['handle'], name); handles.append(('file', fd))
                directory = {'fd': fd, 'name': name, 'parent': parent, 'snapshot': snapshot(fd), 'removed': False, 'files': []}
                report['selection_private']['directories'][path] = directory['snapshot']
                safe_record(directory['snapshot']['stat'], 'directory', 0o700)
                need(directory['snapshot']['stat'] == checked_record(fs.linked(parent['handle'].fd, name)), 'selected_directory_link')
                for spec in self.files:
                    if spec['path'].rsplit('/', 1)[0] != path: continue
                    child = fs.open_file(fd, spec['name']); handles.append(('file', child))
                    item = dict(spec, fd=child, directory=directory); item['selected'] = read_file(item); directory['files'].append(item)
                    report['selection_private']['files'][item['path']] = {'stat': item['selected'], 'sha256': item['sha256']}
                directory['remaining'] = {item['name'] for item in directory['files']}
                need(directory['snapshot']['names'] == sorted(directory['remaining']), 'exact_five_children_no_foreign_entries')
                directories[path] = directory
            need(len(directories) == 2 and sum(len(d['files']) for d in directories.values()) == 5, 'all_seven_objects_required')
            checked_namespace()
            report['all_seven_prevalidated'] = True
            for path, directory in directories.items():
                for item in directory['files']:
                    observed = gates(); checked_namespace(); need(tick() - observed <= 1, 'gate_stale_before_unlink')
                    report['attempted'].append({'operation': 'unlink', 'path': item['path']})
                    fs.unlink(directory['fd'], item['name'])
                    report['completed'].append({'operation': 'unlink', 'path': item['path']})
                    directory['remaining'].remove(item['name'])
                    removed = checked_record(fs.record(item['fd']))
                    need(removed['nlink'] == 0 and all(removed[k] == item['selected'][k] for k in (*IDENTITY, 'size', 'mtime_ns')), 'held_file_not_unlinked_as_expected')
                    checked_namespace(update=directory)
                observed = gates(); checked_namespace(); need(tick() - observed <= 1, 'gate_stale_before_rmdir')
                report['attempted'].append({'operation': 'rmdir', 'path': path})
                fs.rmdir(directory['parent']['handle'], directory['name'])
                report['completed'].append({'operation': 'rmdir', 'path': path})
                directory['removed'] = True; directory['parent']['remaining'].remove(directory['name'])
                removed = checked_record(fs.record(directory['fd']))
                need(ident(removed) == ident(directory['snapshot']['stat']), 'held_directory_identity_changed')
                # Darwin may retain a positive nlink on this open removed FD.
                # The namespace check below requires ENOENT and the exact parent
                # name set minus this name, preserving every other entry.
                report.setdefault('removed_directory_records_private', []).append({'path': path, 'held_stat_after': removed})
                checked_namespace(update=directory['parent'])
            observed = gates(); checked_namespace(); need(tick() - observed <= 1, 'gate_stale_at_final_verification')
            report.update(cleanup_verified=True, outcome='scoped_paths_absent_after_effects')
        except Exception as error:
            report['outcome'] = 'partial_or_unknown' if report['attempted'] else 'refused_before_effect'
            report['refusal'] = str(error) if type(error) is Refused else type(error).__name__
        finally:
            for kind, handle in reversed(handles):
                try:
                    fs.close_parent(handle) if kind == 'parent' else fs.close_file(handle)
                except Exception as error:
                    report['finalization_errors'].append(type(error).__name__); report['cleanup_verified'] = False
                    report['outcome'] = 'partial_or_unknown' if report['attempted'] else 'refused_before_effect'
            if start is not None:
                try:
                    end = tick(); report['elapsed_seconds'] = end - start
                    if report['cleanup_verified']:
                        need(end - report['gate_observations_private'][-1]['observed_monotonic'] <= 1, 'gate_stale_after_close')
                except Exception as error:
                    report['cleanup_verified'] = False; report['finalization_errors'].append(type(error).__name__)
                    report['outcome'] = 'partial_or_unknown' if report['attempted'] else 'refused_before_effect'
            report['file_read_bytes'] = charged
        return report
