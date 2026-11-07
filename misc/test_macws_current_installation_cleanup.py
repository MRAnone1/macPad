"""Invented metadata and host-owned temp files only. No device/native gate."""
import base64
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from macws_swap_pair import current_installation_cleanup as core
import test_macws_installation_revalidation as old_fixture

class Clock:
    profile = {'domain': 'mach_absolute_time.absolute_seconds.v1', 'numer': 1, 'denom': 1}
    def __init__(self): self.value = 1000; self.calls = 0
    def now(self): self.calls += 1; self.value += .00001; return self.value

class Gate:
    def __init__(self, context, clock): self.context = context; self.clock = clock; self.calls = 0; self.hook = None
    def observe(self, deadline):
        self.calls += 1
        result = dict(copy.deepcopy(self.context), schema='macws.current-installation-cleanup.gates.v1',
            observed_monotonic=self.clock.now(), thermal=0, jobs_absent={name: True for name in core.LABELS},
            scratch_absent={name: True for name in core.SCRATCH}, no_candidate_or_test_workloads=True, exclusive_operator=True)
        if self.hook: self.hook(self.calls, result)
        return result

class MappedFS(core.PhysicalFS):
    """Only the two fixed virtual parents map to this test's private temp roots."""
    def __init__(self, root, original, blobs):
        self.events = []; self.opened_files = 0; self.hook_unlink = None; self.hook_rmdir = None; self.hook_read = None
        self.original = original; self.parents = {}; self.targets = {}
        rootless, physical = core.provenance._delivery(original)
        self.rootless = rootless
        for index, row in enumerate(original['parents_private']):
            path = root / str(index) / 'libexec'; path.mkdir(parents=True); path.chmod(0o755)
            self.parents[row['resolved']] = path
        for row in original['created_directories_private']:
            virtual = physical(row['path']); parent, name = virtual.rsplit('/', 1)
            target = self.parents[parent] / name; target.mkdir(mode=0o700); target.chmod(0o700); self.targets[virtual] = target
        for row in original['installed_files_private']:
            path = physical(row['path']); parent, name = path.rsplit('/', 1); target = self.targets[parent] / name
            target.write_bytes(blobs[name]); target.chmod(row['stat']['mode'])
        self.anchor_path = root / 'rootless-anchor'; self.anchor_path.symlink_to(rootless + '/')
    def open_parent(self, path):
        self.events.append(('open_parent', path)); return core.physical.PhysicalDirectory(str(self.parents[path]))
    def open_file(self, directory, name):
        self.opened_files += 1; self.events.append(('open_file', name)); return super().open_file(directory, name)
    def anchor(self):
        before = os.lstat(self.anchor_path); target = os.readlink(self.anchor_path)
        assert core.records.stat_record(before) == core.records.stat_record(os.lstat(self.anchor_path))
        return {'stat': core.records.stat_record(before), 'target': target}
    def read(self, fd, limit, check):
        if self.hook_read: self.hook_read()
        return super().read(fd, limit, check)
    def unlink(self, directory, name):
        self.events.append(('unlink', name))
        if self.hook_unlink: self.hook_unlink(directory, name)
        super().unlink(directory, name)
    def rmdir(self, parent, name):
        self.events.append(('rmdir', name))
        if self.hook_rmdir: self.hook_rmdir(parent, name)
        super().rmdir(parent, name)

class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/private/tmp'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.original = old_fixture.fixture()[0]
        self.blobs = {name: b'INVENTED fixture bytes ' + name.encode() for name in core.provenance.FILE_NAMES}
        self.hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in self.blobs.items()}
        owner = (self.root.stat().st_uid, self.root.stat().st_gid)
        self.patches = [patch.object(core, 'EXPECTED_FILES', self.hashes), patch.object(core, 'OWNER', owner)]
        for value in self.patches: value.start(); self.addCleanup(value.stop)
        self.clock = Clock()
        self.context = {'binding': dict(old_fixture.fixture()[5], rootfs_product_version='13.4', rootfs_product_build='22F66'),
            'UI_private': {'SpringBoard': [10, 100, 0], 'backboardd': [11, 100, 0]}, 'attempt_nonce': 'a' * 32,
            'clock_info': dict(self.clock.profile), 'source_sha256': {key: 'b' * 64 for key in ('cleanup', 'physical_directory', 'stat_record', 'provenance')}}
        self.fs = MappedFS(self.root, self.original, self.blobs); self.gate = Gate(self.context, self.clock)
        self.archive_calls = []
    def action(self, original=None, context=None, blobs=None):
        raw = old_fixture.raw(self.original if original is None else original)
        return core.CurrentInstallationCleanup(delivery_raw=raw, delivery_sha256=core.sha(raw),
            archived_files=self.blobs if blobs is None else blobs, context=self.context if context is None else context)
    def archive(self, raw, digest):
        self.archive_calls.append((raw, digest)); self.assertEqual(core.sha(raw), digest)
        self.assertEqual(self.fs.events, []); self.assertEqual(self.clock.calls, 0)
    def run_action(self, action=None, archive=None):
        return (self.action() if action is None else action).run(cleanup=True, fs=self.fs, gate=self.gate,
            clock=self.clock, verify_archive=self.archive if archive is None else archive)
    def assert_no_effect(self, result):
        self.assertFalse(result['cleanup_verified']); self.assertEqual(result['attempted'], [])
        self.assertFalse(any(event[0] in ('unlink', 'rmdir') for event in self.fs.events))
    def first_file(self): return next(iter(self.fs.targets.values())) / 'probe.arm64'

    def test_default_and_constructor_are_inert(self):
        action = self.action(); self.assertEqual(self.fs.events, []); self.assertEqual(self.clock.calls, 0)
        self.assertEqual(action.run(), core.metadata()); self.assertFalse(action.used)
    def test_real_fd_success_prevalidates_all_and_never_reuses_old_tokens(self):
        original_raw = old_fixture.raw(self.original); action = self.action(); result = self.run_action(action)
        self.assertTrue(result['cleanup_verified'], result)
        self.assertEqual(len(result['attempted']), 7); self.assertEqual(result['attempted'], result['completed'])
        self.assertEqual(self.gate.calls, 9); self.assertEqual(len(self.archive_calls), 1)
        first = next(i for i, event in enumerate(self.fs.events) if event[0] == 'unlink')
        self.assertEqual(sum(event[0] == 'open_file' for event in self.fs.events[:first]), 5)
        self.assertTrue(result['all_seven_prevalidated']); self.assertEqual(old_fixture.raw(self.original), original_raw)
        selected = result['selection_private']['files']
        for row in self.original['installed_files_private']:
            current = selected[core.provenance._delivery(self.original)[1](row['path'])]['stat']
            self.assertNotEqual(current['dev'], row['stat']['dev']); self.assertNotEqual(current['ino'], row['stat']['ino'])
        self.assertTrue(all(not target.exists() for target in self.fs.targets.values()))
        self.assertFalse(result['original_ownership_recovered']); self.assertFalse(result['native_evidence_authenticity_verified'])
    def test_one_use_consumed_before_callback_even_callback_failure(self):
        action = self.action()
        def fail(raw, digest):
            self.assertTrue(action.used); raise OSError('archive unavailable')
        result = self.run_action(action, archive=fail); self.assert_no_effect(result)
        self.assertEqual(self.clock.calls, 0); self.assertEqual(self.fs.events, [])
        with self.assertRaises(core.Refused): self.run_action(action)
    def test_saved_true_archive_receipt_cannot_authorize(self):
        result = self.run_action(archive=lambda *args: True); self.assert_no_effect(result)
        self.assertEqual(self.fs.events, []); self.assertEqual(self.clock.calls, 0)
    def test_wrong_original_pin_or_archive_hash_refuses_before_io(self):
        raw = old_fixture.raw(self.original)
        with self.assertRaises(core.Refused):
            core.CurrentInstallationCleanup(delivery_raw=raw, delivery_sha256='0' * 64, archived_files=self.blobs, context=self.context)
        for changed in ({**self.blobs, 'probe.arm64': b'changed'}, {key: value for key, value in self.blobs.items() if key != 'controller.py'}):
            with self.assertRaises((core.Refused, ValueError)): self.action(blobs=changed)
        self.assertEqual(self.fs.events, [])
    def test_unreviewed_original_fixed_path_or_hash_is_rejected(self):
        for key, value in [('sha256', '0' * 64), ('path', '/private/tmp/foreign'), ('new_vnode_created_exclusively', False)]:
            original = copy.deepcopy(self.original); original['installed_files_private'][0][key] = value
            with self.subTest(key=key), self.assertRaises((core.Refused, ValueError)): self.action(original=original)
    def test_missing_explicit_backends_never_opens_fixed_paths(self):
        action = self.action(); result = action.run(cleanup=True)
        self.assert_no_effect(result); self.assertTrue(action.used)
    def test_every_failed_health_gate_prevents_effects(self):
        changes = [('thermal', True), ('thermal', 1), ('exclusive_operator', False), ('no_candidate_or_test_workloads', False),
                   ('attempt_nonce', 'c' * 32), ('schema', 'other')]
        for key, value in changes:
            self.fs.events.clear(); self.clock.calls = 0
            self.gate.hook = lambda count, report, key=key, value=value: report.update({key: value})
            with self.subTest(key=key): self.assert_no_effect(self.run_action())
    def test_bool_UI_clock_and_source_aliases_refuse(self):
        for change in ('UI', 'clock', 'source', 'boot', 'job', 'scratch', 'age'):
            self.fs.events.clear(); self.clock.calls = 0
            def hook(count, report):
                if change == 'UI': report['UI_private']['SpringBoard'][2] = False
                elif change == 'clock': report['clock_info']['numer'] = True
                elif change == 'source': report['source_sha256']['cleanup'] = 'c' * 64
                elif change == 'boot': report['binding']['kern.bootsessionuuid'] = '87654321-1234-1234-1234-123456789ABC'
                elif change == 'job': report['jobs_absent'][core.LABELS[0]] = 1
                elif change == 'scratch': report['scratch_absent'][core.SCRATCH[0]] = False
                else: report['observed_monotonic'] -= 2
            self.gate.hook = hook
            with self.subTest(change=change): self.assert_no_effect(self.run_action())
    def test_last_file_bad_hash_keeps_all_seven_objects(self):
        path = next(p for p in self.fs.targets.values() if 'controller' in p.name) / 'offline-QA.canonical.private.json'
        path.write_bytes(b'offending bytes'); path.chmod(0o600)
        result = self.run_action(); self.assert_no_effect(result)
        self.assertEqual(base64.b64decode(result['offending_file_copies_private'][0]['bytes_private_b64']), b'offending bytes')
        self.assertTrue(self.first_file().exists())
    def test_foreign_child_or_missing_child_refuses_before_any_unlink(self):
        foreign = next(iter(self.fs.targets.values())) / 'foreign'; foreign.write_bytes(b'leave me')
        result = self.run_action(); self.assert_no_effect(result); self.assertEqual(foreign.read_bytes(), b'leave me')
    def test_missing_expected_file_prevents_all_mutation(self):
        self.first_file().unlink(); result = self.run_action(); self.assert_no_effect(result)
        self.assertTrue(all(target.exists() for target in self.fs.targets.values()))
    def test_partial_read_error_preserves_copied_prefix(self):
        real = self.fs.read
        def partial(fd, limit, check):
            raw, error = real(fd, limit, check); return raw[:3], 'OSError'
        with patch.object(self.fs, 'read', side_effect=partial): result = self.run_action()
        self.assert_no_effect(result)
        self.assertEqual(base64.b64decode(result['offending_file_copies_private'][0]['bytes_private_b64']), b'INV')
        self.assertEqual(result['offending_file_copies_private'][0]['read_error'], 'OSError')
    def test_mutable_read_result_is_rejected(self):
        real = self.fs.read
        def mutable(fd, limit, check):
            raw, error = real(fd, limit, check); return bytearray(raw), error
        with patch.object(self.fs, 'read', side_effect=mutable): result = self.run_action()
        self.assert_no_effect(result); self.assertEqual(result['refusal'], 'bounded_read_callback_result')
    def test_symlink_and_hardlink_sources_refuse(self):
        path = self.first_file(); data = path.read_bytes(); path.unlink(); path.symlink_to(self.root / 'foreign-target')
        result = self.run_action(); self.assert_no_effect(result); path.unlink(); path.write_bytes(data); path.chmod(0o755)
        os.link(path, self.root / 'hardlink'); self.fs.events.clear(); self.clock.calls = 0
        self.assert_no_effect(self.run_action())
    def test_wrong_mode_and_owner_token_refuse(self):
        path = self.first_file(); path.chmod(0o777)
        self.assert_no_effect(self.run_action()); path.chmod(0o755)
        real = self.fs.record
        def record(fd):
            result = real(fd)
            if result['kind'] == 'regular': result['uid'] = True
            return result
        self.fs.events.clear(); self.clock.calls = 0
        with patch.object(self.fs, 'record', side_effect=record): self.assert_no_effect(self.run_action())
    def test_replaced_directory_after_selection_refuses_before_first_unlink(self):
        target = next(iter(self.fs.targets.values()))
        def hook(count, report):
            if count == 2:
                target.rename(target.with_name('retained-original'))
                target.mkdir(mode=0o700)
        self.gate.hook = hook; result = self.run_action(); self.assert_no_effect(result)
        self.assertTrue(target.with_name('retained-original').joinpath('probe.arm64').exists())
    def test_new_foreign_child_after_prevalidation_is_not_removed(self):
        target = next(iter(self.fs.targets.values())); foreign = target / 'foreign'
        def hook(count, report):
            if count == 2: foreign.write_bytes(b'new foreign')
        self.gate.hook = hook; result = self.run_action(); self.assert_no_effect(result)
        self.assertEqual(foreign.read_bytes(), b'new foreign')
    def test_changed_rootless_anchor_before_mutation_refuses(self):
        def hook(count, report):
            if count == 2:
                self.fs.anchor_path.unlink(); self.fs.anchor_path.symlink_to(self.fs.rootless + '/different')
        self.gate.hook = hook; self.assert_no_effect(self.run_action())
    def test_expensive_recheck_cannot_use_stale_gate(self):
        def hook(count, report):
            if count == 2:
                def slow():
                    self.clock.value += 2; self.fs.hook_read = None
                self.fs.hook_read = slow
        self.gate.hook = hook; result = self.run_action(); self.assert_no_effect(result)
        self.assertEqual(result['refusal'], 'gate_stale_before_unlink')
    def test_partial_unlink_failure_stops_without_retry(self):
        action = self.action()
        def fail(directory, name): raise OSError('unknown effect')
        self.fs.hook_unlink = fail; result = self.run_action(action)
        self.assertEqual(len(result['attempted']), 1); self.assertEqual(result['completed'], [])
        self.assertEqual(result['outcome'], 'partial_or_unknown')
        with self.assertRaises(core.Refused): self.run_action(action)
    def test_effect_then_exception_preserves_uncertainty(self):
        def fail(directory, name):
            os.unlink(name, dir_fd=directory); raise OSError('lost syscall result')
        self.fs.hook_unlink = fail; result = self.run_action()
        self.assertEqual(len(result['attempted']), 1); self.assertEqual(result['completed'], [])
        self.assertEqual(result['outcome'], 'partial_or_unknown'); self.assertFalse(self.first_file().exists())
    def test_rmdir_failure_keeps_other_directory_untouched(self):
        self.fs.hook_rmdir = lambda *args: (_ for _ in ()).throw(OSError('rmdir failure'))
        result = self.run_action(); self.assertEqual([r['operation'] for r in result['attempted']], ['unlink', 'rmdir'])
        control = next(p for p in self.fs.targets.values() if 'controller' in p.name)
        self.assertEqual(len(list(control.iterdir())), 4); self.assertFalse(result['cleanup_verified'])
    def test_post_unlink_nlink_exposes_inherent_check_unlink_race(self):
        path = self.first_file(); moved = path.with_name('retained-original')
        def substitute(directory, name):
            path.rename(moved); path.write_bytes(b'raced foreign entry'); path.chmod(0o755)
        self.fs.hook_unlink = substitute; result = self.run_action()
        self.assertEqual(len(result['attempted']), 1); self.assertEqual(result['refusal'], 'held_file_not_unlinked_as_expected')
        self.assertTrue(moved.exists()); self.assertFalse(result['atomic_namespace_ownership_claimed'])
        self.assertEqual(result['outcome'], 'partial_or_unknown')
    def test_parent_sibling_is_preserved(self):
        sibling = next(iter(self.fs.parents.values())) / 'unrelated-sibling'; sibling.write_bytes(b'preserve')
        result = self.run_action(); self.assertTrue(result['cleanup_verified'], result)
        self.assertEqual(sibling.read_bytes(), b'preserve')
    def test_post_rmdir_reappearance_fails_and_never_adopts_new_directory(self):
        real = self.fs.rmdir; done = []
        def replace(parent, name):
            real(parent, name)
            os.mkdir(name, mode=0o700, dir_fd=parent.fd); done.append(name)
        with patch.object(self.fs, 'rmdir', side_effect=replace): result = self.run_action()
        self.assertFalse(result['cleanup_verified']); self.assertEqual(len(result['attempted']), 2)
        self.assertEqual(len(done), 1)
    def test_finalization_error_removes_verified_claim(self):
        real = self.fs.close_file; first = [True]
        def close(fd):
            real(fd)
            if first[0]: first[0] = False; raise OSError('close result unavailable')
        with patch.object(self.fs, 'close_file', side_effect=close): result = self.run_action()
        self.assertFalse(result['cleanup_verified']); self.assertEqual(result['finalization_errors'], ['OSError'])
    def test_deadline_and_clock_regression_stop_before_filesystem(self):
        for values in ([1000, 999], [1000, 1009]):
            self.fs.events.clear(); self.clock.calls = 0
            with patch.object(self.clock, 'now', side_effect=values):
                self.assert_no_effect(self.run_action(archive=lambda *args: None))
    def test_slow_final_close_cannot_return_a_fresh_verified_result(self):
        real = self.fs.close_file; first = [True]
        def close(fd):
            real(fd)
            if first[0]: first[0] = False; self.clock.value += 2
        with patch.object(self.fs, 'close_file', side_effect=close): result = self.run_action()
        self.assertEqual(len(result['completed']), 7); self.assertFalse(result['cleanup_verified'])
        self.assertIn('Refused', result['finalization_errors'])

if __name__ == '__main__': unittest.main()
