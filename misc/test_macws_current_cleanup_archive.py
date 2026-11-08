"""Owned host files and invented context only; no native acceptance."""
import base64
from collections import Counter
import copy
import errno
import importlib.util
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

import test_macws_current_installation_cleanup as fixture
from macws_swap_pair import current_cleanup_archive as subject
core = subject.core


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture.CleanupTests('runTest')
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        self.parent = f.root / 'archive-ledger'; self.parent.mkdir(mode=0o700)
        self.action = f.action()
        self.raw = self.action.archive_raw
        self.kwargs = {'archive_raw': self.raw, 'archive_sha256': core.sha(self.raw),
            'delivery_sha256': self.action.delivery_sha256, 'context': f.context,
            'parent_directory': str(self.parent)}
        real_directory = core.physical.PhysicalDirectory
        def mapped(path):
            return real_directory(str(f.fs.parents.get(path, path)))
        self.mapping = patch.object(core.physical, 'PhysicalDirectory', side_effect=mapped)
        self.mapping.start(); self.addCleanup(self.mapping.stop)
        owner = (f.root.stat().st_uid, f.root.stat().st_gid)
        p = patch.object(subject, 'OWNER', owner); p.start(); self.addCleanup(p.stop)
        # Temp files inherit their directory group; emulate only that process
        # group in this invented host fixture, never in production code.
        p = patch.object(subject.os, 'getegid', return_value=owner[1]); p.start(); self.addCleanup(p.stop)
        self.callback = subject.CoLocatedArchive(**self.kwargs)
        self.slot = Path(self.callback.path)

    def call(self, callback=None):
        return (callback or self.callback)(self.raw, core.sha(self.raw))

    def test_constructor_default_and_snapshot_are_inert(self):
        with patch.object(subject.os, 'open', side_effect=AssertionError('open')), \
             patch.object(subject.os, 'mkdir', side_effect=AssertionError('mkdir')), \
             patch.object(core.CurrentInstallationCleanup, 'run', side_effect=AssertionError('run')):
            c = subject.CoLocatedArchive(**self.kwargs)
            self.assertEqual(c.snapshot()['outcome'], 'not_called')
            self.assertTrue(subject.metadata()['default_inert'])
        self.assertEqual(list(self.parent.iterdir()), [])

    def test_success_exact_private_archive_none_only_after_closes(self):
        real_close = os.close; closes = []
        def close(fd):
            closes.append(fd); return real_close(fd)
        with patch.object(subject.os, 'close', side_effect=close):
            self.assertIsNone(self.call())
        self.assertGreater(len(closes), 3)
        self.assertEqual((self.slot / subject.FILE_NAME).read_bytes(), self.raw)
        self.assertEqual(stat.S_IMODE(self.slot.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.slot / subject.FILE_NAME).stat().st_mode), 0o600)
        result = self.callback.snapshot()
        self.assertTrue(result['archive_verified'])
        self.assertFalse(result['default_inert'])
        self.assertTrue(result['archive_callback_requested'])
        self.assertEqual(result['attempted'], result['completed'])
        self.assertEqual(len(result['attempted']), 4)
        self.assertFalse(result['host_durability_claimed'])
        self.assertFalse(result['timed_by_core_cleanup_clock'])
        result['attempted'].clear()
        self.assertEqual(len(self.callback.snapshot()['attempted']), 4)

    def test_bad_callback_bytes_or_pin_consume_before_path_io(self):
        for raw, digest in [(b'changed', core.sha(self.raw)), (self.raw, '0' * 64),
                            (bytearray(self.raw), core.sha(self.raw)), (self.raw, True)]:
            c = subject.CoLocatedArchive(**self.kwargs)
            with patch.object(subject.os, 'open', side_effect=AssertionError('open')):
                with self.assertRaises(ValueError): c(raw, digest)
            self.assertEqual(c.snapshot()['outcome'], 'refused_before_archive_effect')
            self.assertEqual(c.snapshot()['attempted'], [])
            with self.assertRaises(ValueError): self.call(c)

    def test_constructor_rejects_external_pins_types_and_bounds(self):
        for key, value in [('archive_sha256', '0' * 64), ('delivery_sha256', '0' * 64),
                           ('archive_raw', b''), ('archive_raw', bytearray(self.raw)),
                           ('archive_raw', b'x' * (subject.MAX_ARCHIVE_BYTES + 1))]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                subject.CoLocatedArchive(**dict(self.kwargs, **{key: value}))
        self.assertEqual(list(self.parent.iterdir()), [])

    def changed_archive(self, mutate):
        value = core.provenance.decode(self.raw, subject.MAX_ARCHIVE_BYTES)
        mutate(value); raw = core.provenance.canonical(value)
        return dict(self.kwargs, archive_raw=raw, archive_sha256=core.sha(raw))

    def test_canonical_schema_duplicate_and_foreign_entries_refused(self):
        changes = [lambda v: v.update(schema='foreign'), lambda v: v.update(foreign=True),
                   lambda v: v['files_private_b64'].update(foreign='eA=='),
                   lambda v: v['files_private_b64'].pop('probe.arm64')]
        for change in changes:
            with self.assertRaises(ValueError): subject.CoLocatedArchive(**self.changed_archive(change))
        for raw in [b' ' + self.raw, self.raw[:-1] + b',"schema":"duplicate"}']:
            with self.assertRaises(ValueError):
                subject.CoLocatedArchive(**dict(self.kwargs, archive_raw=raw, archive_sha256=core.sha(raw)))

    def test_changed_file_and_noncanonical_base64_refused(self):
        for word in ['not base64!', 'eA==', 'eB==', True, 'x' * 200000]:
            with self.assertRaises(ValueError):
                subject.CoLocatedArchive(**self.changed_archive(lambda v: v['files_private_b64'].update({'probe.arm64': word})))

    def test_context_aliases_and_historical_receipt_edits_refused(self):
        context = copy.deepcopy(self.fixture.context); context['clock_info']['numer'] = True
        with self.assertRaises(ValueError): subject.CoLocatedArchive(**dict(self.kwargs, context=context))
        def changed(v):
            receipt = core.provenance.decode(base64.b64decode(v['delivery_private_b64']), 65536)
            receipt['installed_files_private'][0]['new_vnode_created_exclusively'] = False
            v['delivery_private_b64'] = base64.b64encode(core.provenance.canonical(receipt)).decode()
        kwargs = self.changed_archive(changed)
        receipt = base64.b64decode(core.provenance.decode(kwargs['archive_raw'], 1048576)['delivery_private_b64'])
        kwargs['delivery_sha256'] = core.sha(receipt)
        with self.assertRaises(ValueError): subject.CoLocatedArchive(**kwargs)

    def test_parent_namespace_literal_alias_and_watched_scope_refused(self):
        forbidden = list(self.callback._watched) + list(self.action.paths) + [item['path'] for item in self.action.files]
        for path in [*forbidden, *(p + '/archive' for p in forbidden), '/private',
                     '/var/tmp/archive', '/private/var/jb/archive', str(self.parent) + '/',
                     str(self.parent) + '//child', str(self.parent) + '/../other']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                subject.CoLocatedArchive(**dict(self.kwargs, parent_directory=path))

    def test_existing_slot_refuses_without_overwrite_and_consumes(self):
        self.slot.mkdir(mode=0o700); foreign = self.slot / 'foreign'; foreign.write_bytes(b'keep')
        with self.assertRaises(FileExistsError): self.call()
        self.assertEqual(foreign.read_bytes(), b'keep')
        self.assertEqual(len(self.callback.snapshot()['attempted']), 1)
        self.assertEqual(self.callback.snapshot()['outcome'], 'partial_or_unknown')
        with self.assertRaises(ValueError): self.call()

    def test_symlink_or_nonprivate_parent_refuses_before_archive_effect(self):
        link = self.fixture.root / 'alias'; link.symlink_to(self.parent)
        for path in [str(link), str(self.parent)]:
            if path == str(self.parent): self.parent.chmod(0o755)
            c = subject.CoLocatedArchive(**dict(self.kwargs, parent_directory=path))
            with self.assertRaises((core.Refused, OSError)): self.call(c)
            self.assertEqual(c.snapshot()['attempted'], [])

    def test_missing_watched_parent_refuses_before_mkdir(self):
        parent = next(iter(self.fixture.fs.parents.values()))
        parent.rename(parent.with_name('original'))
        with self.assertRaises(FileNotFoundError): self.call()
        self.assertEqual(self.callback.snapshot()['attempted'], [])
        self.assertFalse(self.slot.exists())

    def test_intent_is_recorded_before_mkdir(self):
        def fail(*args, **kwargs):
            self.assertEqual(self.callback.snapshot()['attempted'][0]['operation'], 'mkdir')
            raise OSError(errno.EIO, 'fixture mkdir')
        with patch.object(subject.os, 'mkdir', side_effect=fail):
            with self.assertRaises(OSError): self.call()
        self.assertEqual(self.callback.snapshot()['outcome'], 'partial_or_unknown')

    def test_partial_write_failure_keeps_file_and_reports_unknown_effect(self):
        real_write = os.write; count = [0]
        def partial(fd, raw):
            count[0] += 1
            if count[0] == 1: return real_write(fd, raw[:7])
            raise OSError(errno.EIO, 'fixture partial write')
        with patch.object(subject.os, 'write', side_effect=partial):
            with self.assertRaises(OSError): self.call()
        self.assertEqual((self.slot / subject.FILE_NAME).read_bytes(), self.raw[:7])
        self.assertEqual(len(self.callback.snapshot()['attempted']), 2)
        self.assertFalse(self.callback.snapshot()['archive_verified'])
        with self.assertRaises(ValueError): self.call()

    def test_each_file_directory_parent_fsync_failure_keeps_artifacts(self):
        real_sync = os.fsync
        for failure in (1, 2, 3):
            parent = self.fixture.root / ('ledger-' + str(failure)); parent.mkdir(mode=0o700)
            c = subject.CoLocatedArchive(**dict(self.kwargs, parent_directory=str(parent)))
            count = [0]
            def fsync(fd):
                count[0] += 1
                if count[0] == failure: raise OSError(errno.EIO, 'fixture fsync')
                return real_sync(fd)
            with patch.object(subject.os, 'fsync', side_effect=fsync):
                with self.assertRaises(OSError): self.call(c)
            self.assertEqual((Path(c.path) / subject.FILE_NAME).read_bytes(), self.raw)
            self.assertEqual(c.snapshot()['outcome'], 'partial_or_unknown')
            self.assertFalse(c.snapshot()['archive_verified'])

    def test_final_close_failure_withdraws_success_and_attempts_all_closes(self):
        real_close = os.close; count = [0]
        def close(fd):
            count[0] += 1; real_close(fd)
            if count[0] == 1: raise OSError(errno.EIO, 'fixture close')
        with patch.object(subject.os, 'close', side_effect=close):
            with self.assertRaises(OSError): self.call()
        self.assertGreater(count[0], 3)
        self.assertEqual(self.callback.snapshot()['close_errors'], ['OSError'])
        self.assertFalse(self.callback.snapshot()['archive_verified'])

    def test_changed_archive_extra_child_hardlink_or_replacement_refuses(self):
        real_sync = os.fsync
        for kind in ('bytes', 'extra', 'hardlink', 'replace', 'parent'):
            parent = self.fixture.root / ('changed-' + kind); parent.mkdir(mode=0o700)
            c = subject.CoLocatedArchive(**dict(self.kwargs, parent_directory=str(parent)))
            done = [False]
            def mutate(fd):
                real_sync(fd)
                path = Path(c.path) / subject.FILE_NAME
                if path.exists() and not done[0]:
                    done[0] = True
                    if kind == 'bytes': path.write_bytes(b'changed')
                    elif kind == 'extra': (path.parent / 'extra').write_bytes(b'keep')
                    elif kind == 'hardlink': os.link(path, path.parent / 'second')
                    elif kind == 'replace':
                        path.rename(path.with_name('retained')); path.write_bytes(self.raw); path.chmod(0o600)
                    else:
                        parent.rename(parent.with_name('retained-parent')); parent.mkdir(mode=0o700)
            with patch.object(subject.os, 'fsync', side_effect=mutate):
                with self.assertRaises((ValueError, OSError)): self.call(c)
            self.assertFalse(c.snapshot()['archive_verified'])
            self.assertEqual(c.snapshot()['outcome'], 'partial_or_unknown')

    def test_core_own_refusal_can_follow_successful_archive_effects(self):
        f = self.fixture
        f.gate.hook = lambda count, row: row.update(thermal=1)
        result = self.action.run(cleanup=True, fs=f.fs, gate=f.gate, clock=f.clock,
                                 verify_archive=self.callback)
        self.assertEqual(result['outcome'], 'refused_before_effect')
        self.assertEqual(result['attempted'], [])
        self.assertTrue(self.callback.snapshot()['archive_verified'])
        self.assertEqual((self.slot / subject.FILE_NAME).read_bytes(), self.raw)
        self.assertEqual(f.fs.events, [])

    def test_integrated_owned_host_cleanup_archive_before_core_selection(self):
        f = self.fixture
        real_open = f.fs.open_parent
        def open_parent(path):
            self.assertTrue(self.callback.snapshot()['archive_verified'])
            self.assertTrue(self.callback._used)
            return real_open(path)
        with patch.object(f.fs, 'open_parent', side_effect=open_parent):
            result = self.action.run(cleanup=True, fs=f.fs, gate=f.gate, clock=f.clock,
                                     verify_archive=self.callback)
        self.assertTrue(result['cleanup_verified'], result)
        self.assertEqual(len(result['completed']), 7)
        self.assertEqual((self.slot / subject.FILE_NAME).read_bytes(), self.raw)
        self.assertFalse(result['device_acceptance'])


    def test_independent_direct_watched_parent_alias_refuses_before_mkdir(self):
        original_factory = self.mapping.temp_original
        selected_parent = next(iter(self.fixture.fs.parents.values()))
        def alias(path):
            actual = selected_parent if path == str(self.parent) else self.fixture.fs.parents.get(path, path)
            return original_factory(str(actual))
        with patch.object(core.physical, 'PhysicalDirectory', side_effect=alias):
            with self.assertRaises(core.Refused): self.call()
        self.assertEqual(self.callback.snapshot()['attempted'], [])
        self.assertEqual(list(self.parent.iterdir()), [])
        self.assertFalse(self.slot.exists())

    def test_independent_watched_parent_change_after_file_fsync_refuses(self):
        real_sync = os.fsync
        watched = next(iter(self.fixture.fs.parents.values()))
        foreign = watched / 'independent-foreign-child'
        changed = [False]
        def fsync(fd):
            real_sync(fd)
            if not changed[0]:
                changed[0] = True
                foreign.write_bytes(b'keep foreign entry')
        with patch.object(subject.os, 'fsync', side_effect=fsync):
            with self.assertRaisesRegex(core.Refused, 'watched_parent_changed_during_archive'):
                self.call()
        self.assertEqual(foreign.read_bytes(), b'keep foreign entry')
        self.assertEqual((self.slot / subject.FILE_NAME).read_bytes(), self.raw)
        self.assertFalse(self.callback.snapshot()['archive_verified'])
        self.assertEqual(self.callback.snapshot()['outcome'], 'partial_or_unknown')

    def test_independent_first_stats_of_root_child_and_watched_fds_close(self):
        real_open, real_stat, real_close = os.open, os.fstat, os.close
        for number in (1, 3, 7):
            callback = subject.CoLocatedArchive(**self.kwargs)
            opened, closed, first_stat = [], [], set()
            def opening(*args, **kwargs):
                fd = real_open(*args, **kwargs)
                opened.append(fd); first_stat.add(fd)
                return fd
            def fstat(fd):
                if fd in first_stat:
                    first_stat.remove(fd)
                    if len(opened) == number:
                        raise OSError(errno.EIO, 'independent first fstat failure')
                return real_stat(fd)
            def closing(fd):
                real_close(fd); closed.append(fd)
            with patch.object(subject.os, 'open', side_effect=opening), \
                 patch.object(subject.os, 'fstat', side_effect=fstat), \
                 patch.object(subject.os, 'close', side_effect=closing):
                with self.assertRaises(OSError): self.call(callback)
            self.assertEqual(len(opened), number)
            self.assertEqual(Counter(opened), Counter(closed))
            self.assertEqual(callback.snapshot()['attempted'], [])
            self.assertFalse(self.slot.exists())

    def test_independent_zero_write_progress_keeps_empty_partial_file(self):
        with patch.object(subject.os, 'write', return_value=0):
            with self.assertRaises(subject.storage.ArchiveRefused): self.call()
        self.assertEqual((self.slot / subject.FILE_NAME).read_bytes(), b'')
        result = self.callback.snapshot()
        self.assertEqual(len(result['attempted']), 2)
        self.assertEqual(len(result['completed']), 1)
        self.assertEqual(result['outcome'], 'partial_or_unknown')
        self.assertFalse(result['archive_verified'])

    def test_independent_same_bytes_single_name_substitution_refuses(self):
        real_sync = os.fsync
        changed = [False]
        def fsync(fd):
            real_sync(fd)
            path = self.slot / subject.FILE_NAME
            if path.exists() and not changed[0]:
                changed[0] = True
                path.unlink()
                path.write_bytes(self.raw)
                path.chmod(0o600)
        with patch.object(subject.os, 'fsync', side_effect=fsync):
            with self.assertRaises((core.Refused, subject.storage.ArchiveRefused)):
                self.call()
        self.assertEqual(set(path.name for path in self.slot.iterdir()), {subject.FILE_NAME})
        self.assertEqual((self.slot / subject.FILE_NAME).read_bytes(), self.raw)
        self.assertFalse(self.callback.snapshot()['archive_verified'])

    def test_independent_unknown_first_close_never_returns_success_or_retries(self):
        real_close = os.close
        first_fd, calls = [], []
        def closing(fd):
            calls.append(fd)
            if not first_fd:
                first_fd.append(fd)
                # Model an uncertain close that has not actually closed the
                # owned host fixture FD. The callback must not assume success.
                raise OSError(errno.EIO, 'independent uncertain close')
            return real_close(fd)
        try:
            with patch.object(subject.os, 'close', side_effect=closing):
                with self.assertRaises(OSError): self.call()
            self.assertGreater(len(calls), 3)
            self.assertEqual(calls.count(first_fd[0]), 1)
            self.assertEqual(self.callback.snapshot()['close_errors'], ['OSError'])
            self.assertFalse(self.callback.snapshot()['archive_verified'])
            self.assertEqual((self.slot / subject.FILE_NAME).read_bytes(), self.raw)
        finally:
            # The injected handler is known to leave this own test FD open;
            # this explicit fixture teardown does not add a callback retry.
            if first_fd: real_close(first_fd[0])


if __name__ == '__main__':
    unittest.main()
