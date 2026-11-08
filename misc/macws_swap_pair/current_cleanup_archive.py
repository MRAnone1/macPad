"""Explicit, once-only co-located archive callback, with no cleanup/transport.

Construction is pure. Only a direct successful __call__ return (None) attests
this process completed its local archive sequence and closes. No host durability,
native authenticity, fresh mount inventory or privileged-writer exclusion is
proved. The core's eight-second cleanup clock starts AFTER this callback; an
independently reviewed full-worker deadline/alarm is still required.
"""
import base64
import os
import stat

from macws_swap_pair import current_installation_cleanup as core
from macws_swap_pair import retained_archive as storage

SCHEMA = 'macws.current-cleanup.co-located-archive.v1'
OWNER = (0, 0)
MAX_ARCHIVE_BYTES = 1024 * 1024
FILE_NAME = 'archive.private.bin'


def need(condition, reason):
    core.need(condition, reason)


def metadata():
    return {'schema': SCHEMA, 'default_inert': True, 'archive_callback_requested': False,
            'cleanup_available': False,
            'transport_available': False, 'native_qualification': False,
            'host_durability_claimed': False, 'device_acceptance': False,
            'timed_by_core_cleanup_clock': False}


def _below(path, root):
    return path == root or path.startswith(root + '/')


def _b64(word, limit):
    need(type(word) is str and 0 < len(word) <= 4 * ((limit + 2) // 3), 'bounded_archive_base64')
    try:
        raw = base64.b64decode(word, validate=True)
    except (ValueError, UnicodeError) as error:
        raise core.Refused('valid_archive_base64') from error
    need(0 < len(raw) <= limit and base64.b64encode(raw).decode('ascii') == word,
         'canonical_bounded_archive_base64')
    return raw


class CoLocatedArchive:
    """No default parent. Caller must supply one reviewed physical private path.

    Current mount/namespace inventory and exclusion of capable writers are
    trusted caller prerequisites. NOFOLLOW and held dev/ino comparisons reject
    symlinks/direct watched-parent aliases, not every possible deep bind alias.
    Constructor context is structural binding only, never current freshness.
    """
    def __init__(self, *, archive_raw, archive_sha256, delivery_sha256,
                 context, parent_directory):
        core.provenance.digest(archive_sha256)
        core.provenance.digest(delivery_sha256)
        need(type(archive_raw) is bytes and 0 < len(archive_raw) <= MAX_ARCHIVE_BYTES
             and core.sha(archive_raw) == archive_sha256, 'externally_pinned_archive')
        value = core.provenance.decode(archive_raw, MAX_ARCHIVE_BYTES)
        core.provenance.exact_keys(value, ('schema', 'delivery_private_b64', 'files_private_b64'))
        need(value['schema'] == 'macws.current-installation-cleanup.archive.v1'
             and core.provenance.canonical(value) == archive_raw, 'canonical_core_archive')
        core.provenance.exact_keys(value['files_private_b64'], core.EXPECTED_FILES)
        delivery = _b64(value['delivery_private_b64'], 65536)
        files = {name: _b64(word, core.MAX_FILE) for name, word in value['files_private_b64'].items()}
        # Reuse exact inert production validation, never invoke its run method.
        checked = core.CurrentInstallationCleanup(delivery_raw=delivery,
            delivery_sha256=delivery_sha256, archived_files=files, context=context)
        need(checked.archive_raw == archive_raw, 'exact_original_archive_reconstruction')
        self._parent = core.provenance.physical_path(parent_directory)
        self._name = 'cleanup-archive-' + archive_sha256
        self.path = self._parent + '/' + self._name
        self._watched = tuple(sorted({path.rsplit('/', 1)[0] for path in checked.paths}))
        selected = [item['path'] for item in checked.files] + checked.paths
        for path in (self._parent, self.path):
            for forbidden in [*self._watched, *selected]:
                need(not _below(path, forbidden) and not _below(forbidden, path),
                     'archive_namespace_must_be_disjoint')
        self._raw, self._sha = archive_raw, archive_sha256
        self._used = False
        self._report = dict(metadata(), outcome='not_called', attempted=[], completed=[],
            archive_verified=False, close_errors=[], refusal=None)

    def snapshot(self):
        """A copied progress report, never serialized authority or durability."""
        return core.copied(self._report)

    def __call__(self, raw, digest):
        need(self._used is False, 'archive_callback_consumed_no_retry')
        self._used = True
        self._report.update(outcome='in_progress', default_inert=False,
            archive_callback_requested=True, archive_path_private=self.path,
            archive_sha256=self._sha, archive_bytes=len(self._raw),
            watched_parents_private=list(self._watched))
        report = self._report
        parent = None; watched = []; directory = file_fd = None
        directory_identity = file_token = None
        error = None

        def intent(operation, path):
            row = {'operation': operation, 'path_private': path}
            report['attempted'].append(row)
            return row

        def entries():
            names = []
            with os.scandir(directory) as stream:
                for entry in stream:
                    need(len(names) < 1 and entry.name == FILE_NAME, 'exact_single_archive_entry')
                    names.append(entry.name)
            need(names == ([] if file_fd is None else [FILE_NAME]), 'archive_entries_complete')

        def check():
            parent.checked()
            info = os.fstat(parent.fd)
            need((info.st_uid, info.st_gid) == OWNER and stat.S_IMODE(info.st_mode) == 0o700,
                 'private_archive_parent_owner_mode')
            for chain, token in watched:
                chain.checked()
                need(storage._stat_tuple(os.fstat(chain.fd)) == token,
                     'watched_parent_changed_during_archive')
                needle = token[:2]
                need(all((os.fstat(fd).st_dev, os.fstat(fd).st_ino) != needle
                         for _, fd, _ in parent.chain), 'direct_watched_parent_alias')
            if directory is not None:
                before = storage._stat_tuple(storage._check_directory(directory, private=True))
                need(storage._directory_identity(os.fstat(directory)) == directory_identity
                     and (os.fstat(directory).st_uid, os.fstat(directory).st_gid) == OWNER,
                     'archive_directory_identity_owner')
                linked = os.stat(self._name, dir_fd=parent.fd, follow_symlinks=False)
                need(before == storage._stat_tuple(linked), 'archive_directory_link')
                entries()
                if file_fd is not None:
                    actual, current = storage._read_checked(file_fd, len(self._raw))
                    need(actual == self._raw and current == file_token
                         and (current[6], current[7]) == OWNER, 'archive_final_bytes_token_owner')
                    storage._path_checked(directory, FILE_NAME, file_fd, file_token)
                need(before == storage._stat_tuple(os.fstat(directory)) ==
                     storage._stat_tuple(os.stat(self._name, dir_fd=parent.fd, follow_symlinks=False)),
                     'archive_directory_changed_during_check')
                entries()
            parent.checked()

        try:
            core.provenance.digest(digest)
            need(type(raw) is bytes and raw == self._raw and digest == self._sha,
                 'callback_exact_archive_bytes_and_pin')
            need((os.geteuid(), os.getegid()) == OWNER, 'explicit_root_archive_process')
            parent = core.physical.PhysicalDirectory(self._parent)
            for path in self._watched:
                chain = core.physical.PhysicalDirectory(path)
                watched.append((chain, None))
                info = os.fstat(chain.fd)
                need((info.st_uid, info.st_gid) == OWNER and stat.S_IMODE(info.st_mode) == 0o755,
                     'watched_parent_owner_mode')
                watched[-1] = (chain, storage._stat_tuple(info))
            check()
            row = intent('mkdir', self.path)
            os.mkdir(self._name, 0o700, dir_fd=parent.fd)
            report['completed'].append(row)
            directory = os.open(self._name, storage._DIR_FLAGS, dir_fd=parent.fd)
            directory_identity = storage._directory_identity(storage._check_directory(directory, private=True))
            check()
            file_path = self.path + '/' + FILE_NAME
            row = intent('exclusive_create_write_fsync_readback', file_path)
            file_fd, file_token = storage._write_checked(directory, FILE_NAME, self._raw)
            report['completed'].append(row)
            check()
            row = intent('fsync_archive_directory', self.path)
            os.fsync(directory); report['completed'].append(row)
            row = intent('fsync_archive_parent', self._parent)
            os.fsync(parent.fd); report['completed'].append(row)
            check()
        except BaseException as caught:
            error = caught
        finally:
            descriptors = [file_fd, directory]
            for chain, _ in reversed(watched):
                descriptors.extend(fd for _, fd, _ in reversed(chain.chain))
                chain.chain = []
            if parent is not None:
                descriptors.extend(fd for _, fd, _ in reversed(parent.chain))
                parent.chain = []
            for fd in descriptors:
                if fd is not None:
                    try:
                        os.close(fd)
                    except BaseException as caught:
                        report['close_errors'].append(type(caught).__name__)
                        if error is None: error = caught
        if error is not None:
            report['outcome'] = 'partial_or_unknown' if report['attempted'] else 'refused_before_archive_effect'
            report['refusal'] = str(error) if type(error) is core.Refused else type(error).__name__
            raise error
        report.update(outcome='co_located_archive_verified_after_close', archive_verified=True)
        return None


if __name__ == '__main__':
    import json
    print(json.dumps(metadata(), sort_keys=True))
