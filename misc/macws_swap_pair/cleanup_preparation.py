"""Host-only, explicit preparation of one current-cleanup attempt.

The same archive gets one deterministic slot within one trusted parent. This
does not exclude capable writers or another parent. No transport or native
cleanup factory exists here. Archive bytes are externally pinned, not thereby
semantically validated or authenticated. Only successful direct method returns
describe this process's completed persistence steps; saved JSON grants none.
Failures consume their transition and retain partial artifacts without retry.
"""
import hashlib
import json
import os
import re
import stat

from macws_swap_pair import capture_journal as journal
from macws_swap_pair import retained_archive as archive

SCHEMA = "macws.current-cleanup.host-attempt.v1"
ARCHIVE_LIMIT = 1024 * 1024
ARCHIVE_NAME = "archive.private.bin"
CAPTURE_NAME = "capture"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class AttemptRefused(ValueError):
    pass


def need(value, message):
    if value is not True:
        raise AttemptRefused(message)


def _pinned(raw, digest, limit, role):
    need(type(raw) is bytes and 0 < len(raw) <= limit, role + " byte bound")
    need(type(digest) is str and _DIGEST.fullmatch(digest) is not None,
         role + " external SHA-256")
    need(hashlib.sha256(raw).hexdigest() == digest, role + " SHA-256 mismatch")


def metadata():
    return {"schema": SCHEMA, "default_inert": True,
            "host_persistence_only": True, "native_actions_available": False,
            "transport_available": False, "device_acceptance": False,
            "global_exclusivity_proven": False}


class CleanupAttempt:
    """Pure construction; prepare and mark_dispatch each consume one phase.

    The caller must retain the same trusted parent across restarts and exclude
    other capable writers. A different nonce/payload cannot bypass the same
    archive's slot in that parent. This object does not establish exclusivity
    across parents, machines, accounts, or independent privileged operators.
    """
    def __init__(self, *, archive_raw, archive_sha256, payload,
                 payload_sha256, intent):
        _pinned(archive_raw, archive_sha256, ARCHIVE_LIMIT, "archive")
        _pinned(payload, payload_sha256, journal.PAYLOAD_LIMIT, "payload")
        # Freeze caller JSON without paths, native calls, or arbitrary coercion.
        frozen_intent = json.loads(archive.canonical_json(intent))
        self._intent = {"schema": SCHEMA, "archive_sha256": archive_sha256,
                        "archive_bytes": len(archive_raw),
                        "payload_sha256": payload_sha256,
                        "payload_bytes": len(payload),
                        "caller_intent_private": frozen_intent,
                        "native_evidence_authenticity_verified": False,
                        "device_acceptance": False}
        journal._plain_json(self._intent)
        self._raw, self._payload = archive_raw, payload
        self._archive_sha, self._payload_sha = archive_sha256, payload_sha256
        self._name = "cleanup-" + archive_sha256
        self._state = "new"
        self._chain = []
        self._parent_path = self._directory_path = None
        self._directory_fd = self._archive_fd = self._capture_fd = None
        self._directory_identity = self._capture_identity = None
        self._archive_token = None
        self._journal = None

    def _open_parent(self, path):
        self._parent_path, parts = archive._absolute_path(path)
        def register(name, fd):
            try:
                identity = archive._directory_identity(os.fstat(fd))
                self._chain.append((name, fd, identity))
            except BaseException:
                os.close(fd)
                raise
            return fd
        fd = register(None, os.open("/", archive._DIR_FLAGS))
        for part in parts:
            fd = register(part, os.open(part, archive._DIR_FLAGS,
                                       dir_fd=self._chain[-1][1]))
        info = archive._check_directory(fd, private=False)
        need(stat.S_IMODE(info.st_mode) in (0o700, 0o755), "trusted parent mode")
        self._check_chain()

    def _check_chain(self):
        need(bool(self._chain), "parent is not held")
        for index, (name, fd, identity) in enumerate(self._chain):
            info = os.fstat(fd)
            linked = (os.lstat("/") if index == 0 else os.stat(
                name, dir_fd=self._chain[index - 1][1], follow_symlinks=False))
            need(stat.S_ISDIR(info.st_mode) and
                 archive._directory_identity(info) == identity ==
                 archive._directory_identity(linked), "physical parent chain changed")
        archive._check_directory(self._chain[-1][1], private=False)

    def _check(self):
        self._check_chain()
        parent_fd = self._chain[-1][1]
        info = archive._check_directory(self._directory_fd, private=True)
        token = archive._stat_tuple(info)
        need(archive._directory_identity(info) == self._directory_identity ==
             archive._directory_identity(os.stat(
                 self._name, dir_fd=parent_fd, follow_symlinks=False)),
             "attempt directory identity changed")
        expected = set()
        if self._archive_fd is not None:
            expected.add(ARCHIVE_NAME)
            raw, current = archive._read_checked(self._archive_fd, len(self._raw))
            need(raw == self._raw and current == self._archive_token,
                 "archive bytes or token changed")
            archive._path_checked(self._directory_fd, ARCHIVE_NAME,
                                  self._archive_fd, self._archive_token)
        if self._capture_fd is not None:
            expected.add(CAPTURE_NAME)
            need(archive._directory_identity(archive._check_directory(
                self._capture_fd, private=True)) == self._capture_identity ==
                archive._directory_identity(os.stat(CAPTURE_NAME,
                    dir_fd=self._directory_fd, follow_symlinks=False)),
                "capture directory identity changed")
            self._journal._check()
        need(set(os.listdir(self._directory_fd)) == expected,
             "attempt directory entries changed")
        need(token == archive._stat_tuple(os.fstat(self._directory_fd)) ==
             archive._stat_tuple(os.stat(self._name, dir_fd=parent_fd,
                                         follow_symlinks=False)),
             "attempt directory changed during readback")
        self._check_chain()

    def _sync_archive(self):
        self._check()
        os.fsync(self._directory_fd)
        os.fsync(self._chain[-1][1])
        self._check()
        # _write_checked already fsynced and read back the held archive file.
        # This direct return completes this process's archive sequence only.

    def prepare(self, parent_directory):
        """Create the deterministic private slot; never dispatch anything.

        Partial files remain if archive or nested journal preparation fails.
        A JSON copy of this return cannot establish that final fsync happened.
        """
        need(self._state == "new", "prepare already consumed")
        self._state = "preparing"
        try:
            self._open_parent(parent_directory)
            parent_fd = self._chain[-1][1]
            os.mkdir(self._name, 0o700, dir_fd=parent_fd)
            self._directory_fd = os.open(self._name, archive._DIR_FLAGS,
                                         dir_fd=parent_fd)
            self._directory_identity = archive._directory_identity(
                archive._check_directory(self._directory_fd, private=True))
            self._directory_path = self._parent_path + "/" + self._name
            self._check()
            self._archive_fd, self._archive_token = archive._write_checked(
                self._directory_fd, ARCHIVE_NAME, self._raw)
            self._sync_archive()
            self._journal = journal.Journal(self._directory_path, CAPTURE_NAME,
                payload=self._payload, intent=self._intent)
            self._capture_fd = os.open(CAPTURE_NAME, archive._DIR_FLAGS,
                                       dir_fd=self._directory_fd)
            self._capture_identity = archive._directory_identity(
                archive._check_directory(self._capture_fd, private=True))
            self._check()
            self._state = "prepared"
            return dict(metadata(), default_inert=False, phase="prepared",
                directory_private=self._directory_path,
                archive_sha256=self._archive_sha, payload_sha256=self._payload_sha,
                archive_sequence_completed_in_this_invocation=True,
                journal_preparation_private=self._journal.preparation_receipt)
        except BaseException:
            self._state = "failed"
            try:
                self.close()
            except OSError:
                pass
            raise

    def mark_dispatch(self):
        """Persist intent once after fresh archive readback; invoke no transport."""
        need(self._state == "prepared", "dispatch unavailable or consumed")
        self._state = "marking-dispatch"
        try:
            self._check()
            result = self._journal.mark_dispatch()
            self._check()
            self._state = "dispatched"
            return result
        except BaseException:
            self._state = "failed"
            raise

    def _preserve(self, required, next_state, method, **kwargs):
        need(self._state == required, "preservation phase unavailable")
        self._state = "preserving"
        try:
            # Preserve received bytes before unrelated archive validation.
            # Journal independently checks its held safe namespace. If either
            # stage fails, the caller retains its original buffers as well.
            if method == "save_assessment":
                self._check()
            result = getattr(self._journal, method)(**kwargs)
            self._check()
            self._state = next_state
            return result
        except BaseException:
            self._state = "failed"
            raise

    def save_transport(self, *, stdout, stderr, transport):
        return self._preserve("dispatched", "transport-preserved", "save_transport",
                              stdout=stdout, stderr=stderr, transport=transport)

    def save_partial_transport(self, *, streams, transport):
        return self._preserve("dispatched", "partial-finished", "save_partial_transport",
                              streams=streams, transport=transport)

    def save_assessment(self, assessment):
        return self._preserve("transport-preserved", "finished", "save_assessment",
                              assessment=assessment)

    def close(self):
        """Close only owned descriptors, retaining every created artifact."""
        self._state = "closed"
        first = None
        if self._journal is not None:
            try:
                self._journal.close()
            except OSError as error:
                first = error
            self._journal = None
        fds = [self._archive_fd, self._capture_fd, self._directory_fd]
        self._archive_fd = self._capture_fd = self._directory_fd = None
        fds += [fd for _, fd, _ in reversed(self._chain)]
        self._chain = []
        for fd in fds:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError as error:
                    if first is None:
                        first = error
        if first is not None:
            raise first


if __name__ == "__main__":
    print(json.dumps(metadata(), sort_keys=True))
