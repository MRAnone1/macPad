"""Host-only, one-attempt preservation of a bounded read-only capture.

This module opens no network connection and grants no native authority. Only a
successful direct method return attests to that invocation's completed fsync
sequence. A persisted true bit cannot prove that the last fsync happened.
Failures retain partial files and consume the attempted phase; never retry or
delete them here. The caller must exclude concurrent same-UID/root writers.
"""

import json
import os

from macws_swap_pair import retained_archive as archive


SCHEMA = "macws.retained-artifact.capture-journal.v1"
PAYLOAD_LIMIT = 256 * 1024
STDOUT_LIMIT = 4 * 1024 * 1024 + 1
STDERR_LIMIT = 16 * 1024 + 1
JSON_LIMIT = 256 * 1024
_BASE = frozenset({"stdin.private.py", "intent.private.json"})
_DISPATCH = _BASE | {"dispatch-intent.private.json"}
_TRANSPORT = _DISPATCH | {"stdout.original.private.bin", "stderr.original.private.bin",
                          "transport.private.json"}
_RESULT = _TRANSPORT | {"assessment.private.json", "receipt.private.json"}


class JournalRefused(ValueError):
    """The bounded host preservation contract did not hold."""


def _require(condition, message):
    if not condition:
        raise JournalRefused(message)


def _plain_json(value):
    data = archive.canonical_json(value)
    _require(len(data) <= JSON_LIMIT, "journal JSON bytes exceed bound")
    return data


def _copy(value):
    return json.loads(archive.canonical_json(value))


class Journal:
    """Hold one new private directory and every created file until close.

    Construction must return successfully before a dispatch is considered.
    mark_dispatch must return successfully before invoking transport. It records
    dispatch intent only, never proof that SSH or a device worker ran.
    save_transport must return before any semantic assessment is attempted.
    It retains received bytes before validating the transport JSON object.
    Every failed mutation consumes this instance, including pre-write failures.
    """

    def __init__(self, parent_directory, capture_name, *, payload, intent):
        self._parent_fd = None
        self._directory_fd = None
        self._held = {}
        self._payloads = {}
        self._state = "initializing"
        self._preparation = None
        _require(type(capture_name) is str and archive._NAME.fullmatch(capture_name)
                 and capture_name not in (".", ".."), "unsafe capture name")
        _require(type(payload) is bytes and 0 < len(payload) <= PAYLOAD_LIMIT,
                 "payload bytes must be nonempty and bounded")
        intent_bytes = _plain_json(intent)
        self._parent_path, _ = archive._absolute_path(parent_directory)
        self._name = capture_name
        try:
            self._parent_fd = archive._open_directory_path(self._parent_path)
            self._parent_identity = archive._directory_identity(
                archive._check_directory(self._parent_fd, private=False))
            _require(self._parent_identity[2] & 0o7777 in (0o700, 0o755),
                     "parent must have mode 0700 or 0755")
            archive._parent_path_checked(self._parent_fd, self._parent_path,
                                         self._parent_identity)
            os.mkdir(capture_name, 0o700, dir_fd=self._parent_fd)
            self._directory_fd = os.open(capture_name, archive._DIR_FLAGS,
                                         dir_fd=self._parent_fd)
            self._directory_identity = archive._directory_identity(
                archive._check_directory(self._directory_fd, private=True))
            self._check()
            self._add("stdin.private.py", payload)
            self._add("intent.private.json", intent_bytes)
            self._sync(_BASE)
            self._preparation = self._receipt("prepared")
            self._state = "prepared"
        except BaseException:
            self._state = "failed"
            self._close_after_error()
            raise

    @property
    def directory(self):
        return self._parent_path + "/" + self._name

    @property
    def preparation_receipt(self):
        _require(self._preparation is not None, "preparation did not complete")
        return _copy(self._preparation)

    def _check(self):
        _require(self._parent_fd is not None and self._directory_fd is not None,
                 "journal is closed")
        archive._parent_path_checked(self._parent_fd, self._parent_path,
                                     self._parent_identity)
        info = archive._check_directory(self._directory_fd, private=True)
        _require(archive._directory_identity(info) == self._directory_identity,
                 "held capture directory identity changed")
        token = archive._stat_tuple(info)
        _require(token == archive._stat_tuple(os.stat(
            self._name, dir_fd=self._parent_fd, follow_symlinks=False)),
            "capture directory descriptor/path mismatch")
        expected_entries = set(self._held)
        _require(set(os.listdir(self._directory_fd)) == expected_entries,
                 "capture entries mismatch")
        for name, (fd, expected_token) in self._held.items():
            expected = self._payloads[name]
            actual, actual_token = archive._read_checked(fd, max(len(expected), 1))
            _require(actual == expected and actual_token == expected_token,
                     "capture readback or file token changed")
            archive._path_checked(self._directory_fd, name, fd, expected_token)
        _require(token == archive._stat_tuple(os.fstat(self._directory_fd))
                 == archive._stat_tuple(os.stat(self._name, dir_fd=self._parent_fd,
                                                follow_symlinks=False))
                 and set(os.listdir(self._directory_fd)) == expected_entries,
                 "capture directory changed during check")
        archive._parent_path_checked(self._parent_fd, self._parent_path,
                                     self._parent_identity)

    def _add(self, name, data):
        self._check()
        _require(name not in self._held, "capture file already created")
        self._held[name] = archive._write_checked(self._directory_fd, name, data)
        self._payloads[name] = data
        self._check()

    def _sync(self, entries):
        _require(set(self._held) == set(entries), "capture phase entries mismatch")
        self._check()
        os.fsync(self._directory_fd)
        os.fsync(self._parent_fd)
        self._check()

    def _receipt(self, phase):
        # receipt.private.json deliberately does not hash itself.
        return {"schema": SCHEMA, "phase": phase,
                "files": {name: {"bytes": len(data), "sha256": archive.sha256(data)}
                          for name, data in sorted(self._payloads.items())
                          if name != "receipt.private.json"},
                "host_durability_steps_completed": True,
                "native_evidence_authenticity_verified": False,
                "device_acceptance": False}

    def mark_dispatch(self):
        """Consume the only dispatch transition and durably preserve its intent."""
        _require(self._state == "prepared", "dispatch phase unavailable")
        self._state = "dispatching"
        try:
            _require(set(self._held) == _BASE, "pre-dispatch entries mismatch")
            dispatch = {"schema": SCHEMA, "phase": "dispatch-intent",
                        "payload_sha256": archive.sha256(self._payloads["stdin.private.py"]),
                        "intent_sha256": archive.sha256(self._payloads["intent.private.json"]),
                        "maximum_transport_invocations": 1,
                        "transport_invocation_confirmed": False,
                        "device_acceptance": False}
            self._add("dispatch-intent.private.json", _plain_json(dispatch))
            self._sync(_DISPATCH)
            receipt = self._receipt("dispatch-intent-preserved")
            self._state = "dispatched"
            return receipt
        except BaseException:
            self._state = "failed"
            raise

    def save_transport(self, *, stdout, stderr, transport):
        """Durably preserve received prefixes before the caller parses them.

        The extra byte permits exact retention of the transport's cap sentinel.
        Returned host durability grants no cleanup or native authenticity.
        """
        _require(self._state == "dispatched", "result phase unavailable")
        self._state = "saving-transport"
        try:
            _require(type(stdout) is bytes and len(stdout) <= STDOUT_LIMIT,
                     "stdout must be bounded original bytes")
            _require(type(stderr) is bytes and len(stderr) <= STDERR_LIMIT,
                     "stderr must be bounded original bytes")
            _require(set(self._held) == _DISPATCH, "pre-result entries mismatch")
            self._add("stdout.original.private.bin", stdout)
            self._add("stderr.original.private.bin", stderr)
            # Preserve both raw streams even when the metadata object refuses.
            os.fsync(self._directory_fd)
            os.fsync(self._parent_fd)
            self._check()
            transport_bytes = _plain_json(transport)
            self._add("transport.private.json", transport_bytes)
            self._sync(_TRANSPORT)
            receipt = self._receipt("transport-preserved")
            self._state = "transport-preserved"
            return _copy(receipt)
        except BaseException:
            self._state = "failed"
            raise

    def save_assessment(self, assessment):
        """Preserve caller assessment after successful raw transport durability."""
        _require(self._state == "transport-preserved", "assessment phase unavailable")
        self._state = "saving-assessment"
        try:
            _require(set(self._held) == _TRANSPORT, "pre-assessment entries mismatch")
            self._add("assessment.private.json", _plain_json(assessment))
            receipt = self._receipt("result-preserved")
            self._add("receipt.private.json", _plain_json(receipt))
            self._sync(_RESULT)
            self._state = "finished"
            return _copy(receipt)
        except BaseException:
            self._state = "failed"
            raise

    def save_partial_transport(self, *, streams, transport):
        """Preserve only known original streams after a transport contract error.

        An absent stream stays absent; even known empty bytes are represented by
        an actual empty file. This terminal phase can never admit assessment.
        Its receipt records host preservation only, not transport completeness.
        """
        _require(self._state == "dispatched", "partial transport phase unavailable")
        self._state = "saving-partial-transport"
        try:
            _require(type(streams) is dict and bool(streams)
                     and all(type(name) is str for name in streams)
                     and set(streams) <= {"stdout", "stderr"},
                     "partial streams require a nonempty known-name subset")
            frozen = dict(streams)
            limits = {"stdout": STDOUT_LIMIT, "stderr": STDERR_LIMIT}
            for name, raw in frozen.items():
                _require(type(name) is str and type(raw) is bytes
                         and len(raw) <= limits[name],
                         "partial stream must be bounded original bytes")
            _require(set(self._held) == _DISPATCH, "pre-partial entries mismatch")
            raw_entries = set(_DISPATCH)
            for name in ("stdout", "stderr"):
                if name in frozen:
                    filename = name + ".original.private.bin"
                    self._add(filename, frozen[name])
                    raw_entries.add(filename)
            # Both the known bytes and their directory entries survive even
            # when the caller's later metadata cannot be serialized safely.
            self._sync(raw_entries)
            self._add("transport.private.json", _plain_json(transport))
            receipt = self._receipt("partial-transport-preserved")
            receipt.update(captured_streams=sorted(frozen),
                           missing_streams=sorted({"stdout", "stderr"} - set(frozen)),
                           transport_contract_complete=False,
                           assessment_performed=False)
            self._add("receipt.private.json", _plain_json(receipt))
            self._sync(raw_entries | {"transport.private.json", "receipt.private.json"})
            self._state = "partial-finished"
            return _copy(receipt)
        except BaseException:
            self._state = "failed"
            raise

    def save_result(self, *, stdout, stderr, transport, assessment):
        """Convenience only for an assessment already held by a trusted caller.

        Call save_transport, then assess raw data, then save_assessment when the
        assessment itself may parse untrusted bytes or raise before completion.
        """
        self.save_transport(stdout=stdout, stderr=stderr, transport=transport)
        return self.save_assessment(assessment)

    def _close_after_error(self):
        try:
            self.close()
        except OSError:
            pass

    def close(self):
        """Close held descriptors only. Never unlink or retry a partial capture."""
        descriptors = [fd for fd, _ in self._held.values()]
        self._held = {}
        descriptors += [self._directory_fd, self._parent_fd]
        self._directory_fd = self._parent_fd = None
        self._state = "closed"
        first_error = None
        for fd in descriptors:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError as exc:
                    if first_error is None:
                        first_error = exc
        if first_error is not None:
            raise first_error

    def __enter__(self):
        _require(self._state == "prepared", "journal is not prepared")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            self._close_after_error()
        else:
            self.close()


def main():
    print(json.dumps({"schema": SCHEMA, "host_persistence_only": True,
                      "native_actions_available": False,
                      "device_acceptance": False}, sort_keys=True))


if __name__ == "__main__":
    main()
