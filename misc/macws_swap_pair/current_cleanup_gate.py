"""Read-only observations for the current-installation cleanup core.

The caller owns source authentication and an actual exclusion lease covering
the entire action, including intervals between observations. A process list
cannot supply that lease. The explicit native factory reuses the exact copied
read-only primitives. No action worker or device acceptance is provided here.
"""
import os

from macws_swap_pair import current_installation_cleanup as core
from macws_swap_pair import readonly_observer as readonly


MAX_OBSERVATIONS = 9
OBSERVATION_SECONDS = 1
UI_PATHS = {
    'SpringBoard': '/System/Library/CoreServices/SpringBoard.app/SpringBoard',
    'backboardd': '/usr/libexec/backboardd',
}
WORKER_BASENAME = 'python3'
BLOCKED_NAMES = frozenset(name.lower() for name in
    (*readonly.BLOCKED_BASENAMES, *core.EXPECTED_FILES,
     readonly.DEPENDENCIES['wrapper']['path'].rsplit('/', 1)[-1]))


def metadata():
    return {'schema': 'macws.current-cleanup-gate.metadata.v1', 'default_inert': True,
            'maximum_observations': MAX_OBSERVATIONS, 'observation_seconds': OBSERVATION_SECONDS,
            'device_acceptance': False}


class CleanupGate:
    """Collect one current bracket per call, with terminal refusal on error."""

    def __init__(self, context, *, clock, new_observer, absence_parser,
                 assert_exclusive, worker_pid):
        self.context = core.checked_context(context)
        core.need(type(worker_pid) is int and 1 < worker_pid <= 0x7fffffff,
                  'exact_worker_pid')
        core.need(all(callable(item) for item in (new_observer, absence_parser, assert_exclusive)),
                  'explicit_trusted_observer_parser_and_exclusion_check')
        self.clock = clock
        self._new_observer = new_observer
        self._absence_parser = absence_parser
        self._assert_exclusive = assert_exclusive
        self._worker_pid = worker_pid
        self._deadline = None
        self._last_clock = None
        self._failed = False
        self._records = []
        self._check_clock_profile(clock.profile)

    def _check_clock_profile(self, profile):
        current = core.checked_context(dict(self.context, clock_info=profile))
        core.need(current == self.context, 'shared_clock_profile')

    def _tick(self, stop=None):
        current = core.number(self.clock.now())
        core.need(self._last_clock is None or current >= self._last_clock,
                  'gate_clock_regression')
        self._last_clock = current
        core.need(stop is None or current < stop, 'gate_observation_deadline')
        return current

    def _bracket(self, observer, stop, record):
        record['binding'] = core.copied(observer.metadata())
        self._tick(stop)
        processes = observer.process_snapshot()
        self._tick(stop)
        record['UI_private'] = core.copied(processes['UI_private'])
        current = core.checked_context(dict(self.context, binding=record['binding'],
                                           UI_private=record['UI_private']))
        core.need(current == self.context, 'live_binding_or_UI_changed')
        details = processes['UI_details_private']
        core.provenance.exact_keys(details, UI_PATHS)
        for name, path in UI_PATHS.items():
            item = details[name]
            readonly.birth_checked(item['birth_private'])
            core.need(item['path'] == path and item['stopped'] is False and
                      item['birth_private'] == current['UI_private'][name],
                      'live_UI_path_or_state_changed')
        blocked = processes['blocked_private']
        core.need(type(blocked) is list and not blocked, 'blocked_workload_reported')
        rows = processes['rows_private']
        core.need(type(rows) is list and 0 < len(rows) <= readonly.LIMITS['process_count'],
                  'bounded_current_process_rows')
        names = {}
        for row in rows:
            pid, name = row['pid_private'], row['basename']
            core.need(type(pid) is int and pid > 0 and pid not in names and
                      type(name) is str and 0 < len(name) <= 4096, 'current_process_row')
            names[pid] = name
            lower = name.lower()
            if pid == self._worker_pid:
                continue
            if lower in BLOCKED_NAMES or lower.startswith(('python', 'pypy', 'launchdchrootexec')):
                record['conflicting_basename_private'] = name
                raise core.Refused('conflicting_cleanup_workload')
        core.need(names.get(self._worker_pid) == WORKER_BASENAME and
                  all(names.get(birth[0]) == name for name, birth in current['UI_private'].items()),
                  'current_worker_or_UI_process_row_missing')
        record['process_rows'] = len(rows)
        record['thermal'] = observer.thermal()
        self._tick(stop)
        core.need(type(record['thermal']) is int and record['thermal'] == 0,
                  'nominal_current_thermal_required')
        record['scratch_absent'] = {}
        for path in core.SCRATCH:
            absent = observer.path_absent(path)
            self._tick(stop)
            record['scratch_absent'][path] = absent
            core.need(absent is True, 'current_scratch_present_or_unknown')

    def observe(self, deadline):
        core.need(self._failed is False and len(self._records) < MAX_OBSERVATIONS,
                  'gate_refused_or_observation_limit')
        record = {'completed': False, 'before': {}, 'after': {}, 'jobs_absent': {}}
        self._records.append(record)
        try:
            start = self._tick()
            deadline = core.number(deadline)
            core.need(0 < deadline - start <= core.SECONDS and
                      (self._deadline is None or deadline == self._deadline),
                      'fixed_cleanup_action_deadline')
            self._deadline = deadline
            stop = min(deadline, start + OBSERVATION_SECONDS)
            record['started_monotonic'] = start
            self._check_clock_profile(self.clock.profile)
            core.need(self._assert_exclusive(core.copied(self.context), deadline) is None,
                      'direct_exclusion_check_required')
            self._tick(stop)
            observer = self._new_observer(stop)
            self._check_clock_profile(observer.clock_info())
            self._tick(stop)
            self._bracket(observer, stop, record['before'])
            for label in core.LABELS:
                result = observer.job(label)
                self._tick(stop)
                record['jobs_absent'][label] = readonly.job_absent(result, label, self._absence_parser)
            self._bracket(observer, stop, record['after'])
            self._check_clock_profile(observer.clock_info())
            self._check_clock_profile(self.clock.profile)
            core.need(self._assert_exclusive(core.copied(self.context), deadline) is None,
                      'direct_exclusion_check_required')
            finished = self._tick(stop)
            # Include the age of the oldest read when the core checks freshness
            # again after its namespace work and before each filesystem effect.
            record.update(completed=True, finished_monotonic=finished)
            return dict(core.copied(self.context), schema='macws.current-installation-cleanup.gates.v1',
                        observed_monotonic=start, thermal=record['after']['thermal'],
                        jobs_absent=dict(record['jobs_absent']),
                        scratch_absent=dict(record['after']['scratch_absent']),
                        no_candidate_or_test_workloads=True, exclusive_operator=True)
        except BaseException as error:
            self._failed = True
            record['refusal'] = type(error).__name__
            raise

    def snapshot(self):
        """Copy the bounded gate report without granting authority from JSON."""
        return core.copied({'observations_private': self._records, 'terminal_refusal': self._failed,
                            'device_acceptance': False})


def native_gate(context, *, frozen_input_bytes, assert_exclusive):
    """Explicit native binding for a caller with an independently held lease."""
    checked = core.checked_context(context)
    core.need(callable(assert_exclusive), 'explicit_direct_exclusion_check_required')
    inputs = readonly.checked_inputs(frozen_input_bytes)
    core.need((os.geteuid(), os.getegid()) == (0, 0), 'explicit_root_gate_process')
    clock = readonly.extracted_shared_clock(inputs)()
    parser = readonly.extracted_absence_parser(inputs)

    def new_observer(stop):
        observer = readonly.NativeObserver(inputs)
        # One frozen read-only scope per gate, with a tighter absolute stop.
        observer.deadline = min(observer.deadline, stop)
        return observer

    return CleanupGate(checked, clock=clock, new_observer=new_observer, absence_parser=parser,
                       assert_exclusive=assert_exclusive, worker_pid=os.getpid())
