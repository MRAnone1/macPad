"""Host fixtures for current cleanup gates. No iPad or native calls."""
from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch

from macws_swap_pair import current_cleanup_gate as gate
from macws_swap_pair import readonly_observer as readonly
import test_macws_current_installation_cleanup as cleanup_fixture
from test_macws_swap_pair_observer import absent


INPUTS = (Path(__file__).resolve().parent / 'macws_swap_pair/observer_inputs.json').read_bytes()
REFUSALS = (gate.core.Refused, readonly.Refused)


class FakeObserver:
    def __init__(self, context):
        self.context = deepcopy(context)
        self.command_calls = 0
        self.temperature = 0
        self.scratch = True
        self.extra_processes = []
        self.bad_job = None
        self.ui_path = None
        self.bad_birth = None
        self.snapshot_hook = None

    def clock_info(self):
        return self.context['clock_info']

    def metadata(self):
        return self.context['binding']

    def process_snapshot(self):
        self.command_calls += 1
        if self.snapshot_hook is not None:
            self.snapshot_hook()
        ui = self.context['UI_private']
        details = {name: {'birth_private': deepcopy(birth), 'path': gate.UI_PATHS[name],
                          'stopped': False} for name, birth in ui.items()}
        if self.ui_path is not None:
            details['SpringBoard']['path'] = self.ui_path
        if self.bad_birth is not None:
            details['SpringBoard']['birth_private'] = self.bad_birth
        rows = [{'pid_private': birth[0], 'basename': name} for name, birth in ui.items()]
        rows.append({'pid_private': 100, 'basename': 'python3'})
        return {'UI_private': ui, 'UI_details_private': details, 'blocked_private': [],
                'rows_private': rows + self.extra_processes}

    def thermal(self):
        return self.temperature

    def job(self, label):
        self.command_calls += 1
        return absent(label) if self.bad_job is None else self.bad_job

    def path_absent(self, path):
        return self.scratch


class GateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = staticmethod(readonly.extracted_absence_parser(readonly.checked_inputs(INPUTS)))

    def setUp(self):
        self.clock = cleanup_fixture.Clock()
        self.clock.profile = dict(self.clock.profile)
        binding = cleanup_fixture.old_fixture.fixture()[5]
        self.context = {'binding': dict(binding, rootfs_product_version='13.4', rootfs_product_build='22F66'),
                        'UI_private': {'SpringBoard': [10, 100, 0], 'backboardd': [11, 100, 0]},
                        'attempt_nonce': 'a' * 32, 'clock_info': dict(self.clock.profile),
                        'source_sha256': {key: 'b' * 64 for key in
                                          ('cleanup', 'physical_directory', 'stat_record', 'provenance')}}
        self.observers = []
        self.exclusion_calls = []
        self.change = lambda observer: None
        self.deadline = self.clock.value + 8

    def new_observer(self, stop):
        result = FakeObserver(self.context)
        self.change(result)
        self.observers.append(result)
        return result

    def assert_exclusive(self, context, deadline):
        self.exclusion_calls.append((context, deadline))

    def action(self, **overrides):
        kwargs = dict(clock=self.clock, new_observer=self.new_observer, absence_parser=self.parser,
                      assert_exclusive=self.assert_exclusive, worker_pid=100)
        return gate.CleanupGate(self.context, **dict(kwargs, **overrides))

    def test_construction_has_no_observation_or_exclusion_calls(self):
        self.assertTrue(gate.metadata()['default_inert'])
        self.assertEqual(self.action().snapshot()['observations_private'], [])
        self.assertEqual(self.observers, [])
        self.assertEqual(self.exclusion_calls, [])
        self.assertEqual(self.clock.calls, 0)

    def test_full_nine_gates_and_four_commands_per_scope(self):
        action = self.action()
        for _ in range(9):
            row = action.observe(self.deadline)
            self.assertEqual(row['UI_private'], self.context['UI_private'])
            self.assertTrue(row['exclusive_operator'])
            self.assertTrue(all(row['jobs_absent'].values()))
        self.assertEqual([observer.command_calls for observer in self.observers], [4] * 9)
        self.assertEqual(len(self.exclusion_calls), 18)
        with self.assertRaises(gate.core.Refused):
            action.observe(self.deadline)
        self.assertEqual(len(self.observers), 9)

    def test_oldest_read_timestamp_survives_a_slow_scan(self):
        def delay():
            self.clock.value += .3
        self.change = lambda observer: setattr(observer, 'snapshot_hook', delay)
        action = self.action()
        row = action.observe(self.deadline)
        record = action.snapshot()['observations_private'][0]
        self.assertEqual(row['observed_monotonic'], record['started_monotonic'])
        self.assertGreater(record['finished_monotonic'] - row['observed_monotonic'], .59)

    def test_slow_scan_consumes_gate_without_retry(self):
        def delay():
            self.clock.value += .55
        self.change = lambda observer: setattr(observer, 'snapshot_hook', delay)
        action = self.action()
        with self.assertRaisesRegex(gate.core.Refused, 'gate_observation_deadline'):
            action.observe(self.deadline)
        self.assertTrue(action.snapshot()['terminal_refusal'])
        with self.assertRaises(gate.core.Refused):
            action.observe(self.deadline)
        self.assertEqual(len(self.observers), 1)

    def test_clock_regression_is_refused(self):
        def regress():
            self.clock.value -= .2
        self.change = lambda observer: setattr(observer, 'snapshot_hook', regress)
        with self.assertRaisesRegex(gate.core.Refused, 'gate_clock_regression'):
            self.action().observe(self.deadline)

    def test_changed_deadline_and_boolean_clock_alias_are_refused(self):
        action = self.action()
        action.observe(self.deadline)
        with self.assertRaisesRegex(gate.core.Refused, 'fixed_cleanup_action_deadline'):
            action.observe(self.deadline - .1)
        self.clock.profile['numer'] = True
        with self.assertRaises(gate.core.Refused):
            self.action()

    def test_serialized_truth_and_final_exclusion_refusal(self):
        with self.assertRaises(gate.core.Refused):
            self.action(assert_exclusive=True)
        with self.assertRaises(gate.core.Refused):
            self.action(assert_exclusive=lambda context, deadline: True).observe(self.deadline)
        self.assertEqual(self.observers, [])
        def lose_lease(context, deadline):
            self.assert_exclusive(context, deadline)
            if len(self.exclusion_calls) == 2:
                raise gate.core.Refused('lease lost')
        action = self.action(assert_exclusive=lose_lease)
        with self.assertRaisesRegex(gate.core.Refused, 'lease lost'):
            action.observe(self.deadline)
        self.assertFalse(action.snapshot()['observations_private'][0]['completed'])

    def test_generation_changes_in_either_bracket(self):
        def change(observer):
            def change_second_birth():
                if observer.command_calls == 4:
                    observer.context['UI_private']['SpringBoard'][1] += 1
            observer.snapshot_hook = change_second_birth
        self.change = change
        with self.assertRaisesRegex(gate.core.Refused, 'live_binding_or_UI_changed'):
            self.action().observe(self.deadline)

    def test_ui_path_and_detail_birth_are_checked(self):
        for name, value in [('ui_path', '/tmp/SpringBoard'), ('bad_birth', [10, 100, False])]:
            with self.subTest(name=name):
                self.change = lambda observer: setattr(observer, name, value)
                with self.assertRaises(REFUSALS):
                    self.action().observe(self.deadline)

    def test_competing_worker_and_wrapper_are_refused(self):
        for name in ('python3', 'Python3.11', 'pypy3', 'controller.py', 'watchdog.py',
                     'launchdchrootexec_fullframe_streamgate_20261009', 'probe.arm64'):
            with self.subTest(name=name):
                self.change = lambda observer: observer.extra_processes.append({'pid_private': 200, 'basename': name})
                with self.assertRaisesRegex(gate.core.Refused, 'conflicting_cleanup_workload'):
                    self.action().observe(self.deadline)
        with self.assertRaises(gate.core.Refused):
            self.action(worker_pid=True)

    def test_wrong_launchd_domain_thermal_and_scratch_do_not_pass(self):
        for name, value in [('temperature', False), ('temperature', 1), ('scratch', 1),
                            ('scratch', False), ('bad_job', (113, '', 'No service in system\n'))]:
            with self.subTest(name=name, value=value):
                self.change = lambda observer: setattr(observer, name, value)
                with self.assertRaises(REFUSALS):
                    self.action().observe(self.deadline)

    def test_native_factory_keeps_frozen_observer_and_tightens_deadline(self):
        made = []
        def observer_factory(inputs):
            instance = FakeObserver(self.context)
            instance.deadline = 1008
            made.append(instance)
            return instance
        with patch.object(gate.os, 'geteuid', return_value=0), \
             patch.object(gate.os, 'getegid', return_value=0), \
             patch.object(gate.os, 'getpid', return_value=100), \
             patch.object(readonly, 'extracted_shared_clock', return_value=lambda: self.clock), \
             patch.object(readonly, 'NativeObserver', side_effect=observer_factory):
            with self.assertRaises(readonly.Refused):
                gate.native_gate(self.context, frozen_input_bytes=b'invalid', assert_exclusive=self.assert_exclusive)
            action = gate.native_gate(self.context, frozen_input_bytes=INPUTS,
                                      assert_exclusive=self.assert_exclusive)
            self.assertEqual(made, [])
            action.observe(self.deadline)
        self.assertEqual(len(made), 1)
        self.assertLess(made[0].deadline, 1001.01)

    def test_core_refuses_effect_when_namespace_work_ages_first_read(self):
        fixture = cleanup_fixture.CleanupTests('runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.clock = fixture.clock
        self.context = fixture.context
        def scan_delay():
            self.clock.value += .3
        self.change = lambda observer: setattr(observer, 'snapshot_hook', scan_delay)
        action = self.action()
        original = fixture.fs.snapshot
        late = False
        def snapshot(fd, check):
            nonlocal late
            result = original(fd, check)
            if len(self.observers) == 2 and not late:
                self.clock.value += .45
                late = True
            return result
        with patch.object(fixture.fs, 'snapshot', side_effect=snapshot):
            result = fixture.action().run(cleanup=True, fs=fixture.fs, gate=action,
                                          clock=self.clock, verify_archive=fixture.archive)
        self.assertTrue(late)
        fixture.assert_no_effect(result)
        self.assertEqual(result['refusal'], 'gate_stale_before_unlink')


if __name__ == '__main__':
    unittest.main()
