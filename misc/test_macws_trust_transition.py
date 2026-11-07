"""Invented query evidence only; never a device/trust witness."""
import copy
import unittest
from macws_swap_pair import trust_transition as core

OTHER = '1' * 40

def result(raw):
    return {'returncode': 0, 'stdout': raw, 'stderr': b'', 'capture_complete': True,
            'timed_out': False, 'output_limit_exceeded': False, 'local_cleanup_errors': []}

def query(hashes):
    return result(('Jailbreak Trustcache 0 <UUID: ' + 'A' * 32 + '> (length: ' + str(len(hashes)) + ')\n' +
        ''.join('| %d:\t%s\n' % (i + 1, word) for i, word in enumerate(hashes))).encode())

def fixture(role='candidate'):
    return {'role': role, 'before': query([OTHER]), 'addition': result(b''), 'after': query([OTHER, core.TARGETS[role]])}

class TrustTransitionTests(unittest.TestCase):
    def test_fixed_roles_exact_transition_and_no_authority(self):
        for role in core.TARGETS:
            args = fixture(role); original = copy.deepcopy(args); report = core.assess(**args)
            self.assertEqual(args, original); self.assertTrue(report['exact_reported_transition'])
            self.assertEqual((report['before_entries'], report['after_entries']), (1, 2))
            for name in ('native_authenticity_verified', 'native_freshness_verified', 'execution_authorized',
                         'session_authorized', 'cleanup_authorized', 'retry_authorized', 'rollback_authorized', 'device_acceptance'):
                self.assertIs(report[name], False)
    def test_zero_exit_empty_info_cannot_mean_empty_trust_set(self):
        for phase in ('before', 'after'):
            args = fixture(); args[phase] = result(b'')
            with self.subTest(phase=phase), self.assertRaises(core.Refused): core.assess(**args)
    def test_zero_exit_add_without_membership_change_refuses(self):
        args = fixture(); args['after'] = query([OTHER])
        with self.assertRaises(core.Refused): core.assess(**args)
    def test_extra_addition_or_removal_refuses(self):
        for hashes in ([core.TARGETS['candidate']], [OTHER, core.TARGETS['candidate'], '2' * 40]):
            args = fixture(); args['after'] = query(hashes)
            with self.subTest(hashes=hashes), self.assertRaises(core.Refused): core.assess(**args)
    def test_already_present_target_requires_skipping_add(self):
        args = fixture(); args['before'] = query([OTHER, core.TARGETS['candidate']])
        with self.assertRaises(core.Refused): core.assess(**args)
    def test_unknown_role_and_free_hash_are_not_accepted(self):
        for role in ('unknown', 'clear', core.TARGETS['candidate'], True):
            args = fixture(); args['role'] = role
            with self.subTest(role=role), self.assertRaises(core.Refused): core.assess(**args)
    def test_partial_nonzero_or_ambiguous_transport_refuses(self):
        for phase in ('before', 'addition', 'after'):
            for name, value in [('returncode', True), ('returncode', 1), ('returncode', None), ('capture_complete', False),
                ('timed_out', True), ('output_limit_exceeded', True), ('local_cleanup_errors', ['failure'])]:
                args = fixture(); args[phase][name] = value
                with self.subTest(phase=phase, name=name), self.assertRaises(core.Refused): core.assess(**args)
    def test_malformed_or_truncated_info_refuses(self):
        for raw in (b'\xff', b'ERROR\n', b'| 1: ' + OTHER.encode(), query([OTHER])['stdout'].replace(b'length: 1', b'length: 2'),
                    query([OTHER])['stdout'].replace(b'| 1:', b'| 2:')):
            args = fixture(); args['before']['stdout'] = raw
            with self.subTest(raw=raw[:50]), self.assertRaises(core.Refused): core.assess(**args)
    def test_unknown_transport_fields_types_noise_and_bounds_refuse(self):
        for phase, key, value in [('addition', 'extra', True), ('after', 'stdout', 'text'), ('after', 'stderr', b'warning'),
            ('before', 'stdout', b'X' * (core.MAX_QUERY_STDOUT + 1)), ('addition', 'stdout', b'X' * (core.MAX_ADD_STREAM + 1))]:
            args = fixture(); args[phase][key] = value
            with self.subTest(phase=phase, key=key), self.assertRaises(core.Refused): core.assess(**args)
    def test_add_output_is_retained_without_becoming_success_basis(self):
        args = fixture(); args['addition'].update(stdout=b'\x00uninterpreted', stderr=b'bounded diagnostics')
        report = core.assess(**args)
        self.assertEqual(report['add_stdout_private_b64'], 'AHVuaW50ZXJwcmV0ZWQ=')
        args['after'] = query([OTHER])
        with self.assertRaises(core.Refused): core.assess(**args)
    def test_default_metadata_is_inert(self):
        self.assertEqual(core.metadata()['native_calls'], 0); self.assertEqual(core.metadata()['trust_mutations'], 0)

if __name__ == '__main__': unittest.main()
