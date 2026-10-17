"""Synthetic passive route controls; no native calls or real task reads."""
import copy
import hashlib
import struct
import unittest

import macos_producer_registration_probe as core
import macos_producer_swap_routes as routes


class Fixture:
    def __init__(self):
        self.memory = {}
        self.now = 1.0
        self.reads = []
        self.checks = 0
        self.candidate = 'selected.dylib'
        self.fb_base, self.hook_base, self.handle = 0x100000, 0x200000, 0x300000
        self.images = {'IOMobileFramebuffer': {'UUID': '9485c742-b91f-3c6c-897c-ab2c8acf7625',
                                              'base_private': self.fb_base},
                       self.candidate: {'UUID': 'selected-UUID', 'base_private': self.hook_base}}
        self.profile = {'prepared_only': True, 'device_calls': 0,
                        'framebuffer_UUID': self.images['IOMobileFramebuffer']['UUID'],
                        'method_slots': {'SwapBegin': 0x720, 'SwapEnd': 0x728, 'SwapCancel': 0x758},
                        'expected_method_targets': {'SwapBegin': 0x4334, 'SwapEnd': 0x4400, 'SwapCancel': 0x4714},
                        'public_SwapEnd_offset': 0x11cc, 'public_entry_read_bytes': 64,
                        'original_framework_windows': [],
                        'profiles': [{'image_basename': self.candidate, 'UUID': 'selected-UUID',
                                      'coexist_flag_offset': 0x800, 'original_trampoline_slot_offset': 0x808,
                                      'hook_entry_offset': 0x900},
                                     {'image_basename': 'other.dylib', 'UUID': 'other-UUID'}]}
        self.rows = [{'image_basename': self.candidate, 'framebuffer_private': self.handle}]
        for index in range(5):
            raw = bytes([index + 1]) * 16
            where = 0x5000 + index * 16
            self.profile['original_framework_windows'].append(
                {'role': str(index), 'image_offset': where, 'bytes': 16,
                 'sha256': hashlib.sha256(raw).hexdigest()})
            self.memory[self.fb_base + where] = raw
        self.memory[self.hook_base + 0x800] = struct.pack('<I', 1)
        self.memory[self.hook_base + 0x808] = struct.pack('<Q', 0x400000)
        for name, offset in self.profile['method_slots'].items():
            self.memory[self.handle + offset] = struct.pack('<Q', self.fb_base + self.profile['expected_method_targets'][name])
        self.entry = self.fb_base + 0x11cc
        self.target = self.hook_base + 0x900
        self.literal(self.entry, self.target)
        self.reader = core.BudgetReader(self.read, 5.0, clock=lambda: self.now)

    def literal(self, entry, target):
        self.memory[entry] = struct.pack('<IIQ', 0x58000051, 0xd61f0220, target) + bytes(48)

    def read(self, address, length):
        self.reads.append((address, length))
        raw = self.memory[address]
        if len(raw) != length:
            raise AssertionError('unexpected synthetic range')
        return raw

    def identity(self):
        self.checks += 1
        return True

    def observe(self):
        return routes.observe_swap_routes(self.rows, self.images, self.reader, self.profile,
                                          check_identity=self.identity)


class RouteControls(unittest.TestCase):
    def test_literal_route_keeps_limits_explicit(self):
        f = Fixture()
        result, guards = f.observe()
        self.assertTrue(result['accepted_swap_dispatch_address_observation'])
        self.assertFalse(result['PAC_authentication_performed'])
        self.assertFalse(result['original_swap_status_observed'])
        self.assertFalse(result['freeze_cause_proven'])
        self.assertEqual(f.checks, 2)
        self.assertEqual(len(guards), 11)
        self.assertEqual(f.reader.calls, 22)

    def test_signed_word_is_classified_only_by_low_address(self):
        f = Fixture()
        f.memory[f.handle + 0x720] = struct.pack('<Q', (0xa12345 << 40) | f.fb_base + 0x4334)
        result, _ = f.observe()
        self.assertTrue(result['accepted_swap_dispatch_address_observation'])
        self.assertFalse(result['function_callability_proven'])

    def test_one_b_relay_then_literal(self):
        f = Fixture()
        relay = f.entry + 0x1000
        f.memory[f.entry] = struct.pack('<I', 0x14000000 | ((relay - f.entry) // 4)) + bytes(60)
        f.literal(relay, f.target)
        result, _ = f.observe()
        self.assertEqual(len(result['dispatch_private']['steps_private']), 2)

    def test_disabled_flag_refuses_without_reading_public_entry(self):
        f = Fixture()
        f.memory[f.hook_base + 0x800] = struct.pack('<I', 0)
        with self.assertRaisesRegex(routes.Refused, 'not exactly armed'):
            f.observe()
        self.assertNotIn((f.entry, 64), f.reads)

    def test_wrong_method_refuses_with_partial_evidence(self):
        f = Fixture()
        f.memory[f.handle + 0x758] = struct.pack('<Q', f.fb_base + 0x4718)
        with self.assertRaisesRegex(routes.Refused, 'method target') as raised:
            f.observe()
        rows = raised.exception.details['swap_routes_private']['observations_private']
        self.assertFalse(rows[0]['method_targets_private']['SwapCancel']['matches_expected_low_address'])

    def test_unknown_entry_refuses_and_preserves_bytes(self):
        f = Fixture()
        f.memory[f.entry] = bytes(64)
        with self.assertRaisesRegex(routes.Refused, 'unclassified public') as raised:
            f.observe()
        steps = raised.exception.details['swap_routes_private']['dispatch_private']['steps_private']
        self.assertEqual(steps[0]['bytes_private_hex'], bytes(64).hex())

    def test_branch_cycle_is_bounded(self):
        f = Fixture()
        f.memory[f.entry] = struct.pack('<I', 0x14000000) + bytes(60)
        with self.assertRaisesRegex(routes.Refused, 'cycle'):
            f.observe()
        self.assertEqual(f.reads.count((f.entry, 64)), 1)

    def test_literal_outside_range_is_not_followed(self):
        raw = struct.pack('<II', 0x58000811, 0xd61f0220) + bytes(56)
        with self.assertRaisesRegex(routes.Refused, 'outside bounded entry'):
            routes.branch_target(0x1000, raw)

    def test_mismatched_branch_register_refuses(self):
        raw = struct.pack('<IIQ', 0x58000051, 0xd61f0200, 0x4000) + bytes(48)
        with self.assertRaisesRegex(routes.Refused, 'register/opcode'):
            routes.branch_target(0x1000, raw)

    def test_identity_change_prevents_reads(self):
        f = Fixture()
        with self.assertRaisesRegex(routes.Refused, 'identity before'):
            routes.observe_swap_routes(f.rows, f.images, f.reader, f.profile, check_identity=lambda: False)
        self.assertEqual(f.reads, [])

    def test_shared_reader_deadline_is_not_extended(self):
        f = Fixture()
        f.now = 10.0
        with self.assertRaisesRegex(core.Refused, 'deadline'):
            f.observe()
        self.assertEqual(f.reader.calls, 0)

    def test_shared_budget_is_not_reset(self):
        f = Fixture()
        f.reader.calls = core.MAX_READ_CALLS
        with self.assertRaisesRegex(core.Refused, 'budget'):
            f.observe()
        self.assertEqual(f.reads, [])

    def test_changed_route_bytes_refuse(self):
        f = Fixture()
        original = f.read
        reads = [0]
        def changing(where, size):
            data = original(where, size)
            if where == f.hook_base + 0x800:
                reads[0] += 1
                if reads[0] == 2:
                    return struct.pack('<I', 0)
            return data
        f.reader.callback = changing
        with self.assertRaisesRegex(routes.Refused, 'route bytes changed'):
            f.observe()


if __name__ == '__main__':
    unittest.main()
