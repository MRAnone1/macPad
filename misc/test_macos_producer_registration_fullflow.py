"""Synthetic full-run observer tests; task APIs and executable reads are mocked."""
import copy
import ctypes
import hashlib
import io
import json
from pathlib import Path
import struct
import unittest
import uuid
from unittest.mock import patch

import macos_producer_registration_probe as reader

PROFILE = Path(__file__).resolve().parent / 'profiles/macos-producer-registration-m1-20e252-streamgate.json'


def header(identity):
    return (struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 6, 1, 24, 0, 0) +
            struct.pack('<II', 0x1b, 24) + uuid.UUID(identity).bytes)


class FakeCall:
    def __init__(self, function): self.function = function
    def __call__(self, *args): return self.function(*args)


class FakeLibrary:
    def __init__(self, **functions):
        for name, function in functions.items(): setattr(self, name, FakeCall(function))


class MockTask:
    PID = 42
    BOOT = '11111111-2222-3333-4444-555555555555'
    def __init__(self):
        self.profile = copy.deepcopy(json.loads(PROFILE.read_bytes()))
        self.profile['profiles'] = self.profile['profiles'][:1]
        self.exe = header('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
        self.memory = []
        self.read_counts = {}
        self.reads = []
        self.acquire_calls = self.release_calls = self.same_task_calls = 0
        self.path_calls = self.boot_calls = 0
        self.generation_calls = 0
        self.fail = None
        self.dyld = 0x100000
        self.array = 0x110000
        self.qc = 0x300000
        self.fb_image = 0x400000
        self.candidate = 0x10000000
        self.framebuffer = 0x20000000
        self.context = 0x21000000
        self.display = 0x22000000
        self.client = 12345
        self.callback = self.qc + 0x29209c
        self.candidate_name = self.profile['profiles'][0]['image_basename']
        image_rows = []
        for index, (name, base, identity) in enumerate([
                ('WindowServer', 0x200000, 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'),
                ('QuartzCore', self.qc, self.profile['macOS_QuartzCore_UUID']),
                ('IOMobileFramebuffer', self.fb_image, self.profile['macOS_framebuffer_UUID']),
                (self.candidate_name, self.candidate, self.profile['profiles'][0]['UUID'])]):
            path = 0x120000 + index * 0x200
            self.put(path, ('/mock/' + name).encode() + b'\0' + bytes(384 - len('/mock/' + name) - 1))
            self.put(base, header(identity))
            image_rows.append(struct.pack('<3Q', base, path, 0))
        self.put(self.array, b''.join(image_rows))
        self.put(self.dyld, struct.pack('<IIQ', 15, 4, self.array))
        self.gate_addresses = []
        for name, gates in self.profile['original_framework_windows'].items():
            base = self.qc if name == 'QuartzCore' else self.fb_image
            for gate in gates:
                address = base + int(gate['image_offset'], 16)
                data = b'F' * gate['bytes']
                gate['sha256'] = hashlib.sha256(data).hexdigest()
                self.put(address, data); self.gate_addresses.append(address)
        declared = self.profile['profiles'][0]
        for gate in declared['compiled_code_windows']:
            address = self.candidate + int(gate['image_offset'], 16)
            data = b'C' * gate['bytes_to_next_distinct_text_symbol']
            gate['sha256'] = hashlib.sha256(data).hexdigest()
            self.put(address, data); self.gate_addresses.append(address)
        self.count_address = self.candidate + int(declared['data_anchors']['_g_macws_iomfb_frame_reg_count']['image_offset'], 16)
        self.regs_address = self.candidate + int(declared['data_anchors']['_g_macws_iomfb_frame_regs']['image_offset'], 16)
        self.put(self.count_address, struct.pack('<I', 1))
        self.put(self.regs_address, struct.pack('<QIIQQQ', self.framebuffer, self.client, 0, self.callback, self.context, 0))
        self.put(self.framebuffer + 0x10, struct.pack('<II', 111, self.client))
        self.put(self.framebuffer + 0x68, struct.pack('<I', 271828))
        self.put(self.context + 0x58, struct.pack('<Q', self.display))
        self.put(self.display + 0x300, struct.pack('<Q', self.framebuffer))
        self.put(self.display + 0x9a4, struct.pack('<Q', 1 << 35))
        self.library = FakeLibrary(sysctlbyname=self.sysctl, task_for_pid=self.acquire,
                                   mach_port_deallocate=self.release, pid_for_task=self.same_task,
                                   vm_read_overwrite=self.vm_read, task_info=self.task_info,
                                   proc_pidinfo=self.proc_pidinfo)
        self.proc = FakeLibrary(proc_pidpath=self.pidpath, proc_pidinfo=self.proc_pidinfo)

    def put(self, address, data): self.memory.append((address, bytes(data)))
    def replace(self, address, data):
        self.memory = [(base, old) for base, old in self.memory if base != address]
        self.put(address, data)
    def lookup(self, address, size):
        for base, data in self.memory:
            if base <= address and address + size <= base + len(data):
                return data[address - base:address - base + size]
        raise AssertionError('mock unmapped task extent')
    def pidpath(self, pid, data, size):
        self.path_calls += 1
        data.value = (reader.EXPECTED_PATH if self.fail != 'path' else '/mock/wrong').encode()
        return len(data.value)
    def sysctl(self, key, data, size, *_):
        values = {b'hw.machine': 'iPad13,6', b'kern.osversion': '20E252',
                  b'kern.uuid': 'd6b9e234-64f1-30ea-ae62-ed8f2dc6efdb', b'kern.bootsessionuuid': self.BOOT}
        if key == b'kern.bootsessionuuid': self.boot_calls += 1
        value = values[key]
        if key == b'kern.bootsessionuuid' and self.fail == 'boot' and self.boot_calls > 1:
            value = 'aaaaaaaa-2222-3333-4444-555555555555'
        data.value = value.encode(); size._obj.value = len(data.value) + 1
        return 0
    def acquire(self, self_task, pid, output):
        self.acquire_calls += 1
        if self.fail == 'access': return 5
        output._obj.value = 555
        return 0
    def proc_pidinfo(self, pid, flavor, arg, data, size):
        self.generation_calls += 1
        assert pid == self.PID and flavor == 3 and arg == 0 and size == 136
        raw = bytearray(136)
        struct.pack_into('<I', raw, 12, self.PID)
        changed = ((self.fail == 'generation' and self.generation_calls > 1) or
                   (self.fail == 'generation_final' and self.generation_calls > 2))
        seconds = 1650000000 + int(changed)
        struct.pack_into('<QQ', raw, 120, seconds, 123456)
        ctypes.memmove(ctypes.addressof(data), bytes(raw), 136)
        errno_failure = (self.fail == 'generation_errno' or
                         (self.fail == 'generation_errno_after' and self.generation_calls > 1))
        ctypes.set_errno(3 if errno_failure else 0)
        short = (self.fail == 'generation_result' or
                 (self.fail == 'generation_result_after' and self.generation_calls > 1))
        return 135 if short else 136
    def release(self, self_task, task):
        self.release_calls += 1
        assert task == 555
        return 5 if self.fail == 'release' else 0
    def same_task(self, task, output):
        self.same_task_calls += 1
        output._obj.value = self.PID + int(self.fail == 'task' and self.same_task_calls > 1)
        return 0
    def task_info(self, task, flavor, data, count):
        assert flavor == 17 and count._obj.value == 5
        ctypes.memmove(ctypes.addressof(data), struct.pack('<QQi', self.dyld, 16, 1), 20)
        count._obj.value = 5
        return 0
    def vm_read(self, task, address, size, destination, returned):
        self.reads.append((address, size))
        self.read_counts[address] = self.read_counts.get(address, 0) + 1
        if self.fail == 'unmapped_path' and address == 0x120000:
            return 1  # Valid short path exists, but the fixed 384-byte read crosses its mapping.
        data = self.lookup(address, size)
        times = self.read_counts[address]
        drift = ((self.fail == 'gate' and address == self.gate_addresses[0]) or
                 (self.fail == 'gate_repeat' and address == self.gate_addresses[0] and times > 1) or
                 (self.fail == 'dyld' and address == self.array and times > 1) or
                 (self.fail == 'regs' and address == self.regs_address and times > 1) or
                 (self.fail == 'handle' and address == self.framebuffer + 0x68 and times > 2))
        if drift: data = bytes([data[0] ^ 1]) + data[1:]
        if self.fail == 'read': return 1
        ctypes.memmove(destination, data, size)
        returned._obj.value = size
        return 0
    def observe(self, *, port_observer=None):
        class FakePath:
            def __init__(self, _): pass
            def open(inner, _): return io.BytesIO(self.exe)
        with patch.object(reader, 'Path', FakePath), \
             patch.object(reader, 'verify_profile', return_value=self.profile), \
             patch.object(reader, 'EXPECTED_EXE_SHA', hashlib.sha256(self.exe).hexdigest()), \
             patch.object(reader.ctypes, 'CDLL', side_effect=lambda name, **_: self.library if name is None else self.proc), \
             patch.object(reader.ctypes.c_uint32, 'in_dll', return_value=ctypes.c_uint32(999)):
            return reader.run(self.PID, b'mocked profile', port_observer=port_observer)


class FullFlow(unittest.TestCase):
    def test_description_observer_borrows_same_task_and_counts_its_rechecks(self):
        task = MockTask()
        def observer(library, held, rows, deadline, recheck):
            self.assertIs(library, task.library)
            self.assertEqual(held, 555)
            self.assertEqual(task.release_calls, 0)
            self.assertEqual(rows[0]['client_name_private'], task.client)
            for _ in range(3):
                self.assertIs(recheck(), True)
            return {'accepted_repeated_registry_object_descriptions': True,
                    'client_provider_relation_proven': False}
        result = task.observe(port_observer=observer)
        self.assertTrue(result['port_descriptions_private']['accepted_repeated_registry_object_descriptions'])
        self.assertEqual(task.generation_calls, 6)
        self.assertEqual(result['process_birth_metadata_calls'], 6)
        self.assertEqual(task.release_calls, 1)

    def test_description_recheck_refuses_changed_original_handle_and_releases(self):
        task = MockTask()
        def observer(library, held, rows, deadline, recheck):
            task.replace(task.framebuffer + 0x10, struct.pack('<II', 111, task.client + 1))
            recheck()
            self.fail('changed handle accepted')
        with self.assertRaisesRegex(reader.Refused, 'registered bytes changed around descriptions'):
            task.observe(port_observer=observer)
        self.assertEqual(task.release_calls, 1)

    def test_description_callback_cannot_mutate_the_base_registration_result(self):
        task = MockTask()
        def observer(library, held, rows, deadline, recheck):
            self.assertEqual(set(rows[0]), {'service_name_private', 'client_name_private'})
            rows[0]['client_name_private'] += 1
            return {'accepted_repeated_registry_object_descriptions': True}
        with self.assertRaisesRegex(reader.Refused, 'port observer changed handle inputs'):
            task.observe(port_observer=observer)
        self.assertEqual(task.release_calls, 1)

    def test_description_refusal_does_not_skip_task_cleanup(self):
        task = MockTask()
        def observer(*_):
            raise ValueError('native description denied')
        with self.assertRaisesRegex(ValueError, 'native description denied'):
            task.observe(port_observer=observer)
        self.assertEqual(task.release_calls, 1)

    def test_description_observer_contract_refusal_does_not_accept_or_leak(self):
        task = MockTask()
        with self.assertRaisesRegex(reader.Refused, 'port description observer refused'):
            task.observe(port_observer=lambda *_: {'accepted_repeated_registry_object_descriptions': False})
        self.assertEqual(task.release_calls, 1)

    def test_empty_registration_does_not_call_description_observer(self):
        task = MockTask(); task.replace(task.count_address, struct.pack('<I', 0))
        with self.assertRaisesRegex(reader.Refused, 'no registrations for description observer'):
            task.observe(port_observer=lambda *_: self.fail('empty table observer invoked'))
        self.assertEqual(task.release_calls, 1)

    def test_invalid_description_observer_refuses_before_task_acquisition(self):
        task = MockTask()
        with self.assertRaisesRegex(reader.Refused, 'port observer callback shape'):
            task.observe(port_observer=False)
        self.assertEqual((task.acquire_calls, task.release_calls), (0, 0))

    def test_success_checks_repeats_and_releases_held_task(self):
        task = MockTask(); result = task.observe()
        self.assertTrue(result['accepted_partial_registration_observation'])
        self.assertEqual(result['registration_observations'], 1)
        self.assertEqual(task.acquire_calls, 1); self.assertEqual(task.release_calls, 1)
        self.assertEqual(task.same_task_calls, 2)
        self.assertEqual(task.generation_calls, 3)
        self.assertEqual(result['process_birth_metadata_calls'], 3)
        self.assertTrue(result['same_process_birth_metadata_repeated_equal'])
        self.assertFalse(result['birth_metadata_proves_authenticated_unique_or_exec_generation'])
        self.assertFalse(result['physical_Framebuffer_binding_proven'])
        self.assertFalse(result['original_swap_call_status_observed'])
        self.assertFalse(result['object_lifetimes_pinned'])
        self.assertTrue(all(task.read_counts[address] >= 2 for address in task.gate_addresses))
        self.assertEqual(result['read_calls'], len(task.reads))
        self.assertEqual(result['requested_read_bytes'], sum(size for _, size in task.reads))

    def test_pre_task_refusal_does_not_acquire_or_deallocate(self):
        task = MockTask(); task.fail = 'path'
        with self.assertRaises(reader.Refused): task.observe()
        self.assertEqual((task.acquire_calls, task.release_calls, len(task.reads)), (0, 0, 0))

    def test_valid_image_path_at_page_edge_does_not_overread(self):
        task = MockTask()
        raw = bytearray(task.lookup(task.array, 4 * 24))
        path = 0x120fe0
        struct.pack_into('<Q', raw, 8, path)
        task.replace(task.array, bytes(raw))
        name = b'/mock/WindowServer\0'
        task.put(path, name + bytes(32 - len(name)))
        result = task.observe()
        self.assertTrue(result['accepted_partial_registration_observation'])
        self.assertEqual([size for address, size in task.reads if address == path], [32])

    def test_task_access_refusal_has_no_memory_reads(self):
        task = MockTask(); task.fail = 'access'
        with self.assertRaises(reader.Refused): task.observe()
        self.assertEqual((task.acquire_calls, task.release_calls, len(task.reads)), (1, 0, 0))

    def test_process_birth_change_before_memory_releases_task(self):
        task = MockTask(); task.fail = 'generation'
        with self.assertRaisesRegex(reader.Refused, 'process birth metadata changed'): task.observe()
        self.assertEqual(task.generation_calls, 2)
        self.assertEqual((task.acquire_calls, task.release_calls, len(task.reads)), (1, 1, 0))

    def test_process_birth_change_at_final_check_refuses_acceptance(self):
        task = MockTask(); task.fail = 'generation_final'
        with self.assertRaisesRegex(reader.Refused, 'process birth metadata changed'): task.observe()
        self.assertEqual(task.generation_calls, 3)
        self.assertEqual((task.acquire_calls, task.release_calls), (1, 1))
        self.assertGreater(len(task.reads), 0)

    def test_short_or_errno_birth_result_refuses_before_task_access(self):
        for reason in ('generation_result', 'generation_errno'):
            with self.subTest(reason=reason):
                task = MockTask(); task.fail = reason
                with self.assertRaisesRegex(reader.Refused, 'complete successful process birth metadata'): task.observe()
                self.assertEqual(task.generation_calls, 1)
                self.assertEqual((task.acquire_calls, task.release_calls, len(task.reads)), (0, 0, 0))

    def test_short_or_errno_birth_result_after_access_releases_before_memory(self):
        for reason in ('generation_result_after', 'generation_errno_after'):
            with self.subTest(reason=reason):
                task = MockTask(); task.fail = reason
                with self.assertRaisesRegex(reader.Refused, 'complete successful process birth metadata'): task.observe()
                self.assertEqual(task.generation_calls, 2)
                self.assertEqual((task.acquire_calls, task.release_calls, len(task.reads)), (1, 1, 0))

    def test_every_after_acquisition_refusal_releases_task(self):
        for reason in ('task', 'boot', 'gate', 'gate_repeat', 'dyld', 'regs', 'handle', 'read', 'unmapped_path'):
            with self.subTest(reason=reason):
                task = MockTask(); task.fail = reason
                with self.assertRaises(reader.Refused): task.observe()
                self.assertEqual(task.release_calls, 1)

    def test_task_release_failure_refuses_acceptance(self):
        task = MockTask(); task.fail = 'release'
        with self.assertRaisesRegex(reader.Refused, 'task right release failed'): task.observe()
        self.assertEqual(task.release_calls, 1)

    def test_registration_count_over_cap_releases_task(self):
        task = MockTask(); task.replace(task.count_address, struct.pack('<I', 9))
        with self.assertRaises(reader.Refused): task.observe()
        self.assertEqual(task.release_calls, 1)

    def test_callback_wrong_low_entry_refuses(self):
        task = MockTask(); task.replace(task.regs_address, struct.pack('<QIIQQQ', task.framebuffer, task.client, 0,
                                                                  task.callback + 4, task.context, 0))
        with self.assertRaises(reader.Refused): task.observe()
        self.assertEqual(task.release_calls, 1)

    def test_callback_high_PAC_bits_are_not_authentication(self):
        task = MockTask(); task.replace(task.regs_address, struct.pack('<QIIQQQ', task.framebuffer, task.client, 0,
                                                                  task.callback | (1 << 63), task.context, 0))
        result = task.observe()
        self.assertFalse(result['registrations_private'][0]['callback_PAC_authentication_performed'])

    def test_mismatched_registered_connection_refuses(self):
        task = MockTask(); task.replace(task.framebuffer + 0x10, struct.pack('<II', 111, task.client + 1))
        with self.assertRaises(reader.Refused): task.observe()
        self.assertEqual(task.release_calls, 1)

    def test_read_budget_failure_releases_task(self):
        task = MockTask()
        with patch.object(reader, 'MAX_READ_CALLS', 1):
            with self.assertRaises(reader.Refused): task.observe()
        self.assertEqual(task.release_calls, 1)

    def test_real_profile_hash_verified_before_mock_run(self):
        self.assertTrue(reader.verify_profile(PROFILE.read_bytes())['prepared_only'])


if __name__ == '__main__': unittest.main()
