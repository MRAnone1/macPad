"""Synthetic file controls: no SSH, framework loading or native API calls."""
import copy
import struct
import unittest
import uuid

import macos_cache_framework_inventory as inventory


class Fixture:
    CACHE_UUID = '11111111-2222-3333-4444-555555555555'
    IMAGE_UUID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
    PATH = '/System/Library/Frameworks/Metal.framework/Metal'

    def __init__(self):
        self.raw = bytearray(0xa000)
        self.raw[:16] = b'dyld_v1  arm64e'.ljust(16, b'\0')
        struct.pack_into('<II', self.raw, 16, 0x270, 1)
        struct.pack_into('<QQQII', self.raw, 0x270, 0x180000000, len(self.raw), 0, 5, 5)
        self.raw[88:104] = uuid.UUID(self.CACHE_UUID).bytes
        struct.pack_into('<II', self.raw, 0x1c0, 0x1200, 1)
        struct.pack_into('<QQ', self.raw, 136, 0x1240, 1)
        struct.pack_into('<QQQII', self.raw, 0x1200, 0x180002000, 0, 0, 0x1800, 0)
        self.raw[0x1240:0x1250] = uuid.UUID(self.IMAGE_UUID).bytes
        struct.pack_into('<QII', self.raw, 0x1250, 0x180002000, 0x4000, 0x1800)
        path = self.PATH.encode() + b'\0'
        self.raw[0x1800:0x1800 + len(path)] = path
        struct.pack_into('<8I', self.raw, 0x2000, 0xfeedfacf, 0x100000c, 2, 6, 1, 24, 0, 0)
        struct.pack_into('<II', self.raw, 0x2020, 0x1b, 24)
        self.raw[0x2028:0x2038] = uuid.UUID(self.IMAGE_UUID).bytes
        self.config = {'name': 'synthetic', 'directory': '/fake', 'main_uuid': self.CACHE_UUID,
                       'roles': {'Metal': {'paths': (self.PATH,), 'uuid': self.IMAGE_UUID}}}
        self.size = len(self.raw)
        self.before = (1, 2, self.size, 3, 4)
        self.closed = 0
        self.reads = []
        self.drift = False
        self.short = False

    def names(self, directory):
        return [inventory.MAIN]

    def open(self, directory, name):
        return self

    def read_at(self, offset, length):
        self.reads.append((offset, length))
        value = bytes(self.raw[offset:offset + length])
        if self.short:
            return value[:-1]
        if self.drift and offset == 0x2000 and self.reads.count((offset, length)) > 1:
            return bytes([value[0] ^ 1]) + value[1:]
        return value

    def token(self):
        return self.before

    def close(self):
        self.closed += 1

    def observe(self, **budget):
        return inventory.inventory_namespace(self.config, self, inventory.Budget(**budget))


class Controls(unittest.TestCase):
    def test_unselected_backup_is_not_opened_as_a_subcache(self):
        f = Fixture()
        f.names = lambda directory: [inventory.MAIN, inventory.MAIN + '.backup']
        opened = []
        def selected(directory, name):
            opened.append(name)
            self.assertEqual(name, inventory.MAIN)
            return f
        f.open = selected
        result = f.observe()
        self.assertTrue(result['accepted_known_filesystem_identities'])
        self.assertEqual(opened, [inventory.MAIN])
        self.assertEqual(result['unselected_cache_prefix_files_private'], [inventory.MAIN + '.backup'])

    def test_declared_missing_subcache_refuses(self):
        f = Fixture()
        struct.pack_into('<II', f.raw, 392, 0x1300, 1)
        f.raw[0x1300:0x1310] = uuid.UUID(f.IMAGE_UUID).bytes
        f.raw[0x1318:0x131c] = b'.01\0'
        result = f.observe()
        self.assertFalse(result['accepted_known_filesystem_identities'])
        self.assertIn('declared subcache file missing', result['errors'][0]['reason'])
        self.assertEqual(f.closed, 1)

    def test_complete_large_header_is_read_and_hashed(self):
        f = Fixture()
        struct.pack_into('<II', f.raw, 0x2010, 2, 20000)
        struct.pack_into('<II', f.raw, 0x2038, 0x19, 19976)
        result = f.observe()
        self.assertTrue(result['accepted_known_filesystem_identities'])
        self.assertEqual(result['images'][0]['header_range_bytes'], 20032)
        self.assertEqual(f.reads.count((0x2000, 20032)), 2)

    def test_header_over_cap_is_not_read(self):
        f = Fixture()
        struct.pack_into('<I', f.raw, 0x2014, 65536)
        result = f.observe()
        self.assertFalse(result['accepted_known_filesystem_identities'])
        self.assertIn('load-command bound', result['errors'][0]['reason'])
        self.assertFalse(any(size > 65536 for _, size in f.reads))

    def test_exact_headers_are_repeated_and_closed(self):
        f = Fixture()
        result = f.observe()
        self.assertIs(result['accepted_known_filesystem_identities'], True)
        self.assertEqual(result['images'][0]['UUID'], f.IMAGE_UUID)
        self.assertEqual(f.reads.count((0x2000, 56)), 2)
        self.assertEqual(f.closed, 1)

    def test_subcache_header_may_have_no_image_tables(self):
        f = Fixture()
        raw = bytearray(f.raw[:4096])
        struct.pack_into('<II', raw, 0x1c0, 0, 0)
        struct.pack_into('<QQ', raw, 136, 0, 0)
        result = inventory.parse_cache_header(bytes(raw), f.size)
        self.assertEqual(result['image_count'], 0)

    def test_main_without_tables_refuses_and_closes(self):
        f = Fixture()
        struct.pack_into('<II', f.raw, 0x1c0, 0, 0)
        self.assertFalse(f.observe()['accepted_known_filesystem_identities'])
        self.assertEqual(f.closed, 1)

    def test_unknown_uuid_cannot_qualify(self):
        f = Fixture()
        f.config['roles']['Metal']['uuid'] = f.CACHE_UUID
        result = f.observe()
        self.assertFalse(result['accepted_known_filesystem_identities'])
        self.assertIn('unknown selected image UUID', result['errors'][0]['reason'])
        self.assertEqual(f.closed, 1)

    def test_changed_image_header_refuses(self):
        f = Fixture()
        f.drift = True
        result = f.observe()
        self.assertFalse(result['accepted_known_filesystem_identities'])
        self.assertIn('header changed', result['errors'][0]['reason'])
        self.assertEqual(f.closed, 1)

    def test_short_read_refuses_and_closes(self):
        f = Fixture()
        f.short = True
        self.assertFalse(f.observe()['accepted_known_filesystem_identities'])
        self.assertEqual(f.closed, 1)

    def test_budget_is_charged_before_read(self):
        f = Fixture()
        result = f.observe(max_calls=1)
        self.assertFalse(result['accepted_known_filesystem_identities'])
        self.assertEqual(len(f.reads), 1)
        self.assertEqual(f.closed, 1)

    def test_duplicate_image_path_refuses(self):
        f = Fixture()
        struct.pack_into('<I', f.raw, 0x1c4, 2)
        f.raw[0x1220:0x1240] = f.raw[0x1200:0x1220]
        result = f.observe()
        self.assertFalse(result['accepted_known_filesystem_identities'])
        self.assertIn('ambiguous selected image', result['errors'][0]['reason'])

    def test_image_text_uuid_disagreement_refuses(self):
        f = Fixture()
        f.raw[0x1240:0x1250] = uuid.UUID(f.CACHE_UUID).bytes
        result = f.observe()
        self.assertFalse(result['accepted_known_filesystem_identities'])
        self.assertIn('UUID tables differ', result['errors'][0]['reason'])

    def test_deadline_does_not_skip_close(self):
        f = Fixture()
        now = [0.0]
        original = f.read_at
        def delayed(offset, length):
            now[0] = 20.0
            return original(offset, length)
        f.read_at = delayed
        result = f.observe(clock=lambda: now[0])
        self.assertFalse(result['accepted_known_filesystem_identities'])
        self.assertIn('deadline', result['errors'][0]['reason'])
        self.assertEqual(f.closed, 1)


if __name__ == '__main__':
    unittest.main()
