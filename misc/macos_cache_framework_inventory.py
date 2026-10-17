"""Finite filesystem-only cache identities; execute the exact source via stdin.

No import-time I/O or native calls. Header-range SHA values are not whole-image
digests, loaded-image observations, code-page validation or port acceptance.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import struct
import time
import uuid

HEADER_BYTES = 4096
IMAGE_HEADER_BYTES = 16384
MAX_FILES = 64
MAX_IMAGES = 8192
MAX_PATH_SLAB_BYTES = 2 * 1024 * 1024
MAX_READ_CALLS = 256
MAX_READ_BYTES = 8 * 1024 * 1024
READ_DEADLINE_SECONDS = 8
ALARM_SECONDS = 12
MAIN = 'dyld_shared_cache_arm64e'


class Refused(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical_uuid(data):
    need(type(data) is bytes and len(data) == 16 and any(data), 'UUID extent/value')
    return str(uuid.UUID(bytes=data))


class Budget:
    def __init__(self, *, clock=time.monotonic, seconds=READ_DEADLINE_SECONDS,
                 max_calls=MAX_READ_CALLS, max_bytes=MAX_READ_BYTES):
        need(type(seconds) in (int, float) and 0 < seconds <= READ_DEADLINE_SECONDS,
             'deadline configuration')
        need(type(max_calls) is int and 0 < max_calls <= MAX_READ_CALLS and
             type(max_bytes) is int and 0 < max_bytes <= MAX_READ_BYTES, 'budget configuration')
        self.clock = clock
        self.started = clock()
        self.deadline = self.started + seconds
        self.max_calls, self.max_bytes = max_calls, max_bytes
        self.calls = self.requested = self.returned = 0

    def check(self):
        need(self.clock() < self.deadline, 'read deadline')

    def read(self, source, offset, length):
        self.check()
        need(type(offset) is int and type(length) is int and offset >= 0 and
             0 < length <= MAX_PATH_SLAB_BYTES and offset + length <= source.size,
             'file range extent')
        need(self.calls < self.max_calls and self.requested + length <= self.max_bytes,
             'read budget')
        self.calls += 1
        self.requested += length
        raw = source.read_at(offset, length)
        need(type(raw) is bytes, 'file read type')
        self.returned += len(raw)
        self.check()
        need(len(raw) == length, 'short file read')
        return raw

    def receipt(self):
        return {'read_calls': self.calls, 'requested_file_bytes': self.requested,
                'returned_file_bytes': self.returned, 'max_read_calls': self.max_calls,
                'max_requested_file_bytes': self.max_bytes,
                'read_deadline_seconds': READ_DEADLINE_SECONDS}


class FileSource:
    def __init__(self, path):
        self.path = Path(path)
        initial = self.path.lstat()
        need(stat.S_ISREG(initial.st_mode), 'cache path is not a regular non-symlink file')
        self.handle = None
        try:
            fd = os.open(str(self.path), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            self.handle = os.fdopen(fd, 'rb')
            self.before = self.token()
            self.size = self.before[2]
            need(self.size >= HEADER_BYTES, 'cache file too short')
        except BaseException:
            self.close()
            raise

    def token(self):
        held = os.fstat(self.handle.fileno())
        current = self.path.lstat()
        need(stat.S_ISREG(held.st_mode) and stat.S_ISREG(current.st_mode), 'cache file kind changed')
        token = lambda value: (value.st_dev, value.st_ino, value.st_size,
                               value.st_mtime_ns, value.st_ctime_ns)
        need(token(held) == token(current), 'held cache file/path identity differs')
        return token(held)

    def read_at(self, offset, length):
        self.handle.seek(offset)
        return self.handle.read(length)

    def close(self):
        if self.handle is not None:
            self.handle.close()
            self.handle = None


class FileStore:
    def names(self, directory):
        names = []
        for path in Path(directory).iterdir():
            if not path.name.startswith(MAIN) or path.name.endswith('.symbols'):
                continue
            need(re.fullmatch(r'dyld_shared_cache_arm64e(?:\.[A-Za-z0-9_-]+)*', path.name),
                 'unsupported cache filename')
            names.append(path.name)
            need(len(names) <= MAX_FILES, 'cache file count cap')
        return sorted(names)

    def open(self, directory, name):
        return FileSource(Path(directory) / name)


def parse_cache_header(raw, file_size):
    need(type(raw) is bytes and len(raw) == HEADER_BYTES and
         raw[:16].rstrip(b'\0') == b'dyld_v1  arm64e', 'cache magic/header extent')
    offset, count = struct.unpack_from('<II', raw, 16)
    need(1 <= count <= 32 and offset >= 0x1d0 and offset + count * 32 <= len(raw),
         'cache mapping table bounds')
    maps = []
    for index in range(count):
        address, size, fileoff, maximum, initial = struct.unpack_from('<QQQII', raw, offset + 32 * index)
        need(size > 0 and address + size < (1 << 64) and fileoff + size <= file_size and
             initial & ~maximum == 0 and maximum & ~7 == 0, 'cache mapping extent/protection')
        maps.append((address, address + size, fileoff))
    image_offset, image_count = struct.unpack_from('<II', raw, 0x1c0)
    text_offset, text_count = struct.unpack_from('<QQ', raw, 136)
    sub_offset, sub_count = struct.unpack_from('<II', raw, 392)
    # Subcaches normally have no image tables. Only the main cache must carry
    # them; a zero count must never be promoted into a complete inventory.
    need(0 <= image_count <= MAX_IMAGES and 0 <= text_count <= MAX_IMAGES and
         (image_count == 0 or (image_offset >= 0x1d0 and
          image_offset + image_count * 32 <= file_size)) and
         (text_count == 0 or (text_offset >= 0x1d0 and
          text_offset + text_count * 32 <= file_size)), 'cache image table extent')
    need(0 <= sub_count < MAX_FILES and (sub_count == 0 or
         (sub_offset >= 0x1d0 and sub_offset + sub_count * 56 <= file_size)),
         'subcache table extent')
    return {'UUID': canonical_uuid(raw[88:104]), 'maps': maps,
            'image_offset': image_offset, 'image_count': image_count,
            'text_offset': text_offset, 'text_count': text_count,
            'sub_offset': sub_offset, 'sub_count': sub_count}


def parse_image_header(raw):
    need(type(raw) is bytes and 56 <= len(raw) <= 65536, 'image header range extent')
    magic, cpu, subtype, filetype, count, size, _, _ = struct.unpack_from('<8I', raw)
    need(magic == 0xfeedfacf and cpu == 0x100000c and subtype & 0xffffff in (0, 2) and
         filetype in (6, 8) and 0 < count <= 1024 and 8 * count <= size <= len(raw) - 32,
         'image Mach-O header/load-command extent')
    cursor, identities = 32, []
    for _ in range(count):
        need(cursor + 8 <= 32 + size, 'image load-command header extent')
        command, length = struct.unpack_from('<II', raw, cursor)
        need(length >= 8 and length % 8 == 0 and cursor + length <= 32 + size,
             'image load-command extent/alignment')
        if command == 0x1b:
            need(length == 24, 'image UUID command extent')
            identities.append(canonical_uuid(raw[cursor + 8:cursor + 24]))
        cursor += length
    need(cursor == 32 + size and len(identities) == 1, 'image unique UUID/complete commands')
    return {'UUID': identities[0], 'architecture': 'arm64e' if subtype & 0xffffff == 2 else 'arm64',
            'cpu_subtype': subtype, 'filetype': filetype, 'load_command_count': count,
            'complete_load_commands_within_hashed_range': True}


def inventory_namespace(config, store, budget):
    result = {'name': config['name'], 'scope': 'filesystem cache and image header ranges only',
              'cache_files_private': [], 'images': [], 'errors': [],
              'accepted_known_filesystem_identities': False,
              'runtime_loaded_images_verified': False, 'whole_framework_file_hashes_verified': False,
              'full_signed_code_pages_verified': False, 'atomic_snapshot_claimed': False}
    sources, parsed, originals = {}, {}, {}
    try:
        budget.check()
        names = store.names(config['directory'])
        need(MAIN in names and 1 <= len(names) <= MAX_FILES, 'main cache/count missing')
        def open_header(name):
            budget.check()
            source = store.open(config['directory'], name)
            sources[name] = source
            raw = budget.read(source, 0, HEADER_BYTES)
            header = parse_cache_header(raw, source.size)
            parsed[name], originals[name] = header, raw
            result['cache_files_private'].append({'name': name, 'bytes': source.size,
                'UUID': header['UUID'], 'header_range_offset': 0, 'header_range_bytes': HEADER_BYTES,
                'header_range_sha256': digest(raw), 'file_token_before_private': source.before})
        open_header(MAIN)
        main, header = sources[MAIN], parsed[MAIN]
        need(header['UUID'] == config['main_uuid'], 'unknown main cache UUID')
        need(header['image_count'] > 0 and header['text_count'] > 0,
             'main cache image tables missing')
        expected = {MAIN: header['UUID']}
        if header['sub_count']:
            table = budget.read(main, header['sub_offset'], header['sub_count'] * 56)
            for index in range(header['sub_count']):
                row = table[index * 56:(index + 1) * 56]
                suffix = row[24:56]
                need(b'\0' in suffix, 'unterminated subcache suffix')
                suffix = suffix.split(b'\0')[0].decode('ascii')
                need(re.fullmatch(r'\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*', suffix),
                     'unsupported subcache suffix')
                name = MAIN + suffix
                need(name not in expected, 'duplicate subcache suffix')
                expected[name] = canonical_uuid(row[:16])
        need(set(expected) <= set(names), 'declared subcache file missing')
        result['unselected_cache_prefix_files_private'] = sorted(set(names) - set(expected))
        for name in expected:
            if name != MAIN:
                open_header(name)
        need(set(expected) == set(sources), 'opened subcache set differs from main manifest')
        need(all(parsed[name]['UUID'] == value for name, value in expected.items()),
             'subcache UUID association differs')
        names = list(expected)
        result['main_and_subcache_UUID_association_verified'] = True
        maps = [(lo, hi, offset, name) for name in names for lo, hi, offset in parsed[name]['maps']]
        ordered = sorted(maps)
        need(all(a[1] <= b[0] for a, b in zip(ordered, ordered[1:])), 'overlapping cache mappings')
        image_table = budget.read(main, header['image_offset'], header['image_count'] * 32)
        text_table = budget.read(main, header['text_offset'], header['text_count'] * 32)
        entries, texts, path_offsets = [], {}, []
        for index in range(header['image_count']):
            address, _, _, pathoff, pad = struct.unpack_from('<QQQII', image_table, index * 32)
            need(pad == 0 and 0 < address < (1 << 64) and pathoff < main.size, 'image-info row')
            entries.append((address, pathoff))
            path_offsets.append(pathoff)
        for index in range(header['text_count']):
            row = text_table[index * 32:(index + 1) * 32]
            address, text_size, pathoff = struct.unpack_from('<QII', row, 16)
            need(address > 0 and text_size >= 32 and pathoff < main.size, 'image-text row')
            texts.setdefault(address, []).append((canonical_uuid(row[:16]), text_size, pathoff))
            path_offsets.append(pathoff)
        low, high = min(path_offsets), min(main.size, max(path_offsets) + 512)
        need(0 <= low < high and high - low <= MAX_PATH_SLAB_BYTES, 'image path slab cap')
        slab = budget.read(main, low, high - low)
        def path_string(offset):
            start = offset - low
            need(0 <= start < len(slab), 'image path offset')
            end = slab.find(b'\0', start, min(len(slab), start + 512))
            need(end >= start, 'unterminated image path')
            path = slab[start:end].decode('utf-8')
            need(path.startswith('/') and len(path) <= 511, 'image path syntax')
            return path
        by_path = {}
        for address, pathoff in entries:
            by_path.setdefault(path_string(pathoff), []).append((address, pathoff))
        result['image_info_count'] = header['image_count']
        result['image_text_count'] = header['text_count']
        for role, selection in config['roles'].items():
            budget.check()
            candidates = [(path, row) for path in selection['paths'] for row in by_path.get(path, [])]
            need(len(candidates) == 1, 'missing or ambiguous selected image: ' + role)
            path, (address, pathoff) = candidates[0]
            text_rows = texts.get(address, [])
            need(len(text_rows) == 1, 'missing or ambiguous selected image-text row: ' + role)
            text_uuid, text_size, text_pathoff = text_rows[0]
            need(path_string(text_pathoff) == path, 'selected image tables disagree on path: ' + role)
            matches = [m for m in maps if m[0] <= address and address + 32 <= m[1]]
            need(len(matches) == 1, 'selected image mapping missing or ambiguous: ' + role)
            lo, hi, fileoff, name = matches[0]
            offset = fileoff + address - lo
            mh = budget.read(sources[name], offset, 32)
            command_count, command_bytes = struct.unpack_from('<II', mh, 16)
            result['current_image_header_fields_private'] = dict(role=role,
                magic=struct.unpack_from('<I', mh)[0], cpu=struct.unpack_from('<I', mh, 4)[0],
                filetype=struct.unpack_from('<I', mh, 12)[0], commands=command_count,
                command_bytes=command_bytes)
            size = 32 + command_bytes
            need(56 <= size <= 65536 and address + size <= hi,
                 'selected complete Mach-O load-command bound: ' + role)
            first = budget.read(sources[name], offset, size)
            second = budget.read(sources[name], offset, size)
            need(first == second, 'selected image header changed: ' + role)
            image = parse_image_header(first)
            item = {'role': role, 'path': path, 'cache_file': name,
                    'image_base_unslid_private': address, 'header_file_offset_private': offset,
                    'header_range_bytes': len(first), 'header_range_sha256': digest(first),
                    'header_bytes_repeated_equal': True, 'image_text_table_UUID': text_uuid,
                    'text_segment_bytes': text_size, **image}
            item['header_and_image_text_UUID_equal'] = image['UUID'] == text_uuid
            item['matches_historical_selected_UUID'] = image['UUID'] == selection['uuid']
            result['images'].append(item)
            need(item['header_and_image_text_UUID_equal'], 'selected image UUID tables differ: ' + role)
            need(item['matches_historical_selected_UUID'], 'unknown selected image UUID: ' + role)
        for row in result['cache_files_private']:
            name = row['name']
            repeated = budget.read(sources[name], 0, HEADER_BYTES)
            need(repeated == originals[name], 'cache header changed')
            after = sources[name].token()
            need(after == sources[name].before, 'cache file metadata changed')
            row.update(header_bytes_repeated_equal=True, file_token_after_private=after,
                       file_metadata_repeated_equal=True)
        result['accepted_known_filesystem_identities'] = True
    except (Refused, OSError, UnicodeError, ValueError, struct.error) as error:
        result['errors'].append({'type': type(error).__name__, 'reason': str(error)[:256]})
    finally:
        for source in sources.values():
            source.close()
    return result


def role(paths, identity):
    return {'paths': tuple(paths), 'uuid': identity}


CONFIGS = (
    {'name': 'native_iPadOS',
     'directory': '/private/preboot/Cryptexes/OS/System/Library/Caches/com.apple.dyld',
     'main_uuid': 'ab5b4d24-48ca-35fd-8cfd-2b44e7310061',
     'roles': {
         'Metal': role(('/System/Library/Frameworks/Metal.framework/Metal',), 'fc81787c-3d56-358e-8215-8495d583f6d4'),
         'AGXMetal13_3': role(('/System/Library/Extensions/AGXMetal13_3.bundle/AGXMetal13_3',), 'e25d17ad-26a8-35d1-a400-8220edcd7d0c'),
         'QuartzCore': role(('/System/Library/Frameworks/QuartzCore.framework/QuartzCore',), '0ae8ceb8-0dd6-363f-951d-16aac60a0951'),
         'IOMobileFramebuffer': role(('/System/Library/PrivateFrameworks/IOMobileFramebuffer.framework/IOMobileFramebuffer',), 'd2cce008-351e-3781-8774-0ed863d941e7'),
         'IOGPU': role(('/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU',), '4a495b72-eeeb-3d74-a7b5-1088f0ea60d7'),
         'SpringBoard_framework': role(('/System/Library/PrivateFrameworks/SpringBoard.framework/SpringBoard',), '45ddeb5e-05b0-3bf3-bb8b-d78e6b95ebb3'),
     }},
    {'name': 'macOS_rootfs',
     'directory': '/private/var/mnt/rootfs/System/Cryptexes/OS/System/Library/dyld',
     'main_uuid': '7d9faa84-5c6b-3ef4-9379-faba64346673',
     'roles': {
         'Metal': role(('/System/Library/Frameworks/Metal.framework/Versions/A/Metal', '/System/Library/Frameworks/Metal.framework/Metal'), '2bab169c-42da-36e3-955a-f30b709ec2ad'),
         'AGXMetal13_3': role(('/System/Library/Extensions/AGXMetal13_3.bundle/Contents/MacOS/AGXMetal13_3',), '727c250e-554d-3921-a5b3-48dae6195b79'),
         'QuartzCore': role(('/System/Library/Frameworks/QuartzCore.framework/Versions/A/QuartzCore', '/System/Library/Frameworks/QuartzCore.framework/QuartzCore'), 'cf853bbd-01b6-3f46-ada1-ec70fd2dc9dc'),
         'IOMobileFramebuffer': role(('/System/Library/PrivateFrameworks/IOMobileFramebuffer.framework/Versions/A/IOMobileFramebuffer', '/System/Library/PrivateFrameworks/IOMobileFramebuffer.framework/IOMobileFramebuffer'), '9485c742-b91f-3c6c-897c-ab2c8acf7625'),
         'IOGPU': role(('/System/Library/PrivateFrameworks/IOGPU.framework/Versions/A/IOGPU', '/System/Library/PrivateFrameworks/IOGPU.framework/IOGPU'), 'ce2b5551-857f-3edd-9e4f-435215cc8c27'),
     }},
)


def standard_metadata(name):
    query = ctypes.CDLL(None).sysctlbyname
    query.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
    query.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(128)
    size = ctypes.c_size_t(128)
    need(query(name.encode(), buffer, ctypes.byref(size), None, 0) == 0 and 0 < size.value <= 128,
         'metadata query failed: ' + name)
    return bytes(buffer)[:size.value].rstrip(b'\0').decode('ascii')


def main():
    signal.alarm(ALARM_SECONDS)
    started = time.monotonic()
    result = {'schema': 3, 'epoch': time.time(), 'device_mutations': 0,
              'new_workloads': 0, 'framework_loads': 0, 'kernel_memory_reads': 0,
              'jailbreak_primitive_initializations': 0,
              'alarm_seconds': ALARM_SECONDS, 'port_status': 'unverified',
              'accepted_known_filesystem_identity_inventory': False,
              'runtime_loaded_images_verified': False, 'whole_framework_hashes_verified': False,
              'freeze_cause_proven': False, 'device_acceptance_claimed': False, 'namespaces': []}
    budget = Budget()
    try:
        boot = standard_metadata('kern.bootsessionuuid')
        need(str(uuid.UUID(boot)).lower() == boot.lower() and uuid.UUID(boot).int, 'boot UUID shape')
        result['boot_session_UUID_private'] = boot
        result['kernel_identity'] = {name: standard_metadata(name) for name in
                                     ('hw.machine', 'kern.osversion', 'kern.uuid')}
        result['namespaces'] = [inventory_namespace(config, FileStore(), budget) for config in CONFIGS]
        repeated = standard_metadata('kern.bootsessionuuid')
        result['boot_session_repeated_equal'] = boot == repeated
        need(result['boot_session_repeated_equal'], 'boot changed during inventory')
        result['accepted_known_filesystem_identity_inventory'] = all(
            row['accepted_known_filesystem_identities'] for row in result['namespaces'])
    except (Refused, OSError, ValueError, UnicodeError) as error:
        result['error'] = {'type': type(error).__name__, 'reason': str(error)[:256]}
    finally:
        result['bounds'] = budget.receipt()
        result['elapsed_seconds'] = time.monotonic() - started
        print(json.dumps(result))
        signal.alarm(0)


if __name__ == '__main__':
    main()
