"""Finite read-only task observer for one exact existing WindowServer.

No process launch/debug admission/injection, private callback or GPU operation.
The result is private partial registration evidence, never physical attribution.
"""
import ctypes
import hashlib
import json
from pathlib import Path
import signal
import struct
import time
import uuid

EXPECTED_PATH = '/private/var/mnt/rootfs/usr/local/libexec/macws-windowserver-preflight-20261007/SkyLight.framework/Resources/WindowServer'
EXPECTED_EXE_SHA = 'b8386dbd24ceedb70fc82eab9c74a315e83d19131282522a3fc55ca2a69be416'
EXPECTED_PROFILE_SHA = '68f10434bf8f903c243b742b814e634919232812ec7181b0ed0f7762ce88d8bf'
MAX_READ_CALLS = 2048
MAX_READ_BYTES = 2 * 1024 * 1024
MAX_ONE_READ = 1024
USER_END = 1 << 39

class Refused(ValueError):
    pass

def require(ok, reason):
    if not ok:
        raise Refused(reason)

def extent(address, size):
    require(type(address) is int and type(size) is int and 0 < address < USER_END and
            0 < size <= 65536 and address + size <= USER_END, 'user address extent')

class BudgetReader:
    def __init__(self, callback, deadline, clock=time.monotonic):
        self.callback, self.deadline, self.clock = callback, deadline, clock
        self.calls = self.bytes = 0
    def read(self, address, size):
        extent(address, size)
        result = bytearray()
        while len(result) < size:
            chunk = min(MAX_ONE_READ, size - len(result))
            require(self.clock() <= self.deadline, 'read deadline')
            require(self.calls < MAX_READ_CALLS and self.bytes + chunk <= MAX_READ_BYTES, 'read budget')
            self.calls += 1
            self.bytes += chunk
            data = self.callback(address + len(result), chunk)
            require(type(data) is bytes and len(data) == chunk, 'short or malformed task read')
            result.extend(data)
        return bytes(result)

def bounded_image_path(reader, address):
    """Stop at NUL without crossing a 4-KiB boundary in one read.

    4 KiB divides the verified platform's VM pages. Splitting reads avoids
    demanding the next page merely because a terminated path is near its end.
    A mapping/permission failure remains a conservative refusal.
    """
    result = bytearray()
    while len(result) < 384:
        where = address + len(result)
        size = min(64, 384 - len(result), 4096 - where % 4096)
        data = reader.read(where, size)
        if b'\0' in data:
            result.extend(data[:data.index(0)])
            return bytes(result).decode('utf-8')
        result.extend(data)
    raise Refused('image path bound')

def parse_header(raw):
    require(type(raw) is bytes and len(raw) >= 40, 'short or mutable Mach-O header')
    magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack_from('<8I', raw)
    require(magic == 0xfeedfacf and cpu == 0x100000c and 0 < count <= 512 and count*8 <= size <= 32768 and 32 + size <= len(raw), 'Mach-O shape')
    at = 32
    identity = None
    for _ in range(count):
        cmd, length = struct.unpack_from('<II', raw, at)
        require(length >= 8 and length % 4 == 0 and at + length <= 32 + size, 'load command extent')
        if cmd == 0x1b:
            require(length == 24 and identity is None, 'UUID command shape')
            identity = str(uuid.UUID(bytes=raw[at+8:at+24]))
        at += length
    require(at == 32 + size and identity is not None, 'missing UUID or command bytes')
    return identity

def executable_UUID(raw):
    require(len(raw) >= 32, 'short executable file')
    magic = struct.unpack_from('>I', raw)[0]
    if magic in (0xcafebabe, 0xcafebabf):
        count = struct.unpack_from('>I', raw, 4)[0]
        require(0 < count <= 16, 'fat executable count')
        candidates = []
        for index in range(count):
            if magic == 0xcafebabe:
                at = 8 + index*20
                require(at+20 <= len(raw), 'fat header extent')
                cpu, subtype, start, size, align = struct.unpack_from('>5I', raw, at)
            else:
                at = 8 + index*32
                require(at+32 <= len(raw), 'fat64 header extent')
                cpu, subtype, start, size, align, reserved = struct.unpack_from('>IIQQII', raw, at)
            if cpu == 0x100000c:
                require(start+size <= len(raw) and size >= 32, 'fat slice extent')
                candidates.append(raw[start:start+size])
        require(len(candidates) == 1, 'ambiguous executable arm64 slice')
        return parse_header(candidates[0])
    return parse_header(raw)

def parse_registrations(raw, count):
    require(type(count) is int and 0 <= count <= 8 and len(raw) == count * 40, 'registration extent')
    rows = []
    for index in range(count):
        framebuffer, client, pad, callback, context, last = struct.unpack_from('<QIIQQQ', raw, index*40)
        require(framebuffer and client and callback and context, 'incomplete active registration')
        extent(framebuffer, 8)
        rows.append({'slot': index, 'framebuffer_private': framebuffer, 'client_name_private': client,
                     'callback_private': callback, 'context_private': context, 'last_clock_private': last})
    require(len({x['framebuffer_private'] for x in rows}) == count, 'aliased active registrations')
    return rows

def verify_profile(raw):
    require(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == EXPECTED_PROFILE_SHA, 'exact prepared profile hash')
    profile = json.loads(raw)
    require(profile['prepared_only'] and not profile['device_execution_performed'] and
            profile['registration_slots'] == 8 and profile['registration_stride_bytes'] == 40, 'profile scope')
    require(profile['macOS_QuartzCore_UUID'] == 'cf853bbd-01b6-3f46-ada1-ec70fd2dc9dc' and
            profile['macOS_framebuffer_UUID'] == '9485c742-b91f-3c6c-897c-ab2c8acf7625', 'framework ABI roles')
    require(len(profile['profiles']) == 2, 'candidate pair')
    return profile

def parse_process_start_info(raw, pid):
    """Exact 20E252 proc_bsdinfo birth metadata, not an exec/unique token."""
    require(type(pid) is int and 0 < pid < 0x7fffffff and type(raw) is bytes and len(raw) == 136, 'process birth metadata shape')
    observed = struct.unpack_from('<I', raw, 12)[0]
    seconds, microseconds = struct.unpack_from('<QQ', raw, 120)
    require(observed == pid and 0 < seconds < (1 << 63) and 0 <= microseconds < 1000000, 'process birth metadata fields')
    return seconds, microseconds

def process_start_token(proc, pid):
    query = proc.proc_pidinfo
    query.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    query.restype = ctypes.c_int
    raw = ctypes.create_string_buffer(136)
    ctypes.set_errno(0)
    returned = query(pid, 3, 0, raw, 136)
    error = ctypes.get_errno()
    require(returned == 136 and error == 0, 'complete successful process birth metadata')
    return parse_process_start_info(bytes(raw), pid)

def run(pid, profile_raw, *, port_observer=None):
    profile = verify_profile(profile_raw)
    require(port_observer is None or callable(port_observer), 'port observer callback shape')
    require(type(pid) is int and pid > 1, 'target PID')
    library = ctypes.CDLL(None)
    proc = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    proc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    proc.proc_pidpath.restype = ctypes.c_int
    def path_now():
        data = ctypes.create_string_buffer(4096)
        length = proc.proc_pidpath(pid, data, len(data))
        require(0 < length < len(data), 'target process path unavailable')
        return data.value.decode('utf-8')
    # Refuse before acquiring task rights or reading task memory.
    require(path_now() == EXPECTED_PATH, 'target path mismatch')
    with Path(EXPECTED_PATH).open('rb') as handle:
        binary = handle.read(1024*1024+1)
    require(len(binary) <= 1024*1024 and hashlib.sha256(binary).hexdigest() == EXPECTED_EXE_SHA, 'target executable file digest')
    exe_uuid = executable_UUID(binary)
    query = library.sysctlbyname
    query.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
    query.restype = ctypes.c_int
    def metadata(name):
        data = ctypes.create_string_buffer(128); size = ctypes.c_size_t(128)
        require(query(name.encode(), data, ctypes.byref(size), None, 0) == 0 and 0 < size.value <= 128, 'metadata query')
        return bytes(data)[:size.value].rstrip(b'\0').decode('ascii')
    require(metadata('hw.machine') == 'iPad13,6' and metadata('kern.osversion') == '20E252' and
            metadata('kern.uuid').lower() == 'd6b9e234-64f1-30ea-ae62-ed8f2dc6efdb', 'device identity')
    session = metadata('kern.bootsessionuuid')
    require(str(uuid.UUID(session)).lower() == session.lower(), 'boot-session UUID shape')
    birth_metadata_calls = 0
    def current_birth_token():
        nonlocal birth_metadata_calls
        birth_metadata_calls += 1
        return process_start_token(proc, pid)
    start_token = current_birth_token()
    task_self = ctypes.c_uint32.in_dll(library, 'mach_task_self_').value
    task = ctypes.c_uint32()
    library.task_for_pid.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.POINTER(ctypes.c_uint32)]
    library.task_for_pid.restype = ctypes.c_int
    require(library.task_for_pid(task_self, pid, ctypes.byref(task)) == 0 and task.value != 0, 'task access refused')
    library.mach_port_deallocate.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    library.mach_port_deallocate.restype = ctypes.c_int
    try:
        library.pid_for_task.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_int)]
        library.pid_for_task.restype = ctypes.c_int
        def same_task():
            observed = ctypes.c_int()
            require(library.pid_for_task(task.value, ctypes.byref(observed)) == 0 and observed.value == pid, 'held task identity')
            require(current_birth_token() == start_token, 'process birth metadata changed')
        same_task()
        library.vm_read_overwrite.argtypes = [ctypes.c_uint32, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        library.vm_read_overwrite.restype = ctypes.c_int
        def raw_read(address, size):
            data = ctypes.create_string_buffer(size); returned = ctypes.c_size_t()
            require(library.vm_read_overwrite(task.value, address, size, ctypes.addressof(data), ctypes.byref(returned)) == 0 and returned.value == size, 'task read refused')
            return bytes(data)
        reader = BudgetReader(raw_read, time.monotonic()+5)
        library.task_info.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        library.task_info.restype = ctypes.c_int
        def dyld_info():
            info = (ctypes.c_uint32*5)(); count = ctypes.c_uint32(5)
            require(library.task_info(task.value, 17, info, ctypes.byref(count)) == 0 and count.value == 5, 'task dyld info')
            address, size, fmt = struct.unpack('<QQi', bytes(info))
            require(fmt == 1 and 16 <= size <= 65536, '64-bit dyld info format')
            return address, size, fmt
        dyld_before = dyld_info(); header = reader.read(dyld_before[0], 16)
        version, count, array = struct.unpack('<IIQ', header)
        require(version >= 1 and 0 < count <= 1024 and array != 0, 'dyld image array')
        image_bytes = reader.read(array, count*24)
        candidates = {x['image_basename']: x for x in profile['profiles']}
        expected = {**{k:v['UUID'] for k,v in candidates.items()}, 'WindowServer':exe_uuid, 'QuartzCore':profile['macOS_QuartzCore_UUID'], 'IOMobileFramebuffer':profile['macOS_framebuffer_UUID']}
        images = {}
        for offset in range(0, len(image_bytes), 24):
            base, path, modified = struct.unpack_from('<QQQ', image_bytes, offset)
            basename = bounded_image_path(reader, path).rsplit('/',1)[-1]
            if basename not in expected:
                continue
            mh = reader.read(base, 32); cmd_bytes = struct.unpack_from('<I', mh, 20)[0]
            require(cmd_bytes <= 32768, 'image command bound')
            full = reader.read(base, 32+cmd_bytes); identity = parse_header(full)
            if identity != expected[basename]:
                continue # Same basename can belong to a native image; never reuse its ABI.
            require(basename not in images, 'duplicate matching image')
            images[basename] = {'base_private':base, 'UUID':identity, 'header_private':full}
        require('WindowServer' in images and 'QuartzCore' in images and 'IOMobileFramebuffer' in images, 'target executable or macOS framework images absent')
        repeats = []
        for framework, gates in profile['original_framework_windows'].items():
            base = images[framework]['base_private']
            for gate in gates:
                where = base + int(gate['image_offset'], 16)
                observed = reader.read(where, gate['bytes'])
                require(hashlib.sha256(observed).hexdigest() == gate['sha256'], 'original framework window changed')
                repeats.append((where, observed))
        records = []
        for name, declared in candidates.items():
            if name not in images:
                continue
            base = images[name]['base_private']
            for gate in declared['compiled_code_windows']:
                where = base+int(gate['image_offset'],16); size=gate['bytes_to_next_distinct_text_symbol']
                first=reader.read(where,size);second=reader.read(where,size)
                require(first == second and hashlib.sha256(first).hexdigest() == gate['sha256'], 'candidate code window')
                repeats.append((where, first))
            count_address=base+int(declared['data_anchors']['_g_macws_iomfb_frame_reg_count']['image_offset'],16)
            regs_address=base+int(declared['data_anchors']['_g_macws_iomfb_frame_regs']['image_offset'],16)
            count_before=reader.read(count_address,4); n=struct.unpack('<I',count_before)[0]
            require(n<=8,'registration count')
            first=reader.read(regs_address,n*40) if n else b''
            second=reader.read(regs_address,n*40) if n else b''
            require(first==second and reader.read(count_address,4)==count_before,'registration list changed')
            repeats.append((count_address, count_before))
            if n: repeats.append((regs_address, first))
            for row in parse_registrations(first,n):
                fb=row['framebuffer_private']
                words=reader.read(fb+0x10,8);swap=reader.read(fb+0x68,4)
                require(reader.read(fb+0x10,8)==words and reader.read(fb+0x68,4)==swap,'framebuffer words changed')
                service,client=struct.unpack('<II',words)
                require(service!=0 and client==row['client_name_private'],'own-task handle client differs from registration')
                row.update(image_basename=name,service_name_private=service,active_swap_ID_private=struct.unpack('<I',swap)[0],
                           service_and_connection_are_names_in_producer_task_only=True,
                           original_SwapBegin_or_Cancel_status_observed=False,client_provider_registry_identity_observed=False)
                repeats.extend([(fb+0x10, words), (fb+0x68, swap)])
                context = row['context_private']
                display_word = reader.read(context+0x58, 8)
                display = struct.unpack('<Q', display_word)[0]
                framebuffer_word = reader.read(display+0x300, 8)
                enabled_word = reader.read(display+0x9a4, 8)
                require(struct.unpack('<Q', framebuffer_word)[0] == fb and struct.unpack('<Q', enabled_word)[0] & (1 << 35), 'registered context/display framebuffer or enabled flag differs')
                callback_low = row['callback_private'] & ((1 << 39)-1)
                require(callback_low == images['QuartzCore']['base_private']+0x29209c, 'callback low address differs from original entry')
                row.update(context_display_framebuffer_chain_repeated_equal=True, callback_low_address_matches_original_entry=True, callback_PAC_authentication_performed=False)
                repeats.extend([(context+0x58, display_word), (display+0x300, framebuffer_word), (display+0x9a4, enabled_word)])
                records.append(row)
        require(any(name in images for name in candidates),'exact candidate images absent')
        port_observations = None
        if port_observer is not None:
            def recheck_registered_task():
                same_task()
                require(path_now() == EXPECTED_PATH and metadata('kern.bootsessionuuid') == session,
                        'target or boot session changed around descriptions')
                for where, data in repeats:
                    require(reader.read(where, len(data)) == data,
                            'registered bytes changed around descriptions')
                return True
            require(records, 'no registrations for description observer')
            port_pairs = [{'service_name_private': row['service_name_private'],
                           'client_name_private': row['client_name_private']} for row in records]
            port_observations = port_observer(library, task.value, port_pairs, reader.deadline,
                                               recheck_registered_task)
            require(port_pairs == [{'service_name_private': row['service_name_private'],
                                    'client_name_private': row['client_name_private']} for row in records],
                    'port observer changed handle inputs')
            require(type(port_observations) is dict and
                    port_observations.get('accepted_repeated_registry_object_descriptions') is True,
                    'port description observer refused')
        require(reader.read(array,count*24)==image_bytes and reader.read(dyld_before[0],16)==header and dyld_info()==dyld_before,'dyld snapshot changed')
        for image in images.values():require(reader.read(image['base_private'],len(image['header_private']))==image['header_private'],'image header changed')
        for where, data in repeats: require(reader.read(where, len(data)) == data, 'retained code or registration words changed')
        same_task()
        require(path_now()==EXPECTED_PATH and metadata('kern.bootsessionuuid')==session,'target or boot session changed')
        result = {'accepted_partial_registration_observation':True,'scope':'held producer task and repeated registered handle words; no physical attribution',
                'target_pid_private':pid,'boot_session_UUID_private':session,'profile_sha256':EXPECTED_PROFILE_SHA,
                'process_start_token_private':start_token,'process_birth_metadata_calls':birth_metadata_calls,
                'same_process_birth_metadata_repeated_equal':True,'birth_metadata_proves_authenticated_unique_or_exec_generation':False,
                'matched_images_private':{name:{'base_private':item['base_private'],'UUID':item['UUID']} for name,item in images.items()},
                'registrations_private':records,'registration_observations':len(records),'read_calls':reader.calls,'requested_read_bytes':reader.bytes,
                'max_read_calls':MAX_READ_CALLS,'max_requested_read_bytes':MAX_READ_BYTES,'read_deadline_seconds':5,
                'held_task_identity_repeated_equal':True,'loaded_executable_UUID_matches_selected_file':True,'entire_executable_loaded_bytes_verified':False,'same_task_namespace_for_handle_names':True,
                'object_lifetimes_pinned':False,'atomic_snapshot_proven':False,'physical_Framebuffer_binding_proven':False,
                'original_swap_call_status_observed':False,'new_GPU_workloads':0,'process_debug_admission_calls':0,
                'process_suspend_or_injection_calls':0,'explicit_memory_write_calls':0}
        if port_observations is not None:
            result['port_descriptions_private'] = port_observations
        return result
    finally:
        require(library.mach_port_deallocate(task_self,task.value)==0,'task right release failed')

if __name__ == '__main__':
    import sys
    signal.alarm(10)
    try:
        require(len(sys.argv)==3,'usage: observer PID exact-private-profile.json')
        with Path(sys.argv[2]).open('rb') as handle: data=handle.read(65537)
        result=run(int(sys.argv[1]),data)
        print(json.dumps(result))
    except (Refused,OSError,ValueError,KeyError,AttributeError,struct.error,ctypes.ArgumentError) as error:
        print(json.dumps({'accepted_partial_registration_observation':False,'reason':str(error),'physical_Framebuffer_binding_proven':False,'new_GPU_workloads':0}))
        raise SystemExit(1)
