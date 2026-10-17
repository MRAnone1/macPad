"""Finite passive swap-route observations using a caller-owned task reader.

No native calls, task acquisition, function invocation or writes. Address
classification strips to the verified platform's low 39 bits; it does not
authenticate PAC or establish that a function was called or is callable.
"""
import hashlib
import struct

USER_END = 1 << 39
MAX_REGISTRATIONS = 2
MAX_GUARDS = 32


class Refused(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def low_address(value):
    need(type(value) is int and 0 < value < (1 << 64), 'nonzero pointer word')
    address = value & (USER_END - 1)
    need(address > 0 and address % 4 == 0, 'aligned low user address')
    return address


def branch_target(address, raw):
    """Only an unconditional B or an in-range 64-bit LDR+BR/BRAAZ literal."""
    need(type(address) is int and 0 < address < USER_END and
         type(raw) is bytes and len(raw) == 64, 'dispatch entry extent')
    first, second = struct.unpack_from('<II', raw)
    if first & 0xfc000000 == 0x14000000:
        immediate = first & 0x3ffffff
        if immediate & (1 << 25):
            immediate -= 1 << 26
        target = address + immediate * 4
        need(0 < target < USER_END and target % 4 == 0, 'B target extent')
        return target, 'B-immediate'
    if first & 0xff000000 == 0x58000000:
        register = first & 31
        need(register < 31 and second in (0xd61f0000 | register << 5,
                                         0xd61f081f | register << 5),
             'literal branch register/opcode')
        immediate = first >> 5 & 0x7ffff
        if immediate & (1 << 18):
            immediate -= 1 << 19
        offset = immediate * 4
        need(8 <= offset <= len(raw) - 8 and offset % 8 == 0,
             'dispatch literal outside bounded entry')
        return low_address(struct.unpack_from('<Q', raw, offset)[0]), 'LDR-literal-branch'
    raise Refused('unclassified public dispatch instructions')


def observe_swap_routes(registrations, images, reader, profile, *, check_identity):
    """Return private observations and bytes to join the owner's final guards.

    The caller must retain the same task, use its shared deadline/budget and
    repeat returned guards before accepting its final task snapshot. Unknown
    identity, method target, branch shape or flag state refuses before any
    subsequent frame experiment. This observer cannot start such an experiment.
    """
    result = {'accepted_swap_dispatch_address_observation': False,
              'scope': 'repeated addresses, flag and code only',
              'PAC_authentication_performed': False, 'function_callability_proven': False,
              'original_swap_status_observed': False, 'freeze_cause_proven': False,
              'explicit_memory_writes': 0, 'GPU_selector_calls': 0,
              'observations_private': [], 'dispatch_private': None}
    guards = []
    try:
        need(type(profile) is dict and profile.get('prepared_only') is True and
             profile.get('device_calls') == 0, 'route profile scope')
        need(profile.get('framebuffer_UUID') == '9485c742-b91f-3c6c-897c-ab2c8acf7625' and
             profile.get('method_slots') == {'SwapBegin': 0x720, 'SwapEnd': 0x728, 'SwapCancel': 0x758} and
             profile.get('expected_method_targets') == {'SwapBegin': 0x4334, 'SwapEnd': 0x4400, 'SwapCancel': 0x4714} and
             profile.get('public_SwapEnd_offset') == 0x11cc and
             profile.get('public_entry_read_bytes') == 64, 'exact route profile ABI')
        need(type(registrations) is list and 0 < len(registrations) <= MAX_REGISTRATIONS and
             type(images) is dict and callable(check_identity), 'route inputs')
        need(check_identity() is True, 'route identity before')
        framework = images.get('IOMobileFramebuffer', {})
        need(framework.get('UUID') == profile['framebuffer_UUID'], 'route framework identity')
        framework_base = low_address(framework.get('base_private'))
        candidates = {row['image_basename']: row for row in profile['profiles']}
        need(len(candidates) == len(profile['profiles']) == 2, 'route candidate identities')

        def read(where, size):
            need(type(where) is int and type(size) is int and where > 0 and
                 0 < size <= 1024 and where + size <= USER_END, 'route read extent')
            need(len(guards) < MAX_GUARDS, 'route guard cap')
            raw = reader.read(where, size)
            need(type(raw) is bytes and len(raw) == size, 'route short read')
            guards.append((where, raw))
            return raw

        windows = profile['original_framework_windows']
        need(type(windows) is list and len(windows) == 5, 'route framework windows')
        for window in windows:
            raw = read(framework_base + window['image_offset'], window['bytes'])
            need(hashlib.sha256(raw).hexdigest() == window['sha256'],
                 'route original framework window changed: ' + window['role'])

        owners = {}
        seen = set()
        for row in registrations:
            name = row['image_basename']
            need(name in candidates and name in images, 'route registration owner absent')
            selected = candidates[name]
            need(images[name]['UUID'] == selected['UUID'], 'route candidate UUID')
            base = low_address(images[name]['base_private'])
            if name not in owners:
                where = base + selected['coexist_flag_offset']
                flag = struct.unpack('<I', read(where, 4))[0]
                trampoline_word = struct.unpack('<Q', read(base + selected['original_trampoline_slot_offset'], 8))[0]
                owners[name] = {'name': name, 'hook_entry_private': base + selected['hook_entry_offset'],
                                'coexist_flag': flag, 'original_trampoline_private': trampoline_word}
            owner = owners[name]
            framebuffer = low_address(row['framebuffer_private'])
            need(framebuffer not in seen, 'duplicate route framebuffer')
            seen.add(framebuffer)
            methods = {}
            for role, offset in profile['method_slots'].items():
                word = struct.unpack('<Q', read(framebuffer + offset, 8))[0]
                methods[role] = {'word_private': word, 'low_address_private': low_address(word),
                                 'matches_expected_low_address': low_address(word) ==
                                 framework_base + profile['expected_method_targets'][role]}
            observed = {'owner': name, 'framebuffer_private': framebuffer,
                        'coexist_flag': owner['coexist_flag'], 'method_targets_private': methods}
            result['observations_private'].append(observed)
            need(all(item['matches_expected_low_address'] for item in methods.values()),
                 'unclassified framebuffer method target')
            need(owner['coexist_flag'] == 1, 'coexist cancellation flag is not exactly armed')
            low_address(owner['original_trampoline_private'])

        # Only one hook owner may own the actual exported dispatch route.
        need(len(owners) == 1, 'ambiguous public dispatch hook owner')
        expected_target = next(iter(owners.values()))['hook_entry_private']
        entry = framework_base + profile['public_SwapEnd_offset']
        dispatch = {'entry_private': entry, 'expected_hook_private': expected_target, 'steps_private': []}
        result['dispatch_private'] = dispatch
        visited = set()
        for _ in range(2):
            need(entry not in visited, 'dispatch branch cycle')
            visited.add(entry)
            raw = read(entry, 64)
            step = {'address_private': entry, 'bytes_private_hex': raw.hex()}
            dispatch['steps_private'].append(step)
            target, shape = branch_target(entry, raw)
            step.update(shape=shape, target_private=target)
            if target == expected_target:
                dispatch['points_to_selected_hook_low_address'] = True
                break
            entry = target
        else:
            raise Refused('dispatch branch depth or target differs')
        for where, raw in guards:
            need(reader.read(where, len(raw)) == raw, 'route bytes changed')
        need(check_identity() is True, 'route identity after')
        result.update(accepted_swap_dispatch_address_observation=True,
                      guard_ranges=len(guards), registrations=len(registrations),
                      repeated_route_bytes_equal=True, same_held_task_context=True)
        return result, guards
    except (Refused, KeyError, TypeError, ValueError, struct.error) as error:
        error.details = {'swap_routes_private': result, 'completed_route_guard_ranges': len(guards)}
        raise
