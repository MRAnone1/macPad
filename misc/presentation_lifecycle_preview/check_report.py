#!/usr/bin/env python3
"""Check exported v1 records locally; never grant device or freeze acceptance.

Input is untrusted, unsigned JSON. No device, subprocess, network or write API is
used. A consistent record is still a claim requiring independent human review.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import sys


MAX_BYTES = 1024 * 1024
MAX_EVENTS = 256
MAX_DEPTH = 16
BASE = {'event', 'run', 'frame', 'wall_seconds', 'uptime_seconds'}
TOP = {'schema', 'events', 'mode', 'finished', 'outcome', 'target',
       'presentation_callback_supported', 'dropped_events', 'human_review_required'}
LIFECYCLE = {'UIApplicationWillResignActiveNotification',
             'UIApplicationDidEnterBackgroundNotification',
             'UIApplicationWillEnterForegroundNotification',
             'UIApplicationDidBecomeActiveNotification'}
FIELDS = {
    'app_ready': {'machine', 'os', 'os_build', 'bundle_version', 'target',
                  'presentation_callback_supported'},
    'run_started': {'mode', 'thermal', 'low_power'},
    'metal_setup_started': set(),
    'metal_setup_finished': {'pipeline_ready', 'error'},
    'frame_requested': set(),
    'uikit_draw': set(),
    'human_colors_visible': set(),
    'command_commit': {'drawable_width', 'drawable_height'},
    'command_completed': {'status', 'error', 'sample_bgra', 'four_samples_match'},
    'drawable_presented': {'presented_time', 'positive_presented_time', 'drawable_id'},
    'presentation_callback_unavailable': {'target'},
    'drawable_size_changed': {'width', 'height'},
    **{name: {'application_state'} for name in LIFECYCLE},
}
EXPECTED_BGRA = [[0, 0, 255, 255], [0, 255, 0, 255],
                 [255, 0, 0, 255], [0, 255, 255, 255]]
UUID = re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z')


class Refused(ValueError):
    """Missing, unsupported, inconsistent or incomplete record evidence."""


def need(condition, code):
    if not condition:
        raise Refused(code)


def integer(value, minimum=0, maximum=2**64 - 1):
    return type(value) is int and minimum <= value <= maximum


def number(value, minimum=0):
    return (type(value) in (int, float) and
            (type(value) is int or math.isfinite(value)) and
            minimum <= value <= sys.float_info.max)


def text(value):
    return type(value) is str and 0 < len(value) <= 512


def load(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, 'input_byte_limit')
    # Bound nesting before the recursive JSON decoder sees it. Brackets inside
    # JSON strings are data; malformed syntax is left to the decoder below.
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            need(depth <= MAX_DEPTH, 'json_depth_limit')
        elif byte in (93, 125):
            depth -= 1

    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate_json_key')
            result[key] = value
        return result

    def constant(_):
        raise Refused('nonfinite_json_number')

    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=constant)
    except Refused:
        raise
    except (ValueError, UnicodeError, RecursionError, OverflowError) as exc:
        raise Refused('invalid_json') from exc


def assess(raw, *, allow_simulator=False):
    """Validate a completed record, not its authenticity or physical acceptance."""
    report = load(raw)
    need(type(report) is dict and set(report) == TOP, 'report_keys')
    need(report['schema'] == 'macws.presentation-comparison.v1', 'report_schema')
    mode, target = report['mode'], report['target']
    need(mode in ('UIKit', 'Metal') and type(mode) is str, 'report_mode')
    need(target in ('device', 'simulator') and type(target) is str, 'report_target')
    need(type(allow_simulator) is bool, 'simulator_option_type')
    need(target == 'device' or allow_simulator, 'simulator_is_not_device_evidence')
    supported = target == 'device'
    need(report['presentation_callback_supported'] is supported, 'report_capability')
    need(report['finished'] is True and
         report['outcome'] == 'two_frames_observed_and_confirmed', 'run_incomplete')
    need(integer(report['dropped_events'], 0, 0), 'events_dropped')
    need(report['human_review_required'] is True, 'human_review_required')
    events = report['events']
    need(type(events) is list and 0 < len(events) <= MAX_EVENTS, 'event_count')

    run = None
    current = 0
    setup = 0
    background = returned = finished = False
    seen = {1: set(), 2: set()}
    presentation = {}
    context = {}

    def observed(frame):
        if frame not in seen:
            return False
        required = {'uikit_draw'} if mode == 'UIKit' else {
            'command_completed', 'drawable_presented' if supported else
            'presentation_callback_unavailable'}
        return required <= seen[frame]

    for index, event in enumerate(events):
        need(type(event) is dict, 'event_type')
        name = event.get('event')
        need(type(name) is str and name in FIELDS, 'unknown_event')
        need(set(event) == BASE | FIELDS[name], 'event_keys')
        frame = event['frame']
        need(integer(frame, 0, 2), 'frame_number')
        need(type(event['run']) is str and len(event['run']) <= 36, 'run_type')
        need(number(event['wall_seconds']) and number(event['uptime_seconds']), 'event_time')
        # Callback timestamps are captured off-main before insertion into this
        # array. Preserve insertion order; never require global clock ordering.
        if index == 0:
            need(name == 'app_ready' and event['run'] == '' and frame == 0, 'app_ready')
            need(event['target'] == target and
                 event['presentation_callback_supported'] is supported, 'app_capability')
            for key in ('machine', 'os', 'os_build', 'bundle_version'):
                need(text(event[key]) and event[key] != 'unknown', 'app_metadata')
                context[key] = event[key]
            need(event['bundle_version'] == '1', 'unsupported_bundle_version')
            continue
        need(name != 'app_ready', 'duplicate_app_ready')
        if name == 'run_started':
            need(run is None and current == 0 and frame == 0 and
                 UUID.fullmatch(event['run']) is not None, 'run_start')
            need(event['mode'] == mode and integer(event['thermal'], 0, 3) and
                 type(event['low_power']) is bool, 'run_context')
            run = event['run']
            context.update(thermal=event['thermal'], low_power=event['low_power'])
            continue
        if name == 'frame_requested':
            need(run is not None and event['run'] == run and not finished,
                 'frame_request_scope')
            if frame == 1:
                need(current == 0 and (mode == 'UIKit' or setup == 2),
                     'first_frame_order')
            elif frame == 2:
                need(current == 1 and returned and
                     'human_colors_visible' in seen[1], 'second_frame_order')
            else:
                raise Refused('requested_frame_number')
            current = frame
            returned = False
            continue
        if run is None:
            need(name in LIFECYCLE and event['run'] == '' and frame == 0,
                 'event_before_run')
        else:
            need(event['run'] == run and frame == current, 'event_run_or_frame')

        if name in LIFECYCLE:
            state = event['application_state']
            need(integer(state, 0, 2), 'application_state')
            if name == 'UIApplicationDidEnterBackgroundNotification':
                need(state == 2, 'background_state')
            if name == 'UIApplicationDidBecomeActiveNotification':
                need(state == 0, 'active_state')
            if run is not None and not finished:
                if name == 'UIApplicationWillResignActiveNotification':
                    need(observed(current), 'inactive_before_observation')
                    returned = False
                elif name == 'UIApplicationDidEnterBackgroundNotification':
                    need(current in seen and 'human_colors_visible' in seen[current],
                         'background_before_confirmation')
                    background = True
                    returned = False
                elif name == 'UIApplicationWillEnterForegroundNotification':
                    returned = False
                elif name == 'UIApplicationDidBecomeActiveNotification' and background:
                    background = False
                    returned = current == 1 and 'human_colors_visible' in seen[1]
            continue
        if name == 'drawable_size_changed':
            need(mode == 'Metal' and number(event['width']) and number(event['height']),
                 'drawable_size')
            continue
        need(not finished, 'event_after_completion')
        if name.startswith('metal_setup_'):
            need(mode == 'Metal' and current == 0 and frame == 0, 'metal_setup_scope')
            if name == 'metal_setup_started':
                need(setup == 0, 'metal_setup_order')
                setup = 1
            else:
                need(setup == 1 and event['pipeline_ready'] is True and
                     event['error'] == '', 'metal_setup_failed')
                setup = 2
            continue
        need(current in (1, 2), 'endpoint_without_frame')
        need(name not in seen[current], 'duplicate_endpoint')
        if name == 'human_colors_visible':
            need(observed(current), 'confirmation_before_endpoints')
            seen[current].add(name)
            finished = current == 2
            continue
        if name == 'uikit_draw':
            need(mode == 'UIKit', 'uikit_endpoint_in_metal')
        else:
            need(mode == 'Metal', 'metal_endpoint_in_uikit')
            if name == 'command_commit':
                need(integer(event['drawable_width'], 4) and
                     integer(event['drawable_height'], 4), 'drawable_geometry')
                need(supported or 'presentation_callback_unavailable' in seen[current],
                     'simulator_marker_order')
            elif name == 'presentation_callback_unavailable':
                need(not supported and event['target'] == 'simulator' and
                     'command_commit' not in seen[current], 'unavailable_callback_scope')
            elif name == 'command_completed':
                need('command_commit' in seen[current], 'completion_before_commit')
                need(integer(event['status'], 4, 4) and event['error'] == '' and
                     event['four_samples_match'] is True, 'gpu_completion_failed')
                pixels = event['sample_bgra']
                need(type(pixels) is list and len(pixels) == 4 and all(
                    type(pixel) is list and len(pixel) == 4 and all(
                        integer(channel, 0, 255) for channel in pixel) for pixel in pixels)
                    and pixels == EXPECTED_BGRA, 'gpu_pixels')
            elif name == 'drawable_presented':
                need(supported and 'command_commit' in seen[current], 'presentation_scope')
                need(number(event['presented_time']) and event['presented_time'] > 0 and
                     event['positive_presented_time'] is True and
                     integer(event['drawable_id']), 'presentation_value')
                presentation[current] = (event['presented_time'], event['drawable_id'])
                if current == 2:
                    need(presentation[2][0] > presentation[1][0] and
                         presentation[2][1] > presentation[1][1], 'presentation_not_advanced')
            else:
                raise Refused('unsupported_endpoint')
        seen[current].add(name)

    need(run is not None and current == 2 and finished, 'missing_completed_frames')
    return {'schema': 'macws.presentation-record-assessment.v1',
            'completed_record_consistent': True, 'mode': mode, 'target': target,
            'run': run, 'context': context, 'input_sha256': hashlib.sha256(raw).hexdigest(),
            'device_presentation_records_complete': mode == 'Metal' and supported,
            'device_acceptance': False, 'authenticity_verified': False,
            'human_review_required': True, 'original_freeze_fixed': False}


def assess_pair(uikit_raw, metal_raw, *, allow_simulator=False):
    """Check compatible reported contexts, never physical trial acceptance."""
    ui = assess(uikit_raw, allow_simulator=allow_simulator)
    metal = assess(metal_raw, allow_simulator=allow_simulator)
    need(ui['mode'] == 'UIKit' and metal['mode'] == 'Metal', 'pair_mode_order')
    need(ui['target'] == metal['target'] and ui['context'] == metal['context'],
         'pair_context_mismatch')
    need(ui['run'].upper() != metal['run'].upper(), 'pair_run_reused')
    return {'schema': 'macws.presentation-pair-assessment.v1',
            'completed_record_consistent': True, 'compatible_reported_contexts': True,
            'reports': [ui, metal], 'device_acceptance': False,
            'authenticity_verified': False, 'human_review_required': True,
            'original_freeze_fixed': False,
            'unverified': ['report authenticity', 'installed app identity',
                           'fresh process launches', 'orientation and window size',
                           'charging state', 'Home and touch responsiveness',
                           'device thermals after trial', 'new crash reports']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-simulator', action='store_true',
                        help='check Simulator record consistency without device acceptance')
    parser.add_argument('reports', nargs='+', metavar='REPORT',
                        help='one report, or UIKit report followed by Metal report')
    args = parser.parse_args(argv)
    if len(args.reports) not in (1, 2):
        parser.error('supply one report, or UIKit then Metal')
    try:
        raw = []
        for name in args.reports:
            with Path(name).open('rb') as stream:
                raw.append(stream.read(MAX_BYTES + 1))
        result = (assess(raw[0], allow_simulator=args.allow_simulator) if len(raw) == 1
                  else assess_pair(*raw, allow_simulator=args.allow_simulator))
        status = 0
    except (OSError, Refused) as exc:
        result = {'completed_record_consistent': False,
                  'reason': str(exc) if isinstance(exc, Refused) else 'input_io_error',
                  'device_acceptance': False, 'authenticity_verified': False,
                  'human_review_required': True, 'original_freeze_fixed': False}
        status = 2
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    return status


if __name__ == '__main__':
    sys.exit(main())
