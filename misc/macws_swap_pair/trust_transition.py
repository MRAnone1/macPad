"""Pure postcondition for one fixed diagnostic trust addition; no native calls.

The exact jbctl binary can return zero for an info client error. Require complete
parsed query output and the exact set transition. This checks supplied evidence;
it does not authenticate it, perform an add, or authorize execution/cleanup.
"""
import base64

from macws_swap_pair import readonly_observer as observer

TARGETS = {
    'candidate': '6665b5a54da06153a5940368788cdb9b6e9be3dc',
    'wrapper': '770cc7b5423da57bb1c5b644b7362c6d740cd8ff',
    'hook_arm64': '430ef5e0426c75e525aefe280b943a5d9bd00511',
    'hook_arm64e': 'e5be4b2e2addf514451db9df5e74d37bc5a2b4c3',
}
MAX_QUERY_STDOUT = 256 * 1024
MAX_ADD_STREAM = 16 * 1024

class Refused(ValueError):
    pass

def need(value, reason):
    if value is not True:
        raise Refused(reason)

def _result(value, stdout_limit):
    need(type(value) is dict and set(value) == {'returncode', 'stdout', 'stderr', 'capture_complete', 'timed_out',
         'output_limit_exceeded', 'local_cleanup_errors'}, 'exact_transport_fields')
    need(type(value['returncode']) is int and value['returncode'] == 0 and value['capture_complete'] is True and
         value['timed_out'] is False and value['output_limit_exceeded'] is False and
         type(value['local_cleanup_errors']) is list and value['local_cleanup_errors'] == [], 'complete_zero_exit_transport')
    need(type(value['stdout']) is bytes and len(value['stdout']) <= stdout_limit and
         type(value['stderr']) is bytes and len(value['stderr']) <= MAX_ADD_STREAM, 'bounded_original_streams')
    return value['stdout'], value['stderr']

def _query(value):
    stdout, stderr = _result(value, MAX_QUERY_STDOUT)
    need(stderr == b'', 'quiet_trust_query')
    try:
        return observer.trust_rows(stdout.decode('utf-8', 'strict'))
    except (observer.Refused, UnicodeError) as error:
        raise Refused('complete_parsed_trust_query_required') from error

def assess(*, role, before, addition, after):
    """Return a non-authoritative witness for exactly ONE observed addition.

    Callers must preserve raw/partial evidence before invoking this parser. A
    refusal never proves zero mutations, authorizes retry, or grants rollback.
    All source/file identity, native freshness and health gates belong to the
    separately reviewed native caller, which is not implemented here.
    """
    need(type(role) is str and role in TARGETS, 'fixed_artifact_role')
    initial = _query(before)
    target = TARGETS[role]
    need(target not in initial, 'target_already_present_no_add_should_be_attempted')
    stdout, stderr = _result(addition, MAX_ADD_STREAM)
    final = _query(after)
    need(final == initial | {target}, 'exact_single_hash_addition_required')
    return {
        'schema': 'macws.trust-transition.evidence.v1', 'role': role, 'cdhash': target,
        'exact_reported_transition': True, 'before_entries': len(initial), 'after_entries': len(final),
        'add_stdout_private_b64': base64.b64encode(stdout).decode('ascii'),
        'add_stderr_private_b64': base64.b64encode(stderr).decode('ascii'),
        'native_authenticity_verified': False, 'native_freshness_verified': False,
        'execution_authorized': False, 'session_authorized': False, 'cleanup_authorized': False,
        'retry_authorized': False, 'rollback_authorized': False, 'device_acceptance': False,
    }

def metadata():
    return {'schema': 'macws.trust-transition.default.v1', 'default_inert': True,
            'native_calls': 0, 'trust_mutations': 0, 'device_acceptance': False}

if __name__ == '__main__':
    import json
    print(json.dumps(metadata(), sort_keys=True))
