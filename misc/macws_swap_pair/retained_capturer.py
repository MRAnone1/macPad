"""Default-inert, one-attempt host preservation around a trusted transport.

No endpoint, SSH construction, native query or device action is provided here.
The explicit caller must review/pin the invoked transport and establish current
device readiness/inventory. Historical bytes and JSON cannot do that. Even a
complete source-bound report supplies no cleanup or native freshness authority.
"""
import hashlib
import json

from macws_swap_pair import capture_journal as journal
from macws_swap_pair import capture_result as result_core
from macws_swap_pair import retained_archive as archive

STDIN_LIMIT = 256*1024
STDOUT_LIMIT = 4*1024*1024
STDERR_LIMIT = 16*1024
HOST_SECONDS = 20
EVIDENCE = ('config', 'control_wire', 'host', 'delivery', 'retirement_wire', 'snapshot')
SOURCES = ('process_retirement.py', 'cleanup_payload.py', 'reviewed_delivery_plan.json',
           'retained_inputs.py', 'retained_cleanup.py', 'readonly_observer.py', 'retained_observer.py')
ENTRY_NAMES = frozenset(['evidence.'+name for name in EVIDENCE]+
                        ['source.'+name for name in SOURCES])
TRANSPORT_KEYS = frozenset(('returncode', 'stdout', 'stderr', 'timed_out',
                            'output_limit_exceeded', 'stdin_complete', 'capture_complete',
                            'local_cleanup_errors_private'))


class Refused(ValueError):
    pass


def need(value, category):
    if value is not True:
        raise Refused(category)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def word(value):
    return type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value)


def freeze(value):
    return archive.canonical_json(value)


def checked_expected(expected):
    need(type(expected)is dict and set(expected)=={'payload_sha256','codec_sha256','frame_sha256','entry_sha256'},
         'exact_expected_binding')
    need(all(word(expected[key])for key in ('payload_sha256','codec_sha256','frame_sha256')),
         'expected_hash_words')
    entries=expected['entry_sha256']
    need(type(entries)is dict and set(entries)==ENTRY_NAMES and
         all(type(key)is str and word(value)for key,value in entries.items()), 'exact_expected_entries')
    return json.loads(freeze(expected))


def transport_parts(value):
    """Keep original bounded streams; malformed trusted-transport returns refuse.

    This function never synthesizes an empty stream or a zero-effect result.
    If a trusted transport violates its contract, saveable_streams() separately
    retains only actually returned, bounded byte streams, labelled incomplete.
    """
    need(type(value)is dict and TRANSPORT_KEYS<=set(value)<=TRANSPORT_KEYS|{'transport_error_private'},
         'transport_result_fields')
    for name,limit in (('stdout',STDOUT_LIMIT),('stderr',STDERR_LIMIT)):
        need(type(value[name])is bytes and len(value[name])<=limit+1, 'bounded_original_streams')
    need((type(value['returncode'])is int and -255<=value['returncode']<=255) or value['returncode']is None,
         'typed_transport_exit')
    need(all(type(value[key])is bool for key in ('timed_out','output_limit_exceeded','capture_complete')) and
         (type(value['stdin_complete'])is bool or value['stdin_complete']is None), 'typed_transport_flags')
    errors=value['local_cleanup_errors_private']
    need(type(errors)is list and len(errors)<=16 and all(type(x)is str and len(x)<=4096 for x in errors),
         'bounded_local_cleanup_errors')
    if 'transport_error_private'in value:
        need(type(value['transport_error_private'])is str and len(value['transport_error_private'])<=4096,
             'bounded_transport_error')
    metadata={key:item for key,item in value.items()if key not in ('stdout','stderr')}
    metadata.update(schema='macws.retained-capturer.transport.v1',
                    stdout_bytes_captured=len(value['stdout']), stderr_bytes_captured=len(value['stderr']),
                    stdout_sha256=sha(value['stdout']), stderr_sha256=sha(value['stderr']),
                    trusted_transport_contract_checked=True,
                    remote_effects_known_from_transport=False)
    return value['stdout'],value['stderr'],metadata


def saveable_streams(value):
    """Only actually present, bounded bytes survive a transport contract error."""
    streams={}
    for name,limit in (('stdout',STDOUT_LIMIT),('stderr',STDERR_LIMIT)):
        raw=value.get(name)if type(value)is dict else None
        if type(raw)is bytes and len(raw)<=limit+1:
            streams[name]=raw
    return streams


class OneShotCapture:
    """Explicit trusted-caller route; each instance consumes before any IO.

    The private live adapter also fixes one exclusive attempt directory, so a
    fresh process cannot silently reuse that same attempt. The public API does
    not claim global exactly-once delivery or remote cancellation.
    """
    def __init__(self,payload,expected,inputs,*,caller_provenance=None):
        need(type(payload)is bytes and 0<len(payload)<=STDIN_LIMIT,'bounded_exact_payload')
        expected=checked_expected(expected)
        need(sha(payload)==expected['payload_sha256'],'payload_byte_binding')
        self.payload=payload
        self.expected_raw=freeze(expected)
        self.inputs=inputs
        self.context_raw=freeze(inputs.context)
        self.provenance_raw=freeze({}if caller_provenance is None else caller_provenance)
        self.used=False
        self._intact()

    def _intact(self):
        need(self.inputs.intact()is True,'intact_original_inputs')
        need(freeze(self.inputs.context)==self.context_raw,'immutable_input_context')
        original=self.inputs.original_bytes
        need(type(original)is dict and set(original)==set(EVIDENCE) and all(
            type(raw)is bytes and 0<len(raw)<=512*1024 for raw in original.values()),'six_original_byte_inputs')
        expected=json.loads(self.expected_raw)
        need(all(sha(raw)==expected['entry_sha256']['evidence.'+name]for name,raw in original.items()),
             'original_bytes_match_worker_entries')
        need(sha(self.payload)==expected['payload_sha256'],'unchanged_payload_binding')
        return expected

    def execute_once(self,parent_directory,capture_name,invoke):
        need(self.used is False,'capture_one_attempt_no_retry')
        self.used=True
        report={'schema':'macws.retained-capturer.result.v1','stage':'before_preparation',
                'transport_attempted':False,'transport_invocations':0,
                'preparation_durable':False,'dispatch_intent_durable':False,
                'original_captured_streams_durable':False,'known_captured_streams_durable':[],
                'assessment_durable':False,
                'source_bound_capture_received':False,'automatic_retry':False,
                'remote_effects_known_from_transport':False,'native_freshness_authority':False,
                'cleanup_authorized':False,'native_evidence_authenticity_verified':False,
                'device_acceptance':False,'freeze_fix':False,'error_category':None,'refusal_category':None,
                'assessment':None,'journal_receipt':None}
        held=None
        try:
            expected=self._intact()
            need(callable(invoke),'explicit_trusted_transport_callback')
            intent={'schema':'macws.retained-capturer.intent.v1','payload_bytes':len(self.payload),
                    'expected_worker':expected,'input_context_sha256':sha(self.context_raw),
                    'caller_provenance':json.loads(self.provenance_raw),
                    'host_timeout_seconds':HOST_SECONDS,'worker_self_alarm_seconds':12,
                    'automatic_retry':False,'device_readiness_not_inferred':True,
                    'fresh_inventory_required':True,'cleanup_authorized':False,'device_acceptance':False}
            held=journal.Journal(parent_directory,capture_name,payload=self.payload,intent=intent)
            report['preparation_durable']=True
            report['stage']='before_dispatch'
            self._intact()
            held.mark_dispatch()
            report['dispatch_intent_durable']=True
            report['stage']='transport'
            report['transport_attempted']=True
            report['transport_invocations']=1
            # Only a reviewed callback may construct the fixed SSH command and
            # invoke the unchanged R3 transport here. No automatic retry.
            try:
                captured=invoke(self.payload,timeout=HOST_SECONDS)
            except Exception as error:
                report['transport_callback_error_category']=type(error).__name__
                present=saveable_streams({'stdout':getattr(error,'stdout',None),
                                          'stderr':getattr(error,'stderr',None)})
                if present:
                    report['journal_receipt']=held.save_partial_transport(streams=present,transport={
                        'schema':'macws.retained-capturer.callback-exception.v1',
                        'transport_callback_error_category':type(error).__name__,
                        'original_bytes_from_exception_attributes':True,
                        'remote_effects_known_from_transport':False})
                    report['known_captured_streams_durable']=sorted(present)
                    report['original_captured_streams_durable']=set(present)=={'stdout','stderr'}
                raise Refused('transport_callback_failed_without_outcome')from error
            report['stage']='raw_preservation'
            try:
                stdout,stderr,transport=transport_parts(captured)
            except Exception as error:
                present=saveable_streams(captured)
                # Missing or over-bound streams cannot be replaced by invented
                # empty originals. The partial journal names only known bytes.
                if present:
                    report['journal_receipt']=held.save_partial_transport(streams=present,transport={
                        'schema':'macws.retained-capturer.invalid-transport.v1',
                        'trusted_transport_contract_checked':False,
                        'transport_contract_error_category':type(error).__name__,
                        'remote_effects_known_from_transport':False})
                    report['known_captured_streams_durable']=sorted(present)
                    report['original_captured_streams_durable']=set(present)=={'stdout','stderr'}
                raise Refused('trusted_transport_contract_refused')from error
            held.save_transport(stdout=stdout,stderr=stderr,transport=transport)
            report['original_captured_streams_durable']=True
            report['known_captured_streams_durable']=['stderr','stdout']
            report['stage']='assessment'
            try:
                self._intact()
                assessment=result_core.assess(captured,expected=expected,inputs=self.inputs)
                need(type(assessment)is dict and assessment.get('cleanup_authorized')is False and
                     assessment.get('device_acceptance')is False,'assessment_never_grants_authority')
                freeze(assessment)
            except Exception as error:
                assessment={'schema':'macws.retained-capturer.assessment-error.v1',
                            'source_bound_capture_received':False,'cleanup_authorized':False,
                            'device_acceptance':False,'assessment_error_category':type(error).__name__}
            report['assessment']=assessment
            report['stage']='assessment_preservation'
            report['journal_receipt']=held.save_assessment(assessment)
            report['assessment_durable']=True
            report['source_bound_capture_received']=assessment.get('source_bound_capture_received')is True
            report['stage']='complete'
        except Exception as error:
            report['error_category']=type(error).__name__
            report['refusal_category']=str(error)if type(error)is Refused else None
        finally:
            if held is not None:
                try:held.close()
                except Exception as error:
                    report['journal_close_error_category']=type(error).__name__
                    report['source_bound_capture_received']=False
        return report


def metadata():
    return {'schema':'macws.retained-capturer.metadata.v1','default_inert':True,
            'device_commands':0,'endpoint_provided':False,'automatic_retry':False,
            'cleanup_authorized':False,'device_acceptance':False,'freeze_fix':False}


if __name__=='__main__':
    print(json.dumps(metadata(),sort_keys=True))
