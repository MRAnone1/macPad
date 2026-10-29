"""Host-only orchestration tests with self-owned journals and invented reports."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from macws_swap_pair import retained_capturer as core
import test_macws_capture_result as fixture_module


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.parent=Path(self.temp.name).resolve()
        self.payload=b'invented reviewed payload\n'
        self.inputs,self.expected,self.worker,self.result=fixture_module.fixture()
        self.expected['payload_sha256']=core.sha(self.payload)
        self.capture=core.OneShotCapture(self.payload,self.expected,self.inputs)
        self.calls=0
    def invoke(self,payload,*,timeout):
        self.calls+=1;self.assertEqual(timeout,20);self.assertEqual(payload,self.payload)
        for file in ('stdin.private.py','intent.private.json','dispatch-intent.private.json'):
            self.assertTrue((self.parent/'once'/file).is_file())
        return self.result
    def execute(self,callback=None):
        return self.capture.execute_once(str(self.parent),'once',self.invoke if callback is None else callback)
    def raw(self,name):return (self.parent/'once'/name).read_bytes()
    def test_actual_journal_and_assessor_interoperate_without_authority(self):
        report=self.execute()
        self.assertTrue(report['source_bound_capture_received'],report)
        self.assertTrue(report['assessment_durable']);self.assertEqual(self.calls,1)
        self.assertEqual(self.raw('stdout.original.private.bin'),self.result['stdout'])
        self.assertEqual(self.raw('stderr.original.private.bin'),b'')
        receipt=json.loads(self.raw('receipt.private.json'))
        self.assertEqual(receipt['files']['stdout.original.private.bin']['sha256'],core.sha(self.result['stdout']))
        for flag in ('cleanup_authorized','device_acceptance','freeze_fix','remote_effects_known_from_transport','native_freshness_authority'):
            self.assertIs(report[flag],False)
    def test_assessment_starts_after_durable_raw_transport_phase(self):
        original=core.result_core.assess
        def assess(*args,**kwargs):
            self.assertEqual(self.raw('stdout.original.private.bin'),self.result['stdout'])
            self.assertEqual(self.raw('stderr.original.private.bin'),self.result['stderr'])
            self.assertTrue((self.parent/'once/transport.private.json').exists())
            return original(*args,**kwargs)
        with patch.object(core.result_core,'assess',side_effect=assess):
            self.assertTrue(self.execute()['source_bound_capture_received'])
    def test_constructor_rejects_wrong_or_overbound_payload(self):
        for payload in (b'',bytearray(self.payload),b'x'*(core.STDIN_LIMIT+1),self.payload+b'x'):
            with self.subTest(kind=type(payload)),self.assertRaises(core.Refused):
                core.OneShotCapture(payload,self.expected,self.inputs)
    def test_constructor_requires_exact_entry_and_evidence_binding(self):
        for name in ('source.retained_observer.py','evidence.snapshot'):
            expected=copy.deepcopy(self.expected)
            if name.startswith('source.'):expected['entry_sha256'].pop(name)
            else:expected['entry_sha256'][name]='0'*64
            with self.assertRaises(core.Refused):core.OneShotCapture(self.payload,expected,self.inputs)
    def test_mutation_before_preparation_consumes_attempt_without_dispatch(self):
        self.inputs.context['exclusive_operator']=False
        report=self.execute()
        self.assertFalse(report['transport_attempted']);self.assertEqual(self.calls,0)
        self.assertFalse((self.parent/'once').exists())
        with self.assertRaises(core.Refused):self.execute()
    def test_prepare_fsync_failure_prevents_transport_and_preserves_partial(self):
        with patch.object(core.archive.os,'fsync',side_effect=OSError('invented failure')):
            report=self.execute()
        self.assertFalse(report['transport_attempted']);self.assertEqual(self.calls,0)
        self.assertTrue((self.parent/'once').exists())
        self.assertFalse(report['preparation_durable'])
    def test_dispatch_failure_prevents_transport(self):
        with patch.object(core.journal.Journal,'mark_dispatch',side_effect=OSError('invented')):
            report=self.execute()
        self.assertTrue(report['preparation_durable']);self.assertFalse(report['transport_attempted'])
        self.assertEqual(self.calls,0)
    def test_duplicate_object_and_fresh_instance_cannot_reuse_reserved_name(self):
        self.execute()
        with self.assertRaises(core.Refused):self.execute()
        second=core.OneShotCapture(self.payload,self.expected,self.inputs)
        report=second.execute_once(str(self.parent),'once',self.invoke)
        self.assertFalse(report['transport_attempted']);self.assertEqual(self.calls,1)
    def test_binary_negative_and_exit_states_preserved_no_retry(self):
        for code in (1,124,255,-9):
            with self.subTest(code=code),tempfile.TemporaryDirectory()as temp:
                self.parent=Path(temp).resolve()
                self.capture=core.OneShotCapture(self.payload,self.expected,self.inputs)
                self.result=dict(self.result,stdout=b'\0\xffpartial',stderr=b'\xfe',returncode=code)
                report=self.execute()
                self.assertFalse(report['source_bound_capture_received'])
                self.assertTrue(report['original_captured_streams_durable'])
                self.assertEqual(self.raw('stdout.original.private.bin'),b'\0\xffpartial')
                self.assertFalse(report['remote_effects_known_from_transport'])
                with self.assertRaises(core.Refused):self.execute()
        self.assertEqual(self.calls,4)
    def test_timeout_and_overflow_sentinel_preserved(self):
        self.result=dict(self.result,returncode=None,stdout=b'x'*(core.STDOUT_LIMIT+1),
                         capture_complete=False,timed_out=True,stdin_complete=False,output_limit_exceeded=True)
        report=self.execute()
        self.assertTrue(report['original_captured_streams_durable']);self.assertFalse(report['source_bound_capture_received'])
        self.assertEqual(len(self.raw('stdout.original.private.bin')),core.STDOUT_LIMIT+1)
    def test_raw_save_failure_never_reaches_assessor_or_retries(self):
        with patch.object(core.journal.Journal,'save_transport',side_effect=OSError('invented')), \
             patch.object(core.result_core,'assess',side_effect=AssertionError('too early')):
            report=self.execute()
        self.assertEqual(self.calls,1);self.assertFalse(report['original_captured_streams_durable'])
        with self.assertRaises(core.Refused):self.execute()
    def test_assessor_exception_retains_raw_and_negative_assessment(self):
        with patch.object(core.result_core,'assess',side_effect=ValueError('private detail')):
            report=self.execute()
        self.assertTrue(report['original_captured_streams_durable']);self.assertTrue(report['assessment_durable'])
        self.assertFalse(report['source_bound_capture_received'])
        self.assertNotIn('private detail',json.dumps(report))
    def test_assessor_cannot_grant_cleanup(self):
        with patch.object(core.result_core,'assess',return_value={'source_bound_capture_received':True,'cleanup_authorized':True,'device_acceptance':False}):
            report=self.execute()
        self.assertFalse(report['source_bound_capture_received'])
        self.assertFalse(json.loads(self.raw('assessment.private.json'))['cleanup_authorized'])
    def test_final_assessment_persistence_failure_cannot_accept(self):
        with patch.object(core.journal.Journal,'save_assessment',side_effect=OSError('invented')):
            report=self.execute()
        self.assertTrue(report['original_captured_streams_durable']);self.assertFalse(report['assessment_durable'])
        self.assertFalse(report['source_bound_capture_received']);self.assertEqual(self.calls,1)
    def test_callback_exception_known_bytes_are_preserved(self):
        def invoke(*args,**kwargs):
            self.calls+=1
            raise subprocess.TimeoutExpired('invented local child',20,output=b'\xffprefix',stderr=b'\0error')
        report=self.execute(invoke)
        self.assertTrue(report['original_captured_streams_durable']);self.assertFalse(report['source_bound_capture_received'])
        self.assertEqual(self.raw('stdout.original.private.bin'),b'\xffprefix')
        self.assertEqual(self.calls,1)
    def test_malformed_boolean_exit_preserves_known_bytes(self):
        self.result['returncode']=True
        report=self.execute()
        self.assertFalse(report['source_bound_capture_received']);self.assertTrue(report['original_captured_streams_durable'])
        self.assertEqual(self.raw('stdout.original.private.bin'),self.result['stdout'])
    def test_one_known_stdout_is_preserved_without_invented_stderr(self):
        self.result.pop('stderr')
        report=self.execute()
        self.assertEqual(report['known_captured_streams_durable'],['stdout'])
        self.assertFalse(report['original_captured_streams_durable'])
        self.assertEqual(self.raw('stdout.original.private.bin'),self.result['stdout'])
        self.assertFalse((self.parent/'once/stderr.original.private.bin').exists())
        self.assertFalse(report['source_bound_capture_received'])
    def test_exception_with_one_known_stderr_is_preserved(self):
        def invoke(*args,**kwargs):
            self.calls+=1
            raise subprocess.TimeoutExpired('invented',20,stderr=b'\xfeactual error')
        report=self.execute(invoke)
        self.assertEqual(report['known_captured_streams_durable'],['stderr'])
        self.assertEqual(self.raw('stderr.original.private.bin'),b'\xfeactual error')
        self.assertFalse((self.parent/'once/stdout.original.private.bin').exists())
        self.assertFalse(report['original_captured_streams_durable'])
    def test_oversized_invalid_callback_stream_is_explicitly_unknown(self):
        self.result['stdout']=b'x'*(core.STDOUT_LIMIT+2)
        report=self.execute()
        self.assertEqual(report['known_captured_streams_durable'],['stderr'])
        self.assertFalse((self.parent/'once/stdout.original.private.bin').exists())
        receipt=json.loads(self.raw('receipt.private.json'))
        self.assertEqual(receipt['missing_streams'],['stdout'])
    def test_context_change_during_transport_refuses_after_raw_save(self):
        def invoke(*args,**kwargs):
            value=self.invoke(*args,**kwargs)
            self.inputs.context['exclusive_operator']=False
            return value
        report=self.execute(invoke)
        self.assertTrue(report['original_captured_streams_durable']);self.assertFalse(report['source_bound_capture_received'])
    def test_public_defaults_are_metadata_only(self):
        with patch.object(core.journal,'Journal',side_effect=AssertionError('unexpected IO')):
            self.assertTrue(core.metadata()['default_inert'])
            self.assertEqual(core.metadata()['device_commands'],0)


if __name__=='__main__':unittest.main()
