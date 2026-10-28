"""Offline subprocess-only worker boundaries; no device, SSH or native backend.

Synthetic trusted codec/helper sources exercise orchestration, never weaken a
production source pin. Deadline cases use a derived test fixture with 50 ms;
the reviewed template's literal deadline remains twelve seconds.
"""
import ast
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

TEMPLATE = Path(__file__).parent / 'macws_swap_pair' / 'retained_worker.py.in'
TOKENS = ('__CODEC_B64__', '__CODEC_SHA__', '__FRAME_B64__', '__FRAME_SHA__',
          '__ENTRY_PINS__', '__CAPTURE__')
EVIDENCE = ('config', 'control_wire', 'host', 'delivery', 'retirement_wire', 'snapshot')
SOURCES = ('process_retirement.py', 'cleanup_payload.py', 'reviewed_delivery_plan.json',
           'retained_inputs.py', 'retained_cleanup.py', 'readonly_observer.py', 'retained_observer.py')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


CODEC = b'''import base64,json
def decode(raw,pins):
    return {key:base64.b64decode(value) for key,value in json.loads(raw).items()}
'''

INPUTS = b'''from types import SimpleNamespace
def build_inputs(*args,source_directory,validator_sources):
    assert len(args)==6 and all(type(x)is bytes for x in args)
    assert source_directory=='/var/jb/usr/libexec/macws-swap-pair-controller-20261018'
    assert set(validator_sources)=={'process_retirement.py','cleanup_payload.py','reviewed_delivery_plan.json'}
    assert all(type(x)is bytes for x in validator_sources.values())
    return SimpleNamespace(checked=True)
'''

OBSERVER = b'''from macws_swap_pair import retained_cleanup,readonly_observer,retained_inputs
class Observer:
    def report(self):return {'synthetic_partial_witness':'raw-retained'}
def native_observer(inputs,dependency_sources):
    assert inputs.checked is True
    assert set(dependency_sources)=={'retained_cleanup.py','readonly_observer.py'}
    return Observer()
def capture_observation(observer):
    return {'capture_completed':True,'capture_only_not_cleanup_admission':True,
            'cleanup_authorized':False,'device_acceptance':False,
            'synthetic_full_witness':'both exact file copies',
            'observer_private':observer.report()}
'''


def entries():
    data = {'evidence.' + name: name.encode() for name in EVIDENCE}
    data.update({'source.' + name: b'# synthetic inert source\n' for name in SOURCES})
    data['source.reviewed_delivery_plan.json'] = b'{}'
    data['source.retained_inputs.py'] = INPUTS
    data['source.retained_observer.py'] = OBSERVER
    return data


def render(capture=True, *, data=None, codec=CODEC, pins=None, values=None, quick=False):
    data = entries() if data is None else data
    raw = json.dumps({key: base64.b64encode(value).decode('ascii')
                      for key, value in data.items()}, sort_keys=True, separators=(',', ':')).encode()
    replacements = {'__CODEC_B64__': repr(base64.b64encode(codec).decode('ascii')),
                    '__CODEC_SHA__': repr(sha(codec)),
                    '__FRAME_B64__': repr(base64.b64encode(raw).decode('ascii')),
                    '__FRAME_SHA__': repr(sha(raw)),
                    '__ENTRY_PINS__': repr({key: sha(value) for key, value in data.items()}
                                           if pins is None else pins),
                    '__CAPTURE__': repr(capture)}
    if values:
        replacements.update(values)
    result = TEMPLATE.read_text()
    for token, value in replacements.items():
        if result.count(token) != 1:
            raise AssertionError('template token count')
        result = result.replace(token, value)
    if quick:
        if result.count('HARD_SECONDS = 12') != 1:
            raise AssertionError('fixed reviewed deadline')
        result = result.replace('HARD_SECONDS = 12', 'HARD_SECONDS = 0.05')
    return result


def run(script, prefix='', timeout=4):
    result = subprocess.run([sys.executable, '-I', '-c', prefix + script],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    parsed = json.loads(result.stdout) if result.stdout else None
    return result, parsed


class RetainedWorkerTests(unittest.TestCase):
    def test_exact_once_placeholders_and_twelve_second_deadline(self):
        raw = TEMPLATE.read_text()
        for token in TOKENS:
            self.assertEqual(raw.count(token), 1)
        self.assertEqual(raw.count('HARD_SECONDS = 12'), 1)
        ast.parse(render())

    def test_metadata_default_does_not_decode_or_execute_any_helper(self):
        result, value = run(render(False, codec=b'raise RuntimeError("must not execute")',
            values={'__CODEC_B64__': 'None', '__CODEC_SHA__': 'None',
                    '__FRAME_B64__': 'None', '__FRAME_SHA__': 'None', '__ENTRY_PINS__': 'None'}))
        self.assertEqual(result.returncode, 0)
        self.assertTrue(value['default_inert'])
        self.assertEqual(value['stage'], 'metadata_only')
        self.assertEqual(value['helper_modules_executed'], [])
        self.assertIsNone(value['codec_sha256'])
        self.assertFalse(value['native_backend_construction_attempted'])

    def test_nonboolean_mode_refuses_before_decode(self):
        for mode in (1, 0, 'True', None):
            with self.subTest(mode=mode):
                result, value = run(render(mode))
                self.assertEqual(result.returncode, 1)
                self.assertEqual(value['worker_refusal_category'], 'explicit_boolean_capture')
                self.assertEqual(value['helper_modules_executed'], [])

    def test_success_is_read_only_and_exact_dependency_order(self):
        result, value = run(render())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(value['capture_completed'])
        self.assertFalse(value['cleanup_authorized'])
        self.assertFalse(value['device_acceptance'])
        self.assertFalse(value['original_ownership_recovered'])
        self.assertEqual(value['helper_modules_executed'],
                         ['retained_cleanup', 'readonly_observer', 'retained_inputs', 'retained_observer'])
        self.assertEqual(value['entry_sha256'], {key: sha(raw) for key, raw in entries().items()})
        self.assertEqual(value['capture_report_private']['synthetic_full_witness'], 'both exact file copies')

    def test_bad_codec_pin_refuses_before_codec_exec(self):
        result, value = run(render(codec=b'raise SystemExit(99)', values={'__CODEC_SHA__': repr('0'*64)}))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(value['worker_refusal_category'], 'literal_sha256_mismatch')
        self.assertEqual(value['helper_modules_executed'], [])

    def test_bad_frame_pin_refuses_before_codec_exec(self):
        result, value = run(render(codec=b'raise SystemExit(99)', values={'__FRAME_SHA__': repr('0'*64)}))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(value['worker_refusal_category'], 'literal_sha256_mismatch')

    def test_canonical_base64_and_size_boundaries(self):
        for token, value in (('__CODEC_B64__', repr('YQ==\n')), ('__FRAME_B64__', repr('YQ= =')),
                             ('__CODEC_B64__', repr('A' * 44000)), ('__CODEC_SHA__', repr('A' * 64))):
            with self.subTest(token=token, value=value[:30]):
                result, parsed = run(render(values={token: value}))
                self.assertEqual(result.returncode, 1)
                self.assertEqual(parsed['helper_modules_executed'], [])
                self.assertFalse(parsed['native_backend_construction_attempted'])

    def test_all_entry_pins_verified_before_first_helper_exec(self):
        data = entries()
        data['source.retained_cleanup.py'] = b'raise SystemExit(99)'
        pins = {key: sha(raw) for key, raw in data.items()}
        pins['evidence.snapshot'] = '0' * 64
        result, value = run(render(data=data, pins=pins))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(value['stage'], 'all_entries')
        self.assertEqual(value['worker_refusal_category'], 'decoded_entry_sha256_mismatch')
        self.assertEqual(value['helper_modules_executed'], [])

    def test_exact_thirteen_pin_and_decoded_entry_names(self):
        original = entries()
        for data, pins in ((original, {}), (dict(original, extra=b'extra'), None),
                           ({key: raw for key, raw in original.items() if key != 'evidence.host'}, None)):
            with self.subTest(keys=list(data)):
                result, value = run(render(data=data, pins=pins))
                self.assertEqual(result.returncode, 1)
                self.assertEqual(value['worker_refusal_category'], 'exact_entry_pin_schema')
        codec = CODEC.replace(b'for key,value in json.loads(raw).items()',
                             b'for key,value in json.loads(raw).items() if key!="evidence.host"')
        result, value = run(render(codec=codec))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(value['worker_refusal_category'], 'exact_decoded_entry_schema')

    def test_ambient_package_and_codec_namespaces_refuse(self):
        for name in ('macws_swap_pair', 'macws_swap_pair.retained_cleanup',
                     '_macws_retained_frame_worker_v1'):
            with self.subTest(name=name):
                prefix = 'import sys,types\nsys.modules[' + repr(name) + ']=types.ModuleType(' + repr(name) + ')\n'
                result, value = run(render(), prefix)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(value['worker_refusal_category'], 'ambient_module_namespace_conflict')
                self.assertEqual(value['helper_modules_executed'], [])

    def test_inputs_refusal_never_attempts_native_factory(self):
        data = entries()
        data['source.retained_inputs.py'] = b'def build_inputs(*args,**kwargs):raise ValueError("synthetic")'
        result, value = run(render(data=data))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(value['stage'], 'historical_lineage')
        self.assertFalse(value['native_backend_construction_attempted'])
        self.assertEqual(value['worker_error_category'], 'ValueError')

    def test_negative_capture_retains_full_partial_report(self):
        data = entries()
        data['source.retained_observer.py'] = OBSERVER.replace(b"'capture_completed':True", b"'capture_completed':False")
        result, value = run(render(data=data))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(value['stage'], 'capture_refused')
        self.assertEqual(value['capture_report_private']['observer_private'],
                         {'synthetic_partial_witness': 'raw-retained'})
        self.assertFalse(value['capture_report_omitted'])

    def test_unexpected_capture_error_retains_observer_partial(self):
        data = entries()
        data['source.retained_observer.py'] = OBSERVER.replace(b'def capture_observation(observer):',
            b'def capture_observation(observer):\n    raise RuntimeError("synthetic")')
        result, value = run(render(data=data))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(value['observer_partial_private'], {'synthetic_partial_witness': 'raw-retained'})
        self.assertEqual(value['worker_error_category'], 'RuntimeError')

    def test_result_cannot_promote_cleanup_authorization(self):
        data = entries()
        data['source.retained_observer.py'] = OBSERVER.replace(b"'cleanup_authorized':False", b"'cleanup_authorized':True")
        result, value = run(render(data=data))
        self.assertEqual(result.returncode, 1)
        self.assertFalse(value['capture_completed'])
        self.assertFalse(value['cleanup_authorized'])
        self.assertEqual(value['worker_refusal_category'], 'read_only_capture_result_schema')
        self.assertTrue(value['capture_report_private']['cleanup_authorized'])

    def test_oversized_output_is_explicit_negative_without_truncation(self):
        data = entries()
        data['source.retained_observer.py'] = OBSERVER.replace(
            b"'synthetic_full_witness':'both exact file copies'", b"'synthetic_full_witness':'x'*(4*1024*1024)")
        result, value = run(render(data=data))
        self.assertEqual(result.returncode, 1)
        self.assertTrue(value['capture_report_omitted'])
        self.assertTrue(value['output_limit_exceeded'])
        self.assertFalse(value['full_current_native_wire_witness'])
        self.assertFalse(value['capture_completed'])
        self.assertLess(len(result.stdout), 4096)

    def test_hard_self_exit_is_armed_before_decode(self):
        result, value = run(render(codec=b'import time\ndef decode(raw,pins):time.sleep(5)', quick=True))
        self.assertEqual(result.returncode, 124)
        self.assertIsNone(value)

    def test_actual_reviewed_twelve_second_self_deadline(self):
        # The unmodified reviewed constant is exercised in our own disposable
        # host child; no native factory, filesystem helper or device is reached.
        result, value = run(render(codec=b'import time\ndef decode(raw,pins):time.sleep(30)'), timeout=17)
        self.assertEqual(result.returncode, 124)
        self.assertIsNone(value)

    def test_actual_alarm_remains_armed_during_stdout_flush(self):
        prefix = ('import sys,signal\n'
                  'original_stdout=sys.stdout\n'
                  'class CheckFlush:\n'
                  ' def write(self,value):return original_stdout.write(value)\n'
                  ' def flush(self):\n'
                  '  if signal.getitimer(signal.ITIMER_REAL)[0]<=0:raise RuntimeError("timer not armed")\n'
                  '  return original_stdout.flush()\n'
                  'sys.stdout=CheckFlush()\n')
        # Python performs another finalizer flush after worker disarms the
        # timer. Avoid checking that unrelated shutdown flush a second time.
        prefix = prefix.replace('  return original_stdout.flush()\n',
                                '  sys.stdout=original_stdout\n  return original_stdout.flush()\n')
        result, value = run(render(), prefix)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(value['capture_completed'])

    def test_hard_self_exit_covers_helper_exec(self):
        data = entries()
        data['source.retained_cleanup.py'] = b'import time\ntime.sleep(5)'
        result, value = run(render(data=data, quick=True))
        self.assertEqual(result.returncode, 124)
        self.assertIsNone(value)

    def test_hard_self_exit_covers_output_serialization(self):
        prefix = ('import json,time\n'
                  'class SlowEncoder:\n'
                  ' def __init__(self,*args,**kwargs):pass\n'
                  ' def iterencode(self,value):time.sleep(5);return iter([])\n'
                  'json.JSONEncoder=SlowEncoder\n')
        result, value = run(render(quick=True), prefix)
        self.assertEqual(result.returncode, 124)
        self.assertIsNone(value)

    def test_hard_self_exit_covers_output_write_and_flush(self):
        for method in ('write', 'flush'):
            with self.subTest(method=method):
                prefix = ('import sys,time\n'
                          'class SlowOutput:\n'
                          ' def write(self,value):' + ('time.sleep(5)' if method == 'write' else 'pass') + '\n'
                          ' def flush(self):' + ('time.sleep(5)' if method == 'flush' else 'pass') + '\n'
                          'sys.stdout=SlowOutput()\n')
                result, value = run(render(quick=True), prefix)
                self.assertEqual(result.returncode, 124)
                self.assertIsNone(value)

    def test_template_contains_no_existing_workload_action(self):
        tree = ast.parse(render())
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    calls.append(node.func.attr)
                elif isinstance(node.func, ast.Name):
                    calls.append(node.func.id)
        self.assertFalse({'kill', 'killpg', 'unlink', 'rmdir', 'remove', 'Cleaner', 'Popen',
                          'observe_or_retire', 'bootstrap', 'resume'} & set(calls))


if __name__ == '__main__':
    unittest.main()
