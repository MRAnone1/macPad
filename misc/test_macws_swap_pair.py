"""Portable synthetic gates; no device, launchd, native API or candidate."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
DIRECTORY = HERE / 'macws_swap_pair'
spec = importlib.util.spec_from_file_location('macws_public_swap_support', DIRECTORY / 'runtime_support.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


def configuration():
    return {'operation': 'control_normal', 'arch': 'arm64', 'profile_sha256': 'a' * 64}


def synthetic_job(config):
    # Synthetic PID only. This fixture is not a copied native receipt.
    return ('user/501/' + s.CONTROL_LABEL + ' = {\n'
            '\tpath = ' + s.CONTROL_SCRATCH + '/job.plist\n'
            '\tprogram = ' + s.WRAPPER + '\n'
            '\targuments = {\n' + ''.join('\t\t' + word + '\n' for word in s.arguments(config)) + '\t}\n'
            '\tstdout path = ' + s.CONTROL_SCRATCH + '/probe.log\n'
            '\tstderr path = ' + s.CONTROL_SCRATCH + '/probe.log\n'
            '\tdomain = user/501\n\tpid = 4242\n}\n')


def backend_for(config, result):
    backend = object.__new__(s.RealBackend)
    backend.config = config
    backend.calls = []
    def command(argv, deadline):
        backend.calls.append(argv)
        return result
    backend.command = command
    return backend


class PublicSwapPairControls(unittest.TestCase):
    def test_default_cli_forbids_native_and_child_operations(self):
        child = '''import ctypes,os,pathlib,runpy,signal,subprocess,sys
def forbidden(*args,**kwargs):
    raise AssertionError("metadata default invoked an operation")
ctypes.CDLL=forbidden
os.kill=forbidden
subprocess.Popen=forbidden
signal.setitimer=forbidden
script=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(script.parent));sys.argv=[str(script)]
runpy.run_path(str(script),run_name="__main__")
'''
        result = subprocess.run([sys.executable, '-c', child, str(DIRECTORY / 'controller.py')],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        metadata = json.loads(result.stdout)
        self.assertEqual(metadata['schema'], 'macws.swap-pair.controller-source-preparation.v7')
        self.assertEqual(metadata['device_commands'], 0)
        self.assertIs(metadata['device_acceptance'], False)

    def test_job_query_uses_the_explicit_domain(self):
        config = configuration()
        backend = backend_for(config, (0, synthetic_job(config), ''))
        self.assertEqual(backend.job(100)['pid'], 4242)
        self.assertEqual(backend.calls, [[s.LAUNCHCTL, 'print', 'user/501/' + s.CONTROL_LABEL]])

    def test_redirected_domain_and_all_stderr_refuse(self):
        config = configuration(); text = synthetic_job(config)
        for result in [(0, text.replace('user/501/', 'system/', 1), ''),
                       (0, text, 'Warning: Please switch to another service identifier\n'),
                       (0, text, 'unrecognized output\n')]:
            with self.subTest(result=result), self.assertRaises(s.Refused):
                s.parsed_job(config, result)

    def test_absence_requires_exact_status_label_uid_and_empty_stdout(self):
        config = configuration()
        absent = 'Could not find service "' + s.CONTROL_LABEL + '" in domain for uid: 501\n'
        self.assertIsNone(s.parsed_job(config, (113, '', absent)))
        for result in [(1, '', absent), (False, '', absent), (113, 'extra', absent),
                       (113, '', absent.replace('501', '502')), (113, '', absent + 'extra'),
                       (113, '', absent.replace(s.CONTROL_LABEL, s.LABEL))]:
            with self.subTest(result=result), self.assertRaises(s.Refused):
                s.parsed_job(config, result)

    def test_foreign_duplicate_or_missing_owned_fields_refuse(self):
        config = configuration(); text = synthetic_job(config)
        changed = [text.replace('\tprogram = ' + s.WRAPPER, '\tprogram = /different/program'),
                   text.replace('\tdomain = user/501\n', ''),
                   text.replace('\tpid = 4242\n', '\tpid = 4242\n\tpid = 4243\n'),
                   text.replace('\tstdout path = ', '\tstdout path = /different'),
                   text.replace('\tstderr path = ', '\tstderr path = /different'),
                   text.replace('\tpath = ', '\tpath = /different'),
                   text.replace('\t\t--one-pair\n', '\t\t--different-operation\n'), text + text]
        for value in changed:
            with self.subTest(value=value), self.assertRaises(s.Refused):
                s.parsed_job(config, (0, value, ''))

    def test_other_label_query_uses_the_same_explicit_domain(self):
        absent = 'Could not find service "' + s.LABEL + '" in domain for uid: 501\n'
        backend = backend_for(configuration(), (113, '', absent))
        self.assertIs(backend.other_label_absent(100), True)
        self.assertEqual(backend.calls, [[s.LAUNCHCTL, 'print', 'user/501/' + s.LABEL]])

    def test_mutation_receipts_require_exact_quiet_success(self):
        s.launchctl_success((0, '', ''), 'quiet result')
        for result in [(1, '', ''), (False, '', ''), (0, 'output', ''), (0, '', 'warning')]:
            with self.subTest(result=result), self.assertRaises(s.Refused):
                s.launchctl_success(result, 'quiet result')


if __name__ == '__main__':
    unittest.main()
