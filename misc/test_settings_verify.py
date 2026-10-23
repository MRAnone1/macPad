import contextlib
import importlib.util
import io
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_boot_trust import macho, directory, trust, ROOT

sys.modules['macws_boot_trust'] = trust
SPEC = importlib.util.spec_from_file_location('settings_verify',
    ROOT / 'layout/usr/macOS/bin/macws_settings_verify.py')
settings = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(settings)


class SettingsVerification(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = Path(self.folder.name)
        self.extensions, self.carriers = root / 'Extensions', root / 'Carriers'
        self.bundle = self.extensions / 'Test.appex'
        self.contents = self.bundle / 'Contents'
        self.info = self.contents / 'Info.plist'
        self.info.parent.mkdir(parents=True)
        self.identifier = 'com.apple.TestSettings'
        self.info.write_bytes(plistlib.dumps({'CFBundleIdentifier': self.identifier,
            'CFBundleExecutable': 'Test', 'EXAppExtensionAttributes': {
                'EXExtensionPointIdentifier': 'com.apple.Settings.extension.ui'}}))
        self.carrier_id = 'com.macwsguide.settings-extension-carrier.' + self.identifier
        carrier = self.carriers / ('MacWSSettingsExtension-' + self.identifier + '.app')
        carrier.mkdir(parents=True)
        (carrier / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': self.carrier_id}))
        self.frameworks = self.contents / 'Frameworks'
        self.dependencies = [self.contents / 'MacOS/Test', carrier / 'SettingsExtensionProxy',
            self.frameworks / 'libmachook.dylib',
            self.frameworks / '.jbroot/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate',
            self.frameworks / 'libobjc-trampolines.dylib']
        self.base = [root / 'hook', root / 'substrate', root / 'trampolines']
        for path in self.dependencies + self.base:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(macho())
            path.chmod(0o755)
        # A host temporary file need not retain privileged mode bits. Model
        # only this invented carrier's mode; keep real file kind, owner,
        # contents, identity and every other path's complete stat unchanged.
        self.carrier_mode = 0o4755
        self.real_stat = os.stat
        carrier_path = str(self.dependencies[1])
        def fixture_stat(path, *args, **kwargs):
            info = self.real_stat(path, *args, **kwargs)
            if not isinstance(path, (str, os.PathLike)) or os.fspath(path) != carrier_path:
                return info
            fields = {name: getattr(info, name) for name in dir(info)
                      if name.startswith('st_')}
            fields['st_mode'] = (info.st_mode & ~0o7777) | self.carrier_mode
            return SimpleNamespace(**fields)
        active = patch.object(settings.os, 'stat', side_effect=fixture_stat)
        active.start()
        self.addCleanup(active.stop)
        records, _, _ = trust.scan([str(path) for path in self.base + self.dependencies], {})
        marker = [settings.SCHEMA] + [settings.selected(records, str(path))
                                     for path in self.base + self.dependencies]
        (self.frameworks / '.macws-settings-runtime').write_text('|'.join(marker) + '\n')
        for name, value in (('EXTENSIONS', str(self.extensions)),
                            ('SETTINGS_PLUGINS', str(root / 'Settings.app/Contents/PlugIns')),
                            ('CARRIER_ROOT', str(self.carriers)),
                            ('BASE', [str(path) for path in self.base]),
                            ('MANIFEST', str(root / 'cache/hashes.json'))):
            active = patch.object(settings, name, value)
            active.start()
            self.addCleanup(active.stop)

    def verify(self, ui=None):
        ui = self.carrier_id + ' : /registered/path\n' if ui is None else ui
        with patch.object(settings.subprocess, 'run', return_value=
                subprocess.CompletedProcess([], 0, ui, '')), \
                patch.object(settings.trust, 'restore', return_value=(0, 'test')) as restore, \
                contextlib.redirect_stdout(io.StringIO()):
            settings.verify()
            self.assertEqual(restore.call_count, 1)

    def test_complete_real_signature_verification_passes(self):
        physical = self.real_stat(self.dependencies[1])
        modeled = settings.os.stat(self.dependencies[1])
        self.assertEqual(trust.identity(modeled), trust.identity(physical))
        self.assertEqual(modeled.st_uid, physical.st_uid)
        self.assertEqual(stat.S_IFMT(modeled.st_mode), stat.S_IFMT(physical.st_mode))
        self.assertEqual(modeled.st_mode & 0o7777, 0o4755)
        self.assertEqual(settings.os.stat(self.dependencies[2]),
                         self.real_stat(self.dependencies[2]))
        self.verify()
        self.verify()  # positive extraction cache also has to pass all checks

    def test_changed_dependency_rejected_even_same_boot(self):
        self.verify()
        self.dependencies[2].write_bytes(macho(codes=[directory(1)]))
        with self.assertRaisesRegex(ValueError, 'signature changed'):
            self.verify()

    def test_current_registration_required(self):
        with self.assertRaisesRegex(ValueError, 'not registered'):
            self.verify(ui='')

    def test_setuid_carrier_required(self):
        self.carrier_mode = 0o755
        self.assertFalse(settings.os.stat(self.dependencies[1]).st_mode & stat.S_ISUID)
        with self.assertRaisesRegex(ValueError, 'setuid'):
            self.verify()

    def test_marker_and_base_dependency_must_match(self):
        self.base[0].write_bytes(macho(codes=[directory(1)]))
        with self.assertRaisesRegex(ValueError, 'signature changed'):
            self.verify()

    def test_missing_executable_name_requires_unique_image(self):
        info = plistlib.loads(self.info.read_bytes())
        info.pop('CFBundleExecutable')
        self.info.write_bytes(plistlib.dumps(info))
        self.verify()
        (self.contents / 'MacOS/Another').write_bytes(macho())
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            self.verify()

    def test_other_extensions_cannot_satisfy_readiness(self):
        info = plistlib.loads(self.info.read_bytes())
        info['EXAppExtensionAttributes']['EXExtensionPointIdentifier'] = 'other'
        self.info.write_bytes(plistlib.dumps(info))
        with self.assertRaisesRegex(ValueError, 'no Settings'):
            self.verify()

    def test_embedded_settings_pane_must_be_prepared(self):
        contents = Path(settings.SETTINGS_PLUGINS) / 'GeneralSettings.appex/Contents'
        contents.mkdir(parents=True)
        info = plistlib.loads(self.info.read_bytes())
        info['CFBundleIdentifier'] = 'com.apple.systempreferences.GeneralSettings'
        (contents / 'Info.plist').write_bytes(plistlib.dumps(info))
        with self.assertRaises(FileNotFoundError):
            self.verify()  # 48 external panes cannot hide the missing 49th.

    def test_embedded_non_settings_plugin_is_untouched(self):
        contents = Path(settings.SETTINGS_PLUGINS) / 'csimporter.appex/Contents'
        contents.mkdir(parents=True)
        (contents / 'Info.plist').write_bytes(plistlib.dumps({
            'EXAppExtensionAttributes': {'EXExtensionPointIdentifier': 'spotlight'}}))
        self.verify()


if __name__ == '__main__':
    unittest.main()
