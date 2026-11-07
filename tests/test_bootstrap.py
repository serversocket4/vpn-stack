"""Installation safety checks; no system users, services, or network access."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

PROJECT=Path(__file__).resolve().parents[1]


def module(name):
    spec=importlib.util.spec_from_file_location('bootstrap_'+name,PROJECT/'scripts'/f'{name}.py')
    result=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


INSTALL=module('install')
PREPARE=module('prepare')
RELAY=module('relay')


class BootstrapSafety(unittest.TestCase):
    def make_runtime(self,root):
        runtime=root/'runtime';runtime.mkdir()
        for relative in INSTALL.REQUIRED:
            path=runtime/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('{}\n')
        (runtime/'etc/bvpn/config.json').write_text(json.dumps({'kits':'/root/bvpn-kits','server_id':'nl'}))
        for name in ('site.crt','site.key'):
            path=runtime/'etc/bvpn/tls'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('test fixture\n')
        return runtime

    def test_dry_run_has_no_side_effects(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);runtime=self.make_runtime(root)
            result=INSTALL.execute(runtime,root/'target',True)
            self.assertTrue(result['dry_run'])
            self.assertFalse((root/'target').exists())

    def test_refuses_to_replace_existing_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);runtime=self.make_runtime(root)
            target=root/'target';existing=target/'etc/bvpn/server'
            existing.parent.mkdir(parents=True);existing.write_text('keep\n')
            with self.assertRaises(ValueError):INSTALL.execute(runtime,target)
            self.assertEqual(existing.read_text(),'keep\n')
            self.assertFalse((target/'opt/bvpn-admin').exists())

    def test_fixture_permissions_and_second_install_refusal(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);runtime=self.make_runtime(root);target=root/'target'
            self.assertTrue(INSTALL.execute(runtime,target)['installed'])
            self.assertEqual((target/'opt/bvpn-admin/admin').stat().st_mode&0o777,0o755)
            self.assertEqual((target/'etc/bvpn/tls/site.key').stat().st_mode&0o777,0o640)
            with self.assertRaises(ValueError):INSTALL.execute(runtime,target)

    def test_runtime_output_cannot_be_source_tree(self):
        with self.assertRaises(ValueError):PREPARE.private_output(PROJECT/'generated')

    def test_symlink_runtime_source_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);runtime=self.make_runtime(root)
            (runtime/'etc/bvpn/extra').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):INSTALL.plan(runtime)

    def test_relay_is_scoped_and_preserves_input(self):
        text=RELAY.render('203.0.113.10')
        self.assertNotIn('flush ruleset',text)
        self.assertIn('table inet bvpn_relay',text)
        self.assertIn('policy accept',text)
        self.assertIn('18443 dnat to 203.0.113.10:8443',text)
        self.assertNotIn('tcp dport 443 dnat',text)
        compile(RELAY.LOADER,'relay-loader','exec')

    def test_venv_creation_is_accessible_and_private_umask_is_restored(self):
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp)/'venv'
            def create(*args):
                if args[0]=='python3':
                    (directory/'bin').mkdir(parents=True)
                    (directory/'lib/site-packages').mkdir(parents=True)
            previous=os.umask(0o077)
            try:
                with mock.patch.object(INSTALL,'run',side_effect=create):
                    INSTALL.install_venv(directory,Path(temp)/'requirements.txt')
                self.assertEqual((directory/'bin').stat().st_mode&0o777,0o755)
                self.assertEqual((directory/'lib/site-packages').stat().st_mode&0o777,0o755)
                restored=os.umask(0o077)
                self.assertEqual(restored,0o077)
                with mock.patch.object(INSTALL,'run',side_effect=RuntimeError('test failure')):
                    with self.assertRaises(RuntimeError):
                        INSTALL.install_venv(directory,Path(temp)/'requirements.txt')
                self.assertEqual(os.umask(0o077),0o077)
            finally:
                os.umask(previous)


if __name__=='__main__':unittest.main()
