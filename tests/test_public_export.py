"""Meaningful publication boundaries: credentials, generated files and Git's index."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid


SOURCE = Path(__file__).resolve().parents[1]/'scripts'/'check_public.py'
SPEC = importlib.util.spec_from_file_location('check_public', SOURCE)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class PublicExportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='vpn-public-export-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)/'repo'
        self.root.mkdir()

    def test_placeholders_and_documentation_addresses_are_clean(self):
        (self.root/'config.example.env').write_text(
            'VPN_IP=203.0.113.20\nRELAY_IP=198.51.100.10\n'
            'DNS=1.1.1.1\nBOT_TOKEN=YOUR_BOT_TOKEN\n'
            'CLIENT_ID=00000000-0000-0000-0000-000000000000\n')
        self.assertTrue(CHECK.check(self.root)['clean'])

    def test_source_credentials_are_detected_without_echoing_values(self):
        private_marker = '-----BEGIN '+ 'OPENSSH PRIVATE KEY-----'
        fake_token = str(123000000+456789)+':'+'AbCdEf0123456789_'*2
        credential_id = str(uuid.uuid4())
        fake_password = ''.join(chr(i) for i in range(65, 91))+str(1234*5678)
        (self.root/'unsafe.py').write_text('\n'.join((private_marker, fake_token, credential_id,
                                                    json.dumps({'PASSWORD': fake_password}))))
        result = CHECK.check(self.root)
        self.assertFalse(result['clean'])
        categories = {row['category'] for row in result['findings']}
        self.assertTrue({'private-key', 'telegram-token', 'credential-uuid', 'literal-secret'} <= categories)
        serialized = json.dumps(result)
        for secret in (private_marker, fake_token, credential_id, fake_password):
            self.assertNotIn(secret, serialized)

    def test_untracked_generated_files_are_ignored_but_explicit_audit_catches_them(self):
        generated = self.root/'generated'
        generated.mkdir()
        (generated/'client.txt').write_text(str(uuid.uuid4()))
        self.assertTrue(CHECK.check(self.root)['clean'])
        self.assertFalse(CHECK.check(self.root, include_generated=True)['clean'])

    def test_git_tracked_generated_secrets_are_never_ignored(self):
        if subprocess.run(['git', '--version'], capture_output=True).returncode:
            self.skipTest('Git is unavailable')
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True, capture_output=True)
        generated = self.root/'generated'
        generated.mkdir()
        (generated/'client.txt').write_text(str(uuid.uuid4()))
        subprocess.run(['git', '-C', str(self.root), 'add', 'generated/client.txt'], check=True, capture_output=True)
        self.assertFalse(CHECK.check(self.root)['clean'])

    def test_runtime_artifacts_and_symlinks_are_rejected(self):
        (self.root/'.env').write_text('TOKEN=not-a-real-token')
        (self.root/'users.sqlite3').write_bytes(b'SQLite format 3'+bytes([0]))
        (self.root/'linked').symlink_to(self.root/'.env')
        result = CHECK.check(self.root)
        categories = {row['category'] for row in result['findings']}
        self.assertTrue({'private-or-runtime-artifact', 'symlink-or-special-file', 'binary-needs-review'} <= categories)

    def test_unreadable_git_metadata_does_not_silently_skip_the_index(self):
        (self.root/'.git').mkdir()
        with self.assertRaises(ValueError):
            CHECK.check(self.root)

    def test_code_slices_are_not_mistaken_for_ipv6(self):
        (self.root/'app.py').write_text('pairs = zip(lines[::2], lines[1::2])\n')
        (self.root/'app.css').write_text('.meter.bad::-webkit-progress-value { color: red; }\n')
        self.assertTrue(CHECK.check(self.root)['clean'])


if __name__ == '__main__':
    unittest.main()
