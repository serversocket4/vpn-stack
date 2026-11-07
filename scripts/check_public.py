#!/usr/bin/env python3
"""Check source files for deployment credentials and runtime artifacts.

Run before committing or publishing. Generated deployment files belong outside
the repository. Locally ignored build/runtime directories are skipped, but any
file tracked by Git is always inspected, including files in those directories.
Findings show a path, line and category; matched credential text is never shown.
This is a conservative preflight check, not a guarantee that all sensitive data
has been found. Review the files and Git history as well.
"""
from __future__ import annotations

import argparse
from collections import Counter
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

SKIP_DIRS = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', '.pytest_cache',
             '.mypy_cache', 'generated', 'runtime', 'dist', 'build', '.runtime'}
MAX_FILE_BYTES = 8 * 1024 * 1024
PRIVATE_SUFFIXES = {'.pem', '.key', '.p12', '.pfx', '.db', '.sqlite', '.sqlite3', '.log',
                    '.pcap', '.pcapng', '.zip', '.tar', '.gz', '.tgz', '.bak', '.dump'}
PRIVATE_NAMES = {'.env', 'authorized_keys', 'known_hosts', 'relay_known_hosts',
                 'settings.env', 'sub-tokens.json', 'sub-settings.json', 'relay-state.json',
                 'panel.json', 'sessions.json', 'snapshot.json'}
PUBLIC_DNS = {'1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112',
              '77.88.8.8', '77.88.8.1', '77.88.8.88', '77.88.8.2', '94.140.14.14', '94.140.15.15',
              '208.67.222.222', '208.67.220.220', '2606:4700:4700::1111', '2606:4700:4700::1001',
              '2001:4860:4860::8888', '2001:4860:4860::8844', '2620:fe::fe', '2620:fe::9'}
DOCUMENTATION_NETS = tuple(ipaddress.ip_network(value) for value in
                          ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32'))
EXAMPLE_UUIDS = {'00000000-0000-0000-0000-000000000000', '11111111-1111-1111-1111-111111111111',
                 '123e4567-e89b-12d3-a456-426614174000', '550e8400-e29b-41d4-a716-446655440000'}
PATTERNS = {
    'private-key': re.compile(r'-----BEGIN (?:[A-Z ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----'),
    'telegram-token': re.compile(r'(?<![\w-])\d{6,12}:[A-Za-z0-9_-]{30,50}(?![\w-])'),
    'jwt': re.compile(r'(?<![\w-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![\w-])'),
    'ssh-public-key': re.compile(r'\b(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/]{30,}={0,3}'),
    'url-credentials': re.compile(r'(?i)\b(?:https?|socks5?|ssh)://[^\s/"\'<>@]+:[^\s/"\'<>@]+@[^\s"\'<>]+'),
    'personal-home-path': re.compile(r'/(?:Users|home)/[A-Za-z0-9_.-]+(?:/[^\s\x00"\'<>]*)?'),
    'chat-or-owner-id': re.compile(r'''(?ix)["']?(?:[a-z0-9_]*(?:chat[_-]?ids?|owner[_-]?ids?|admin[_-]?ids?)[a-z0-9_]*)["']?\s*[:=]\s*[\[({]?\s*-?\d{5,16}\b'''),
}
UUID_PATTERN = re.compile(r'(?i)(?<![\w-])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![\w-])')
IPV4_PATTERN = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
IPV6_PATTERN = re.compile(r'(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.%]*(?![\w:])')
VPN_URI = re.compile(r'(?i)\b(?:vless|vmess|hysteria2?|hy2|trojan|ss)://([^\s"\'<>]+)')
SUBSCRIPTION_URI = re.compile(r'(?i)\bhttps?://[^\s/"\'<>]+/(?:s|sub|subscribe|subscription|invite)/([A-Za-z0-9_-]{16,})')
SECRET_LITERAL = re.compile(r'''(?ix)["']?(?:[a-z0-9_]*(?:token|password|passwd|secret|private[_-]?key|api[_-]?key)[a-z0-9_]*)["']?\s*[:=]\s*(["'])([A-Za-z0-9_+/:=.!@%?-]{16,})\1''')
ENV_SECRET = re.compile(r'(?m)^\s*(?:export\s+)?[A-Z0-9_]*(?:TOKEN|PASSWORD|PASSWD|SECRET|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*([A-Za-z0-9_+/:=.!@%?-]{16,})\s*(?:#.*)?$')
PLACEHOLDER = re.compile(r'(?i)(?:example|replace|change[_ -]?me|your[_ -]|placeholder|dummy|redacted|'
                         r'^<[^>]+>$|^\$|^\{[A-Z_]+\}$|^x{6,}$|^0+$|^test(?:[-_]|$))')


def deployment_ip(value):
    try:
        address = ipaddress.ip_address(value.split('%', 1)[0])
    except ValueError:
        return False
    if str(address) in PUBLIC_DNS:
        return False
    if any(address.version == net.version and address in net for net in DOCUMENTATION_NETS):
        return False
    return not (address.is_loopback or address.is_unspecified or address.is_link_local
                or address.is_private or address.is_reserved or address.is_multicast)


def text_findings(text):
    for category, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            if category == 'personal-home-path' and match.group().startswith(('/home/example', '/home/USER')):
                continue
            yield category, text.count('\n', 0, match.start())+1
    for match in UUID_PATTERN.finditer(text):
        if match.group().lower() not in EXAMPLE_UUIDS:
            yield 'credential-uuid', text.count('\n', 0, match.start())+1
    for pattern in (IPV4_PATTERN, IPV6_PATTERN):
        for match in pattern.finditer(text):
            if deployment_ip(match.group()):
                yield 'deployment-ip', text.count('\n', 0, match.start())+1
    for match in VPN_URI.finditer(text):
        value = match.group(1)
        if not PLACEHOLDER.search(value) and ('@' in value or len(value) >= 20):
            yield 'vpn-client-link', text.count('\n', 0, match.start())+1
    for match in SUBSCRIPTION_URI.finditer(text):
        if not PLACEHOLDER.search(match.group(1)):
            yield 'subscription-link', text.count('\n', 0, match.start())+1
    for pattern, group in ((SECRET_LITERAL, 2), (ENV_SECRET, 1)):
        for match in pattern.finditer(text):
            value = match.group(group)
            entropy = -sum((n/len(value))*math.log2(n/len(value)) for n in Counter(value).values())
            if not PLACEHOLDER.search(value) and entropy >= 3.3:
                yield 'literal-secret', text.count('\n', 0, match.start())+1


def tracked_files(root):
    has_git_metadata = any((parent/'.git').exists() or (parent/'.git').is_symlink()
                           for parent in (root, *root.parents))
    try:
        result = subprocess.run(['git', '-C', str(root), 'ls-files', '-z', '--', '.'],
                                capture_output=True, timeout=10,
                                env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0'})
    except (OSError, subprocess.TimeoutExpired):
        if has_git_metadata:
            raise ValueError('Git index could not be inspected')
        return set()
    if result.returncode:
        if has_git_metadata:
            raise ValueError('Git index could not be inspected')
        return set()
    files = set()
    for raw in result.stdout.split(b'\x00'):
        if raw:
            candidate = root/os.fsdecode(raw)
            if '..' not in candidate.relative_to(root).parts:
                files.add(candidate)
    return files


def source_files(root, include_generated=False):
    files = tracked_files(root)
    skip = {'.git'} if include_generated else SKIP_DIRS
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            path = Path(directory)/name
            if path.is_symlink():
                files.add(path)
        dirs[:] = sorted(name for name in dirs if name not in skip and not (Path(directory)/name).is_symlink())
        files.update(Path(directory)/name for name in names)
    return sorted(files)


def check(root, include_generated=False):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('root must be a directory')
    findings = set()
    count = 0
    for path in source_files(root, include_generated):
        relative = path.relative_to(root).as_posix()
        if not path.exists() and not path.is_symlink():
            continue  # deleted but still present in Git's index
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            findings.add((relative, 0, 'symlink-or-special-file'))
            continue
        count += 1
        example = bool(re.search(r'(?:^|[._-])(?:example|template|sample)(?:[._-]|$)', path.name, re.I))
        if not example and (path.name.lower() in PRIVATE_NAMES or path.suffix.lower() in PRIVATE_SUFFIXES):
            findings.add((relative, 0, 'private-or-runtime-artifact'))
        if info.st_size > MAX_FILE_BYTES:
            findings.add((relative, 0, 'oversized-unreviewed-file'))
            continue
        try:
            text = path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            findings.add((relative, 0, 'binary-needs-review'))
            continue
        if '\x00' in text:
            findings.add((relative, 0, 'binary-needs-review'))
            continue
        for category, line in text_findings(text):
            findings.add((relative, line, category))
    return {'clean': not findings, 'files_scanned': count,
            'findings': [{'path': path, 'line': line, 'category': category}
                         for path, line, category in sorted(findings)]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--include-generated', action='store_true', help='also inspect untracked generated/runtime/build files')
    args = parser.parse_args()
    try:
        result = check(args.root, args.include_generated)
    except (OSError, ValueError):
        print(json.dumps({'clean': False, 'error': 'cannot complete publication audit'}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['clean'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
