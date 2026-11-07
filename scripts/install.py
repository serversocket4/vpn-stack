#!/usr/bin/env python3
"""Install code and a private prepared runtime onto a FRESH exit server.

This script never replaces existing target files, changes firewall rules, or
starts/enables services. Install official external binaries first. --root copies
to an isolated filesystem fixture and never runs useradd, pip, or systemctl.
"""
from __future__ import annotations

import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys

PROJECT = Path(__file__).resolve().parents[1]
REQUIRED = ('etc/bvpn/config.json','etc/bvpn/server','etc/bvpn-admin/env',
            'etc/caddy/Caddyfile','usr/local/etc/xray/config.json',
            'etc/hysteria/config.yaml','etc/telemt/telemt.toml','root/bvpn-kits/owner/6-tls.txt')


def files_below(root: Path):
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('symlink in installation source')
        if path.is_file():
            yield path


def plan(runtime: Path) -> list[tuple[Path,str,int]]:
    if runtime == PROJECT or PROJECT in runtime.parents:
        raise ValueError('private runtime must be outside the source repository')
    if not runtime.is_dir() or any(not (runtime/p).is_file() for p in REQUIRED):
        raise ValueError('runtime is incomplete; use scripts/prepare.py first')
    config=json.loads((runtime/'etc/bvpn/config.json').read_text())
    if config.get('kits')!='/root/bvpn-kits' or config.get('server_id')!='nl':
        raise ValueError('unsupported runtime paths/identity')
    todo=[]
    for base,dest in [('admin','opt/bvpn-admin/admin'),('backend','usr/local/lib/bvpn'),
                      ('bin','usr/local/sbin'),('deploy/systemd','etc/systemd/system'),
                      ('deploy/polkit','etc/polkit-1/rules.d')]:
        for path in files_below(PROJECT/base):
            if '__pycache__' in path.parts or path.suffix=='.pyc':
                continue
            mode=0o755 if base=='bin' else 0o644
            todo.append((path,str(Path(dest)/path.relative_to(PROJECT/base)),mode))
    for path in files_below(runtime):
        relative=path.relative_to(runtime).as_posix()
        if relative=='RUNTIME-PRIVATE.txt':
            continue
        if not relative.startswith(('etc/bvpn/','etc/bvpn-admin/','etc/caddy/',
                                   'etc/hysteria/','etc/telemt/','etc/systemd/system/',
                                   'usr/local/etc/xray/','root/bvpn-kits/')):
            raise ValueError('unexpected private runtime path')
        todo.append((path,relative,stat.S_IMODE(path.stat().st_mode)))
    paths=[row[1] for row in todo]
    if len(paths)!=len(set(paths)):
        raise ValueError('duplicate target in installation plan')
    return todo


def run(*args):
    subprocess.run(args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def ensure_group(name):
    try:return grp.getgrnam(name).gr_gid
    except KeyError:
        run('groupadd','--system',name)
        return grp.getgrnam(name).gr_gid


def install_venv(directory: Path,requirements: Path):
    # The service runs as bvpn-admin. Its root-owned code/venv must be readable
    # and traversable; the surrounding installer keeps private runtime files 077.
    previous=os.umask(0o022)
    try:
        run('python3','-m','venv',str(directory))
        run(str(directory/'bin/pip'),'install','-r',str(requirements))
    finally:
        os.umask(previous)


def execute(runtime: Path,root: Path,dry_run=False):
    rows=plan(runtime)
    root=root.resolve()
    live=root==Path('/')
    if root==PROJECT or PROJECT in root.parents:
        raise ValueError('installation root must be outside the source repository')
    for _,relative,_ in rows:
        target=root/relative
        if target.exists() or target.is_symlink():
            raise ValueError('target already exists: '+relative)
        if any(p.is_symlink() for p in target.parents if p!=root.parent):
            raise ValueError('symlink in destination parents')
    if (root/'opt/bvpn-admin').exists() or (root/'var/lib/bvpn-admin/admin.db').exists():
        raise ValueError('an existing admin installation must be migrated manually')
    if dry_run:
        return {'dry_run':True,'files':len(rows),'live_target':live,'services_started':False}
    if live:
        if os.geteuid()!=0 or sys.platform!='linux':
            raise ValueError('live installation requires Linux root')
        missing=[x for x in ('xray','hysteria','telemt','caddy','python3','systemctl','qrencode','curl','openssl','nft','jq') if not shutil.which(x)]
        if missing:
            raise ValueError('install required upstream/system tools first: '+', '.join(missing))
        try:run('/usr/bin/python3','-I','-c','import yaml')
        except subprocess.CalledProcessError:
            raise ValueError('install the system python3-yaml package; backend does not use the admin venv') from None
        admin_gid=ensure_group('bvpn-admin');caddy_gid=ensure_group('caddy')
        try:caddy_uid=pwd.getpwnam('caddy').pw_uid
        except KeyError:
            run('useradd','--system','--gid','caddy','--home-dir','/var/lib/caddy','--shell','/usr/sbin/nologin','caddy')
            caddy_uid=pwd.getpwnam('caddy').pw_uid
        try:admin_uid=pwd.getpwnam('bvpn-admin').pw_uid
        except KeyError:
            run('useradd','--system','--gid','bvpn-admin','--home-dir','/var/lib/bvpn-admin','--shell','/usr/sbin/nologin','bvpn-admin')
            admin_uid=pwd.getpwnam('bvpn-admin').pw_uid
    else:
        admin_uid=admin_gid=caddy_gid=os.getuid()
        caddy_uid=os.getuid()
    dirs={
        'opt/bvpn-admin':(0o755,0,0),'usr/local/lib/bvpn':(0o755,0,0),
        'etc/caddy':(0o755,0,caddy_gid),'var/lib/caddy':(0o750,caddy_uid,caddy_gid),
        'etc/bvpn':(0o755,0,0),'etc/bvpn-admin':(0o700,0,0),'etc/bvpn/tls':(0o750,0,caddy_gid),
        'var/lib/bvpn-admin':(0o700,admin_uid,admin_gid),'var/lib/bvpn':(0o755,0,0),
        'var/lib/bvpn/results':(0o755,0,0),'var/lib/bvpn/pending':(0o700,0,0),
        'var/lib/bvpn-outbox':(0o2770,0,admin_gid),'var/lib/bvpn-proposals':(0o2770,0,admin_gid),
        'var/lib/bvpn-kits':(0o2770,0,admin_gid),'var/lib/bvpn-monitor':(0o750,0,admin_gid),
        'var/lib/bvpn-sub':(0o750,0,caddy_gid),'var/lib/bvpn-sub/meta':(0o750,0,caddy_gid),
        'var/lib/bvpn-sub/tg':(0o750,0,caddy_gid),'var/lib/bvpn-checks':(0o2770,0,caddy_gid),
        'root/bvpn-kits':(0o700,0,0),'etc/telemt':(0o700,0,0),'etc/hysteria':(0o700,0,0)}
    for relative,(mode,uid,gid) in dirs.items():
        target=root/relative;target.mkdir(parents=True,exist_ok=True);target.chmod(mode)
        if live:os.chown(target,uid,gid)
    for source,relative,mode in rows:
        target=root/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,target);target.chmod(mode)
        if live and relative in ('etc/systemd/system/xray.service','etc/systemd/system/hysteria-server.service',
                                 'etc/systemd/system/telemt.service','etc/systemd/system/caddy.service'):
            text=target.read_text()
            for binary in ('xray','hysteria','telemt','caddy'):
                text=text.replace('/usr/local/bin/'+binary,shutil.which(binary) or '/usr/local/bin/'+binary)
            target.write_text(text);target.chmod(mode)
        if relative.startswith('etc/bvpn/tls/'):
            target.chmod(0o640)
            if live:os.chown(target,0,caddy_gid)
    for relative in ('opt/bvpn-admin/admin','usr/local/lib/bvpn'):
        base=root/relative
        for directory in [base,*[p for p in base.rglob('*') if p.is_dir()]]:
            directory.chmod(0o755)
    if live:
        install_venv(Path('/opt/bvpn-admin/venv'),PROJECT/'requirements.txt')
        run('systemctl','daemon-reload')
    return {'installed':True,'files':len(rows),'live_target':live,'services_started':False}


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,required=True)
    parser.add_argument('--root',type=Path,default=Path('/'))
    parser.add_argument('--dry-run',action='store_true')
    args=parser.parse_args()
    try:result=execute(args.runtime.resolve(),args.root,args.dry_run)
    except (ValueError,OSError,subprocess.SubprocessError) as error:
        parser.exit(1,'install: '+str(error)+'\n')
    print(json.dumps(result))


if __name__=='__main__':main()
