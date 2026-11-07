#!/usr/bin/env python3
"""Generate a new private installation tree, never inside the source repository.

Requires xray and openssl in PATH. Existing certificates must cover the exit IP
and be trusted by devices; certificate issuance/renewal is deliberately external.
No network calls, server changes, downloads, or credentials printed to stdout.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import urllib.parse
import uuid

PROJECT = Path(__file__).resolve().parents[1]


def private_output(path: Path) -> Path:
    path = path.expanduser().resolve()
    if path == PROJECT or PROJECT in path.parents:
        raise ValueError('runtime output must be outside the source repository')
    if path.exists():
        raise ValueError('output already exists; choose an empty new path')
    return path


def settings(path: Path) -> dict:
    data = json.loads(path.read_text())
    for key in ('ip', 'relay_ip'):
        address = ipaddress.ip_address(data[key])
        if address.version != 4 or address.is_loopback or address.is_multicast:
            raise ValueError(key+' must be an IPv4 address')
    if data['ip'] == data['relay_ip']:
        raise ValueError('exit and relay must be different servers')
    if not re.fullmatch(r'[A-Za-z0-9 ._-]{1,60}', data.get('brand', '')):
        raise ValueError('brand: use 1..60 ASCII letters, numbers, spaces, dots, underscores or hyphens')
    if not re.fullmatch(r'[^\s=\r\n]+@[^\s=\r\n]+', data.get('owner_email', '')):
        raise ValueError('owner_email is invalid')
    if not re.fullmatch(r'[0-9]+:[A-Za-z0-9_-]+', data.get('bot_token', '')):
        raise ValueError('replace bot_token with your own BotFather token')
    if not isinstance(data.get('chat_id'), int) or data['chat_id'] <= 0:
        raise ValueError('chat_id must be your positive personal Telegram user/chat ID')
    for key in ('reality_server_name', 'telegram_tls_domain'):
        data.setdefault(key, 'www.microsoft.com')
        if not re.fullmatch(r'[a-zA-Z0-9.-]+', data[key]):
            raise ValueError(key+' must be a hostname')
    data.setdefault('relay_xhttp_port', 18443)
    if not isinstance(data['relay_xhttp_port'], int) or not 1024 <= data['relay_xhttp_port'] <= 65535:
        raise ValueError('relay_xhttp_port must be 1024..65535')
    if data['relay_xhttp_port'] in (2083, 8880, 2222):
        raise ValueError('relay_xhttp_port collides with another service')
    return data


def write(root: Path, path: str, text: str, mode: int = 0o600) -> None:
    target = root/path.lstrip('/')
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.write_text(text)
    target.chmod(mode)


def run(args: list[str]) -> str:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if proc.returncode:
        raise RuntimeError(args[0]+' failed; no installation files applied')
    return proc.stdout


def reality_keys() -> tuple[str, str]:
    output = run(['xray', 'x25519'])
    def pick(labels):
        for line in output.splitlines():
            key, sep, value = line.partition(':')
            if sep and key.strip().lower().replace(' ', '') in labels:
                return value.strip()
        raise RuntimeError('unrecognized xray x25519 output')
    return pick({'privatekey'}), pick({'publickey', 'password', 'password(publickey)'})


def service(binary: str, args: str) -> str:
    return ('[Unit]\nDescription=VPN Stack '+binary+'\nAfter=network-online.target\nWants=network-online.target\n'
            '\n[Service]\nType=simple\nExecStart=/usr/local/bin/'+binary+' '+args+'\n'
            'Restart=on-failure\nRestartSec=3\nLimitNOFILE=1048576\nUMask=0077\n'
            '\n[Install]\nWantedBy=multi-user.target\n')


def generate(data: dict, output: Path, cert: Path, key: Path) -> None:
    if not cert.is_file() or not key.is_file():
        raise ValueError('site certificate/key must be existing regular files')
    # Check address coverage and certificate/key correspondence before generating anything.
    certificate_text = run(['openssl', 'x509', '-in', str(cert), '-noout', '-text'])
    if data['ip'] not in re.findall(r'IP Address:([0-9.]+)', certificate_text):
        raise ValueError('site certificate does not cover the exit IP')
    cert_pub = run(['openssl', 'x509', '-in', str(cert), '-noout', '-pubkey'])
    key_pub = run(['openssl', 'pkey', '-in', str(key), '-pubout'])
    if cert_pub != key_pub:
        raise ValueError('site certificate and private key do not match')
    private, public = reality_keys()
    users = {name: {'uuid': str(uuid.uuid4()), 'hy': secrets.token_hex(16), 'tg': secrets.token_hex(16)}
             for name in ('owner', 'monitoring')}
    short_id, xhttp_path = secrets.token_hex(8), '/'+secrets.token_urlsafe(18)
    hy_obfs, hy_stats = secrets.token_hex(16), secrets.token_hex(16)
    output.mkdir(mode=0o700, parents=True)
    try:
        ip, relay = data['ip'], data['relay_ip']
        config = {'server_id':'nl', 'title':'Нидерланды', 'label':'Нидерланды', 'flag':'🇳🇱',
                  'ip':ip, 'brand':data['brand'], 'sub_url':f'https://{ip}/', 'template':'owner',
                  'monitor_account':'monitoring', 'kits':'/root/bvpn-kits',
                  'tcp':{'tls':2083,'xhttp':8443,'telegram':8880}, 'hop':[20000,40000],
                  'relay_tcp_alt':{str(data['relay_xhttp_port']):8443}, 'relay_preserve_services':True}
        write(output,'etc/bvpn/config.json',json.dumps(config,ensure_ascii=False,indent=2)+'\n',0o644)
        write(output,'etc/bvpn/server',f'ID=nl\nTITLE=Netherlands\nIP={ip}\nRU_IP=\nLINK_HOSTS={relay}\n',0o644)
        write(output,'etc/bvpn/people','owner|Owner\nmonitoring|Monitoring\n',0o644)
        write(output,'etc/bvpn/relay.json',json.dumps({'ip':relay,'servers':[],'history':[]})+'\n',0o644)
        write(output,'etc/bvpn/sub-tokens.json','{}\n')
        write(output,'etc/bvpn/sub-settings.json',json.dumps({'owner':{'routing':'all-but-ru'}})+'\n')
        env=(f'TELEGRAM_BOT_TOKEN={data["bot_token"]}\nTELEGRAM_CHAT_ID={data["chat_id"]}\n'
             f'OWNER_EMAIL={data["owner_email"]}\nPUBLIC_URL=https://{ip}:8444\nLISTEN_PORT=8092\n')
        write(output,'etc/bvpn-admin/env',env)
        cert_target=output/'etc/bvpn/tls/site.crt';cert_target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        shutil.copyfile(cert,cert_target);cert_target.chmod(0o600)
        shutil.copyfile(key,cert_target.with_name('site.key'));cert_target.with_name('site.key').chmod(0o600)
        # Xray's independent copy is compatible with the existing certificate checker.
        for suffix, source in [('crt',cert),('key',key)]:
            target=output/f'usr/local/etc/xray/tls/sub.{suffix}';target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            shutil.copyfile(source,target);target.chmod(0o600)
        clients=lambda suffix:[{'id':v['uuid'],'email':name+suffix,'level':0} for name,v in users.items()]
        xc={'log':{'loglevel':'warning'}, 'api':{'tag':'api','listen':'127.0.0.1:10085','services':['StatsService']},
            'stats':{},'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True,'statsUserOnline':True}}},
            'inbounds':[
              {'tag':'tls','listen':'0.0.0.0','port':2083,'protocol':'vless','settings':{'clients':clients('-tls'),'decryption':'none'},
               'streamSettings':{'network':'tcp','security':'tls','tlsSettings':{'alpn':['http/1.1'],'certificates':[{'certificateFile':'/usr/local/etc/xray/tls/sub.crt','keyFile':'/usr/local/etc/xray/tls/sub.key'}]}}},
              {'tag':'xhttp','listen':'0.0.0.0','port':8443,'protocol':'vless','settings':{'clients':clients('-xhttp'),'decryption':'none'},
               'streamSettings':{'network':'xhttp','security':'reality','realitySettings':{'target':data['reality_server_name']+':443','serverNames':[data['reality_server_name']],'privateKey':private,'shortIds':[short_id]},'xhttpSettings':{'path':xhttp_path,'mode':'auto'}}}],
            'outbounds':[{'tag':'direct','protocol':'freedom'},{'tag':'blocked','protocol':'blackhole'}],
            'routing':{'rules':[{'type':'field','ip':['0.0.0.0/8','127.0.0.0/8','10.0.0.0/8','172.16.0.0/12',
                    '192.168.0.0/16','169.254.0.0/16','::1/128','fc00::/7','fe80::/10'],'outboundTag':'blocked'}]}}
        write(output,'usr/local/etc/xray/config.json',json.dumps(xc,indent=2)+'\n')
        hy_dir=output/'etc/hysteria';hy_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
        hy_conf=hy_dir/'certificate.cnf'
        hy_conf.write_text('[req]\ndistinguished_name=dn\nx509_extensions=alt\n[dn]\n[alt]\nsubjectAltName=DNS:www.bing.com\n')
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','365',
             '-subj','/CN=www.bing.com','-config',str(hy_conf),
             '-keyout',str(hy_dir/'server.key'),'-out',str(hy_dir/'server.crt')])
        hy_conf.unlink()
        (hy_dir/'server.key').chmod(0o600);(hy_dir/'server.crt').chmod(0o600)
        hc=('listen: :443\ntls:\n  cert: /etc/hysteria/server.crt\n  key: /etc/hysteria/server.key\n'
            'auth:\n  type: userpass\n  userpass:\n'+''.join(f'    {n}: {v["hy"]}\n' for n,v in users.items())+
            f'obfs:\n  type: salamander\n  salamander:\n    password: {hy_obfs}\n'
            f'trafficStats:\n  listen: 127.0.0.1:9999\n  secret: {hy_stats}\n'
            'acl:\n  inline:\n    - reject(0.0.0.0/8)\n    - reject(127.0.0.0/8)\n    - reject(10.0.0.0/8)\n'
            '    - reject(172.16.0.0/12)\n    - reject(192.168.0.0/16)\n    - reject(169.254.0.0/16)\n'
            '    - reject(::1/128)\n    - reject(fc00::/7)\n    - reject(fe80::/10)\n    - direct(all)\n')
        write(output,'etc/hysteria/config.yaml',hc)
        tc=('[general]\nuse_middle_proxy = true\nlog_level = "normal"\n[general.modes]\nclassic = false\nsecure = false\ntls = true\n'
            f'[general.links]\npublic_host = "{relay}"\npublic_port = 8880\n'
            '[server]\nport = 8880\n[server.api]\nenabled = true\nlisten = "127.0.0.1:9091"\n'
            'whitelist = ["127.0.0.1/32"]\n[[server.listeners]]\nip = "0.0.0.0"\n'
            f'[censorship]\ntls_domain = "{data["telegram_tls_domain"]}"\nmask = true\ntls_emulation = true\n'
            '[access.users]\n'+''.join(f'{n} = "{v["tg"]}"\n' for n,v in users.items()))
        write(output,'etc/telemt/telemt.toml',tc)
        caddy=(f'https://{ip} {{\n  tls /etc/bvpn/tls/site.crt /etc/bvpn/tls/site.key\n'
               '  reverse_proxy 127.0.0.1:9446\n}\n'
               f'https://{ip}:8444 {{\n  tls /etc/bvpn/tls/site.crt /etc/bvpn/tls/site.key\n'
               '  reverse_proxy 127.0.0.1:8092 {\n'
               '    header_up X-Real-IP {remote_host}\n  }\n}\n')
        write(output,'etc/caddy/Caddyfile',caddy,0o644)
        for name,args in [('xray','run -config /usr/local/etc/xray/config.json'),('hysteria','server -c /etc/hysteria/config.yaml'),('telemt','/etc/telemt/telemt.toml')]:
            unit='hysteria-server' if name=='hysteria' else name
            write(output,'etc/systemd/system/'+unit+'.service',service(name,args),0o644)
        write(output,'etc/systemd/system/caddy.service',
              '[Unit]\nDescription=VPN Stack HTTPS front end\nAfter=network-online.target\nWants=network-online.target\n'
              '\n[Service]\nUser=caddy\nGroup=caddy\nWorkingDirectory=/var/lib/caddy\n'
              'Environment=HOME=/var/lib/caddy\n'
              'ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile\n'
              'ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile\n'
              'AmbientCapabilities=CAP_NET_BIND_SERVICE\nNoNewPrivileges=true\nRestart=on-failure\n'
              '\n[Install]\nWantedBy=multi-user.target\n',0o644)
        run(['openssl','x509','-in',str(hy_dir/'server.crt'),'-outform','DER','-out',str(hy_dir/'pin.der')])
        pin=hashlib.sha256((hy_dir/'pin.der').read_bytes()).hexdigest();(hy_dir/'pin.der').unlink()
        for name,values in users.items():
            kit='root/bvpn-kits/'+name+'/'
            def vless(port,query,title):
                return f'vless://{values["uuid"]}@{ip}:{port}?'+urllib.parse.urlencode(query)+'#'+urllib.parse.quote(title)+'\n'
            write(output,kit+'setup.txt','VPN Stack — '+name+'\n')
            write(output,kit+'6-tls.txt',vless(2083,{'encryption':'none','security':'tls','sni':ip,'fp':'ios','alpn':'http/1.1','type':'tcp'},'Запасной 1'))
            write(output,kit+'3-backup.txt',vless(8443,{'encryption':'none','security':'reality','sni':data['reality_server_name'],'fp':'chrome','pbk':public,'sid':short_id,'type':'xhttp','path':xhttp_path,'mode':'auto'},'Запасной 3'))
            hy=(f'hysteria2://{name}:{values["hy"]}@{ip}:443?'+urllib.parse.urlencode({'sni':'www.bing.com','pinSHA256':pin,'obfs':'salamander','obfs-password':hy_obfs})+'#'+urllib.parse.quote('Основной')+'\n')
            write(output,kit+'2-calls.txt',hy)
            tgsecret='ee'+values['tg']+data['telegram_tls_domain'].encode().hex()
            write(output,kit+'telegram-proxy.txt','tg://proxy?'+urllib.parse.urlencode({'server':relay,'port':8880,'secret':tgsecret})+'\n')
            base=PROJECT/'examples/routing.json'
            if base.exists():
                profile=json.loads(base.read_text())
                profile['Name']=data['brand']+' routing'
                routing='happ://routing/onadd/'+base64.b64encode(json.dumps(profile,ensure_ascii=False).encode()).decode()+'\n'
            else:
                routing=''
            write(output,kit+'routing.txt',routing)
        write(output,'RUNTIME-PRIVATE.txt','Private generated installation. Never commit or share this directory.\n')
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--site-cert',type=Path,required=True)
    parser.add_argument('--site-key',type=Path,required=True)
    args=parser.parse_args()
    try:
        generate(settings(args.settings),private_output(args.output),args.site_cert,args.site_key)
    except (ValueError,RuntimeError,OSError,subprocess.SubprocessError) as error:
        parser.exit(1,'prepare: '+str(error)+'\n')
    print('Private runtime prepared; no services or firewall rules were changed.')


if __name__=='__main__':
    main()
