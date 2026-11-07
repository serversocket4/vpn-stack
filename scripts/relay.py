#!/usr/bin/env python3
"""Render a scoped RU relay tree for review; never apply firewall changes.

Only inet/bvpn_relay and ip/bvpn_relay_nat are managed. Host INPUT remains
accept; existing web/SSH services and all unrelated nftables tables are kept.
Review provider firewall, forwarding policy and port availability before use.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
import os
from pathlib import Path

PROJECT=Path(__file__).resolve().parents[1]


def render(nl_ip: str,xhttp_port: int=18443) -> str:
    address=ipaddress.ip_address(nl_ip)
    if address.version!=4 or address.is_loopback or address.is_multicast:
        raise ValueError('nl-ip must be an IPv4 address')
    if not 1024<=xhttp_port<=65535 or xhttp_port in (2083,8880,2222):
        raise ValueError('xhttp port is invalid or collides with another service')
    sets=[];counters=[];rules=[]
    operators=('mts','megafon','beeline','t2')
    for op in operators:
        sets.append(f'  set {op} {{ type ipv4_addr; flags interval; auto-merge; }}')
    for op in (*operators,'other'):
        for suffix in ('conn','down','up','tconn','tdown'):
            counters.append(f'  counter {op}_{suffix} {{}}')
        match=f'ip saddr @{op}' if op!='other' else ' '.join('ip saddr != @'+o for o in operators)
        down=match.replace('saddr','daddr')
        rules.extend([f'    ip daddr {{ {nl_ip} }} ct state new {match} counter name {op}_conn',
                      f'    ip daddr {{ {nl_ip} }} {match} counter name {op}_up',
                      f'    ip saddr {{ {nl_ip} }} {down} counter name {op}_down',
                      f'    meta l4proto tcp ip daddr {{ {nl_ip} }} ct state new {match} counter name {op}_tconn',
                      f'    meta l4proto tcp ip saddr {{ {nl_ip} }} {down} counter name {op}_tdown'])
    return '\n'.join(['table inet bvpn_relay {',*sets,*counters,
        '  chain input { type filter hook input priority filter; policy accept; }',
        '  chain forward {','    type filter hook forward priority filter; policy accept;',*rules,'  }','}',
        'table ip bvpn_relay_nat {','  chain prerouting {','    type nat hook prerouting priority dstnat;',
        f'    fib daddr type local tcp dport {{ 2083, 8880 }} dnat to {nl_ip}',
        f'    fib daddr type local udp dport {{ 443 }} dnat to {nl_ip}',
        f'    fib daddr type local tcp dport {xhttp_port} dnat to {nl_ip}:8443',
        f'    fib daddr type local udp dport 20000-40000 dnat to {nl_ip}:443','  }',
        '  chain postrouting {','    type nat hook postrouting priority srcnat;',
        f'    ip daddr {{ {nl_ip} }} masquerade random','  }','}',''])


LOADER='''#!/usr/bin/env python3
import fcntl,pathlib,subprocess,sys
tables=[('inet','bvpn_relay'),('ip','bvpn_relay_nat')]
with pathlib.Path('/run/bvpn-relay-forwarding.lock').open('a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 batch=[]
 for family,table in tables:
  if subprocess.run(['nft','list','table',family,table],capture_output=True).returncode==0:
   batch.append('delete table '+family+' '+table)
 if sys.argv[1]=='apply':
  batch.append(pathlib.Path('/etc/bvpn-relay-forwarding.nft').read_text())
 elif sys.argv[1]!='remove':
  raise SystemExit('unsupported action')
 if batch:
  text=chr(10).join(batch)+chr(10)
  subprocess.run(['nft','--check','-f','-'],input=text,text=True,check=True)
  subprocess.run(['nft','-f','-'],input=text,text=True,check=True)
'''
UNIT='''[Unit]
Description=VPN Stack RU forwarding
Wants=network-online.target
After=network-online.target nftables.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/sbin/sysctl -q -w net.ipv4.ip_forward=1
ExecStart=/usr/bin/python3 /usr/local/sbin/bvpn-relay-forwarding apply
ExecStop=/usr/bin/python3 /usr/local/sbin/bvpn-relay-forwarding remove
[Install]
WantedBy=multi-user.target
'''


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--nl-ip',required=True)
    p.add_argument('--xhttp-port',type=int,default=18443)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    try:
        nft=render(a.nl_ip,a.xhttp_port);output=a.output.expanduser().resolve()
        if output==PROJECT or PROJECT in output.parents or output.exists():
            raise ValueError('output must be a new directory outside the source repository')
        for relative,text,mode in [('etc/bvpn-relay-forwarding.nft',nft,0o600),
             ('usr/local/sbin/bvpn-relay-forwarding',LOADER,0o700),
             ('etc/systemd/system/bvpn-relay-forwarding.service',UNIT,0o644)]:
            target=output/relative;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            target.write_text(text);target.chmod(mode)
    except (ValueError,OSError) as error:p.exit(1,'relay: '+str(error)+'\n')
    print(json.dumps({'rendered':True,'applied':False,'owned_tables':['inet bvpn_relay','ip bvpn_relay_nat']}))


if __name__=='__main__':main()
