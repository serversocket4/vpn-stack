#!/usr/bin/env python3
"""Bounded, read-only VPN probes and sanitized host samples for the dashboard.

The only persistent writes are this collector's latest/state files. Real VPN
probes start temporary clients on loopback and never restart live VPN services.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import fcntl
import grp
import importlib
import ipaddress
import json
import math
import os
import random
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

INTERVAL = 60
PROBE_TIMEOUT = 32
LATEST = Path('/var/lib/bvpn-monitor/latest.json')
STATE = Path('/var/lib/bvpn-monitor/state.json')
LOCK = Path('/run/bvpn-monitor.lock')
PROBE_META = {
    'primary': ('Основной', 'Hysteria2 · случайный hopping-порт'),
    'backup1': ('Запасной 1', 'VLESS · TCP/TLS'),
    'backup2': ('Запасной 2', 'Hysteria2 · фиксированный UDP-порт'),
    'backup3': ('Запасной 3', 'VLESS · XHTTP/REALITY'),
    'telegram': ('Telegram-прокси', 'TCP-доступность'),
    'ru_nl': ('RU → NL', 'ICMP'),
    'nl_exit': ('Интернет с NL', 'HTTPS'),
}
VPN_SCOPE = 'Серверная проверка NL → RU → NL → интернет; участок устройства не проверяется'
METRIC_KEYS = ('cpu_pct', 'steal_pct', 'load1', 'cpus', 'mem_available_mb', 'mem_total_mb',
               'disk_pct', 'uptime_s', 'rx_bytes', 'tx_bytes', 'rx_mbps', 'tx_mbps',
               'tcp_retrans_delta', 'tcp_out_delta', 'rx_dropped_delta', 'tx_dropped_delta',
               'rx_errors_delta', 'tx_errors_delta')

# Sent as stdin to python on RU through the already-installed root relay SSH key.
# No file is written on RU; no subscriber address or credential is read.
HOST_SOURCE = r'''
import json,os,pathlib,re,shutil,subprocess,sys,time
role=sys.argv[1]
peer=sys.argv[2] if len(sys.argv)>2 else ''
def read(p):
 try:return pathlib.Path(p).read_text()
 except OSError:return ''
mem=dict(re.findall(r'^(\w+):\s+(\d+) kB',read('/proc/meminfo'),re.M))
cpu=[int(x) for x in read('/proc/stat').splitlines()[0].split()[1:9]]
uptime=float(read('/proc/uptime').split()[0])
iface=''
for line in read('/proc/net/route').splitlines()[1:]:
 f=line.split()
 if len(f)>2 and f[1]=='00000000':iface=f[0];break
net={}
for key in ('rx_bytes','tx_bytes','rx_dropped','tx_dropped','rx_errors','tx_errors'):
 value=read('/sys/class/net/'+iface+'/statistics/'+key).strip()
 net[key]=int(value) if value.isdigit() else 0
tcp={}
lines=read('/proc/net/snmp').splitlines()
for a,b in zip(lines[::2],lines[1::2]):
 k=a.split();v=b.split()
 if k and k[0]=='Tcp:':tcp=dict(zip(k[1:],map(int,v[1:])))
du=shutil.disk_usage('/')
units=['ssh'] if role=='ru' else ['xray','hysteria-server','telemt','caddy','bvpn-admin']
services=[]
try:
 p=subprocess.run(['systemctl','is-active',*units],capture_output=True,text=True,timeout=3)
 states=p.stdout.splitlines()
 services=[{'id':u,'active':(states[i]=='active') if i<len(states) else False} for i,u in enumerate(units)]
except (OSError,subprocess.TimeoutExpired):services=[{'id':u,'active':False} for u in units]
out={'sample_at':time.time(),'cpu_ticks':cpu,'uptime_s':uptime,'load1':float(read('/proc/loadavg').split()[0]),
 'cpus':os.cpu_count() or 1,'mem_total_mb':int(mem.get('MemTotal',0))//1024,
 'mem_available_mb':int(mem.get('MemAvailable',0))//1024,
 'disk_pct':round(du.used/du.total*100,2) if du.total else 0,
 **net,'tcp_retrans':int(tcp.get('RetransSegs',0)),'tcp_out':int(tcp.get('OutSegs',0)),
 'services':services}
if peer:
 try:
  p=subprocess.run(['ping','-n','-c','3','-i','0.2','-W','1',peer],capture_output=True,text=True,timeout=4)
  out['ping_text']=p.stdout[-1500:]
 except (OSError,subprocess.TimeoutExpired):out['ping_text']=''
print(json.dumps(out,separators=(',',':')))
'''


def iso(value=None):
    return datetime.fromtimestamp(time.time() if value is None else value, timezone.utc).isoformat().replace('+00:00', 'Z')


def load_json(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {} if default is None else default


def modules():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    # Also permit validation from a closed staging directory before installation.
    sys.path.insert(0, '/usr/local/lib/bvpn')
    return importlib.import_module('vpnlib'), importlib.import_module('vpnjob')


def address(value):
    try:
        ip = ipaddress.ip_address(str(value))
        return str(ip) if ip.version == 4 and ip.is_global else ''
    except ValueError:
        return ''


def finite(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value if isinstance(value, int) or math.isfinite(value) else None


def parse_ping(text):
    """Linux ping summary only; the raw peer/address text is never published."""
    loss = re.search(r'([\d.]+)% packet loss', text or '')
    rtt = re.search(r'(?:rtt|round-trip)[^=]*=\s*[\d.]+/([\d.]+)/', text or '')
    return {'ok': bool(loss and rtt and float(loss[1]) < 100),
            'loss_pct': float(loss[1]) if loss else None,
            'latency_ms': float(rtt[1]) if rtt else None}


def probe_result(pid, *, ok=False, latency_ms=None, error=None, **extra):
    title, kind = PROBE_META[pid]
    scope = VPN_SCOPE if pid in ('primary', 'backup1', 'backup2', 'backup3') else {
        'ru_nl': 'ICMP с RU до NL; не задержка устройства',
        'nl_exit': 'HTTPS напрямую с NL до внешней контрольной цели',
        'telegram': 'TCP-подключение NL → RU → NL; MTProto и доставка сообщений не проверяются',
    }[pid]
    return {'id': pid, 'title': title, 'kind': kind, 'scope': scope, 'at': iso(),
            'ok': bool(ok), 'latency_ms': finite(latency_ms), 'loss_pct': None,
            'error': error, **extra}


def host_result(role, ip, raw, previous):
    metrics = {key: None for key in METRIC_KEYS}
    for key in ('load1', 'cpus', 'mem_available_mb', 'mem_total_mb', 'disk_pct', 'uptime_s', 'rx_bytes', 'tx_bytes'):
        metrics[key] = finite(raw.get(key))
    elapsed = (raw.get('sample_at', 0) or 0) - (previous.get('sample_at', 0) or 0)
    same_boot = bool(previous) and raw.get('uptime_s', 0) >= previous.get('uptime_s', 0)
    if same_boot and 0 < elapsed < 600:
        cur, old = raw.get('cpu_ticks') or [], previous.get('cpu_ticks') or []
        if len(cur) >= 8 and len(old) >= 8:
            delta = [max(0, a - b) for a, b in zip(cur[:8], old[:8])]
            total = sum(delta)
            if total:
                metrics['cpu_pct'] = round(100 * (total - delta[3] - delta[4]) / total, 2)
                metrics['steal_pct'] = round(100 * delta[7] / total, 2)
        for direction in ('rx', 'tx'):
            a, b = raw.get(direction + '_bytes'), previous.get(direction + '_bytes')
            if finite(a) is not None and finite(b) is not None and a >= b:
                metrics[direction + '_mbps'] = round((a - b) * 8 / elapsed / 1e6, 4)
        for source, dest in (('tcp_retrans', 'tcp_retrans_delta'), ('tcp_out', 'tcp_out_delta'),
                             ('rx_dropped', 'rx_dropped_delta'), ('tx_dropped', 'tx_dropped_delta'),
                             ('rx_errors', 'rx_errors_delta'), ('tx_errors', 'tx_errors_delta')):
            a, b = raw.get(source), previous.get(source)
            if finite(a) is not None and finite(b) is not None and a >= b:
                metrics[dest] = a - b
    services = [{'id': str(s.get('id', ''))[:48], 'active': bool(s.get('active'))}
                for s in raw.get('services', []) if isinstance(s, dict)]
    return {'id': role, 'title': 'Россия' if role == 'ru' else 'Нидерланды', 'ip': ip,
            'ok': True, 'at': iso(), 'metrics': metrics, 'services': services, 'error': None}


def failed_host(role, ip):
    return {'id': role, 'title': 'Россия' if role == 'ru' else 'Нидерланды', 'ip': ip,
            'ok': False, 'at': iso(), 'metrics': {key: None for key in METRIC_KEYS},
            'services': [], 'error': 'Не удалось получить серверные метрики'}


def read_local_host():
    p = subprocess.run([sys.executable, '-c', HOST_SOURCE, 'nl'], capture_output=True, text=True, timeout=8)
    return json.loads(p.stdout) if p.returncode == 0 else {}


def read_ru_host(vpnjob, relay, nl):
    if not relay:
        return {}
    # relay_ssh retains the existing known-hosts and key rules; no setup/key push.
    rc, output = vpnjob.relay_ssh(relay, f'python3 - ru {nl}', stdin=HOST_SOURCE, timeout=9)
    if rc:
        return {}
    try:
        value = json.loads(output)
        return value if isinstance(value, dict) else {}
    except ValueError:
        return {}


def curl_measure(url, socks=None, want_ip=False, timeout=6):
    cmd = ['curl', '--silent', '--show-error', '--max-time', str(timeout), '--connect-timeout', '3',
           '--proto', '=https', '--max-redirs', '0']
    if socks:
        cmd += ['--socks5-hostname', f'127.0.0.1:{socks}']
    cmd += ['--write-out', '\n__BVPN_METRIC__%{http_code} %{time_total} %{time_namelookup} %{time_appconnect} %{time_starttransfer}\n', url]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)
    except (OSError, subprocess.TimeoutExpired):
        return None
    body, marker, trailer = p.stdout.rpartition('\n__BVPN_METRIC__')
    parts = trailer.strip().split()
    if p.returncode or not marker or len(parts) != 5 or parts[0] not in ('200', '204'):
        return None
    try:
        result = {'latency_ms': round(float(parts[1]) * 1000, 2), 'dns_ms': round(float(parts[2]) * 1000, 2),
                  'tls_ms': round(float(parts[3]) * 1000, 2), 'ttfb_ms': round(float(parts[4]) * 1000, 2)}
    except ValueError:
        return None
    if want_ip:
        found = re.search(r'^ip=([0-9.]+)$', body, re.M)
        got = found[1] if found else body.strip()
        if not address(got):
            return None
        result['ip'] = got
    return result


def nl_exit_probe():
    started = time.monotonic()
    for i, url in enumerate(('https://cp.cloudflare.com/generate_204', 'https://www.gstatic.com/generate_204')):
        got = curl_measure(url)
        if got:
            got['latency_ms'] = round((time.monotonic() - started) * 1000, 2)
            return probe_result('nl_exit', ok=True, resource_fallback=bool(i), **got)
    return probe_result('nl_exit', error='Не ответили две внешние HTTPS-цели')


def telegram_probe(relay, port):
    if not relay or not 1 <= int(port) <= 65535:
        return probe_result('telegram', error='Посредник не настроен')
    started = time.monotonic()
    try:
        with socket.create_connection((relay, int(port)), timeout=3):
            return probe_result('telegram', ok=True, latency_ms=round((time.monotonic() - started) * 1000, 2))
    except OSError:
        return probe_result('telegram', error='TCP-подключение не установлено')


def probe_specs(vpnlib, vpnjob):
    xc = vpnlib.load_json(vpnlib.XCONF, {})
    tls, xhttp = None, None
    for inbound in vpnlib.vless_inbounds(xc):
        stream = inbound.get('streamSettings') or {}
        try:
            port = 443 if not vpnlib._public(inbound.get('listen')) else int(inbound.get('port'))
        except (ValueError, TypeError):
            continue
        if stream.get('security') == 'tls' and stream.get('network', 'tcp') == 'tcp':
            tls = port
        if stream.get('security') == 'reality' and stream.get('network') == 'xhttp':
            xhttp = port
    hc = vpnlib.yaml_load(vpnlib.read(vpnlib.HCONF))
    try:
        udp = int(str(hc.get('listen', '')).rpartition(':')[2])
    except ValueError:
        udp = 0
    hop = tuple(vpnjob.RELAY_UDP_HOP)
    valid_udp = 1 <= udp <= 65535
    return {
        'backup1': {('tcp', tls): vpnjob.relay_tcp_port(tls)} if tls else {},
        'backup3': {('tcp', xhttp): vpnjob.relay_tcp_port(xhttp)} if xhttp else {},
        'backup2': {('udp', udp): udp} if valid_udp else {},
        'primary': {('udp', udp): random.SystemRandom().randint(int(hop[0]), int(hop[1]))}
                   if valid_udp and len(hop) == 2 and 1 <= int(hop[0]) <= int(hop[1]) <= 65535 else {},
    }


def account_inbounds(inbounds, account, split_email):
    """Select only the dedicated service identity; never borrow a subscriber's key."""
    selected = []
    for inbound in inbounds:
        clients = [c for c in (inbound.get('settings') or {}).get('clients', [])
                   if split_email(c.get('email', '')) == (account, False)]
        if clients:
            selected.append({**inbound, 'settings': {**(inbound.get('settings') or {}), 'clients': [clients[0]]}})
    return selected


def tunnel_probe(pid):
    vpnlib, vpnjob = modules()
    account = os.environ.get('BVPN_MONITOR_ACCOUNT', 'monitoring')
    if not re.fullmatch(r'[a-z][a-z0-9]{1,15}', account):
        return probe_result(pid, error='Нет отдельного служебного доступа для проверки', exit_ok=False)
    relay = address(vpnjob.relay_ip())
    mapping = probe_specs(vpnlib, vpnjob).get(pid) or {}
    if not relay or not mapping:
        return probe_result(pid, error='Нет действующей конфигурации канала', exit_ok=False)
    if pid in ('primary', 'backup2'):
        hc = vpnlib.yaml_load(vpnlib.read(vpnlib.HCONF))
        auth = hc.get('auth') or {}
        if auth.get('type') != 'userpass' or account not in (auth.get('userpass') or {}):
            return probe_result(pid, error='Нет отдельного служебного Hysteria-доступа для проверки', exit_ok=False,
                                probe_account=account)
        cert = (hc.get('tls') or {}).get('cert')
        if not cert or not vpnlib.cert_pin(hc):
            return probe_result(pid, error='Нет сертификата для проверяемого Hysteria-клиента', exit_ok=False)
        original_auth = vpnlib.hy_auth
        vpnlib.hy_auth = lambda conf: (original_auth(conf)[0], [account])
    original_inbounds = vpnlib.vless_inbounds
    vpnlib.vless_inbounds = lambda conf: account_inbounds(original_inbounds(conf), account, vpnlib.split_email)
    measurements = []

    def exit_through(cmd, port):
        process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   env=dict(os.environ, HYSTERIA_DISABLE_UPDATE_CHECK='1'))
        try:
            ready = False
            for _ in range(35):
                if process.poll() is not None:
                    break
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                        ready = True
                        break
                except OSError:
                    time.sleep(0.1)
            if not ready:
                return ''
            started = time.monotonic()
            for i, url in enumerate(('https://www.cloudflare.com/cdn-cgi/trace', 'https://api.ipify.org')):
                got = curl_measure(url, socks=port, want_ip=True)
                if got:
                    got['latency_ms'] = round((time.monotonic() - started) * 1000, 2)
                    measurements.append({k: v for k, v in got.items() if k != 'ip'} | {'resource_fallback': bool(i)})
                    return got['ip']
            return ''
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)

    vpnlib._exit_ip_through = exit_through
    try:
        result = vpnlib.selftest(via=relay, ports=mapping)
    except Exception:
        return probe_result(pid, error='Проверка VPN-клиента завершилась ошибкой', exit_ok=False, probe_account=account)
    results = result.get('results') or []
    ok = bool(results) and all(x.get('ok') for x in results)
    latency = max((x['latency_ms'] for x in measurements), default=None)
    return probe_result(pid, ok=ok, latency_ms=latency, exit_ok=ok,
                        probe_account=account,
                        resource_fallback=any(x.get('resource_fallback') for x in measurements),
                        error=None if ok else 'Запрос через канал или проверка выходного IP не прошли')


def group_alive(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def kill_group(process):
    # A client may still live after the probe interpreter exits. Reap the probe,
    # then wait for its whole session and forcibly stop surviving descendants.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    deadline = time.monotonic() + 2
    while group_alive(process.pid) and time.monotonic() < deadline:
        process.poll()
        time.sleep(0.05)
    if group_alive(process.pid):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    if process.poll() is None:
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            # The service's KillMode=control-group is a final outer deadline.
            pass


def child_probe(pid, tmpdir):
    env = dict(os.environ, TMPDIR=str(tmpdir), HYSTERIA_DISABLE_UPDATE_CHECK='1')
    process = subprocess.Popen([sys.executable, '-I', str(Path(__file__).resolve()), '--probe', pid],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                               env=env, start_new_session=True)
    try:
        output, _ = process.communicate(timeout=PROBE_TIMEOUT)
        if process.returncode == 0:
            got = json.loads(output)
            if isinstance(got, dict) and got.get('id') == pid:
                return got
    except (subprocess.TimeoutExpired, ValueError):
        pass
    finally:
        kill_group(process)
    return probe_result(pid, error='Превышено время серверной проверки', exit_ok=False)


def atomic_write(path, value, mode, group=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    if group is not None:
        os.chown(path.parent, 0, group)
        os.chmod(path.parent, 0o750)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.' + path.name + '.', delete=False) as stream:
        tmp = Path(stream.name)
        stream.write((json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n').encode())
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.chmod(tmp, mode)
        if group is not None:
            os.chown(tmp, 0, group)
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()


def collect():
    vpnlib, vpnjob = modules()
    conf = vpnlib.config()
    nl, relay = address(conf.get('ip')), address(vpnjob.relay_ip())
    previous = load_json(STATE, {})
    raw = {}
    probes = []
    with tempfile.TemporaryDirectory(prefix='bvpn-monitor.') as temporary:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            work = {pool.submit(child_probe, pid, temporary): ('probe', pid)
                    for pid in ('primary', 'backup1', 'backup2', 'backup3')}
            work[pool.submit(read_local_host)] = ('host', 'nl')
            work[pool.submit(read_ru_host, vpnjob, relay, nl)] = ('host', 'ru')
            work[pool.submit(nl_exit_probe)] = ('probe', 'nl_exit')
            work[pool.submit(telegram_probe, relay, conf.get('tcp', {}).get('telegram', 8880))] = ('probe', 'telegram')
            for future in concurrent.futures.as_completed(work):
                kind, key = work[future]
                try:
                    value = future.result()
                except Exception:
                    value = {} if kind == 'host' else probe_result(key, error='Серверная проверка завершилась ошибкой')
                if kind == 'host':
                    raw[key] = value
                else:
                    probes.append(value)
    hosts = [host_result(role, ip, raw.get(role, {}), previous.get(role, {}))
             if raw.get(role) else failed_host(role, ip)
             for role, ip in (('ru', relay), ('nl', nl))]
    ping = parse_ping(raw.get('ru', {}).get('ping_text', ''))
    probes.append(probe_result('ru_nl', **ping,
                              error=None if ping['ok'] else 'Нет ответа ICMP с RU до NL'))
    result = {'schema': 1, 'at': iso(), 'interval_s': INTERVAL,
              'probe_account': os.environ.get('BVPN_MONITOR_ACCOUNT', 'monitoring')[:16], 'hosts': hosts,
              'probes': sorted(probes, key=lambda p: list(PROBE_META).index(p['id']))}
    # The private baseline contains only kernel counters; strip ping text and service list.
    new_state = {role: {k: v for k, v in data.items() if k not in ('ping_text', 'services')}
                 for role, data in raw.items() if data}
    if vpnlib.scan(json.dumps(result, ensure_ascii=False)):
        raise RuntimeError('sanitized monitor sample failed the existing secret scan')
    return result, new_state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--no-write', action='store_true', help='run probes and print sanitized sample without persistent writes')
    parser.add_argument('--dry-run', action='store_true', help='show safe plan only; no probes or files')
    parser.add_argument('--probe', choices=('primary', 'backup1', 'backup2', 'backup3'))
    parser.add_argument('--fixture', type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.fixture:
        sample = load_json(args.fixture)
        if sample.get('schema') != 1 or not isinstance(sample.get('hosts'), list) or not isinstance(sample.get('probes'), list):
            raise SystemExit('invalid monitor fixture')
        print(json.dumps(sample, ensure_ascii=False))
        return
    if args.probe:
        def stopped(signum, frame):
            raise TimeoutError('probe stopped')
        signal.signal(signal.SIGTERM, stopped)
        print(json.dumps(tunnel_probe(args.probe), ensure_ascii=False))
        return
    if args.dry_run:
        vpnlib, vpnjob = modules()
        configured = {key: bool(value) for key, value in probe_specs(vpnlib, vpnjob).items()}
        print(json.dumps({'schema': 1, 'interval_s': INTERVAL, 'nl': address(vpnlib.config().get('ip')),
                          'ru': address(vpnjob.relay_ip()), 'probes': list(PROBE_META),
                          'probe_account': os.environ.get('BVPN_MONITOR_ACCOUNT', 'monitoring')[:16],
                          'configured': configured, 'writes': [str(LATEST), str(STATE)],
                          'vpn_service_restarts': False}, ensure_ascii=False))
        return
    if not args.once:
        parser.error('choose --once, --dry-run, or --fixture')
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('monitor collector already running')
        result, state = collect()
        if args.no_write:
            print(json.dumps(result, ensure_ascii=False))
            return
        gid = grp.getgrnam('bvpn-admin').gr_gid
        atomic_write(STATE, state, 0o600)
        atomic_write(LATEST, result, 0o640, gid)
        print('monitor sample collected')


if __name__ == '__main__':
    main()
