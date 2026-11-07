#!/usr/bin/env python3
"""vpnlib - the Python half of bvpn. Runs as root on a VPN server, stdlib + PyYAML only.
Installed to /usr/local/lib/bvpn/vpnlib.py, called by /usr/local/sbin/bvpn:

  snapshot [--probe IP]    JSON state of this server for the admin panel. Counts, states and
                           logins only: no UUIDs, keys, shortIds, XHTTP path, passwords, proxy
                           secrets, links or client IPs. The finished JSON is scanned for every
                           secret of the live configs and for secret-looking strings; on a hit
                           nothing is printed and the exit code is 3.
  selftest [--baseline F]  temporary clients through every channel of this server (Reality,
                           XHTTP, Hysteria2, the "Russia" users), checks the exit IP. With a
                           baseline (an earlier selftest JSON): exit 1 only if a channel that
                           worked then fails now - a channel broken before the change is not
                           the change's fault
  selftest --via IP        the same through a relay that forwards this server's ports (the Russian
                           chain): the clients dial IP instead of this server; the exit IP is still
                           this server's. Not stored as the server's own selftest
  guard OLD NEW            exit 1 if a candidate Xray config changes public listeners or clients
  hy-auth CAND             stdin JSON {"users": {login: hex32}, "stats": {"listen", "secret"}}
                           (switch to userpass), or {"merge": true, "users": {...}, "remove": [...]}
                           (add / drop people, keep the rest): writes CAND = live Hysteria2 config
                           with the auth and trafficStats blocks replaced; prints nothing secret
  scan FILE                exit 1 if FILE has anything that looks like a secret
  linkcheck                stdin: vless:// and hysteria2:// links (a subscription); exit 0 only if
                           every one matches the live configs of this server. Prints line numbers
                           and field names of mismatches, never values

Server identity: /etc/bvpn/server (ID, TITLE, IP, RU_IP), display names:
/etc/bvpn/people ("login|Имя" per line). State: /var/lib/bvpn.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

XCONF = Path("/usr/local/etc/xray/config.json")
HCONF = Path("/etc/hysteria/config.yaml")
TCONF = Path("/etc/telemt/telemt.toml")
CONFIG = Path("/etc/bvpn/config.json")           # 644, no secrets: who this installation is (config/example.json)
DEFAULT_CONFIG = {"server_id": "nl", "title": "Нидерланды", "label": "Нидерланды", "flag": "🇳🇱", "ip": "203.0.113.10",
                  "brand": "VPN", "sub_url": "https://203.0.113.10/", "template": "owner",
                  "kits": "/root/bvpn-kits", "tcp": {"tls": 2083, "xhttp": 8443, "telegram": 8880},
                  "hop": [20000, 40000]}
SERVER_ENV = Path("/etc/bvpn/server")
PEOPLE = Path("/etc/bvpn/people")
PAUSED = Path("/etc/bvpn/paused")          # bvpn person-pause: what was taken out, root 600
STATE = Path("/var/lib/bvpn")
HEALTH = Path("/var/lib/bvpn-health/status")

UNITS = ["xray", "hysteria-server", "telemt", "fail2ban", "ufw",
         "bvpn-health.timer", "bvpn-snapshot.timer"]
BACKUP_TIMERS: list[str] = []                    # automatic backup timers are not configured by default
SELFTEST_MAX_AGE = 30 * 60
ONLINE_BY_TRAFFIC = 10 * 60
HOUR = 3600
KEEP_HOURS = 31 * 24

# channel id -> (number and name as in the people's kits, protocol)
CHANNELS = {
    "calls": ("Основной и Запасной 2", "Hysteria2"),
    "main": ("Запасной 1", "VLESS TLS"),
    "backup": ("Запасной 3", "VLESS XHTTP"),
    "telegram": ("Telegram-прокси", "MTProto (Telemt)"),
}

UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
HEX_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32,}(?![0-9a-fA-F])")
LINK_RE = re.compile(r"\b(?:vless|vmess|trojan|ss|hysteria2|hy2|tg)://", re.I)
B64KEY_RE = re.compile(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/-]{43}=?(?![A-Za-z0-9_+/=-])")
LOGIN_RE = re.compile(r"^[a-z][a-z0-9]{1,15}$")


# ---------- small helpers ----------

def iso(ts: float | None) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else ""


def run(*cmd: str, timeout: int = 10, stdin: str | None = None) -> str:
    try:
        return subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def read(p: Path) -> str:
    try:
        return p.read_text()
    except OSError:
        return ""


def read_env(p: Path) -> dict[str, str]:
    out = {}
    for line in read(p).splitlines():
        m = re.match(r"^\s*([A-Z_][A-Z0-9_]*)=(.*)$", line)
        if m:
            out[m.group(1)] = re.sub(r"\s+#.*$", "", m.group(2)).strip().strip('"\'')
    return out


def read_people(p: Path) -> dict[str, str]:
    out = {}
    for line in read(p).splitlines():
        login, _, name = line.partition("|")
        if LOGIN_RE.match(login.strip()):
            out[login.strip()] = name.strip() or login.strip()
    return out


def write_atomic(p: Path, text: str, mode: int = 0o644) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=f".{p.name}.")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, p)


def load_json(p: Path, default):
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return default


# ---------- configs: who is where, and what is secret ----------

def split_email(email: str) -> tuple[str, bool]:
    """'olga' / 'olga-xhttp' / 'olga-tls' -> ('olga', ru?); ru is always False here (no Russian exit)."""
    parts = (email or "").split("-")
    return parts[0], "ru" in parts[1:]


def xray_channel(inbound: dict, ru: bool) -> str:
    net = inbound.get("streamSettings", {}).get("network", "tcp")
    return "backup" if net == "xhttp" else "main"


def vless_inbounds(xc: dict) -> list[dict]:
    return [i for i in xc.get("inbounds", []) if i.get("protocol") == "vless"]


def xray_people(xc: dict) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for ib in vless_inbounds(xc):
        for c in ib.get("settings", {}).get("clients", []):
            login, ru = split_email(c.get("email", ""))
            if login:
                out.setdefault(login, set()).add(xray_channel(ib, ru))
    return out


def yaml_load(text: str) -> dict:
    try:
        import yaml
        return yaml.safe_load(text) or {}
    except Exception:
        return {}


def hy_auth(hc: dict) -> tuple[str, list[str]]:
    a = hc.get("auth") or {}
    if a.get("type") == "userpass":
        return "userpass", sorted((a.get("userpass") or {}).keys())
    return a.get("type") or "none", []


def telemt_users(text: str) -> dict[str, str]:
    return dict(re.findall(r'^\s*([A-Za-z0-9_-]+)\s*=\s*"([0-9a-fA-F]{32})"', text, re.M))


def telemt_port(text: str, key: str, default: str) -> str:
    sect = re.search(r"^\[server\.api\]\s*$(.*?)(?=^\[)", text + "\n[", re.M | re.S)
    if key == "api":
        m = sect and re.search(r'^\s*listen\s*=\s*"([^"]+)"', sect.group(1), re.M)
        return m.group(1) if m else default
    m = re.search(r"^\[server\]\s*$(.*?)(?=^\[)", text + "\n[", re.M | re.S)
    m = m and re.search(r"^\s*port\s*=\s*(\d+)", m.group(1), re.M)
    return m.group(1) if m else default


def known_secrets(xc: dict, hc: dict, ttext: str) -> set[str]:
    s: set[str] = set()
    for ib in xc.get("inbounds", []):
        for c in ib.get("settings", {}).get("clients", []):
            s.update(str(c[k]) for k in ("id", "password") if c.get(k))
        ss = ib.get("streamSettings", {})
        r = ss.get("realitySettings", {})
        if r.get("privateKey"):
            s.add(r["privateKey"])
        s.update(x for x in r.get("shortIds", []) if x)
        p = ss.get("xhttpSettings", {}).get("path", "")
        if p.strip("/"):
            s.add(p)
    a = hc.get("auth") or {}
    if a.get("password"):
        s.add(str(a["password"]))
    s.update(str(v) for v in (a.get("userpass") or {}).values())
    o = hc.get("obfs") or {}
    if (o.get("salamander") or {}).get("password"):
        s.add(str(o["salamander"]["password"]))
    if (hc.get("trafficStats") or {}).get("secret"):
        s.add(str(hc["trafficStats"]["secret"]))
    s.update(telemt_users(ttext).values())
    return {x for x in s if len(x) >= 6}


def scan(text: str, known: set[str] = frozenset()) -> list[str]:
    """Reasons why `text` must not leave the server (empty list = clean)."""
    bad = []
    if UUID_RE.search(text):
        bad.append("uuid")
    if HEX_RE.search(text):
        bad.append("hex32")
    if LINK_RE.search(text):
        bad.append("link")
    for m in B64KEY_RE.finditer(text):
        t = m.group(0)
        if re.search(r"[A-Z]", t) and re.search(r"[a-z]", t) and re.search(r"[0-9]", t):
            bad.append("base64-key")
            break
    if any(k in text for k in known):
        bad.append("known-secret")
    return bad


# ---------- guard for Xray candidates ----------

def _public(listen) -> bool:
    l = str(listen or "0.0.0.0")
    return not (l.startswith("127.") or l in ("::1", "localhost"))


def guard(old: dict, new: dict) -> list[str]:
    """Changes requiring dedicated management commands or SSH rather than a generic bot-approved patch."""
    probs = []
    pub = lambda c: sorted((str(i.get("listen") or "0.0.0.0"), int(i.get("port") or 0), i.get("protocol"))
                           for i in c.get("inbounds", []) if _public(i.get("listen")))
    if pub(old) != pub(new):
        probs.append(f"public listeners change: {pub(old)} -> {pub(new)}")
    cl = lambda c: {i.get("tag"): sorted((k.get("id", ""), k.get("email", ""), k.get("flow", ""))
                                         for k in i.get("settings", {}).get("clients", []))
                    for i in c.get("inbounds", []) if i.get("settings", {}).get("clients") is not None}
    if cl(old) != cl(new):
        probs.append("clients change (use dedicated person-management commands or SSH)")
    keys = lambda c: {i.get("tag"): i.get("streamSettings", {}).get("realitySettings", {}).get("privateKey")
                      for i in c.get("inbounds", [])}
    if any(keys(new).get(t) != k for t, k in keys(old).items() if k):
        probs.append("Reality private key changes")
    if not vless_inbounds(new):
        probs.append("no vless inbounds left")
    return probs


# ---------- Hysteria2: userpass + traffic stats ----------

def replace_block(text: str, key: str, block: str) -> str:
    """Replace the top-level YAML block `key:` (its line and the indented lines after it)."""
    lines = text.splitlines()
    out, i, done = [], 0, False
    while i < len(lines):
        if re.match(rf"^{re.escape(key)}:(\s|$)", lines[i]):
            i += 1
            while i < len(lines) and (lines[i].startswith((" ", "\t")) or not lines[i].strip()):
                i += 1
            out.extend(block.rstrip("\n").splitlines())
            done = True
            continue
        out.append(lines[i])
        i += 1
    if not done:
        out.extend(block.rstrip("\n").splitlines())
    return "\n".join(out) + "\n"


def hy_set_userpass(text: str, users: dict[str, str], stats_listen: str, stats_secret: str) -> str:
    for login, pw in users.items():
        if not LOGIN_RE.match(login) or not re.fullmatch(r"[0-9a-f]{32}", pw):
            raise ValueError(f"bad user entry for {login!r}")
    if not re.fullmatch(r"127\.0\.0\.1:\d{2,5}", stats_listen) or not re.fullmatch(r"[0-9a-f]{32}", stats_secret):
        raise ValueError("trafficStats must listen on 127.0.0.1 with a hex32 secret")
    auth = "auth:\n  type: userpass\n  userpass:\n" + "".join(f"    {u}: {p}\n" for u, p in sorted(users.items()))
    stats = f"trafficStats:\n  listen: {stats_listen}\n  secret: {stats_secret}\n"
    new = replace_block(replace_block(text, "auth", auth), "trafficStats", stats)
    hc = yaml_load(new)
    if hy_auth(hc) != ("userpass", sorted(users)) or (hc.get("trafficStats") or {}).get("listen") != stats_listen:
        raise ValueError("candidate does not parse back as expected")
    return new


def hy_update(text: str, req: dict) -> tuple[str, list[str]]:
    hc = yaml_load(text)
    kind, _ = hy_auth(hc)
    cur = dict((hc.get("auth") or {}).get("userpass") or {}) if kind == "userpass" else {}
    if req.get("merge"):
        if kind != "userpass":
            raise ValueError("Hysteria2 still has one shared password: switch with scripts/hy2-userpass.sh first")
        users = {**cur, **(req.get("users") or {})}
    else:
        users = dict(req.get("users") or {})
    for login in req.get("remove") or []:
        users.pop(login, None)
    if not users:
        raise ValueError("no Hysteria2 users would be left")
    st = req.get("stats") or hc.get("trafficStats") or {}
    return hy_set_userpass(text, {k: str(v) for k, v in users.items()}, str(st.get("listen", "")),
                           str(st.get("secret", ""))), sorted(users)


# ---------- live data ----------

def systemd_show(unit: str, props: list[str]) -> dict[str, str]:
    out = run("systemctl", "show", unit, *[f"-p{p}" for p in props])
    return dict(l.split("=", 1) for l in out.splitlines() if "=" in l)


def ts_from_systemd(v: str) -> float | None:
    v = (v or "").strip()
    if not v or v in ("n/a", "0"):
        return None
    try:                                   # our own ISO stamps: no `date -d` (absent on macOS)
        return datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        pass
    out = run("date", "-u", "-d", v, "+%s").strip()
    return float(out) if out.isdigit() else None


def units_state() -> dict[str, dict]:
    res = {}
    for u in UNITS:
        p = systemd_show(u, ["LoadState", "ActiveState", "SubState", "ActiveEnterTimestamp", "NRestarts"])
        if p.get("LoadState") in ("not-found", "", None):
            continue
        res[u] = {"state": p.get("ActiveState", ""), "sub": p.get("SubState", ""),
                  "since": iso(ts_from_systemd(p.get("ActiveEnterTimestamp", ""))),
                  "restarts": int(p.get("NRestarts") or 0) if (p.get("NRestarts") or "").isdigit() else 0}
    return res


def listening() -> tuple[set[str], set[str]]:
    """({'tcp/443', ...} public, {'tcp/127.0.0.1:4443', ...} loopback)."""
    pub, lo = set(), set()
    for line in run("ss", "-lntuH").splitlines():
        f = line.split()
        if len(f) < 5:
            continue
        addr, _, port = f[4].rpartition(":")
        addr = addr.strip("[]")
        if addr.startswith("127.") or addr == "::1":
            lo.add(f"{f[0]}/{addr}:{port}")
        else:
            pub.add(f"{f[0]}/{port}")
    return pub, lo


def host_info() -> dict:
    mem = dict(re.findall(r"^(\w+):\s+(\d+) kB", read(Path("/proc/meminfo")), re.M))
    du = shutil.disk_usage("/")
    iface = ""
    for line in read(Path("/proc/net/route")).splitlines()[1:]:
        f = line.split()
        if len(f) > 1 and f[1] == "00000000":
            iface = f[0]
            break
    rx = tx = 0
    for line in read(Path("/proc/net/dev")).splitlines():
        if iface and line.strip().startswith(iface + ":"):
            f = line.split(":", 1)[1].split()
            rx, tx = int(f[0]), int(f[8])
    up = float((read(Path("/proc/uptime")).split() or ["0"])[0])
    return {
        "hostname": socket.gethostname(),
        "boot_at": iso(time.time() - up),
        "load1": float((read(Path("/proc/loadavg")).split() or ["0"])[0]),
        "cpus": os.cpu_count() or 1,
        "mem_total_mb": int(mem.get("MemTotal", 0)) // 1024,
        "mem_available_mb": int(mem.get("MemAvailable", 0)) // 1024,
        "disk_total_gb": round(du.total / 1e9, 1), "disk_used_gb": round(du.used / 1e9, 1),
        "disk_pct": round(100 * du.used / du.total) if du.total else 0,
        "net_iface": iface, "net_rx_bytes": rx, "net_tx_bytes": tx,
        "reboot_required": Path("/var/run/reboot-required").exists(),
    }


def versions() -> dict[str, str]:
    x = run("xray", "version").split()
    h = re.search(r"^Version:\s*(\S+)", run("hysteria", "version"), re.M)
    t = run("telemt", "--version").split()
    return {"xray": x[1] if len(x) > 1 else "", "hysteria": h.group(1) if h else "",
            "telemt": t[1] if len(t) > 1 else ""}


def http_json(url: str, headers: dict | None = None, timeout: int = 5):
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def xray_api(xc: dict) -> str | None:
    a = xc.get("api") or {}
    if "StatsService" in (a.get("services") or []) and str(a.get("listen", "")).startswith("127.0.0.1:"):
        return a["listen"]
    return None


def xray_stats(xc: dict) -> tuple[dict[str, int], dict[str, dict]] | None:
    """({login: up+down bytes since xray start}, {login: {"devices": n, "last": ts}}) or None."""
    api = xray_api(xc)
    if not api:
        return None
    q = run("xray", "api", "statsquery", f"--server={api}", "-pattern", "user>>>")
    try:
        stats = json.loads(q).get("stat", []) if q.strip() else []
    except ValueError:
        return None
    total: dict[str, int] = {}
    for s in stats:
        parts = s.get("name", "").split(">>>")
        if len(parts) == 4 and parts[2] == "traffic":
            login, _ = split_email(parts[1])
            total[login] = total.get(login, 0) + int(s.get("value") or 0)
    online: dict[str, dict] = {}
    for ib in vless_inbounds(xc):
        for c in ib.get("settings", {}).get("clients", []):
            email = c.get("email", "")
            login, _ = split_email(email)
            if not email:
                continue
            o = online.setdefault(login, {"ips": set(), "last": 0})
            try:
                d = json.loads(run("xray", "api", "statsonlineiplist", f"--server={api}", "-email", email) or "{}")
            except ValueError:
                d = {}
            for ip, ts in (d.get("ips") or {}).items():
                o["ips"].add(ip)
                o["last"] = max(o["last"], int(ts or 0))
    return total, {k: {"devices": len(v["ips"]), "last": v["last"] or None} for k, v in online.items()}


def hy_stats(hc: dict) -> tuple[dict[str, int], dict[str, int]] | None:
    ts = hc.get("trafficStats") or {}
    if not str(ts.get("listen", "")).startswith("127.0.0.1:") or not ts.get("secret"):
        return None
    h = {"Authorization": str(ts["secret"])}
    traffic = http_json(f"http://{ts['listen']}/traffic", h)
    online = http_json(f"http://{ts['listen']}/online", h)
    if traffic is None or online is None:
        return None
    return ({u: int(v.get("tx", 0)) + int(v.get("rx", 0)) for u, v in traffic.items()},
            {u: int(n) for u, n in online.items()})


def telemt_stats(ttext: str) -> dict[str, dict] | None:
    d = http_json(f"http://{telemt_port(ttext, 'api', '127.0.0.1:9091')}/v1/users")
    if not isinstance(d, dict):
        return None
    out = {}
    for u in d.get("data") or []:
        if u.get("username"):
            out[u["username"]] = {"enabled": bool(u.get("enabled", True)),
                                  "online": int(u.get("current_connections") or 0),
                                  "total": int(u.get("total_octets") or 0)}
    return out


def account(state: dict, now: float, counters: dict[str, int]) -> None:
    """Fold cumulative counters (they reset when a service restarts) into hourly buckets."""
    last = state.setdefault("last", {})
    hours = state.setdefault("hours", {})
    hk = str(int(now // HOUR * HOUR))
    for key, cur in counters.items():
        prev = last.get(key)
        # first sight: nothing to compare with; smaller than before: the service restarted
        delta = 0 if prev is None else (cur if cur < prev else cur - prev)
        last[key] = cur
        if delta:
            login = key.split(":", 1)[1]
            b = hours.setdefault(hk, {})
            b[login] = b.get(login, 0) + delta
            state.setdefault("seen", {})[login] = now
    for k in [k for k in hours if int(k) < now - KEEP_HOURS * HOUR]:
        del hours[k]


def window(state: dict, now: float, login: str, seconds: int) -> int:
    return sum(b.get(login, 0) for k, b in state.get("hours", {}).items() if int(k) > now - seconds - HOUR)


def daily(state: dict, now: float, login: str, days: int = 30) -> list[int]:
    """Bytes per day (Moscow days), oldest first, today last - for the chart on the admin's tab."""
    msk = 3 * HOUR
    today = int((now + msk) // 86400)
    out = [0] * days
    for k, b in state.get("hours", {}).items():
        i = days - 1 - (today - int((int(k) + msk) // 86400))
        if 0 <= i < days:
            out[i] += b.get(login, 0)
    return out


def ru_exit(env: dict) -> dict | None:
    p = systemd_show("ru-exit-tunnel", ["LoadState", "ActiveState"])
    if p.get("LoadState") in ("not-found", "", None):
        return None
    ip = run("curl", "-s", "--max-time", "12", "--socks5-hostname", "127.0.0.1:10808", "https://ifconfig.me",
             timeout=15).strip()
    ip = ip if re.fullmatch(r"[0-9.]{7,15}", ip) else ""
    return {"tunnel": p.get("ActiveState", ""), "exit_ip": ip, "expected": env.get("RU_IP", ""),
            "ok": bool(ip) and ip == env.get("RU_IP")}


def probe(ip: str, xc: dict, ttext: str) -> dict:
    """Seen from this server: is the OTHER server's VPN reachable (TCP + TLS by SNI, no keys)."""
    res = {"target": ip, "ports": {}}
    snis = {}
    for ib in vless_inbounds(xc):
        net = ib.get("streamSettings", {}).get("network", "tcp")
        names = ib.get("streamSettings", {}).get("realitySettings", {}).get("serverNames") or [None]
        snis[8443 if net == "xhttp" else 443] = names[0]
    snis[int(telemt_port(ttext, "server", "5223"))] = None
    for port, sni in sorted(snis.items()):
        t0 = time.monotonic()
        r = {"tcp": False, "tls": None, "ms": None}
        try:
            with socket.create_connection((ip, port), timeout=6) as s:
                r["tcp"] = True
                if sni:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                    with ctx.wrap_socket(s, server_hostname=sni):
                        r["tls"] = True
        except (OSError, ssl.SSLError):
            if r["tcp"] and sni:
                r["tls"] = False
        r["ms"] = round((time.monotonic() - t0) * 1000)
        res["ports"][f"tcp/{port}"] = r
    return res


def deadlines(hc: dict, state: dict, now: float, cur: dict[str, str]) -> list[dict]:
    out = []
    cert = (hc.get("tls") or {}).get("cert")
    if cert:
        end = run("openssl", "x509", "-enddate", "-noout", "-in", cert).strip().partition("=")[2]
        ts = ts_from_systemd(end)
        if ts:
            out.append({"what": "сертификат Hysteria2 (pinSHA256 в ссылках «2 Звонки»)", "at": iso(ts),
                        "days": int((ts - now) // 86400)})
    lat = state.get("latest", {})
    if now - lat.get("at", 0) > 86400:
        for k, repo in (("xray", "XTLS/Xray-core"), ("hysteria", "HyNetworks/hysteria")):
            d = http_json(f"https://api.github.com/repos/{repo}/releases/latest", timeout=8)
            if isinstance(d, dict) and d.get("tag_name"):
                lat[k] = d["tag_name"].rsplit("/", 1)[-1].lstrip("v")
        lat["at"] = now
        state["latest"] = lat
    for k in ("xray", "hysteria"):
        if lat.get(k) and cur.get(k) and lat[k] != cur[k].lstrip("v"):
            out.append({"what": f"вышел {k} {lat[k]} (стоит {cur[k]}) — обновление только с согласия", "at": "",
                        "days": None})
    for t in BACKUP_TIMERS:
        p = systemd_show(t, ["LoadState", "LastTriggerUSec"])
        if p.get("LoadState") == "loaded":
            svc = systemd_show(t.replace(".timer", ".service"), ["Result"])
            ts = ts_from_systemd(p.get("LastTriggerUSec", ""))
            out.append({"what": f"копия настроек ({t.removesuffix('.timer')}): {svc.get('Result', '?')}",
                        "at": iso(ts), "days": int((ts - now) // 86400) if ts else None})
    return out


def pending() -> list[dict]:
    out = []
    for f in sorted((STATE / "pending").glob("*")):
        e = read_env(f)
        out.append({"id": f.name, "unit": e.get("UNIT", ""), "revert_at": iso(float(e.get("REVERT_AT", 0) or 0))})
    return out


def health() -> dict:
    lines = read(HEALTH).splitlines()
    first = (lines or [""])[0].split()
    # a failed unit with a long hash in its name looks like a secret to scan(): keep 7 characters of it
    short = lambda l: re.sub(r"\b([0-9a-f]{7})[0-9a-f]{25,33}\b", r"\1…", l)
    return {"state": first[0] if first else "", "at": " ".join(first[1:]), "problems": [short(l) for l in lines[1:]]}


# ---------- selftest ----------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _exit_ip_through(cmd: list[str], port: int) -> str:
    env = dict(os.environ, HYSTERIA_DISABLE_UPDATE_CHECK="1")
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        ip = run("curl", "-s", "--max-time", "15", "--socks5-hostname", f"127.0.0.1:{port}",
                 "https://ifconfig.me", timeout=20).strip()
        return ip if re.fullmatch(r"[0-9.]{7,15}", ip) else ""
    finally:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()


def regressions(before: dict, after: dict) -> list[str]:
    ok = lambda r: {x["channel"] for x in r.get("results", []) if x.get("ok")}
    return sorted(ok(before) - ok(after))


MAP_RE = re.compile(r"^(tcp|udp)[0-9]{1,5}=[0-9]{1,5}(,(tcp|udp)[0-9]{1,5}=[0-9]{1,5}){0,9}$")


def parse_map(spec: str) -> dict[tuple[str, int], int]:
    """'tcp8443=18443,udp443=10443' -> {("tcp", 8443): 18443, ...}: the relay's port for a port of this server."""
    if not MAP_RE.match(spec or ""):
        raise ValueError("map: tcpPORT=PORT,udpPORT=PORT")
    return {(k[:3], int(k[3:])): int(v) for k, v in (x.split("=") for x in spec.split(","))}


def selftest(via: str | None = None, ports: dict[tuple[str, int], int] | None = None) -> dict:
    env = read_env(SERVER_ENV)
    ip, ru_ip = env.get("IP", ""), env.get("RU_IP", "")
    dial = via or ip                                   # a relay forwards the same ports here (or `ports` says which)
    xc = load_json(XCONF, {})
    hc = yaml_load(read(HCONF))
    results = []
    with tempfile.TemporaryDirectory(prefix="bvpn-selftest.") as d:
        for ib in vless_inbounds(xc):
            ss = ib.get("streamSettings", {})
            r = ss.get("realitySettings", {})
            sec = ss.get("security")
            if sec not in ("reality", "tls"):
                continue
            pbk = reality_pbk(r.get("privateKey", "")) if sec == "reality" else ""
            clients = ib.get("settings", {}).get("clients", [])
            picks = {}
            for c in clients:
                login, ru = split_email(c.get("email", ""))
                picks.setdefault(ru, c)
            port = 443 if not _public(ib.get("listen")) else int(ib.get("port"))
            if ports is not None:
                if ("tcp", port) not in ports:
                    continue                           # the relay does not carry this channel of this server
                port = ports[("tcp", port)]
            for ru, c in sorted(picks.items()):
                ch = xray_channel(ib, ru)
                sp = _free_port()
                if sec == "reality":
                    stream = {"network": ss.get("network", "tcp"), "security": "reality",
                              "realitySettings": {"serverName": (r.get("serverNames") or [""])[0], "fingerprint": "chrome",
                                                  "publicKey": pbk, "shortId": (r.get("shortIds") or [""])[0]}}
                else:                                  # the certificate is for the server's IP: checked, not skipped
                    stream = {"network": "tcp", "security": "tls",
                              "tlsSettings": {"serverName": ip, "fingerprint": "ios", "alpn": ["http/1.1"]}}
                if stream["network"] == "xhttp":
                    x = ss.get("xhttpSettings", {})
                    stream["xhttpSettings"] = {"path": x.get("path", "/"), "mode": x.get("mode", "auto")}
                user = {"id": c.get("id"), "encryption": "none"}
                if c.get("flow"):
                    user["flow"] = c["flow"]
                conf = {"log": {"loglevel": "none"},
                        "inbounds": [{"listen": "127.0.0.1", "port": sp, "protocol": "socks"}],
                        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": dial, "port": port, "users": [user]}]},
                                       "streamSettings": stream}]}
                f = Path(d) / f"x-{ch}.json"
                f.write_text(json.dumps(conf))
                got = _exit_ip_through(["xray", "run", "-config", str(f)], sp)
                want = ru_ip if ru else ip
                results.append({"channel": ch, "login": split_email(c.get("email", ""))[0], "exit_ip": got,
                                "expected": want, "ok": bool(got) and got == want})
        if hc.get("listen") and (ports is None or ("udp", int(str(hc["listen"]).rpartition(":")[2])) in ports):
            kind, users = hy_auth(hc)
            a = hc.get("auth") or {}
            auth = f"{users[0]}:{a['userpass'][users[0]]}" if kind == "userpass" and users else str(a.get("password", ""))
            pin = ""
            cert = (hc.get("tls") or {}).get("cert")
            if cert:
                der = subprocess.run(["openssl", "x509", "-in", cert, "-outform", "der"], capture_output=True).stdout
                pin = hashlib.sha256(der).hexdigest() if der else ""
            sp = _free_port()
            hport = int(str(hc["listen"]).rpartition(":")[2])
            conf = {"server": f"{dial}:{(ports or {}).get(('udp', hport), hport)}", "auth": auth,
                    "tls": {"insecure": True, **({"pinSHA256": pin} if pin else {})},
                    "socks5": {"listen": f"127.0.0.1:{sp}"}}
            o = hc.get("obfs") or {}
            if o.get("type") == "salamander":
                conf["obfs"] = {"type": "salamander", "salamander": {"password": o["salamander"]["password"]}}
            f = Path(d) / "hy.json"
            f.write_text(json.dumps(conf))
            got = _exit_ip_through(["hysteria", "client", "-c", str(f)], sp)
            results.append({"channel": "calls", "login": users[0] if kind == "userpass" and users else "",
                            "exit_ip": got, "expected": ip, "ok": bool(got) and got == ip})
    res = {"at": iso(time.time()), "ok": bool(results) and all(r["ok"] for r in results), "results": results}
    if via:
        res["via"] = via
    else:
        write_atomic(STATE / "selftest.json", json.dumps(res, ensure_ascii=False) + "\n")
    return res


def config() -> dict:
    return {**DEFAULT_CONFIG, **load_json(CONFIG, {})}


def relay_tcp_ports(conf: dict | None = None) -> dict[int, int]:
    """Configured relay-facing TCP port -> this server's inbound TCP port."""
    values = (config() if conf is None else conf).get("relay_tcp_alt", {})
    ports = {int(public): int(backend) for public, backend in values.items()}
    if any(not 1 <= port <= 65535 for pair in ports.items() for port in pair):
        raise ValueError("relay_tcp_alt: TCP ports must be in 1..65535")
    return ports


# ---------- subscription links ----------

def reality_pbk(private_key: str) -> str:
    m = re.search(r"(?:Public key|PublicKey\)?|Password):\s*(\S+)", run("xray", "x25519", "-i", private_key))
    return m.group(1) if m else ""


def cert_pin(hc: dict) -> str:
    cert = (hc.get("tls") or {}).get("cert")
    if not cert:
        return ""
    der = subprocess.run(["openssl", "x509", "-in", cert, "-outform", "der"], capture_output=True).stdout
    return hashlib.sha256(der).hexdigest() if der else ""


def check_links(text: str, xc: dict, hc: dict, addrs: set[str], pbk=reality_pbk, pin=cert_pin,
                relay_ports: dict[str, dict[int, int]] | None = None) -> tuple[int, list[str]]:
    """Every vless:// and hysteria2:// line of `text` against the live configs of this server: the link
    must work as it is (same port, key, SNI, shortId, path, password) and point at this server - its IP
    or an address of /etc/bvpn/server LINK_HOSTS (a relay that forwards the same ports here, e.g.
    the Russian chain). Returns (links checked, problems); a problem names the line and the field,
    never the value. Known relay TCP ports are translated to the corresponding inbound before
    validating its protocol and credentials."""
    if relay_ports is None:
        relays = read_env(SERVER_ENV).get("LINK_HOSTS", "").split()
        ports = relay_tcp_ports()
        relay_ports = {host: ports for host in relays}
    resolved = {}

    def addr_ok(host: str) -> bool:
        if host in addrs:
            return True
        try:
            resolved[host] = socket.gethostbyname(host)
            return resolved[host] in addrs
        except OSError:
            return False

    inbounds = {}
    for ib in vless_inbounds(xc):
        port = 443 if not _public(ib.get("listen")) else int(ib.get("port") or 0)
        inbounds[port] = ib
    pbks: dict[str, str] = {}
    n, probs = 0, []
    for no, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line.startswith(("vless://", "hysteria2://")):
            continue
        n += 1
        bad = lambda what: probs.append(f"line {no}: {what}")
        try:
            u = urllib.parse.urlsplit(line)
            port = u.port
        except ValueError:
            bad("not a link")
            continue
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query, keep_blank_values=True).items()}
        if not addr_ok(u.hostname or ""):
            bad("address is not this server")
        if u.scheme == "vless":
            mapped = relay_ports.get(u.hostname or "", relay_ports.get(resolved.get(u.hostname), {}))
            port = mapped.get(port, port)
            ib = inbounds.get(port)
            if not ib:
                bad(f"no VLESS on port {port}")
                continue
            client = next((c for c in ib.get("settings", {}).get("clients", [])
                           if c.get("id") == urllib.parse.unquote(u.username or "")), None)
            if not client:
                bad("user id is not on the server")
                continue
            if (q.get("flow") or "") != (client.get("flow") or ""):
                bad("flow")
            ss = ib.get("streamSettings", {})
            if (q.get("type") or "tcp") != ss.get("network", "tcp"):
                bad("transport type")
            if ss.get("security") == "reality":
                r = ss.get("realitySettings", {})
                if q.get("security") != "reality":
                    bad("security")
                if q.get("sni") not in (r.get("serverNames") or []):
                    bad("sni")
                if (q.get("sid") or "") not in (r.get("shortIds") or [""]):
                    bad("shortId")
                key = r.get("privateKey", "")
                if key not in pbks:
                    pbks[key] = pbk(key)
                if not pbks[key] or q.get("pbk") != pbks[key]:
                    bad("public key")
            if ss.get("security") == "tls" and q.get("security") != "tls":
                bad("security")
            if ss.get("network") == "xhttp" and q.get("path") != ss.get("xhttpSettings", {}).get("path", "/"):
                bad("xhttp path")
        else:
            if str(port) != str(hc.get("listen", "")).rpartition(":")[2]:
                bad("hysteria port")
            a = hc.get("auth") or {}
            auth = urllib.parse.unquote(u.netloc.rpartition("@")[0]) if "@" in u.netloc else ""
            if a.get("type") == "userpass":
                user, _, pw = auth.partition(":")
                if not user or (a.get("userpass") or {}).get(user) != pw:
                    bad("hysteria login or password")
            elif auth != str(a.get("password", "")):
                bad("hysteria password")
            o = hc.get("obfs") or {}
            if o.get("type") == "salamander" and (q.get("obfs") != "salamander"
                                                  or q.get("obfs-password") != o["salamander"]["password"]):
                bad("obfs")
            want = pin(hc)
            if q.get("pinSHA256") and want and q["pinSHA256"].replace(":", "").lower() != want:
                bad("certificate pin")
    return n, probs


# ---------- snapshot ----------

def snapshot(probe_ip: str | None = None) -> dict:
    now = time.time()
    env = read_env(SERVER_ENV)
    names = read_people(PEOPLE)
    xc = load_json(XCONF, {})
    htext, ttext = read(HCONF), read(TCONF)
    hc = yaml_load(htext)
    units = units_state()
    pub, lo = listening()
    ver = versions()

    st = load_json(STATE / "selftest.json", {})
    if not st.get("at") or now - (ts_from_systemd(st["at"]) or 0) > SELFTEST_MAX_AGE:
        st = selftest()
    by_ch = {}
    for r in st.get("results", []):
        by_ch.setdefault(r["channel"], []).append(r["ok"])

    state = load_json(STATE / "counters.json", {})
    xs = xray_stats(xc)
    hs = hy_stats(hc)
    tsx = telemt_stats(ttext)
    counters = {}
    if xs:
        counters.update({f"xray:{k}": v for k, v in xs[0].items()})
    if hs:
        counters.update({f"hy:{k}": v for k, v in hs[0].items()})
    if tsx:
        counters.update({f"tg:{k}": v["total"] for k, v in tsx.items()})
    account(state, now, counters)

    hy_kind, hy_users = hy_auth(hc)
    hy_port = str(hc.get("listen", ":443")).rpartition(":")[2]
    tport = telemt_port(ttext, "server", "5223")
    people_x = xray_people(xc)
    logins = sorted(set(people_x) | set(hy_users) | set(telemt_users(ttext)) | set(names))
    people = []
    for login in logins:
        chans = sorted(people_x.get(login, set()))
        if hy_kind == "userpass" and login in hy_users:
            chans.append("calls")
        elif hy_kind != "userpass" and people_x.get(login):
            chans.append("calls")          # one shared password: everybody with a kit has "2 Звонки"
        if login in telemt_users(ttext):
            chans.append("telegram")
        if not chans:
            if (PAUSED / f"{login}.json").exists():     # paused: out of every config, kept for person-resume
                people.append({"login": login, "name": names.get(login, login), "paused": True, "channels": [],
                               "online": False, "last_seen": iso(state.get("seen", {}).get(login)),
                               "traffic": {"1h": 0, "24h": 0, "7d": window(state, now, login, 7 * 86400),
                                           "30d": window(state, now, login, 30 * 86400)},
                               "daily": daily(state, now, login)})
            continue
        xo = (xs[1].get(login) if xs else None) or {}
        last = max([t for t in (xo.get("last"), state.get("seen", {}).get(login)) if t] or [0]) or None
        people.append({
            "login": login, "name": names.get(login, login),
            "channels": [c for c in CHANNELS if c in chans],
            "vless": {"devices": xo.get("devices", 0)} if xs else None,
            "calls": {"online": (hs[1].get(login, 0) if hs else None)} if hy_kind == "userpass" else None,
            "telegram": {k: tsx[login][k] for k in ("enabled", "online")} if tsx and login in tsx else None,
            # Xray 26 keeps "online" for XHTTP but not for Reality Vision: traffic in the last
            # 10 minutes counts as online there
            "online": bool(xo.get("devices")) or bool(hs and hs[1].get(login))
                      or bool(tsx and tsx.get(login, {}).get("online"))
                      or now - (state.get("seen", {}).get(login) or 0) < ONLINE_BY_TRAFFIC,
            "last_seen": iso(last),
            "traffic": {"1h": window(state, now, login, 0), "24h": window(state, now, login, 86400),
                        "7d": window(state, now, login, 7 * 86400), "30d": window(state, now, login, 30 * 86400)},
            "daily": daily(state, now, login),
        })
    deadl = deadlines(hc, state, now, ver)
    write_atomic(STATE / "counters.json", json.dumps(state) + "\n", 0o600)

    channels = []
    tcp_ports = config()["tcp"]
    for cid, (title, proto) in CHANNELS.items():
        if cid in ("main", "backup"):
            unit = "xray"
            port = f"tcp/{tcp_ports['tls' if cid == 'main' else 'xhttp']}"
            listen = port in pub
        elif cid == "calls":
            unit, port = "hysteria-server", f"udp/{hy_port}"
            listen = port in pub
        else:
            unit, port = "telemt", f"tcp/{tport}"
            listen = port in pub
        if unit not in units:
            continue
        oks = by_ch.get(cid)
        channels.append({"id": cid, "title": title, "proto": proto, "port": port, "unit": unit,
                         "unit_state": units[unit]["state"], "listening": listen,
                         "selftest": None if oks is None else all(oks),
                         "ok": units[unit]["state"] == "active" and listen and oks is not False})
    out = {
        "schema": 1,
        "server": env.get("ID", ""), "title": env.get("TITLE", socket.gethostname()), "ip": env.get("IP", ""),
        "collected_at": iso(now),
        "host": host_info(), "versions": ver, "units": units, "listen_public": sorted(pub),
        "channels": channels, "russia": ru_exit(env),
        "accounting": {"xray": bool(xs), "calls": "per-person" if hs else ("shared-password" if hy_kind != "userpass" else "no-stats"),
                       "telegram": tsx is not None},
        "people": people,
        "health": health(),
        "selftest": {"at": st.get("at", ""), "ok": st.get("ok", False),
                     "results": [{k: r[k] for k in ("channel", "login", "exit_ip", "expected", "ok")} for r in st.get("results", [])]},
        "probe": probe(probe_ip, xc, ttext) if probe_ip else None,
        "deadlines": deadl,
        "pending": pending(),
    }
    return out


def emit_clean(obj: dict, known: set[str]) -> int:
    text = json.dumps(obj, ensure_ascii=False, indent=1)
    bad = scan(text, known)
    if bad:
        print(f"vpnlib: refusing to print, looks like a secret: {', '.join(bad)}", file=sys.stderr)
        return 3
    print(text)
    return 0


def _known_live() -> set[str]:
    return known_secrets(load_json(XCONF, {}), yaml_load(read(HCONF)), read(TCONF))


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else ""
    if cmd in ("snapshot", "selftest", "hy-auth", "scan", "linkcheck"):
        try:
            import yaml  # noqa: F401  - without it Hysteria2 secrets would be invisible to scan
        except ImportError:
            print("vpnlib: python3-yaml is missing (apt install python3-yaml)", file=sys.stderr)
            return 2
    if cmd == "template":
        print(config()["template"])
        return 0
    if cmd == "snapshot":
        ip = argv[2] if len(argv) > 2 and argv[1] == "--probe" else None
        if ip and not re.fullmatch(r"[0-9.]{7,15}", ip):
            print("vpnlib: --probe IPv4", file=sys.stderr)
            return 2
        return emit_clean(snapshot(ip), _known_live())
    if cmd == "selftest" and len(argv) in (3, 5) and argv[1] == "--via":
        if not re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", argv[2]) or (len(argv) == 5 and argv[3] != "--map"):
            print("vpnlib: --via IPv4 [--map tcpPORT=PORT,...]", file=sys.stderr)
            return 2
        try:
            ports = parse_map(argv[4]) if len(argv) == 5 else None
        except ValueError as e:
            print(f"vpnlib: {e}", file=sys.stderr)
            return 2
        res = selftest(argv[2], ports)
        return emit_clean(res, _known_live()) or (0 if res["ok"] else 1)
    if cmd == "selftest":
        res = selftest()
        rc = emit_clean(res, _known_live())
        if len(argv) == 3 and argv[1] == "--baseline":
            lost = regressions(load_json(Path(argv[2]), {}), res)
            for c in lost:
                print(f"selftest: {c} worked before and fails now", file=sys.stderr)
            return rc or (1 if lost else 0)
        return rc or (0 if res["ok"] else 1)
    if cmd == "guard" and len(argv) == 3:
        probs = guard(load_json(Path(argv[1]), {}), load_json(Path(argv[2]), {}))
        for p in probs:
            print(f"guard: {p}", file=sys.stderr)
        return 1 if probs else 0
    if cmd == "hy-auth" and len(argv) == 2:
        try:
            new, users = hy_update(read(HCONF), json.loads(sys.stdin.read()))
        except (ValueError, KeyError, TypeError) as e:
            print(f"vpnlib: {e}", file=sys.stderr)
            return 1
        write_atomic(Path(argv[1]), new, 0o640)
        print(f"candidate {argv[1]}: userpass for {', '.join(users)}")
        return 0
    if cmd == "linkcheck":
        env = read_env(SERVER_ENV)
        addrs = {a for a in [env.get("IP", ""), *env.get("LINK_HOSTS", "").split()] if a}
        n, probs = check_links(sys.stdin.read(200000), load_json(XCONF, {}), yaml_load(read(HCONF)), addrs)
        for x in probs:
            print(f"linkcheck: {x}")
        print(f"linkcheck: {n} links, {'OK' if n and not probs else 'NOT OK'}")
        return 0 if n and not probs else 1
    if cmd == "scan" and len(argv) == 2:
        bad = scan(read(Path(argv[1])), _known_live())
        print("clean" if not bad else "secret-like: " + ", ".join(bad))
        return 1 if bad else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
