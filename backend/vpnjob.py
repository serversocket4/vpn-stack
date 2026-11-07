#!/usr/bin/env python3
"""vpnjob - VPN panel backend on the VPN server (stdlib). Installed to
/usr/local/lib/bvpn/vpnjob.py next to vpnlib.py.

  snapshot-all       (root, bvpn-snapshot.timer, 5 min) snapshots of every server ->
                     /var/lib/bvpn/panel.json (644, no secrets)
  run ID             (root, bvpn-job@ID.service, started by bvpn-admin through polkit
                     after the owner pressed "Подтвердить" in боте)
                     /var/lib/bvpn-outbox/ID.json -> /var/lib/bvpn/results/ID.json
  propose            (user operator, from the repo) request JSON on stdin -> checked like `run`
                     checks it -> /var/lib/bvpn-proposals/<id>.json for the admin to offer
  digest             request JSON on stdin -> the digest the admin must put into the job

A request: {"id", "server", "action", "args": {...}, "title", "why"}; the job adds
{"digest", "approved": {"by", "at"}}. Only the actions in ACTIONS exist; the arguments are
checked here again, whatever the admin checked before. Nothing here prints a secret: the
wrapper bvpn never does, and its output is scanned once more before it is stored.
"""
from __future__ import annotations

import base64
import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vpnlib  # noqa: E402

VAR = Path("/var/lib/bvpn")
OUTBOX = Path("/var/lib/bvpn-outbox")
PROPOSALS = Path("/var/lib/bvpn-proposals")
PANEL = VAR / "panel.json"
RESULTS = VAR / "results"
KITS_OUT = Path("/var/lib/bvpn-kits")      # root:bvpn-admin 2770: the admin sends a kit and deletes it
LOCK = Path("/run/bvpn-job.lock")
WRAPPER = "/usr/local/sbin/bvpn"
ID_RE = re.compile(r"^[a-z0-9-]{3,40}$")
LOGIN_RE = re.compile(r"^[a-z][a-z0-9]{1,15}$")
CONF = vpnlib.config()
KITS = Path(CONF["kits"])                         # kits of people, root 700
SERVER_ID = CONF["server_id"]
TEMPLATE = CONF["template"]                        # whose kit and settings a new person copies; never removed
KEEP_PEOPLE = (TEMPLATE,)
PERSON_SECONDS = 600
KIT_FILE_RE = re.compile(r"^[0-9a-z][0-9a-z_-]{0,60}\.(txt|png|yaml|json)$")   # no .bak, no dotfiles
KIT_MAX_BYTES = 20 * 1024 * 1024
SUB_DIR = Path("/var/lib/bvpn-sub")              # root:caddy 750, one file per token; Caddy serves it
SUB_TOKENS = Path("/etc/bvpn/sub-tokens.json")   # root 600: {person: token}
SUB_URL = CONF["sub_url"]
SUB_SETTINGS = Path("/etc/bvpn/sub-settings.json")   # root 600: {person: {group, expire, limit_gb, routing, proxy_add, direct_add, relay_only}}
WECHAT_SITES = ("domain:wechat.com", "domain:weixin.qq.com", "domain:wx.qq.com", "domain:qq.com",
                "domain:qpic.cn", "domain:qlogo.cn", "domain:servicewechat.com", "domain:wechatpay.com", "domain:tenpay.com")
ROUTING_PROFILES = {"ai-social": "ИИ и соцсети через VPN", "all": "всё через VPN",
                    "all-but-ru": "всё через VPN, кроме российских сайтов"}
DOMAIN_RE = re.compile(r"^(?=.{4,80}$)([a-z0-9-]+\.)+[a-z]{2,24}$")
SUBS = VAR / "subs.json"                               # 644 summary for the admin: persons and sources, no tokens
NOTE_RE = re.compile(r"^[0-9A-Za-zА-Яа-яЁё .,()!-]*$")
SUB_LABELS = {SERVER_ID: CONF["label"]}              # added to each name in the app
SUB_FILES = ("6-tls.txt", "3-backup.txt", "2-calls.txt")   # order = order in the app

SERVERS = {SERVER_ID: {"title": CONF["title"], "ip": CONF["ip"], "probe": "", "ssh": None}}
UNITS = ("xray", "hysteria-server", "telemt")

# The Russian chain: phone -> relay in Russia -> the VPN server. The relay only
# forwards ports (nftables DNAT), holds no keys and decrypts nothing, so any fresh VPS becomes one in a
# couple of minutes: relay-set renders the setup, checks every channel through it and re-publishes the
# subscriptions. One relay at a time; a banned one is replaced, not kept as a spare.
RELAY = Path("/etc/bvpn/relay.json")             # 644: {"ip", "since", "job", "history"} - no secrets
RELAY_SERVER = SERVER_ID                            # whose ports the relay forwards
RELAY_KEY = Path("/root/.ssh/id_ed25519_vpn_relay")    # root's key to the relay; its .pub goes to the VPS
RELAY_PUB = VAR / "relay-key.pub"                      # 644 copy, so the chat and the owner can read it
RELAY_KNOWN = Path("/etc/bvpn/relay_known_hosts")
# Some providers restrict outbound TCP/22. A relay can expose this additional management port;
# a fresh VPS may need a separate bootstrap connection before this port is available.
RELAY_SSH_PORT = 2222
RELAY_STATE = VAR / "relay-state.json"                 # counter samples and the last alert
RELAY_TCP = tuple(CONF["tcp"].values())                # NL inbound ports carried by the relay
RELAY_UDP = (443,)
RELAY_TCP_ALT = vpnlib.relay_tcp_ports(CONF)             # relay-facing port -> NL inbound port
# The Telegram proxy has a port of its own: the hoster of a relay may let no tcp/5223 out
RELAY_TG_PORT = CONF["tcp"]["telegram"]
RELAY_REMOTE: dict[str, dict] = {}
# Hysteria port hopping (Happ: several ports in the link + mportHopInt): the relay takes this UDP range and hands it
# to 443 on the VPN server, so neither its config nor its ufw change
RELAY_UDP_HOP, RELAY_HOP_SECONDS = tuple(CONF["hop"]), 30
# What a person sees through the relay: four servers, plain names. (kit file, variant, name); "hop" = Hysteria with
# port hopping. Hysteria first: UDP has no ClientHello for an operator to cut. VLESS Reality with vision is not offered:
# on MTS the 2nd segment of a long ClientHello is cut; TLS with fp ios sends it in one segment.
RELAY_PLAN = (("2-calls.txt", "hop", "Основной"), ("6-tls.txt", "", "Запасной 1"),
              ("2-calls.txt", "", "Запасной 2"), ("3-backup.txt", "", "Запасной 3"))
RELAY_FILES = tuple(dict.fromkeys(f for f, _, _ in RELAY_PLAN))
RELAY_FLAG = CONF["flag"]
# Only for Reality (relay_variants): plain TLS with fp ios has a one-segment ClientHello already
RELAY_FRAGMENT = "100-200,5-10,tlshello"
RELAY_LABEL = "через РФ"
PREFIXES = VAR / "operator-prefixes.json"              # RIPEstat cache: {"at", "ops": {op: [prefix]}}
OPERATORS = {"mts": ("МТС", (8359,)), "megafon": ("МегаФон", (31133, 25159)),
             "beeline": ("Билайн", (3216, 16345)), "t2": ("Т2", (15378, 12958, 48092, 42437))}
STALL_BYTES = 20 * 1024        # TSPU freezes a session after ~16 KB: fewer bytes per new connection = stalled
STALL_MIN_CONN = 5
CHECKS = Path("/var/lib/bvpn-checks")            # results of the phone check page (vpnsub) -> the bot
CHECK_STARTS = VAR / "check-starts.json"               # relay counters when a phone check began, per person
IPV4_RE = re.compile(r"^(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$")

# action -> (title for the bot, what it drops for connected people)
ACTIONS = {
    "refresh": ("обновить снимок", "ничего"),
    "selftest": ("самопроверка всех каналов временными клиентами", "ничего"),
    "restart": ("перезапуск службы", "у всех на этом сервере канал службы моргнёт на пару секунд"),
    "xray-apply": ("правка Xray с откатом по таймеру",
                   "Xray перезапустится: «Запасной 1» и «Запасной 3» моргнут на пару секунд; "
                   "без «Работает» правка откатится сама"),
    "confirm": ("оставить правку", "ничего"),
    "revert": ("откатить правку сейчас", "служба правки перезапустится, канал моргнёт"),
    "update": ("обновить программу (официальная сборка, проверка SHA-256)",
               "служба перезапустится, её каналы моргнут на пару секунд у всех на сервере; "
               "без «Работает» за 5 минут вернётся прежняя версия"),
    "ufw": ("одно правило firewall (не порт 22) с откатом по таймеру",
            "правила перечитаются без разрыва; без «Работает» за 5 минут вернутся прежние"),
    "person-add": ("подключить человека",
                   "Xray и прокси Telegram (и «Звонки», если у сервера личные пароли) моргнут на пару секунд "
                   "у всех на сервере; без «Работает» за 10 минут человек уберётся сам"),
    "person-remove": ("отключить человека",
                      "Xray и прокси Telegram (и «Звонки») моргнут на пару секунд у всех на сервере; "
                      "без «Работает» за 10 минут человек вернётся сам"),
    "kit-send": ("прислать комплект человека файлом (только владельцу)", "ничего: VPN не трогается"),
    "sub-publish": ("опубликовать подписку человека (что увидит его приложение)",
                    "ничего на серверах; приложение человека подтянет новые ссылки само в течение часа"),
    "person-pause": ("приостановить человека (ссылки сохранятся)",
                     "Xray и прокси Telegram (и «Звонки») моргнут на пару секунд у всех на сервере; "
                     "без «Работает» за 10 минут человек вернётся сам"),
    "person-resume": ("возобновить человека (те же ссылки)",
                      "Xray и прокси Telegram (и «Звонки») моргнут на пару секунд у всех на сервере; "
                      "без «Работает» за 10 минут пауза вернётся сама"),
    "sub-send": ("прислать ссылку-подписку человека (QR и текст для пересылки)", "ничего: VPN не трогается"),
    "sub-rotate": ("новая ссылка-подписка вместо старой", "ничего на серверах; старая ссылка сразу перестаёт работать"),
    "sub-settings": ("настройки подписки: срок, лимит, группа, маршрутизация",
                     "ничего на серверах; приложение человека подтянет изменения в течение часа"),
    "sub-reveal": ("показать ссылку-подписку на странице админки (один раз)", "ничего: VPN не трогается"),
    "relay-set": ("новый посредник в РФ: настроить, проверить все каналы через него, обновить подписки",
                  "VPN-сервер не меняется; приложения возьмут новый адрес за час или по «Обновить»"),
    "relay-check": ("проверить посредник в РФ: все каналы через него и счётчики операторов", "ничего"),
}


class Bad(ValueError):
    pass


def validate(req: dict) -> dict:
    """Return a clean copy of the request or raise Bad. Used by run, propose and digest."""
    if not isinstance(req, dict):
        raise Bad("request must be an object")
    rid, server, action = req.get("id", ""), req.get("server", ""), req.get("action", "")
    args = req.get("args") or {}
    if not ID_RE.match(str(rid)):
        raise Bad("id: [a-z0-9-]{3,40}")
    if action == "refresh":
        server = server or "all"
        if server != "all" and server not in SERVERS:
            raise Bad("server: all | " + " | ".join(SERVERS))
    elif action in ("relay-set", "relay-check"):
        if (server or RELAY_SERVER) != RELAY_SERVER:
            raise Bad(f"server: {RELAY_SERVER} (the relay forwards its ports)")
        server = RELAY_SERVER
    elif action in ("sub-publish", "sub-send", "sub-rotate", "sub-settings", "sub-reveal"):
        if (server or "all") != "all":
            raise Bad("server: all (sources name the servers)")
        server = "all"
    elif server not in SERVERS:
        raise Bad("server: " + " | ".join(SERVERS))
    if action not in ACTIONS:
        raise Bad("action: " + " | ".join(ACTIONS))
    if not isinstance(args, dict):
        raise Bad("args must be an object")
    clean: dict = {}
    if action == "restart":
        if args.get("unit") not in UNITS:
            raise Bad("unit: " + " | ".join(UNITS))
        clean["unit"] = args["unit"]
    elif action == "xray-apply":
        f = args.get("filter")
        if not isinstance(f, str) or not f.strip() or len(f) > 20000:
            raise Bad("filter: a jq filter, up to 20000 characters")
        if vpnlib.scan(f):
            raise Bad("filter looks like it carries a secret - make such changes through SSH")
        sec = args.get("seconds", 300)
        if not isinstance(sec, int) or not 60 <= sec <= 900:
            raise Bad("seconds: 60..900")
        clean.update(filter=f, seconds=sec)
    elif action == "ufw":
        op, rule = args.get("op"), args.get("rule")
        m = re.fullmatch(r"([0-9]{1,5})/(tcp|udp)", rule or "")
        if op not in ("allow", "delete") or not m or not 1 <= int(m.group(1)) <= 65535 or m.group(1) == "22":
            raise Bad("op: allow | delete; rule: PORT/tcp|udp, never port 22")
        clean.update(op=op, rule=rule)
    elif action == "update":
        if args.get("program") not in ("xray", "hysteria"):
            raise Bad("program: xray | hysteria")
        if not isinstance(args.get("version"), str) or not re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", args["version"]):
            raise Bad("version: N.N.N")
        clean.update(program=args["program"], version=args["version"])
    elif action in ("person-add", "person-remove", "person-pause", "person-resume"):
        login = args.get("login", "")
        if not isinstance(login, str) or not LOGIN_RE.match(login):
            raise Bad("login: 2-16 latin lowercase letters and digits, starting with a letter")
        if action == "person-remove" and login in KEEP_PEOPLE:
            raise Bad(f"{login} is not removed through the panel")
        if action == "person-pause" and login in KEEP_PEOPLE:
            raise Bad(f"{login} is not paused: the template of new people")
        clean["login"] = login
        if action in ("person-add", "person-remove") and "sub" in args:   # add: published / remove: deleted after "Работает"
            if not isinstance(args["sub"], str) or not LOGIN_RE.match(args["sub"]):
                raise Bad("sub: the person of the subscription, like a login")
            if action == "person-add" and relay_ip() and not relay_carries(server):
                raise Bad(f"the relay does not forward the ports of {server} yet - relay-set {relay_ip()} again first")
            clean["sub"] = args["sub"]
        if action == "person-add":
            name = args.get("name", "")
            if not isinstance(name, str) or not 1 <= len(name.strip()) <= 40 or re.search(r'["|\\\n\r]', name):
                raise Bad("name: 1-40 characters, no quotes, | or backslash")
            clean["name"] = name.strip()
    elif action == "kit-send":
        login, files = args.get("login", ""), args.get("files", [])
        if not isinstance(login, str) or not LOGIN_RE.match(login):
            raise Bad("login: 2-16 latin lowercase letters and digits, starting with a letter")
        if (not isinstance(files, list) or len(files) > 30
                or not all(isinstance(f, str) and KIT_FILE_RE.match(f) for f in files)):
            raise Bad("files: up to 30 kit file names like 2-calls.png (.txt .png .yaml .json, no .bak)")
        clean["login"] = login
        if files:
            clean["files"] = sorted(set(files))
    elif action == "sub-publish":
        person, sources = args.get("person", ""), args.get("sources")
        if not isinstance(person, str) or not LOGIN_RE.match(person):
            raise Bad("person: 2-16 latin lowercase letters and digits, starting with a letter")
        if not isinstance(sources, list) or not 1 <= len(sources) <= 4:
            raise Bad("sources: 1-4 of {server, login}")
        clean_src = []
        for x in sources:
            if (not isinstance(x, dict) or not {"server", "login"} <= set(x) <= {"server", "login", "note"}
                    or x["server"] not in SERVERS or not isinstance(x["login"], str) or not LOGIN_RE.match(x["login"])):
                raise Bad("sources: [{server: " + " | ".join(SERVERS) + ", login, note?}]")
            note = x.get("note", "")
            if not isinstance(note, str) or len(note) > 40 or not NOTE_RE.match(note):
                raise Bad("note: up to 40 letters, digits, spaces and . , - ( ) !")
            src = {"server": x["server"], "login": x["login"]}
            if relay_ip() and not relay_carries(src["server"]):
                raise Bad(f"the relay does not forward the ports of {src['server']} yet - relay-set {relay_ip()} again first")
            if any(c["server"] == src["server"] and c["login"] == src["login"] for c in clean_src):
                raise Bad("sources: the same source twice")
            if note.strip():
                src["note"] = note.strip()
            clean_src.append(src)
        clean.update(person=person, sources=clean_src)
    elif action == "sub-settings":
        person = args.get("person", "")
        if not isinstance(person, str) or not LOGIN_RE.match(person):
            raise Bad("person: 2-16 latin lowercase letters and digits, starting with a letter")
        clean["person"] = person
        group = args.get("group", "")
        if not isinstance(group, str) or len(group) > 24 or not NOTE_RE.match(group):
            raise Bad("group: up to 24 letters, digits, spaces and . , - ( ) !")
        expire = args.get("expire", "")
        if not isinstance(expire, str) or (expire and not re.fullmatch(r"20[2-9][0-9]-[01][0-9]-[0-3][0-9]", expire)):
            raise Bad("expire: YYYY-MM-DD or empty")
        limit = args.get("limit_gb", 0)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 0 <= limit <= 10000:
            raise Bad("limit_gb: 0..10000 (0 - no limit)")
        routing = args.get("routing", "ai-social")
        if routing not in ROUTING_PROFILES:
            raise Bad("routing: " + " | ".join(ROUTING_PROFILES))
        lists = {}
        for k in ("proxy_add", "direct_add"):
            v = args.get(k, [])
            if not isinstance(v, list) or len(v) > 50 or not all(isinstance(d, str) and DOMAIN_RE.match(d) for d in v):
                raise Bad(f"{k}: up to 50 domains like example.com")
            lists[k] = sorted(set(v))
        clean.update(group=group.strip(), expire=expire, limit_gb=limit, routing=routing, **lists)
    elif action in ("sub-send", "sub-rotate", "sub-reveal"):
        person = args.get("person", "")
        if not isinstance(person, str) or not LOGIN_RE.match(person):
            raise Bad("person: 2-16 latin lowercase letters and digits, starting with a letter")
        clean["person"] = person
    elif action == "relay-set":
        ip = args.get("ip", "")
        if not isinstance(ip, str) or not public_ipv4(ip):
            raise Bad("ip: the public IPv4 of the new relay")
        if ip in {x["ip"] for x in SERVERS.values()}:
            raise Bad("ip: that is one of our VPN servers, not a relay")
        clean["ip"] = ip
    elif action in ("confirm", "revert"):
        if not ID_RE.match(str(args.get("ref", ""))):
            raise Bad("ref: id of the xray-apply job")
        clean["ref"] = args["ref"]
    extra = set(args) - set(clean)
    if extra:
        raise Bad(f"unknown args: {sorted(extra)}")
    return {"id": rid, "server": server, "action": action, "args": clean,
            "title": str(req.get("title", ""))[:200], "why": str(req.get("why", ""))[:2000]}


def digest(req: dict) -> str:
    core = {k: req[k] for k in ("server", "action", "args")}
    return hashlib.sha256(json.dumps(core, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


# ---------- kits ----------

UUID_ANY = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
QR_WHOLE = ("6-tls", "2-calls", "3-backup")       # QR of the whole file, like onboard.sh
QR_FIRST = ("telegram-proxy",)                      # QR of the first line


def kit_name(setup: str) -> str:
    first = (setup.splitlines() or [""])[0]
    return first.rsplit("— ", 1)[-1].strip() if "— " in first else ""


def build_kit(src: Path, dst: Path, v: dict, new_name: str, move: tuple[str, str] | None = None) -> list[str]:
    """Copy the template kit `src` into `dst` for the new person. v: OLDU NEWU OLDK NEWK OLDAUTH NEWAUTH.
    Lines with any other UUID (e.g. the template's "Russia" users) are dropped; the result must hold
    none of the template's own secrets. move: (old IP, new IP) when the template kit is of another server
    : the address changes, and the Telegram proxy and pictures that are not drawn anew stay behind. Returns the file
    names written."""
    old_name = kit_name((src / "setup.txt").read_text()) if (src / "setup.txt").exists() else ""
    subs = [(v["OLDU"], v["NEWU"]), (v["OLDK"], v["NEWK"]), (v["OLDAUTH"] + "@", v["NEWAUTH"] + "@")]
    if v["OLDAUTH"] != v["NEWAUTH"]:
        subs.append((v["OLDAUTH"], v["NEWAUTH"]))     # the yaml of Clash Verge has the password alone
    if old_name:
        subs += [(urllib.parse.quote(old_name), urllib.parse.quote(new_name)), (old_name, new_name)]
    if move:
        subs.append(move)
    dst.mkdir(mode=0o700)
    written = []
    for f in sorted(src.iterdir()):
        n = f.name
        if (not f.is_file() or n.startswith(".") or f.suffix not in (".txt", ".png", ".yaml", ".json")
                or ".bak" in n or n.startswith("0-subscription")
                or (move and n.startswith("telegram"))):
            continue                                   # .DS_Store and other stray files of the Mac stay behind
        if f.suffix == ".png":
            if f.stem in QR_WHOLE + QR_FIRST or move:
                continue                               # drawn anew below
            shutil.copyfile(f, dst / n)
        else:
            text = f.read_text()
            for a, b in subs:
                text = text.replace(a, b)
            text = "\n".join(l for l in text.split("\n") if all(u == v["NEWU"] for u in UUID_ANY.findall(l)))
            (dst / n).write_text(text)
        os.chmod(dst / n, 0o600)
        written.append(n)
    for stem in QR_WHOLE + QR_FIRST:
        t = dst / f"{stem}.txt"
        if t.exists():
            data = t.read_text() if stem in QR_WHOLE else (t.read_text().splitlines() or [""])[0]
            png = subprocess.run(["qrencode", "-t", "PNG", "-s", "8", "-o", "-"], input=data.encode(),
                                 capture_output=True, check=True).stdout
            (dst / f"{stem}.png").write_bytes(png)
            os.chmod(dst / f"{stem}.png", 0o600)
            written.append(f"{stem}.png")
    left = [s for s in (v["OLDU"], v["OLDK"]) + ((v["OLDAUTH"],) if v["OLDAUTH"] != v["NEWAUTH"] else ())
            for f in dst.iterdir() if f.suffix != ".png" and s in f.read_text()]
    if left:
        raise Bad("the template's secrets are still in the new kit - stopped")
    if not ((dst / "6-tls.txt").exists() and v["NEWU"] in (dst / "6-tls.txt").read_text()):
        raise Bad("the new kit has no TLS link with the new key - stopped")
    return sorted(set(written))


def pack_kit(job_id: str, login: str, files: dict[str, bytes]) -> Path:
    """{name: content} -> KITS_OUT/<id>.kit.zip for the admin, which sends it to the owner in
    боте and deletes it (KITS_OUT root:bvpn-admin 2770, the zip 640)."""
    KITS_OUT.mkdir(mode=0o2770, exist_ok=True)
    try:
        os.chown(KITS_OUT, 0, grp.getgrnam("bvpn-admin").gr_gid)
    except (KeyError, PermissionError):
        pass
    z = KITS_OUT / f"{job_id}.kit.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(files):
            zf.writestr(f"{login}/{name}", files[name])
    try:
        os.chown(z, 0, grp.getgrnam("bvpn-admin").gr_gid)
    except (KeyError, PermissionError):
        pass
    os.chmod(z, 0o640)
    return z


def read_kit(login: str, only: list[str] | None) -> dict[str, bytes]:
    """The current kit of a connected person from KITS/<login> (a folder the chat user owns, read here
    as root): only regular files named like KIT_FILE_RE, never through a symlink, at most KIT_MAX_BYTES."""
    home = KITS / login
    if home.is_symlink() or not home.is_dir():
        raise Bad(f"no kit folder {home}")
    names = sorted(f.name for f in home.iterdir() if KIT_FILE_RE.match(f.name))
    if only:
        missing = sorted(set(only) - set(names))
        if missing:
            raise Bad(f"not in the kit of {login}: {', '.join(missing)}")
        names = list(only)
    if not names or ("6-tls.txt" not in names and not only):
        raise Bad(f"the kit of {login} has no 6-tls.txt - nothing sent")
    out, total = {}, 0
    for n in names:
        try:
            fd = os.open(home / n, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as e:
            raise Bad(f"{n}: not a plain file ({e.strerror})") from None
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                raise Bad(f"{n}: not a plain file")
            data = fh.read(KIT_MAX_BYTES + 1)
        total += len(data)
        if total > KIT_MAX_BYTES:
            raise Bad("the kit is larger than 20 MB - nothing sent")
        out[n] = data
    return out


def kit_links(login: str, only: tuple[str, ...] = SUB_FILES) -> list[str]:
    """vless:// and hysteria2:// lines of the person's current kit, in SUB_FILES order (no Telegram proxy:
    the apps that read subscriptions do not take MTProto). `only`: these kit files only."""
    files = read_kit(login, None)
    out = []
    for n in only:                                   # the order of `only` is the order in the app
        for line in files.get(n, b"").decode("utf-8", "replace").splitlines():
            line = line.strip()
            if line.startswith(("vless://", "hysteria2://")) and line not in out:
                out.append(line)
    return out


def relay_tcp_port(backend: int) -> int:
    """Public TCP port of the primary relay for one NL inbound."""
    return next((public for public, port in RELAY_TCP_ALT.items() if port == backend), backend)


def via_relay(link: str, ip: str, server: str = RELAY_SERVER) -> str:
    """Dial the relay, using its configured TCP port for the primary server."""
    u = urllib.parse.urlsplit(link)
    user, _, _ = u.netloc.rpartition("@")
    port = relay_tcp_port(u.port) if u.scheme == "vless" and server == RELAY_SERVER else u.port
    return urllib.parse.urlunsplit(u._replace(netloc=f"{user}@{ip}:{port}" if user else f"{ip}:{port}"))


def short_name(link: str, single: bool) -> str:
    """Names in the app, short: no person (the subscription is theirs anyway), no server when there is only one.
    Only the name changes."""
    base, _, frag = link.partition("#")
    parts = [x.strip() for x in urllib.parse.unquote(frag).split(" · ") if x.strip()]
    if len(parts) > 1 and re.match(r"\d", parts[1]):                  # "Имя · 1 Основной ..." -> drop the person
        parts = parts[1:]
    out = []
    for x in parts:
        x = x.replace("Звонки Telegram", "Звонки")
        for srv in SUB_LABELS.values():
            rest = x[len(srv):].strip() if x.startswith(srv) else None
            if rest == RELAY_LABEL or (rest is not None and single):
                x = rest                                               # "<сервер> через РФ" -> "через РФ"
        if x:
            out.append(x)
    return base + "#" + urllib.parse.quote(" · ".join(out) or " · ".join(parts), safe="")


def tg_proxy(login: str, relay: str) -> str:
    """The person's Telegram proxy (Telemt, Fake TLS) from the kit, using the relay's configured Telegram port
    when available. It is shown separately on the subscription page rather than as a Happ VPN profile."""
    files = read_kit(login, None)
    line = next((l.strip() for l in files.get("telegram-proxy.txt", b"").decode("utf-8", "replace").splitlines()
                 if l.strip().startswith("tg://proxy?")), "")
    if not line or not relay:
        return line
    u = urllib.parse.urlsplit(line)
    q = [(k, relay if k == "server" else str(RELAY_TG_PORT) if k == "port" else v)
         for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True)]
    return "tg://proxy?" + urllib.parse.urlencode(q)


def remote_port(link: str, server: str) -> str:
    """A link of a RELAY_REMOTE server, already dialing the relay -> the relay's port of that channel ('' when the
    relay does not carry it)."""
    u = urllib.parse.urlsplit(link.partition("#")[0])
    m = RELAY_REMOTE[server]["udp" if u.scheme.startswith("hysteria") else "tcp"]
    if u.port not in m:
        return ""
    return link.replace(f"@{u.hostname}:{u.port}", f"@{u.hostname}:{m[u.port]}", 1)


def plan_link(login: str, relay: str, kit_file: str, variant: str, title: str, server: str = RELAY_SERVER) -> str:
    """One RELAY_PLAN entry: the kit's link of that file through the relay, as the variant, named "🇺🇸 <title>"
    ('' when the kit has no such file or the relay does not carry that channel of this server)."""
    got = kit_links(login, (kit_file,))
    if not got:
        return ""                                      # an older kit without this channel: just fewer servers
    if server == RELAY_SERVER:
        link = via_relay(got[0], relay)
    else:
        link = remote_port(via_relay(got[0], relay, server), server)
        if not link:
            return ""
    if variant == "hop":
        link = relay_variants(link, RELAY_UDP_HOP if server == RELAY_SERVER else RELAY_REMOTE[server]["hop"])[0]
    return link.partition("#")[0] + "#" + urllib.parse.quote(f"{RELAY_FLAG} {title}", safe="")


def relay_variants(link: str, hop: tuple[int, int] = RELAY_UDP_HOP) -> list[str]:
    """A link through the relay -> itself, and a copy first: VLESS with RELAY_FRAGMENT ("· дробление"), Hysteria
    with port hopping over RELAY_UDP_HOP ("· прыжки"; the port list makes it no URL for urlsplit - nothing parses
    it after this)."""
    base, _, frag = link.partition("#")
    name = urllib.parse.unquote(frag).strip()
    if link.startswith("hysteria2://"):
        u = urllib.parse.urlsplit(base)
        if not u.port:
            return [link]
        lo, hi = hop
        hopped = base.replace(f"@{u.hostname}:{u.port}", f"@{u.hostname}:{u.port},{lo}-{hi}", 1)
        hopped += ("&" if "?" in hopped else "?") + f"mportHopInt={RELAY_HOP_SECONDS}"
        return [hopped + "#" + urllib.parse.quote(f"{name} · прыжки" if name else "прыжки", safe=""), link]
    if not link.startswith("vless://") or not RELAY_FRAGMENT or "security=reality" not in base:
        return [link]                                  # plain TLS with fp ios: the ClientHello is one segment already
    sep = "&" if "?" in base else "?"
    return [base + sep + "fragment=" + urllib.parse.quote(RELAY_FRAGMENT, safe="-,") + "#"
            + urllib.parse.quote(f"{name} · дробление" if name else "дробление", safe=""), link]


def label_link(link: str, label: str) -> str:
    """'...#Имя · Основной' -> '...#Имя · Основной · сервер': the same channel from two
    servers must not look the same in the app. Only the name changes, never the link itself."""
    base, _, frag = link.partition("#")
    name = urllib.parse.unquote(frag).strip()
    for old in SUB_LABELS.values():                   # a kit name never carries a label; drop a stale one
        if f" · {old}" in name:
            name = name[:name.index(f" · {old}")]
    if name.endswith(label):
        return link
    return base + "#" + urllib.parse.quote(f"{name} · {label}" if name else label, safe="")


def routing_link(text: str) -> str:
    """The Happ routing profile of the kit (happ://routing/onadd/<base64 JSON>): which sites go through the
    VPN and which go direct. Domains and public DNS only - checked to be a JSON object with no secret in it."""
    line = next((l.strip() for l in text.splitlines() if l.strip().startswith("happ://routing/")), "")
    m = re.fullmatch(r"happ://routing/(?:onadd|add)/([A-Za-z0-9+/=_-]{16,12000})", line)
    if not m:
        return ""
    try:
        prof = json.loads(base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4)))
    except (ValueError, TypeError):
        return ""
    if not isinstance(prof, dict) or vpnlib.scan(json.dumps(prof, ensure_ascii=False)):
        return ""
    return line


def stamp_routing(new: str, old: str) -> str:
    """Increase LastUpdated for changed Happ routing profiles. An unchanged profile keeps its existing link
    so applications do not reload geofiles unnecessarily."""
    def load(link: str) -> dict:
        b64 = link.rsplit("/", 1)[1]
        return json.loads(base64.b64decode(b64 + "=" * (-len(b64) % 4)))
    if not new:
        return new
    prof = load(new)
    try:
        before = load(old) if old else {}
    except (ValueError, IndexError):
        before = {}
    if before and {k: v for k, v in prof.items() if k != "LastUpdated"} == {k: v for k, v in before.items() if k != "LastUpdated"}:
        return old
    prof["LastUpdated"] = str(int(time.time()))
    return new.rsplit("/", 1)[0] + "/" + base64.b64encode(json.dumps(prof, ensure_ascii=False).encode()).decode()


def build_routing(base: str, st: dict) -> str:
    """The person's routing profile: the kit's one (base) changed by the subscription settings - which profile
    and which extra sites go through the VPN or direct. Same shape Happ reads (happ://routing/onadd/<b64>)."""
    prof = {}
    if base:
        b64 = base.rsplit("/", 1)[1]
        prof = json.loads(base64.b64decode(b64 + "=" * (-len(b64) % 4)))
    prof = {"Name": "", "GlobalProxy": "false", "RemoteDNSType": "DoU", "RemoteDNSDomain": "", "RemoteDNSIP": "1.1.1.1",
            "DomesticDNSType": "DoU", "DomesticDNSDomain": "", "DomesticDNSIP": "77.88.8.8", "DirectSites": [],
            "DirectIp": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"], "ProxySites": [], "ProxyIp": [],
            "BlockSites": [], "BlockIp": [], "DomainStrategy": "IPIfNonMatch", "FakeDNS": "false", **prof}
    kind = st.get("routing") or "ai-social"
    prof["Name"] = CONF["brand"] + " · " + ROUTING_PROFILES[kind]
    prof["GlobalProxy"] = "false" if kind == "ai-social" else "true"
    if kind == "all-but-ru":
        prof["DirectSites"] = list(prof["DirectSites"]) + ["geosite:category-ru", "domain:ru", "domain:su", "domain:xn--p1ai"]
        prof["DirectIp"] = list(prof["DirectIp"]) + ["geoip:ru"]
    prof["ProxySites"] = list(prof["ProxySites"]) + [f"domain:{d}" for d in st.get("proxy_add") or []]
    prof["DirectSites"] = list(prof["DirectSites"]) + [f"domain:{d}" for d in st.get("direct_add") or []]
    # Built-in profiles route Tencent domains and Chinese destination addresses directly for WeChat.
    prof["DirectSites"] = list(prof["DirectSites"]) + list(WECHAT_SITES)
    prof["DirectIp"] = list(prof["DirectIp"]) + ["geoip:cn"]
    if relay_ip():                                    # the Telegram proxy sits on the relay: straight to it, VPN on or off
        prof["DirectIp"] = list(prof["DirectIp"]) + [f"{relay_ip()}/32"]
    for k in ("ProxySites", "DirectSites", "DirectIp"):
        prof[k] = list(dict.fromkeys(prof[k]))
    prof["LastUpdated"] = str(int(time.time()))
    if vpnlib.scan(json.dumps(prof, ensure_ascii=False)):
        raise Bad("the routing profile looks like it carries a secret - stopped")
    return "happ://routing/onadd/" + base64.b64encode(json.dumps(prof, ensure_ascii=False).encode()).decode()


def connected(server: str) -> set[str]:
    try:
        snap = json.loads(PANEL.read_text())
        return {p["login"] for p in next(x for x in snap["servers"] if x.get("id") == server)["snapshot"]["people"]}
    except (OSError, ValueError, KeyError, TypeError, StopIteration):
        raise Bad(f"no fresh snapshot of the people on {server} - press refresh first") from None


def pending_add(server: str, login: str) -> str:
    """The id of an add of `login` on `server` still waiting for "Работает" ('' when none)."""
    rc, out = call(server, ["pending"], timeout=60)
    return next((l.split()[0] for l in out.splitlines() if rc == 0 and l.startswith(f"person-add-{login}-")), "")


def publish_sub(job_id: str, person: str, sources: list[dict]) -> tuple[str, dict | None]:
    """Links of every source, each checked by `bvpn linkcheck` on its own server, -> SUB_DIR/<token>
    (base64, as the apps expect). A new person gets a token, and the owner gets the link as a file."""
    links, parts, labels, name, routing, tg = [], [], [], "", "", ""
    for src in sources:
        if src["login"] not in connected(src["server"]):
            raise Bad(f"{src['login']} is not connected on {src['server']}")
        if pending_add(src["server"], src["login"]):    # it may still revert itself: the link would point at nobody
            raise Bad(f"{src['login']} on {src['server']} waits for \"Работает\" - the subscription comes after it by itself")
        got = kit_links(src["login"])
        if not got:
            raise Bad(f"the kit of {src['login']} has no links")
        relay = relay_ip() if src["server"] == RELAY_SERVER or src["server"] in RELAY_REMOTE else ""
        if relay and not relay_carries(src["server"]):
            raise Bad(f"the relay does not forward the ports of {src['server']} yet - relay-set {relay} again first")
        # relay links of other servers come from links checked right here (got): only the host and port change
        via = [via_relay(l, relay) for l in kit_links(src["login"], RELAY_FILES)] if relay and src["server"] == RELAY_SERVER else []
        rc, out = call(src["server"], ["linkcheck"], stdin="\n".join(got + via) + "\n", timeout=90)
        if rc != 0:
            raise Bad(f"links of {src['login']} do not match {src['server']}: {clean_output(out)[-400:]}")
        label = SUB_LABELS.get(src["server"], src["server"]) + (f" ({src['note']})" if src.get("note") else "")
        # relay_only: a phone on MTS reaches only the relay, so no direct links at all while there is a relay;
        # "relay_only": false in sub-settings brings the direct links back for one person
        direct = [] if relay_ip() and (vpnlib.load_json(SUB_SETTINGS, {}).get(person) or {}).get("relay_only", True) else got
        title_of = lambda t: t if len(sources) == 1 else f"{t} · {label}"
        links += [x for f, variant, title in RELAY_PLAN if relay
                  if (x := plan_link(src["login"], relay, f, variant, title_of(title), src["server"]))]
        links += [label_link(l, label) for l in direct]
        labels.append({"server": src["server"], "login": src["login"], "label": SUB_LABELS.get(src["server"], src["server"]),
                       "note": src.get("note", "")})
        tg = tg or tg_proxy(src["login"], relay)
        if not name:
            kit = read_kit(src["login"], None)
            name = kit_name(kit.get("setup.txt", b"").decode("utf-8", "replace"))
            routing = routing_link(kit.get("routing.txt", b"").decode("utf-8", "replace"))
        parts.append(f"{src['login']}@{src['server']}: {len(got)}")
    links = [short_name(l, len(sources) == 1) for l in links]
    tokens = vpnlib.load_json(SUB_TOKENS, {})
    new = person not in tokens
    token = tokens.get(person) or secrets.token_urlsafe(24)
    SUB_DIR.mkdir(mode=0o750, exist_ok=True)
    try:
        gid = grp.getgrnam("caddy").gr_gid
        os.chown(SUB_DIR, 0, gid)
    except (KeyError, PermissionError):
        gid = -1
    f = SUB_DIR / token
    if f.exists():
        (SUB_DIR / "prev").mkdir(mode=0o700, exist_ok=True)
        shutil.copyfile(f, SUB_DIR / "prev" / token)
    vpnlib.write_atomic(f, base64.b64encode("\n".join(links).encode()).decode() + "\n", 0o640)
    meta_dir = SUB_DIR / "meta"                  # what the page shows: no secrets, only names and servers
    meta_dir.mkdir(mode=0o750, exist_ok=True)
    meta = meta_dir / f"{token}.json"
    st = vpnlib.load_json(SUB_SETTINGS, {}).get(person) or {}
    if st:
        routing = build_routing(routing, st)
    routing = stamp_routing(routing, str(vpnlib.load_json(meta, {}).get("routing", "")))
    vpnlib.write_atomic(meta, json.dumps({"person": person, "name": name or person, "sources": labels, "routing": routing,
                                          "published": vpnlib.iso(time.time()),
                                          **{k: st[k] for k in ("group", "expire", "limit_gb", "proxy_add", "direct_add") if k in st},
                                          **({"routing_profile": st["routing"]} if st.get("routing") else {})},
                                         ensure_ascii=False) + "\n", 0o640)
    tg_dir = SUB_DIR / "tg"                      # the Telegram proxy of the page: a secret like the subscription itself
    tg_dir.mkdir(mode=0o750, exist_ok=True)
    tg_file = tg_dir / token
    if tg:
        vpnlib.write_atomic(tg_file, tg + "\n", 0o640)
    else:
        tg_file.unlink(missing_ok=True)
    if gid >= 0:
        for x in (f, meta_dir, meta, tg_dir, *([tg_file] if tg else [])):
            os.chown(x, 0, gid)
    if new:
        tokens[person] = token
        SUB_TOKENS.parent.mkdir(mode=0o755, exist_ok=True)
        vpnlib.write_atomic(SUB_TOKENS, json.dumps(tokens, indent=1) + "\n", 0o600)
    write_subs_summary()
    summary = f"subscription {person}: {len(links)} links ({'; '.join(parts)})"
    if not new:
        return summary + " - the apps pick it up within an hour", None
    save_link_in_kit(person, token)
    deliver_link(job_id, person, token)
    return summary + " - new link, sent to the owner", {"sub": job_id}


def link_files(token: str) -> dict[str, bytes]:
    url = SUB_URL + token + "\n"
    png = subprocess.run(["qrencode", "-t", "PNG", "-s", "8", "-o", "-"], input=url.strip().encode(),
                         capture_output=True, check=True).stdout
    return {"0-subscription.txt": url.encode(), "0-subscription.png": png}


def save_link_in_kit(person: str, token: str) -> None:
    """0-subscription.txt/.png into the person's kit folder (operator 700): kit-send then carries them too."""
    files = link_files(token)
    home = KITS / person
    if KITS.is_dir() and not home.is_symlink():
        home.mkdir(mode=0o700, exist_ok=True)
        try:
            pw = None
        except KeyError:
            pw = None
        for n, data in files.items():
            (home / n).write_bytes(data)
            os.chmod(home / n, 0o600)
            if pw:
                os.chown(home / n, pw.pw_uid, pw.pw_gid)
        if pw:
            os.chown(home, pw.pw_uid, pw.pw_gid)


def deliver_link(job_id: str, person: str, token: str) -> None:
    """The QR and a ready message with the subscription address -> KITS_OUT/<id>.sub.png and .sub.txt
    (root:bvpn-admin 640). The admin sends them as one photo with a caption to the owner's chat only
    and deletes them: the owner forwards that message to the person. Never into results or logs."""
    meta = vpnlib.load_json(SUB_DIR / "meta" / f"{token}.json", {})
    name = meta.get("name") or person
    files = link_files(token)
    text = (f"{name}, привет! Это твой {CONF['brand']}.\n\n"
            f"Открой ссылку — там всё по шагам: какое приложение поставить и как добавить подписку:\n"
            f"{SUB_URL}{token}\n\n"
            "Ссылка личная, никому её не пересылай.")
    KITS_OUT.mkdir(mode=0o2770, exist_ok=True)
    try:
        gid = grp.getgrnam("bvpn-admin").gr_gid
    except KeyError:
        gid = -1
    for ext, data in (("png", files["0-subscription.png"]), ("txt", text.encode())):
        f = KITS_OUT / f"{job_id}.sub.{ext}"
        f.write_bytes(data)
        os.chmod(f, 0o640)
        if gid >= 0:
            try:
                os.chown(f, 0, gid)
            except PermissionError:
                pass


def delete_sub(person: str) -> str:
    """The person's subscription is gone: token, links, page. The kit folder stays (the chat keeps kits)."""
    tokens = vpnlib.load_json(SUB_TOKENS, {})
    token = tokens.pop(person, None)
    if not token:
        return f"{person} had no subscription"
    for f in (SUB_DIR / token, SUB_DIR / "meta" / f"{token}.json", SUB_DIR / "prev" / token):
        if f.exists():
            f.unlink()
    vpnlib.write_atomic(SUB_TOKENS, json.dumps(tokens, indent=1) + "\n", 0o600)
    write_subs_summary()
    return f"subscription {person} deleted: its address answers 404"


def write_subs_summary() -> None:
    """VAR/subs.json (644) for the admin's tab: who has a subscription and from which servers. No tokens."""
    out = {}
    for f in sorted((SUB_DIR / "meta").glob("*.json")) if (SUB_DIR / "meta").is_dir() else []:
        m = vpnlib.load_json(f, {})
        if m.get("person"):
            out[m["person"]] = {"name": m.get("name", m["person"]), "published": m.get("published", ""),
                                **{k: m[k] for k in ("group", "expire", "limit_gb", "routing_profile", "proxy_add", "direct_add")
                                   if k in m},
                                "sources": [{k: x.get(k, "") for k in ("server", "login", "note")} for x in m.get("sources", [])]}
    vpnlib.write_atomic(SUBS, json.dumps(out, ensure_ascii=False, indent=1) + "\n", 0o644)


def settings_sub(job_id: str, args: dict) -> tuple[str, dict | None]:
    """Save the subscription settings and publish the subscription again with them (same sources, same link)."""
    person = args["person"]
    token = vpnlib.load_json(SUB_TOKENS, {}).get(person)
    meta = vpnlib.load_json(SUB_DIR / "meta" / f"{token}.json", {}) if token else {}
    if not meta.get("sources"):
        raise Bad(f"{person} has no subscription yet - publish it first (sub-publish)")
    all_st = vpnlib.load_json(SUB_SETTINGS, {})
    all_st[person] = {k: v for k, v in args.items() if k != "person"}
    SUB_SETTINGS.parent.mkdir(mode=0o755, exist_ok=True)
    vpnlib.write_atomic(SUB_SETTINGS, json.dumps(all_st, ensure_ascii=False, indent=1) + "\n", 0o600)
    out, pend = publish_sub(job_id, person, [{k: x[k] for k in ("server", "login", "note") if x.get(k)} for x in meta["sources"]])
    return f"settings of {person} saved; " + out, pend


def reveal_sub(job_id: str, person: str) -> tuple[str, dict]:
    """The address for the admin's page, once: KITS_OUT/<id>.reveal.txt (root:bvpn-admin 640); the page reads
    it, shows it to the owner and deletes it. Not into results, logs or the bot."""
    token = vpnlib.load_json(SUB_TOKENS, {}).get(person)
    if not token or not (SUB_DIR / token).exists():
        raise Bad(f"{person} has no subscription yet - publish it first (sub-publish)")
    KITS_OUT.mkdir(mode=0o2770, exist_ok=True)
    f = KITS_OUT / f"{job_id}.reveal.txt"
    f.write_text(SUB_URL + token + "\n")
    os.chmod(f, 0o640)
    try:
        os.chown(f, 0, grp.getgrnam("bvpn-admin").gr_gid)
    except (KeyError, PermissionError):
        pass
    return f"subscription address of {person} ready for the admin's page", {"reveal": job_id}


def send_sub(job_id: str, person: str) -> tuple[str, dict]:
    token = vpnlib.load_json(SUB_TOKENS, {}).get(person)
    if not token or not (SUB_DIR / token).exists():
        raise Bad(f"{person} has no subscription yet - publish it first (sub-publish)")
    deliver_link(job_id, person, token)
    return f"subscription link of {person} sent to the owner", {"sub": job_id}


def rotate_sub(job_id: str, person: str) -> tuple[str, dict]:
    """A new token for the person; the old address answers 404 at once. The apps keep the servers they have
    until the person adds the new link."""
    tokens = vpnlib.load_json(SUB_TOKENS, {})
    old = tokens.get(person)
    if not old or not (SUB_DIR / old).exists():
        raise Bad(f"{person} has no subscription yet - publish it first (sub-publish)")
    new = secrets.token_urlsafe(24)
    os.replace(SUB_DIR / old, SUB_DIR / new)
    if (SUB_DIR / "meta" / f"{old}.json").exists():
        os.replace(SUB_DIR / "meta" / f"{old}.json", SUB_DIR / "meta" / f"{new}.json")
    for f in (SUB_DIR / "prev" / old,):
        if f.exists():
            f.unlink()
    tokens[person] = new
    vpnlib.write_atomic(SUB_TOKENS, json.dumps(tokens, indent=1) + "\n", 0o600)
    save_link_in_kit(person, new)
    deliver_link(job_id, person, new)
    return f"new subscription link of {person} sent to the owner; the old one stopped working", {"sub": job_id}


def deliver_kit(job_id: str, login: str, dst: Path, send: bool = True) -> Path | None:
    """kit folder -> KITS/<login> (operator, the chat keeps kits) and, with send, KITS_OUT/<id>.kit.zip for the admin.
    A person added with a subscription gets no zip: the owner gets the subscription link after "Работает"."""
    z = pack_kit(job_id, login, {f.name: f.read_bytes() for f in sorted(dst.iterdir())}) if send else None
    home = KITS / login
    if not home.exists() and KITS.is_dir():
        shutil.copytree(dst, home)
        (home / ".panel-job").write_text(job_id + "\n")
    return z


# ---------- the Russian relay ----------

def public_ipv4(ip: str) -> bool:
    if not IPV4_RE.match(ip):
        return False
    a, b = (int(x) for x in ip.split(".")[:2])
    return not (a in (0, 10, 127) or a >= 224 or (a == 100 and 64 <= b < 128) or (a == 169 and b == 254)
                or (a == 172 and 16 <= b < 32) or (a == 192 and b == 168))


def relay_ip() -> str:
    ip = vpnlib.load_json(RELAY, {}).get("ip", "")
    return ip if isinstance(ip, str) and public_ipv4(ip) else ""


def relay_carries(server: str) -> bool:
    """The relay forwards this server's ports: RELAY_SERVER always, a RELAY_REMOTE one only after a relay-set that knew
    it (relay.json "servers"). A server added to RELAY_REMOTE later
    needs relay-set again (the same IP) before anyone moves there - else the links would dial ports nobody forwards."""
    if server == RELAY_SERVER:
        return True
    got = vpnlib.load_json(RELAY, {}).get("servers", [])
    return server in RELAY_REMOTE and isinstance(got, list) and server in got


def operator_prefixes(refresh: bool = False) -> dict[str, list[str]]:
    """IPv4 prefixes announced by the mobile operators' ASNs (RIPEstat), cached for a week. Only counters
    use them: a stale or empty list never blocks anything, it just counts those people as "other"."""
    cache = vpnlib.load_json(PREFIXES, {})
    if not refresh and time.time() - cache.get("at", 0) < 7 * 86400 and cache.get("ops"):
        return cache["ops"]
    ops = {}
    for op, (_, asns) in OPERATORS.items():
        got = []
        for asn in asns:
            try:
                d = vpnlib.http_json(f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}", timeout=60)
                got += [x["prefix"] for x in d["data"]["prefixes"] if re.fullmatch(r"[0-9.]+/[0-9]{1,2}", x.get("prefix", ""))]
            except (OSError, ValueError, KeyError, TypeError):
                got = []
                break
        ops[op] = sorted(set(got)) or (cache.get("ops") or {}).get(op, [])
    if any(ops.values()):
        vpnlib.write_atomic(PREFIXES, json.dumps({"at": time.time(), "ops": ops}) + "\n", 0o644)
    return ops


def relay_script(target: str, ops: dict[str, list[str]]) -> str:
    """Bash for a fresh Debian/Ubuntu VPS (root): nftables forwards RELAY_TCP/RELAY_UDP to `target`, counts
    new connections and bytes per mobile operator, drops everything else but SSH. Idempotent. No secret in it."""
    tcp, udp = ", ".join(map(str, RELAY_TCP)), ", ".join(map(str, RELAY_UDP))
    direct_tcp = ", ".join(str(port) for port in RELAY_TCP if port not in RELAY_TCP_ALT.values())
    remote = {SERVERS[k]["ip"]: m for k, m in RELAY_REMOTE.items()}
    every = "{ " + ", ".join([target, *remote]) + " }"
    alt = "".join(f", {a}->{b}" for a, b in RELAY_TCP_ALT.items()) + f"; udp {RELAY_UDP_HOP[0]}-{RELAY_UDP_HOP[1]}->443"
    sets, counters, count_rules = [], [], []
    for op in OPERATORS:
        elems = ", ".join(ops.get(op) or [])
        sets.append(f"\tset {op} {{ type ipv4_addr; flags interval; auto-merge;" + (f" elements = {{ {elems} }}" if elems else "") + " }")
    for op in (*OPERATORS, "other"):
        counters.append(f"\tcounter {op}_conn {{}}\n\tcounter {op}_down {{}}\n\tcounter {op}_up {{}}"
                        f"\n\tcounter {op}_tconn {{}}\n\tcounter {op}_tdown {{}}")
        match = f"ip saddr @{op}" if op != "other" else " ".join(f"ip saddr != @{o}" for o in OPERATORS)
        dmatch = match.replace("saddr", "daddr")
        count_rules.append(f"\t\tip daddr {every} ct state new {match} counter name {op}_conn\n"
                           f"\t\tip daddr {every} {match} counter name {op}_up\n"
                           f"\t\tip saddr {every} {dmatch} counter name {op}_down\n"
                           # TCP alone for the stall check: Hysteria hops UDP ports every 30 s, so an idle phone opens
                           # many tiny UDP flows; count TCP separately to avoid false stall reports.
                           f"\t\tmeta l4proto tcp ip daddr {every} ct state new {match} counter name {op}_tconn\n"
                           f"\t\tmeta l4proto tcp ip saddr {every} {dmatch} counter name {op}_tdown")
    nft = "\n".join([
        "#!/usr/sbin/nft -f",
        "# bvpn relay (bvpn vpnjob relay-set): forwards the VPN ports to " + target + ", holds no keys",
        "flush ruleset",
        "table inet bvpn_relay {",
        *sets, *counters,
        "\tchain input {", "\t\ttype filter hook input priority filter; policy drop;",
        '\t\tiif "lo" accept', "\t\tct state established,related accept", "\t\tct state invalid drop",
        "\t\ttcp dport { @SSH@ } accept", "\t\tmeta l4proto { icmp, ipv6-icmp } accept", "\t}",
        "\tchain forward {", "\t\ttype filter hook forward priority filter; policy drop;",
        *count_rules,
        "\t\tct state established,related accept",
        f"\t\tip daddr {target} tcp dport {{ {tcp} }} accept",
        f"\t\tip daddr {target} udp dport {{ {udp} }} accept",
        *(f"\t\tip daddr {ip} tcp dport {{ {', '.join(map(str, m['tcp']))} }} accept\n"
          f"\t\tip daddr {ip} udp dport {{ {', '.join(map(str, m['udp']))} }} accept" for ip, m in remote.items()), "\t}",
        "}",
        "table ip bvpn_relay_nat {",
        "\tchain prerouting {", "\t\ttype nat hook prerouting priority dstnat;",
        *([f"\t\tfib daddr type local tcp dport {{ {direct_tcp} }} dnat to {target}"] if direct_tcp else []),
        f"\t\tfib daddr type local udp dport {{ {udp} }} dnat to {target}",
        *(f"\t\tfib daddr type local tcp dport {a} dnat to {target}:{b}" for a, b in RELAY_TCP_ALT.items()),
        f"\t\tfib daddr type local udp dport {RELAY_UDP_HOP[0]}-{RELAY_UDP_HOP[1]} dnat to {target}:443",
        *(f"\t\tfib daddr type local {proto} dport {rp} dnat to {ip}:{sp}"
          for ip, m in remote.items() for proto in ("tcp", "udp") for sp, rp in m[proto].items()),
        *(f"\t\tfib daddr type local udp dport {m['hop'][0]}-{m['hop'][1]} dnat to {ip}:443" for ip, m in remote.items()), "\t}",
        "\tchain postrouting {", "\t\ttype nat hook postrouting priority srcnat;",
        f"\t\tip daddr {every} masquerade random", "\t}",   # random: a phone's port never meets a dead socket on the VPN server
        "}",
    ])
    if CONF.get("relay_preserve_services", False):
        expected_dnat = [line.strip() for line in nft.splitlines() if " dnat to " in line]
        return f"""#!/bin/bash
set -euo pipefail
export LC_ALL=C
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
    echo 'relay: existing UFW needs an explicit compatible setup' >&2
    exit 1
fi
python3 - <<'PY'
from pathlib import Path
import re, subprocess
paths = ['/etc/bvpn-relay-forwarding.nft', '/usr/local/sbin/bvpn-relay-forwarding',
         '/etc/systemd/system/bvpn-relay-forwarding.service']
if not all(Path(path).is_file() for path in paths):
    raise SystemExit('relay: prepare the owned forwarding service on this multi-use VPS first')
text = Path(paths[0]).read_text()
tables = set(re.findall(r'^table\\s+(\\w+)\\s+(\\w+)\\s*\\{{', text, re.M))
if tables != {{('inet', 'bvpn_relay'), ('ip', 'bvpn_relay_nat')}}:
    raise SystemExit('relay: unexpected tables in the owned forwarding file')
if re.search(r'^\\s*(?:flush|delete|include|add|insert|replace)\\b', text, re.M):
    raise SystemExit('relay: the owned forwarding file must contain table definitions only')
input_blocks = re.findall(r'chain\\s+input\\s*\\{{(.*?)\\n\\s*\\}}', text, re.S)
if not input_blocks or any('policy accept;' not in ' '.join(block.split()) for block in input_blocks):
    raise SystemExit('relay: the existing input policy must preserve host services')
actual_dnat = [line.strip() for line in text.splitlines() if ' dnat to ' in line]
if actual_dnat != {expected_dnat!r}:
    raise SystemExit('relay: installed forwarding target or ports differ; stage the new mapping first')
batch = []
for family, name in [('inet', 'bvpn_relay'), ('ip', 'bvpn_relay_nat')]:
    found = subprocess.run(['nft', 'list', 'table', family, name], capture_output=True)
    if found.returncode == 0:
        batch.append('delete table ' + family + ' ' + name)
batch.append(text)
subprocess.run(['nft', '--check', '-f', '-'], input='\\n'.join(batch)+'\\n', text=True, check=True)
PY
systemctl restart bvpn-relay-forwarding.service
systemctl is-active --quiet bvpn-relay-forwarding.service
echo 'relay: reapplied the prepared forwarding service for {target}'
"""
    return f"""#!/bin/bash
# bvpn relay setup, rendered by vpnjob relay-set and run as root on the relay over SSH
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
command -v nft >/dev/null || {{ apt-get -qq update; apt-get -qq install -y nftables >/dev/null; }}
SSH_PORTS="$(ss -Hltnp 2>/dev/null | awk '/sshd/ {{ n = split($4, a, ":"); print a[n] }}' | sort -un | paste -sd, -)"
[ -n "$SSH_PORTS" ] || SSH_PORTS=22
case ",$SSH_PORTS," in *,{RELAY_SSH_PORT},*) ;; *) SSH_PORTS="$SSH_PORTS,{RELAY_SSH_PORT}" ;; esac
cat > /etc/sysctl.d/90-bvpn-relay.conf <<'SYSCTL'
net.ipv4.ip_forward = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
SYSCTL
sysctl -q --system >/dev/null 2>&1 || true
[ -f /etc/nftables.conf ] && cp -p /etc/nftables.conf "/etc/nftables.conf.bak.$(date +%F-%H%M%S)"
cat > /etc/nftables.conf.new <<'NFT'
{nft}
NFT
sed -i "s/@SSH@/$SSH_PORTS/" /etc/nftables.conf.new
nft -c -f /etc/nftables.conf.new
mv /etc/nftables.conf.new /etc/nftables.conf
systemctl disable --now ufw >/dev/null 2>&1 || true
nft -f /etc/nftables.conf
systemctl enable nftables >/dev/null 2>&1 || true
# sshd also on {RELAY_SSH_PORT}: the VPN server cannot reach port 22 anywhere
if ! ss -Hltnp 2>/dev/null | awk '/sshd/ {{ n = split($4, a, ":"); print a[n] }}' | grep -qx '{RELAY_SSH_PORT}' &&
   ! grep -qs '^Port {RELAY_SSH_PORT}$' /etc/ssh/sshd_config.d/10-bvpn-relay-port.conf; then
    install -d -m 755 /etc/ssh/sshd_config.d
    printf 'Port 22\\nPort {RELAY_SSH_PORT}\\n' > /etc/ssh/sshd_config.d/10-bvpn-relay-port.conf
    if sshd -t; then
        systemctl daemon-reload
        systemctl restart ssh.socket 2>/dev/null || true
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    else
        rm -f /etc/ssh/sshd_config.d/10-bvpn-relay-port.conf
    fi
fi
# we came in by key: passwords are not needed any more (/etc/bvpn-keep-passwords keeps them)
if grep -q bvpn-relay /root/.ssh/authorized_keys 2>/dev/null && [ ! -e /etc/bvpn-keep-passwords ]; then
    install -d -m 755 /etc/ssh/sshd_config.d
    printf 'PasswordAuthentication no\\nKbdInteractiveAuthentication no\\nPermitRootLogin prohibit-password\\n' > /etc/ssh/sshd_config.d/00-bvpn-relay.conf
    sshd -t && {{ systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true; }}
fi
echo "relay: forwarding tcp {tcp}{alt} udp {udp} to {target}, ssh on $SSH_PORTS"
"""


def ensure_relay_key() -> str:
    if not RELAY_KEY.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "bvpn-relay", "-f", str(RELAY_KEY)], check=True)
    pub = Path(str(RELAY_KEY) + ".pub").read_text().strip()
    if not RELAY_PUB.exists() or RELAY_PUB.read_text().strip() != pub:
        vpnlib.write_atomic(RELAY_PUB, pub + "\n", 0o644)
    return pub


def relay_routes(ip: str) -> list[list[str]]:
    """How to reach sshd of `ip`, best first: its extra port; port 22, if the hoster ever opens it; a new VPS through the
    current relay, which still answers from abroad even when operators have cut it."""
    routes = [["-p", str(RELAY_SSH_PORT)], ["-p", "22"]]
    old = relay_ip()
    if old and old != ip:
        routes.append(["-p", "22", "-o", f"ProxyCommand=ssh -i {RELAY_KEY} -o BatchMode=yes -o UserKnownHostsFile={RELAY_KNOWN} "
                                         f"-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -p {RELAY_SSH_PORT} "
                                         f"root@{old} -W %h:%p"])
    return routes


def relay_ssh(ip: str, command: str, stdin: str | None = None, timeout: int = 60) -> tuple[int, str]:
    rc, out = 255, ""
    for route in relay_routes(ip):
        cmd = ["ssh", "-i", str(RELAY_KEY), "-o", "BatchMode=yes", "-o", f"UserKnownHostsFile={RELAY_KNOWN}",
               "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15", *route, f"root@{ip}", command]
        try:
            p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return 124, f"timeout after {timeout}s"
        except OSError as e:
            return 127, str(e)
        rc, out = p.returncode, (p.stdout + p.stderr).strip()
        if rc != 255:                                  # 255: ssh itself did not get in, try the next way
            break
    return rc, out


def relay_push_key(ip: str, password: str, pub: str) -> tuple[int, str]:
    """The root password from the hoster's letter (/relay IP ПАРОЛЬ in the bot) -> our key into root's authorized_keys,
    once. The password goes to ssh through SSH_ASKPASS in the environment (root-only), never on a command line or to
    disk; relay_script then turns password logins off."""
    out, rc = "", 1
    with tempfile.TemporaryDirectory(prefix="bvpn-relay-") as d:
        ask = Path(d) / "askpass"
        ask.write_text('#!/bin/sh\nprintf \'%s\\n\' "$BVPN_RELAY_PW"\n')
        ask.chmod(0o700)
        env = dict(os.environ, SSH_ASKPASS=str(ask), SSH_ASKPASS_REQUIRE="force", DISPLAY=":0", BVPN_RELAY_PW=password)
        for route in relay_routes(ip):
            cmd = ["ssh", "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive",
                   "-o", "NumberOfPasswordPrompts=1", "-o", f"UserKnownHostsFile={RELAY_KNOWN}",
                   "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15", *route, f"root@{ip}",
                   'umask 077; mkdir -p ~/.ssh; read -r k; grep -qxF "$k" ~/.ssh/authorized_keys 2>/dev/null '
                   '|| echo "$k" >> ~/.ssh/authorized_keys; echo key-ok']
            try:
                p = subprocess.run(cmd, input=pub + "\n", capture_output=True, text=True, timeout=60, env=env,
                                   start_new_session=True)     # no tty: ssh asks SSH_ASKPASS
            except (subprocess.TimeoutExpired, OSError) as e:
                out, rc = type(e).__name__, 1
                continue
            out, rc = (p.stdout + p.stderr).replace(password, "***"), p.returncode
            if rc == 0 and "key-ok" in p.stdout:
                return 0, "key-ok"
    return rc or 1, out.strip()[-300:]


def relay_selftest(ip: str) -> tuple[bool, str]:
    """Every channel of RELAY_SERVER through the relay must work - that decides; the other servers are checked
    on their ports and reported (a server that is down must not block a new relay)."""
    args = ["selftest", "--via", ip]
    if RELAY_TCP_ALT:
        mappings = [f"tcp{port}={relay_tcp_port(port)}" for port in RELAY_TCP]
        mappings += [f"udp{port}={port}" for port in RELAY_UDP]
        args += ["--map", ",".join(mappings)]
    ok, res = _selftest_via(RELAY_SERVER, args)
    for server, m in RELAY_REMOTE.items():
        spec = ",".join(f"{proto}{sp}={rp}" for proto in ("tcp", "udp") for sp, rp in m[proto].items())
        r_ok, r_res = _selftest_via(server, ["selftest", "--via", ip, "--map", spec])
        res += f"; {SERVERS[server]['title']}: {r_res or 'нет каналов'}"
    return ok, res


def _selftest_via(server: str, args: list[str]) -> tuple[bool, str]:
    rc, out = call(server, args, timeout=180)
    try:
        r = json.loads(out)
        return bool(r.get("ok")), "; ".join(f"{x['channel']}: {'OK' if x['ok'] else 'НЕТ'}" for x in r["results"])
    except (ValueError, KeyError, TypeError):
        return False, clean_output(out)[-300:] or f"exit {rc}"


def set_link_hosts(ip: str) -> None:
    """LINK_HOSTS of /etc/bvpn/server = the relay: linkcheck accepts links that dial it."""
    env = vpnlib.SERVER_ENV
    text = env.read_text()
    shutil.copyfile(env, f"{env}.bak.{time.strftime('%Y%m%d%H%M%S')}")
    line = f"LINK_HOSTS={ip}"
    text = re.sub(r"(?m)^LINK_HOSTS=.*$", line, text) if re.search(r"(?m)^LINK_HOSTS=", text) else text.rstrip("\n") + "\n" + line + "\n"
    vpnlib.write_atomic(env, text, 0o644)


def republish_all(job_id: str) -> list[str]:
    """Every subscription again with its own sources: now with the relay's links."""
    out = []
    for person, token in sorted(vpnlib.load_json(SUB_TOKENS, {}).items()):
        meta = vpnlib.load_json(SUB_DIR / "meta" / f"{token}.json", {})
        srcs = [{k: x[k] for k in ("server", "login", "note") if x.get(k)} for x in meta.get("sources", [])]
        if not srcs:
            out.append(f"{person}: no sources in the page data - publish it with sub-publish")
            continue
        try:
            out.append(publish_sub(job_id, person, srcs)[0])
        except (Bad, OSError, ValueError, subprocess.SubprocessError) as e:
            out.append(f"{person}: NOT published ({e})")
    return out


def relay_set(job_id: str, ip: str, password: str = "") -> tuple[int, str]:
    """Owner pressed "Подтвердить" with the IP of a new VPS (and maybe its root password): set it up, check every
    channel through it, then switch: LINK_HOSTS, relay.json, subscriptions. Nothing on the VPN server changes before
    the check."""
    pub = ensure_relay_key()
    subprocess.run(["ssh-keygen", "-q", "-R", ip, "-f", str(RELAY_KNOWN)], capture_output=True)
    if password:
        rc, out = relay_push_key(ip, password, pub)
        if rc != 0:
            return 1, f"relay {ip}: SSH access setup failed ({out}) - check the route, SSH ports and root authentication"
    script = relay_script(SERVERS[RELAY_SERVER]["ip"], operator_prefixes(refresh=True))
    rc, out = relay_ssh(ip, "bash -s", stdin=script, timeout=600)
    if rc != 0:
        hint = (f"\nno way in: the VPN server's hoster closes tcp/22, and the old relay did not help. Add our key to root's "
                f"authorized_keys there and open port {RELAY_SSH_PORT} (or ask the hoster of the VPN server to open tcp/22 "
                f"out) - {pub}") if rc == 255 else ""
        return 1, f"relay {ip}: setup failed (exit {rc}): {clean_output(out)[-400:]}{hint}"
    ok, res = relay_selftest(ip)
    if not ok:
        return 1, f"relay {ip}: set up, but not every channel works through it ({res}) - nothing switched"
    old = vpnlib.load_json(RELAY, {})
    hist = (old.get("history") or [])[-20:]
    if old.get("ip") and old["ip"] != ip:
        hist.append({"ip": old["ip"], "since": old.get("since", ""), "until": vpnlib.iso(time.time())})
    set_link_hosts(ip)
    vpnlib.write_atomic(RELAY, json.dumps({"ip": ip, "since": vpnlib.iso(time.time()), "job": job_id, "history": hist,
                                           "servers": sorted(RELAY_REMOTE)},
                                          ensure_ascii=False, indent=1) + "\n", 0o644)
    vpnlib.write_atomic(RELAY_STATE, "{}\n", 0o644)        # counters of the old relay mean nothing here
    # the page and the subscription stay on the VPN server's own address, whatever the relay is
    lines = [f"relay {ip}: {res}", *republish_all(job_id)]
    if old.get("ip") and old["ip"] != ip:
        lines.append(f"old relay {old['ip']} is out of the subscriptions - cancel it at the hoster")
    return 0, "\n".join(lines)


def relay_counters(ip: str) -> dict[str, int] | None:
    rc, out = relay_ssh(ip, "nft -j list counters table inet bvpn_relay", timeout=25)
    if rc != 0:
        return None
    try:
        items = json.loads(out)["nftables"]
        return {c["counter"]["name"] + (":p" if k else ":b"): c["counter"]["packets" if k else "bytes"]
                for c in items if "counter" in c for k in (0, 1)}
    except (ValueError, KeyError, TypeError):
        return None


def tcp_open(ip: str, port: int) -> bool:
    try:
        socket.create_connection((ip, port), timeout=6).close()
        return True
    except OSError:
        return False


def stalls(old: dict[str, int], new: dict[str, int]) -> dict[str, dict]:
    """Per operator since the older sample: new connections, bytes to the phones, and whether TCP looks cut
    (TCP connections arrive but each gets less than STALL_BYTES back - the TSPU freeze). A relay set up before the
    TCP counters existed (no *_tconn) is never "stalled": the old mixed count gave false alarms."""
    out = {}
    def delta(name: str) -> int:
        d = new.get(name, 0) - old.get(name, 0)
        return d if d >= 0 else new.get(name, 0)           # the relay was rebooted: counters restarted
    for op in (*OPERATORS, "other"):
        conn, down = delta(f"{op}_conn:p"), delta(f"{op}_down:b")
        tconn, tdown = delta(f"{op}_tconn:p"), delta(f"{op}_tdown:b")
        known = f"{op}_tconn:p" in new
        out[op] = {"conn": conn, "down": down,
                   "stalled": known and tconn >= STALL_MIN_CONN and tdown < tconn * STALL_BYTES}
    return out


def relay_status(now: float) -> dict | None:
    """For panel.json and the alert: is the relay alive, what each operator gets through it (last ~15 min)."""
    ip = relay_ip()
    if not ip:
        return None
    st = vpnlib.load_json(RELAY_STATE, {})
    cnt = relay_counters(ip)
    samples = [x for x in st.get("samples", []) if now - x.get("at", 0) < 3600]
    ops = {}
    if cnt is not None:
        samples.append({"at": now, "c": cnt})
        base = next((x for x in samples if now - x["at"] >= 900), samples[0])
        ops = stalls(base["c"], cnt)
    reach = cnt is not None or tcp_open(ip, CONF["tcp"]["xhttp"])
    problems = [] if reach else [f"посредник {ip} не отвечает"]
    # Unclassified traffic may include scanners and service checks: display it without operator-specific alerts.
    problems += [f"{OPERATORS[o][0]}: подключения идут, данные нет" for o, v in ops.items() if v["stalled"] and o in OPERATORS]
    seen = "; ".join(problems)
    # the same state twice in a row (10 min) before the owner hears of it: one bad 5-minute window flapped every run
    alert = seen if seen == st.get("seen", "") else st.get("alert", "")
    if alert != st.get("alert", ""):
        text = (f"VPN, посредник в РФ: {alert}. Проверьте с телефона; подтвердится — закажите новый сервер "
                f"и пришлите в бот /relay IP." if alert else f"VPN, посредник в РФ {ip}: снова в порядке.")
        try:
            subprocess.run(["/usr/local/sbin/bvpn-alert", "--text", text], capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            pass
    vpnlib.write_atomic(RELAY_STATE, json.dumps({"samples": samples[-14:], "alert": alert, "seen": seen}) + "\n", 0o644)
    return {"ip": ip, "since": vpnlib.load_json(RELAY, {}).get("since", ""), "reach": reach, "counters": cnt is not None,
            "ops": {o: {"name": OPERATORS[o][0] if o in OPERATORS else "другие", **v} for o, v in ops.items()},
            "alert": alert}


def check_text(r: dict, seen: dict | None = None) -> str:
    """One phone check (vpnsub <token>/check, run with the VPN on) as a message for the owner. seen: what the
    relay counted from this operator while the check ran ({conn, down}), None when unknown."""
    import vpnsub
    op = {"mts": "МТС", "beeline": "Билайн", "megafon": "МегаФон", "t2": "Т2", "other": "другой оператор",
          "wifi": "Wi-Fi"}.get(r.get("op"), "?")
    who = r.get("name") or r.get("person") or "?"
    level, lines = vpnsub.check_report(r, vpnsub.exits())
    text = [f"📱 Проверка VPN с телефона: {who}, {op}" + (" (отправлено позже — связи не было)" if r.get("late") else ""),
            *lines]
    relay = r.get("relay") or relay_ip()
    if relay and seen is not None:
        if seen["conn"]:
            text.append(f"Посредник {relay} за проверку: {seen['conn']} новых подключений, "
                        f"{vpnsub.size(seen['down'])} к телефону")
        elif seen["down"]:
            text.append(f"Посредник {relay} за проверку: {vpnsub.size(seen['down'])} к телефону "
                        f"(по соединениям, открытым раньше)")
        else:
            text.append(f"Посредник {relay} не видел трафика из сети этого оператора: телефон был на Wi-Fi или в другой сети, "
                        "поэтому для этого оператора проверка не считается")
    if level == "bad" and r.get("op") != "wifi":
        text.append("Переключите в Happ другой сервер и проверьте ещё раз. Плохо на всех «через РФ», а прямые "
                    "работают — замените посредник: закажите сервер и пришлите в бот /relay НОВЫЙ_IP.")
    return "\n".join(text)


def relay_seen(r: dict, starts: dict, now: float) -> dict | None:
    """The relay counters of this person's operator between their /start and now (None: no start or no relay)."""
    st = starts.pop(r.get("person", ""), None)
    ip = relay_ip()
    if not st or not ip or r.get("late") or now - st.get("at", 0) > 600 or st.get("ip") != ip:
        return None
    cnt = relay_counters(ip)
    if cnt is None:
        return None
    op = r.get("op") if r.get("op") in OPERATORS else "other"
    v = stalls(st["c"], cnt)[op]
    return {"conn": v["conn"], "down": v["down"]}


def phone_checks(now: float) -> list[str]:
    """bvpn-checks.path: every result vpnsub left in CHECKS -> a message to the owner, then the file is
    gone (the folder must end empty: the path unit fires while it is not). A start only notes the relay
    counters for the result that follows. Unreadable files are dropped too."""
    out = []
    starts = {k: v for k, v in vpnlib.load_json(CHECK_STARTS, {}).items() if now - v.get("at", 0) < 3600}
    for f in sorted(CHECKS.glob("*")):
        if f.is_dir():
            continue
        try:
            r = json.loads(f.read_text())
            if not isinstance(r, dict):
                raise ValueError
        except (OSError, ValueError):
            if now - f.stat().st_mtime < 5:              # vpnsub may still be writing it
                time.sleep(1)
                try:
                    r = json.loads(f.read_text())
                except (OSError, ValueError):
                    r = None
            else:
                r = None
        if isinstance(r, dict) and r.get("kind") == "start":
            ip = relay_ip()
            cnt = relay_counters(ip) if ip else None
            if cnt is not None:
                starts[r.get("person", "")] = {"at": now, "ip": ip, "c": cnt}
        elif isinstance(r, dict) and r.get("kind") == "vpn":
            text = check_text(r, relay_seen(r, starts, now))
            try:
                subprocess.run(["/usr/local/sbin/bvpn-alert", "--text", text], capture_output=True, timeout=30)
            except (OSError, subprocess.SubprocessError):
                pass
            out.append(text)                             # the whole text: the journal keeps what the bot got
        f.unlink(missing_ok=True)
    vpnlib.write_atomic(CHECK_STARTS, json.dumps(starts) + "\n", 0o600)
    return out


def call(server: str, args: list[str], stdin: str | None = None, timeout: int = 240) -> tuple[int, str]:
    s = SERVERS[server]
    cmd = [*s["ssh"], " ".join(args)] if s["ssh"] else [WRAPPER, *args]
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s"
    except OSError as e:
        return 127, str(e)


def clean_output(text: str) -> str:
    text = text[-4000:]
    known = vpnlib._known_live()
    return text if not vpnlib.scan(text, known) else "(output withheld: it looked like it carried a secret)"


def fetch(server: str) -> tuple[dict | None, str]:
    rc, out = call(server, ["snapshot"], timeout=150)
    if rc != 0:
        return None, clean_output(out)[-300:] or f"exit {rc}"
    try:
        snap = json.loads(out)
    except ValueError:
        return None, "snapshot is not JSON"
    if vpnlib.scan(json.dumps(snap, ensure_ascii=False)):
        return None, "snapshot withheld: it looked like it carried a secret"
    return snap, ""


def snapshot_all(only: str = "all") -> dict:
    old = vpnlib.load_json(PANEL, {})
    prev = {s.get("id"): s for s in old.get("servers", [])}
    now = time.time()
    servers = []
    for sid, meta in SERVERS.items():
        if only != "all" and sid != only:
            servers.append(prev.get(sid) or {"id": sid})
            continue
        snap, err = fetch(sid)
        p = prev.get(sid, {})
        servers.append({
            "id": sid, "title": meta["title"], "ip": meta["ip"], "label": SUB_LABELS.get(sid, sid),
            "reach": snap is not None, "error": err, "fetched_at": vpnlib.iso(now),
            "fresh_at": vpnlib.iso(now) if snap else p.get("fresh_at", ""),
            "snapshot": snap if snap else p.get("snapshot"),
        })
    panel = {"schema": 1, "generated_at": vpnlib.iso(now), "servers": servers}
    if only == "all":
        try:
            panel["relay"] = relay_status(now)
        except (OSError, ValueError) as e:
            panel["relay"] = {"ip": relay_ip(), "error": type(e).__name__}
    elif old.get("relay") is not None:
        panel["relay"] = old["relay"]
    vpnlib.write_atomic(PANEL, json.dumps(panel, ensure_ascii=False, indent=1) + "\n", 0o644)
    return panel


def execute(req: dict, secret: str = "") -> tuple[int, str, dict | None]:
    a, s, args = req["action"], req["server"], req["args"]
    if a == "refresh":
        p = snapshot_all(s)
        return 0, " ".join(f"{x['id']}: {'ok' if x.get('reach') else 'нет связи'}" for x in p["servers"]), None
    if a == "selftest":
        rc, out = call(s, ["selftest"], timeout=120)
        try:
            r = json.loads(out)
            out = "; ".join(f"{x['channel']}: {'OK' if x['ok'] else 'НЕТ'} ({x['exit_ip'] or '—'})" for x in r["results"])
        except (ValueError, KeyError, TypeError):
            pass
        return rc, out, None
    if a == "restart":
        rc, out = call(s, ["restart", args["unit"]], timeout=60)
        return rc, out, None
    if a == "xray-apply":
        rc, out = call(s, ["apply", req["id"], "xray", str(args["seconds"])], stdin=args["filter"], timeout=240)
        pend = {"ref": req["id"], "revert_at": vpnlib.iso(time.time() + args["seconds"])} if rc == 0 else None
        return rc, out, pend
    if a in ("confirm", "revert"):
        rc, out = call(s, [a, args["ref"]], timeout=90)
        if rc != 0 or a != "confirm":
            return rc, out, None
        # person-add with a subscription: it is published now that the owner said "Работает"
        orig = vpnlib.load_json(RESULTS / f"{args['ref']}.json", {})
        oargs = orig.get("args") or {}
        if orig.get("ok") and orig.get("action") == "person-remove" and orig.get("server") == s and oargs.get("sub"):
            try:
                return 0, out + "\n" + delete_sub(oargs["sub"]), None
            except OSError as e:
                return 0, out + f"\nsubscription NOT deleted ({e})", None
        if orig.get("ok") and orig.get("action") == "person-add" and orig.get("server") == s and oargs.get("sub"):
            try:
                more, pend = publish_sub(req["id"], oargs["sub"], [{"server": s, "login": oargs["login"]}])
            except (Bad, OSError, ValueError, subprocess.SubprocessError) as e:
                return 0, out + f"\nsubscription NOT published ({e}) - publish it with sub-publish", None
            return 0, out + "\n" + more, pend
        return rc, out, None
    if a == "ufw":
        rc, out = call(s, ["ufw", req["id"], args["op"], args["rule"], "300"], timeout=300)
        return rc, out, ({"ref": req["id"], "revert_at": vpnlib.iso(time.time() + 300)} if rc == 0 else None)
    if a == "update":
        rc, out = call(s, ["update", req["id"], args["program"], args["version"], "300"], timeout=400)
        return rc, out, ({"ref": req["id"], "revert_at": vpnlib.iso(time.time() + 300)} if rc == 0 else None)
    if a == "relay-set":
        rc, out = relay_set(req["id"], args["ip"], secret)
        return rc, out, None
    if a == "relay-check":
        ip = relay_ip()
        if not ip:
            raise Bad("no relay yet - relay-set first")
        ok, res = relay_selftest(ip)
        st = relay_status(time.time()) or {}
        ops = ", ".join(f"{v['name']} {v['conn']} подкл." + (" (данные не идут)" if v["stalled"] else "")
                        for v in st.get("ops", {}).values())
        return (0 if ok else 1), f"relay {ip}: {res}" + (f"\nза 15 мин: {ops}" if ops else ""), None
    if a == "sub-publish":
        out, pend = publish_sub(req["id"], args["person"], args["sources"])
        return 0, out, pend
    if a == "sub-send":
        out, pend = send_sub(req["id"], args["person"])
        return 0, out, pend
    if a == "sub-settings":
        out, pend = settings_sub(req["id"], args)
        return 0, out, pend
    if a == "sub-reveal":
        out, pend = reveal_sub(req["id"], args["person"])
        return 0, out, pend
    if a == "sub-rotate":
        out, pend = rotate_sub(req["id"], args["person"])
        return 0, out, pend
    if a in ("person-pause", "person-resume"):
        rc, out = call(s, [a, req["id"], args["login"], str(PERSON_SECONDS)], timeout=300)
        return rc, out, ({"ref": req["id"], "revert_at": vpnlib.iso(time.time() + PERSON_SECONDS)} if rc == 0 else None)
    if a == "kit-send":
        login = args["login"]
        if login not in connected(s):
            raise Bad(f"{login} is not connected on {s}")
        files = read_kit(login, args.get("files"))
        pack_kit(req["id"], login, files)
        return 0, f"kit: {len(files)} files ({', '.join(sorted(files))}), sent to the owner as {req['id']}.kit.zip", \
            {"kit": f"{req['id']}.kit.zip"}
    if a in ("person-add", "person-remove"):
        login, tmpl = args["login"], TEMPLATE
        if a == "person-remove":
            # an add of this very person still waiting for "Работает": undo it instead of refusing - the server takes
            # no new change while one waits
            own = pending_add(s, login)
            if own:
                rc, out = call(s, ["revert", own], timeout=120)
                if rc != 0:
                    return rc, out, None
                out += f"\n{login}: the unconfirmed add {own} is undone - {login} is off the server"
                if args.get("sub"):
                    try:
                        out += "\n" + delete_sub(args["sub"])
                    except OSError as e:
                        out += f"\nsubscription NOT deleted ({e})"
                return 0, out, None
            rc, out = call(s, [a, req["id"], login, str(PERSON_SECONDS)], timeout=300)
            pend = {"ref": req["id"], "revert_at": vpnlib.iso(time.time() + PERSON_SECONDS)} if rc == 0 else None
            return rc, out, pend
        src = KITS / tmpl
        if not (src / "6-tls.txt").exists():
            raise Bad(f"no template kit {src} - nothing changed")
        if (KITS / login).exists():
            if not (KITS / login / ".panel-job").exists():
                raise Bad(f"a kit folder {KITS / login} already exists - nothing changed")
            # left by an earlier panel attempt that was reverted: keep it aside, never delete a kit
            (KITS / login).rename(KITS / f"{login}.reverted-{time.strftime('%Y%m%d%H%M%S')}")
        rc, out = call(s, [a, req["id"], tmpl, str(PERSON_SECONDS)],
                       stdin=json.dumps({"login": login, "name": args["name"]}, ensure_ascii=False), timeout=300)
        kit = [l for l in out.splitlines() if l.startswith("kit: ")]
        out = "\n".join(l for l in out.splitlines() if not l.startswith("kit: "))
        if rc != 0:
            return rc, out, None
        parts = kit[0].split()[1:] if kit else []
        if len(parts) != 6:
            call(s, ["revert", req["id"]], timeout=90)
            return 1, out + "\nthe server did not hand back the new keys - reverted", None
        v = dict(zip(("OLDU", "NEWU", "OLDK", "NEWK", "OLDAUTH", "NEWAUTH"), parts))
        try:
            with tempfile.TemporaryDirectory(prefix="kit-", dir=VAR) as d:
                names = build_kit(src, Path(d) / login, v, args["name"])
                deliver_kit(req["id"], login, Path(d) / login, send=not args.get("sub"))
        except (Bad, OSError, ValueError, subprocess.SubprocessError) as e:   # ValueError: a kit file is not UTF-8
            call(s, ["revert", req["id"]], timeout=90)
            return 1, out + f"\nkit failed ({e}) - the server change was reverted", None
        pend = {"ref": req["id"], "revert_at": vpnlib.iso(time.time() + PERSON_SECONDS)}
        if args.get("sub"):
            return rc, out + f"\nkit: {len(names)} files kept; the subscription {args['sub']} comes after \"Работает\"", pend
        out += f"\nkit: {len(names)} files, sent to the owner as {req['id']}.kit.zip"
        return rc, out, dict(pend, kit=f"{req['id']}.kit.zip")
    raise Bad(a)


def run(job_id: str) -> int:
    if not ID_RE.match(job_id):
        print("vpnjob: bad id", file=sys.stderr)
        return 2
    res_file = RESULTS / f"{job_id}.json"
    if res_file.exists():
        print(f"vpnjob: {job_id} already ran", file=sys.stderr)
        return 2
    started = time.time()
    result = {"id": job_id, "ok": False, "started": vpnlib.iso(started)}
    try:
        job = json.loads((OUTBOX / f"{job_id}.json").read_text())
        secret = job.pop("relay_password", "") if isinstance(job.get("relay_password", ""), str) else ""
        if secret:                                   # off the disk before anything else happens
            vpnlib.write_atomic(OUTBOX / f"{job_id}.json", json.dumps(job, ensure_ascii=False), 0o600)
        req = validate(job)
        if req["id"] != job_id:
            raise Bad("id in the file differs from the unit instance")
        if job.get("digest") != digest(req):
            raise Bad("digest does not match: the job is not what the owner approved")
        ap = job.get("approved") or {}
        if not ap.get("by") or not isinstance(ap.get("at"), (int, float)) or time.time() - ap["at"] > 1800:
            raise Bad("no fresh approval (older than 30 min or missing)")
        result.update(server=req["server"], action=req["action"],
                      args={k: v for k, v in req["args"].items() if k not in ("filter", "config")})
        with open(LOCK, "w") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            rc, out, pend = execute(req, secret if req["action"] == "relay-set" else "")
        result.update(ok=rc == 0, rc=rc, output=clean_output(out).replace(secret, "***") if secret else clean_output(out),
                      pending=pend)
        if req["action"] not in ("refresh", "kit-send", "sub-publish", "sub-settings", "sub-reveal", "sub-send", "sub-rotate",
                                 "relay-set", "relay-check"):
            with open(LOCK, "w") as lk:
                fcntl.flock(lk, fcntl.LOCK_EX)
                snapshot_all(req["server"])
    except (OSError, ValueError, Bad) as e:
        result.update(ok=False, rc=2, output=f"refused: {e}")
    result["finished"] = vpnlib.iso(time.time())
    vpnlib.write_atomic(res_file, json.dumps(result, ensure_ascii=False, indent=1) + "\n", 0o644)
    vpnlib.write_atomic(RESULTS / ".last", job_id + "\n", 0o644)
    try:
        subprocess.run(["logger", "-t", "bvpn-job", f"{job_id} {result.get('action', '?')} {result.get('server', '?')} ok={result['ok']}"])
    except OSError:
        pass
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["ok"] else 1


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else ""
    if cmd == "snapshot-all":
        with open(LOCK, "w") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            p = snapshot_all()
            try:
                write_subs_summary()
            except OSError:
                pass
        print(" ".join(f"{s['id']}={'ok' if s.get('reach') else 'unreachable'}" for s in p["servers"]))
        return 0
    if cmd == "phone-checks":
        for line in phone_checks(time.time()):
            print(line)
        return 0
    if cmd == "run" and len(argv) == 2:
        return run(argv[1])
    if cmd in ("propose", "digest"):
        try:
            req = validate(json.loads(sys.stdin.read()))
        except (ValueError, Bad) as e:
            print(f"vpnjob: {e}", file=sys.stderr)
            return 2
        if cmd == "digest":
            print(digest(req))
            return 0
        req.update(digest=digest(req), created=vpnlib.iso(time.time()), drops=ACTIONS[req["action"]][1])
        dst = PROPOSALS / f"{req['id']}.json"
        if dst.exists():
            print(f"vpnjob: proposal {req['id']} already exists", file=sys.stderr)
            return 2
        vpnlib.write_atomic(dst, json.dumps(req, ensure_ascii=False, indent=1) + "\n", 0o640)
        print(f"proposed {req['id']}: {req['action']} on {req['server']} - the owner gets it in the bot")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
