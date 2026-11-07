#!/usr/bin/env python3
"""vpnsub - the subscription service behind https://<server IP>/<token> on the VPN server (stdlib).

Caddy (127.0.0.1:9445, TLS) proxies here (127.0.0.1:9446). One address, two answers:
  - an app (Happ and the like): the subscription itself - base64 links written by `vpnjob sub-publish` -
    with the headers the apps read: title, update interval, traffic (subscription-userinfo) and the
    address of the page (profile-web-page-url);
  - a browser: the person's page - name, status, traffic, servers, how to install Happ and add the
    subscription. The page never shows a link of a server (vless://, hysteria2://): only the
    subscription address, which the person already holds.

Reads SUB_DIR/<token> and SUB_DIR/meta/<token>.json (vpnjob, root:caddy 640), PANEL (the 5-minute
snapshot of both servers, 644). Writes only CHECKS: <token>/check is a page the phone opens with the VPN
on; it times the tunnel itself (exit address, 15 small requests, Telegram/YouTube/Instagram/Google, 15 s of
download in 4 streams against Cloudflare) and posts the result here; `vpnjob phone-checks` (a path unit, root)
adds what the relay saw meanwhile and sends it to the bot.
Runs as a DynamicUser in group caddy (bvpn-sub.service). Nothing is logged: the token in the path
is the key, and a result carries the person's name, never the token or an address.
"""
from __future__ import annotations

import base64
import html
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SUB_DIR = Path("/var/lib/bvpn-sub")
PANEL = Path("/var/lib/bvpn/panel.json")
try:
    CONF = json.loads(Path("/etc/bvpn/config.json").read_text(encoding="utf-8"))
except (OSError, ValueError):
    CONF = {}
BASE_URL = CONF.get("sub_url", "https://203.0.113.10/")
LISTEN = ("127.0.0.1", 9446)
TOKEN_RE = re.compile(r"^/([A-Za-z0-9_-]{32})/?$")
# Phone check: <token>/check serves the page; /start and /done receive its results.
# The page runs with the VPN on and measures the tunnel against Cloudflare and real sites.
# A direct download outside the tunnel cannot establish whether the VPN protocol works.
CHECK_RE = re.compile(r"^/([A-Za-z0-9_-]{32})/check(?:/(start|done))?/?$")
CHECKS = Path("/var/lib/bvpn-checks")        # root:caddy 2770: results for `vpnjob phone-checks` -> the bot
RELAY = Path("/etc/bvpn/relay.json")         # the Russian relay (vpnjob relay-set), 644, no secrets
SERVER_ENV = Path("/etc/bvpn/server")        # 644: IP, RU_IP - our exits, to tell "through the VPN"
EXITS = Path("/etc/bvpn/exits.json")         # 644: {ip: name} of more exits
CF_SPEED = "https://speed.cloudflare.com"          # CORS open, tells the address it sees (cf-meta-ip)
# Query the exit address using a destination routed through the VPN by the built-in profiles.
# speed.cloudflare.com follows the active profile; a different observed address means the speed
# measurement used a route outside the tested VPN exit.
CF_TRACE = "https://1.1.1.1/cdn-cgi/trace"
SITES = (("tg", "Telegram", "https://telegram.org/favicon.ico"), ("yt", "YouTube", "https://www.youtube.com/favicon.ico"),
         ("ig", "Instagram", "https://www.instagram.com/favicon.ico"), ("g", "Google", "https://www.google.com/favicon.ico"))
LAT_N = 15                                         # small requests one after another: what Telegram feels as lag
DL_STREAMS, DL_BYTES, DL_SECONDS = 4, 6_000_000, 15
CHECKS_MAX = 30                                    # a full folder means nobody reads it: stop taking more
CHECK_EVERY = 20                                   # seconds between two results of one person
OPS = {"mts": "МТС", "beeline": "Билайн", "megafon": "МегаФон", "t2": "Т2", "other": "другой", "wifi": "Wi-Fi"}
_last_check: dict[str, float] = {}
APP_UA = re.compile(r"happ|v2ray|xray|clash|mihomo|sing-?box|hiddify|streisand|shadowrocket|nekobox|"
                    r"foxray|karing|v2box|incy|stash|surge|quantumult|loon", re.I)
TITLE = CONF.get("brand", "VPN")
FONTS = Path("/usr/local/lib/bvpn/fonts")    # woff2 subsets of the brand fonts (design-system), deploy/fonts
FACES = ()  # Public distribution uses system fonts.
LOGO = f'<span class="wordmark">{html.escape(TITLE)}</span>'
MSK = timezone(timedelta(hours=3))

HAPP = {
    "ios": [("App Store (Россия)", "https://apps.apple.com/ru/app/happ-lite/id6799917773"),
            ("App Store (другие страны)", "https://apps.apple.com/us/app/happ-proxy-utility/id6504287215")],
    "android": [("Google Play", "https://play.google.com/store/apps/details?id=com.happproxy"),
                ("Файл APK", "https://github.com/Happ-proxy/happ-android/releases/latest/download/Happ.apk")],
    "mac": [("App Store (Россия)", "https://apps.apple.com/ru/app/happ-proxy-utility/id6783623643"),
            ("Файл DMG", "https://github.com/Happ-proxy/happ-desktop/releases/latest/download/Happ.macOS.universal.dmg")],
    "windows": [("Установщик Windows", "https://github.com/Happ-proxy/happ-desktop/releases/latest/download/setup-Happ.x64.exe"),
                ("Для ARM (Snapdragon)", "https://github.com/Happ-proxy/happ-desktop/releases/latest/download/setup-Happ.arm64.exe")],
}
OS_TITLES = {"ios": "iPhone", "android": "Android", "mac": "Mac", "windows": "Windows"}
CHANNELS = {"calls": "Основной и Запасной 2", "main": "Запасной 1", "backup": "Запасной 3"}


TG_RE = re.compile(r"^tg://proxy\?[A-Za-z0-9=&._%-]{10,600}$")


def tg_card(tg: str) -> str:
    if not tg:
        return ""
    web = "https://t.me/proxy?" + tg.split("?", 1)[1]
    return f"""<section class="card">
  <h2><span class="br">[</span> Прокси Telegram <span class="br">]</span></h2>
  <p class="sub">Telegram будет работать и без VPN. Нажмите кнопку — Telegram спросит «Подключить прокси?» → «Подключить».
  Пока VPN включён, прокси не нужен: можно оставить, он не мешает.</p>
  <div class="row" style="margin-top:16px"><a class="btn primary" href="{html.escape(tg)}">Подключить прокси Telegram</a>
  <a class="btn" href="{html.escape(web)}">Если кнопка не открыла Telegram</a></div>
</section>"""


def tg_link(token: str) -> str:
    """The person's Telegram proxy link (vpnjob writes SUB_DIR/tg/<token>), '' when there is none."""
    try:
        line = (SUB_DIR / "tg" / token).read_text().strip()
    except OSError:
        return ""
    return line if TG_RE.match(line) else ""


def load(token: str) -> tuple[str, dict] | None:
    body, meta = SUB_DIR / token, SUB_DIR / "meta" / f"{token}.json"
    try:
        return body.read_text(), json.loads(meta.read_text()) if meta.exists() else {}
    except (OSError, ValueError):
        return None


def people_state(meta: dict) -> dict:
    """Traffic, last seen and server health of the person's sources from the panel snapshot."""
    try:
        servers = {s["id"]: s for s in json.loads(PANEL.read_text())["servers"]}
    except (OSError, ValueError, KeyError, TypeError):
        servers = {}
    out = {"traffic_30d": 0, "traffic_24h": 0, "last_seen": "", "online": False, "sources": [], "paused": False}
    paused = []
    for src in meta.get("sources", []):
        snap = (servers.get(src.get("server")) or {}).get("snapshot") or {}
        person = next((p for p in snap.get("people", []) if p.get("login") == src.get("login")), {})
        paused.append(bool(person.get("paused")))
        t = person.get("traffic") or {}
        out["traffic_30d"] += int(t.get("30d") or 0)
        out["traffic_24h"] += int(t.get("24h") or 0)
        out["online"] = out["online"] or bool(person.get("online"))
        if (person.get("last_seen") or "") > out["last_seen"]:
            out["last_seen"] = person["last_seen"]
        chans = [c for c in snap.get("channels", []) if c.get("id") in person.get("channels", [])]
        out["sources"].append({"label": src.get("label") or src.get("server", ""), "note": src.get("note", ""),
                               "up": bool(chans) and all(c.get("ok") for c in chans),
                               "channels": [CHANNELS.get(c["id"], c.get("title", "")) for c in chans if c["id"] in CHANNELS]})
    out["paused"] = bool(paused) and all(paused)
    return out


def expire_ts(meta: dict) -> int:
    """End of the expiry day in Moscow time, as unix seconds; 0 - no expiry."""
    try:
        d = datetime.strptime(str(meta.get("expire") or ""), "%Y-%m-%d").replace(tzinfo=MSK)
    except ValueError:
        return 0
    return int((d + timedelta(days=1)).timestamp()) - 1


def size(n: int) -> str:
    for unit, k in (("ТБ", 1 << 40), ("ГБ", 1 << 30), ("МБ", 1 << 20)):
        if n >= k:
            return f"{n / k:.1f} {unit}".replace(".", ",")
    return f"{n / 1024:.0f} КБ"


def when(iso: str) -> str:
    try:
        ts = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return "ещё не подключался"
    s = (datetime.now(timezone.utc) - ts).total_seconds()
    if s < 600:
        return "сейчас в сети"
    if s < 3600:
        return f"{s / 60:.0f} мин назад"
    if s < 86400:
        return f"{s / 3600:.0f} ч назад"
    return ts.astimezone(MSK).strftime("%d.%m.%Y")


_css_fonts: list[str] = []


def font_css() -> str:
    if not _css_fonts:
        faces = []
        for fam, w, f in FACES:
            try:
                data = base64.b64encode((FONTS / f"{f}.woff2").read_bytes()).decode()
            except OSError:
                continue
            faces.append(f'@font-face{{font-family:"{fam}";font-weight:{w};font-style:normal;font-display:swap;'
                         f'src:url(data:font/woff2;base64,{data}) format("woff2")}}')
        _css_fonts.append("\n".join(faces))
    return _css_fonts[0]


_qr: dict[str, str] = {}


def qr_svg(url: str) -> str:
    if url not in _qr:
        try:
            svg = subprocess.run(["qrencode", "-t", "SVG", "-m", "1", "-o", "-", url], capture_output=True,
                                 timeout=5, check=True).stdout.decode()
            _qr[url] = svg[svg.index("<svg"):]
        except (OSError, ValueError, subprocess.SubprocessError):
            _qr[url] = ""
    return _qr[url]


STYLE = """:root{--page:#0B2348;--bg:#0E2A55;--card:#123262;--raised:#183C72;--line:#2A4F86;--line-hi:#3B639C;
--text:#F5F6F7;--dim:#C6CACF;--mute:rgba(245,246,247,.72);
--aqua:#8FB8FA;--aqua-hi:#A9CBFC;--aqua-300:#C4DCFD;--aqua-bg:rgba(143,184,250,.14);
--ok:#3ED598;--ok-bg:rgba(62,213,152,.12);--warn:#F5B544;--warn-bg:rgba(245,181,68,.12);
--metal:linear-gradient(180deg,#FFFFFF 0%,#EDEFF1 34%,#AEB4BC 62%,#F4F6F8 100%);
--aqua-fill:linear-gradient(180deg,#A9CBFC 0%,#8FB8FA 100%);
--glow-sm:0 0 12px rgba(143,184,250,.5);--glow:0 0 24px rgba(143,184,250,.45);
--display:system-ui,sans-serif;--body:system-ui,-apple-system,"Segoe UI",sans-serif;--r:20px}
*{box-sizing:border-box}
html{background:var(--page)}
body{margin:0;min-height:100vh;color:var(--text);font:400 16px/1.5 var(--body);background:
radial-gradient(70% 45% at 50% -8%,rgba(143,184,250,.20),transparent 70%),
radial-gradient(45% 35% at 100% 30%,rgba(143,184,250,.07),transparent 70%),
radial-gradient(60% 40% at 50% 108%,rgba(143,184,250,.16),transparent 70%),var(--page);background-attachment:fixed}
.wrap{max-width:760px;margin:0 auto;padding:28px 16px 56px}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:28px}
.wordmark{font-family:var(--body);font-weight:800;font-size:20px;letter-spacing:.01em;color:var(--text)}
.tag{font:700 12px/1 var(--display);letter-spacing:.16em;color:var(--dim);text-transform:uppercase}
.tag b,.br{color:var(--aqua);font-weight:700}
.card{position:relative;overflow:hidden;background:linear-gradient(180deg,rgba(255,255,255,.025),transparent 40%),var(--card);
border:1px solid var(--line);border-radius:var(--r);padding:24px;margin-bottom:16px}
.card.hero{background:radial-gradient(70% 120% at 50% 0,rgba(143,184,250,.16),transparent 60%),var(--card);border-color:rgba(143,184,250,.28);
box-shadow:0 0 0 1px rgba(143,184,250,.06),0 24px 60px -30px rgba(143,184,250,.45)}
.card.hero:after{content:"";position:absolute;left:10%;right:10%;top:0;height:1px;background:linear-gradient(90deg,transparent,var(--aqua),transparent);opacity:.8}
.who{display:flex;align-items:center;gap:16px;margin-bottom:22px}
.badge{width:52px;height:52px;border-radius:16px;display:grid;place-items:center;background:var(--aqua-bg);color:var(--aqua-300);
border:1px solid rgba(143,184,250,.45);box-shadow:var(--glow-sm);flex:none}
.who h1{margin:0;font:700 26px/1.05 var(--display);letter-spacing:.03em;text-transform:uppercase;
background:var(--metal);-webkit-background-clip:text;background-clip:text;color:transparent}
.who p{margin:6px 0 0;color:var(--mute);font-size:14px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.tile{background:var(--raised);border:1px solid var(--line);border-radius:14px;padding:14px 16px;min-width:0}
.tile .k{color:var(--mute);font-size:12px;letter-spacing:.02em}
.tile .v{font:800 18px/1.25 var(--body);margin-top:4px;overflow-wrap:anywhere}
.tile .v.big{font:700 22px/1.1 var(--display);letter-spacing:.02em}
.v.ok{color:var(--ok)}
.bar{height:6px;border-radius:3px;background:var(--line);margin:8px 0 4px;overflow:hidden}
.bar span{display:block;height:100%;background:var(--aqua-fill);box-shadow:var(--glow-sm)}
.v.warn{color:var(--warn)}
.pill.warn:before{background:var(--warn);box-shadow:0 0 10px var(--warn)}
.pill{display:inline-flex;align-items:center;gap:8px}
.pill:before{content:"";width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 10px var(--ok)}
h2{margin:0 0 6px;font:700 15px/1.2 var(--display);letter-spacing:.14em;text-transform:uppercase}
.sub{color:var(--mute);font-size:14px;margin:0 0 18px}
ul{list-style:none;margin:0;padding:0}
.srv{display:grid;grid-template-columns:12px 1fr auto;gap:4px 12px;align-items:center;padding:14px 0;border-top:1px solid var(--line)}
.srv:first-child{border-top:0;padding-top:2px}
.dot{width:10px;height:10px;border-radius:50%}
.dot.ok{background:var(--ok);box-shadow:0 0 0 4px var(--ok-bg),0 0 12px var(--ok)}
.dot.warn{background:var(--warn);box-shadow:0 0 0 4px var(--warn-bg),0 0 12px rgba(245,181,68,.6)}
.srv-name{font-weight:800}
.srv-state{font-size:13px;font-weight:600;text-align:right;padding:4px 10px;border-radius:999px}
.srv-state.ok{color:var(--ok);background:var(--ok-bg)}
.srv-state.warn{color:var(--warn);background:var(--warn-bg)}
.srv-ch{grid-column:2/4;color:var(--mute);font-size:13px}
.tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:6px}
.tab{background:var(--raised);color:var(--dim);border:1px solid var(--line);border-radius:999px;padding:9px 16px;
font-family:inherit;font-size:14px;font-weight:600;line-height:1;cursor:pointer}
.tab[aria-selected=true]{background:var(--aqua-bg);border-color:var(--aqua);color:var(--text);box-shadow:var(--glow-sm)}
.step{display:grid;grid-template-columns:40px 1fr;gap:14px;padding:18px 0;border-top:1px solid var(--line)}
.step:first-of-type{border-top:0}
.num{width:40px;height:40px;border-radius:12px;background:var(--aqua-bg);border:1px solid rgba(143,184,250,.4);color:var(--aqua-300);
display:grid;place-items:center;font:700 16px/1 var(--display)}
.step h3{margin:6px 0 4px;font-size:16px;font-weight:800}
.step p{margin:0 0 14px;color:var(--dim);font-size:14px}
.pane{display:none;gap:8px;flex-wrap:wrap}
.pane.on{display:flex}
.btn{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line-hi);background:var(--raised);color:var(--text);
text-decoration:none;border-radius:12px;padding:11px 18px;font-family:inherit;font-size:15px;font-weight:600;line-height:1.2;cursor:pointer;
transition:box-shadow .2s,border-color .2s,transform .1s}
.btn:hover{border-color:var(--aqua-hi)}
.btn:active{transform:translateY(1px)}
.btn.primary{background:var(--aqua-fill);border-color:transparent;color:#0B2348;font-weight:800;box-shadow:0 8px 24px -10px rgba(143,184,250,.8)}
.btn.primary:hover{box-shadow:var(--glow)}
.row{display:flex;gap:8px;flex-wrap:wrap}
.qr{display:none;margin-top:18px;align-items:center;gap:16px}
.qr svg{width:148px;height:148px;background:#fff;border-radius:14px;padding:6px;flex:none;box-shadow:0 0 0 1px rgba(143,184,250,.35),var(--glow)}
.qr p{margin:0;color:var(--mute);font-size:13px}
.desk .qr{display:flex}
footer{color:var(--mute);font-size:12px;text-align:center;margin-top:28px;line-height:1.7}
@media (max-width:520px){.card{padding:20px 16px}.tile{padding:12px}.tile .v{font-size:16px}.tile .v.big{font-size:19px}.who h1{font-size:22px}}
@media (max-width:340px){.grid{grid-template-columns:1fr}}
"""   # the look of both pages (design system, the brand color of this installation)


def page(token: str, meta: dict, st: dict, tg: str = "") -> str:
    e = html.escape
    url = BASE_URL + token
    name = meta.get("name") or meta.get("person") or "VPN"
    servers = "".join(
        f'<li class="srv"><span class="dot {"ok" if s["up"] and not s["note"] else "warn"}"></span>'
        f'<span class="srv-name">{e(s["label"][:1].upper() + s["label"][1:])}</span>'
        f'<span class="srv-state {"ok" if s["up"] and not s["note"] else "warn"}">{e(s["note"] or ("работает" if s["up"] else "проверяется"))}</span>'
        f'<span class="srv-ch">{e(" · ".join(s["channels"]))}</span></li>'
        for s in st["sources"])
    tabs = "".join(f'<button class="tab" data-os="{k}" type="button">{v}</button>' for k, v in OS_TITLES.items())
    panes = "".join(
        f'<div class="pane" data-os="{k}">' + "".join(
            f'<a class="btn {"primary" if i == 0 else ""}" href="{e(href)}" rel="noopener">{e(t)}</a>'
            for i, (t, href) in enumerate(links)) + "</div>"
        for k, links in HAPP.items())
    seen = "сейчас в сети" if st["online"] else when(st["last_seen"])
    exp = expire_ts(meta)
    term = ("Личная подписка · до " + datetime.fromtimestamp(exp, MSK).strftime("%d.%m.%Y")) if exp else "Личная подписка · бессрочно"
    limit = int(meta.get("limit_gb") or 0) << 30
    limit_line = (f'<div class="bar"><span style="width:{min(100, round(100 * st["traffic_30d"] / limit))}%"></span></div>'
                  f'<div class="k">из {size(limit)} в месяц</div>') if limit else ""
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<meta name="referrer" content="no-referrer">
<meta name="theme-color" content="#0B2348">
<title>{e(TITLE)} · {e(name)}</title>
<style>
{font_css()}
{STYLE}
</style></head>
<body><div class="wrap">
<header><div class="logo">{LOGO}</div><div class="tag"><b>[</b> VPN <b>]</b></div></header>

<section class="card hero">
  <div class="who"><div class="badge"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg></div>
  <div><h1>{e(name)}</h1><p>{e(term)}</p></div></div>
  <div class="grid">
    <div class="tile"><div class="k">Имя пользователя</div><div class="v">{e(meta.get("person", ""))}</div></div>
    <div class="tile"><div class="k">Статус</div>{'<div class="v warn"><span class="pill warn">Приостановлена</span></div>' if st.get("paused") else '<div class="v ok"><span class="pill">Активна</span></div>'}</div>
    <div class="tile"><div class="k">Трафик за 30 дней</div><div class="v big">{size(st["traffic_30d"])}</div>{limit_line}</div>
    <div class="tile"><div class="k">Последнее подключение</div><div class="v">{e(seen)}</div></div>
  </div>
</section>

<section class="card">
  <h2><span class="br">[</span> Серверы <span class="br">]</span></h2>
  <p class="sub">Если один перестал отвечать — выберите в Happ другой.</p>
  <ul>{servers}</ul>
  <div class="row" style="margin-top:16px"><a class="btn" href="/{e(token)}/check">Проверить связь с телефона</a></div>
</section>

{tg_card(tg)}
<section class="card" id="install">
  <h2><span class="br">[</span> Установка <span class="br">]</span></h2>
  <p class="sub">Три шага, один раз. Дальше серверы и настройки обновляются сами.</p>
  <div class="tabs" role="tablist">{tabs}</div>
  <div class="step"><div class="num">1</div><div><h3>Установите Happ</h3>
    <p>Бесплатное приложение для VPN.</p>{panes}</div></div>
  <div class="step"><div class="num">2</div><div><h3>Добавьте подписку</h3>
    <p>Кнопка откроет Happ и добавит подписку вместе с правилами: российские сайты — напрямую, без VPN. Не открылось — скопируйте ссылку и в Happ нажмите «+» → «Вставить из буфера».</p>
    <div class="row"><a class="btn primary" href="happ://add/{e(url)}">Добавить подписку</a>
    <button class="btn" type="button" id="copy" data-url="{e(url)}">Скопировать ссылку</button></div>
    <div class="qr">{qr_svg(url)}<p>На компьютере? Отсканируйте камерой телефона, когда Happ уже установлен.</p></div></div></div>
  <div class="step"><div class="num">3</div><div><h3>Подключитесь</h3>
    <p>В Happ нажмите большую кнопку включения. Выключать VPN для Госуслуг и банков не нужно. Для звонков в Telegram и WhatsApp выберите «2 Звонки».</p></div></div>
</section>

<footer>Ссылка личная — не пересылайте её.<br>Обновлено {datetime.now(MSK).strftime("%d.%m.%Y %H:%M")} МСК</footer>
</div>
<script>
(function(){{
  var ua=navigator.userAgent||"", os=/iPhone|iPad|iPod/.test(ua)?"ios":/Android/.test(ua)?"android":/Mac/.test(ua)?"mac":/Windows/.test(ua)?"windows":"ios";
  if(!/iPhone|iPad|iPod|Android/.test(ua)) document.body.classList.add("desk");
  function pick(k){{document.querySelectorAll(".tab").forEach(function(t){{t.setAttribute("aria-selected",t.dataset.os===k)}});
    document.querySelectorAll(".pane").forEach(function(p){{p.classList.toggle("on",p.dataset.os===k)}});}}
  document.querySelectorAll(".tab").forEach(function(t){{t.addEventListener("click",function(){{pick(t.dataset.os)}})}});
  pick(os);
  var c=document.getElementById("copy");
  c.addEventListener("click",function(){{
    var u=c.dataset.url, done=function(){{c.textContent="Скопировано"; setTimeout(function(){{c.textContent="Скопировать ссылку"}},2000)}};
    if(navigator.clipboard) navigator.clipboard.writeText(u).then(done,function(){{prompt("Ссылка:",u)}}); else prompt("Ссылка:",u);
  }});
}})();
</script>
</body></html>
"""



def route_now() -> str:
    """The page lives on the VPN server's own address, never behind the relay."""
    return ""


def exits() -> dict[str, str]:
    """Our VPN exit addresses -> a label: what the internet sees when a phone goes through one of our servers."""
    out = {}
    try:
        env = dict(l.split("=", 1) for l in SERVER_ENV.read_text().splitlines() if "=" in l and not l.startswith("#"))
    except OSError:
        env = {}
    try:
        servers = json.loads(PANEL.read_text()).get("servers") or []
    except (OSError, ValueError, AttributeError):
        servers = []
    for s in servers:
        if isinstance(s, dict) and s.get("ip"):
            out[str(s["ip"])] = "сервер " + str(s.get("title") or s.get("id") or s["ip"])
    if env.get("IP", "").strip():
        out.setdefault(env["IP"].strip(), "сервер " + str(CONF.get("label", "")))
    if env.get("RU_IP", "").strip():
        out[env["RU_IP"].strip()] = "выход «Россия»"
    try:                                         # servers outside the panel, e.g. a stand-in during an outage
        extra = json.loads(EXITS.read_text())
        out.update({str(k): str(v) for k, v in extra.items()} if isinstance(extra, dict) else {})
    except (OSError, ValueError):
        pass
    return out


def _num(x: float, d: int = 1) -> str:
    return f"{x:.{d}f}".replace(".", ",")



def check_report(r: dict, ex: dict[str, str]) -> tuple[str, list[str]]:
    """A result of the page -> (ok | warn | bad, lines for people). One place: the page shows it, vpnjob sends it."""
    levels, lines = [], []

    def say(level: str, text: str) -> None:
        levels.append(level)
        lines.append({"ok": "✅", "warn": "⚠️", "bad": "❌"}[level] + " " + text)

    ip = str(r.get("ip") or "")
    via = ex.get(ip, "")
    if via:
        say("ok", f"трафик идёт через VPN ({via})")
        if r.get("dl_ip") and r["dl_ip"] != ip:
            say("warn", "скорость ниже измерена мимо VPN: в Happ старый список сайтов. Обновите подписку или добавьте её заново")
    else:
        where = f"выход {r.get('country') or '?'}" + (f", AS{r['asn']}" if r.get("asn") else "")
        say("bad", f"мимо VPN ({where}): включите VPN в Happ и повторите" if ip else
            "не узнал адрес выхода: даже первый запрос не прошёл")
    lat = [int(x) for x in r.get("lat") or []]
    good = sorted(x for x in lat if x >= 0)
    lost = len(lat) - len(good)
    if good:
        med, worst = good[len(good) // 2], good[-1]
        part = f"обычно {med} мс, хуже всего {worst} мс" + (f", не прошли {lost} из {len(lat)}" if lost else "")
        if not lost and med <= 400 and worst <= 1500:
            say("ok", "отклик: " + part)
        elif lost <= 2 and med <= 1000:
            say("warn", "отклик медленный: " + part)
        else:
            say("bad", "отклик плохой: " + part)
    else:
        say("bad", f"отклик: ни один из {len(lat)} запросов не прошёл")
    slow, dead, fine = [], [], []
    for key, name, _ in SITES:
        t = [int(x) for x in (r.get("sites") or {}).get(key) or []]
        if not t or any(x < 0 for x in t):
            dead.append(name)
        elif max(t) > 3000:
            slow.append(f"{name} {_num(max(t) / 1000)} с")
        else:
            fine.append(name)
    if dead:
        say("bad", "не открылись: " + ", ".join(dead) + (f" (открылись: {', '.join(fine + slow)})" if fine or slow else ""))
    elif slow:
        say("warn", "сайты медленно: " + ", ".join(slow))
    else:
        say("ok", "сайты открываются: " + ", ".join(fine))
    dl = r.get("dl") or {}
    got, ms, gap = int(dl.get("bytes") or 0), max(1, int(dl.get("ms") or 1)), int(dl.get("gap_ms") or 0)
    mbit = got * 8 / ms / 1000
    speed = f"{_num(mbit, 2 if mbit < 1 else 1)} Мбит/с, {size(got)} за {_num(ms / 1000)} с"
    if not got:
        say("bad", "загрузка не пошла совсем")
    elif gap >= 3000:
        say("bad", f"загрузка вставала на {_num(gap / 1000)} с — похоже, режут ({speed})")
    elif mbit >= 2 and gap < 2000:
        say("ok", f"загрузка без пауз: {speed}")
    else:
        say("warn", f"загрузка медленная: {speed}")
    level = "bad" if "bad" in levels else "warn" if "warn" in levels else "ok"
    head = {"ok": "✅ VPN работает", "warn": "⚠️ VPN работает, но с проблемами",
            "bad": "❌ VPN работает плохо" if via else "❌ Проверка прошла мимо VPN"}[level]
    return level, [head, *lines]


def check_page(token: str, meta: dict, relay: str) -> str:
    e = html.escape
    name = meta.get("name") or meta.get("person") or "VPN"
    ops = "".join(f'<button class="tab" type="button" data-op="{k}">{e(v)}</button>' for k, v in OPS.items())
    sites = [[k, n, u] for k, n, u in SITES]
    relay_hint = (f" Серверы с пометкой «через РФ» идут через посредник в России ({e(relay)})." if relay else "")
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<meta name="referrer" content="no-referrer">
<meta name="theme-color" content="#0B2348">
<title>{e(TITLE)} · проверка VPN</title>
<style>
{font_css()}
{STYLE}
.meter{{height:10px;border-radius:5px;background:var(--line);overflow:hidden;margin:16px 0 8px}}
.meter span{{display:block;height:100%;width:0;background:var(--aqua-fill);box-shadow:var(--glow-sm);transition:width .2s}}
.res{{font:800 18px/1.35 var(--body);margin:14px 0 0}}
.res.ok{{color:var(--ok)}} .res.warn{{color:var(--warn)}} .res.bad{{color:#FF6B6B}}
.lines{{margin:10px 0 0;padding:0;list-style:none}} .lines li{{margin:6px 0;line-height:1.4}}
.hide{{display:none}}
</style></head>
<body><div class="wrap">
<header><div class="logo">{LOGO}</div><div class="tag"><b>[</b> Проверка <b>]</b></div></header>

<section class="card hero">
  <h2><span class="br">[</span> Работает ли VPN <span class="br">]</span></h2>
  <p class="sub">{e(name)} · проверяем сам VPN: откроются ли Telegram, YouTube и другие сайты, не тормозит ли и не рвётся ли загрузка.</p>
  <div class="step"><div class="num">1</div><div><h3>Включите VPN, Wi‑Fi выключите</h3>
    <p>В Happ выберите сервер, который хотите проверить, и включите VPN.{relay_hint} Выберите оператора:</p>
    <div class="tabs" role="tablist">{ops}</div></div></div>
  <div class="step"><div class="num">2</div><div><h3>Запустить проверку</h3>
    <p>Около 30 секунд и до 25 МБ трафика. Итог сразу уйдёт владельцу. Другой сервер — переключите в Happ и проверьте ещё раз.</p>
    <button class="btn primary" type="button" id="go">Проверить</button>
    <div class="meter"><span id="bar"></span></div><div class="k" id="info"></div>
    <div class="res" id="res"></div><ul class="lines" id="lines"></ul><p class="res hide" id="sent"></p></div></div>
</section>
<footer>Итог уйдёт владельцу в бот. Ссылка личная — не пересылайте её.</footer>
</div>
<script>
(function(){{
  var T={json.dumps(token)}, CF={json.dumps(CF_SPEED)}, TRACE={json.dumps(CF_TRACE)}, SITES={json.dumps(sites, ensure_ascii=False)}, LATN={LAT_N},
      NS={DL_STREAMS}, NB={DL_BYTES}, DLMS={DL_SECONDS * 1000}, KEY="bvpn-check-pending", op="";
  try{{op=localStorage.getItem("bvpn-op")||""}}catch(x){{}}
  function pickOp(k){{op=k;try{{localStorage.setItem("bvpn-op",k)}}catch(x){{}}
    document.querySelectorAll("[data-op]").forEach(function(b){{b.setAttribute("aria-selected",b.dataset.op===k)}})}}
  document.querySelectorAll("[data-op]").forEach(function(b){{b.addEventListener("click",function(){{pickOp(b.dataset.op)}})}});
  if(op)pickOp(op);
  function post(path,r,cb){{fetch("/"+T+"/check/"+path,{{method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify(r),cache:"no-store"}})
    .then(function(x){{if(!x.ok)throw 0;return x.json()}})
    .then(function(j){{if(path==="done")try{{localStorage.removeItem(KEY)}}catch(y){{}};cb&&cb(j)}})
    .catch(function(){{if(path==="done")try{{r.late=true;localStorage.setItem(KEY,JSON.stringify(r))}}catch(y){{}};cb&&cb(null)}})}}
  try{{var p=localStorage.getItem(KEY);if(p)post("done",JSON.parse(p))}}catch(x){{}}
  var bar=document.getElementById("bar"),info=document.getElementById("info"),res=document.getElementById("res"),
      list=document.getElementById("lines"),sent=document.getElementById("sent"),go=document.getElementById("go");
  function show(pct,t){{bar.style.width=pct+"%";info.textContent=t}}
  function timed(url,ms,mode){{var c=new AbortController(),t0=performance.now(),to=setTimeout(function(){{c.abort()}},ms);
    return fetch(url,{{cache:"no-store",mode:mode||"cors",signal:c.signal,referrerPolicy:"no-referrer"}})
      .then(function(r){{clearTimeout(to);return {{ms:Math.round(performance.now()-t0),r:r}}}},function(){{clearTimeout(to);return {{ms:-1,r:null}}}})}}
  function latency(rec,i){{if(i>=LATN)return Promise.resolve();
    return timed(CF+"/__down?bytes=0&n="+i+"-"+Date.now(),5000).then(function(x){{rec.lat.push(x.ms);
      if(x.r&&!rec.dl_ip){{rec.dl_ip=x.r.headers.get("cf-meta-ip")||"";rec.asn=x.r.headers.get("cf-meta-asn")||""}}
      show(5+i*25/LATN,"Отклик: "+(i+1)+" из "+LATN);return latency(rec,i+1)}})}}
  function exit(rec){{return timed(TRACE,8000).then(function(x){{return x.r?x.r.text():""}}).then(function(t){{
      var i=/^ip=(.+)$/m.exec(t||""),l=/^loc=([A-Z]{{2}})$/m.exec(t||"");rec.ip=i?i[1]:"";rec.country=l?l[1]:""}},function(){{}})}}
  function sites(rec,k){{if(k>=2)return Promise.resolve();show(30+k*15,"Сайты: Telegram, YouTube, Instagram, Google");
    return Promise.all(SITES.map(function(s){{return timed(s[2]+"?n="+Date.now(),6000,"no-cors").then(function(x){{(rec.sites[s[0]]=rec.sites[s[0]]||[]).push(x.ms)}})}}))
      .then(function(){{return sites(rec,k+1)}})}}
  function download(rec){{return new Promise(function(done){{var t0=performance.now(),total=0,gap=0,fin=0,ctl=[],last=[],stop=false,iv;
    function end(){{if(stop)return;stop=true;clearInterval(iv);var n=performance.now();
      for(var i=0;i<NS;i++){{if(last[i]!==null)gap=Math.max(gap,n-last[i]);ctl[i].abort()}}
      rec.dl={{bytes:total,ms:Math.round(n-t0),gap_ms:Math.round(gap),done:fin}};done()}}
    iv=setInterval(function(){{var n=performance.now();show(60+40*Math.min(1,(n-t0)/DLMS),"Загрузка: "+(total/1048576).toFixed(1).replace(".",",")+" МБ");
      if(n-t0>DLMS)end()}},250);
    function one(i){{ctl[i]=new AbortController();last[i]=t0;
      fetch(CF+"/__down?bytes="+NB+"&s="+i+"-"+Date.now(),{{cache:"no-store",signal:ctl[i].signal}}).then(function(r){{var rd=r.body.getReader();
        function step(){{return rd.read().then(function(c){{if(stop)return;
          if(c.done){{last[i]=null;fin++;if(fin===NS)end();return}}
          var n=performance.now();gap=Math.max(gap,n-last[i]);last[i]=n;total+=c.value.length;return step()}})}}
        return step()}}).catch(function(){{}})}}             // a failed stream keeps its last time: it counts as a pause
    for(var i=0;i<NS;i++)one(i)}})}}
  go.addEventListener("click",function(){{
    if(!op){{res.className="res warn";res.textContent="Сначала выберите оператора.";return}}
    go.disabled=true;res.textContent="";res.className="res";list.innerHTML="";sent.className="res hide";show(0,"Начинаю…");
    var rec={{op:op,ip:"",dl_ip:"",country:"",asn:"",lat:[],sites:{{}},dl:{{}}}};
    post("start",{{op:op}});
    exit(rec).then(function(){{return latency(rec,0)}}).then(function(){{return sites(rec,0)}}).then(function(){{return download(rec)}}).then(function(){{
      show(100,"Готово");sent.className="res";sent.textContent="Отправляю итог…";
      post("done",rec,function(j){{go.disabled=false;
        if(j&&j.lines){{res.className="res "+j.level;res.textContent=j.lines[0];
          j.lines.slice(1).forEach(function(t){{var li=document.createElement("li");li.textContent=t;list.appendChild(li)}});
          sent.textContent="Итог отправлен владельцу."}}
        else{{res.className="res warn";res.textContent="Итог не отправился — уйдёт, когда откроете эту страницу при любой связи.";
          sent.textContent="Скачано "+(rec.dl.bytes/1048576).toFixed(1).replace(".",",")+" МБ, выход: "+(rec.country||"?")}}}})}})}});
}})();
</script>
</body></html>
"""


def _ints(x, n: int, lo: int, hi: int) -> list[int] | None:
    if not isinstance(x, list) or len(x) > n or not all(isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi for v in x):
        return None
    return x


def save_check(token: str, meta: dict, data, relay: str, now: float) -> tuple[str, dict]:
    """The page -> CHECKS/<time>-<n>.json for vpnjob: {start} when it begins (vpnjob notes the relay counters),
    then the result. Returns ('' or why it was refused, the report for the page)."""
    if not isinstance(data, dict) or data.get("op") not in OPS:
        return "bad result", {}
    if set(data) == {"op"}:                       # the start: no message, only the relay counters
        return _write_check(token + ":start", meta, {"kind": "start", "op": data["op"]}, relay, now), {}
    lat = _ints(data.get("lat"), LAT_N, -1, 60000)
    s = data.get("sites")
    sites = {k: _ints(s.get(k), 3, -1, 60000) for k, _, _ in SITES} if isinstance(s, dict) else None
    d = data.get("dl")
    try:
        dl = {k: int(d.get(k) or 0) for k in ("bytes", "ms", "gap_ms", "done")} if isinstance(d, dict) else None
    except (TypeError, ValueError):
        dl = None
    ip, dl_ip, country, asn = (str(data.get(k) or "") for k in ("ip", "dl_ip", "country", "asn"))
    if (lat is None or sites is None or any(v is None for v in sites.values()) or dl is None
            or not (0 <= dl["bytes"] <= DL_STREAMS * DL_BYTES and 0 <= dl["ms"] <= 120000 and 0 <= dl["gap_ms"] <= 120000
                    and 0 <= dl["done"] <= DL_STREAMS)
            or not re.fullmatch(r"[0-9A-Fa-f:.]{0,45}", ip) or not re.fullmatch(r"[0-9A-Fa-f:.]{0,45}", dl_ip) or not re.fullmatch(r"[A-Z]{0,2}", country)
            or not re.fullmatch(r"\d{0,10}", asn)):
        return "bad result", {}
    rec = {"kind": "vpn", "op": data["op"], "ip": ip, "dl_ip": dl_ip, "country": country, "asn": asn, "lat": lat, "sites": sites,
           "dl": dl, "late": bool(data.get("late"))}
    level, lines = check_report(rec, exits())
    return _write_check(token, meta, rec, relay, now), {"level": level, "lines": lines}


def _write_check(key: str, meta: dict, rec: dict, relay: str, now: float) -> str:
    if now - _last_check.get(key, 0) < CHECK_EVERY:
        return "too often"
    try:
        if sum(1 for _ in CHECKS.iterdir()) >= CHECKS_MAX:
            return "full"
    except OSError:
        return "no place"
    _last_check[key] = now
    rec = {"at": int(now), "person": meta.get("person", ""), "name": meta.get("name") or meta.get("person", ""),
           **rec, "relay": relay}
    try:
        with open(CHECKS / f"{int(now)}-{os.getpid()}-{len(_last_check)}.json", "x") as f:
            f.write(json.dumps(rec, ensure_ascii=False))
    except OSError:
        return "no place"
    return ""


def wants_page(headers) -> bool:
    ua = headers.get("User-Agent", "")
    return "text/html" in headers.get("Accept", "") and not APP_UA.search(ua)


class Handler(BaseHTTPRequestHandler):
    server_version = "web"
    sys_version = ""

    def log_message(self, *args):          # the path is the key: never logged
        pass

    def send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Robots-Tag", "noindex")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        c = CHECK_RE.match(self.path.split("?", 1)[0])
        if c and not c.group(2):
            got = load(c.group(1))
            if not got:
                return self.send(404, b"not found\n", "text/plain; charset=utf-8")
            hosts = " ".join(sorted({CF_SPEED, CF_TRACE.split("/cdn-cgi")[0], *(u.split("/favicon")[0] for _, _, u in SITES)}))
            return self.send(200, check_page(c.group(1), got[1], route_now()).encode(), "text/html; charset=utf-8", {
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                                           f"connect-src 'self' {hosts}; img-src data:; font-src data:; base-uri 'none'; "
                                           "form-action 'none'; frame-ancestors 'none'",
                "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"})
        m = TOKEN_RE.match(self.path.split("?", 1)[0])
        got = load(m.group(1)) if m else None
        if not got:
            return self.send(404, b"not found\n", "text/plain; charset=utf-8")
        token, (body, meta) = m.group(1), got
        st = people_state(meta)
        if wants_page(self.headers):
            return self.send(200, page(token, meta, st, tg_link(token)).encode(), "text/html; charset=utf-8", {
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                                           "img-src data:; font-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
                "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"})
        title = f"{TITLE} · {meta.get('name') or meta.get('person') or ''}".strip(" ·")
        return self.send(200, body.encode(), "text/plain; charset=utf-8", {
            "profile-title": "base64:" + base64.b64encode(title.encode()).decode(),
            "profile-update-interval": "1",
            "subscription-userinfo": f"upload=0; download={st['traffic_30d']}; "
                                     f"total={int(meta.get('limit_gb') or 0) << 30}; expire={expire_ts(meta)}",
            "profile-web-page-url": BASE_URL + token,
            **({"routing": meta["routing"]} if str(meta.get("routing", "")).startswith("happ://routing/") else {})})

    do_HEAD = do_GET

    def do_POST(self):
        c = CHECK_RE.match(self.path.split("?", 1)[0])
        got = load(c.group(1)) if c and c.group(2) else None
        if not got:
            return self.send(404, b"not found\n", "text/plain; charset=utf-8")
        try:
            n = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(n)) if 0 < n <= 2048 else None
        except (ValueError, OSError):
            data = None
        if c.group(2) == "start" and not (isinstance(data, dict) and set(data) == {"op"}):
            data = None
        why, report = save_check(c.group(1), got[1], data, route_now(), time.time())
        code = {"": 200, "too often": 429, "full": 503, "no place": 503}.get(why, 400)
        return self.send(code, json.dumps({"ok": not why, "why": why, **report}, ensure_ascii=False).encode(),
                         "application/json; charset=utf-8")


def main(argv: list[str]) -> int:
    srv = ThreadingHTTPServer(LISTEN, Handler)
    srv.daemon_threads = True
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
