"""VPN со стороны админки: «Подтвердить» в боте, задания root-исполнителю (устройство — docs/panel.md).
Правки делает root-юнит `bvpn-job@<id>` (vpnjob.py из bvpn), админка лишь:

1. читает предложения чата `<proposals>/<id>.json` (operator:bvpn-admin 2770), проверяет их теми же
   правилами, что `vpnjob.validate`, и шлёт карточку «✅ Подтвердить / Отмена» (кнопка несёт только
   номер, запрос лежит в kv хранилища); обработанный файл удаляет;
2. после «Подтвердить» пишет `<outbox>/<id>.json` = запрос + digest + approved {by, at} и стартует
   `bvpn-job@<id>.service` (polkit, маска имени в whitelist.polkit_rule);
3. итог `<vpn_dir>/results/<id>.json` дописывает в то же сообщение; правка с откатом по таймеру
   (`pending`) — новое сообщение «Работает?» с «✅ Работает» / «↩️ Откатить»: нажатие и есть согласие.

С вкладки «VPN» без подтверждения — только «Обновить» и «Самопроверка» (ничего не меняют,
approved.by = page:<логин>); «Перезапустить …» — та же карточка в боте. Ссылок и QR нигде нет.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import hashlib
import html
import json
import logging
import os
import re
import secrets
import time
from typing import Callable

from admin.config import CONF, Settings
from admin.store import Store

log = logging.getLogger("admin.vpn")


async def run(*cmd: str, timeout: float = 30) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return 124, f"таймаут {timeout:.0f} с"
    return proc.returncode or 0, out.decode("utf-8", "replace")


e = html.escape

# --- то же, что в scripts/vpnjob.py bvpn (тест сверяет, если рабочая копия рядом) ---
ID_RE = re.compile(r"^[a-z0-9-]{3,40}$")
SERVERS = {CONF["server_id"]: CONF["title"]}
UNITS = ("xray", "hysteria-server", "telemt")
# действие -> (что это для бота, что моргнёт у подключённых)
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
RELAY_SERVER = CONF["server_id"]      # как vpnjob: посредник пересылает порты этого сервера
IPV4_RE = re.compile(r"^(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$")
OUR_IPS = (CONF["ip"],)
ROUTING_PROFILES = {"ai-social": "ИИ и соцсети через VPN", "all": "всё через VPN",
                    "all-but-ru": "всё через VPN, кроме российских сайтов"}
DOMAIN_RE = re.compile(r"^(?=.{4,80}$)([a-z0-9-]+\.)+[a-z]{2,24}$")
LOGIN_RE = re.compile(r"^[a-z][a-z0-9]{1,15}$")
NOTE_RE = re.compile(r"^[0-9A-Za-zА-Яа-яЁё .,()!-]*$")             # как vpnjob: примечание к источнику подписки
KIT_FILE_RE = re.compile(r"^[0-9a-z][0-9a-z_-]{0,60}\.(txt|png|yaml|json)$")   # как vpnjob: без .bak и скрытых
KEEP_PEOPLE = (CONF["template"],)
# --- то же, что vpnlib.scan: что похоже на секрет и не должно уйти в бот или на страницу ---
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
HEX_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32,}(?![0-9a-fA-F])")
LINK_RE = re.compile(r"\b(?:vless|vmess|trojan|ss|hysteria2|hy2|tg)://", re.I)
B64KEY_RE = re.compile(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/-]{43}=?(?![A-Za-z0-9_+/=-])")

QUICK = ("refresh", "selftest", "relay-check")
STALL_BYTES = 50 * 1024           # за час при «в сети» — почти ноль
STALL_DAILY = 30 * (1 << 20)      # обычно пользуется: в среднем ≥ 30 МБ в день за неделю
IDLE_DAYS = 7                     # «давно не подключался»
MANY_DEVICES = 4                  # «много устройств на одной ссылке»
TRANSLIT = dict(zip("абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
                    ["a", "b", "v", "g", "d", "e", "e", "zh", "z", "i", "i", "k", "l", "m", "n", "o", "p", "r", "s", "t",
                     "u", "f", "h", "ts", "ch", "sh", "sch", "", "y", "", "e", "yu", "ya"]))


def translit(name: str) -> str:
    """«Ольга Петрова» → olga: первое слово латиницей, только a-z0-9 — так выглядят логины VPN."""
    word = (str(name).split() or [""])[0].lower()
    out = re.sub(r"[^a-z0-9]", "", "".join(TRANSLIT.get(c, c) for c in word))
    out = re.sub(r"^[0-9]+", "", out)[:14]
    return out if len(out) >= 2 else "user"      # с вкладки без подтверждения: ничего не меняют
UNIT = "bvpn-job@{}.service"
OFFER_TTL = 30 * 60                  # карточка «Подтвердить» живёт полчаса (исполнитель ждёт согласие не старше 30 мин)
RESULT_WAIT = 15 * 60                # правка Xray — до 4 мин, снимки обоих серверов — ещё до 5
KEEP = 7 * 86400                     # завершённые задания в kv — неделю (для вкладки)
MAX_FILE = 64 * 1024
CARD_MAX = 3000                      # длиннее — фильтр уходит отдельными сообщениями (лимит Telegram 4096)
MSK = dt.timezone(dt.timedelta(hours=3))


class Bad(ValueError):
    pass


def scan(text: str) -> list[str]:
    """Почему текст нельзя показывать (пусто — можно). Копия vpnlib.scan без живых конфигов."""
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
    return bad


def validate(req: dict) -> dict:
    """Чистая копия запроса или Bad — те же правила, что vpnjob.validate (исполнитель проверит ещё раз)."""
    if not isinstance(req, dict):
        raise Bad("запрос — не объект")
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
            raise Bad(f"server: {RELAY_SERVER} (посредник пересылает его порты)")
        server = RELAY_SERVER
    elif action in ("sub-publish", "sub-send", "sub-rotate", "sub-settings", "sub-reveal"):
        if (server or "all") != "all":
            raise Bad("server: all (серверы — в sources)")
        server = "all"
    elif server not in SERVERS:
        raise Bad("server: " + " | ".join(SERVERS))
    if action not in ACTIONS:
        raise Bad("action: " + " | ".join(ACTIONS))
    if not isinstance(args, dict):
        raise Bad("args — не объект")
    clean: dict = {}
    if action == "restart":
        if args.get("unit") not in UNITS:
            raise Bad("unit: " + " | ".join(UNITS))
        clean["unit"] = args["unit"]
    elif action == "xray-apply":
        f = args.get("filter")
        if not isinstance(f, str) or not f.strip() or len(f) > 20000:
            raise Bad("filter: фильтр jq до 20000 знаков")
        if scan(f):
            raise Bad("в фильтре что-то похожее на секрет — такие правки выполняйте через SSH")
        sec = args.get("seconds", 300)
        if not isinstance(sec, int) or not 60 <= sec <= 900:
            raise Bad("seconds: 60..900")
        clean.update(filter=f, seconds=sec)
    elif action == "ufw":
        op, rule = args.get("op"), args.get("rule")
        m = re.fullmatch(r"([0-9]{1,5})/(tcp|udp)", rule or "")
        if op not in ("allow", "delete") or not m or not 1 <= int(m.group(1)) <= 65535 or m.group(1) == "22":
            raise Bad("op: allow | delete; rule: ПОРТ/tcp|udp, порт 22 — никогда")
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
            raise Bad("login: 2–16 строчных латинских букв и цифр, первая — буква")
        if action == "person-remove" and login in KEEP_PEOPLE:
            raise Bad(f"{login} через панель не отключается")
        if action == "person-pause" and login in KEEP_PEOPLE:
            raise Bad(f"{login} не приостанавливается: это образец для новых людей")
        clean["login"] = login
        if action in ("person-add", "person-remove") and "sub" in args:
            if not isinstance(args["sub"], str) or not LOGIN_RE.match(args["sub"]):
                raise Bad("sub: чья подписка — как логин")
            clean["sub"] = args["sub"]
        if action == "person-add":
            name = args.get("name", "")
            if not isinstance(name, str) or not 1 <= len(name.strip()) <= 40 or re.search(r'["|\\\n\r]', name):
                raise Bad("name: 1–40 знаков, без кавычек, | и обратной косой")
            clean["name"] = name.strip()
    elif action == "kit-send":
        login, files = args.get("login", ""), args.get("files", [])
        if not isinstance(login, str) or not LOGIN_RE.match(login):
            raise Bad("login: 2–16 строчных латинских букв и цифр, первая — буква")
        if (not isinstance(files, list) or len(files) > 30
                or not all(isinstance(f, str) and KIT_FILE_RE.match(f) for f in files)):
            raise Bad("files: до 30 имён файлов комплекта вроде 2-calls.png (.txt .png .yaml .json, без .bak)")
        clean["login"] = login
        if files:
            clean["files"] = sorted(set(files))
    elif action == "sub-publish":
        person, sources = args.get("person", ""), args.get("sources")
        if not isinstance(person, str) or not LOGIN_RE.match(person):
            raise Bad("person: 2–16 строчных латинских букв и цифр, первая — буква")
        if not isinstance(sources, list) or not 1 <= len(sources) <= 4:
            raise Bad("sources: 1–4 источника {server, login}")
        clean_src = []
        for x in sources:
            if (not isinstance(x, dict) or not {"server", "login"} <= set(x) <= {"server", "login", "note"}
                    or x["server"] not in SERVERS or not isinstance(x["login"], str) or not LOGIN_RE.match(x["login"])):
                raise Bad("sources: [{server: " + " | ".join(SERVERS) + ", login, note?}]")
            note = x.get("note", "")
            if not isinstance(note, str) or len(note) > 40 or not NOTE_RE.match(note):
                raise Bad("note: до 40 букв, цифр, пробелов и . , - ( ) !")
            src = {"server": x["server"], "login": x["login"]}
            if any(c["server"] == src["server"] and c["login"] == src["login"] for c in clean_src):
                raise Bad("sources: один источник дважды")
            if note.strip():
                src["note"] = note.strip()
            clean_src.append(src)
        clean.update(person=person, sources=clean_src)
    elif action == "sub-settings":
        person = args.get("person", "")
        if not isinstance(person, str) or not LOGIN_RE.match(person):
            raise Bad("person: 2–16 строчных латинских букв и цифр, первая — буква")
        clean["person"] = person
        group = args.get("group", "")
        if not isinstance(group, str) or len(group) > 24 or not NOTE_RE.match(group):
            raise Bad("группа: до 24 букв, цифр, пробелов и . , - ( ) !")
        expire = args.get("expire", "")
        if not isinstance(expire, str) or (expire and not re.fullmatch(r"20[2-9][0-9]-[01][0-9]-[0-3][0-9]", expire)):
            raise Bad("срок: ГГГГ-ММ-ДД или пусто")
        limit = args.get("limit_gb", 0)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 0 <= limit <= 10000:
            raise Bad("лимит: 0..10000 ГБ (0 — без лимита)")
        routing = args.get("routing", "ai-social")
        if routing not in ROUTING_PROFILES:
            raise Bad("маршрутизация: " + " | ".join(ROUTING_PROFILES))
        lists = {}
        for k in ("proxy_add", "direct_add"):
            v = args.get(k, [])
            if not isinstance(v, list) or len(v) > 50 or not all(isinstance(d, str) and DOMAIN_RE.match(d) for d in v):
                raise Bad(f"{k}: до 50 доменов вида example.com")
            lists[k] = sorted(set(v))
        clean.update(group=group.strip(), expire=expire, limit_gb=limit, routing=routing, **lists)
    elif action in ("sub-send", "sub-rotate", "sub-reveal"):
        person = args.get("person", "")
        if not isinstance(person, str) or not LOGIN_RE.match(person):
            raise Bad("person: 2–16 строчных латинских букв и цифр, первая — буква")
        clean["person"] = person
    elif action in ("confirm", "revert"):
        if not ID_RE.match(str(args.get("ref", ""))):
            raise Bad("ref: номер правки")
        clean["ref"] = args["ref"]
    elif action == "relay-set":
        ip = args.get("ip", "")
        if not isinstance(ip, str) or not public_ipv4(ip) or ip in OUR_IPS:
            raise Bad("ip: публичный IPv4 нового сервера в РФ (не наш VPN)")
        clean["ip"] = ip
    extra = set(args) - set(clean)
    if extra:
        raise Bad(f"лишние аргументы: {sorted(extra)}")
    return {"id": rid, "server": server, "action": action, "args": clean,
            "title": str(req.get("title", ""))[:200], "why": str(req.get("why", ""))[:2000]}


def public_ipv4(ip: str) -> bool:
    """Как vpnjob.public_ipv4: не частная, не служебная сеть."""
    if not IPV4_RE.match(ip):
        return False
    a, b = (int(x) for x in ip.split(".")[:2])
    return not (a in (0, 10, 127) or a >= 224 or (a == 100 and 64 <= b < 128) or (a == 169 and b == 254)
                or (a == 172 and 16 <= b < 32) or (a == 192 and b == 168))


def digest(req: dict) -> str:
    core = {k: req[k] for k in ("server", "action", "args")}
    return hashlib.sha256(json.dumps(core, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


# ---------------------------------------------------------------- время и подписи

def parse_iso(value) -> float | None:
    if not value or not isinstance(value, str):
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def ago(ts: float | None) -> str:
    if not ts:
        return "—"
    s = max(0.0, time.time() - ts)
    if s < 90:
        return "только что"
    if s < 3600:
        return f"{s / 60:.0f} мин назад"
    if s < 86400 * 2:
        return f"{s / 3600:.0f} ч назад"
    return f"{s / 86400:.0f} дн. назад"


def msk(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, MSK).strftime("%H:%M МСК")


def server_title(server: str) -> str:
    return "оба сервера" if server == "all" else SERVERS.get(server, server)


def what(req: dict) -> str:
    """Одна строка о запросе (уже экранированная)."""
    a, args = req["action"], req.get("args") or {}
    tail = ""
    if a == "restart":
        tail = f": {args.get('unit', '')}"
    elif a in ("confirm", "revert"):
        tail = f": {args.get('ref', '')}"
    elif a == "update":
        tail = f": {args.get('program', '')} {args.get('version', '')}"
    elif a == "ufw":
        tail = f": {args.get('op', '')} {args.get('rule', '')}"
    elif a in ("person-add", "person-remove", "kit-send", "person-pause", "person-resume"):
        tail = f": {args.get('name') or args.get('login', '')}"
    elif a in ("sub-publish", "sub-send", "sub-rotate", "sub-settings", "sub-reveal"):
        tail = f": {args.get('person', '')}"
    elif a == "relay-set":
        tail = f": {args.get('ip', '')}"
    return e(f"{ACTIONS[a][0]}{tail} · {server_title(req['server'])}")


def card(req: dict, dig: str, source: str) -> tuple[str, list[str]]:
    """Карточка для бота и, если фильтр длинный, сообщения с ним целиком (идут перед карточкой)."""
    a, args = req["action"], req["args"]
    lines = [f"🛡 <b>VPN: {e(req.get('title') or ACTIONS[a][0])}</b>",
             f"Сервер: {e(server_title(req['server']))}",
             f"Действие: <code>{e(a)}</code> — {e(ACTIONS[a][0])}"]
    if a == "restart":
        lines.append(f"Служба: <code>{e(args['unit'])}</code>")
    elif a in ("confirm", "revert"):
        lines.append(f"Правка: <code>{e(args['ref'])}</code>")
    elif a == "xray-apply":
        lines.append(f"Без «✅ Работает» сервер откатит правку сам через {args['seconds']} с.")
    elif a == "update":
        lines.append(f"Программа: <code>{e(args['program'])}</code> → {e(args['version'])}")
    elif a == "ufw":
        lines.append(f"Правило: <code>ufw {e(args['op'])} {e(args['rule'])}</code>")
    elif a == "person-add" and args.get("sub"):
        lines.append(f"Человек: {e(args['name'])} (<code>{e(args['login'])}</code>), подписка <code>{e(args['sub'])}</code>. "
                     "После самопроверки нажмите «✅ Работает» — сюда придёт QR и готовый текст со ссылкой для пересылки.")
    elif a == "person-add":
        lines.append(f"Человек: {e(args['name'])} (<code>{e(args['login'])}</code>). "
                     "Комплект придёт сюда файлом после самопроверки.")
    elif a == "person-remove" and args.get("sub"):
        lines.append(f"Человек: <code>{e(args['login'])}</code>. После «✅ Работает» удалится и подписка "
                     f"<code>{e(args['sub'])}</code> — её ссылка перестанет открываться. Комплект останется у чата vpn.")
    elif a in ("person-remove", "person-pause", "person-resume"):
        lines.append(f"Человек: <code>{e(args['login'])}</code>"
                     + (". Ссылки и подписка сохраняются — «Возобновить» вернёт всё как было." if a == "person-pause" else ""))
    elif a == "sub-send":
        lines.append(f"Подписка <code>{e(args['person'])}</code>: сюда придёт QR и готовый текст со ссылкой — перешлите человеку.")
    elif a == "sub-settings":
        lines.append(f"Подписка <code>{e(args['person'])}</code>: группа «{e(args['group'] or '—')}», "
                     f"срок {e(args['expire'] or 'бессрочно')}, лимит {e(str(args['limit_gb']) + ' ГБ в месяц' if args['limit_gb'] else 'нет')}, "
                     f"маршрутизация «{e(ROUTING_PROFILES[args['routing']])}»"
                     + (f", через VPN ещё: {e(', '.join(args['proxy_add']))}" if args["proxy_add"] else "")
                     + (f", напрямую: {e(', '.join(args['direct_add']))}" if args["direct_add"] else "")
                     + ". Ссылка та же, Happ подтянет за час.")
    elif a == "sub-rotate":
        lines.append(f"Подписка <code>{e(args['person'])}</code>: старая ссылка сразу перестанет работать, новая придёт сюда. "
                     "Человеку нужно будет добавить новую ссылку в Happ.")
    elif a == "sub-publish":
        src = ", ".join(f"{x['login']} на {SERVERS.get(x['server'], x['server'])}"
                        + (f" («{x['note']}»)" if x.get("note") else "") for x in args["sources"])
        lines.append(f"Подписка: <code>{e(args['person'])}</code> ← {e(src)}. Перед публикацией каждая ссылка "
                     "сверяется с живыми настройками сервера; не совпало — не публикуется ничего. "
                     "Первая публикация — ссылка-подписка придёт сюда файлом.")
    elif a == "kit-send":
        files = ", ".join(args.get("files") or []) or "весь комплект (без копий .bak)"
        lines.append(f"Человек: <code>{e(args['login'])}</code>. Файлы: {e(files)}. "
                     "Придут сюда файлом, только в этот чат.")
    lines.append(f"Что моргнёт: {e(ACTIONS[a][1])}")
    why = req.get("why") or ""
    if why:
        lines.append(f"Зачем: {e(why[:1500])}{'…' if len(why) > 1500 else ''}")
    lines.append(e(source))
    extra: list[str] = []
    if a == "xray-apply":
        f, label = (args["filter"], "Фильтр") if a == "xray-apply" else (args["config"], "Конфиг")
        inline = f"{label} целиком:\n<pre>{e(f)}</pre>"
        if len("\n".join(lines)) + len(inline) <= CARD_MAX:
            lines.append(inline)
        else:
            parts = [f[i:i + CARD_MAX] for i in range(0, len(f), CARD_MAX)]
            extra = [f"🛡 {label} «{e(req['id'])}», часть {n}/{len(parts)}:\n<pre>{e(p)}</pre>"
                     for n, p in enumerate(parts, 1)]
            lines.append(f"{label} целиком — в {len(parts)} сообщениях выше.")
    lines.append(f"digest <code>{dig[:8]}</code> · номер <code>{e(req['id'])}</code>")
    return "\n".join(lines), extra


def result_block(res: dict) -> str:
    rc = res.get("rc")
    head = "✅ Готово." if res.get("ok") else f"❌ Не получилось (код {e(str(rc))})."
    out = str(res.get("output") or "")[-1500:]
    if out and scan(out):
        out = "(вывод скрыт: похоже на секрет)"
    return head + (f"\n<pre>{e(out)}</pre>" if out else "")


RELAY_PW_RE = re.compile(r"^[\x21-\x7e]{1,128}$")
RELAY_HELP = (
    "🆘 <b>Посредник в РФ отлетел — что делать с телефона</b>\n\n"
    "<b>1. Убедиться.</b> /relay → «🔎 Проверить посредник». Или страница подписки (в Happ — значок страницы) → "
    "«Проверить связь с телефона» на мобильном интернете. Красное на всех серверах — меняем.\n\n"
    "<b>2. Заказать новый сервер в России</b> у любого хостера: система <b>Ubuntu 24.04</b>, самый дешёвый тариф, "
    "оплата на месяц, без бэкапов.\n\n"
    "<b>3. Дождаться письма</b> от хостера: там <b>IP</b> и <b>пароль root</b>.\n\n"
    "<b>4. Прислать сюда:</b> <code>/relay IP ПАРОЛЬ</code>\n"
    "Бот удалит сообщение с паролем, положит на сервер свой ключ и выключит там вход по паролю.\n\n"
    "<b>5. Нажать «✅ Подтвердить»</b> в карточке. Через 1–3 минуты придёт итог: все каналы проверены через новый "
    "сервер, подписки обновлены. Если проверка не прошла — ничего не переключится, старое останется.\n\n"
    "<b>6. В Happ обновить подписку</b> (потянуть список вниз или ⟳ у подписки) и попросить об этом остальных.\n\n"
    "<b>7. Старый сервер отменить</b> у хостера.")


class Vpn:
    """Состояние — в kv хранилища: vpn:<номер> → {kind, state, req, digest, message_id, text, …}.

    kind: offer (карточка «Подтвердить»), quick (кнопка вкладки), pending («Работает?»),
    job (оставить/откатить по кнопке «Работает?»)."""

    def __init__(self, s: Settings, store: Store, bot_fn: Callable[[], object]):
        self.s, self.store, self._bot = s, store, bot_fn
        self._relay_pw: dict[str, str] = {}      # card number -> root password of a new relay, memory only

    @property
    def bot(self):
        return self._bot()

    # ------------------------------------------------------------ чтение
    def panel(self) -> dict | None:
        """Снимок панели (пишет root раз в 5 минут). None — панели ещё нет."""
        try:
            text = (self.s.vpn_dir / "panel.json").read_text(encoding="utf-8")
            data = json.loads(text)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        if scan(text):          # исполнитель такое не выдаёт; не показываю на всякий случай
            return {"withheld": True, "servers": []}
        data["servers"] = [x for x in data.get("servers") or [] if isinstance(x, dict)]
        return data

    def result(self, jid: str) -> dict | None:
        if not ID_RE.match(jid or ""):
            return None
        try:
            data = json.loads((self.s.vpn_dir / "results" / f"{jid}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) and data.get("id") == jid else None

    def recent(self, limit: int = 50) -> list[dict]:
        rows = [d for _, d in self.store.items("vpn:") if d.get("kind") in ("offer", "quick", "job")]
        rows.sort(key=lambda d: d.get("created", 0), reverse=True)
        return rows[:limit]

    def moving(self) -> dict[str, tuple[str, str]]:
        """Переносы, что ещё не случились: человек → (сервер, «ждёт «Подтвердить»» / «переношу»). Для плашки серверов:
        пока снимок не показал человека на новом месте, она говорит, куда его уже везут."""
        out: dict[str, tuple[str, str]] = {}
        for d in sorted(self.recent(200), key=lambda d: d.get("created", 0)):
            req, state = d.get("req") or {}, d.get("state")
            if state not in ("offered", "running") or time.time() - d.get("created", 0) > 3600:
                continue
            args = req.get("args") or {}
            if req.get("action") == "person-add" and args.get("sub"):
                person, target = args["sub"], req.get("server")
            elif req.get("action") == "sub-publish" and args.get("sources"):
                person, target = args.get("person"), (args["sources"][0] or {}).get("server")
            else:
                continue
            if person and target in SERVERS:
                out[person] = (target, "ждёт «Подтвердить» в боте" if state == "offered" else "переношу")
        return out

    def _busy(self, rid: str) -> bool:
        """Запрос с этим номером уже ждёт кнопки, идёт или исполнялся."""
        if (self.s.vpn_dir / "results" / f"{rid}.json").exists():
            return True
        return any(d.get("req", {}).get("id") == rid and d.get("state") in ("offered", "running", "done", "failed")
                   for _, d in self.store.items("vpn:"))

    def _new_id(self, prefix: str) -> str:
        while True:
            rid = f"{prefix[:33]}-{secrets.token_hex(3)}"
            if not self._busy(rid):
                return rid

    # ------------------------------------------------------------ запуск
    def _write_job(self, req: dict, dig: str, by: str, secret: str = "") -> None:
        self.s.vpn_outbox.mkdir(parents=True, exist_ok=True)
        path = self.s.vpn_outbox / f"{req['id']}.json"
        tmp = path.with_name(f".{req['id']}.tmp")
        extra = {"relay_password": secret} if secret and req["action"] == "relay-set" else {}   # vpnjob reads and wipes it
        tmp.write_text(json.dumps({**req, "digest": dig, "approved": {"by": by, "at": time.time()}, **extra},
                                  ensure_ascii=False), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(path)

    async def _launch(self, req: dict, dig: str, by: str, secret: str = "") -> tuple[bool, str]:
        if (self.s.vpn_dir / "results" / f"{req['id']}.json").exists():
            return False, "задание с таким номером уже исполнялось"
        try:
            self._write_job(req, dig, by, secret)
        except OSError as exc:
            return False, f"не записал задание ({type(exc).__name__}): панель VPN на сервере установлена?"
        unit = UNIT.format(req["id"])
        if self.s.dry_run:
            rc, out = 0, ""
        else:
            rc, out = await run("systemctl", "start", "--no-block", unit, timeout=30)
        self.store.log_action(f"vpn:{req['action']}:{req['server']}:{req['id']}", by, rc == 0, out[-500:])
        return rc == 0, out.strip()[-300:]

    def _running(self, num: str, req: dict, dig: str, mid: int, text: str, kind: str, by: str = "") -> None:
        self.store.put(f"vpn:{num}", {"kind": kind, "state": "running", "req": req, "digest": dig,
                                      "created": time.time(), "started": time.time(),
                                      "message_id": mid, "text": text, "by": by})

    # ------------------------------------------------------------ предложения и карточки
    async def offer(self, raw: dict, source: str) -> tuple[str | None, str]:
        """Карточка «Подтвердить / Отмена» в бот. (номер, ошибка)"""
        try:
            req = validate(raw)
        except Bad as exc:
            return None, str(exc)
        if self._busy(req["id"]):
            return None, f"запрос {req['id']} уже есть"
        dig = digest(req)
        text, extra = card(req, dig, source)
        num = secrets.token_hex(6)
        for part in extra:
            await self.bot.send(part)
        mid = await self.bot.send(text, [[("✅ Подтвердить", f"vpn:go:{num}"), ("✖️ Отмена", f"vpn:no:{num}")]])
        self.store.put(f"vpn:{num}", {"kind": "offer", "state": "offered", "req": req, "digest": dig,
                                      "created": time.time(), "message_id": mid, "text": text})
        return num, ""

    async def take_proposals(self) -> None:
        """Предложения чата vpn → карточки. Файл удаляется, когда сообщение (карточка или отказ) ушло."""
        try:
            files = sorted(p for p in self.s.vpn_proposals.glob("*.json") if not p.name.startswith("."))
        except OSError:
            return
        for path in files:
            try:
                if path.stat().st_size > MAX_FILE:
                    raise Bad("файл больше 64 КБ")
                raw = json.loads(path.read_text(encoding="utf-8"))
                req = validate(raw)
                if req["id"] != path.stem:
                    raise Bad("номер в файле не совпадает с именем файла")
                if raw.get("digest") and raw["digest"] != digest(req):
                    raise Bad("digest предложения не сходится с его содержимым")
                if self._busy(req["id"]):
                    log.info("предложение VPN %s уже показано — убираю файл", req["id"])
                else:
                    num, err = await self.offer(req, "Предложил чат vpn. Исполнится только после «Подтвердить» (30 минут).")
                    if not num:
                        raise Bad(err)
            except (OSError, ValueError) as exc:     # Bad — тоже ValueError
                why = str(exc) if isinstance(exc, Bad) else f"не читается ({type(exc).__name__})"
                try:
                    await self.bot.send(f"⚠️ Предложение VPN <code>{e(path.name[:60])}</code> не принято: {e(why[:300])}")
                except Exception as send_exc:  # noqa: BLE001 — повторю в следующий проход
                    log.warning("отказ по предложению VPN не отправлен: %s", type(send_exc).__name__)
                    continue
            except Exception as exc:  # noqa: BLE001 — бот не ответил: файл остаётся, повторю
                log.warning("предложение VPN %s не отправлено: %s", path.name, type(exc).__name__)
                continue
            with contextlib.suppress(OSError):
                path.unlink()

    async def ask_restart(self, server: str, unit: str, who: str) -> tuple[str | None, str]:
        if server not in SERVERS or unit not in UNITS:
            return None, "нет такого сервера или службы"
        req = {"id": self._new_id(f"restart-{unit}"), "server": server, "action": "restart", "args": {"unit": unit},
               "title": f"Перезапустить {unit} на {SERVERS[server]}", "why": "кнопка на вкладке «VPN»"}
        try:
            return await self.offer(req, f"Запрошено со страницы админки ({who}). Исполнится только после «Подтвердить» (30 минут).")
        except Exception as exc:  # noqa: BLE001
            log.warning("карточка VPN не отправлена: %s", type(exc).__name__)
            return None, "бот не отправил подтверждение — попробуйте ещё раз"

    async def quick(self, action: str, server: str, who: str) -> tuple[str | None, str]:
        """«Обновить» и «Самопроверка» с вкладки — без подтверждения, approved.by = page:<логин>."""
        if action not in QUICK:
            return None, "изменения — только через «Подтвердить» в боте"
        if server not in SERVERS and not (action == "refresh" and server == "all"):
            return None, "нет такого сервера"
        busy = sum(1 for _, d in self.store.items("vpn:")
                   if d.get("kind") == "quick" and d.get("state") == "running" and d.get("started", 0) > time.time() - 300)
        if busy >= 3:
            return None, "уже идут три задания — подождите пару минут"
        req = {"id": self._new_id(f"{action}-{server}"), "server": server, "action": action, "args": {},
               "title": ACTIONS.get(action, ("", ""))[0], "why": "кнопка на вкладке «VPN»"}
        try:
            req = validate(req)
        except Bad as exc:
            return None, str(exc)
        dig = digest(req)
        ok, out = await self._launch(req, dig, f"page:{who}")
        if not ok:
            return None, f"задание не запустилось: {out}"
        self._running(secrets.token_hex(6), req, dig, 0, "", "quick", f"page:{who}")
        return req["id"], ""

    # ------------------------------------------------------------ люди и подписки (вкладка)
    def subs(self) -> dict:
        """`<vpn_dir>/subs.json` (пишет исполнитель): у кого подписка и из каких источников. Токенов там нет."""
        try:
            data = json.loads((self.s.vpn_dir / "subs.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) and not scan(json.dumps(data, ensure_ascii=False)) else {}

    def people(self) -> list[dict]:
        """Люди для вкладки: подписки и логины без подписки. По каждому — источники и сведения из снимка."""
        panel = self.panel() or {}
        snap = {x.get("id"): ((x.get("snapshot") or {}).get("people") or []) for x in panel.get("servers") or []
                if isinstance(x, dict)}
        by = {(sid, p.get("login")): p for sid, ps in snap.items() for p in ps if isinstance(p, dict)}
        out, used = [], set()
        for person, sub in sorted(self.subs().items()):
            if not isinstance(sub, dict) or not LOGIN_RE.match(str(person)):
                continue
            srcs = []
            for x in sub.get("sources") or []:
                if not isinstance(x, dict):
                    continue
                key = (x.get("server"), x.get("login"))
                used.add(key)
                srcs.append({"server": key[0], "login": key[1], "note": x.get("note", ""), "info": by.get(key) or {}})
            out.append({"person": person, "name": sub.get("name") or person, "sub": True, "sources": srcs, "accounts": {},
                        **{k: sub[k] for k in ("group", "expire", "limit_gb", "routing_profile", "proxy_add", "direct_add")
                           if k in sub}})
        owner = {x["login"]: p for p in out for x in p["sources"]}
        alone: dict[str, dict] = {}
        for (sid, login), p in sorted(by.items(), key=lambda kv: (kv[0][1] or "", list(SERVERS).index(kv[0][0])
                                                                  if kv[0][0] in SERVERS else 99)):
            if (sid, login) in used or not LOGIN_RE.match(str(login)):
                continue
            if login in owner:
                owner[login]["accounts"].setdefault(sid, login)
            elif login in alone:
                alone[login]["accounts"].setdefault(sid, login)
            else:
                alone[login] = {"person": login, "name": p.get("name") or login, "sub": False, "accounts": {},
                                "sources": [{"server": sid, "login": login, "note": "", "info": p}]}
        return [p for p in out + list(alone.values()) if p.get("person") != CONF.get("monitor_account", "monitoring")]

    def free_login(self, base: str) -> str:
        taken = {p.get("login") for x in (self.panel() or {}).get("servers") or [] if isinstance(x, dict)
                 for p in ((x.get("snapshot") or {}).get("people") or []) if isinstance(p, dict)} | set(self.subs())
        base = (base or "user")[:14]
        if base not in taken and LOGIN_RE.match(base):
            return base
        for n in range(2, 100):
            if f"{base}{n}" not in taken:
                return f"{base}{n}"
        return f"{base[:10]}{secrets.token_hex(2)}"

    async def ask(self, action: str, server: str, args: dict, title: str, who: str,
                  source: str = "") -> tuple[str | None, str]:
        """Карточка «Подтвердить» в бот для кнопки вкладки «Люди» (или для напоминания админки — source)."""
        tag = args.get("login") or args.get("person") or ""
        req = {"id": self._new_id(f"{action}-{tag}"), "server": server, "action": action, "args": args,
               "title": title, "why": "кнопка на вкладке «VPN» → «Люди»"}
        try:
            return await self.offer(req, (source or f"Запрошено со страницы админки ({who}).")
                                    + " Исполнится только после «Подтвердить» (30 минут).")
        except Exception as exc:  # noqa: BLE001
            log.warning("карточка VPN не отправлена: %s", type(exc).__name__)
            return None, "бот не отправил подтверждение — попробуйте ещё раз"

    async def add_person(self, name: str, login: str, server: str, who: str) -> tuple[str | None, str]:
        name = " ".join(str(name).split())[:40]
        login = (login or "").strip().lower() or self.free_login(translit(name))
        if server not in SERVERS:
            return None, "нет такого сервера"
        if login in {p["person"] for p in self.people()}:
            return None, f"логин {login} уже занят — укажите другой"
        return await self.ask("person-add", server, {"login": login, "name": name, "sub": login},
                              f"Подключить: {name}", who)

    async def move(self, person: str, target: str, who: str) -> tuple[str | None, str]:
        """Перенос на другой сервер: там уже есть логин этого человека — переключить подписку; нет — завести
        его там с той же подпиской (после «Работает» подписка переключится сама). Ссылка у человека та же.
        У кого подписки не было — она появится, и ссылка придёт в бот: её надо отправить человеку."""
        p = next((x for x in self.people() if x["person"] == person), None)
        if not p or target not in SERVERS:
            return None, "нет такого человека или сервера"
        if any(x["server"] == target for x in p["sources"]) and len(p["sources"]) == 1:
            return None, "человек уже на этом сервере"
        have = next((x["login"] for x in p["sources"] if x["server"] == target and not (x["info"] or {}).get("paused")),
                    p.get("accounts", {}).get(target))
        if have:     # a login already there: the subscription switches to it (none yet: created with it)
            return await self.ask("sub-publish", "all", {"person": person, "sources": [{"server": target, "login": have}]},
                                  f"Перенести {p['name']} на {SERVERS[target]}", who)
        name = re.sub(r'["|\\\n\r]', "", str(p["name"]))[:40] or person
        return await self.ask("person-add", target, {"login": self.free_login(person), "name": name, "sub": person},
                              f"Перенести {name} на {SERVERS[target]}", who)

    async def reveal(self, person: str, who: str) -> tuple[str | None, str]:
        """«Показать ссылку»: задание без «Подтвердить» (VPN не трогается); адрес читает только страница того,
        кто нажал (link()), один раз."""
        try:
            req = validate({"id": self._new_id(f"sub-reveal-{person}"), "server": "all", "action": "sub-reveal",
                            "args": {"person": person}, "title": f"Показать ссылку: {person}", "why": "кнопка «Показать ссылку»"})
        except Bad as exc:
            return None, str(exc)
        dig = digest(req)
        ok, out = await self._launch(req, dig, f"page:{who}")
        if not ok:
            return None, f"задание не запустилось: {out}"
        self._running(secrets.token_hex(6), req, dig, 0, "", "quick", f"page:{who}")
        return req["id"], ""

    def link(self, jid: str, who: str) -> tuple[str, str]:
        """(состояние, адрес): wait — ещё готовится, ok — показать (файл стёрт), gone — нет/чужое/устарело."""
        if not ID_RE.match(jid) or not jid.startswith("sub-reveal-"):
            return "gone", ""
        key, d = next(((k, d) for k, d in self.store.items("vpn:") if (d.get("req") or {}).get("id") == jid), (None, None))
        if not d or d.get("by") != f"page:{who}" or time.time() - d.get("created", 0) > 600 or d.get("revealed"):
            return "gone", ""
        f = self.s.vpn_kits / f"{jid}.reveal.txt"
        try:
            url = f.read_text(encoding="utf-8").strip()
        except OSError:
            res = self.result(jid)
            return ("gone", "") if res is not None and not res.get("ok") else ("wait", "")
        with contextlib.suppress(OSError):
            f.unlink()
        d["revealed"] = True
        self.store.put(key, d)
        return ("ok", url) if re.fullmatch(re.escape(CONF["sub_url"]) + r"[A-Za-z0-9_-]{32}", url) else ("gone", "")

    async def set_servers(self, person: str, where: str, who: str) -> tuple[str | None, str]:
        """Переключатель «Где подключён»: «сервер» / «сервер,другой» (порядок — основной первым) —
        подписка из уже заведённых аккаунтов; «move:<сервер>» — завести там и перенести (как «Перенести»)."""
        p = next((x for x in self.people() if x["person"] == person), None)
        if not p:
            return None, "нет такого человека"
        if where.startswith("move:"):
            return await self.move(person, where[5:], who)
        if not p["sub"]:
            return None, "без подписки можно только перенести на другой сервер"
        order = [x for x in where.split(",") if x]
        by = {sid: {"login": login} for sid, login in (p.get("accounts") or {}).items()}
        by.update({x["server"]: x for x in p["sources"] if x["info"]})
        if not order or len(set(order)) != len(order) or any(sid not in by for sid in order):
            return None, "на этом сервере у человека нет аккаунта — выберите «Перенести на …»"
        if order == [x["server"] for x in p["sources"]]:
            return None, "так уже и есть — ничего не меняю"
        srcs = [{"server": sid, "login": by[sid]["login"], **({"note": by[sid]["note"]} if by[sid].get("note") else {})}
                for sid in order]
        title = " и ".join(SERVERS.get(sid, sid) for sid in order)
        return await self.ask("sub-publish", "all", {"person": person, "sources": srcs}, f"Серверы {p['name']}: {title}", who)

    async def send_link(self, person: str, who: str) -> tuple[str | None, str]:
        """«Ссылку в бот»: без «Подтвердить» — VPN не трогается, ссылка уходит только в чат владельца."""
        busy = sum(1 for _, d in self.store.items("vpn:")
                   if d.get("kind") == "quick" and d.get("state") == "running" and d.get("started", 0) > time.time() - 300)
        if busy >= 3:
            return None, "уже идут три задания — подождите пару минут"
        try:
            req = validate({"id": self._new_id(f"sub-send-{person}"), "server": "all", "action": "sub-send",
                            "args": {"person": person}, "title": f"Ссылка-подписка: {person}", "why": "кнопка «Ссылку в бот»"})
        except Bad as exc:
            return None, str(exc)
        dig = digest(req)
        ok, out = await self._launch(req, dig, f"page:{who}")
        if not ok:
            return None, f"задание не запустилось: {out}"
        self._running(secrets.token_hex(6), req, dig, 0, "", "quick", f"page:{who}")
        return req["id"], ""

    async def remove(self, person: str, server: str, login: str, who: str) -> tuple[str | None, str]:
        """«Отключить насовсем»: убрать логин с сервера; если это последний источник подписки — и подписку."""
        p = next((x for x in self.people() if x["person"] == person), None)
        if not p or not any(x["server"] == server and x["login"] == login for x in p["sources"]):
            return None, "нет такого человека на этом сервере"
        if login in KEEP_PEOPLE or person in KEEP_PEOPLE:
            return None, f"{p['name']} через панель не отключается"
        args = {"login": login}
        if p["sub"] and len(p["sources"]) == 1:
            args["sub"] = person
        return await self.ask("person-remove", server, args, f"Отключить насовсем: {p['name']}", who)

    def updates(self) -> list[dict]:
        """«вышел xray 26.10.21 (стоит 26.3.27)» из сроков снимка → кнопка «Обновить» (карточка `update`)."""
        out = []
        for srv in (self.panel() or {}).get("servers") or []:
            for d in ((srv.get("snapshot") or {}).get("deadlines") or []) if isinstance(srv, dict) else []:
                m = re.match(r"вышел (xray|hysteria) v?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", str((d or {}).get("what", "")))
                if m and srv.get("id") in SERVERS:
                    out.append({"server": srv["id"], "program": m.group(1), "version": m.group(2)})
        return out

    # ------------------------------------------------------------ «подключён, а данные не идут»
    async def watch_stalls(self) -> None:
        """Раз на снимок: у кого VPN подключён, а трафик за час почти не растёт (днём, у того, кто обычно
        пользуется) — сигнал в бот. Так выглядит блокировка оператором.
        Догадка, а не проверка: не чаще раза в 12 часов на человека и сервер."""
        panel = self.panel() or {}
        gen = parse_iso(panel.get("generated_at"))
        if not gen or self.store.get("vpnstall:last") == {"gen": gen}:
            return
        self.store.put("vpnstall:last", {"gen": gen})
        hour = dt.datetime.fromtimestamp(gen, MSK).hour
        await self._watch_people(panel, gen, hour)
        for srv in panel.get("servers") or []:
            if not isinstance(srv, dict):
                continue
            for p in ((srv.get("snapshot") or {}).get("people") or []):
                if not isinstance(p, dict) or p.get("paused") or not LOGIN_RE.match(str(p.get("login"))):
                    continue
                key = f"vpnstall:{srv.get('id')}:{p['login']}"
                d = self.store.get(key) or {"s": [], "alerted": 0}
                t = p.get("traffic") or {}
                d["s"] = (d.get("s") or [])[-12:] + [[gen, int(t.get("24h") or 0), bool(p.get("online"))]]
                self.store.put(key, d)
                win = [x for x in d["s"] if x[0] >= gen - 3600 - 60]
                if (len(win) < 11 or not all(x[2] for x in win) or win[-1][1] < win[0][1]
                        or win[-1][1] - win[0][1] > STALL_BYTES or int(t.get("7d") or 0) / 7 < STALL_DAILY
                        or not 9 <= hour < 23 or time.time() - d.get("alerted", 0) < 12 * 3600):
                    continue
                d["alerted"] = time.time()
                self.store.put(key, d)
                await self._safe(self.bot.send(
                    f"⚠️ <b>VPN: похоже на блокировку</b> · {e(server_title(str(srv.get('id'))))}\n"
                    f"{e(p.get('name') or p['login'])} (<code>{e(p['login'])}</code>) подключён уже час, а данные почти не идут "
                    f"(+{(win[-1][1] - win[0][1]) // 1024} КБ за час, обычно ~{int(t.get('7d') or 0) // 7 // (1 << 20)} МБ в день). "
                    "Так выглядит, когда провайдер режет сервер. Спросите человека; если не работает — «Перенести» на вкладке VPN."))

    async def _watch_people(self, panel: dict, gen: float, hour: int) -> None:
        """Раз на снимок: «давно не подключался» (раз в неделю), «много устройств» (раз в сутки), недельная сводка
        по понедельникам в 10 МСК."""
        rows = []
        for srv in panel.get("servers") or []:
            if not isinstance(srv, dict):
                continue
            for p in ((srv.get("snapshot") or {}).get("people") or []):
                if (not isinstance(p, dict) or not LOGIN_RE.match(str(p.get("login")))
                        or p.get("login") == CONF.get("monitor_account", "monitoring")):
                    continue
                rows.append((str(srv.get("id")), p))
                name, login, sid = e(p.get("name") or p["login"]), e(p["login"]), str(srv.get("id"))
                seen = parse_iso(p.get("last_seen"))
                t30 = int((p.get("traffic") or {}).get("30d") or 0)
                k = f"vpnidle:{sid}:{p['login']}"
                if (not p.get("paused") and seen and gen - seen > IDLE_DAYS * 86400 and t30 > 0 and 9 <= hour < 23
                        and time.time() - (self.store.get(k) or {}).get("at", 0) > 7 * 86400):
                    self.store.put(k, {"at": time.time()})
                    await self._safe(self.bot.send(
                        f"💤 VPN: {name} (<code>{login}</code>, {e(server_title(sid))}) не подключался {int((gen - seen) // 86400)} дн. "
                        "Если перестало работать — «Перенести» или «Ссылку в бот» на вкладке VPN."))
                dev = int((p.get("vless") or {}).get("devices") or 0) if isinstance(p.get("vless"), dict) else 0
                k = f"vpndev:{sid}:{p['login']}"
                if dev >= MANY_DEVICES and time.time() - (self.store.get(k) or {}).get("at", 0) > 86400:
                    self.store.put(k, {"at": time.time()})
                    await self._safe(self.bot.send(
                        f"👥 VPN: у {name} (<code>{login}</code>, {e(server_title(sid))}) сейчас {dev} устройств с разных адресов. "
                        "Если столько у него нет — ссылкой поделились: «Новая ссылка» на вкладке VPN."))
        await self._watch_terms(panel, gen, hour)
        day = dt.datetime.fromtimestamp(gen, MSK)
        week = f"vpnweek:{day.isocalendar()[0]}-{day.isocalendar()[1]}"
        if day.weekday() == 0 and day.hour >= 10 and rows and not self.store.get(week):
            self.store.put(week, {"at": time.time()})
            lines = ["📊 <b>VPN за неделю</b>"]
            for sid, p in sorted(rows, key=lambda r: -int((r[1].get("traffic") or {}).get("7d") or 0)):
                t7 = int((p.get("traffic") or {}).get("7d") or 0)
                lines.append(f"{e(p.get('name') or p['login'])} · {e(server_title(sid))} · {t7 / (1 << 30):.1f} ГБ"
                             + (" · пауза" if p.get("paused") else f" · был {e(ago(parse_iso(p.get('last_seen'))))}"))
            await self._safe(self.bot.send("\n".join(lines)))

    async def _watch_terms(self, panel: dict, gen: float, hour: int) -> None:
        """Срок и лимит подписок: напоминание заранее; когда вышли — карточка «приостановить?» (сама пауза только
        после «Подтвердить»). Не чаще раза в сутки на человека."""
        if not 9 <= hour < 23:
            return
        for p in self.people():
            if not p["sub"]:
                continue
            active = [x for x in p["sources"] if x["info"] and not x["info"].get("paused")]
            name = e(p["name"])
            exp = p.get("expire") or ""
            if exp:
                try:
                    end = dt.datetime.strptime(exp, "%Y-%m-%d").replace(tzinfo=MSK) + dt.timedelta(days=1)
                except ValueError:
                    end = None
                if end:
                    left = (end.timestamp() - gen) / 86400
                    k = f"vpnterm:exp:{p['person']}"
                    if 0 < left <= 3 and not self.store.get(k + ":soon"):
                        self.store.put(k + ":soon", {"at": time.time()})
                        await self._safe(self.bot.send(f"⏳ VPN: у {name} подписка до {e(exp)} "
                                                       f"— осталось {max(1, int(left + .99))} дн. Продлить — «Настройки» на вкладке VPN."))
                    if left <= 0 and active and time.time() - (self.store.get(k) or {}).get("at", 0) > 86400:
                        self.store.put(k, {"at": time.time()})
                        for x in active:
                            await self.ask("person-pause", x["server"], {"login": x["login"]},
                                           f"Срок подписки {p['name']} вышел ({exp}) — приостановить?", "админка",
                                           "Предлагает админка: срок подписки вышел. Не нужно — «Отмена».")
            limit = int(p.get("limit_gb") or 0) << 30
            if limit:
                used = sum(int(((x["info"] or {}).get("traffic") or {}).get("30d") or 0) for x in p["sources"])
                k = f"vpnterm:lim:{p['person']}"
                if limit * 0.8 <= used < limit and time.time() - (self.store.get(k + ":80") or {}).get("at", 0) > 7 * 86400:
                    self.store.put(k + ":80", {"at": time.time()})
                    await self._safe(self.bot.send(f"📶 VPN: {name} израсходовал {used / (1 << 30):.1f} из {limit >> 30} ГБ "
                                                   "за 30 дней (80%+)."))
                if used >= limit and active and time.time() - (self.store.get(k) or {}).get("at", 0) > 86400:
                    self.store.put(k, {"at": time.time()})
                    for x in active:
                        await self.ask("person-pause", x["server"], {"login": x["login"]},
                                       f"{p['name']}: лимит {limit >> 30} ГБ за 30 дней исчерпан — приостановить?", "админка",
                                       "Предлагает админка: лимит трафика исчерпан. Не нужно — «Отмена».")

    def cleanup_reveals(self) -> None:
        """Невостребованные адреса для страницы — не дольше 10 минут."""
        with contextlib.suppress(OSError):
            for f in self.s.vpn_kits.glob("*.reveal.txt"):
                if time.time() - f.stat().st_mtime > 600:
                    f.unlink()

    # ------------------------------------------------------------ кнопки в боте
    async def decide(self, num: str, go: bool, by: int, message_id: int = 0) -> str:
        key = f"vpn:{num}"
        d = self.store.get(key)
        if not d or d.get("kind") != "offer" or d.get("state") != "offered":
            return "Эта кнопка уже нажата или устарела."
        mid = message_id or d["message_id"]
        secret = self._relay_pw.pop(num, "")
        if not go:
            d["state"] = "cancelled"
            self.store.put(key, d)
            await self.bot.edit(mid, d["text"] + "\n\n✖️ Отменено.")
            return "Отменено."
        if time.time() - d["created"] > OFFER_TTL:
            d["state"] = "stale"
            self.store.put(key, d)
            await self.bot.edit(mid, d["text"] + "\n\n⌛ Устарело — попросите предложить заново.")
            return "Устарело."
        try:                                    # ещё раз: в kv могло оказаться что угодно
            req = validate(d["req"])
        except Bad:
            req = None
        if req is None or digest(req) != d.get("digest"):
            d["state"] = "failed"
            self.store.put(key, d)
            return "Запрос испорчен — не исполняю."
        ok, out = await self._launch(req, d["digest"], str(by), secret)
        if not ok:
            d["state"] = "failed"
            self.store.put(key, d)
            await self.bot.edit(mid, d["text"] + f"\n\n❌ Не запустилось: <code>{e(out)}</code>")
            return "Не запустилось."
        d.update(state="running", started=time.time(), message_id=mid, by=str(by))
        self.store.put(key, d)
        await self.bot.edit(mid, d["text"] + "\n\n⏳ Исполняю, итог пришлю сюда.")
        return "Исполняю."

    async def answer_pending(self, num: str, keep: bool, by: int, message_id: int = 0) -> str:
        """«✅ Работает» / «↩️ Откатить»: само нажатие — согласие, второго «Подтвердить» нет."""
        key = f"vpn:{num}"
        d = self.store.get(key)
        if not d or d.get("kind") != "pending" or d.get("state") != "waiting":
            return "Эта кнопка уже нажата или устарела."
        mid = message_id or d["message_id"]
        if time.time() > d["revert_at"]:
            d["state"] = "expired"
            self.store.put(key, d)
            await self.bot.edit(mid, d["text"] + "\n\n⌛ Время вышло — сервер откатывает правку сам.")
            return "Время вышло."
        action = "confirm" if keep else "revert"
        req = validate({"id": self._new_id(f"{action}-{d['ref']}"), "server": d["server"], "action": action,
                        "args": {"ref": d["ref"]}, "title": f"{ACTIONS[action][0]} {d['ref']}",
                        "why": "кнопка «✅ Работает»" if keep else "кнопка «↩️ Откатить»"})
        dig = digest(req)
        ok, out = await self._launch(req, dig, str(by))
        if not ok:
            await self.bot.edit(mid, d["text"] + f"\n\n❌ Не запустилось: <code>{e(out)}</code>",
                                pending_buttons(num))
            return "Не запустилось — можно нажать ещё раз."
        d["state"] = "answered"
        self.store.put(key, d)
        text = d["text"] + ("\n\n⏳ Оставляю правку…" if keep else "\n\n⏳ Откатываю…")
        self._running(secrets.token_hex(6), req, dig, mid, d["text"], "job", str(by))
        await self.bot.edit(mid, text)
        return "Оставляю." if keep else "Откатываю."

    # ------------------------------------------------------------ итоги
    async def poll(self) -> None:
        await self.take_proposals()
        self.cleanup_reveals()
        try:
            await self.watch_stalls()
        except Exception as exc:  # noqa: BLE001 — сигнал — подсказка, не должен мешать заданиям
            log.warning("проверка «данные не идут»: %s", type(exc).__name__)
        now = time.time()
        for key, d in self.store.items("vpn:"):
            if d.get("state") != "running":
                if d.get("state") != "offered" and now - d.get("created", now) > KEEP:
                    self.store.x("DELETE FROM kv WHERE k=?", key)
                continue
            req = d["req"]
            res = self.result(req["id"])
            if res is None:
                if now - d.get("started", now) <= RESULT_WAIT:
                    continue
                d.update(state="lost", summary="итога нет за 15 минут")
                if d.get("message_id"):
                    await self._safe(self.bot.edit(d["message_id"], d["text"] + "\n\n❓ Итога нет за 15 минут — "
                                                   f"journalctl -u {UNIT.format(req['id'])}"))
                self.store.put(key, d)
                continue
            d.update(state="done" if res.get("ok") else "failed", summary=str(res.get("output") or "")[-300:])
            self.store.put(key, d)
            with contextlib.suppress(OSError):
                (self.s.vpn_outbox / f"{req['id']}.json").unlink()
            if d.get("message_id"):
                await self._safe(self.bot.edit(d["message_id"], d["text"] + "\n\n" + result_block(res)))
            elif req.get("action") == "relay-check":       # кнопка в боте: итог — новым сообщением
                await self._safe(self.bot.send("🇷🇺 Проверка посредника\n" + result_block(res)))
            pend = res.get("pending")
            if res.get("ok") and isinstance(pend, dict):
                if pend.get("kit"):              # person-add и kit-send; у kit-send нет правки и «Работает?»
                    await self._send_kit(req, str(pend["kit"]))
                if pend.get("sub"):              # ссылка-подписка: QR и текст для пересылки
                    await self._send_sub(req, str(pend["sub"]))
                if ID_RE.match(str(pend.get("ref", ""))):
                    await self._ask_works(req, pend)

    async def _send_kit(self, req: dict, name: str) -> None:
        """Комплект нового человека — файлом только в чат владельца (s.chat_id), затем удалить с диска."""
        if name != f"{req['id']}.kit.zip":
            log.warning("комплект %r не от задания %s — не отправляю", name, req["id"])
            return
        path = self.s.vpn_kits / name
        try:
            data = path.read_bytes()
        except OSError as exc:
            log.warning("комплект %s не прочитан: %s", name, type(exc).__name__)
            await self._safe(self.bot.send(f"🛡 Комплект «{e(req['id'])}» не найден в {e(str(self.s.vpn_kits))} — "
                                           "он есть в папке человека у чата vpn."))
            return
        args = req.get("args") or {}
        who = args.get("name") or args.get("login") or args.get("person", "")
        if await self._safe(self.bot.send_document(
                f"{args.get('login') or args.get('person') or 'kit'}.zip", data,
                f"🛡 Комплект VPN: {e(who)} · {e(server_title(req['server']))}. Не пересылайте в общие чаты.")):
            with contextlib.suppress(OSError):
                path.unlink()

    async def _send_sub(self, req: dict, name: str) -> None:
        """Ссылка-подписка — фото QR с готовым текстом, только в чат владельца, затем файлы стираются."""
        if name != req["id"]:
            log.warning("ссылка %r не от задания %s — не отправляю", name, req["id"])
            return
        png, txt = self.s.vpn_kits / f"{name}.sub.png", self.s.vpn_kits / f"{name}.sub.txt"
        try:
            data, caption = png.read_bytes(), txt.read_text(encoding="utf-8")
        except OSError as exc:
            log.warning("ссылка %s не прочитана: %s", name, type(exc).__name__)
            await self._safe(self.bot.send(f"🛡 Ссылка-подписка задания «{e(req['id'])}» не найдена — "
                                           "попросите прислать её ещё раз («Ссылку в бот» на вкладке VPN)."))
            return
        if await self._safe(self.bot.send_photo(f"{name}.png", data, caption)):
            for f in (png, txt):
                with contextlib.suppress(OSError):
                    f.unlink()

    async def _ask_works(self, req: dict, pend: dict) -> None:
        revert_at = parse_iso(pend.get("revert_at")) or time.time() + 300
        left = max(0, round((revert_at - time.time()) / 60))
        text = (f"🛡 <b>VPN: {e(req.get('title') or ACTIONS[req['action']][0])}</b> · {e(server_title(req['server']))}\n"
                f"Правка применена, самопроверка прошла. Работает?\n"
                f"Без ответа сервер откатит её сам в {msk(revert_at)} (≈ через {left} мин).")
        num = secrets.token_hex(6)
        try:
            mid = await self.bot.send(text, pending_buttons(num))
        except Exception as exc:  # noqa: BLE001 — сервер всё равно откатит сам
            log.warning("«Работает?» не отправлено: %s", type(exc).__name__)
            return
        self.store.put(f"vpn:{num}", {"kind": "pending", "state": "waiting", "ref": pend["ref"],
                                      "server": req["server"], "revert_at": revert_at, "created": time.time(),
                                      "message_id": mid, "text": text})

    async def _safe(self, coro) -> bool:
        try:
            await coro
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("бот: %s", type(exc).__name__)
            return False

    # ------------------------------------------------------------ /vpn
    async def relay_set(self, ip: str, who: str, password: str = "") -> tuple[str | None, str]:
        """/relay <IP> [пароль root] в боте: карточка «Подтвердить» на замену посредника в РФ. Пароль (из письма
        хостера) живёт только в памяти до «Подтвердить»: тогда он уходит в задание, vpnjob кладёт им ключ и
        выключает на посреднике вход по паролю."""
        if not public_ipv4(ip) or ip in OUR_IPS:
            return None, "нужен публичный IPv4 нового сервера в РФ, например /relay 203.0.113.20 ПАРОЛЬ"
        if password and not RELAY_PW_RE.match(password):
            return None, "пароль странный (пробелы или длиннее 128 знаков) — пришлите /relay IP ПАРОЛЬ ещё раз"
        num, why = await self.ask("relay-set", RELAY_SERVER, {"ip": ip}, f"Новый посредник в РФ: {ip}", who,
                                  source=f"Запрошено в боте ({who})."
                                  + (" Пароль root получен (сообщение удалено) — ключ положу сам." if password else ""))
        if num and password:
            self._relay_pw[num] = password
        return num, why

    def relay_help(self) -> str:
        """Кнопка «Посредник отлетел»: что делать с телефона, по шагам."""
        return RELAY_HELP

    def relay_text(self) -> str:
        """/relay без адреса: посредник, операторы за 15 минут, как заменить."""
        panel = self.panel() or {}
        r = panel.get("relay")
        how = ("\n\nС телефона: страница подписки (в Happ — значок страницы у подписки) → «Проверить связь с телефона»; "
               "итог придёт сюда."
               "\n\nОтлетел — кнопка «🆘 Посредник отлетел» ниже: что сделать с телефона по шагам.")
        if not r:
            return "🇷🇺 <b>Посредник в РФ</b>\nЕщё не настроен." + how
        lines = [f"🇷🇺 <b>Посредник в РФ</b> · {e(r.get('ip', ''))} · с {e(ago(parse_iso(r.get('since'))))}",
                 ("🔴 " + e(r["alert"])) if r.get("alert") else ("🟢 отвечает" if r.get("reach") else "🔴 не отвечает")]
        ops = r.get("ops") or {}
        if ops:
            lines.append("За 15 минут: " + ", ".join(
                f"{e(v.get('name', o))} {int(v.get('conn', 0))}" + (" ⚠️" if v.get("stalled") else "") for o, v in ops.items()))
        return "\n".join(lines) + how

    def summary_text(self) -> str:
        panel = self.panel()
        if panel is None:
            return "🛡 <b>VPN</b>\nПанель VPN ещё не установлена: снимка нет."
        if panel.get("withheld"):
            return "🛡 <b>VPN</b>\nСнимок похож на секрет — не показываю. Посмотрите на сервере."
        lines = [f"🛡 <b>VPN</b> · снимок {e(ago(parse_iso(panel.get('generated_at'))))}"]
        for srv in panel["servers"]:
            lines.append(server_line(srv))
        lines.append(f"\nПодробно — {e(self.s.public_url)}/vpn")
        return "\n".join(lines)


def pending_buttons(num: str) -> list[list[tuple[str, str]]]:
    return [[("✅ Работает", f"vpn:keep:{num}"), ("↩️ Откатить", f"vpn:back:{num}")]]


def server_tone(srv: dict) -> str:
    """off — нет связи, bad — канал не работает, warn — есть проблемы, ok."""
    if not srv.get("reach"):
        return "off"
    snap = srv.get("snapshot") if isinstance(srv.get("snapshot"), dict) else {}
    channels = [c for c in snap.get("channels") or [] if isinstance(c, dict)]
    if any(not c.get("ok") for c in channels):
        return "bad"
    health = snap.get("health") or {}
    russia = snap.get("russia")
    if health.get("state") not in (None, "OK") or (isinstance(russia, dict) and not russia.get("ok")):
        return "warn"
    return "ok"


def server_line(srv: dict) -> str:
    """Строка сервера для /vpn (экранированная)."""
    title = e(str(srv.get("title") or server_title(str(srv.get("id", "")))))
    snap = srv.get("snapshot") if isinstance(srv.get("snapshot"), dict) else {}
    tone = server_tone(srv)
    mark = {"off": "⚪", "bad": "🔴", "warn": "🟡", "ok": "🟢"}[tone]
    if tone == "off":
        head = (f"{mark} <b>{title}</b>: нет связи ({e(str(srv.get('error') or '—')[:120])}), "
                f"последний снимок {e(ago(parse_iso(srv.get('fresh_at'))))}")
        if not snap:
            return head
    else:
        head = f"{mark} <b>{title}</b>"
    channels = [c for c in snap.get("channels") or [] if isinstance(c, dict)]
    people = [p for p in snap.get("people") or [] if isinstance(p, dict)
              and p.get("login") != CONF.get("monitor_account", "monitoring")]
    parts = [f"каналы {sum(1 for c in channels if c.get('ok'))} из {len(channels)}"]
    st = snap.get("selftest") or {}
    if st:
        parts.append(f"самопроверка {'ОК' if st.get('ok') else 'НЕ ПРОШЛА'} {e(ago(parse_iso(st.get('at'))))}")
    if people:
        parts.append(f"в сети {sum(1 for p in people if p.get('online'))} из {len(people)}")
    host = snap.get("host") or {}
    if host:
        parts.append(f"диск {e(str(host.get('disk_pct', '—')))} %, свободно памяти {e(str(host.get('mem_available_mb', '—')))} МБ")
    out = [f"{head}: " + ", ".join(parts) if tone != "off" else head + "\n   " + ", ".join(parts)]
    problems = (snap.get("health") or {}).get("problems") or []
    for p in problems[:3]:
        out.append(f"   ⚠️ {e(str(p)[:120])}")
    for p in snap.get("pending") or []:
        if isinstance(p, dict):
            at = parse_iso(p.get("revert_at"))
            out.append(f"   ⏳ ждёт «Работает»: {e(str(p.get('id', ''))[:40])}" + (f", откат сам в {msk(at)}" if at else ""))
    return "\n".join(out)
