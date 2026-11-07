"""Рабочий стол VPN: подписки, инфраструктура и журнал из существующих снимков.

Формы и обработчики сохраняют прежние действия и подтверждения в Telegram.
Страница использует серверный HTML; без JavaScript все разделы остаются доступны.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import html
import re
from pathlib import Path

from aiohttp import web

from admin import vpn as vpnmod
from admin.config import CONF
from admin.vpn import ACTIONS, SERVERS, UNITS, ago, msk, parse_iso, server_tone

NAV = ("/vpn", "VPN")
ICON = "shield"
e = html.escape
def _asset_head() -> str:
    digest = hashlib.sha256()
    for name in ("vpn.css", "vpn.js"):
        try:
            digest.update((Path(__file__).resolve().parents[1] / "static" / name).read_bytes())
        except OSError:
            pass
    version = digest.hexdigest()[:10]
    return (f'<link rel="stylesheet" href="/static/vpn.css?v={version}">'
            f'<script src="/static/vpn.js?v={version}" defer></script>')


HEAD = _asset_head()
TONE = {"ok": ("ok", "в порядке"), "warn": ("warn", "внимание"), "bad": ("bad", "сбой"), "off": ("", "нет связи")}
STATE_WORD = {"offered": "ждёт «Подтвердить» в боте", "running": "исполняется", "done": "готово",
              "failed": "не получилось", "cancelled": "отменено", "stale": "не подтверждено вовремя",
              "lost": "итога нет"}


def s(value) -> str:
    return e(str(value if value is not None else "—"))


def size(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit, k in (("ГБ", 1 << 30), ("МБ", 1 << 20), ("КБ", 1 << 10)):
        if n >= k:
            return f"{n / k:.1f} {unit}"
    return f"{n:.0f} Б"


def yes(v, word_yes: str = "да", word_no: str = "нет", unknown: str = "—") -> str:
    return word_yes if v is True else (word_no if v is False else unknown)


def _form(action: str, label: str, server: str, unit: str = "", cls: str = "small") -> str:
    extra = f'<input type="hidden" name="unit" value="{e(unit)}">' if unit else ""
    return (f'<form method="post" action="/vpn/act" class="inline"><input type="hidden" name="action" value="{e(action)}">'
            f'<input type="hidden" name="server" value="{e(server)}">{extra}'
            f'<button type="submit" class="{cls}">{e(label)}</button></form>')


def _pform(fields: dict, label: str, cls: str = "small", action: str = "/vpn/act") -> str:
    hidden = "".join(f'<input type="hidden" name="{e(k)}" value="{e(v)}">' for k, v in fields.items())
    return (f'<form method="post" action="{e(action)}" class="inline">{hidden}'
            f'<button type="submit" class="{cls}">{e(label)}</button></form>')


SHORT = {CONF["server_id"]: CONF["label"]}
# плашка серверов у человека: страна крупно; порядок — как в SERVERS
PLACE = {CONF["server_id"]: (CONF["label"], "")}


def chart(daily: list[int]) -> str:
    """30 столбиков — трафик по дням (московские сутки), сегодня справа. Подсказка у столбика — дата и объём."""
    if not daily or not any(daily):
        return '<p class="muted small">За 30 дней трафика нет.</p>'
    top = max(daily) or 1
    today = dt.datetime.now(vpnmod.MSK).date()
    bars = []
    for i, v in enumerate(daily):
        h = max(1, round(46 * v / top)) if v else 0
        day = today - dt.timedelta(days=len(daily) - 1 - i)
        bars.append(f'<rect class="track" x="{i * 8}" y="46" width="6" height="2"/>'
                    f'<rect x="{i * 8}" y="{48 - h}" width="6" height="{h}" rx="1"><title>{day:%d.%m}: {size(v)}</title></rect>')
    return (f'<svg class="vpn-chart" viewBox="0 0 {len(daily) * 8} 48" preserveAspectRatio="none" role="img" '
            f'aria-label="Трафик по дням за 30 дней, максимум {size(top)} в день">{"".join(bars)}</svg>'
            f'<p class="muted small">30 дней · максимум {size(top)} в день · сегодня {size(daily[-1])}</p>')


CH_ORDER = ("Основной/Запасной", "Звонки", "Telegram")


def channels_now(i: dict) -> list[str]:
    out = []
    if isinstance(i.get("vless"), dict) and int(i["vless"].get("devices") or 0):
        out.append("Основной/Запасной")
    if isinstance(i.get("calls"), dict) and int(i["calls"].get("online") or 0):
        out.append("Звонки")
    if isinstance(i.get("telegram"), dict) and int(i["telegram"].get("online") or 0):
        out.append("Telegram")
    return out


def cap(text: str) -> str:
    return text[:1].upper() + text[1:]


def _state(i: dict, note: str) -> tuple[str, str]:
    if not i:
        return "bad", "нет на сервере"
    if i.get("paused"):
        return "warn", "на паузе"
    if note:
        return "warn", note
    return ("ok", "в сети") if i.get("online") else ("", "не в сети")


def server_choices(p: dict) -> list[tuple[str, str]]:
    """Варианты переключателя «Где подключён»: значение формы → подпись. Первый сервер — основной в Happ."""
    have = [x["server"] for x in p["sources"] if x["info"]]
    out = [(sid, f"Только {SHORT.get(sid, sid)}") for sid in have]
    if len(have) == 2:
        a, b = have
        out += [(f"{a},{b}", f"Оба: сначала {SHORT.get(a, a)}"), (f"{b},{a}", f"Оба: сначала {SHORT.get(b, b)}")]
    tail = " (заведу аккаунт там)" if p["sub"] else " (заведу аккаунт и подписку — ссылка придёт в бот)"
    out += [(f"move:{sid}", f"Перенести на {SHORT.get(sid, sid)}{tail}") for sid in SERVERS if sid not in have]
    return out


def plaque(p: dict, reach: dict[str, bool]) -> str:
    """Все серверы рядом, всегда на виду: горит тот, через который сейчас подписка человека (первый — основной),
    тусклые — нажать, и человек переедет туда (карточка «Подтвердить» в боте; аккаунта там нет — заведу).
    Всё — из снимка серверов и сводки подписок: изменения через CLI видны здесь после очередного снимка."""
    live = {x["server"]: x for x in p["sources"] if x["info"]}
    order = [x["server"] for x in p["sources"]]
    going = p.get("moving")
    cells = []
    for sid in SERVERS:
        city, whose = PLACE.get(sid, (SHORT.get(sid, sid), ""))
        x = next((y for y in p["sources"] if y["server"] == sid), None)
        i = (x or {}).get("info") or {}
        if sid in order:
            n = order.index(sid)
            cls = "on" if n == 0 else "on second"
            word = "основной" if n == 0 and len(order) > 1 else ("запасной" if n else "")
            st = _state(i, (x or {}).get("note") or "")[1]
            note = " · ".join(w for w in (word, st) if w)
            cells.append(f'<div class="vpn-plq-cell {cls}" aria-current="true"><span class="vpn-plq-led" aria-hidden="true">'
                         f'</span><b>{e(city)}</b><small>{e(whose)}</small><small class="vpn-plq-st">{e(note)}</small></div>')
            continue
        if going and going[0] == sid:
            cells.append(f'<div class="vpn-plq-cell going"><span class="vpn-plq-led" aria-hidden="true"></span><b>{e(city)}</b>'
                         f'<small>{e(whose)}</small><small class="vpn-plq-st">{e(going[1])}</small></div>')
            continue
        acc = (p.get("accounts") or {}).get(sid)
        where = sid if p["sub"] and ((sid in live and not live[sid]["info"].get("paused")) or acc) else f"move:{sid}"
        down = reach.get(sid) is False
        hint = ("нет связи с сервером" if down else "есть аккаунт — переключить" if where == sid or acc
                else "перенести сюда" if p["sub"] else "перенести сюда, с подпиской")
        cells.append('<form method="post" action="/vpn/act" class="vpn-plq-cell off">'
                     f'<input type="hidden" name="action" value="servers"><input type="hidden" name="person" value="{e(p["person"])}">'
                     f'<input type="hidden" name="where" value="{e(where)}">'
                     f'<button type="submit"{" disabled" if down or going else ""} title="{e(hint)}">'
                     f'<span class="vpn-plq-led" aria-hidden="true"></span><b>{e(city)}</b><small>{e(whose)}</small>'
                     f'<small class="vpn-plq-st">{e(hint)}</small></button></form>')
    return f'<div class="vpn-plq" role="group" aria-label="Сервер: {e(p["name"])}">{"".join(cells)}</div>'


def _person_facts(p: dict) -> dict:
    """Aggregate existing source data, retaining unknown and partial accounting."""
    infos = [x.get("info") or {} for x in p.get("sources") or []]
    paused = bool(infos) and all(i.get("paused") for i in infos)
    online = any(i.get("online") for i in infos)
    known = any(i for i in infos)
    tone, word = (("warn", "на паузе") if paused else ("ok", "в сети") if online else ("", "не в сети") if known else ("", "нет данных"))
    def total(field, key):
        values = []
        for info in infos:
            value = (info.get(field) or {}).get(key)
            try:
                values.append(max(0, int(value)) if value is not None and not isinstance(value, bool) else None)
            except (ValueError, TypeError, OverflowError):
                values.append(None)
        return (sum(v for v in values if v is not None), any(v is None for v in values)) if any(v is not None for v in values) else (None, False)
    t24, part24 = total("traffic", "24h"); t30, part30 = total("traffic", "30d"); devices, partdev = total("vless", "devices")
    daily, have_daily = [0] * 30, False
    for info in infos:
        if not isinstance(info.get("daily"), list):
            continue
        have_daily = True
        values = info["daily"][-30:]
        for n, value in enumerate(values):
            try:
                daily[30 - len(values) + n] += max(0, int(value or 0))
            except (ValueError, TypeError, OverflowError):
                pass
    return {"tone": tone, "word": word, "online": online, "t24": t24, "t30": t30, "part24": part24, "part30": part30,
            "devices": devices, "partdev": partdev, "seen": max((i.get("last_seen") or "" for i in infos), default=""),
            "channels": [c for c in CH_ORDER if any(c in channels_now(i) for i in infos)], "daily": daily if have_daily else None}


def _traffic_label(value: int | None, partial: bool = False) -> str:
    return ("≥ " if partial and value is not None else "") + size(value)


def _detail_panel(person: str, key: str, body: str) -> str:
    return (f'<section id="vpn-person-{e(person)}-{key}" class="vpn-detail-panel" data-vpn-detail-panel="{key}" '
            f'role="tabpanel" aria-labelledby="vpn-person-{e(person)}-tab-{key}">{body}</section>')


def person_row(p: dict, reach: dict[str, bool] | None = None) -> str:
    """User detail with unchanged actions and one complete subscription settings form."""
    person = p["person"]; facts = _person_facts(p); sources = p.get("sources") or []
    x = sources[0] if sources else None; i = (x or {}).get("info") or {}
    if p["sub"]:
        main = (_pform({"action": "sub-send", "person": person}, "Ссылку в бот", "small primary")
                + _pform({"action": "reveal", "person": person}, "Показать ссылку"))
    elif x:
        main = _pform({"action": "sub-create", "person": person, "server": x["server"], "login": x["login"]}, "Создать подписку", "small primary")
    else:
        main = '<p class="muted small">Нет источника для создания подписки.</p>'
    servers = plaque(p, reach or {})
    both = [(v, t) for v, t in server_choices(p) if "," in v]
    if p["sub"] and both:
        cur = ",".join(source["server"] for source in sources)
        opts = "".join(f'<option value="{e(v)}"{" selected" if v == cur else ""}>{e(t)}</option>' for v, t in both)
        servers += ('<details class="vpn-more"><summary>Два сервера сразу</summary><form method="post" action="/vpn/act" class="vpn-where">'
                    f'<input type="hidden" name="action" value="servers"><input type="hidden" name="person" value="{e(person)}">'
                    f'<label>В Happ оба <select name="where">{opts}</select></label><button type="submit" class="small">Применить</button></form></details>')
    ctl = []
    if x and i.get("paused"):
        ctl.append(_pform({"action": "person-resume", "server": x["server"], "login": x["login"]}, "Возобновить"))
    else:
        why = "" if x and i and x["login"] not in vpnmod.KEEP_PEOPLE else ("образец для новых людей" if x and i else "нет на сервере")
        ctl.append(_pform({"action": "person-pause", "server": x["server"], "login": x["login"]}, "Пауза") if not why else f'<button type="button" class="small" disabled title="{e(why)}">Пауза</button>')
    keep = not x or not i or x["login"] in vpnmod.KEEP_PEOPLE or person in vpnmod.KEEP_PEOPLE
    ctl.append('<button type="button" class="small danger" disabled title="через панель не отключается">Отключить</button>' if keep else _pform({"action": "remove", "person": person, "server": x["server"], "login": x["login"]}, "Отключить", "small danger"))
    access = ('<div class="vpn-detail-block"><h3>Ссылка-подписка</h3><p class="muted small">QR и готовый текст для пересылки — в вашем личном чате с ботом. Показ ссылки здесь — одноразовый.</p>'
              f'<div class="vpn-actions vpn-main">{main}</div></div><div class="vpn-detail-block"><h3>Подключение</h3>{servers}'
              f'<p class="muted small">Активные каналы: {s(", ".join(facts["channels"]) or "—")} · последний визит: {e(ago(parse_iso(facts["seen"])))}</p>'
              '<p class="muted small">Счётчик устройств — только VLESS. Hysteria2 и Telegram показаны в активных каналах.</p></div>')
    if p["sub"]:
        fields = "".join(f'<label>{s(SHORT.get(source["server"], source["server"]))} <small class="muted">{s(source["login"])}</small><input name="note_{n}" maxlength="40" value="{e(source.get("note") or "")}" placeholder="например: пока не работает"></label>' for n, source in enumerate(sources))
        access += ('<details class="vpn-more"><summary>Пометки серверов</summary><form method="post" action="/vpn/act" class="vpn-add-form">'
                   f'<input type="hidden" name="action" value="sub-notes"><input type="hidden" name="person" value="{e(person)}">{fields}'
                   '<button type="submit" class="small">Сохранить (карточка в бот)</button><p class="muted small">Пометка появится в названии сервера в Happ у человека и на его странице.</p></form></details>')
    access += ('<details class="vpn-more"><summary>Пауза или отключение</summary>' + f'<div class="vpn-actions">{"".join(ctl)}</div>'
               '<p class="muted small">Пауза сохраняет ссылки: «Возобновить» вернёт всё как было. «Отключить» — насовсем.</p></details>')
    if p["sub"]:
        access += ('<details class="vpn-more"><summary>Если ссылка утекла</summary><p class="muted small">Новая ссылка заменит старую: старая сразу перестанёт работать, человеку нужно будет добавить новую в Happ.</p>'
                   + _pform({"action": "sub-rotate", "person": person}, "Выдать новую ссылку", "small danger") + '</details>')
        prof = "".join(f'<option value="{key}"{" selected" if p.get("routing_profile", "ai-social") == key else ""}>{e(label)}</option>' for key, label in vpnmod.ROUTING_PROFILES.items())
        routing = ('<h3>Маршрутизация</h3><div class="vpn-settings-fields">'
                   f'<label class="vpn-field-wide">Режим<select name="routing">{prof}</select></label>'
                   '<label class="vpn-field-wide">Ещё через VPN <small class="muted">домены, по одному в строке</small>'
                   f'<textarea name="proxy_add" rows="3" placeholder="discord.com">{e(chr(10).join(p.get("proxy_add") or []))}</textarea></label>'
                   '<label class="vpn-field-wide">Ещё напрямую <small class="muted">домены, по одному в строке</small>'
                   f'<textarea name="direct_add" rows="3" placeholder="gosuslugi.ru">{e(chr(10).join(p.get("direct_add") or []))}</textarea></label></div>'
                   '<div class="vpn-actions"><button type="submit" class="small primary">Сохранить (карточка в бот)</button></div>'
                   '<p class="muted small">Маршрут и условия сохраняются одной карточкой, включая изменения в другой вкладке формы.</p>')
        terms = ('<h3>Условия подписки</h3><div class="vpn-settings-fields">'
                 f'<label>Группа<input name="group" maxlength="24" value="{e(p.get("group") or "")}" placeholder="Семья, Работа…"></label>'
                 f'<label>Действует до <small class="muted">пусто — бессрочно</small><input type="date" name="expire" value="{e(p.get("expire") or "")}"></label>'
                 f'<label>Лимит в месяц, ГБ <small class="muted">0 — без лимита</small><input type="number" name="limit_gb" min="0" max="10000" value="{int(p.get("limit_gb") or 0)}"></label></div>'
                 '<div class="vpn-actions"><button type="submit" class="small primary">Сохранить (карточка в бот)</button></div>'
                 '<p class="muted small">За 3 дня до конца срока и при 80% лимита бот напомнит; когда выйдут — пришлёт карточку «приостановить?».</p>'
                 '<p class="muted small">Маршрут и условия сохраняются одной карточкой.</p>')
        # One form spans both tabs: fields in hidden panels are still submitted.
        settings = ('<form method="post" action="/vpn/act" class="vpn-sub-settings">'
                    f'<input type="hidden" name="action" value="sub-settings"><input type="hidden" name="person" value="{e(person)}">'
                    + _detail_panel(person, "routing", routing) + _detail_panel(person, "terms", terms) + '</form>')
    else:
        hint = '<p class="muted">Эти настройки доступны после создания подписки во вкладке «Доступ».</p>'
        settings = _detail_panel(person, "routing", hint) + _detail_panel(person, "terms", hint)
    traffic = ('<h3>Трафик по дням</h3><p class="muted small">Приём + передача · последние 30 дней</p>'
               + (chart(facts["daily"]) if facts["daily"] is not None else '<p class="muted">График недоступен: нет данных учёта.</p>')
               + '<p class="muted small">Один профиль на нескольких устройствах учитывается вместе.</p>')
    tabs = "".join(f'<a href="#vpn-person-{e(person)}-{key}" id="vpn-person-{e(person)}-tab-{key}" data-vpn-detail-tab="{key}" aria-controls="vpn-person-{e(person)}-{key}">{label}</a>' for key, label in (("access", "Доступ"), ("routing", "Маршрут"), ("terms", "Условия"), ("traffic", "Трафик")))
    devices = ("≥ " if facts["partdev"] and facts["devices"] is not None else "") + (str(facts["devices"]) if facts["devices"] is not None else "—")
    meta = " · ".join(str(v) for v in (p.get("group"), f'до {p["expire"]}' if p.get("expire") else "", f'лимит {p["limit_gb"]} ГБ/мес' if p.get("limit_gb") else "", "без подписки" if not p["sub"] else "") if v)
    return (f'<article class="card vpn-person-detail {facts["tone"]}" id="vpn-person-{e(person)}" data-vpn-person-panel="{e(person)}">'
            '<div class="vpn-detail-header"><div class="vpn-detail-identity">' + f'<span class="vpn-avatar" aria-hidden="true">{s((p["name"] or person)[:1].upper())}</span><div><h2>{s(p["name"])}</h2>'
            + f'<p class="muted small">{s(person)}' + (f' · {s(meta)}' if meta else "") + '</p></div></div>'
            + f'<span class="vpn-pill {facts["tone"]}">{facts["word"]}</span></div><div class="vpn-person-facts">'
            + f'<div class="vpn-fact"><span class="vpn-fact-label">За 24 часа</span><strong class="vpn-fact-value">{_traffic_label(facts["t24"], facts["part24"])}</strong></div>'
            + f'<div class="vpn-fact"><span class="vpn-fact-label">За 30 дней</span><strong class="vpn-fact-value">{_traffic_label(facts["t30"], facts["part30"])}</strong></div>'
            + f'<div class="vpn-fact"><span class="vpn-fact-label">Устройств VLESS</span><strong class="vpn-fact-value">{e(devices)}</strong></div></div>'
            + f'<nav class="vpn-detail-tabs" aria-label="Карточка {s(p["name"])}">{tabs}</nav>'
            + _detail_panel(person, "access", access) + settings + _detail_panel(person, "traffic", traffic) + '</article>')


def _roster_row(p: dict) -> str:
    facts = _person_facts(p); person = p["person"]
    search = f'{p["name"]} {person} {p.get("group") or ""} ' + " ".join(f'{x["login"]} {SHORT.get(x["server"], "")}' for x in p.get("sources") or [])
    return (f'<li class="vpn-roster-entry" data-search="{e(search.lower())}"><a class="vpn-roster-person" href="#vpn-person-{e(person)}" data-vpn-person="{e(person)}" aria-controls="vpn-person-{e(person)}">'
            + f'<span class="vpn-avatar" aria-hidden="true">{s((p["name"] or person)[:1].upper())}</span>'
            + f'<span class="vpn-roster-identity"><strong class="vpn-roster-name">{s(p["name"])}</strong><span class="vpn-roster-meta"><span class="dot {facts["tone"]}" aria-hidden="true"></span>{facts["word"]} · {s(person)}</span></span>'
            + f'<span class="vpn-roster-traffic">{_traffic_label(facts["t30"], facts["part30"])}</span></a></li>')


def people_section(people: list[dict], reach: dict[str, bool] | None = None) -> str:
    opts = "".join(f'<option value="{e(key)}">{e(SHORT.get(key, value))}</option>' for key, value in SERVERS.items())
    add = ('<details id="vpn-add-person" class="vpn-add card"><summary>Добавить человека</summary><form method="post" action="/vpn/person" class="vpn-add-form">'
           '<label>Имя<input name="name" required maxlength="40" placeholder="Ольга"></label><label>Логин <small class="muted">необязательно, латиницей</small>'
           '<input name="login" maxlength="16" pattern="[a-z][a-z0-9]{1,15}" placeholder="olga"></label>'
           + f'<label>Сервер<select name="server">{opts}</select></label><button type="submit" class="primary">Подключить</button>'
           + '<p class="muted small">В бот придёт карточка «Подтвердить». После самопроверки — «✅ Работает», QR и готовый текст со ссылкой.</p></form></details>')
    groups = {}
    for p in people:
        groups.setdefault(p.get("group") or "", []).append(p)
    rows, ordered = [], []
    for group, persons in sorted(groups.items(), key=lambda item: (item[0] == "", item[0])):
        if len(groups) > 1:
            rows.append(f'<li class="vpn-roster-group" data-group="{s(group)}"><h3>{s(group or "Без группы")}</h3></li>')
        for person in persons:
            rows.append(_roster_row(person)); ordered.append(person)
    online = [p for p in people if _person_facts(p)["online"]]
    now = ('<p class="vpn-online"><span class="dot ok" aria-hidden="true"></span>В сети: ' + " · ".join(s(p["name"]) for p in online) + '</p>' if online else '<p class="vpn-online muted">Нет недавней активности.</p>')
    roster = "".join(rows) or '<li class="muted">Снимка ещё нет.</li>'
    empty = '<section class="card"><h2>Пользователей пока нет</h2><p class="muted">Добавьте человека, чтобы выдать подписку.</p></section>' if not ordered else ''
    return (add + '<div class="vpn-workspace-grid"><aside class="card vpn-roster"><div class="vpn-roster-heading"><h2>Пользователи</h2>'
            + f'<span class="muted small">{len(people)}</span></div><label class="vpn-search-label" for="vpn-search">Поиск по людям</label>'
            + '<input type="search" id="vpn-search" class="vpn-search" placeholder="Имя, логин, группа или сервер" aria-label="Поиск по людям">'
            + f'<ul class="vpn-roster-list">{roster}</ul><p class="vpn-search-empty muted small" data-vpn-search-empty hidden>Никого не найдено.</p>'
            + '<p class="vpn-roster-note muted small">Трафик за 30 дней · статус по недавней активности</p></aside><div class="vpn-detail-stack">'
            + "".join(person_row(p, reach) for p in ordered) + empty + '</div></div><div class="vpn-people-footer">' + now
            + '<p class="muted small">«Ссылку в бот» — сразу. Пауза, перенос, новая ссылка и настройки — с подтверждением в Telegram.</p></div>')


def _section(title: str, items: list[tuple[str, str]], note: str = "") -> str:
    if not items and not note:
        return ""
    lis = "".join(f'<li class="{c}">{t}</li>' for c, t in items)
    return (f'<h3>{e(title)}</h3>' + (f'<ul class="list">{lis}</ul>' if lis else "")
            + (f'<p class="muted">{note}</p>' if note else ""))


def _countdown(ts: float | None) -> str:
    if not ts:
        return "—"
    return (f'<span class="countdown" data-until="{int(ts)}">в {e(msk(ts))}</span>')


# ---------------------------------------------------------------- разделы сервера

def _channels(snap: dict) -> str:
    rows = []
    for c in snap.get("channels") or []:
        if not isinstance(c, dict):
            continue
        st = c.get("selftest")
        bits = [s(c.get("proto")), s(c.get("port")), f'служба {s(c.get("unit"))}: {s(c.get("unit_state"))}']
        if c.get("listening") is False:
            bits.append("<b>порт не слушает</b>")
        if c.get("via"):
            bits.append(f'через {s(c.get("via"))}')
        bits.append("самопроверка " + yes(st, "ОК", "<b>НЕ ПРОШЛА</b>", "не проверялась"))
        rows.append(("ok" if c.get("ok") else "bad", f'<b>{s(c.get("title") or c.get("id"))}</b> · ' + " · ".join(bits)))
    return _section("Каналы", rows)


def _russia(snap: dict) -> str:
    r = snap.get("russia")
    if not isinstance(r, dict):
        return ""
    exit_ip, expected = r.get("exit_ip"), r.get("expected")
    text = f'туннель {s(r.get("tunnel"))} · выход {s(exit_ip)}'
    if expected and exit_ip != expected:
        text += f' — <b>ждём {s(expected)}</b>'
    return _section("Россия", [("ok" if r.get("ok") else "bad", text)])


def _probe(snap: dict) -> str:
    p = snap.get("probe") or {}
    ports = p.get("ports") or {}
    if not isinstance(ports, dict) or not ports:
        return ""
    rows = []
    for port, r in ports.items():
        r = r if isinstance(r, dict) else {}
        ok = r.get("tcp") is True and r.get("tls") is not False
        ms = f' · {s(r.get("ms"))} мс' if r.get("ms") is not None else ""
        rows.append(("ok" if ok else "bad", f'<b>{s(port)}</b>: TCP {yes(r.get("tcp"))}'
                     + (f', TLS {yes(r.get("tls"))}' if "tls" in r else "") + ms))
    return _section(f'Видно с соседа (отсюда до {s(p.get("target"))})', rows)


def _people(snap: dict) -> str:
    titles = {c.get("id"): c.get("title") for c in snap.get("channels") or [] if isinstance(c, dict)}
    rows = []
    for p in snap.get("people") or []:
        if not isinstance(p, dict) or p.get("login") == CONF.get("monitor_account", "monitoring"):
            continue
        chans = ", ".join(s(titles.get(c) or c) for c in p.get("channels") or [])
        dev = []
        if isinstance(p.get("vless"), dict):
            dev.append(f'устройств {s(p["vless"].get("devices"))}')
        if isinstance(p.get("calls"), dict):
            dev.append(f'«Звонки»: {s(p["calls"].get("online"))}')
        tg = p.get("telegram")
        if isinstance(tg, dict):
            dev.append(f'Telegram: {s(tg.get("online"))}' if tg.get("enabled", True) else "Telegram выключен")
        t = p.get("traffic") or {}
        traffic = f'трафик 24 ч {size(t.get("24h"))} · 7 дн {size(t.get("7d"))} · 30 дн {size(t.get("30d"))}'
        name = s(p.get("name") or p.get("login"))
        login = f' <small class="muted">{s(p.get("login"))}</small>' if p.get("name") and p.get("login") != p.get("name") else ""
        rows.append(("ok" if p.get("online") else "",
                     f'<b>{name}</b>{login} · {"в сети" if p.get("online") else "не в сети"}'
                     + (f' · {" · ".join(dev)}' if dev else "")
                     + f' · последний раз {e(ago(parse_iso(p.get("last_seen"))))}'
                     + f'<br><small class="muted">{chans or "каналов нет"} · {traffic}</small>'))
    acc = snap.get("accounting") or {}
    notes = []
    if acc and not acc.get("xray"):
        notes.append("учёт Xray выключен — устройства и трафик основного канала не видны")
    if acc.get("calls") == "shared-password":
        notes.append("«Звонки» по общему паролю — сессии по людям не видны")
    elif acc.get("calls") == "no-stats":
        notes.append("у «Звонков» нет учёта")
    return _section("Люди", rows, "; ".join(notes))


def _selftest(snap: dict) -> str:
    st = snap.get("selftest") or {}
    if not st:
        return ""
    rows = []
    for r in st.get("results") or []:
        if not isinstance(r, dict):
            continue
        tail = f' · выход {s(r.get("exit_ip") or "—")}'
        if r.get("expected") and r.get("exit_ip") != r.get("expected"):
            tail += f' (ждём {s(r.get("expected"))})'
        rows.append(("ok" if r.get("ok") else "bad", f'<b>{s(r.get("channel"))}</b>: {"ОК" if r.get("ok") else "НЕ ПРОШЛА"}{tail}'))
    head = f'{"прошла" if st.get("ok") else "НЕ ПРОШЛА"} · {e(ago(parse_iso(st.get("at"))))}'
    return _section(f"Самопроверка: {head}", rows)


def _pending(snap: dict) -> str:
    rows = []
    for p in snap.get("pending") or []:
        if isinstance(p, dict):
            rows.append(("warn", f'<b>{s(p.get("id"))}</b> ({s(p.get("unit"))}) — откат сам '
                         f'{_countdown(parse_iso(p.get("revert_at")))}'))
    return _section("Ждут «✅ Работает»", rows, "Кнопки «✅ Работает» и «↩️ Откатить» — в боте." if rows else "")


def _deadlines(snap: dict) -> str:
    rows = []
    for d in snap.get("deadlines") or []:
        if not isinstance(d, dict):
            continue
        days = d.get("days")
        when = ""
        if isinstance(days, (int, float)):
            when = f"через {days:.0f} дн." if days >= 0 else f"{-days:.0f} дн. назад"
        tone = "warn" if isinstance(days, (int, float)) and 0 <= days <= 30 else ""
        rows.append((tone, f'{s(d.get("what"))}' + (f' · {when}' if when else "")))
    return _section("Сроки", rows)


def _host(snap: dict) -> str:
    h = snap.get("host") or {}
    v = snap.get("versions") or {}
    units = snap.get("units") or {}
    rows = []
    if h:
        rows.append(("warn" if (h.get("disk_pct") or 0) > 85 else "",
                     f'диск {s(h.get("disk_pct"))} % ({s(h.get("disk_used_gb"))} из {s(h.get("disk_total_gb"))} ГБ)'))
        rows.append(("", f'память: свободно {s(h.get("mem_available_mb"))} из {s(h.get("mem_total_mb"))} МБ · '
                         f'нагрузка {s(h.get("load1"))} на {s(h.get("cpus"))} ядр.'))
        if h.get("reboot_required"):
            rows.append(("warn", "нужна перезагрузка (обновления ядра) — выполните через SSH"))
    if v:
        rows.append(("", " · ".join(f"{s(k)} {s(x)}" for k, x in v.items())))
    if isinstance(units, dict) and units:
        rows.append(("", " · ".join(
            f'{s(name)}: {s((u or {}).get("state"))}' + (f' (перезапусков {s(u.get("restarts"))})' if (u or {}).get("restarts") else "")
            for name, u in units.items() if isinstance(u, dict))))
    return _section("Сервер", rows)


def server_card(srv: dict) -> str:
    sid = str(srv.get("id", ""))
    title = s(srv.get("title") or SERVERS.get(sid, sid))
    snap = srv.get("snapshot") if isinstance(srv.get("snapshot"), dict) else {}
    tone = server_tone(srv)
    badge_cls, word = TONE[tone]
    fresh = e(ago(parse_iso(srv.get("fresh_at"))))
    head = (f'<div class="project-head"><h2><span class="dot {badge_cls}" aria-hidden="true"></span>{title}</h2>'
            f'<span class="badge {badge_cls}">{e(word)}</span></div>'
            f'<p class="muted">{s(srv.get("ip"))} · снимок {fresh}</p>')
    if tone == "off":
        head += (f'<p class="err">Нет связи: {s(srv.get("error") or "—")}. '
                 + (f"Ниже — последний снимок ({fresh})." if snap else "Снимка с него ещё не было.") + "</p>")
    problems = (snap.get("health") or {}).get("problems") or []
    body = (_section("Проблемы", [("bad", s(p)) for p in problems]) if problems else "")
    body += (_pending(snap) + _channels(snap) + _russia(snap) + _probe(snap) + _people(snap)
             + _selftest(snap) + _deadlines(snap) + _host(snap))
    buttons = ""
    if sid in SERVERS:
        buttons = ('<div class="vpn-actions">' + _form("refresh", "Обновить", sid) + _form("selftest", "Самопроверка", sid)
                   + "".join(_form("restart", f"Перезапустить {u}", sid, u) for u in UNITS) + "</div>"
                   '<p class="muted">«Обновить» и «Самопроверка» — сразу; перезапуск — после «Подтвердить» в боте.</p>')
    return f'<article class="card vpn-server {tone}">{head}{body}{buttons}</article>'


def _who(by: str) -> str:
    if not by:
        return ""
    if by.startswith("page:"):
        return "страница админки (" + by[5:] + ")"
    return "кнопка в Telegram"


def _recent(rows: list[dict]) -> str:
    cls = {"done": "ok", "failed": "bad", "lost": "bad", "running": "warn", "offered": "warn"}
    items = []
    for d in rows:
        req = d.get("req") or {}
        if req.get("action") not in ACTIONS:
            continue
        summary = str(d.get("summary") or "")
        if summary and vpnmod.scan(summary):
            summary = "(вывод скрыт: похоже на секрет)"
        ts = d.get("started") or d.get("created")
        when = dt.datetime.fromtimestamp(ts, vpnmod.MSK).strftime("%d.%m %H:%M МСК") if ts else "—"
        who = _who(str(d.get("by") or ""))
        items.append(f'<li class="{cls.get(d.get("state"), "")}">{vpnmod.what(req)}<br>'
                     f'<small class="muted">{e(when)} · {e(STATE_WORD.get(d.get("state"), str(d.get("state"))))}'
                     + (f" · {e(who)}" if who else "")
                     + (f" · {e(summary[-200:])}" if summary else "") + "</small></li>")
    body = f'<ul class="list">{"".join(items)}</ul>' if items else '<p class="muted">Действий пока нет.</p>'
    return f'<section class="card vpn-journal"><h2>Журнал действий <span class="muted small">{len(items)}</span></h2>{body}</section>' 


def updates_block(updates: list[dict]) -> str:
    if not updates:
        return ""
    btn = "".join(_pform({"action": "update", "server": u["server"], "program": u["program"], "version": u["version"]},
                         f'Обновить {u["program"].capitalize()} до {u["version"]} · {SHORT.get(u["server"], u["server"])}')
                  for u in updates)
    return (f'<section class="card"><h2>Обновления</h2><div class="vpn-actions">{btn}</div>'
            '<p class="muted small">Официальная сборка, проверка SHA-256, без «✅ Работает» за 5 минут вернётся прежняя '
            'версия. Карточка «Подтвердить» придёт в бот.</p></section>')


def _relay_card(panel: dict) -> str:
    """Read the actual top-level relay snapshot; RU is not a user-placement target."""
    relay = panel.get("relay")
    if not isinstance(relay, dict) or not relay:
        return ""
    reach = relay.get("reach")
    tone, word = ("ok", "доступен") if reach is True else ("bad", "нет связи") if reach is False else ("", "нет данных")
    ops = relay.get("ops") or {}
    rows = []
    for key in ("mts", "megafon", "beeline", "t2", "other"):
        op = ops.get(key)
        if not isinstance(op, dict):
            continue
        state = " · данные не идут" if op.get("stalled") else ""
        rows.append(f'<li class="{"warn" if op.get("stalled") else ""}"><b>{s(op.get("name") or key)}</b>: '
                    f'{s(op.get("conn"))} подключений{state}</li>')
    counters = ('<ul class="list">' + "".join(rows) + '</ul>') if rows else '<p class="muted small">Счётчики операторов недоступны.</p>'
    alert = f'<p class="err">{s(relay["alert"])}</p>' if relay.get("alert") else ""
    return ('<article class="card vpn-relay-card"><div class="project-head"><h2>🇷🇺 Посредник в России</h2>'
            f'<span class="badge {tone}">{word}</span></div><p class="muted">{s(relay.get("ip"))} · снимок '
            f'{e(ago(parse_iso(panel.get("generated_at"))))}</p>'
            + (f'<p class="muted small">Установлен {e(ago(parse_iso(relay.get("since"))))}</p>' if relay.get("since") else "")
            + alert + '<p class="muted small">Соединения по операторам за 15 минут. Подключение не всегда означает передачу данных.</p>'
            + counters + '<div class="vpn-actions">' + _form("relay-check", "Проверить посредник", CONF["server_id"]) + '</div></article>')


def render(panel: dict | None, recent: list[dict], people: list[dict] | None = None,
           updates: list[dict] | None = None) -> str:
    people = [p for p in people or [] if p.get("person") != CONF.get("monitor_account", "monitoring")]
    if panel and panel.get("withheld"):
        return ('<div id="vpn-workspace" class="vpn-workspace"><header class="vpn-workspace-header"><h1>VPN и подписки</h1></header>'
                '<section class="card"><p class="err">Снимок похож на секрет — не показываю.</p></section></div>')
    snapshot = panel or {}
    servers = [server for server in snapshot.get("servers") or [] if isinstance(server, dict)]
    cards = "".join(server_card(server) for server in servers)
    reach = {server.get("id"): bool(server.get("reach")) for server in servers}
    fresh = e(ago(parse_iso(snapshot.get("generated_at")))) if panel else "ещё не получен"
    online = sum(_person_facts(p)["online"] for p in people)
    header = ('<header class="vpn-workspace-header"><div><p class="vpn-eyebrow">Управление доступом</p><h1>VPN и подписки</h1>'
              f'<p class="muted">Пользователей: {len(people)} · в сети: {online} · снимок {fresh}</p>'
              '<p class="muted small">Снимок учёта обновляется каждые 5 минут.</p></div><div class="vpn-header-actions">'
              + _form("refresh", "Обновить всё", "all")
              + '<a class="button primary" href="#vpn-add-person" data-vpn-add>Добавить человека</a></div></header>')
    tabs = ('<nav class="vpn-workspace-tabs" aria-label="Разделы VPN">'
            + "".join(f'<a href="#vpn-section-{key}" data-vpn-section="{key}" aria-controls="vpn-section-{key}">{label}</a>'
                      for key, label in (("people", "Подписки"), ("infrastructure", "Инфраструктура"), ("log", "Журнал")))
            + '</nav>')
    notice = ('<section class="card"><h2>Снимок VPN ещё не получен</h2><p class="muted">Обновите снимок, чтобы увидеть состояние серверов и учёт.</p></section>' if panel is None else "")
    infra = (notice + updates_block(updates or []) + '<div class="vpn-servers">'
             + (cards or '<section class="card"><p class="muted">В снимке нет серверов.</p></section>') + '</div>' + _relay_card(snapshot))
    return ('<div id="vpn-workspace" class="vpn-workspace">' + header + tabs
            + '<section id="vpn-section-people" data-vpn-section-panel="people">' + notice + people_section(people, reach) + '</section>'
            + '<section id="vpn-section-infrastructure" data-vpn-section-panel="infrastructure">' + infra + '</section>'
            + '<section id="vpn-section-log" data-vpn-section-panel="log">' + _recent(recent) + '</section></div>')


# ---------------------------------------------------------------- обработчики

def routes(site) -> list[web.RouteDef]:
    def vpn():
        v = getattr(site, "vpn", None)
        if v is None:
            raise web.HTTPServiceUnavailable(text="VPN не подключён")
        return v

    async def index(request: web.Request) -> web.Response:
        site.require_user(request)
        v = vpn()
        people, moving = v.people(), v.moving()
        for p in people:
            p["moving"] = moving.get(p["person"])
        return site.page(f"VPN — {CONF['brand']}", render(v.panel(), v.recent(), people, v.updates()), active="/vpn", head=HEAD)

    def _done(title: str, text: str, ok: bool = True) -> web.Response:
        cls = "ok" if ok else "err"
        return site.page(title, f'<section class="card narrow"><h1>{e(title)}</h1><p class="{cls}">{e(text)}</p>'
                                f'<p><a href="/vpn">К VPN</a></p></section>', active="/vpn", head=HEAD)

    async def act(request: web.Request) -> web.Response:
        site.check_origin(request)
        user = site.require_user(request)
        form = await request.post()
        action, server = str(form.get("action", ""))[:20], str(form.get("server", ""))[:20]
        who = str(user.get("email") or "owner")[:100]
        if action in vpnmod.QUICK:
            jid, err = await vpn().quick(action, server, who)
            if not jid:
                return _done("Не запущено", err, ok=False)
            return _done("Запущено", f"{ACTIONS[action][0].capitalize()}: {vpnmod.server_title(server)}. "
                                     "Через минуту обновите вкладку — итог будет в «Последних заданиях».")
        person, login = str(form.get("person", ""))[:16], str(form.get("login", ""))[:16]
        sent = ("Подтвердите в Telegram", "Бот боте прислал карточку. Исполнится только после «Подтвердить» (30 минут).")
        if action == "reveal":
            jid, err = await vpn().reveal(person, who)
            if not jid:
                return _done("Не запущено", err, ok=False)
            raise web.HTTPSeeOther(f"/vpn/link/{jid}")
        if action == "sub-settings":
            def domains(name: str) -> list[str]:
                return [d.strip().lower() for d in re.split(r"[\s,;]+", str(form.get(name, ""))[:4000]) if d.strip()]
            try:
                limit = int(str(form.get("limit_gb", "0")).strip() or 0)
            except ValueError:
                return _done("Не отправлено", "лимит — целое число гигабайт", ok=False)
            num, err = await vpn().ask("sub-settings", "all", {
                "person": person, "group": " ".join(str(form.get("group", "")).split())[:24],
                "expire": str(form.get("expire", "")).strip()[:10], "limit_gb": limit,
                "routing": str(form.get("routing", "ai-social"))[:12],
                "proxy_add": domains("proxy_add"), "direct_add": domains("direct_add")}, f"Настройки подписки: {person}", who)
            return _done(*sent) if num else _done("Не отправлено", err, ok=False)
        if action == "sub-send":
            jid, err = await vpn().send_link(person, who)
            return (_done("Отправляю", "Через минуту в боте будет QR и готовый текст со ссылкой — перешлите его человеку.")
                    if jid else _done("Не запущено", err, ok=False))
        if action in ("person-pause", "person-resume", "sub-rotate", "sub-create", "move", "remove", "sub-notes", "update",
                      "servers"):
            v = vpn()
            if action == "servers":
                num, err = await v.set_servers(person, str(form.get("where", ""))[:60], who)
            elif action == "remove":
                num, err = await v.remove(person, server, login, who)
            elif action == "update":
                prog, ver = str(form.get("program", ""))[:10], str(form.get("version", ""))[:12]
                num, err = await v.ask("update", server, {"program": prog, "version": ver},
                                       f"Обновить {prog} до {ver} на {SERVERS.get(server, server)}", who)
            elif action == "sub-notes":
                pp = next((x for x in v.people() if x["person"] == person and x["sub"]), None)
                if not pp:
                    return _done("Не отправлено", "нет такой подписки", ok=False)
                srcs = []
                for n, x in enumerate(pp["sources"]):
                    src = {"server": x["server"], "login": x["login"]}
                    note = str(form.get(f"note_{n}", "")).strip()[:40]
                    if note:
                        src["note"] = note
                    srcs.append(src)
                num, err = await v.ask("sub-publish", "all", {"person": person, "sources": srcs},
                                       f"Пометки серверов: {pp['name']}", who)
            elif action == "move":
                num, err = await v.move(person, server, who)
            elif action == "sub-create":
                num, err = await v.ask("sub-publish", "all", {"person": person, "sources": [{"server": server, "login": login}]},
                                       f"Создать подписку: {person}", who)
            elif action == "sub-rotate":
                num, err = await v.ask("sub-rotate", "all", {"person": person}, f"Новая ссылка: {person}", who)
            else:
                num, err = await v.ask(action, server, {"login": login}, f"{ACTIONS[action][0].capitalize()}: {login}", who)
            return _done(*sent) if num else _done("Не отправлено", err, ok=False)
        if action == "restart":
            num, err = await vpn().ask_restart(server, str(form.get("unit", ""))[:40], who)
            if not num:
                return _done("Не отправлено", err, ok=False)
            return _done("Подтвердите в Telegram", "Бот боте прислал карточку перезапуска. "
                                                   "Исполнится только после «Подтвердить» (30 минут).")
        raise web.HTTPBadRequest(text="нет такого действия")

    async def add(request: web.Request) -> web.Response:
        site.check_origin(request)
        user = site.require_user(request)
        form = await request.post()
        name = str(form.get("name", "")).strip()
        if not name or len(name) > 40 or re.search(r'["|\\\n\r]', name):
            return _done("Не отправлено", "Имя: 1–40 знаков, без кавычек, | и обратной косой.", ok=False)
        num, err = await vpn().add_person(name, str(form.get("login", ""))[:16], str(form.get("server", ""))[:20],
                                          str(user.get("email") or "owner")[:100])
        if not num:
            return _done("Не отправлено", err, ok=False)
        return _done("Подтвердите в Telegram", f"Карточка «Подключить: {name}» в боте. После самопроверки нажмите "
                                               "«✅ Работает» — придёт QR и текст со ссылкой для пересылки.")

    async def link(request: web.Request) -> web.Response:
        """Адрес подписки — один раз тому, кто нажал «Показать ссылку»; обновите страницу — его уже нет."""
        user = site.require_user(request)
        jid = request.match_info["jid"][:60]
        state, url = vpn().link(jid, str(user.get("email") or "owner")[:100])
        if state == "wait":
            resp = site.page("Ссылка — VPN", '<section class="card narrow"><h1>Готовлю ссылку…</h1>'
                                             '<p class="muted">Страница обновится сама через пару секунд.</p></section>',
                             active="/vpn", head=HEAD, refresh=2)
        elif state == "ok":
            resp = site.page("Ссылка — VPN", (
                '<section class="card narrow vpn-link"><h1>Ссылка-подписка</h1>'
                f'<input id="vpn-link" class="vpn-search" readonly value="{e(url)}">'
                f'<div class="vpn-actions"><button type="button" class="small primary" id="vpn-copy" data-url="{e(url)}">Скопировать</button>'
                f'<a class="button small" href="{e(url)}" target="_blank" rel="noopener noreferrer">Открыть страницу человека</a></div>'
                '<p class="muted small">Показана один раз: после обновления страницы её здесь не будет. Ссылка личная — '
                'отправляйте только этому человеку.</p><p><a href="/vpn">К VPN</a></p></section>'), active="/vpn", head=HEAD)
        else:
            resp = _done("Ссылки нет", "Она уже была показана, устарела (10 минут) или запрошена не вами. Нажмите «Показать ссылку» ещё раз.",
                         ok=False)
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    return [web.get("/vpn", index), web.post("/vpn/act", act), web.post("/vpn/person", add),
            web.get("/vpn/link/{jid}", link)]
