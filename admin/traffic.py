"""Read-only traffic reports from the existing per-account VPN snapshots."""
from __future__ import annotations

import datetime as dt
import html
import math
import time

PERIODS = {"24h": "24 часа", "7d": "7 дней", "30d": "30 дней"}
PAGE_SIZE = 10


def _stamp(value):
    try:
        stamp = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=dt.timezone.utc)
        return stamp.timestamp()
    except (ValueError, TypeError, OverflowError):
        return None


def _age(value, now):
    stamp = _stamp(value)
    if stamp is None:
        return "время неизвестно"
    seconds = max(0, now - stamp)
    if seconds < 60:
        return "только что"
    if seconds < 3600:
        return f"{int(seconds // 60)} мин назад"
    if seconds < 86400:
        return f"{int(seconds // 3600)} ч назад"
    return f"{int(seconds // 86400)} дн назад"


def _bytes(value):
    if value == 0:
        return "0 Б"
    for divisor, unit in ((1 << 40, "ТБ"), (1 << 30, "ГБ"), (1 << 20, "МБ"), (1 << 10, "КБ")):
        if value >= divisor:
            return f"{value / divisor:.2f}".replace(".", ",") + " " + unit
    return f"{value} Б"


def _amount(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return max(0, int(value)) if isinstance(value, int) or math.isfinite(value) else None


def traffic_view(panel, people, period="30d", page=0, now=None):
    """Return bounded Telegram HTML and buttons, without resetting or refreshing counters."""
    period = period if period in PERIODS else "30d"
    now = time.time() if now is None else now
    if not isinstance(panel, dict):
        return "📊 <b>Трафик VPN</b>\nСнимка статистики пока нет.", []
    if panel.get("withheld"):
        return "📊 <b>Трафик VPN</b>\nСнимок скрыт проверкой безопасности.", []
    servers = [s for s in panel.get("servers") or [] if isinstance(s, dict)]
    lookup = {(s.get("id"), p.get("login")): p for s in servers
              for p in (s.get("snapshot") or {}).get("people") or [] if isinstance(p, dict)}
    totals, rows, owners = {}, [], {}
    unknown = shared = False
    for person in people:
        sources = {}
        for source in person.get("sources", []):
            key = (source.get("server"), source.get("login"))
            if all(isinstance(x, str) and x for x in key):
                sources[key] = lookup.get(key) or source.get("info") or {}
        for server, login in (person.get("accounts") or {}).items():
            sources.setdefault((server, login), lookup.get((server, login)) or {})
        amount, known, missing = 0, 0, not bool(sources)
        for key, info in sources.items():
            value = _amount((info.get("traffic") or {}).get(period))
            if value is None:
                missing = unknown = True
                continue
            amount += value
            known += 1
            totals[key] = value
            if key in owners and owners[key] != person.get("person"):
                shared = True
            owners[key] = person.get("person")
        unknown = unknown or missing
        rows.append({"person": str(person.get("person") or ""),
                     "name": str(person.get("name") or person.get("person") or "Без имени")[:32],
                     "amount": amount if known else None, "partial": missing})
    rows.sort(key=lambda p: (p["amount"] is None, -(p["amount"] or 0), p["name"].casefold(), p["person"]))
    pages = max(1, (len(rows) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(int(page), pages - 1))
    text = [f"📊 <b>Трафик VPN · последние {PERIODS[period]}</b>",
            f"Снимок {_age(panel.get('generated_at'), now)}\n"]
    for index, row in enumerate(rows[page * PAGE_SIZE:(page + 1) * PAGE_SIZE], page * PAGE_SIZE + 1):
        usage = "нет данных" if row["amount"] is None else ("≥ " if row["partial"] else "") + _bytes(row["amount"])
        name = html.escape(row["name"])
        login = html.escape(row["person"][:16])
        label = name + (f" (<code>{login}</code>)" if row["name"] != row["person"] and login else "")
        text.append(f"{index}. {label} — <b>{usage}</b>")
    if not rows:
        text.append("Пользователей в снимке пока нет.")
    total = ("≥ " if unknown else "") + _bytes(sum(totals.values())) if totals else "нет данных"
    text.append(f"\n<b>Всего: {total}</b>")
    text.append("Приём + передача: VPN и Telegram-прокси. Учёт по профилям, с момента включения статистики.")
    if unknown:
        text.append("⚠️ Для части источников нет данных; ноль им не приписан.")
    stale = sum(1 for s in servers if not s.get("reach", True))
    if stale:
        text.append(f"⚠️ Недоступно серверов: {stale}; их данные могут быть устаревшими.")
    dates = [s.get("fresh_at") for s in servers if _stamp(s.get("fresh_at")) is not None]
    oldest = min(dates, key=_stamp) if dates else None
    if oldest and now - _stamp(oldest) > 15 * 60:
        text.append(f"⚠️ Самые старые данные сервера: {_age(oldest, now)}.")
    if shared:
        text.append("Общие ключи показаны у связанных подписок; в итоге учтены один раз.")
    if pages > 1:
        text.append(f"Страница {page + 1} из {pages}.")
    buttons = [[(("✓ " if p == period else "") + label, f"vpnstats:{p}:0")
                for p, label in (("24h", "24 ч"), ("7d", "7 дней"), ("30d", "30 дней"))]]
    navigation = []
    if page:
        navigation.append(("←", f"vpnstats:{period}:{page - 1}"))
    if page + 1 < pages:
        navigation.append(("→", f"vpnstats:{period}:{page + 1}"))
    if navigation:
        buttons.append(navigation)
    buttons.append([("↻ Обновить список", f"vpnstats:{period}:{page}")])
    return "\n".join(text), buttons
