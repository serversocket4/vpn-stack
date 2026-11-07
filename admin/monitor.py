"""Private monitoring history and debounced alerts, independent of VPN configuration."""
from __future__ import annotations

import contextlib
import datetime as dt
import html
import json
import math
import os
import sqlite3
import time
from pathlib import Path

from admin.config import CONF
from admin.vpn import scan

RANGES = {"1h": (3600, "1 час"), "6h": (21600, "6 часов"), "24h": (86400, "24 часа"),
          "7d": (604800, "7 дней"), "30d": (2592000, "30 дней")}
DEFAULTS = {"latency_ms": 3000, "latency_checks": 2, "failure_checks": 3,
            "recovery_checks": 2, "alerts_enabled": True}
PROBES = {"ru_nl", "nl_exit", "primary", "backup1", "backup2", "backup3", "telegram"}
CHANNELS = {"primary", "backup1", "backup2", "backup3"}
METRICS = {"cpu_pct", "steal_pct", "load1", "cpus", "mem_available_mb", "mem_total_mb", "disk_pct",
           "uptime_s", "rx_mbps", "tx_mbps", "tcp_retrans_delta", "tcp_out_delta",
           "rx_dropped_delta", "tx_dropped_delta", "rx_errors_delta", "tx_errors_delta", "rx_bytes", "tx_bytes"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS seen(at REAL PRIMARY KEY);
CREATE TABLE IF NOT EXISTS points(at REAL NOT NULL,series TEXT NOT NULL,value REAL,ok INTEGER NOT NULL,
 PRIMARY KEY(at,series));
CREATE INDEX IF NOT EXISTS points_time ON points(at);
CREATE TABLE IF NOT EXISTS states(key TEXT PRIMARY KEY,title TEXT NOT NULL,status TEXT NOT NULL,
 fails INTEGER NOT NULL DEFAULT 0,slow INTEGER NOT NULL DEFAULT 0,good INTEGER NOT NULL DEFAULT 0,
 updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,at REAL NOT NULL,key TEXT NOT NULL,kind TEXT NOT NULL,
 severity TEXT NOT NULL,title TEXT NOT NULL,detail TEXT NOT NULL DEFAULT '',closed REAL,
 notified INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS events_time ON events(at);
"""


def stamp(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value) if math.isfinite(value) else None
    try:
        d = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return d.replace(tzinfo=d.tzinfo or dt.timezone.utc).timestamp()
    except (ValueError, TypeError, OverflowError):
        return None


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) and abs(value) <= 1e18 else None


def text(value, limit=160):
    s = str(value or "")[:limit]
    return "Подробности скрыты" if scan(s) else s


class Monitor:
    def __init__(self, settings, vpn, *, db_path=None, sample_path=None, clock=time.time):
        self.s, self.vpn, self.clock = settings, vpn, clock
        self.sample_path = Path(sample_path or getattr(settings, "monitor_file", "/var/lib/bvpn-monitor/latest.json"))
        path = Path(db_path or settings.data_dir / "monitor.db")
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=3000")
        self.db.executescript(SCHEMA)
        os.chmod(path, 0o600)
        if self._get("started_at") is None:
            self._put("started_at", self.clock())
        self._last_cleanup = 0

    def close(self):
        self.db.close()

    def _get(self, key, default=None):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def _put(self, key, value):
        self.db.execute("INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (key, json.dumps(value, ensure_ascii=False, separators=(",", ":"))))

    @contextlib.contextmanager
    def _transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        else:
            self.db.execute("COMMIT")

    def settings(self):
        return {**DEFAULTS, **self._get("settings", {})}

    def update_settings(self, data, who="владелец"):
        if not isinstance(data, dict) or set(data) - set(DEFAULTS):
            raise ValueError("Неизвестные настройки мониторинга")
        result = self.settings()
        for key, value in data.items():
            if key == "alerts_enabled":
                if not isinstance(value, bool):
                    raise ValueError("Уведомления: требуется да или нет")
            else:
                upper, lower = (60000, 100) if key == "latency_ms" else (10, 1)
                if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
                    raise ValueError("Задержка: 100–60000 мс; число проверок: 1–10")
            result[key] = value
        if result == self.settings():
            return result
        with self._transaction():
            self._put("settings", result)
            self.db.execute("UPDATE states SET fails=0,slow=0,good=0")
            self.db.execute("UPDATE events SET notified=1 WHERE notified=0")
            self.db.execute("INSERT INTO events(at,key,kind,severity,title,detail,closed,notified) VALUES(?,?,?,?,?,?,?,1)",
                            (self.clock(), "settings", "settings", "ok", "Настройки мониторинга изменены",
                             f"Порог {result['latency_ms']} мс × {result['latency_checks']}; "
                             f"недоступность × {result['failure_checks']}; уведомления "
                             + ("включены" if result["alerts_enabled"] else "выключены"), self.clock()))
        return result

    def _clean(self, data):
        if not isinstance(data, dict) or data.get("schema") != 1:
            raise ValueError("invalid monitoring schema")
        at = stamp(data.get("at"))
        if at is None or at > self.clock() + 90 or at < 1577836800:
            raise ValueError("invalid monitoring timestamp")
        out = {"schema": 1, "at": dt.datetime.fromtimestamp(at, dt.timezone.utc).isoformat(),
               "interval_s": 60, "hosts": [], "probes": []}
        def observed(raw):
            measured = stamp(raw.get("at")) or at
            if measured > at + 60:
                raise ValueError("measurement timestamp is in the future")
            return dt.datetime.fromtimestamp(measured, dt.timezone.utc).isoformat()
        host_seen, probe_seen = set(), set()
        if not isinstance(data.get("hosts"), list) or not isinstance(data.get("probes"), list):
            raise ValueError("invalid monitoring lists")
        for raw in data.get("hosts") or []:
            if not isinstance(raw, dict) or raw.get("id") not in ("nl", "ru") or raw["id"] in host_seen:
                continue
            host_seen.add(raw["id"])
            raw_metrics = raw.get("metrics") or {}
            if not isinstance(raw_metrics, dict) or not isinstance(raw.get("services") or [], list):
                raise ValueError("invalid host metrics")
            metrics = {k: number(v) for k, v in raw_metrics.items() if k in METRICS}
            services = [{"id": text(x.get("id"), 48), "active": bool(x.get("active"))}
                        for x in (raw.get("services") or []) if isinstance(x, dict)][:12]
            out["hosts"].append({"id": raw["id"], "title": text(raw.get("title"), 64),
                                 "ip": text(raw.get("ip"), 48), "at": observed(raw),
                                 "ok": raw.get("ok") is True, "metrics": metrics, "services": services,
                                 "error": text(raw.get("error"), 200)})
        for raw in data.get("probes") or []:
            if not isinstance(raw, dict) or raw.get("id") not in PROBES or raw["id"] in probe_seen:
                continue
            probe_seen.add(raw["id"])
            latency = number(raw.get("latency_ms"))
            out["probes"].append({"id": raw["id"], "title": text(raw.get("title"), 80),
                                  "kind": text(raw.get("kind"), 32), "scope": text(raw.get("scope"), 180),
                                  "at": observed(raw),
                                  "ok": raw.get("ok") is True and raw.get("exit_ok") is not False,
                                  "latency_ms": latency if latency is not None and latency >= 0 else None,
                                  "loss_pct": number(raw.get("loss_pct")), "error": text(raw.get("error"), 200),
                                  "exit_ok": raw.get("exit_ok") if isinstance(raw.get("exit_ok"), bool) else None,
                                  "resource_fallback": raw.get("resource_fallback") is True})
        # Missing checks must never become implicit successful measurements.
        for hid, title in (("nl", "Нидерланды"), ("ru", "Россия")):
            if hid not in host_seen:
                out["hosts"].append({"id": hid, "title": title, "ok": False, "at": out["at"],
                                     "metrics": {}, "services": [], "error": "Нет результата сбора"})
        for pid in sorted(PROBES - probe_seen):
            out["probes"].append({"id": pid, "title": pid, "kind": "unknown", "scope": "",
                                  "at": out["at"], "ok": False, "latency_ms": None, "loss_pct": None,
                                  "error": "Нет результата проверки", "exit_ok": None})
        return out, at

    def _transition(self, key, title, old, new, at, detail):
        if old == new:
            return
        channel_probe = key.startswith("probe:") and key[6:] in CHANNELS
        if channel_probe:
            detail = (detail.rstrip(". ") + ". " if detail else "") + \
                     "Маршрут: NL → RU → NL → интернет; устройство не проверяется."
        notifying = 0 if self.settings()["alerts_enabled"] else 1
        self.db.execute("UPDATE events SET closed=? WHERE key=? AND closed IS NULL", (at, key))
        if new == "ok":
            if old not in ("bad", "warn"):
                return
            self.db.execute("INSERT INTO events(at,key,kind,severity,title,detail,closed,notified) VALUES(?,?,?,?,?,?,?,?)",
                            (at, key, "recovery", "ok", title + (": серверная проверка восстановилась" if channel_probe else ": восстановление"), detail, at, notifying))
        else:
            kind = "down" if new == "bad" else "latency"
            label = ((": серверная проверка не прошла" if new == "bad" else ": серверная проверка — высокая задержка")
                     if channel_probe else (": недоступно" if new == "bad" else ": высокая задержка"))
            self.db.execute("INSERT INTO events(at,key,kind,severity,title,detail,notified) VALUES(?,?,?,?,?,?,?)",
                            (at, key, kind, new, title + label, detail, notifying))

    def _observe(self, key, title, ok, latency, at, detail=""):
        cfg = self.settings()
        previous = self.db.execute("SELECT * FROM states WHERE key=?", (key,)).fetchone()
        old = dict(previous) if previous else {"status": "unknown", "fails": 0, "slow": 0, "good": 0, "updated": 0}
        if at <= old["updated"]:
            return
        status = old["status"]
        fails = old["fails"] + 1 if not ok else 0
        is_slow = ok and latency is not None and latency > cfg["latency_ms"]
        slow = old["slow"] + 1 if is_slow else 0
        good = old["good"] + 1 if ok and (status == "bad" or not is_slow) else 0
        target = status
        if fails >= cfg["failure_checks"]:
            target = "bad"
            detail = detail or f"Неуспешных проверок подряд: {fails}"
        elif ok:
            if status == "bad":
                if good >= cfg["recovery_checks"]:
                    target = "warn" if slow >= cfg["latency_checks"] else "ok"
            elif slow >= cfg["latency_checks"]:
                target = "warn"
                detail = f"{latency:.0f} мс; выше {cfg['latency_ms']} мс {slow} проверки подряд"
            elif status == "unknown" or status == "ok" or good >= cfg["recovery_checks"]:
                target = "ok"
        self._transition(key, title, status, target, at, detail or "Проверка снова проходит")
        self.db.execute("INSERT INTO states VALUES(?,?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET "
                        "title=excluded.title,status=excluded.status,fails=excluded.fails,slow=excluded.slow,"
                        "good=excluded.good,updated=excluded.updated",
                        (key, title, target, fails, slow, good, at))

    def _feed(self, now):
        latest = self._get("latest")
        last = stamp((latest or {}).get("at")) or self._get("started_at", now)
        stale = now - last > 180
        row = self.db.execute("SELECT status FROM states WHERE key='collector'").fetchone()
        old = row[0] if row else "unknown"
        target = "bad" if stale else ("ok" if latest else "unknown")
        if target != old:
            self._transition("collector", "Сбор мониторинга", old, target, now,
                             "Нет свежих измерений более трёх минут" if stale else "Новые измерения получены")
            self.db.execute("INSERT INTO states VALUES('collector','Сбор мониторинга',?,0,0,0,?) "
                            "ON CONFLICT(key) DO UPDATE SET status=excluded.status,updated=excluded.updated", (target, now))

    def ingest(self):
        now = self.clock()
        try:
            if self.sample_path.stat().st_size > 128 * 1024:
                raise ValueError("sample too large")
            sample, at = self._clean(json.loads(self.sample_path.read_text()))
        except (OSError, ValueError, TypeError, KeyError):
            self._feed(now)
            return False
        if self.db.execute("SELECT 1 FROM seen WHERE at=?", (at,)).fetchone():
            self._feed(now)
            return False
        latest = self._get("latest")
        if latest and at <= stamp(latest["at"]):
            self._feed(now)
            return False
        with self._transaction():
            self.db.execute("INSERT INTO seen VALUES(?)", (at,))
            self._put("latest", sample)
            for host in sample["hosts"]:
                m = host["metrics"]
                service_ok = all(s["active"] for s in host["services"])
                measured = stamp(host.get("at")) or at
                previous = self.db.execute("SELECT updated FROM states WHERE key=?", ("host:" + host["id"],)).fetchone()
                self._observe("host:" + host["id"], host["title"], host["ok"] and service_ok, None, measured,
                              host["error"] or ", ".join(s["id"] for s in host["services"] if not s["active"]))
                total, available = m.get("mem_total_mb"), m.get("mem_available_mb")
                mem = max(0, min(100, 100 * (1 - available / total))) if total and available is not None else None
                network = {k: m.get(k) for k in ("tcp_retrans_delta", "tcp_out_delta", "rx_dropped_delta",
                                                  "tx_dropped_delta", "rx_errors_delta", "tx_errors_delta", "steal_pct")}
                for metric, value in {"cpu_pct": m.get("cpu_pct"), "mem_used_pct": mem,
                                      "rx_mbps": m.get("rx_mbps"), "tx_mbps": m.get("tx_mbps"), **network}.items():
                    if not previous or measured > previous[0]:
                        self.db.execute("INSERT OR IGNORE INTO points VALUES(?,?,?,?)", (measured, f"host.{host['id']}.{metric}", value, int(host["ok"])))
            for probe in sample["probes"]:
                measured = stamp(probe.get("at")) or at
                self._observe("probe:" + probe["id"], probe["title"], probe["ok"], probe["latency_ms"], measured, probe["error"])
                self.db.execute("INSERT OR IGNORE INTO points VALUES(?,?,?,?)", (measured, f"probe.{probe['id']}.latency_ms",
                                                                       probe["latency_ms"], int(probe["ok"])))
            self._feed(now)
            if now - self._last_cleanup > 3600:
                cutoff = now - RANGES["30d"][0]
                self.db.execute("DELETE FROM points WHERE at<?", (cutoff,))
                self.db.execute("DELETE FROM seen WHERE at<?", (cutoff,))
                self.db.execute("DELETE FROM events WHERE at<? AND closed IS NOT NULL", (cutoff,))
                self._last_cleanup = now
        return True

    async def notify(self, bot):
        if not self.settings()["alerts_enabled"]:
            self.db.execute("UPDATE events SET notified=1 WHERE notified=0")
            return
        rows = self.db.execute("SELECT * FROM events WHERE notified=0 ORDER BY id LIMIT 12").fetchall()
        if not rows:
            return
        chunks, ids, length = [], [], 0
        for row in rows:
            marker = {"bad": "🔴", "warn": "🟠", "ok": "🟢"}.get(row["severity"], "ℹ️")
            line = f"{marker} <b>{html.escape(row['title'])}</b>\n{html.escape(row['detail'])}"
            if length + len(line) > 3300 and chunks:
                break
            chunks.append(line)
            ids.append(row["id"])
            length += len(line) + 2
        await bot.send("🛡 <b>Мониторинг VPN</b>\n\n" + "\n\n".join(chunks)
                       + "\n\n" + html.escape(self.s.public_url + "/dashboard"))
        self.db.executemany("UPDATE events SET notified=1 WHERE id=?", [(i,) for i in ids])

    def _people(self):
        panel = self.vpn.panel() or {}
        lookup = {(s.get("id"), p.get("login")): p for s in panel.get("servers") or []
                  for p in (s.get("snapshot") or {}).get("people") or [] if isinstance(p, dict)}
        out = []
        for person in self.vpn.people():
            sources = {(x.get("server"), x.get("login")): lookup.get((x.get("server"), x.get("login"))) or x.get("info") or {}
                       for x in person.get("sources") or []}
            for sid, login in (person.get("accounts") or {}).items():
                sources.setdefault((sid, login), lookup.get((sid, login)) or {})
            traffic, partial = {}, False
            for period in ("24h", "7d", "30d"):
                values = [number((x.get("traffic") or {}).get(period)) for x in sources.values()]
                traffic[period] = sum(max(0, n) for n in values if n is not None) if any(n is not None for n in values) else None
                partial = partial or not values or any(n is None for n in values)
            out.append({"id": text(person.get("person"), 32), "name": text(person.get("name"), 80),
                        "online": any(x.get("online") for x in sources.values()),
                        "paused": bool(sources) and all(x.get("paused") for x in sources.values()),
                        "traffic": traffic, "partial": partial})
        return sorted(out, key=lambda x: -(x["traffic"]["30d"] or 0))

    def view(self, period="24h"):
        period = period if period in RANGES else "24h"
        duration, label = RANGES[period]
        now = self.clock()
        sample = self._get("latest", {"at": None, "hosts": [], "probes": []})
        age = max(0, now - stamp(sample["at"])) if stamp(sample.get("at")) is not None else None
        sample["age_s"], sample["stale"] = age, age is None or age > 180
        states = {r["key"]: dict(r) for r in self.db.execute("SELECT * FROM states")}
        for kind, values in (("host", sample["hosts"]), ("probe", sample["probes"])):
            for value in values:
                state = states.get(kind + ":" + value["id"], {})
                status = state.get("status", "unknown")
                item_at = stamp(value.get("at"))
                if sample["stale"] or item_at is None or now - item_at > 180:
                    status = "unknown"
                elif not value.get("ok") and status != "bad":
                    status = "warn"
                value["status"] = status
                value["pending_failures"] = state.get("fails", 0)
                value["state_label"] = {"ok": "В порядке", "warn": "Внимание", "bad": "Сбой", "unknown": "Нет свежих данных"}[status]
                if value.get("ok") is False and 0 < state.get("fails", 0) < self.settings()["failure_checks"]:
                    value["state_label"] = f"Ошибка {state['fails']}/{self.settings()['failure_checks']}"
        bucket = max(60, int(math.ceil(duration / 360 / 60)) * 60)
        rows = self.db.execute("SELECT CAST(at/? AS INTEGER) AS bucket,series, "
                               "CASE WHEN series LIKE 'probe.%' OR series LIKE '%.%_delta' THEN MAX(value) ELSE AVG(value) END AS value, "
                               "MIN(ok) AS ok FROM points WHERE at>=? GROUP BY bucket,series ORDER BY bucket",
                               (bucket, now - duration)).fetchall()
        bins = {}
        for row in rows:
            point = bins.setdefault(row["bucket"], {"at": row["bucket"] * bucket, "hosts": {}, "probes": {}})
            kind, entity, metric = row["series"].split(".")
            if kind == "host":
                point["hosts"].setdefault(entity, {})[metric] = row["value"] if row["ok"] else None
            else:
                point["probes"][entity] = {"latency_ms": row["value"], "ok": bool(row["ok"])}
        series = [bins.get(b, {"at": b * bucket, "hosts": {}, "probes": {}})
                  for b in range(int((now - duration) // bucket), int(now // bucket) + 1)]
        people = self._people()
        events = [{"id": r["id"], "at": r["at"], "kind": r["kind"], "severity": r["severity"],
                   "title": r["title"], "detail": r["detail"], "open": r["closed"] is None}
                  for r in self.db.execute("SELECT * FROM events WHERE at>=? OR closed IS NULL ORDER BY at DESC,id DESC LIMIT 80", (now - duration,))]
        opened = self.db.execute("SELECT COUNT(*) FROM events WHERE closed IS NULL").fetchone()[0]
        values = [x.get("status", "unknown") for x in sample["hosts"] + sample["probes"]]
        status = "unknown" if sample["stale"] or not values else ("bad" if "bad" in values else "warn" if "warn" in values else "unknown" if "unknown" in values else "ok")
        nl = next((x["metrics"] for x in sample["hosts"] if x["id"] == "nl"), {})
        first = self.db.execute("SELECT MIN(at) FROM seen").fetchone()[0]
        panel_at = stamp((self.vpn.panel() or {}).get("generated_at"))
        return {"range": period, "range_label": label, "now": now, "sample": sample, "series": series,
                "people": people, "events": events, "settings": self.settings(),
                "summary": {"status": status, "label": {"ok": "Система в порядке", "warn": "Требует внимания", "bad": "Есть подтверждённый сбой", "unknown": "Ожидание свежих измерений"}[status],
                            "online_users": sum(p["online"] for p in people), "users": len(people),
                            "channels_up": sum(p.get("ok") is True and p.get("status") != "unknown" for p in sample["probes"] if p["id"] in CHANNELS),
                            "channels_total": 4, "rx_mbps": nl.get("rx_mbps"), "tx_mbps": nl.get("tx_mbps"),
                            "open_incidents": opened},
                "meta": {"started_at": self._get("started_at"), "available_from": first, "retention_days": 30,
                         "interval_s": 60, "bucket_s": bucket, "people_age_s": max(0, now - panel_at) if panel_at else None,
                         "probe_account": text(CONF.get("monitor_account", "monitoring"), 32),
                         "probe_scope": "Проверки выполняются с серверов. Они не измеряют участок от телефона до RU."}}
