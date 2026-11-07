"""SQLite админки: последнее состояние проверок, инциденты, заглушки, вход, задания.

Одно соединение на процесс (бот, сборщик и страница живут в одном asyncio-цикле),
поэтому без пулов и блокировок. Время — UTC, секунды от эпохи.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
    key TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    title TEXT NOT NULL,
    ok INTEGER NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    action TEXT,
    fails INTEGER NOT NULL DEFAULT 0,      -- провалов подряд
    updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    project TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    opened REAL NOT NULL,
    closed REAL,
    message_id INTEGER,
    note TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS incidents_open ON incidents(key) WHERE closed IS NULL;
CREATE TABLE IF NOT EXISTS mutes (
    key TEXT PRIMARY KEY,
    until REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS actions_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at REAL NOT NULL,
    action TEXT NOT NULL,
    who TEXT NOT NULL,                    -- 'auto' | 'owner-bot' | 'owner-web'
    ok INTEGER NOT NULL,
    output TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    pw_hash TEXT NOT NULL,
    updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    created REAL NOT NULL,
    expires REAL NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    ua TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS pending_logins (
    token_hash TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    created REAL NOT NULL,
    state TEXT NOT NULL,                  -- 'wait' | 'ok' | 'denied'
    ip TEXT NOT NULL DEFAULT '',
    ua TEXT NOT NULL DEFAULT '',
    message_id INTEGER
);
CREATE TABLE IF NOT EXISTS setup_codes (
    code_hash TEXT PRIMARY KEY,
    expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS login_fails (
    subject TEXT NOT NULL,                -- 'email:…' | 'ip:…'
    at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    incident_id INTEGER,
    project TEXT NOT NULL,
    state TEXT NOT NULL,                  -- started | pr | no-change | failed | merging | merged | merge-failed | closed
    created REAL NOT NULL,
    updated REAL NOT NULL,
    pr_url TEXT NOT NULL DEFAULT '',
    pr_number INTEGER,
    head_sha TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    message_id INTEGER
);
CREATE TABLE IF NOT EXISTS asks (           -- «Да / Нет» владельцу на шаги, требующие согласия (python -m admin ask)
    id TEXT PRIMARY KEY,
    text TEXT NOT NULL,
    created REAL NOT NULL,
    answer TEXT,                          -- NULL | 'yes' | 'no'
    answered REAL,
    message_id INTEGER
);
CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: Path | str):
        self.db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)

    # --- общее ---
    def q(self, sql: str, *args) -> list[sqlite3.Row]:
        return self.db.execute(sql, args).fetchall()

    def one(self, sql: str, *args) -> sqlite3.Row | None:
        return self.db.execute(sql, args).fetchone()

    def x(self, sql: str, *args) -> sqlite3.Cursor:
        return self.db.execute(sql, args)

    def get(self, k: str, default=None):
        row = self.one("SELECT v FROM kv WHERE k=?", k)
        return json.loads(row["v"]) if row else default

    def put(self, k: str, v) -> None:
        self.x("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", k, json.dumps(v, ensure_ascii=False))

    def items(self, prefix: str) -> list[tuple[str, object]]:
        rows = self.q("SELECT k, v FROM kv WHERE substr(k, 1, ?) = ? ORDER BY k", len(prefix), prefix)
        return [(r["k"], json.loads(r["v"])) for r in rows]

    # --- заглушки ---
    def muted(self, key: str, now: float | None = None) -> bool:
        row = self.one("SELECT until FROM mutes WHERE key=?", key)
        return bool(row and row["until"] > (now or time.time()))

    def mute(self, key: str, seconds: float) -> None:
        self.x("INSERT INTO mutes(key,until) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET until=excluded.until",
               key, time.time() + seconds)

    def unmute(self, key: str) -> None:
        self.x("DELETE FROM mutes WHERE key=?", key)

    # --- журнал действий ---
    def log_action(self, action: str, who: str, ok: bool, output: str) -> None:
        self.x("INSERT INTO actions_log(at,action,who,ok,output) VALUES(?,?,?,?,?)",
               time.time(), action, who, int(ok), output[-2000:])

    def auto_count(self, action: str, within: float) -> int:
        row = self.one("SELECT COUNT(*) n FROM actions_log WHERE action=? AND who='auto' AND at>?",
                       action, time.time() - within)
        return int(row["n"]) if row else 0
