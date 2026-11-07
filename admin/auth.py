"""Вход на страницу: почта и пароль (как в базовом приложении), плюс «Разрешить» в боте.

* Пароль — scrypt (n=2^15, r=8, p=1), как в базовом приложении `app/auth.py`. Задаёт его сам
  владелец по одноразовой ссылке из бота (`/password`): секрет ссылки стоит после
  `#`, на сервер и в журналы не уходит, страница отправляет его POST.
* Перебор: 5 неудач за 15 минут по почте или по адресу — вход закрыт на 15 минут.
* Верный пароль ещё не вход: бот присылает «Вход в админку с адреса X» с кнопками,
  ожидание живёт 5 минут. Сессия — cookie на 30 дней (HttpOnly, Secure,
  SameSite=Strict), в базе только sha256 от неё; «Выйти везде» и `/logout_all`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

from admin.store import Store

SESSION_DAYS = 30
PENDING_SECONDS = 300
SETUP_SECONDS = 900
FAIL_WINDOW = 900
FAIL_LIMIT = 5
MIN_PASSWORD = 12

_N, _R, _P, _MAXMEM = 2**15, 8, 1, 64 * 1024 * 1024


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=_MAXMEM, dklen=32)
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, digest = stored.split("$")
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             maxmem=_MAXMEM, dklen=32)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, base64.b64decode(digest))


# пустышка: время ответа не выдаёт, есть ли такая почта
_DUMMY = hash_password(secrets.token_hex(8))


def sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Auth:
    def __init__(self, store: Store, owner_email: str):
        self.store = store
        self.owner = owner_email

    # --- одноразовая ссылка «задать пароль» ---
    def new_setup_code(self) -> str:
        code = secrets.token_urlsafe(24)
        self.store.x("DELETE FROM setup_codes")
        self.store.x("INSERT INTO setup_codes(code_hash,expires) VALUES(?,?)", sha(code), time.time() + SETUP_SECONDS)
        return code

    def use_setup_code(self, code: str, password: str) -> str:
        """'' если пароль задан, иначе причина."""
        if len(password) < MIN_PASSWORD:
            return f"пароль короче {MIN_PASSWORD} символов"
        row = self.store.one("SELECT expires FROM setup_codes WHERE code_hash=?", sha(code))
        if not row or row["expires"] < time.time():
            return "ссылка устарела или уже использована — попросите новую командой /password"
        self.store.x("DELETE FROM setup_codes")
        self.store.x("INSERT INTO users(email,pw_hash,updated) VALUES(?,?,?) ON CONFLICT(email) DO UPDATE"
                     " SET pw_hash=excluded.pw_hash, updated=excluded.updated", self.owner, hash_password(password),
                     time.time())
        self.store.x("DELETE FROM sessions")          # новый пароль — все прежние входы закрыты
        return ""

    # --- перебор ---
    def locked(self, email: str, ip: str) -> bool:
        since = time.time() - FAIL_WINDOW
        self.store.x("DELETE FROM login_fails WHERE at<?", since)
        for subject in (f"email:{email}", f"ip:{ip}"):
            row = self.store.one("SELECT COUNT(*) n FROM login_fails WHERE subject=? AND at>?", subject, since)
            if row["n"] >= FAIL_LIMIT:
                return True
        return False

    def _fail(self, email: str, ip: str) -> None:
        now = time.time()
        self.store.x("INSERT INTO login_fails(subject,at) VALUES(?,?)", f"email:{email}", now)
        self.store.x("INSERT INTO login_fails(subject,at) VALUES(?,?)", f"ip:{ip}", now)

    # --- пароль → ожидание подтверждения ---
    def check_password(self, email: str, password: str, ip: str) -> bool:
        email = email.strip().lower()
        row = self.store.one("SELECT pw_hash FROM users WHERE email=?", email)
        ok = verify_password(password, row["pw_hash"] if row else _DUMMY) and row is not None
        if not ok:
            self._fail(email, ip)
        return ok

    def new_pending(self, email: str, ip: str, ua: str) -> str:
        token = secrets.token_urlsafe(32)
        self.store.x("DELETE FROM pending_logins WHERE created<?", time.time() - PENDING_SECONDS)
        self.store.x("INSERT INTO pending_logins(token_hash,email,created,state,ip,ua) VALUES(?,?,?,?,?,?)",
                     sha(token), email.strip().lower(), time.time(), "wait", ip[:64], ua[:200])
        return token

    def pending(self, token: str | None) -> dict | None:
        if not token:
            return None
        row = self.store.one("SELECT rowid AS rid, * FROM pending_logins WHERE token_hash=? AND created>?",
                             sha(token), time.time() - PENDING_SECONDS)
        return dict(row) if row else None

    def decide(self, rid: int, allow: bool) -> dict | None:
        row = self.store.one("SELECT rowid AS rid, * FROM pending_logins WHERE rowid=? AND state='wait' AND created>?",
                             rid, time.time() - PENDING_SECONDS)
        if not row:
            return None
        self.store.x("UPDATE pending_logins SET state=? WHERE rowid=?", "ok" if allow else "denied", rid)
        return dict(row)

    def finish(self, token: str) -> str | None:
        """Подтверждённое ожидание → токен сессии (одноразово)."""
        p = self.pending(token)
        if not p or p["state"] != "ok":
            return None
        self.store.x("DELETE FROM pending_logins WHERE token_hash=?", sha(token))
        session = secrets.token_urlsafe(32)
        now = time.time()
        self.store.x("INSERT INTO sessions(token_hash,email,created,expires,ip,ua) VALUES(?,?,?,?,?,?)",
                     sha(session), p["email"], now, now + SESSION_DAYS * 86400, p["ip"], p["ua"])
        return session

    # --- сессии ---
    def session(self, token: str | None) -> dict | None:
        if not token:
            return None
        row = self.store.one("SELECT * FROM sessions WHERE token_hash=? AND expires>?", sha(token), time.time())
        return dict(row) if row else None

    def logout(self, token: str | None) -> None:
        if token:
            self.store.x("DELETE FROM sessions WHERE token_hash=?", sha(token))

    def logout_all(self) -> int:
        return self.store.x("DELETE FROM sessions").rowcount
