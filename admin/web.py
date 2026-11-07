"""Страница админки: aiohttp на 127.0.0.1 за Caddy.

Безопасность:
* секретов в адресе нет никогда: вход — форма POST, ссылка «задать пароль» несёт
  секрет после `#` (на сервер не уходит), журнал запросов aiohttp выключен;
* cookie сессии HttpOnly + Secure + SameSite=Strict; каждый POST сверяет Origin;
* CSP без inline-скриптов и стилей, nosniff, запрет фреймов, no-referrer, no-store;
* всё, что пришло из проверок (журналы, названия PR, ответы серверов), экранируется.
"""

from __future__ import annotations

import asyncio
import contextvars
import datetime as dt
import hashlib
import html
import time
from pathlib import Path
from typing import Awaitable, Callable

from aiohttp import web

from admin.auth import Auth
from admin.config import CONF, Settings
from admin.store import Store

e = html.escape
STATIC = Path(__file__).parent / "static"
COOKIE, WAIT_COOKIE = "adm", "adm_wait"

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")


@web.middleware
async def security_headers(request: web.Request, handler):
    try:
        resp = await handler(request)
    except web.HTTPException as exc:
        resp = exc
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    # не no-referrer: с ним Chrome шлёт в формах «Origin: null», и проверка источника отвергает свои же POST
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if not request.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "no-store"
    if isinstance(resp, web.HTTPException):
        raise resp
    return resp


def client_ip(request: web.Request) -> str:
    # за Caddy адрес посетителя — X-Real-IP (Caddy ставит его сам)
    if request.remote in ("127.0.0.1", "::1"):
        return (request.headers.get("X-Real-IP") or request.remote or "")[:64]
    return request.remote or ""


# Дизайн-система: копия токенов и шрифтов в static/brand (как в базовом приложении и базовом интерфейсе),
# каждый файл — своим <link> с версией в адресе, чтобы после выкатки браузер не держал старое.
BRAND_CSS = ("brand/fonts.css", "brand/colors.css", "brand/typography.css", "brand/layout.css",
             "brand/theme-light.css", "admin.css")


def _asset_version() -> str:
    h = hashlib.sha1()
    for name in (*BRAND_CSS, "theme.js"):
        try:
            h.update((STATIC / name).read_bytes())
        except OSError:
            pass
    return h.hexdigest()[:10]


ASSET_V = _asset_version()
BRAND = CONF["brand"]
LOGO = f'<span class="wordmark">{e(BRAND)}</span>'
ICON_SUN = ('<svg class="icon i-sun" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="4"/>'
            '<path d="M12 2v2M12 20v2m-7.07-17.07 1.41 1.41m11.32 11.32 1.41 1.41M2 12h2m16 0h2'
            'm-15.66 5.66-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>')
ICON_MOON = ('<svg class="icon i-moon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">'
             '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg>')
# Спрайт разделов — Lucide (ISC), как в базовом приложении и базовом интерфейсе (components/icons.html). Новая вкладка приходит
# со своей иконкой (ICON в модуле страницы): в свёрнутой колонке видна только она.
SPRITE = ('<svg class="sprite" aria-hidden="true" focusable="false">'
          '<symbol id="i-activity" viewBox="0 0 24 24"><path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0'
          'L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2"/></symbol>'
          '<symbol id="i-network" viewBox="0 0 24 24"><rect x="16" y="16" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" '
          'height="6" rx="1"/><rect x="9" y="2" width="6" height="6" rx="1"/><path d="M5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3"/>'
          '<path d="M12 12V8"/></symbol>'
          '<symbol id="i-shield" viewBox="0 0 24 24"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6'
          'a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></symbol>'
          '<symbol id="i-wallet" viewBox="0 0 24 24"><path d="M19 7V4a1 1 0 0 0-1-1H5a2 2 0 0 0 0 4h15a1 1 0 0 1 1 1v4h-3a2 2 0 0 0 0 4'
          'h3a1 1 0 0 0 1-1v-2a1 1 0 0 0-1-1"/><path d="M3 5v14a2 2 0 0 0 2 2h15a1 1 0 0 0 1-1v-4"/></symbol>'
          '<symbol id="i-warehouse" viewBox="0 0 24 24"><path d="M22 8.35V20a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V8.35A2 2 0 0 1 3.26 6.5'
          'l8-3.2a2 2 0 0 1 1.48 0l8 3.2A2 2 0 0 1 22 8.35Z"/><path d="M6 18h12"/><path d="M6 14h12"/>'
          '<rect width="12" height="12" x="6" y="10"/></symbol>'
          '<symbol id="i-logout" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/>'
          '<path d="M21 12H9"/></symbol>'
          '<symbol id="i-panel-close" viewBox="0 0 24 24"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M9 3v18"/>'
          '<path d="m16 15-3-3 3-3"/></symbol>'
          '<symbol id="i-panel-open" viewBox="0 0 24 24"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M9 3v18"/>'
          '<path d="m14 9 3 3-3 3"/></symbol></svg>')


def icon(name: str) -> str:
    return f'<svg class="icon" aria-hidden="true" focusable="false"><use href="#i-{e(name)}"/></svg>' if name else ""


# Кто вошёл — для строки внизу колонки; ставит Site._user на время запроса.
CURRENT_USER: contextvars.ContextVar[str] = contextvars.ContextVar("admin_user", default="")


def page(title: str, body: str, refresh: int | None = None, nav: list[tuple] | None = None,
         active: str = "", head: str = "") -> web.Response:
    """Общий каркас. nav — разделы (href, подпись, иконка) — только для вошедшего; head — свои <link>/<script src>.

    Без nav (вход, пароль) — карточка по центру экрана без шапки. Разметка шапки одна на оба режима, как у
    базовом интерфейсе и базовом приложении: на узком экране — полоса сверху и лента разделов, от 1100 px — колонка слева (admin.css)."""
    meta = f'<meta http-equiv="refresh" content="{refresh}">' if refresh else ""
    links = "".join(f'<link rel="stylesheet" href="/static/{name}?v={ASSET_V}">' for name in BRAND_CSS)
    top, main_cls, body_cls = "", ' class="solo"', ""
    if nav:
        items = "".join(
            f'<a class="nav-item" href="{e(href)}" title="{e(label)}"{" aria-current=page" if href == active else ""}>'
            f'{icon(ico)}<span class="nav-label">{e(label)}</span></a>'
            for href, label, *rest in nav for ico in [rest[0] if rest else ""])
        who = CURRENT_USER.get()
        account = (f'<div class="account"><span class="user" title="{e(who)}">{e(who)}</span>'
                   f'<form method="post" action="/logout"><button type="submit" class="bare icon-only" aria-label="Выйти" '
                   f'title="Выйти">{icon("logout")}</button></form></div>')
        top = (f'{SPRITE}<header class="topbar"><div class="topbar-row">'
               f'<a class="brand" href="/" aria-label="Админка, на главную">{LOGO}'
               f'<span class="brand-title">Админка</span></a><div class="topbar-right">'
               f'<button type="button" class="bare theme-toggle" aria-label="Сменить тему" title="Сменить тему">'
               f'{ICON_SUN}{ICON_MOON}<span class="nav-label">Сменить тему</span></button>{account}</div></div>'
               f'<nav class="sections" aria-label="Разделы админки">{items}</nav>'
               f'<button type="button" class="bare nav-toggle" aria-expanded="true" aria-label="Свернуть панель" '
               f'title="Свернуть панель">{icon("panel-close")}<span class="nav-label">Свернуть</span></button></header>')
        main_cls, body_cls = "", ' class="shell"'
    return web.Response(content_type="text/html", charset="utf-8", text=f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#0B2348" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#E6E8EB" media="(prefers-color-scheme: light)">{meta}<title>{e(title)}</title>
{links}<script src="/static/theme.js?v={ASSET_V}"></script>{head}</head>
<body{body_cls}>{top}<main{main_cls}>{body}</main></body></html>""")


def auth_card(title: str, inner: str, note: str = "") -> str:
    """Карточка входа/пароля: логотип, заголовок, содержимое, служебная подсказка снизу."""
    note_html = f'<div class="note">{note}</div>' if note else ""
    return f'<section class="card narrow auth">{LOGO}<h1>{title}</h1>{inner}{note_html}</section>'


def plural(n: int, one: str, few: str, many: str) -> str:
    n10, n100 = n % 10, n % 100
    if n10 == 1 and n100 != 11:
        return one
    if 2 <= n10 <= 4 and not 12 <= n100 <= 14:
        return few
    return many


TONE_WORD = {"ok": "в порядке", "warn": "внимание", "bad": "сбой"}


def tone_of(check: dict) -> str:
    if check.get("ok"):
        return "ok"
    return "bad" if check.get("severity") == "fail" else "warn"


def capital(text: str) -> str:
    """Названия действий в белом списке — со строчной («перезапустить …»), на кнопке — с заглавной."""
    return text[:1].upper() + text[1:]


def badge(tone: str, text: str | None = None) -> str:
    return f'<span class="badge {tone}">{e(text or TONE_WORD.get(tone, tone))}</span>'


def ago(ts: float | None) -> str:
    if not ts:
        return "—"
    s = time.time() - ts
    if s < 90:
        return "только что"
    if s < 3600:
        return f"{s/60:.0f} мин назад"
    if s < 86400 * 2:
        return f"{s/3600:.0f} ч назад"
    return f"{s/86400:.0f} дн. назад"


def iso_ago(value: str | None) -> str:
    if not value:
        return "—"
    try:
        return ago(dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return e(value)


class Site:
    def __init__(self, s: Settings, store: Store, auth: Auth,
                 on_login_request: Callable[[dict], Awaitable[None]]):
        self.s, self.store, self.auth = s, store, auth
        self.on_login_request = on_login_request
        from admin import pages
        self.pages = pages.load()

    # ------------------------------------------------------------ служебное
    def _same_origin(self, request: web.Request) -> bool:
        origin = request.headers.get("Origin")
        if origin in (self.s.public_url, f"http://127.0.0.1:{self.s.listen_port}"):
            return True
        # Sec-Fetch-Site ставит сам браузер, страница подделать его не может
        return origin in (None, "null") and request.headers.get("Sec-Fetch-Site") == "same-origin"

    def _cookie(self, resp: web.StreamResponse, name: str, value: str, max_age: int, path: str = "/") -> None:
        resp.set_cookie(name, value, max_age=max_age, path=path, httponly=True, secure=True, samesite="Strict")

    def _user(self, request: web.Request) -> dict | None:
        user = self.auth.session(request.cookies.get(COOKIE))
        CURRENT_USER.set(str((user or {}).get("email") or ""))
        return user

    # ------------------------------------------------------------ для подключаемых страниц
    @property
    def nav(self) -> list[tuple[str, str]]:
        return [(*m.NAV, getattr(m, "ICON", "")) for m in self.pages]

    def require_user(self, request: web.Request) -> dict:
        user = self._user(request)
        if not user:
            raise web.HTTPSeeOther("/login")
        return user

    def check_origin(self, request: web.Request) -> None:
        if not self._same_origin(request):
            raise web.HTTPForbidden(text="чужой источник запроса")

    def page(self, title: str, body: str, active: str = "", head: str = "", refresh: int | None = None) -> web.Response:
        return page(title, body, refresh=refresh, nav=self.nav, active=active, head=head)

    # ------------------------------------------------------------ вход
    async def login_form(self, request: web.Request, error: str = "") -> web.Response:
        err = f'<p class="err" role="alert">{e(error)}</p>' if error else ""
        return page(f"Вход — {BRAND}", auth_card("Вход в админку", f"""{err}
<form method="post" action="/login">
<label class="field"><span>Почта</span><input name="email" type="email" autocomplete="username" autocapitalize="none" spellcheck="false" required></label>
<label class="field"><span>Пароль</span><input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit" class="primary wide">Войти</button></form>""",
            "<p>После пароля подтвердите вход кнопкой в боте.</p>"
            "<p>Нет пароля — напишите боту <code>/password</code>.</p>"))

    async def login(self, request: web.Request) -> web.Response:
        if not self._same_origin(request):
            raise web.HTTPForbidden(text="чужой источник запроса")
        form = await request.post()
        email, password = str(form.get("email", ""))[:200], str(form.get("password", ""))[:500]
        ip = client_ip(request)
        if self.auth.locked(email.strip().lower(), ip):
            return await self.login_form(request, "Слишком много попыток. Подождите 15 минут.")
        ok = await asyncio.to_thread(self.auth.check_password, email, password, ip)
        if not ok:
            return await self.login_form(request, "Неверная почта или пароль.")
        token = self.auth.new_pending(email, ip, request.headers.get("User-Agent", ""))
        await self.on_login_request(self.auth.pending(token) or {})
        resp = web.HTTPSeeOther("/login/wait")
        self._cookie(resp, WAIT_COOKIE, token, 300, "/login")
        raise resp

    async def login_wait(self, request: web.Request) -> web.Response:
        token = request.cookies.get(WAIT_COOKIE)
        p = self.auth.pending(token)
        if not p:
            return page("Вход", auth_card("Время вышло", '<p>Подтверждение не пришло за 5 минут.</p>'
                                          '<div class="actions-row"><a class="btn primary wide" href="/login">Войти снова</a></div>'))
        if p["state"] == "denied":
            return page("Вход", auth_card("Вход отклонён", '<p>Запрос отклонили кнопкой в боте.</p>'
                                          '<div class="actions-row"><a class="btn wide" href="/login">Назад</a></div>'))
        if p["state"] == "ok":
            session = self.auth.finish(token or "")
            resp = web.HTTPSeeOther("/")
            if session:
                self._cookie(resp, COOKIE, session, 30 * 86400)
            resp.del_cookie(WAIT_COOKIE, path="/login")
            raise resp
        return page("Подтвердите вход", auth_card(
            "Подтвердите в Telegram",
            '<p>Бот боте прислал кнопку «Разрешить».</p>'
            '<p class="waiting" role="status"><span class="dot" aria-hidden="true"></span>Жду подтверждения — '
            'страница обновится сама</p>'), refresh=3)

    async def setup_form(self, request: web.Request, error: str = "") -> web.Response:
        err = f'<p class="err" role="alert">{e(error)}</p>' if error else ""
        return page(f"Пароль — {BRAND}", auth_card("Новый пароль", f"""{err}
<form method="post" action="/setup" id="setup">
<input type="hidden" name="code" id="code">
<label class="field"><span>Почта</span><input type="email" name="email" autocomplete="username" value="{e(self.s.owner_email)}" readonly></label>
<label class="field"><span>Пароль <span class="hint">· не короче 12 символов</span></span><input name="password" type="password" autocomplete="new-password" required minlength="12"></label>
<label class="field"><span>Ещё раз</span><input name="password2" type="password" autocomplete="new-password" required minlength="12"></label>
<button type="submit" class="primary wide">Сохранить пароль</button></form>""",
            "<p>Ссылка одноразовая и живёт 15 минут. Все прежние входы закроются.</p>")
            + '<script src="/static/setup.js"></script>')

    async def setup(self, request: web.Request) -> web.Response:
        if not self._same_origin(request):
            raise web.HTTPForbidden(text="чужой источник запроса")
        form = await request.post()
        pw, pw2 = str(form.get("password", ""))[:500], str(form.get("password2", ""))[:500]
        if pw != pw2:
            return await self.setup_form(request, "Пароли не совпадают. Попросите новую ссылку: /password")
        problem = await asyncio.to_thread(self.auth.use_setup_code, str(form.get("code", ""))[:100], pw)
        if problem:
            return await self.setup_form(request, problem)
        raise web.HTTPSeeOther("/login")

    async def logout(self, request: web.Request) -> web.Response:
        if not self._same_origin(request):
            raise web.HTTPForbidden(text="чужой источник запроса")
        form = await request.post()
        if form.get("all") == "1" and self._user(request):
            self.auth.logout_all()
        else:
            self.auth.logout(request.cookies.get(COOKIE))
        resp = web.HTTPSeeOther("/login")
        resp.del_cookie(COOKIE, path="/")
        raise resp

    # ------------------------------------------------------------ действия
    async def home(self, request: web.Request) -> web.Response:
        raise web.HTTPSeeOther("/dashboard")

    async def healthz(self, request: web.Request) -> web.Response:
        return web.Response(text="ok")

    def app(self) -> web.Application:
        app = web.Application(middlewares=[security_headers], client_max_size=64 * 1024)
        app.add_routes([
            web.get("/", self.home),
            web.get("/login", self.login_form),
            web.post("/login", self.login),
            web.get("/login/wait", self.login_wait),
            web.get("/setup", self.setup_form),
            web.post("/setup", self.setup),
            web.post("/logout", self.logout),
            web.get("/healthz", self.healthz),
            web.static("/static", STATIC, follow_symlinks=False),
        ])
        for m in self.pages:
            app.add_routes(m.routes(self))
        return app
