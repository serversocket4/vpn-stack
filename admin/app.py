"""Один процесс: бот (длинный опрос) и страница (127.0.0.1) за Caddy.

Бот слушает только владельца: сообщение или нажатие из другого чата молча отбрасывается. Кнопки несут только номер
задания, а что делать, решает код. Упавшие службы VPN поднимает сам systemd (Restart=always), тревоги шлёт bvpn-health.
"""

from __future__ import annotations

import asyncio
import html
import logging
import re

from aiohttp import web

from admin.auth import Auth
from admin.config import CONF, Settings
from admin.store import Store
from admin.telegram import Bot, TelegramError
from admin.traffic import PERIODS, traffic_view
from admin.vpn import RELAY_SERVER, Vpn
from admin.monitor import Monitor
from admin.web import Site

log = logging.getLogger("admin")
e = html.escape
# Меню команд бота (кнопка «Меню» в Telegram). Ставится при каждом старте службы.
COMMANDS = [
    ("vpn", "VPN: сервер и посредник коротко"),
    ("stats", "Трафик по пользователям: 24 часа, 7 и 30 дней"),
    ("relay", "Посредник в РФ: состояние, проверка"),
    ("relayhelp", "Посредник отлетел — что делать с телефона"),
    ("link", "Адрес админки"),
    ("password", "Задать пароль админки"),
    ("logout_all", "Закрыть все входы в админку"),
    ("help", "Что умеет бот"),
]
HELP = (f"{CONF['brand']}: сюда приходят тревоги и подтверждения.\n"
        "/vpn — сервер и посредник коротко\n/stats — расход трафика по пользователям\n"
        "/relay — посредник в РФ; /relay IP ПАРОЛЬ — заменить на новый сервер; "
        "/relayhelp — посредник отлетел: что делать\n/link — адрес админки\n/password — задать пароль админки\n"
        "/logout_all — закрыть все входы в админку")


class App:
    def __init__(self, s: Settings):
        self.s = s
        s.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(s.db_path)
        self.bot = Bot(s.bot_token, s.chat_id, s.dry_run)
        self.auth = Auth(self.store, s.owner_email)
        self.site = Site(s, self.store, self.auth, self.on_login_request)
        self.vpn = Vpn(s, self.store, lambda: self.bot)
        self.site.vpn = self.vpn
        self.monitor = Monitor(s, self.vpn)
        self.site.monitor = self.monitor

    # ------------------------------------------------------------ вход на страницу
    async def on_login_request(self, pending: dict) -> None:
        if not pending:
            return
        text = (f"🔐 Вход в админку\nпочта: {e(pending['email'])}\nадрес: {e(pending['ip'])}\n"
                f"браузер: {e(pending['ua'][:120])}\n\nЕсли это не вы — «Отклонить» и смените пароль (/password).")
        try:
            mid = await self.bot.send(text, [[("✅ Разрешить", f"login:{pending['rid']}:ok"),
                                              ("⛔ Отклонить", f"login:{pending['rid']}:no")]])
            self.store.x("UPDATE pending_logins SET message_id=? WHERE rowid=?", mid, pending["rid"])
        except TelegramError as exc:
            log.warning("запрос входа не отправлен: %s", exc)

    # ------------------------------------------------------------ бот
    def _from_owner(self, chat_id: int, user_id: int) -> bool:
        return chat_id == self.s.chat_id and (self.s.chat_id < 0 or user_id == self.s.chat_id)

    async def handle_message(self, msg: dict) -> None:
        if not self._from_owner(msg.get("chat", {}).get("id", 0), msg.get("from", {}).get("id", 0)):
            return
        cmd = (msg.get("text") or "").split()[0].split("@")[0] if msg.get("text") else ""
        if cmd in ("/start", "/help"):
            await self.bot.send(e(HELP))
        elif cmd == "/vpn":
            await self.bot.send(self.vpn.summary_text())
        elif cmd in ("/stats", "/статс"):
            words = (msg.get("text") or "").split()
            period = words[1].lower() if len(words) > 1 else "30d"
            if len(words) > 2 or period not in PERIODS:
                await self.bot.send("Трафик: /stats или /stats 24h, /stats 7d, /stats 30d.")
            else:
                text, buttons = traffic_view(self.vpn.panel(), self.vpn.people(), period)
                await self.bot.send(text, buttons)
        elif cmd == "/relay":
            words = (msg.get("text") or "").split()
            arg, pw = (words + ["", ""])[1], " ".join(words[2:])
            if pw:                                  # a root password: off the chat history at once
                try:
                    await self.bot.call("deleteMessage", chat_id=msg["chat"]["id"], message_id=msg["message_id"])
                except Exception:  # noqa: BLE001
                    await self.bot.send("⚠️ Не смог удалить сообщение с паролем — удалите его сами.")
            if arg:
                _, why = await self.vpn.relay_set(arg, "владелец", pw)
                if why:
                    await self.bot.send(e(why))
            else:
                await self.bot.send(self.vpn.relay_text(), [[("🔎 Проверить посредник", "vpnrelay:check")],
                                                            [("🆘 Посредник отлетел", "vpnrelay:help")]])
        elif cmd == "/relayhelp":
            await self.bot.send(self.vpn.relay_help())
        elif cmd == "/link":
            await self.bot.send(f"Админка: {e(self.s.public_url)}")
        elif cmd == "/password":
            code = self.auth.new_setup_code()
            await self.bot.send(f"Ссылка, чтобы задать пароль (одноразовая, 15 минут):\n"
                                f"{e(self.s.public_url)}/setup#{code}\n\nПосле — удалите это сообщение.")
        elif cmd == "/logout_all":
            n = self.auth.logout_all()
            await self.bot.send(f"Закрыто входов в админку: {n}.")

    async def handle_callback(self, cb: dict) -> None:
        msg = cb.get("message") or {}
        if not self._from_owner(msg.get("chat", {}).get("id", 0), cb.get("from", {}).get("id", 0)):
            return
        data = cb.get("data") or ""
        answer = ""
        try:
            if m := re.fullmatch(r"vpnstats:(24h|7d|30d):(\d{1,4})", data):
                text, buttons = traffic_view(self.vpn.panel(), self.vpn.people(), m.group(1), int(m.group(2)))
                await self.bot.edit(msg.get("message_id", 0), text, buttons)
            elif data == "vpnrelay:help":
                await self.bot.send(self.vpn.relay_help())
            elif data == "vpnrelay:check":
                jid, why = await self.vpn.quick("relay-check", RELAY_SERVER, "бот")
                answer = "Проверяю посредник, итог придёт сюда." if jid else why
            elif m := re.fullmatch(r"vpn:(go|no):([a-f0-9]{12})", data):
                answer = await self.vpn.decide(m.group(2), m.group(1) == "go", cb.get("from", {}).get("id", 0),
                                               msg.get("message_id", 0))
            elif m := re.fullmatch(r"vpn:(keep|back):([a-f0-9]{12})", data):
                answer = await self.vpn.answer_pending(m.group(2), m.group(1) == "keep", cb.get("from", {}).get("id", 0),
                                                       msg.get("message_id", 0))
            elif m := re.fullmatch(r"login:(\d+):(ok|no)", data):
                row = self.auth.decide(int(m.group(1)), m.group(2) == "ok")
                answer = ("Вход разрешён." if m.group(2) == "ok" else "Вход отклонён.") if row else "Запрос устарел."
                await self.bot.edit(msg.get("message_id", 0), (msg.get("text") or "")[:3500] + f"\n\n{answer}")
            else:
                answer = "Неизвестная кнопка."
        finally:
            await self.bot.answer(cb.get("id", ""), answer)

    async def set_menu(self) -> None:
        try:
            await self.bot.call("setMyCommands", commands=[{"command": c, "description": d} for c, d in COMMANDS])
            await self.bot.call("setChatMenuButton", menu_button={"type": "commands"})
        except TelegramError as exc:
            log.warning("меню команд не поставлено: %s", exc)

    async def poll_bot(self) -> None:
        if not self.s.bot_token:
            log.warning("TELEGRAM_BOT_TOKEN не задан — бот не слушает")
            return
        await self.set_menu()
        offset = int(self.store.get("tg_offset", 0))
        while True:
            try:
                for upd in await self.bot.updates(offset):
                    offset = max(offset, upd["update_id"] + 1)
                    self.store.put("tg_offset", offset)
                    try:
                        if "callback_query" in upd:
                            await self.handle_callback(upd["callback_query"])
                        elif "message" in upd:
                            await self.handle_message(upd["message"])
                    except Exception:  # noqa: BLE001 — одна плохая кнопка не должна ронять бота
                        log.exception("обработка обновления %s", upd.get("update_id"))
            except TelegramError as exc:
                log.warning("getUpdates: %s", exc)
                await asyncio.sleep(10)

    # ------------------------------------------------------------ циклы
    async def vpn_loop(self) -> None:
        while True:
            try:
                await self.vpn.poll()
            except Exception:  # noqa: BLE001
                log.exception("опрос VPN")
            await asyncio.sleep(30)

    async def monitor_loop(self) -> None:
        while True:
            try:
                self.monitor.ingest()
                await self.monitor.notify(self.bot)
            except Exception:
                log.exception("опрос мониторинга")
            await asyncio.sleep(15)

    async def run(self) -> None:
        runner = web.AppRunner(self.site.app(), access_log=None)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", self.s.listen_port).start()
        log.info("страница на 127.0.0.1:%s", self.s.listen_port)
        try:
            await asyncio.gather(self.vpn_loop(), self.poll_bot(), self.monitor_loop())
        finally:
            await self.bot.close()
            await runner.cleanup()
            self.monitor.close()
