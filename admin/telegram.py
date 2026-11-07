"""Минимальный клиент Bot API: отправка, правка, кнопки, длинный опрос.

Токен не попадает ни в журнал, ни в текст исключений: адрес собирается здесь, а
ошибки aiohttp, где он мог бы оказаться, заменяются своим текстом.
"""

from __future__ import annotations

import asyncio
import json
import logging

import aiohttp

log = logging.getLogger("admin.telegram")


class TelegramError(Exception):
    pass


Button = tuple[str, str]          # (надпись, callback_data ≤ 64 байт)


def keyboard(rows: list[list[Button]]) -> dict:
    return {"inline_keyboard": [[{"text": t, "callback_data": d} for t, d in row] for row in rows if row]}


class Bot:
    def __init__(self, token: str, chat_id: int, dry_run: bool = False):
        self._base = f"https://api.telegram.org/bot{token}/"
        self.chat_id = chat_id
        self.dry_run = dry_run or not token
        self._http: aiohttp.ClientSession | None = None

    async def _session(self) -> aiohttp.ClientSession:
        if self._http is None or self._http.closed:
            self._http = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=70))
        return self._http

    async def close(self) -> None:
        if self._http:
            await self._http.close()

    async def call(self, method: str, **params) -> dict | list | bool:
        if self.dry_run and method not in ("getUpdates",):
            log.info("dry-run %s %s", method, json.dumps(params, ensure_ascii=False)[:500])
            return {"message_id": 0}
        http = await self._session()
        payload = {k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in params.items() if v is not None}
        try:
            async with http.post(self._base + method, data=payload) as r:
                body = await r.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            raise TelegramError(f"{method}: сеть ({type(exc).__name__})") from None
        if not body.get("ok"):
            raise TelegramError(f"{method}: {body.get('description', 'ошибка')}")
        return body["result"]

    async def send(self, text: str, buttons: list[list[Button]] | None = None, chat_id: int | None = None) -> int:
        res = await self.call("sendMessage", chat_id=chat_id or self.chat_id, text=text[:4000], parse_mode="HTML",
                              disable_web_page_preview="true",
                              reply_markup=keyboard(buttons) if buttons else None)
        return int(res.get("message_id", 0)) if isinstance(res, dict) else 0

    async def send_document(self, filename: str, data: bytes, caption: str = "", chat_id: int | None = None) -> int:
        """Файл в чат (по умолчанию — владельца). multipart: aiohttp сам собирает форму."""
        if self.dry_run:
            log.info("dry-run sendDocument %s (%d байт)", filename, len(data))
            return 0
        form = aiohttp.FormData()
        form.add_field("chat_id", str(chat_id or self.chat_id))
        form.add_field("caption", caption[:1000])
        form.add_field("parse_mode", "HTML")
        form.add_field("document", data, filename=filename, content_type="application/zip")
        http = await self._session()
        try:
            async with http.post(self._base + "sendDocument", data=form) as r:
                body = await r.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            raise TelegramError(f"sendDocument: сеть ({type(exc).__name__})") from None
        if not body.get("ok"):
            raise TelegramError(f"sendDocument: {body.get('description', 'ошибка')}")
        return int(body["result"].get("message_id", 0))

    async def send_photo(self, filename: str, data: bytes, caption: str = "", chat_id: int | None = None) -> int:
        """Картинка с подписью (без HTML: подпись пересылают человеку как есть)."""
        if self.dry_run:
            log.info("dry-run sendPhoto %s (%d байт)", filename, len(data))
            return 0
        form = aiohttp.FormData()
        form.add_field("chat_id", str(chat_id or self.chat_id))
        form.add_field("caption", caption[:1000])
        form.add_field("photo", data, filename=filename, content_type="image/png")
        http = await self._session()
        try:
            async with http.post(self._base + "sendPhoto", data=form) as r:
                body = await r.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
            raise TelegramError(f"sendPhoto: сеть ({type(exc).__name__})") from None
        if not body.get("ok"):
            raise TelegramError(f"sendPhoto: {body.get('description', 'ошибка')}")
        return int(body["result"].get("message_id", 0))

    async def edit(self, message_id: int, text: str, buttons: list[list[Button]] | None = None) -> None:
        if not message_id:
            return
        try:
            await self.call("editMessageText", chat_id=self.chat_id, message_id=message_id, text=text[:4000],
                            parse_mode="HTML", disable_web_page_preview="true",
                            reply_markup=keyboard(buttons) if buttons else {"inline_keyboard": []})
        except TelegramError as exc:
            if "not modified" not in str(exc):
                log.warning("правка сообщения %s: %s", message_id, exc)

    async def answer(self, callback_id: str, text: str = "") -> None:
        try:
            await self.call("answerCallbackQuery", callback_query_id=callback_id, text=text[:190])
        except TelegramError as exc:
            log.warning("answerCallbackQuery: %s", exc)

    async def updates(self, offset: int) -> list[dict]:
        res = await self.call("getUpdates", offset=offset, timeout=50,
                              allowed_updates=["message", "callback_query"])
        return res if isinstance(res, list) else []
