"""Подключаемые страницы админки (вкладки). Каждый модуль даёт:

    NAV = ("/путь", "Название вкладки")
    ICON = "имя"                             # иконка раздела из web.SPRITE (Lucide)
    def routes(site) -> list[web.RouteDef]   # site — admin.web.Site: s, store, auth, require_user(), page()

Обработчики сами зовут `site.require_user(request)` (редирект на вход) и рисуют через
`site.page(title, body, active="/путь")`. POST — только после `site.check_origin(request)`.
Подключение — строкой в MODULES ниже.
"""

from __future__ import annotations

import importlib

MODULES: list[str] = ["dashboard", "vpn"]


def load():
    return [importlib.import_module(f"admin.pages.{m}") for m in MODULES]
