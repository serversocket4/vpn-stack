"""Authenticated monitoring dashboard; measurement and history live in site.monitor."""
from __future__ import annotations

import hashlib
from pathlib import Path

from aiohttp import web

NAV = ("/dashboard", "Дашборд")
ICON = "activity"
RANGES = ("1h", "6h", "24h", "7d", "30d")


def _version() -> str:
    static = Path(__file__).resolve().parents[1] / "static"
    digest = hashlib.sha256()
    for name in ("dashboard.js", "dashboard.css"):
        try:
            digest.update((static / name).read_bytes())
        except OSError:
            pass
    return digest.hexdigest()[:10]


def render() -> str:
    return '''<div class="dash" id="monitor-dashboard">
  <header class="dash-header">
    <div><p class="dash-eyebrow">Состояние сети</p><h1>Мониторинг VPN</h1>
      <div class="dash-live"><span class="dash-status unknown" id="dash-status">Получаем данные</span><span id="dash-freshness">Первый снимок ещё не получен</span></div>
    </div>
    <div class="dash-tools"><a class="dash-link" href="#monitor-settings">Настройки уведомлений</a><button class="dash-button" id="dash-refresh" type="button"><span aria-hidden="true">↻</span> Обновить</button></div>
  </header>
  <div class="dash-banner" id="dash-error" role="alert" hidden></div>
  <div class="dash-banner warn" id="dash-stale" role="status" hidden>Сборщик не прислал свежий снимок. Ниже показаны последние известные значения.</div>
  <section class="dash-toolbar" aria-label="Период истории">
    <div class="dash-ranges" role="group" aria-label="Период графиков">
      <button type="button" data-range="1h" aria-pressed="false">1 час</button><button type="button" data-range="6h" aria-pressed="false">6 часов</button><button type="button" data-range="24h" aria-pressed="true">24 часа</button><button type="button" data-range="7d" aria-pressed="false">7 дней</button><button type="button" data-range="30d" aria-pressed="false">30 дней</button>
    </div>
    <div class="dash-toolbar-meta"><label class="dash-auto-control" for="dash-auto-refresh">Обновление экрана<select id="dash-auto-refresh"><option value="0">Вручную</option><option value="1" selected>1 секунда</option><option value="5">5 секунд</option><option value="15">15 секунд</option><option value="30">30 секунд</option><option value="60">60 секунд</option></select></label><span class="dash-auto-note" id="dash-auto-note">Сбор данных: каждые 60 с</span><span class="dash-history-note" id="dash-history-note">История накапливается с момента запуска мониторинга</span></div>
  </section>
  <section class="dash-kpis" aria-label="Общие показатели">
    <article class="card dash-kpi"><span class="dash-kpi-label">VPN-каналы</span><strong id="kpi-channels">—</strong><span id="kpi-channels-note">Ожидаем проверку четырёх каналов</span></article>
    <article class="card dash-kpi"><span class="dash-kpi-label">Пользователи в сети</span><strong id="kpi-users">—</strong><span id="kpi-users-note">По соединениям и недавнему трафику</span></article>
    <article class="card dash-kpi"><span class="dash-kpi-label">Сеть NL</span><strong id="kpi-network">—</strong><span id="kpi-network-note">Вход / выход, Мбит/с</span></article>
    <article class="card dash-kpi"><span class="dash-kpi-label">Открытые инциденты</span><strong id="kpi-incidents">—</strong><span id="kpi-incidents-note">Подтверждённые проверками</span></article>
  </section>

  <section class="dash-section" aria-labelledby="hosts-title"><div class="dash-section-head"><h2 id="hosts-title">Серверы и ресурсы</h2><span class="dash-note">Снимок с каждого VPS</span></div><div class="dash-hosts" id="dash-hosts"><div class="card dash-empty">Ждём данные российского и нидерландского серверов.</div></div></section>

  <section class="dash-section" aria-labelledby="channels-title"><div class="dash-section-head"><div><h2 id="channels-title">Качество подключения</h2><p class="dash-note" id="dash-scope">Проверки со стороны серверов. Путь от вашего устройства до RU проверяется отдельно.</p></div></div><div class="dash-channels" id="dash-channels"><div class="card dash-empty">Первый запрос через VPN ещё не выполнен.</div></div><div class="dash-path-checks" id="dash-path-checks"></div></section>

  <section class="dash-charts" aria-label="История показателей">
    <article class="card dash-chart-card"><div class="dash-chart-head"><div><h2>Задержка каналов</h2><p class="dash-note">Полный запрос через VPN, мс</p></div><label class="dash-select"><span class="sr-only">Канал графика задержки</span><select id="dash-probe"><option value="primary">Основной</option><option value="backup1">Запасной 1</option><option value="backup2">Запасной 2</option><option value="backup3">Запасной 3</option><option value="ru_nl">RU → NL</option><option value="nl_exit">Выход NL</option></select></label></div><div class="dash-chart-summary"><strong id="latency-current">—</strong><span id="latency-range">История пока пуста</span></div><div class="dash-chart" id="dash-latency-chart" role="img" aria-label="График задержки: данные пока не получены"></div><div class="dash-chart-footer"><span><i class="dash-key latency"></i>Задержка</span><span id="dash-threshold">Порог уведомления: 3000 мс</span></div></article>
    <article class="card dash-chart-card"><div class="dash-chart-head"><div><h2>Скорость сети</h2><p class="dash-note">Сетевой интерфейс, Мбит/с</p></div><label class="dash-select"><span class="sr-only">Сервер графика трафика</span><select id="dash-host"><option value="nl">Нидерланды</option><option value="ru">Россия</option></select></label></div><div class="dash-chart-summary"><strong id="throughput-current">—</strong><span id="throughput-range">История пока пуста</span></div><div class="dash-chart" id="dash-throughput-chart" role="img" aria-label="График скорости сети: данные пока не получены"></div><div class="dash-chart-footer"><span><i class="dash-key rx"></i>Входящий</span><span><i class="dash-key tx"></i>Исходящий</span><span>Пропуски — нет измерений</span></div></article>
    <article class="card dash-chart-card"><div class="dash-chart-head"><div><h2>Сетевые повторы и ошибки</h2><p class="dash-note">Пик за один серверный замер; RU не учитывает весь транзит через NAT</p></div></div><div class="dash-chart-summary"><strong id="quality-current">—</strong><span id="quality-range">История начнёт накапливаться после обновления</span></div><div class="dash-chart" id="dash-quality-chart" role="img" aria-label="График сетевых повторов и ошибок: данных пока нет"></div><div class="dash-chart-footer"><span><i class="dash-key latency"></i>Повторы TCP</span><span><i class="dash-key rx"></i>Отброшено при приёме</span><span><i class="dash-key tx"></i>Отброшено при отправке</span></div></article>
  </section>

  <section class="dash-bottom-grid">
    <article class="card dash-people"><div class="dash-section-head"><div><h2>Трафик пользователей</h2><p class="dash-note">Приём + передача по профилям</p></div><label class="dash-select"><span class="sr-only">Период трафика пользователей</span><select id="dash-people-period"><option value="24h">За 24 часа</option><option value="7d">За 7 дней</option><option value="30d" selected>За 30 дней</option></select></label></div><div class="dash-table-wrap"><table class="dash-table"><thead><tr><th scope="col">Пользователь</th><th scope="col">Статус</th><th scope="col" class="dash-numeric">Трафик</th></tr></thead><tbody id="dash-people-body"><tr><td colspan="3" class="dash-empty">Ждём снимок учёта.</td></tr></tbody></table></div><p class="dash-note dash-table-note">Учёт с момента включения статистики. Один профиль на нескольких устройствах считается вместе.</p></article>
    <article class="card dash-events"><div class="dash-section-head"><div><h2>События и сбои</h2><p class="dash-note" id="dash-events-period">За выбранный период и открытые</p></div><span class="dash-count" id="dash-events-count">—</span></div><ol class="dash-event-list" id="dash-events"><li class="dash-empty">События появятся после первых проверок.</li></ol></article>
  </section>

  <details class="card dash-settings" id="monitor-settings"><summary><span><strong>Настройки мониторинга</strong><small>Пороги и уведомления в Telegram</small></span><span class="dash-chevron" aria-hidden="true">⌄</span></summary><form id="dash-settings-form"><div class="dash-settings-grid"><label>Порог задержки, мс<input name="latency_ms" type="number" min="100" max="60000" step="100" value="3000" required><small>Тревога о длительном ухудшении</small></label><label>Проверок с высокой задержкой подряд<input name="latency_checks" type="number" min="1" max="10" value="2" required><small>Одиночный скачок не создаёт событие</small></label><label>Неудачных проверок до сбоя<input name="failure_checks" type="number" min="1" max="10" value="3" required><small>Подтверждение недоступности канала</small></label><label>Успешных проверок до восстановления<input name="recovery_checks" type="number" min="1" max="10" value="2" required><small>Защита от повторяющихся уведомлений</small></label></div><label class="dash-checkbox"><input name="alerts_enabled" type="checkbox" checked><span>Присылать сбои, восстановление и длительную задержку в Telegram</span></label><div class="dash-settings-actions"><button type="submit" class="dash-button primary">Сохранить настройки</button><span id="dash-settings-result" role="status" aria-live="polite"></span></div><p class="dash-note" id="dash-refresh-help">Интервал обновления экрана выбирается сверху. Данные поступают по расписанию сборщика. Настройки относятся к мониторингу.</p></form></details>
  <p class="dash-note dash-probe-account" id="dash-probe-account">Активные проверки используют отдельный технический профиль «Мониторинг». Его служебный трафик исключён из пользовательской статистики.</p>
  <footer class="dash-footer"><span id="dash-collection-note">История хранится 30 дней.</span><a href="/vpn">Управление VPN и подписками →</a></footer>
</div>'''


def routes(site) -> list[web.RouteDef]:
    def monitor():
        value = getattr(site, "monitor", None)
        if value is None:
            raise web.HTTPServiceUnavailable(text="Мониторинг ещё не подключён")
        return value

    def api_user(request):
        user = site._user(request)
        if not user:
            raise web.HTTPUnauthorized(content_type="application/json", text='{"error":"Требуется вход"}')
        return user

    async def index(request):
        site.require_user(request)
        version = _version()
        head = (f'<link rel="stylesheet" href="/static/dashboard.css?v={version}">'
                f'<script src="/static/dashboard.js?v={version}" defer></script>')
        return site.page("Мониторинг VPN", render(), active="/dashboard", head=head)

    async def data(request):
        api_user(request)
        period = request.query.get("range", "24h")
        if period not in RANGES:
            return web.json_response({"error": "Неизвестный период истории"}, status=400)
        return web.json_response(monitor().view(period))

    async def settings(request):
        site.check_origin(request)
        user = api_user(request)
        try:
            values = await request.json()
            if not isinstance(values, dict):
                raise ValueError("Параметры должны быть объектом")
            updated = monitor().update_settings(values, str(user.get("email") or "owner"))
        except (ValueError, TypeError) as exc:
            return web.json_response({"error": str(exc)}, status=400)
        return web.json_response({"ok": True, "settings": updated})

    return [web.get("/dashboard", index), web.get("/api/monitoring", data),
            web.post("/api/monitoring/settings", settings)]
