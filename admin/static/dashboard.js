/* Authenticated, read-only dashboard polling plus explicit monitoring settings. */
(function () {
  'use strict';
  var root = document.getElementById('monitor-dashboard');
  if (!root) return;
  var ranges = { '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800, '30d': 2592000 };
  var channelIds = ['primary', 'backup1', 'backup2', 'backup3'];
  var channelNames = { primary: 'Основной', backup1: 'Запасной 1', backup2: 'Запасной 2', backup3: 'Запасной 3' };
  var protocolNames = { primary: 'Hysteria2 · смена UDP-порта', backup1: 'VLESS · TCP / TLS', backup2: 'Hysteria2 · UDP / 443', backup3: 'VLESS · XHTTP / REALITY' };
  var currentRange = '24h', currentData = null, controller = null, settingsDirty = false;
  var autoIntervals = [0, 1, 5, 15, 30, 60], autoSeconds = 1, autoTimer = null, requestActive = false;
  try { if (ranges[localStorage.getItem('bvpn:monitor-range')]) currentRange = localStorage.getItem('bvpn:monitor-range'); } catch (_) {}
  try { var savedRefresh = localStorage.getItem('bvpn:monitor-refresh'); if (savedRefresh !== null && autoIntervals.indexOf(Number(savedRefresh)) >= 0) autoSeconds = Number(savedRefresh); } catch (_) {}

  function $(id) { return document.getElementById(id); }
  function node(tag, cls, text) { var n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = String(text); return n; }
  function put(id, text) { $(id).textContent = text; }
  function numeric(value) { return typeof value === 'number' && Number.isFinite(value); }
  function number(value, digits) { return numeric(value) ? value.toLocaleString('ru-RU', { maximumFractionDigits: digits === undefined ? 1 : digits }) : '—'; }
  function percent(value) { return numeric(value) ? Math.max(0, Math.min(100, value)) : null; }
  function bytes(value) { if (!numeric(value)) return 'нет данных'; if (!value) return '0 Б'; var units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'], i = Math.min(4, Math.max(0, Math.floor(Math.log(Math.max(1, value)) / Math.log(1024)))); return number(value / Math.pow(1024, i), i > 1 ? 2 : 0) + ' ' + units[i]; }
  function latency(value) { return numeric(value) ? number(value, 0) + ' мс' : '—'; }
  function epoch(value) { if (numeric(value)) return value; var result = Date.parse(value); return Number.isFinite(result) ? result / 1000 : null; }
  function date(value, options) { var t = epoch(value); return t === null ? '—' : new Date(t * 1000).toLocaleString('ru-RU', Object.assign({ timeZone: 'Europe/Moscow' }, options)); }
  function ago(value, now) { var t = epoch(value); if (t === null) return 'нет времени'; var s = Math.max(0, (numeric(now) ? now : Date.now() / 1000) - t); if (s < 60) return 'только что'; if (s < 3600) return Math.floor(s / 60) + ' мин назад'; if (s < 86400) return Math.floor(s / 3600) + ' ч назад'; return Math.floor(s / 86400) + ' дн назад'; }
  function tone(value) { return { healthy: 'ok', up: 'ok', success: 'ok', degraded: 'warn', slow: 'warn', pending: 'warn', down: 'bad', error: 'bad', unavailable: 'bad' }[value] || (['ok', 'warn', 'bad', 'unknown'].indexOf(value) >= 0 ? value : 'unknown'); }
  function state(item, stale) { return stale ? 'unknown' : tone(item.status || (item.ok === true ? 'ok' : item.ok === false ? 'warn' : 'unknown')); }
  function stateText(item, stale) { if (stale) return 'Нет свежих данных'; if (item.state_label) return item.state_label; if (item.pending_failures) return 'Неудачных: ' + item.pending_failures; return { ok: 'Работает', warn: 'Ухудшение', bad: 'Недоступно', unknown: 'Нет данных' }[state(item, false)]; }
  function stateNode(item, stale) { return node('span', 'dash-state ' + state(item, stale), stateText(item, stale)); }
  function empty(parent, text, tag) { parent.replaceChildren(node(tag || 'div', 'dash-empty', text)); }
  function mbit(value) { return number(value, numeric(value) && value > 0 && value < 0.1 ? 3 : numeric(value) && value < 1 ? 2 : numeric(value) && value < 10 ? 1 : 0); }

  function renderSummary(data) {
    var s = data.summary || {}, sample = data.sample || {}, probes = sample.probes || [];
    var isStale = Boolean(sample.at && sample.stale), status = isStale ? 'unknown' : tone(s.status);
    $('dash-status').className = 'dash-status ' + status;
    put('dash-status', isStale ? 'Данные устарели' : (s.label || 'Ожидаем первый снимок'));
    put('dash-freshness', sample.at ? 'Снимок ' + date(sample.at, { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' МСК · ' + ago(sample.at, data.now) : 'Первый снимок ещё не получен');
    $('dash-freshness').title = sample.at ? date(sample.at, { dateStyle: 'medium', timeStyle: 'medium' }) + ' МСК' : '';
    $('dash-stale').hidden = !isStale;
    var channels = probes.filter(function (p) { return channelIds.indexOf(p.id) >= 0; });
    var up = numeric(s.channels_up) ? s.channels_up : channels.filter(function (p) { return p.ok === true; }).length;
    var total = numeric(s.channels_total) ? s.channels_total : 4;
    put('kpi-channels', sample.at ? (isStale ? '—' : up) + ' / ' + total : '—');
    put('kpi-channels-note', isStale ? 'Последний снимок · данные устарели' : 'Запросы через RU → NL → интернет');
    var peopleAge = (data.meta || {}).people_age_s, peopleFresh = numeric(peopleAge) && peopleAge <= 600;
    put('kpi-users', numeric(s.online_users) && peopleFresh ? s.online_users + ' / ' + number(s.users || 0, 0) : '— / ' + number(s.users || 0, 0));
    put('kpi-users-note', numeric(peopleAge) ? (peopleFresh ? 'Снимок учёта: ' : 'Учёт устарел: ') + (peopleAge < 60 ? 'только что' : Math.floor(peopleAge / 60) + ' мин назад') : 'Свежий снимок учёта ещё не получен');
    put('kpi-network', numeric(s.rx_mbps) || numeric(s.tx_mbps) ? mbit(s.rx_mbps) + ' / ' + mbit(s.tx_mbps) : '—');
    put('kpi-incidents', numeric(s.open_incidents) ? number(s.open_incidents, 0) : '—');
    $('kpi-incidents').parentElement.classList.toggle('has-incident', s.open_incidents > 0);
    put('kpi-incidents-note', s.open_incidents > 0 ? 'Подтверждены несколькими проверками' : sample.at ? 'Нет подтверждённых открытых сбоев' : 'Ожидаем первые проверки');
    var meta = data.meta || {}, start = meta.available_from || meta.started_at;
    put('dash-history-note', start ? 'История с ' + date(start, { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) + ' МСК' : 'История начнёт накапливаться после первого снимка');
    put('dash-collection-note', 'История: ' + (meta.retention_days || 30) + ' дней · шаг проверок ' + (meta.interval_s || 60) + ' с');
    put('dash-scope', meta.probe_scope || 'Проверки со стороны серверов. Путь от вашего устройства до RU проверяется отдельно.');
    put('dash-threshold', 'Порог уведомления: ' + latency((data.settings || {}).latency_ms || 3000));
    refreshCaption();
  }

  function metric(label, value, hint, unit) {
    var box = node('div', 'dash-metric'), labelEl = node('div', 'dash-metric-title', label), strong = node('div', 'dash-metric-value');
    strong.appendChild(document.createTextNode(number(value, 0)));
    if (numeric(value)) strong.appendChild(node('small', '', unit || '%'));
    var progress = node('progress', 'dash-meter'); progress.max = 100; progress.setAttribute('aria-label', label);
    if (numeric(value)) { progress.value = percent(value); if (value >= 95) progress.classList.add('bad'); else if (value >= 85) progress.classList.add('warn'); }
    else { progress.value = 0; progress.setAttribute('aria-valuetext', 'Нет данных'); }
    box.append(labelEl, strong, progress, node('p', 'dash-metric-hint', hint));
    return box;
  }

  function renderHosts(data) {
    var parent = $('dash-hosts'), sample = data.sample || {}, hosts = sample.hosts || [];
    if (!hosts.length) { empty(parent, 'Ждём данные российского и нидерландского серверов.'); return; }
    parent.replaceChildren();
    hosts.slice().sort(function (a, b) { return (a.id === 'ru' ? 0 : 1) - (b.id === 'ru' ? 0 : 1); }).forEach(function (host) {
      var card = node('article', 'card dash-host'), top = node('div', 'dash-host-top'), identity = node('div', 'dash-host-name');
      identity.appendChild(node('span', 'dash-host-flag', host.id === 'ru' ? '🇷🇺' : '🇳🇱'));
      var name = node('div'); name.append(node('h3', '', host.title || (host.id === 'ru' ? 'Россия' : 'Нидерланды')), node('div', 'dash-host-address', host.ip || 'Адрес не получен'));
      identity.appendChild(name); top.append(identity, stateNode(host, sample.stale));
      var m = host.metrics || {}, memory = numeric(m.mem_total_mb) && m.mem_total_mb > 0 && numeric(m.mem_available_mb) ? 100 * (1 - m.mem_available_mb / m.mem_total_mb) : null;
      var metrics = node('div', 'dash-host-metrics');
      metrics.append(metric('Процессор', m.cpu_pct, 'Load ' + number(m.load1, 2) + ' · ' + number(m.cpus, 0) + ' CPU'), metric('Память', memory, numeric(m.mem_available_mb) ? number(m.mem_available_mb, 0) + ' МБ доступно' : 'Нет данных о памяти'), metric('Диск', m.disk_pct, 'Использовано на системном диске'));
      var facts = node('div', 'dash-host-facts');
      [['↓ Вход', mbit(m.rx_mbps) + ' Мбит/с'], ['↑ Выход', mbit(m.tx_mbps) + ' Мбит/с'], ['Повторы TCP', number(m.tcp_retrans_delta, 0)], ['Steal CPU', number(m.steal_pct, 1) + (numeric(m.steal_pct) ? '%' : '')]].forEach(function (p) { var f = node('span', '', p[0] + ' '); f.appendChild(node('b', '', p[1])); facts.appendChild(f); });
      var services = node('div', 'dash-services'); (host.services || []).forEach(function (service) { var active = service.active === true || service.active === 'active'; services.appendChild(node('span', 'dash-service ' + (active ? 'ok' : 'bad'), (active ? '✓ ' : '! ') + service.id)); });
      card.append(top, metrics, facts, services);
      if (host.error) card.appendChild(node('p', 'dash-host-error', host.error));
      var stamp = node('p', 'dash-note', host.at ? 'Снимок ' + ago(host.at, data.now) : 'Время снимка неизвестно'); card.appendChild(stamp);
      parent.appendChild(card);
    });
  }

  function renderChannels(data) {
    var sample = data.sample || {}, list = sample.probes || [], byId = {};
    list.forEach(function (p) { byId[p.id] = p; });
    var parent = $('dash-channels'); parent.replaceChildren();
    channelIds.forEach(function (id) {
      var p = byId[id] || { id: id, ok: null, status: 'unknown', state_label: 'Ждём проверку' }, t = state(p, sample.stale);
      var card = node('article', 'card dash-channel ' + t), top = node('div', 'dash-channel-top');
      top.append(node('h3', '', p.title || channelNames[id]), stateNode(p, sample.stale));
      var value = node('div', 'dash-latency'); value.appendChild(document.createTextNode(numeric(p.latency_ms) ? number(p.latency_ms, 0) : '—')); if (numeric(p.latency_ms)) value.appendChild(node('small', '', 'мс'));
      card.append(top, node('p', 'dash-channel-protocol', p.protocol || protocolNames[id]), value, node('p', 'dash-channel-scope', p.scope || 'Запрос через RU → NL → интернет'));
      if (p.resource_fallback) card.appendChild(node('p', 'dash-channel-error', 'Первая цель не ответила; время включает повторную проверку.'));
      if (p.error) card.appendChild(node('p', 'dash-channel-error', p.error));
      if (p.at) card.title = 'Последняя проверка: ' + date(p.at, { dateStyle: 'medium', timeStyle: 'medium' }) + ' МСК';
      parent.appendChild(card);
    });
    var paths = $('dash-path-checks'); paths.replaceChildren();
    ['ru_nl', 'nl_exit', 'telegram'].forEach(function (id) {
      var p = byId[id]; if (!p) return;
      var card = node('div', 'dash-path-check'), top = node('div', 'dash-path-top'), title = node('span', '', p.title || id);
      var right = node('span', 'dash-state ' + state(p, sample.stale));
      right.appendChild(node('strong', '', numeric(p.latency_ms) ? latency(p.latency_ms) : stateText(p, sample.stale)));
      top.append(title, right);
      card.append(top, node('p', '', p.scope || (id === 'telegram' ? 'TCP-доступность порта · без MTProto-проверки' : 'Проверка со стороны серверов')));
      if (numeric(p.loss_pct)) card.appendChild(node('p', '', 'Потери ICMP: ' + number(p.loss_pct, 0) + '%'));
      if (p.resource_fallback) card.appendChild(node('p', 'dash-channel-error', 'Первая цель не ответила; время включает повторную проверку.'));
      if (p.error) card.appendChild(node('p', 'dash-channel-error', p.error));
      paths.appendChild(card);
    });
  }

  var SVG = 'http://www.w3.org/2000/svg';
  function svg(tag, attrs, text) { var n = document.createElementNS(SVG, tag); Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, String(attrs[k])); }); if (text !== undefined) n.textContent = text; return n; }
  function plot(target, data, lines, label, unit, threshold) {
    var wrap = $(target), width = 600, height = 210, left = 49, right = 10, top = 15, bottom = 30;
    var end = numeric(data.now) ? data.now : Date.now() / 1000, start = end - (ranges[data.range] || ranges[currentRange]);
    var series = (data.series || []).filter(function (r) { return numeric(r.at) && r.at >= start && r.at <= end; }).sort(function (a, b) { return a.at - b.at; });
    var values = [], points = lines.map(function (line) { return series.map(function (r) { var v = line.get(r); if (numeric(v)) values.push(Math.max(0, v)); return { at: r.at, value: numeric(v) ? Math.max(0, v) : null, ok: line.ok ? line.ok(r) : true }; }); });
    var max = Math.max(unit === 'мс' ? 250 : 1, values.length ? Math.max.apply(null, values) * 1.18 : 0);
    var base = Math.pow(10, Math.floor(Math.log10(max))); max = Math.ceil(max / base * 2) / 2 * base;
    function x(t) { return left + (t - start) / (end - start) * (width - left - right); }
    function y(v) { return height - bottom - Math.min(max, v) / max * (height - top - bottom); }
    var picture = svg('svg', { viewBox: '0 0 ' + width + ' ' + height, preserveAspectRatio: 'none', 'aria-hidden': 'true' });
    [0, .5, 1].forEach(function (ratio) { var v = ratio * max, yy = y(v); picture.append(svg('line', { x1: left, x2: width - right, y1: yy, y2: yy, class: 'grid' }), svg('text', { x: left - 9, y: yy + 3, 'text-anchor': 'end' }, number(v, max < 10 ? 1 : 0))); });
    [0, .5, 1].forEach(function (ratio) { var t = start + ratio * (end - start); picture.appendChild(svg('text', { x: x(t), y: height - 7, class: 'axis-time', 'text-anchor': ratio === 0 ? 'start' : ratio === 1 ? 'end' : 'middle' }, date(t, ranges[data.range] > 86400 ? { day: '2-digit', month: '2-digit' } : { hour: '2-digit', minute: '2-digit' }))); });
    if (numeric(threshold) && threshold <= max) picture.appendChild(svg('line', { x1: left, x2: width - right, y1: y(threshold), y2: y(threshold), class: 'threshold' }));
    var interval = (data.meta || {}).bucket_s || (data.meta || {}).interval_s || 60;
    lines.forEach(function (line, index) {
      var segment = [], previous = null;
      function flush() { if (segment.length > 1) picture.appendChild(svg('polyline', { points: segment.join(' '), class: 'line ' + (line.cls || '') })); segment = []; }
      points[index].forEach(function (p) {
        if (p.value === null || (previous !== null && p.at - previous > interval * 2.5)) flush();
        if (p.value !== null) {
          segment.push(x(p.at).toFixed(2) + ',' + y(p.value).toFixed(2));
          var dot = svg('circle', { cx: x(p.at), cy: y(p.value), r: series.length < 80 ? 2.8 : 1.5, class: 'point ' + (line.cls || '') });
          dot.appendChild(svg('title', {}, date(p.at, { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) + ' МСК · ' + line.label + ': ' + number(p.value, unit === 'мс' ? 0 : 2) + ' ' + unit)); picture.appendChild(dot);
        } else if (p.ok === false) {
          var failure = svg('circle', { cx: x(p.at), cy: height - bottom, r: 3, class: 'failed' }); failure.appendChild(svg('title', {}, 'Неудачная проверка · ' + date(p.at, { hour: '2-digit', minute: '2-digit' }) + ' МСК')); picture.appendChild(failure);
        }
        previous = p.at;
      }); flush();
    });
    wrap.replaceChildren(picture);
    wrap.setAttribute('aria-label', label + '. ' + (values.length ? 'Измерений: ' + values.length + ', максимум ' + number(Math.max.apply(null, values), 1) + ' ' + unit : 'История пока пуста'));
    if (!values.length) wrap.appendChild(node('div', 'chart-empty', 'Пока недостаточно данных для графика. История начнёт появляться после первых проверок.'));
    return values;
  }

  function renderCharts(data) {
    var id = $('dash-probe').value, probe = ((data.sample || {}).probes || []).find(function (p) { return p.id === id; });
    var values = plot('dash-latency-chart', data, [{ label: 'Задержка', get: function (r) { return r.probes && r.probes[id] ? r.probes[id].latency_ms : null; }, ok: function (r) { return r.probes && r.probes[id] ? r.probes[id].ok : null; } }], 'История задержки ' + ($('dash-probe').selectedOptions[0] || {}).textContent, 'мс', (data.settings || {}).latency_ms);
    put('latency-current', probe ? latency(probe.latency_ms) : '—');
    put('latency-range', values.length ? 'Пик за период: ' + latency(Math.max.apply(null, values)) : 'История пока пуста');
    var host = $('dash-host').value, live = ((data.sample || {}).hosts || []).find(function (p) { return p.id === host; });
    var speeds = plot('dash-throughput-chart', data, [{ label: 'Входящий', cls: 'rx', get: function (r) { return r.hosts && r.hosts[host] ? r.hosts[host].rx_mbps : null; } }, { label: 'Исходящий', cls: 'tx', get: function (r) { return r.hosts && r.hosts[host] ? r.hosts[host].tx_mbps : null; } }], 'История сетевого трафика ' + ($('dash-host').selectedOptions[0] || {}).textContent, 'Мбит/с');
    var m = live && live.metrics || {};
    put('throughput-current', numeric(m.rx_mbps) || numeric(m.tx_mbps) ? '↓ ' + mbit(m.rx_mbps) + ' / ↑ ' + mbit(m.tx_mbps) : '—');
    put('throughput-range', speeds.length ? 'Пик: ' + mbit(Math.max.apply(null, speeds)) + ' Мбит/с' : 'История пока пуста');
    var quality = plot('dash-quality-chart', data, [{ label: 'Повторы TCP', get: function (r) { return r.hosts && r.hosts[host] ? r.hosts[host].tcp_retrans_delta : null; } }, { label: 'Отброшено при приёме', cls: 'rx', get: function (r) { return r.hosts && r.hosts[host] ? r.hosts[host].rx_dropped_delta : null; } }, { label: 'Отброшено при отправке', cls: 'tx', get: function (r) { return r.hosts && r.hosts[host] ? r.hosts[host].tx_dropped_delta : null; } }], 'История сетевых повторов и ошибок ' + ($('dash-host').selectedOptions[0] || {}).textContent, 'событий');
    put('quality-current', numeric(m.tcp_retrans_delta) ? 'Повторы TCP: ' + number(m.tcp_retrans_delta, 0) : '—');
    put('quality-range', quality.length ? 'Максимум за замер: ' + number(Math.max.apply(null, quality), 0) : 'История начнёт накапливаться после обновления');
  }

  function renderPeople(data) {
    var parent = $('dash-people-body'), period = $('dash-people-period').value;
    var people = (data.people || []).slice().sort(function (a, b) { var aa = (a.traffic || {})[period], bb = (b.traffic || {})[period]; if (!numeric(aa)) return numeric(bb) ? 1 : String(a.name || '').localeCompare(String(b.name || ''), 'ru'); if (!numeric(bb)) return -1; return bb - aa; });
    parent.replaceChildren();
    if (!people.length) { var tr = node('tr'), cell = node('td', 'dash-empty', 'В снимке пока нет пользовательской статистики.'); cell.colSpan = 3; tr.appendChild(cell); parent.appendChild(tr); return; }
    people.forEach(function (person) {
      var tr = node('tr'), identity = node('td'), value = (person.traffic || {})[period];
      identity.append(node('div', 'dash-person-name', person.name || person.id), node('span', 'dash-person-id', person.id || ''));
      var status = node('td'); status.appendChild(node('span', 'dash-state ' + (person.paused ? 'warn' : person.online ? 'ok' : 'unknown'), person.paused ? 'Пауза' : person.online ? 'Активен' : 'Не активен'));
      tr.append(identity, status, node('td', 'dash-numeric', (person.partial && numeric(value) ? '≥ ' : '') + bytes(value)));
      parent.appendChild(tr);
    });
  }

  function renderEvents(data) {
    var parent = $('dash-events'), events = (data.events || []).slice().sort(function (a, b) { return (epoch(b.at) || 0) - (epoch(a.at) || 0); });
    put('dash-events-count', number(events.length, 0)); put('dash-events-period', 'За выбранный период и открытые · ' + (data.range_label || currentRange));
    parent.replaceChildren();
    if (!events.length) { empty(parent, (data.meta || {}).available_from ? 'За доступную историю этого периода событий не было.' : 'События появятся после первых проверок.', 'li'); return; }
    events.slice(0, 50).forEach(function (event) {
      var li = node('li', 'dash-event ' + tone(event.severity)), content = node('div'), time = node('time', '', date(event.at, { hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit' }));
      var t = epoch(event.at); if (t !== null) time.dateTime = new Date(t * 1000).toISOString();
      time.title = date(event.at, { dateStyle: 'medium', timeStyle: 'medium' }) + ' МСК';
      content.appendChild(node('h3', '', event.title || 'Событие мониторинга'));
      if (event.detail) content.appendChild(node('p', '', event.detail));
      if (event.open) content.appendChild(node('span', 'dash-event-open', 'Открыт'));
      li.append(node('span', 'dash-event-marker'), content, time); parent.appendChild(li);
    });
  }

  function fillSettings(settings) {
    if (settingsDirty || !settings) return;
    var form = $('dash-settings-form');
    ['latency_ms', 'latency_checks', 'failure_checks', 'recovery_checks'].forEach(function (key) { if (numeric(settings[key])) form.elements[key].value = settings[key]; });
    form.elements.alerts_enabled.checked = settings.alerts_enabled !== false;
  }
  function render(data) { currentData = data; renderSummary(data); renderHosts(data); renderChannels(data); renderCharts(data); renderPeople(data); renderEvents(data); fillSettings(data.settings); }
  function setRange(value) { currentRange = ranges[value] ? value : '24h'; root.querySelectorAll('[data-range]').forEach(function (b) { b.setAttribute('aria-pressed', b.dataset.range === currentRange ? 'true' : 'false'); }); try { localStorage.setItem('bvpn:monitor-range', currentRange); } catch (_) {} }
  function refreshCaption() {
    var collection = currentData && currentData.meta && currentData.meta.interval_s || 60;
    put('dash-auto-note', 'Сбор данных: каждые ' + collection + ' с');
    put('dash-refresh-help', 'Обновление экрана: ' + (autoSeconds ? 'не чаще чем раз в ' + autoSeconds + ' с' : 'вручную') + '. Новые измерения поступают каждые ' + collection + ' с. Настройки относятся к мониторингу.');
  }
  function clearAutoTimer() { if (autoTimer !== null) { clearTimeout(autoTimer); autoTimer = null; } }
  function scheduleAuto() {
    clearAutoTimer();
    if (!autoSeconds || document.hidden || requestActive) return;
    autoTimer = setTimeout(function () { autoTimer = null; if (autoSeconds && !document.hidden) load(false); }, autoSeconds * 1000);
  }
  async function load(manual) {
    if (requestActive && !manual) return;
    clearAutoTimer();
    if (controller) controller.abort(); controller = new AbortController(); var request = controller;
    requestActive = true;
    var timeout = setTimeout(function () { request.abort(); }, 12000); $('dash-refresh').disabled = true; $('dash-refresh').setAttribute('aria-busy', 'true');
    try {
      var response = await fetch('/api/monitoring?range=' + encodeURIComponent(currentRange), { credentials: 'same-origin', cache: 'no-store', signal: request.signal, headers: { Accept: 'application/json' } });
      if (response.status === 401) { window.location.assign('/login'); return; }
      if (!response.ok) throw new Error('Мониторинг временно недоступен (' + response.status + ').');
      var data = await response.json(); if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Некорректный ответ мониторинга.');
      if (request !== controller) return;
      $('dash-error').hidden = true; render(data);
    } catch (error) {
      if (request !== controller) return;
      $('dash-error').textContent = error.name === 'AbortError' ? 'Обновление заняло слишком долго. Последний полученный снимок сохранён на экране.' : (error.message || 'Не удалось обновить мониторинг.');
      $('dash-error').hidden = false;
    } finally { clearTimeout(timeout); if (request === controller) { requestActive = false; controller = null; $('dash-refresh').disabled = false; $('dash-refresh').removeAttribute('aria-busy'); scheduleAuto(); } }
  }
  root.querySelectorAll('[data-range]').forEach(function (button) { button.addEventListener('click', function () { setRange(button.dataset.range); load(true); }); });
  $('dash-refresh').addEventListener('click', function () { load(true); });
  $('dash-auto-refresh').value = String(autoSeconds);
  $('dash-auto-refresh').addEventListener('change', function (event) {
    var selected = Number(event.currentTarget.value);
    autoSeconds = autoIntervals.indexOf(selected) >= 0 ? selected : 1;
    try { localStorage.setItem('bvpn:monitor-refresh', String(autoSeconds)); } catch (_) {}
    clearAutoTimer(); refreshCaption();
    if (autoSeconds && !document.hidden && !requestActive) load(false);
  });
  $('dash-probe').addEventListener('change', function () { if (currentData) renderCharts(currentData); });
  $('dash-host').addEventListener('change', function () { if (currentData) renderCharts(currentData); });
  $('dash-people-period').addEventListener('change', function () { if (currentData) renderPeople(currentData); });
  $('dash-settings-form').addEventListener('input', function () { settingsDirty = true; put('dash-settings-result', 'Есть несохранённые изменения'); $('dash-settings-result').className = ''; });
  $('dash-settings-form').addEventListener('submit', async function (event) {
    event.preventDefault(); var form = event.currentTarget, values = {}, button = form.querySelector('button[type=submit]');
    ['latency_ms', 'latency_checks', 'failure_checks', 'recovery_checks'].forEach(function (key) { values[key] = Number(form.elements[key].value); }); values.alerts_enabled = form.elements.alerts_enabled.checked;
    button.disabled = true; put('dash-settings-result', 'Сохраняем…'); $('dash-settings-result').className = '';
    try {
      var response = await fetch('/api/monitoring/settings', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(values) });
      if (response.status === 401) { window.location.assign('/login'); return; }
      var data = await response.json(); if (!response.ok || !data.ok) throw new Error(data.error || 'Не удалось сохранить настройки.');
      settingsDirty = false; fillSettings(data.settings); put('dash-settings-result', 'Настройки сохранены'); $('dash-settings-result').className = 'ok'; await load(true);
    } catch (error) { put('dash-settings-result', error.message || 'Ошибка сети. Повторите сохранение.'); $('dash-settings-result').className = 'bad'; }
    finally { button.disabled = false; }
  });
  setRange(currentRange); refreshCaption(); load(false);
  document.addEventListener('visibilitychange', function () {
    clearAutoTimer();
    if (!document.hidden && autoSeconds && !requestActive) load(false);
  });
})();
