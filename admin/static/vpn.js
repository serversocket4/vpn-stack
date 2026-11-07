/* VPN workspace: local navigation only. Server actions remain ordinary forms. */
(function () {
  'use strict';

  function ready(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

  ready(function () {
    function tick() {
      var now = Date.now() / 1000;
      document.querySelectorAll('.countdown[data-until]').forEach(function (el) {
        var left = Math.round(Number(el.getAttribute('data-until')) - now);
        if (!(left > 0)) { el.textContent = 'уже сейчас — обновите страницу'; return; }
        var m = Math.floor(left / 60), seconds = left % 60;
        el.textContent = 'через ' + m + ' мин ' + (seconds < 10 ? '0' : '') + seconds + ' с';
      });
    }
    tick();
    if (document.querySelector('.countdown[data-until]')) window.setInterval(tick, 1000);
  });

  ready(function () {
    var root = document.getElementById('vpn-workspace');
    if (!root) return;
    var topTabs = Array.from(root.querySelectorAll('[data-vpn-section]'));
    var topPanels = Array.from(root.querySelectorAll('[data-vpn-section-panel]'));
    if (!topPanels.length) topPanels = ['people', 'infrastructure', 'log'].map(function (key) { return document.getElementById('vpn-section-' + key); }).filter(Boolean);
    var peopleLinks = Array.from(root.querySelectorAll('[data-vpn-person]'));
    var personPanels = Array.from(root.querySelectorAll('[data-vpn-person-panel]'));
    var people = Object.create(null), panels = Object.create(null);
    peopleLinks.forEach(function (link) { people[link.getAttribute('data-vpn-person')] = link; });
    personPanels.forEach(function (panel) { panels[panel.getAttribute('data-vpn-person-panel')] = panel; });
    var storageKey = 'bvpn:vpn-workspace', saved = {}, state = { section: 'people', person: '', tabs: Object.create(null) };
    var sectionNames = ['people', 'infrastructure', 'log'], tabNames = ['access', 'routing', 'terms', 'traffic'];
    var mainTablist = root.querySelector('.vpn-workspace-tabs');
    if (mainTablist) mainTablist.setAttribute('role', 'tablist');
    root.querySelectorAll('.vpn-detail-tabs').forEach(function (nav) { nav.setAttribute('role', 'tablist'); });
    topTabs.forEach(function (tab) { tab.id = 'vpn-section-tab-' + tab.getAttribute('data-vpn-section'); });
    topPanels.forEach(function (panel) {
      panel.setAttribute('role', 'tabpanel');
      panel.setAttribute('aria-labelledby', 'vpn-section-tab-' + (panel.getAttribute('data-vpn-section-panel') || panel.id.replace('vpn-section-', '')));
    });
    try { saved = JSON.parse(window.localStorage.getItem(storageKey) || '{}') || {}; } catch (_) {}
    if (sectionNames.indexOf(saved.section) >= 0) state.section = saved.section;
    if (typeof saved.person === 'string' && people[saved.person] && panels[saved.person]) state.person = saved.person;
    if (!state.person && peopleLinks.length) state.person = peopleLinks[0].getAttribute('data-vpn-person');
    if (saved.tabs && typeof saved.tabs === 'object') peopleLinks.forEach(function (link) {
      var key = link.getAttribute('data-vpn-person');
      if (tabNames.indexOf(saved.tabs[key]) >= 0) state.tabs[key] = saved.tabs[key];
    });

    function save() {
      try { window.localStorage.setItem(storageKey, JSON.stringify(state)); } catch (_) {}
    }
    function scrollTo(el) {
      if (!el) return;
      var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      el.scrollIntoView({ block: 'start', behavior: reduce ? 'auto' : 'smooth' });
    }
    function topKey(el) { return el.getAttribute('data-vpn-section'); }
    function topPanelKey(el) { return el.getAttribute('data-vpn-section-panel') || el.id.replace('vpn-section-', ''); }
    function showSection(key, remember) {
      if (sectionNames.indexOf(key) < 0) return;
      state.section = key;
      topTabs.forEach(function (tab) {
        var active = topKey(tab) === key;
        tab.setAttribute('aria-selected', String(active));
        tab.setAttribute('role', 'tab');
        tab.tabIndex = active ? 0 : -1;
        tab.setAttribute('aria-controls', 'vpn-section-' + topKey(tab));
      });
      topPanels.forEach(function (panel) { panel.hidden = topPanelKey(panel) !== key; });
      if (remember) save();
    }
    function showDetailTab(panel, key, remember) {
      if (!panel) return;
      var available = Array.from(panel.querySelectorAll('[data-vpn-detail-tab]'));
      var content = Array.from(panel.querySelectorAll('[data-vpn-detail-panel]'));
      if (!available.some(function (tab) { return tab.getAttribute('data-vpn-detail-tab') === key; })) key = 'access';
      var person = panel.getAttribute('data-vpn-person-panel');
      state.tabs[person] = key;
      available.forEach(function (tab) {
        var active = tab.getAttribute('data-vpn-detail-tab') === key;
        tab.setAttribute('role', 'tab'); tab.setAttribute('aria-selected', String(active)); tab.tabIndex = active ? 0 : -1;
        var target = content.find(function (el) { return el.getAttribute('data-vpn-detail-panel') === tab.getAttribute('data-vpn-detail-tab'); });
        if (target) tab.setAttribute('aria-controls', target.id);
      });
      content.forEach(function (el) { el.hidden = el.getAttribute('data-vpn-detail-panel') !== key; });
      if (remember) save();
    }
    var stack = root.querySelector('.vpn-detail-stack');
    var selectionEmpty = document.createElement('p');
    selectionEmpty.className = 'card vpn-selection-empty'; selectionEmpty.textContent = 'По этому запросу пользователей нет.'; selectionEmpty.hidden = true;
    if (stack) stack.appendChild(selectionEmpty);
    function choosePerson(key, options) {
      options = options || {};
      if (!people[key] || !panels[key]) return;
      state.person = key;
      peopleLinks.forEach(function (link) {
        if (link.getAttribute('data-vpn-person') === key) link.setAttribute('aria-current', 'true');
        else link.removeAttribute('aria-current');
      });
      personPanels.forEach(function (panel) { panel.hidden = panel.getAttribute('data-vpn-person-panel') !== key; });
      selectionEmpty.hidden = true;
      showDetailTab(panels[key], state.tabs[key] || 'access', false);
      if (options.remember) save();
      if (options.scroll && window.matchMedia && window.matchMedia('(max-width: 700px)').matches) scrollTo(panels[key]);
    }

    var search = document.getElementById('vpn-search');
    var roster = root.querySelector('.vpn-roster-list');
    var empty = root.querySelector('[data-vpn-search-empty]') || document.createElement('p');
    empty.className = 'vpn-search-empty'; empty.setAttribute('role', 'status'); empty.textContent = 'Никого не найдено. Измените запрос.'; empty.hidden = true;
    if (!empty.parentNode && roster && roster.parentNode) roster.parentNode.insertBefore(empty, roster.nextSibling);
    function filterPeople() {
      var query = search ? search.value.trim().toLowerCase() : '';
      var matches = [];
      peopleLinks.forEach(function (link) {
        var entry = link.closest('.vpn-roster-entry') || link;
        var haystack = (entry.getAttribute('data-search') || link.getAttribute('data-search') || link.textContent).toLowerCase();
        var shown = !query || haystack.indexOf(query) >= 0;
        entry.hidden = !shown;
        if (shown) matches.push(link.getAttribute('data-vpn-person'));
      });
      root.querySelectorAll('.vpn-roster-group').forEach(function (heading) {
        var next = heading.nextElementSibling, visible = false;
        while (next && !next.classList.contains('vpn-roster-group')) {
          if (next.matches('.vpn-roster-entry') && !next.hidden) visible = true;
          next = next.nextElementSibling;
        }
        heading.hidden = !visible;
      });
      empty.hidden = matches.length > 0 || peopleLinks.length === 0;
      if (!matches.length) {
        personPanels.forEach(function (panel) { panel.hidden = true; });
        selectionEmpty.hidden = peopleLinks.length === 0;
      } else choosePerson(matches.indexOf(state.person) >= 0 ? state.person : matches[0]);
    }

    root.addEventListener('click', function (event) {
      var tab = event.target.closest('[data-vpn-section]');
      if (tab && root.contains(tab)) { event.preventDefault(); showSection(topKey(tab), true); return; }
      var person = event.target.closest('[data-vpn-person]');
      if (person && root.contains(person)) { event.preventDefault(); choosePerson(person.getAttribute('data-vpn-person'), { remember: true, scroll: true }); return; }
      var detailTab = event.target.closest('[data-vpn-detail-tab]');
      if (detailTab && root.contains(detailTab)) { event.preventDefault(); showDetailTab(detailTab.closest('[data-vpn-person-panel]'), detailTab.getAttribute('data-vpn-detail-tab'), true); return; }
      var add = event.target.closest('[data-vpn-add]');
      if (add && root.contains(add)) {
        event.preventDefault(); showSection('people', true);
        var form = document.getElementById('vpn-add-person');
        if (form) { form.open = true; scrollTo(form); var input = form.querySelector('input[name="name"]'); if (input) input.focus({ preventScroll: true }); }
      }
    });
    root.addEventListener('keydown', function (event) {
      var top = event.target.closest('[data-vpn-section]'), detail = event.target.closest('[data-vpn-detail-tab]');
      var current = top || detail;
      if (!current || ['ArrowLeft', 'ArrowRight', 'Home', 'End'].indexOf(event.key) < 0) return;
      var tabs = top ? topTabs : Array.from(detail.closest('[data-vpn-person-panel]').querySelectorAll('[data-vpn-detail-tab]'));
      var i = tabs.indexOf(current), index = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (i + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      event.preventDefault(); tabs[index].focus();
      if (top) showSection(topKey(tabs[index]), true);
      else showDetailTab(detail.closest('[data-vpn-person-panel]'), tabs[index].getAttribute('data-vpn-detail-tab'), true);
    });
    /* Reveal the first invalid control before native validation focuses it.
       This matters because one settings form deliberately spans two local tabs. */
    var firstInvalid = null;
    root.addEventListener('invalid', function (event) {
      if (firstInvalid) return;
      firstInvalid = event.target;
      window.setTimeout(function () { firstInvalid = null; }, 0);
      var person = event.target.closest('[data-vpn-person-panel]');
      var detail = event.target.closest('[data-vpn-detail-panel]');
      if (person) {
        showSection('people', false);
        choosePerson(person.getAttribute('data-vpn-person-panel'));
        if (detail) showDetailTab(person, detail.getAttribute('data-vpn-detail-panel'), false);
      } else {
        var section = event.target.closest('[data-vpn-section-panel]');
        if (section) showSection(topPanelKey(section), false);
      }
      var parent = event.target.parentElement;
      while (parent && parent !== root) { if (parent.tagName === 'DETAILS') parent.open = true; parent = parent.parentElement; }
    }, true);
    if (search) search.addEventListener('input', filterPeople);
    root.classList.add('vpn-enhanced');
    showSection(state.section, false);
    personPanels.forEach(function (panel) { showDetailTab(panel, state.tabs[panel.getAttribute('data-vpn-person-panel')] || 'access', false); });
    if (state.person) choosePerson(state.person);
    filterPeople();
  });

  /* One-shot subscription page: neither URL nor clipboard content enters storage. */
  ready(function () {
    var button = document.getElementById('vpn-copy'), field = document.getElementById('vpn-link');
    if (!button || !field) return;
    button.addEventListener('click', function () {
      var url = button.getAttribute('data-url');
      function done() { button.textContent = 'Скопировано'; window.setTimeout(function () { button.textContent = 'Скопировать'; }, 2000); }
      function select() { field.focus(); field.select(); }
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(url).then(done, select);
      else { select(); if (document.execCommand('copy')) done(); }
    });
  });
})();
