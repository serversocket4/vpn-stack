// Тема и колонка разделов. Тема — по системе (prefers-color-scheme), ручной выбор — атрибут data-theme
// на <html>, он главнее системы (как в базовом приложении и базовом интерфейсе). Свёрнутая колонка — data-nav="collapsed".
// Файл подключён в <head> без defer, чтобы выбор ставился до отрисовки и страница не мигала.
// Inline-скрипты запрещены CSP, поэтому всё здесь, а кнопки находятся по классу.
(function () {
  var KEY = "bvpn-admin:theme", NAV = "bvpn-admin:nav";
  var root = document.documentElement;
  try {
    var saved = localStorage.getItem(KEY);
    if (saved === "light" || saved === "dark") root.setAttribute("data-theme", saved);
    if (localStorage.getItem(NAV) === "collapsed") root.setAttribute("data-nav", "collapsed");
  } catch (e) {}

  function label(btn, text) {
    btn.setAttribute("aria-label", text);
    btn.title = text;
    var span = btn.querySelector(".nav-label");
    if (span) span.textContent = text;
  }

  function wireTheme() {
    var btn = document.querySelector(".theme-toggle");
    if (!btn) return;
    var media = window.matchMedia("(prefers-color-scheme: light)");
    function current() {
      return root.getAttribute("data-theme") || (media.matches ? "light" : "dark");
    }
    // Кнопка называет тему, на которую переключит; иконку меняет CSS.
    function sync() { label(btn, current() === "light" ? "Тёмная тема" : "Светлая тема"); }
    btn.addEventListener("click", function () {
      root.setAttribute("data-theme", current() === "light" ? "dark" : "light");
      try { localStorage.setItem(KEY, root.getAttribute("data-theme")); } catch (e) {}
      sync();
    });
    if (media.addEventListener) media.addEventListener("change", sync);
    sync();
  }

  function wireNav() {
    var btn = document.querySelector(".nav-toggle");
    if (!btn) return;
    function sync() {
      var collapsed = root.getAttribute("data-nav") === "collapsed";
      btn.setAttribute("aria-expanded", collapsed ? "false" : "true");
      label(btn, collapsed ? "Развернуть панель" : "Свернуть панель");
      btn.querySelector(".nav-label").textContent = collapsed ? "Развернуть" : "Свернуть";
      btn.querySelector("use").setAttribute("href", collapsed ? "#i-panel-open" : "#i-panel-close");
    }
    btn.addEventListener("click", function () {
      if (root.getAttribute("data-nav") === "collapsed") root.removeAttribute("data-nav");
      else root.setAttribute("data-nav", "collapsed");
      try { localStorage.setItem(NAV, root.getAttribute("data-nav") || "open"); } catch (e) {}
      sync();
    });
    sync();
  }

  function wire() { wireTheme(); wireNav(); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", wire);
  else wire();
})();
