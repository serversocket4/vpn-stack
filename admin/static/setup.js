// Секрет одноразовой ссылки стоит после «#»: браузер не шлёт его на сервер, и он не
// попадает в журналы. Переносим его в скрытое поле формы и стираем из адреса.
(function () {
  var code = location.hash.replace(/^#/, "");
  if (code) {
    document.getElementById("code").value = code;
    history.replaceState(null, "", location.pathname);
  }
})();
