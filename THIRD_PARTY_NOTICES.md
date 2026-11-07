# Сторонние компоненты

Лицензия MIT этого проекта относится к собственному коду VPN Stack. Она не заменяет лицензии перечисленных ниже проектов.

## Включённые SVG-иконки

Спрайт интерфейса содержит иконки [Lucide](https://github.com/lucide-icons/lucide). Их исходная лицензия и уведомления для иконок, производных от Feather, сохранены без изменений в [licenses/lucide.txt](licenses/lucide.txt).

Источник уведомления: [официальный LICENSE Lucide](https://raw.githubusercontent.com/lucide-icons/lucide/main/LICENSE). Lucide использует ISC; для перечисленных в этом файле иконок Feather также сохранено уведомление MIT.

Бинарные файлы шрифтов в публичный комплект не входят. Интерфейс использует системные шрифты.

## Зависимости, устанавливаемые отдельно

Эти проекты не включены в виде бинарных архивов. Установите их отдельно и соблюдайте условия соответствующих версий:

| Компонент | Официальный проект |
| --- | --- |
| Xray-core | [XTLS/Xray-core](https://github.com/XTLS/Xray-core) |
| Hysteria | [HyNetworks/hysteria](https://github.com/HyNetworks/hysteria) |
| Telemt | [telemt/telemt](https://github.com/telemt/telemt) |
| Caddy | [caddyserver/caddy](https://github.com/caddyserver/caddy) |
| aiohttp | [aio-libs/aiohttp](https://github.com/aio-libs/aiohttp) |
| PyYAML | [yaml/pyyaml](https://github.com/yaml/pyyaml) |

Python, OpenSSL, OpenSSH, nftables, systemd, polkit и qrencode также поставляются отдельно средствами вашей системы. Геобазы и правила не включены в этот экспорт; при их отдельной загрузке учитывайте лицензию выбранного источника.

Ссылки на установку Happ в странице подписки ведут на внешние площадки. Само приложение Happ не является частью этого репозитория.
