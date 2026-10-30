# RouteClue: техническая приёмка

Обновлено 2026-10-30 по прямому уточнению владельца. Интервью, пилоты и
метрики спроса отменены. Этот документ — проверки работоспособности.
Основной scope: [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

## Сборка и CLI

- `swift build -c release` и `swift run -c release RouteClueSelfTest`.
- `Scripts/build-app.sh release` создаёт `dist/RouteClue.app`.
- CLI `routeclue --help`, ошибки аргументов и JSON соответствуют документации.
- Kill switch, routes, DNS и config команды остаются доступны; root operations
  не вызываются запуском приложения или командой диагностики.

## Регрессии

- Реалистичные netstat fixtures: Flags/Netif/Expire, host/short CIDR/scoped,
  несколько интерфейсов, неверный gateway и link#.
- Строгие subnet/zone/nameserver/PF inputs и безопасный shell quoting.
- Ненулевой PF validation, недоступный pfctl и неизвестный anchor не дают успех.
- Идемпотентный план on/off, enable-token lifecycle, отсутствие глобального
  pf disable/flush/перезаписи ruleset.
- Ошибка route add или DNS copy останавливает пакет и доходит до UI/CLI.
- Дубли snapshot/policy не вызывают crash; unknown не превращается в pass.
- IPv6 resolver и routes parsing без обрезания адреса; ограничения указаны.
- Config migration тестируется в temp directory, повреждённый JSON сохраняется.
- Экспорт без secrets из URL, credentials и произвольного stderr.

## GUI

Ручной ввод/Paste, объяснение результата, kill switch toggle с честным unknown,
маршруты/DNS, refresh без параллельного шторма, ошибки операций, snapshot/diff.
Проверить доступность управления без установки config вручную и без зависания.
Находки фиксируются по наблюдаемому поведению, а не по числу нарисованных окон.

## Сетевые проверки

Unit/integration checks не меняют рабочую сеть, PF и /etc/resolver пользователя.
TCP/TLS/HTTP, если реализованы, тестируются локальными fixture servers:
success/refused/timeout, плохой сертификат, 403, redirect без follow,
IPv6 и отмена. Страна/репутация IP не выводятся из одного HTTP-кода.

PF enforcement требует отдельного стенда: до/после fingerprint чужих правил,
проверка счетчиков anchor, user/root IPv4/IPv6, tunnel up/down, существующие
states, repeated on/off. Пока не выполнено — явно unverified, без обещания
«никаких утечек». Не выдавать dry-run и генерацию текста за такую проверку.

## Публикация

Проверены README install/uninstall, LICENSE, CHANGELOG, SECURITY, CI и отсутствие
секретов/локальных логов. Документирована реально проверенная macOS/архитектура.
Подписанный/notarized GUI binary публикуем как рекомендованный только при
проверенной подписи; иначе source/CLI experimental release с честным статусом.
Публичный GitHub не зависит от количества пользователей или звёзд.
