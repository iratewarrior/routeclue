# RouteClue: инженерный план

Актуальное задание владельца, 2026-10-30. Этот документ имеет приоритет над
предыдущими предложениями о diagnostic-only alpha, интервью и проверке спроса.

## Результат

Полезная владельцу универсальная macOS утилита с GUI и CLI, затем публичный
GitHub repository `routeclue`. Без маркетинговой программы, интервью и метрик
удержания. Имя RouteClue принято; интерес других пользователей не является gate.

## Функции сохраняются

- `explain`, `doctor`, `status`: понятная диагностика DNS, маршрута, интерфейса
  и предполагаемой политики для host/IP/URL; факты отделены от предположений.
- Kill switch: явное включение/выключение, статус on/off/unknown и правила PF,
  не зависящие от фиксированного адреса VPN-сервера. Никаких гарантий анонимности.
- Восстановление/удаление корпоративных маршрутов и split DNS apply/remove.
- Config CLI и настройки GUI, явные Save/Apply, без автоматической смены сети.
- Snapshot/diff и verify с полезными кодами завершения и JSON.
- Ввод host/URL и явный Paste, отзывчивый интерфейс, сообщения об ошибках.

Диагностика не требует root. Изменения сети выполняются отдельным действием
через штатную авторизацию macOS. Kill switch не вырезать из CLI/GUI/package.
Автодемон, собственный VPN и облако не нужны. Profiles и дополнительные TCP/TLS/
HTTP probes — после рабочего базового набора, не блокируют переименование.

## Этап 1. Название и существующие возможности

Исполнитель работает в `разработка-2`, сохраняет незакоммиченные изменения.
Переименовать package/products/targets/imports в RouteClue, CLI `routeclue`,
app `RouteClue.app`, self-test `RouteClueSelfTest`; Scripts, CI, bundle metadata,
README/help/version должны совпадать. Не переименовывать старые PF anchors или
resolver-файлы автоматически. Existing config: read-only fallback старого
Application Support/TunnelGuard при отсутствии нового config; явное сохранение
в RouteClue, без потери/перезаписи старого файла. Ошибка JSON не превращается
в молчаливый defaults с последующей перезаписью. Миграцию покрыть temp-dir тестами.

## Этап 2. Исправить подтверждённые дефекты

- Общий parser BSD netstat: Flags/Netif/Expire, короткие CIDR, host routes,
  link# gateways. Строгие IPv4/CIDR и DNS nameservers, без compactMap-пропусков.
  Route health проверяет ожидаемые gateway/interface, не только scoped flag.
- PF validation fail closed по exit status/ошибке запуска. Anchor должен быть
  достижим из активного ruleset; неизвестный статус нельзя показывать как on.
  Не заменять глобальные правила, не вызывать глобальный pfctl -d/flush.
  Проверить ownership и reference tokens; повторное on/off идемпотентно.
  Если нельзя доказать безопасное включение — вернуть конкретную ошибку,
  а не успешный результат. Проверить PF/config inputs и staging.
- Сохранить root bypass и последствия существующих states как явные ограничения.
  IPv6 policy не выдавать за полноценное управление IPv6 routes.
- Батчи routes/DNS не скрывают ошибки; quote всех shell arguments; приватные
  уникальные staging; удаление resolver-файлов только с ясным ownership.
- explain: tunnel traffic не объявляется blocked по direct allowlist; фактический
  source socket не подменяется адресом интерфейса. IPv6 resolver не обрезается.
- verify/diff не падают на дублях, required subnet учитывается вне config,
  required zone сверяется с реальным scoped resolver. Unknown не равно pass.
- GUI: явный Paste, debounced/coalesced refresh, перечитывание config,
  ошибки Heal All не теряются; kill switch доступен и правдиво отражает unknown.

## Этап 3. Проверка и GitHub

Применить [VALIDATION_PLAN.md](VALIDATION_PLAN.md). Координатор независимо
проверяет diff и сборки, принимает или возвращает исправления исполнителю.
Рабочую сеть/PF/etc/resolver пользователя при автоматических тестах не менять.
Интеграцию kill switch проверять на отдельной машине/изолированном стенде;
без такой проверки не объявлять защиту доказанной. Остальной инструмент можно
публиковать с честным статусом experimental и конкретными ограничениями.

После приёмки: README RU/EN, примеры синтетических адресов, install/uninstall,
MIT LICENSE, CHANGELOG, SECURITY, CONTRIBUTING, CI и source release. GitHub
публикация разрешена владельцем; учётная запись по текущему gh auth — iratewarrior.
Перед созданием проверить `iratewarrior/routeclue`; чужой repo не перезаписывать.
Не выкладывать логи, рабочие config, credentials, локальные agent IDs и черновики
исследования. Документы оркестрации не обязаны входить в публичную ветку.
