# RouteClue Implementation Review (Ревизия 3)

**Дата:** 2026-10-30  
**Исполнитель:** Antigravity (разработка-2)  
**Координатор и приёмщик:** Codex  
**Статус:** Исправлены замечания код-ревью координатора по жизненному циклу PF, исключению гонок, тестам production script builders и санитизации данных. Готово к приёмке.

---

## 1. Резюме исправлений по замечаниям координатора

В ревизии 3 полностью устранены все выявленные race conditions, дефекты обработки ошибок в шелл-скриптах и примитивные моки:

1. **Ликвидация гонки (Race Condition) в KillSwitch `apply` и `disable`:**
   - **Устранение внешнего состояния:** Чтение `alreadyHasToken` и запись `saveToken` в Swift до и после блокировки полностью удалены. Все операции — проверка symlink, валидация active ruleset, проверка живого токена через `pfctl -s References`, получение нового токена через `/sbin/pfctl -E 2>&1`, атомарное сохранение токена с правами `0600`, загрузка правил анкера и компенсирующий откат — перенесены внутрь **единого root batch скрипта под единым мьютексом `$STATE_DIR/lock`**.
   - **Взаимное исключение `apply` и `disable`:** Скрипт `disable` выполняется под тем же самым файловым локом `$STATE_DIR/lock`. Параллельный запуск `apply` и `disable` гарантированно приводит к отказу второй операции с кодом `2` (`FAIL_LOCK`), исключая torn state и порчу токенов.
   - **Изоляция state каталога от пользовательского профиля:** Состояние фаервола хранится в выделенном каталоге `/var/run/routeclue` (mode `0700`, token mode `0600`). Пользовательский каталог `~/Library/Application Support/` никогда не создаётся и не модифицируется от root.
   - **Защита от подмены через Symlink:** До создания каталога или записи токена скрипты проверяют, не являются ли `$STATE_DIR` или `$TOKEN_FILE` символическими ссылками. При обнаружении symlink выполнение немедленно прерывается с кодом `8` (`FAIL_SYMLINK`).

2. **Атомарная запись токена и надежный компенсирующий откат:**
   - Вся цепочка сохранения токена (`echo "$NEW_TOKEN" > "$TMP_TOKEN" && chmod 600 "$TMP_TOKEN" && mv "$TMP_TOKEN" "$TOKEN_FILE"`) обёрнута в единый условный блок. Любой сбой (заполнение диска, права только на чтение, ошибка `mv`) не приводит к аварийному выходу по `set -e` до освобождения токена.
   - При сбое сохранения немедленно вызывается компенсирующий релиз `"$PFCTL" -X "$NEW_TOKEN"`.
   - Если компенсирующий релиз успешен, скрипт выводит `ROLLBACK_SUCCESS`. Если релиз завершился с ошибкой, скрипт выводит `ROLLBACK_FAILED` с выводом ошибки и **явной командой для ручного восстановления: `sudo pfctl -X <token>`**.

3. **Проверка актуальности токена через `pfctl -s References`:**
   - При обнаружении существующего файла токена скрипт не просто проверяет глобальный `Status: Enabled`, а запрашивает `pfctl -s References`.
   - Если токен отсутствует в активных ссылках ядра, токен признаётся устаревшим (`FAIL_STALE`, код `4`), исключая ложный reuse чужого или недействительного токена.

4. **Откат при ошибке загрузки правил (`FAIL_LOAD`):**
   - При ошибке загрузки правил (`pfctl -a <anchor> -f <rules>`):
     - Если токен был только что захвачен (`NEW_TOKEN` не пуст): правила анкера очищаются, выполняется релиз токена `"$PFCTL" -X "$NEW_TOKEN"`, и файл токена удаляется **только при успешном релизе**. Если релиз не удался, файл токена сохраняется для recovery.
     - Если использовался ранее существовавший токен (`REUSED_TOKEN`): существующие рабочие правила в анкере **не сбрасываются** (устранено безусловное `-F rules`), и токен сохраняется.

5. **Корректная обработка ошибок под `set -e` в `disable`:**
   - Вызовы командных подстановок `REL_OUT=$("$PFCTL" -X "$TOKEN" 2>&1)` больше не вызывают внезапный аборт `set -e` с потерей текста ошибки. Они структурированы через безопасные проверки `if REL_OUT=$(...); then ... else ... fi`.
   - При успешном релизе токена выполняется удаление файла токена. Если удаление файла не удалось, выводится `FAIL_CLEANUP` (код `6`), исключая ложный `SUCCESS` при оставшемся файле токена.
   - Старый токен и anchor `com.apple/routeclue.legacy` полностью изолированы: сбой релиза legacy токена выводится как предупреждение (`WARN_LEGACY_RELEASE_FAILED`) и код `5` (`PARTIAL_SUCCESS`), не очищая незавершённое состояние.

6. **Тестирование продакшн-скриптов через `FakePfctlHarness`:**
   - Полностью удалены фиктивные тесты `FileManager` с фиктивным токеном `424242`.
   - Выделены чистые фабрики продакшн-скриптов с инъекцией путей:
     - `KillSwitch.makeApplyScript(rulesFile:anchor:stateDir:pfctl:)`
     - `KillSwitch.makeDisableScript(anchor:stateDir:pfctl:legacyTokenFile:legacyAnchor:)`
     - `DNSZones.makeApplyScript(stagedEntries:targetDirectory:flushCache:)`
     - `DNSZones.makeRemoveScript(zone:targetDirectory:flushCache:)`
   - Создан модульный стенд `FakePfctlHarness`, эмулирующий поведение `/sbin/pfctl` (`-sr`, `-s info`, `-s References`, `-E` с выводом токена на stderr, `-X`, `-a ... -f`, `-a ... -F rules`) и запускающий продакшн-скрипты через реальный `/bin/sh` без root в изолированных каталогах `tmp`.
   - Проверены все сценарии:
     - Повторный `apply` приводит ровно к 1 ссылке ядра (`e_count == 1`).
     - Конкурентный `apply` блокируется локом (`FAIL_LOCK`, код `2`) без утечки токенов.
     - Конкурентные `apply` и `disable` взаимоисключаются.
     - Неуспешный `-X` сохраняет файл токена.
     - Сбой записи на диск (read-only stateDir) выполняет компенсирующий откат.
     - Пустой ruleset и отсутствие анкера `com.apple/*` приводят к немедленному fail-closed (0 токенов, 0 загрузок правил).
     - Отклонение symlink на state directory и token file (код `8`).
     - Отклонение stale token через `pfctl -s References` (код `4`).
     - Откат при сбое загрузки правил с сохранением файла при ошибке релиза.
     - Обнаружение сбоя очистки токена при `disable` (код `6`).
     - DNS скрипты: отказ при symlink (код `4`), защита не-RouteClue файлов (код `5`), остановка батча под `set -e` при ошибке `cp` без вызова flush кэша.

7. **Санитизация документации:**
   - Удалены все реальные имена корпоративных зон и сетевые реквизиты владельца хоста. Использованы исключительно зарезервированные домены `.example` (`corp.example.com`) и префиксы документации RFC 5737 (`198.51.100.0/24`, `203.0.113.0/24`, `192.0.2.0/24`) и RFC 3849 (`2001:db8::/32`).

---

## 2. Разделение проверенного и честно unverified

### Реально проверено в рабочей копии (Verified):
1. **Компиляция Swift 6:** `swift build -c release` успешно собирает все цели (`RouteClueCore`, `routeclue`, `RouteClueApp`, `RouteClueSelfTest`) без предупреждений и ошибок.
2. **Модульные и интеграционные тесты:** `swift run -c release RouteClueSelfTest` — успешно пройдены **все 148 проверок** без сетевых запросов.
3. **Бандл macOS:** `./Scripts/build-app.sh release` собирает и подписывает `dist/RouteClue.app` с метаданными `dev.routeclue.app`.
4. **Реальное выполнение шелл-скриптов:**
   - 11 изолированных тестовых сценариев `FakePfctlHarness` для `KillSwitch` скриптов через `/bin/sh`.
   - 4 тестовых сценария для `DNSZones` скриптов с проверкой symlinks, unowned файлов, `cp` fail и кэша.
5. **Read-only CLI интерфейс:**
   - `routeclue --help`, `status --json`, `doctor --json`.
   - `routeclue explain "https://user:pass@127.0.0.1:8080/test"` — подтверждено удаление credentials и корректный разбор порта/пути.
   - `routeclue explain "bad host with spaces"` — подтверждено fail-closed завершение с кодом 1.

### Честно не верифицировано (Runtime Unverified):
1. **Реальный packet drop ядром PF на хосте:**
   Мы **не запускали команды под root** на рабочей станции владельца и **не включали системный фаервол macOS**. Реальная фильтрация пакетов ядром требует тестирования на выделенной виртуальной машине или тестовом стенде с root-правами. Никаких неподтверждённых гарантий отсутствия утечек в проде не заявляется.
2. **Реальная модификация `/etc/resolver`:**
   Каталог `/etc/resolver` на хосте владельца не затрагивался; проверены генерация команд, проверка ownership, symlink-проверки и остановка по `set -e` во временных каталогах.

---

## 3. Точный перечень файлов

### Измененные/созданные файлы:
- `Sources/RouteClueCore/KillSwitch.swift` — атомарный root batch под `/var/run/routeclue/lock`, `makeApplyScript`, `makeDisableScript`, проверка `pfctl -s References`, symlink checks, компенсирующий release.
- `Sources/RouteClueCore/DNSZones.swift` — `makeApplyScript`, `makeRemoveScript`, staged entries, symlink & ownership checks в bash.
- `Sources/RouteClueCore/Shell.swift` — поддержка `environment: [String: String]?` для шелл-процессов.
- `Sources/RouteClueCore/Config.swift` — чистый `ConfigStore` без глобального состояния, `ConfigError.corrupted`.
- `Sources/RouteClueCore/TargetInputNormalizer.swift` — нормализация URL/IPv6, удаление credentials.
- `Sources/RouteClueCore/PolicyVerifier.swift` — инъекция наблюдений, dup-safe route evaluation.
- `Sources/RouteClueCore/PathExplainer.swift` — интеграция с `TargetInputNormalizer`.
- `Sources/RouteClueCore/RouteManager.swift` — BSD netstat парсер, строгая валидация октетов.
- `Sources/RouteClueCore/DNSQuery.swift` — строгий `ipv4Bytes` без `compactMap`.
- `Sources/RouteClueCore/Diagnostics.swift` — сохранение двоеточий в IPv6 nameservers.
- `Sources/RouteClueCore/SnapshotDiff.swift` — защита от дубликатов маршрутов.
- `Sources/RouteClueApp/RouteClueApp.swift` — явные Enable/Disable при unknown PF, блокировка при ошибках конфига.
- `Sources/RouteClueCLI/main.swift` — CLI с поддержкой `TargetInputNormalizer` и `--json`.
- `Sources/RouteClueSelfTest/main.swift` — 148 изолированных тестов, включая `FakePfctlHarness`, проверку коллизий токенов, сбоев сохранения с откатом, проверок UID каталога и DNS script tests.
- `docs/IMPLEMENTATION_REVIEW.md` — актуализированный отчет ревизии 3 с санитизированными данными.
- `Package.swift`, `Scripts/build-app.sh`, `Scripts/install-cli.sh`, `.github/workflows/ci.yml`.
- `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/POSITIONING.md`.

---

## 4. Сводка результатов верификации

```bash
# 1. Релизная компиляция
swift build -c release
# Результат: Build complete! — Exit code 0

# 2. Модульные тесты без сетевых зависимостей
swift run -c release RouteClueSelfTest
# Результат: Self test passed: 148 checks — Exit code 0

# 3. Бандл приложения
./Scripts/build-app.sh release
# Результат: Built dist/RouteClue.app — Exit code 0

# 4. Проверка CLI explain с credentials и портом
.build/release/routeclue explain "https://user:pass@127.0.0.1:8080/test"
# Результат: Host: 127.0.0.1, credentials stripped, Verdict: LOCAL (LOOPBACK) — Exit code 0

# 5. Проверка CLI explain на невалидном вводе
.build/release/routeclue explain "bad host with spaces"
# Результат: Error: Некорректный адрес или имя хоста — Exit code 1
```
