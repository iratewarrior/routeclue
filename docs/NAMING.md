# Название и публичное описание

Дата проверки: 2026-10-30. Владелец выбрал **RouteClue**.
Остальные варианты сохранены как история выбора. Переименование кода ещё в работе.

## Критерии

Имя легко произнести и набрать, удобно как CLI-команда, не обещает защиту или
разблокировку, подходит и личному, и корпоративному VPN. Предпочтительнее
описание исследования пути/причины, чем Guard, Shield, Secure или Unblock.
Подзаголовок должен объяснять пользу без знания сетевого жаргона.

## Выбор: RouteClue

Название приложения — RouteClue; команда — `routeclue`; будущие Swift targets —
`RouteClueCore`, `RouteClueCLI`, `RouteClueApp`, `RouteClueSelfTest`.
Подзаголовок: **Explain connection problems on your Mac.**

## Рассмотренные варианты

| Имя / команда | Смысл и преимущество | Недостаток | Предварительная проверка |
|---|---|---|---|
| **RouteClue / routeclue** | Подсказка к причине сетевого сбоя; мой рабочий фаворит | По имени можно ожидать только маршруты, нужен подзаголовок про соединение | В точном веб-поиске не найден явный продукт; GitHub repository search: 0 |
| **PathTeller / pathteller** | Рассказывает о пути соединения; звучит как отдельное приложение | Смысл сети неочевиден без подзаголовка | В точном веб-поиске не найден явный продукт; GitHub repository search: 0 |
| **RouteWhy / routewhy** | Прямо выражает «почему»; хорошо подходит CLI | Неестественная английская конструкция, похож на WhyRoute | В точном веб-поиске не найден явный сетевой продукт; GitHub repository search: 0 |

Метод: точный веб-поиск имён и запросы публичного GitHub API
`search/repositories?q=<name>+in:name`, `incomplete_results=false`.
Нулевой результат не означает свободное имя, домен, организацию или trademark.
Проверка package registries/App Store, похожих написаний и прав на бренд пока
не выполнена. Выбор владельца зафиксирован; дополнительные пользовательские исследования
не требуются. Повторная проверка совпадений перед публикацией желательна. Отдельный домен для alpha не нужен.

Журнал проверки 2026-10-30: точные веб-запросы `"RouteClue"`, `"PathTeller"`,
`"RouteWhy"`, `"RouteWhy" github` не дали явного одноимённого продукта.
Публичный GitHub API вернул total_count=0 для каждого запроса ниже:

- [routeclue in:name](https://api.github.com/search/repositories?q=routeclue%20in%3Aname)
- [pathteller in:name](https://api.github.com/search/repositories?q=pathteller%20in%3Aname)
- [routewhy in:name](https://api.github.com/search/repositories?q=routewhy%20in%3Aname)

Для всех трёх incomplete_results=false. Результаты могут измениться;
это проверка совпадений, а не резервирование или заключение о правах.

## Отсеянные варианты

- Прежнее рабочее название: отвергнуто из-за коллизий в той же нише; дополнительно Guard создаёт ожидание защиты.
- TunnelScope: [существующий VPN analyzer](https://github.com/7-Bala/TunnelScope)
  и другие сетевые применения имени.
- NetWhy: [существующая Linux-утилита диагностики](https://github.com/Ninso112/netwhy).
- PathLens: [существующий сервис](https://pathlens.io/).
- PathClue: [существующая платформа аналитики](https://pathclue.com/).
- NetClue: существующие компании/сетевые применения имени; нет преимуществ
  перед более различимыми кандидатами.

## Предлагаемая подача RouteClue

RU: **«Разберись, почему сервис не открывается с VPN».**

EN: **“Explain connection problems on your Mac.”**

Описание для GitHub (целевое, после реализации):

> A macOS app and CLI for investigating DNS, connection and routing problems
> with VPNs and proxies. Compare checks and export a report. No network changes.

Первый экран README: проблема → реальный пример результата → установка →
границы проверки → сравнение запусков → отчёт → поддерживаемые окружения.
Скриншоты на синтетических доменах, без рекламных «100% secure» и «works with
any VPN». Упоминать интернет-блокировки как сценарий, а не как гарантированный
диагноз. Не добавлять AI в название: доказательность важнее такого обещания.

После выбора имени: согласованно переименовать package/products, CLI, app bundle,
документацию, CI и release assets; спроектировать миграцию Application Support
без потери старого config. Старые PF anchors и resolver-файлы не трогать
автоматически при переименовании. Сначала проверить legacy ownership.
