<p align="center">
  <a href="docs/assets/gedefense-logo.png">
    <img src="docs/assets/gedefense-logo.png" alt="GeDefense Retail" width="360">
  </a>
</p>

<h1 align="center">GeDefense Retail</h1>

<p align="center"><strong>ColdChain &amp; Store Infrastructure Security</strong><br>
Пассивный мониторинг OT и Access Gate с применением Default-Deny для пути управления магазином.</p>

<p align="center">
  <a href="https://github.com/visiongaiatechnology/gedefense-retail/releases"><img alt="Релиз" src="https://img.shields.io/github/v/release/visiongaiatechnology/gedefense-retail?style=flat-square&label=release"></a>
  <img alt="Лицензия: AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square">
  <img alt="Go 1.23+" src="https://img.shields.io/badge/go-1.23%2B-00ADD8?style=flat-square&logo=go&logoColor=white">
  <img alt="Платформы: Linux и Windows" src="https://img.shields.io/badge/platforms-Linux%20%7C%20Windows-444?style=flat-square">
  <img alt="Статус: Alpha" src="https://img.shields.io/badge/status-alpha-orange?style=flat-square">
</p>

[English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Italiano](README.it.md) · [Español](README.es.md) · [日本語](README.ja.md) · [中文](README.zh.md) · [Русский](README.ru.md)

---

<a id="alpha-status"></a>
## Статус альфа-версии

> **0.2.0-alpha.3 — экспериментальная версия, не готова к промышленной эксплуатации.**
> GeDefense Retail — ранняя альфа-версия. Проверка выполнялась на loopback с имитированными
> контроллерами и супервизорами, а не на реальном холодильном оборудовании в магазине. Независимого
> теста на проникновение Access Gate пока нет, заявлений о соответствии требованиям или сертификации
> не делается. Не используйте продукт в качестве единственного средства обеспечения безопасности,
> безопасности пищевых продуктов или мониторинга холодильной установки.

<a id="overview"></a>
## Что это

GeDefense Retail защищает и документирует инфраструктуру, стоящую за супермаркетом: холодильные
контроллеры, холодильные камеры, холодильные витрины, шлюзы датчиков, автоматизацию здания и путь
удалённого обслуживания, который используют сервисные холодильные компании.

Продукт поставляется в виде двух отдельных сервисов:

| Сервис | Бинарный файл | Роль |
|---|---|---|
| **Мониторинг** | `retaild` | Пассивная наблюдаемость OT только для чтения: активы, потоки, целостность холодовой цепи, качество данных, оповещения, аудит, панель управления |
| **Access Gate** | `retailgate` | Единственный разрешённый путь для записей управления/конфигурации в контроллеры: Default-Deny, привязка к плану, одобрение человеком, полный аудит |
| **Симулятор** | `retail-sim` | Локальные тестовые данные для разработки и приёмочных прогонов (только loopback) |

**Обещание продукта:**

- **Никакого пути записи в процесс OT со стороны GeDefense.** `retaild` и все пассивные адаптеры
  никогда не пишут в контроллер. Access Gate не управляет процессом; он авторизует и передаёт одну
  явно одобренную операцию конфигурации.
- **Записи выполняются по принципу Default-Deny.** Запись передаётся только в том случае, если она
  соответствует одобренному *Write-Plan* (цель, протокол, функция, адрес **и** значение) в пределах
  одобренного временного окна.
- **Человеческий контроль.** Для критических активов требуются два разных одобрения, одно из них —
  от `master_admin`. Автономных записей, записей по расписанию и решений на основе ИИ нет.
- **Fail-closed для пути управления.** Если Access Gate останавливается, удалённое управление закрывается.
  Холодильная установка продолжает работать автономно, поскольку Access Gate не входит в контур процесса.
- **Сначала доказательство, затем эффект.** Каждое действие и каждая отклонённая запись заносятся в
  журнал аудита, связанный хеш-цепочкой; при нарушении цепочки Access Gate отказывается запускаться.

<a id="features"></a>
## Возможности

### Мониторинг ColdChain (`retaild`, пассивный/только чтение)

- Пассивное обнаружение активов по метаданным потоков, признакам OUI и свидетельствам протоколов —
  неизвестные устройства остаются неизвестными, с указанием достоверности.
- Наблюдение за сетью OT: новые собеседники, неожиданные пути, метаданные протоколов, базовые линии
  потоков.
- Целостность холодовой цепи: заданные оператором температурные пределы, скорость изменения,
  отклонение от уставки, расхождение независимых датчиков.
- Проверки качества данных: замороженные значения, пропуски телеметрии, рассинхронизация часов,
  неправдоподобные значения — плохое измерение никогда не отображается как хорошая температура.
- Доступ для обслуживания: одобренные окна, аномалии доступа подрядчиков, метаданные сеансов.
- Правила обнаружения и коррелированные инциденты: факты, гипотеза и рекомендуемые проверки
  остаются разделёнными в каждом оповещении.
- Работа в первую очередь локально: обнаружение и оповещение продолжают работать без WAN;
  ограниченный локальный буфер для последующей передачи.
- Аудит с хеш-цепочкой, ролевой доступ к API, панель в стеклянном стиле, без внешнего CDN и без
  сторонних frontend-фреймворков.
- Пассивные адаптеры/адаптеры только для чтения для Modbus TCP, MQTT, BACnet/IP, SNMP (v1/v2c GET),
  PCAP и метаданных интерфейсов управления HTTP.

### Access Gate (`retailgate`, применение Default-Deny)

- Write-Plan с текущим значением, новым значением, причиной, ссылкой на заявку (необязательно),
  окном и неизменяемым хешем плана.
- Процесс одобрения с MFA (TOTP в этой альфа-версии), идемпотентными одобрениями, запретом
  самоодобрения и принципом четырёх глаз для критических активов.
- Одноразовый токен и сеанс записи, привязанный к IP-адресу источника; попытки повторного
  воспроизведения, истечения срока и неверного источника отклоняются и вызывают оповещение.
- Прокси применения Modbus TCP и обратный прокси HTTP(S) для веб-интерфейсов супервизоров.
- Списки разрешённых регистров и URL; allowlisting необходим, но недостаточен — одобренный план
  также должен точно совпадать.
- Deny-таймлайн, доказательства отказов и аудит для каждой отклонённой записи.
- Матрица fail-safe: ошибки хранилища/аудита, скачки часов и недействительная политика закрывают путь
  записи; неработающий Access Gate не влияет на установку.
- Уведомления webhook с подписью HMAC, эскалацией и подтверждением (`GET /escalations`,
  `POST /escalations/{id}/ack`).

### Новое в 0.2.0-alpha.2

- **Мастер настройки** (первый запуск, только loopback) с пошаговыми этапами для языка, площадки,
  списка разрешённых адресов доступа, учётной записи администратора, коллекторов и завершения.
- **Список разрешённых IP-адресов** применяется к панели управления, API, SSE, статическим ресурсам и
  настройке после конфигурации (`require_whitelist` включён по умолчанию; fail-closed).
- **Восемь языков интерфейса**: английский, немецкий, французский, итальянский, испанский, японский,
  китайский, русский.
- **Оригинальный логотип GeDefense** и талисман как локальные ресурсы (без внешнего CDN).
- Пакеты для Linux и Windows со скриптами установки и контрольными суммами SHA-256.

<a id="architecture"></a>
## Архитектура (кратко)

```text
 Сервисная компания / оператор
 (VPN / ZTNA, в списке разрешённых)
        │
        ▼
 ┌──────────────────────────────┐        ┌──────────────────────────────┐
 │ retaild (мониторинг)         │        │ retailgate (применение)      │
 │ пассивный TAP/SPAN, чтение   │        │ идентификация, одобрение,    │
 │ обнаружение, оповещения, UI  │        │ токен, аудит, прокси Modbus/HTTP│
 └──────────────┬───────────────┘        └──────────────┬───────────────┘
                │ пассивное наблюдение                   │ только путь управления
                │ (никогда не пишет)                     │ (привязка к плану, Default-Deny)
                ▼                                        ▼
        Сегмент мониторинга OT                   Контроллеры / супервизоры
        (TAP/SPAN, опрос только на чтение)       (Modbus TCP, HTTP(S) admin UI)
```

- Один шлюз на магазин; локальная работа не зависит от интернета.
- Access Gate разворачивается как **отдельное устройство/VM с двумя сетевыми интерфейсами**: сторона
  управления/подрядчика и контур управления OT. Это не маршрутизатор, и он не находится в
  технологической связи между контроллером и исполнительными механизмами.
- Необязательное централизованное управление работает только на исходящих соединениях (mTLS).

<a id="alpha-limitations"></a>
## Честные ограничения альфа-версии

- **Реальное оборудование OT не тестировалось.** Доказательства data plane получены на имитированных
  контроллерах и супервизорах в loopback. Реальные unit ID, сценарии входа производителей, сертификаты
  и состояния прошивок — темы пилота.
- **TOTP не является фактором, устойчивым к фишингу.** FIDO2/WebAuthn планируется в более позднем
  релизе; устойчивость фактора альфа-версии не заявляется.
- **Сегментация — обязанность оператора.** Без реальной сетевой схемы «нет второго пути» Access Gate можно
  обойти. Служба мониторинга делает обходы видимыми, но не может их предотвратить.
- **Автоматической корреляции обходов нет.** Access Gate и служба мониторинга разделены; отклонённые записи и
  пассивные оповещения `retail.write-attempt` в этой альфа-версии сопоставляются вручную.
- **Закрепление сертификатов и списки разрешённых параметров** реализованы в прокси, но ещё не
  представлены в схеме конфигурации.
- **`write_unknown` без автоматического обратного чтения.** Если ответ контроллера неясен (тайм-аут,
  разрыв соединения), запись помечается как `write_unknown` с критическим оповещением; оператор должен
  проверить значение обратным чтением и **не повторять попытку автоматически**.
- **Сеансы API хранятся в памяти.** Перезапуск выполняет выход пользователей; это намеренное
  поведение fail-closed.
- **Нет data plane BACnet/MQTT, нет управления облаком производителя/локальным HMI/USB.** Это вне
  рамок данной альфа-версии и остаётся задачей оператора.
- **Никаких заявлений о соответствии.** GeDefense Retail не заявляет о соответствии HACCP, NIS2,
  IEC 62443 или какой-либо иной сертификации.
- **Права Windows отличаются от Linux.** Режимы POSIX `0600/0700` не являются механизмом контроля
  доступа в Windows; используйте выделенную сервисную учётную запись и явные ACL. Это
  задокументированное бета-условие.

<a id="download"></a>
## Загрузка

**Последний альфа-релиз: [v0.2.0-alpha.3](https://github.com/visiongaiatechnology/gedefense-retail/releases/tag/v0.2.0-alpha.3).**
Ресурсы: четыре архива, [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS),
[SHA256SUMS.archives](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS.archives),
[SBOM.spdx.json](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SBOM.spdx.json)
и подписи cosign (`*.sig`/`*.pem`). Бинарные файлы Windows — **NOT_SIGNED** (Authenticode, альфа);
используйте хеши/подписи.

| Платформа | Архив | Контрольные суммы |
|---|---|---|
| Linux amd64 | [gedefense-retail-0.2.0-alpha.3-linux-amd64.tar.gz](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/gedefense-retail-0.2.0-alpha.3-linux-amd64.tar.gz) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS) · [архивы](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS.archives) |
| Linux arm64 | [gedefense-retail-0.2.0-alpha.3-linux-arm64.tar.gz](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/gedefense-retail-0.2.0-alpha.3-linux-arm64.tar.gz) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS) · [архивы](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS.archives) |
| Windows amd64 | [gedefense-retail-0.2.0-alpha.3-windows-amd64.zip](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/gedefense-retail-0.2.0-alpha.3-windows-amd64.zip) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS) · [архивы](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS.archives) |
| Windows arm64 | [gedefense-retail-0.2.0-alpha.3-windows-arm64.zip](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/gedefense-retail-0.2.0-alpha.3-windows-arm64.zip) | [SHA256SUMS](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS) · [архивы](https://github.com/visiongaiatechnology/gedefense-retail/releases/download/v0.2.0-alpha.3/SHA256SUMS.archives) |

**Проверьте перед установкой:** `sha256sum -c SHA256SUMS` в распакованном архиве и
`sha256sum -c SHA256SUMS.archives` для скачанных архивов. Архивы и `SHA256SUMS` подписаны cosign
keyless; проверка: `cosign verify-blob --certificate <файл>.pem --signature <файл>.sig
--certificate-oidc-issuer https://token.actions.githubusercontent.com
--certificate-identity-regexp 'https://github.com/visiongaiatechnology/gedefense-retail/.github/workflows/release.yml@refs/tags/v.*' <файл>` (точная идентичность в
[docs/BUILD-AND-RELEASE.md](docs/BUILD-AND-RELEASE.md)). `SBOM.spdx.json` — инвентарь компонентов
SPDX. **Если файл подписи отсутствует, считайте загрузку неподписанной.**

Каждый архив содержит `bin/` (бинарные файлы), `config/` (примеры конфигурации и unit-файлы systemd),
`docs/`, `README.md`, `LICENSE`, `VERSION`, `THIRD-PARTY-NOTICES.md`, скрипты установки и файл
`SHA256SUMS`.

<a id="install-linux"></a>
## Установка — Linux

**Требования**

- Linux x86-64 или arm64 с systemd.
- Права администратора для установки.
- Клиент управления в пределах запланированного CIDR белого списка (во время настройки — loopback).
- Для бинарных пакетов инструменты Go не требуются.
- Спланируйте белый список и сегментацию OT/управления **до** включения удалённого доступа.

**1. Загрузка и проверка**

```bash
tar -xzf gedefense-retail-<version>-linux-amd64.tar.gz
cd gedefense-retail-<version>-linux-amd64
sha256sum -c SHA256SUMS
```

**2. Установка**

```bash
sudo ./install.sh
```

Установщик создаёт сервисные учётные записи, устанавливает unit-файлы systemd из `config/`
(`gedefense-retail.service`, `gedefense-retailgate.service`), готовит `/etc/gedefense-retail/`,
`/var/lib/gedefense-retail/`, `/var/lib/gedefense-gate/` и `/var/log/gedefense-retail/` и оставляет
службу мониторинга готовой к настройке при первом запуске. Он копирует **только примеры
конфигурации** (`retail.example.json`, `gate.example.json`, `gate-policy.example.json`) и никогда не
перезаписывает существующие файлы. Конфигурация устанавливается `root:gedefense` (каталоги `0750`,
файлы `0640`), каталоги данных принадлежат сервисным учётным записям; при ошибке установки прав
инсталлятор прерывается (fail-closed). Оператор создаёт рабочую конфигурацию на основе примеров:

```bash
sudo cp /etc/gedefense-retail/retail.example.json /etc/gedefense-retail/retail.json
# отредактируйте retail.json: площадка, пользователи, коллекторы, белый список безопасности, цели/апстримы шлюза
```

**3. Настройка при первом запуске (только loopback)**

```bash
sudo systemctl enable --now gedefense-retail
```

При `setup.completed=false` первый запуск привязывается **только к loopback** (задайте `listen` как
`127.0.0.1:8080` для указанного ниже URL). Откройте `http://127.0.0.1:8080/setup` на самом шлюзе
(SSH-туннель или локальный браузер) и завершите мастер: язык, площадка/часовой пояс, белый список
доступа (например `127.0.0.1/32`, `::1/128` плюс ваш управляющий CIDR), токен администратора
(показывается **один раз**), необязательные коллекторы, завершение (`restart_required: true`).
`security.setup_token_ttl_s` по умолчанию равно 3600 секундам. Белый список работает по принципу
fail-closed: без записи клиенты вне loopback получают `403 ip_not_allowed`, и страница входа не
отображается.

```bash
sudo systemctl restart gedefense-retail
```

**4. Проверка**

```bash
systemctl status gedefense-retail --no-pager
retaild version
curl -s http://127.0.0.1:8080/api/v1/health
```

Только IP-адреса источников из `security.dashboard_whitelist_cidrs` могут обращаться к панели
управления, API, SSE и статическим ресурсам. Запрос извне белого списка получает
`403 ip_not_allowed`; резервной страницы входа не существует.

**5. Необязательно: включение Access Gate**

Включайте Access Gate только после завершения настройки мониторинга. Ему нужны **оба** файла:
`gate.json` и `gate-policy.json`; без действующих конфигурации и политики он отказывается
запускаться (fail-closed).

```bash
sudo cp /etc/gedefense-retail/gate.example.json /etc/gedefense-retail/gate.json
sudo cp /etc/gedefense-retail/gate-policy.example.json /etc/gedefense-retail/gate-policy.json
# отредактируйте оба файла: цели, пользователи, белый список, критические активы, allowlists
sudo retailgate hash-password --password "<at least 12 characters>"
sudo retailgate gen-totp
# вставьте выведенные хеш пароля и секрет TOTP в gate.json, затем проверьте и запустите:
sudo -u gedefense-gate retailgate check --config /etc/gedefense-retail/gate.json
sudo systemctl enable --now gedefense-retailgate
```

Access Gate должен работать на отдельном устройстве/VM с двумя сетевыми картами (сторона управления и
контур управления OT), а не на хосте мониторинга. Без правильной сегментации Access Gate можно обойти.

<a id="install-windows"></a>
## Установка — Windows

**Требования**

- Windows 10/11 или Windows Server 2019+ (x64 или arm64), PowerShell 5.1+.
- Права администратора.
- Клиент управления в пределах запланированного CIDR белого списка; настройка выполняется только через
  loopback.

**1. Загрузка, распаковка, проверка**

```powershell
Expand-Archive .\gedefense-retail-<version>-windows-amd64.zip -DestinationPath .
cd .\gedefense-retail-<version>-windows-amd64
Get-FileHash .\bin\retaild.exe -Algorithm SHA256
# сравните со значениями в SHA256SUMS (все файлы в архиве)
```

**2. Установка**

```powershell
# PowerShell с правами администратора
.\install-windows.ps1
```

Установщик создаёт каталог программы `C:\Program Files\GeDefense\Retail\` (с `bin\` и `config\`),
каталог данных `C:\ProgramData\GeDefense\Retail\` и регистрирует службы Windows через `sc.exe`
(`gedefense-retail`, `gedefense-retailgate`). Он копирует **только примеры конфигурации**; оператор
создаёт рабочие файлы `retail.json` / `gate.json` на основе примеров в `config\`. **Правила
брандмауэра не создаются автоматически** — добавьте только те порты белого списка и управления,
которые действительно нужны.

**3. Настройка при первом запуске**

```powershell
Start-Service gedefense-retail
```

Откройте `http://127.0.0.1:8080/setup` на шлюзе (с `listen`, заданным как `127.0.0.1:8080`), выполните
шесть шагов настройки, затем перезапустите:

```powershell
Restart-Service gedefense-retail
Get-Service gedefense-retail
.\bin\retaild.exe version
```

**Права Windows (альфа):** инсталлятор запускает обе службы как `NT AUTHORITY\LocalService` и задаёт
явные DACL через `icacls` без наследования: `config\` — чтение, `C:\ProgramData\GeDefense\Retail\` —
изменение для службы, Administrators — полный доступ, `Users` — без доступа. Режимы POSIX не
защищают NTFS; не включайте унаследованные ACL. Деинсталляция не восстанавливает прежние ACL.

**4. Необязательно: Access Gate**

```powershell
# примеры конфигурации: C:\Program Files\GeDefense\Retail\config\gate.example.json / gate-policy.example.json
# рабочие файлы: ...\config\gate.json и ...\config\gate-policy.json (отредактируйте цели/пользователей/allowlists)
.\bin\retailgate.exe hash-password --password "<at least 12 characters>"
.\bin\retailgate.exe gen-totp
# вставьте выведенные хеш пароля и секрет TOTP в gate.json, затем проверьте и запустите:
.\bin\retailgate.exe check --config "C:\Program Files\GeDefense\Retail\config\gate.json"
Start-Service gedefense-retailgate
```

Access Gate требует оба файла конфигурации и отказывается запускаться без действующей политики
(fail-closed). Запускайте его на отдельном устройстве/VM с двумя сетевыми картами; установщик Windows
не настраивает ни сегментацию, ни правила брандмауэра.

<a id="quickstart"></a>
## Быстрый старт

1. Установите пакет для вашей платформы.
2. Запустите службу мониторинга и завершите мастер настройки в loopback.
3. Добавьте хотя бы один CIDR клиента управления в список разрешённых — иначе все запросы, кроме
   loopback, будут отклоняться.
4. Войдите в панель управления с токеном администратора, который мастер показывает один раз.
5. Для симуляции или разработки запускайте `retail-sim` на шлюзе (только loopback, требуется флаг
   симуляции) — никогда против рабочих устройств OT.

Из исходного кода (для разработчиков, Go 1.23+, только стандартная библиотека, без CGO):

```bash
go build ./...
go vet ./...
go test ./...
```

<a id="security"></a>
## Модель безопасности

- **Мониторинг только для чтения.** У `retaild` нет пути записи в OT. Пассивные адаптеры никогда не
  отправляют функциональные коды записи, не выполняют активное сканирование и не отправляют сырые пробы.
- **Путь управления Default-Deny.** `retailgate` передаёт только операции, точно соответствующие
  одобренному плану; всё остальное отклоняется, аудируется и вызывает оповещение.
- **Точная привязка.** Цель, протокол, функция, адрес и значение одобряются как единое целое. Другое
  значение или адрес является отказом даже внутри одобренного временного окна.
- **Человеческое одобрение.** Самоодобрение отклоняется; для критических активов требуются два разных
  одобряющих, включая `master_admin`. Одноразовый токен показывается один раз и привязывается к хешу
  плана и IP-адресу источника.
- **Аудит до эффекта.** Отклонённые и разрешённые операции записываются в журнал аудита с
  хеш-цепочкой; при нарушении цепочки Access Gate отказывается запускаться.
- **Fail-closed.** Проблемы Access Gate, хранилища, часов или политики закрывают путь управления; установка
  продолжает работать.
- **Сеть.** Применение списка разрешённых адресов работает по принципу fail-closed. Не выставляйте
  панель управления или Access Gate в интернет; при необходимости удалённого доступа используйте путь VPN/ZTNA
  и задокументированные настройки прокси.
- **Сообщения об уязвимостях.** Сообщайте об уязвимостях конфиденциально, как описано в
  [SECURITY.md](SECURITY.md). Не тестируйте на рабочих холодильных установках.
- **Никаких заявлений о соответствии.** См. [SECURITY.md](SECURITY.md) и [NOTICE](NOTICE).

<a id="evidence"></a>
## Статус проверки (честно)

| Область | Статус |
|---|---|
| Сборка, vet, модульные/интеграционные тесты, детектор гонок | зелёный (loopback/CI) |
| Приёмочные сквозные проверки 0.1 (мониторинг) | пройдено 39/39 (loopback/симуляция) |
| Сквозные проверки Access Gate 0.2.0-alpha.1 | пройдено 25/25 (loopback, имитированные контроллеры) |
| Design QA | созданы скриншоты с имитационными данными; проверка скринридером/сенсорным вводом/длительной работой не выполнялась |
| Реальное оборудование OT | ещё не тестировалось (тема пилота) |
| Независимый тест на проникновение Access Gate | пока недоступен |
| Соответствие/сертификация | не заявлено |

Цифры относятся к прогонам проверки, описанным в примечаниях к релизу; они не являются заявлением о
готовности к эксплуатации.

<a id="documentation"></a>
## Документация

- [README (English)](README.md) · [README (Deutsch)](README.de.md)
- [SECURITY.md](SECURITY.md) — сообщения об уязвимостях, статус альфа, область применения
- [CONTRIBUTING.md](CONTRIBUTING.md) — сборка, тесты, инварианты безопасности, pull request'ы
- [CHANGELOG.md](CHANGELOG.md) — история релизов
- [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) — зависимости и ресурсы
- [NOTICE](NOTICE) — уведомление об авторских правах и лицензии
- [LICENSE](LICENSE) — GNU Affero General Public License v3.0
- [Индекс документации](docs/README.md)
- [Releases](https://github.com/visiongaiatechnology/gedefense-retail/releases) ·
  [Issues](https://github.com/visiongaiatechnology/gedefense-retail/issues)

<a id="license"></a>
## Лицензия

GeDefense Retail распространяется под **GNU Affero General Public License v3.0** (AGPL-3.0).
См. [LICENSE](LICENSE) и [NOTICE](NOTICE).

Copyright © 2026 VisionGaiaTechnology.
