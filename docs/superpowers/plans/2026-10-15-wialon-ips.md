# Wialon IPS PowerShell Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Сделать переносимый скрипт проверки TCP-подключения и обмена L/AL, P/AP для Wialon IPS 1.1 и 2.2.

**Architecture:** Один пользовательский PS1-файл использует стандартные классы .NET для TCP и отдельные функции формирования пакетов, чтения ответа и запуска проверки. Один тестовый PS1-файл запускает локальный TCP-сервер и настоящий скрипт в дочернем Windows PowerShell; Pester не нужен.

**Tech Stack:** Windows PowerShell 5.1, .NET Framework, System.Net.Sockets.TcpClient/TcpListener.

**Spec:** [Согласованная спецификация](../specs/2026-10-15-wialon-ips-design.md).

## Global Constraints

- «Скрипт работает в штатном Windows PowerShell 5.1 без сторонних модулей.»
- «Файл с русским текстом сохраняется в UTF-8 с BOM для совместимости с 5.1.»
- «Версии — только `1.1` и `2.2`.»
- «Таймаут по умолчанию — 5 секунд.»
- «В отправленном L пароль скрыт.»
- «Код завершения — 0 при полном успехе, ненулевой при ошибке.»
- Комментарии и README на русском; возможные commit messages на английском. Сейчас каталога .git нет: не создавать репозиторий ради служебных коммитов.

## Review Focus

Дополнительные сценарии, которые включить в проверки задачи 2:

1. IMEI с начальным нулём: байты идентификатора не меняются.
2. Не-ASCII пароль и разделители: понятный отказ до подключения, без утечки пароля.
3. Медленная посимвольная передача: общий таймаут ответа не растягивается.
4. Ответ без CRLF длиной более 4096 байт: ограничение размера вместо накопления данных.
5. Полностью заданные обязательные параметры: отсутствие интерактивных запросов, даже если пароль не указан.

## Протокол, подтверждённый документацией

Официальные источники:

- https://extapi.wialon.com/hw/cfg/Wialon%20IPS_en.pdf — Login packet.
- https://wialon.com/hw/files/Wialon%20IPS%20v.2.2%20%28EN%29.pdf — Login Packet, Ping Packet, Checksum.

IPS 1.1: `#L#<IMEI>;<Password>\r\n`. При отсутствии пароля передавать `NA`.

IPS 2.2: `#L#2.0;<IMEI>;<Password>;<CRC16>\r\n`. Поле версии именно `2.0`, как требует раздел Login Packet документа версии 2.2. CRC вычисляется по ASCII `2.0;<IMEI>;<Password>;`, без `#L#`, включая последний `;`. Алгоритм CRC-16/ARC: начальное значение 0, отражённый полином 0xA001, без финального XOR. Результат — четыре ASCII HEX-цифры, старший разряд первым.

Обе версии: `#AL#1\r\n` подтверждает логин, `#P#\r\n` получает `#AP#\r\n`. AL 0 — отклонение соединения; 01 — неверный пароль; 10 — неверный CRC в версии 2.x. Не сравнивать строковые коды как числа: `01` отличается от `1`.

## Task 1: Формирование пакетов

**Files:** Create `Test-WialonIps.ps1`; create `tests/Test-WialonIps.Tests.ps1`.

**Interfaces:**

- `Get-IpsCrc16([string] $Text)` возвращает четырёхзначную HEX-строку.
- `New-IpsLoginPacket([string] $Imei, [string] $Protocol, [string] $Password)` возвращает строку ASCII-пакета с CRLF, пустой пароль заменяет на NA.
- Dot-source скрипта определяет функции без интерактивного ввода и сетевых действий: основной блок ограждается проверкой `$MyInvocation.InvocationName -ne '.'`.

- [x] Написать тесты функций и запустить их до реализации. Простые проверки без модулей:

```powershell
. "$PSScriptRoot/../Test-WialonIps.ps1"
if ((Get-IpsCrc16 '123456789') -cne 'BB3D') { throw 'CRC-16/ARC check failed' }
if ((New-IpsLoginPacket -Imei '012345678901234' -Protocol '1.1' -Password '') -cne "#L#012345678901234;NA`r`n") { throw 'IPS 1.1 packet mismatch' }
```

- [x] Добавить тест контрольного CRC из документа: строка `231012;153959;5354.49260;N;02731.44990;E;0;0;300;7;1.1;0;0;1,0,0,0;NA;ign:1:1,dparam:2:3.14159265,tparam:3:lorem,iparam:1:-55,SOS:1:1;` должна давать `4BC3`. Для L 2.2 отдельно проверить префикс `#L#2.0;`, границы области CRC и завершающий CRLF; эталон CRC в тесте вычислить независимой табличной реализацией из официального примера, а не вызовом производственной функции.
- [x] Реализовать CRC и L. Основа вычисления:

```powershell
$crc = 0
foreach ($octet in [Text.Encoding]::ASCII.GetBytes($Text)) {
    $crc = $crc -bxor [int]$octet
    for ($bit = 0; $bit -lt 8; $bit++) {
        if ($crc -band 1) { $crc = ($crc -shr 1) -bxor 0xA001 }
        else { $crc = $crc -shr 1 }
    }
}
'{0:X4}' -f $crc
```

- [x] Запустить `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-WialonIps.Tests.ps1`. Ожидается успешная проверка CRC и обоих форматов L.

## Task 2: Интерактивный запуск, TCP и пользовательская документация

**Files:** Modify `Test-WialonIps.ps1`, `tests/Test-WialonIps.Tests.ps1`; create `README.md`.

**Interfaces:**

- Параметры скрипта `Server`, `Port`, `Imei`, `Protocol`, `Password`, `TimeoutSeconds`; значения проверяются до сетевых действий. Port и TimeoutSeconds — целые числа; TimeoutSeconds от 1 до 300.
- `Read-IpsResponse([System.Net.Sockets.NetworkStream] $Stream, [int] $TimeoutMilliseconds)` возвращает одну строку без CRLF, читает по одному байту, чтобы не поглощать следующий пакет; максимум 4096 байт на строку.
- `Invoke-IpsProbe([string] $Server, [int] $Port, [string] $Imei, [string] $Protocol, [string] $Password, [int] $TimeoutSeconds)` выполняет один сеанс; ошибки выбрасывает с названием этапа. Внешний основной блок печатает итог и устанавливает exit code.

- [x] Дополнить тесты локальным сервером: `[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)` выбирает свободный порт; `[PowerShell]::Create().AddScript(...).BeginInvoke()` обслуживает соединение в отдельном runspace. Дочерний powershell.exe запускает реальный скрипт; вывод и ExitCode проверяются; TCP-пакеты записываются сервером. Все сокеты, runspace и процессы закрываются в finally, зависший дочерний процесс останавливается только по его собственному PID.
- [x] До реализации проверить падение сетевых сценариев: успех 1.1 и 2.2, L с паролем, фрагментированный AL/AP, AL 0/01/10 без последующего P, неожиданные AL и AP, закрытие на каждом этапе, отсутствие AL и отсутствие AP. Добавить пять сценариев Review Focus, неверные порт/версию/IMEI/таймаут, сохранение начального нуля и отсутствие пароля в выводе. Интерактивные исправления проверить перенаправленным stdin дочернего процесса; в тестах не обращаться к внешним серверам.
- [x] Реализовать подключение через `BeginConnect` и ограниченный `AsyncWaitHandle.WaitOne`, затем `EndConnect`. Всегда закрывать клиент и wait handle в finally. Это ограничивает ожидание DNS и TCP целиком.
- [x] Реализовать чтение по дедлайну: `Stopwatch` измеряет время всей строки, перед каждым `ReadByte` задаётся оставшийся `ReadTimeout`; EOF и IOException выводятся как ошибка соответствующего этапа. Запись имеет WriteTimeout, равный заданному таймауту.
- [x] Реализовать проверку ответов с точным строковым сравнением. Основа управления:

```powershell
if ($loginReply -cne '#AL#1') { throw 'Логин: сервер не подтвердил авторизацию.' }
$pingBytes = [Text.Encoding]::ASCII.GetBytes("#P#`r`n")
$stream.Write($pingBytes, 0, $pingBytes.Length)
$pingReply = Read-IpsResponse -Stream $stream -TimeoutMilliseconds ($TimeoutSeconds * 1000)
if ($pingReply -cne '#AP#') { throw 'Ping: неожиданный ответ сервера.' }
```

- [x] Добавить цикл исправления интерактивного ввода, SecureString-ввод пароля, проверку ASCII и недопустимых `;`, `#`, CR/LF. Не включать пароль в сообщения валидации. Отправленный L показывать с маской пароля; перед выводом ответа сервера также скрывать в нём известный пароль. Итоговая ошибка содержит этап подключения, логина или ping.
- [x] Написать README: интерактивная команда `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-WialonIps.ps1`; команда с `-Server example.org -Port 20332 -Imei 012345678901234 -Protocol 2.2`; таймаут, пароль, exit codes, пример успешного вывода, регистрация IMEI на целевом сервере и отличие версии документа 2.2 от значения 2.0 в L. Дать ссылки на официальные спецификации. Пояснить, что ExecutionPolicy меняется только для процесса.
- [x] Сохранить PS1 в UTF-8 с BOM. Проверить синтаксис через `[System.Management.Automation.Language.Parser]::ParseFile`, затем запустить весь тестовый файл в Windows PowerShell 5.1. Ожидаются нулевой ExitCode тестов и отсутствие незакрытых локальных серверов/процессов. Без изменений после успешной проверки повторные прогоны не нужны.
- [x] Проверить согласованность README со скриптом и спецификацией. Зафиксировать число проверок и реальные ограничения в итоговом сообщении; тест на внешнем сервере не заявлять выполненным.

## Execution recommendation

Native: выполнить обе задачи в текущем сеансе, поскольку вторая зависит от функций первой, а поставляемый инструмент — один небольшой скрипт. После реализации провести отдельную проверку кода и результатов тестов по правилам применимого навыка review.

## Self-review

План покрывает ввод, Windows PowerShell 5.1/BOM, версии и CRC, скрытие пароля, TCP, общий таймаут, EOF/отказы/неожиданные ответы, ограничение размера, завершение, README и локальные проверки. Неподтверждённый в исходной спецификации формат L 2.2 уточнён по официальному документу. Интерфейсы функций едины между задачами.
