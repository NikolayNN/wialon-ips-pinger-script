#requires -Version 5.1
param(
    [string] $Server,
    [string] $Port,
    [string] $Imei,
    [string] $Protocol,
    [string] $Password,
    [string] $TimeoutSeconds = '5'
)

function Get-IpsCrc16([string] $Text) {
    $crc = 0
    foreach ($octet in [Text.Encoding]::ASCII.GetBytes($Text)) {
        $crc = $crc -bxor [int]$octet
        for ($bit = 0; $bit -lt 8; $bit++) {
            if ($crc -band 1) { $crc = ($crc -shr 1) -bxor 0xA001 }
            else { $crc = $crc -shr 1 }
        }
    }
    '{0:X4}' -f $crc
}

function New-IpsLoginPacket([string] $Imei, [string] $Protocol, [string] $Password) {
    $wirePassword = if ([string]::IsNullOrEmpty($Password)) { 'NA' } else { $Password }
    if ($Protocol -ceq '1.1') { return "#L#$Imei;$wirePassword`r`n" }
    if ($Protocol -ceq '2.2') {
        # В спецификации 2.2 поле версии логина остаётся 2.0; CRC включает последний ;.
        $payload = "2.0;$Imei;$wirePassword;"
        return ('#L#' + $payload + (Get-IpsCrc16 $payload) + "`r`n")
    }
    throw 'Версия протокола: допустимы 1.1 и 2.2.'
}

function Read-IpsText([string] $Prompt) {
    if ([Console]::IsInputRedirected) {
        Write-Host ($Prompt + ': ') -NoNewline
        $value = [Console]::ReadLine()
        if ($null -eq $value) { throw 'Ввод завершён до получения всех параметров.' }
        return $value
    }
    Read-Host $Prompt
}

function Get-IpsInput([string] $Value, [bool] $Supplied, [string] $Prompt,
    [scriptblock] $Validate, [string] $Hint) {
    while ($true) {
        if (-not $Supplied) { $Value = Read-IpsText $Prompt }
        $Value = $Value.Trim()
        if (& $Validate $Value) { return $Value }
        if ($Supplied) { throw $Hint }
        Write-Host $Hint -ForegroundColor Yellow
    }
}

function Test-IpsPassword([string] $Value) {
    # ASCII без управляющих символов и разделителей пакета.
    return $Value -cnotmatch '[^\x20-\x7E]|[;#]'
}

function Format-IpsDisplay([string] $Text, [string] $Secret) {
    if (-not [string]::IsNullOrEmpty($Secret)) { $Text = $Text.Replace($Secret, '***') }
    $Text = $Text.Replace("`r", '\r').Replace("`n", '\n')
    return ($Text -replace '[\x00-\x1F\x7F]', '?')
}

function Read-IpsResponse([Net.Sockets.NetworkStream] $Stream, [int] $TimeoutMilliseconds) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $response = [Text.StringBuilder]::new()
    while ($true) {
        $remaining = $TimeoutMilliseconds - $clock.ElapsedMilliseconds
        if ($remaining -le 0) { throw 'Таймаут ожидания полного ответа.' }
        $Stream.ReadTimeout = [int][Math]::Max(1, $remaining)
        try { $octet = $Stream.ReadByte() }
        catch [IO.IOException] {
            $cause = $_.Exception
            while ($cause.InnerException) { $cause = $cause.InnerException }
            if (($cause -is [Net.Sockets.SocketException] -and $cause.SocketErrorCode -eq [Net.Sockets.SocketError]::TimedOut) -or
                $clock.ElapsedMilliseconds -ge $TimeoutMilliseconds) {
                throw 'Таймаут ожидания полного ответа.'
            }
            throw 'Ошибка чтения ответа: соединение разорвано или недоступно.'
        }
        if ($octet -lt 0) { throw 'Сервер закрыл соединение до получения полного ответа.' }
        [void]$response.Append([char]$octet)
        $length = $response.Length
        if ($length -gt 4096) { throw 'Ответ сервера превышает 4096 байт.' }
        if ($length -ge 2 -and $response[$length - 2] -eq "`r" -and $response[$length - 1] -eq "`n") {
            return $response.ToString(0, $length - 2)
        }
    }
}

function Write-IpsProgress([string] $Stage, [string] $State, [string] $Message,
    [scriptblock] $OnProgress, [ConsoleColor] $Color = 'Gray') {
    if ($OnProgress) {
        & $OnProgress ([pscustomobject]@{ Stage = $Stage; State = $State; Message = $Message })
    }
    else { Write-Host $Message -ForegroundColor $Color }
}

function Invoke-IpsProbe([string] $Server, [int] $Port, [string] $Imei,
    [string] $Protocol, [string] $Password, [int] $TimeoutSeconds, [scriptblock] $OnProgress,
    [hashtable] $Session) {
    # Обычный TcpClient в .NET Framework создаёт только IPv4-сокет.
    if ([Net.Sockets.Socket]::OSSupportsIPv6) {
        $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
        $client.Client.DualMode = $true
    }
    else { $client = [Net.Sockets.TcpClient]::new() }
    $waitHandle = $null
    $stage = 'Подключение'
    $stageKey = 'Connection'
    $milliseconds = $TimeoutSeconds * 1000
    try {
        if ($Session) {
            $Session.Client = $client
            if ($Session.Cancelled) { throw 'Проверка остановлена.' }
        }
        Write-IpsProgress $stageKey 'Running' "Подключение к ${Server}:$Port (Wialon IPS $Protocol)..." $OnProgress
        $connecting = $client.BeginConnect($Server, $Port, $null, $null)
        $waitHandle = $connecting.AsyncWaitHandle
        if (-not $waitHandle.WaitOne($milliseconds)) { throw 'Таймаут подключения (DNS/TCP).' }
        $client.EndConnect($connecting)
        Write-IpsProgress $stageKey 'Passed' 'TCP: подключено.' $OnProgress
        $stream = $client.GetStream()
        $stream.WriteTimeout = $milliseconds

        $stage = 'Логин'
        $stageKey = 'Login'
        Write-IpsProgress $stageKey 'Running' 'Авторизация трекера...' $OnProgress
        $login = New-IpsLoginPacket -Imei $Imei -Protocol $Protocol -Password $Password
        Write-IpsProgress $stageKey 'Info' ('TX: ' + (Format-IpsDisplay $login $Password)) $OnProgress
        $bytes = [Text.Encoding]::ASCII.GetBytes($login)
        $stream.Write($bytes, 0, $bytes.Length)
        $reply = Read-IpsResponse $stream $milliseconds
        Write-IpsProgress $stageKey 'Info' ('RX: ' + (Format-IpsDisplay ($reply + "`r`n") $Password)) $OnProgress
        if ($reply -cne '#AL#1') {
            switch -CaseSensitive ($reply) {
                '#AL#0' { throw 'Сервер отклонил логин: проверьте регистрацию IMEI, версию и формат пакета.' }
                '#AL#01' { throw 'Сервер отклонил пароль трекера.' }
                '#AL#10' { throw 'Сервер сообщил об ошибке CRC.' }
                default { throw 'Неожиданный ответ сервера; ожидался #AL#1.' }
            }
        }
        Write-IpsProgress $stageKey 'Passed' 'Логин: принят.' $OnProgress

        $stage = 'Ping'
        $stageKey = 'Ping'
        Write-IpsProgress $stageKey 'Running' 'Проверка ping...' $OnProgress
        Write-IpsProgress $stageKey 'Info' 'TX: #P#\r\n' $OnProgress
        $bytes = [Text.Encoding]::ASCII.GetBytes("#P#`r`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $reply = Read-IpsResponse $stream $milliseconds
        Write-IpsProgress $stageKey 'Info' ('RX: ' + (Format-IpsDisplay ($reply + "`r`n") $Password)) $OnProgress
        if ($reply -cne '#AP#') { throw 'Неожиданный ответ сервера; ожидался #AP#.' }
        Write-IpsProgress $stageKey 'Passed' 'Ping: ответ получен.' $OnProgress
        Write-IpsProgress 'Summary' 'Passed' 'Проверка пройдена: L/AL и P/AP подтверждены.' $OnProgress 'Green'
    }
    catch {
        $message = Format-IpsDisplay $_.Exception.Message $Password
        if ($OnProgress) { Write-IpsProgress $stageKey 'Failed' "${stage}: $message" $OnProgress }
        throw "${stage}: $message"
    }
    finally {
        $client.Dispose()
        if ($Session) { $Session.Client = $null }
        if ($waitHandle) { $waitHandle.Dispose() }
    }
}

function Resolve-IpsProbeParameters([hashtable] $Values, [switch] $Interactive) {
        [string] $Server = $Values.Server
        [string] $Port = $Values.Port
        [string] $Imei = $Values.Imei
        [string] $Protocol = $Values.Protocol
        [string] $Password = $Values.Password
        [string] $TimeoutSeconds = if ($Values.ContainsKey('TimeoutSeconds')) { $Values.TimeoutSeconds } else { '5' }
        $promptPassword = $Interactive -and -not ($Values.ContainsKey('Server') -and $Values.ContainsKey('Port') -and
            $Values.ContainsKey('Imei') -and $Values.ContainsKey('Protocol'))
        try {
            $Server = Get-IpsInput $Server ($Values.ContainsKey('Server') -or -not $Interactive) 'IP или домен сервера' {
                param($v)
                $v -and $v -notmatch '[\s/\\;#]' -and [Uri]::CheckHostName($v.Trim('[', ']')) -ne [UriHostNameType]::Unknown
            } 'Укажите IP или домен без схемы URL, пути и пробелов.'
            $Server = $Server.Trim('[', ']')
            $Port = Get-IpsInput $Port ($Values.ContainsKey('Port') -or -not $Interactive) 'TCP-порт' {
                param($v)
                $number = 0
                $v -cmatch '^[0-9]+$' -and [int]::TryParse($v, [ref]$number) -and $number -ge 1 -and $number -le 65535
            } 'Порт должен быть целым числом от 1 до 65535.'
            $Imei = Get-IpsInput $Imei ($Values.ContainsKey('Imei') -or -not $Interactive) 'IMEI трекера (15 цифр)' {
                param($v) $v -cmatch '^[0-9]{15}$'
            } 'IMEI должен содержать ровно 15 цифр.'
            $Protocol = Get-IpsInput $Protocol ($Values.ContainsKey('Protocol') -or -not $Interactive) 'Версия Wialon IPS (1.1 или 2.2)' {
                param($v) $v -cin @('1.1', '2.2')
            } 'Версия протокола: допустимы 1.1 и 2.2.'
            $TimeoutSeconds = Get-IpsInput $TimeoutSeconds $true '' {
                param($v)
                $number = 0
                $v -cmatch '^[0-9]+$' -and [int]::TryParse($v, [ref]$number) -and $number -ge 1 -and $number -le 300
            } 'Таймаут должен быть целым числом от 1 до 300 секунд.'

            if ($promptPassword -and -not $Values.ContainsKey('Password')) {
                do {
                    if ([Console]::IsInputRedirected) {
                        $Password = Read-IpsText 'Пароль трекера (Enter — нет)'
                    }
                    else {
                        $secure = Read-Host 'Пароль трекера (Enter — нет)' -AsSecureString
                        try { $Password = [Net.NetworkCredential]::new('', $secure).Password }
                        finally { $secure.Dispose() }
                    }
                    if (-not (Test-IpsPassword $Password)) {
                        Write-Host 'Пароль: используйте ASCII без управляющих символов и разделителей ; #.' -ForegroundColor Yellow
                    }
                } while (-not (Test-IpsPassword $Password))
            }
            elseif (-not (Test-IpsPassword $Password)) { throw 'Пароль: используйте ASCII без управляющих символов и разделителей ; #.' }
        }
        catch { throw ('Ввод: ' + $_.Exception.Message) }

        return @{ Server = $Server; Port = [int]$Port; Imei = $Imei; Protocol = $Protocol;
            Password = $Password; TimeoutSeconds = [int]$TimeoutSeconds }
}

if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    try {
        $options = Resolve-IpsProbeParameters -Values $PSBoundParameters -Interactive
        Invoke-IpsProbe @options
        exit 0
    }
    catch {
        Write-Host ('Проверка не пройдена. ' + (Format-IpsDisplay $_.Exception.Message $Password)) -ForegroundColor Red
        exit 1
    }
}
