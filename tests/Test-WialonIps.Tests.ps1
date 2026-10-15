param([switch] $PacketsOnly, [string] $Filter = '*')
$ErrorActionPreference = 'Stop'
$script:passed = 0
$script:failed = 0
$probePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-WialonIps.ps1'
if (Test-Path -LiteralPath $probePath) { . $probePath }

function Assert-Equal($Actual, $Expected) {
    if ($Actual -cne $Expected) { throw "Expected <$Expected>, got <$Actual>" }
}
function Test-Case([string] $Name, [scriptblock] $Body) {
    if ($Name -notlike $Filter) { return }
    try { & $Body; $script:passed++; Write-Host "PASS $Name" }
    catch { $script:failed++; Write-Host "FAIL $Name : $($_.Exception.Message)" }
}

# These fixtures catch a wrong CRC variant, a missing final semicolon and a wrong wire version.
Test-Case 'CRC-16/ARC standard check' { Assert-Equal (Get-IpsCrc16 '123456789') 'BB3D' }
Test-Case 'Official Wialon checksum example' {
    $payload = '231012;153959;5354.49260;N;02731.44990;E;0;0;300;7;1.1;0;0;1,0,0,0;NA;ign:1:1,dparam:2:3.14159265,tparam:3:lorem,iparam:1:-55,SOS:1:1;'
    Assert-Equal (Get-IpsCrc16 $payload) '4BC3'
}
Test-Case 'IPS 1.1 preserves leading zero and sends NA' {
    Assert-Equal (New-IpsLoginPacket -Imei '012345678901234' -Protocol '1.1' -Password '') "#L#012345678901234;NA`r`n"
}
Test-Case 'IPS 1.1 password' {
    Assert-Equal (New-IpsLoginPacket -Imei '012345678901234' -Protocol '1.1' -Password 'secret') "#L#012345678901234;secret`r`n"
}

# Independent table recurrence from the official C example, not the production bit loop.
function Get-ReferenceCrc([string] $Text) {
    $table = @(0..255 | ForEach-Object {
        $entry = $_
        foreach ($shift in 1..8) {
            if ($entry -band 1) { $entry = ($entry -shr 1) -bxor 0xA001 }
            else { $entry = $entry -shr 1 }
        }
        $entry
    })
    $value = 0
    foreach ($octet in [Text.Encoding]::ASCII.GetBytes($Text)) {
        $value = ($value -shr 8) -bxor $table[($value -bxor $octet) -band 255]
    }
    '{0:X4}' -f $value
}
foreach ($passwordFixture in @('', 'secret')) {
    Test-Case "IPS 2.2 wire version and CRC (password='$passwordFixture')" {
        $wirePassword = if ($passwordFixture) { $passwordFixture } else { 'NA' }
        $data = "2.0;012345678901234;$wirePassword;"
        $expected = '#L#' + $data + (Get-ReferenceCrc $data) + "`r`n"
        Assert-Equal (New-IpsLoginPacket -Imei '012345678901234' -Protocol '2.2' -Password $passwordFixture) $expected
    }
}

function Invoke-ProbeProcess([hashtable] $Parameters, [string] $InputText = '') {
    $command = "[Console]::OutputEncoding = [Text.UTF8Encoding]::new(); & '" + $probePath.Replace("'", "''") + "'"
    foreach ($key in $Parameters.Keys) {
        $command += " -$key '" + ([string]$Parameters[$key]).Replace("'", "''") + "'"
    }
    $command += '; exit $LASTEXITCODE'
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $process = [Diagnostics.Process]::new()
    $process.StartInfo.FileName = Join-Path $PSHOME 'powershell.exe'
    $process.StartInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded"
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    $process.StartInfo.RedirectStandardInput = $true
    $process.StartInfo.StandardOutputEncoding = [Text.Encoding]::UTF8
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.Write($InputText)
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(12000)) { throw 'Probe process exceeded 12 seconds (possibly prompting)' }
        [pscustomobject]@{ Code = $process.ExitCode; Output = $stdout.Result + $stderr.Result }
    }
    finally {
        if ($process.Id -and -not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
        $process.Dispose()
    }
}

function Invoke-NetworkCase([string] $Mode, [string] $Version = '2.2', [string] $Secret = '',
    [string] $BindAddress = '127.0.0.1', [string] $ConnectServer = '127.0.0.1', [int] $ConnectTimeout = 1) {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($BindAddress), 0)
    $listener.Start()
    $worker = [PowerShell]::Create()
    $serverBody = {
        param($Listener, $Mode)
        $ErrorActionPreference = 'Stop'
        function Read-Line($Stream) {
            $line = ''
            while ($true) {
                $b = $Stream.ReadByte()
                if ($b -lt 0) { return $line }
                $line += [char]$b
                if ($line.EndsWith("`r`n")) { return $line }
            }
        }
        function Send($Stream, $Text) {
            $bytes = [Text.Encoding]::ASCII.GetBytes($Text)
            $Stream.Write($bytes, 0, $bytes.Length)
        }
        $client = $null
        try {
            $accept = $Listener.AcceptTcpClientAsync()
            if (-not $accept.Wait(5000)) { throw 'Client did not connect' }
            $client = $accept.Result
            $stream = $client.GetStream()
            $stream.ReadTimeout = 5000
            $login = Read-Line $stream
            if ($Mode -eq 'closeLogin') { return @{ Login = $login; Ping = '' } }
            if ($Mode -eq 'silentLogin') { Start-Sleep -Milliseconds 1600; return @{ Login = $login; Ping = '' } }
            if ($Mode -eq 'slow') {
                # Keep sending within the deadline, then leave the partial line open beyond it.
                foreach ($c in '#AL'.ToCharArray()) {
                    Send $stream ([string]$c)
                    Start-Sleep -Milliseconds 450
                }
                return @{ Login = $login; Ping = '' }
            }
            if ($Mode -eq 'oversized') {
                Send $stream ('x' * 4100)
                return @{ Login = $login; Ping = '' }
            }
            if ($Mode -in @('0', '01', '10', 'unexpectedLogin')) {
                $reply = if ($Mode -eq 'unexpectedLogin') { '#AP#' } else { "#AL#$Mode" }
                Send $stream ($reply + "`r`n")
                $extra = Read-Line $stream
                return @{ Login = $login; Ping = $extra }
            }
            if ($Mode -eq 'fragmented') {
                Send $stream '#AL#'; Start-Sleep -Milliseconds 60
                Send $stream "1`r"; Start-Sleep -Milliseconds 60
                Send $stream "`n"
            }
            elseif ($Mode -eq 'combined') { Send $stream "#AL#1`r`n#AP#`r`n" }
            else { Send $stream "#AL#1`r`n" }
            $ping = Read-Line $stream
            if ($Mode -eq 'closePing') { return @{ Login = $login; Ping = $ping } }
            if ($Mode -eq 'silentPing') { Start-Sleep -Milliseconds 1600; return @{ Login = $login; Ping = $ping } }
            if ($Mode -eq 'unexpectedPing') { Send $stream "#AL#1`r`n" }
            elseif ($Mode -eq 'echoSecret') { Send $stream "secret`r`n" }
            elseif ($Mode -eq 'fragmented') {
                Send $stream '#A'; Start-Sleep -Milliseconds 60; Send $stream "P#`r`n"
            }
            elseif ($Mode -ne 'combined') { Send $stream "#AP#`r`n" }
            return @{ Login = $login; Ping = $ping }
        }
        finally { if ($client) { $client.Dispose() } }
    }
    try {
        [void]$worker.AddScript($serverBody.ToString()).AddArgument($listener).AddArgument($Mode)
        $running = $worker.BeginInvoke()
        $argsForProbe = @{ Server = $ConnectServer; Port = $listener.LocalEndpoint.Port; Imei = '012345678901234'; Protocol = $Version; TimeoutSeconds = $ConnectTimeout }
        if ($Secret) { $argsForProbe.Password = $Secret }
        $result = Invoke-ProbeProcess $argsForProbe
        if (-not $running.AsyncWaitHandle.WaitOne(6000)) { throw 'Server did not finish' }
        try { $serverResult = @($worker.EndInvoke($running)) }
        catch { throw ("Server error: $($_.Exception.Message); client output: " + $result.Output) }
        if ($worker.HadErrors) { throw ($worker.Streams.Error | Out-String) }
        if ($serverResult.Count -ne 1) { throw 'No server result' }
        $wire = $serverResult[0]
        $wirePassword = if ($Secret) { $Secret } else { 'NA' }
        $expected = if ($Version -eq '1.1') { "#L#012345678901234;$wirePassword`r`n" }
        else {
            $data = "2.0;012345678901234;$wirePassword;"
            '#L#' + $data + (Get-ReferenceCrc $data) + "`r`n"
        }
        Assert-Equal $wire.Login $expected
        $success = $Mode -in @('success', 'fragmented', 'combined')
        if ($success) { Assert-Equal $result.Code 0 }
        elseif ($result.Code -eq 0) { throw 'Failure scenario reported success' }
        $hasPing = $success -or $Mode -in @('closePing', 'silentPing', 'unexpectedPing', 'echoSecret')
        Assert-Equal $wire.Ping $(if ($hasPing) { "#P#`r`n" } else { '' })
        if ($Secret -and $result.Output.Contains($Secret)) { throw 'Password leaked into console output' }
        if ($Mode -like 'silent*' -or $Mode -eq 'slow') {
            if ($result.Output -notmatch 'таймаут') { throw "Missing timeout diagnostic: $($result.Output)" }
        }
        if ($Mode -eq '01' -and $result.Output -notmatch 'парол') { throw 'Missing password rejection diagnostic' }
        if ($Mode -eq '10' -and $result.Output -notmatch 'CRC') { throw 'Missing CRC rejection diagnostic' }
    }
    finally { $listener.Stop(); $worker.Dispose() }
}

if (-not $PacketsOnly) {
    Test-Case 'TCP IPv6 literal' { Invoke-NetworkCase 'success' '2.2' '' '::1' '::1' }
    Test-Case 'TCP IPv6 bracketed' { Invoke-NetworkCase 'success' '1.1' '' '::1' '[::1]' }
    Test-Case 'TCP domain localhost' { Invoke-NetworkCase 'success' '2.2' '' '127.0.0.1' 'localhost' 5 }
    foreach ($versionFixture in @('1.1', '2.2')) {
        foreach ($secretFixture in @('', 'secret')) {
            Test-Case "TCP success $versionFixture password='$secretFixture'" { Invoke-NetworkCase 'success' $versionFixture $secretFixture }
        }
    }
    foreach ($modeFixture in @('fragmented', 'combined', '0', '01', '10', 'unexpectedLogin', 'unexpectedPing', 'closeLogin', 'closePing', 'silentLogin', 'silentPing', 'slow', 'oversized', 'echoSecret')) {
        Test-Case "TCP $modeFixture" { Invoke-NetworkCase $modeFixture '2.2' 'secret' }
    }
    foreach ($bad in @(
        @{ Port = '0' }, @{ Port = '65536' }, @{ Port = 'abc' }, @{ Imei = '123' },
        @{ Protocol = '2.0' }, @{ TimeoutSeconds = '0' }, @{ TimeoutSeconds = '301' },
        @{ Server = 'http://localhost' }, @{ Server = '' }, @{ Password = 'bad;password' },
        @{ Password = "bad`r`npassword" }, @{ Password = ([string][char]0x044F) }
    )) {
        Test-Case "Reject invalid $($bad.Keys -join ',') '$($bad.Values -join ',')'" {
            $parameters = @{ Server = '127.0.0.1'; Port = '9'; Imei = '012345678901234'; Protocol = '1.1' }
            foreach ($key in $bad.Keys) { $parameters[$key] = $bad[$key] }
            $result = Invoke-ProbeProcess $parameters
            if ($result.Code -eq 0) { throw 'Invalid argument accepted' }
            if ($result.Output -notmatch 'Ввод') { throw "Expected validation error: $($result.Output)" }
            if ($bad.ContainsKey('Password') -and $result.Output.Contains($bad.Password)) { throw 'Invalid password leaked' }
        }
    }
    Test-Case 'Connection refused is diagnosed' {
        $reserved = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $reserved.Start(); $closedPort = $reserved.LocalEndpoint.Port; $reserved.Stop()
        $result = Invoke-ProbeProcess @{ Server = '127.0.0.1'; Port = $closedPort; Imei = '012345678901234'; Protocol = '1.1'; TimeoutSeconds = '1' }
        if ($result.Code -eq 0 -or $result.Output -notmatch 'Подключение') { throw "Wrong connection diagnostic: $($result.Output)" }
    }
    Test-Case 'Interactive invalid port can be corrected' {
        # The corrected port is closed: reaching connection diagnostics proves input correction completed.
        $result = Invoke-ProbeProcess @{ Server = '127.0.0.1'; Imei = '012345678901234'; Protocol = '1.1'; Password = ''; TimeoutSeconds = '1' } "wrong`n9`n"
        if ($result.Code -eq 0 -or $result.Output -notmatch 'Подключение') { throw "Interactive correction failed: $($result.Output)" }
    }
}

Write-Host "Tests: $script:passed passed, $script:failed failed"
if ($script:failed) { exit 1 }
exit 0
