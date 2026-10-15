#requires -Version 5.1
param([string] $Filter = '*')
$ErrorActionPreference = 'Stop'
$script:passed = 0
$script:failed = 0
$projectPath = Split-Path $PSScriptRoot -Parent
. (Join-Path $projectPath 'Test-WialonIps.ps1')
$guiPath = Join-Path $projectPath 'WialonIps.Gui.ps1'
if (Test-Path -LiteralPath $guiPath) { . $guiPath }

function Assert-True($Condition, [string] $Message) { if (-not $Condition) { throw $Message } }
function Test-Case([string] $Name, [scriptblock] $Body) {
    if ($Name -notlike $Filter) { return }
    try { & $Body; $script:passed++; Write-Host "PASS $Name" }
    catch { $script:failed++; Write-Host "FAIL $Name : $($_.Exception.Message)" }
}

Test-Case 'Shared validation normalizes input and preserves IMEI' {
    $options = Resolve-IpsProbeParameters @{ Server = ' [::1] '; Port = '20332'; Imei = '012345678901234'; Protocol = '2.2'; Password = '' }
    Assert-True ($options.Server -ceq '::1' -and $options.Port -eq 20332 -and $options.Imei -ceq '012345678901234' -and $options.TimeoutSeconds -eq 5) 'Incorrect normalized parameters'
}
Test-Case 'GUI validation rejects incomplete values without prompting' {
    $rejected = $false
    try { $null = Resolve-IpsProbeParameters @{ Server = ''; Port = 20332; Imei = '012345678901234'; Protocol = '2.2' } }
    catch { $rejected = $_.Exception.Message -match 'Ввод' }
    Assert-True $rejected 'Empty server must be rejected'
}
Test-Case 'Form has editable inputs and correct initial states' {
    $view = New-IpsGui
    try {
        Assert-True ($view.Form -is [Windows.Forms.Form]) 'Missing window'
        Assert-True ($view.Protocol.Items.Count -eq 2 -and $view.Protocol.SelectedItem -ceq '2.2') 'Protocol choice missing'
        Assert-True $view.Password.UseSystemPasswordChar 'Password must be hidden'
        Assert-True ($view.Port.Value -eq 20332 -and $view.Timeout.Value -eq 5) 'Wrong defaults'
        Assert-True ($view.RunButton.Enabled -and -not $view.CopyButton.Enabled) 'Wrong button state'
        Assert-True ($view.Journal.ReadOnly -and $view.Journal.TextLength -eq 0) 'Journal must be empty and read-only'
    }
    finally { $view.Form.Dispose() }
}
Test-Case 'Invalid form stays idle and shows useful error' {
    $view = New-IpsGui
    try {
        $view.Server.Text = ''
        $view.Imei.Text = '012345678901234'
        Start-IpsGuiCheck $view
        Assert-True ($null -eq $view.Worker -and $view.RunButton.Enabled) 'Invalid input started worker'
        Assert-True ($view.Summary.Text -match 'IP|домен' -and $view.Summary.Text -notmatch 'пройдена') 'Missing validation guidance'
    }
    finally { $view.Form.Dispose() }
}

function Test-GuiNetwork([string] $Mode, [string] $Version = '2.2') {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $server = [PowerShell]::Create()
    $view = $null
    $listener.Start()
    try {
        $serverCode = {
            param($Listener, $Mode)
            function Send($Stream, $Text) {
                $b = [Text.Encoding]::ASCII.GetBytes($Text)
                $Stream.Write($b, 0, $b.Length)
            }
            $client = $null
            try {
                $accept = $Listener.AcceptTcpClientAsync()
                if (-not $accept.Wait(5000)) { throw 'Client did not connect' }
                $client = $accept.Result
                $stream = $client.GetStream()
                $stream.ReadTimeout = 4000
                $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::ASCII)
                $login = $reader.ReadLine()
                if ($Mode -eq 'timeout' -or $Mode -eq 'close') {
                    Start-Sleep -Milliseconds 1700
                    return @{ Login = $login; Ping = $null }
                }
                if ($Mode -eq 'refused') {
                    Send $stream "#AL#01`r`n"
                    $extra = $reader.ReadLine()
                    return @{ Login = $login; Ping = $extra }
                }
                Send $stream "#AL#1`r`n"
                $ping = $reader.ReadLine()
                Send $stream "#AP#`r`n"
                return @{ Login = $login; Ping = $ping }
            }
            finally { if ($client) { $client.Dispose() } }
        }
        [void]$server.AddScript($serverCode.ToString()).AddArgument($listener).AddArgument($Mode)
        $serverAsync = $server.BeginInvoke()
        $view = New-IpsGui
        $view.Server.Text = '127.0.0.1'
        $view.Port.Value = $listener.LocalEndpoint.Port
        $view.Imei.Text = '012345678901234'
        $view.Protocol.SelectedItem = $Version
        $view.Password.Text = 'secret'
        $view.Timeout.Value = if ($Mode -eq 'close') { 300 } else { 1 }
        $startClock = [Diagnostics.Stopwatch]::StartNew()
        Start-IpsGuiCheck $view
        Assert-True ($startClock.ElapsedMilliseconds -lt 700) 'Start blocked the UI thread'
        Assert-True (-not $view.RunButton.Enabled -and -not $view.Server.Enabled) 'Inputs remain active while checking'
        if ($Mode -eq 'close') {
            $waitClock = [Diagnostics.Stopwatch]::StartNew()
            while ($view.StageStates.Login -ne 'Running' -and $waitClock.ElapsedMilliseconds -lt 2000) {
                [Windows.Forms.Application]::DoEvents()
                Start-Sleep -Milliseconds 20
            }
            Assert-True ($view.StageStates.Login -ceq 'Running' -and $null -ne $view.Session.Client) 'Did not reach an active response wait'
            $stopClock = [Diagnostics.Stopwatch]::StartNew()
            Stop-IpsGuiWorker $view
            Assert-True ($null -eq $view.Worker) 'Closing did not release the worker'
            Assert-True ($stopClock.ElapsedMilliseconds -lt 700) 'Closing waits for the network timeout'
            return
        }
        $deadline = [Diagnostics.Stopwatch]::StartNew()
        while ($null -ne $view.Worker -and $deadline.ElapsedMilliseconds -lt 7000) {
            [Windows.Forms.Application]::DoEvents()
            Start-Sleep -Milliseconds 20
        }
        Assert-True ($null -eq $view.Worker -and $view.RunButton.Enabled -and $view.Server.Enabled) 'Check did not finish and restore controls'
        Assert-True ($view.Journal.Text -notmatch 'secret' -and $view.CopyButton.Enabled) 'Journal leaked password or cannot be copied'
        if ($Mode -eq 'success') {
            Assert-True ($view.Summary.Text -match 'Проверка пройдена') 'Missing success result'
            foreach ($key in @('Connection', 'Login', 'Ping')) {
                Assert-True ($view.StageStates[$key] -ceq 'Passed') "Stage $key not passed"
            }
            Assert-True ($view.Journal.Text -match '#AL#1' -and $view.Journal.Text -match '#AP#') 'Missing packet log'
        }
        else {
            Assert-True ($view.StageStates.Login -ceq 'Failed' -and $view.StageStates.Ping -ceq 'Waiting') 'Failed login incorrectly advanced ping'
            if ($Mode -eq 'timeout') { Assert-True ($view.Summary.Text -match 'Таймаут') 'Missing timeout guidance' }
            else { Assert-True ($view.Summary.Text -match 'парол') 'Missing refusal guidance' }
        }
        if (-not $serverAsync.AsyncWaitHandle.WaitOne(5000)) { throw 'Server did not finish' }
        $wire = @($server.EndInvoke($serverAsync))[0]
        Assert-True ($wire.Login.StartsWith($(if ($Version -eq '1.1') { '#L#012345678901234;secret' } else { '#L#2.0;012345678901234;secret;' }))) 'Unexpected login packet'
        Assert-True ($wire.Ping -ceq $(if ($Mode -eq 'success') { '#P#' } else { $null })) 'Unexpected ping behavior'
        # A second check in the same window must start from clean state.
        $view.Server.Text = ''
        Start-IpsGuiCheck $view
        Assert-True ($null -eq $view.Worker -and $view.Summary.Text -match 'IP|домен') 'Window cannot run another check'
    }
    finally {
        if ($view) { Stop-IpsGuiWorker $view; $view.Form.Dispose() }
        $listener.Stop()
        $server.Dispose()
    }
}

Test-Case 'GUI runs successful IPS 1.1 exchange in background' { Test-GuiNetwork 'success' '1.1' }
Test-Case 'GUI runs successful IPS 2.2 exchange in background' { Test-GuiNetwork 'success' '2.2' }
Test-Case 'GUI reports refused login and does not ping' { Test-GuiNetwork 'refused' }
Test-Case 'GUI reports timeout and restores controls' { Test-GuiNetwork 'timeout' }
Test-Case 'Closing window releases active worker' { Test-GuiNetwork 'close' }

Test-Case 'Launcher starts STA PowerShell from a path with spaces and Cyrillic' {
    $scratch = Join-Path ([IO.Path]::GetTempPath()) ('ips-ui-' + [Guid]::NewGuid().ToString('N') + ' папка с пробелами')
    [void][IO.Directory]::CreateDirectory($scratch)
    $cmdProcess = [Diagnostics.Process]::new()
    try {
        $sourceLauncher = Join-Path $projectPath 'Запустить.cmd'
        $targetLauncher = Join-Path $scratch 'Запустить.cmd'
        [IO.File]::Copy($sourceLauncher, $targetLauncher)
        $stub = '[IO.File]::WriteAllText((Join-Path $PSScriptRoot ''started.txt''), ([Threading.Thread]::CurrentThread.ApartmentState.ToString() + '':'' + (Get-ExecutionPolicy -Scope Process)))'
        [IO.File]::WriteAllText((Join-Path $scratch 'WialonIps.Gui.ps1'), $stub, [Text.UTF8Encoding]::new($true))
        $cmdProcess.StartInfo.FileName = $env:ComSpec
        $cmdProcess.StartInfo.Arguments = '/d /s /c ""' + $targetLauncher + '""'
        $cmdProcess.StartInfo.UseShellExecute = $false
        $cmdProcess.StartInfo.CreateNoWindow = $true
        $cmdProcess.StartInfo.WindowStyle = 'Hidden'
        [void]$cmdProcess.Start()
        Assert-True ($cmdProcess.WaitForExit(5000)) 'Launcher did not exit'
        $marker = Join-Path $scratch 'started.txt'
        $clock = [Diagnostics.Stopwatch]::StartNew()
        while (-not [IO.File]::Exists($marker) -and $clock.ElapsedMilliseconds -lt 5000) { Start-Sleep -Milliseconds 40 }
        Assert-True ([IO.File]::Exists($marker)) 'Launcher did not execute the PS1 beside it'
        Assert-True ([IO.File]::ReadAllText($marker) -ceq 'STA:Bypass') 'Wrong apartment or process execution policy'
    }
    finally {
        $cmdProcess.Dispose()
        foreach ($name in @('Запустить.cmd', 'WialonIps.Gui.ps1', 'started.txt')) {
            $path = Join-Path $scratch $name
            if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) }
        }
        [IO.Directory]::Delete($scratch)
    }
}

Write-Host "Tests: $script:passed passed, $script:failed failed"
if ($script:failed) { exit 1 }
exit 0
