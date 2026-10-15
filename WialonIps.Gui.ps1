#requires -Version 5.1

$script:IpsCorePath = Join-Path $PSScriptRoot 'Test-WialonIps.ps1'
. $script:IpsCorePath

function Set-IpsGuiStage($View, [string] $Stage, [string] $State) {
    $names = @{ Waiting = 'Ожидание'; Running = 'Выполняется...'; Passed = 'Успешно'; Failed = 'Ошибка' }
    $colors = @{ Waiting = '#64748B'; Running = '#175CD3'; Passed = '#167044'; Failed = '#B42318' }
    $View.StageStates[$Stage] = $State
    $View.StageLabels[$Stage].Text = $names[$State]
    $View.StageLabels[$Stage].ForeColor = [Drawing.ColorTranslator]::FromHtml($colors[$State])
}

function Set-IpsGuiBusy($View, [bool] $Busy) {
    foreach ($control in @($View.Server, $View.Port, $View.Imei, $View.Protocol, $View.Password, $View.Timeout, $View.RunButton)) {
        $control.Enabled = -not $Busy
    }
    $View.RunButton.Text = if ($Busy) { 'Проверяем...' } else { 'Проверить' }
}

function Add-IpsGuiLog($View, [string] $Message) {
    $View.Journal.AppendText($Message + [Environment]::NewLine)
    $View.CopyButton.Enabled = $View.Journal.TextLength -gt 0
}

function Stop-IpsGuiWorker($View) {
    $View.Timer.Stop()
    if ($View.Worker) {
        # Закрытие сокета прерывает ожидание ответа даже при большом таймауте.
        $View.Session.Cancelled = $true
        $client = $View.Session.Client
        if ($client) { $client.Dispose() }
        try { $View.Worker.Stop() }
        finally { $View.Worker.Dispose(); $View.Worker = $null; $View.Async = $null }
    }
}

function Start-IpsGuiCheck($View) {
    if ($View.Worker) { return }
    $View.Journal.Clear()
    $View.CopyButton.Enabled = $false
    foreach ($key in @('Connection', 'Login', 'Ping')) { Set-IpsGuiStage $View $key 'Waiting' }
    try {
        $values = @{ Server = $View.Server.Text; Port = [string]$View.Port.Value;
            Imei = $View.Imei.Text; Protocol = [string]$View.Protocol.SelectedItem;
            Password = $View.Password.Text; TimeoutSeconds = [string]$View.Timeout.Value }
        $options = Resolve-IpsProbeParameters $values
        $View.Summary.Text = 'Проверка выполняется...'
        $View.Summary.ForeColor = [Drawing.ColorTranslator]::FromHtml('#175CD3')
        Set-IpsGuiBusy $View $true
        $View.Queue = [Collections.Concurrent.ConcurrentQueue[object]]::new()
        $View.Session = [hashtable]::Synchronized(@{ Client = $null; Cancelled = $false })
        $View.Worker = [PowerShell]::Create()
        $workerBody = {
            param($CorePath, $Options, $Queue, $Session)
            $ErrorActionPreference = 'Stop'
            try {
                . $CorePath
                Invoke-IpsProbe @Options -Session $Session -OnProgress { param($entry) $Queue.Enqueue($entry) }
                return @{ Success = $true }
            }
            catch { return @{ Success = $false; Message = (Format-IpsDisplay $_.Exception.Message $Options.Password) } }
        }
        [void]$View.Worker.AddScript($workerBody.ToString()).AddArgument($script:IpsCorePath).AddArgument($options).AddArgument($View.Queue).AddArgument($View.Session)
        $View.Async = $View.Worker.BeginInvoke()
        $View.Timer.Start()
    }
    catch {
        $View.Summary.Text = Format-IpsDisplay $_.Exception.Message $View.Password.Text
        $View.Summary.ForeColor = [Drawing.ColorTranslator]::FromHtml('#B42318')
        Add-IpsGuiLog $View $View.Summary.Text
        Stop-IpsGuiWorker $View
        Set-IpsGuiBusy $View $false
    }
}

function Update-IpsGuiCheck($View) {
    if (-not $View.Worker) { return }
    # Сначала проверяем завершение, затем читаем очередь: последние события уже опубликованы.
    $completed = $View.Async.IsCompleted
    $entry = $null
    while ($View.Queue.TryDequeue([ref]$entry)) {
        Add-IpsGuiLog $View $entry.Message
        if ($entry.Stage -in @('Connection', 'Login', 'Ping') -and $entry.State -ne 'Info') {
            Set-IpsGuiStage $View $entry.Stage $entry.State
        }
        if ($entry.State -eq 'Failed') {
            $View.Summary.Text = 'Проверка не пройдена. ' + $entry.Message
            $View.Summary.ForeColor = [Drawing.ColorTranslator]::FromHtml('#B42318')
        }
        elseif ($entry.Stage -eq 'Summary') {
            $View.Summary.Text = $entry.Message
            $View.Summary.ForeColor = [Drawing.ColorTranslator]::FromHtml('#167044')
        }
        elseif ($entry.State -eq 'Running') { $View.Summary.Text = $entry.Message }
    }
    if ($completed) {
        try {
            $result = @($View.Worker.EndInvoke($View.Async))
            if ($result.Count -ne 1) { throw 'Не удалось получить результат проверки.' }
            if (-not $result[0].Success -and $View.Summary.Text -notlike 'Проверка не пройдена.*') {
                throw $result[0].Message
            }
        }
        catch {
            $View.Summary.Text = 'Проверка не пройдена. ' + (Format-IpsDisplay $_.Exception.Message $View.Password.Text)
            $View.Summary.ForeColor = [Drawing.ColorTranslator]::FromHtml('#B42318')
            Add-IpsGuiLog $View $View.Summary.Text
            foreach ($key in @('Connection', 'Login', 'Ping')) {
                if ($View.StageStates[$key] -eq 'Running') { Set-IpsGuiStage $View $key 'Failed' }
            }
        }
        finally {
            $View.Worker.Dispose()
            $View.Worker = $null
            $View.Async = $null
            $View.Queue = $null
            $View.Session = $null
            $View.Timer.Stop()
            Set-IpsGuiBusy $View $false
        }
    }
}

function New-IpsGui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()
    $form = [Windows.Forms.Form]::new()
    $form.Text = 'Проверка Wialon IPS'
    $form.ClientSize = [Drawing.Size]::new(760, 720)
    $form.MinimumSize = [Drawing.Size]::new(720, 660)
    $form.StartPosition = 'CenterScreen'
    $form.Font = [Drawing.Font]::new('Segoe UI', 10)
    $form.BackColor = [Drawing.Color]::White
    $form.ForeColor = [Drawing.ColorTranslator]::FromHtml('#243247')
    $form.AutoScaleMode = 'Font'
    $layout = [Windows.Forms.TableLayoutPanel]::new()
    $layout.Dock = 'Fill'
    $layout.Padding = [Windows.Forms.Padding]::new(24, 18, 24, 22)
    $layout.ColumnCount = 1
    $layout.RowCount = 7
    [void]$layout.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new([Windows.Forms.SizeType]::Percent, 100))
    foreach ($height in @(76, 144, 52, 72, 68, 28)) {
        [void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new([Windows.Forms.SizeType]::Absolute, $height))
    }
    [void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new([Windows.Forms.SizeType]::Percent, 100))
    $form.Controls.Add($layout)
    $header = [Windows.Forms.Panel]::new()
    $header.Dock = 'Fill'
    $title = [Windows.Forms.Label]::new()
    $title.Text = 'Проверка Wialon IPS'
    $title.Font = [Drawing.Font]::new('Segoe UI', 20, [Drawing.FontStyle]::Bold)
    $title.AutoSize = $true
    $title.Location = [Drawing.Point]::new(0, 0)
    $subtitle = [Windows.Forms.Label]::new()
    $subtitle.Text = 'Введите данные сервера и трекера, затем нажмите «Проверить».'
    $subtitle.AutoSize = $true
    $subtitle.Location = [Drawing.Point]::new(2, 43)
    $header.Controls.AddRange(@($title, $subtitle))
    $layout.Controls.Add($header, 0, 0)

    $fields = [Windows.Forms.TableLayoutPanel]::new()
    $fields.Dock = 'Fill'
    $fields.ColumnCount = 4
    $fields.RowCount = 3
    foreach ($width in @(18, 43, 21, 18)) {
        [void]$fields.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new([Windows.Forms.SizeType]::Percent, $width))
    }
    foreach ($row in 1..3) { [void]$fields.RowStyles.Add([Windows.Forms.RowStyle]::new([Windows.Forms.SizeType]::Percent, 33.333)) }
    $serverBox = [Windows.Forms.TextBox]::new()
    $portBox = [Windows.Forms.NumericUpDown]::new()
    $portBox.Minimum = 1; $portBox.Maximum = 65535; $portBox.Value = 20332
    $imeiBox = [Windows.Forms.TextBox]::new()
    $protocolBox = [Windows.Forms.ComboBox]::new()
    $protocolBox.DropDownStyle = 'DropDownList'
    $protocolBox.Items.AddRange(@('1.1', '2.2')); $protocolBox.SelectedItem = '2.2'
    $passwordBox = [Windows.Forms.TextBox]::new()
    $passwordBox.UseSystemPasswordChar = $true
    $timeoutBox = [Windows.Forms.NumericUpDown]::new()
    $timeoutBox.Minimum = 1; $timeoutBox.Maximum = 300; $timeoutBox.Value = 5
    $inputRows = @(
        @{ Label = 'IP / домен'; Control = $serverBox; Row = 0; Col = 0 },
        @{ Label = 'Порт'; Control = $portBox; Row = 0; Col = 2 },
        @{ Label = 'IMEI'; Control = $imeiBox; Row = 1; Col = 0 },
        @{ Label = 'Версия IPS'; Control = $protocolBox; Row = 1; Col = 2 },
        @{ Label = 'Пароль'; Control = $passwordBox; Row = 2; Col = 0 },
        @{ Label = 'Таймаут, с'; Control = $timeoutBox; Row = 2; Col = 2 }
    )
    foreach ($item in $inputRows) {
        $label = [Windows.Forms.Label]::new()
        $label.Text = $item.Label
        $label.Dock = 'Fill'; $label.TextAlign = 'MiddleLeft'
        $label.Margin = [Windows.Forms.Padding]::new($(if ($item.Col -eq 2) { 18 } else { 0 }), 0, 0, 8)
        $item.Control.Anchor = 'Left,Right'
        $item.Control.Margin = [Windows.Forms.Padding]::new(0, 0, 0, 8)
        $fields.Controls.Add($label, $item.Col, $item.Row)
        $fields.Controls.Add($item.Control, ($item.Col + 1), $item.Row)
    }
    $layout.Controls.Add($fields, 0, 1)
    $actions = [Windows.Forms.FlowLayoutPanel]::new()
    $actions.Dock = 'Fill'
    $actions.Margin = [Windows.Forms.Padding]::new(0)
    $runButton = [Windows.Forms.Button]::new()
    $runButton.Text = 'Проверить'; $runButton.Size = [Drawing.Size]::new(152, 38)
    $runButton.FlatStyle = 'Flat'; $runButton.FlatAppearance.BorderSize = 0
    $runButton.BackColor = [Drawing.ColorTranslator]::FromHtml('#175CD3')
    $runButton.ForeColor = [Drawing.Color]::White
    $runButton.Margin = [Windows.Forms.Padding]::new(0, 2, 12, 0)
    $copyButton = [Windows.Forms.Button]::new()
    $copyButton.Text = 'Скопировать журнал'; $copyButton.Size = [Drawing.Size]::new(196, 38)
    $copyButton.Margin = [Windows.Forms.Padding]::new(0, 2, 0, 0)
    $copyButton.Enabled = $false
    $actions.Controls.AddRange(@($runButton, $copyButton))
    $layout.Controls.Add($actions, 0, 2)

    $stages = [Windows.Forms.TableLayoutPanel]::new()
    $stages.Dock = 'Fill'; $stages.ColumnCount = 3; $stages.RowCount = 1
    $stages.Margin = [Windows.Forms.Padding]::new(0)
    $stageLabels = @{}
    $stageNames = @{ Connection = 'Подключение'; Login = 'Авторизация'; Ping = 'Ping' }
    $column = 0
    foreach ($key in @('Connection', 'Login', 'Ping')) {
        [void]$stages.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new([Windows.Forms.SizeType]::Percent, 33.333))
        $panel = [Windows.Forms.Panel]::new()
        $panel.Dock = 'Fill'; $panel.BackColor = [Drawing.ColorTranslator]::FromHtml('#F2F5F9')
        $panel.Margin = [Windows.Forms.Padding]::new(0, 0, $(if ($column -lt 2) { 8 } else { 0 }), 0)
        $heading = [Windows.Forms.Label]::new()
        $heading.Text = $stageNames[$key]; $heading.AutoSize = $true
        $heading.Font = [Drawing.Font]::new('Segoe UI', 10, [Drawing.FontStyle]::Bold)
        $heading.Location = [Drawing.Point]::new(12, 10)
        $state = [Windows.Forms.Label]::new()
        $state.AutoSize = $true; $state.Location = [Drawing.Point]::new(12, 37)
        $panel.Controls.AddRange(@($heading, $state))
        $stages.Controls.Add($panel, $column, 0)
        $stageLabels[$key] = $state; $column++
    }
    $layout.Controls.Add($stages, 0, 3)
    $summary = [Windows.Forms.Label]::new()
    $summary.Dock = 'Fill'; $summary.TextAlign = 'MiddleLeft'
    $summary.Text = 'Готово к проверке. Пароль можно оставить пустым.'
    $summary.Margin = [Windows.Forms.Padding]::new(0)
    $layout.Controls.Add($summary, 0, 4)
    $logLabel = [Windows.Forms.Label]::new()
    $logLabel.Text = 'Обмен с сервером'; $logLabel.Dock = 'Fill'
    $logLabel.Margin = [Windows.Forms.Padding]::new(0)
    $layout.Controls.Add($logLabel, 0, 5)
    $journal = [Windows.Forms.TextBox]::new()
    $journal.Multiline = $true; $journal.ReadOnly = $true; $journal.WordWrap = $false
    $journal.ScrollBars = 'Both'; $journal.Dock = 'Fill'
    $journal.Font = [Drawing.Font]::new('Consolas', 10)
    $journal.BackColor = [Drawing.ColorTranslator]::FromHtml('#F8FAFC')
    $journal.BorderStyle = 'FixedSingle'; $journal.Margin = [Windows.Forms.Padding]::new(0)
    $layout.Controls.Add($journal, 0, 6)
    $timer = [Windows.Forms.Timer]::new()
    $timer.Interval = 100
    $view = @{ Form = $form; Server = $serverBox; Port = $portBox; Imei = $imeiBox;
        Protocol = $protocolBox; Password = $passwordBox; Timeout = $timeoutBox;
        RunButton = $runButton; CopyButton = $copyButton; Journal = $journal; Summary = $summary;
        StageLabels = $stageLabels; StageStates = @{}; Timer = $timer;
        Worker = $null; Async = $null; Queue = $null; Session = $null }
    foreach ($key in @('Connection', 'Login', 'Ping')) { Set-IpsGuiStage $view $key 'Waiting' }
    $form.Tag = $view
    $runButton.Add_Click({ param($sender, $e) Start-IpsGuiCheck $sender.FindForm().Tag })
    $copyButton.Add_Click({
        param($sender, $e)
        $current = $sender.FindForm().Tag
        try { [Windows.Forms.Clipboard]::SetText($current.Journal.Text) }
        catch { $current.Summary.Text = 'Буфер обмена занят. Повторите копирование.' }
    })
    $timer.Add_Tick({ Update-IpsGuiCheck $view }.GetNewClosure())
    $form.Add_FormClosing({ param($sender, $e) Stop-IpsGuiWorker $sender.Tag })
    $form.Add_FormClosed({ param($sender, $e) $sender.Tag.Timer.Dispose(); $sender.Tag.Password.Clear() })
    $form.Add_Disposed({ param($sender, $e) Stop-IpsGuiWorker $sender.Tag; $sender.Tag.Timer.Dispose() })
    $form.AcceptButton = $runButton
    $form.ActiveControl = $serverBox
    return $view
}

if ($MyInvocation.InvocationName -ne '.') {
    $ErrorActionPreference = 'Stop'
    try {
        $window = New-IpsGui
        try { [void]$window.Form.ShowDialog() }
        finally { Stop-IpsGuiWorker $window; $window.Timer.Dispose(); $window.Form.Dispose() }
    }
    catch {
        Add-Type -AssemblyName System.Windows.Forms
        [void][Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Не удалось открыть Wialon IPS', 'OK', 'Error')
        exit 1
    }
}
