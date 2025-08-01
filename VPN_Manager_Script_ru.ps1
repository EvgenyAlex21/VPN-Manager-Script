# ПРОВЕРКА ПРАВ АДМИНИСТРАТОРА

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    try {
        $arguments = "& '" + $myinvocation.mycommand.path + "'"
        Start-Process powershell -Verb runAs -ArgumentList $arguments
        exit
    } catch {
        Write-Host "Не удалось получить права администратора! Пожалуйста, запустите скрипт от имени администратора..." -ForegroundColor Red
        exit
    }
}

# КОДИРОВКА UTF-8 С ПОДДЕРЖКОЙ КИРИЛЛИЦЫ

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# НАСТРОЙКИ ПО УМОЛЧАНИЮ

$vpnNameDefault = "VPN_EvgenyAlex"
$usernameDefault = "vpn"
$passwordDefault = "vpn"
$txtFile = Join-Path -Path $PSScriptRoot -ChildPath "sstp.txt"
$vpnServersBaseURL = "https://ipspeed.info/freevpn_sstp.php?language=ru&page="
$maxPages = 4

# ФУНКЦИЯ ДЛЯ ПОЛУЧЕНИЯ СЛУЧАЙНЫХ СЕРВЕРОВ SSTP ИЗ TXT ФАЙЛА

function Get-RandomServerFromFile {
    param ([string]$FilePath)
    try {
        if (-not (Test-Path $FilePath)) {
            Write-Host "Файл $FilePath не найден!" -ForegroundColor Red
            return $null
        }
        $servers = Get-Content -Path $FilePath -Encoding Default | Where-Object { -not [string]::IsNullOrEmpty($_.Trim()) }
        if ($servers.Count -eq 0) {
            Write-Host "Файл $FilePath пуст, либо не содержит серверов!" -ForegroundColor Yellow
            return $null
        }

        Write-Host "Всего серверов: $($servers.Count)" -ForegroundColor Cyan
        Write-Host "Выполняется случайный перебор доступных серверов..." -ForegroundColor Cyan
        foreach ($server in ($servers | Get-Random -Count $servers.Count)) {
            Write-Host "Пробуем сервер: $server" -ForegroundColor Yellow
            if (Test-VpnServerReachable -Server $server) {
                Write-Host "Сервер $server доступен и отвечает на пинг!" -ForegroundColor Green
                return $server
            }
        }
        Write-Host "Не удалось найти доступный сервер!" -ForegroundColor Red
        return $null
    }
    catch {
        Write-Host "Ошибка при чтении файла: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
} 

# ФУНКЦИЯ ДЛЯ ПОЛУЧЕНИЯ СЛУЧАЙНЫХ СЕРВЕРОВ SSTP ИЗ ВЕБ-САЙТА

function Get-RandomServerFromWeb {
    param ([string]$BaseURL, [int]$MaxPages)
    try {
        $allServers = @()
        for ($page = 1; $page -le $MaxPages; $page++) {
            $URL = "$BaseURL$page"
            Write-Host "Запрос к $URL..." -ForegroundColor Yellow
            $response = Invoke-WebRequest -Uri $URL -UseBasicParsing -ErrorAction Stop
            $html = $response.Content
            $divMatches = [regex]::Matches($html, '<div class="list".*?>(.*?)</div>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
            foreach ($match in $divMatches) {
                $divContent = $match.Groups[1].Value
                $pMatches = [regex]::Matches($divContent, '<p[^>]*>(.*?)</p>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
                if ($pMatches.Count -ge 2) {
                    $hostname = $pMatches[1].Groups[1].Value.Trim()
                    if ($hostname -match '\.') {
                        $allServers += $hostname
                    }
                }
            }
        }
        if ($allServers.Count -eq 0) { return $null }
        foreach ($server in ($allServers | Get-Random -Count $allServers.Count)) {
            if (Test-VpnServerReachable -Server $server) { return $server }
        }
        Write-Host "Нет доступных серверов по результатам проверки!" -ForegroundColor Red
        return $null
    }
    catch {
        Write-Host "Ошибка запроса к веб-сайту: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# ФУНКЦИЯ ДЛЯ ПРОВЕРКИ ДОСТУПНОСТИ СЕРВЕРА

function Test-VpnServerReachable {
    param ([string]$Server)
    try {
        Write-Host "Проверка доступности сервера: $Server..." -ForegroundColor Yellow
        $ping = Test-Connection -ComputerName $Server -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($ping) {
            Write-Host "Сервер $Server доступен!" -ForegroundColor Green
            return $true
        } else {
            Write-Host "Сервер $Server недоступен! Пробуем следующий..." -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "Ошибка при проверке доступности сервера ${Server}: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ФУНКЦИЯ ДЛЯ СМЕНЫ VPN СЕРВЕРА

function Change-VPNServer {
    param ([string]$VpnName, [string]$ServerAddress)
    try {
        $existingVpn = Get-VpnConnection -Name $VpnName -ErrorAction SilentlyContinue
        if (-not $existingVpn) {
            Write-Host "VPN '$VpnName' не найден!" -ForegroundColor Red
            return $false
        }
        Write-Host "Изменяем адрес сервера для VPN '$VpnName' на '$ServerAddress'..." -ForegroundColor Yellow
        Set-VpnConnection -Name $VpnName -ServerAddress $ServerAddress -ErrorAction Stop
        Write-Host "Адрес для '$VpnName' успешно изменён на: $ServerAddress" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Ошибка изменения сервера: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ФУНКЦИЯ ДЛЯ ПОДКЛЮЧЕНИЯ К VPN

function Connect-VPN {
    param ([string]$VpnName, [string]$Username, [string]$Password)
    $returnValue = $false 
    try {
        Write-Host "Проверка и отключение активных VPN-подключений перед подключением к '$VpnName'…" -ForegroundColor Cyan
        $null = Disconnect-AllActiveVpnConnections 
        
        Write-Host "Подключение к VPN '$VpnName'…" -ForegroundColor Yellow
        rasdial $VpnName $Username $Password | Out-Null 
        $rasdialExitCode = $LASTEXITCODE 

        Start-Sleep -Seconds 3 

        $vpnStatus = Get-VpnConnection -Name $VpnName -ErrorAction SilentlyContinue

        if ($rasdialExitCode -eq 0 -and $vpnStatus -and $vpnStatus.ConnectionStatus -eq 'Connected') {
            Write-Host "Успешно подключено к VPN '$VpnName'! (Rasdial Code: $rasdialExitCode, Status: $($vpnStatus.ConnectionStatus))." -ForegroundColor Green
            $returnValue = $true
        } else {

            $statusMsg = if ($vpnStatus) { $vpnStatus.ConnectionStatus } else { "Не найдено" }
            Write-Host "Ошибка подключения к VPN '$VpnName'! Код ошибки rasdial: $rasdialExitCode. Фактический статус VPN: '$statusMsg'..." -ForegroundColor Red
            
            if (($rasdialExitCode -ne 0 -and $vpnStatus -and $vpnStatus.ConnectionStatus -eq 'Connected') -or `
                ($rasdialExitCode -eq 0 -and ($vpnStatus -eq $null -or $vpnStatus.ConnectionStatus -ne 'Connected'))) {
                Write-Host "Обнаружено несоответствие состояния VPN для '$VpnName'! Попытка принудительного отключения..." -ForegroundColor Yellow
                rasdial $VpnName /DISCONNECT | Out-Null 
            }
            $returnValue = $false
        }
    }
    catch { 
        Write-Host "Исключение при выполнении Connect-VPN для '$VpnName': $($_.Exception.Message)" -ForegroundColor Red
        $returnValue = $false
    }
    Write-Host "Connect-VPN для '$VpnName' возвращает: $returnValue" -ForegroundColor Magenta
    return $returnValue
}

# ФУНКЦИЯ ДЛЯ ОТКЛЮЧЕНИЯ ОТ VPN

function Disconnect-VPN {
    param ([string]$VpnName)
    try {
        Write-Host "Отключение от VPN '$VpnName'..." -ForegroundColor Yellow
        rasdial $VpnName /DISCONNECT | Out-Null 
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Успешно отключен от VPN '$VpnName'!" -ForegroundColor Green
            return $true
        } else {
            Write-Host "Ошибка отключения от VPN '$VpnName'! Код ошибки: $LASTEXITCODE" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "Ошибка при отключении от VPN: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ФУНКЦИЯ ДЛЯ ОТКЛЮЧЕНИЯ ОТ АКТИВНЫХ ПОДКЛЮЧЕНИЙ VPN

function Disconnect-AllActiveVpnConnections {
    Write-Host "Проверка активных VPN-подключений..." -ForegroundColor Yellow
    try {

        $allVpnConnections = Get-VpnConnection -ErrorAction Stop
        $activeConnections = @()
        
        foreach ($vpn in $allVpnConnections) {
            $connectionStatus = Get-VpnConnection -Name $vpn.Name -ErrorAction SilentlyContinue
            if ($connectionStatus -and $connectionStatus.ConnectionStatus -eq "Connected") {
                $activeConnections += $connectionStatus
                Write-Host "Найдено активное VPN-подключение: '$($vpn.Name)'" -ForegroundColor Cyan
            }
        }
        
        if ($activeConnections.Count -gt 0) {
            Write-Host "Найдено $($activeConnections.Count) активных VPN-подключений! Отключаем..." -ForegroundColor Yellow
            foreach ($activeVpn in $activeConnections) {
                Write-Host "Отключение '$($activeVpn.Name)'..." -ForegroundColor Yellow
                if (Disconnect-VPN -VpnName $activeVpn.Name) {
                    Write-Host "VPN '$($activeVpn.Name)' успешно отключен!" -ForegroundColor Green
                } else {
                    Write-Host "Не удалось отключить VPN '$($activeVpn.Name)'!" -ForegroundColor Red
                }
                Start-Sleep -Seconds 2  
            }
        } else {
            Write-Host "Активных VPN-подключений не найдено!" -ForegroundColor Green
        }
        
        return $true
    }
    catch {
        Write-Host "Ошибка при проверке активных VPN-подключений: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ФУНКЦИЯ ДЛЯ ИЗМЕНЕНИЯ СЕРВЕРА ДЛЯ СУЩЕСТВУЮЩЕГО VPN

function Change-ExistingServer {
    Write-Host ""
    Write-Host "--- Изменить сервер для существующего VPN ---" -ForegroundColor Yellow
    Write-Host "---------------------------------------------"
    try {
        $vpnConnections = @(Get-VpnConnection -ErrorAction Stop)
        if ($vpnConnections.Count -eq 0) {
            Write-Host "Нет сохранённых VPN-подключений!" -ForegroundColor Red
            Show-MainMenu
            return
        }
        for ($i = 0; $i -lt $vpnConnections.Count; $i++) {
            Write-Host "$($i + 1). $($vpnConnections[$i].Name)"
        }
        Write-Host "0. Выход" 
    }
    catch {
        Write-Host "Ошибка получения списка VPN: $($_.Exception.Message)" -ForegroundColor Red
        Show-MainMenu
        return
    }
    $choice = Read-Host "Введите номер VPN для смены сервера:"
    if ($choice -eq "0") { Show-MainMenu; return }

    if ($choice -notmatch "^\d+$" -or [int]$choice -lt 1 -or [int]$choice -gt $vpnConnections.Count) {
        Write-Host "Некорректный номер!" -ForegroundColor Red
        Show-MainMenu
        return
    }
    $vpnName = $vpnConnections[[int]$choice - 1].Name
    Write-Host "Выбран VPN профиль: '$vpnName'" -ForegroundColor Cyan
    Write-Host "---------------------------------------------"

    Write-Host ""
    Write-Host "--- Параметры для VPN '$vpnName' ---" -ForegroundColor Cyan
    Write-Host "  Имя подключения: $vpnName" -ForegroundColor Cyan
    Write-Host "  Пользователь   : $usernameDefault" -ForegroundColor Cyan
    Write-Host "  Пароль         : $passwordDefault" -ForegroundColor Cyan
    Write-Host "-----------------------------------"
    Write-Host ""

    Write-Host "1. Получить сервера из интернета"
    Write-Host "2. Получить сервера из файла sstp.txt"
    Write-Host "0. Выход"
    $sourceChoice = Read-Host "Выберите источник списка серверов:"
    if ($sourceChoice -eq "0") { Show-MainMenu; return } 

    $availableServers = @()
    $serverSourceDescription = ""

    switch ($sourceChoice) {
        "1" {
            Write-Host "Загрузка списка серверов из интернета..." -ForegroundColor Yellow
            $availableServers = Get-SstpHostsFromWeb 
            $serverSourceDescription = "интернет"
            if ($availableServers.Count -eq 0) {
                Write-Host "Не удалось получить список серверов SSTP из $serverSourceDescription! Возврат в главное меню....." -ForegroundColor Red
                Show-MainMenu
                return
            }
            Write-Host "Получено $($availableServers.Count) серверов из $serverSourceDescription!" -ForegroundColor Green
        }
        "2" {
            Write-Host "Загрузка списка серверов из файла '$txtFile'..." -ForegroundColor Yellow
            if (-not (Test-Path $txtFile)) {
                Write-Host "Файл $txtFile не найден! Возврат в главное меню....." -ForegroundColor Red
                Show-MainMenu
                return
            }
            $fileContent = Get-Content -Path $txtFile -Encoding Default | Where-Object { -not [string]::IsNullOrEmpty($_.Trim()) }
            if ($fileContent.Count -eq 0) {
                Write-Host "Файл $txtFile пуст! Возврат в главное меню....." -ForegroundColor Red
                Show-MainMenu
                return
            }
            $availableServers = $fileContent
            $serverSourceDescription = "файла '$txtFile'"
            Write-Host "Получено $($availableServers.Count) серверов из $serverSourceDescription!" -ForegroundColor Green
        }
        default {
            Write-Host "Некорректный выбор! Возврат в главное меню....." -ForegroundColor Red
            Show-MainMenu
            return
        }
    }

    $shuffledServers = $availableServers | Get-Random -Count $availableServers.Count
    $connectionEstablished = $false
    $serverSuccessfullyChangedAtLeastOnce = $false
    $lastSuccessfullySetServer = $null

    foreach ($serverAddress in $shuffledServers) {
        Write-Host ""
        Write-Host "-------------------------------------------------------------"
        Write-Host "Пробуем сервер: $serverAddress (источник: $serverSourceDescription)" -ForegroundColor Cyan
        if (-not (Test-VpnServerReachable -Server $serverAddress)) {
            Write-Host "Сервер $serverAddress недоступен (не пингуется), пробуем следующий..." -ForegroundColor Yellow
            continue
        }
        
        Write-Host "Сервер $serverAddress доступен! Меняем адрес сервера для VPN '$vpnName' на '$serverAddress'..." -ForegroundColor Green
        if (Change-VPNServer -VpnName $vpnName -ServerAddress $serverAddress) {
            Write-Host "Адрес сервера для VPN '$vpnName' успешно изменён на '$serverAddress'!" -ForegroundColor Green
            $serverSuccessfullyChangedAtLeastOnce = $true
            $lastSuccessfullySetServer = $serverAddress
            
            Write-Host "Пробуем подключиться к VPN '$vpnName' с новым сервером..." -ForegroundColor Cyan
            if (Connect-VPN -VpnName $vpnName -Username $usernameDefault -Password $passwordDefault) {
                if (Test-InternetAccess) {
                    Write-Host "Успешно подключено к VPN '$vpnName' через сервер $serverAddress и есть доступ в интернет!" -ForegroundColor Green
                    $connectionEstablished = $true
                    break 
                } else {
                    Write-Host "Подключение к VPN '$vpnName' через $serverAddress установлено, но нет доступа в интернет! Отключаемся..." -ForegroundColor Yellow
                    Disconnect-VPN -VpnName $vpnName
                }
            } else {
                Write-Host "Не удалось подключиться к VPN '$vpnName' через сервер $serverAddress!" -ForegroundColor Yellow
                continue 
            }
        } else {
            Write-Host "Не удалось изменить адрес сервера для VPN '$vpnName' на '$serverAddress'!" -ForegroundColor Red
        }
    }

    if ($connectionEstablished) {
        Write-Host "Адрес сервера и подключение к VPN '$vpnName' успешно выполнены через сервер $serverAddress!" -ForegroundColor Green
    } else {
        Write-Host "Не удалось установить рабочее VPN-подключение для '$vpnName' ни с одним из доступных серверов (источник: $serverSourceDescription)!" -ForegroundColor Red
        if ($serverSuccessfullyChangedAtLeastOnce) {
            Write-Host "Адрес сервера для VPN '$vpnName' был изменён на последний успешно проверенный: $lastSuccessfullySetServer, но подключение к интернету не установлено!" -ForegroundColor Yellow
        } else {
            Write-Host "Адрес сервера для VPN '$vpnName' не был изменён!" -ForegroundColor Yellow
        }
    }
    Show-MainMenu
}

# ФУНКЦИЯ ДЛЯ ВКЛЮЧЕНИЯ VPN

function Enable-VpnMenu {
    Write-Host ""
    Write-Host "--- Включить VPN ---" -ForegroundColor Yellow
    Write-Host "--------------------"
    try {
        $vpnConnections = @(Get-VpnConnection -ErrorAction SilentlyContinue)
        if ($vpnConnections.Count -eq 0) {
            Write-Host "Нет сохранённых VPN-подключений для включения!" -ForegroundColor Red
            Show-MainMenu
            return
        }

        Write-Host "Выберите VPN подключение для включения:"
        for ($i = 0; $i -lt $vpnConnections.Count; $i++) {
            Write-Host "$($i + 1). $($vpnConnections[$i].Name)"
        }
        Write-Host "0. Выход"
        Write-Host "--------------------------------"

        $choice = Read-Host "Введите номер VPN для включения или 0 для возврата:"

        if ($choice -eq "0") {
            Show-MainMenu
            return
        }

        if ($choice -notmatch "^\d+$" -or [int]$choice -lt 1 -or [int]$choice -gt $vpnConnections.Count) {
            Write-Host "Некорректный номер!" -ForegroundColor Red
            Show-MainMenu
            return
        }

        $vpnNameToConnect = $vpnConnections[[int]$choice - 1].Name
        Write-Host "Выбрано для подключения: '$vpnNameToConnect'" -ForegroundColor Cyan
        
        Connect-VPN -VpnName $vpnNameToConnect -Username $usernameDefault -Password $passwordDefault
        
    } catch {
        Write-Host "Произошла ошибка при включении VPN: $($_.Exception.Message)" -ForegroundColor Red
    }
    Show-MainMenu
}

# ФУНКЦИЯ ДЛЯ ОТКЛЮЧЕНИЯ VPN

function Disable-VpnMenu {
    Write-Host ""
    Write-Host "--- Отключить VPN ---" -ForegroundColor Yellow
    Write-Host "---------------------"
    Disconnect-AllActiveVpnConnections
    Show-MainMenu
}

# ФУНКЦИЯ ДЛЯ ГЛАВНОГО МЕНЮ

function Show-MainMenu {
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Yellow
    Write-Host "     VPN Manager Script for Windows (powered by SSTP)     " -ForegroundColor Yellow
    Write-Host "                     by EvgenyAlex                        " -ForegroundColor Yellow
    Write-Host "              telegram - @x_evgenyalex_x                  " -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Инструкция по использованию:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Этот скрипт поможет вам управлять VPN-подключениями." -ForegroundColor Cyan
    Write-Host "Вы можете включить или выключить VPN." -ForegroundColor Cyan
    Write-Host "Создавать новые подключения (автоматически или вручную)." -ForegroundColor Cyan
    Write-Host "Изменять сервера для существующих, а также удалять их." -ForegroundColor Cyan
    Write-Host "Для навигации по меню используйте цифровые клавиши." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Выберите действие:"
    Write-Host "  1. Включить VPN"
    Write-Host "  2. Отключить VPN"
    Write-Host "  3. Автоматическая настройка VPN"
    Write-Host "  4. Ручная настройка VPN"
    Write-Host "  5. Изменить сервер существующего подключения"
    Write-Host "  6. Удаление сети" 
    Write-Host "  0. Выход"
    Write-Host "---------------------------------------------"
    $choice = Read-Host "Введите номер пункта меню:"
    switch ($choice) {
        "1" {
            Enable-VpnMenu
        }
        "2" {
            Disable-VpnMenu
        }
        "3" {
            Automatic-VPNSetup
        }
        "4" {
            Manual-VPNSetup
        }
        "5" {
            Change-ExistingServer
        }
        "6" { 
            Remove-VpnConnectionMenu
        }
        "0" {
            Write-Host "Выход из программы!" -ForegroundColor Green
            exit
        }
        default {
            Write-Host "Некорректный ввод! Пожалуйста, выберите пункт из меню..." -ForegroundColor Red
            Show-MainMenu
        }
    }
}

# ФУНКЦИЯ ДЛЯ АВТОМАТИЧЕСКОЙ НАСТРОЙКИ VPN

function Automatic-VPNSetup {
    Write-Host ""
    Write-Host "--- Автоматическая настройка VPN ---" -ForegroundColor Yellow
    Write-Host "----------------------------------"
    Write-Host ""

    Write-Host "--- Параметры VPN по умолчанию для автоматической настройки ---" -ForegroundColor Cyan
    Write-Host "  Имя подключения: $vpnNameDefault" -ForegroundColor Cyan
    Write-Host "  Пользователь   : $usernameDefault" -ForegroundColor Cyan
    Write-Host "  Пароль         : $passwordDefault" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------"
    Write-Host ""
    Write-Host "1. Продолжить с этими параметрами"
    Write-Host "0. Выход"
    $confirmation = Read-Host "Выберите действие:"

    if ($confirmation -ne "1") {
        Show-MainMenu
        return
    }
    Write-Host "" 

    $allHosts = Get-SstpHostsFromWeb
    if ($allHosts.Count -eq 0) {
        Write-Host "Не удалось получить список серверов SSTP из интернета! Попробуйте другой метод..." -ForegroundColor Red
        Show-MainMenu
        return
    }

    $shuffledHosts = $allHosts | Get-Random -Count $allHosts.Count
    $connectionEstablished = $false

    foreach ($serverAddress in $shuffledHosts) {
        Write-Host ""
        Write-Host "-------------------------------------------------------------"
        Write-Host "Пробуем сервер: $serverAddress" -ForegroundColor Cyan
        if (-not (Test-VpnServerReachable -Server $serverAddress)) {
            Write-Host "Сервер $serverAddress недоступен (не пингуется), пробуем следующий..." -ForegroundColor Yellow
            continue
        }
        
        Write-Host "Сервер $serverAddress доступен! Обеспечиваем конфигурацию VPN '$vpnNameDefault' с этим сервером..." -ForegroundColor Green

        if (Create-VpnConnectionIfNotExists -VpnName $vpnNameDefault -ServerAddress $serverAddress -Username $usernameDefault -Password $passwordDefault) {
            if (Connect-VPN -VpnName $vpnNameDefault -Username $usernameDefault -Password $passwordDefault) {
                if (Test-InternetAccess) {
                    Write-Host "Успешно подключено к VPN и есть доступ в интернет через сервер $serverAddress!" -ForegroundColor Green
                    $connectionEstablished = $true
                    break 
                } else {
                    Write-Host "Подключение к VPN '$vpnNameDefault' установлено, но нет доступа в интернет через $serverAddress! Отключаемся..." -ForegroundColor Yellow
                    Disconnect-VPN -VpnName $vpnNameDefault
                }
            } else {
                 Write-Host "Не удалось подключиться к VPN '$vpnNameDefault' через сервер $serverAddress! Пробуем следующий сервер..." -ForegroundColor Yellow
                 continue 
            }
        } else {
             Write-Host "Не удалось настроить (создать/обновить) VPN подключение '$vpnNameDefault' для сервера $serverAddress! Пробуем следующий сервер..." -ForegroundColor Red
             continue 
        }
    }

    if (-not $connectionEstablished) {
        Write-Host "Не удалось установить рабочее VPN-подключение ни с одним из доступных серверов!" -ForegroundColor Red
    }
    Show-MainMenu
}

# ФУНКЦИЯ ДЛЯ РУЧНОЙ НАСТРОЙКИ VPN

function Manual-VPNSetup {
    Write-Host ""
    Write-Host "--- Ручная настройка VPN ---" -ForegroundColor Yellow
    Write-Host "--------------------------" 

    $vpnName = $null
    while ($true) {
        $inputVpnName = Read-Host "1. Введите имя VPN подключения (нажмите Enter для '$vpnNameDefault' или 0 для выхода):"
        if ($inputVpnName -eq "0") { Show-MainMenu; return }
        $vpnName = if ([string]::IsNullOrWhiteSpace($inputVpnName)) { $vpnNameDefault } else { $inputVpnName }

        $existingVpn = Get-VpnConnection -Name $vpnName -ErrorAction SilentlyContinue
        if (-not $existingVpn) {
            break 
        }
        Write-Host "VPN с именем '$vpnName' уже существует!" -ForegroundColor Yellow
        $choice = Read-Host "Хотите ввести другое имя (д) или вернуться в главное меню (0)?"
        if ($choice -eq "0") { Show-MainMenu; return }
        if ($choice -ne "д") { 
             Write-Host "Некорректный ввод, возврат в главное меню..." -ForegroundColor Red
             Show-MainMenu; return
        }
    }
    
    $inputUsername = Read-Host "2. Введите имя пользователя (нажмите Enter для '$usernameDefault' или 0 для выхода):"
    if ($inputUsername -eq "0") { Show-MainMenu; return }
    $username = if ([string]::IsNullOrWhiteSpace($inputUsername)) { $usernameDefault } else { $inputUsername }

    $inputPassword = Read-Host "3. Введите пароль (нажмите Enter для '$passwordDefault' или 0 для выхода):"
    if ($inputPassword -eq "0") { Show-MainMenu; return }
    $password = if ([string]::IsNullOrWhiteSpace($inputPassword)) { $passwordDefault } else { $inputPassword }

    Write-Host ""
    Write-Host "--- Параметры для нового VPN ---" -ForegroundColor Cyan 
    Write-Host "  Имя подключения: $vpnName" -ForegroundColor Cyan
    Write-Host "  Пользователь   : $username" -ForegroundColor Cyan
    Write-Host "  Пароль         : $password" -ForegroundColor Cyan 
    Write-Host "--------------------------------" 
    Write-Host ""

    Write-Host "Выберите источник серверов для подключения:"
    Write-Host "1. Получить сервера из интернета"
    Write-Host "2. Получить сервера из файла sstp.txt"
    Write-Host "0. Выход" 
    Write-Host ""

    $serverSourceChoice = Read-Host "Выберите способ получения серверов или 0 для выхода:"
    if ($serverSourceChoice -eq "0") { Show-MainMenu; return }

    $availableServers = @()
    $serverSourceDescription = "" 

    switch ($serverSourceChoice) {
        "1" {
            Write-Host "Загрузка списка серверов из интернета..." -ForegroundColor Yellow
            $availableServers = Get-SstpHostsFromWeb
            if ($availableServers.Count -eq 0) {
                Write-Host "Не удалось получить список серверов SSTP из интернета! Возврат в главное меню..." -ForegroundColor Red
                Show-MainMenu
                return
            }
            $serverSourceDescription = "интернет"
            Write-Host "Получено $($availableServers.Count) серверов из $serverSourceDescription!" -ForegroundColor Green
        }
        "2" {
            Write-Host "Загрузка списка серверов из файла '$txtFile'..." -ForegroundColor Yellow
            if (-not (Test-Path $txtFile)) {
                Write-Host "Файл $txtFile не найден! Возврат в главное меню..." -ForegroundColor Red
                Show-MainMenu
                return
            }
            $fileServers = Get-Content -Path $txtFile -Encoding Default | Where-Object { -not [string]::IsNullOrEmpty($_.Trim()) }
            if ($fileServers.Count -eq 0) {
                Write-Host "Файл $txtFile пуст! Возврат в главное меню..." -ForegroundColor Red
                Show-MainMenu
                return
            }
            $availableServers = $fileServers
            $serverSourceDescription = "файла '$txtFile'"
            Write-Host "Получено $($availableServers.Count) серверов из $serverSourceDescription!" -ForegroundColor Green
        }
        "0" { 
            Show-MainMenu
            return
        }
        default {
            Write-Host "Некорректный выбор! Возврат в главное меню..." -ForegroundColor Red
            Show-MainMenu
            return
        }
    }

    $shuffledServers = $availableServers | Get-Random -Count $availableServers.Count
    $connectionEstablished = $false

    foreach ($serverAddress in $shuffledServers) {
        Write-Host ""
        Write-Host "-------------------------------------------------------------"
        Write-Host "Пробуем сервер: $serverAddress (источник: $serverSourceDescription)" -ForegroundColor Cyan 
        if (-not (Test-VpnServerReachable -Server $serverAddress)) {
            Write-Host "Сервер $serverAddress недоступен (не пингуется), пробуем следующий..." -ForegroundColor Yellow
            continue
        }
        
        Write-Host "Сервер $serverAddress доступен! Обеспечиваем конфигурацию VPN '$vpnName' с этим сервером..." -ForegroundColor Green

        if (Create-VpnConnectionIfNotExists -VpnName $vpnName -ServerAddress $serverAddress -Username $username -Password $password) {
            if (Connect-VPN -VpnName $vpnName -Username $username -Password $password) {
                if (Test-InternetAccess) {
                    Write-Host "Успешно подключено к VPN '$vpnName' и есть доступ в интернет через сервер $serverAddress!" -ForegroundColor Green
                    $connectionEstablished = $true
                    break 
                } else {
                    Write-Host "Подключение к VPN '$vpnName' установлено, но нет доступа в интернет через $serverAddress! Отключаемся..." -ForegroundColor Yellow
                    Disconnect-VPN -VpnName $vpnName
                }
            } else {
                 Write-Host "Не удалось подключиться к VPN '$vpnName' через сервер $serverAddress! Пробуем следующий сервер..." -ForegroundColor Yellow
                 continue 
            }
        } else {
            Write-Host "Не удалось настроить (создать/обновить) VPN подключение '$vpnName' для сервера $serverAddress! Пробуем следующий сервер..." -ForegroundColor Red
            continue
        }
    }

    if (-not $connectionEstablished) {
        Write-Host "Не удалось установить рабочее VPN-подключение '$vpnName' ни с одним из доступных серверов (источник: $serverSourceChoice)!" -ForegroundColor Red
    }
    Show-MainMenu
}

# ФУНКЦИЯ ДЛЯ УДАЛЕНИЕ СЕТИ VPN

function Remove-VpnConnectionMenu {
    Write-Host ""
    Write-Host "--- Удаление VPN подключения ---" -ForegroundColor Yellow
    Write-Host "--------------------------------"
    try {
        $vpnConnections = @(Get-VpnConnection -ErrorAction SilentlyContinue)
        if ($vpnConnections.Count -eq 0) {
            Write-Host "Нет сохранённых VPN-подключений для удаления!" -ForegroundColor Red
            Show-MainMenu
            return
        }

        Write-Host "Выберите VPN подключение для удаления:"
        for ($i = 0; $i -lt $vpnConnections.Count; $i++) {
            Write-Host "$($i + 1). $($vpnConnections[$i].Name)"
        }
        Write-Host "0. Выход"
        Write-Host "--------------------------------"

        $choice = Read-Host "Введите номер VPN для удаления или 0 для возврата:"

        if ($choice -eq "0") {
            Show-MainMenu
            return
        }

        if ($choice -notmatch "^\d+$" -or [int]$choice -lt 1 -or [int]$choice -gt $vpnConnections.Count) {
            Write-Host "Некорректный номер!" -ForegroundColor Red
            Show-MainMenu
            return
        }

        $vpnNameToRemove = $vpnConnections[[int]$choice - 1].Name
        Write-Host "Выбрано для удаления: '$vpnNameToRemove'" -ForegroundColor Cyan
        $confirmation = Read-Host "Вы уверены, что хотите удалить VPN подключение '$vpnNameToRemove'? (д/н)"

        if ($confirmation -eq "д") {
            $vpnStatus = Get-VpnConnection -Name $vpnNameToRemove -ErrorAction SilentlyContinue
            if ($vpnStatus -and $vpnStatus.ConnectionStatus -eq 'Connected') {
                Write-Host "VPN '$vpnNameToRemove' активно! Отключаем перед удалением..." -ForegroundColor Yellow
                Disconnect-VPN -VpnName $vpnNameToRemove
                Start-Sleep -Seconds 2 
            }

            Write-Host "Удаление VPN подключения '$vpnNameToRemove'..." -ForegroundColor Yellow
            Remove-VpnConnection -Name $vpnNameToRemove -Force -ErrorAction SilentlyContinue
            $checkVpn = Get-VpnConnection -Name $vpnNameToRemove -ErrorAction SilentlyContinue
            if (-not $checkVpn) {
                Write-Host "VPN подключение '$vpnNameToRemove' успешно удалено!" -ForegroundColor Green
            } else {
                Write-Host "Не удалось удалить VPN подключение '$vpnNameToRemove'!" -ForegroundColor Red
            }
        } else {
            Write-Host "Удаление отменено!" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Произошла ошибка при удалении VPN: $($_.Exception.Message)" -ForegroundColor Red
    }
    Show-MainMenu
}

# ФУНКЦИЯ ДЛЯ ПРОВЕРКИ ДОСТУПА В ИНТЕРНЕТ

function Test-InternetAccess {
    param ([string]$HostName = "google.com")
    try {
        Write-Host "Проверка доступа в интернет (хост: $HostName)..." -ForegroundColor Cyan
        $ping = Test-Connection -ComputerName $HostName -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($ping) {
            Write-Host "Доступ в интернет есть!" -ForegroundColor Green
            return $true
        } else {
            Write-Host "Доступ в интернет отсутствует!" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "Ошибка при проверке доступа в интернет: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ФУНКЦИЯ ДЛЯ ПОЛУЧЕНИЯ СПИСКА СЕРВЕРОВ SSTP ИЗ ВЕБ-САЙТА №2

function Get-SstpHostsFromWeb {
    $hosts = @()
    for ($page = 1; $page -le $maxPages; $page++) { 
        $url = "$vpnServersBaseURL$page" 
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
            $html = $response.Content
            $matches = [regex]::Matches($html, '<span class="list_s2">(.*?)</span>', [System.Text.RegularExpressions.RegexOptions]::Singleline) 
            foreach ($match in $matches) {
                $hostValue = $match.Groups[1].Value.Trim()
                if ($hostValue -and $hostValue -ne 'нет хоста') { 
                    $hosts += $hostValue
                }
            }
        } catch {
            Write-Host "Ошибка при получении данных с ${url}: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    return $hosts
}

# ФУНКЦИЯ ДЛЯ СОЗДАНИЯ ИЛИ ОБНОВЛЕНИЯ VPN ПОДКЛЮЧЕНИЯ

function Create-VpnConnectionIfNotExists {
    param (
        [string]$VpnName,
        [string]$ServerAddress,
        [string]$Username, 
        [string]$Password
    )
    $existingVpn = Get-VpnConnection -Name $VpnName -ErrorAction SilentlyContinue
    if (-not $existingVpn) {
        try {
            Write-Host "Подключение VPN '$VpnName' не найдено! Создаём новое подключение с сервером '$ServerAddress'..." -ForegroundColor Yellow
            Add-VpnConnection -Name $VpnName -ServerAddress $ServerAddress -TunnelType SSTP -EncryptionLevel Required -AuthenticationMethod MSCHAPv2 -RememberCredential -Force -ErrorAction Stop
            Write-Host "Подключение VPN '$VpnName' успешно создано с сервером '$ServerAddress'!" -ForegroundColor Green
            return $true
        } catch {
            Write-Host "Ошибка при создании VPN-подключения '$VpnName' с сервером '$ServerAddress': $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    } else {
        Write-Host "Подключение VPN '$VpnName' уже существует! Обновляем адрес сервера на '$ServerAddress'..." -ForegroundColor Cyan
        try {
            Set-VpnConnection -Name $VpnName -ServerAddress $ServerAddress -ErrorAction Stop
            Write-Host "Адрес сервера для VPN '$VpnName' успешно обновлён на '$ServerAddress'!" -ForegroundColor Green
            return $true
        } catch {
            Write-Host "Не удалось обновить адрес сервера для существующего VPN '$VpnName' на '$ServerAddress': $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }
}

# ФУНКЦИЯ ДЛЯ ЗАПУСКА ГЛАВНОГО МЕНЮ

Show-MainMenu