# ADMIN RIGHTS CHECK

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    try {
        $arguments = "& '" + $myinvocation.mycommand.path + "'"
        Start-Process powershell -Verb runAs -ArgumentList $arguments
        exit
    } catch {
        Write-Host "Failed to get administrator rights! Please run the script as an administrator..." -ForegroundColor Red
        exit
    }
}

# UTF-8 ENCODING WITH CYRILLIC SUPPORT

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::InputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# DEFAULT SETTINGS

$vpnNameDefault = "VPN_EvgenyAlex"
$usernameDefault = "vpn"
$passwordDefault = "vpn"
$txtFile = Join-Path -Path $PSScriptRoot -ChildPath "sstp.txt"
$vpnServersBaseURL = "https://ipspeed.info/freevpn_sstp.php?language=en&page="
$maxPages = 4

# FUNCTION TO GET RANDOM SSTP SERVERS FROM TXT FILE

function Get-RandomServerFromFile {
    param ([string]$FilePath)
    try {
        if (-not (Test-Path $FilePath)) {
            Write-Host "File $FilePath not found!" -ForegroundColor Red
            return $null
        }
        $servers = Get-Content -Path $FilePath -Encoding Default | Where-Object { -not [string]::IsNullOrEmpty($_.Trim()) }
        if ($servers.Count -eq 0) {
            Write-Host "File $FilePath is empty or does not contain servers!" -ForegroundColor Yellow
            return $null
        }

        Write-Host "Total servers: $($servers.Count)" -ForegroundColor Cyan
        Write-Host "Performing random scan of available servers..." -ForegroundColor Cyan
        foreach ($server in ($servers | Get-Random -Count $servers.Count)) {
            Write-Host "Trying server: $server" -ForegroundColor Yellow
            if (Test-VpnServerReachable -Server $server) {
                Write-Host "Server $server is available and responds to ping!" -ForegroundColor Green
                return $server
            }
        }
        Write-Host "Failed to find an available server!" -ForegroundColor Red
        return $null
    }
    catch {
        Write-Host "Error reading file: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
} 

# FUNCTION TO GET RANDOM SSTP SERVERS FROM WEBSITE

function Get-RandomServerFromWeb {
    param ([string]$BaseURL, [int]$MaxPages)
    try {
        $allServers = @()
        for ($page = 1; $page -le $MaxPages; $page++) {
            $URL = "$BaseURL$page"
            Write-Host "Requesting $URL..." -ForegroundColor Yellow
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
        Write-Host "No available servers found after checking!" -ForegroundColor Red
        return $null
    }
    catch {
        Write-Host "Error requesting website: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# FUNCTION TO CHECK SERVER AVAILABILITY

function Test-VpnServerReachable {
    param ([string]$Server)
    try {
        Write-Host "Checking server availability: $Server..." -ForegroundColor Yellow
        $ping = Test-Connection -ComputerName $Server -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($ping) {
            Write-Host "Server $Server is available!" -ForegroundColor Green
            return $true
        } else {
            Write-Host "Server $Server is unavailable! Trying next..." -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "Error checking server availability ${Server}: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# FUNCTION TO CHANGE VPN SERVER

function Change-VPNServer {
    param ([string]$VpnName, [string]$ServerAddress)
    try {
        $existingVpn = Get-VpnConnection -Name $VpnName -ErrorAction SilentlyContinue
        if (-not $existingVpn) {
            Write-Host "VPN '$VpnName' not found!" -ForegroundColor Red
            return $false
        }
        Write-Host "Changing server address for VPN '$VpnName' to '$ServerAddress'..." -ForegroundColor Yellow
        Set-VpnConnection -Name $VpnName -ServerAddress $ServerAddress -ErrorAction Stop
        Write-Host "Address for '$VpnName' successfully changed to: $ServerAddress" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Error changing server: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# FUNCTION TO CONNECT TO VPN

function Connect-VPN {
    param ([string]$VpnName, [string]$Username, [string]$Password)
    $returnValue = $false 
    try {
        Write-Host "Checking and disconnecting active VPN connections before connecting to '$VpnName'..." -ForegroundColor Cyan
        $null = Disconnect-AllActiveVpnConnections 
        
        Write-Host "Connecting to VPN '$VpnName'..." -ForegroundColor Yellow
        rasdial $VpnName $Username $Password | Out-Null 
        $rasdialExitCode = $LASTEXITCODE 

        Start-Sleep -Seconds 3 

        $vpnStatus = Get-VpnConnection -Name $VpnName -ErrorAction SilentlyContinue

        if ($rasdialExitCode -eq 0 -and $vpnStatus -and $vpnStatus.ConnectionStatus -eq 'Connected') {
            Write-Host "Successfully connected to VPN '$VpnName'! (Rasdial Code: $rasdialExitCode, Status: $($vpnStatus.ConnectionStatus))." -ForegroundColor Green
            $returnValue = $true
        } else {

            $statusMsg = if ($vpnStatus) { $vpnStatus.ConnectionStatus } else { "Not found" }
            Write-Host "Error connecting to VPN '$VpnName'! Rasdial error code: $rasdialExitCode. Actual VPN status: '$statusMsg'..." -ForegroundColor Red
            
            if (($rasdialExitCode -ne 0 -and $vpnStatus -and $vpnStatus.ConnectionStatus -eq 'Connected') -or `
                ($rasdialExitCode -eq 0 -and ($vpnStatus -eq $null -or $vpnStatus.ConnectionStatus -ne 'Connected'))) {
                Write-Host "VPN state mismatch detected for '$VpnName'! Attempting to force disconnect..." -ForegroundColor Yellow
                rasdial $VpnName /DISCONNECT | Out-Null 
            }
            $returnValue = $false
        }
    }
    catch { 
        Write-Host "Exception during Connect-VPN for '$VpnName': $($_.Exception.Message)" -ForegroundColor Red
        $returnValue = $false
    }
    Write-Host "Connect-VPN for '$VpnName' returns: $returnValue" -ForegroundColor Magenta
    return $returnValue
}

# FUNCTION TO DISCONNECT FROM VPN

function Disconnect-VPN {
    param ([string]$VpnName)
    try {
        Write-Host "Disconnecting from VPN '$VpnName'..." -ForegroundColor Yellow
        rasdial $VpnName /DISCONNECT | Out-Null 
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully disconnected from VPN '$VpnName'!" -ForegroundColor Green
            return $true
        } else {
            Write-Host "Error disconnecting from VPN '$VpnName'! Error code: $LASTEXITCODE" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "Error disconnecting from VPN: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# FUNCTION TO DISCONNECT FROM ACTIVE VPN CONNECTIONS

function Disconnect-AllActiveVpnConnections {
    Write-Host "Checking active VPN connections..." -ForegroundColor Yellow
    try {

        $allVpnConnections = Get-VpnConnection -ErrorAction Stop
        $activeConnections = @()
        
        foreach ($vpn in $allVpnConnections) {
            $connectionStatus = Get-VpnConnection -Name $vpn.Name -ErrorAction SilentlyContinue
            if ($connectionStatus -and $connectionStatus.ConnectionStatus -eq "Connected") {
                $activeConnections += $connectionStatus
                Write-Host "Found active VPN connection: '$($vpn.Name)'" -ForegroundColor Cyan
            }
        }
        
        if ($activeConnections.Count -gt 0) {
            Write-Host "Found $($activeConnections.Count) active VPN connections! Disconnecting..." -ForegroundColor Yellow
            foreach ($activeVpn in $activeConnections) {
                Write-Host "Disconnecting '$($activeVpn.Name)'..." -ForegroundColor Yellow
                if (Disconnect-VPN -VpnName $activeVpn.Name) {
                    Write-Host "VPN '$($activeVpn.Name)' successfully disconnected!" -ForegroundColor Green
                } else {
                    Write-Host "Failed to disconnect VPN '$($activeVpn.Name)'!" -ForegroundColor Red
                }
                Start-Sleep -Seconds 2  
            }
        } else {
            Write-Host "No active VPN connections found!" -ForegroundColor Green
        }
        
        return $true
    }
    catch {
        Write-Host "Error checking active VPN connections: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# FUNCTION TO CHANGE SERVER FOR EXISTING VPN

function Change-ExistingServer {
    Write-Host ""
    Write-Host "--- Change server for existing VPN ---" -ForegroundColor Yellow
    Write-Host "---------------------------------------------"
    try {
        $vpnConnections = @(Get-VpnConnection -ErrorAction Stop)
        if ($vpnConnections.Count -eq 0) {
            Write-Host "No saved VPN connections!" -ForegroundColor Red
            Show-MainMenu
            return
        }
        for ($i = 0; $i -lt $vpnConnections.Count; $i++) {
            Write-Host "$($i + 1). $($vpnConnections[$i].Name)"
        }
        Write-Host "0. Exit" 
    }
    catch {
        Write-Host "Error getting VPN list: $($_.Exception.Message)" -ForegroundColor Red
        Show-MainMenu
        return
    }
    $choice = Read-Host "Enter VPN number to change server:"
    if ($choice -eq "0") { Show-MainMenu; return }

    if ($choice -notmatch "^\d+$" -or [int]$choice -lt 1 -or [int]$choice -gt $vpnConnections.Count) {
        Write-Host "Invalid number!" -ForegroundColor Red
        Show-MainMenu
        return
    }
    $vpnName = $vpnConnections[[int]$choice - 1].Name
    Write-Host "Selected VPN profile: '$vpnName'" -ForegroundColor Cyan
    Write-Host "---------------------------------------------"

    Write-Host ""
    Write-Host "--- Parameters for VPN '$vpnName' ---" -ForegroundColor Cyan
    Write-Host "  Connection name: $vpnName" -ForegroundColor Cyan
    Write-Host "  User           : $usernameDefault" -ForegroundColor Cyan
    Write-Host "  Password       : $passwordDefault" -ForegroundColor Cyan
    Write-Host "-----------------------------------"
    Write-Host ""

    Write-Host "1. Get servers from internet"
    Write-Host "2. Get servers from sstp.txt file"
    Write-Host "0. Exit"
    $sourceChoice = Read-Host "Select server list source:"
    if ($sourceChoice -eq "0") { Show-MainMenu; return } 

    $availableServers = @()
    $serverSourceDescription = ""

    switch ($sourceChoice) {
        "1" {
            Write-Host "Loading server list from internet..." -ForegroundColor Yellow
            $availableServers = Get-SstpHostsFromWeb 
            $serverSourceDescription = "internet"
            if ($availableServers.Count -eq 0) {
                Write-Host "Failed to get SSTP server list from $serverSourceDescription! Returning to main menu....." -ForegroundColor Red
                Show-MainMenu
                return
            }
            Write-Host "Received $($availableServers.Count) servers from $serverSourceDescription!" -ForegroundColor Green
        }
        "2" {
            Write-Host "Loading server list from file '$txtFile'..." -ForegroundColor Yellow
            if (-not (Test-Path $txtFile)) {
                Write-Host "File $txtFile not found! Returning to main menu....." -ForegroundColor Red
                Show-MainMenu
                return
            }
            $fileContent = Get-Content -Path $txtFile -Encoding Default | Where-Object { -not [string]::IsNullOrEmpty($_.Trim()) }
            if ($fileContent.Count -eq 0) {
                Write-Host "File $txtFile is empty! Returning to main menu....." -ForegroundColor Red
                Show-MainMenu
                return
            }
            $availableServers = $fileContent
            $serverSourceDescription = "file '$txtFile'"
            Write-Host "Received $($availableServers.Count) servers from $serverSourceDescription!" -ForegroundColor Green
        }
        default {
            Write-Host "Invalid choice! Returning to main menu....." -ForegroundColor Red
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
        Write-Host "Trying server: $serverAddress (source: $serverSourceDescription)" -ForegroundColor Cyan
        if (-not (Test-VpnServerReachable -Server $serverAddress)) {
            Write-Host "Server $serverAddress is unavailable (does not ping), trying next..." -ForegroundColor Yellow
            continue
        }
        
        Write-Host "Server $serverAddress is available! Changing server address for VPN '$vpnName' to '$serverAddress'..." -ForegroundColor Green
        if (Change-VPNServer -VpnName $vpnName -ServerAddress $serverAddress) {
            Write-Host "Server address for VPN '$vpnName' successfully changed to '$serverAddress'!" -ForegroundColor Green
            $serverSuccessfullyChangedAtLeastOnce = $true
            $lastSuccessfullySetServer = $serverAddress
            
            Write-Host "Trying to connect to VPN '$vpnName' with new server..." -ForegroundColor Cyan
            if (Connect-VPN -VpnName $vpnName -Username $usernameDefault -Password $passwordDefault) {
                if (Test-InternetAccess) {
                    Write-Host "Successfully connected to VPN '$vpnName' via server $serverAddress and internet access is available!" -ForegroundColor Green
                    $connectionEstablished = $true
                    break 
                } else {
                    Write-Host "Connection to VPN '$vpnName' via $serverAddress established, but no internet access! Disconnecting..." -ForegroundColor Yellow
                    Disconnect-VPN -VpnName $vpnName
                }
            } else {
                Write-Host "Failed to connect to VPN '$vpnName' via server $serverAddress!" -ForegroundColor Yellow
                continue 
            }
        } else {
            Write-Host "Failed to change server address for VPN '$vpnName' to '$serverAddress'!" -ForegroundColor Red
        }
    }

    if ($connectionEstablished) {
        Write-Host "Server address and connection to VPN '$vpnName' successfully completed via server $serverAddress!" -ForegroundColor Green
    } else {
        Write-Host "Failed to establish a working VPN connection for '$vpnName' with any of the available servers (source: $serverSourceDescription)!" -ForegroundColor Red
        if ($serverSuccessfullyChangedAtLeastOnce) {
            Write-Host "Server address for VPN '$vpnName' was changed to the last successfully checked: $lastSuccessfullySetServer, but internet connection was not established!" -ForegroundColor Yellow
        } else {
            Write-Host "Server address for VPN '$vpnName' was not changed!" -ForegroundColor Yellow
        }
    }
    Show-MainMenu
}

# FUNCTION FOR MAIN MENU

function Show-MainMenu {
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Yellow
    Write-Host "     VPN Manager Script for Windows (powered by SSTP)     " -ForegroundColor Yellow
    Write-Host "                     by EvgenyAlex                        " -ForegroundColor Yellow
    Write-Host "              telegram - @x_evgenyalex_x                  " -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Usage instructions:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This script will help you manage VPN connections." -ForegroundColor Cyan
    Write-Host "You can create new connections (automatically or manually)." -ForegroundColor Cyan
    Write-Host "Change servers for existing ones, and also delete them." -ForegroundColor Cyan
    Write-Host "Use numeric keys to navigate the menu." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Select action:"
    Write-Host "  1. Automatic VPN setup"
    Write-Host "  2. Manual VPN setup"
    Write-Host "  3. Change server for existing connection"
    Write-Host "  4. Remove network" 
    Write-Host "  0. Exit"
    Write-Host "---------------------------------------------"
    $choice = Read-Host "Enter menu item number:"
    switch ($choice) {
        "1" {
            Automatic-VPNSetup
        }
        "2" {
            Manual-VPNSetup
        }
        "3" {
            Change-ExistingServer
        }
        "4" { 
            Remove-VpnConnectionMenu
        }
        "0" {
            Write-Host "Exiting program!" -ForegroundColor Green
            exit
        }
        default {
            Write-Host "Invalid input! Please select an item from the menu..." -ForegroundColor Red
            Show-MainMenu
        }
    }
}

# FUNCTION FOR AUTOMATIC VPN SETUP

function Automatic-VPNSetup {
    Write-Host ""
    Write-Host "--- Automatic VPN setup ---" -ForegroundColor Yellow
    Write-Host "----------------------------------"
    Write-Host ""

    Write-Host "--- Default VPN parameters for automatic setup ---" -ForegroundColor Cyan
    Write-Host "  Connection name: $vpnNameDefault" -ForegroundColor Cyan
    Write-Host "  User           : $usernameDefault" -ForegroundColor Cyan
    Write-Host "  Password       : $passwordDefault" -ForegroundColor Cyan
    Write-Host "-------------------------------------------------------------"
    Write-Host ""
    Write-Host "1. Continue with these parameters"
    Write-Host "0. Exit"
    $confirmation = Read-Host "Select action:"

    if ($confirmation -ne "1") {
        Show-MainMenu
        return
    }
    Write-Host "" 

    $allHosts = Get-SstpHostsFromWeb
    if ($allHosts.Count -eq 0) {
        Write-Host "Failed to get SSTP server list from internet! Try another method..." -ForegroundColor Red
        Show-MainMenu
        return
    }

    $shuffledHosts = $allHosts | Get-Random -Count $allHosts.Count
    $connectionEstablished = $false

    foreach ($serverAddress in $shuffledHosts) {
        Write-Host ""
        Write-Host "-------------------------------------------------------------"
        Write-Host "Trying server: $serverAddress" -ForegroundColor Cyan
        if (-not (Test-VpnServerReachable -Server $serverAddress)) {
            Write-Host "Server $serverAddress is unavailable (does not ping), trying next..." -ForegroundColor Yellow
            continue
        }
        
        Write-Host "Server $serverAddress is available! Ensuring VPN configuration '$vpnNameDefault' with this server..." -ForegroundColor Green

        if (Create-VpnConnectionIfNotExists -VpnName $vpnNameDefault -ServerAddress $serverAddress -Username $usernameDefault -Password $passwordDefault) {
            if (Connect-VPN -VpnName $vpnNameDefault -Username $usernameDefault -Password $passwordDefault) {
                if (Test-InternetAccess) {
                    Write-Host "Successfully connected to VPN and internet access is available via server $serverAddress!" -ForegroundColor Green
                    $connectionEstablished = $true
                    break 
                } else {
                    Write-Host "Connection to VPN '$vpnNameDefault' established, but no internet access via $serverAddress! Disconnecting..." -ForegroundColor Yellow
                    Disconnect-VPN -VpnName $vpnNameDefault
                }
            } else {
                 Write-Host "Failed to connect to VPN '$vpnNameDefault' via server $serverAddress! Trying next server..." -ForegroundColor Yellow
                 continue 
            }
        } else {
             Write-Host "Failed to configure (create/update) VPN connection '$vpnNameDefault' for server $serverAddress! Trying next server..." -ForegroundColor Red
             continue 
        }
    }

    if (-not $connectionEstablished) {
        Write-Host "Failed to establish a working VPN connection with any of the available servers!" -ForegroundColor Red
    }
    Show-MainMenu
}

# FUNCTION FOR MANUAL VPN SETUP

function Manual-VPNSetup {
    Write-Host ""
    Write-Host "--- Manual VPN setup ---" -ForegroundColor Yellow
    Write-Host "--------------------------" 

    $vpnName = $null
    while ($true) {
        $inputVpnName = Read-Host "1. Enter VPN connection name (press Enter for '$vpnNameDefault' or 0 to exit):"
        if ($inputVpnName -eq "0") { Show-MainMenu; return }
        $vpnName = if ([string]::IsNullOrWhiteSpace($inputVpnName)) { $vpnNameDefault } else { $inputVpnName }

        $existingVpn = Get-VpnConnection -Name $vpnName -ErrorAction SilentlyContinue
        if (-not $existingVpn) {
            break 
        }
        Write-Host "VPN with name '$vpnName' already exists!" -ForegroundColor Yellow
        $choice = Read-Host "Do you want to enter a different name (y) or return to the main menu (0)?"
        if ($choice -eq "0") { Show-MainMenu; return }
        if ($choice -ne "y") { 
             Write-Host "Invalid input, returning to main menu..." -ForegroundColor Red
             Show-MainMenu; return
        }
    }
    
    $inputUsername = Read-Host "2. Enter username (press Enter for '$usernameDefault' or 0 to exit):"
    if ($inputUsername -eq "0") { Show-MainMenu; return }
    $username = if ([string]::IsNullOrWhiteSpace($inputUsername)) { $usernameDefault } else { $inputUsername }

    $inputPassword = Read-Host "3. Enter password (press Enter for '$passwordDefault' or 0 to exit):"
    if ($inputPassword -eq "0") { Show-MainMenu; return }
    $password = if ([string]::IsNullOrWhiteSpace($inputPassword)) { $passwordDefault } else { $inputPassword }

    Write-Host ""
    Write-Host "--- Parameters for new VPN ---" -ForegroundColor Cyan 
    Write-Host "  Connection name: $vpnName" -ForegroundColor Cyan
    Write-Host "  User           : $username" -ForegroundColor Cyan
    Write-Host "  Password       : $password" -ForegroundColor Cyan 
    Write-Host "--------------------------------" 
    Write-Host ""

    Write-Host "Select server source for connection:"
    Write-Host "1. Get servers from internet"
    Write-Host "2. Get servers from sstp.txt file"
    Write-Host "0. Exit" 
    Write-Host ""

    $serverSourceChoice = Read-Host "Select server retrieval method or 0 to exit:"
    if ($serverSourceChoice -eq "0") { Show-MainMenu; return }

    $availableServers = @()
    $serverSourceDescription = "" 

    switch ($serverSourceChoice) {
        "1" {
            Write-Host "Loading server list from internet..." -ForegroundColor Yellow
            $availableServers = Get-SstpHostsFromWeb
            if ($availableServers.Count -eq 0) {
                Write-Host "Failed to get SSTP server list from internet! Returning to main menu..." -ForegroundColor Red
                Show-MainMenu
                return
            }
            $serverSourceDescription = "internet"
            Write-Host "Received $($availableServers.Count) servers from $serverSourceDescription!" -ForegroundColor Green
        }
        "2" {
            Write-Host "Loading server list from file '$txtFile'..." -ForegroundColor Yellow
            if (-not (Test-Path $txtFile)) {
                Write-Host "File $txtFile not found! Returning to main menu..." -ForegroundColor Red
                Show-MainMenu
                return
            }
            $fileServers = Get-Content -Path $txtFile -Encoding Default | Where-Object { -not [string]::IsNullOrEmpty($_.Trim()) }
            if ($fileServers.Count -eq 0) {
                Write-Host "File $txtFile is empty! Returning to main menu..." -ForegroundColor Red
                Show-MainMenu
                return
            }
            $availableServers = $fileServers
            $serverSourceDescription = "file '$txtFile'"
            Write-Host "Received $($availableServers.Count) servers from $serverSourceDescription!" -ForegroundColor Green
        }
        "0" { 
            Show-MainMenu
            return
        }
        default {
            Write-Host "Invalid choice! Returning to main menu..." -ForegroundColor Red
            Show-MainMenu
            return
        }
    }

    $shuffledServers = $availableServers | Get-Random -Count $availableServers.Count
    $connectionEstablished = $false

    foreach ($serverAddress in $shuffledServers) {
        Write-Host ""
        Write-Host "-------------------------------------------------------------"
        Write-Host "Trying server: $serverAddress (source: $serverSourceDescription)" -ForegroundColor Cyan 
        if (-not (Test-VpnServerReachable -Server $serverAddress)) {
            Write-Host "Server $serverAddress is unavailable (does not ping), trying next..." -ForegroundColor Yellow
            continue
        }
        
        Write-Host "Server $serverAddress is available! Ensuring VPN configuration '$vpnName' with this server..." -ForegroundColor Green

        if (Create-VpnConnectionIfNotExists -VpnName $vpnName -ServerAddress $serverAddress -Username $username -Password $password) {
            if (Connect-VPN -VpnName $vpnName -Username $username -Password $password) {
                if (Test-InternetAccess) {
                    Write-Host "Successfully connected to VPN '$vpnName' and internet access is available via server $serverAddress!" -ForegroundColor Green
                    $connectionEstablished = $true
                    break 
                } else {
                    Write-Host "Connection to VPN '$vpnName' established, but no internet access via $serverAddress! Disconnecting..." -ForegroundColor Yellow
                    Disconnect-VPN -VpnName $vpnName
                }
            } else {
                 Write-Host "Failed to connect to VPN '$vpnName' via server $serverAddress! Trying next server..." -ForegroundColor Yellow
                 continue 
            }
        } else {
            Write-Host "Failed to configure (create/update) VPN connection '$vpnName' for server $serverAddress! Trying next server..." -ForegroundColor Red
            continue
        }
    }

    if (-not $connectionEstablished) {
        Write-Host "Failed to establish a working VPN connection '$vpnName' with any of the available servers (source: $serverSourceChoice)!" -ForegroundColor Red
    }
    Show-MainMenu
}

# FUNCTION TO REMOVE VPN NETWORK

function Remove-VpnConnectionMenu {
    Write-Host ""
    Write-Host "--- Remove VPN connection ---" -ForegroundColor Yellow
    Write-Host "--------------------------------"
    try {
        $vpnConnections = @(Get-VpnConnection -ErrorAction SilentlyContinue)
        if ($vpnConnections.Count -eq 0) {
            Write-Host "No saved VPN connections to remove!" -ForegroundColor Red
            Show-MainMenu
            return
        }

        Write-Host "Select VPN connection to remove:"
        for ($i = 0; $i -lt $vpnConnections.Count; $i++) {
            Write-Host "$($i + 1). $($vpnConnections[$i].Name)"
        }
        Write-Host "0. Exit"
        Write-Host "--------------------------------"

        $choice = Read-Host "Enter VPN number to remove or 0 to return:"

        if ($choice -eq "0") {
            Show-MainMenu
            return
        }

        if ($choice -notmatch "^\d+$" -or [int]$choice -lt 1 -or [int]$choice -gt $vpnConnections.Count) {
            Write-Host "Invalid number!" -ForegroundColor Red
            Show-MainMenu
            return
        }

        $vpnNameToRemove = $vpnConnections[[int]$choice - 1].Name
        Write-Host "Selected for removal: '$vpnNameToRemove'" -ForegroundColor Cyan
        $confirmation = Read-Host "Are you sure you want to remove VPN connection '$vpnNameToRemove'? (y/n)"

        if ($confirmation -eq "y") {
            $vpnStatus = Get-VpnConnection -Name $vpnNameToRemove -ErrorAction SilentlyContinue
            if ($vpnStatus -and $vpnStatus.ConnectionStatus -eq 'Connected') {
                Write-Host "VPN '$vpnNameToRemove' is active! Disconnecting before removal..." -ForegroundColor Yellow
                Disconnect-VPN -VpnName $vpnNameToRemove
                Start-Sleep -Seconds 2 
            }

            Write-Host "Removing VPN connection '$vpnNameToRemove'..." -ForegroundColor Yellow
            Remove-VpnConnection -Name $vpnNameToRemove -Force -ErrorAction SilentlyContinue
            $checkVpn = Get-VpnConnection -Name $vpnNameToRemove -ErrorAction SilentlyContinue
            if (-not $checkVpn) {
                Write-Host "VPN connection '$vpnNameToRemove' successfully removed!" -ForegroundColor Green
            } else {
                Write-Host "Failed to remove VPN connection '$vpnNameToRemove'!" -ForegroundColor Red
            }
        } else {
            Write-Host "Removal cancelled!" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "An error occurred while removing VPN: $($_.Exception.Message)" -ForegroundColor Red
    }
    Show-MainMenu
}

# FUNCTION TO CHECK INTERNET ACCESS

function Test-InternetAccess {
    param ([string]$HostName = "google.com")
    try {
        Write-Host "Checking internet access (host: $HostName)..." -ForegroundColor Cyan
        $ping = Test-Connection -ComputerName $HostName -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($ping) {
            Write-Host "Internet access is available!" -ForegroundColor Green
            return $true
        } else {
            Write-Host "No internet access!" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "Error checking internet access: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# FUNCTION TO GET LIST OF SSTP SERVERS FROM WEBSITE #2

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
                if ($hostValue -and $hostValue -ne 'no host') { # Changed 'нет хоста' to 'no host'
                    $hosts += $hostValue
                }
            }
        } catch {
            Write-Host "Error getting data from ${url}: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    return $hosts
}

# FUNCTION TO CREATE OR UPDATE VPN CONNECTION

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
            Write-Host "VPN connection '$VpnName' not found! Creating new connection with server '$ServerAddress'..." -ForegroundColor Yellow
            Add-VpnConnection -Name $VpnName -ServerAddress $ServerAddress -TunnelType SSTP -EncryptionLevel Required -AuthenticationMethod MSCHAPv2 -RememberCredential -Force -ErrorAction Stop
            Write-Host "VPN connection '$VpnName' successfully created with server '$ServerAddress'!" -ForegroundColor Green
            return $true
        } catch {
            Write-Host "Error creating VPN connection '$VpnName' with server '$ServerAddress': $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    } else {
        Write-Host "VPN connection '$VpnName' already exists! Updating server address to '$ServerAddress'..." -ForegroundColor Cyan
        try {
            Set-VpnConnection -Name $VpnName -ServerAddress $ServerAddress -ErrorAction Stop
            Write-Host "Server address for VPN '$VpnName' successfully updated to '$ServerAddress'!" -ForegroundColor Green
            return $true
        } catch {
            Write-Host "Failed to update server address for existing VPN '$VpnName' to '$ServerAddress': $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }
}

# FUNCTION TO START MAIN MENU

Show-MainMenu