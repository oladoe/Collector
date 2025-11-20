param (
    [string]$Collector = "No name given",
    [switch]$silent
)



chcp 65001 | Out-Null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"




$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$hostname = $env:COMPUTERNAME
$base = "C:\\ForensicCollection\\$hostname`_$timestamp"
$folders = @{
    'System'         = "$base\System"
    'Network'        = "$base\Network"
    'UsersAndGroups' = "$base\UsersAndGroups"
    'Processes'      = "$base\Processes"
    'Services'       = "$base\Services"
    'ScheduledTasks' = "$base\ScheduledTasks"
    'Prefetch'       = "$base\Prefetch"
    'EventLogs'      = "$base\EventLogs"
    'Autoruns'       = "$base\Autoruns"
    'RDP'            = "$base\RDP"
    'Timeline'       = "$base\Timeline"
    'JumpLists'      = "$base\JumpLists"
    'RecentLNKs'     = "$base\RecentLNKs"
    'PowerShell'     = "$base\PowerShell"
    'Browsers'       = "$base\Browsers"
    'Temp folders'   = "$base\Temp Directories"
    'Installed'      = "$base\Installed Programs"
    'SMB'            = "$base\SMB Sessions"
}

foreach ($f in $folders.Values) {
    New-Item -Path $f -ItemType Directory -Force | Out-Null
}

$log = "$base\Errors.log"

Function Write-ErrorLog($msg) {
    "[ERROR] $msg" | Out-File -FilePath $log -Append -Encoding UTF8
}

Function Invoke-Task($desc, $scriptblock) {
    $width = 40

    $formatted = ("[*] " + $desc).PadRight($width)

    Write-Host $formatted -NoNewline
    try {
        & $scriptblock
        Write-Host " Done" -ForegroundColor Green
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-ErrorLog ("`$desc: " + $_.ToString())
    }
}

function Resolve-BuiltinGroupName {
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^S-1-5-32-\d+$')]
        [string]$Sid
    )
    try {
        $nt = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).
        Translate([System.Security.Principal.NTAccount]).Value
        return $nt.Split('\')[-1]
    }
    catch {
        return $null
    }
}


function Collect-BrowserData {
    param (
        [Parameter(Mandatory)]
        [ValidateSet("Chrome", "Edge", "Brave")]
        [string]$Browser,

        [Parameter(Mandatory)]
        [string]$OutRoot
    )

    $browserPaths = @{
        "Chrome" = "AppData\Local\Google\Chrome\User Data"
        "Edge"   = "AppData\Local\Microsoft\Edge\User Data"
        "Brave"  = "AppData\Local\BraveSoftware\Brave-Browser\User Data"
    }

    if (-not $browserPaths.ContainsKey($Browser)) {
        Write-Warning "Unsupported browser: $Browser"
        return
    }

    New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null

    $profiles = Get-CimInstance Win32_UserProfile |
        Where-Object { -not $_.Special -and $_.LocalPath -like 'C:\Users\*' }

    foreach ($p in $profiles) {
        $userName = Split-Path $p.LocalPath -Leaf
        $basePath = Join-Path $p.LocalPath $browserPaths[$Browser]
        if (-not (Test-Path $basePath)) { continue }

        $userOut = Join-Path $OutRoot $userName
        New-Item -ItemType Directory -Force -Path $userOut | Out-Null

        $profDirs = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^Default$|^Profile\s?\d+$' }

        foreach ($prof in $profDirs) {
            $profName = $prof.Name
            $profOut = Join-Path $userOut $profName
            New-Item -ItemType Directory -Force -Path $profOut | Out-Null

    
            $histFile = Join-Path $prof.FullName "History"
            if (Test-Path $histFile) {
                Copy-Item -Path $histFile -Destination (Join-Path $profOut "History") -Force -ErrorAction SilentlyContinue
            }

            $extDir = Join-Path $prof.FullName "Extensions"
            if (Test-Path $extDir) {
                $extOut = Join-Path $profOut "Extensions"
                New-Item -ItemType Directory -Force -Path $extOut | Out-Null

                Get-ChildItem -Path $extDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    $extId = $_.Name
                    Get-ChildItem -Path $_.FullName -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                        $ver = $_.Name
                        $manifest = Join-Path $_.FullName "manifest.json"
                        if (Test-Path $manifest) {
                            $destDir = Join-Path $extOut (Join-Path $extId $ver)
                            New-Item -ItemType Directory -Force -Path $destDir | Out-Null
                            Copy-Item -Path $manifest -Destination (Join-Path $destDir "manifest.json") -Force -ErrorAction SilentlyContinue
                        }
                    }
                }
            }

            $cacheDirs = @(
                Join-Path $prof.FullName "Cache"
                Join-Path $prof.FullName "Cache2"
            )

            foreach ($cd in $cacheDirs) {
                if (-not (Test-Path $cd)) { continue }

                $cacheOut = Join-Path $profOut (Split-Path $cd -Leaf)
                New-Item -ItemType Directory -Force -Path $cacheOut | Out-Null

                $robo = Get-Command robocopy.exe -ErrorAction SilentlyContinue
                if ($robo) {
                    & robocopy $cd $cacheOut * /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP > $null 2>&1
                    $rc = $LASTEXITCODE
                    if ($rc -ge 8) {
                        "$((Get-Date).ToString('o')) robocopy failed ($rc) for '$cd' -> '$cacheOut'" |
                        Out-File -FilePath (Join-Path $cacheOut "cache_errors.log") -Append -Encoding UTF8
                    }
                }
                else {
                    try {
                        Copy-Item -Path (Join-Path $cd '*') -Destination $cacheOut -Recurse -Force -ErrorAction Stop
                    }
                    catch {
                        "$((Get-Date).ToString('o')) Copy-Item failed for '$cd': $($_.Exception.Message)" |
                        Out-File -FilePath (Join-Path $cacheOut "cache_errors.log") -Append -Encoding UTF8
                    }
                }
            }
        }
    }
}



$banner = @'


 __  __                     _    ____         
|  \/  | _____   _____     / \  / ___|        
| |\/| |/ _ \ \ / / _ \   / _ \ \___ \        
| |  | | (_) \ V /  __/  / ___ \ ___) |       
|_| _|_|\___/ \_/ \___|_/_/   \_\____/        
   / \   _ __| |_ ___ / _| __ _  ___| |_ ___  
  / _ \ | '__| __/ _ \ |_ / _` |/ __| __/ __| 
 / ___ \| |  | ||  __/  _| (_| | (__| |_\__ \ 
/_/___\_\_| _ \__\___|_|  \__,_|\___|\__|___/ 
 / ___|___ | | | ___  ___| |_ ___  _ __       
| |   / _ \| | |/ _ \/ __| __/ _ \| '__|      
| |__| (_) | | |  __/ (__| || (_) | |         
 \____\___/|_|_|\___|\___|\__\___/|_|         


'@
Write-Host $banner



$collectionStart = Get-Date


Invoke-Task "Collecting system information" {
    Get-ComputerInfo | Out-File -FilePath "$($folders['System'])\ComputerInfo.txt" -Encoding UTF8
    Get-WmiObject -Class Win32_BIOS | Out-File -FilePath "$($folders['System'])\BIOS.txt" -Encoding UTF8
    Get-Volume | Out-File -FilePath "$($folders['System'])\Volumes.txt" -Encoding UTF8
    Get-PhysicalDisk | Out-File -FilePath "$($folders['System'])\Disks.txt" -Encoding UTF8
    Get-WmiObject -Namespace root\subscription -Class __EventFilter | Out-File "$($folders['System'])\WMI_EventFilters.txt" -Encoding UTF8
    Get-WmiObject -Namespace root\subscription -Class __EventConsumer | Out-File "$($folders['System'])\WMI_EventConsumers.txt" -Encoding UTF8
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Out-File "$($folders['System'])\WMI_Bindings.txt" -Encoding UTF8
}

Invoke-Task "Collecting network artefacts" {
    ipconfig /all | Out-File -FilePath "$($folders['Network'])\IPConfig.txt" -Encoding UTF8
    Get-DnsClientCache | Select-Object Entry, Name, Type, Status, TimeToLive, DataLength, Data | Format-Table -AutoSize | Out-File -FilePath "$($folders['Network'])\DNSCache.txt" -Encoding UTF8
    arp -a | Out-File -FilePath "$($folders['Network'])\ARPTable.txt" -Encoding UTF8
    route print | Out-File -FilePath "$($folders['Network'])\RoutingTable.txt" -Encoding UTF8
    netstat -nao | Out-File -FilePath "$($folders['Network'])\Netstat.txt" -Encoding UTF8
    netstat -anob | Out-File -FilePath "$($folders['Network'])\Netstat_Extended.txt" -Encoding UTF8
    netsh advfirewall show allprofiles | Out-File -FilePath "$($folders['Network'])\Firewall.txt" -Encoding UTF8
    Get-BitsTransfer -AllUsers | Out-File -FilePath "$($folders['Network'])\BitsJobs.txt" -Encoding UTF8
}

Invoke-Task "Collecting users and groups" {
    net user | Out-File -FilePath "$($folders['UsersAndGroups'])\Users.txt" -Encoding UTF8
    net localgroup | Out-File -FilePath "$($folders['UsersAndGroups'])\Groups.txt" -Encoding UTF8

    Get-LocalUser | Out-File -FilePath "$($folders['UsersAndGroups'])\Users_PS.txt" -Encoding UTF8
    Get-LocalGroup | Out-File -FilePath "$($folders['UsersAndGroups'])\Groups_PS.txt" -Encoding UTF8

    $adminGroupSid = "S-1-5-32-544"

    $adminGroupName = Resolve-BuiltinGroupName -Sid $adminGroupSid

    if ($adminGroupName) {
        try {
            net localgroup "$adminGroupName" | Out-File -FilePath "$($folders['UsersAndGroups'])\LocalAdmins.txt" -Encoding UTF8
        }
        catch {
            "[WARN] net localgroup $adminGroupName failed: $($_.Exception.Message)" | Out-File -FilePath "$($folders['UsersAndGroups'])\LocalAdmins.txt" -Append -Encoding UTF8
        }

        try {

            Get-LocalGroupMember -Group $adminGroupName | Out-File -FilePath "$($folders['UsersAndGroups'])\Admins_PS.txt" -Encoding UTF8
        }
        catch {
            "[WARN] Get-LocalGroupMember $adminGroupName failed: $($_.Exception.Message)" | Out-File -FilePath "$($folders['UsersAndGroups'])\Admins_PS.txt" -Append -Encoding UTF8        
        }
    }

    $psloggedonPath = Join-Path $PSScriptRoot "sysinternals\psloggedon"
    & $psloggedonPath -accepteula > "$($folders['UsersAndGroups'])\PsLoggedOn.txt"
}

Invoke-Task "Collecting PowerShell data" {
    $psOut = $folders['PowerShell']
    New-Item -ItemType Directory -Force -Path $psOut | Out-Null

    $patterns = @(
        'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt',  # WinPS 5.1
        'C:\Users\*\AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt'           # PowerShell 7+
    )

    $haveRobo = Get-Command robocopy.exe -ErrorAction SilentlyContinue

    foreach ($pattern in $patterns) {
        Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue -File | ForEach-Object {
            $m = [regex]::Match($_.FullName, '^C:\\Users\\([^\\]+)\\')
            $user = if ($m.Success) { $m.Groups[1].Value } else { 'UnknownUser' }

            $outDir = Join-Path $psOut $user
            New-Item -ItemType Directory -Force -Path $outDir | Out-Null

            if ($haveRobo) {
                $logFile = Join-Path $outDir 'robocopy_history.log'
                & robocopy $_.DirectoryName $outDir $_.Name /COPYALL /R:2 /W:2 /NFL /NDL /NJH /NJS /NP /LOG+:"$logFile" > $null 2>&1
                $rc = $LASTEXITCODE
                if ($rc -ge 8) {
                    "$((Get-Date).ToString('o')) Robocopy exit $rc for '$($_.FullName)'. Falling back to Copy-Item." |
                    Out-File -FilePath $logFile -Append -Encoding UTF8
                    try {
                        Copy-Item -Path $_.FullName -Destination (Join-Path $outDir $_.Name) -Force -ErrorAction Stop
                    }
                    catch {
                        "$((Get-Date).ToString('o')) Copy-Item failed: $($_.Exception.Message)" |
                        Out-File -FilePath $logFile -Append -Encoding UTF8
                    }
                }
            }
            else {
                Copy-Item -Path $_.FullName -Destination (Join-Path $outDir $_.Name) -Force -ErrorAction SilentlyContinue
            }
        }
    }

    $transRoot = Join-Path $psOut 'Transcripts'
    New-Item -ItemType Directory -Force -Path $transRoot | Out-Null

    Get-ChildItem 'C:\Users\*\Documents\PowerShell_transcript*' -ErrorAction SilentlyContinue -Recurse -File |
    ForEach-Object {
        $m = [regex]::Match($_.FullName, '^C:\\Users\\([^\\]+)\\')
        $user = if ($m.Success) { $m.Groups[1].Value } else { 'UnknownUser' }
        $userTransDir = Join-Path $transRoot $user
        New-Item -ItemType Directory -Force -Path $userTransDir | Out-Null

        if ($haveRobo) {
            $logFile = Join-Path $userTransDir 'robocopy_transcripts.log'
            & robocopy $_.DirectoryName $userTransDir $_.Name /COPYALL /R:2 /W:2 /NFL /NDL /NJH /NJS /NP /LOG+:"$logFile" > $null 2>&1
            if ($LASTEXITCODE -ge 8) {
                try {
                    Copy-Item -Path $_.FullName -Destination (Join-Path $userTransDir $_.Name) -Force -ErrorAction Stop
                }
                catch {}
            }
        }
        else {
            Copy-Item -Path $_.FullName -Destination (Join-Path $userTransDir $_.Name) -Force -ErrorAction SilentlyContinue
        }
    }
}


Invoke-Task "Collecting process information" {
    tasklist /svc | Out-File -FilePath "$($folders['Processes'])\Tasklist.txt" -Encoding UTF8
    Get-Process | Out-File -FilePath "$($folders['Processes'])\Processes.txt" -Encoding UTF8
}

Invoke-Task "Collecting services" {
    Get-Service | Export-Csv -Path "$($folders['Services'])\Services.csv" -NoTypeInformation -Encoding UTF8
    Get-CimInstance -ClassName Win32_Service | Select-Object Name, DisplayName, State, StartMode, StartName |
    Export-Csv -Path "$($folders['Services'])\ServiceStates.csv" -NoTypeInformation -Encoding UTF8
}

Invoke-Task "Collecting Autoruns data" {
    $autorunsPath = Join-Path $PSScriptRoot "sysinternals\autorunsc64"
    & $autorunsPath -a * -h -nobanner -accepteula -c > "$($folders['Autoruns'])\Autoruns.csv"
}

Invoke-Task "Collecting scheduled tasks" {
    schtasks /query /fo TABLE | Out-File -FilePath "$($folders['ScheduledTasks'])\ScheduledTasks_TABLE.txt" -Encoding UTF8
    schtasks /query /fo LIST /v | Out-File -FilePath "$($folders['ScheduledTasks'])\ScheduledTasks_V_LIST.txt" -Encoding UTF8
}

Invoke-Task "Collecting prefetch files" {
    $prefetchDir = "$env:SystemRoot\Prefetch"
    if (Test-Path $prefetchDir) {
        Copy-Item "$prefetchDir\*" -Destination "$($folders['Prefetch'])" -Recurse -ErrorAction SilentlyContinue
    }
    else {
        "Prefetch folder not found" | Out-File -FilePath "$($folders['Prefetch'])\status.txt" -Encoding UTF8
    }
}


Invoke-Task "Collecting RDP bitmap cache" {
    try {
        $rdpOut = Join-Path $base 'RDP'
        if (-not (Test-Path $rdpOut)) {
            New-Item -ItemType Directory -Path $rdpOut -Force | Out-Null
        }
        $profiles = Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath -like 'C:\Users\*' }
        foreach ($p in $profiles) {
            $userName = Split-Path $p.LocalPath -Leaf
            $mstsc = Join-Path $p.LocalPath 'AppData\Local\Microsoft\Terminal Server Client\Cache'
            if (Test-Path $mstsc) {
                $dst = Join-Path $rdpOut ($userName + '_MSTSC')
                New-Item -ItemType Directory -Path $dst -Force | Out-Null
                Copy-Item (Join-Path $mstsc '*') -Destination $dst -Recurse -ErrorAction SilentlyContinue
            }
            $uwp = Join-Path $p.LocalPath 'AppData\Local\Packages\Microsoft.RemoteDesktop_8wekyb3d8bbwe\LocalState\Cache'
            if (Test-Path $uwp) {
                $dst = Join-Path $rdpOut ($userName + '_UWP')
                New-Item -ItemType Directory -Path $dst -Force | Out-Null
                Copy-Item (Join-Path $uwp '*') -Destination $dst -Recurse -ErrorAction SilentlyContinue
            }
        }

        try { reg.exe query "HKCU\Software\Policies\Microsoft\Windows NT\Terminal Services" /s > (Join-Path $rdpOut 'Policy_CurrentUser.txt') 2>&1 } catch {}
        try { reg.exe query "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /s > (Join-Path $rdpOut 'Policy_LocalMachine.txt') 2>&1 } catch {}
    }
    catch {
        "RDP bitmap cache collection error: $($_.Exception.Message)" | Out-File -FilePath (Join-Path $rdpOut 'rdp_bitmap_cache_error.txt') -Encoding UTF8
    }

}

Invoke-Task "Collecting RDP connection history" {
    query user | Out-File -FilePath "$($folders['RDP'])\QueryUser.txt" -Encoding UTF8
    Get-WmiObject -Class Win32_LogonSession | Out-File -FilePath "$($folders['RDP'])\LogonSessions.txt" -Encoding UTF8
    Get-WmiObject -Class Win32_LoggedOnUser | Out-File -FilePath "$($folders['RDP'])\LoggedOnUsers.txt" -Encoding UTF8
}

Invoke-Task "Collecting Windows Timeline" {
    $timelineSrc = "$env:LOCALAPPDATA\ConnectedDevicesPlatform"
    if (Test-Path $timelineSrc) {
        Copy-Item "$timelineSrc\*" -Destination "$($folders['Timeline'])" -Recurse -ErrorAction SilentlyContinue
    }
}

Invoke-Task "Collecting Jump Lists" {
    $jumpListPath = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
    if (Test-Path $jumpListPath) {
        Copy-Item "$jumpListPath\*" -Destination "$($folders['JumpLists'])" -Recurse -ErrorAction SilentlyContinue
    }
    $customListPath = "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations"
    if (Test-Path $customListPath) {
        Copy-Item "$customListPath\*" -Destination "$($folders['JumpLists'])" -Recurse -ErrorAction SilentlyContinue
    }
}

Invoke-Task "Collecting recent LNK files" {
    $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
    if (Test-Path $recentPath) {
        Copy-Item "$recentPath\*.lnk" -Destination "$($folders['RecentLNKs'])" -ErrorAction SilentlyContinue
    }
}

Invoke-Task "Collecting browser data"{
    Collect-BrowserData -Browser "Chrome" -OutRoot "$($folders['Browsers'])\Chrome"
    Collect-BrowserData -Browser "Edge" -OutRoot "$($folders['Browsers'])\Edge"
    Collect-BrowserData -Browser "Brave" -OutRoot "$($folders['Browsers'])\Brave"

}

Invoke-Task "Collection SMB Sessions"{
    try {
        $smbConnections = Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 445 -or $_.RemotePort -eq 445 }


        $connectionDetails = $smbConnections | ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Direction     = if ($_.LocalPort -eq 445) { "Inbound" } else { "Outbound" }
                LocalAddress  = $_.LocalAddress
                RemoteAddress = $_.RemoteAddress
                State         = $_.State
                ProcessName   = $proc.ProcessName
                PID           = $_.OwningProcess
            }
        }

        $connectionDetails | Sort-Object Direction, RemoteAddress | Format-Table -AutoSize | Out-File -FilePath "$($folders['SMB'])\smb-sessions.txt"  -Encoding UTF8
    } catch {
        Write-ErrorLog "Could not fetch smb-sessions"
    }
}


Invoke-Task "Collecting installed programs" {
 
    $programs = @()

    $registryPaths = @(
        "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
        "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"
    )

    foreach ($path in $registryPaths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object {
            $_.DisplayName -and $_.DisplayName -ne ""
        } | ForEach-Object {
            $programs += [PSCustomObject]@{
                Name        = $_.DisplayName
                Version     = $_.DisplayVersion
                Publisher   = $_.Publisher
                InstallDate = $_.InstallDate
            }
        }
    }

    $programs | Sort-Object Name | Export-Csv -Path "$($folders['Installed'])\installed_programs.csv" -NoTypeInformation -Encoding UTF8

}

Invoke-Task "Collecting Temp Folders" {

    $profiles = Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath -like 'C:\Users\*' }

    foreach ($p in $profiles) {
 
        $userName = Split-Path $p.LocalPath -Leaf
        $tempPath = Join-Path $p.LocalPath "AppData\Local\Temp"

        if (Test-Path $tempPath) {
            try {
                Get-ChildItem -Path $tempPath -ErrorAction SilentlyContinue |
                Select-Object FullName, Length, LastWriteTime |
                Out-File -FilePath "$($folders['Temp folders'])\$userName.txt" -Encoding UTF8

            }
            catch {
                Write-ErrorLog "Failed to list temp contents for $userName"
            }
        }
        else {
            Write-ErrorLog "Temp path not found for $userName"
        }
    }
}



Invoke-Task "Collecting event logs" {
    $eventDir = "$env:SystemRoot\System32\winevt\Logs"
    if (Test-Path $eventDir) {
        Copy-Item "$eventDir\*evtx" -Destination $folders['EventLogs'] -ErrorAction SilentlyContinue -Force
    }
    else {
        "Event log folder not found" | Out-File -FilePath "$finalDir\status.txt" -Encoding UTF8
    }
}

Invoke-Task "Zipping up" {
    Compress-archive -Path $base -CompressionLevel "Fastest" -Destination "C:\\ForensicCollection\\collection.zip"
}

Invoke-Task "Hashing" {
    Get-ChildItem -Path "C:\\ForensicCollection" -Recurse | 
    Where-Object {$_.FullName -notlike "*File_Hashes.csv"} |
    ForEach-Object {
    $hash = Get-FileHash -Path $_.FullName -Algorithm SHA256
    [PSCustomObject]@{
        FilePath = $hash.Path
        Hash     = $hash.Hash
        Algorithm = $hash.Algorithm
    }
} | Export-Csv -Path "$base\File_Hashes.csv" -NoTypeInformation

}


Write-Host "[*] Collection complete. Data stored in: $base"

$collectionEnd = Get-Date
$infoFile = "$base\collection_info.txt"
$infoText = @"


Collected by: $collector
Start time: $($collectionStart.ToString("yyyy-MM-dd HH:mm:ss"))
End time: $($collectionEnd.ToString("yyyy-MM-dd HH:mm:ss"))
Output directory: $base
"@

$utf8Encoding = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($infoFile, $infoText, $utf8Encoding)