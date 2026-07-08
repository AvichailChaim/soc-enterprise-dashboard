# install.ps1 - מורץ כמנהל מערכת (Administrator) במחשב הקצה

# הגדרת נתיבים
$localNssmPath = "D:\Cyber\soc-system\nssm.exe"
$installDir = "C:\Program Files\Hayanuka_SIEM"
$agentPath = "$installDir\send.ps1"
$nssmPath = "$installDir\nssm.exe"

# הכתובת הציבורית הרשמית שלך דרך קלאודפלייר
$SIEM_SERVER = "https://creatures-nottingham-suitable-salaries.trycloudflare.com" 

if (!(Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

Write-Host "[*] Looking for local nssm.exe file..." -ForegroundColor Cyan

# שלב 1: בדיקה אם הקובץ קיים מקומית בתיקייה ששמת
if (Test-Path $localNssmPath) {
    Write-Host "[+] Found local nssm.exe! Copying to system folder..." -ForegroundColor Green
    Copy-Item -Path $localNssmPath -Destination $nssmPath -Force
} else {
    # שלב 2: אם לא מצא מקומית, רק אז ינסה להוריד (כדי שלא ייכשל אצלך)
    Write-Host "[-] Local nssm.exe not found. Trying to download from web..." -ForegroundColor Yellow
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
    $nssmUrl = "https://raw.githubusercontent.com/x64dbg/x64dbg/master/src/nssm/nssm.exe"
    try {
        Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmPath -UserAgent "Mozilla/5.0" -ErrorAction Stop
        Write-Host "[+] nssm.exe downloaded successfully from web!" -ForegroundColor Green
    } catch {
        Write-Host "[!] CRITICAL: nssm.exe is missing. Please ensure it is placed exactly at: $localNssmPath" -ForegroundColor Red
        exit
    }
}

Write-Host "[*] Deploying Native SIEM Agent logic..." -ForegroundColor Cyan

# כתיבת קוד ה-Agent עצמו לתוך הקובץ המקומי
$agentCode = @"
`$SIEM_BASE = "$SIEM_SERVER"
`$SIEM_EVENT = "`$SIEM_BASE/event"
`$SIEM_UPDATE = "`$SIEM_BASE/updates/send.ps1"

`$lastCheck = (Get-Date).AddMinutes(-5)
`$loopCount = 0

while (`$true) {
    if (`$loopCount -ge 10) {
        `$loopCount = 0
        try {
            `$currentScript = `$MyInvocation.MyCommand.Path
            if (`$currentScript) {
                `$newScriptPath = "`$currentScript.new"
                Invoke-WebRequest -Uri `$SIEM_UPDATE -OutFile `$newScriptPath -TimeoutSec 15 -ErrorAction SilentlyContinue
                if (Test-Path `$newScriptPath) {
                    if ((Get-FileHash `$currentScript).Hash -ne (Get-FileHash `$newScriptPath).Hash) {
                        Move-Item -Path `$newScriptPath -Destination `$currentScript -Force
                        Restart-Service "Hayanuka_SIEM_Agent" -Force
                        exit
                    }
                    Remove-Item `$newScriptPath -ErrorAction SilentlyContinue
                }
            }
        } catch {}
    }
    `$loopCount++

    `$events = Get-WinEvent -LogName "Security" -FilterXPath "*[System[( (EventID=4625) or (EventID=4624) or (EventID=4720) or (EventID=1102) or (EventID=4663) ) and TimeCreated[@SystemTime>='`$(`$lastCheck.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))']]]" -ErrorAction SilentlyContinue
    `$lastCheck = (Get-Date)

    foreach (`$log in `$events) {
        `$xml = [xml]`$log.ToXml()
        `$eventID = `$log.Id
        `$targetUser = "System"
        `$action = "unknown_event"
        `$ipAddress = "127.0.0.1"
        `$source = "`$(`$env:COMPUTERNAME) (Event ID `$eventID)"

        if (`$eventID -eq 4625) {
            `$targetUser = (`$xml.Event.EventData.Data | Where-Object { `$_.Name -eq "TargetUserName" }).'#text'
            `$ipAddress = (`$xml.Event.EventData.Data | Where-Object { `$_.Name -eq "IpAddress" }).'#text'
            `$logonType = (`$xml.Event.EventData.Data | Where-Object { `$_.Name -eq "LogonType" }).'#text'
            `$action = if (`$logonType -eq "3") { "network_file_access_failed" } else { "login_failed" }
        }
        elif (`$eventID -eq 4663) {
            `$targetUser = (`$xml.Event.EventData.Data | Where-Object { `$_.Name -eq "SubjectUserName" }).'#text'
            `$objectName = (`$xml.Event.EventData.Data | Where-Object { `$_.Name -eq "ObjectName" }).'#text'
            `$action = "file_permission_denied"
            `$source = "File: `$(Split-Path `$objectName -Leaf)"
        }
        elif (`$eventID -eq 4624) {
            `$targetUser = (`$xml.Event.EventData.Data | Where-Object { `$_.Name -eq "TargetUserName" }).'#text'
            `$ipAddress = (`$xml.Event.EventData.Data | Where-Object { `$_.Name -eq "IpAddress" }).'#text'
            `$action = "login_success"
        }
        elif (`$eventID -eq 4720) {
            `$targetUser = (`$xml.Event.EventData.Data | Where-Object { `$_.Name -eq "TargetUserName" }).'#text'
            `$action = "user_created"
        }
        elif (`$eventID -eq 1102) {
            `$targetUser = (`$xml.Event.UserData.LogClear.SubjectUserName).'#text'
            if (!`$targetUser) { `$targetUser = "Admin/System" }
            `$action = "audit_log_cleared"
        }

        `$siemEvent = @{ user = `$targetUser; action = `$action; source = `$source; ip = if (`$ipAddress -and `$ipAddress -ne "-") { `$ipAddress } else { "127.0.0.1" } }
        try {
            `$json = `$siemEvent | ConvertTo-Json
            Invoke-RestMethod -Uri `$SIEM_EVENT -Method Post -Body `$json -ContentType "application/json" -TimeoutSec 5
        } catch {}
    }
    Start-Sleep -Seconds 10
}
"@

Set-Content -Path $agentPath -Value $agentCode -Force

# הסרה והתקנה מחדש נקייה של שירות הווינדוס
if (Get-Service "Hayanuka_SIEM_Agent" -ErrorAction SilentlyContinue) {
    Stop-Service "Hayanuka_SIEM_Agent" -Force -ErrorAction SilentlyContinue
    & $nssmPath remove "Hayanuka_SIEM_Agent" confirm | Out-Null
}

Write-Host "[*] Creating Windows background service using NSSM..." -ForegroundColor Cyan
& $nssmPath install "Hayanuka_SIEM_Agent" "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$agentPath`""
& $nssmPath set "Hayanuka_SIEM_Agent" Start SERVICE_AUTO_START
& $nssmPath start "Hayanuka_SIEM_Agent"

Write-Host "[+] HAYANUKA SIEM Agent Deployed and Monitoring in Background via Cloudflare Tunnel!" -ForegroundColor Green