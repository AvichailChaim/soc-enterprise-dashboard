# install.ps1 - מורץ כמנהל מערכת (Administrator) בכל תחנת קצה בארגון, כולל מחשבים מרוחקים.
#
# שימוש (אופציה מומלצת - לא צריך להעתיק את AGENT_TOKEN בכלל, רק את המשתמש/סיסמה של הדשבורד עצמו):
#   .\install.ps1 -AdminUsername "admin" -AdminPassword "הסיסמה-שלך-לדשבורד" -UninstallPassword "סיסמת-הסרה"
#
# שימוש (אופציה ידנית - אם יש לך את AGENT_TOKEN המדויק):
#   .\install.ps1 -AgentToken "הטוקן-הסודי-שהוגדר-ב-Vercel" -UninstallPassword "סיסמת-הסרה"
#
# הקובץ הזה עצמאי: אם send.ps1 ו/או nssm.exe לא נמצאים באותה תיקייה, הוא מוריד אותם
# אוטומטית מהאינטרנט. כלומר אפשר להעתיק *רק* את הקובץ הזה למחשב מרוחק (למשל דרך RDP,
# מייל, או כונן משותף) ולהריץ אותו שם - אין צורך להעתיק את כל תיקיית api/.
#
# הסקריפט מזריק את הטוקן לתוך send.ps1, ומתקין אותו כשירות Windows קבוע (auto-start) באמצעות NSSM.

param(
    [string]$AgentToken = "",
    [string]$AdminUsername = "",       # במקום AgentToken: משתמש/סיסמה של הדשבורד עצמו - שאותם אתה בוודאות זוכר
    [string]$AdminPassword = "",       # (בניגוד ל-AGENT_TOKEN שוורסל מסתיר אחרי השמירה) - הסקריפט ישלוף את הטוקן לבד
    [string]$UninstallPassword = "",   # מגדיר/מעדכן את הסיסמה הנדרשת כדי להסיר או להתקין-מחדש את השירות
    [switch]$NoProtect                 # דגל לבדיקות בלבד - מדלג על הקשחת ההרשאות ועל דרישת הסיסמה
)

$DASHBOARD_BASE = "https://soc-enterprise-dashboard-hayanuka.vercel.app"

if ($AgentToken -eq "" -and $AdminUsername -ne "" -and $AdminPassword -ne "") {
    Write-Host "[*] Fetching AGENT_TOKEN automatically using dashboard admin login..." -ForegroundColor Cyan
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        $loginBody = @{ username = $AdminUsername; password = $AdminPassword } | ConvertTo-Json
        $loginResp = Invoke-RestMethod -Uri "$DASHBOARD_BASE/api/login" -Method Post -Body $loginBody -ContentType "application/json" -ErrorAction Stop
        $tokenResp = Invoke-RestMethod -Uri "$DASHBOARD_BASE/api/agent-token" -Headers @{ "X-Session-Token" = $loginResp.token } -ErrorAction Stop
        if ($tokenResp.agent_token) {
            $AgentToken = $tokenResp.agent_token
            Write-Host "[+] AGENT_TOKEN fetched successfully - no manual copy-paste needed." -ForegroundColor Green
        } else {
            Write-Host "[!] Dashboard login succeeded, but no AGENT_TOKEN is configured on the server." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "[!] Could not fetch AGENT_TOKEN automatically (wrong admin username/password?): $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

$installDir  = "C:\Hayanuka_SIEM"   # בכוונה בלי רווח בנתיב (כגון "Program Files") - זו הייתה סיבת הבאג
$agentPath   = "$installDir\send.ps1"
$nssmPath    = "$installDir\nssm.exe"
$localNssm   = Join-Path $PSScriptRoot "..\nssm.exe"   # api/nssm.exe, לצד תיקיית agent/ (אם קיים מקומית)
$localSend   = Join-Path $PSScriptRoot "send.ps1"       # api/agent/send.ps1 (אם קיים מקומית)
$localWatchdog = Join-Path $PSScriptRoot "watchdog.ps1" # api/agent/watchdog.ps1 (אם קיים מקומית)
$hashFile    = "$installDir\uninstall.hash"
$watchdogTask = "Hayanuka_SIEM_Watchdog"
$serviceSddl  = "D:(A;;GA;;;SY)(A;;CCLCSWLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"

$SEND_PS1_URL     = "https://soc-enterprise-dashboard-hayanuka.vercel.app/api/agent-update"
$WATCHDOG_PS1_URL = "https://soc-enterprise-dashboard-hayanuka.vercel.app/api/watchdog-update"
$NSSM_URL         = "https://soc-enterprise-dashboard-hayanuka.vercel.app/api/nssm-download"

if (!(Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

function Get-Sha256Hex($text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))
    return ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLower()
}

function Invoke-PrivilegedServiceRemoval {
    # מבצע עצירה/הסרה של השירות MSD-ידי משימה מתוזמנת שרצה כ-SYSTEM.
    # זה נחוץ כי לאחר ההקשחה (sc sdset), אפילו מנהל מערכת רגיל לא יכול לעצור/למחוק
    # את השירות ישירות - רק SYSTEM יכול, לכן "עוקפים" את זה דרך Scheduled Task שרץ כ-SYSTEM.
    param([ValidateSet('ServiceOnly', 'Full')]$Mode = 'ServiceOnly')

    $helperPath = Join-Path $env:TEMP "hayanuka_priv_removal.ps1"
    $donePath   = Join-Path $env:TEMP "hayanuka_priv_removal.done"
    Remove-Item $donePath -ErrorAction SilentlyContinue

    $helperScript = @"
try {
    Stop-Service 'Hayanuka_SIEM_Agent' -Force -ErrorAction SilentlyContinue
    if (Test-Path '$installDir\nssm.exe') { & '$installDir\nssm.exe' remove 'Hayanuka_SIEM_Agent' confirm 2>`$null | Out-Null }
    if ('$Mode' -eq 'Full') {
        Unregister-ScheduledTask -TaskName '$watchdogTask' -Confirm:`$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        Remove-Item -Path '$installDir' -Recurse -Force -ErrorAction SilentlyContinue
    }
} catch {}
'done' | Out-File '$donePath' -Force
"@
    Set-Content -Path $helperPath -Value $helperScript -Force

    $taskName = "Hayanuka_Priv_Removal_$([guid]::NewGuid().ToString('N').Substring(0,8))"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$helperPath`""
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName

    $waited = 0
    while (-not (Test-Path $donePath) -and $waited -lt 30) { Start-Sleep -Seconds 1; $waited++ }
    $success = Test-Path $donePath

    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $helperPath -ErrorAction SilentlyContinue
    Remove-Item $donePath -ErrorAction SilentlyContinue

    return $success
}

# --- שלב 0: הפעלת Audit Policies הנדרשות, כדי שהאירועים בכלל ייכתבו ל-Security log ---
# (הגדרה מקומית לכל מחשב - אם יש לך AD domain, עדיף להגדיר את זה פעם אחת ב-GPO במקום כאן)
Write-Host "[*] Enabling required audit policies..." -ForegroundColor Cyan
try {
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable | Out-Null
    Write-Host "[+] Audit policies enabled." -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to set audit policies (need Administrator): $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- שלב 1: nssm.exe (מקומי, ואם לא נמצא - הורדה) ---
Write-Host "[*] Looking for nssm.exe..." -ForegroundColor Cyan
if (Test-Path $localNssm) {
    Write-Host "[+] Found local nssm.exe, copying..." -ForegroundColor Green
    Copy-Item -Path $localNssm -Destination $nssmPath -Force
} else {
    Write-Host "[*] Not found locally, downloading nssm.exe..." -ForegroundColor Yellow
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        Invoke-WebRequest -Uri $NSSM_URL -OutFile $nssmPath -UserAgent "Mozilla/5.0" -ErrorAction Stop
        Write-Host "[+] nssm.exe downloaded successfully." -ForegroundColor Green
    } catch {
        Write-Host "[!] CRITICAL: could not find or download nssm.exe. $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# --- שלב 2: agent script (מקומי, ואם לא נמצא - הורדה מהשרת) ---
if (Test-Path $localSend) {
    Write-Host "[*] Using local send.ps1..." -ForegroundColor Cyan
    $agentContent = Get-Content -Path $localSend -Raw
} else {
    Write-Host "[*] send.ps1 not found locally, downloading latest version from server..." -ForegroundColor Yellow
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        $agentContent = (Invoke-WebRequest -Uri $SEND_PS1_URL -UseBasicParsing -ErrorAction Stop).Content
        Write-Host "[+] send.ps1 downloaded successfully." -ForegroundColor Green
    } catch {
        Write-Host "[!] CRITICAL: could not find or download send.ps1. $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

Write-Host "[*] Deploying agent script..." -ForegroundColor Cyan

if ($AgentToken -ne "") {
    $agentContent = $agentContent -replace 'CHANGE_ME_SET_SAME_VALUE_AS_VERCEL_AGENT_TOKEN', $AgentToken
} else {
    Write-Host "[!] WARNING: No -AgentToken provided. The placeholder token will be used and the server will reject events (401) until you set AGENT_TOKEN to match Vercel." -ForegroundColor Yellow
}

Set-Content -Path $agentPath -Value $agentContent -Force -Encoding UTF8

# --- שלב 3: התקנה/הפעלה מחדש נקייה כשירות Windows ---
if (Get-Service "Hayanuka_SIEM_Agent" -ErrorAction SilentlyContinue) {
    if ((Test-Path $hashFile) -and -not $NoProtect) {
        Write-Host "[*] Existing PROTECTED installation detected - the removal password is required to reinstall/update." -ForegroundColor Cyan
        if ($UninstallPassword -eq "") {
            $sec = Read-Host "Enter removal password" -AsSecureString
            $UninstallPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
        }
        if ((Get-Sha256Hex $UninstallPassword) -ne (Get-Content $hashFile -Raw).Trim()) {
            Write-Host "[!] Incorrect removal password. Aborting - the existing protected service was NOT touched." -ForegroundColor Red
            exit 1
        }
        Write-Host "[+] Password verified." -ForegroundColor Green
    }
    Write-Host "[*] Removing existing service registration (will recreate)..." -ForegroundColor Cyan
    Invoke-PrivilegedServiceRemoval -Mode ServiceOnly | Out-Null
    Start-Sleep -Seconds 1
}

Write-Host "[*] Creating Windows background service (Hayanuka_SIEM_Agent) via NSSM..." -ForegroundColor Cyan
# חשוב: Application ו-AppParameters נקבעים בקריאות "set" נפרדות (לא כמחרוזת אחת ל-"install"),
# אחרת ה-quoting של הנתיב יכול להישבר אם יש רווח בנתיב (למשל "Program Files") - זה היה הבאג בפועל.
& $nssmPath install "Hayanuka_SIEM_Agent" "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
& $nssmPath set "Hayanuka_SIEM_Agent" AppParameters "-ExecutionPolicy Bypass -NoProfile -File `"$agentPath`""
& $nssmPath set "Hayanuka_SIEM_Agent" AppDirectory $installDir
& $nssmPath set "Hayanuka_SIEM_Agent" Start SERVICE_AUTO_START
& $nssmPath set "Hayanuka_SIEM_Agent" AppThrottle 15000 | Out-Null
& $nssmPath start "Hayanuka_SIEM_Agent" 2>$null | Out-Null

# NSSM לפעמים מעלה את השירות למצב Paused ברגע הראשון (תקלה ידועה) - מתקנים אוטומטית
Start-Sleep -Seconds 3
$svc = Get-Service "Hayanuka_SIEM_Agent" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Paused") {
    Write-Host "[*] Service came up Paused (known NSSM quirk) - resuming..." -ForegroundColor Yellow
    & $nssmPath resume "Hayanuka_SIEM_Agent" 2>$null | Out-Null
    Start-Sleep -Seconds 2
    $svc = Get-Service "Hayanuka_SIEM_Agent" -ErrorAction SilentlyContinue
}
if ($svc -and $svc.Status -ne "Running") {
    Write-Host "[*] Service not running yet, retrying Start-Service..." -ForegroundColor Yellow
    Start-Service "Hayanuka_SIEM_Agent" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $svc = Get-Service "Hayanuka_SIEM_Agent" -ErrorAction SilentlyContinue
}

if ($svc -and $svc.Status -eq "Running") {
    Write-Host "[+] Hayanuka SIEM Agent deployed and running as a Windows service." -ForegroundColor Green
} else {
    Write-Host "[!] Service installed, but status is '$($svc.Status)' - not confirmed Running." -ForegroundColor Red
    Write-Host "    Check $installDir\debug.txt, or run: Get-Service Hayanuka_SIEM_Agent" -ForegroundColor Red
}
Write-Host "    Logs: $installDir\debug.txt" -ForegroundColor DarkGray

# --- שלב 4: הגנה מפני הסרה/עצירה ללא אישור ---
if (-not $NoProtect) {
    Write-Host "[*] Hardening service permissions (blocks Stop/Delete via normal admin tools - only SYSTEM can)..." -ForegroundColor Cyan
    & sc.exe sdset "Hayanuka_SIEM_Agent" $serviceSddl | Out-Null

    if ($UninstallPassword -ne "") {
        Set-Content -Path $hashFile -Value (Get-Sha256Hex $UninstallPassword) -Force
        Write-Host "[+] Removal password set/updated. Uninstalling or reinstalling this agent will require it." -ForegroundColor Green
    } elseif (-not (Test-Path $hashFile)) {
        Write-Host "[!] No -UninstallPassword provided - service is hardened, but no removal password is configured yet." -ForegroundColor Yellow
        Write-Host "    Run again with -UninstallPassword 'yourpassword' to set one (recommended)." -ForegroundColor Yellow
    }

    Write-Host "[*] Registering tamper-detection watchdog (runs as SYSTEM every 5 minutes)..." -ForegroundColor Cyan
    $watchdogScriptPath = "$installDir\watchdog.ps1"
    # watchdog.ps1 הוא כרגע קובץ עצמאי (api/agent/watchdog.ps1) עם מנגנון self-update משלו -
    # בדיוק כמו send.ps1 - כדי שתיקונים עתידיים יתפשטו אוטומטית בלי להריץ install.ps1 מחדש
    # בכל מחשב. זה גם מבטל לצמיתות את כל הבעיות השבירות שהיו במחרוזת מקוננת שיצרה אותו בעבר.
    if (Test-Path $localWatchdog) {
        Write-Host "[*] Using local watchdog.ps1..." -ForegroundColor Cyan
        $watchdogContent = Get-Content -Path $localWatchdog -Raw
    } else {
        Write-Host "[*] watchdog.ps1 not found locally, downloading latest version from server..." -ForegroundColor Yellow
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
            $watchdogContent = (Invoke-WebRequest -Uri $WATCHDOG_PS1_URL -UseBasicParsing -ErrorAction Stop).Content
            Write-Host "[+] watchdog.ps1 downloaded successfully." -ForegroundColor Green
        } catch {
            Write-Host "[!] CRITICAL: could not find or download watchdog.ps1. $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }
    if ($AgentToken -ne "") {
        $watchdogContent = $watchdogContent -replace 'CHANGE_ME_SET_SAME_VALUE_AS_VERCEL_AGENT_TOKEN', $AgentToken
    }
    Set-Content -Path $watchdogScriptPath -Value $watchdogContent -Force -Encoding UTF8

    Unregister-ScheduledTask -TaskName $watchdogTask -Confirm:$false -ErrorAction SilentlyContinue
    $wdAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$watchdogScriptPath`""
    # שים לב: [TimeSpan]::MaxValue שובר את ה-Register-ScheduledTask (חורג ממגבלת ה-XML של Task
    # Scheduler, שגיאה "Duration:P99999999DT23H59M59S") - במקום זה משתמשים במשך ארוך אך תקין (10 שנים).
    $wdTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
    $wdPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    try {
        Register-ScheduledTask -TaskName $watchdogTask -Action $wdAction -Trigger $wdTrigger -Principal $wdPrincipal -Force -ErrorAction Stop | Out-Null
        Write-Host "[+] Watchdog registered." -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to register the watchdog: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "    Tamper-detection and remote Stop/Start/Uninstall from the dashboard will NOT work until this is fixed." -ForegroundColor Red
    }
    Write-Host "[i] To fully uninstall later, use uninstall.ps1 (requires the removal password)." -ForegroundColor DarkGray
} else {
    Write-Host "[i] -NoProtect used: service left unprotected (no ACL hardening, no password, no watchdog)." -ForegroundColor DarkGray
}
