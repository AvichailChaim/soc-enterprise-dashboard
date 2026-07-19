# install.ps1 - מורץ כמנהל מערכת (Administrator) בכל תחנת קצה בארגון, כולל מחשבים מרוחקים.
#
# שימוש:
#   .\install.ps1 -AgentToken "הטוקן-הסודי-שהוגדר-ב-Vercel"
#
# הקובץ הזה עצמאי: אם send.ps1 ו/או nssm.exe לא נמצאים באותה תיקייה, הוא מוריד אותם
# אוטומטית מהאינטרנט. כלומר אפשר להעתיק *רק* את הקובץ הזה למחשב מרוחק (למשל דרך RDP,
# מייל, או כונן משותף) ולהריץ אותו שם - אין צורך להעתיק את כל תיקיית api/.
#
# הסקריפט מזריק את הטוקן לתוך send.ps1, ומתקין אותו כשירות Windows קבוע (auto-start) באמצעות NSSM.

param(
    [string]$AgentToken = ""
)

$installDir  = "C:\Program Files\Hayanuka_SIEM"
$agentPath   = "$installDir\send.ps1"
$nssmPath    = "$installDir\nssm.exe"
$localNssm   = Join-Path $PSScriptRoot "..\nssm.exe"   # api/nssm.exe, לצד תיקיית agent/ (אם קיים מקומית)
$localSend   = Join-Path $PSScriptRoot "send.ps1"       # api/agent/send.ps1 (אם קיים מקומית)

$SEND_PS1_URL = "https://soc-enterprise-dashboard-hayanuka.vercel.app/api/agent-update"
$NSSM_URL     = "https://raw.githubusercontent.com/x64dbg/x64dbg/master/src/nssm/nssm.exe"

if (!(Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
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

Set-Content -Path $agentPath -Value $agentContent -Force

# --- שלב 3: התקנה/הפעלה מחדש נקייה כשירות Windows ---
if (Get-Service "Hayanuka_SIEM_Agent" -ErrorAction SilentlyContinue) {
    Stop-Service "Hayanuka_SIEM_Agent" -Force -ErrorAction SilentlyContinue
    & $nssmPath remove "Hayanuka_SIEM_Agent" confirm | Out-Null
}

Write-Host "[*] Creating Windows background service (Hayanuka_SIEM_Agent) via NSSM..." -ForegroundColor Cyan
& $nssmPath install "Hayanuka_SIEM_Agent" "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$agentPath`""
& $nssmPath set "Hayanuka_SIEM_Agent" Start SERVICE_AUTO_START
& $nssmPath start "Hayanuka_SIEM_Agent"

Write-Host "[+] Hayanuka SIEM Agent deployed and running as a Windows service." -ForegroundColor Green
Write-Host "    Logs: $installDir\debug.txt" -ForegroundColor DarkGray
