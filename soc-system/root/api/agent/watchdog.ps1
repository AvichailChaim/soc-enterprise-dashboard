# Hayanuka SIEM Watchdog - רץ כ-SYSTEM כל 5 דקות (Scheduled Task, לא שירות).
# self-update test marker: v2
# 1. self-update - מוריד גרסה עדכנית של עצמו מהשרת (בדיוק כמו send.ps1), כדי שתיקונים עתידיים
#    יתפשטו אוטומטית לכל המחשבים בלי צורך להריץ install.ps1 מחדש בכל מחשב בנפרד.
# 2. אם השירות נעלם/נעצר בלי אישור (לא דרך control.ps1/uninstall.ps1/הדשבורד) - משחזר אותו
#    אוטומטית ושולח התראת Critical לדשבורד (agent_tamper_detected).
# 3. בודק פקודות מרוחקות מהדשבורד (Computers page: Stop/Start/Uninstall) - מבוצעות רק אם
#    הסיסמה שנשלחה מהדשבורד תואמת ל-hash המקומי (uninstall.hash) שנקבע ב-install.ps1.

$DASHBOARD_BASE = "https://soc-enterprise-dashboard-hayanuka.vercel.app"
$WATCHDOG_UPDATE_URL = "$DASHBOARD_BASE/api/watchdog-update"
# חייב להיות זהה לערך AGENT_TOKEN שמוגדר ב-Vercel (אם בכלל מוגדר - כרגע לא בשימוש בפרויקט הזה).
$AGENT_TOKEN = "CHANGE_ME_SET_SAME_VALUE_AS_VERCEL_AGENT_TOKEN"

$installDir = "C:\Hayanuka_SIEM"
$debugFile = "$installDir\debug.txt"
$maintenanceFile = "$installDir\maintenance.flag"
$hashFile = "$installDir\uninstall.hash"
$watchdogTaskName = "Hayanuka_SIEM_Watchdog"
$serviceSddl = "D:(A;;GA;;;SY)(A;;CCLCSWLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"

# --- self-update: בודק גרסה חדשה בכל ריצה (כל 5 דק'). שים לב: אם ה-AGENT_TOKEN בקובץ הזה
# הוחלף ידנית ל-token אמיתי ע"י install.ps1, self-update ידרוס אותו בחזרה לברירת המחדל -
# בדיוק כמו ההתנהגות הקיימת ב-send.ps1. לא רלוונטי כרגע כי AGENT_TOKEN לא מוגדר בפרויקט הזה. ---
try {
    $newContent = (Invoke-WebRequest -Uri $WATCHDOG_UPDATE_URL -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop).Content
    $currentContent = Get-Content -Path $PSCommandPath -Raw -ErrorAction Stop
    if ($newContent -and ($newContent.Trim() -ne $currentContent.Trim())) {
        Set-Content -Path $PSCommandPath -Value $newContent -Force -Encoding UTF8
        "$(Get-Date) Watchdog: self-update - new version installed, effective next run (~5 min)." | Out-File $debugFile -Append
        exit
    }
} catch {
    "$(Get-Date) Watchdog: self-update check failed: $($_.Exception.Message)" | Out-File $debugFile -Append
}

function Get-Sha256Hex($text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))
    return ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLower()
}

function Send-TamperAlert($reasonText) {
    try {
        Invoke-RestMethod -Uri "$DASHBOARD_BASE/api/event" -Method Post `
            -Body (@{ user = $env:USERNAME; action = "agent_tamper_detected"; source = "$($env:COMPUTERNAME): $reasonText"; ip = "127.0.0.1" } | ConvertTo-Json) `
            -ContentType "application/json" -Headers @{ "X-Agent-Token" = $AGENT_TOKEN } -TimeoutSec 5 | Out-Null
    } catch {}
}

# ===== פקודות מרוחקות מהדשבורד (Computers page: Stop / Start / Uninstall) =====
# נבדק בכל ריצה, בלי קשר למצב השירות. הפקודה מבוצעת רק אם הסיסמה שנשלחה מהדשבורד תואמת
# ל-hash המקומי - כלומר גישה לדשבורד לבדה לא מספיקה כדי להסיר/לעצור.
try {
    $cmdResp = Invoke-RestMethod -Uri "$DASHBOARD_BASE/api/agent-command?host=$($env:COMPUTERNAME)" `
        -Headers @{ "X-Agent-Token" = $AGENT_TOKEN } -TimeoutSec 10 -ErrorAction Stop
    "$(Get-Date) Watchdog: checked for remote commands - found: $(if ($cmdResp -and $cmdResp.command) { $cmdResp.command } else { 'none' })" | Out-File $debugFile -Append
    if ($cmdResp -and $cmdResp.command) {
        $passOk = (Test-Path $hashFile) -and $cmdResp.password -and ((Get-Sha256Hex $cmdResp.password) -eq (Get-Content $hashFile -Raw).Trim())
        if (-not $passOk) {
            "$(Get-Date) Remote command '$($cmdResp.command)' received but password did NOT match local hash - ignored." | Out-File $debugFile -Append
        } else {
            "$(Get-Date) Remote command '$($cmdResp.command)' verified - executing." | Out-File $debugFile -Append
            if ($cmdResp.command -eq "stop") {
                $minutes = if ($cmdResp.maintenance_minutes) { $cmdResp.maintenance_minutes } else { 60 }
                (Get-Date).ToUniversalTime().AddMinutes($minutes).ToString("o") | Out-File $maintenanceFile -Force
                Stop-Service "Hayanuka_SIEM_Agent" -Force -ErrorAction SilentlyContinue
            } elseif ($cmdResp.command -eq "start") {
                Remove-Item $maintenanceFile -ErrorAction SilentlyContinue
                Start-Service "Hayanuka_SIEM_Agent" -ErrorAction SilentlyContinue
            } elseif ($cmdResp.command -eq "uninstall") {
                $q = [char]34
                $helperPath = Join-Path $env:TEMP "hayanuka_remote_removal.ps1"
                $helperLines = @(
                    "try {"
                    "    Stop-Service ${q}Hayanuka_SIEM_Agent${q} -Force -ErrorAction SilentlyContinue"
                    "    if (Test-Path ${q}$installDir\nssm.exe${q}) { & ${q}$installDir\nssm.exe${q} remove ${q}Hayanuka_SIEM_Agent${q} confirm 2>`$null | Out-Null }"
                    "    Unregister-ScheduledTask -TaskName ${q}$watchdogTaskName${q} -Confirm:`$false -ErrorAction SilentlyContinue"
                    "    Start-Sleep -Seconds 1"
                    "    Remove-Item -Path ${q}$installDir${q} -Recurse -Force -ErrorAction SilentlyContinue"
                    "} catch {}"
                )
                Set-Content -Path $helperPath -Value ($helperLines -join "`n") -Force
                $rTaskName = "Hayanuka_Remote_Removal_$([guid]::NewGuid().ToString('N').Substring(0,8))"
                $argValue = "-ExecutionPolicy Bypass -NoProfile -File $q$helperPath$q"
                $rAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argValue
                $rPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                Register-ScheduledTask -TaskName $rTaskName -Action $rAction -Principal $rPrincipal -Force | Out-Null
                Start-ScheduledTask -TaskName $rTaskName
                "$(Get-Date) Remote uninstall triggered via dashboard - agent will be removed shortly." | Out-File $debugFile -Append
                exit
            }
        }
    }
} catch {
    "$(Get-Date) Watchdog: remote-command check failed: $($_.Exception.Message)" | Out-File $debugFile -Append
}

# חלון תחזוקה מבוקר-סיסמה (נפתח ע"י control.ps1 -Action Stop, או "Stop" מהדשבורד) - כל עוד הוא
# בתוקף, לא משחזרים ולא מתריעים.
$maintenanceActive = $false
if (Test-Path $maintenanceFile) {
    try {
        $expiry = [datetime]::Parse((Get-Content $maintenanceFile -Raw).Trim(), $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
        if ((Get-Date).ToUniversalTime() -lt $expiry) { $maintenanceActive = $true }
        else { Remove-Item $maintenanceFile -ErrorAction SilentlyContinue }
    } catch { Remove-Item $maintenanceFile -ErrorAction SilentlyContinue }
}

if ($maintenanceActive) {
    "$(Get-Date) Watchdog: authorized maintenance window active, skipping checks." | Out-File $debugFile -Append
    exit
}

$svc = Get-Service "Hayanuka_SIEM_Agent" -ErrorAction SilentlyContinue
if (-not $svc) {
    "$(Get-Date) TAMPER ALERT: service is missing - attempting automatic restore." | Out-File $debugFile -Append
    if ((Test-Path "$installDir\send.ps1") -and (Test-Path "$installDir\nssm.exe")) {
        & "$installDir\nssm.exe" install "Hayanuka_SIEM_Agent" "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        & "$installDir\nssm.exe" set "Hayanuka_SIEM_Agent" AppParameters "-ExecutionPolicy Bypass -NoProfile -File `"$installDir\send.ps1`""
        & "$installDir\nssm.exe" set "Hayanuka_SIEM_Agent" AppDirectory $installDir
        & "$installDir\nssm.exe" set "Hayanuka_SIEM_Agent" Start SERVICE_AUTO_START
        & "$installDir\nssm.exe" start "Hayanuka_SIEM_Agent" 2>$null | Out-Null
        & sc.exe sdset "Hayanuka_SIEM_Agent" $serviceSddl | Out-Null
        Send-TamperAlert "SIEM agent service was REMOVED without authorization and was auto-restored"
    }
} elseif ($svc.Status -notin @("Running", "StartPending")) {
    "$(Get-Date) TAMPER ALERT: service found in state $($svc.Status) without an authorized maintenance window - restarting." | Out-File $debugFile -Append
    Start-Service "Hayanuka_SIEM_Agent" -ErrorAction SilentlyContinue
    Send-TamperAlert "SIEM agent service was STOPPED without authorization and was auto-restarted"
}
