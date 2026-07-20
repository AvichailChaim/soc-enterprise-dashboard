# Hayanuka SIEM Agent
# רץ כשירות Windows (מותקן ע"י install.ps1). קורא Security + System event logs
# ושולח אירועים ל-SOC dashboard (Vercel + Neon Postgres) לצורך ניקוד/התראות/חקירה.

$SIEM_BASE   = "https://soc-enterprise-dashboard-hayanuka.vercel.app"
$SIEM_EVENT  = "$SIEM_BASE/api/event"
$SIEM_UPDATE = "$SIEM_BASE/api/agent-update"

# חייב להיות זהה לערך AGENT_TOKEN שמוגדר ב-Vercel -> Settings -> Environment Variables.
# בלי טוקן תואם, השרת ידחה את האירועים (401).
$AGENT_TOKEN = "CHANGE_ME_SET_SAME_VALUE_AS_VERCEL_AGENT_TOKEN"

$installDir = "C:\Hayanuka_SIEM"
$debugFile  = "$installDir\debug.txt"
if (!(Test-Path $installDir)) { New-Item -ItemType Directory -Path $installDir -Force | Out-Null }

"Agent Started $(Get-Date)" | Out-File $debugFile -Append

function Get-LocalLanIp {
    # כתובת ה-IP המקומית (LAN) האמיתית של המחשב - לא 127.0.0.1, ולא כתובת link-local אוטומטית.
    # קודם מנסים למצוא את המתאם עם Default Gateway מוגדר (סימן חזק שזו ההתחברות "האמיתית"
    # לרשת/אינטרנט - Wi-Fi/Ethernet פיזי), כדי לא לבחור בטעות מתאם וירטואלי (VPN, Hyper-V, VMware וכו').
    try {
        $cfg = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
            Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq "Up" } |
            Select-Object -First 1
        if ($cfg -and $cfg.IPv4Address) {
            return $cfg.IPv4Address.IPAddress
        }
        # נפילה לאחור: כל כתובת IPv4 שאינה loopback/link-local
        $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
            Select-Object -First 1).IPAddress
        if (!$ip) { return "unknown" }
        return $ip
    } catch { return "unknown" }
}
$LAN_IP = Get-LocalLanIp
"LAN IP detected: $LAN_IP" | Out-File $debugFile -Append

$lastCheckSecurity = (Get-Date).AddMinutes(-5)
$lastCheckSystem   = (Get-Date).AddMinutes(-5)
$lastCheckDefender = (Get-Date).AddMinutes(-5)
$loopCount = 0

function Get-LogonFailureReason {
    # ממפה קוד Sub Status/Status של Event 4625 לסיבה קריאה לבן אדם, כדי שההתראה בדשבורד
    # תגיד במפורש "סיסמה שגויה" / "משתמש לא קיים" וכו', ולא רק "ניסיון כניסה נכשל".
    param($subStatus, $status)
    $map = @{
        '0XC000006A' = 'Bad password (user name exists, wrong password)'
        '0XC0000064' = 'User name does not exist'
        '0XC0000234' = 'Account is currently locked out'
        '0XC0000072' = 'Account is disabled'
        '0XC0000193' = 'Account has expired'
        '0XC0000071' = 'Password has expired'
        '0XC0000224' = 'Password change required at next logon'
        '0XC000006F' = 'Logon attempted outside allowed hours'
        '0XC0000070' = 'Workstation restriction (not permitted to log on from this device)'
        '0XC0000133' = 'Clock skew between client and domain controller is too large'
        '0XC000015B' = 'User does not have the requested logon type on this machine'
    }
    foreach ($code in @($subStatus, $status)) {
        if ($code) {
            $key = $code.ToString().ToUpper()
            if ($map.ContainsKey($key)) { return $map[$key] }
        }
    }
    if ($subStatus -or $status) { return "Unknown reason (code: $subStatus$status)" }
    return $null
}

function Send-SiemEvent {
    param($user, $action, $source, $ip, $reason = $null)
    $body = @{ user = $user; action = $action; source = $source; ip = $ip; lan_ip = $LAN_IP; reason = $reason } | ConvertTo-Json
    try {
        Invoke-RestMethod -Uri $SIEM_EVENT -Method Post -Body $body -ContentType "application/json" `
            -Headers @{ "X-Agent-Token" = $AGENT_TOKEN } -TimeoutSec 5 | Out-Null
        "Sent: $action ($user)" | Out-File $debugFile -Append
    } catch {
        "Send error ($action): $($_.Exception.Message)" | Out-File $debugFile -Append
    }
}

while ($true) {

    # --- self-update: כל ~10 סבבים (~100 שניות) בודק גרסה חדשה ---
    if ($loopCount -ge 10) {
        $loopCount = 0
        try {
            $currentScript = $MyInvocation.MyCommand.Path
            if ($currentScript) {
                $newScriptPath = "$currentScript.new"
                Invoke-WebRequest -Uri $SIEM_UPDATE -OutFile $newScriptPath -TimeoutSec 15 -ErrorAction SilentlyContinue
                if (Test-Path $newScriptPath) {
                    if ((Get-FileHash $currentScript).Hash -ne (Get-FileHash $newScriptPath).Hash) {
                        "Self-update: new version detected, swapping file and exiting $(Get-Date)" | Out-File $debugFile -Append
                        Move-Item -Path $newScriptPath -Destination $currentScript -Force
                        # לא קוראים כאן ל-Restart-Service על עצמנו (זה שביר תחת nssm - התהליך
                        # מבקש לעצור את עצמו ולפעמים לא חוזר). במקום זה פשוט יוצאים, ו-nssm
                        # (AppExit=Restart, ברירת מחדל) יעלה מחדש את התהליך עם הקובץ המעודכן.
                        exit
                    }
                    Remove-Item $newScriptPath -ErrorAction SilentlyContinue
                }
            }
        } catch {}
    }
    $loopCount++

    # --- Security log: כניסות, יצירת משתמשים, ניקוי לוג, הרשאות, brute force, lateral movement ---
    try {
        $secIds = @(4624,4625,4720,1102,4663,4740,4648,4672,4697)
        $filter = "*[System[( " + (($secIds | ForEach-Object { "(EventID=$_)" }) -join " or ") + " ) and TimeCreated[@SystemTime>='$($lastCheckSecurity.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))']]]"
        $events = Get-WinEvent -LogName "Security" -FilterXPath $filter -ErrorAction SilentlyContinue
        $lastCheckSecurity = Get-Date

        foreach ($log in $events) {
            try {
                $xml = [xml]$log.ToXml()
                $eventID = $log.Id
                $targetUser = "System"
                $action = "unknown_event"
                $ip = "127.0.0.1"
                $source = "$($env:COMPUTERNAME) (Event ID $eventID)"
                $reason = $null

                switch ($eventID) {
                    4625 {
                        $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                        $ip = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
                        $logonType = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "LogonType" }).'#text'
                        $subStatus = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SubStatus" }).'#text'
                        $status = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "Status" }).'#text'
                        $reason = Get-LogonFailureReason -subStatus $subStatus -status $status
                        $action = if ($logonType -eq "3") { "network_file_access_failed" } else { "login_failed" }
                    }
                    4624 {
                        $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                        $ip = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
                        $action = "login_success"
                    }
                    4720 {
                        $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                        $action = "user_created"
                    }
                    1102 {
                        $targetUser = ($xml.Event.UserData.LogClear.SubjectUserName).'#text'
                        if (!$targetUser) { $targetUser = "Admin/System" }
                        $action = "audit_log_cleared"
                    }
                    4663 {
                        $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
                        $objectName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ObjectName" }).'#text'
                        $action = "file_permission_denied"
                        $source = "File: $(Split-Path $objectName -Leaf)"
                    }
                    4740 {
                        # נעילת חשבון - סימן חזק לניסיון brute force
                        $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                        $ip = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetDomainName" }).'#text'
                        $action = "account_locked_out"
                    }
                    4648 {
                        # התחברות עם קרדנשיאלס מפורשים - סימן אפשרי לתנועה רוחבית / pass-the-hash.
                        # שולפים גם מי ביצע את זה (SubjectUserName), איזה תהליך (ProcessName) ולאיזה
                        # יעד (TargetServerName), כדי שההתראה תגיד בדיוק מה קרה ולא רק "יש חשד".
                        $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                        $ip = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
                        $subjectUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
                        $processName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ProcessName" }).'#text'
                        $targetServer = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetServerName" }).'#text'
                        $procShort = if ($processName) { Split-Path $processName -Leaf } else { "unknown process" }
                        $reason = "Process '$procShort' on this machine (run by '$subjectUser') explicitly authenticated as user '$targetUser'" + $(if ($targetServer -and $targetServer -notlike "localhost*") { " to target '$targetServer'" } else { "" }) + ". Common legitimate causes: Run-as/elevation with different credentials, saved-credential RDP/network drive, or a scheduled task/service configured with explicit credentials. Verify this matches something you or IT actually did."
                        $action = "explicit_credential_logon"
                    }
                    4672 {
                        # התחברות עם הרשאות מנהל
                        $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
                        $action = "privileged_logon"
                    }
                    4697 {
                        # התקנת שירות חדש - סימן אפשרי ל-persistence
                        $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
                        $action = "new_service_installed"
                    }
                }

                if (!$ip -or $ip -eq "-") { $ip = "127.0.0.1" }
                Send-SiemEvent -user $targetUser -action $action -source $source -ip $ip -reason $reason
            } catch { "Error parsing security event: $($_.Exception.Message)" | Out-File $debugFile -Append }
        }
    } catch { "Security log query error: $($_.Exception.Message)" | Out-File $debugFile -Append }

    # --- System log: התקנת שירותים (7045) - עוד מנגנון persistence שכיח ---
    try {
        $filter7045 = "*[System[(EventID=7045) and TimeCreated[@SystemTime>='$($lastCheckSystem.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))']]]"
        $sysEvents = Get-WinEvent -LogName "System" -FilterXPath $filter7045 -ErrorAction SilentlyContinue
        $lastCheckSystem = Get-Date

        foreach ($log in $sysEvents) {
            $xml = [xml]$log.ToXml()
            $serviceName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ServiceName" }).'#text'
            Send-SiemEvent -user "System" -action "new_service_installed" -source "Service: $serviceName" -ip "127.0.0.1"
        }
    } catch { "System log query error: $($_.Exception.Message)" | Out-File $debugFile -Append }

    # --- Windows Defender log: זיהוי/חסימה של malware-ransomware, וכיבוי הגנה בזמן אמת ---
    try {
        $defIds = @(1116,1117,5001,5010,5012)
        $defFilter = "*[System[( " + (($defIds | ForEach-Object { "(EventID=$_)" }) -join " or ") + " ) and TimeCreated[@SystemTime>='$($lastCheckDefender.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))']]]"
        $defEvents = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -FilterXPath $defFilter -ErrorAction SilentlyContinue
        $lastCheckDefender = Get-Date

        foreach ($log in $defEvents) {
            $action = switch ($log.Id) {
                1116 { "malware_detected" }
                1117 { "malware_blocked" }
                default { "defender_protection_disabled" }
            }
            $msg = $log.Message
            $shortMsg = if ($msg) { $msg.Substring(0, [Math]::Min(150, $msg.Length)) -replace "[\r\n]+", " " } else { "Windows Defender event $($log.Id)" }
            Send-SiemEvent -user $env:USERNAME -action $action -source "$($env:COMPUTERNAME): $shortMsg" -ip "127.0.0.1"
        }
    } catch { "Defender log query error: $($_.Exception.Message)" | Out-File $debugFile -Append }

    Start-Sleep -Seconds 10
}
