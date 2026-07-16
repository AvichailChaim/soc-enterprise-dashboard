# Hayanuka SIEM Agent
# רץ כשירות Windows (מותקן ע"י install.ps1). קורא Security + System event logs
# ושולח אירועים ל-SOC dashboard (Vercel + Neon Postgres) לצורך ניקוד/התראות/חקירה.

$SIEM_BASE   = "https://soc-enterprise-dashboard-hayanuka.vercel.app"
$SIEM_EVENT  = "$SIEM_BASE/api/event"
$SIEM_UPDATE = "$SIEM_BASE/api/agent-update"

# חייב להיות זהה לערך AGENT_TOKEN שמוגדר ב-Vercel -> Settings -> Environment Variables.
# בלי טוקן תואם, השרת ידחה את האירועים (401).
$AGENT_TOKEN = "CHANGE_ME_SET_SAME_VALUE_AS_VERCEL_AGENT_TOKEN"

$installDir = "C:\Program Files\Hayanuka_SIEM"
$debugFile  = "$installDir\debug.txt"
if (!(Test-Path $installDir)) { New-Item -ItemType Directory -Path $installDir -Force | Out-Null }

"Agent Started $(Get-Date)" | Out-File $debugFile -Append

$lastCheckSecurity = (Get-Date).AddMinutes(-5)
$lastCheckSystem   = (Get-Date).AddMinutes(-5)
$loopCount = 0

function Send-SiemEvent {
    param($user, $action, $source, $ip)
    $body = @{ user = $user; action = $action; source = $source; ip = $ip } | ConvertTo-Json
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
                        Move-Item -Path $newScriptPath -Destination $currentScript -Force
                        Restart-Service "Hayanuka_SIEM_Agent" -Force
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

                switch ($eventID) {
                    4625 {
                        $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                        $ip = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
                        $logonType = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "LogonType" }).'#text'
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
                        # התחברות עם קרדנשיאלס מפורשים - סימן אפשרי לתנועה רוחבית / pass-the-hash
                        $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                        $ip = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
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
                Send-SiemEvent -user $targetUser -action $action -source $source -ip $ip
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

    Start-Sleep -Seconds 10
}
