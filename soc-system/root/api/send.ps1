# עדכן את הכתובת הזו לכתובת האתר האמיתית שלך ב-Vercel
$SIEM_BASE = "https://soc-enterprise-dashboard-hayanuka.vercel.app"
$SIEM_EVENT = "$SIEM_BASE/api" # שינינו ל-/api כדי שיתאים ל-Vercel
$logPath = "D:\Cyber\soc-system\agent_log.txt"

"Agent Started at $(Get-Date)" | Out-File $logPath -Append

$lastCheck = (Get-Date).AddMinutes(-1)

while ($true) {
    try {
        $events = Get-WinEvent -LogName "Security" -FilterXPath "*[System[( (EventID=4625) or (EventID=4624) or (EventID=4720) or (EventID=1102) or (EventID=4663) ) and TimeCreated[@SystemTime>='$($lastCheck.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))']]]" -ErrorAction SilentlyContinue
        
        if ($events) {
            foreach ($log in $events) {
                try {
                    $xml = [xml]$log.ToXml()
                    $eventID = $log.Id
                    $targetUser = "System"
                    
                    # מיפוי פעולות בהתאם ל-engine.py שלך
                    $action = switch ($eventID) {
                        4625 { "login_failed" }
                        4624 { "login_success" }
                        4720 { "user_created" }
                        1102 { "audit_log_cleared" }
                        4663 { "file_permission_denied" }
                        Default { "event_$eventID" }
                    }

                    if ($eventID -eq 4625 -or $eventID -eq 4624 -or $eventID -eq 4720) {
                        $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                    }
                    
                    $json = @{ user = $targetUser; action = $action; source = $env:COMPUTERNAME } | ConvertTo-Json -Compress
                    
                    # שליחה ל-Vercel
                    Invoke-RestMethod -Uri $SIEM_EVENT -Method Post -Body $json -ContentType "application/json" -TimeoutSec 5
                    "Sent Event $action for $targetUser at $(Get-Date)" | Out-File $logPath -Append
                } catch { "Event processing error: $($_.Exception.Message)" | Out-File $logPath -Append }
            }
        }
        $lastCheck = (Get-Date)
    } catch { "Main loop error: $($_.Exception.Message)" | Out-File $logPath -Append }
    
    Start-Sleep -Seconds 10
}
