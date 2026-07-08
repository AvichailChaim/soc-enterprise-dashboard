$SIEM_BASE = "https://creatures-nottingham-suitable-salaries.trycloudflare.com"
$SIEM_EVENT = "$SIEM_BASE/event"
$debugFile = "C:\Hayanuka_SIEM\debug.txt"

"Agent Started $(Get-Date)" | Out-File $debugFile -Append

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
                    $action = "event_$eventID"
                    
                    if ($eventID -eq 4625 -or $eventID -eq 4624) {
                        $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
                        $action = if($eventID -eq 4625) {"login_failed"} else {"login_success"}
                    }
                    
                    $json = @{ user = $targetUser; action = $action; source = $env:COMPUTERNAME } | ConvertTo-Json
                    Invoke-RestMethod -Uri $SIEM_EVENT -Method Post -Body $json -ContentType "application/json" -TimeoutSec 3
                    "Sent Event $eventID" | Out-File $debugFile -Append
                } catch { "Error in event loop: $($_.Exception.Message)" | Out-File $debugFile -Append }
            }
        }
        $lastCheck = (Get-Date)
    } catch { "Main loop error: $($_.Exception.Message)" | Out-File $debugFile -Append }
    Start-Sleep -Seconds 10
}