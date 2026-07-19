# control.ps1 - עצירה/הפעלה מבוקרת של סוכן ה-SIEM, בסיסמה בלבד.
#
# מכיוון שהשירות מוקשח (רק SYSTEM יכול לעצור/להפעיל אותו - Stop-Service/sc/nssm/Services.msc
# רגילים יחזירו "Access is denied"), זו הדרך הרשמית היחידה לעצור אותו זמנית (לצורך תחזוקה)
# מבלי להסיר אותו לגמרי. עצירה דרך כאן פותחת "חלון תחזוקה" מוגבל בזמן - כל עוד הוא בתוקף,
# ה-Watchdog לא יחזיר את השירות אוטומטית ולא יתריע. בתום הזמן (או עם -Action Start), הניטור חוזר.
#
# שימוש:
#   .\control.ps1 -Action Stop  -Password "הסיסמה" [-MaintenanceMinutes 60]
#   .\control.ps1 -Action Start -Password "הסיסמה"

param(
    [Parameter(Mandatory = $true)][ValidateSet('Stop', 'Start')]$Action,
    [Parameter(Mandatory = $true)][string]$Password,
    [int]$MaintenanceMinutes = 60
)

$installDir      = "C:\Hayanuka_SIEM"
$hashFile        = "$installDir\uninstall.hash"
$maintenanceFile = "$installDir\maintenance.flag"

function Get-Sha256Hex($text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))
    return ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLower()
}

if (!(Test-Path $hashFile)) {
    Write-Host "[!] This installation has no removal/control password configured (uninstall.hash missing)." -ForegroundColor Red
    Write-Host "    Re-run install.ps1 with -UninstallPassword to set one before this script can be used." -ForegroundColor Red
    exit 1
}
if ((Get-Sha256Hex $Password) -ne (Get-Content $hashFile -Raw).Trim()) {
    Write-Host "[!] Incorrect password. Nothing was changed." -ForegroundColor Red
    exit 1
}
Write-Host "[+] Password verified." -ForegroundColor Green

function Invoke-PrivilegedServiceAction {
    param([string]$ScriptBody)

    $helperPath = Join-Path $env:TEMP "hayanuka_priv_action.ps1"
    $donePath   = Join-Path $env:TEMP "hayanuka_priv_action.done"
    Remove-Item $donePath -ErrorAction SilentlyContinue

    $helperScript = "try {`n$ScriptBody`n} catch {}`n'done' | Out-File '$donePath' -Force"
    Set-Content -Path $helperPath -Value $helperScript -Force

    $taskName = "Hayanuka_Priv_Action_$([guid]::NewGuid().ToString('N').Substring(0,8))"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$helperPath`""
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName

    $waited = 0
    while (-not (Test-Path $donePath) -and $waited -lt 20) { Start-Sleep -Seconds 1; $waited++ }
    $success = Test-Path $donePath

    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $helperPath -ErrorAction SilentlyContinue
    Remove-Item $donePath -ErrorAction SilentlyContinue
    return $success
}

if ($Action -eq 'Stop') {
    $expiry = (Get-Date).ToUniversalTime().AddMinutes($MaintenanceMinutes).ToString("o")
    Set-Content -Path $maintenanceFile -Value $expiry -Force
    Write-Host "[*] Maintenance window opened until $expiry UTC (watchdog will not auto-restore during this window)." -ForegroundColor Cyan
    $ok = Invoke-PrivilegedServiceAction -ScriptBody "Stop-Service 'Hayanuka_SIEM_Agent' -Force -ErrorAction SilentlyContinue"
    if ($ok) { Write-Host "[+] Service stopped for up to $MaintenanceMinutes minute(s). Run '.\control.ps1 -Action Start -Password ...' to resume sooner." -ForegroundColor Green }
    else { Write-Host "[!] Could not confirm the service stopped. Check: Get-Service Hayanuka_SIEM_Agent" -ForegroundColor Red }
} else {
    Remove-Item $maintenanceFile -ErrorAction SilentlyContinue
    $ok = Invoke-PrivilegedServiceAction -ScriptBody "Start-Service 'Hayanuka_SIEM_Agent' -ErrorAction SilentlyContinue"
    if ($ok) { Write-Host "[+] Monitoring resumed." -ForegroundColor Green }
    else { Write-Host "[!] Could not confirm the service started. Check: Get-Service Hayanuka_SIEM_Agent" -ForegroundColor Red }
}
