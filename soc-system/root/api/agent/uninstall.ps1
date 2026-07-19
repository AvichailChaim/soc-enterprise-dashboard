# uninstall.ps1 - מסיר לגמרי את סוכן ה-SIEM (שירות + Watchdog + כל הקבצים) מתחנת קצה.
#
# שימוש:
#   .\uninstall.ps1
#   (יבקש את סיסמת ההסרה שהוגדרה בהתקנה עם -UninstallPassword)
#
# זו הדרך הרשמית היחידה שנועדה להסיר את הסוכן. אם השירות הוקשח בהתקנה (ברירת המחדל),
# אי אפשר להסיר/לעצור אותו ישירות עם Stop-Service / sc delete / nssm remove / Services.msc -
# פעולות כאלה יחזירו "Access is denied" כי רק SYSTEM מורשה לכך. הסקריפט הזה מאמת את הסיסמה
# ואז מפעיל הסרה מלאה דרך Scheduled Task זמני שרץ כ-SYSTEM.
#
# הערה לגבי הגבלות: הגנה זו מיועדת למנוע הסרה בטעות/על ידי משתמש קצה או מנהל מערכת מזדמן.
# מנהל מערכת מקומי מיומן, שמכיר לעומק הרשאות שירותי Windows, יכול תיאורטית עדיין לעקוף הגנה
# מבוססת-תוכנה כזו (זו מגבלה ידועה של Windows - אין הגנה מוחלטת בפני Administrator מקומי בלי
# דרייבר חתום ברמת הליבה). ההגנה כאן מונעת את כל דרכי ההסרה/העצירה הרגילות והמקובלות.

param(
    [string]$Password = ""
)

$installDir   = "C:\Hayanuka_SIEM"
$hashFile     = "$installDir\uninstall.hash"
$watchdogTask = "Hayanuka_SIEM_Watchdog"

function Get-Sha256Hex($text) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))
    return ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLower()
}

if (-not (Get-Service "Hayanuka_SIEM_Agent" -ErrorAction SilentlyContinue) -and -not (Test-Path $installDir)) {
    Write-Host "[i] Hayanuka SIEM Agent is not installed on this machine. Nothing to do." -ForegroundColor DarkGray
    exit 0
}

if (Test-Path $hashFile) {
    if ($Password -eq "") {
        $sec = Read-Host "Enter removal password" -AsSecureString
        $Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
    }
    if ((Get-Sha256Hex $Password) -ne (Get-Content $hashFile -Raw).Trim()) {
        Write-Host "[!] Incorrect removal password. Uninstall aborted - nothing was changed." -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Password verified." -ForegroundColor Green
} else {
    Write-Host "[!] WARNING: No removal password was configured for this installation - proceeding without a password check." -ForegroundColor Yellow
}

Write-Host "[*] Removing service, watchdog and all files via SYSTEM-level helper task..." -ForegroundColor Cyan

$helperPath = Join-Path $env:TEMP "hayanuka_priv_removal.ps1"
$donePath   = Join-Path $env:TEMP "hayanuka_priv_removal.done"
Remove-Item $donePath -ErrorAction SilentlyContinue

$helperScript = @"
try {
    Stop-Service 'Hayanuka_SIEM_Agent' -Force -ErrorAction SilentlyContinue
    if (Test-Path '$installDir\nssm.exe') { & '$installDir\nssm.exe' remove 'Hayanuka_SIEM_Agent' confirm 2>`$null | Out-Null }
    Unregister-ScheduledTask -TaskName '$watchdogTask' -Confirm:`$false -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Remove-Item -Path '$installDir' -Recurse -Force -ErrorAction SilentlyContinue
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

if ($success -and -not (Get-Service "Hayanuka_SIEM_Agent" -ErrorAction SilentlyContinue) -and -not (Test-Path $installDir)) {
    Write-Host "[+] Hayanuka SIEM Agent fully removed from this machine." -ForegroundColor Green
} else {
    Write-Host "[!] Removal may not have completed. Check manually: Get-Service Hayanuka_SIEM_Agent ; Test-Path '$installDir'" -ForegroundColor Red
}
