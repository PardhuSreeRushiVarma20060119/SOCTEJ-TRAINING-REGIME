# IR Triage Collection Script for Windows

# Create output folder
$ComputerName = $env:computername
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutDir = "Triage_$($ComputerName)_$Timestamp"
New-Item -ItemType Directory -Path $OutDir

Write-Host "[*] Starting Triage Collection on $ComputerName" -ForegroundColor Cyan

# 1. System Info
Write-Host "[*] Collecting System Info..."
systeminfo > "$OutDir\systeminfo.txt"

# 2. Network Connections
Write-Host "[*] Collecting Network Info..."
netstat -ano > "$OutDir\netstat.txt"
ipconfig /all > "$OutDir\ipconfig.txt"
Get-NetRoute > "$OutDir\routing_table.txt"

# 3. Process List with Command Line
Write-Host "[*] Collecting Process List..."
Get-WmiObject Win32_Process | Select-Object Name, ProcessId, ParentProcessId, CommandLine, ExecutablePath | Export-Csv -Path "$OutDir\process_list.csv" -NoTypeInformation

# 4. Persistence (Scheduled Tasks & Services)
Write-Host "[*] Collecting Persistence Artifacts..."
Get-ScheduledTask | Select-Object TaskName, TaskPath, State | Export-Csv -Path "$OutDir\scheduled_tasks.csv" -NoTypeInformation
Get-Service | Select-Object Name, DisplayName, Status, StartType | Export-Csv -Path "$OutDir\services.csv" -NoTypeInformation

# 5. Local Users & Groups
Write-Host "[*] Collecting User Info..."
net user > "$OutDir\local_users.txt"
net localgroup administrators > "$OutDir\local_admins.txt"

Write-Host "[+] Triage collection complete. Output saved to: $OutDir" -ForegroundColor Green
