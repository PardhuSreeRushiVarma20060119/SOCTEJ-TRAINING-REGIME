function Get-SuspiciousProcesses {
    <#
    .SYNOPSIS
        Triage script to find suspicious processes on a Windows host.
    #>
    $SuspiciousNames = @("powershell", "cmd", "whoami", "net", "nltest", "certutil", "vssadmin")
    
    $Processes = Get-Process | Where-Object { $SuspiciousNames -contains $_.ProcessName }
    
    foreach ($Proc in $Processes) {
        $Owner = (Get-WmiObject -Query "Select * from Win32_Process Where ProcessId = $($Proc.Id)").GetOwner().User
        [PSCustomObject]@{
            Id          = $Proc.Id
            Name        = $Proc.ProcessName
            Owner       = $Owner
            Path        = $Proc.Path
            StartTime   = $Proc.StartTime
            CommandLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($Proc.Id)").CommandLine
        }
    }
}

# Run the triage
Get-SuspiciousProcesses | Export-Csv -Path ".\Suspicious_Process_Triage.csv" -NoTypeInformation
Write-Host "Triage complete. Results saved to Suspicious_Process_Triage.csv" -ForegroundColor Cyan
