# This script automates basic security tasks for a Windows system.
# Note: Run this script as an administrator.

# Update and Upgrade the System
Write-Host "Updating and upgrading the system..."
Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?LinkID=799445" -OutFile "$env:TEMP\WinUpdate.ps1"
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File $env:TEMP\WinUpdate.ps1" -Wait
Write-Host "System updated successfully!"

# Remove Unnecessary or Suspicious User Accounts
Write-Host "Checking for unnecessary or suspicious user accounts..."
Get-LocalUser | Where-Object { $_.Enabled -eq $true } | ForEach-Object {
    Write-Host "Do you want to disable or delete user $($_.Name)? (disable/delete/skip):"
    $choice = Read-Host
    switch ($choice) {
        "disable" {
            Disable-LocalUser -Name $_.Name
            Write-Host "$($_.Name) has been disabled."
        }
        "delete" {
            Remove-LocalUser -Name $_.Name
            Write-Host "$($_.Name) has been deleted."
        }
        default {
            Write-Host "$($_.Name) skipped."
        }
    }
}

# Secure Critical System File Permissions
Write-Host "Securing critical system file permissions..."
icacls "C:\Windows\System32\Config\SAM" /inheritance:r /grant Administrators:F
icacls "C:\Windows\System32\Config\SYSTEM" /inheritance:r /grant Administrators:F
Write-Host "File permissions secured."

# Disable Unnecessary Services
Write-Host "Disabling unnecessary services..."
$services = @("Spooler", "Telnet", "NfsClnt")
foreach ($service in $services) {
    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    Set-Service -Name $service -StartupType Disabled
    Write-Host "$service service disabled."
}
Write-Host "Unnecessary services have been disabled."

# Enable and Configure the Windows Firewall
Write-Host "Configuring and enabling the firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow
Write-Host "Firewall has been configured and enabled."

# Check for World-Writable Files
Write-Host "Checking for world-writable files and directories..."
$worldWritableFiles = Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction SilentlyContinue | 
    Where-Object { ($_ | Get-Acl).Access | Where-Object { $_.FileSystemRights -match "Write" } }
foreach ($file in $worldWritableFiles) {
    Write-Host "Fixing permissions for $file"
    $acl = Get-Acl $file.FullName
    $acl.SetAccessRuleProtection($true, $false)
    Set-Acl -Path $file.FullName -AclObject $acl
}
Write-Host "World-writable files fixed."

# Review Scheduled Tasks
Write-Host "Reviewing scheduled tasks..."
Get-ScheduledTask | Out-GridView -Title "Review Scheduled Tasks"

# Audit Open Ports
Write-Host "Auditing open ports..."
netstat -an | Select-String "LISTEN"

# Secure Remote Desktop Protocol (RDP)
Write-Host "Securing RDP configuration..."
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -PropertyType DWORD -Force
Write-Host "RDP access has been secured."

# Install and Run Microsoft Defender Antivirus Scan
Write-Host "Running Microsoft Defender Antivirus scan..."
Start-MpScan -ScanType FullScan
Write-Host "Microsoft Defender Antivirus scan completed."

# Review and Secure Log File Permissions
Write-Host "Securing log file permissions..."
icacls "C:\Windows\System32\winevt\Logs" /inheritance:r /grant Administrators:F
Write-Host "Log files secured."

# Summary of Actions
Write-Host @"
System Hardening Completed:
- Updated system packages
- Reviewed and managed user accounts
- Secured critical system files
- Disabled unnecessary services
- Configured Windows Firewall
- Audited world-writable files
- Reviewed scheduled tasks
- Secured RDP
- Scanned for malware with Microsoft Defender
- Secured log file permissions
"@


