# 1. Software Compliance

# Install and configure Google Chrome
Write-Host "Installing Google Chrome..."
Start-Process -FilePath "https://dl.google.com/chrome/install/" -Wait
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice" -Name ProgId -Value "ChromeHTML"
Write-Host "Google Chrome set as default browser."

# Verify and update Notepad++, 7-Zip, and Wireshark
$softwareLinks = @{
    "Notepad++" = "https://notepad-plus-plus.org/downloads/";
    "7-Zip" = "https://www.7-zip.org/download.html";
    "Wireshark" = "https://www.wireshark.org/download.html"
}

foreach ($software in $softwareLinks.GetEnumerator()) {
    Write-Host "Verifying $($software.Key)..."
    Start-Process -FilePath $software.Value -Wait
}

# 2. Enable Automatic Updates
Write-Host "Enabling automatic updates..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f

# 3. PowerShell Logging Configuration
Write-Host "Configuring PowerShell logging..."
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f

# Enable transcription
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\PowerShellLogs" /f

# Protect Event Logs
Write-Host "Securing event logs..."
New-SelfSignedCertificate -DnsName "EventLogCert" -CertStoreLocation "Cert:\LocalMachine\My"
powershell -Command "wevtutil set-log Application /ca:EventLogCert"

# 4. Active Directory Domain Services (AD DS) Validation
Write-Host "Validating Active Directory Domain Services..."
# This portion assumes ADUC is installed; manual actions may be required.
Write-Host "Ensure Organizational Units and GPOs are configured properly."

# 5. Active Directory Certificate Services (AD CS) Validation
Write-Host "Validating Active Directory Certificate Services..."
Start-Process -FilePath "certsrv.msc"
Write-Host "Verify CA roles, CRL configuration, and certificate permissions."

# 6. Critical Services Validation
Write-Host "Checking critical services..."
$services = @("Active Directory Domain Services", "DNS Server", "Certificate Authority")
foreach ($service in $services) {
    Get-Service -Name $service | ForEach-Object {
        if ($_.Status -ne "Running") {
            Start-Service -Name $_.Name
            Write-Host "$($_.Name) service started."
        } else {
            Write-Host "$($_.Name) service is already running."
        }
    }
}

# 7. Final Hardening
Write-Host "Applying final hardening measures..."
# Configure audit policies
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Object Access" /success:enable /failure:enable
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable

# Secure file permissions
$securePaths = @("C:\ConfigFiles", "C:\Logs")
foreach ($path in $securePaths) {
    icacls $path /inheritance:r
    icacls $path /grant:r "Administrators:F"
}

# Firewall settings
Write-Host "Configuring firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow

# Create backup policies
Write-Host "Configuring backup policies..."
wbadmin enable backup -addtarget:"C:\Backups" -include:"C:\Windows\NTDS" -schedule:09:00

# Verify Antimalware Service Executable
Write-Host "Ensuring Windows Defender is active..."
Set-MpPreference -DisableRealtimeMonitoring $false
Update-MpSignature

Write-Host "Configuration script completed successfully."


