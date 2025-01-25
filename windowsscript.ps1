# PowerShell Script for Windows 10 Security Configuration

# Ensure the script runs with administrator privileges
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "You need to run this script as Administrator."
    exit
}

# Enable Windows Updates
Write-Output "Enabling Windows Updates..."
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

# Enable Windows Firewall
Write-Output "Enabling Windows Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Configure Strong Password Policies
Write-Output "Configuring password policies..."
secedit /export /cfg password_policy.inf
$pwdPolicy = @"
[System Access]
MinimumPasswordLength = 12
PasswordComplexity = 1
MaximumPasswordAge = 90
MinimumPasswordAge = 1
PasswordHistorySize = 24
"@
$pwdPolicy | Out-File -Encoding ASCII password_policy.inf
secedit /configure /db secedit.sdb /cfg password_policy.inf /overwrite
Remove-Item -Path .\password_policy.inf

# Remove Guest Account
Write-Output "Disabling Guest account..."
Disable-LocalUser -Name Guest

# Set Account Lockout Policies
Write-Output "Setting account lockout policies..."
secedit /export /cfg lockout_policy.inf
$lockoutPolicy = @"
[System Access]
LockoutBadCount = 5
LockoutDuration = 15
ResetLockoutCount = 15
"@
$lockoutPolicy | Out-File -Encoding ASCII lockout_policy.inf
secedit /configure /db secedit.sdb /cfg lockout_policy.inf /overwrite
Remove-Item -Path .\lockout_policy.inf

# Enable Windows Defender
Write-Output "Enabling Windows Defender..."
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent AlwaysPrompt

# Disable Remote Desktop
Write-Output "Disabling Remote Desktop..."
Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1

# Enable Windows Security Features
Write-Output "Configuring additional security features..."
Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart:$false # Disables legacy SMB protocol
Set-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\System' -Name 'DisableCMD' -Value 1

Write-Output "Security hardening completed!"
