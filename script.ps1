# Define Root Folder (replace with your Google Drive path)
$googleDrivePath = "C:\Users\YourUsername\Google Drive\CyberPatriot"

# Create Folder Structure
$folders = @(
    "Scenarios",
    "Checklists",
    "Reports",
    "Reference Material",
    "System Logs",
    "Tools"
)

Write-Host "Creating folder structure..."
foreach ($folder in $folders) {
    $folderPath = Join-Path -Path $googleDrivePath -ChildPath $folder
    if (-Not (Test-Path -Path $folderPath)) {
        New-Item -ItemType Directory -Path $folderPath | Out-Null
        Write-Host "Created: $folderPath"
    } else {
        Write-Host "Exists: $folderPath"
    }
}

# Preload Templates
Write-Host "Copying template files..."
$templateFiles = @{
    "System_Log_Template.txt" = "System Logs"
    "Task_Tracker.xlsx"       = "Checklists"
    "Report_Template.docx"    = "Reports"
}

foreach ($template in $templateFiles.GetEnumerator()) {
    $srcFile = Join-Path -Path "C:\PathToYourTemplates" -ChildPath $template.Key
    $destFolder = Join-Path -Path $googleDrivePath -ChildPath $template.Value
    $destFile = Join-Path -Path $destFolder -ChildPath $template.Key

    if (Test-Path -Path $srcFile -and -Not (Test-Path -Path $destFile)) {
        Copy-Item -Path $srcFile -Destination $destFile
        Write-Host "Copied: $template.Key to $template.Value"
    } else {
        Write-Host "Skipped: $template.Key"
    }
}

# Set Basic File Permissions (Optional)
Write-Host "Configuring file permissions..."
$restrictedFolders = @("Checklists", "Reports", "System Logs")
foreach ($folder in $restrictedFolders) {
    $folderPath = Join-Path -Path $googleDrivePath -ChildPath $folder
    $acl = Get-Acl -Path $folderPath
    $acl.SetAccessRuleProtection($true, $true)
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Authenticated Users", "Read", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($accessRule)
    Set-Acl -Path $folderPath -AclObject $acl
    Write-Host "Restricted access to: $folder"
}

# Final Summary
Write-Host "Google Drive setup complete!"
Start-Process explorer.exe $googleDrivePath
