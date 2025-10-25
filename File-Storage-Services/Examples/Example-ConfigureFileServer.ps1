#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    File Server Configuration Example Script

.DESCRIPTION
    This example script demonstrates how to configure a Windows File Server
    with common settings including SMB configuration, share creation, and
    basic security settings.

.EXAMPLE
    .\Example-ConfigureFileServer.ps1

.NOTES
    Author: File and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "FileStorage-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "FileStorage-Management.psm1") -Force
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

Write-Host "=== File Server Configuration Example ===" -ForegroundColor Cyan
Write-Host "This example demonstrates basic file server configuration" -ForegroundColor White

try {
    # Step 1: Check prerequisites
    Write-Host "`nStep 1: Checking prerequisites..." -ForegroundColor Yellow
    $prerequisites = Test-FileStoragePrerequisites
    if ($prerequisites) {
        Write-Host "Prerequisites check passed" -ForegroundColor Green
    } else {
        Write-Host "Prerequisites check failed" -ForegroundColor Red
        exit 1
    }
    
    # Step 2: Install file server role
    Write-Host "`nStep 2: Installing file server role..." -ForegroundColor Yellow
    $installResult = Install-FileStoragePrerequisites
    if ($installResult) {
        Write-Host "File server role installed successfully" -ForegroundColor Green
    } else {
        Write-Host "File server role installation failed" -ForegroundColor Red
        exit 1
    }
    
    # Step 3: Configure file server
    Write-Host "`nStep 3: Configuring file server..." -ForegroundColor Yellow
    Set-FileServerConfiguration -EnableSMB3 -RequireSigning -EnableEncryption
    Write-Host "File server configuration completed" -ForegroundColor Green
    
    # Step 4: Create example shares
    Write-Host "`nStep 4: Creating example shares..." -ForegroundColor Yellow
    
    # Create Data share
    $dataPath = "C:\Shares\Data"
    New-FileShare -ShareName "Data" -Path $dataPath -Description "Data Share" -FullAccess @("Administrators") -ReadAccess @("Users") -EnableAccessBasedEnumeration
    
    # Create Public share
    $publicPath = "C:\Shares\Public"
    New-FileShare -ShareName "Public" -Path $publicPath -Description "Public Share" -ChangeAccess @("Users") -FullAccess @("Administrators")
    
    # Create Temp share
    $tempPath = "C:\Shares\Temp"
    New-FileShare -ShareName "Temp" -Path $tempPath -Description "Temporary Share" -FullAccess @("Administrators") -ChangeAccess @("Users")
    
    Write-Host "Example shares created successfully" -ForegroundColor Green
    
    # Step 5: Enable FSRM
    Write-Host "`nStep 5: Enabling File Server Resource Manager..." -ForegroundColor Yellow
    Enable-FSRM -EnableQuotas -EnableFileScreening -EnableReporting
    Write-Host "FSRM enabled successfully" -ForegroundColor Green
    
    # Step 6: Get file server status
    Write-Host "`nStep 6: Getting file server status..." -ForegroundColor Yellow
    $status = Get-FileServerStatus
    Write-Host "File server status retrieved successfully" -ForegroundColor Green
    
    # Display summary
    Write-Host "`n=== Configuration Summary ===" -ForegroundColor Cyan
    Write-Host "Computer Name: $($env:COMPUTERNAME)" -ForegroundColor White
    Write-Host "File Server Installed: $($status.FileServerInstalled)" -ForegroundColor White
    Write-Host "SMB 3.0 Enabled: $($status.SMB3Enabled)" -ForegroundColor White
    Write-Host "SMB Signing Required: $($status.SMBSigningRequired)" -ForegroundColor White
    Write-Host "SMB Encryption Enabled: $($status.SMBEncryptionEnabled)" -ForegroundColor White
    Write-Host "Shares Created: Data, Public, Temp" -ForegroundColor White
    Write-Host "FSRM Enabled: $($status.FSRMEnabled)" -ForegroundColor White
    
    Write-Host "`nFile server configuration example completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Host "`nFile server configuration example failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
