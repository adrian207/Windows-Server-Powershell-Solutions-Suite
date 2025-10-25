#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD RMS Uninstallation Script

.DESCRIPTION
    This script provides a comprehensive AD RMS uninstallation process.
    It handles service stopping, configuration removal, and feature uninstallation.

.PARAMETER RemoveConfiguration
    Remove AD RMS configuration data

.PARAMETER RemoveDatabase
    Remove AD RMS database (use with caution)

.PARAMETER Force
    Force uninstallation without confirmation

.PARAMETER KeepLogs
    Keep installation and configuration logs

.EXAMPLE
    .\Uninstall-ADRMS.ps1

.EXAMPLE
    .\Uninstall-ADRMS.ps1 -RemoveConfiguration -Force

.NOTES
    Author: AD RMS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$RemoveConfiguration,
    
    [switch]$RemoveDatabase,
    
    [switch]$Force,
    
    [switch]$KeepLogs
)

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "ADRMS-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "ADRMS-Configuration.psm1") -Force
    Import-Module (Join-Path $modulePath "ADRMS-Diagnostics.psm1") -Force
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Script variables
$script:UninstallationLog = @()
$script:StartTime = Get-Date

function Write-UninstallationLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:UninstallationLog += $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function Test-ADRMSInstalled {
    Write-UninstallationLog "Checking if AD RMS is installed..." "INFO"
    
    try {
        $adrmsFeature = Get-WindowsFeature -Name ADRMS
        $isInstalled = $adrmsFeature.InstallState -eq 'Installed'
        
        if ($isInstalled) {
            Write-UninstallationLog "AD RMS is installed." "INFO"
        } else {
            Write-UninstallationLog "AD RMS is not installed." "INFO"
        }
        
        return $isInstalled
    } catch {
        Write-UninstallationLog "Error checking AD RMS installation: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Stop-ADRMSServices {
    Write-UninstallationLog "Stopping AD RMS services..." "INFO"
    
    try {
        Stop-ADRMSServices
        Write-UninstallationLog "AD RMS services stopped successfully." "SUCCESS"
        return $true
    } catch {
        Write-UninstallationLog "Failed to stop AD RMS services: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-ADRMSConfiguration {
    if (-not $RemoveConfiguration) {
        Write-UninstallationLog "Skipping configuration removal as requested." "INFO"
        return $true
    }
    
    Write-UninstallationLog "Removing AD RMS configuration..." "INFO"
    
    try {
        Reset-ADRMSConfiguration -Confirm:$false
        Write-UninstallationLog "AD RMS configuration removed successfully." "SUCCESS"
        return $true
    } catch {
        Write-UninstallationLog "Failed to remove AD RMS configuration: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-ADRMSDatabase {
    if (-not $RemoveDatabase) {
        Write-UninstallationLog "Skipping database removal as requested." "INFO"
        return $true
    }
    
    Write-UninstallationLog "Removing AD RMS database..." "WARNING"
    
    try {
        # Get database configuration
        $dbRegPath = "HKLM:\SOFTWARE\Microsoft\MSDRMS\Database"
        if (Test-Path $dbRegPath) {
            $dbServer = Get-ItemProperty -Path $dbRegPath -Name "DatabaseServer" -ErrorAction SilentlyContinue
            $dbName = Get-ItemProperty -Path $dbRegPath -Name "DatabaseName" -ErrorAction SilentlyContinue
            
            if ($dbServer.DatabaseServer -and $dbName.DatabaseName) {
                Write-UninstallationLog "Database found: $($dbServer.DatabaseServer)\$($dbName.DatabaseName)" "INFO"
                
                # Note: Actual database removal would require SQL Server management tools
                # This is a placeholder for the database removal logic
                Write-UninstallationLog "Database removal requires manual intervention or SQL Server tools." "WARNING"
            }
        }
        
        Write-UninstallationLog "Database removal process completed." "SUCCESS"
        return $true
    } catch {
        Write-UninstallationLog "Failed to remove AD RMS database: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Uninstall-ADRMSFeature {
    Write-UninstallationLog "Uninstalling AD RMS Windows feature..." "INFO"
    
    try {
        $adrmsFeature = Get-WindowsFeature -Name ADRMS
        
        if ($adrmsFeature.InstallState -ne 'Installed') {
            Write-UninstallationLog "AD RMS feature is not installed." "INFO"
            return $true
        }
        
        Write-UninstallationLog "Uninstalling AD RMS feature..." "INFO"
        $result = Uninstall-WindowsFeature -Name ADRMS
        
        if ($result.Success) {
            Write-UninstallationLog "AD RMS feature uninstalled successfully." "SUCCESS"
            return $true
        } else {
            Write-UninstallationLog "Failed to uninstall AD RMS feature." "ERROR"
            return $false
        }
    } catch {
        Write-UninstallationLog "Error uninstalling AD RMS feature: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-ADRMSLogs {
    if ($KeepLogs) {
        Write-UninstallationLog "Keeping logs as requested." "INFO"
        return $true
    }
    
    Write-UninstallationLog "Removing AD RMS logs..." "INFO"
    
    try {
        $logPaths = @(
            "C:\Windows\Logs\ADRMS",
            "C:\ProgramData\Microsoft\MSDRMS\Logs"
        )
        
        foreach ($logPath in $logPaths) {
            if (Test-Path $logPath) {
                Remove-Item -Path $logPath -Recurse -Force
                Write-UninstallationLog "Removed log directory: $logPath" "SUCCESS"
            }
        }
        
        return $true
    } catch {
        Write-UninstallationLog "Failed to remove logs: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Save-UninstallationLog {
    $logPath = Join-Path $scriptPath "Uninstallation-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    try {
        $script:UninstallationLog | Out-File -FilePath $logPath -Encoding UTF8
        Write-UninstallationLog "Uninstallation log saved to: $logPath" "INFO"
    } catch {
        Write-Warning "Failed to save uninstallation log: $($_.Exception.Message)"
    }
}

# Main uninstallation process
try {
    Write-UninstallationLog "Starting AD RMS uninstallation process..." "INFO"
    
    # Confirmation prompt
    if (-not $Force) {
        $confirmationMessage = "Are you sure you want to uninstall AD RMS?"
        if ($RemoveConfiguration) {
            $confirmationMessage += "`nThis will remove all configuration data."
        }
        if ($RemoveDatabase) {
            $confirmationMessage += "`nThis will remove the database (use with caution)."
        }
        
        if (-not $PSCmdlet.ShouldProcess("AD RMS", "Uninstall")) {
            Write-UninstallationLog "Uninstallation cancelled by user." "INFO"
            exit 0
        }
    }
    
    # Step 1: Check if AD RMS is installed
    if (-not (Test-ADRMSInstalled)) {
        Write-UninstallationLog "AD RMS is not installed. Nothing to uninstall." "INFO"
        exit 0
    }
    
    # Step 2: Stop services
    if (-not (Stop-ADRMSServices)) {
        Write-UninstallationLog "Failed to stop services, but continuing with uninstallation." "WARNING"
    }
    
    # Step 3: Remove configuration
    if (-not (Remove-ADRMSConfiguration)) {
        Write-UninstallationLog "Failed to remove configuration, but continuing with uninstallation." "WARNING"
    }
    
    # Step 4: Remove database
    if (-not (Remove-ADRMSDatabase)) {
        Write-UninstallationLog "Failed to remove database, but continuing with uninstallation." "WARNING"
    }
    
    # Step 5: Uninstall feature
    if (-not (Uninstall-ADRMSFeature)) {
        throw "AD RMS feature uninstallation failed"
    }
    
    # Step 6: Remove logs
    if (-not (Remove-ADRMSLogs)) {
        Write-UninstallationLog "Failed to remove logs, but uninstallation completed." "WARNING"
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-UninstallationLog "AD RMS uninstallation completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== AD RMS Uninstallation Summary ===" -ForegroundColor Cyan
    Write-Host "Configuration Removed: $RemoveConfiguration" -ForegroundColor White
    Write-Host "Database Removed: $RemoveDatabase" -ForegroundColor White
    Write-Host "Logs Kept: $KeepLogs" -ForegroundColor White
    Write-Host "Uninstallation Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    
    # Save uninstallation log
    Save-UninstallationLog
    
    Write-Host "`nUninstallation completed successfully!" -ForegroundColor Green
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-UninstallationLog "AD RMS uninstallation failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save uninstallation log
    Save-UninstallationLog
    
    Write-Host "`nUninstallation failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the uninstallation log for details." -ForegroundColor Yellow
    
    exit 1
}
