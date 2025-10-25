#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD RMS Configuration Management Script

.DESCRIPTION
    This script provides comprehensive AD RMS configuration management including
    cluster configuration, service account management, and policy settings.

.PARAMETER Action
    The action to perform (Configure, Update, Backup, Restore, Validate)

.PARAMETER DomainName
    The domain name for the AD RMS cluster

.PARAMETER ServiceAccount
    The service account for AD RMS

.PARAMETER ServiceAccountPassword
    The password for the service account

.PARAMETER DatabaseServer
    The database server

.PARAMETER DatabaseName
    The database name

.PARAMETER ClusterUrl
    The cluster URL

.PARAMETER LicensingUrl
    The licensing URL

.PARAMETER BackupPath
    Path to save configuration backup

.PARAMETER RestorePath
    Path to restore configuration from

.PARAMETER PolicyTemplate
    Path to policy template file

.EXAMPLE
    .\Manage-ADRMSConfiguration.ps1 -Action Configure -DomainName "contoso.com" -ServiceAccountPassword $securePassword

.EXAMPLE
    .\Manage-ADRMSConfiguration.ps1 -Action Backup -BackupPath "C:\Backups\ADRMS-Config.xml"

.EXAMPLE
    .\Manage-ADRMSConfiguration.ps1 -Action Restore -RestorePath "C:\Backups\ADRMS-Config.xml"

.NOTES
    Author: AD RMS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Configure", "Update", "Backup", "Restore", "Validate", "Reset")]
    [string]$Action,
    
    [string]$DomainName,
    
    [string]$ServiceAccount,
    
    [SecureString]$ServiceAccountPassword,
    
    [string]$DatabaseServer,
    
    [string]$DatabaseName,
    
    [string]$ClusterUrl,
    
    [string]$LicensingUrl,
    
    [string]$BackupPath,
    
    [string]$RestorePath,
    
    [string]$PolicyTemplate
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
$script:ConfigurationLog = @()
$script:StartTime = Get-Date

function Write-ConfigurationLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:ConfigurationLog += $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function New-ConfigurationBackup {
    param([string]$BackupPath)
    
    Write-ConfigurationLog "Creating AD RMS configuration backup..." "INFO"
    
    try {
        $backup = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            Configuration = @{}
            Registry = @{}
        }
        
        # Backup registry configuration
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\MSDRMS\Cluster",
            "HKLM:\SOFTWARE\Microsoft\MSDRMS\Database",
            "HKLM:\SOFTWARE\Microsoft\MSDRMS\ServiceAccount"
        )
        
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                $regData = Get-ItemProperty -Path $regPath
                $backup.Registry[$regPath] = $regData
            }
        }
        
        # Backup current configuration
        $currentConfig = Get-ADRMSConfigurationStatus
        $backup.Configuration = $currentConfig
        
        # Save backup
        $backup | Export-Clixml -Path $BackupPath -Force
        
        Write-ConfigurationLog "Configuration backup saved to: $BackupPath" "SUCCESS"
        return $true
        
    } catch {
        Write-ConfigurationLog "Failed to create configuration backup: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Restore-ConfigurationBackup {
    param([string]$RestorePath)
    
    Write-ConfigurationLog "Restoring AD RMS configuration from backup..." "INFO"
    
    try {
        if (-not (Test-Path $RestorePath)) {
            throw "Backup file not found: $RestorePath"
        }
        
        # Load backup
        $backup = Import-Clixml -Path $RestorePath
        
        Write-ConfigurationLog "Restoring configuration from: $($backup.Timestamp)" "INFO"
        
        # Restore registry configuration
        foreach ($regPath in $backup.Registry.Keys) {
            $regData = $backup.Registry[$regPath]
            
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            
            foreach ($property in $regData.PSObject.Properties) {
                if ($property.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                    Set-ItemProperty -Path $regPath -Name $property.Name -Value $property.Value
                }
            }
        }
        
        Write-ConfigurationLog "Configuration restored successfully from backup." "SUCCESS"
        return $true
        
    } catch {
        Write-ConfigurationLog "Failed to restore configuration backup: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-ADRMSClusterConfiguration {
    param(
        [string]$DomainName,
        [string]$ServiceAccount,
        [SecureString]$ServiceAccountPassword,
        [string]$DatabaseServer,
        [string]$DatabaseName,
        [string]$ClusterUrl,
        [string]$LicensingUrl
    )
    
    Write-ConfigurationLog "Configuring AD RMS cluster..." "INFO"
    
    try {
        # Generate URLs if not provided
        if (-not $ClusterUrl -and $DomainName) {
            $computerName = $env:COMPUTERNAME
            $ClusterUrl = "https://$computerName.$DomainName/_wmcs"
        }
        
        if (-not $LicensingUrl -and $ClusterUrl) {
            $LicensingUrl = "$ClusterUrl/licensing"
        }
        
        # Set default values
        if (-not $ServiceAccount) { $ServiceAccount = "RMS_Service" }
        if (-not $DatabaseServer) { $DatabaseServer = "localhost" }
        if (-not $DatabaseName) { $DatabaseName = "DRMS" }
        
        # Configure cluster
        if ($ClusterUrl -and $LicensingUrl -and $DatabaseServer -and $DatabaseName -and $ServiceAccount -and $ServiceAccountPassword) {
            New-ADRMSCluster -ClusterUrl $ClusterUrl -LicensingUrl $LicensingUrl -DatabaseServer $DatabaseServer -DatabaseName $DatabaseName -ServiceAccount $ServiceAccount -ServiceAccountPassword $ServiceAccountPassword
        } else {
            # Configure individual components
            if ($ServiceAccount -and $ServiceAccountPassword) {
                Set-ADRMSServiceAccount -ServiceAccount $ServiceAccount -ServiceAccountPassword $ServiceAccountPassword
            }
            
            if ($DatabaseServer -and $DatabaseName) {
                Set-ADRMSDatabase -DatabaseServer $DatabaseServer -DatabaseName $DatabaseName
            }
        }
        
        Write-ConfigurationLog "AD RMS cluster configuration completed." "SUCCESS"
        return $true
        
    } catch {
        Write-ConfigurationLog "Failed to configure AD RMS cluster: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-ConfigurationValidation {
    Write-ConfigurationLog "Validating AD RMS configuration..." "INFO"
    
    try {
        $configStatus = Get-ADRMSConfigurationStatus
        $healthCheck = Test-ADRMSHealth
        
        $validationResults = @{
            ConfigurationValid = $configStatus.ConfigurationStatus.Overall -eq 'Fully Configured'
            ServicesHealthy = $healthCheck.Overall -eq 'Healthy'
            ConnectivityOK = $healthCheck.Connectivity.Overall -eq 'All Accessible'
            Overall = 'Unknown'
        }
        
        if ($validationResults.ConfigurationValid -and $validationResults.ServicesHealthy -and $validationResults.ConnectivityOK) {
            $validationResults.Overall = 'Valid'
            Write-ConfigurationLog "Configuration validation passed." "SUCCESS"
        } else {
            $validationResults.Overall = 'Invalid'
            Write-ConfigurationLog "Configuration validation failed." "WARNING"
        }
        
        return [PSCustomObject]$validationResults
        
    } catch {
        Write-ConfigurationLog "Error validating configuration: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Save-ConfigurationLog {
    $logPath = Join-Path $scriptPath "Configuration-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    try {
        $script:ConfigurationLog | Out-File -FilePath $logPath -Encoding UTF8
        Write-ConfigurationLog "Configuration log saved to: $logPath" "INFO"
    } catch {
        Write-Warning "Failed to save configuration log: $($_.Exception.Message)"
    }
}

# Main configuration management process
try {
    Write-ConfigurationLog "Starting AD RMS configuration management..." "INFO"
    Write-ConfigurationLog "Action: $Action" "INFO"
    
    switch ($Action) {
        "Configure" {
            if (-not $DomainName) {
                throw "DomainName parameter is required for Configure action"
            }
            
            if (-not $ServiceAccountPassword) {
                throw "ServiceAccountPassword parameter is required for Configure action"
            }
            
            if (-not (Set-ADRMSClusterConfiguration -DomainName $DomainName -ServiceAccount $ServiceAccount -ServiceAccountPassword $ServiceAccountPassword -DatabaseServer $DatabaseServer -DatabaseName $DatabaseName -ClusterUrl $ClusterUrl -LicensingUrl $LicensingUrl)) {
                throw "Configuration failed"
            }
        }
        
        "Update" {
            if (-not (Set-ADRMSClusterConfiguration -DomainName $DomainName -ServiceAccount $ServiceAccount -ServiceAccountPassword $ServiceAccountPassword -DatabaseServer $DatabaseServer -DatabaseName $DatabaseName -ClusterUrl $ClusterUrl -LicensingUrl $LicensingUrl)) {
                throw "Configuration update failed"
            }
        }
        
        "Backup" {
            if (-not $BackupPath) {
                $BackupPath = Join-Path $scriptPath "ADRMS-Config-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
            }
            
            if (-not (New-ConfigurationBackup -BackupPath $BackupPath)) {
                throw "Configuration backup failed"
            }
        }
        
        "Restore" {
            if (-not $RestorePath) {
                throw "RestorePath parameter is required for Restore action"
            }
            
            if (-not (Restore-ConfigurationBackup -RestorePath $RestorePath)) {
                throw "Configuration restore failed"
            }
        }
        
        "Validate" {
            $validationResults = Test-ConfigurationValidation
            if (-not $validationResults) {
                throw "Configuration validation failed"
            }
            
            Write-Host "`n=== Configuration Validation Results ===" -ForegroundColor Cyan
            Write-Host "Configuration Valid: $($validationResults.ConfigurationValid)" -ForegroundColor White
            Write-Host "Services Healthy: $($validationResults.ServicesHealthy)" -ForegroundColor White
            Write-Host "Connectivity OK: $($validationResults.ConnectivityOK)" -ForegroundColor White
            Write-Host "Overall Status: $($validationResults.Overall)" -ForegroundColor White
        }
        
        "Reset" {
            Write-ConfigurationLog "Resetting AD RMS configuration..." "WARNING"
            Reset-ADRMSConfiguration -Confirm:$false
            Write-ConfigurationLog "AD RMS configuration reset completed." "SUCCESS"
        }
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-ConfigurationLog "AD RMS configuration management completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== AD RMS Configuration Management Summary ===" -ForegroundColor Cyan
    Write-Host "Action: $Action" -ForegroundColor White
    Write-Host "Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    
    # Save configuration log
    Save-ConfigurationLog
    
    Write-Host "`nConfiguration management completed successfully!" -ForegroundColor Green
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-ConfigurationLog "AD RMS configuration management failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save configuration log
    Save-ConfigurationLog
    
    Write-Host "`nConfiguration management failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the configuration log for details." -ForegroundColor Yellow
    
    exit 1
}
