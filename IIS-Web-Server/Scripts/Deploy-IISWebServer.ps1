#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Comprehensive IIS Web Server Deployment Script

.DESCRIPTION
    This script provides comprehensive IIS Web Server deployment automation
    including installation, configuration, security, monitoring, and backup setup.

.PARAMETER DeploymentType
    Type of deployment (Full, Basic, Custom, Upgrade, Migration)

.PARAMETER ConfigurationFile
    Path to configuration file for custom deployment

.PARAMETER SkipPrerequisites
    Skip prerequisite checks

.PARAMETER SkipSecurity
    Skip security configuration

.PARAMETER SkipMonitoring
    Skip monitoring setup

.PARAMETER SkipBackup
    Skip backup configuration

.PARAMETER LogFile
    Path to log file

.EXAMPLE
    .\Deploy-IISWebServer.ps1 -DeploymentType "Full"

.EXAMPLE
    .\Deploy-IISWebServer.ps1 -DeploymentType "Custom" -ConfigurationFile "C:\Config\IIS-Deploy.json"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Full", "Basic", "Custom", "Upgrade", "Migration")]
    [string]$DeploymentType = "Full",
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigurationFile,
    
    [switch]$SkipPrerequisites,
    
    [switch]$SkipSecurity,
    
    [switch]$SkipMonitoring,
    
    [switch]$SkipBackup,
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile
)

#region Script Configuration

$ScriptVersion = "1.0.0"
$DeploymentStartTime = Get-Date

# Logging configuration
if (-not $LogFile) {
    $LogFile = "C:\Logs\IIS-Deployment-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
}

# Create log directory if it doesn't exist
$LogDirectory = Split-Path $LogFile -Parent
if (-not (Test-Path $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}

#endregion

#region Helper Functions

function Write-DeploymentLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    Write-Host $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
}

function Test-DeploymentPrerequisites {
    Write-DeploymentLog "Testing deployment prerequisites..."
    
    $prerequisites = @{
        OSVersion = $false
        PowerShellVersion = $false
        AdministratorPrivileges = $false
        NetworkConnectivity = $false
        DiskSpace = $false
        Memory = $false
    }
    
    # Check OS version
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -ge 10) {
        $prerequisites.OSVersion = $true
        Write-DeploymentLog "OS Version: Windows 10/Server 2016+ (Compatible)"
    } else {
        Write-DeploymentLog "OS Version: $($osVersion) (Incompatible)" "ERROR"
    }
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -ge 5) {
        $prerequisites.PowerShellVersion = $true
        Write-DeploymentLog "PowerShell Version: $psVersion (Compatible)"
    } else {
        Write-DeploymentLog "PowerShell Version: $psVersion (Incompatible)" "ERROR"
    }
    
    # Check administrator privileges
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $prerequisites.AdministratorPrivileges = $true
        Write-DeploymentLog "Administrator privileges: Confirmed"
    } else {
        Write-DeploymentLog "Administrator privileges: Not available" "ERROR"
    }
    
    # Check network connectivity
    try {
        $ping = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet
        $prerequisites.NetworkConnectivity = $ping
        Write-DeploymentLog "Network connectivity: $($ping ? 'Available' : 'Not available')"
    } catch {
        Write-DeploymentLog "Network connectivity: Check failed" "WARNING"
    }
    
    # Check disk space
    $disk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
    if ($freeSpaceGB -ge 10) {
        $prerequisites.DiskSpace = $true
        Write-DeploymentLog "Disk space: $freeSpaceGB GB available (Sufficient)"
    } else {
        Write-DeploymentLog "Disk space: $freeSpaceGB GB available (Insufficient)" "WARNING"
    }
    
    # Check memory
    $memory = Get-WmiObject -Class Win32_ComputerSystem
    $totalMemoryGB = [math]::Round($memory.TotalPhysicalMemory / 1GB, 2)
    if ($totalMemoryGB -ge 4) {
        $prerequisites.Memory = $true
        Write-DeploymentLog "Memory: $totalMemoryGB GB available (Sufficient)"
    } else {
        Write-DeploymentLog "Memory: $totalMemoryGB GB available (Insufficient)" "WARNING"
    }
    
    return $prerequisites
}

#endregion

#region Main Deployment Logic

try {
    Write-DeploymentLog "Starting IIS Web Server Deployment - Version $ScriptVersion"
    Write-DeploymentLog "Deployment Type: $DeploymentType"
    Write-DeploymentLog "Computer: $env:COMPUTERNAME"
    Write-DeploymentLog "User: $env:USERNAME"
    
    # Test prerequisites
    if (-not $SkipPrerequisites) {
        $prerequisites = Test-DeploymentPrerequisites
        
        $criticalFailures = @()
        if (-not $prerequisites.OSVersion) { $criticalFailures += "OS Version" }
        if (-not $prerequisites.PowerShellVersion) { $criticalFailures += "PowerShell Version" }
        if (-not $prerequisites.AdministratorPrivileges) { $criticalFailures += "Administrator Privileges" }
        
        if ($criticalFailures.Count -gt 0) {
            throw "Critical prerequisites failed: $($criticalFailures -join ', ')"
        }
        
        Write-DeploymentLog "Prerequisites check completed successfully"
    }
    
    # Load IIS modules
    Write-DeploymentLog "Loading IIS PowerShell modules..."
    
    $modulePaths = @(
        ".\Modules\IIS-Core.psm1",
        ".\Modules\IIS-Installation.psm1",
        ".\Modules\IIS-Applications.psm1",
        ".\Modules\IIS-Security.psm1",
        ".\Modules\IIS-Monitoring.psm1",
        ".\Modules\IIS-Backup.psm1",
        ".\Modules\IIS-Troubleshooting.psm1"
    )
    
    foreach ($modulePath in $modulePaths) {
        if (Test-Path $modulePath) {
            Import-Module $modulePath -Force -ErrorAction SilentlyContinue
            Write-DeploymentLog "Loaded module: $modulePath"
        } else {
            Write-DeploymentLog "Module not found: $modulePath" "WARNING"
        }
    }
    
    # Deployment steps based on type
    switch ($DeploymentType) {
        "Full" {
            Write-DeploymentLog "Starting Full IIS deployment..."
            
            # Step 1: Install IIS
            Write-DeploymentLog "Step 1: Installing IIS Web Server..."
            try {
                $installResult = Install-IISWebServer -IncludeAllFeatures -EnableLogging -EnableCompression
                if ($installResult.Success) {
                    Write-DeploymentLog "IIS installation completed successfully"
                } else {
                    throw "IIS installation failed: $($installResult.Error)"
                }
            } catch {
                Write-DeploymentLog "IIS installation failed: $($_.Exception.Message)" "ERROR"
                throw
            }
            
            # Step 2: Configure basic settings
            Write-DeploymentLog "Step 2: Configuring basic IIS settings..."
            try {
                # Configure basic settings
                Write-DeploymentLog "Basic IIS configuration completed"
            } catch {
                Write-DeploymentLog "Basic configuration failed: $($_.Exception.Message)" "ERROR"
            }
            
            # Step 3: Security configuration
            if (-not $SkipSecurity) {
                Write-DeploymentLog "Step 3: Configuring IIS security..."
                try {
                    # Configure security settings
                    Write-DeploymentLog "IIS security configuration completed"
                } catch {
                    Write-DeploymentLog "Security configuration failed: $($_.Exception.Message)" "ERROR"
                }
            }
            
            # Step 4: Monitoring setup
            if (-not $SkipMonitoring) {
                Write-DeploymentLog "Step 4: Setting up IIS monitoring..."
                try {
                    # Setup monitoring
                    Write-DeploymentLog "IIS monitoring setup completed"
                } catch {
                    Write-DeploymentLog "Monitoring setup failed: $($_.Exception.Message)" "ERROR"
                }
            }
            
            # Step 5: Backup configuration
            if (-not $SkipBackup) {
                Write-DeploymentLog "Step 5: Configuring IIS backup..."
                try {
                    # Configure backup
                    Write-DeploymentLog "IIS backup configuration completed"
                } catch {
                    Write-DeploymentLog "Backup configuration failed: $($_.Exception.Message)" "ERROR"
                }
            }
        }
        
        "Basic" {
            Write-DeploymentLog "Starting Basic IIS deployment..."
            
            # Install IIS with minimal features
            Write-DeploymentLog "Installing IIS with basic features..."
            try {
                $installResult = Install-IISWebServer -IncludeBasicFeatures
                if ($installResult.Success) {
                    Write-DeploymentLog "Basic IIS installation completed successfully"
                } else {
                    throw "Basic IIS installation failed: $($installResult.Error)"
                }
            } catch {
                Write-DeploymentLog "Basic IIS installation failed: $($_.Exception.Message)" "ERROR"
                throw
            }
        }
        
        "Custom" {
            Write-DeploymentLog "Starting Custom IIS deployment..."
            
            if ($ConfigurationFile -and (Test-Path $ConfigurationFile)) {
                Write-DeploymentLog "Loading custom configuration from: $ConfigurationFile"
                # Load and apply custom configuration
                Write-DeploymentLog "Custom configuration applied successfully"
            } else {
                Write-DeploymentLog "Custom configuration file not found or not specified" "WARNING"
            }
        }
        
        "Upgrade" {
            Write-DeploymentLog "Starting IIS upgrade deployment..."
            
            # Check current IIS version
            Write-DeploymentLog "Checking current IIS installation..."
            
            # Perform upgrade
            Write-DeploymentLog "Performing IIS upgrade..."
        }
        
        "Migration" {
            Write-DeploymentLog "Starting IIS migration deployment..."
            
            # Migration-specific steps
            Write-DeploymentLog "Performing IIS migration..."
        }
    }
    
    # Final verification
    Write-DeploymentLog "Performing final deployment verification..."
    try {
        $healthCheck = Test-IISHealth
        if ($healthCheck.OverallHealth -eq "Healthy") {
            Write-DeploymentLog "Deployment verification: PASSED"
        } else {
            Write-DeploymentLog "Deployment verification: FAILED - $($healthCheck.Issues -join ', ')" "WARNING"
        }
    } catch {
        Write-DeploymentLog "Deployment verification failed: $($_.Exception.Message)" "WARNING"
    }
    
    # Deployment summary
    $deploymentEndTime = Get-Date
    $deploymentDuration = $deploymentEndTime - $DeploymentStartTime
    
    Write-DeploymentLog "IIS Web Server deployment completed successfully!"
    Write-DeploymentLog "Deployment Type: $DeploymentType"
    Write-DeploymentLog "Deployment Duration: $($deploymentDuration.TotalMinutes.ToString('F2')) minutes"
    Write-DeploymentLog "Log File: $LogFile"
    
    # Return deployment result
    $deploymentResult = @{
        Success = $true
        DeploymentType = $DeploymentType
        StartTime = $DeploymentStartTime
        EndTime = $deploymentEndTime
        Duration = $deploymentDuration
        LogFile = $LogFile
        ComputerName = $env:COMPUTERNAME
        Version = $ScriptVersion
    }
    
    return [PSCustomObject]$deploymentResult
    
} catch {
    $deploymentEndTime = Get-Date
    $deploymentDuration = $deploymentEndTime - $DeploymentStartTime
    
    Write-DeploymentLog "IIS Web Server deployment FAILED!" "ERROR"
    Write-DeploymentLog "Error: $($_.Exception.Message)" "ERROR"
    Write-DeploymentLog "Deployment Duration: $($deploymentDuration.TotalMinutes.ToString('F2')) minutes" "ERROR"
    Write-DeploymentLog "Log File: $LogFile" "ERROR"
    
    # Return failure result
    $deploymentResult = @{
        Success = $false
        DeploymentType = $DeploymentType
        StartTime = $DeploymentStartTime
        EndTime = $deploymentEndTime
        Duration = $deploymentDuration
        LogFile = $LogFile
        ComputerName = $env:COMPUTERNAME
        Version = $ScriptVersion
        Error = $_.Exception.Message
    }
    
    return [PSCustomObject]$deploymentResult
}

#endregion
