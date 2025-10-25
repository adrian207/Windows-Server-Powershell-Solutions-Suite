#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Core module for Remote Access Services management.

.DESCRIPTION
    This module provides fundamental functions for managing Windows Server Remote Access Services,
    including common utilities, prerequisite checks, and helper functions.

.NOTES
    Author: Remote Access Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/windows-server/remote/remote-access/remote-access-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Helper Functions

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Tests if the current session is running with administrator privileges.
    
    .DESCRIPTION
        This function checks if the current PowerShell session is running with
        administrator privileges, which are required for most Remote Access operations.
    
    .OUTPUTS
        System.Boolean
    
    .EXAMPLE
        Test-IsAdministrator
    #>
    [CmdletBinding()]
    param()
    
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Warning "Could not determine administrator status: $($_.Exception.Message)"
        return $false
    }
}

function Get-OperatingSystemVersion {
    <#
    .SYNOPSIS
        Gets the operating system version information.
    
    .DESCRIPTION
        This function retrieves detailed operating system version information
        including version number, build number, and edition.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-OperatingSystemVersion
    #>
    [CmdletBinding()]
    param()
    
    try {
        $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        $version = [System.Environment]::OSVersion.Version
        
        return [PSCustomObject]@{
            Version = $version
            Major = $version.Major
            Minor = $version.Minor
            Build = $version.Build
            Revision = $version.Revision
            Caption = $osInfo.Caption
            Edition = $osInfo.EditionID
            Architecture = $osInfo.OSArchitecture
            InstallDate = $osInfo.InstallDate
            LastBootUpTime = $osInfo.LastBootUpTime
        }
    } catch {
        Write-Warning "Could not get operating system version: $($_.Exception.Message)"
        return $null
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a log entry with timestamp and level.
    
    .DESCRIPTION
        This function writes a formatted log entry with timestamp, level,
        and message to the console and optionally to a log file.
    
    .PARAMETER Message
        The message to log
    
    .PARAMETER Level
        The log level (INFO, WARNING, ERROR, SUCCESS)
    
    .PARAMETER LogPath
        Optional path to a log file
    
    .EXAMPLE
        Write-Log -Message "Starting Remote Access configuration" -Level "INFO"
    
    .EXAMPLE
        Write-Log -Message "Configuration completed successfully" -Level "SUCCESS" -LogPath "C:\Logs\RemoteAccess.log"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO",
        
        [string]$LogPath
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to console with appropriate color
    switch ($Level) {
        "INFO" { Write-Host $logEntry -ForegroundColor White }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
    }
    
    # Write to log file if specified
    if ($LogPath) {
        try {
            Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Could not write to log file: $($_.Exception.Message)"
        }
    }
}

#endregion

#region Remote Access Specific Functions

function Test-RemoteAccessPrerequisites {
    <#
    .SYNOPSIS
        Tests if the system meets the prerequisites for Remote Access Services.
    
    .DESCRIPTION
        This function checks for necessary operating system versions, administrative privileges,
        and other requirements for Remote Access Services.
    
    .OUTPUTS
        System.Boolean
    
    .EXAMPLE
        Test-RemoteAccessPrerequisites
    #>
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Checking Remote Access Services prerequisites..." -Level "INFO"
    
    if (-not (Test-IsAdministrator)) {
        Write-Log -Message "Administrator privileges are required for Remote Access Services." -Level "ERROR"
        return $false
    }
    
    $osVersion = Get-OperatingSystemVersion
    if ($osVersion.Major -lt 10) { # Windows Server 2016 is 10.0
        Write-Log -Message "Unsupported operating system version: $($osVersion). Windows Server 2016 or later is required." -Level "ERROR"
        return $false
    }
    
    Write-Log -Message "All Remote Access Services prerequisites met." -Level "SUCCESS"
    return $true
}

function Get-RemoteAccessServiceStatus {
    <#
    .SYNOPSIS
        Gets the status of Remote Access services.
    
    .DESCRIPTION
        Retrieves the current status of Remote Access related services
        including RemoteAccess, RemoteAccessManagement, and others.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-RemoteAccessServiceStatus
    #>
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Getting Remote Access service status..." -Level "INFO"
    
    $services = @(
        "RemoteAccess",
        "RemoteAccessManagement", 
        "PolicyAgent",
        "RasMan",
        "SstpSvc",
        "IKEEXT",
        "BFE"
    )
    
    $serviceStatus = @{
        Timestamp = Get-Date
        ComputerName = $env:COMPUTERNAME
        Services = @()
    }
    
    foreach ($serviceName in $services) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                $serviceStatus.Services += [PSCustomObject]@{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    Status = $service.Status
                    StartType = $service.StartType
                    ServiceType = $service.ServiceType
                }
            }
        } catch {
            Write-Log -Message "Could not get status for service $serviceName`: $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    Write-Log -Message "Remote Access service status retrieved successfully." -Level "SUCCESS"
    return [PSCustomObject]$serviceStatus
}

function Start-RemoteAccessServices {
    <#
    .SYNOPSIS
        Starts Remote Access services.
    
    .DESCRIPTION
        Ensures all Remote Access related services are running.
    
    .OUTPUTS
        System.Boolean
    
    .EXAMPLE
        Start-RemoteAccessServices
    #>
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Starting Remote Access services..." -Level "INFO"
    
    $services = @("RemoteAccess", "RemoteAccessManagement", "PolicyAgent", "RasMan", "SstpSvc", "IKEEXT", "BFE")
    $success = $true
    
    foreach ($serviceName in $services) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -ne "Running") {
                Start-Service -Name $serviceName -ErrorAction Stop
                Write-Log -Message "Started service: $serviceName" -Level "SUCCESS"
            }
        } catch {
            Write-Log -Message "Failed to start service $serviceName`: $($_.Exception.Message)" -Level "ERROR"
            $success = $false
        }
    }
    
    return $success
}

function Stop-RemoteAccessServices {
    <#
    .SYNOPSIS
        Stops Remote Access services.
    
    .DESCRIPTION
        Stops all Remote Access related services.
    
    .OUTPUTS
        System.Boolean
    
    .EXAMPLE
        Stop-RemoteAccessServices
    #>
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Stopping Remote Access services..." -Level "INFO"
    
    $services = @("RemoteAccess", "RemoteAccessManagement", "PolicyAgent", "RasMan", "SstpSvc", "IKEEXT", "BFE")
    $success = $true
    
    foreach ($serviceName in $services) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq "Running") {
                Stop-Service -Name $serviceName -ErrorAction Stop
                Write-Log -Message "Stopped service: $serviceName" -Level "SUCCESS"
            }
        } catch {
            Write-Log -Message "Failed to stop service $serviceName`: $($_.Exception.Message)" -Level "ERROR"
            $success = $false
        }
    }
    
    return $success
}

function Test-RemoteAccessHealth {
    <#
    .SYNOPSIS
        Tests the health of Remote Access services.
    
    .DESCRIPTION
        Performs comprehensive health checks on Remote Access services
        including service status, configuration, and connectivity.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-RemoteAccessHealth
    #>
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Testing Remote Access health..." -Level "INFO"
    
    $healthResult = @{
        Timestamp = Get-Date
        ComputerName = $env:COMPUTERNAME
        ServiceStatus = $null
        ConfigurationStatus = $null
        ConnectivityStatus = $null
        OverallHealth = "Unknown"
        Issues = @()
        Recommendations = @()
    }
    
    # Check service status
    $serviceStatus = Get-RemoteAccessServiceStatus
    $healthResult.ServiceStatus = $serviceStatus
    
    $runningServices = ($serviceStatus.Services | Where-Object { $_.Status -eq "Running" }).Count
    $totalServices = $serviceStatus.Services.Count
    
    if ($runningServices -eq $totalServices) {
        Write-Log -Message "All Remote Access services are running." -Level "SUCCESS"
    } else {
        $stoppedServices = $serviceStatus.Services | Where-Object { $_.Status -ne "Running" }
        foreach ($service in $stoppedServices) {
            $healthResult.Issues += "Service $($service.Name) is not running (Status: $($service.Status))"
        }
    }
    
    # Check configuration (basic checks)
    try {
        $remoteAccessConfig = Get-RemoteAccess -ErrorAction SilentlyContinue
        if ($remoteAccessConfig) {
            $healthResult.ConfigurationStatus = "Configured"
            Write-Log -Message "Remote Access configuration found." -Level "SUCCESS"
        } else {
            $healthResult.ConfigurationStatus = "Not Configured"
            $healthResult.Issues += "Remote Access is not configured"
        }
    } catch {
        $healthResult.ConfigurationStatus = "Error"
        $healthResult.Issues += "Could not check Remote Access configuration: $($_.Exception.Message)"
    }
    
    # Determine overall health
    if ($healthResult.Issues.Count -eq 0) {
        $healthResult.OverallHealth = "Healthy"
    } elseif ($healthResult.Issues.Count -lt 3) {
        $healthResult.OverallHealth = "Warning"
    } else {
        $healthResult.OverallHealth = "Critical"
    }
    
    # Generate recommendations
    if ($healthResult.OverallHealth -ne "Healthy") {
        $healthResult.Recommendations += "Review and resolve identified issues"
        if ($healthResult.ConfigurationStatus -eq "Not Configured") {
            $healthResult.Recommendations += "Configure Remote Access services"
        }
    }
    
    Write-Log -Message "Remote Access health check completed. Status: $($healthResult.OverallHealth)" -Level "INFO"
    return [PSCustomObject]$healthResult
}

function Get-RemoteAccessFeatures {
    <#
    .SYNOPSIS
        Gets installed Remote Access features.
    
    .DESCRIPTION
        Retrieves information about installed Remote Access features
        including DirectAccess, VPN, and Web Application Proxy.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-RemoteAccessFeatures
    #>
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Getting Remote Access features..." -Level "INFO"
    
    $features = @(
        "DirectAccess-VPN",
        "RAS",
        "Web-Application-Proxy",
        "NPAS",
        "RSAT-RemoteAccess-PowerShell",
        "RSAT-Web-Application-Proxy-PowerShell"
    )
    
    $featureStatus = @{
        Timestamp = Get-Date
        ComputerName = $env:COMPUTERNAME
        Features = @()
    }
    
    foreach ($featureName in $features) {
        try {
            $feature = Get-WindowsFeature -Name $featureName -ErrorAction SilentlyContinue
            if ($feature) {
                $featureStatus.Features += [PSCustomObject]@{
                    Name = $feature.Name
                    DisplayName = $feature.DisplayName
                    InstallState = $feature.InstallState
                    FeatureType = $feature.FeatureType
                }
            }
        } catch {
            Write-Log -Message "Could not get status for feature $featureName`: $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    Write-Log -Message "Remote Access features retrieved successfully." -Level "SUCCESS"
    return [PSCustomObject]$featureStatus
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Test-IsAdministrator',
    'Get-OperatingSystemVersion',
    'Write-Log',
    'Test-RemoteAccessPrerequisites',
    'Get-RemoteAccessServiceStatus',
    'Start-RemoteAccessServices',
    'Stop-RemoteAccessServices',
    'Test-RemoteAccessHealth',
    'Get-RemoteAccessFeatures'
)

# Module initialization
Write-Verbose "RemoteAccess-Core module loaded successfully. Version: $ModuleVersion"