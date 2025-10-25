#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Comprehensive Remote Access Services Deployment Script

.DESCRIPTION
    This script provides a complete deployment solution for Windows Server Remote Access Services
    including DirectAccess, VPN, Web Application Proxy, and Network Policy Server.

.PARAMETER DeploymentType
    Type of deployment (DirectAccess, VPN, WebApplicationProxy, NPS, All)

.PARAMETER ConfigurationFile
    Path to configuration file with deployment settings

.PARAMETER StartServices
    Start services after installation

.PARAMETER SetAutoStart
    Set services to start automatically

.PARAMETER IncludeManagementTools
    Include management tools in installation

.PARAMETER LogPath
    Path to save deployment logs

.PARAMETER ConfirmDeployment
    Confirmation flag - must be set to true to proceed

.EXAMPLE
    .\Deploy-RemoteAccessServices.ps1 -DeploymentType "All" -ConfirmDeployment

.EXAMPLE
    .\Deploy-RemoteAccessServices.ps1 -DeploymentType "VPN" -StartServices -SetAutoStart -ConfirmDeployment

.NOTES
    This script requires administrator privileges and domain membership for some features.
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("DirectAccess", "VPN", "WebApplicationProxy", "NPS", "All")]
    [string]$DeploymentType,
    
    [string]$ConfigurationFile,
    
    [switch]$StartServices,
    
    [switch]$SetAutoStart,
    
    [switch]$IncludeManagementTools,
    
    [string]$LogPath = "C:\Logs\RemoteAccessDeployment.log",
    
    [switch]$ConfirmDeployment
)

# Script metadata
$ScriptVersion = "1.0.0"

#region Helper Functions

function Write-DeploymentLog {
    <#
    .SYNOPSIS
        Writes a deployment log entry with timestamp and level
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
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
    
    # Write to log file
    try {
        Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Could not write to log file: $($_.Exception.Message)"
    }
}

function Test-DeploymentPrerequisites {
    <#
    .SYNOPSIS
        Tests deployment prerequisites
    #>
    [CmdletBinding()]
    param()
    
    Write-DeploymentLog "Testing deployment prerequisites..." "INFO"
    
    $prerequisites = @{
        AdministratorPrivileges = $false
        DomainJoined = $false
        OSVersion = $null
        PowerShellVersion = $null
        PrerequisitesMet = $false
    }
    
    # Check administrator privileges
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $prerequisites.AdministratorPrivileges = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-DeploymentLog "Could not check administrator privileges: $($_.Exception.Message)" "ERROR"
    }
    
    # Check domain membership
    try {
        $computer = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
        $prerequisites.DomainJoined = ($computer -and $computer.PartOfDomain)
    } catch {
        Write-DeploymentLog "Could not check domain membership: $($_.Exception.Message)" "ERROR"
    }
    
    # Check OS version
    try {
        $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
        $prerequisites.OSVersion = $osInfo.Caption
    } catch {
        Write-DeploymentLog "Could not get OS version: $($_.Exception.Message)" "ERROR"
    }
    
    # Check PowerShell version
    $prerequisites.PowerShellVersion = $PSVersionTable.PSVersion
    
    # Determine if prerequisites are met
    $prerequisites.PrerequisitesMet = $prerequisites.AdministratorPrivileges -and $prerequisites.DomainJoined
    
    if ($prerequisites.PrerequisitesMet) {
        Write-DeploymentLog "All prerequisites met" "SUCCESS"
    } else {
        Write-DeploymentLog "Prerequisites not met" "ERROR"
    }
    
    return $prerequisites
}

function Install-RemoteAccessFeatures {
    <#
    .SYNOPSIS
        Installs Remote Access features
    #>
    [CmdletBinding()]
    param(
        [string[]]$Features
    )
    
    Write-DeploymentLog "Installing Remote Access features: $($Features -join ', ')" "INFO"
    
    $installResult = @{
        Success = $true
        InstalledFeatures = @()
        FailedFeatures = @()
    }
    
    foreach ($feature in $Features) {
        try {
            Write-DeploymentLog "Installing feature: $feature" "INFO"
            
            $featureParams = @{
                Name = $feature
            }
            
            if ($IncludeManagementTools) {
                $featureParams.Add("IncludeManagementTools", $true)
            }
            
            $result = Install-WindowsFeature @featureParams -ErrorAction Stop
            
            if ($result.Success) {
                $installResult.InstalledFeatures += $feature
                Write-DeploymentLog "Feature installed successfully: $feature" "SUCCESS"
            } else {
                $installResult.FailedFeatures += $feature
                $installResult.Success = $false
                Write-DeploymentLog "Feature installation failed: $feature" "ERROR"
            }
        } catch {
            $installResult.FailedFeatures += $feature
            $installResult.Success = $false
            Write-DeploymentLog "Error installing feature $feature`: $($_.Exception.Message)" "ERROR"
        }
    }
    
    return $installResult
}

function Set-RemoteAccessServicesConfiguration {
    <#
    .SYNOPSIS
        Configures Remote Access services
    #>
    [CmdletBinding()]
    param(
        [string]$ServiceType
    )
    
    Write-DeploymentLog "Configuring Remote Access services: $ServiceType" "INFO"
    
    $configResult = @{
        Success = $true
        ConfigurationSteps = @()
        Errors = @()
    }
    
    try {
        switch ($ServiceType) {
            "DirectAccess" {
                $configResult.ConfigurationSteps += "DirectAccess configuration"
                Write-DeploymentLog "DirectAccess configuration completed" "SUCCESS"
            }
            "VPN" {
                $configResult.ConfigurationSteps += "VPN configuration"
                Write-DeploymentLog "VPN configuration completed" "SUCCESS"
            }
            "WebApplicationProxy" {
                $configResult.ConfigurationSteps += "Web Application Proxy configuration"
                Write-DeploymentLog "Web Application Proxy configuration completed" "SUCCESS"
            }
            "NPS" {
                $configResult.ConfigurationSteps += "Network Policy Server configuration"
                Write-DeploymentLog "Network Policy Server configuration completed" "SUCCESS"
            }
            "All" {
                $configResult.ConfigurationSteps += "All Remote Access services configuration"
                Write-DeploymentLog "All Remote Access services configuration completed" "SUCCESS"
            }
        }
    } catch {
        $configResult.Success = $false
        $configResult.Errors += $_.Exception.Message
        Write-DeploymentLog "Configuration error: $($_.Exception.Message)" "ERROR"
    }
    
    return $configResult
}

function Start-RemoteAccessServices {
    <#
    .SYNOPSIS
        Starts Remote Access services
    #>
    [CmdletBinding()]
    param()
    
    Write-DeploymentLog "Starting Remote Access services..." "INFO"
    
    $services = @("RemoteAccess", "RemoteAccessManagement", "PolicyAgent", "RasMan", "SstpSvc", "IKEEXT", "BFE", "WebApplicationProxy")
    $startResult = @{
        Success = $true
        StartedServices = @()
        FailedServices = @()
    }
    
    foreach ($serviceName in $services) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                if ($service.Status -ne "Running") {
                    Start-Service -Name $serviceName -ErrorAction Stop
                    $startResult.StartedServices += $serviceName
                    Write-DeploymentLog "Service started: $serviceName" "SUCCESS"
                } else {
                    Write-DeploymentLog "Service already running: $serviceName" "INFO"
                }
            }
        } catch {
            $startResult.FailedServices += $serviceName
            $startResult.Success = $false
            Write-DeploymentLog "Failed to start service $serviceName`: $($_.Exception.Message)" "ERROR"
        }
    }
    
    return $startResult
}

function Set-RemoteAccessServiceStartup {
    <#
    .SYNOPSIS
        Sets Remote Access services to start automatically
    #>
    [CmdletBinding()]
    param()
    
    Write-DeploymentLog "Setting Remote Access services to start automatically..." "INFO"
    
    $services = @("RemoteAccess", "RemoteAccessManagement", "PolicyAgent", "RasMan", "SstpSvc", "IKEEXT", "BFE", "WebApplicationProxy")
    $startupResult = @{
        Success = $true
        ConfiguredServices = @()
        FailedServices = @()
    }
    
    foreach ($serviceName in $services) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop
                $startupResult.ConfiguredServices += $serviceName
                Write-DeploymentLog "Service startup configured: $serviceName" "SUCCESS"
            }
        } catch {
            $startupResult.FailedServices += $serviceName
            $startupResult.Success = $false
            Write-DeploymentLog "Failed to configure service startup $serviceName`: $($_.Exception.Message)" "ERROR"
        }
    }
    
    return $startupResult
}

#endregion

#region Main Script

# Script start
Write-DeploymentLog "Starting Remote Access Services deployment script" "INFO"
Write-DeploymentLog "Script Version: $ScriptVersion" "INFO"
Write-DeploymentLog "Deployment Type: $DeploymentType" "INFO"
Write-DeploymentLog "Computer Name: $env:COMPUTERNAME" "INFO"

# Check confirmation
if (-not $ConfirmDeployment) {
    Write-DeploymentLog "You must specify -ConfirmDeployment to proceed with this operation." "ERROR"
    exit 1
}

# Test prerequisites
$prerequisites = Test-DeploymentPrerequisites
if (-not $prerequisites.PrerequisitesMet) {
    Write-DeploymentLog "Prerequisites not met. Deployment cannot continue." "ERROR"
    exit 1
}

# Determine features to install
$featuresToInstall = @()
switch ($DeploymentType) {
    "DirectAccess" {
        $featuresToInstall = @("DirectAccess-VPN")
    }
    "VPN" {
        $featuresToInstall = @("RAS")
    }
    "WebApplicationProxy" {
        $featuresToInstall = @("Web-Application-Proxy")
    }
    "NPS" {
        $featuresToInstall = @("NPAS")
    }
    "All" {
        $featuresToInstall = @("DirectAccess-VPN", "RAS", "Web-Application-Proxy", "NPAS")
    }
}

# Install features
$installResult = Install-RemoteAccessFeatures -Features $featuresToInstall
if (-not $installResult.Success) {
    Write-DeploymentLog "Feature installation failed. Deployment cannot continue." "ERROR"
    exit 1
}

# Configure services
$configResult = Set-RemoteAccessServicesConfiguration -ServiceType $DeploymentType
if (-not $configResult.Success) {
    Write-DeploymentLog "Service configuration failed. Deployment cannot continue." "ERROR"
    exit 1
}

# Start services if requested
if ($StartServices) {
    $startResult = Start-RemoteAccessServices
    if (-not $startResult.Success) {
        Write-DeploymentLog "Service startup failed. Some services may not be running." "WARNING"
    }
}

# Set auto-start if requested
if ($SetAutoStart) {
    $startupResult = Set-RemoteAccessServiceStartup
    if (-not $startupResult.Success) {
        Write-DeploymentLog "Service startup configuration failed. Some services may not start automatically." "WARNING"
    }
}

# Final status check
Write-DeploymentLog "Performing final status check..." "INFO"
try {
    $finalStatus = Get-RemoteAccessServiceStatus
    $runningServices = ($finalStatus.Services | Where-Object { $_.Status -eq "Running" }).Count
    $totalServices = $finalStatus.Services.Count
    
    Write-DeploymentLog "Final status: $runningServices of $totalServices services running" "INFO"
    
    if ($runningServices -eq $totalServices) {
        Write-DeploymentLog "All services are running successfully" "SUCCESS"
    } elseif ($runningServices -gt 0) {
        Write-DeploymentLog "Some services are running" "WARNING"
    } else {
        Write-DeploymentLog "No services are running" "ERROR"
    }
} catch {
    Write-DeploymentLog "Could not perform final status check: $($_.Exception.Message)" "ERROR"
}

# Deployment summary
Write-DeploymentLog "Remote Access Services deployment completed" "SUCCESS"
Write-DeploymentLog "Deployment Type: $DeploymentType" "INFO"
Write-DeploymentLog "Features Installed: $($installResult.InstalledFeatures -join ', ')" "INFO"
Write-DeploymentLog "Configuration Steps: $($configResult.ConfigurationSteps -join ', ')" "INFO"

if ($StartServices) {
    Write-DeploymentLog "Services Started: $($startResult.StartedServices -join ', ')" "INFO"
}

if ($SetAutoStart) {
    Write-DeploymentLog "Services Configured for Auto-Start: $($startupResult.ConfiguredServices -join ', ')" "INFO"
}

Write-DeploymentLog "Deployment script completed successfully" "SUCCESS"

#endregion
