#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Core Active Directory Rights Management Services (AD RMS) PowerShell Module

.DESCRIPTION
    This module provides core functions for AD RMS operations including installation,
    configuration, and basic management tasks.

.NOTES
    Author: AD RMS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Module metadata
$ModuleVersion = "1.0.0"
$ModuleName = "ADRMS-Core"

# Import required modules
try {
    Import-Module ServerManager -ErrorAction Stop
    Import-Module ADDSDeployment -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Required modules not available. Some functions may not work properly."
}

#region Private Functions

function Test-ADRMSPrerequisites {
    <#
    .SYNOPSIS
        Tests if the system meets AD RMS prerequisites
    
    .DESCRIPTION
        Checks Windows version, PowerShell version, domain membership, and required features
    
    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        WindowsVersion = $false
        PowerShellVersion = $false
        DomainMember = $false
        RequiredFeatures = $false
    }
    
    try {
        # Check Windows version (Server 2016+)
        $osVersion = [System.Environment]::OSVersion.Version
        if ($osVersion.Major -ge 10) {
            $prerequisites.WindowsVersion = $true
            Write-Verbose "Windows version check passed: $($osVersion.ToString())"
        } else {
            Write-Warning "Windows Server 2016 or later required. Current: $($osVersion.ToString())"
        }
        
        # Check PowerShell version (5.1+)
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            $prerequisites.PowerShellVersion = $true
            Write-Verbose "PowerShell version check passed: $($PSVersionTable.PSVersion.ToString())"
        } else {
            Write-Warning "PowerShell 5.1 or later required. Current: $($PSVersionTable.PSVersion.ToString())"
        }
        
        # Check domain membership
        $computer = Get-WmiObject -Class Win32_ComputerSystem
        if ($computer.PartOfDomain) {
            $prerequisites.DomainMember = $true
            Write-Verbose "Domain membership check passed: $($computer.Domain)"
        } else {
            Write-Warning "Computer must be a domain member"
        }
        
        # Check required Windows features
        $requiredFeatures = @('ADRMS', 'IIS-WebServer', 'IIS-WebServerRole', 'IIS-CommonHttpFeatures')
        $installedFeatures = Get-WindowsFeature | Where-Object { $_.InstallState -eq 'Installed' }
        
        $missingFeatures = @()
        foreach ($feature in $requiredFeatures) {
            if ($installedFeatures.Name -notcontains $feature) {
                $missingFeatures += $feature
            }
        }
        
        if ($missingFeatures.Count -eq 0) {
            $prerequisites.RequiredFeatures = $true
            Write-Verbose "Required Windows features check passed"
        } else {
            Write-Warning "Missing required Windows features: $($missingFeatures -join ', ')"
        }
        
        # Return overall result
        $allPassed = $prerequisites.Values -notcontains $false
        return $allPassed
        
    } catch {
        Write-Error "Error checking prerequisites: $($_.Exception.Message)"
        return $false
    }
}

function Get-ADRMSConfiguration {
    <#
    .SYNOPSIS
        Retrieves current AD RMS configuration
    
    .DESCRIPTION
        Gets the current AD RMS configuration including cluster information,
        service account, and database settings
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    try {
        $config = @{}
        
        # Check if AD RMS is installed
        $adrmsFeature = Get-WindowsFeature -Name ADRMS
        $config.Installed = $adrmsFeature.InstallState -eq 'Installed'
        
        if ($config.Installed) {
            # Get AD RMS service status
            $adrmsService = Get-Service -Name MSDRMS -ErrorAction SilentlyContinue
            $config.ServiceStatus = if ($adrmsService) { $adrmsService.Status } else { 'Not Found' }
            
            # Try to get cluster information from registry
            $regPath = "HKLM:\SOFTWARE\Microsoft\MSDRMS\Cluster"
            if (Test-Path $regPath) {
                $config.ClusterUrl = Get-ItemProperty -Path $regPath -Name "ClusterURL" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ClusterURL
                $config.LicensingUrl = Get-ItemProperty -Path $regPath -Name "LicensingURL" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LicensingURL
            }
            
            # Get IIS configuration
            $iisService = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
            $config.IISStatus = if ($iisService) { $iisService.Status } else { 'Not Found' }
        }
        
        return [PSCustomObject]$config
        
    } catch {
        Write-Error "Error retrieving AD RMS configuration: $($_.Exception.Message)"
        return $null
    }
}

function Test-ADRMSHealth {
    <#
    .SYNOPSIS
        Performs basic health checks on AD RMS installation
    
    .DESCRIPTION
        Checks service status, IIS configuration, and basic connectivity
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    $health = @{
        Overall = 'Unknown'
        Services = @{}
        IIS = @{}
        Connectivity = @{}
        Timestamp = Get-Date
    }
    
    try {
        # Check AD RMS service
        $adrmsService = Get-Service -Name MSDRMS -ErrorAction SilentlyContinue
        if ($adrmsService) {
            $health.Services.ADRMS = $adrmsService.Status
        } else {
            $health.Services.ADRMS = 'Not Found'
        }
        
        # Check IIS service
        $iisService = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
        if ($iisService) {
            $health.Services.IIS = $iisService.Status
        } else {
            $health.Services.IIS = 'Not Found'
        }
        
        # Check IIS sites
        try {
            Import-Module WebAdministration -ErrorAction Stop
            $adrmsSite = Get-Website -Name "*RMS*" -ErrorAction SilentlyContinue
            $health.IIS.RMSSite = if ($adrmsSite) { 'Found' } else { 'Not Found' }
        } catch {
            $health.IIS.RMSSite = 'Cannot Check'
        }
        
        # Basic connectivity test
        try {
            $testUrl = "http://localhost/_wmcs/licensing"
            $response = Invoke-WebRequest -Uri $testUrl -TimeoutSec 10 -ErrorAction Stop
            $health.Connectivity.LicensingEndpoint = 'Accessible'
        } catch {
            $health.Connectivity.LicensingEndpoint = 'Not Accessible'
        }
        
        # Determine overall health
        $allServicesRunning = ($health.Services.Values -eq 'Running').Count -eq $health.Services.Count
        $iisAccessible = $health.Connectivity.LicensingEndpoint -eq 'Accessible'
        
        if ($allServicesRunning -and $iisAccessible) {
            $health.Overall = 'Healthy'
        } elseif ($allServicesRunning) {
            $health.Overall = 'Degraded'
        } else {
            $health.Overall = 'Unhealthy'
        }
        
        return [PSCustomObject]$health
        
    } catch {
        Write-Error "Error performing health check: $($_.Exception.Message)"
        $health.Overall = 'Error'
        return [PSCustomObject]$health
    }
}

#endregion

#region Public Functions

function Install-ADRMSPrerequisites {
    <#
    .SYNOPSIS
        Installs required Windows features for AD RMS
    
    .DESCRIPTION
        Installs AD RMS, IIS, and other required Windows features
    
    .PARAMETER RestartRequired
        Specifies whether to restart the computer if required
    
    .EXAMPLE
        Install-ADRMSPrerequisites
    
    .EXAMPLE
        Install-ADRMSPrerequisites -RestartRequired $true
    #>
    [CmdletBinding()]
    param(
        [switch]$RestartRequired
    )
    
    try {
        Write-Host "Installing AD RMS prerequisites..." -ForegroundColor Green
        
        # Define required features
        $features = @(
            'ADRMS',
            'IIS-WebServer',
            'IIS-WebServerRole',
            'IIS-CommonHttpFeatures',
            'IIS-HttpErrors',
            'IIS-HttpLogging',
            'IIS-RequestFiltering',
            'IIS-StaticContent',
            'IIS-DefaultDocument',
            'IIS-DirectoryBrowsing',
            'IIS-ASPNET45',
            'IIS-NetFxExtensibility45',
            'IIS-ISAPIExtensions',
            'IIS-ISAPIFilter',
            'IIS-HttpCompressionStatic',
            'IIS-HttpCompressionDynamic',
            'IIS-Security',
            'IIS-RequestFiltering',
            'IIS-Performance',
            'IIS-HttpTracing',
            'IIS-ManagementConsole'
        )
        
        $restartNeeded = $false
        
        foreach ($feature in $features) {
            $featureInfo = Get-WindowsFeature -Name $feature
            if ($featureInfo.InstallState -ne 'Installed') {
                Write-Host "Installing feature: $feature" -ForegroundColor Yellow
                $result = Install-WindowsFeature -Name $feature -IncludeManagementTools
                
                if ($result.RestartNeeded) {
                    $restartNeeded = $true
                }
                
                if ($result.Success) {
                    Write-Host "Successfully installed: $feature" -ForegroundColor Green
                } else {
                    Write-Warning "Failed to install: $feature"
                }
            } else {
                Write-Host "Feature already installed: $feature" -ForegroundColor Cyan
            }
        }
        
        if ($restartNeeded -and $RestartRequired) {
            Write-Host "Restart required. Restarting computer..." -ForegroundColor Yellow
            Restart-Computer -Force
        } elseif ($restartNeeded) {
            Write-Warning "A restart is required to complete the installation."
        }
        
        Write-Host "Prerequisites installation completed." -ForegroundColor Green
        
    } catch {
        Write-Error "Error installing prerequisites: $($_.Exception.Message)"
        throw
    }
}

function Get-ADRMSStatus {
    <#
    .SYNOPSIS
        Gets comprehensive AD RMS status information
    
    .DESCRIPTION
        Returns detailed status information including configuration,
        health, and service status
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Gathering AD RMS status information..." -ForegroundColor Green
        
        $status = @{
            Prerequisites = Test-ADRMSPrerequisites
            Configuration = Get-ADRMSConfiguration
            Health = Test-ADRMSHealth
            Timestamp = Get-Date
        }
        
        return [PSCustomObject]$status
        
    } catch {
        Write-Error "Error getting AD RMS status: $($_.Exception.Message)"
        throw
    }
}

function Start-ADRMSServices {
    <#
    .SYNOPSIS
        Starts AD RMS related services
    
    .DESCRIPTION
        Starts AD RMS and dependent services
    
    .EXAMPLE
        Start-ADRMSServices
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Starting AD RMS services..." -ForegroundColor Green
        
        $services = @('W3SVC', 'MSDRMS')
        
        foreach ($serviceName in $services) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                if ($service.Status -ne 'Running') {
                    Write-Host "Starting service: $serviceName" -ForegroundColor Yellow
                    Start-Service -Name $serviceName
                    Write-Host "Service started: $serviceName" -ForegroundColor Green
                } else {
                    Write-Host "Service already running: $serviceName" -ForegroundColor Cyan
                }
            } else {
                Write-Warning "Service not found: $serviceName"
            }
        }
        
    } catch {
        Write-Error "Error starting AD RMS services: $($_.Exception.Message)"
        throw
    }
}

function Stop-ADRMSServices {
    <#
    .SYNOPSIS
        Stops AD RMS related services
    
    .DESCRIPTION
        Stops AD RMS and dependent services
    
    .EXAMPLE
        Stop-ADRMSServices
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Stopping AD RMS services..." -ForegroundColor Green
        
        $services = @('MSDRMS', 'W3SVC')
        
        foreach ($serviceName in $services) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq 'Running') {
                Write-Host "Stopping service: $serviceName" -ForegroundColor Yellow
                Stop-Service -Name $serviceName -Force
                Write-Host "Service stopped: $serviceName" -ForegroundColor Green
            } else {
                Write-Host "Service not running or not found: $serviceName" -ForegroundColor Cyan
            }
        }
        
    } catch {
        Write-Error "Error stopping AD RMS services: $($_.Exception.Message)"
        throw
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Install-ADRMSPrerequisites',
    'Get-ADRMSStatus',
    'Start-ADRMSServices',
    'Stop-ADRMSServices'
)

# Module initialization
Write-Verbose "ADRMS-Core module loaded successfully. Version: $ModuleVersion"
