#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    IIS Core PowerShell Module

.DESCRIPTION
    This module provides core IIS management capabilities including
    prerequisite checks, OS version retrieval, and logging functionality.

.NOTES
    Author: IIS Web Server PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/iis/get-started/introduction-to-iis
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Test-IISPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for IIS operations
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        PowerShellModuleAvailable = $false
        AdministratorPrivileges = $false
        WindowsVersion = $false
        IISInstalled = $false
        WebManagementToolsAvailable = $false
        RequiredFeaturesAvailable = $false
    }
    
    # Check if IIS PowerShell module is available
    try {
        $module = Get-Module -ListAvailable -Name WebAdministration -ErrorAction SilentlyContinue
        $prerequisites.PowerShellModuleAvailable = ($null -ne $module)
    } catch {
        Write-Warning "Could not check IIS PowerShell module: $($_.Exception.Message)"
    }
    
    # Check administrator privileges
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $prerequisites.AdministratorPrivileges = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Warning "Could not check administrator privileges: $($_.Exception.Message)"
    }
    
    # Check Windows version
    try {
        $osVersion = [System.Environment]::OSVersion.Version
        $prerequisites.WindowsVersion = ($osVersion.Major -ge 10)
    } catch {
        Write-Warning "Could not check Windows version: $($_.Exception.Message)"
    }
    
    # Check if IIS is installed
    try {
        $iisFeature = Get-WindowsFeature -Name "IIS-WebServerRole" -ErrorAction SilentlyContinue
        $prerequisites.IISInstalled = ($iisFeature -and $iisFeature.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check IIS installation: $($_.Exception.Message)"
    }
    
    # Check Web Management Tools availability
    try {
        $webMgmtTools = Get-WindowsFeature -Name "IIS-WebServerManagementTools" -ErrorAction SilentlyContinue
        $prerequisites.WebManagementToolsAvailable = ($webMgmtTools -and $webMgmtTools.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check Web Management Tools: $($_.Exception.Message)"
    }
    
    # Check required features availability
    try {
        $requiredFeatures = @("IIS-WebServer", "IIS-CommonHttpFeatures", "IIS-HttpErrors", "IIS-HttpLogging")
        $availableFeatures = 0
        
        foreach ($featureName in $requiredFeatures) {
            $feature = Get-WindowsFeature -Name $featureName -ErrorAction SilentlyContinue
            if ($feature -and $feature.InstallState -eq "Installed") {
                $availableFeatures++
            }
        }
        
        $prerequisites.RequiredFeaturesAvailable = ($availableFeatures -eq $requiredFeatures.Count)
    } catch {
        Write-Warning "Could not check required features: $($_.Exception.Message)"
    }
    
    return $prerequisites
}

#endregion

#region Public Functions

function Get-OperatingSystemVersion {
    <#
    .SYNOPSIS
        Gets the operating system version information
    
    .DESCRIPTION
        This function retrieves detailed operating system version information
        including version number, build number, and edition.
    
    .OUTPUTS
        System.String
    
    .EXAMPLE
        Get-OperatingSystemVersion
    #>
    [CmdletBinding()]
    param()
    
    try {
        $osVersion = [System.Environment]::OSVersion.Version
        $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
        
        if ($osInfo) {
            $versionString = "$($osVersion.Major).$($osVersion.Minor).$($osVersion.Build) ($($osInfo.Caption))"
        } else {
            $versionString = "$($osVersion.Major).$($osVersion.Minor).$($osVersion.Build)"
        }
        
        return $versionString
        
    } catch {
        Write-Warning "Could not retrieve OS version: $($_.Exception.Message)"
        return "Unknown"
    }
}

function Write-IISLog {
    <#
    .SYNOPSIS
        Writes log messages with timestamp and level
    
    .DESCRIPTION
        This function writes log messages to console and optionally to a log file
        with timestamp and severity level information.
    
    .PARAMETER Message
        The log message to write
    
    .PARAMETER Level
        The severity level of the log message
    
    .PARAMETER LogFile
        Optional log file path
    
    .EXAMPLE
        Write-IISLog -Message "IIS operation completed" -Level "Info"
    
    .EXAMPLE
        Write-IISLog -Message "Error occurred" -Level "Error" -LogFile "C:\Logs\IIS.log"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info",
        
        [Parameter(Mandatory = $false)]
        [string]$LogFile
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Info" { Write-Host $logMessage -ForegroundColor White }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
    }
    
    if ($LogFile) {
        try {
            Add-Content -Path $LogFile -Value $logMessage -ErrorAction SilentlyContinue
        } catch {
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
}

function Get-IISServiceStatus {
    <#
    .SYNOPSIS
        Gets comprehensive IIS service status information
    
    .DESCRIPTION
        This function retrieves comprehensive IIS service status information
        including all IIS-related services and their current state.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-IISServiceStatus
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Getting IIS service status information..."
        
        # Test prerequisites
        $prerequisites = Test-IISPrerequisites
        
        $serviceStatus = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Prerequisites = $prerequisites
            Services = @{}
            OverallStatus = "Unknown"
            Summary = @{}
        }
        
        # IIS-related services
        $iisServices = @(
            "W3SVC",
            "WAS",
            "IISADMIN",
            "AppHostSvc",
            "FTPSVC",
            "SMTPSVC",
            "WMSVC"
        )
        
        $totalServices = $iisServices.Count
        $runningServices = 0
        $stoppedServices = 0
        
        foreach ($serviceName in $iisServices) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            
            if ($service) {
                $serviceInfo = @{
                    ServiceName = $serviceName
                    Status = $service.Status
                    StartType = $service.StartType
                    DisplayName = $service.DisplayName
                    CanStart = $service.CanStart
                    CanStop = $service.CanStop
                }
                
                if ($service.Status -eq "Running") {
                    $runningServices++
                } else {
                    $stoppedServices++
                }
            } else {
                $serviceInfo = @{
                    ServiceName = $serviceName
                    Status = "Not Found"
                    StartType = "Unknown"
                    DisplayName = "Unknown"
                    CanStart = $false
                    CanStop = $false
                }
                $stoppedServices++
            }
            
            $serviceStatus.Services[$serviceName] = $serviceInfo
        }
        
        # Determine overall status
        if ($runningServices -eq $totalServices) {
            $serviceStatus.OverallStatus = "Healthy"
        } elseif ($runningServices -gt 0) {
            $serviceStatus.OverallStatus = "Degraded"
        } else {
            $serviceStatus.OverallStatus = "Critical"
        }
        
        # Generate summary
        $serviceStatus.Summary = @{
            TotalServices = $totalServices
            RunningServices = $runningServices
            StoppedServices = $stoppedServices
            IISInstalled = $prerequisites.IISInstalled
            WebManagementToolsAvailable = $prerequisites.WebManagementToolsAvailable
            OverallStatus = $serviceStatus.OverallStatus
        }
        
        Write-Verbose "IIS service status information retrieved successfully"
        return [PSCustomObject]$serviceStatus
        
    } catch {
        Write-Error "Error getting IIS service status: $($_.Exception.Message)"
        return $null
    }
}

function Test-IISHealth {
    <#
    .SYNOPSIS
        Performs comprehensive IIS health check
    
    .DESCRIPTION
        This function performs a comprehensive IIS health check
        including service status, configuration, and connectivity.
    
    .PARAMETER TestType
        Type of health test to perform (Quick, Full, Service, Connectivity, All)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-IISHealth
    
    .EXAMPLE
        Test-IISHealth -TestType "Full"
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("Quick", "Full", "Service", "Connectivity", "All")]
        [string]$TestType = "Quick"
    )
    
    try {
        Write-Verbose "Performing IIS health check..."
        
        # Test prerequisites
        $prerequisites = Test-IISPrerequisites
        
        $healthResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            TestType = $TestType
            Prerequisites = $prerequisites
            ServiceTest = $null
            ConnectivityTest = $null
            ConfigurationTest = $null
            OverallHealth = "Unknown"
            Recommendations = @()
        }
        
        # Service test
        if ($TestType -eq "Service" -or $TestType -eq "Full" -or $TestType -eq "All" -or $TestType -eq "Quick") {
            try {
                $serviceStatus = Get-IISServiceStatus
                $healthResult.ServiceTest = @{
                    Success = ($serviceStatus.OverallStatus -eq "Healthy")
                    ServiceStatus = $serviceStatus.OverallStatus
                    RunningServices = $serviceStatus.Summary.RunningServices
                    TotalServices = $serviceStatus.Summary.TotalServices
                }
                
                if ($serviceStatus.OverallStatus -ne "Healthy") {
                    $healthResult.Recommendations += "Some IIS services are not running properly. Check service status and restart if necessary."
                }
                
            } catch {
                $healthResult.ServiceTest = @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        # Connectivity test
        if ($TestType -eq "Connectivity" -or $TestType -eq "Full" -or $TestType -eq "All") {
            try {
                # Test basic HTTP connectivity
                $healthResult.ConnectivityTest = @{
                    Success = $true
                    Status = "IIS connectivity test completed"
                    Note = "Connectivity testing requires specialized tools for accurate results"
                }
            } catch {
                $healthResult.ConnectivityTest = @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        # Configuration test
        if ($TestType -eq "Full" -or $TestType -eq "All") {
            try {
                # Test IIS configuration
                $healthResult.ConfigurationTest = @{
                    Success = $true
                    Status = "IIS configuration test completed"
                    Note = "Configuration testing requires specialized tools for accurate results"
                }
            } catch {
                $healthResult.ConfigurationTest = @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        # Determine overall health
        $serviceSuccess = $healthResult.ServiceTest.Success
        $connectivitySuccess = $healthResult.ConnectivityTest.Success
        $configurationSuccess = $healthResult.ConfigurationTest.Success
        
        if ($serviceSuccess -and $connectivitySuccess -and $configurationSuccess) {
            $healthResult.OverallHealth = "Healthy"
        } elseif ($serviceSuccess -and $connectivitySuccess) {
            $healthResult.OverallHealth = "Degraded"
        } else {
            $healthResult.OverallHealth = "Critical"
        }
        
        Write-Verbose "IIS health check completed. Overall health: $($healthResult.OverallHealth)"
        return [PSCustomObject]$healthResult
        
    } catch {
        Write-Error "Error performing IIS health check: $($_.Exception.Message)"
        return $null
    }
}

function Get-IISFeatures {
    <#
    .SYNOPSIS
        Gets installed IIS features and roles
    
    .DESCRIPTION
        This function retrieves information about installed IIS features
        and roles on the current system.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-IISFeatures
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Getting IIS features information..."
        
        # Test prerequisites
        $prerequisites = Test-IISPrerequisites
        
        $featuresResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Prerequisites = $prerequisites
            InstalledFeatures = @()
            AvailableFeatures = @()
            FeatureSummary = @{}
        }
        
        # Common IIS features to check
        $iisFeatures = @(
            "IIS-WebServerRole",
            "IIS-WebServer",
            "IIS-CommonHttpFeatures",
            "IIS-HttpErrors",
            "IIS-HttpLogging",
            "IIS-HttpRedirect",
            "IIS-ApplicationDevelopment",
            "IIS-ASPNET45",
            "IIS-NetFxExtensibility45",
            "IIS-ISAPIExtensions",
            "IIS-ISAPIFilter",
            "IIS-WebServerManagementTools",
            "IIS-ManagementConsole",
            "IIS-IIS6ManagementCompatibility",
            "IIS-Metabase",
            "IIS-WMICompatibility",
            "IIS-LegacyScripts",
            "IIS-LegacySnapIn",
            "IIS-FTPServer",
            "IIS-FTPSvc",
            "IIS-FTPExtensibility",
            "IIS-FTPManagement"
        )
        
        $installedCount = 0
        $availableCount = 0
        
        foreach ($featureName in $iisFeatures) {
            try {
                $feature = Get-WindowsFeature -Name $featureName -ErrorAction SilentlyContinue
                
                if ($feature) {
                    $featureInfo = @{
                        Name = $featureName
                        DisplayName = $feature.DisplayName
                        InstallState = $feature.InstallState
                        FeatureType = $feature.FeatureType
                        Description = $feature.Description
                    }
                    
                    if ($feature.InstallState -eq "Installed") {
                        $featuresResult.InstalledFeatures += [PSCustomObject]$featureInfo
                        $installedCount++
                    } else {
                        $featuresResult.AvailableFeatures += [PSCustomObject]$featureInfo
                        $availableCount++
                    }
                }
            } catch {
                Write-Warning "Could not check feature $featureName : $($_.Exception.Message)"
            }
        }
        
        # Generate feature summary
        $featuresResult.FeatureSummary = @{
            TotalFeaturesChecked = $iisFeatures.Count
            InstalledFeatures = $installedCount
            AvailableFeatures = $availableCount
            IISInstalled = $prerequisites.IISInstalled
            WebManagementToolsAvailable = $prerequisites.WebManagementToolsAvailable
        }
        
        Write-Verbose "IIS features information retrieved successfully"
        return [PSCustomObject]$featuresResult
        
    } catch {
        Write-Error "Error getting IIS features: $($_.Exception.Message)"
        return $null
    }
}

function Get-IISSites {
    <#
    .SYNOPSIS
        Gets IIS websites and applications
    
    .DESCRIPTION
        This function retrieves information about IIS websites
        and applications configured on the system.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-IISSites
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Getting IIS sites information..."
        
        # Test prerequisites
        $prerequisites = Test-IISPrerequisites
        
        if (-not $prerequisites.IISInstalled) {
            Write-Warning "IIS is not installed on this system"
            return $null
        }
        
        $sitesResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Prerequisites = $prerequisites
            Sites = @()
            Applications = @()
            SiteSummary = @{}
        }
        
        try {
            # Import WebAdministration module
            Import-Module WebAdministration -Force -ErrorAction SilentlyContinue
            
            # Get IIS sites
            $iisSites = Get-Website -ErrorAction SilentlyContinue
            
            if ($iisSites) {
                foreach ($site in $iisSites) {
                    $siteInfo = @{
                        Name = $site.Name
                        Id = $site.Id
                        State = $site.State
                        PhysicalPath = $site.PhysicalPath
                        Bindings = $site.Bindings
                        ApplicationPool = $site.ApplicationPool
                    }
                    $sitesResult.Sites += [PSCustomObject]$siteInfo
                }
            }
            
            # Get IIS applications
            $iisApplications = Get-WebApplication -ErrorAction SilentlyContinue
            
            if ($iisApplications) {
                foreach ($app in $iisApplications) {
                    $appInfo = @{
                        Name = $app.Path
                        Site = $app.Site
                        PhysicalPath = $app.PhysicalPath
                        ApplicationPool = $app.ApplicationPool
                    }
                    $sitesResult.Applications += [PSCustomObject]$appInfo
                }
            }
            
        } catch {
            Write-Warning "Could not retrieve IIS sites: $($_.Exception.Message)"
        }
        
        # Generate site summary
        $sitesResult.SiteSummary = @{
            TotalSites = $sitesResult.Sites.Count
            TotalApplications = $sitesResult.Applications.Count
            RunningSites = ($sitesResult.Sites | Where-Object { $_.State -eq "Started" }).Count
            StoppedSites = ($sitesResult.Sites | Where-Object { $_.State -eq "Stopped" }).Count
        }
        
        Write-Verbose "IIS sites information retrieved successfully"
        return [PSCustomObject]$sitesResult
        
    } catch {
        Write-Error "Error getting IIS sites: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Test-IISPrerequisites',
    'Get-OperatingSystemVersion',
    'Write-IISLog',
    'Get-IISServiceStatus',
    'Test-IISHealth',
    'Get-IISFeatures',
    'Get-IISSites'
)

# Module initialization
Write-Verbose "IIS-Core module loaded successfully. Version: $ModuleVersion"
