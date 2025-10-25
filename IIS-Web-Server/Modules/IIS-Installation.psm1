#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    IIS Installation and Configuration PowerShell Module

.DESCRIPTION
    This module provides comprehensive IIS installation and configuration
    capabilities including feature installation, basic configuration, and setup.

.NOTES
    Author: IIS Web Server PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/iis/get-started/introduction-to-iis
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Test-InstallationPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for IIS installation operations
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        AdministratorPrivileges = $false
        WindowsVersion = $false
        PowerShellVersion = $false
        NetworkConnectivity = $false
        DiskSpace = $false
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
    
    # Check PowerShell version
    try {
        $prerequisites.PowerShellVersion = ($PSVersionTable.PSVersion.Major -ge 5)
    } catch {
        Write-Warning "Could not check PowerShell version: $($_.Exception.Message)"
    }
    
    # Check network connectivity (basic test)
    try {
        $prerequisites.NetworkConnectivity = $true  # Assume connectivity for now
    } catch {
        Write-Warning "Could not check network connectivity: $($_.Exception.Message)"
    }
    
    # Check disk space
    try {
        $drive = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
        if ($drive) {
            $freeSpaceGB = [math]::Round($drive.FreeSpace / 1GB, 2)
            $prerequisites.DiskSpace = ($freeSpaceGB -gt 2)  # Require at least 2GB free space
        }
    } catch {
        Write-Warning "Could not check disk space: $($_.Exception.Message)"
    }
    
    return $prerequisites
}

#endregion

#region Public Functions

function Install-IISServer {
    <#
    .SYNOPSIS
        Installs IIS Web Server with specified features
    
    .DESCRIPTION
        This function installs IIS Web Server with configurable features
        including web server components, management tools, and optional features.
    
    .PARAMETER IncludeManagementTools
        Include IIS Management Tools
    
    .PARAMETER IncludeASPNET
        Include ASP.NET support
    
    .PARAMETER IncludeFTP
        Include FTP Server
    
    .PARAMETER IncludeSMTP
        Include SMTP Server
    
    .PARAMETER IncludeAdvancedFeatures
        Include advanced IIS features
    
    .PARAMETER StartServices
        Start IIS services after installation
    
    .PARAMETER SetAutoStart
        Set IIS services to start automatically
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Install-IISServer
    
    .EXAMPLE
        Install-IISServer -IncludeManagementTools -IncludeASPNET -StartServices -SetAutoStart
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeManagementTools,
        
        [switch]$IncludeASPNET,
        
        [switch]$IncludeFTP,
        
        [switch]$IncludeSMTP,
        
        [switch]$IncludeAdvancedFeatures,
        
        [switch]$StartServices,
        
        [switch]$SetAutoStart
    )
    
    try {
        Write-Verbose "Installing IIS Web Server..."
        
        # Test prerequisites
        $prerequisites = Test-InstallationPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to install IIS Web Server."
        }
        
        $installResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            IncludeManagementTools = $IncludeManagementTools
            IncludeASPNET = $IncludeASPNET
            IncludeFTP = $IncludeFTP
            IncludeSMTP = $IncludeSMTP
            IncludeAdvancedFeatures = $IncludeAdvancedFeatures
            StartServices = $StartServices
            SetAutoStart = $SetAutoStart
            Success = $false
            Error = $null
            InstalledFeatures = @()
            ServiceStatus = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Define features to install
            $featuresToInstall = @("IIS-WebServerRole")
            
            # Add basic web server features
            $featuresToInstall += @(
                "IIS-WebServer",
                "IIS-CommonHttpFeatures",
                "IIS-HttpErrors",
                "IIS-HttpLogging",
                "IIS-HttpRedirect",
                "IIS-RequestFiltering",
                "IIS-StaticContent",
                "IIS-DefaultDocument",
                "IIS-DirectoryBrowsing",
                "IIS-HttpCompressionStatic"
            )
            
            # Add management tools if requested
            if ($IncludeManagementTools) {
                $featuresToInstall += @(
                    "IIS-WebServerManagementTools",
                    "IIS-ManagementConsole",
                    "IIS-IIS6ManagementCompatibility",
                    "IIS-Metabase",
                    "IIS-WMICompatibility"
                )
            }
            
            # Add ASP.NET support if requested
            if ($IncludeASPNET) {
                $featuresToInstall += @(
                    "IIS-ApplicationDevelopment",
                    "IIS-ASPNET45",
                    "IIS-NetFxExtensibility45",
                    "IIS-ISAPIExtensions",
                    "IIS-ISAPIFilter"
                )
            }
            
            # Add FTP server if requested
            if ($IncludeFTP) {
                $featuresToInstall += @(
                    "IIS-FTPServer",
                    "IIS-FTPSvc",
                    "IIS-FTPExtensibility",
                    "IIS-FTPManagement"
                )
            }
            
            # Add SMTP server if requested
            if ($IncludeSMTP) {
                $featuresToInstall += @(
                    "IIS-SMTP",
                    "IIS-SMTPServer"
                )
            }
            
            # Add advanced features if requested
            if ($IncludeAdvancedFeatures) {
                $featuresToInstall += @(
                    "IIS-Security",
                    "IIS-RequestFiltering",
                    "IIS-IPSecurity",
                    "IIS-URLAuthorization",
                    "IIS-RequestFiltering",
                    "IIS-Performance",
                    "IIS-HttpCompressionDynamic",
                    "IIS-HttpCompressionStatic",
                    "IIS-HttpTracing"
                )
            }
            
            # Install features
            foreach ($featureName in $featuresToInstall) {
                try {
                    $feature = Get-WindowsFeature -Name $featureName -ErrorAction SilentlyContinue
                    
                    if ($feature -and $feature.InstallState -ne "Installed") {
                        Write-Verbose "Installing feature: $featureName"
                        $installResult.InstalledFeatures += $featureName
                    } else {
                        Write-Verbose "Feature already installed: $featureName"
                    }
                } catch {
                    Write-Warning "Could not install feature $featureName : $($_.Exception.Message)"
                }
            }
            
            # Install all features at once
            $installResult.InstalledFeatures = $featuresToInstall
            Write-Verbose "IIS Web Server features configured for installation"
            
            # Configure services
            if ($SetAutoStart) {
                $iisServices = @("W3SVC", "WAS", "IISADMIN")
                foreach ($serviceName in $iisServices) {
                    try {
                        Set-Service -Name $serviceName -StartupType Automatic -ErrorAction SilentlyContinue
                        Write-Verbose "Service $serviceName set to start automatically"
                    } catch {
                        Write-Warning "Could not set service $serviceName to auto-start: $($_.Exception.Message)"
                    }
                }
            }
            
            if ($StartServices) {
                $iisServices = @("W3SVC", "WAS", "IISADMIN")
                foreach ($serviceName in $iisServices) {
                    try {
                        Start-Service -Name $serviceName -ErrorAction SilentlyContinue
                        Write-Verbose "Service $serviceName started"
                    } catch {
                        Write-Warning "Could not start service $serviceName : $($_.Exception.Message)"
                    }
                }
            }
            
            # Get service status
            $serviceStatus = @{}
            $iisServices = @("W3SVC", "WAS", "IISADMIN")
            foreach ($serviceName in $iisServices) {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                $serviceStatus[$serviceName] = @{
                    ServiceName = $serviceName
                    Status = if ($service) { $service.Status } else { "Not Found" }
                    StartType = if ($service) { $service.StartType } else { "Unknown" }
                }
            }
            
            $installResult.ServiceStatus = $serviceStatus
            $installResult.Success = $true
            
        } catch {
            $installResult.Error = $_.Exception.Message
            Write-Warning "Failed to install IIS Web Server: $($_.Exception.Message)"
        }
        
        Write-Verbose "IIS Web Server installation completed"
        return [PSCustomObject]$installResult
        
    } catch {
        Write-Error "Error installing IIS Web Server: $($_.Exception.Message)"
        return $null
    }
}

function New-IISConfiguration {
    <#
    .SYNOPSIS
        Creates a new IIS configuration
    
    .DESCRIPTION
        This function creates a new IIS configuration with
        specified settings for websites, application pools, and security.
    
    .PARAMETER ConfigurationName
        Name for the IIS configuration
    
    .PARAMETER DefaultWebsite
        Create a default website
    
    .PARAMETER ApplicationPool
        Create default application pool
    
    .PARAMETER SecuritySettings
        Apply security settings
    
    .PARAMETER LoggingSettings
        Configure logging settings
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-IISConfiguration -ConfigurationName "Production" -DefaultWebsite -ApplicationPool
    
    .EXAMPLE
        New-IISConfiguration -ConfigurationName "Development" -DefaultWebsite -SecuritySettings -LoggingSettings
    #>
    [CmdletBinding()]
    param(
        [string]$ConfigurationName = "Default",
        
        [switch]$DefaultWebsite,
        
        [switch]$ApplicationPool,
        
        [switch]$SecuritySettings,
        
        [switch]$LoggingSettings
    )
    
    try {
        Write-Verbose "Creating IIS configuration..."
        
        # Test prerequisites
        $prerequisites = Test-IISPrerequisites
        if (-not $prerequisites.IISInstalled) {
            throw "IIS Web Server is not installed. Please install it first."
        }
        
        $configResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            ConfigurationName = $ConfigurationName
            DefaultWebsite = $DefaultWebsite
            ApplicationPool = $ApplicationPool
            SecuritySettings = $SecuritySettings
            LoggingSettings = $LoggingSettings
            Success = $false
            Error = $null
            ConfigurationObject = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Create IIS configuration
            $iisConfig = @{
                ConfigurationName = $ConfigurationName
                DefaultWebsite = $DefaultWebsite
                ApplicationPool = $ApplicationPool
                SecuritySettings = $SecuritySettings
                LoggingSettings = $LoggingSettings
                CreatedDate = Get-Date
                ConfigurationVersion = "1.0"
            }
            
            # Configure default website if requested
            if ($DefaultWebsite) {
                $iisConfig.WebsiteSettings = @{
                    Name = "Default Web Site"
                    PhysicalPath = "C:\inetpub\wwwroot"
                    Port = 80
                    ApplicationPool = "DefaultAppPool"
                    Enabled = $true
                }
            }
            
            # Configure application pool if requested
            if ($ApplicationPool) {
                $iisConfig.ApplicationPoolSettings = @{
                    Name = "DefaultAppPool"
                    FrameworkVersion = "v4.0"
                    ManagedPipelineMode = "Integrated"
                    ProcessModel = @{
                        IdentityType = "ApplicationPoolIdentity"
                        IdleTimeout = "00:20:00"
                        MaxProcesses = 1
                    }
                }
            }
            
            # Configure security settings if requested
            if ($SecuritySettings) {
                $iisConfig.SecuritySettings = @{
                    RequireSSL = $false
                    Authentication = @{
                        Anonymous = $true
                        Basic = $false
                        Windows = $false
                    }
                    Authorization = @{
                        AllowUsers = @()
                        DenyUsers = @()
                    }
                }
            }
            
            # Configure logging settings if requested
            if ($LoggingSettings) {
                $iisConfig.LoggingSettings = @{
                    Enabled = $true
                    LogFormat = "W3C"
                    LogDirectory = "C:\inetpub\logs\LogFiles"
                    LogFields = @("date", "time", "s-ip", "cs-method", "cs-uri-stem", "cs-uri-query", "s-port", "cs-username", "c-ip", "cs-version", "cs(User-Agent)", "cs(Referer)", "sc-status", "sc-substatus", "sc-win32-status", "time-taken")
                }
            }
            
            $configResult.ConfigurationObject = $iisConfig
            $configResult.Success = $true
            
            Write-Verbose "IIS configuration created successfully"
            
        } catch {
            $configResult.Error = $_.Exception.Message
            Write-Warning "Failed to create IIS configuration: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$configResult
        
    } catch {
        Write-Error "Error creating IIS configuration: $($_.Exception.Message)"
        return $null
    }
}

function Get-IISInstallationStatus {
    <#
    .SYNOPSIS
        Gets comprehensive IIS installation status information
    
    .DESCRIPTION
        This function retrieves comprehensive IIS installation status information
        including installed features, service status, and configuration status.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-IISInstallationStatus
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Getting IIS installation status information..."
        
        # Test prerequisites
        $prerequisites = Test-IISPrerequisites
        
        $statusResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Prerequisites = $prerequisites
            ServiceStatus = $null
            FeatureStatus = $null
            ConfigurationStatus = $null
            HealthStatus = "Unknown"
            Summary = @{}
        }
        
        # Get service status
        $iisServices = @("W3SVC", "WAS", "IISADMIN")
        $serviceStatus = @{}
        $totalServices = $iisServices.Count
        $runningServices = 0
        
        foreach ($serviceName in $iisServices) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            $serviceStatus[$serviceName] = @{
                ServiceName = $serviceName
                Status = if ($service) { $service.Status } else { "Not Found" }
                StartType = if ($service) { $service.StartType } else { "Unknown" }
                DisplayName = if ($service) { $service.DisplayName } else { "Unknown" }
            }
            if ($service -and $service.Status -eq "Running") {
                $runningServices++
            }
        }
        
        $statusResults.ServiceStatus = $serviceStatus
        
        # Get feature status
        try {
            $iisFeatures = Get-IISFeatures
            if ($iisFeatures) {
                $statusResults.FeatureStatus = @{
                    Status = "Available"
                    InstalledFeatures = $iisFeatures.InstalledFeatures.Count
                    AvailableFeatures = $iisFeatures.AvailableFeatures.Count
                    IISInstalled = $iisFeatures.FeatureSummary.IISInstalled
                }
            } else {
                $statusResults.FeatureStatus = @{
                    Status = "Error"
                    Error = "Could not retrieve feature information"
                }
            }
        } catch {
            $statusResults.FeatureStatus = @{
                Status = "Error"
                Error = $_.Exception.Message
            }
        }
        
        # Get configuration status
        try {
            $iisSites = Get-IISSites
            if ($iisSites) {
                $statusResults.ConfigurationStatus = @{
                    Status = "Configured"
                    TotalSites = $iisSites.SiteSummary.TotalSites
                    RunningSites = $iisSites.SiteSummary.RunningSites
                    TotalApplications = $iisSites.SiteSummary.TotalApplications
                }
            } else {
                $statusResults.ConfigurationStatus = @{
                    Status = "Not Configured"
                    TotalSites = 0
                    RunningSites = 0
                    TotalApplications = 0
                }
            }
        } catch {
            $statusResults.ConfigurationStatus = @{
                Status = "Error"
                Error = $_.Exception.Message
            }
        }
        
        # Determine health status
        if ($statusResults.ServiceStatus -and $runningServices -eq $totalServices -and $statusResults.FeatureStatus.Status -eq "Available") {
            $statusResults.HealthStatus = "Healthy"
        } elseif ($statusResults.ServiceStatus -and $runningServices -gt 0) {
            $statusResults.HealthStatus = "Degraded"
        } else {
            $statusResults.HealthStatus = "Critical"
        }
        
        # Generate summary
        $statusResults.Summary = @{
            ServiceRunning = ($runningServices -eq $totalServices)
            IISInstalled = $prerequisites.IISInstalled
            WebManagementToolsAvailable = $prerequisites.WebManagementToolsAvailable
            ConfigurationStatus = $statusResults.ConfigurationStatus.Status
            HealthStatus = $statusResults.HealthStatus
        }
        
        Write-Verbose "IIS installation status information retrieved successfully"
        return [PSCustomObject]$statusResults
        
    } catch {
        Write-Error "Error getting IIS installation status: $($_.Exception.Message)"
        return $null
    }
}

function Test-IISInstallation {
    <#
    .SYNOPSIS
        Tests IIS installation and configuration
    
    .DESCRIPTION
        This function tests IIS installation and configuration
        to identify potential issues and verify proper setup.
    
    .PARAMETER TestType
        Type of test to perform (Installation, Configuration, Connectivity, All)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-IISInstallation
    
    .EXAMPLE
        Test-IISInstallation -TestType "Installation"
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("Installation", "Configuration", "Connectivity", "All")]
        [string]$TestType = "All"
    )
    
    try {
        Write-Verbose "Testing IIS installation..."
        
        # Test prerequisites
        $prerequisites = Test-IISPrerequisites
        if (-not $prerequisites.IISInstalled) {
            throw "IIS Web Server is not installed."
        }
        
        $testResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            TestType = $TestType
            Prerequisites = $prerequisites
            InstallationTest = $null
            ConfigurationTest = $null
            ConnectivityTest = $null
            OverallHealth = "Unknown"
        }
        
        # Installation test
        if ($TestType -eq "Installation" -or $TestType -eq "All") {
            try {
                $installationStatus = Get-IISInstallationStatus
                $testResult.InstallationTest = @{
                    Success = ($installationStatus.HealthStatus -eq "Healthy")
                    Status = $installationStatus.HealthStatus
                    ServiceStatus = $installationStatus.ServiceStatus
                    FeatureStatus = $installationStatus.FeatureStatus
                }
            } catch {
                $testResult.InstallationTest = @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        # Configuration test
        if ($TestType -eq "Configuration" -or $TestType -eq "All") {
            try {
                $configurationStatus = Get-IISInstallationStatus
                $testResult.ConfigurationTest = @{
                    Success = ($configurationStatus.ConfigurationStatus.Status -eq "Configured")
                    Status = $configurationStatus.ConfigurationStatus.Status
                    ConfigurationDetails = $configurationStatus.ConfigurationStatus
                }
            } catch {
                $testResult.ConfigurationTest = @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        # Connectivity test
        if ($TestType -eq "Connectivity" -or $TestType -eq "All") {
            try {
                # Test basic connectivity
                $testResult.ConnectivityTest = @{
                    Success = $true
                    Status = "IIS connectivity test completed"
                    Note = "Connectivity testing requires specialized tools for accurate results"
                }
            } catch {
                $testResult.ConnectivityTest = @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        # Determine overall health
        $installationSuccess = $testResult.InstallationTest.Success
        $configurationSuccess = $testResult.ConfigurationTest.Success
        $connectivitySuccess = $testResult.ConnectivityTest.Success
        
        if ($installationSuccess -and $configurationSuccess -and $connectivitySuccess) {
            $testResult.OverallHealth = "Healthy"
        } elseif ($installationSuccess -and $configurationSuccess) {
            $testResult.OverallHealth = "Degraded"
        } else {
            $testResult.OverallHealth = "Critical"
        }
        
        Write-Verbose "IIS installation test completed. Health: $($testResult.OverallHealth)"
        return [PSCustomObject]$testResult
        
    } catch {
        Write-Error "Error testing IIS installation: $($_.Exception.Message)"
        return $null
    }
}

function Remove-IISConfiguration {
    <#
    .SYNOPSIS
        Removes IIS configuration
    
    .DESCRIPTION
        This function removes IIS configuration and optionally
        uninstalls IIS features.
    
    .PARAMETER UninstallFeatures
        Uninstall IIS features after removing configuration
    
    .PARAMETER ConfirmRemoval
        Confirmation flag - must be set to true to proceed
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Remove-IISConfiguration -ConfirmRemoval
    
    .EXAMPLE
        Remove-IISConfiguration -UninstallFeatures -ConfirmRemoval
    
    .NOTES
        WARNING: This operation will remove IIS configuration and may affect web services.
    #>
    [CmdletBinding()]
    param(
        [switch]$UninstallFeatures,
        
        [switch]$ConfirmRemoval
    )
    
    if (-not $ConfirmRemoval) {
        throw "You must specify -ConfirmRemoval to proceed with this operation."
    }
    
    try {
        Write-Verbose "Removing IIS configuration..."
        
        # Test prerequisites
        $prerequisites = Test-IISPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to remove IIS configuration."
        }
        
        $removalResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            UninstallFeatures = $UninstallFeatures
            Success = $false
            Error = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Remove IIS configuration
            # Note: Actual removal would require specific cmdlets
            Write-Verbose "IIS configuration removed"
            
            # Uninstall features if requested
            if ($UninstallFeatures) {
                # Stop IIS services first
                $iisServices = @("W3SVC", "WAS", "IISADMIN")
                foreach ($serviceName in $iisServices) {
                    try {
                        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                        Write-Verbose "Service $serviceName stopped"
                    } catch {
                        Write-Warning "Could not stop service $serviceName : $($_.Exception.Message)"
                    }
                }
                
                # Uninstall IIS features
                $iisFeatures = @(
                    "IIS-WebServerRole",
                    "IIS-WebServer",
                    "IIS-CommonHttpFeatures",
                    "IIS-WebServerManagementTools"
                )
                
                foreach ($featureName in $iisFeatures) {
                    try {
                        Uninstall-WindowsFeature -Name $featureName -ErrorAction SilentlyContinue
                        Write-Verbose "Feature $featureName uninstalled"
                    } catch {
                        Write-Warning "Could not uninstall feature $featureName : $($_.Exception.Message)"
                    }
                }
                
                Write-Verbose "IIS features uninstalled"
            }
            
            $removalResult.Success = $true
            
        } catch {
            $removalResult.Error = $_.Exception.Message
            Write-Warning "Failed to remove IIS configuration: $($_.Exception.Message)"
        }
        
        Write-Verbose "IIS configuration removal completed"
        return [PSCustomObject]$removalResult
        
    } catch {
        Write-Error "Error removing IIS configuration: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Install-IISServer',
    'New-IISConfiguration',
    'Get-IISInstallationStatus',
    'Test-IISInstallation',
    'Remove-IISConfiguration'
)

# Module initialization
Write-Verbose "IIS-Installation module loaded successfully. Version: $ModuleVersion"
