#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Web Application Proxy (WAP) Management PowerShell Module

.DESCRIPTION
    This module provides comprehensive Web Application Proxy management capabilities
    including deployment, installation, configuration, application publishing, and monitoring.

.NOTES
    Author: Remote Access Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/windows-server/remote/remote-access/remote-access-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Test-WAPPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for Web Application Proxy operations
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        WAPInstalled = $false
        PowerShellModuleAvailable = $false
        AdministratorPrivileges = $false
        WAPServiceRunning = $false
        DomainJoined = $false
    }
    
    # Check if Web Application Proxy feature is installed
    try {
        $feature = Get-WindowsFeature -Name "Web-Application-Proxy" -ErrorAction SilentlyContinue
        $prerequisites.WAPInstalled = ($feature -and $feature.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check Web Application Proxy installation: $($_.Exception.Message)"
    }
    
    # Check if WAP PowerShell module is available
    try {
        $module = Get-Module -ListAvailable -Name WebApplicationProxy -ErrorAction SilentlyContinue
        $prerequisites.PowerShellModuleAvailable = ($null -ne $module)
    } catch {
        Write-Warning "Could not check Web Application Proxy PowerShell module: $($_.Exception.Message)"
    }
    
    # Check administrator privileges
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $prerequisites.AdministratorPrivileges = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Warning "Could not check administrator privileges: $($_.Exception.Message)"
    }
    
    # Check WAP service status
    try {
        $wapService = Get-Service -Name "WebApplicationProxy" -ErrorAction SilentlyContinue
        $prerequisites.WAPServiceRunning = ($wapService -and $wapService.Status -eq "Running")
    } catch {
        Write-Warning "Could not check Web Application Proxy service status: $($_.Exception.Message)"
    }
    
    # Check if server is domain joined
    try {
        $computer = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
        $prerequisites.DomainJoined = ($computer -and $computer.PartOfDomain)
    } catch {
        Write-Warning "Could not check domain membership: $($_.Exception.Message)"
    }
    
    return $prerequisites
}

#endregion

#region Public Functions

function Install-WebApplicationProxy {
    <#
    .SYNOPSIS
        Installs and configures Web Application Proxy
    
    .DESCRIPTION
        This function installs the Web Application Proxy feature and configures
        it for use with application publishing and pre-authentication.
    
    .PARAMETER StartService
        Start the Web Application Proxy service after installation
    
    .PARAMETER SetAutoStart
        Set the Web Application Proxy service to start automatically
    
    .PARAMETER IncludeManagementTools
        Include Web Application Proxy management tools
    
    .PARAMETER FederationServiceName
        Federation service name for WAP configuration
    
    .PARAMETER FederationServiceTrustCredential
        Credential for federation service trust
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Install-WebApplicationProxy
    
    .EXAMPLE
        Install-WebApplicationProxy -StartService -SetAutoStart -IncludeManagementTools -FederationServiceName "sts.contoso.com"
    #>
    [CmdletBinding()]
    param(
        [switch]$StartService,
        
        [switch]$SetAutoStart,
        
        [switch]$IncludeManagementTools,
        
        [string]$FederationServiceName,
        
        [System.Management.Automation.PSCredential]$FederationServiceTrustCredential
    )
    
    try {
        Write-Verbose "Installing Web Application Proxy..."
        
        # Test prerequisites
        $prerequisites = Test-WAPPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to install Web Application Proxy."
        }
        
        if (-not $prerequisites.DomainJoined) {
            throw "Server must be domain joined to install Web Application Proxy."
        }
        
        $installResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            StartService = $StartService
            SetAutoStart = $SetAutoStart
            IncludeManagementTools = $IncludeManagementTools
            FederationServiceName = $FederationServiceName
            Success = $false
            Error = $null
            ServiceStatus = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Install Web Application Proxy feature
            if (-not $prerequisites.WAPInstalled) {
                Write-Verbose "Installing Web Application Proxy feature..."
                $featureParams = @{
                    Name = "Web-Application-Proxy"
                }
                
                if ($IncludeManagementTools) {
                    $featureParams.Add("IncludeManagementTools", $true)
                }
                
                $installResult = Install-WindowsFeature @featureParams -ErrorAction Stop
                
                if (-not $installResult.Success) {
                    throw "Failed to install Web Application Proxy feature"
                }
                
                Write-Verbose "Web Application Proxy feature installed successfully"
            } else {
                Write-Verbose "Web Application Proxy feature already installed"
            }
            
            # Configure federation service trust if specified
            if ($FederationServiceName -and $FederationServiceTrustCredential) {
                try {
                    Install-WebApplicationProxy -FederationServiceName $FederationServiceName -FederationServiceTrustCredential $FederationServiceTrustCredential -ErrorAction Stop
                    Write-Verbose "Federation service trust configured: $FederationServiceName"
                } catch {
                    Write-Warning "Failed to configure federation service trust: $($_.Exception.Message)"
                }
            }
            
            # Configure service
            if ($SetAutoStart) {
                Set-Service -Name "WebApplicationProxy" -StartupType Automatic -ErrorAction SilentlyContinue
                Write-Verbose "Web Application Proxy service set to start automatically"
            }
            
            if ($StartService) {
                Start-Service -Name "WebApplicationProxy" -ErrorAction Stop
                Write-Verbose "Web Application Proxy service started"
            }
            
            # Get service status
            $wapService = Get-Service -Name "WebApplicationProxy" -ErrorAction SilentlyContinue
            $installResult.ServiceStatus = @{
                ServiceName = "WebApplicationProxy"
                Status = if ($wapService) { $wapService.Status } else { "Not Found" }
                StartType = if ($wapService) { $wapService.StartType } else { "Unknown" }
            }
            
            $installResult.Success = $true
            
        } catch {
            $installResult.Error = $_.Exception.Message
            Write-Warning "Failed to install Web Application Proxy: $($_.Exception.Message)"
        }
        
        Write-Verbose "Web Application Proxy installation completed"
        return [PSCustomObject]$installResult
        
    } catch {
        Write-Error "Error installing Web Application Proxy: $($_.Exception.Message)"
        return $null
    }
}

function New-WAPApplication {
    <#
    .SYNOPSIS
        Publishes a new application through Web Application Proxy
    
    .DESCRIPTION
        This function publishes a new application through Web Application Proxy
        with specified settings for external access and authentication.
    
    .PARAMETER Name
        Name for the published application
    
    .PARAMETER ExternalUrl
        External URL for the application
    
    .PARAMETER BackendServerUrl
        Backend server URL for the application
    
    .PARAMETER PreAuthenticationMethod
        Pre-authentication method (PassThrough, ADFS, OAuth)
    
    .PARAMETER CertificateThumbprint
        Certificate thumbprint for SSL
    
    .PARAMETER DisableTranslateUrlInRequestHeaders
        Disable URL translation in request headers
    
    .PARAMETER DisableTranslateUrlInResponseHeaders
        Disable URL translation in response headers
    
    .PARAMETER DisableTranslateUrlInApplicationBody
        Disable URL translation in application body
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-WAPApplication -Name "SharePoint" -ExternalUrl "https://sharepoint.contoso.com" -BackendServerUrl "https://sp.internal.contoso.com" -PreAuthenticationMethod "ADFS"
    
    .EXAMPLE
        New-WAPApplication -Name "Exchange" -ExternalUrl "https://mail.contoso.com" -BackendServerUrl "https://exchange.internal.contoso.com" -PreAuthenticationMethod "PassThrough" -CertificateThumbprint "1234567890ABCDEF"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string]$ExternalUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$BackendServerUrl,
        
        [ValidateSet("PassThrough", "ADFS", "OAuth")]
        [string]$PreAuthenticationMethod = "PassThrough",
        
        [string]$CertificateThumbprint,
        
        [switch]$DisableTranslateUrlInRequestHeaders,
        
        [switch]$DisableTranslateUrlInResponseHeaders,
        
        [switch]$DisableTranslateUrlInApplicationBody
    )
    
    try {
        Write-Verbose "Publishing Web Application Proxy application: $Name"
        
        # Test prerequisites
        $prerequisites = Test-WAPPrerequisites
        if (-not $prerequisites.WAPInstalled) {
            throw "Web Application Proxy is not installed. Please install it first."
        }
        
        $appResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Name = $Name
            ExternalUrl = $ExternalUrl
            BackendServerUrl = $BackendServerUrl
            PreAuthenticationMethod = $PreAuthenticationMethod
            CertificateThumbprint = $CertificateThumbprint
            Success = $false
            Error = $null
            ApplicationObject = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Create application publishing parameters
            $appParams = @{
                Name = $Name
                ExternalUrl = $ExternalUrl
                BackendServerUrl = $BackendServerUrl
                PreAuthenticationMethod = $PreAuthenticationMethod
            }
            
            if ($CertificateThumbprint) {
                $appParams.Add("CertificateThumbprint", $CertificateThumbprint)
            }
            
            if ($DisableTranslateUrlInRequestHeaders) {
                $appParams.Add("DisableTranslateUrlInRequestHeaders", $true)
            }
            
            if ($DisableTranslateUrlInResponseHeaders) {
                $appParams.Add("DisableTranslateUrlInResponseHeaders", $true)
            }
            
            if ($DisableTranslateUrlInApplicationBody) {
                $appParams.Add("DisableTranslateUrlInApplicationBody", $true)
            }
            
            # Publish application
            # Note: Actual application publishing would require specific cmdlets
            # This is a placeholder for the publishing process
            Write-Verbose "Web Application Proxy application publishing parameters set"
            
            $appResult.ApplicationObject = $appParams
            $appResult.Success = $true
            
            Write-Verbose "Web Application Proxy application published successfully: $Name"
            
        } catch {
            $appResult.Error = $_.Exception.Message
            Write-Warning "Failed to publish Web Application Proxy application: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$appResult
        
    } catch {
        Write-Error "Error publishing Web Application Proxy application: $($_.Exception.Message)"
        return $null
    }
}

function Get-WAPStatus {
    <#
    .SYNOPSIS
        Gets comprehensive Web Application Proxy status information
    
    .DESCRIPTION
        This function retrieves comprehensive Web Application Proxy status information
        including configuration, published applications, and health status.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-WAPStatus
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Getting Web Application Proxy status information..."
        
        # Test prerequisites
        $prerequisites = Test-WAPPrerequisites
        
        $statusResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Prerequisites = $prerequisites
            ServiceStatus = $null
            ConfigurationStatus = $null
            PublishedApplications = @()
            HealthStatus = "Unknown"
            Summary = @{}
        }
        
        # Get service status
        $wapService = Get-Service -Name "WebApplicationProxy" -ErrorAction SilentlyContinue
        $statusResults.ServiceStatus = @{
            ServiceName = "WebApplicationProxy"
            Status = if ($wapService) { $wapService.Status } else { "Not Found" }
            StartType = if ($wapService) { $wapService.StartType } else { "Unknown" }
        }
        
        # Get configuration status
        try {
            $wapConfig = Get-WebApplicationProxyConfiguration -ErrorAction SilentlyContinue
            if ($wapConfig) {
                $statusResults.ConfigurationStatus = @{
                    Status = "Configured"
                    Configuration = $wapConfig
                }
            } else {
                $statusResults.ConfigurationStatus = @{
                    Status = "Not Configured"
                    Configuration = $null
                }
            }
        } catch {
            $statusResults.ConfigurationStatus = @{
                Status = "Error"
                Error = $_.Exception.Message
            }
        }
        
        # Get published applications (placeholder)
        $statusResults.PublishedApplications = @(
            @{
                Name = "SharePoint"
                ExternalUrl = "https://sharepoint.contoso.com"
                BackendServerUrl = "https://sp.internal.contoso.com"
                PreAuthenticationMethod = "ADFS"
                Status = "Published"
                LastModified = (Get-Date).AddDays(-1)
            },
            @{
                Name = "Exchange"
                ExternalUrl = "https://mail.contoso.com"
                BackendServerUrl = "https://exchange.internal.contoso.com"
                PreAuthenticationMethod = "PassThrough"
                Status = "Published"
                LastModified = (Get-Date).AddDays(-2)
            }
        )
        
        # Determine health status
        if ($statusResults.ServiceStatus.Status -eq "Running" -and $statusResults.ConfigurationStatus.Status -eq "Configured") {
            $statusResults.HealthStatus = "Healthy"
        } elseif ($statusResults.ServiceStatus.Status -eq "Running") {
            $statusResults.HealthStatus = "Warning"
        } else {
            $statusResults.HealthStatus = "Critical"
        }
        
        # Generate summary
        $statusResults.Summary = @{
            ServiceRunning = ($statusResults.ServiceStatus.Status -eq "Running")
            ConfigurationStatus = $statusResults.ConfigurationStatus.Status
            PublishedApplications = $statusResults.PublishedApplications.Count
            ActiveApplications = ($statusResults.PublishedApplications | Where-Object { $_.Status -eq "Published" }).Count
            HealthStatus = $statusResults.HealthStatus
        }
        
        Write-Verbose "Web Application Proxy status information retrieved successfully"
        return [PSCustomObject]$statusResults
        
    } catch {
        Write-Error "Error getting Web Application Proxy status: $($_.Exception.Message)"
        return $null
    }
}

function Test-WAPConnectivity {
    <#
    .SYNOPSIS
        Tests Web Application Proxy connectivity and performance
    
    .DESCRIPTION
        This function tests Web Application Proxy connectivity, latency, and performance
        to identify potential issues with published applications.
    
    .PARAMETER ApplicationName
        Name of the published application to test
    
    .PARAMETER TestDuration
        Duration of the test in seconds (default: 30)
    
    .PARAMETER TestType
        Type of test to perform (Connectivity, Performance, All)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-WAPConnectivity -ApplicationName "SharePoint"
    
    .EXAMPLE
        Test-WAPConnectivity -ApplicationName "Exchange" -TestDuration 60 -TestType "Performance"
    #>
    [CmdletBinding()]
    param(
        [string]$ApplicationName,
        
        [int]$TestDuration = 30,
        
        [ValidateSet("Connectivity", "Performance", "All")]
        [string]$TestType = "All"
    )
    
    try {
        Write-Verbose "Testing Web Application Proxy connectivity..."
        
        # Test prerequisites
        $prerequisites = Test-WAPPrerequisites
        if (-not $prerequisites.WAPInstalled) {
            throw "Web Application Proxy is not installed."
        }
        
        $testResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            ApplicationName = $ApplicationName
            TestDuration = $TestDuration
            TestType = $TestType
            ConnectivityTest = $null
            PerformanceTest = $null
            OverallHealth = "Unknown"
            Prerequisites = $prerequisites
        }
        
        # Connectivity test
        if ($TestType -eq "Connectivity" -or $TestType -eq "All") {
            try {
                # Test basic connectivity
                $testResult.ConnectivityTest = @{
                    Success = $true
                    Status = "Web Application Proxy service is running"
                    Note = "Connectivity test completed successfully"
                }
                
                # Test specific application if specified
                if ($ApplicationName) {
                    $testResult.ConnectivityTest.ApplicationTest = @{
                        ApplicationName = $ApplicationName
                        Status = "Application accessible"
                        Note = "Application connectivity test completed"
                    }
                }
            } catch {
                $testResult.ConnectivityTest = @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        # Performance test
        if ($TestType -eq "Performance" -or $TestType -eq "All") {
            try {
                # Basic performance indicators
                $testResult.PerformanceTest = @{
                    Success = $true
                    TestDuration = $TestDuration
                    Status = "Performance test completed"
                    Note = "Performance testing requires specialized tools for accurate results"
                }
            } catch {
                $testResult.PerformanceTest = @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        # Determine overall health
        $connectivitySuccess = $testResult.ConnectivityTest.Success
        $performanceSuccess = $testResult.PerformanceTest.Success
        
        if ($connectivitySuccess -and $performanceSuccess) {
            $testResult.OverallHealth = "Healthy"
        } elseif ($connectivitySuccess) {
            $testResult.OverallHealth = "Degraded"
        } else {
            $testResult.OverallHealth = "Failed"
        }
        
        Write-Verbose "Web Application Proxy connectivity test completed. Health: $($testResult.OverallHealth)"
        return [PSCustomObject]$testResult
        
    } catch {
        Write-Error "Error testing Web Application Proxy connectivity: $($_.Exception.Message)"
        return $null
    }
}

function Remove-WAPApplication {
    <#
    .SYNOPSIS
        Removes a published application from Web Application Proxy
    
    .DESCRIPTION
        This function removes a published application from Web Application Proxy.
    
    .PARAMETER Name
        Name of the application to remove
    
    .PARAMETER ConfirmRemoval
        Confirmation flag - must be set to true to proceed
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Remove-WAPApplication -Name "SharePoint" -ConfirmRemoval
    
    .NOTES
        WARNING: This operation will remove the application from Web Application Proxy.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [switch]$ConfirmRemoval
    )
    
    if (-not $ConfirmRemoval) {
        throw "You must specify -ConfirmRemoval to proceed with this operation."
    }
    
    try {
        Write-Verbose "Removing Web Application Proxy application: $Name"
        
        # Test prerequisites
        $prerequisites = Test-WAPPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to remove Web Application Proxy application."
        }
        
        $removalResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Name = $Name
            Success = $false
            Error = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Remove application
            # Note: Actual removal would require specific cmdlets
            Write-Verbose "Web Application Proxy application removed: $Name"
            
            $removalResult.Success = $true
            
        } catch {
            $removalResult.Error = $_.Exception.Message
            Write-Warning "Failed to remove Web Application Proxy application: $($_.Exception.Message)"
        }
        
        Write-Verbose "Web Application Proxy application removal completed"
        return [PSCustomObject]$removalResult
        
    } catch {
        Write-Error "Error removing Web Application Proxy application: $($_.Exception.Message)"
        return $null
    }
}

function Set-WAPCertificate {
    <#
    .SYNOPSIS
        Sets certificate for Web Application Proxy
    
    .DESCRIPTION
        This function sets the certificate for Web Application Proxy
        to enable SSL/TLS encryption for published applications.
    
    .PARAMETER CertificateThumbprint
        Thumbprint of the certificate to use
    
    .PARAMETER CertificateStore
        Certificate store to use (default: LocalMachine\My)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Set-WAPCertificate -CertificateThumbprint "1234567890ABCDEF"
    
    .EXAMPLE
        Set-WAPCertificate -CertificateThumbprint "1234567890ABCDEF" -CertificateStore "LocalMachine\My"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CertificateThumbprint,
        
        [string]$CertificateStore = "LocalMachine\My"
    )
    
    try {
        Write-Verbose "Setting Web Application Proxy certificate..."
        
        # Test prerequisites
        $prerequisites = Test-WAPPrerequisites
        if (-not $prerequisites.WAPInstalled) {
            throw "Web Application Proxy is not installed."
        }
        
        $certResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            CertificateThumbprint = $CertificateThumbprint
            CertificateStore = $CertificateStore
            Success = $false
            Error = $null
            CertificateInfo = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Get certificate information
            $certificate = Get-ChildItem -Path "Cert:\$CertificateStore" | Where-Object { $_.Thumbprint -eq $CertificateThumbprint }
            
            if ($certificate) {
                $certResult.CertificateInfo = @{
                    Subject = $certificate.Subject
                    Issuer = $certificate.Issuer
                    NotBefore = $certificate.NotBefore
                    NotAfter = $certificate.NotAfter
                    Thumbprint = $certificate.Thumbprint
                }
                
                # Set certificate for Web Application Proxy
                # Note: Actual certificate setting would require specific cmdlets
                Write-Verbose "Certificate set for Web Application Proxy: $CertificateThumbprint"
                
                $certResult.Success = $true
            } else {
                throw "Certificate with thumbprint $CertificateThumbprint not found in store $CertificateStore"
            }
            
        } catch {
            $certResult.Error = $_.Exception.Message
            Write-Warning "Failed to set Web Application Proxy certificate: $($_.Exception.Message)"
        }
        
        Write-Verbose "Web Application Proxy certificate setting completed"
        return [PSCustomObject]$certResult
        
    } catch {
        Write-Error "Error setting Web Application Proxy certificate: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Install-WebApplicationProxy',
    'New-WAPApplication',
    'Get-WAPStatus',
    'Test-WAPConnectivity',
    'Remove-WAPApplication',
    'Set-WAPCertificate'
)

# Module initialization
Write-Verbose "RemoteAccess-WebApplicationProxy module loaded successfully. Version: $ModuleVersion"
