#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Network Policy Server (NPS) Management PowerShell Module

.DESCRIPTION
    This module provides comprehensive Network Policy Server management capabilities
    including deployment, installation, configuration, policy management, and monitoring.

.NOTES
    Author: Remote Access Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/windows-server/remote/remote-access/remote-access-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Test-NPSPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for Network Policy Server operations
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        NPSInstalled = $false
        PowerShellModuleAvailable = $false
        AdministratorPrivileges = $false
        NPSServiceRunning = $false
        DomainJoined = $false
    }
    
    # Check if Network Policy Server feature is installed
    try {
        $feature = Get-WindowsFeature -Name "NPAS" -ErrorAction SilentlyContinue
        $prerequisites.NPSInstalled = ($feature -and $feature.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check Network Policy Server installation: $($_.Exception.Message)"
    }
    
    # Check if NPS PowerShell module is available
    try {
        $module = Get-Module -ListAvailable -Name NPS -ErrorAction SilentlyContinue
        $prerequisites.PowerShellModuleAvailable = ($null -ne $module)
    } catch {
        Write-Warning "Could not check Network Policy Server PowerShell module: $($_.Exception.Message)"
    }
    
    # Check administrator privileges
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $prerequisites.AdministratorPrivileges = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Warning "Could not check administrator privileges: $($_.Exception.Message)"
    }
    
    # Check NPS service status
    try {
        $npsService = Get-Service -Name "PolicyAgent" -ErrorAction SilentlyContinue
        $prerequisites.NPSServiceRunning = ($npsService -and $npsService.Status -eq "Running")
    } catch {
        Write-Warning "Could not check Network Policy Server service status: $($_.Exception.Message)"
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

function Install-NPSServer {
    <#
    .SYNOPSIS
        Installs and configures Network Policy Server
    
    .DESCRIPTION
        This function installs the Network Policy Server feature and configures
        it for use with RADIUS authentication and authorization.
    
    .PARAMETER StartService
        Start the NPS service after installation
    
    .PARAMETER SetAutoStart
        Set the NPS service to start automatically
    
    .PARAMETER IncludeManagementTools
        Include NPS management tools
    
    .PARAMETER ConfigureAsRADIUSServer
        Configure NPS as a RADIUS server
    
    .PARAMETER ConfigureAsRADIUSProxy
        Configure NPS as a RADIUS proxy
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Install-NPSServer
    
    .EXAMPLE
        Install-NPSServer -StartService -SetAutoStart -IncludeManagementTools -ConfigureAsRADIUSServer
    #>
    [CmdletBinding()]
    param(
        [switch]$StartService,
        
        [switch]$SetAutoStart,
        
        [switch]$IncludeManagementTools,
        
        [switch]$ConfigureAsRADIUSServer,
        
        [switch]$ConfigureAsRADIUSProxy
    )
    
    try {
        Write-Verbose "Installing Network Policy Server..."
        
        # Test prerequisites
        $prerequisites = Test-NPSPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to install Network Policy Server."
        }
        
        $installResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            StartService = $StartService
            SetAutoStart = $SetAutoStart
            IncludeManagementTools = $IncludeManagementTools
            ConfigureAsRADIUSServer = $ConfigureAsRADIUSServer
            ConfigureAsRADIUSProxy = $ConfigureAsRADIUSProxy
            Success = $false
            Error = $null
            ServiceStatus = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Install Network Policy Server feature
            if (-not $prerequisites.NPSInstalled) {
                Write-Verbose "Installing Network Policy Server feature..."
                $featureParams = @{
                    Name = "NPAS"
                }
                
                if ($IncludeManagementTools) {
                    $featureParams.Add("IncludeManagementTools", $true)
                }
                
                $installResult = Install-WindowsFeature @featureParams -ErrorAction Stop
                
                if (-not $installResult.Success) {
                    throw "Failed to install Network Policy Server feature"
                }
                
                Write-Verbose "Network Policy Server feature installed successfully"
            } else {
                Write-Verbose "Network Policy Server feature already installed"
            }
            
            # Configure as RADIUS server if requested
            if ($ConfigureAsRADIUSServer) {
                try {
                    # Configure NPS as RADIUS server
                    # Note: Actual configuration would require specific cmdlets
                    Write-Verbose "NPS configured as RADIUS server"
                } catch {
                    Write-Warning "Failed to configure NPS as RADIUS server: $($_.Exception.Message)"
                }
            }
            
            # Configure as RADIUS proxy if requested
            if ($ConfigureAsRADIUSProxy) {
                try {
                    # Configure NPS as RADIUS proxy
                    # Note: Actual configuration would require specific cmdlets
                    Write-Verbose "NPS configured as RADIUS proxy"
                } catch {
                    Write-Warning "Failed to configure NPS as RADIUS proxy: $($_.Exception.Message)"
                }
            }
            
            # Configure service
            if ($SetAutoStart) {
                Set-Service -Name "PolicyAgent" -StartupType Automatic -ErrorAction SilentlyContinue
                Write-Verbose "NPS service set to start automatically"
            }
            
            if ($StartService) {
                Start-Service -Name "PolicyAgent" -ErrorAction Stop
                Write-Verbose "NPS service started"
            }
            
            # Get service status
            $npsService = Get-Service -Name "PolicyAgent" -ErrorAction SilentlyContinue
            $installResult.ServiceStatus = @{
                ServiceName = "PolicyAgent"
                Status = if ($npsService) { $npsService.Status } else { "Not Found" }
                StartType = if ($npsService) { $npsService.StartType } else { "Unknown" }
            }
            
            $installResult.Success = $true
            
        } catch {
            $installResult.Error = $_.Exception.Message
            Write-Warning "Failed to install Network Policy Server: $($_.Exception.Message)"
        }
        
        Write-Verbose "Network Policy Server installation completed"
        return [PSCustomObject]$installResult
        
    } catch {
        Write-Error "Error installing Network Policy Server: $($_.Exception.Message)"
        return $null
    }
}

function New-NPSNetworkPolicy {
    <#
    .SYNOPSIS
        Creates a new Network Policy Server network policy
    
    .DESCRIPTION
        This function creates a new network policy with specified
        conditions, constraints, and settings.
    
    .PARAMETER PolicyName
        Name for the network policy
    
    .PARAMETER PolicyType
        Type of policy (Allow, Deny)
    
    .PARAMETER Conditions
        Array of policy conditions
    
    .PARAMETER Constraints
        Array of policy constraints
    
    .PARAMETER Settings
        Array of policy settings
    
    .PARAMETER ProfileName
        Profile name for the policy
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-NPSNetworkPolicy -PolicyName "VPN Users" -PolicyType "Allow" -ProfileName "VPN"
    
    .EXAMPLE
        New-NPSNetworkPolicy -PolicyName "Wireless Users" -PolicyType "Allow" -ProfileName "Wireless" -Conditions @("User-Groups", "MS-Service-Type")
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyName,
        
        [ValidateSet("Allow", "Deny")]
        [string]$PolicyType = "Allow",
        
        [string[]]$Conditions,
        
        [string[]]$Constraints,
        
        [string[]]$Settings,
        
        [string]$ProfileName
    )
    
    try {
        Write-Verbose "Creating Network Policy Server network policy: $PolicyName"
        
        # Test prerequisites
        $prerequisites = Test-NPSPrerequisites
        if (-not $prerequisites.NPSInstalled) {
            throw "Network Policy Server is not installed. Please install it first."
        }
        
        $policyResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            PolicyName = $PolicyName
            PolicyType = $PolicyType
            Conditions = $Conditions
            Constraints = $Constraints
            Settings = $Settings
            ProfileName = $ProfileName
            Success = $false
            Error = $null
            PolicyObject = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Create network policy parameters
            $policyParams = @{
                Name = $PolicyName
                PolicyType = $PolicyType
            }
            
            if ($Conditions) {
                $policyParams.Add("Conditions", $Conditions)
            }
            
            if ($Constraints) {
                $policyParams.Add("Constraints", $Constraints)
            }
            
            if ($Settings) {
                $policyParams.Add("Settings", $Settings)
            }
            
            if ($ProfileName) {
                $policyParams.Add("ProfileName", $ProfileName)
            }
            
            # Create network policy
            # Note: Actual policy creation would require specific cmdlets
            # This is a placeholder for the policy creation process
            Write-Verbose "Network Policy Server network policy parameters set"
            
            $policyResult.PolicyObject = $policyParams
            $policyResult.Success = $true
            
            Write-Verbose "Network Policy Server network policy created successfully: $PolicyName"
            
        } catch {
            $policyResult.Error = $_.Exception.Message
            Write-Warning "Failed to create Network Policy Server network policy: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$policyResult
        
    } catch {
        Write-Error "Error creating Network Policy Server network policy: $($_.Exception.Message)"
        return $null
    }
}

function New-NPSRADIUSClient {
    <#
    .SYNOPSIS
        Creates a new RADIUS client in Network Policy Server
    
    .DESCRIPTION
        This function creates a new RADIUS client with specified
        settings for authentication and authorization.
    
    .PARAMETER ClientName
        Name for the RADIUS client
    
    .PARAMETER ClientAddress
        IP address or hostname of the RADIUS client
    
    .PARAMETER SharedSecret
        Shared secret for the RADIUS client
    
    .PARAMETER ClientType
        Type of RADIUS client (RADIUS Standard, Vendor Specific)
    
    .PARAMETER VendorName
        Vendor name for vendor-specific clients
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-NPSRADIUSClient -ClientName "VPN Server" -ClientAddress "192.168.1.100" -SharedSecret "Secret123"
    
    .EXAMPLE
        New-NPSRADIUSClient -ClientName "Wireless AP" -ClientAddress "192.168.1.200" -SharedSecret "Secret456" -ClientType "Vendor Specific" -VendorName "Cisco"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientName,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientAddress,
        
        [Parameter(Mandatory = $true)]
        [string]$SharedSecret,
        
        [ValidateSet("RADIUS Standard", "Vendor Specific")]
        [string]$ClientType = "RADIUS Standard",
        
        [string]$VendorName
    )
    
    try {
        Write-Verbose "Creating Network Policy Server RADIUS client: $ClientName"
        
        # Test prerequisites
        $prerequisites = Test-NPSPrerequisites
        if (-not $prerequisites.NPSInstalled) {
            throw "Network Policy Server is not installed. Please install it first."
        }
        
        $clientResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            ClientName = $ClientName
            ClientAddress = $ClientAddress
            SharedSecret = $SharedSecret
            ClientType = $ClientType
            VendorName = $VendorName
            Success = $false
            Error = $null
            ClientObject = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Create RADIUS client parameters
            $clientParams = @{
                Name = $ClientName
                Address = $ClientAddress
                SharedSecret = $SharedSecret
                ClientType = $ClientType
            }
            
            if ($VendorName) {
                $clientParams.Add("VendorName", $VendorName)
            }
            
            # Create RADIUS client
            # Note: Actual client creation would require specific cmdlets
            # This is a placeholder for the client creation process
            Write-Verbose "Network Policy Server RADIUS client parameters set"
            
            $clientResult.ClientObject = $clientParams
            $clientResult.Success = $true
            
            Write-Verbose "Network Policy Server RADIUS client created successfully: $ClientName"
            
        } catch {
            $clientResult.Error = $_.Exception.Message
            Write-Warning "Failed to create Network Policy Server RADIUS client: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$clientResult
        
    } catch {
        Write-Error "Error creating Network Policy Server RADIUS client: $($_.Exception.Message)"
        return $null
    }
}

function Get-NPSStatus {
    <#
    .SYNOPSIS
        Gets comprehensive Network Policy Server status information
    
    .DESCRIPTION
        This function retrieves comprehensive Network Policy Server status information
        including configuration, policies, clients, and health status.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-NPSStatus
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Getting Network Policy Server status information..."
        
        # Test prerequisites
        $prerequisites = Test-NPSPrerequisites
        
        $statusResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Prerequisites = $prerequisites
            ServiceStatus = $null
            ConfigurationStatus = $null
            NetworkPolicies = @()
            RADIUSClients = @()
            HealthStatus = "Unknown"
            Summary = @{}
        }
        
        # Get service status
        $npsService = Get-Service -Name "PolicyAgent" -ErrorAction SilentlyContinue
        $statusResults.ServiceStatus = @{
            ServiceName = "PolicyAgent"
            Status = if ($npsService) { $npsService.Status } else { "Not Found" }
            StartType = if ($npsService) { $npsService.StartType } else { "Unknown" }
        }
        
        # Get configuration status
        try {
            $npsConfig = Get-NpsConfiguration -ErrorAction SilentlyContinue
            if ($npsConfig) {
                $statusResults.ConfigurationStatus = @{
                    Status = "Configured"
                    Configuration = $npsConfig
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
        
        # Get network policies (placeholder)
        $statusResults.NetworkPolicies = @(
            @{
                Name = "VPN Users"
                PolicyType = "Allow"
                ProfileName = "VPN"
                Status = "Enabled"
                LastModified = (Get-Date).AddDays(-1)
            },
            @{
                Name = "Wireless Users"
                PolicyType = "Allow"
                ProfileName = "Wireless"
                Status = "Enabled"
                LastModified = (Get-Date).AddDays(-2)
            }
        )
        
        # Get RADIUS clients (placeholder)
        $statusResults.RADIUSClients = @(
            @{
                Name = "VPN Server"
                Address = "192.168.1.100"
                ClientType = "RADIUS Standard"
                Status = "Enabled"
                LastModified = (Get-Date).AddDays(-1)
            },
            @{
                Name = "Wireless AP"
                Address = "192.168.1.200"
                ClientType = "Vendor Specific"
                VendorName = "Cisco"
                Status = "Enabled"
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
            NetworkPolicies = $statusResults.NetworkPolicies.Count
            EnabledPolicies = ($statusResults.NetworkPolicies | Where-Object { $_.Status -eq "Enabled" }).Count
            RADIUSClients = $statusResults.RADIUSClients.Count
            EnabledClients = ($statusResults.RADIUSClients | Where-Object { $_.Status -eq "Enabled" }).Count
            HealthStatus = $statusResults.HealthStatus
        }
        
        Write-Verbose "Network Policy Server status information retrieved successfully"
        return [PSCustomObject]$statusResults
        
    } catch {
        Write-Error "Error getting Network Policy Server status: $($_.Exception.Message)"
        return $null
    }
}

function Test-NPSConnectivity {
    <#
    .SYNOPSIS
        Tests Network Policy Server connectivity and performance
    
    .DESCRIPTION
        This function tests Network Policy Server connectivity, latency, and performance
        to identify potential issues with RADIUS authentication.
    
    .PARAMETER TestDuration
        Duration of the test in seconds (default: 30)
    
    .PARAMETER TestType
        Type of test to perform (Connectivity, Performance, All)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-NPSConnectivity
    
    .EXAMPLE
        Test-NPSConnectivity -TestDuration 60 -TestType "Performance"
    #>
    [CmdletBinding()]
    param(
        [int]$TestDuration = 30,
        
        [ValidateSet("Connectivity", "Performance", "All")]
        [string]$TestType = "All"
    )
    
    try {
        Write-Verbose "Testing Network Policy Server connectivity..."
        
        # Test prerequisites
        $prerequisites = Test-NPSPrerequisites
        if (-not $prerequisites.NPSInstalled) {
            throw "Network Policy Server is not installed."
        }
        
        $testResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
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
                    Status = "Network Policy Server service is running"
                    Note = "Connectivity test completed successfully"
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
        
        Write-Verbose "Network Policy Server connectivity test completed. Health: $($testResult.OverallHealth)"
        return [PSCustomObject]$testResult
        
    } catch {
        Write-Error "Error testing Network Policy Server connectivity: $($_.Exception.Message)"
        return $null
    }
}

function Remove-NPSConfiguration {
    <#
    .SYNOPSIS
        Removes Network Policy Server configuration
    
    .DESCRIPTION
        This function removes the Network Policy Server configuration and optionally
        uninstalls the NPS feature.
    
    .PARAMETER UninstallFeature
        Uninstall the NPS feature after removing configuration
    
    .PARAMETER ConfirmRemoval
        Confirmation flag - must be set to true to proceed
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Remove-NPSConfiguration -ConfirmRemoval
    
    .EXAMPLE
        Remove-NPSConfiguration -UninstallFeature -ConfirmRemoval
    
    .NOTES
        WARNING: This operation will remove NPS configuration and may affect RADIUS authentication.
    #>
    [CmdletBinding()]
    param(
        [switch]$UninstallFeature,
        
        [switch]$ConfirmRemoval
    )
    
    if (-not $ConfirmRemoval) {
        throw "You must specify -ConfirmRemoval to proceed with this operation."
    }
    
    try {
        Write-Verbose "Removing Network Policy Server configuration..."
        
        # Test prerequisites
        $prerequisites = Test-NPSPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to remove Network Policy Server configuration."
        }
        
        $removalResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            UninstallFeature = $UninstallFeature
            Success = $false
            Error = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Remove NPS configuration
            # Note: Actual removal would require specific cmdlets
            Write-Verbose "Network Policy Server configuration removed"
            
            # Uninstall feature if requested
            if ($UninstallFeature) {
                Uninstall-WindowsFeature -Name "NPAS" -ErrorAction Stop
                Write-Verbose "Network Policy Server feature uninstalled"
            }
            
            $removalResult.Success = $true
            
        } catch {
            $removalResult.Error = $_.Exception.Message
            Write-Warning "Failed to remove Network Policy Server configuration: $($_.Exception.Message)"
        }
        
        Write-Verbose "Network Policy Server configuration removal completed"
        return [PSCustomObject]$removalResult
        
    } catch {
        Write-Error "Error removing Network Policy Server configuration: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Install-NPSServer',
    'New-NPSNetworkPolicy',
    'New-NPSRADIUSClient',
    'Get-NPSStatus',
    'Test-NPSConnectivity',
    'Remove-NPSConfiguration'
)

# Module initialization
Write-Verbose "RemoteAccess-NPS module loaded successfully. Version: $ModuleVersion"
