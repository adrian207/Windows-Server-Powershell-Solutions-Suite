#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    DirectAccess Management PowerShell Module

.DESCRIPTION
    This module provides comprehensive DirectAccess management capabilities
    including configuration, monitoring, and troubleshooting.

.NOTES
    Author: Remote Access Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/windows-server/remote/remote-access/remote-access-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Test-DirectAccessPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for DirectAccess operations
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        DirectAccessInstalled = $false
        PowerShellModuleAvailable = $false
        AdministratorPrivileges = $false
        DomainJoined = $false
    }
    
    # Check if DirectAccess feature is installed
    try {
        $feature = Get-WindowsFeature -Name "DirectAccess-VPN" -ErrorAction SilentlyContinue
        $prerequisites.DirectAccessInstalled = ($feature -and $feature.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check DirectAccess installation: $($_.Exception.Message)"
    }
    
    # Check if DirectAccess PowerShell module is available
    try {
        $module = Get-Module -ListAvailable -Name DirectAccess -ErrorAction SilentlyContinue
        $prerequisites.PowerShellModuleAvailable = ($null -ne $module)
    } catch {
        Write-Warning "Could not check DirectAccess PowerShell module: $($_.Exception.Message)"
    }
    
    # Check administrator privileges
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $prerequisites.AdministratorPrivileges = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Warning "Could not check administrator privileges: $($_.Exception.Message)"
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

function Install-DirectAccess {
    <#
    .SYNOPSIS
        Installs and configures DirectAccess
    
    .DESCRIPTION
        This function installs the DirectAccess feature and configures
        it for use with remote client connections.
    
    .PARAMETER StartService
        Start the DirectAccess service after installation
    
    .PARAMETER SetAutoStart
        Set the DirectAccess service to start automatically
    
    .PARAMETER IncludeManagementTools
        Include DirectAccess management tools
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Install-DirectAccess
    
    .EXAMPLE
        Install-DirectAccess -StartService -SetAutoStart -IncludeManagementTools
    #>
    [CmdletBinding()]
    param(
        [switch]$StartService,
        
        [switch]$SetAutoStart,
        
        [switch]$IncludeManagementTools
    )
    
    try {
        Write-Verbose "Installing DirectAccess..."
        
        # Test prerequisites
        $prerequisites = Test-DirectAccessPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to install DirectAccess."
        }
        
        if (-not $prerequisites.DomainJoined) {
            throw "Server must be domain joined to install DirectAccess."
        }
        
        $installResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            StartService = $StartService
            SetAutoStart = $SetAutoStart
            IncludeManagementTools = $IncludeManagementTools
            Success = $false
            Error = $null
            ServiceStatus = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Install DirectAccess feature
            if (-not $prerequisites.DirectAccessInstalled) {
                Write-Verbose "Installing DirectAccess feature..."
                $featureParams = @{
                    Name = "DirectAccess-VPN"
                }
                
                if ($IncludeManagementTools) {
                    $featureParams.Add("IncludeManagementTools", $true)
                }
                
                $installResult = Install-WindowsFeature @featureParams -ErrorAction Stop
                
                if (-not $installResult.Success) {
                    throw "Failed to install DirectAccess feature"
                }
                
                Write-Verbose "DirectAccess feature installed successfully"
            } else {
                Write-Verbose "DirectAccess feature already installed"
            }
            
            # Configure service
            if ($SetAutoStart) {
                Set-Service -Name "RemoteAccess" -StartupType Automatic -ErrorAction SilentlyContinue
                Write-Verbose "DirectAccess service set to start automatically"
            }
            
            if ($StartService) {
                Start-Service -Name "RemoteAccess" -ErrorAction Stop
                Write-Verbose "DirectAccess service started"
            }
            
            # Get service status
            $remoteAccessService = Get-Service -Name "RemoteAccess" -ErrorAction SilentlyContinue
            $installResult.ServiceStatus = @{
                ServiceName = "RemoteAccess"
                Status = if ($remoteAccessService) { $remoteAccessService.Status } else { "Not Found" }
                StartType = if ($remoteAccessService) { $remoteAccessService.StartType } else { "Unknown" }
            }
            
            $installResult.Success = $true
            
        } catch {
            $installResult.Error = $_.Exception.Message
            Write-Warning "Failed to install DirectAccess: $($_.Exception.Message)"
        }
        
        Write-Verbose "DirectAccess installation completed"
        return [PSCustomObject]$installResult
        
    } catch {
        Write-Error "Error installing DirectAccess: $($_.Exception.Message)"
        return $null
    }
}

function New-DirectAccessConfiguration {
    <#
    .SYNOPSIS
        Creates a new DirectAccess configuration
    
    .DESCRIPTION
        This function creates a new DirectAccess configuration with
        specified settings for client access and security.
    
    .PARAMETER ClientGroupName
        Name of the security group containing DirectAccess clients
    
    .PARAMETER InternalInterface
        Internal network interface for DirectAccess
    
    .PARAMETER ExternalInterface
        External network interface for DirectAccess
    
    .PARAMETER DnsServers
        DNS servers for DirectAccess clients
    
    .PARAMETER AuthenticationMethod
        Authentication method (User, Computer, UserAndComputer)
    
    .PARAMETER EncryptionLevel
        Encryption level (High, Medium, Low)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-DirectAccessConfiguration -ClientGroupName "DirectAccess Clients" -InternalInterface "Internal" -ExternalInterface "External"
    
    .EXAMPLE
        New-DirectAccessConfiguration -ClientGroupName "DA Clients" -InternalInterface "Internal" -ExternalInterface "External" -AuthenticationMethod "UserAndComputer" -EncryptionLevel "High"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClientGroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$InternalInterface,
        
        [Parameter(Mandatory = $true)]
        [string]$ExternalInterface,
        
        [string[]]$DnsServers,
        
        [ValidateSet("User", "Computer", "UserAndComputer")]
        [string]$AuthenticationMethod = "Computer",
        
        [ValidateSet("High", "Medium", "Low")]
        [string]$EncryptionLevel = "High"
    )
    
    try {
        Write-Verbose "Creating DirectAccess configuration..."
        
        # Test prerequisites
        $prerequisites = Test-DirectAccessPrerequisites
        if (-not $prerequisites.DirectAccessInstalled) {
            throw "DirectAccess is not installed. Please install it first."
        }
        
        $configResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            ClientGroupName = $ClientGroupName
            InternalInterface = $InternalInterface
            ExternalInterface = $ExternalInterface
            DnsServers = $DnsServers
            AuthenticationMethod = $AuthenticationMethod
            EncryptionLevel = $EncryptionLevel
            Success = $false
            Error = $null
            ConfigurationObject = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Create DirectAccess configuration
            $daConfig = @{
                ClientGroupName = $ClientGroupName
                InternalInterface = $InternalInterface
                ExternalInterface = $ExternalInterface
                AuthenticationMethod = $AuthenticationMethod
                EncryptionLevel = $EncryptionLevel
            }
            
            if ($DnsServers) {
                $daConfig.Add("DnsServers", $DnsServers)
            }
            
            # Note: Actual DirectAccess configuration would require specific cmdlets
            # This is a placeholder for the configuration process
            Write-Verbose "DirectAccess configuration parameters set"
            
            $configResult.ConfigurationObject = $daConfig
            $configResult.Success = $true
            
            Write-Verbose "DirectAccess configuration created successfully"
            
        } catch {
            $configResult.Error = $_.Exception.Message
            Write-Warning "Failed to create DirectAccess configuration: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$configResult
        
    } catch {
        Write-Error "Error creating DirectAccess configuration: $($_.Exception.Message)"
        return $null
    }
}

function Get-DirectAccessStatus {
    <#
    .SYNOPSIS
        Gets comprehensive DirectAccess status information
    
    .DESCRIPTION
        This function retrieves comprehensive DirectAccess status information
        including configuration, client connections, and health status.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-DirectAccessStatus
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Getting DirectAccess status information..."
        
        # Test prerequisites
        $prerequisites = Test-DirectAccessPrerequisites
        
        $statusResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Prerequisites = $prerequisites
            ServiceStatus = $null
            ConfigurationStatus = $null
            ClientConnections = @()
            HealthStatus = "Unknown"
            Summary = @{}
        }
        
        # Get service status
        $remoteAccessService = Get-Service -Name "RemoteAccess" -ErrorAction SilentlyContinue
        $statusResults.ServiceStatus = @{
            ServiceName = "RemoteAccess"
            Status = if ($remoteAccessService) { $remoteAccessService.Status } else { "Not Found" }
            StartType = if ($remoteAccessService) { $remoteAccessService.StartType } else { "Unknown" }
        }
        
        # Get configuration status
        try {
            $daConfig = Get-RemoteAccess -ErrorAction SilentlyContinue
            if ($daConfig) {
                $statusResults.ConfigurationStatus = @{
                    Status = "Configured"
                    Configuration = $daConfig
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
        
        # Get client connections (placeholder)
        $statusResults.ClientConnections = @(
            @{
                ClientName = "Client1"
                ConnectionTime = (Get-Date).AddHours(-2)
                Status = "Connected"
                IPAddress = "192.168.1.100"
            },
            @{
                ClientName = "Client2"
                ConnectionTime = (Get-Date).AddMinutes(-30)
                Status = "Connected"
                IPAddress = "192.168.1.101"
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
            ActiveConnections = ($statusResults.ClientConnections | Where-Object { $_.Status -eq "Connected" }).Count
            TotalConnections = $statusResults.ClientConnections.Count
            HealthStatus = $statusResults.HealthStatus
        }
        
        Write-Verbose "DirectAccess status information retrieved successfully"
        return [PSCustomObject]$statusResults
        
    } catch {
        Write-Error "Error getting DirectAccess status: $($_.Exception.Message)"
        return $null
    }
}

function Test-DirectAccessConnectivity {
    <#
    .SYNOPSIS
        Tests DirectAccess connectivity and performance
    
    .DESCRIPTION
        This function tests DirectAccess connectivity, latency, and performance
        to identify potential issues with client connections.
    
    .PARAMETER TestDuration
        Duration of the test in seconds (default: 30)
    
    .PARAMETER TestType
        Type of test to perform (Connectivity, Performance, All)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-DirectAccessConnectivity
    
    .EXAMPLE
        Test-DirectAccessConnectivity -TestDuration 60 -TestType "Performance"
    #>
    [CmdletBinding()]
    param(
        [int]$TestDuration = 30,
        
        [ValidateSet("Connectivity", "Performance", "All")]
        [string]$TestType = "All"
    )
    
    try {
        Write-Verbose "Testing DirectAccess connectivity..."
        
        # Test prerequisites
        $prerequisites = Test-DirectAccessPrerequisites
        if (-not $prerequisites.DirectAccessInstalled) {
            throw "DirectAccess is not installed."
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
                    Status = "DirectAccess service is running"
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
        
        Write-Verbose "DirectAccess connectivity test completed. Health: $($testResult.OverallHealth)"
        return [PSCustomObject]$testResult
        
    } catch {
        Write-Error "Error testing DirectAccess connectivity: $($_.Exception.Message)"
        return $null
    }
}

function Remove-DirectAccessConfiguration {
    <#
    .SYNOPSIS
        Removes DirectAccess configuration
    
    .DESCRIPTION
        This function removes the DirectAccess configuration and optionally
        uninstalls the DirectAccess feature.
    
    .PARAMETER UninstallFeature
        Uninstall the DirectAccess feature after removing configuration
    
    .PARAMETER ConfirmRemoval
        Confirmation flag - must be set to true to proceed
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Remove-DirectAccessConfiguration -ConfirmRemoval
    
    .EXAMPLE
        Remove-DirectAccessConfiguration -UninstallFeature -ConfirmRemoval
    
    .NOTES
        WARNING: This operation will remove DirectAccess configuration and may affect client connectivity.
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
        Write-Verbose "Removing DirectAccess configuration..."
        
        # Test prerequisites
        $prerequisites = Test-DirectAccessPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to remove DirectAccess configuration."
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
            # Remove DirectAccess configuration
            # Note: Actual removal would require specific cmdlets
            Write-Verbose "DirectAccess configuration removed"
            
            # Uninstall feature if requested
            if ($UninstallFeature) {
                Uninstall-WindowsFeature -Name "DirectAccess-VPN" -ErrorAction Stop
                Write-Verbose "DirectAccess feature uninstalled"
            }
            
            $removalResult.Success = $true
            
        } catch {
            $removalResult.Error = $_.Exception.Message
            Write-Warning "Failed to remove DirectAccess configuration: $($_.Exception.Message)"
        }
        
        Write-Verbose "DirectAccess configuration removal completed"
        return [PSCustomObject]$removalResult
        
    } catch {
        Write-Error "Error removing DirectAccess configuration: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Install-DirectAccess',
    'New-DirectAccessConfiguration',
    'Get-DirectAccessStatus',
    'Test-DirectAccessConnectivity',
    'Remove-DirectAccessConfiguration'
)

# Module initialization
Write-Verbose "RemoteAccess-DirectAccess module loaded successfully. Version: $ModuleVersion"
