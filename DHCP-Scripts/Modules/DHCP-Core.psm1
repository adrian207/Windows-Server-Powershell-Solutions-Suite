#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Core DHCP PowerShell Module

.DESCRIPTION
    This module provides core functions for DHCP operations including installation,
    configuration, and basic management tasks.

.NOTES
    Author: DHCP PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-top
#>

# Module metadata
# $ModuleVersion = "1.0.0"  # Used for module documentation

# Import required modules
try {
    Import-Module DhcpServer -ErrorAction Stop
    Import-Module ServerManager -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Required modules not available. Some functions may not work properly."
}

#region Private Functions

function Test-DHCPPrerequisites {
    <#
    .SYNOPSIS
        Tests if the system meets DHCP prerequisites

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
        AdministratorPrivileges = $false
        DHCPInstalled = $false
        DomainMember = $false
        RequiredFeatures = $false
    }

    # Check Windows version
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -ge 10 -or ($osVersion.Major -eq 6 -and $osVersion.Minor -ge 2)) {
        $prerequisites.WindowsVersion = $true
    }

    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        $prerequisites.PowerShellVersion = $true
    }

    # Check administrator privileges
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $prerequisites.AdministratorPrivileges = $true
    }

    # Check if DHCP is installed
    try {
        $dhcpFeature = Get-WindowsFeature -Name DHCP -ErrorAction Stop
        if ($dhcpFeature.InstallState -eq "Installed") {
            $prerequisites.DHCPInstalled = $true
        }
    } catch {
        Write-Warning "Could not check DHCP installation status"
    }

    # Check domain membership
    try {
        $domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain
        if ($domain -ne $env:COMPUTERNAME) {
            $prerequisites.DomainMember = $true
        }
    } catch {
        Write-Warning "Could not check domain membership"
    }

    # Check required features
    try {
        $requiredFeatures = @("DHCP", "RSAT-DHCP")
        $installedFeatures = Get-WindowsFeature | Where-Object { $_.InstallState -eq "Installed" -and $_.Name -in $requiredFeatures }
        if ($installedFeatures.Count -eq $requiredFeatures.Count) {
            $prerequisites.RequiredFeatures = $true
        }
    } catch {
        Write-Warning "Could not check required features"
    }

    return $prerequisites
}

function Get-DHCPServerStatus {
    <#
    .SYNOPSIS
        Gets the current status of DHCP server

    .DESCRIPTION
        Returns comprehensive status information about the DHCP server

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param()

    $status = @{
        Success = $false
        ServiceStatus = $null
        ServerConfiguration = $null
        ScopeCount = 0
        LeaseCount = 0
        Error = $null
    }

    try {
        # Check DHCP service status
        $dhcpService = Get-Service -Name DHCPServer -ErrorAction Stop
        $status.ServiceStatus = @{
            Name = $dhcpService.Name
            Status = $dhcpService.Status
            StartType = $dhcpService.StartType
        }

        # Get DHCP server configuration
        $dhcpConfig = Get-DhcpServerConfiguration -ErrorAction Stop
        $status.ServerConfiguration = @{
            Authorized = $dhcpConfig.Authorized
            DatabasePath = $dhcpConfig.DatabasePath
            BackupPath = $dhcpConfig.BackupPath
            AuditLogPath = $dhcpConfig.AuditLogPath
        }

        # Get scope count
        $scopes = Get-DhcpServerv4Scope -ErrorAction Stop
        $status.ScopeCount = $scopes.Count

        # Get lease count
        $leases = Get-DhcpServerv4Lease -ErrorAction Stop
        $status.LeaseCount = $leases.Count

        $status.Success = $true
    } catch {
        $status.Error = $_.Exception.Message
        Write-Error "Failed to get DHCP server status: $($_.Exception.Message)"
    }

    return $status
}

#endregion

#region Public Functions

function Install-DHCPServer {
    <#
    .SYNOPSIS
        Installs DHCP Server role

    .DESCRIPTION
        Installs the DHCP Server role and required management tools

    .PARAMETER IncludeManagementTools
        Include DHCP management tools

    .PARAMETER RestartRequired
        Whether a restart is required

    .EXAMPLE
        Install-DHCPServer -IncludeManagementTools

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$IncludeManagementTools,

        [Parameter(Mandatory = $false)]
        [switch]$RestartRequired
    )

    $result = @{
        Success = $false
        FeaturesInstalled = @()
        RestartRequired = $false
        Error = $null
    }

    try {
        Write-Host "Installing DHCP Server role..." -ForegroundColor Green

        # Install DHCP Server feature
        $dhcpFeature = Install-WindowsFeature -Name DHCP -IncludeManagementTools:$IncludeManagementTools -ErrorAction Stop
        $result.FeaturesInstalled += "DHCP"

        if ($dhcpFeature.RestartNeeded -eq "Yes") {
            $result.RestartRequired = $true
        }

        # Install RSAT-DHCP if management tools requested
        if ($IncludeManagementTools) {
            Install-WindowsFeature -Name RSAT-DHCP -ErrorAction Stop
            $result.FeaturesInstalled += "RSAT-DHCP"
        }

        Write-Host "DHCP Server role installed successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to install DHCP Server role: $($_.Exception.Message)"
    }

    return $result
}

function New-DHCPScope {
    <#
    .SYNOPSIS
        Creates a new DHCP scope

    .DESCRIPTION
        Creates a new DHCP scope with specified configuration

    .PARAMETER ScopeName
        Name of the scope

    .PARAMETER StartRange
        Start IP address of the scope

    .PARAMETER EndRange
        End IP address of the scope

    .PARAMETER SubnetMask
        Subnet mask for the scope

    .PARAMETER LeaseDuration
        Lease duration for the scope

    .PARAMETER Description
        Description for the scope

    .PARAMETER State
        State of the scope (Active, Inactive)

    .EXAMPLE
        New-DHCPScope -ScopeName "Production" -StartRange "192.168.1.100" -EndRange "192.168.1.200" -SubnetMask "255.255.255.0"

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScopeName,

        [Parameter(Mandatory = $true)]
        [string]$StartRange,

        [Parameter(Mandatory = $true)]
        [string]$EndRange,

        [Parameter(Mandatory = $true)]
        [string]$SubnetMask,

        [Parameter(Mandatory = $false)]
        [TimeSpan]$LeaseDuration = (New-TimeSpan -Days 8),

        [Parameter(Mandatory = $false)]
        [string]$Description = "",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Active", "Inactive")]
        [string]$State = "Active"
    )

    $result = @{
        Success = $false
        ScopeName = $ScopeName
        ScopeId = $null
        Error = $null
    }

    try {
        Write-Host "Creating DHCP scope: $ScopeName" -ForegroundColor Green

        $scopeParams = @{
            Name = $ScopeName
            StartRange = $StartRange
            EndRange = $EndRange
            SubnetMask = $SubnetMask
            LeaseDuration = $LeaseDuration
            State = $State
        }

        if ($Description) {
            $scopeParams.Description = $Description
        }

        $scope = Add-DhcpServerv4Scope @scopeParams -ErrorAction Stop

        Write-Host "DHCP scope '$ScopeName' created successfully!" -ForegroundColor Green
        $result.Success = $true
        $result.ScopeId = $scope.ScopeId

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to create DHCP scope '$ScopeName': $($_.Exception.Message)"
    }

    return $result
}

function Set-DHCPOptions {
    <#
    .SYNOPSIS
        Sets DHCP options for a scope

    .DESCRIPTION
        Configures DHCP options for a specific scope

    .PARAMETER ScopeId
        Scope ID to configure options for

    .PARAMETER Router
        Router IP address (Option 3)

    .PARAMETER DNSServers
        Array of DNS server IP addresses (Option 6)

    .PARAMETER DomainName
        DNS domain name (Option 15)

    .PARAMETER LeaseTime
        Lease time in hours (Option 51)

    .PARAMETER CustomOptions
        Hashtable of custom options

    .EXAMPLE
        Set-DHCPOptions -ScopeId "192.168.1.0" -Router "192.168.1.1" -DNSServers @("8.8.8.8", "8.8.4.4")

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScopeId,

        [Parameter(Mandatory = $false)]
        [string]$Router,

        [Parameter(Mandatory = $false)]
        [string[]]$DNSServers,

        [Parameter(Mandatory = $false)]
        [string]$DomainName,

        [Parameter(Mandatory = $false)]
        [int]$LeaseTime,

        [Parameter(Mandatory = $false)]
        [hashtable]$CustomOptions
    )

    $result = @{
        Success = $false
        ScopeId = $ScopeId
        OptionsConfigured = @()
        Error = $null
    }

    try {
        Write-Host "Configuring DHCP options for scope: $ScopeId" -ForegroundColor Green

        # Configure Router (Option 3)
        if ($Router) {
            Set-DhcpServerv4OptionValue -ScopeId $ScopeId -OptionId 3 -Value $Router -ErrorAction Stop
            $result.OptionsConfigured += "Router (Option 3)"
        }

        # Configure DNS Servers (Option 6)
        if ($DNSServers) {
            Set-DhcpServerv4OptionValue -ScopeId $ScopeId -OptionId 6 -Value $DNSServers -ErrorAction Stop
            $result.OptionsConfigured += "DNS Servers (Option 6)"
        }

        # Configure Domain Name (Option 15)
        if ($DomainName) {
            Set-DhcpServerv4OptionValue -ScopeId $ScopeId -OptionId 15 -Value $DomainName -ErrorAction Stop
            $result.OptionsConfigured += "Domain Name (Option 15)"
        }

        # Configure Lease Time (Option 51)
        if ($LeaseTime) {
            $leaseDuration = New-TimeSpan -Hours $LeaseTime
            Set-DhcpServerv4Scope -ScopeId $ScopeId -LeaseDuration $leaseDuration -ErrorAction Stop
            $result.OptionsConfigured += "Lease Time (Option 51)"
        }

        # Configure custom options
        if ($CustomOptions) {
            foreach ($option in $CustomOptions.GetEnumerator()) {
                Set-DhcpServerv4OptionValue -ScopeId $ScopeId -OptionId $option.Key -Value $option.Value -ErrorAction Stop
                $result.OptionsConfigured += "Custom Option $($option.Key)"
            }
        }

        Write-Host "DHCP options configured successfully for scope '$ScopeId'!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to configure DHCP options for scope '$ScopeId': $($_.Exception.Message)"
    }

    return $result
}

function Add-DHCPReservation {
    <#
    .SYNOPSIS
        Adds a DHCP reservation

    .DESCRIPTION
        Creates a DHCP reservation for a specific MAC address

    .PARAMETER ScopeId
        Scope ID for the reservation

    .PARAMETER IPAddress
        IP address to reserve

    .PARAMETER ClientId
        MAC address or client identifier

    .PARAMETER Name
        Name for the reservation

    .PARAMETER Description
        Description for the reservation

    .EXAMPLE
        Add-DHCPReservation -ScopeId "192.168.1.0" -IPAddress "192.168.1.50" -ClientId "00-11-22-33-44-55" -Name "Server01"

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScopeId,

        [Parameter(Mandatory = $true)]
        [string]$IPAddress,

        [Parameter(Mandatory = $true)]
        [string]$ClientId,

        [Parameter(Mandatory = $false)]
        [string]$Name = "",

        [Parameter(Mandatory = $false)]
        [string]$Description = ""
    )

    $result = @{
        Success = $false
        ScopeId = $ScopeId
        IPAddress = $IPAddress
        ClientId = $ClientId
        Error = $null
    }

    try {
        Write-Host "Adding DHCP reservation: $IPAddress for $ClientId" -ForegroundColor Green

        $reservationParams = @{
            ScopeId = $ScopeId
            IPAddress = $IPAddress
            ClientId = $ClientId
        }

        if ($Name) {
            $reservationParams.Name = $Name
        }

        if ($Description) {
            $reservationParams.Description = $Description
        }

        Add-DhcpServerv4Reservation @reservationParams -ErrorAction Stop

        Write-Host "DHCP reservation added successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to add DHCP reservation: $($_.Exception.Message)"
    }

    return $result
}

function Enable-DHCPFailover {
    <#
    .SYNOPSIS
        Enables DHCP failover

    .DESCRIPTION
        Configures DHCP failover between two servers

    .PARAMETER PartnerServer
        Partner DHCP server name or IP

    .PARAMETER ScopeId
        Scope ID to configure failover for

    .PARAMETER FailoverMode
        Failover mode (LoadBalance, HotStandby)

    .PARAMETER LoadBalancePercentage
        Load balance percentage (for LoadBalance mode)

    .PARAMETER MaxClientLeadTime
        Maximum client lead time

    .EXAMPLE
        Enable-DHCPFailover -PartnerServer "DHCP-Server2" -ScopeId "192.168.1.0" -FailoverMode "LoadBalance"

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PartnerServer,

        [Parameter(Mandatory = $true)]
        [string]$ScopeId,

        [Parameter(Mandatory = $true)]
        [ValidateSet("LoadBalance", "HotStandby")]
        [string]$FailoverMode,

        [Parameter(Mandatory = $false)]
        [int]$LoadBalancePercentage = 50,

        [Parameter(Mandatory = $false)]
        [TimeSpan]$MaxClientLeadTime = (New-TimeSpan -Hours 1)
    )

    $result = @{
        Success = $false
        PartnerServer = $PartnerServer
        ScopeId = $ScopeId
        FailoverMode = $FailoverMode
        Error = $null
    }

    try {
        Write-Host "Enabling DHCP failover for scope: $ScopeId" -ForegroundColor Green

        $failoverParams = @{
            ComputerName = $PartnerServer
            ScopeId = $ScopeId
            Name = "Failover-$ScopeId"
            MaxClientLeadTime = $MaxClientLeadTime
        }

        if ($FailoverMode -eq "LoadBalance") {
            $failoverParams.LoadBalancePercentage = $LoadBalancePercentage
        }

        Add-DhcpServerv4Failover @failoverParams -ErrorAction Stop

        Write-Host "DHCP failover enabled successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to enable DHCP failover: $($_.Exception.Message)"
    }

    return $result
}

function Enable-DHCPAuditLogging {
    <#
    .SYNOPSIS
        Enables DHCP audit logging

    .DESCRIPTION
        Configures DHCP audit logging for compliance and troubleshooting

    .PARAMETER AuditLogPath
        Path for audit log files

    .PARAMETER EnableAuditLog
        Enable audit logging

    .PARAMETER DiskSpaceCheckInterval
        Disk space check interval in hours

    .PARAMETER MaxLogFileSize
        Maximum log file size in MB

    .EXAMPLE
        Enable-DHCPAuditLogging -AuditLogPath "C:\DHCP\AuditLogs" -EnableAuditLog

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$AuditLogPath = "C:\DHCP\AuditLogs",

        [Parameter(Mandatory = $false)]
        [switch]$EnableAuditLog,

        [Parameter(Mandatory = $false)]
        [int]$DiskSpaceCheckInterval = 24,

        [Parameter(Mandatory = $false)]
        [int]$MaxLogFileSize = 70
    )

    $result = @{
        Success = $false
        AuditLogPath = $AuditLogPath
        EnableAuditLog = $EnableAuditLog
        Error = $null
    }

    try {
        Write-Host "Configuring DHCP audit logging..." -ForegroundColor Green

        # Create audit log directory if it doesn't exist
        if (-not (Test-Path $AuditLogPath)) {
            New-Item -Path $AuditLogPath -ItemType Directory -Force
        }

        # Configure audit logging
        Set-DhcpServerConfiguration -AuditLogPath $AuditLogPath -ErrorAction Stop

        if ($EnableAuditLog) {
            Set-DhcpServerConfiguration -AuditLogEnabled $true -ErrorAction Stop
        }

        # Configure disk space check interval
        Set-DhcpServerConfiguration -DiskSpaceCheckInterval $DiskSpaceCheckInterval -ErrorAction Stop

        # Configure maximum log file size
        Set-DhcpServerConfiguration -MaxLogFileSize $MaxLogFileSize -ErrorAction Stop

        Write-Host "DHCP audit logging configured successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to configure DHCP audit logging: $($_.Exception.Message)"
    }

    return $result
}

function Get-DHCPStatistics {
    <#
    .SYNOPSIS
        Gets DHCP server statistics

    .DESCRIPTION
        Returns comprehensive DHCP server performance statistics

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param()

    $result = @{
        Success = $false
        Statistics = $null
        Error = $null
    }

    try {
        Write-Host "Collecting DHCP statistics..." -ForegroundColor Green

        $stats = Get-DhcpServerv4Statistics -ErrorAction Stop

        $result.Statistics = @{
            TotalScopes = $stats.TotalScopes
            ActiveScopes = $stats.ActiveScopes
            TotalAddresses = $stats.TotalAddresses
            InUseAddresses = $stats.InUseAddresses
            AvailableAddresses = $stats.AvailableAddresses
            TotalReservations = $stats.TotalReservations
            TotalLeases = $stats.TotalLeases
            ActiveLeases = $stats.ActiveLeases
            ExpiredLeases = $stats.ExpiredLeases
            DeclinedLeases = $stats.DeclinedLeases
        }

        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to get DHCP statistics: $($_.Exception.Message)"
    }

    return $result
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Test-DHCPPrerequisites',
    'Get-DHCPServerStatus',
    'Install-DHCPServer',
    'New-DHCPScope',
    'Set-DHCPOptions',
    'Add-DHCPReservation',
    'Enable-DHCPFailover',
    'Enable-DHCPAuditLogging',
    'Get-DHCPStatistics'
)
