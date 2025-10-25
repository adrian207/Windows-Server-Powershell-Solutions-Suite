#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Core DNS PowerShell Module

.DESCRIPTION
    This module provides core functions for DNS operations including installation,
    configuration, and basic management tasks.

.NOTES
    Author: DNS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top
#>

# Module metadata
$ModuleVersion = "1.0.0"

# Import required modules
try {
    Import-Module DnsServer -ErrorAction Stop
    Import-Module ServerManager -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Required modules not available. Some functions may not work properly."
}

#region Private Functions

function Test-DNSPrerequisites {
    <#
    .SYNOPSIS
        Tests if the system meets DNS prerequisites

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
        DNSInstalled = $false
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

    # Check if DNS is installed
    try {
        $dnsFeature = Get-WindowsFeature -Name DNS -ErrorAction Stop
        if ($dnsFeature.InstallState -eq "Installed") {
            $prerequisites.DNSInstalled = $true
        }
    } catch {
        Write-Warning "Could not check DNS installation status"
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
        $requiredFeatures = @("DNS", "RSAT-DNS-Server")
        $installedFeatures = Get-WindowsFeature | Where-Object { $_.InstallState -eq "Installed" -and $_.Name -in $requiredFeatures }
        if ($installedFeatures.Count -eq $requiredFeatures.Count) {
            $prerequisites.RequiredFeatures = $true
        }
    } catch {
        Write-Warning "Could not check required features"
    }

    return $prerequisites
}

function Get-DNSServerStatus {
    <#
    .SYNOPSIS
        Gets the current status of DNS server

    .DESCRIPTION
        Returns comprehensive status information about the DNS server

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param()

    $status = @{
        Success = $false
        ServiceStatus = $null
        ServerConfiguration = $null
        ZoneCount = 0
        ForwarderCount = 0
        Error = $null
    }

    try {
        # Check DNS service status
        $dnsService = Get-Service -Name DNS -ErrorAction Stop
        $status.ServiceStatus = @{
            Name = $dnsService.Name
            Status = $dnsService.Status
            StartType = $dnsService.StartType
        }

        # Get DNS server configuration
        $dnsConfig = Get-DnsServerConfiguration -ErrorAction Stop
        $status.ServerConfiguration = @{
            Forwarders = $dnsConfig.Forwarders
            LogLevel = $dnsConfig.LogLevel
            EnableDnsSec = $dnsConfig.EnableDnsSec
            EnableIPv6 = $dnsConfig.EnableIPv6
        }

        # Get zone count
        $zones = Get-DnsServerZone -ErrorAction Stop
        $status.ZoneCount = $zones.Count

        # Get forwarder count
        $status.ForwarderCount = $dnsConfig.Forwarders.Count

        $status.Success = $true
    } catch {
        $status.Error = $_.Exception.Message
        Write-Error "Failed to get DNS server status: $($_.Exception.Message)"
    }

    return $status
}

#endregion

#region Public Functions

function Install-DNSServer {
    <#
    .SYNOPSIS
        Installs DNS Server role

    .DESCRIPTION
        Installs the DNS Server role and required management tools

    .PARAMETER IncludeManagementTools
        Include DNS management tools

    .PARAMETER RestartRequired
        Whether a restart is required

    .EXAMPLE
        Install-DNSServer -IncludeManagementTools

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
        Write-Host "Installing DNS Server role..." -ForegroundColor Green

        # Install DNS Server feature
        $dnsFeature = Install-WindowsFeature -Name DNS -IncludeManagementTools:$IncludeManagementTools -ErrorAction Stop
        $result.FeaturesInstalled += "DNS"

        if ($dnsFeature.RestartNeeded -eq "Yes") {
            $result.RestartRequired = $true
        }

        # Install RSAT-DNS-Server if management tools requested
        if ($IncludeManagementTools) {
            $rsatFeature = Install-WindowsFeature -Name RSAT-DNS-Server -ErrorAction Stop
            $result.FeaturesInstalled += "RSAT-DNS-Server"
        }

        Write-Host "DNS Server role installed successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to install DNS Server role: $($_.Exception.Message)"
    }

    return $result
}

function New-DNSZone {
    <#
    .SYNOPSIS
        Creates a new DNS zone

    .DESCRIPTION
        Creates a new DNS zone with specified configuration

    .PARAMETER ZoneName
        Name of the zone to create

    .PARAMETER ZoneType
        Type of zone (Primary, Secondary, Stub, Forwarder)

    .PARAMETER ReplicationScope
        Replication scope for AD-integrated zones

    .PARAMETER DynamicUpdate
        Dynamic update setting

    .PARAMETER AgingEnabled
        Enable aging/scavenging

    .EXAMPLE
        New-DNSZone -ZoneName "contoso.com" -ZoneType "Primary" -ReplicationScope "Domain"

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZoneName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Primary", "Secondary", "Stub", "Forwarder")]
        [string]$ZoneType,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Domain", "Forest", "Legacy")]
        [string]$ReplicationScope = "Domain",

        [Parameter(Mandatory = $false)]
        [ValidateSet("None", "NonsecureAndSecure", "Secure")]
        [string]$DynamicUpdate = "Secure",

        [Parameter(Mandatory = $false)]
        [switch]$AgingEnabled
    )

    $result = @{
        Success = $false
        ZoneName = $ZoneName
        ZoneType = $ZoneType
        Error = $null
    }

    try {
        Write-Host "Creating DNS zone: $ZoneName" -ForegroundColor Green

        $zoneParams = @{
            Name = $ZoneName
            ZoneType = $ZoneType
            DynamicUpdate = $DynamicUpdate
        }

        if ($ZoneType -eq "Primary" -and $ReplicationScope) {
            $zoneParams.ReplicationScope = $ReplicationScope
        }

        if ($AgingEnabled) {
            $zoneParams.Aging = $true
        }

        $zone = Add-DnsServerPrimaryZone @zoneParams -ErrorAction Stop

        Write-Host "DNS zone '$ZoneName' created successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to create DNS zone '$ZoneName': $($_.Exception.Message)"
    }

    return $result
}

function Add-DNSRecord {
    <#
    .SYNOPSIS
        Adds a DNS record to a zone

    .DESCRIPTION
        Adds various types of DNS records to a specified zone

    .PARAMETER ZoneName
        Name of the zone

    .PARAMETER RecordType
        Type of record (A, AAAA, CNAME, MX, SRV, TXT, PTR)

    .PARAMETER Name
        Name of the record

    .PARAMETER Value
        Value of the record

    .PARAMETER TTL
        Time to live for the record

    .PARAMETER Priority
        Priority for MX and SRV records

    .PARAMETER Weight
        Weight for SRV records

    .PARAMETER Port
        Port for SRV records

    .EXAMPLE
        Add-DNSRecord -ZoneName "contoso.com" -RecordType "A" -Name "www" -Value "192.168.1.100"

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZoneName,

        [Parameter(Mandatory = $true)]
        [ValidateSet("A", "AAAA", "CNAME", "MX", "SRV", "TXT", "PTR")]
        [string]$RecordType,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $false)]
        [TimeSpan]$TTL = (New-TimeSpan -Hours 1),

        [Parameter(Mandatory = $false)]
        [int]$Priority = 0,

        [Parameter(Mandatory = $false)]
        [int]$Weight = 0,

        [Parameter(Mandatory = $false)]
        [int]$Port = 0
    )

    $result = @{
        Success = $false
        ZoneName = $ZoneName
        RecordType = $RecordType
        Name = $Name
        Value = $Value
        Error = $null
    }

    try {
        Write-Host "Adding DNS record: $Name.$ZoneName ($RecordType)" -ForegroundColor Green

        $recordParams = @{
            ZoneName = $ZoneName
            Name = $Name
            TTL = $TTL
        }

        switch ($RecordType) {
            "A" {
                $recordParams.Ipv4Address = $Value
                $record = Add-DnsServerResourceRecordA @recordParams -ErrorAction Stop
            }
            "AAAA" {
                $recordParams.Ipv6Address = $Value
                $record = Add-DnsServerResourceRecordAAAA @recordParams -ErrorAction Stop
            }
            "CNAME" {
                $recordParams.HostNameAlias = $Value
                $record = Add-DnsServerResourceRecordCName @recordParams -ErrorAction Stop
            }
            "MX" {
                $recordParams.MailExchange = $Value
                $recordParams.Preference = $Priority
                $record = Add-DnsServerResourceRecordMX @recordParams -ErrorAction Stop
            }
            "SRV" {
                $recordParams.DomainName = $Value
                $recordParams.Priority = $Priority
                $recordParams.Weight = $Weight
                $recordParams.Port = $Port
                $record = Add-DnsServerResourceRecordSrv @recordParams -ErrorAction Stop
            }
            "TXT" {
                $recordParams.DescriptiveText = $Value
                $record = Add-DnsServerResourceRecordTxt @recordParams -ErrorAction Stop
            }
            "PTR" {
                $recordParams.PtrDomainName = $Value
                $record = Add-DnsServerResourceRecordPtr @recordParams -ErrorAction Stop
            }
        }

        Write-Host "DNS record '$Name.$ZoneName' ($RecordType) added successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to add DNS record '$Name.$ZoneName' ($RecordType): $($_.Exception.Message)"
    }

    return $result
}

function Set-DNSForwarders {
    <#
    .SYNOPSIS
        Configures DNS forwarders

    .DESCRIPTION
        Sets DNS forwarders for external resolution

    .PARAMETER Forwarders
        Array of forwarder IP addresses

    .PARAMETER EnableRecursion
        Enable recursion for forwarders

    .EXAMPLE
        Set-DNSForwarders -Forwarders @("8.8.8.8", "8.8.4.4") -EnableRecursion

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Forwarders,

        [Parameter(Mandatory = $false)]
        [switch]$EnableRecursion
    )

    $result = @{
        Success = $false
        Forwarders = $Forwarders
        Error = $null
    }

    try {
        Write-Host "Configuring DNS forwarders..." -ForegroundColor Green

        Set-DnsServerForwarder -IPAddress $Forwarders -ErrorAction Stop

        if ($EnableRecursion) {
            Set-DnsServerRecursion -Enable $true -ErrorAction Stop
        }

        Write-Host "DNS forwarders configured successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to configure DNS forwarders: $($_.Exception.Message)"
    }

    return $result
}

function Enable-DNSLogging {
    <#
    .SYNOPSIS
        Enables DNS logging

    .DESCRIPTION
        Configures DNS query and debug logging

    .PARAMETER LogPath
        Path for DNS log files

    .PARAMETER LogLevel
        Logging level (Errors, Warnings, All)

    .PARAMETER EnableQueryLogging
        Enable query logging

    .PARAMETER EnableDebugLogging
        Enable debug logging

    .EXAMPLE
        Enable-DNSLogging -LogPath "C:\DNS\Logs" -LogLevel "All" -EnableQueryLogging

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$LogPath = "C:\DNS\Logs",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Errors", "Warnings", "All")]
        [string]$LogLevel = "All",

        [Parameter(Mandatory = $false)]
        [switch]$EnableQueryLogging,

        [Parameter(Mandatory = $false)]
        [switch]$EnableDebugLogging
    )

    $result = @{
        Success = $false
        LogPath = $LogPath
        LogLevel = $LogLevel
        Error = $null
    }

    try {
        Write-Host "Configuring DNS logging..." -ForegroundColor Green

        # Create log directory if it doesn't exist
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force
        }

        # Configure DNS server logging
        $logLevelValue = switch ($LogLevel) {
            "Errors" { 0 }
            "Warnings" { 1 }
            "All" { 2 }
        }

        Set-DnsServerDiagnostics -LogLevel $logLevelValue -ErrorAction Stop

        if ($EnableQueryLogging) {
            Set-DnsServerDiagnostics -EnableLoggingForQuery $true -ErrorAction Stop
        }

        if ($EnableDebugLogging) {
            Set-DnsServerDiagnostics -EnableLoggingForDebug $true -ErrorAction Stop
        }

        Write-Host "DNS logging configured successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to configure DNS logging: $($_.Exception.Message)"
    }

    return $result
}

function Get-DNSStatistics {
    <#
    .SYNOPSIS
        Gets DNS server statistics

    .DESCRIPTION
        Returns comprehensive DNS server performance statistics

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
        Write-Host "Collecting DNS statistics..." -ForegroundColor Green

        $stats = Get-DnsServerStatistics -ErrorAction Stop

        $result.Statistics = @{
            TotalQueries = $stats.TotalQueries
            TotalResponses = $stats.TotalResponses
            QueriesPerSecond = $stats.QueriesPerSecond
            ResponsesPerSecond = $stats.ResponsesPerSecond
            CacheHits = $stats.CacheHits
            CacheMisses = $stats.CacheMisses
            RecursiveQueries = $stats.RecursiveQueries
            IterativeQueries = $stats.IterativeQueries
            FailedQueries = $stats.FailedQueries
            TimeoutQueries = $stats.TimeoutQueries
        }

        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to get DNS statistics: $($_.Exception.Message)"
    }

    return $result
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Test-DNSPrerequisites',
    'Get-DNSServerStatus',
    'Install-DNSServer',
    'New-DNSZone',
    'Add-DNSRecord',
    'Set-DNSForwarders',
    'Enable-DNSLogging',
    'Get-DNSStatistics'
)
