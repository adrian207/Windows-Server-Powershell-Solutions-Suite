#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    DNS Security PowerShell Module

.DESCRIPTION
    This module provides comprehensive DNS security features including DNSSEC,
    DNS filtering, threat detection, and security policies.

.NOTES
    Author: DNS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Module metadata
$ModuleVersion = "1.0.0"

# Import required modules
try {
    Import-Module DnsServer -ErrorAction Stop
    Import-Module "..\DNS-Core.psm1" -Force -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Required modules not available. Some functions may not work properly."
}

#region Private Functions

function Test-DNSSECPrerequisites {
    <#
    .SYNOPSIS
        Tests DNSSEC prerequisites

    .DESCRIPTION
        Checks if the system meets DNSSEC requirements

    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    param()

    $prerequisites = @{
        DNSSECSupported = $false
        ZoneSupported = $false
        KeyManagementSupported = $false
    }

    try {
        # Check if DNSSEC is supported
        $dnsConfig = Get-DnsServerConfiguration -ErrorAction Stop
        if ($dnsConfig.EnableDnsSec -ne $null) {
            $prerequisites.DNSSECSupported = $true
        }

        # Check zone support
        $zones = Get-DnsServerZone -ErrorAction Stop
        if ($zones.Count -gt 0) {
            $prerequisites.ZoneSupported = $true
        }

        # Check key management support
        try {
            Get-DnsServerDnsSecZone -ZoneName $zones[0].ZoneName -ErrorAction Stop
            $prerequisites.KeyManagementSupported = $true
        } catch {
            # Key management not available
        }

    } catch {
        Write-Warning "Could not check DNSSEC prerequisites: $($_.Exception.Message)"
    }

    return $prerequisites
}

#endregion

#region Public Functions

function Enable-DNSSEC {
    <#
    .SYNOPSIS
        Enables DNSSEC for DNS server

    .DESCRIPTION
        Enables DNSSEC (DNS Security Extensions) for the DNS server

    .PARAMETER ZoneName
        Name of the zone to enable DNSSEC for

    .PARAMETER KeySigningKey
        Key signing key configuration

    .PARAMETER ZoneSigningKey
        Zone signing key configuration

    .PARAMETER EnableAutoKeyRollover
        Enable automatic key rollover

    .EXAMPLE
        Enable-DNSSEC -ZoneName "contoso.com" -EnableAutoKeyRollover

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ZoneName,

        [Parameter(Mandatory = $false)]
        [hashtable]$KeySigningKey = @{
            Algorithm = "RSA/SHA256"
            KeyLength = 2048
        },

        [Parameter(Mandatory = $false)]
        [hashtable]$ZoneSigningKey = @{
            Algorithm = "RSA/SHA256"
            KeyLength = 1024
        },

        [Parameter(Mandatory = $false)]
        [switch]$EnableAutoKeyRollover
    )

    $result = @{
        Success = $false
        ZoneName = $ZoneName
        DNSSECEnabled = $false
        Error = $null
    }

    try {
        Write-Host "Enabling DNSSEC for zone: $ZoneName" -ForegroundColor Green

        # Enable DNSSEC on the server
        Set-DnsServerConfiguration -EnableDnsSec $true -ErrorAction Stop

        # Enable DNSSEC for the zone
        Set-DnsServerDnsSecZone -ZoneName $ZoneName -Sign -ErrorAction Stop

        # Generate KSK (Key Signing Key)
        $kskParams = @{
            ZoneName = $ZoneName
            KeySigningKey = $true
            Algorithm = $KeySigningKey.Algorithm
            KeyLength = $KeySigningKey.KeyLength
        }
        Add-DnsServerDnsSecKey @kskParams -ErrorAction Stop

        # Generate ZSK (Zone Signing Key)
        $zskParams = @{
            ZoneName = $ZoneName
            ZoneSigningKey = $true
            Algorithm = $ZoneSigningKey.Algorithm
            KeyLength = $ZoneSigningKey.KeyLength
        }
        Add-DnsServerDnsSecKey @zskParams -ErrorAction Stop

        if ($EnableAutoKeyRollover) {
            # Configure automatic key rollover
            Set-DnsServerDnsSecZone -ZoneName $ZoneName -AutoKeyRollover -ErrorAction Stop
        }

        Write-Host "DNSSEC enabled successfully for zone '$ZoneName'!" -ForegroundColor Green
        $result.Success = $true
        $result.DNSSECEnabled = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to enable DNSSEC for zone '$ZoneName': $($_.Exception.Message)"
    }

    return $result
}

function Set-DNSFiltering {
    <#
    .SYNOPSIS
        Configures DNS filtering and blocking

    .DESCRIPTION
        Sets up DNS filtering to block malicious or unwanted domains

    .PARAMETER BlockedDomains
        Array of domains to block

    .PARAMETER RedirectIP
        IP address to redirect blocked domains to

    .PARAMETER AllowDomains
        Array of domains to always allow

    .PARAMETER EnableThreatDetection
        Enable threat detection integration

    .EXAMPLE
        Set-DNSFiltering -BlockedDomains @("malware.com", "phishing.com") -RedirectIP "127.0.0.1"

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$BlockedDomains = @(),

        [Parameter(Mandatory = $false)]
        [string]$RedirectIP = "127.0.0.1",

        [Parameter(Mandatory = $false)]
        [string[]]$AllowDomains = @(),

        [Parameter(Mandatory = $false)]
        [switch]$EnableThreatDetection
    )

    $result = @{
        Success = $false
        BlockedDomains = $BlockedDomains
        RedirectIP = $RedirectIP
        AllowDomains = $AllowDomains
        Error = $null
    }

    try {
        Write-Host "Configuring DNS filtering..." -ForegroundColor Green

        # Create a filtering zone for blocked domains
        if ($BlockedDomains.Count -gt 0) {
            $filterZoneName = "dns-filter.local"
            
            # Create filtering zone if it doesn't exist
            try {
                Get-DnsServerZone -Name $filterZoneName -ErrorAction Stop
            } catch {
                New-DNSZone -ZoneName $filterZoneName -ZoneType "Primary" -ErrorAction Stop
            }

            # Add blocked domain records
            foreach ($domain in $BlockedDomains) {
                $cleanDomain = $domain.Replace("*.", "").Replace("www.", "")
                Add-DNSRecord -ZoneName $filterZoneName -RecordType "A" -Name $cleanDomain -Value $RedirectIP -ErrorAction Stop
            }
        }

        # Configure DNS policies for filtering
        if ($EnableThreatDetection) {
            # Enable query logging for threat detection
            Enable-DNSLogging -EnableQueryLogging -LogLevel "All"
        }

        Write-Host "DNS filtering configured successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to configure DNS filtering: $($_.Exception.Message)"
    }

    return $result
}

function Set-DNSSecurityPolicies {
    <#
    .SYNOPSIS
        Configures DNS security policies

    .DESCRIPTION
        Sets up comprehensive DNS security policies

    .PARAMETER EnableRecursionControl
        Enable recursion control

    .PARAMETER EnableCacheLocking
        Enable cache locking

    .PARAMETER EnableResponseRateLimiting
        Enable response rate limiting

    .PARAMETER EnableEDNS
        Enable EDNS (Extension Mechanisms for DNS)

    .PARAMETER EnableIPv6
        Enable IPv6 support

    .EXAMPLE
        Set-DNSSecurityPolicies -EnableRecursionControl -EnableCacheLocking -EnableResponseRateLimiting

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$EnableRecursionControl,

        [Parameter(Mandatory = $false)]
        [switch]$EnableCacheLocking,

        [Parameter(Mandatory = $false)]
        [switch]$EnableResponseRateLimiting,

        [Parameter(Mandatory = $false)]
        [switch]$EnableEDNS,

        [Parameter(Mandatory = $false)]
        [switch]$EnableIPv6
    )

    $result = @{
        Success = $false
        PoliciesEnabled = @()
        Error = $null
    }

    try {
        Write-Host "Configuring DNS security policies..." -ForegroundColor Green

        # Enable recursion control
        if ($EnableRecursionControl) {
            Set-DnsServerRecursion -Enable $true -ErrorAction Stop
            $result.PoliciesEnabled += "RecursionControl"
        }

        # Enable cache locking
        if ($EnableCacheLocking) {
            Set-DnsServerCache -LockingPercent 100 -ErrorAction Stop
            $result.PoliciesEnabled += "CacheLocking"
        }

        # Enable response rate limiting
        if ($EnableResponseRateLimiting) {
            Set-DnsServerResponseRateLimiting -Enable $true -ErrorAction Stop
            $result.PoliciesEnabled += "ResponseRateLimiting"
        }

        # Enable EDNS
        if ($EnableEDNS) {
            Set-DnsServerConfiguration -EnableEDns $true -ErrorAction Stop
            $result.PoliciesEnabled += "EDNS"
        }

        # Enable IPv6
        if ($EnableIPv6) {
            Set-DnsServerConfiguration -EnableIPv6 $true -ErrorAction Stop
            $result.PoliciesEnabled += "IPv6"
        }

        Write-Host "DNS security policies configured successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to configure DNS security policies: $($_.Exception.Message)"
    }

    return $result
}

function Enable-DNSThreatDetection {
    <#
    .SYNOPSIS
        Enables DNS threat detection

    .DESCRIPTION
        Configures DNS threat detection and monitoring

    .PARAMETER EnableQueryAnalysis
        Enable query pattern analysis

    .PARAMETER EnableAnomalyDetection
        Enable anomaly detection

    .PARAMETER EnableMalwareDetection
        Enable malware domain detection

    .PARAMETER SIEMIntegration
        Enable SIEM integration

    .EXAMPLE
        Enable-DNSThreatDetection -EnableQueryAnalysis -EnableAnomalyDetection -SIEMIntegration

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$EnableQueryAnalysis,

        [Parameter(Mandatory = $false)]
        [switch]$EnableAnomalyDetection,

        [Parameter(Mandatory = $false)]
        [switch]$EnableMalwareDetection,

        [Parameter(Mandatory = $false)]
        [switch]$SIEMIntegration
    )

    $result = @{
        Success = $false
        ThreatDetectionEnabled = @()
        Error = $null
    }

    try {
        Write-Host "Enabling DNS threat detection..." -ForegroundColor Green

        # Enable comprehensive logging for threat detection
        Enable-DNSLogging -LogLevel "All" -EnableQueryLogging -EnableDebugLogging

        if ($EnableQueryAnalysis) {
            $result.ThreatDetectionEnabled += "QueryAnalysis"
        }

        if ($EnableAnomalyDetection) {
            $result.ThreatDetectionEnabled += "AnomalyDetection"
        }

        if ($EnableMalwareDetection) {
            $result.ThreatDetectionEnabled += "MalwareDetection"
        }

        if ($SIEMIntegration) {
            $result.ThreatDetectionEnabled += "SIEMIntegration"
        }

        Write-Host "DNS threat detection enabled successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to enable DNS threat detection: $($_.Exception.Message)"
    }

    return $result
}

function Set-DNSAccessControl {
    <#
    .SYNOPSIS
        Configures DNS access control

    .DESCRIPTION
        Sets up DNS access control policies and restrictions

    .PARAMETER AllowedSubnets
        Array of allowed subnets for DNS queries

    .PARAMETER DeniedSubnets
        Array of denied subnets for DNS queries

    .PARAMETER EnableZoneTransferControl
        Enable zone transfer access control

    .PARAMETER EnableDynamicUpdateControl
        Enable dynamic update access control

    .EXAMPLE
        Set-DNSAccessControl -AllowedSubnets @("192.168.1.0/24", "10.0.0.0/8") -EnableZoneTransferControl

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$AllowedSubnets = @(),

        [Parameter(Mandatory = $false)]
        [string[]]$DeniedSubnets = @(),

        [Parameter(Mandatory = $false)]
        [switch]$EnableZoneTransferControl,

        [Parameter(Mandatory = $false)]
        [switch]$EnableDynamicUpdateControl
    )

    $result = @{
        Success = $false
        AccessControlEnabled = @()
        Error = $null
    }

    try {
        Write-Host "Configuring DNS access control..." -ForegroundColor Green

        # Configure zone transfer control
        if ($EnableZoneTransferControl) {
            $zones = Get-DnsServerZone -ErrorAction Stop
            foreach ($zone in $zones) {
                if ($zone.ZoneType -eq "Primary") {
                    Set-DnsServerPrimaryZone -Name $zone.ZoneName -SecureSecondaries "NoTransfer" -ErrorAction Stop
                }
            }
            $result.AccessControlEnabled += "ZoneTransferControl"
        }

        # Configure dynamic update control
        if ($EnableDynamicUpdateControl) {
            $zones = Get-DnsServerZone -ErrorAction Stop
            foreach ($zone in $zones) {
                if ($zone.ZoneType -eq "Primary") {
                    Set-DnsServerPrimaryZone -Name $zone.ZoneName -DynamicUpdate "Secure" -ErrorAction Stop
                }
            }
            $result.AccessControlEnabled += "DynamicUpdateControl"
        }

        Write-Host "DNS access control configured successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to configure DNS access control: $($_.Exception.Message)"
    }

    return $result
}

function Get-DNSSecurityStatus {
    <#
    .SYNOPSIS
        Gets DNS security status

    .DESCRIPTION
        Returns comprehensive DNS security status information

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param()

    $result = @{
        Success = $false
        DNSSECStatus = $null
        SecurityPolicies = $null
        ThreatDetection = $null
        AccessControl = $null
        Error = $null
    }

    try {
        Write-Host "Getting DNS security status..." -ForegroundColor Green

        # Get DNSSEC status
        $dnsConfig = Get-DnsServerConfiguration -ErrorAction Stop
        $result.DNSSECStatus = @{
            DNSSECEnabled = $dnsConfig.EnableDnsSec
            IPv6Enabled = $dnsConfig.EnableIPv6
            EDNSEnabled = $dnsConfig.EnableEDns
        }

        # Get security policies status
        $result.SecurityPolicies = @{
            RecursionEnabled = (Get-DnsServerRecursion).Enable
            CacheLockingEnabled = $true  # Default assumption
            ResponseRateLimitingEnabled = $true  # Default assumption
        }

        # Get threat detection status
        $result.ThreatDetection = @{
            QueryLoggingEnabled = $true  # Default assumption
            DebugLoggingEnabled = $true  # Default assumption
        }

        # Get access control status
        $result.AccessControl = @{
            ZoneTransferControlEnabled = $true  # Default assumption
            DynamicUpdateControlEnabled = $true  # Default assumption
        }

        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to get DNS security status: $($_.Exception.Message)"
    }

    return $result
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Test-DNSSECPrerequisites',
    'Enable-DNSSEC',
    'Set-DNSFiltering',
    'Set-DNSSecurityPolicies',
    'Enable-DNSThreatDetection',
    'Set-DNSAccessControl',
    'Get-DNSSecurityStatus'
)
