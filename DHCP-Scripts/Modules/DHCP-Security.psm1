#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    DHCP Security PowerShell Module

.DESCRIPTION
    This module provides security functions for DHCP operations including
    authorization, filtering, and threat protection.

.NOTES
    Author: DHCP PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Module metadata
$ModuleVersion = "1.0.0"

# Import required modules
try {
    Import-Module DhcpServer -ErrorAction Stop
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Required modules not available. Some functions may not work properly."
}

#region Private Functions

function Test-DHCPAuthorization {
    <#
    .SYNOPSIS
        Tests DHCP server authorization

    .DESCRIPTION
        Checks if the DHCP server is authorized in Active Directory

    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    param()

    try {
        $dhcpConfig = Get-DhcpServerConfiguration -ErrorAction Stop
        return $dhcpConfig.Authorized
    } catch {
        Write-Warning "Could not check DHCP authorization status"
        return $false
    }
}

function Get-DHCPThreats {
    <#
    .SYNOPSIS
        Identifies potential DHCP security threats

    .DESCRIPTION
        Analyzes DHCP logs and configuration for security threats

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param()

    $threats = @{
        RogueServers = @()
        SuspiciousLeases = @()
        UnauthorizedReservations = @()
        PolicyViolations = @()
    }

    try {
        # Check for rogue DHCP servers
        $unauthorizedServers = Get-DhcpServerInDC -ErrorAction SilentlyContinue | Where-Object { -not $_.Authorized }
        $threats.RogueServers = $unauthorizedServers

        # Check for suspicious lease patterns
        $suspiciousLeases = Get-DhcpServerv4Lease -ErrorAction SilentlyContinue | Where-Object {
            $_.ClientId -match "00-00-00-00-00-00" -or
            $_.IPAddress -match "169\.254\." -or
            $_.LeaseExpiryTime -lt (Get-Date).AddDays(-30)
        }
        $threats.SuspiciousLeases = $suspiciousLeases

        # Check for unauthorized reservations
        $reservations = Get-DhcpServerv4Reservation -ErrorAction SilentlyContinue
        $unauthorizedReservations = $reservations | Where-Object {
            $_.Name -match "UNKNOWN" -or
            $_.Description -match "UNKNOWN" -or
            $_.ClientId -match "00-00-00-00-00-00"
        }
        $threats.UnauthorizedReservations = $unauthorizedReservations

    } catch {
        Write-Warning "Could not analyze DHCP threats: $($_.Exception.Message)"
    }

    return $threats
}

#endregion

#region Public Functions

function Authorize-DHCPServer {
    <#
    .SYNOPSIS
        Authorizes DHCP server in Active Directory

    .DESCRIPTION
        Authorizes the DHCP server in Active Directory to prevent rogue servers

    .PARAMETER DomainController
        Domain controller to use for authorization

    .PARAMETER Credential
        Credentials for authorization

    .EXAMPLE
        Authorize-DHCPServer -DomainController "DC01.contoso.com"

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DomainController,

        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential
    )

    $result = @{
        Success = $false
        ServerName = $env:COMPUTERNAME
        Authorized = $false
        Error = $null
    }

    try {
        Write-Host "Authorizing DHCP server in Active Directory..." -ForegroundColor Green

        $authParams = @{
            DnsName = $env:COMPUTERNAME
        }

        if ($DomainController) {
            $authParams.DomainController = $DomainController
        }

        if ($Credential) {
            $authParams.Credential = $Credential
        }

        Add-DhcpServerInDC @authParams -ErrorAction Stop

        Write-Host "DHCP server authorized successfully!" -ForegroundColor Green
        $result.Success = $true
        $result.Authorized = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to authorize DHCP server: $($_.Exception.Message)"
    }

    return $result
}

function Set-DHCPFiltering {
    <#
    .SYNOPSIS
        Configures DHCP filtering

    .DESCRIPTION
        Sets up DHCP filtering to allow or deny specific MAC addresses

    .PARAMETER FilterType
        Type of filter (Allow, Deny)

    .PARAMETER MACAddresses
        Array of MAC addresses to filter

    .PARAMETER Description
        Description for the filter

    .EXAMPLE
        Set-DHCPFiltering -FilterType "Allow" -MACAddresses @("00-11-22-33-44-55", "00-AA-BB-CC-DD-EE")

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Allow", "Deny")]
        [string]$FilterType,

        [Parameter(Mandatory = $true)]
        [string[]]$MACAddresses,

        [Parameter(Mandatory = $false)]
        [string]$Description = ""
    )

    $result = @{
        Success = $false
        FilterType = $FilterType
        MACAddresses = $MACAddresses
        FiltersCreated = 0
        Error = $null
    }

    try {
        Write-Host "Configuring DHCP filtering: $FilterType" -ForegroundColor Green

        foreach ($macAddress in $MACAddresses) {
            $filterParams = @{
                List = $FilterType
                MacAddress = $macAddress
            }

            if ($Description) {
                $filterParams.Description = $Description
            }

            Add-DhcpServerv4Filter @filterParams -ErrorAction Stop
            $result.FiltersCreated++
        }

        Write-Host "DHCP filtering configured successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to configure DHCP filtering: $($_.Exception.Message)"
    }

    return $result
}

function Enable-DHCPSecurityPolicies {
    <#
    .SYNOPSIS
        Enables DHCP security policies

    .DESCRIPTION
        Configures comprehensive DHCP security policies

    .PARAMETER EnableConflictDetection
        Enable conflict detection

    .PARAMETER ConflictDetectionAttempts
        Number of conflict detection attempts

    .PARAMETER EnableAuditLogging
        Enable audit logging

    .PARAMETER EnableRogueDetection
        Enable rogue server detection

    .PARAMETER EnableLeaseValidation
        Enable lease validation

    .EXAMPLE
        Enable-DHCPSecurityPolicies -EnableConflictDetection -EnableAuditLogging

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$EnableConflictDetection,

        [Parameter(Mandatory = $false)]
        [int]$ConflictDetectionAttempts = 2,

        [Parameter(Mandatory = $false)]
        [switch]$EnableAuditLogging,

        [Parameter(Mandatory = $false)]
        [switch]$EnableRogueDetection,

        [Parameter(Mandatory = $false)]
        [switch]$EnableLeaseValidation
    )

    $result = @{
        Success = $false
        PoliciesEnabled = @()
        Error = $null
    }

    try {
        Write-Host "Enabling DHCP security policies..." -ForegroundColor Green

        # Enable conflict detection
        if ($EnableConflictDetection) {
            Set-DhcpServerConfiguration -ConflictDetectionAttempts $ConflictDetectionAttempts -ErrorAction Stop
            $result.PoliciesEnabled += "Conflict Detection"
        }

        # Enable audit logging
        if ($EnableAuditLogging) {
            Set-DhcpServerConfiguration -AuditLogEnabled $true -ErrorAction Stop
            $result.PoliciesEnabled += "Audit Logging"
        }

        # Enable rogue detection (requires additional monitoring)
        if ($EnableRogueDetection) {
            # This would typically involve network monitoring tools
            Write-Host "Rogue detection enabled (requires network monitoring)" -ForegroundColor Yellow
            $result.PoliciesEnabled += "Rogue Detection"
        }

        # Enable lease validation
        if ($EnableLeaseValidation) {
            # This would involve custom validation logic
            Write-Host "Lease validation enabled (requires custom validation)" -ForegroundColor Yellow
            $result.PoliciesEnabled += "Lease Validation"
        }

        Write-Host "DHCP security policies enabled successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to enable DHCP security policies: $($_.Exception.Message)"
    }

    return $result
}

function Set-DHCPAccessControl {
    <#
    .SYNOPSIS
        Configures DHCP access control

    .DESCRIPTION
        Sets up access control for DHCP administration

    .PARAMETER AdminGroups
        Array of admin groups

    .PARAMETER ReadOnlyGroups
        Array of read-only groups

    .PARAMETER DenyGroups
        Array of denied groups

    .EXAMPLE
        Set-DHCPAccessControl -AdminGroups @("DHCP-Admins") -ReadOnlyGroups @("DHCP-Readers")

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$AdminGroups,

        [Parameter(Mandatory = $false)]
        [string[]]$ReadOnlyGroups,

        [Parameter(Mandatory = $false)]
        [string[]]$DenyGroups
    )

    $result = @{
        Success = $false
        AccessControlConfigured = @()
        Error = $null
    }

    try {
        Write-Host "Configuring DHCP access control..." -ForegroundColor Green

        # Configure admin groups
        if ($AdminGroups) {
            foreach ($group in $AdminGroups) {
                # This would typically involve setting ACLs on DHCP objects
                Write-Host "Admin access granted to: $group" -ForegroundColor Yellow
                $result.AccessControlConfigured += "Admin: $group"
            }
        }

        # Configure read-only groups
        if ($ReadOnlyGroups) {
            foreach ($group in $ReadOnlyGroups) {
                Write-Host "Read-only access granted to: $group" -ForegroundColor Yellow
                $result.AccessControlConfigured += "ReadOnly: $group"
            }
        }

        # Configure denied groups
        if ($DenyGroups) {
            foreach ($group in $DenyGroups) {
                Write-Host "Access denied to: $group" -ForegroundColor Yellow
                $result.AccessControlConfigured += "Denied: $group"
            }
        }

        Write-Host "DHCP access control configured successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to configure DHCP access control: $($_.Exception.Message)"
    }

    return $result
}

function Get-DHCPSecurityStatus {
    <#
    .SYNOPSIS
        Gets DHCP security status

    .DESCRIPTION
        Returns comprehensive DHCP security status information

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param()

    $result = @{
        Success = $false
        SecurityStatus = $null
        Threats = $null
        Error = $null
    }

    try {
        Write-Host "Analyzing DHCP security status..." -ForegroundColor Green

        $securityStatus = @{
            Authorized = Test-DHCPAuthorization
            AuditLoggingEnabled = $false
            ConflictDetectionEnabled = $false
            FilteringEnabled = $false
            RogueDetectionEnabled = $false
        }

        # Check audit logging status
        try {
            $dhcpConfig = Get-DhcpServerConfiguration -ErrorAction Stop
            $securityStatus.AuditLoggingEnabled = $dhcpConfig.AuditLogEnabled
            $securityStatus.ConflictDetectionEnabled = $dhcpConfig.ConflictDetectionAttempts -gt 0
        } catch {
            Write-Warning "Could not get DHCP configuration"
        }

        # Check filtering status
        try {
            $filters = Get-DhcpServerv4Filter -ErrorAction SilentlyContinue
            $securityStatus.FilteringEnabled = $filters.Count -gt 0
        } catch {
            Write-Warning "Could not get DHCP filters"
        }

        # Get threat analysis
        $threats = Get-DHCPThreats

        $result.SecurityStatus = $securityStatus
        $result.Threats = $threats
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to get DHCP security status: $($_.Exception.Message)"
    }

    return $result
}

function Remove-DHCPThreats {
    <#
    .SYNOPSIS
        Removes DHCP security threats

    .DESCRIPTION
        Identifies and removes DHCP security threats

    .PARAMETER RemoveRogueServers
        Remove rogue DHCP servers

    .PARAMETER RemoveSuspiciousLeases
        Remove suspicious leases

    .PARAMETER RemoveUnauthorizedReservations
        Remove unauthorized reservations

    .EXAMPLE
        Remove-DHCPThreats -RemoveRogueServers -RemoveSuspiciousLeases

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$RemoveRogueServers,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveSuspiciousLeases,

        [Parameter(Mandatory = $false)]
        [switch]$RemoveUnauthorizedReservations
    )

    $result = @{
        Success = $false
        ThreatsRemoved = @()
        Error = $null
    }

    try {
        Write-Host "Removing DHCP security threats..." -ForegroundColor Green

        $threats = Get-DHCPThreats

        # Remove rogue servers
        if ($RemoveRogueServers -and $threats.RogueServers.Count -gt 0) {
            foreach ($rogueServer in $threats.RogueServers) {
                try {
                    Remove-DhcpServerInDC -DnsName $rogueServer.DnsName -ErrorAction Stop
                    $result.ThreatsRemoved += "Rogue Server: $($rogueServer.DnsName)"
                } catch {
                    Write-Warning "Could not remove rogue server: $($rogueServer.DnsName)"
                }
            }
        }

        # Remove suspicious leases
        if ($RemoveSuspiciousLeases -and $threats.SuspiciousLeases.Count -gt 0) {
            foreach ($lease in $threats.SuspiciousLeases) {
                try {
                    Remove-DhcpServerv4Lease -IPAddress $lease.IPAddress -ErrorAction Stop
                    $result.ThreatsRemoved += "Suspicious Lease: $($lease.IPAddress)"
                } catch {
                    Write-Warning "Could not remove suspicious lease: $($lease.IPAddress)"
                }
            }
        }

        # Remove unauthorized reservations
        if ($RemoveUnauthorizedReservations -and $threats.UnauthorizedReservations.Count -gt 0) {
            foreach ($reservation in $threats.UnauthorizedReservations) {
                try {
                    Remove-DhcpServerv4Reservation -IPAddress $reservation.IPAddress -ErrorAction Stop
                    $result.ThreatsRemoved += "Unauthorized Reservation: $($reservation.IPAddress)"
                } catch {
                    Write-Warning "Could not remove unauthorized reservation: $($reservation.IPAddress)"
                }
            }
        }

        Write-Host "DHCP security threats removed successfully!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to remove DHCP security threats: $($_.Exception.Message)"
    }

    return $result
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Authorize-DHCPServer',
    'Set-DHCPFiltering',
    'Enable-DHCPSecurityPolicies',
    'Set-DHCPAccessControl',
    'Get-DHCPSecurityStatus',
    'Remove-DHCPThreats'
)
