#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    DNS Troubleshooting PowerShell Module

.DESCRIPTION
    This module provides comprehensive DNS troubleshooting, diagnostics,
    and automated repair capabilities.

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

function Test-DNSConnectivity {
    <#
    .SYNOPSIS
        Tests DNS connectivity

    .DESCRIPTION
        Tests DNS connectivity to various targets

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param()

    $connectivityTests = @{
        LocalResolution = $false
        ForwarderResolution = $false
        RootServerResolution = $false
        ReverseResolution = $false
    }

    try {
        # Test local resolution
        $localTest = Resolve-DnsName -Name "localhost" -ErrorAction SilentlyContinue
        if ($localTest) {
            $connectivityTests.LocalResolution = $true
        }

        # Test forwarder resolution
        $forwarderTest = Resolve-DnsName -Name "google.com" -ErrorAction SilentlyContinue
        if ($forwarderTest) {
            $connectivityTests.ForwarderResolution = $true
        }

        # Test root server resolution
        $rootTest = Resolve-DnsName -Name "example.com" -ErrorAction SilentlyContinue
        if ($rootTest) {
            $connectivityTests.RootServerResolution = $true
        }

        # Test reverse resolution
        $reverseTest = Resolve-DnsName -Name "8.8.8.8" -Type PTR -ErrorAction SilentlyContinue
        if ($reverseTest) {
            $connectivityTests.ReverseResolution = $true
        }

    } catch {
        Write-Warning "Connectivity test failed: $($_.Exception.Message)"
    }

    return $connectivityTests
}

function Analyze-DNSEventLogs {
    <#
    .SYNOPSIS
        Analyzes DNS event logs

    .DESCRIPTION
        Analyzes DNS event logs for errors and issues

    .PARAMETER LogPath
        Path to event logs

    .PARAMETER TimeWindow
        Time window for analysis in hours

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$LogPath = "C:\Windows\System32\winevt\Logs",

        [Parameter(Mandatory = $false)]
        [int]$TimeWindow = 24
    )

    $analysis = @{
        Errors = @()
        Warnings = @()
        CriticalIssues = @()
        Recommendations = @()
    }

    try {
        # Analyze DNS event logs
        $startTime = (Get-Date).AddHours(-$TimeWindow)
        
        $dnsEvents = Get-WinEvent -FilterHashtable @{
            LogName = "DNS Server"
            StartTime = $startTime
        } -ErrorAction SilentlyContinue

        foreach ($event in $dnsEvents) {
            switch ($event.LevelDisplayName) {
                "Error" {
                    $analysis.Errors += @{
                        Time = $event.TimeCreated
                        ID = $event.Id
                        Message = $event.Message
                        Source = $event.ProviderName
                    }
                }
                "Warning" {
                    $analysis.Warnings += @{
                        Time = $event.TimeCreated
                        ID = $event.Id
                        Message = $event.Message
                        Source = $event.ProviderName
                    }
                }
                "Critical" {
                    $analysis.CriticalIssues += @{
                        Time = $event.TimeCreated
                        ID = $event.Id
                        Message = $event.Message
                        Source = $event.ProviderName
                    }
                }
            }
        }

        # Generate recommendations based on errors
        if ($analysis.Errors.Count -gt 0) {
            $analysis.Recommendations += "Review DNS configuration for errors"
        }
        if ($analysis.CriticalIssues.Count -gt 0) {
            $analysis.Recommendations += "Address critical DNS issues immediately"
        }

    } catch {
        Write-Warning "Could not analyze DNS event logs: $($_.Exception.Message)"
    }

    return $analysis
}

#endregion

#region Public Functions

function Invoke-DNSDiagnostics {
    <#
    .SYNOPSIS
        Performs comprehensive DNS diagnostics

    .DESCRIPTION
        Runs comprehensive DNS diagnostics and returns detailed results

    .PARAMETER DiagnosticLevel
        Level of diagnostics (Basic, Comprehensive, Deep)

    .PARAMETER IncludeConnectivityTests
        Include connectivity tests

    .PARAMETER IncludePerformanceTests
        Include performance tests

    .PARAMETER IncludeSecurityTests
        Include security tests

    .PARAMETER EnableAutoRepair
        Enable automatic repair of detected issues

    .EXAMPLE
        Invoke-DNSDiagnostics -DiagnosticLevel "Comprehensive" -IncludeConnectivityTests -EnableAutoRepair

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("Basic", "Comprehensive", "Deep")]
        [string]$DiagnosticLevel = "Comprehensive",

        [Parameter(Mandatory = $false)]
        [switch]$IncludeConnectivityTests,

        [Parameter(Mandatory = $false)]
        [switch]$IncludePerformanceTests,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeSecurityTests,

        [Parameter(Mandatory = $false)]
        [switch]$EnableAutoRepair
    )

    $result = @{
        Success = $false
        DiagnosticLevel = $DiagnosticLevel
        ServiceStatus = $null
        ConfigurationStatus = $null
        ConnectivityStatus = $null
        PerformanceStatus = $null
        SecurityStatus = $null
        IssuesFound = 0
        IssuesFixed = 0
        Recommendations = @()
        Error = $null
    }

    try {
        Write-Host "Running DNS diagnostics..." -ForegroundColor Green

        # Test service status
        $serviceStatus = Get-DNSServerStatus
        $result.ServiceStatus = $serviceStatus

        # Test configuration
        $result.ConfigurationStatus = @{
            ZonesConfigured = $serviceStatus.ZoneCount
            ForwardersConfigured = $serviceStatus.ForwarderCount
            ConfigurationValid = $serviceStatus.Success
        }

        # Test connectivity
        if ($IncludeConnectivityTests) {
            $connectivityTests = Test-DNSConnectivity
            $result.ConnectivityStatus = $connectivityTests
        }

        # Test performance
        if ($IncludePerformanceTests) {
            $performanceData = Get-DNSPerformanceCounters
            $result.PerformanceStatus = $performanceData
        }

        # Test security
        if ($IncludeSecurityTests) {
            $securityStatus = Get-DNSSecurityStatus
            $result.SecurityStatus = $securityStatus
        }

        # Analyze event logs
        $eventAnalysis = Analyze-DNSEventLogs
        $result.IssuesFound = $eventAnalysis.Errors.Count + $eventAnalysis.Warnings.Count + $eventAnalysis.CriticalIssues.Count
        $result.Recommendations = $eventAnalysis.Recommendations

        # Auto-repair if enabled
        if ($EnableAutoRepair -and $result.IssuesFound -gt 0) {
            $repairResult = Invoke-DNSRepair -IssuesFound $result.IssuesFound
            $result.IssuesFixed = $repairResult.IssuesFixed
        }

        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to run DNS diagnostics: $($_.Exception.Message)"
    }

    return $result
}

function Invoke-DNSRepair {
    <#
    .SYNOPSIS
        Performs automated DNS repair

    .DESCRIPTION
        Automatically repairs common DNS issues

    .PARAMETER IssuesFound
        Number of issues found

    .PARAMETER RepairLevel
        Level of repair (Basic, Comprehensive, Deep)

    .PARAMETER BackupBeforeRepair
        Create backup before repair

    .EXAMPLE
        Invoke-DNSRepair -IssuesFound 5 -RepairLevel "Comprehensive" -BackupBeforeRepair

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$IssuesFound = 0,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Basic", "Comprehensive", "Deep")]
        [string]$RepairLevel = "Comprehensive",

        [Parameter(Mandatory = $false)]
        [switch]$BackupBeforeRepair
    )

    $result = @{
        Success = $false
        IssuesDetected = $IssuesFound
        IssuesFixed = 0
        IssuesFailed = 0
        RepairActions = @()
        Error = $null
    }

    try {
        Write-Host "Starting DNS repair..." -ForegroundColor Green

        # Create backup if requested
        if ($BackupBeforeRepair) {
            Write-Host "Creating DNS configuration backup..." -ForegroundColor Yellow
            $backupResult = Backup-DNSConfiguration
            if ($backupResult.Success) {
                $result.RepairActions += "Configuration backup created"
            }
        }

        # Restart DNS service if needed
        $dnsService = Get-Service -Name DNS -ErrorAction Stop
        if ($dnsService.Status -ne "Running") {
            Write-Host "Restarting DNS service..." -ForegroundColor Yellow
            Restart-Service -Name DNS -ErrorAction Stop
            $result.RepairActions += "DNS service restarted"
            $result.IssuesFixed++
        }

        # Clear DNS cache
        Write-Host "Clearing DNS cache..." -ForegroundColor Yellow
        Clear-DnsServerCache -ErrorAction Stop
        $result.RepairActions += "DNS cache cleared"
        $result.IssuesFixed++

        # Verify zone integrity
        $zones = Get-DnsServerZone -ErrorAction Stop
        foreach ($zone in $zones) {
            try {
                # Test zone integrity
                $zoneRecords = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -ErrorAction Stop
                $result.RepairActions += "Zone '$($zone.ZoneName)' integrity verified"
            } catch {
                $result.RepairActions += "Zone '$($zone.ZoneName)' integrity check failed"
                $result.IssuesFailed++
            }
        }

        # Verify forwarders
        try {
            $forwarders = Get-DnsServerForwarder -ErrorAction Stop
            if ($forwarders.IPAddress.Count -eq 0) {
                Write-Host "Configuring default forwarders..." -ForegroundColor Yellow
                Set-DNSForwarders -Forwarders @("8.8.8.8", "8.8.4.4")
                $result.RepairActions += "Default forwarders configured"
                $result.IssuesFixed++
            }
        } catch {
            $result.RepairActions += "Forwarder verification failed"
            $result.IssuesFailed++
        }

        Write-Host "DNS repair completed!" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to perform DNS repair: $($_.Exception.Message)"
    }

    return $result
}

function Test-DNSZoneIntegrity {
    <#
    .SYNOPSIS
        Tests DNS zone integrity

    .DESCRIPTION
        Tests the integrity of DNS zones and records

    .PARAMETER ZoneName
        Name of the zone to test

    .PARAMETER TestAllZones
        Test all zones

    .EXAMPLE
        Test-DNSZoneIntegrity -ZoneName "contoso.com"

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ZoneName,

        [Parameter(Mandatory = $false)]
        [switch]$TestAllZones
    )

    $result = @{
        Success = $false
        ZonesTested = @()
        IntegrityIssues = @()
        Recommendations = @()
        Error = $null
    }

    try {
        Write-Host "Testing DNS zone integrity..." -ForegroundColor Green

        $zonesToTest = @()

        if ($TestAllZones) {
            $zonesToTest = Get-DnsServerZone -ErrorAction Stop
        } elseif ($ZoneName) {
            $zonesToTest = Get-DnsServerZone -Name $ZoneName -ErrorAction Stop
        } else {
            $zonesToTest = Get-DnsServerZone -ErrorAction Stop
        }

        foreach ($zone in $zonesToTest) {
            $zoneTest = @{
                ZoneName = $zone.ZoneName
                ZoneType = $zone.ZoneType
                IntegrityStatus = "Unknown"
                Issues = @()
            }

            try {
                # Test zone records
                $records = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -ErrorAction Stop
                
                # Check for common issues
                $hasSOA = $records | Where-Object { $_.RecordType -eq "SOA" }
                if (-not $hasSOA) {
                    $zoneTest.Issues += "Missing SOA record"
                }

                $hasNS = $records | Where-Object { $_.RecordType -eq "NS" }
                if (-not $hasNS) {
                    $zoneTest.Issues += "Missing NS records"
                }

                # Check for duplicate records
                $duplicateRecords = $records | Group-Object -Property Name, RecordType | Where-Object { $_.Count -gt 1 }
                if ($duplicateRecords) {
                    $zoneTest.Issues += "Duplicate records found"
                }

                if ($zoneTest.Issues.Count -eq 0) {
                    $zoneTest.IntegrityStatus = "Healthy"
                } else {
                    $zoneTest.IntegrityStatus = "Issues Found"
                }

            } catch {
                $zoneTest.IntegrityStatus = "Error"
                $zoneTest.Issues += "Could not test zone: $($_.Exception.Message)"
            }

            $result.ZonesTested += $zoneTest

            if ($zoneTest.Issues.Count -gt 0) {
                $result.IntegrityIssues += $zoneTest
            }
        }

        # Generate recommendations
        if ($result.IntegrityIssues.Count -gt 0) {
            $result.Recommendations += "Review zone configurations for issues"
            $result.Recommendations += "Consider zone repair operations"
        }

        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to test DNS zone integrity: $($_.Exception.Message)"
    }

    return $result
}

function Get-DNSTroubleshootingStatus {
    <#
    .SYNOPSIS
        Gets DNS troubleshooting status

    .DESCRIPTION
        Returns current DNS troubleshooting status and configuration

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param()

    $result = @{
        Success = $false
        ServiceStatus = $null
        ConfigurationStatus = $null
        ConnectivityStatus = $null
        PerformanceStatus = $null
        SecurityStatus = $null
        Error = $null
    }

    try {
        Write-Host "Getting DNS troubleshooting status..." -ForegroundColor Green

        # Get service status
        $serviceStatus = Get-DNSServerStatus
        $result.ServiceStatus = $serviceStatus.ServiceStatus

        # Get configuration status
        $result.ConfigurationStatus = @{
            ZonesConfigured = $serviceStatus.ZoneCount
            ForwardersConfigured = $serviceStatus.ForwarderCount
            ConfigurationValid = $serviceStatus.Success
        }

        # Get connectivity status
        $connectivityTests = Test-DNSConnectivity
        $result.ConnectivityStatus = $connectivityTests

        # Get performance status
        $performanceData = Get-DNSPerformanceCounters
        $result.PerformanceStatus = $performanceData

        # Get security status
        $securityStatus = Get-DNSSecurityStatus
        $result.SecurityStatus = $securityStatus

        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to get DNS troubleshooting status: $($_.Exception.Message)"
    }

    return $result
}

function Backup-DNSConfiguration {
    <#
    .SYNOPSIS
        Backs up DNS configuration

    .DESCRIPTION
        Creates a backup of DNS configuration and zones

    .PARAMETER BackupPath
        Path for backup files

    .PARAMETER IncludeZones
        Include zone data in backup

    .PARAMETER IncludeRecords
        Include DNS records in backup

    .EXAMPLE
        Backup-DNSConfiguration -BackupPath "C:\DNS\Backup" -IncludeZones -IncludeRecords

    .OUTPUTS
        System.Object
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BackupPath = "C:\DNS\Backup",

        [Parameter(Mandatory = $false)]
        [switch]$IncludeZones,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeRecords
    )

    $result = @{
        Success = $false
        BackupPath = $BackupPath
        BackupFiles = @()
        Error = $null
    }

    try {
        Write-Host "Creating DNS configuration backup..." -ForegroundColor Green

        # Create backup directory
        if (-not (Test-Path $BackupPath)) {
            New-Item -Path $BackupPath -ItemType Directory -Force
        }

        $timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
        $backupFile = Join-Path $BackupPath "DNS-Config-Backup-$timestamp.json"

        # Backup DNS configuration
        $dnsConfig = Get-DnsServerConfiguration -ErrorAction Stop
        $backupData = @{
            Timestamp = $timestamp
            ComputerName = $env:COMPUTERNAME
            Configuration = $dnsConfig
        }

        if ($IncludeZones) {
            $zones = Get-DnsServerZone -ErrorAction Stop
            $backupData.Zones = $zones
        }

        if ($IncludeRecords) {
            $allRecords = @{}
            $zones = Get-DnsServerZone -ErrorAction Stop
            foreach ($zone in $zones) {
                try {
                    $records = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -ErrorAction Stop
                    $allRecords[$zone.ZoneName] = $records
                } catch {
                    Write-Warning "Could not backup records for zone '$($zone.ZoneName)'"
                }
            }
            $backupData.Records = $allRecords
        }

        $backupData | ConvertTo-Json -Depth 10 | Out-File -FilePath $backupFile -Encoding UTF8
        $result.BackupFiles += $backupFile

        Write-Host "DNS configuration backup created: $backupFile" -ForegroundColor Green
        $result.Success = $true

    } catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to create DNS configuration backup: $($_.Exception.Message)"
    }

    return $result
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Test-DNSConnectivity',
    'Analyze-DNSEventLogs',
    'Invoke-DNSDiagnostics',
    'Invoke-DNSRepair',
    'Test-DNSZoneIntegrity',
    'Get-DNSTroubleshootingStatus',
    'Backup-DNSConfiguration'
)
