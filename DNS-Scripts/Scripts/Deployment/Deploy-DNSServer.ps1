#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    DNS Server Deployment Script

.DESCRIPTION
    This script provides comprehensive DNS server deployment including
    installation, configuration, security, and monitoring setup.

.PARAMETER Environment
    Target environment (Development, Staging, Production)

.PARAMETER ZoneName
    Primary zone name to create

.PARAMETER Forwarders
    Array of forwarder IP addresses

.PARAMETER EnableDNSSEC
    Enable DNSSEC

.PARAMETER EnableSecurity
    Enable security features

.PARAMETER EnableMonitoring
    Enable monitoring and alerting

.PARAMETER EnableLogging
    Enable comprehensive logging

.PARAMETER EnableBackup
    Enable configuration backup

.EXAMPLE
    .\Deploy-DNSServer.ps1 -Environment "Production" -ZoneName "contoso.com" -Forwarders @("8.8.8.8", "8.8.4.4") -EnableDNSSEC -EnableSecurity -EnableMonitoring

.EXAMPLE
    .\Deploy-DNSServer.ps1 -Environment "Development" -ZoneName "test.local" -EnableLogging -EnableBackup
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Development", "Staging", "Production")]
    [string]$Environment = "Development",
    
    [Parameter(Mandatory = $false)]
    [string]$ZoneName = "contoso.local",
    
    [Parameter(Mandatory = $false)]
    [string[]]$Forwarders = @("8.8.8.8", "8.8.4.4"),
    
    [switch]$EnableDNSSEC,
    
    [switch]$EnableSecurity,
    
    [switch]$EnableMonitoring,
    
    [switch]$EnableLogging,
    
    [switch]$EnableBackup
)

# Import DNS modules
try {
    Import-Module "..\Modules\DNS-Core.psm1" -Force
    Import-Module "..\Modules\DNS-Security.psm1" -Force
    Import-Module "..\Modules\DNS-Monitoring.psm1" -Force
    Import-Module "..\Modules\DNS-Troubleshooting.psm1" -Force
} catch {
    Write-Error "Failed to import DNS modules: $($_.Exception.Message)"
    exit 1
}

# Script configuration
$scriptConfig = @{
    Environment = $Environment
    ZoneName = $ZoneName
    Forwarders = $Forwarders
    EnableDNSSEC = $EnableDNSSEC
    EnableSecurity = $EnableSecurity
    EnableMonitoring = $EnableMonitoring
    EnableLogging = $EnableLogging
    EnableBackup = $EnableBackup
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "DNS Server Deployment" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Environment: $Environment" -ForegroundColor Yellow
Write-Host "Zone Name: $ZoneName" -ForegroundColor Yellow
Write-Host "Forwarders: $($Forwarders -join ', ')" -ForegroundColor Yellow
Write-Host "DNSSEC: $EnableDNSSEC" -ForegroundColor Yellow
Write-Host "Security: $EnableSecurity" -ForegroundColor Yellow
Write-Host "Monitoring: $EnableMonitoring" -ForegroundColor Yellow
Write-Host "Computer: $($scriptConfig.ComputerName)" -ForegroundColor Yellow
Write-Host "Timestamp: $($scriptConfig.Timestamp)" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Test prerequisites
Write-Host "Testing prerequisites..." -ForegroundColor Green
$prerequisites = Test-DNSPrerequisites

if (-not $prerequisites.AdministratorPrivileges) {
    Write-Error "Administrator privileges are required for DNS server deployment."
    exit 1
}

if (-not $prerequisites.WindowsVersion) {
    Write-Error "Windows Server 2016 or later is required for DNS server deployment."
    exit 1
}

if (-not $prerequisites.PowerShellVersion) {
    Write-Error "PowerShell 5.1 or later is required for DNS server deployment."
    exit 1
}

Write-Host "Prerequisites check passed!" -ForegroundColor Green

# Install DNS Server role
Write-Host "Installing DNS Server role..." -ForegroundColor Green
$installResult = Install-DNSServer -IncludeManagementTools

if ($installResult.Success) {
    Write-Host "DNS Server role installed successfully!" -ForegroundColor Green
} else {
    Write-Error "Failed to install DNS Server role: $($installResult.Error)"
    exit 1
}

# Create primary zone
Write-Host "Creating primary zone: $ZoneName" -ForegroundColor Green
$zoneResult = New-DNSZone -ZoneName $ZoneName -ZoneType "Primary" -ReplicationScope "Domain" -DynamicUpdate "Secure" -AgingEnabled

if ($zoneResult.Success) {
    Write-Host "Primary zone '$ZoneName' created successfully!" -ForegroundColor Green
} else {
    Write-Warning "Failed to create primary zone '$ZoneName': $($zoneResult.Error)"
}

# Configure forwarders
Write-Host "Configuring DNS forwarders..." -ForegroundColor Green
$forwarderResult = Set-DNSForwarders -Forwarders $Forwarders -EnableRecursion

if ($forwarderResult.Success) {
    Write-Host "DNS forwarders configured successfully!" -ForegroundColor Green
} else {
    Write-Warning "Failed to configure DNS forwarders: $($forwarderResult.Error)"
}

# Add basic DNS records
Write-Host "Adding basic DNS records..." -ForegroundColor Green

# Add SOA record (usually created automatically)
# Add NS record (usually created automatically)

# Add A record for the zone
$arecordResult = Add-DNSRecord -ZoneName $ZoneName -RecordType "A" -Name "@" -Value "192.168.1.10"
if ($arecordResult.Success) {
    Write-Host "A record added successfully!" -ForegroundColor Green
}

# Add A record for www
$wwwRecordResult = Add-DNSRecord -ZoneName $ZoneName -RecordType "A" -Name "www" -Value "192.168.1.10"
if ($wwwRecordResult.Success) {
    Write-Host "WWW A record added successfully!" -ForegroundColor Green
}

# Add MX record
$mxRecordResult = Add-DNSRecord -ZoneName $ZoneName -RecordType "MX" -Name "@" -Value "mail.$ZoneName" -Priority 10
if ($mxRecordResult.Success) {
    Write-Host "MX record added successfully!" -ForegroundColor Green
}

# Add CNAME record
$cnameRecordResult = Add-DNSRecord -ZoneName $ZoneName -RecordType "CNAME" -Name "mail" -Value "server1.$ZoneName"
if ($cnameRecordResult.Success) {
    Write-Host "CNAME record added successfully!" -ForegroundColor Green
}

# Enable DNSSEC if requested
if ($EnableDNSSEC) {
    Write-Host "Enabling DNSSEC..." -ForegroundColor Green
    $dnssecResult = Enable-DNSSEC -ZoneName $ZoneName -EnableAutoKeyRollover
    
    if ($dnssecResult.Success) {
        Write-Host "DNSSEC enabled successfully!" -ForegroundColor Green
    } else {
        Write-Warning "Failed to enable DNSSEC: $($dnssecResult.Error)"
    }
}

# Enable security features if requested
if ($EnableSecurity) {
    Write-Host "Configuring DNS security features..." -ForegroundColor Green
    
    # Configure security policies
    $securityResult = Set-DNSSecurityPolicies -EnableRecursionControl -EnableCacheLocking -EnableResponseRateLimiting -EnableEDNS -EnableIPv6
    
    if ($securityResult.Success) {
        Write-Host "DNS security policies configured successfully!" -ForegroundColor Green
    } else {
        Write-Warning "Failed to configure DNS security policies: $($securityResult.Error)"
    }
    
    # Configure access control
    $accessControlResult = Set-DNSAccessControl -EnableZoneTransferControl -EnableDynamicUpdateControl
    
    if ($accessControlResult.Success) {
        Write-Host "DNS access control configured successfully!" -ForegroundColor Green
    } else {
        Write-Warning "Failed to configure DNS access control: $($accessControlResult.Error)"
    }
    
    # Enable threat detection
    $threatDetectionResult = Enable-DNSThreatDetection -EnableQueryAnalysis -EnableAnomalyDetection -EnableMalwareDetection -SIEMIntegration
    
    if ($threatDetectionResult.Success) {
        Write-Host "DNS threat detection enabled successfully!" -ForegroundColor Green
    } else {
        Write-Warning "Failed to enable DNS threat detection: $($threatDetectionResult.Error)"
    }
}

# Enable logging if requested
if ($EnableLogging) {
    Write-Host "Enabling DNS logging..." -ForegroundColor Green
    $loggingResult = Enable-DNSLogging -LogLevel "All" -EnableQueryLogging -EnableDebugLogging
    
    if ($loggingResult.Success) {
        Write-Host "DNS logging enabled successfully!" -ForegroundColor Green
    } else {
        Write-Warning "Failed to enable DNS logging: $($loggingResult.Error)"
    }
}

# Enable monitoring if requested
if ($EnableMonitoring) {
    Write-Host "Enabling DNS monitoring..." -ForegroundColor Green
    
    # Configure alerting
    $alertingResult = Set-DNSAlerting -EnableEmailAlerts -EnableSIEMIntegration -EnablePerformanceAlerts -EnableSecurityAlerts
    
    if ($alertingResult.Success) {
        Write-Host "DNS alerting configured successfully!" -ForegroundColor Green
    } else {
        Write-Warning "Failed to configure DNS alerting: $($alertingResult.Error)"
    }
    
    # Start monitoring
    $monitoringResult = Start-DNSMonitoring -MonitoringInterval 60 -EnablePerformanceMonitoring -EnableQueryAnalysis -EnableAlerting
    
    if ($monitoringResult.Success) {
        Write-Host "DNS monitoring started successfully!" -ForegroundColor Green
    } else {
        Write-Warning "Failed to start DNS monitoring: $($monitoringResult.Error)"
    }
}

# Create backup if requested
if ($EnableBackup) {
    Write-Host "Creating DNS configuration backup..." -ForegroundColor Green
    $backupResult = Backup-DNSConfiguration -IncludeZones -IncludeRecords
    
    if ($backupResult.Success) {
        Write-Host "DNS configuration backup created successfully!" -ForegroundColor Green
    } else {
        Write-Warning "Failed to create DNS configuration backup: $($backupResult.Error)"
    }
}

# Get final DNS status
Write-Host "Getting final DNS status..." -ForegroundColor Green
$finalStatus = Get-DNSServerStatus

if ($finalStatus.Success) {
    Write-Host "Final DNS Status:" -ForegroundColor Cyan
    Write-Host "  Service Status: $($finalStatus.ServiceStatus.Status)" -ForegroundColor White
    Write-Host "  Zones Configured: $($finalStatus.ZoneCount)" -ForegroundColor White
    Write-Host "  Forwarders Configured: $($finalStatus.ForwarderCount)" -ForegroundColor White
    Write-Host "  DNSSEC Enabled: $($finalStatus.ServerConfiguration.EnableDnsSec)" -ForegroundColor White
    Write-Host "  IPv6 Enabled: $($finalStatus.ServerConfiguration.EnableIPv6)" -ForegroundColor White
} else {
    Write-Warning "Failed to get final DNS status: $($finalStatus.Error)"
}

# Get DNS statistics
Write-Host "Getting DNS statistics..." -ForegroundColor Green
$statistics = Get-DNSStatistics

if ($statistics.Success) {
    Write-Host "DNS Statistics:" -ForegroundColor Cyan
    Write-Host "  Total Queries: $($statistics.Statistics.TotalQueries)" -ForegroundColor White
    Write-Host "  Total Responses: $($statistics.Statistics.TotalResponses)" -ForegroundColor White
    Write-Host "  Queries Per Second: $($statistics.Statistics.QueriesPerSecond)" -ForegroundColor White
    Write-Host "  Cache Hits: $($statistics.Statistics.CacheHits)" -ForegroundColor White
    Write-Host "  Cache Misses: $($statistics.Statistics.CacheMisses)" -ForegroundColor White
} else {
    Write-Warning "Failed to get DNS statistics: $($statistics.Error)"
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "DNS Server Deployment Completed!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan

# Summary
Write-Host "Deployment Summary:" -ForegroundColor Yellow
Write-Host "  Environment: $Environment" -ForegroundColor White
Write-Host "  Zone Name: $ZoneName" -ForegroundColor White
Write-Host "  Forwarders: $($Forwarders -join ', ')" -ForegroundColor White
Write-Host "  DNSSEC Enabled: $EnableDNSSEC" -ForegroundColor White
Write-Host "  Security Enabled: $EnableSecurity" -ForegroundColor White
Write-Host "  Monitoring Enabled: $EnableMonitoring" -ForegroundColor White
Write-Host "  Logging Enabled: $EnableLogging" -ForegroundColor White
Write-Host "  Backup Enabled: $EnableBackup" -ForegroundColor White
Write-Host "  Completion Time: $(Get-Date)" -ForegroundColor White
