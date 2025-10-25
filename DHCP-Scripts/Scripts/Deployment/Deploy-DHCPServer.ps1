#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Complete DHCP Server Deployment Script

.DESCRIPTION
    This script deploys a complete DHCP server with all enterprise features including
    scopes, options, reservations, failover, security, monitoring, and troubleshooting.

.PARAMETER Environment
    Environment type (Development, Staging, Production)

.PARAMETER ScopeName
    Name of the primary DHCP scope

.PARAMETER StartRange
    Start IP address for the scope

.PARAMETER EndRange
    End IP address for the scope

.PARAMETER SubnetMask
    Subnet mask for the scope

.PARAMETER Router
    Router IP address (Option 3)

.PARAMETER DNSServers
    Array of DNS server IP addresses (Option 6)

.PARAMETER DomainName
    DNS domain name (Option 15)

.PARAMETER EnableFailover
    Enable DHCP failover

.PARAMETER PartnerServer
    Partner DHCP server for failover

.PARAMETER EnableSecurity
    Enable DHCP security features

.PARAMETER EnableMonitoring
    Enable DHCP monitoring

.PARAMETER EnableAuditLogging
    Enable audit logging

.PARAMETER BackupPath
    Path for DHCP backups

.EXAMPLE
    .\Deploy-DHCP.ps1 -Environment "Production" -ScopeName "Production" -StartRange "192.168.1.100" -EndRange "192.168.1.200" -SubnetMask "255.255.255.0" -Router "192.168.1.1" -DNSServers @("8.8.8.8", "8.8.4.4") -EnableSecurity -EnableMonitoring

.NOTES
    Author: DHCP PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Development", "Staging", "Production")]
    [string]$Environment,

    [Parameter(Mandatory = $true)]
    [string]$ScopeName,

    [Parameter(Mandatory = $true)]
    [string]$StartRange,

    [Parameter(Mandatory = $true)]
    [string]$EndRange,

    [Parameter(Mandatory = $true)]
    [string]$SubnetMask,

    [Parameter(Mandatory = $false)]
    [string]$Router,

    [Parameter(Mandatory = $false)]
    [string[]]$DNSServers,

    [Parameter(Mandatory = $false)]
    [string]$DomainName,

    [Parameter(Mandatory = $false)]
    [switch]$EnableFailover,

    [Parameter(Mandatory = $false)]
    [string]$PartnerServer,

    [Parameter(Mandatory = $false)]
    [switch]$EnableSecurity,

    [Parameter(Mandatory = $false)]
    [switch]$EnableMonitoring,

    [Parameter(Mandatory = $false)]
    [switch]$EnableAuditLogging,

    [Parameter(Mandatory = $false)]
    [string]$BackupPath = "C:\DHCP\Backup"
)

# Script configuration
$scriptConfig = @{
    Environment = $Environment
    ScopeName = $ScopeName
    StartRange = $StartRange
    EndRange = $EndRange
    SubnetMask = $SubnetMask
    Router = $Router
    DNSServers = $DNSServers
    DomainName = $DomainName
    EnableFailover = $EnableFailover
    PartnerServer = $PartnerServer
    EnableSecurity = $EnableSecurity
    EnableMonitoring = $EnableMonitoring
    EnableAuditLogging = $EnableAuditLogging
    BackupPath = $BackupPath
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "DHCP Server Deployment" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Environment: $Environment" -ForegroundColor Yellow
Write-Host "Scope Name: $ScopeName" -ForegroundColor Yellow
Write-Host "IP Range: $StartRange - $EndRange" -ForegroundColor Yellow
Write-Host "Subnet Mask: $SubnetMask" -ForegroundColor Yellow
Write-Host "Computer: $($scriptConfig.ComputerName)" -ForegroundColor Yellow
Write-Host "Timestamp: $($scriptConfig.Timestamp)" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Import required modules
try {
    Import-Module "..\Modules\DHCP-Core.psm1" -Force
    Import-Module "..\Modules\DHCP-Security.psm1" -Force
    Import-Module "..\Modules\DHCP-Monitoring.psm1" -Force
    Import-Module "..\Modules\DHCP-Troubleshooting.psm1" -Force
    Write-Host "DHCP modules imported successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to import DHCP modules: $($_.Exception.Message)"
    exit 1
}

# Step 1: Check prerequisites
Write-Host "`nStep 1: Checking prerequisites..." -ForegroundColor Green
$prerequisites = Test-DHCPPrerequisites

if (-not $prerequisites.WindowsVersion) {
    Write-Error "Windows version not supported. Requires Windows Server 2016 or later."
    exit 1
}

if (-not $prerequisites.PowerShellVersion) {
    Write-Error "PowerShell version not supported. Requires PowerShell 5.1 or later."
    exit 1
}

if (-not $prerequisites.AdministratorPrivileges) {
    Write-Error "Administrator privileges required."
    exit 1
}

Write-Host "Prerequisites check passed!" -ForegroundColor Green

# Step 2: Install DHCP Server role
Write-Host "`nStep 2: Installing DHCP Server role..." -ForegroundColor Green
$installResult = Install-DHCPServer -IncludeManagementTools

if (-not $installResult.Success) {
    Write-Error "Failed to install DHCP Server role: $($installResult.Error)"
    exit 1
}

Write-Host "DHCP Server role installed successfully!" -ForegroundColor Green

# Step 3: Create backup directory
Write-Host "`nStep 3: Setting up backup directory..." -ForegroundColor Green
if (-not (Test-Path $BackupPath)) {
    New-Item -Path $BackupPath -ItemType Directory -Force
    Write-Host "Backup directory created: $BackupPath" -ForegroundColor Green
} else {
    Write-Host "Backup directory already exists: $BackupPath" -ForegroundColor Yellow
}

# Step 4: Create DHCP scope
Write-Host "`nStep 4: Creating DHCP scope..." -ForegroundColor Green
$scopeResult = New-DHCPScope -ScopeName $ScopeName -StartRange $StartRange -EndRange $EndRange -SubnetMask $SubnetMask

if (-not $scopeResult.Success) {
    Write-Error "Failed to create DHCP scope: $($scopeResult.Error)"
    exit 1
}

Write-Host "DHCP scope created successfully!" -ForegroundColor Green

# Step 5: Configure DHCP options
Write-Host "`nStep 5: Configuring DHCP options..." -ForegroundColor Green
$optionsResult = Set-DHCPOptions -ScopeId $scopeResult.ScopeId -Router $Router -DNSServers $DNSServers -DomainName $DomainName

if (-not $optionsResult.Success) {
    Write-Warning "Failed to configure some DHCP options: $($optionsResult.Error)"
} else {
    Write-Host "DHCP options configured successfully!" -ForegroundColor Green
}

# Step 6: Enable audit logging
if ($EnableAuditLogging) {
    Write-Host "`nStep 6: Enabling audit logging..." -ForegroundColor Green
    $auditResult = Enable-DHCPAuditLogging -AuditLogPath "C:\DHCP\AuditLogs" -EnableAuditLog

    if (-not $auditResult.Success) {
        Write-Warning "Failed to enable audit logging: $($auditResult.Error)"
    } else {
        Write-Host "Audit logging enabled successfully!" -ForegroundColor Green
    }
}

# Step 7: Configure security features
if ($EnableSecurity) {
    Write-Host "`nStep 7: Configuring security features..." -ForegroundColor Green
    
    # Authorize DHCP server
    $authResult = Authorize-DHCPServer
    if (-not $authResult.Success) {
        Write-Warning "Failed to authorize DHCP server: $($authResult.Error)"
    } else {
        Write-Host "DHCP server authorized successfully!" -ForegroundColor Green
    }

    # Enable security policies
    $securityResult = Enable-DHCPSecurityPolicies -EnableConflictDetection -EnableAuditLogging
    if (-not $securityResult.Success) {
        Write-Warning "Failed to enable security policies: $($securityResult.Error)"
    } else {
        Write-Host "Security policies enabled successfully!" -ForegroundColor Green
    }
}

# Step 8: Configure failover
if ($EnableFailover -and $PartnerServer) {
    Write-Host "`nStep 8: Configuring DHCP failover..." -ForegroundColor Green
    $failoverResult = Enable-DHCPFailover -PartnerServer $PartnerServer -ScopeId $scopeResult.ScopeId -FailoverMode "LoadBalance"

    if (-not $failoverResult.Success) {
        Write-Warning "Failed to configure DHCP failover: $($failoverResult.Error)"
    } else {
        Write-Host "DHCP failover configured successfully!" -ForegroundColor Green
    }
}

# Step 9: Configure monitoring
if ($EnableMonitoring) {
    Write-Host "`nStep 9: Configuring monitoring..." -ForegroundColor Green
    $monitoringResult = Set-DHCPAlerting -AlertTypes @("HighPacketRate", "LowLeaseUtilization", "HighDeclineRate", "ServiceDown")

    if (-not $monitoringResult.Success) {
        Write-Warning "Failed to configure monitoring: $($monitoringResult.Error)"
    } else {
        Write-Host "Monitoring configured successfully!" -ForegroundColor Green
    }
}

# Step 10: Get final status
Write-Host "`nStep 10: Getting final status..." -ForegroundColor Green
$statusResult = Get-DHCPServerStatus

if ($statusResult.Success) {
    Write-Host "DHCP Server Status:" -ForegroundColor Green
    Write-Host "  Service Status: $($statusResult.ServiceStatus.Status)" -ForegroundColor Cyan
    Write-Host "  Authorized: $($statusResult.ServerConfiguration.Authorized)" -ForegroundColor Cyan
    Write-Host "  Scope Count: $($statusResult.ScopeCount)" -ForegroundColor Cyan
    Write-Host "  Lease Count: $($statusResult.LeaseCount)" -ForegroundColor Cyan
} else {
    Write-Warning "Could not get final status: $($statusResult.Error)"
}

# Step 11: Get statistics
Write-Host "`nStep 11: Getting DHCP statistics..." -ForegroundColor Green
$statsResult = Get-DHCPStatistics

if ($statsResult.Success) {
    Write-Host "DHCP Statistics:" -ForegroundColor Green
    Write-Host "  Total Scopes: $($statsResult.Statistics.TotalScopes)" -ForegroundColor Cyan
    Write-Host "  Active Scopes: $($statsResult.Statistics.ActiveScopes)" -ForegroundColor Cyan
    Write-Host "  Total Addresses: $($statsResult.Statistics.TotalAddresses)" -ForegroundColor Cyan
    Write-Host "  In Use Addresses: $($statsResult.Statistics.InUseAddresses)" -ForegroundColor Cyan
    Write-Host "  Available Addresses: $($statsResult.Statistics.AvailableAddresses)" -ForegroundColor Cyan
} else {
    Write-Warning "Could not get statistics: $($statsResult.Error)"
}

# Step 12: Test configuration
Write-Host "`nStep 12: Testing configuration..." -ForegroundColor Green
$testResult = Test-DHCPConfiguration

if ($testResult.Success) {
    if ($testResult.ConfigurationValid) {
        Write-Host "Configuration test passed!" -ForegroundColor Green
    } else {
        Write-Warning "Configuration issues found:"
        foreach ($issue in $testResult.IssuesFound) {
            Write-Warning "  - $issue"
        }
        Write-Host "Recommendations:"
        foreach ($recommendation in $testResult.Recommendations) {
            Write-Host "  - $recommendation" -ForegroundColor Yellow
        }
    }
} else {
    Write-Warning "Configuration test failed: $($testResult.Error)"
}

# Final summary
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "DHCP Server Deployment Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Environment: $Environment" -ForegroundColor Yellow
Write-Host "Scope Name: $ScopeName" -ForegroundColor Yellow
Write-Host "IP Range: $StartRange - $EndRange" -ForegroundColor Yellow
Write-Host "Subnet Mask: $SubnetMask" -ForegroundColor Yellow
Write-Host "Router: $Router" -ForegroundColor Yellow
Write-Host "DNS Servers: $($DNSServers -join ', ')" -ForegroundColor Yellow
Write-Host "Domain Name: $DomainName" -ForegroundColor Yellow
Write-Host "Failover Enabled: $EnableFailover" -ForegroundColor Yellow
Write-Host "Security Enabled: $EnableSecurity" -ForegroundColor Yellow
Write-Host "Monitoring Enabled: $EnableMonitoring" -ForegroundColor Yellow
Write-Host "Audit Logging Enabled: $EnableAuditLogging" -ForegroundColor Yellow
Write-Host "Backup Path: $BackupPath" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

if ($statusResult.Success -and $statusResult.ServiceStatus.Status -eq "Running") {
    Write-Host "`n🎉 DHCP Server deployment completed successfully!" -ForegroundColor Green
    Write-Host "The DHCP server is now running and ready to serve clients." -ForegroundColor Green
} else {
    Write-Host "`n⚠️ DHCP Server deployment completed with warnings." -ForegroundColor Yellow
    Write-Host "Please review the output above for any issues that need attention." -ForegroundColor Yellow
}

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Test DHCP functionality with a client" -ForegroundColor White
Write-Host "2. Configure additional scopes if needed" -ForegroundColor White
Write-Host "3. Set up monitoring and alerting" -ForegroundColor White
Write-Host "4. Configure backup schedules" -ForegroundColor White
Write-Host "5. Review security settings" -ForegroundColor White
Write-Host "6. Document the configuration" -ForegroundColor White
