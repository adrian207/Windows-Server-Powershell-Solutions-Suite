#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Complete AD LDS Deployment Script

.DESCRIPTION
    This script deploys a complete AD LDS instance with all enterprise features including
    instances, partitions, users, groups, schema extensions, security, monitoring, and troubleshooting.

.PARAMETER Environment
    Environment type (Development, Staging, Production)

.PARAMETER InstanceName
    Name of the AD LDS instance

.PARAMETER Port
    LDAP port for the instance

.PARAMETER SSLPort
    SSL port for the instance

.PARAMETER DataPath
    Path for AD LDS data files

.PARAMETER LogPath
    Path for AD LDS log files

.PARAMETER ServiceAccount
    Service account for the instance

.PARAMETER PartitionDN
    Distinguished name of the primary partition

.PARAMETER EnableSecurity
    Enable AD LDS security features

.PARAMETER EnableMonitoring
    Enable AD LDS monitoring

.PARAMETER EnableAuditLogging
    Enable audit logging

.PARAMETER CustomSchema
    Custom schema attributes to add

.PARAMETER BackupPath
    Path for AD LDS backups

.EXAMPLE
    .\Deploy-ADLDS.ps1 -Environment "Production" -InstanceName "AppDirectory" -Port 389 -SSLPort 636 -PartitionDN "CN=AppUsers,DC=AppDir,DC=local" -EnableSecurity -EnableMonitoring

.NOTES
    Author: AD LDS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Development", "Staging", "Production")]
    [string]$Environment,

    [Parameter(Mandatory = $true)]
    [string]$InstanceName,

    [Parameter(Mandatory = $false)]
    [int]$Port = 389,

    [Parameter(Mandatory = $false)]
    [int]$SSLPort = 636,

    [Parameter(Mandatory = $false)]
    [string]$DataPath = "C:\Program Files\Microsoft ADAM\$InstanceName\data",

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Program Files\Microsoft ADAM\$InstanceName\logs",

    [Parameter(Mandatory = $false)]
    [string]$ServiceAccount,

    [Parameter(Mandatory = $false)]
    [string]$PartitionDN,

    [Parameter(Mandatory = $false)]
    [switch]$EnableSecurity,

    [Parameter(Mandatory = $false)]
    [switch]$EnableMonitoring,

    [Parameter(Mandatory = $false)]
    [switch]$EnableAuditLogging,

    [Parameter(Mandatory = $false)]
    [string[]]$CustomSchema,

    [Parameter(Mandatory = $false)]
    [string]$BackupPath = "C:\ADLDS\Backup"
)

# Script configuration
$scriptConfig = @{
    Environment = $Environment
    InstanceName = $InstanceName
    Port = $Port
    SSLPort = $SSLPort
    DataPath = $DataPath
    LogPath = $LogPath
    ServiceAccount = $ServiceAccount
    PartitionDN = $PartitionDN
    EnableSecurity = $EnableSecurity
    EnableMonitoring = $EnableMonitoring
    EnableAuditLogging = $EnableAuditLogging
    CustomSchema = $CustomSchema
    BackupPath = $BackupPath
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "AD LDS Deployment" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Environment: $Environment" -ForegroundColor Yellow
Write-Host "Instance Name: $InstanceName" -ForegroundColor Yellow
Write-Host "LDAP Port: $Port" -ForegroundColor Yellow
Write-Host "SSL Port: $SSLPort" -ForegroundColor Yellow
Write-Host "Partition DN: $PartitionDN" -ForegroundColor Yellow
Write-Host "Computer: $($scriptConfig.ComputerName)" -ForegroundColor Yellow
Write-Host "Timestamp: $($scriptConfig.Timestamp)" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Import required modules
try {
    Import-Module "..\Modules\ADLDS-Core.psm1" -Force
    Import-Module "..\Modules\ADLDS-Security.psm1" -Force
    Import-Module "..\Modules\ADLDS-Monitoring.psm1" -Force
    Import-Module "..\Modules\ADLDS-Troubleshooting.psm1" -Force
    Write-Host "AD LDS modules imported successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to import AD LDS modules: $($_.Exception.Message)"
    exit 1
}

# Step 1: Check prerequisites
Write-Host "`nStep 1: Checking prerequisites..." -ForegroundColor Green
$prerequisites = Test-ADLDSPrerequisites

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

# Step 2: Install AD LDS role
Write-Host "`nStep 2: Installing AD LDS role..." -ForegroundColor Green
$installResult = Install-ADLDS -IncludeManagementTools

if (-not $installResult.Success) {
    Write-Error "Failed to install AD LDS role: $($installResult.Error)"
    exit 1
}

Write-Host "AD LDS role installed successfully!" -ForegroundColor Green

# Step 3: Create backup directory
Write-Host "`nStep 3: Setting up backup directory..." -ForegroundColor Green
if (-not (Test-Path $BackupPath)) {
    New-Item -Path $BackupPath -ItemType Directory -Force
    Write-Host "Backup directory created: $BackupPath" -ForegroundColor Green
} else {
    Write-Host "Backup directory already exists: $BackupPath" -ForegroundColor Yellow
}

# Step 4: Create AD LDS instance
Write-Host "`nStep 4: Creating AD LDS instance..." -ForegroundColor Green
$instanceResult = New-ADLDSInstance -InstanceName $InstanceName -Port $Port -SSLPort $SSLPort -DataPath $DataPath -LogPath $LogPath -ServiceAccount $ServiceAccount

if (-not $instanceResult.Success) {
    Write-Error "Failed to create AD LDS instance: $($instanceResult.Error)"
    exit 1
}

Write-Host "AD LDS instance created successfully!" -ForegroundColor Green

# Step 5: Create primary partition
if ($PartitionDN) {
    Write-Host "`nStep 5: Creating primary partition..." -ForegroundColor Green
    $partitionResult = New-ADLDSPartition -InstanceName $InstanceName -PartitionName "Primary" -PartitionDN $PartitionDN

    if (-not $partitionResult.Success) {
        Write-Warning "Failed to create primary partition: $($partitionResult.Error)"
    } else {
        Write-Host "Primary partition created successfully!" -ForegroundColor Green
    }
}

# Step 6: Configure custom schema
if ($CustomSchema) {
    Write-Host "`nStep 6: Configuring custom schema..." -ForegroundColor Green
    $schemaResult = Set-ADLDSSchema -InstanceName $InstanceName -CustomAttributes $CustomSchema

    if (-not $schemaResult.Success) {
        Write-Warning "Failed to configure custom schema: $($schemaResult.Error)"
    } else {
        Write-Host "Custom schema configured successfully!" -ForegroundColor Green
    }
}

# Step 7: Configure security features
if ($EnableSecurity) {
    Write-Host "`nStep 7: Configuring security features..." -ForegroundColor Green
    
    # Configure authentication
    $authResult = Set-ADLDSAuthentication -InstanceName $InstanceName -AuthenticationType "Negotiate" -EnableSSL
    if (-not $authResult.Success) {
        Write-Warning "Failed to configure authentication: $($authResult.Error)"
    } else {
        Write-Host "Authentication configured successfully!" -ForegroundColor Green
    }

    # Enable security policies
    $securityResult = Enable-ADLDSSecurityPolicies -InstanceName $InstanceName -EnableAuditLogging -EnablePasswordPolicy -EnableAccountLockout
    if (-not $securityResult.Success) {
        Write-Warning "Failed to enable security policies: $($securityResult.Error)"
    } else {
        Write-Host "Security policies enabled successfully!" -ForegroundColor Green
    }
}

# Step 8: Configure monitoring
if ($EnableMonitoring) {
    Write-Host "`nStep 8: Configuring monitoring..." -ForegroundColor Green
    $monitoringResult = Set-ADLDSAlerting -InstanceName $InstanceName -AlertTypes @("HighConnectionRate", "HighQueryRate", "HighErrorRate", "ServiceDown")

    if (-not $monitoringResult.Success) {
        Write-Warning "Failed to configure monitoring: $($monitoringResult.Error)"
    } else {
        Write-Host "Monitoring configured successfully!" -ForegroundColor Green
    }
}

# Step 9: Get final status
Write-Host "`nStep 9: Getting final status..." -ForegroundColor Green
$statusResult = Get-ADLDSInstanceStatus -InstanceName $InstanceName

if ($statusResult.Success) {
    Write-Host "AD LDS Instance Status:" -ForegroundColor Green
    Write-Host "  Instance Name: $($statusResult.InstanceName)" -ForegroundColor Cyan
    Write-Host "  Service Status: $($statusResult.ServiceStatus.Status)" -ForegroundColor Cyan
    Write-Host "  Partition Count: $($statusResult.PartitionCount)" -ForegroundColor Cyan
    Write-Host "  User Count: $($statusResult.UserCount)" -ForegroundColor Cyan
} else {
    Write-Warning "Could not get final status: $($statusResult.Error)"
}

# Step 10: Get statistics
Write-Host "`nStep 10: Getting AD LDS statistics..." -ForegroundColor Green
$statsResult = Get-ADLDSStatistics -InstanceName $InstanceName

if ($statsResult.Success) {
    Write-Host "AD LDS Statistics:" -ForegroundColor Green
    Write-Host "  Instance Name: $($statsResult.Statistics.InstanceName)" -ForegroundColor Cyan
    Write-Host "  Service Status: $($statsResult.Statistics.ServiceStatus)" -ForegroundColor Cyan
    Write-Host "  Partition Count: $($statsResult.Statistics.PartitionCount)" -ForegroundColor Cyan
    Write-Host "  User Count: $($statsResult.Statistics.UserCount)" -ForegroundColor Cyan
    Write-Host "  Group Count: $($statsResult.Statistics.GroupCount)" -ForegroundColor Cyan
    Write-Host "  Connection Count: $($statsResult.Statistics.ConnectionCount)" -ForegroundColor Cyan
} else {
    Write-Warning "Could not get statistics: $($statsResult.Error)"
}

# Step 11: Test configuration
Write-Host "`nStep 11: Testing configuration..." -ForegroundColor Green
$testResult = Test-ADLDSConfiguration -InstanceName $InstanceName

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
Write-Host "AD LDS Deployment Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Environment: $Environment" -ForegroundColor Yellow
Write-Host "Instance Name: $InstanceName" -ForegroundColor Yellow
Write-Host "LDAP Port: $Port" -ForegroundColor Yellow
Write-Host "SSL Port: $SSLPort" -ForegroundColor Yellow
Write-Host "Data Path: $DataPath" -ForegroundColor Yellow
Write-Host "Log Path: $LogPath" -ForegroundColor Yellow
Write-Host "Service Account: $ServiceAccount" -ForegroundColor Yellow
Write-Host "Partition DN: $PartitionDN" -ForegroundColor Yellow
Write-Host "Security Enabled: $EnableSecurity" -ForegroundColor Yellow
Write-Host "Monitoring Enabled: $EnableMonitoring" -ForegroundColor Yellow
Write-Host "Audit Logging Enabled: $EnableAuditLogging" -ForegroundColor Yellow
Write-Host "Custom Schema: $($CustomSchema -join ', ')" -ForegroundColor Yellow
Write-Host "Backup Path: $BackupPath" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

if ($statusResult.Success -and $statusResult.ServiceStatus.Status -eq "Running") {
    Write-Host "`n🎉 AD LDS deployment completed successfully!" -ForegroundColor Green
    Write-Host "The AD LDS instance is now running and ready to serve LDAP clients." -ForegroundColor Green
} else {
    Write-Host "`n⚠️ AD LDS deployment completed with warnings." -ForegroundColor Yellow
    Write-Host "Please review the output above for any issues that need attention." -ForegroundColor Yellow
}

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Test LDAP connectivity with a client" -ForegroundColor White
Write-Host "2. Create additional partitions if needed" -ForegroundColor White
Write-Host "3. Add users and groups to partitions" -ForegroundColor White
Write-Host "4. Configure LDAP applications to use the instance" -ForegroundColor White
Write-Host "5. Set up monitoring and alerting" -ForegroundColor White
Write-Host "6. Configure backup schedules" -ForegroundColor White
Write-Host "7. Review security settings" -ForegroundColor White
Write-Host "8. Document the configuration" -ForegroundColor White
