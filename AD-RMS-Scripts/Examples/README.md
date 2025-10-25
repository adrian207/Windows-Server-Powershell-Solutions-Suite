# AD RMS PowerShell Scripts - Examples

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Date:** December 2024

This directory contains practical examples and templates for using the AD RMS PowerShell scripts in various scenarios.

## Quick Start Examples

### Basic Installation

```powershell
# Example 1: Basic AD RMS installation
$securePassword = ConvertTo-SecureString "MySecurePassword123!" -AsPlainText -Force
.\Scripts\Implementation\Install-ADRMS.ps1 -DomainName "contoso.com" -ServiceAccountPassword $securePassword
```

### Advanced Installation with Custom Settings

```powershell
# Example 2: Advanced installation with custom database and service account
$securePassword = ConvertTo-SecureString "MySecurePassword123!" -AsPlainText -Force
.\Scripts\Implementation\Install-ADRMS.ps1 -DomainName "contoso.com" -ServiceAccount "RMS_SVC" -ServiceAccountPassword $securePassword -DatabaseServer "SQL01" -DatabaseName "RMS_DB" -ClusterUrl "https://rms.contoso.com/_wmcs"
```

### Service Account Management

```powershell
# Example 3: Create and configure service account
$securePassword = ConvertTo-SecureString "MySecurePassword123!" -AsPlainText -Force
.\Scripts\Configuration\Manage-ADRMSServiceAccount.ps1 -Action Create -ServiceAccount "RMS_Service" -ServiceAccountPassword $securePassword -DomainName "contoso.com" -AccountDescription "AD RMS Service Account" -PasswordNeverExpires
```

### Configuration Management

```powershell
# Example 4: Backup and restore configuration
# Backup
.\Scripts\Configuration\Manage-ADRMSConfiguration.ps1 -Action Backup -BackupPath "C:\Backups\ADRMS-Config-$(Get-Date -Format 'yyyyMMdd').xml"

# Restore
.\Scripts\Configuration\Manage-ADRMSConfiguration.ps1 -Action Restore -RestorePath "C:\Backups\ADRMS-Config-20240101.xml"
```

### Health Monitoring

```powershell
# Example 5: Set up continuous health monitoring
.\Scripts\Troubleshooting\Monitor-ADRMSHealth.ps1 -Action Schedule -CreateTask -TaskName "AD RMS Health Monitor" -TaskInterval 5
```

## Complete Deployment Examples

### Example 1: New AD RMS Deployment

```powershell
# Complete deployment script
param(
    [Parameter(Mandatory = $true)]
    [string]$DomainName,
    
    [Parameter(Mandatory = $true)]
    [SecureString]$ServiceAccountPassword
)

Write-Host "Starting AD RMS deployment..." -ForegroundColor Green

# Step 1: Check prerequisites
Write-Host "Step 1: Checking prerequisites..." -ForegroundColor Yellow
if (-not (Test-ADRMSPrerequisites)) {
    Write-Error "Prerequisites check failed. Please resolve issues before continuing."
    exit 1
}

# Step 2: Install AD RMS
Write-Host "Step 2: Installing AD RMS..." -ForegroundColor Yellow
.\Scripts\Implementation\Install-ADRMS.ps1 -DomainName $DomainName -ServiceAccountPassword $ServiceAccountPassword

# Step 3: Validate installation
Write-Host "Step 3: Validating installation..." -ForegroundColor Yellow
.\Scripts\Troubleshooting\Troubleshoot-ADRMS.ps1 -Action Diagnose

# Step 4: Set up monitoring
Write-Host "Step 4: Setting up monitoring..." -ForegroundColor Yellow
.\Scripts\Troubleshooting\Monitor-ADRMSHealth.ps1 -Action Schedule -CreateTask -TaskName "AD RMS Health Monitor"

Write-Host "AD RMS deployment completed successfully!" -ForegroundColor Green
```

### Example 2: AD RMS Migration

```powershell
# Migration script for moving AD RMS to a new server
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceServer,
    
    [Parameter(Mandatory = $true)]
    [string]$TargetDomainName,
    
    [Parameter(Mandatory = $true)]
    [SecureString]$ServiceAccountPassword
)

Write-Host "Starting AD RMS migration..." -ForegroundColor Green

# Step 1: Backup source configuration
Write-Host "Step 1: Backing up source configuration..." -ForegroundColor Yellow
# Note: This would need to be run on the source server
# .\Scripts\Configuration\Manage-ADRMSConfiguration.ps1 -Action Backup -BackupPath "C:\Backups\ADRMS-Source-Config.xml"

# Step 2: Install on target server
Write-Host "Step 2: Installing AD RMS on target server..." -ForegroundColor Yellow
.\Scripts\Implementation\Install-ADRMS.ps1 -DomainName $TargetDomainName -ServiceAccountPassword $ServiceAccountPassword

# Step 3: Restore configuration
Write-Host "Step 3: Restoring configuration..." -ForegroundColor Yellow
# .\Scripts\Configuration\Manage-ADRMSConfiguration.ps1 -Action Restore -RestorePath "C:\Backups\ADRMS-Source-Config.xml"

# Step 4: Validate migration
Write-Host "Step 4: Validating migration..." -ForegroundColor Yellow
.\Scripts\Troubleshooting\Troubleshoot-ADRMS.ps1 -Action Diagnose

Write-Host "AD RMS migration completed successfully!" -ForegroundColor Green
```

### Example 3: Disaster Recovery

```powershell
# Disaster recovery script
param(
    [Parameter(Mandatory = $true)]
    [string]$BackupPath,
    
    [Parameter(Mandatory = $true)]
    [string]$DomainName,
    
    [Parameter(Mandatory = $true)]
    [SecureString]$ServiceAccountPassword
)

Write-Host "Starting AD RMS disaster recovery..." -ForegroundColor Green

# Step 1: Install AD RMS
Write-Host "Step 1: Installing AD RMS..." -ForegroundColor Yellow
.\Scripts\Implementation\Install-ADRMS.ps1 -DomainName $DomainName -ServiceAccountPassword $ServiceAccountPassword

# Step 2: Restore configuration
Write-Host "Step 2: Restoring configuration from backup..." -ForegroundColor Yellow
.\Scripts\Configuration\Manage-ADRMSConfiguration.ps1 -Action Restore -RestorePath $BackupPath

# Step 3: Start services
Write-Host "Step 3: Starting services..." -ForegroundColor Yellow
Start-ADRMSServices

# Step 4: Validate recovery
Write-Host "Step 4: Validating recovery..." -ForegroundColor Yellow
.\Scripts\Troubleshooting\Troubleshoot-ADRMS.ps1 -Action Diagnose

Write-Host "AD RMS disaster recovery completed successfully!" -ForegroundColor Green
```

## Maintenance Examples

### Example 1: Regular Health Check

```powershell
# Daily health check script
Write-Host "Performing daily AD RMS health check..." -ForegroundColor Green

# Check health
$health = Test-ADRMSHealth
Write-Host "Overall Health: $($health.Overall)" -ForegroundColor White

# Generate report if issues found
if ($health.Overall -ne 'Healthy') {
    $reportPath = "C:\Reports\ADRMS-Health-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    Get-ADRMSDiagnosticReport -OutputPath $reportPath -IncludeLogs
    Write-Host "Health report generated: $reportPath" -ForegroundColor Yellow
}

# Send alert if needed
if ($health.Overall -eq 'Unhealthy') {
    Write-Host "Sending health alert..." -ForegroundColor Red
    # Add email notification logic here
}
```

### Example 2: Configuration Backup

```powershell
# Weekly configuration backup script
$backupPath = "C:\Backups\ADRMS-Config-$(Get-Date -Format 'yyyyMMdd').xml"

Write-Host "Creating AD RMS configuration backup..." -ForegroundColor Green
.\Scripts\Configuration\Manage-ADRMSConfiguration.ps1 -Action Backup -BackupPath $backupPath

# Keep only last 4 weeks of backups
Get-ChildItem "C:\Backups\ADRMS-Config-*.xml" | Sort-Object CreationTime -Descending | Select-Object -Skip 4 | Remove-Item -Force

Write-Host "Configuration backup completed: $backupPath" -ForegroundColor Green
```

### Example 3: Service Account Password Rotation

```powershell
# Monthly service account password rotation
param(
    [Parameter(Mandatory = $true)]
    [SecureString]$NewPassword
)

Write-Host "Rotating AD RMS service account password..." -ForegroundColor Green

# Update service account password
.\Scripts\Configuration\Manage-ADRMSServiceAccount.ps1 -Action Update -ServiceAccount "RMS_Service" -ServiceAccountPassword $NewPassword

# Restart services to apply new password
Stop-ADRMSServices
Start-Sleep -Seconds 5
Start-ADRMSServices

# Validate password change
.\Scripts\Configuration\Manage-ADRMSServiceAccount.ps1 -Action Validate -ServiceAccount "RMS_Service"

Write-Host "Service account password rotation completed successfully!" -ForegroundColor Green
```

## Troubleshooting Examples

### Example 1: Automated Troubleshooting

```powershell
# Automated troubleshooting script
Write-Host "Starting automated AD RMS troubleshooting..." -ForegroundColor Green

# Diagnose issues
$diagnosis = .\Scripts\Troubleshooting\Troubleshoot-ADRMS.ps1 -Action Diagnose -IncludeLogs

if ($diagnosis.Overall -ne 'Healthy') {
    Write-Host "Issues detected. Attempting repair..." -ForegroundColor Yellow
    
    # Attempt repair
    $repair = .\Scripts\Troubleshooting\Troubleshoot-ADRMS.ps1 -Action Repair -RepairType "All"
    
    if ($repair.Overall -eq 'Fully Repaired') {
        Write-Host "Repair successful!" -ForegroundColor Green
    } else {
        Write-Host "Repair partially successful. Manual intervention may be required." -ForegroundColor Yellow
    }
    
    # Generate report
    .\Scripts\Troubleshooting\Troubleshoot-ADRMS.ps1 -Action Report -OutputPath "C:\Reports\ADRMS-Troubleshooting-$(Get-Date -Format 'yyyyMMdd-HHmmss').html" -GenerateReport
}
```

### Example 2: Performance Analysis

```powershell
# Performance analysis script
Write-Host "Starting AD RMS performance analysis..." -ForegroundColor Green

# Monitor performance for 5 minutes
.\Scripts\Troubleshooting\Troubleshoot-ADRMS.ps1 -Action Monitor -MonitorDuration 300 -MonitorInterval 30

# Analyze logs for performance issues
$analysis = .\Scripts\Troubleshooting\Troubleshoot-ADRMS.ps1 -Action Analyze -LogDays 7

Write-Host "Performance Analysis Results:" -ForegroundColor Cyan
Write-Host "Error Rate: $($analysis.LogAnalysis.ErrorRate)%" -ForegroundColor White
Write-Host "Total Errors: $($analysis.LogAnalysis.ErrorCount)" -ForegroundColor White

if ($analysis.LogAnalysis.ErrorRate -gt 5) {
    Write-Host "High error rate detected. Consider investigating performance issues." -ForegroundColor Red
}
```

## Monitoring Examples

### Example 1: Custom Health Monitoring

```powershell
# Custom health monitoring with specific thresholds
param(
    [int]$CheckInterval = 60,
    [int]$AlertThreshold = 2,
    [string[]]$EmailRecipients = @("admin@contoso.com")
)

Write-Host "Starting custom AD RMS health monitoring..." -ForegroundColor Green

while ($true) {
    $health = Test-ADRMSHealth
    
    if ($health.Overall -ne 'Healthy') {
        Write-Host "Health check failed: $($health.Overall)" -ForegroundColor Red
        
        # Send alert if threshold reached
        if ($script:FailureCount -ge $AlertThreshold) {
            Write-Host "Sending alert to: $($EmailRecipients -join ', ')" -ForegroundColor Yellow
            # Add email sending logic here
        }
    } else {
        Write-Host "Health check passed: $($health.Overall)" -ForegroundColor Green
        $script:FailureCount = 0
    }
    
    Start-Sleep -Seconds $CheckInterval
}
```

### Example 2: Scheduled Monitoring Task

```powershell
# Create scheduled monitoring task
$taskName = "AD RMS Health Monitor"
$scriptPath = $MyInvocation.MyCommand.Path

# Create the scheduled task
.\Scripts\Troubleshooting\Monitor-ADRMSHealth.ps1 -Action Schedule -CreateTask -TaskName $taskName -TaskInterval 5

Write-Host "Scheduled task '$taskName' created successfully!" -ForegroundColor Green
```

## Integration Examples

### Example 1: Integration with System Center Operations Manager (SCOM)

```powershell
# SCOM integration script
param(
    [string]$SCOMServer = "scom.contoso.com",
    [string]$ManagementPack = "ADRMS"
)

Write-Host "Integrating AD RMS monitoring with SCOM..." -ForegroundColor Green

# Perform health check
$health = Test-ADRMSHealth

# Send data to SCOM
$healthData = @{
    ComputerName = $env:COMPUTERNAME
    HealthStatus = $health.Overall
    Timestamp = Get-Date
    Services = $health.Services
    Configuration = $health.Configuration
}

# Convert to SCOM format and send
# Note: This would require SCOM PowerShell module
# Send-SCOMData -Server $SCOMServer -ManagementPack $ManagementPack -Data $healthData

Write-Host "SCOM integration completed!" -ForegroundColor Green
```

### Example 2: Integration with PowerShell DSC

```powershell
# PowerShell DSC configuration for AD RMS
Configuration ADRMSConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        
        [Parameter(Mandatory = $true)]
        [PSCredential]$ServiceAccountCredential
    )
    
    Node localhost {
        # Ensure AD RMS is installed
        WindowsFeature ADRMS {
            Name = "ADRMS"
            Ensure = "Present"
        }
        
        # Ensure IIS is installed
        WindowsFeature IIS {
            Name = "IIS-WebServerRole"
            Ensure = "Present"
        }
        
        # Configure AD RMS
        Script ConfigureADRMS {
            GetScript = {
                return @{ Result = "ADRMS Configuration" }
            }
            TestScript = {
                # Test if AD RMS is configured
                $config = Get-ADRMSConfigurationStatus
                return $config.ConfigurationStatus.Overall -eq 'Fully Configured'
            }
            SetScript = {
                # Configure AD RMS
                Import-Module "C:\Scripts\AD-RMS-Scripts\Modules\ADRMS-Configuration.psm1"
                Initialize-ADRMSConfiguration -DomainName $using:DomainName -ServiceAccountPassword $using:ServiceAccountCredential.Password
            }
        }
    }
}

# Apply the configuration
ADRMSConfiguration -DomainName "contoso.com" -ServiceAccountCredential (Get-Credential)
Start-DscConfiguration -Path .\ADRMSConfiguration -Wait -Verbose
```

## Best Practices Examples

### Example 1: Error Handling

```powershell
# Example with proper error handling
try {
    Write-Host "Starting AD RMS operation..." -ForegroundColor Green
    
    # Perform operation
    $result = .\Scripts\Implementation\Install-ADRMS.ps1 -DomainName "contoso.com" -ServiceAccountPassword $securePassword
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Operation completed successfully!" -ForegroundColor Green
    } else {
        throw "Operation failed with exit code: $LASTEXITCODE"
    }
    
} catch {
    Write-Error "Operation failed: $($_.Exception.Message)"
    
    # Log error
    $errorLog = "C:\Logs\ADRMS-Error-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    $_.Exception | Out-File -FilePath $errorLog
    
    # Send notification
    # Send-ErrorNotification -Error $_.Exception -LogPath $errorLog
    
    exit 1
}
```

### Example 2: Logging and Auditing

```powershell
# Example with comprehensive logging
param(
    [string]$LogPath = "C:\Logs\ADRMS-Operations.log"
)

function Write-AuditLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [$env:USERNAME] $Message"
    
    # Write to file
    $logEntry | Out-File -FilePath $LogPath -Append
    
    # Write to console
    Write-Host $logEntry -ForegroundColor White
}

# Use the logging function
Write-AuditLog "Starting AD RMS configuration" "INFO"
.\Scripts\Configuration\Manage-ADRMSConfiguration.ps1 -Action Configure -DomainName "contoso.com" -ServiceAccountPassword $securePassword
Write-AuditLog "AD RMS configuration completed" "SUCCESS"
```

These examples provide practical templates for common AD RMS operations. Customize them based on your specific requirements and environment.
