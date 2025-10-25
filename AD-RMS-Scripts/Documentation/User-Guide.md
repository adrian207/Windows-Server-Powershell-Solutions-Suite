# AD RMS PowerShell Scripts - User Guide

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Date:** December 2024

## Overview

This comprehensive PowerShell solution provides modular, portable scripts for implementing, configuring, and troubleshooting Active Directory Rights Management Services (AD RMS) on Windows Server. The solution is designed to work in any environment and can be easily customized for specific requirements.

## Table of Contents

1. [Installation and Setup](#installation-and-setup)
2. [Core Modules](#core-modules)
3. [Implementation Scripts](#implementation-scripts)
4. [Configuration Scripts](#configuration-scripts)
5. [Troubleshooting Scripts](#troubleshooting-scripts)
6. [Usage Examples](#usage-examples)
7. [Best Practices](#best-practices)
8. [Troubleshooting Guide](#troubleshooting-guide)

## Installation and Setup

### Prerequisites

- Windows Server 2016 or later
- PowerShell 5.1 or later
- Administrator privileges
- Active Directory Domain Services
- Appropriate permissions for AD RMS operations

### Quick Start

1. **Download and Extract**
   ```powershell
   # Extract the AD-RMS-Scripts folder to your desired location
   # Example: C:\Scripts\AD-RMS-Scripts
   ```

2. **Import Core Module**
   ```powershell
   Import-Module "C:\Scripts\AD-RMS-Scripts\Modules\ADRMS-Core.psm1"
   ```

3. **Check Prerequisites**
   ```powershell
   Test-ADRMSPrerequisites
   ```

4. **Install AD RMS**
   ```powershell
   .\Scripts\Implementation\Install-ADRMS.ps1 -DomainName "contoso.com" -ServiceAccountPassword $securePassword
   ```

## Core Modules

### ADRMS-Core.psm1

The core module provides fundamental AD RMS operations:

#### Functions

- `Install-ADRMSPrerequisites` - Installs required Windows features
- `Get-ADRMSStatus` - Gets comprehensive AD RMS status
- `Start-ADRMSServices` - Starts AD RMS services
- `Stop-ADRMSServices` - Stops AD RMS services

#### Usage Examples

```powershell
# Install prerequisites
Install-ADRMSPrerequisites

# Get current status
$status = Get-ADRMSStatus
$status | Format-List

# Start services
Start-ADRMSServices
```

### ADRMS-Configuration.psm1

The configuration module handles AD RMS setup and management:

#### Functions

- `Initialize-ADRMSConfiguration` - Initializes AD RMS with default settings
- `Set-ADRMSServiceAccount` - Configures the service account
- `Set-ADRMSDatabase` - Configures database settings
- `Get-ADRMSConfigurationStatus` - Gets configuration status
- `Reset-ADRMSConfiguration` - Resets configuration

#### Usage Examples

```powershell
# Initialize configuration
Initialize-ADRMSConfiguration -DomainName "contoso.com" -ServiceAccountPassword $securePassword

# Configure service account
Set-ADRMSServiceAccount -ServiceAccount "RMS_Service" -ServiceAccountPassword $securePassword

# Check configuration status
$configStatus = Get-ADRMSConfigurationStatus
$configStatus.ConfigurationStatus
```

### ADRMS-Diagnostics.psm1

The diagnostics module provides troubleshooting and monitoring capabilities:

#### Functions

- `Test-ADRMSHealth` - Performs comprehensive health checks
- `Get-ADRMSDiagnosticReport` - Generates diagnostic reports
- `Repair-ADRMSInstallation` - Attempts to repair issues
- `Watch-ADRMSPerformance` - Monitors performance in real-time

#### Usage Examples

```powershell
# Perform health check
$health = Test-ADRMSHealth
$health.Overall

# Generate diagnostic report
Get-ADRMSDiagnosticReport -OutputPath "C:\Reports\ADRMS-Diagnostic.html" -IncludeLogs

# Repair installation
Repair-ADRMSInstallation -RepairType "Services"
```

## Implementation Scripts

### Install-ADRMS.ps1

Comprehensive AD RMS installation script.

#### Parameters

- `DomainName` (Mandatory) - The domain name for the AD RMS cluster
- `ServiceAccount` - The service account (default: RMS_Service)
- `ServiceAccountPassword` (Mandatory) - The password for the service account
- `DatabaseServer` - The database server (default: localhost)
- `DatabaseName` - The database name (default: DRMS)
- `ClusterUrl` - The cluster URL (optional, will be generated)
- `SkipPrerequisites` - Skip prerequisite installation
- `SkipConfiguration` - Skip initial configuration
- `RestartRequired` - Allow automatic restart if required

#### Usage Examples

```powershell
# Basic installation
.\Install-ADRMS.ps1 -DomainName "contoso.com" -ServiceAccountPassword $securePassword

# Advanced installation
.\Install-ADRMS.ps1 -DomainName "contoso.com" -ServiceAccount "RMS_SVC" -ServiceAccountPassword $securePassword -DatabaseServer "SQL01" -DatabaseName "RMS_DB"

# Installation with custom cluster URL
.\Install-ADRMS.ps1 -DomainName "contoso.com" -ServiceAccountPassword $securePassword -ClusterUrl "https://rms.contoso.com/_wmcs"
```

### Uninstall-ADRMS.ps1

Comprehensive AD RMS uninstallation script.

#### Parameters

- `RemoveConfiguration` - Remove AD RMS configuration data
- `RemoveDatabase` - Remove AD RMS database (use with caution)
- `Force` - Force uninstallation without confirmation
- `KeepLogs` - Keep installation and configuration logs

#### Usage Examples

```powershell
# Basic uninstallation
.\Uninstall-ADRMS.ps1

# Complete uninstallation
.\Uninstall-ADRMS.ps1 -RemoveConfiguration -Force

# Uninstallation keeping logs
.\Uninstall-ADRMS.ps1 -KeepLogs
```

## Configuration Scripts

### Manage-ADRMSConfiguration.ps1

Comprehensive configuration management script.

#### Parameters

- `Action` (Mandatory) - The action to perform (Configure, Update, Backup, Restore, Validate, Reset)
- `DomainName` - The domain name for the AD RMS cluster
- `ServiceAccount` - The service account for AD RMS
- `ServiceAccountPassword` - The password for the service account
- `DatabaseServer` - The database server
- `DatabaseName` - The database name
- `ClusterUrl` - The cluster URL
- `LicensingUrl` - The licensing URL
- `BackupPath` - Path to save configuration backup
- `RestorePath` - Path to restore configuration from

#### Usage Examples

```powershell
# Configure AD RMS
.\Manage-ADRMSConfiguration.ps1 -Action Configure -DomainName "contoso.com" -ServiceAccountPassword $securePassword

# Backup configuration
.\Manage-ADRMSConfiguration.ps1 -Action Backup -BackupPath "C:\Backups\ADRMS-Config.xml"

# Restore configuration
.\Manage-ADRMSConfiguration.ps1 -Action Restore -RestorePath "C:\Backups\ADRMS-Config.xml"

# Validate configuration
.\Manage-ADRMSConfiguration.ps1 -Action Validate
```

### Manage-ADRMSServiceAccount.ps1

Service account management script.

#### Parameters

- `Action` (Mandatory) - The action to perform (Create, Configure, Update, Validate, Reset)
- `ServiceAccount` (Mandatory) - The service account name
- `ServiceAccountPassword` - The password for the service account
- `DomainName` - The domain name (required for account creation)
- `AccountDescription` - Description for the service account
- `PasswordNeverExpires` - Set password to never expire
- `AccountDisabled` - Create the account in disabled state
- `AddToGroups` - Array of groups to add the account to

#### Usage Examples

```powershell
# Create service account
.\Manage-ADRMSServiceAccount.ps1 -Action Create -ServiceAccount "RMS_Service" -ServiceAccountPassword $securePassword -DomainName "contoso.com"

# Configure service account
.\Manage-ADRMSServiceAccount.ps1 -Action Configure -ServiceAccount "RMS_Service" -ServiceAccountPassword $securePassword

# Validate service account
.\Manage-ADRMSServiceAccount.ps1 -Action Validate -ServiceAccount "RMS_Service"
```

## Troubleshooting Scripts

### Troubleshoot-ADRMS.ps1

Comprehensive troubleshooting and diagnostic script.

#### Parameters

- `Action` (Mandatory) - The action to perform (Diagnose, Repair, Monitor, Analyze, Report)
- `OutputPath` - Path to save diagnostic reports
- `IncludeLogs` - Include recent log entries in analysis
- `LogDays` - Number of days of logs to analyze (default: 7)
- `RepairType` - Type of repair to perform (All, Services, Configuration, IIS)
- `MonitorDuration` - Duration to monitor in seconds (default: 300)
- `MonitorInterval` - Monitoring interval in seconds (default: 10)
- `GenerateReport` - Generate detailed HTML report

#### Usage Examples

```powershell
# Diagnose issues
.\Troubleshoot-ADRMS.ps1 -Action Diagnose

# Repair services
.\Troubleshoot-ADRMS.ps1 -Action Repair -RepairType "Services"

# Monitor performance
.\Troubleshoot-ADRMS.ps1 -Action Monitor -MonitorDuration 600 -MonitorInterval 15

# Generate report
.\Troubleshoot-ADRMS.ps1 -Action Report -OutputPath "C:\Reports\ADRMS-Report.html" -GenerateReport
```

### Monitor-ADRMSHealth.ps1

Health monitoring and alerting script.

#### Parameters

- `Action` (Mandatory) - The action to perform (Check, Monitor, Alert, Schedule)
- `CheckInterval` - Interval between health checks in seconds (default: 300)
- `AlertThreshold` - Number of consecutive failures before alerting (default: 3)
- `EmailRecipients` - Email addresses to send alerts to
- `LogPath` - Path to save monitoring logs
- `CreateTask` - Create a scheduled task for continuous monitoring
- `TaskName` - Name for the scheduled task
- `TaskInterval` - Interval for the scheduled task in minutes (default: 5)

#### Usage Examples

```powershell
# Single health check
.\Monitor-ADRMSHealth.ps1 -Action Check

# Continuous monitoring
.\Monitor-ADRMSHealth.ps1 -Action Monitor -CheckInterval 60 -AlertThreshold 2

# Create scheduled task
.\Monitor-ADRMSHealth.ps1 -Action Schedule -CreateTask -TaskName "AD RMS Health Monitor" -TaskInterval 10
```

## Usage Examples

### Complete AD RMS Deployment

```powershell
# Step 1: Check prerequisites
Test-ADRMSPrerequisites

# Step 2: Install AD RMS
.\Scripts\Implementation\Install-ADRMS.ps1 -DomainName "contoso.com" -ServiceAccountPassword $securePassword

# Step 3: Validate installation
.\Scripts\Troubleshooting\Troubleshoot-ADRMS.ps1 -Action Diagnose

# Step 4: Set up monitoring
.\Scripts\Troubleshooting\Monitor-ADRMSHealth.ps1 -Action Schedule -CreateTask -TaskName "AD RMS Health Monitor"
```

### Configuration Management

```powershell
# Backup current configuration
.\Scripts\Configuration\Manage-ADRMSConfiguration.ps1 -Action Backup -BackupPath "C:\Backups\ADRMS-Config.xml"

# Update service account
.\Scripts\Configuration\Manage-ADRMSServiceAccount.ps1 -Action Update -ServiceAccount "RMS_Service" -ServiceAccountPassword $newSecurePassword

# Validate configuration
.\Scripts\Configuration\Manage-ADRMSConfiguration.ps1 -Action Validate
```

### Troubleshooting Workflow

```powershell
# Step 1: Diagnose issues
.\Scripts\Troubleshooting\Troubleshoot-ADRMS.ps1 -Action Diagnose -IncludeLogs

# Step 2: Attempt repair
.\Scripts\Troubleshooting\Troubleshoot-ADRMS.ps1 -Action Repair -RepairType "All"

# Step 3: Generate report
.\Scripts\Troubleshooting\Troubleshoot-ADRMS.ps1 -Action Report -OutputPath "C:\Reports\ADRMS-Troubleshooting.html" -GenerateReport
```

## Best Practices

### Security

1. **Service Account Security**
   - Use dedicated service accounts for AD RMS
   - Set strong passwords and consider password policies
   - Regularly rotate service account passwords
   - Use least privilege principle

2. **Network Security**
   - Configure appropriate firewall rules
   - Use HTTPS for all AD RMS communications
   - Implement network segmentation if possible

3. **Backup and Recovery**
   - Regularly backup AD RMS configuration
   - Test restore procedures
   - Document recovery procedures

### Performance

1. **Monitoring**
   - Implement continuous health monitoring
   - Set up alerting for critical issues
   - Monitor performance counters regularly

2. **Maintenance**
   - Regularly review and clean up logs
   - Perform routine health checks
   - Update Windows and AD RMS components

### Documentation

1. **Configuration Documentation**
   - Document all configuration changes
   - Maintain configuration backups
   - Keep detailed change logs

2. **Operational Procedures**
   - Document standard operating procedures
   - Create runbooks for common tasks
   - Train staff on AD RMS operations

## Troubleshooting Guide

### Common Issues

#### Service Issues

**Problem**: AD RMS services not starting
**Solution**:
```powershell
# Check service status
Get-Service -Name MSDRMS, W3SVC

# Start services
Start-ADRMSServices

# Check for errors
Get-EventLog -LogName Application -Source "*RMS*" -Newest 10
```

#### Configuration Issues

**Problem**: Configuration incomplete
**Solution**:
```powershell
# Check configuration status
Get-ADRMSConfigurationStatus

# Reconfigure if needed
Initialize-ADRMSConfiguration -DomainName "contoso.com" -ServiceAccountPassword $securePassword
```

#### Connectivity Issues

**Problem**: Cannot access AD RMS endpoints
**Solution**:
```powershell
# Test connectivity
Test-ADRMSConnectivity

# Check firewall rules
Get-NetFirewallRule -DisplayName "*RMS*"

# Verify IIS configuration
Import-Module WebAdministration
Get-Website | Where-Object { $_.Name -like "*RMS*" }
```

### Diagnostic Commands

```powershell
# Comprehensive health check
Test-ADRMSHealth

# Get detailed status
Get-ADRMSStatus

# Generate diagnostic report
Get-ADRMSDiagnosticReport -OutputPath "C:\Reports\Diagnostic.html" -IncludeLogs

# Monitor performance
Watch-ADRMSPerformance -Duration 300 -Interval 10
```

### Log Analysis

```powershell
# Get recent AD RMS logs
Get-ADRMSLogEntries -StartTime (Get-Date).AddDays(-1)

# Check for errors
Get-EventLog -LogName Application -Source "*RMS*" -EntryType Error -Newest 50

# Analyze log patterns
.\Scripts\Troubleshooting\Troubleshoot-ADRMS.ps1 -Action Analyze -LogDays 7
```

## Support and Maintenance

### Regular Maintenance Tasks

1. **Daily**
   - Check service status
   - Review error logs
   - Monitor performance

2. **Weekly**
   - Perform health checks
   - Review configuration
   - Clean up logs

3. **Monthly**
   - Generate diagnostic reports
   - Review security settings
   - Update documentation

### Getting Help

1. **Check Logs**
   - Review installation logs
   - Check Windows Event Logs
   - Analyze diagnostic reports

2. **Use Diagnostic Tools**
   - Run comprehensive health checks
   - Generate diagnostic reports
   - Use troubleshooting scripts

3. **Documentation**
   - Refer to this user guide
   - Check script help documentation
   - Review Microsoft AD RMS documentation

## Conclusion

This PowerShell solution provides a comprehensive, modular approach to AD RMS management. The scripts are designed to be portable, reliable, and easy to use in any Windows Server environment. Regular use of the monitoring and diagnostic tools will help maintain a healthy AD RMS infrastructure.

For additional support or customization needs, refer to the individual script documentation and Microsoft's official AD RMS documentation.
