# Print Server PowerShell Scripts - User Guide

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Date:** December 2024

## Table of Contents
1. [Overview](#overview)
2. [Installation](#installation)
3. [Core Modules](#core-modules)
4. [Scripts](#scripts)
5. [Examples](#examples)
6. [Troubleshooting](#troubleshooting)
7. [Best Practices](#best-practices)
8. [Advanced Configuration](#advanced-configuration)
9. [Monitoring and Maintenance](#monitoring-and-maintenance)
10. [Backup and Recovery](#backup-and-recovery)

## Overview

The Print Server PowerShell Scripts provide a comprehensive solution for managing Windows Print Server services. This solution includes:

- **Modular Design**: Separate modules for different aspects of print server management
- **Comprehensive Coverage**: Installation, configuration, management, monitoring, and troubleshooting
- **Portable**: Can run on any Windows Server environment
- **Robust Error Handling**: Comprehensive error handling and logging
- **Documentation**: Detailed documentation and examples

## Installation

### Prerequisites

Before using these scripts, ensure you have:
- Windows Server 2016 or later
- PowerShell 5.1 or later
- Administrator privileges
- Network connectivity for printer installation

### Quick Installation

1. **Download the Scripts**
   ```powershell
   # Clone or download the Print-Server-Scripts directory
   ```

2. **Install Print Server Role**
   ```powershell
   .\Scripts\PrintServer\Install-PrintServer.ps1 -EnableWebManagement -EnableBranchOfficeDirectPrinting
   ```

3. **Verify Installation**
   ```powershell
   .\Scripts\Troubleshooting\Troubleshoot-PrintServer.ps1 -Action Diagnose
   ```

## Core Modules

### PrintServer-Core.psm1

The core module provides fundamental functions for print server management.

#### Key Functions

- **Test-IsAdministrator**: Checks if running as administrator
- **Get-OperatingSystemVersion**: Gets OS version information
- **Write-Log**: Writes timestamped log messages
- **Test-PrintServerPrerequisites**: Validates system requirements
- **Install-PrintServerPrerequisites**: Installs required Windows features
- **Get-PrintServerStatus**: Gets comprehensive print server status
- **Start-PrintServerServices**: Starts print server services
- **Stop-PrintServerServices**: Stops print server services
- **Test-PrintServerHealth**: Performs health checks

#### Usage Examples

```powershell
# Check prerequisites
Test-PrintServerPrerequisites

# Get print server status
$status = Get-PrintServerStatus
$status.PrintServerInstalled

# Perform health check
$health = Test-PrintServerHealth
$health.Overall
```

### PrintServer-Management.psm1

The management module provides printer and driver management functions.

#### Key Functions

- **New-PrintServerPrinter**: Creates new printers
- **Remove-PrintServerPrinter**: Removes printers
- **Install-PrintServerDriver**: Installs printer drivers
- **Remove-PrintServerDriver**: Removes printer drivers
- **Get-PrintServerReport**: Generates comprehensive reports
- **Set-PrintServerConfiguration**: Configures print server settings

#### Usage Examples

```powershell
# Create a printer
New-PrintServerPrinter -PrinterName "Office Printer" -DriverName "Generic / Text Only" -PortName "LPT1:" -Location "Office" -Shared

# Install a driver
Install-PrintServerDriver -DriverName "HP LaserJet Pro" -DriverPath "C:\Drivers\HP" -InfPath "C:\Drivers\HP\hpcu118c.inf"

# Generate report
Get-PrintServerReport -OutputPath "C:\Reports\PrintServer.html" -IncludePrintJobs -IncludeDrivers
```

### PrintServer-Troubleshooting.psm1

The troubleshooting module provides diagnostic and repair functions.

#### Key Functions

- **Test-PrintServerHealth**: Comprehensive health checks
- **Get-PrintServerDiagnosticReport**: Generates diagnostic reports
- **Repair-PrintServerInstallation**: Performs automated repairs
- **Watch-PrintServerPerformance**: Real-time performance monitoring
- **Test-PrinterAccess**: Tests printer connectivity

#### Usage Examples

```powershell
# Perform health check
$health = Test-PrintServerHealth
$health.Overall

# Generate diagnostic report
Get-PrintServerDiagnosticReport -OutputPath "C:\Reports\Diagnostic.html" -IncludeLogs -IncludePerformance

# Repair print server
Repair-PrintServerInstallation -RepairType "All"

# Monitor performance
Watch-PrintServerPerformance -Duration 300 -Interval 10
```

## Scripts

### Print Server Installation

#### Install-PrintServer.ps1

Complete print server installation and configuration script.

**Parameters:**
- `EnableWebManagement`: Enable Print Server Web Management
- `EnableBranchOfficeDirectPrinting`: Enable Branch Office Direct Printing
- `EnablePrintDriverIsolation`: Enable Print Driver Isolation
- `EnablePrinterPooling`: Enable Printer Pooling
- `EnablePrintJobLogging`: Enable Print Job Logging
- `RestartSpooler`: Restart Print Spooler service after installation
- `LogFilePath`: Path to the log file

**Examples:**
```powershell
# Basic installation
.\Install-PrintServer.ps1

# Advanced installation with features
.\Install-PrintServer.ps1 -EnableWebManagement -EnableBranchOfficeDirectPrinting -EnablePrintDriverIsolation -RestartSpooler
```

### Printer Management

#### Manage-Printers.ps1

Comprehensive printer and driver management script.

**Parameters:**
- `Action`: Action to perform (AddPrinter, RemovePrinter, ConfigurePrinter, InstallDriver, RemoveDriver, ListPrinters, ListDrivers, Report)
- `PrinterName`: Name of the printer
- `DriverName`: Name of the printer driver
- `PortName`: Port name for the printer
- `Location`: Location description
- `Comment`: Comment for the printer
- `DriverPath`: Path to driver files
- `InfPath`: Path to .inf file
- `Architecture`: Driver architecture (x86, x64, ARM64)
- `Shared`: Whether printer should be shared
- `Published`: Whether printer should be published
- `FromWindowsUpdate`: Install driver from Windows Update
- `OutputPath`: Path to save reports
- `GenerateReport`: Generate detailed report

**Examples:**
```powershell
# Add printer
.\Manage-Printers.ps1 -Action AddPrinter -PrinterName "Office Printer" -DriverName "Generic / Text Only" -PortName "LPT1:" -Location "Office" -Shared

# Install driver
.\Manage-Printers.ps1 -Action InstallDriver -DriverName "HP LaserJet Pro" -DriverPath "C:\Drivers\HP" -InfPath "C:\Drivers\HP\hpcu118c.inf"

# List printers
.\Manage-Printers.ps1 -Action ListPrinters -GenerateReport -OutputPath "C:\Reports\Printers.html"
```

### Print Queue Management

#### Manage-PrintQueues.ps1

Print queue and job management script.

**Parameters:**
- `Action`: Action to perform (GetQueues, GetJobs, PauseQueue, ResumeQueue, ClearQueue, RestartQueue, PauseJob, ResumeJob, CancelJob, GetQueueStatus, Monitor, Report)
- `PrinterName`: Name of the printer
- `JobId`: ID of the print job
- `JobName`: Name of the print job
- `UserName`: Name of the user
- `JobStatus`: Status of the print job
- `SubmittedAfter`: Get jobs submitted after this date
- `SubmittedBefore`: Get jobs submitted before this date
- `OutputPath`: Path to save reports
- `GenerateReport`: Generate detailed report
- `MonitorDuration`: Duration to monitor in seconds
- `MonitorInterval`: Monitoring interval in seconds

**Examples:**
```powershell
# Get print queues
.\Manage-PrintQueues.ps1 -Action GetQueues

# Get print jobs
.\Manage-PrintQueues.ps1 -Action GetJobs -PrinterName "Office Printer"

# Pause print queue
.\Manage-PrintQueues.ps1 -Action PauseQueue -PrinterName "Office Printer"

# Monitor print queues
.\Manage-PrintQueues.ps1 -Action Monitor -MonitorDuration 300 -MonitorInterval 10
```

### Troubleshooting

#### Troubleshoot-PrintServer.ps1

Comprehensive troubleshooting and diagnostic script.

**Parameters:**
- `Action`: Action to perform (Diagnose, Repair, Monitor, Analyze, Report, TestPrinter)
- `OutputPath`: Path to save diagnostic reports
- `IncludeLogs`: Include recent log entries in analysis
- `IncludePerformance`: Include performance data in reports
- `LogDays`: Number of days of logs to analyze
- `RepairType`: Type of repair to perform (All, Services, Configuration, Printers, Drivers)
- `MonitorDuration`: Duration to monitor in seconds
- `MonitorInterval`: Monitoring interval in seconds
- `PrinterName`: Name of printer to test
- `TestUser`: User account to test printer access with
- `GenerateReport`: Generate detailed HTML report

**Examples:**
```powershell
# Run diagnostics
.\Troubleshoot-PrintServer.ps1 -Action Diagnose

# Repair print server
.\Troubleshoot-PrintServer.ps1 -Action Repair -RepairType "Services"

# Monitor performance
.\Troubleshoot-PrintServer.ps1 -Action Monitor -MonitorDuration 600 -MonitorInterval 15

# Generate report
.\Troubleshoot-PrintServer.ps1 -Action Report -OutputPath "C:\Reports\PrintServer-Report.html" -GenerateReport

# Test printer
.\Troubleshoot-PrintServer.ps1 -Action TestPrinter -PrinterName "Office Printer" -TestUser "Domain\User"
```

### Backup and Recovery

#### Backup-PrintServer.ps1

Backup and disaster recovery script.

**Parameters:**
- `Action`: Action to perform (BackupConfig, BackupPrinters, RestoreConfig, RestorePrinters, CreateSnapshot, ManageSnapshots, DisasterRecovery)
- `BackupPath`: Path to save backups
- `RestorePath`: Path to restore from
- `IncludeDrivers`: Include printer drivers in backup
- `IncludePrintJobs`: Include print job history in backup
- `CompressionLevel`: Compression level for backups (None, Fast, Optimal)
- `VerifyBackup`: Verify backup integrity after creation
- `ScheduleBackup`: Create scheduled backup task
- `TaskName`: Name for the scheduled task
- `ScheduleType`: Schedule type (Daily, Weekly, Monthly)
- `SnapshotName`: Name for the snapshot
- `RetentionDays`: Number of days to retain snapshots

**Examples:**
```powershell
# Backup configuration
.\Backup-PrintServer.ps1 -Action BackupConfig -BackupPath "C:\Backups\PrintServer-Config.xml" -IncludeDrivers -IncludePrintJobs

# Backup printers
.\Backup-PrintServer.ps1 -Action BackupPrinters -BackupPath "C:\Backups\Printers.xml" -IncludeDrivers

# Create snapshot
.\Backup-PrintServer.ps1 -Action CreateSnapshot -SnapshotName "PreMaintenance" -RetentionDays 30

# Disaster recovery
.\Backup-PrintServer.ps1 -Action DisasterRecovery -BackupPath "C:\Backups\PrintServer-Config.xml"
```

## Examples

### Basic Print Server Setup

```powershell
# Install print server role
.\Scripts\PrintServer\Install-PrintServer.ps1 -EnableWebManagement -EnableBranchOfficeDirectPrinting

# Add printers
.\Scripts\PrinterManagement\Manage-Printers.ps1 -Action AddPrinter -PrinterName "Office Printer" -DriverName "Generic / Text Only" -PortName "LPT1:" -Location "Office" -Shared

# Monitor print server
.\Scripts\Troubleshooting\Troubleshoot-PrintServer.ps1 -Action Diagnose
```

### Advanced Configuration

```powershell
# Configure print server with all features
.\Scripts\PrintServer\Install-PrintServer.ps1 -EnableWebManagement -EnableBranchOfficeDirectPrinting -EnablePrintDriverIsolation -EnablePrinterPooling -EnablePrintJobLogging

# Install multiple printers
$printers = @(
    @{Name="Office Printer 1"; Driver="Generic / Text Only"; Port="LPT1:"; Location="Office"},
    @{Name="Office Printer 2"; Driver="Generic / Text Only"; Port="LPT2:"; Location="Office"},
    @{Name="Network Printer"; Driver="Generic / Text Only"; Port="192.168.1.100"; Location="Office"}
)

foreach ($printer in $printers) {
    .\Scripts\PrinterManagement\Manage-Printers.ps1 -Action AddPrinter -PrinterName $printer.Name -DriverName $printer.Driver -PortName $printer.Port -Location $printer.Location -Shared
}

# Generate comprehensive report
.\Scripts\PrinterManagement\Manage-Printers.ps1 -Action Report -OutputPath "C:\Reports\PrintServer-Report.html" -GenerateReport
```

### Monitoring and Maintenance

```powershell
# Daily health check
.\Scripts\Troubleshooting\Troubleshoot-PrintServer.ps1 -Action Diagnose

# Weekly performance monitoring
.\Scripts\Troubleshooting\Troubleshoot-PrintServer.ps1 -Action Monitor -MonitorDuration 1800 -MonitorInterval 30

# Monthly backup
.\Scripts\Backup\Backup-PrintServer.ps1 -Action BackupConfig -BackupPath "C:\Backups\PrintServer-Config-$(Get-Date -Format 'yyyyMM').xml" -IncludeDrivers -IncludePrintJobs
```

## Troubleshooting

### Common Issues

#### Print Server Not Starting
```powershell
# Check service status
Get-Service -Name Spooler

# Restart service
Restart-Service -Name Spooler

# Check for errors
.\Scripts\Troubleshooting\Troubleshoot-PrintServer.ps1 -Action Diagnose
```

#### Printer Not Working
```powershell
# Test printer access
.\Scripts\Troubleshooting\Troubleshoot-PrintServer.ps1 -Action TestPrinter -PrinterName "Office Printer"

# Check printer status
.\Scripts\PrinterManagement\Manage-Printers.ps1 -Action ListPrinters
```

#### Driver Issues
```powershell
# List installed drivers
.\Scripts\PrinterManagement\Manage-Printers.ps1 -Action ListDrivers

# Remove problematic driver
.\Scripts\PrinterManagement\Manage-Printers.ps1 -Action RemoveDriver -DriverName "Problematic Driver"

# Install correct driver
.\Scripts\PrinterManagement\Manage-Printers.ps1 -Action InstallDriver -DriverName "Correct Driver" -DriverPath "C:\Drivers"
```

### Diagnostic Commands

```powershell
# Comprehensive health check
$health = Test-PrintServerHealth
$health.Overall

# Generate diagnostic report
Get-PrintServerDiagnosticReport -OutputPath "C:\Reports\Diagnostic.html" -IncludeLogs -IncludePerformance

# Check print server status
$status = Get-PrintServerStatus
$status.PrintServerInstalled
```

## Best Practices

### Security
- Run scripts with administrator privileges
- Use secure authentication for network printers
- Regularly update printer drivers
- Monitor print server logs for security issues

### Performance
- Monitor print server performance regularly
- Use print driver isolation for stability
- Implement print job logging for auditing
- Regular maintenance and cleanup

### Backup
- Create regular configuration backups
- Test restore procedures
- Document printer configurations
- Keep driver installation media

### Monitoring
- Set up automated health checks
- Monitor print server performance
- Track print job statistics
- Alert on critical issues

## Advanced Configuration

### Print Server Features

#### Web Management
```powershell
# Enable web management
Set-PrintServerConfiguration -EnableWebManagement

# Access via web browser
# http://servername:80/printers
```

#### Branch Office Direct Printing
```powershell
# Enable branch office direct printing
Set-PrintServerConfiguration -EnableBranchOfficeDirectPrinting
```

#### Print Driver Isolation
```powershell
# Enable print driver isolation
Set-PrintServerConfiguration -EnablePrintDriverIsolation
```

### Printer Pooling

```powershell
# Create printer pool
$poolPrinters = @("Printer1", "Printer2", "Printer3")
foreach ($printer in $poolPrinters) {
    Set-Printer -Name $printer -PrinterPool $true
}
```

### Print Job Logging

```powershell
# Enable print job logging
Set-PrintServerConfiguration -EnablePrintJobLogging

# View print job logs
Get-WinEvent -FilterHashtable @{LogName="Application"; ProviderName="Microsoft-Windows-PrintService"}
```

## Monitoring and Maintenance

### Automated Monitoring

```powershell
# Create scheduled health check
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"C:\Scripts\Troubleshoot-PrintServer.ps1`" -Action Diagnose"
$trigger = New-ScheduledTaskTrigger -Daily -At "06:00"
Register-ScheduledTask -TaskName "Print Server Health Check" -Action $action -Trigger $trigger
```

### Performance Monitoring

```powershell
# Monitor performance for 1 hour
Watch-PrintServerPerformance -Duration 3600 -Interval 60

# Generate performance report
Get-PrintServerReport -OutputPath "C:\Reports\Performance.html" -IncludePrintJobs
```

### Maintenance Tasks

```powershell
# Weekly maintenance
.\Scripts\Troubleshooting\Troubleshoot-PrintServer.ps1 -Action Diagnose
.\Scripts\Backup\Backup-PrintServer.ps1 -Action CreateSnapshot -SnapshotName "Weekly-$(Get-Date -Format 'yyyyMMdd')"

# Monthly maintenance
.\Scripts\Backup\Backup-PrintServer.ps1 -Action BackupConfig -BackupPath "C:\Backups\Monthly-$(Get-Date -Format 'yyyyMM').xml" -IncludeDrivers -IncludePrintJobs
```

## Backup and Recovery

### Backup Strategies

#### Configuration Backup
```powershell
# Daily configuration backup
.\Scripts\Backup\Backup-PrintServer.ps1 -Action BackupConfig -BackupPath "C:\Backups\Config-$(Get-Date -Format 'yyyyMMdd').xml" -IncludeDrivers -IncludePrintJobs
```

#### Printer Backup
```powershell
# Weekly printer backup
.\Scripts\Backup\Backup-PrintServer.ps1 -Action BackupPrinters -BackupPath "C:\Backups\Printers-$(Get-Date -Format 'yyyyMMdd').xml" -IncludeDrivers
```

#### Snapshot Management
```powershell
# Create snapshot before maintenance
.\Scripts\Backup\Backup-PrintServer.ps1 -Action CreateSnapshot -SnapshotName "PreMaintenance-$(Get-Date -Format 'yyyyMMdd')" -RetentionDays 30

# Manage snapshots
.\Scripts\Backup\Backup-PrintServer.ps1 -Action ManageSnapshots -RetentionDays 7
```

### Disaster Recovery

#### Recovery Procedures
```powershell
# Full disaster recovery
.\Scripts\Backup\Backup-PrintServer.ps1 -Action DisasterRecovery -BackupPath "C:\Backups\PrintServer-Config.xml"

# Restore specific components
.\Scripts\Backup\Backup-PrintServer.ps1 -Action RestoreConfig -RestorePath "C:\Backups\Config.xml"
.\Scripts\Backup\Backup-PrintServer.ps1 -Action RestorePrinters -RestorePath "C:\Backups\Printers.xml"
```

#### Recovery Testing
```powershell
# Test recovery procedures
$testBackup = "C:\Backups\Test-Recovery.xml"
.\Scripts\Backup\Backup-PrintServer.ps1 -Action BackupConfig -BackupPath $testBackup
.\Scripts\Backup\Backup-PrintServer.ps1 -Action RestoreConfig -RestorePath $testBackup
```

### Scheduled Backups

```powershell
# Create scheduled backup task
.\Scripts\Backup\Backup-PrintServer.ps1 -Action BackupConfig -BackupPath "C:\Backups\Scheduled-Config.xml" -ScheduleBackup -TaskName "Print Server Backup" -ScheduleType "Daily"
```

## Support and Resources

### Documentation
- README.md: Project overview and quick start
- Quick-Start-Guide.md: Step-by-step setup instructions
- User-Guide.md: Comprehensive user documentation (this file)

### Examples
- Example-ConfigurePrintServer.ps1: Basic configuration example
- Example-ManagePrinters.ps1: Printer management example
- Example-MonitorPrintServer.ps1: Monitoring example

### Testing
- Test-PrintServerServices.ps1: Comprehensive test suite
- Run tests: `.\Tests\Test-PrintServerServices.ps1`

### Troubleshooting
- Use the troubleshooting scripts for common issues
- Check the generated log files for detailed error information
- Review the diagnostic reports for system health

### Getting Help
- Check the troubleshooting scripts for common issues
- Review the generated log files for detailed error information
- Use the diagnostic tools included in the solution
- Refer to the comprehensive documentation
