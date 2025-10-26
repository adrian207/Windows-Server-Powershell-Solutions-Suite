# Print Server PowerShell Scripts - Quick Start Guide

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Last updated:** 2025-10-26

This guide will help you get started with the Print Server PowerShell Scripts quickly and efficiently.

## Prerequisites

Before using these scripts, ensure you have:
- Windows Server 2016 or later
- PowerShell 5.1 or later
- Administrator privileges
- Network connectivity for printer installation

## Quick Installation

### 1. Install Print Server Role

```powershell
# Basic installation
.\Scripts\PrintServer\Install-PrintServer.ps1

# Advanced installation with features
.\Scripts\PrintServer\Install-PrintServer.ps1 -EnableWebManagement -EnableBranchOfficeDirectPrinting -EnablePrintDriverIsolation
```

### 2. Configure Print Server

```powershell
# Configure basic settings
.\Scripts\PrintServer\Configure-PrintServer.ps1 -EnableWebManagement -EnableBranchOfficeDirectPrinting

# Configure advanced settings
.\Scripts\PrintServer\Configure-PrintServer.ps1 -EnableWebManagement -EnableBranchOfficeDirectPrinting -EnablePrintDriverIsolation -EnablePrinterPooling
```

## Adding Printers

### 1. Add Local Printer

```powershell
# Add local printer with basic driver
.\Scripts\PrinterManagement\Manage-Printers.ps1 -Action AddPrinter -PrinterName "Office Printer" -DriverName "Generic / Text Only" -PortName "LPT1:"

# Add local printer with specific driver
.\Scripts\PrinterManagement\Manage-Printers.ps1 -Action AddPrinter -PrinterName "Office Printer" -DriverName "HP LaserJet Pro" -PortName "USB001" -Location "Office"
```

### 2. Add Network Printer

```powershell
# Add network printer
.\Scripts\PrinterManagement\Manage-Printers.ps1 -Action AddPrinter -PrinterName "Network Printer" -DriverName "Generic / Text Only" -PortName "192.168.1.100" -Location "Office"
```

### 3. Add Printer Driver

```powershell
# Install printer driver
.\Scripts\PrinterManagement\Manage-Drivers.ps1 -Action InstallDriver -DriverName "HP LaserJet Pro" -DriverPath "C:\Drivers\HP\LaserJet Pro"
```

## Managing Print Queues

### 1. Monitor Print Queues

```powershell
# Get all print queues
.\Scripts\PrintQueue\Manage-PrintQueues.ps1 -Action GetQueues

# Get specific print queue
.\Scripts\PrintQueue\Manage-PrintQueues.ps1 -Action GetQueue -PrinterName "Office Printer"
```

### 2. Manage Print Jobs

```powershell
# Get all print jobs
.\Scripts\PrintQueue\Manage-PrintQueues.ps1 -Action GetJobs

# Get jobs for specific printer
.\Scripts\PrintQueue\Manage-PrintQueues.ps1 -Action GetJobs -PrinterName "Office Printer"

# Pause print queue
.\Scripts\PrintQueue\Manage-PrintQueues.ps1 -Action PauseQueue -PrinterName "Office Printer"

# Resume print queue
.\Scripts\PrintQueue\Manage-PrintQueues.ps1 -Action ResumeQueue -PrinterName "Office Printer"
```

## Monitoring and Troubleshooting

### 1. Monitor Print Server Performance

```powershell
# Monitor for 5 minutes
.\Scripts\Monitoring\Monitor-PrintServer.ps1 -Action Monitor -Duration 300

# Generate performance report
.\Scripts\Monitoring\Monitor-PrintServer.ps1 -Action Report -OutputPath "C:\Reports\PrintServer-Performance.html"
```

### 2. Troubleshoot Print Server Issues

```powershell
# Run comprehensive diagnostics
.\Scripts\Troubleshooting\Troubleshoot-PrintServer.ps1 -Action Diagnose

# Repair print server issues
.\Scripts\Troubleshooting\Troubleshoot-PrintServer.ps1 -Action Repair -RepairType "All"

# Test printer connectivity
.\Scripts\Troubleshooting\Troubleshoot-PrintServer.ps1 -Action TestPrinter -PrinterName "Office Printer"
```

## Backup and Recovery

### 1. Backup Print Server Configuration

```powershell
# Backup configuration
.\Scripts\Backup\Backup-PrintServer.ps1 -Action BackupConfig -BackupPath "C:\Backups\PrintServer-Config.xml"

# Backup with scheduled task
.\Scripts\Backup\Backup-PrintServer.ps1 -Action BackupConfig -BackupPath "C:\Backups\PrintServer-Config.xml" -ScheduleBackup -TaskName "Print Server Backup"
```

### 2. Restore Print Server Configuration

```powershell
# Restore configuration
.\Scripts\Backup\Backup-PrintServer.ps1 -Action RestoreConfig -RestorePath "C:\Backups\PrintServer-Config.xml"
```

## Common Tasks

### 1. List All Printers

```powershell
Get-Printer | Format-Table Name, DriverName, PortName, Location
```

### 2. Check Print Server Status

```powershell
Get-Service -Name Spooler
Get-Printer | Measure-Object
```

### 3. Monitor Print Jobs

```powershell
Get-PrintJob | Where-Object { $_.JobStatus -eq "Printing" }
```

## Advanced Configuration

### 1. Enable Print Server Features

```powershell
# Enable Web Management
.\Scripts\PrintServer\Configure-PrintServer.ps1 -EnableWebManagement

# Enable Branch Office Direct Printing
.\Scripts\PrintServer\Configure-PrintServer.ps1 -EnableBranchOfficeDirectPrinting

# Enable Print Driver Isolation
.\Scripts\PrintServer\Configure-PrintServer.ps1 -EnablePrintDriverIsolation
```

### 2. Configure Printer Permissions

```powershell
# Set printer permissions
.\Scripts\PrinterManagement\Manage-Printers.ps1 -Action SetPermissions -PrinterName "Office Printer" -User "Domain\Users" -Permission "Print"
```

### 3. Configure Printer Pooling

```powershell
# Create printer pool
.\Scripts\PrinterManagement\Manage-Printers.ps1 -Action CreatePool -PoolName "Office Pool" -Printers @("Printer1", "Printer2", "Printer3")
```

## Testing

Run the comprehensive test suite to verify everything is working:

```powershell
.\Tests\Test-PrintServerServices.ps1
```

## Getting Help

- Check the **Documentation/User-Guide.md** for detailed information
- Review the **Examples/** directory for usage examples
- Use the troubleshooting scripts for common issues
- Check the logs generated by the scripts for detailed error information

## Next Steps

After completing the quick start:
1. Review the comprehensive documentation
2. Explore the example scripts
3. Run the test suite to verify functionality
4. Customize the scripts for your specific environment
5. Set up monitoring and backup procedures

## Support

For additional help or issues:
- Review the troubleshooting scripts
- Check the generated log files
- Refer to the comprehensive documentation
- Use the diagnostic tools included in the solution
