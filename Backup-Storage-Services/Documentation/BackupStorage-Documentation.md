# Backup Storage Services PowerShell Scripts

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Date:** December 2024

## Overview

The Backup Storage Services PowerShell Scripts provide comprehensive management capabilities for Windows Server backup and storage systems. This solution includes modules for backup software management, data corruption detection and repair, deduplication, File Server Resource Manager (FSRM), iSCSI management, monitoring, and troubleshooting.

## Features

### Core Modules

- **BackupStorage-Core.psm1** - Core backup and storage management functions
- **BackupStorage-ADBackup.psm1** - Active Directory backup management
- **BackupStorage-DataCorruption.psm1** - Data corruption detection and repair
- **BackupStorage-Deduplication.psm1** - Data deduplication management
- **BackupStorage-FSRM.psm1** - File Server Resource Manager
- **BackupStorage-HardwareMonitoring.psm1** - Hardware monitoring
- **BackupStorage-iSCSI.psm1** - iSCSI management
- **BackupStorage-MPIO.psm1** - Multipath I/O management
- **BackupStorage-PartitionVolume.psm1** - Partition and volume management
- **BackupStorage-StorageSpaces.psm1** - Storage Spaces management
- **BackupStorage-VSS.psm1** - Volume Shadow Copy Service management

### Scripts

#### Backup Software Management
- **Manage-BackupSoftware.ps1** - Comprehensive backup software management
  - Install, configure, start backup, restore, monitor, uninstall
  - Support for Windows Server Backup and third-party solutions
  - Cloud backup integration
  - Automated scheduling and retention policies

#### Data Corruption Management
- **Manage-DataCorruption.ps1** - Data corruption detection and repair
  - Detect corruption using CHKDSK and file integrity checks
  - Automated repair procedures
  - Data validation and integrity monitoring
  - Comprehensive reporting and recommendations

#### Deduplication Management
- **Manage-Deduplication.ps1** - Data deduplication management
  - Enable/disable deduplication on volumes
  - Configure policies for different workloads
  - Optimization and garbage collection
  - Performance monitoring and reporting

#### File Server Resource Manager (FSRM)
- **Manage-FSRM.ps1** - FSRM management
  - Quota management and templates
  - File screening and file groups
  - Storage reports generation
  - Classification management

#### iSCSI Management
- **Manage-iSCSI.ps1** - iSCSI target and initiator management
  - Create and configure iSCSI targets
  - Initiator configuration and authentication
  - Connection management and monitoring
  - Performance monitoring

#### Monitoring and Alerting
- **Monitor-BackupStorage.ps1** - Comprehensive monitoring
  - Real-time performance monitoring
  - Health status checks
  - Alert configuration and notifications
  - Report generation

#### Troubleshooting
- **Troubleshoot-BackupStorage.ps1** - Troubleshooting and diagnostics
  - Automated issue detection
  - Repair procedures
  - Log analysis
  - Connectivity testing

### Examples and Tests

#### Examples
- **BackupStorage-Examples.ps1** - Comprehensive examples and demonstrations
  - Basic setup examples
  - Advanced configuration scenarios
  - Troubleshooting examples
  - Monitoring examples

#### Tests
- **Test-BackupStorage.ps1** - Test suite and validation
  - Unit tests for module functions
  - Integration tests for service connectivity
  - Performance tests
  - Stress tests

## Installation

### Prerequisites

- Windows Server 2016 or later
- PowerShell 5.1 or later
- Administrator privileges
- Required Windows features (installed automatically by scripts)

### Installation Steps

1. **Download the scripts** to your Windows Server
2. **Extract the files** to a directory (e.g., `C:\BackupStorage`)
3. **Run PowerShell as Administrator**
4. **Import the modules**:
   ```powershell
   Import-Module "C:\BackupStorage\Modules\BackupStorage-Core.psm1" -Force
   ```

## Usage

### Basic Usage

#### Install Backup Software
```powershell
.\Scripts\BackupSoftware\Manage-BackupSoftware.ps1 -Action "Install" -BackupType "Full" -BackupDestination "Local"
```

#### Configure Deduplication
```powershell
.\Scripts\Deduplication\Manage-Deduplication.ps1 -Action "Enable" -Volume "D:" -PolicyType "GeneralPurpose"
```

#### Monitor System Health
```powershell
.\Scripts\Monitoring\Monitor-BackupStorage.ps1 -Action "GetHealthStatus" -IncludePerformanceData
```

#### Troubleshoot Issues
```powershell
.\Scripts\Troubleshooting\Troubleshoot-BackupStorage.ps1 -Action "Diagnose" -IssueType "Performance"
```

### Advanced Usage

#### High Availability Setup
```powershell
# Install failover clustering
Install-WindowsFeature -Name Failover-Clustering -IncludeManagementTools

# Configure Storage Replica
Install-WindowsFeature -Name Storage-Replica -IncludeManagementTools
```

#### Performance Optimization
```powershell
# Enable Storage Spaces Direct
Enable-ClusterS2D -Confirm:$false

# Configure deduplication
Enable-DedupVolume -Volume D: -DataAccess
```

## Configuration

### Backup Configuration

#### Windows Server Backup
- **Backup Type**: Full, Incremental, Differential, SystemState, BareMetal
- **Destination**: Local, Network, Cloud, Tape
- **Schedule**: Daily, Weekly, Monthly, Custom
- **Retention**: Configurable retention policies

#### Third-Party Backup
- Support for major backup solutions
- Cloud backup integration
- Automated configuration

### Storage Configuration

#### Deduplication Policies
- **GeneralPurpose**: 3-day minimum age, 32KB minimum size
- **HyperV**: 1-day minimum age, 16KB minimum size
- **VDI**: 0-day minimum age, 8KB minimum size
- **Backup**: 7-day minimum age, 64KB minimum size

#### FSRM Configuration
- **Quota Templates**: Default, Department, Project
- **File Groups**: Audio, Video, Image, Executable
- **Screening**: Active and passive file screening
- **Reports**: Quota, screening, duplicate, large files

### Monitoring Configuration

#### Alert Thresholds
- **CPU Usage**: 80% (configurable)
- **Memory Usage**: 85% (configurable)
- **Disk Space**: 10% free space (configurable)
- **Disk I/O**: 90% (configurable)
- **Backup Failure Rate**: 5% (configurable)

#### Notification Methods
- **Email**: SMTP server configuration
- **Event Log**: Windows Event Log entries
- **File**: Log file output
- **SIEM**: Integration with SIEM systems

## Troubleshooting

### Common Issues

#### Backup Failures
1. **Check service status**:
   ```powershell
   Get-Service -Name "VSS" | Select-Object Name, Status, StartType
   ```

2. **Review backup logs**:
   ```powershell
   Get-WinEvent -LogName 'Microsoft-Windows-Backup' -MaxEvents 10
   ```

3. **Verify storage space**:
   ```powershell
   Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, FreeSpace, Size
   ```

#### Performance Issues
1. **Check CPU usage**:
   ```powershell
   Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 10
   ```

2. **Check memory usage**:
   ```powershell
   Get-Counter '\Memory\Available MBytes' -SampleInterval 1 -MaxSamples 10
   ```

3. **Check disk performance**:
   ```powershell
   Get-Counter '\PhysicalDisk(_Total)\% Disk Time' -SampleInterval 1 -MaxSamples 10
   ```

#### Storage Issues
1. **Check disk health**:
   ```powershell
   Get-PhysicalDisk | Select-Object DeviceID, HealthStatus, OperationalStatus
   ```

2. **Check volume status**:
   ```powershell
   Get-Volume | Select-Object DriveLetter, HealthStatus, OperationalStatus
   ```

3. **Run disk check**:
   ```powershell
   chkdsk C: /F /V
   ```

### Diagnostic Tools

#### Automated Diagnostics
```powershell
.\Scripts\Troubleshooting\Troubleshoot-BackupStorage.ps1 -Action "Diagnose" -IssueType "All"
```

#### Log Analysis
```powershell
.\Scripts\Troubleshooting\Troubleshoot-BackupStorage.ps1 -Action "AnalyzeLogs" -LogDays 7
```

#### Connectivity Testing
```powershell
.\Scripts\Troubleshooting\Troubleshoot-BackupStorage.ps1 -Action "TestConnectivity"
```

## Best Practices

### Backup Best Practices

1. **Regular Testing**: Test backup and restore procedures regularly
2. **Multiple Copies**: Maintain multiple backup copies
3. **Offsite Storage**: Store backups offsite for disaster recovery
4. **Monitoring**: Monitor backup success rates and performance
5. **Documentation**: Document backup procedures and schedules

### Storage Best Practices

1. **RAID Configuration**: Use appropriate RAID levels for redundancy
2. **Monitoring**: Monitor disk health and performance
3. **Deduplication**: Enable deduplication for appropriate workloads
4. **Quotas**: Implement storage quotas to prevent overuse
5. **Maintenance**: Schedule regular maintenance windows

### Security Best Practices

1. **Access Control**: Implement proper access controls
2. **Encryption**: Encrypt sensitive data at rest and in transit
3. **Auditing**: Enable auditing for sensitive operations
4. **Updates**: Keep systems updated with security patches
5. **Monitoring**: Monitor for security events and anomalies

## API Reference

### Core Functions

#### Get-BackupStatus
```powershell
Get-BackupStatus [-BackupType <String>] [-LastBackup] [-NextBackup]
```

#### Set-BackupConfiguration
```powershell
Set-BackupConfiguration [-BackupType <String>] [-Destination <String>] [-Schedule <String>]
```

#### Start-BackupJob
```powershell
Start-BackupJob [-BackupType <String>] [-Destination <String>] [-Compression <Boolean>]
```

#### Get-StorageHealth
```powershell
Get-StorageHealth [-Volume <String>] [-IncludePerformance] [-IncludeHealth]
```

#### Set-StorageConfiguration
```powershell
Set-StorageConfiguration [-Volume <String>] [-Deduplication <Boolean>] [-Quotas <Boolean>]
```

### Monitoring Functions

#### Get-PerformanceMetrics
```powershell
Get-PerformanceMetrics [-Duration <Int32>] [-Interval <Int32>] [-Counters <String[]>]
```

#### Set-AlertThresholds
```powershell
Set-AlertThresholds [-CPUUsage <Int32>] [-MemoryUsage <Int32>] [-DiskUsage <Int32>]
```

#### Send-Alert
```powershell
Send-Alert [-Message <String>] [-Severity <String>] [-Recipients <String[]>]
```

### Troubleshooting Functions

#### Test-SystemHealth
```powershell
Test-SystemHealth [-IncludeCPU] [-IncludeMemory] [-IncludeDisk] [-IncludeNetwork]
```

#### Repair-SystemIssues
```powershell
Repair-SystemIssues [-IssueType <String>] [-RepairMode <String>] [-BackupBeforeRepair]
```

#### Analyze-Logs
```powershell
Analyze-Logs [-LogPath <String>] [-Days <Int32>] [-Pattern <String>]
```

## Examples

### Example 1: Basic File Server Setup

```powershell
# Install File Server role
Install-WindowsFeature -Name FS-FileServer -IncludeManagementTools

# Create shared folders
New-Item -Path 'C:\Shares\Data' -ItemType Directory -Force
New-Item -Path 'C:\Shares\Backup' -ItemType Directory -Force

# Create shares
New-SmbShare -Name 'Data' -Path 'C:\Shares\Data' -FullAccess 'Everyone'
New-SmbShare -Name 'Backup' -Path 'C:\Shares\Backup' -FullAccess 'Administrators'

# Configure backup
.\Scripts\BackupSoftware\Manage-BackupSoftware.ps1 -Action "Install" -BackupType "Full"
```

### Example 2: High Availability Storage

```powershell
# Install failover clustering
Install-WindowsFeature -Name Failover-Clustering -IncludeManagementTools

# Install Storage Replica
Install-WindowsFeature -Name Storage-Replica -IncludeManagementTools

# Enable Storage Spaces Direct
Enable-ClusterS2D -Confirm:$false

# Configure deduplication
.\Scripts\Deduplication\Manage-Deduplication.ps1 -Action "Enable" -Volume "D:" -PolicyType "HyperV"
```

### Example 3: Monitoring Setup

```powershell
# Configure monitoring
.\Scripts\Monitoring\Monitor-BackupStorage.ps1 -Action "ConfigureAlerting" -EmailRecipients @("admin@contoso.com")

# Start monitoring
.\Scripts\Monitoring\Monitor-BackupStorage.ps1 -Action "StartMonitoring" -MonitoringDuration 60

# Generate report
.\Scripts\Monitoring\Monitor-BackupStorage.ps1 -Action "GenerateReport"
```

## Support

### Documentation
- Comprehensive documentation included with scripts
- Examples and best practices
- API reference and troubleshooting guides

### Testing
- Comprehensive test suite included
- Unit tests, integration tests, and performance tests
- Automated validation and reporting

### Updates
- Regular updates and improvements
- Bug fixes and feature enhancements
- Community feedback integration

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Changelog

### Version 1.0.0
- Initial release
- Core backup and storage management
- Comprehensive monitoring and troubleshooting
- Examples and test suite
- Complete documentation
