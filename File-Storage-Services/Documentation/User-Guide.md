# File and Storage Services PowerShell Scripts - User Guide

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Date:** December 2024

## Overview

This comprehensive PowerShell solution provides modular, portable scripts for implementing, configuring, and managing Windows File and Storage Services on Windows Server. The solution is designed to work in any environment and can be easily customized for specific requirements.

## Table of Contents

1. [Installation and Setup](#installation-and-setup)
2. [Core Modules](#core-modules)
3. [File Server Scripts](#file-server-scripts)
4. [File Sharing Scripts](#file-sharing-scripts)
5. [Storage Management Scripts](#storage-management-scripts)
5. [Backup and Recovery Scripts](#backup-and-recovery-scripts)
6. [Performance Monitoring Scripts](#performance-monitoring-scripts)
7. [Usage Examples](#usage-examples)
8. [Best Practices](#best-practices)
9. [Troubleshooting Guide](#troubleshooting-guide)

## Installation and Setup

### Prerequisites

- Windows Server 2016 or later
- PowerShell 5.1 or later
- Administrator privileges
- File and Storage Services role
- Appropriate permissions for file and storage operations

### Quick Start

1. **Download and Extract**
   ```powershell
   # Extract the File-Storage-Services folder to your desired location
   # Example: C:\Scripts\File-Storage-Services
   ```

2. **Import Core Module**
   ```powershell
   Import-Module "C:\Scripts\File-Storage-Services\Modules\FileStorage-Core.psm1"
   ```

3. **Check Prerequisites**
   ```powershell
   Test-FileStoragePrerequisites
   ```

4. **Install File Server**
   ```powershell
   .\Scripts\FileServer\Install-FileServer.ps1 -DomainName "contoso.com" -EnableSMB3 -RequireSigning
   ```

## Core Modules

### FileStorage-Core.psm1

The core module provides fundamental file and storage operations:

#### Functions

- `Install-FileStoragePrerequisites` - Installs required Windows features
- `Get-FileServerStatus` - Gets comprehensive file server status
- `Start-FileServerServices` - Starts file server services
- `Stop-FileServerServices` - Stops file server services
- `Get-StorageInformation` - Gets storage information

#### Usage Examples

```powershell
# Install prerequisites
Install-FileStoragePrerequisites

# Get current status
$status = Get-FileServerStatus
$status | Format-List

# Start services
Start-FileServerServices
```

### FileStorage-Management.psm1

The management module handles file server operations:

#### Functions

- `New-FileShare` - Creates new file shares
- `Remove-FileShare` - Removes file shares
- `Get-FileShareReport` - Generates share reports
- `Set-FileServerConfiguration` - Configures file server settings
- `Enable-FSRM` - Enables File Server Resource Manager

#### Usage Examples

```powershell
# Create a file share
New-FileShare -ShareName "Data" -Path "C:\Shares\Data" -Description "Data Share" -FullAccess @("Administrators") -ReadAccess @("Users")

# Configure file server
Set-FileServerConfiguration -EnableSMB3 -RequireSigning -EnableEncryption

# Enable FSRM
Enable-FSRM -EnableQuotas -EnableFileScreening -EnableReporting
```

## File Server Scripts

### Install-FileServer.ps1

Comprehensive file server installation script.

#### Parameters

- `DomainName` (Mandatory) - The domain name for the file server
- `ServerName` - The name of the file server (default: current computer name)
- `EnableSMB1` - Enable SMB 1.0 protocol (not recommended for security)
- `EnableSMB2` - Enable SMB 2.0 protocol
- `EnableSMB3` - Enable SMB 3.0 protocol (recommended)
- `RequireSigning` - Require SMB signing for security
- `EnableEncryption` - Enable SMB encryption
- `EnableFSRM` - Enable File Server Resource Manager
- `EnableDFS` - Enable Distributed File System
- `EnableNFS` - Enable Network File System
- `SkipPrerequisites` - Skip prerequisite installation
- `SkipConfiguration` - Skip initial configuration
- `RestartRequired` - Allow automatic restart if required

#### Usage Examples

```powershell
# Basic installation
.\Install-FileServer.ps1 -DomainName "contoso.com" -EnableSMB3 -RequireSigning

# Advanced installation with all features
.\Install-FileServer.ps1 -DomainName "contoso.com" -EnableSMB3 -RequireSigning -EnableEncryption -EnableFSRM -EnableDFS

# Installation with custom server name
.\Install-FileServer.ps1 -DomainName "contoso.com" -ServerName "FS01" -EnableSMB3 -EnableFSRM
```

## File Sharing Scripts

### Manage-FileShares.ps1

Comprehensive file sharing management script.

#### Parameters

- `Action` (Mandatory) - The action to perform (Create, Remove, Configure, Report, Backup, Restore)
- `ShareName` - The name of the share
- `Path` - The local path to share
- `Description` - Description for the share
- `FullAccess` - Array of accounts with full access
- `ReadAccess` - Array of accounts with read access
- `ChangeAccess` - Array of accounts with change access
- `EnableAccessBasedEnumeration` - Enable access-based enumeration
- `EnableOfflineFiles` - Enable offline files caching
- `CachingMode` - Offline files caching mode (Manual, Documents, Programs, None)
- `OutputPath` - Path to save reports or backups
- `BackupPath` - Path to restore configuration from
- `IncludePermissions` - Include detailed permission information in reports
- `IncludeUsage` - Include usage statistics in reports

#### Usage Examples

```powershell
# Create a file share
.\Manage-FileShares.ps1 -Action Create -ShareName "Data" -Path "C:\Shares\Data" -Description "Data Share" -FullAccess @("Administrators") -ReadAccess @("Users")

# Configure existing share
.\Manage-FileShares.ps1 -Action Configure -ShareName "Data" -EnableAccessBasedEnumeration -EnableOfflineFiles -CachingMode "Documents"

# Generate report
.\Manage-FileShares.ps1 -Action Report -OutputPath "C:\Reports\FileShares.html" -IncludePermissions -IncludeUsage

# Backup configuration
.\Manage-FileShares.ps1 -Action Backup -OutputPath "C:\Backups\FileShares.xml"

# Restore configuration
.\Manage-FileShares.ps1 -Action Restore -BackupPath "C:\Backups\FileShares.xml"
```

## Storage Management Scripts

### Storage Management Features

The storage management capabilities include:

- **Disk Management**: Partitioning, formatting, and disk operations
- **Storage Pools**: Creating and managing storage pools
- **Storage Spaces**: Configuring storage spaces and tiers
- **Volume Management**: Creating and managing volumes
- **Deduplication**: Configuring data deduplication
- **Storage Replica**: Setting up storage replication

#### Usage Examples

```powershell
# Get storage information
$storageInfo = Get-StorageInformation
$storageInfo.Disks | Format-Table
$storageInfo.Volumes | Format-Table

# Create storage pool
New-StoragePool -FriendlyName "DataPool" -StorageSubSystemFriendlyName "Windows Storage*" -PhysicalDisks (Get-PhysicalDisk)

# Create storage space
New-VirtualDisk -StoragePoolFriendlyName "DataPool" -FriendlyName "DataSpace" -Size 1TB -ResiliencySettingName "Mirror"
```

## Backup and Recovery Scripts

### Backup Features

The backup and recovery capabilities include:

- **Share Configuration Backup**: Backup file share settings and permissions
- **File-Level Backup**: Backup individual files and directories
- **Shadow Copy Management**: Configure and manage shadow copies
- **Disaster Recovery**: Complete disaster recovery procedures
- **Backup Verification**: Verify backup integrity and completeness

#### Usage Examples

```powershell
# Backup file share configuration
.\Manage-FileShares.ps1 -Action Backup -OutputPath "C:\Backups\FileShares.xml"

# Configure shadow copies
Enable-VolumeShadowCopy -Drive "C:" -MaxSpace 10GB

# Create shadow copy
New-VolumeShadowCopy -Drive "C:" -Description "Daily Backup"
```

## Performance Monitoring Scripts

### Performance Monitoring Features

The performance monitoring capabilities include:

- **Storage Performance**: Monitor disk I/O, throughput, and latency
- **File Server Performance**: Monitor SMB performance and connections
- **Capacity Planning**: Track storage usage and growth trends
- **Performance Optimization**: Identify and resolve performance bottlenecks
- **Resource Utilization**: Monitor CPU, memory, and network usage

#### Usage Examples

```powershell
# Monitor storage performance
Get-Counter -Counter "\PhysicalDisk(*)\Disk Reads/sec", "\PhysicalDisk(*)\Disk Writes/sec" -SampleInterval 1 -MaxSamples 10

# Monitor file server performance
Get-Counter -Counter "\Server\Sessions Logged On", "\Server\Files Open" -SampleInterval 1 -MaxSamples 10

# Get storage capacity information
Get-Volume | Select-Object DriveLetter, FileSystemLabel, Size, SizeRemaining | Format-Table
```

## Usage Examples

### Complete File Server Deployment

```powershell
# Step 1: Check prerequisites
Test-FileStoragePrerequisites

# Step 2: Install file server
.\Scripts\FileServer\Install-FileServer.ps1 -DomainName "contoso.com" -EnableSMB3 -RequireSigning -EnableEncryption -EnableFSRM

# Step 3: Create file shares
.\Scripts\FileSharing\Manage-FileShares.ps1 -Action Create -ShareName "Data" -Path "C:\Shares\Data" -Description "Data Share" -FullAccess @("Administrators") -ReadAccess @("Users")

# Step 4: Configure shares
.\Scripts\FileSharing\Manage-FileShares.ps1 -Action Configure -ShareName "Data" -EnableAccessBasedEnumeration -EnableOfflineFiles

# Step 5: Generate report
.\Scripts\FileSharing\Manage-FileShares.ps1 -Action Report -OutputPath "C:\Reports\FileServer.html" -IncludePermissions -IncludeUsage
```

### File Share Management

```powershell
# Create multiple shares
$shares = @(
    @{ Name = "Data"; Path = "C:\Shares\Data"; Description = "Data Share" },
    @{ Name = "Projects"; Path = "C:\Shares\Projects"; Description = "Projects Share" },
    @{ Name = "Backup"; Path = "C:\Shares\Backup"; Description = "Backup Share" }
)

foreach ($share in $shares) {
    .\Scripts\FileSharing\Manage-FileShares.ps1 -Action Create -ShareName $share.Name -Path $share.Path -Description $share.Description -FullAccess @("Administrators") -ReadAccess @("Users")
}

# Backup all configurations
.\Scripts\FileSharing\Manage-FileShares.ps1 -Action Backup -OutputPath "C:\Backups\AllFileShares.xml"
```

### Storage Management

```powershell
# Get comprehensive storage information
$storageInfo = Get-StorageInformation

# Display disk information
$storageInfo.Disks | Format-Table FriendlyName, Size, OperationalStatus, HealthStatus

# Display volume information
$storageInfo.Volumes | Format-Table DriveLetter, FileSystemLabel, Size, SizeRemaining

# Create storage pool and space
$disks = Get-PhysicalDisk | Where-Object { $_.CanPool -eq $true }
New-StoragePool -FriendlyName "DataPool" -StorageSubSystemFriendlyName "Windows Storage*" -PhysicalDisks $disks
New-VirtualDisk -StoragePoolFriendlyName "DataPool" -FriendlyName "DataSpace" -Size 1TB -ResiliencySettingName "Mirror"
```

## Best Practices

### Security

1. **SMB Protocol Security**
   - Use SMB 3.0 or later
   - Enable SMB signing
   - Enable SMB encryption
   - Disable SMB 1.0 if not needed

2. **Share Permissions**
   - Use principle of least privilege
   - Regularly audit share permissions
   - Use access-based enumeration
   - Implement proper NTFS permissions

3. **Network Security**
   - Configure appropriate firewall rules
   - Use secure authentication methods
   - Implement network segmentation
   - Monitor access logs

### Performance

1. **Storage Optimization**
   - Use appropriate RAID levels
   - Implement storage tiering
   - Configure deduplication
   - Monitor storage performance

2. **File Server Optimization**
   - Optimize SMB settings
   - Configure appropriate caching
   - Monitor connection limits
   - Use BranchCache for remote offices

3. **Monitoring**
   - Implement continuous monitoring
   - Set up performance alerts
   - Track capacity usage
   - Monitor access patterns

### Backup and Recovery

1. **Backup Strategy**
   - Regular configuration backups
   - File-level backups
   - Shadow copy management
   - Offsite backup storage

2. **Recovery Planning**
   - Test restore procedures
   - Document recovery steps
   - Maintain recovery contacts
   - Regular disaster recovery drills

## Troubleshooting Guide

### Common Issues

#### Service Issues

**Problem**: File server services not starting
**Solution**:
```powershell
# Check service status
Get-Service -Name LanmanServer, LanmanWorkstation

# Start services
Start-FileServerServices

# Check for errors
Get-EventLog -LogName System -Source "LanmanServer" -Newest 10
```

#### Share Issues

**Problem**: Cannot access file shares
**Solution**:
```powershell
# Check share status
Get-SmbShare | Format-Table Name, ShareState, Path

# Check permissions
Get-SmbShareAccess -Name "ShareName"

# Test connectivity
Test-NetConnection -ComputerName "ServerName" -Port 445
```

#### Permission Issues

**Problem**: Access denied to files or shares
**Solution**:
```powershell
# Check share permissions
Get-SmbShareAccess -Name "ShareName"

# Check NTFS permissions
Get-Acl "C:\Path\To\File" | Format-List

# Check effective permissions
Get-NTFSEffectiveAccess -Path "C:\Path\To\File" -Account "Username"
```

### Diagnostic Commands

```powershell
# Comprehensive file server status
Get-FileServerStatus

# Health check
Test-FileServerHealth

# Storage information
Get-StorageInformation

# Share report
Get-FileShareReport -IncludePermissions -IncludeUsage
```

### Performance Troubleshooting

```powershell
# Check disk performance
Get-Counter -Counter "\PhysicalDisk(*)\Avg. Disk Queue Length" -SampleInterval 1 -MaxSamples 5

# Check SMB performance
Get-Counter -Counter "\Server\Sessions Logged On", "\Server\Files Open" -SampleInterval 1 -MaxSamples 5

# Check network performance
Get-Counter -Counter "\Network Interface(*)\Bytes Total/sec" -SampleInterval 1 -MaxSamples 5
```

## Support and Maintenance

### Regular Maintenance Tasks

1. **Daily**
   - Check service status
   - Monitor disk space
   - Review error logs

2. **Weekly**
   - Generate share reports
   - Check backup status
   - Review performance metrics

3. **Monthly**
   - Audit permissions
   - Update documentation
   - Review capacity planning

### Getting Help

1. **Check Logs**
   - Review installation logs
   - Check Windows Event Logs
   - Analyze performance logs

2. **Use Diagnostic Tools**
   - Run health checks
   - Generate diagnostic reports
   - Use troubleshooting scripts

3. **Documentation**
   - Refer to this user guide
   - Check script help documentation
   - Review Microsoft documentation

## Conclusion

This PowerShell solution provides a comprehensive, modular approach to File and Storage Services management. The scripts are designed to be portable, reliable, and easy to use in any Windows Server environment. Regular use of the monitoring and diagnostic tools will help maintain a healthy file server infrastructure.

For additional support or customization needs, refer to the individual script documentation and Microsoft's official File and Storage Services documentation.
