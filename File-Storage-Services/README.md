# File and Storage Services PowerShell Scripts

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Date:** December 2024

This repository contains a comprehensive set of modular PowerShell scripts for implementing, configuring, and managing Windows File and Storage Services on Windows Server.

## Features

- **Modular Design**: Each component is separate and reusable
- **Portable**: Can run on any Windows Server environment
- **Comprehensive**: Covers file servers, storage management, sharing, backup, and performance
- **Error Handling**: Robust error handling and logging
- **Documentation**: Detailed documentation and examples

## Project Structure

```
File-Storage-Services/
├── Modules/                    # Core PowerShell modules
│   ├── FileStorage-Core.psm1  # Core file and storage functions
│   ├── FileStorage-Management.psm1 # File server management
│   ├── FileStorage-Monitoring.psm1 # Monitoring and diagnostics
│   └── FileStorage-Backup.psm1    # Backup and recovery
├── Scripts/                   # Executable scripts
│   ├── FileServer/           # File server management scripts
│   ├── Storage/              # Storage management scripts
│   ├── FileSharing/         # File sharing and permissions
│   ├── Backup/              # Backup and disaster recovery
│   └── Performance/         # Performance monitoring and optimization
├── Examples/                # Usage examples and templates
├── Documentation/           # Detailed documentation
└── Tests/                  # Pester test files
```

## Prerequisites

- Windows Server 2016 or later
- PowerShell 5.1 or later
- File and Storage Services role installed
- Appropriate permissions for file and storage operations

## Quick Start

1. Import the core module:
   ```powershell
   Import-Module .\Modules\FileStorage-Core.psm1
   ```

2. Check file server status:
   ```powershell
   Get-FileServerStatus
   ```

3. Configure file sharing:
   ```powershell
   .\Scripts\FileSharing\Configure-FileShares.ps1
   ```

## Key Capabilities

### File Server Management
- File server installation and configuration
- Share creation and management
- NTFS permissions management
- DFS (Distributed File System) configuration
- File Server Resource Manager (FSRM) setup

### Storage Management
- Disk management and partitioning
- Storage pools and spaces
- Volume management
- Storage tiering
- Deduplication configuration

### File Sharing
- SMB/CIFS share management
- NFS share configuration
- Access-based enumeration
- Offline files configuration
- BranchCache setup

### Backup and Recovery
- Automated backup scheduling
- Shadow copy management
- File-level backup and restore
- Disaster recovery procedures
- Backup verification and reporting

### Performance Monitoring
- Storage performance monitoring
- File server performance metrics
- Capacity planning and reporting
- Performance optimization recommendations
- Resource utilization tracking

## License

This project is provided as-is for educational and administrative purposes.

## Contributing

Contributions are welcome! Please read the documentation and follow the established patterns for consistency.
