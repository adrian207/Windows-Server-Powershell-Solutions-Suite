# Print Server PowerShell Scripts

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Date:** December 2024

A comprehensive PowerShell solution for managing Windows Print Server services, printers, print queues, and print jobs across any Windows Server environment.

## Overview

This solution provides modular and portable PowerShell scripts for implementing, configuring, and troubleshooting Windows Print Server services. It's designed to work in any environment and provides comprehensive management capabilities for print infrastructure.

## Features

### Core Functionality
- **Print Server Installation & Configuration** - Complete setup and configuration
- **Printer Management** - Add, remove, configure printers and drivers
- **Print Queue Management** - Monitor and manage print queues and jobs
- **Driver Management** - Install, update, and manage printer drivers
- **Print Server Monitoring** - Performance monitoring and health checks
- **Backup & Recovery** - Configuration backup and disaster recovery
- **Troubleshooting** - Comprehensive diagnostics and automated repair

### Key Capabilities
- ✅ **Modular Design** - Each component is separate and reusable
- ✅ **Portable** - Can run on any Windows Server environment
- ✅ **Comprehensive** - Covers all aspects of print server management
- ✅ **Error Handling** - Robust error handling and logging
- ✅ **Documentation** - Detailed documentation and examples
- ✅ **Testing** - Comprehensive test suite with Pester

## Project Structure

```
Print-Server-Scripts/
├── Modules/                    # Core PowerShell modules
│   ├── PrintServer-Core.psm1   # Core print server functions
│   ├── PrintServer-Management.psm1 # Printer and queue management
│   └── PrintServer-Troubleshooting.psm1 # Diagnostics and troubleshooting
├── Scripts/                    # Executable scripts
│   ├── PrintServer/           # Print server installation and configuration
│   ├── PrinterManagement/     # Printer and driver management
│   ├── PrintQueue/           # Print queue and job management
│   ├── Monitoring/           # Performance monitoring
│   ├── Backup/               # Backup and disaster recovery
│   └── Troubleshooting/      # Troubleshooting and diagnostics
├── Documentation/            # Detailed documentation
├── Examples/                 # Usage examples and templates
├── Tests/                    # Pester test files
├── README.md                 # This file
└── Quick-Start-Guide.md      # Quick start guide
```

## Requirements

- Windows Server 2016 or later
- PowerShell 5.1 or later
- Administrator privileges
- Print Server role (installed via scripts)

## Quick Start

1. **Install Print Server Role**
   ```powershell
   .\Scripts\PrintServer\Install-PrintServer.ps1 -EnableWebManagement -EnableBranchOfficeDirectPrinting
   ```

2. **Add Printers**
   ```powershell
   .\Scripts\PrinterManagement\Manage-Printers.ps1 -Action AddPrinter -PrinterName "Office Printer" -DriverName "Generic / Text Only"
   ```

3. **Monitor Print Server**
   ```powershell
   .\Scripts\Monitoring\Monitor-PrintServer.ps1 -Action Monitor -Duration 300
   ```

## Modules

### PrintServer-Core.psm1
Core functions for print server management including:
- Prerequisites checking and installation
- Service management
- Health monitoring
- Basic printer operations

### PrintServer-Management.psm1
Advanced printer and queue management including:
- Printer installation and configuration
- Driver management
- Print queue operations
- Permission management

### PrintServer-Troubleshooting.psm1
Diagnostic and troubleshooting functions including:
- Health checks and diagnostics
- Performance monitoring
- Automated repair procedures
- Log analysis

## Scripts

### Print Server Management
- **Install-PrintServer.ps1** - Complete print server installation and configuration
- **Configure-PrintServer.ps1** - Print server configuration management

### Printer Management
- **Manage-Printers.ps1** - Add, remove, and configure printers
- **Manage-Drivers.ps1** - Driver installation and management

### Print Queue Management
- **Manage-PrintQueues.ps1** - Print queue and job management
- **Monitor-PrintJobs.ps1** - Print job monitoring and management

### Monitoring and Troubleshooting
- **Monitor-PrintServer.ps1** - Performance monitoring
- **Troubleshoot-PrintServer.ps1** - Comprehensive troubleshooting

### Backup and Recovery
- **Backup-PrintServer.ps1** - Configuration backup and disaster recovery

## Examples

See the `Examples/` directory for:
- Basic print server setup
- Printer configuration examples
- Monitoring and troubleshooting examples

## Testing

Run the comprehensive test suite:
```powershell
.\Tests\Test-PrintServerServices.ps1
```

## Documentation

- **Quick-Start-Guide.md** - Get started quickly
- **Documentation/User-Guide.md** - Detailed user guide
- **Examples/** - Usage examples and templates

## Contributing

This solution follows PowerShell best practices and includes comprehensive error handling, logging, and documentation.

## License

This project is part of the Windows Server PowerShell Scripts collection.

## Support

For issues and questions, refer to the documentation or create an issue in the repository.
