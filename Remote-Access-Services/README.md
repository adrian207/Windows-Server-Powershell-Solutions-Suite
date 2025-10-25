# Remote Access Services PowerShell Scripts

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Date:** December 2024

A comprehensive PowerShell solution for managing Windows Server Remote Access Services including DirectAccess, VPN, Web Application Proxy, and Network Policy Server (NPS).

## Overview

This solution provides enterprise-grade PowerShell modules and scripts for managing all aspects of Windows Server Remote Access Services. It includes comprehensive configuration, monitoring, troubleshooting, and automation capabilities.

## Features

### Core Modules
- **RemoteAccess-Core.psm1** - Core utilities and prerequisite checks
- **RemoteAccess-DirectAccess.psm1** - DirectAccess configuration and management
- **RemoteAccess-VPN.psm1** - VPN server configuration and client management
- **RemoteAccess-WebApplicationProxy.psm1** - Web Application Proxy management
- **RemoteAccess-NPS.psm1** - Network Policy Server automation
- **RemoteAccess-Monitoring.psm1** - Comprehensive monitoring and diagnostics

### Key Capabilities

#### DirectAccess Management
- Install and configure DirectAccess
- Client group management
- Authentication and encryption configuration
- Connectivity testing and monitoring
- Health status reporting

#### VPN Server Management
- Multiple VPN protocol support (PPTP, L2TP, SSTP, IKEv2)
- Authentication method configuration
- Client connection monitoring
- Performance testing
- Security policy management

#### Web Application Proxy
- Application publishing configuration
- Pre-authentication setup
- Certificate management
- Access control policies
- Monitoring and diagnostics

#### Network Policy Server (NPS)
- RADIUS server configuration
- Network access policies
- Authentication methods
- Accounting and logging
- Health monitoring

## Prerequisites

- Windows Server 2016 or later
- PowerShell 5.1 or later
- Administrator privileges
- Domain membership (for DirectAccess)

## Installation

1. Clone or download the solution
2. Ensure all prerequisites are met
3. Import the required modules
4. Run prerequisite checks

```powershell
# Import core module
Import-Module .\Modules\RemoteAccess-Core.psm1

# Check prerequisites
Test-RemoteAccessPrerequisites

# Get service status
Get-RemoteAccessServiceStatus
```

## Usage Examples

### DirectAccess Configuration

```powershell
# Import DirectAccess module
Import-Module .\Modules\RemoteAccess-DirectAccess.psm1

# Install DirectAccess
Install-DirectAccess -StartService -SetAutoStart

# Create DirectAccess configuration
New-DirectAccessConfiguration -ClientGroupName "DirectAccess Clients" -InternalInterface "Internal" -ExternalInterface "External"

# Get DirectAccess status
Get-DirectAccessStatus

# Test connectivity
Test-DirectAccessConnectivity -TestDuration 60
```

### VPN Server Configuration

```powershell
# Import VPN module
Import-Module .\Modules\RemoteAccess-VPN.psm1

# Install VPN server
Install-VPNServer -StartService -SetAutoStart

# Create VPN configuration
New-VPNConfiguration -VPNName "Corporate VPN" -VPNType "SSTP" -AuthenticationMethod "MS-CHAPv2"

# Get VPN status
Get-VPNStatus

# Test connectivity
Test-VPNConnectivity -TestType "Performance"
```

### Health Monitoring

```powershell
# Import core module
Import-Module .\Modules\RemoteAccess-Core.psm1

# Test overall health
Test-RemoteAccessHealth

# Get service status
Get-RemoteAccessServiceStatus

# Get installed features
Get-RemoteAccessFeatures
```

## Scripts

### DirectAccess Scripts
- `Install-DirectAccess.ps1` - Complete DirectAccess installation and configuration
- `Configure-DirectAccess.ps1` - DirectAccess configuration management
- `Monitor-DirectAccess.ps1` - DirectAccess monitoring and health checks

### VPN Scripts
- `Install-VPNServer.ps1` - VPN server installation and configuration
- `Configure-VPN.ps1` - VPN configuration management
- `Monitor-VPN.ps1` - VPN monitoring and client management

### Web Application Proxy Scripts
- `Install-WebApplicationProxy.ps1` - WAP installation and configuration
- `Configure-WAP.ps1` - WAP application publishing
- `Monitor-WAP.ps1` - WAP monitoring and diagnostics

### NPS Scripts
- `Install-NPS.ps1` - NPS installation and configuration
- `Configure-NPS.ps1` - NPS policy management
- `Monitor-NPS.ps1` - NPS monitoring and health checks

### Troubleshooting Scripts
- `Troubleshoot-RemoteAccess.ps1` - Comprehensive troubleshooting
- `Diagnose-Connectivity.ps1` - Connectivity diagnostics
- `Repair-Services.ps1` - Service repair and recovery

## Documentation

- **User Guide** - Comprehensive usage documentation
- **Administrator Guide** - Advanced configuration and management
- **Troubleshooting Guide** - Common issues and solutions
- **API Reference** - Complete function documentation

## Examples

See the `Examples` directory for real-world usage scenarios and best practices.

## Testing

Run the comprehensive test suite:

```powershell
# Run all tests
Invoke-Pester .\Tests\

# Run specific test categories
Invoke-Pester .\Tests\ -Tag "DirectAccess"
Invoke-Pester .\Tests\ -Tag "VPN"
```

## Contributing

1. Follow PowerShell best practices
2. Include comprehensive error handling
3. Add detailed documentation
4. Write corresponding tests
5. Ensure all linter errors are resolved

## License

This project is licensed under the MIT License.

## Support

For issues, questions, or contributions, please refer to the documentation or create an issue in the project repository.

## Version History

- **v1.0.0** - Initial release with core Remote Access functionality
  - DirectAccess management
  - VPN server configuration
  - Web Application Proxy support
  - Network Policy Server automation
  - Comprehensive monitoring and diagnostics
