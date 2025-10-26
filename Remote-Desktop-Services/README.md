# RDS PowerShell Scripts

> Recommendation: Use this RDS automation toolkit to deploy, secure, and operate Remote Desktop Services with confidence.

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Last updated:** 2025-10-26

### Why it matters
- Improve reliability: predictable installs, HA/load balancing patterns, and validated health.
- Strengthen security: hardened defaults, encryption, and RBAC-aligned workflows.
- Accelerate delivery: scripted deployments and examples for common enterprise topologies.

### How it works (high-level)
- Modular PowerShell modules for deployment, configuration, security, monitoring, troubleshooting.
- Scenario and role scripts for CB, SH, GW, and Web Access with examples and tests.
- JSON/template-driven configurations to standardize environments.

## Overview

This repository contains a comprehensive collection of PowerShell scripts for managing Remote Desktop Services (RDS) on Windows Server. The solution provides modules, scripts, examples, and documentation for deploying, configuring, securing, troubleshooting, and optimizing RDS environments.

## Features

### Core Functionality
- **RDS Deployment**: Complete RDS role installation and configuration
- **Session Management**: Comprehensive session host management
- **User Access Control**: Advanced user authentication and authorization
- **Security Implementation**: Multi-layered security configurations
- **Performance Optimization**: System and session performance tuning
- **Monitoring & Alerting**: Real-time monitoring and alerting capabilities
- **Backup & Recovery**: Complete backup and disaster recovery solutions
- **Profile Management**: Advanced user profile management
- **Virtualization Support**: VDI, session, and application virtualization
- **Hybrid Cloud Integration**: Azure, AWS, and Google Cloud integration

### Advanced Features
- **High Availability**: Multi-server deployments with failover
- **Load Balancing**: Intelligent load distribution across session hosts
- **Automated Testing**: Comprehensive test suite for validation
- **Documentation**: Complete documentation and examples
- **Modular Design**: Reusable modules for different scenarios
- **Enterprise Ready**: Production-ready scripts with error handling

## Prerequisites

- Windows Server 2016 or later
- PowerShell 5.1 or later
- Administrator privileges
- RDS roles installed
- Active Directory (for domain environments)

## Installation

### Quick Start

1. **Clone the Repository**
   ```powershell
   git clone https://github.com/your-org/RDS-Scripts.git
   cd RDS-Scripts
   ```

2. **Install RDS Roles**
   ```powershell
   .\Scripts\Deployment\Deploy-RDSServer.ps1 -Action "Install" -ServerName "RDS-SERVER01"
   ```

3. **Configure RDS Deployment**
   ```powershell
   .\Scripts\Configuration\Configure-RDS.ps1 -Action "Configure" -ConnectionBroker "RDS-CB01" -SessionHosts @("RDS-SH01", "RDS-SH02")
   ```

4. **Verify Installation**
   ```powershell
   .\Tests\Test-RDS.ps1 -TestType "All" -TestPath "C:\RDS\Tests"
   ```

### Detailed Installation

1. **Download and Extract**
   - Download the latest release
   - Extract to your preferred location
   - Ensure all files are in the correct directory structure

2. **Install Prerequisites**
   ```powershell
   # Install required Windows features
   Install-WindowsFeature -Name RDS-RD-Server
   Install-WindowsFeature -Name RDS-Connection-Broker
   Install-WindowsFeature -Name RDS-Gateway
   Install-WindowsFeature -Name RDS-Web-Access
   ```

3. **Import Modules**
   ```powershell
   # Import RDS modules
   Import-Module ".\Modules\RDS-Core.psm1" -Force
   Import-Module ".\Modules\RDS-Security.psm1" -Force
   Import-Module ".\Modules\RDS-Monitoring.psm1" -Force
   Import-Module ".\Modules\RDS-Troubleshooting.psm1" -Force
   ```

4. **Run Initial Configuration**
   ```powershell
   # Run initial configuration
   .\Scripts\Configuration\Configure-RDS.ps1 -Action "Install" -ConnectionBroker "RDS-CB01" -SessionHosts @("RDS-SH01")
   ```

## Usage

### Basic Operations

#### Deploy RDS Server
```powershell
# Deploy RDS server
.\Scripts\Deployment\Deploy-RDSServer.ps1 -Action "Install" -ServerName "RDS-SERVER01"
```

#### Configure RDS
```powershell
# Configure RDS deployment
.\Scripts\Configuration\Configure-RDS.ps1 -Action "Configure" -ConnectionBroker "RDS-CB01" -SessionHosts @("RDS-SH01", "RDS-SH02")
```

#### Secure RDS
```powershell
# Secure RDS deployment
.\Scripts\Security\Secure-RDS.ps1 -Action "Configure" -ConnectionBroker "RDS-CB01" -SecurityLevel "Enhanced" -EnableEncryption
```

#### Monitor RDS
```powershell
# Monitor RDS performance
.\Scripts\Monitoring\Monitor-RDS.ps1 -Action "Monitor" -ConnectionBroker "RDS-CB01" -SessionHosts @("RDS-SH01", "RDS-SH02")
```

#### Troubleshoot RDS
```powershell
# Troubleshoot RDS issues
.\Scripts\Troubleshooting\Troubleshoot-RDS.ps1 -Action "Diagnose" -ConnectionBroker "RDS-CB01" -SessionHosts @("RDS-SH01", "RDS-SH02")
```

### Advanced Operations

#### High Availability Setup
```powershell
# Configure high availability
.\Scripts\Configuration\Configure-RDS.ps1 -Action "Configure" -ConnectionBroker "RDS-CB01" -SessionHosts @("RDS-SH01", "RDS-SH02") -EnableHighAvailability
```

#### Load Balancing Configuration
```powershell
# Configure load balancing
.\Scripts\Configuration\Configure-RDS.ps1 -Action "Configure" -ConnectionBroker "RDS-CB01" -SessionHosts @("RDS-SH01", "RDS-SH02") -EnableLoadBalancing
```

#### Performance Optimization
```powershell
# Optimize RDS performance
.\Scripts\Performance\Optimize-RDS.ps1 -Action "Optimize" -ConnectionBroker "RDS-CB01" -SessionHosts @("RDS-SH01", "RDS-SH02") -OptimizationLevel "Advanced"
```

#### Backup Configuration
```powershell
# Backup RDS configuration
.\Scripts\Backup\Backup-RDS.ps1 -Action "BackupConfiguration" -BackupPath "C:\RDS\Backup" -BackupType "Full"
```

#### Profile Management
```powershell
# Manage RDS profiles
.\Scripts\ProfileManagement\Manage-RDSProfiles.ps1 -Action "CreateProfile" -ProfilePath "C:\Users" -ProfileType "Roaming"
```

#### Virtualization Setup
```powershell
# Deploy VDI
.\Scripts\Virtualization\Manage-RDSVirtualization.ps1 -Action "DeployVDI" -VirtualizationPath "C:\RDS\Virtualization" -VirtualizationType "VDI"
```

#### Hybrid Cloud Integration
```powershell
# Deploy Azure RDS
.\Scripts\HybridCloud\Manage-RDSHybridCloud.ps1 -Action "DeployAzureRDS" -CloudPath "C:\RDS\Cloud" -CloudProvider "Azure"
```

## Scripts Reference

### Deployment Scripts
- **Deploy-RDSServer.ps1**: Main RDS server deployment script
- **Deploy-RDSRoles.ps1**: RDS roles installation script
- **Deploy-RDSDeployment.ps1**: Complete RDS deployment script

### Configuration Scripts
- **Configure-RDS.ps1**: Comprehensive RDS configuration management
- **Configure-RDSSecurity.ps1**: RDS security configuration
- **Configure-RDSMonitoring.ps1**: RDS monitoring configuration
- **Configure-RDSBackup.ps1**: RDS backup configuration

### Security Scripts
- **Secure-RDS.ps1**: RDS security implementation
- **Secure-RDSAuthentication.ps1**: Authentication configuration
- **Secure-RDSAuthorization.ps1**: Authorization configuration
- **Secure-RDSEncryption.ps1**: Encryption configuration

### Monitoring Scripts
- **Monitor-RDS.ps1**: RDS monitoring and alerting
- **Monitor-RDSPerformance.ps1**: Performance monitoring
- **Monitor-RDSHealth.ps1**: Health monitoring
- **Monitor-RDSSessions.ps1**: Session monitoring

### Troubleshooting Scripts
- **Troubleshoot-RDS.ps1**: RDS troubleshooting and diagnostics
- **Troubleshoot-RDSConnectivity.ps1**: Connectivity troubleshooting
- **Troubleshoot-RDSPerformance.ps1**: Performance troubleshooting
- **Troubleshoot-RDSSecurity.ps1**: Security troubleshooting

### Performance Scripts
- **Optimize-RDS.ps1**: RDS performance optimization
- **Optimize-RDSSessions.ps1**: Session optimization
- **Optimize-RDSResources.ps1**: Resource optimization
- **Optimize-RDSNetwork.ps1**: Network optimization

### Backup Scripts
- **Backup-RDS.ps1**: RDS backup management
- **Backup-RDSConfiguration.ps1**: Configuration backup
- **Backup-RDSProfiles.ps1**: Profile backup
- **Backup-RDSSessions.ps1**: Session backup

### Profile Management Scripts
- **Manage-RDSProfiles.ps1**: Profile management
- **Manage-RDSProfileMigration.ps1**: Profile migration
- **Manage-RDSProfileOptimization.ps1**: Profile optimization
- **Manage-RDSProfileCleanup.ps1**: Profile cleanup

### Virtualization Scripts
- **Manage-RDSVirtualization.ps1**: Virtualization management
- **Manage-RDSVDI.ps1**: VDI management
- **Manage-RDSSessionVirtualization.ps1**: Session virtualization
- **Manage-RDSAppVirtualization.ps1**: Application virtualization

### Hybrid Cloud Scripts
- **Manage-RDSHybridCloud.ps1**: Hybrid cloud management
- **Manage-RDSAzure.ps1**: Azure integration
- **Manage-RDSAWS.ps1**: AWS integration
- **Manage-RDSGoogleCloud.ps1**: Google Cloud integration

## Examples

### Basic Setup Examples

#### Installation Example
```powershell
# Install RDS roles
Install-WindowsFeature -Name RDS-RD-Server
Install-WindowsFeature -Name RDS-Connection-Broker
Install-WindowsFeature -Name RDS-Gateway
Install-WindowsFeature -Name RDS-Web-Access
```

#### Configuration Example
```powershell
# Configure RDS deployment
New-RDSessionDeployment -ConnectionBroker "RDS-CB01" -SessionHost "RDS-SH01" -WebAccessServer "RDS-WA01"
```

#### User Access Example
```powershell
# Create user groups
New-ADGroup -Name "RDS Users" -GroupScope Global
Add-ADGroupMember -Identity "RDS Users" -Members "User1", "User2"
```

### Advanced Configuration Examples

#### High Availability Example
```powershell
# Configure high availability
Set-RDSessionHost -ConnectionBroker "RDS-CB01" -SessionHost "RDS-SH01" -HighAvailability $true
Set-RDSessionHost -ConnectionBroker "RDS-CB01" -SessionHost "RDS-SH02" -HighAvailability $true
```

#### Load Balancing Example
```powershell
# Configure load balancing
Set-RDSessionHost -ConnectionBroker "RDS-CB01" -SessionHost "RDS-SH01" -LoadBalancing $true
Set-RDSessionHost -ConnectionBroker "RDS-CB01" -SessionHost "RDS-SH02" -LoadBalancing $true
```

#### Security Example
```powershell
# Configure security
Set-RDSessionHost -ConnectionBroker "RDS-CB01" -SessionHost "RDS-SH01" -EncryptionLevel "High"
Set-RDSessionHost -ConnectionBroker "RDS-CB01" -SessionHost "RDS-SH01" -AuthenticationMethod "NTLM"
```

### Troubleshooting Examples

#### Connection Issues Example
```powershell
# Test connectivity
Test-NetConnection -ComputerName "RDS-SH01" -Port 3389
Get-Service -Name "TermService"
Get-EventLog -LogName "Application" -Source "TermService"
```

#### Performance Issues Example
```powershell
# Check performance
Get-Counter -Counter "\\Processor(_Total)\\% Processor Time"
Get-Counter -Counter "\\Memory\\Available MBytes"
Get-Counter -Counter "\\Network Interface(*)\\Bytes Total/sec"
```

#### Security Issues Example
```powershell
# Check security
Get-EventLog -LogName "Security" -Source "Microsoft-Windows-Security-Auditing"
Get-ADUser -Identity "Username" | Get-ADUser -Properties "MemberOf"
```

### Best Practices Examples

#### Security Best Practices Example
```powershell
# Enable strong authentication
Set-RDSessionHost -ConnectionBroker "RDS-CB01" -SessionHost "RDS-SH01" -AuthenticationMethod "NTLM"
Set-RDSessionHost -ConnectionBroker "RDS-CB01" -SessionHost "RDS-SH01" -EncryptionLevel "High"
```

#### Performance Best Practices Example
```powershell
# Optimize performance
Set-RDSessionHost -ConnectionBroker "RDS-CB01" -SessionHost "RDS-SH01" -MaxConnections 50
Set-RDSessionHost -ConnectionBroker "RDS-CB01" -SessionHost "RDS-SH01" -IdleTimeout 30
```

#### Monitoring Best Practices Example
```powershell
# Set up monitoring
Get-Counter -Counter "\\Processor(_Total)\\% Processor Time"
Get-Counter -Counter "\\Memory\\Available MBytes"
Get-Counter -Counter "\\Terminal Services\\Active Sessions"
```

## Testing

### Running Tests

#### Unit Tests
```powershell
# Run unit tests
.\Tests\Test-RDS.ps1 -TestType "Unit" -TestPath "C:\RDS\Tests"
```

#### Integration Tests
```powershell
# Run integration tests
.\Tests\Test-RDS.ps1 -TestType "Integration" -TestPath "C:\RDS\Tests"
```

#### Performance Tests
```powershell
# Run performance tests
.\Tests\Test-RDS.ps1 -TestType "Performance" -TestPath "C:\RDS\Tests"
```

#### Security Tests
```powershell
# Run security tests
.\Tests\Test-RDS.ps1 -TestType "Security" -TestPath "C:\RDS\Tests"
```

#### All Tests
```powershell
# Run all tests
.\Tests\Test-RDS.ps1 -TestType "All" -TestPath "C:\RDS\Tests"
```

### Test Categories

- **Unit Tests**: Test individual functions and modules
- **Integration Tests**: Test service integration and communication
- **Performance Tests**: Test system and session performance
- **Security Tests**: Test authentication, authorization, and encryption
- **End-to-End Tests**: Test complete workflows and scenarios

## Configuration

### Configuration Files

#### RDS Configuration
```json
{
    "ConnectionBroker": "RDS-CB01",
    "SessionHosts": ["RDS-SH01", "RDS-SH02"],
    "Gateway": "RDS-GW01",
    "WebAccess": "RDS-WA01",
    "HighAvailability": true,
    "LoadBalancing": true,
    "Monitoring": true,
    "Security": {
        "EncryptionLevel": "High",
        "AuthenticationMethod": "NTLM",
        "Auditing": true
    }
}
```

#### Security Configuration
```json
{
    "Authentication": {
        "Method": "NTLM",
        "Strength": "Strong",
        "MultiFactor": true
    },
    "Authorization": {
        "Method": "RBAC",
        "Strength": "Strong",
        "LeastPrivilege": true
    },
    "Encryption": {
        "Method": "TLS 1.2",
        "Strength": "Strong",
        "KeyManagement": true
    },
    "Auditing": {
        "Method": "Comprehensive",
        "Strength": "Strong",
        "Compliance": true
    }
}
```

#### Monitoring Configuration
```json
{
    "Performance": {
        "CPUThreshold": 80,
        "MemoryThreshold": 85,
        "DiskThreshold": 90,
        "NetworkThreshold": 75
    },
    "Health": {
        "ServiceHealth": true,
        "ResourceHealth": true,
        "ConnectivityHealth": true,
        "SecurityHealth": true
    },
    "Alerting": {
        "EmailAlerts": true,
        "SMSAlerts": false,
        "WebhookAlerts": true,
        "LogAlerts": true
    }
}
```

## Troubleshooting

### Common Issues

#### Connection Issues
- **Symptoms**: Users cannot connect to RDS
- **Causes**: Network connectivity, service issues, authentication problems
- **Solutions**: Check network, verify services, review authentication settings

#### Performance Issues
- **Symptoms**: Slow session performance, high resource usage
- **Causes**: Resource constraints, configuration issues, network problems
- **Solutions**: Optimize resources, adjust configuration, check network

#### Security Issues
- **Symptoms**: Authentication failures, authorization errors
- **Causes**: Configuration issues, policy violations, certificate problems
- **Solutions**: Review configuration, check policies, verify certificates

### Diagnostic Commands

#### System Health Check
```powershell
# Check RDS system health
Get-RDSessionHost -ConnectionBroker "RDS-CB01" -SessionHost "RDS-SH01"
Get-Service -Name "TermService"
Get-EventLog -LogName "Application" -Source "TermService" -Newest 10
```

#### Performance Analysis
```powershell
# Analyze RDS performance
Get-Counter -Counter "\\Processor(_Total)\\% Processor Time"
Get-Counter -Counter "\\Memory\\Available MBytes"
Get-Counter -Counter "\\Terminal Services\\Active Sessions"
```

#### Network Diagnostics
```powershell
# Test network connectivity
Test-NetConnection -ComputerName "RDS-SH01" -Port 3389
Test-NetConnection -ComputerName "RDS-CB01" -Port 135
Test-NetConnection -ComputerName "RDS-WA01" -Port 443
```

## Best Practices

### Security Best Practices

1. **Enable Strong Authentication**
   - Use multi-factor authentication
   - Implement certificate-based authentication
   - Enable smart card authentication

2. **Implement Least Privilege Access**
   - Use role-based access control
   - Implement resource-based access control
   - Set up attribute-based access control

3. **Enable Encryption**
   - Use strong encryption algorithms
   - Enable network encryption
   - Implement storage encryption

4. **Set Up Auditing**
   - Enable comprehensive auditing
   - Monitor security events
   - Set up alerting for security violations

### Performance Best Practices

1. **Optimize System Resources**
   - Monitor CPU usage
   - Optimize memory allocation
   - Manage disk I/O

2. **Configure Session Limits**
   - Set appropriate session limits
   - Implement session timeouts
   - Configure idle timeouts

3. **Implement Load Balancing**
   - Use connection broker load balancing
   - Configure session host load balancing
   - Set up health checks

4. **Monitor Performance**
   - Set up performance monitoring
   - Configure performance alerts
   - Implement performance reporting

### High Availability Best Practices

1. **Configure Redundancy**
   - Use multiple connection brokers
   - Deploy multiple session hosts
   - Implement gateway redundancy

2. **Set Up Failover**
   - Configure automatic failover
   - Test failover procedures
   - Document recovery procedures

3. **Implement Backup**
   - Set up regular backups
   - Test backup procedures
   - Implement disaster recovery

### Monitoring Best Practices

1. **Set Up Comprehensive Monitoring**
   - Monitor system performance
   - Track user sessions
   - Monitor security events

2. **Configure Alerting**
   - Set up performance alerts
   - Configure security alerts
   - Implement availability alerts

3. **Implement Reporting**
   - Generate performance reports
   - Create security reports
   - Set up compliance reports

## Contributing

### Getting Started

1. **Fork the Repository**
   - Fork the repository to your GitHub account
   - Clone your fork locally

2. **Create a Branch**
   - Create a feature branch for your changes
   - Make your changes and test thoroughly

3. **Submit a Pull Request**
   - Submit a pull request with your changes
   - Include documentation and tests

### Contribution Guidelines

1. **Code Standards**
   - Follow PowerShell best practices
   - Include comprehensive error handling
   - Add detailed comments and documentation

2. **Testing**
   - Include unit tests for new functionality
   - Test integration scenarios
   - Verify performance impact

3. **Documentation**
   - Update documentation for new features
   - Include usage examples
   - Update README if necessary

## Support

### Getting Help

1. **Documentation**
   - Review this README
   - Check script help information
   - Consult Microsoft documentation

2. **Community Support**
   - Microsoft Tech Community
   - PowerShell Community
   - RDS User Groups

3. **Professional Support**
   - Microsoft Support
   - Professional Services
   - Consulting Services

### Reporting Issues

1. **Issue Reporting**
   - Document the issue
   - Include error messages
   - Provide system information
   - Include steps to reproduce

2. **System Information**
   - Windows Server version
   - PowerShell version
   - RDS version
   - Hardware specifications

3. **Log Information**
   - Event logs
   - PowerShell logs
   - RDS logs
   - System logs

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Version History

- **v1.0.0** - Initial release with core functionality
- **v1.1.0** - Added security enhancements
- **v1.2.0** - Added monitoring capabilities
- **v1.3.0** - Added troubleshooting tools
- **v1.4.0** - Added performance optimization
- **v1.5.0** - Added backup and recovery
- **v1.6.0** - Added profile management
- **v1.7.0** - Added virtualization support
- **v1.8.0** - Added hybrid cloud integration

## Acknowledgments

- Microsoft for RDS documentation and support
- PowerShell community for best practices
- Contributors and testers
- Users who provided feedback and suggestions

## Contact

- **Email**: support@rds-scripts.com
- **Website**: https://rds-scripts.com
- **GitHub**: https://github.com/rds-scripts
- **Documentation**: https://docs.rds-scripts.com

---

*This README is maintained by the RDS PowerShell Scripts team. For updates and improvements, please contribute to the project.*