# AD LDS PowerShell Scripts - Complete Documentation

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Date:** December 2024

## 📚 Table of Contents

1. [Overview](#overview)
2. [Installation & Setup](#installation--setup)
3. [Core Modules](#core-modules)
4. [Scripts Reference](#scripts-reference)
5. [Enterprise Scenarios](#enterprise-scenarios)
6. [Security Guide](#security-guide)
7. [Monitoring & Alerting](#monitoring--alerting)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)
10. [API Reference](#api-reference)
11. [Examples](#examples)
12. [Testing](#testing)
13. [Troubleshooting Guide](#troubleshooting-guide)
14. [FAQ](#faq)

## 🎯 Overview

The AD LDS PowerShell Scripts solution provides comprehensive automation and management capabilities for Active Directory Lightweight Directory Services (AD LDS) in Windows Server environments. This solution includes deployment automation, security features, monitoring capabilities, troubleshooting tools, and support for 25+ enterprise scenarios.

### Key Features

- **Complete AD LDS Lifecycle Management**: Installation, configuration, deployment, and maintenance
- **Enterprise Scenarios**: 25+ pre-built scenarios for common use cases
- **Security Hardening**: Comprehensive security configuration and compliance testing
- **Monitoring & Alerting**: Real-time monitoring, performance analytics, and automated alerting
- **Troubleshooting Tools**: Automated diagnostics, issue detection, and repair capabilities
- **Production Ready**: Error handling, audit logging, and enterprise-grade reliability

## 🚀 Installation & Setup

### Prerequisites

- Windows Server 2016 or later
- PowerShell 5.1 or later
- Administrator privileges
- Network connectivity for LDAP services

### Quick Installation

```powershell
# Clone or download the solution
# Navigate to the AD-LDS-Scripts directory

# Import all modules
Import-Module ".\Modules\ADLDS-Core.psm1" -Force
Import-Module ".\Modules\ADLDS-Security.psm1" -Force
Import-Module ".\Modules\ADLDS-Monitoring.psm1" -Force
Import-Module ".\Modules\ADLDS-Troubleshooting.psm1" -Force

# Deploy a complete AD LDS instance
.\Scripts\Deployment\Deploy-ADLDSInstance.ps1 -Environment "Production" -InstanceName "AppDirectory" -Port 389 -SSLPort 636 -PartitionDN "CN=AppUsers,DC=AppDir,DC=local" -EnableSecurity -EnableMonitoring
```

### Verification

```powershell
# Test prerequisites
Test-ADLDSPrerequisites

# Check instance status
Get-ADLDSInstanceStatus -InstanceName "AppDirectory"

# Get statistics
Get-ADLDSStatistics -InstanceName "AppDirectory"
```

## 🔧 Core Modules

### ADLDS-Core.psm1

Core AD LDS operations including installation, instance management, and basic operations.

**Key Functions:**
- `Install-ADLDS` - Install AD LDS role
- `New-ADLDSInstance` - Create AD LDS instance
- `New-ADLDSPartition` - Create LDAP partition
- `Add-ADLDSUser` - Add LDAP user
- `Add-ADLDSGroup` - Add LDAP group
- `Set-ADLDSSchema` - Extend schema
- `Get-ADLDSStatistics` - Get performance statistics

### ADLDS-Security.psm1

Security features including authentication, access control, and compliance testing.

**Key Functions:**
- `Set-ADLDSAuthentication` - Configure authentication
- `Set-ADLDSAccessControl` - Set access control
- `Enable-ADLDSSecurityPolicies` - Enable security policies
- `Get-ADLDSSecurityStatus` - Get security status
- `Test-ADLDSSecurityCompliance` - Test compliance
- `Set-ADLDSCredentialVault` - Configure credential vault

### ADLDS-Monitoring.psm1

Monitoring and performance analysis capabilities.

**Key Functions:**
- `Start-ADLDSMonitoring` - Start monitoring
- `Get-ADLDSHealthStatus` - Get health status
- `Set-ADLDSAlerting` - Configure alerting
- `Get-ADLDSAnalytics` - Get analytics

### ADLDS-Troubleshooting.psm1

Troubleshooting and diagnostics tools.

**Key Functions:**
- `Start-ADLDSDiagnostics` - Run diagnostics
- `Repair-ADLDSIssues` - Repair issues
- `Test-ADLDSConfiguration` - Test configuration
- `Get-ADLDSTroubleshootingGuide` - Get troubleshooting guide

## 📜 Scripts Reference

### Deployment Scripts

#### Deploy-ADLDSInstance.ps1
Complete AD LDS instance deployment with all enterprise features.

**Parameters:**
- `Environment` - Environment type (Development, Staging, Production)
- `InstanceName` - Name of the AD LDS instance
- `Port` - LDAP port (default: 389)
- `SSLPort` - SSL port (default: 636)
- `EnableSecurity` - Enable security features
- `EnableMonitoring` - Enable monitoring

**Example:**
```powershell
.\Deploy-ADLDSInstance.ps1 -Environment "Production" -InstanceName "AppDirectory" -EnableSecurity -EnableMonitoring
```

### Configuration Scripts

#### Configure-ADLDS.ps1
Comprehensive configuration management for AD LDS instances.

**Actions:**
- `ConfigureInstance` - Configure instance settings
- `CreatePartition` - Create partitions
- `ExtendSchema` - Extend schema
- `ManageUsers` - Manage users
- `ManageGroups` - Manage groups
- `BackupConfiguration` - Backup configuration
- `RestoreConfiguration` - Restore configuration

**Example:**
```powershell
.\Configure-ADLDS.ps1 -Action "ConfigureInstance" -InstanceName "AppDirectory" -ConfigurationFile ".\Config\AppDirectory-Config.json"
```

### Security Scripts

#### Secure-ADLDS.ps1
Comprehensive security hardening for AD LDS instances.

**Parameters:**
- `SecurityLevel` - Security level (Basic, Enhanced, Maximum)
- `ComplianceStandard` - Compliance standard (SOX, HIPAA, PCI-DSS, ISO27001)
- `EnableAuditLogging` - Enable audit logging
- `EnableCredentialVault` - Enable credential vault

**Example:**
```powershell
.\Secure-ADLDS.ps1 -InstanceName "AppDirectory" -SecurityLevel "Enhanced" -ComplianceStandard "SOX" -EnableAuditLogging
```

### Monitoring Scripts

#### Monitor-ADLDS.ps1
Comprehensive monitoring and alerting for AD LDS instances.

**Actions:**
- `StartMonitoring` - Start monitoring
- `GetHealthStatus` - Get health status
- `ConfigureAlerting` - Configure alerting
- `GetAnalytics` - Get analytics

**Example:**
```powershell
.\Monitor-ADLDS.ps1 -InstanceName "AppDirectory" -Action "StartMonitoring" -MonitoringDuration 60
```

### Troubleshooting Scripts

#### Troubleshoot-ADLDS.ps1
Comprehensive troubleshooting and diagnostics for AD LDS instances.

**Actions:**
- `RunDiagnostics` - Run diagnostics
- `RepairIssues` - Repair issues
- `TestConfiguration` - Test configuration
- `GetTroubleshootingGuide` - Get troubleshooting guide

**Example:**
```powershell
.\Troubleshoot-ADLDS.ps1 -InstanceName "AppDirectory" -Action "RunDiagnostics" -DiagnosticLevel "Comprehensive"
```

## 🏢 Enterprise Scenarios

### Application-Specific Directory Store

**Use Case:** Independent identity repository for ERP, CRM, HR systems requiring LDAP.

**Deployment:**
```powershell
.\Deploy-ADLDSEnterpriseScenarios.ps1 -Scenario "ApplicationDirectory" -InstanceName "AppDirectory" -Environment "Production"
```

**Features:**
- Application-specific partitions
- Custom schema extensions
- Enhanced security
- Comprehensive monitoring

### Partner Identity Directory

**Use Case:** External contractor/vendor authentication separate from corporate AD.

**Deployment:**
```powershell
.\Deploy-ADLDSEnterpriseScenarios.ps1 -Scenario "PartnerIdentity" -InstanceName "PartnerDir" -Environment "Production"
```

**Features:**
- Partner-specific partitions
- Contract and access level management
- Maximum security
- Audit logging

### Credential Vault

**Use Case:** Secure storage and management of service credentials and application secrets.

**Deployment:**
```powershell
.\Deploy-ADLDSEnterpriseScenarios.ps1 -Scenario "CredentialVault" -InstanceName "CredVault" -Environment "Production"
```

**Features:**
- Credential-specific partitions
- Encryption key management
- Maximum security
- Rotation schedule support

### Hybrid Identity Staging

**Use Case:** Preprocessing and transformation of identity data before Azure AD Connect.

**Deployment:**
```powershell
.\Deploy-ADLDSEnterpriseScenarios.ps1 -Scenario "HybridIdentity" -InstanceName "HybridDir" -Environment "Production"
```

**Features:**
- On-premises and cloud user partitions
- Sync metadata management
- Enhanced security
- Transformation capabilities

### Multi-Tenant Directory Platform

**Use Case:** Host identities for different business units or clients on a single server.

**Deployment:**
```powershell
.\Deploy-ADLDSEnterpriseScenarios.ps1 -Scenario "MultiTenant" -InstanceName "MultiTenant" -Environment "Production"
```

**Features:**
- Tenant-specific partitions
- Quota and usage tracking
- Maximum security
- Audit logging

## 🔒 Security Guide

### Authentication Methods

#### Basic Authentication
```powershell
Set-ADLDSAuthentication -InstanceName "AppDirectory" -AuthenticationType "Simple"
```

#### Enhanced Authentication
```powershell
Set-ADLDSAuthentication -InstanceName "AppDirectory" -AuthenticationType "Negotiate" -EnableSSL
```

#### Maximum Security Authentication
```powershell
Set-ADLDSAuthentication -InstanceName "AppDirectory" -AuthenticationType "Kerberos" -EnableSSL -RequireStrongAuthentication
```

### Access Control Configuration

```powershell
# Set access control for administrators
Set-ADLDSAccessControl -InstanceName "AppDirectory" -ObjectDN "CN=AppUsers,DC=AppDir,DC=local" -Principal "CN=Administrators" -Permission "Full Control"

# Set access control for service accounts
Set-ADLDSAccessControl -InstanceName "AppDirectory" -ObjectDN "CN=AppUsers,DC=AppDir,DC=local" -Principal "CN=ServiceAccounts" -Permission "Read"
```

### Security Policies

```powershell
# Enable comprehensive security policies
Enable-ADLDSSecurityPolicies -InstanceName "AppDirectory" -EnableAuditLogging -EnablePasswordPolicy -EnableAccountLockout -EnableSSLRequired -EnableStrongAuthentication
```

### Compliance Testing

```powershell
# Test SOX compliance
Test-ADLDSSecurityCompliance -InstanceName "AppDirectory" -ComplianceStandard "SOX"

# Test HIPAA compliance
Test-ADLDSSecurityCompliance -InstanceName "AppDirectory" -ComplianceStandard "HIPAA"

# Test PCI-DSS compliance
Test-ADLDSSecurityCompliance -InstanceName "AppDirectory" -ComplianceStandard "PCI-DSS"
```

## 📊 Monitoring & Alerting

### Performance Monitoring

```powershell
# Start comprehensive monitoring
Start-ADLDSMonitoring -InstanceName "AppDirectory" -MonitoringDuration 60 -AlertThresholds @{
    HighConnectionRate = 100
    HighQueryRate = 1000
    HighResponseTime = 1000
    HighErrorRate = 10
    HighMemoryUsage = 80
}
```

### Health Status Monitoring

```powershell
# Get comprehensive health status
Get-ADLDSHealthStatus -InstanceName "AppDirectory"
```

### Alerting Configuration

```powershell
# Configure email alerting
Set-ADLDSAlerting -InstanceName "AppDirectory" -AlertTypes @("HighConnectionRate", "HighErrorRate", "ServiceDown") -EmailRecipients @("admin@contoso.com") -SMTPServer "smtp.contoso.com"
```

### Analytics and Reporting

```powershell
# Get comprehensive analytics
Get-ADLDSAnalytics -InstanceName "AppDirectory" -TimeRange 24
```

## 🛠️ Troubleshooting

### Comprehensive Diagnostics

```powershell
# Run comprehensive diagnostics
Start-ADLDSDiagnostics -InstanceName "AppDirectory" -IncludeEventLogs -IncludeConnectivity -IncludePerformance -LogPath "C:\ADLDS\Diagnostics"
```

### Automated Repair

```powershell
# Repair common issues
Repair-ADLDSIssues -InstanceName "AppDirectory" -RepairType "All" -BackupPath "C:\ADLDS\Backup"
```

### Configuration Testing

```powershell
# Test configuration
Test-ADLDSConfiguration -InstanceName "AppDirectory"
```

### Troubleshooting Guide

```powershell
# Get troubleshooting guide
Get-ADLDSTroubleshootingGuide
```

## 📋 Best Practices

### Instance Design

1. **Use separate instances for different applications**
2. **Implement proper partition design**
3. **Configure appropriate security levels**
4. **Set up monitoring and alerting**
5. **Implement backup and recovery procedures**

### Security Best Practices

1. **Use strong authentication methods**
2. **Implement comprehensive access control**
3. **Enable audit logging**
4. **Regular security compliance testing**
5. **Implement credential vault for sensitive data**

### Performance Optimization

1. **Monitor performance metrics**
2. **Optimize partition design**
3. **Implement caching strategies**
4. **Scale instances as needed**
5. **Regular performance analysis**

### Operational Best Practices

1. **Document configurations**
2. **Implement change management**
3. **Regular testing and validation**
4. **Train administrators**
5. **Maintain disaster recovery procedures**

## 🔌 API Reference

### Core Functions

#### Install-ADLDS
```powershell
Install-ADLDS [-IncludeManagementTools] [-RestartRequired]
```

#### New-ADLDSInstance
```powershell
New-ADLDSInstance -InstanceName <String> [-Port <Int32>] [-SSLPort <Int32>] [-DataPath <String>] [-LogPath <String>] [-ServiceAccount <String>] [-Description <String>]
```

#### New-ADLDSPartition
```powershell
New-ADLDSPartition -InstanceName <String> -PartitionName <String> -PartitionDN <String> [-Description <String>]
```

#### Add-ADLDSUser
```powershell
Add-ADLDSUser -InstanceName <String> -PartitionDN <String> -UserName <String> -UserDN <String> [-Password <SecureString>] [-Description <String>] [-Email <String>]
```

#### Add-ADLDSGroup
```powershell
Add-ADLDSGroup -InstanceName <String> -PartitionDN <String> -GroupName <String> -GroupDN <String> [-GroupType <String>] [-Description <String>]
```

#### Set-ADLDSSchema
```powershell
Set-ADLDSSchema -InstanceName <String> [-SchemaFile <String>] [-CustomAttributes <String[]>] [-CustomClasses <String[]>]
```

### Security Functions

#### Set-ADLDSAuthentication
```powershell
Set-ADLDSAuthentication -InstanceName <String> [-AuthenticationType <String>] [-EnableSSL] [-SSLPort <Int32>] [-RequireStrongAuthentication]
```

#### Set-ADLDSAccessControl
```powershell
Set-ADLDSAccessControl -InstanceName <String> -ObjectDN <String> -Principal <String> -Permission <String> [-AccessType <String>]
```

#### Enable-ADLDSSecurityPolicies
```powershell
Enable-ADLDSSecurityPolicies -InstanceName <String> [-EnableAuditLogging] [-EnablePasswordPolicy] [-EnableAccountLockout] [-EnableSSLRequired] [-EnableStrongAuthentication]
```

### Monitoring Functions

#### Start-ADLDSMonitoring
```powershell
Start-ADLDSMonitoring [-InstanceName <String>] [-MonitoringDuration <Int32>] [-AlertThresholds <Hashtable>] [-LogPath <String>]
```

#### Get-ADLDSHealthStatus
```powershell
Get-ADLDSHealthStatus [-InstanceName <String>]
```

#### Get-ADLDSAnalytics
```powershell
Get-ADLDSAnalytics [-InstanceName <String>] [-TimeRange <Int32>]
```

## 📖 Examples

### Basic Setup Example

```powershell
# Install AD LDS
Install-ADLDS -IncludeManagementTools

# Create instance
New-ADLDSInstance -InstanceName "DemoInstance" -Port 389 -SSLPort 636

# Create partition
New-ADLDSPartition -InstanceName "DemoInstance" -PartitionName "DefaultPartition" -PartitionDN "CN=DefaultPartition,DC=DemoDir,DC=local"

# Add user
Add-ADLDSUser -InstanceName "DemoInstance" -PartitionDN "CN=DefaultPartition,DC=DemoDir,DC=local" -UserName "demoUser" -UserDN "CN=demoUser,CN=DefaultPartition,DC=DemoDir,DC=local"

# Add group
Add-ADLDSGroup -InstanceName "DemoInstance" -PartitionDN "CN=DefaultPartition,DC=DemoDir,DC=local" -GroupName "DemoGroup" -GroupDN "CN=DemoGroup,CN=DefaultPartition,DC=DemoDir,DC=local"
```

### Application Directory Example

```powershell
# Create application directory instance
New-ADLDSInstance -InstanceName "AppDirectory" -Port 389 -SSLPort 636

# Create application-specific partitions
New-ADLDSPartition -InstanceName "AppDirectory" -PartitionName "AppUsers" -PartitionDN "CN=AppUsers,DC=AppDir,DC=local"
New-ADLDSPartition -InstanceName "AppDirectory" -PartitionName "AppGroups" -PartitionDN "CN=AppGroups,DC=AppDir,DC=local"
New-ADLDSPartition -InstanceName "AppDirectory" -PartitionName "AppDevices" -PartitionDN "CN=AppDevices,DC=AppDir,DC=local"

# Extend schema
Set-ADLDSSchema -InstanceName "AppDirectory" -CustomAttributes @("deviceSerialNumber", "licenseKey", "appRole") -CustomClasses @("deviceObject", "applicationUser")

# Configure security
Set-ADLDSAuthentication -InstanceName "AppDirectory" -AuthenticationType "Negotiate" -EnableSSL
Enable-ADLDSSecurityPolicies -InstanceName "AppDirectory" -EnableAuditLogging -EnablePasswordPolicy
```

### Credential Vault Example

```powershell
# Create credential vault instance
New-ADLDSInstance -InstanceName "CredVault" -Port 391 -SSLPort 638

# Create credential-specific partitions
New-ADLDSPartition -InstanceName "CredVault" -PartitionName "ServiceCredentials" -PartitionDN "CN=ServiceCredentials,DC=CredVault,DC=local"
New-ADLDSPartition -InstanceName "CredVault" -PartitionName "ApplicationSecrets" -PartitionDN "CN=ApplicationSecrets,DC=CredVault,DC=local"

# Extend schema for credential management
Set-ADLDSSchema -InstanceName "CredVault" -CustomAttributes @("credentialType", "encryptionKey", "accessLevel", "rotationSchedule") -CustomClasses @("credentialObject", "secretObject")

# Configure maximum security
Set-ADLDSAuthentication -InstanceName "CredVault" -AuthenticationType "Kerberos" -EnableSSL -RequireStrongAuthentication
Enable-ADLDSSecurityPolicies -InstanceName "CredVault" -EnableAuditLogging -EnablePasswordPolicy -EnableAccountLockout -EnableSSLRequired -EnableStrongAuthentication

# Configure credential vault
Set-ADLDSCredentialVault -InstanceName "CredVault" -VaultName "SecureCredentials" -AccessGroups @("CN=Administrators", "CN=ServiceAccounts")
```

## 🧪 Testing

### Running Tests

```powershell
# Run all tests
.\Tests\Test-ADLDSScripts.ps1 -TestType "All" -InstanceName "TestInstance"

# Run specific test types
.\Tests\Test-ADLDSScripts.ps1 -TestType "Unit" -InstanceName "TestInstance"
.\Tests\Test-ADLDSScripts.ps1 -TestType "Integration" -InstanceName "TestInstance"
.\Tests\Test-ADLDSScripts.ps1 -TestType "Security" -InstanceName "TestInstance"
```

### Test Types

- **Unit Tests**: Test individual functions
- **Integration Tests**: Test function interactions
- **Validation Tests**: Test configuration validation
- **Performance Tests**: Test performance monitoring
- **Security Tests**: Test security features

## 🔍 Troubleshooting Guide

### Common Issues

#### Service Not Running
**Symptoms:** LDAP connections fail, AD LDS service shows as stopped
**Causes:** Service manually stopped, service failed to start, dependency issues
**Solutions:** Start the AD LDS service, check service dependencies, review event logs

#### Instance Not Found
**Symptoms:** Cannot connect to instance, instance directory not found
**Causes:** Instance not created, wrong instance name, path issues
**Solutions:** Create AD LDS instance, verify instance name, check instance paths

#### Authentication Failures
**Symptoms:** LDAP bind failures, access denied errors
**Causes:** Invalid credentials, authentication method issues, user not found
**Solutions:** Verify credentials, check authentication method, verify user exists

#### Partition Access Issues
**Symptoms:** Cannot access partitions, permission denied errors
**Causes:** Partition not created, permission issues, schema problems
**Solutions:** Create partitions, check permissions, verify schema

#### Performance Issues
**Symptoms:** Slow LDAP responses, high CPU usage, memory issues
**Causes:** Insufficient resources, poor indexing, large datasets
**Solutions:** Increase resources, optimize indexes, review data size

### Diagnostic Steps

1. Check AD LDS service status
2. Verify instance configuration
3. Test LDAP connectivity
4. Check authentication
5. Review event logs
6. Test partition access
7. Monitor performance

### PowerShell Commands

```powershell
# Check service status
Get-Service -Name "ADAM_*"

# List instances
Get-ChildItem "C:\Program Files\Microsoft ADAM\"

# Test LDAP connection
Test-NetConnection -ComputerName localhost -Port 389

# Check event logs
Get-WinEvent -FilterHashtable @{LogName="Application"; ProviderName="ADAM"}
```

## ❓ FAQ

### General Questions

**Q: What is AD LDS?**
A: Active Directory Lightweight Directory Services (AD LDS) is a Microsoft directory service that provides LDAP functionality without the overhead of a full domain controller.

**Q: When should I use AD LDS?**
A: Use AD LDS for application-specific directories, partner identity management, schema testing, credential vaults, and hybrid identity scenarios.

**Q: What are the benefits of AD LDS?**
A: Benefits include lightweight deployment, flexible schema, application isolation, cross-platform compatibility, and cost-effective directory services.

### Technical Questions

**Q: How do I extend the AD LDS schema?**
A: Use the `Set-ADLDSSchema` function with custom attributes and classes:
```powershell
Set-ADLDSSchema -InstanceName "AppDirectory" -CustomAttributes @("deviceSerialNumber", "licenseKey") -CustomClasses @("deviceObject", "applicationUser")
```

**Q: How do I configure security for AD LDS?**
A: Use the security functions to configure authentication, access control, and security policies:
```powershell
Set-ADLDSAuthentication -InstanceName "AppDirectory" -AuthenticationType "Negotiate" -EnableSSL
Enable-ADLDSSecurityPolicies -InstanceName "AppDirectory" -EnableAuditLogging -EnablePasswordPolicy
```

**Q: How do I monitor AD LDS performance?**
A: Use the monitoring functions to track performance and set up alerting:
```powershell
Start-ADLDSMonitoring -InstanceName "AppDirectory" -MonitoringDuration 60
Get-ADLDSHealthStatus -InstanceName "AppDirectory"
```

### Troubleshooting Questions

**Q: How do I troubleshoot AD LDS issues?**
A: Use the troubleshooting functions for comprehensive diagnostics:
```powershell
Start-ADLDSDiagnostics -InstanceName "AppDirectory" -IncludeEventLogs -IncludeConnectivity
Repair-ADLDSIssues -InstanceName "AppDirectory" -RepairType "All"
```

**Q: How do I test AD LDS configuration?**
A: Use the configuration testing function:
```powershell
Test-ADLDSConfiguration -InstanceName "AppDirectory"
```

**Q: How do I get help with AD LDS issues?**
A: Use the troubleshooting guide function:
```powershell
Get-ADLDSTroubleshootingGuide
```

---

**📚 This documentation provides comprehensive guidance for using the AD LDS PowerShell Scripts solution. For additional support, refer to the examples, test the solution, and follow the best practices outlined in this guide.**
