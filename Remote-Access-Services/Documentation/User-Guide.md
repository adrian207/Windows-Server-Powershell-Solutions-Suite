# Remote Access Services PowerShell Scripts - User Guide

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Date:** December 2024

## Table of Contents
1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Core Modules](#core-modules)
6. [Deployment Guide](#deployment-guide)
7. [Configuration Guide](#configuration-guide)
8. [Monitoring Guide](#monitoring-guide)
9. [Security Guide](#security-guide)
10. [Troubleshooting Guide](#troubleshooting-guide)
11. [Best Practices](#best-practices)
12. [Examples](#examples)
13. [API Reference](#api-reference)

## Overview

The Remote Access Services PowerShell Scripts provide a comprehensive solution for managing Windows Server Remote Access Services including DirectAccess, VPN, Web Application Proxy (WAP), and Network Policy Server (NPS). This solution covers the complete lifecycle from deployment to ongoing monitoring and troubleshooting.

### Key Features
- **Complete Deployment Automation** - Automated installation and configuration
- **Service Management** - Start, stop, and configure services
- **Health Monitoring** - Continuous monitoring with alerts
- **Performance Testing** - Comprehensive performance analysis
- **Security Management** - Security policies and compliance reporting
- **Troubleshooting** - Diagnostic tools and repair functions

## Prerequisites

### System Requirements
- Windows Server 2016 or later
- PowerShell 5.1 or later
- Administrator privileges
- Domain membership (for DirectAccess)

### Optional Requirements
- Active Directory Domain Services
- Certificate Services (for SSL/TLS)
- Federation Services (for Web Application Proxy)

## Installation

### 1. Download the Solution
```powershell
# Clone or download the solution to your server
git clone <repository-url> C:\RemoteAccessServices
```

### 2. Verify Prerequisites
```powershell
# Import the core module
Import-Module .\Modules\RemoteAccess-Core.psm1

# Check prerequisites
Test-RemoteAccessPrerequisites
```

### 3. Initialize the Solution
```powershell
# Set execution policy if needed
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Import all modules
Import-Module .\Modules\RemoteAccess-Core.psm1
Import-Module .\Modules\RemoteAccess-DirectAccess.psm1
Import-Module .\Modules\RemoteAccess-VPN.psm1
Import-Module .\Modules\RemoteAccess-WebApplicationProxy.psm1
Import-Module .\Modules\RemoteAccess-NPS.psm1
Import-Module .\Modules\RemoteAccess-Monitoring.psm1
Import-Module .\Modules\RemoteAccess-Security.psm1
```

## Quick Start

### Deploy All Remote Access Services
```powershell
# Deploy all services with automatic startup
.\Scripts\Deploy-RemoteAccessServices.ps1 -DeploymentType "All" -StartServices -SetAutoStart -ConfirmDeployment
```

### Deploy Specific Service
```powershell
# Deploy VPN server only
.\Scripts\Deploy-RemoteAccessServices.ps1 -DeploymentType "VPN" -StartServices -SetAutoStart -ConfirmDeployment
```

### Check Service Status
```powershell
# Get overall status
Get-RemoteAccessServiceStatus

# Get health status
Test-RemoteAccessHealth
```

## Core Modules

### RemoteAccess-Core.psm1
Core utilities and prerequisite checks.

**Key Functions:**
- `Test-RemoteAccessPrerequisites` - Check system prerequisites
- `Get-RemoteAccessServiceStatus` - Get service status
- `Test-RemoteAccessHealth` - Test overall health
- `Get-RemoteAccessFeatures` - Get installed features

### RemoteAccess-DirectAccess.psm1
DirectAccess configuration and management.

**Key Functions:**
- `Install-DirectAccess` - Install DirectAccess
- `New-DirectAccessConfiguration` - Create configuration
- `Get-DirectAccessStatus` - Get status information
- `Test-DirectAccessConnectivity` - Test connectivity

### RemoteAccess-VPN.psm1
VPN server configuration and client management.

**Key Functions:**
- `Install-VPNServer` - Install VPN server
- `New-VPNConfiguration` - Create VPN configuration
- `Get-VPNStatus` - Get VPN status
- `Test-VPNConnectivity` - Test connectivity

### RemoteAccess-WebApplicationProxy.psm1
Web Application Proxy management.

**Key Functions:**
- `Install-WebApplicationProxy` - Install WAP
- `New-WAPApplication` - Publish application
- `Get-WAPStatus` - Get WAP status
- `Set-WAPCertificate` - Set SSL certificate

### RemoteAccess-NPS.psm1
Network Policy Server automation.

**Key Functions:**
- `Install-NPSServer` - Install NPS
- `New-NPSNetworkPolicy` - Create network policy
- `New-NPSRADIUSClient` - Create RADIUS client
- `Get-NPSStatus` - Get NPS status

### RemoteAccess-Monitoring.psm1
Comprehensive monitoring and diagnostics.

**Key Functions:**
- `Get-RemoteAccessMonitoringStatus` - Get monitoring status
- `Start-RemoteAccessMonitoring` - Start continuous monitoring
- `Test-RemoteAccessPerformance` - Test performance
- `Get-RemoteAccessReport` - Generate reports

### RemoteAccess-Security.psm1
Security and compliance management.

**Key Functions:**
- `Get-RemoteAccessSecurityStatus` - Get security status
- `Set-RemoteAccessSecurityPolicy` - Set security policies
- `Test-RemoteAccessCompliance` - Test compliance
- `Start-RemoteAccessSecurityMonitoring` - Start security monitoring

## Deployment Guide

### Automated Deployment
```powershell
# Deploy all services
.\Scripts\Deploy-RemoteAccessServices.ps1 -DeploymentType "All" -StartServices -SetAutoStart -ConfirmDeployment

# Deploy with custom log path
.\Scripts\Deploy-RemoteAccessServices.ps1 -DeploymentType "All" -StartServices -SetAutoStart -LogPath "C:\Logs\Deployment.log" -ConfirmDeployment
```

### Manual Deployment
```powershell
# Install DirectAccess
Install-DirectAccess -StartService -SetAutoStart

# Install VPN server
Install-VPNServer -StartService -SetAutoStart

# Install Web Application Proxy
Install-WebApplicationProxy -StartService -SetAutoStart

# Install Network Policy Server
Install-NPSServer -StartService -SetAutoStart
```

## Configuration Guide

### DirectAccess Configuration
```powershell
# Create DirectAccess configuration
New-DirectAccessConfiguration -ClientGroupName "DirectAccess Clients" -InternalInterface "Internal" -ExternalInterface "External" -AuthenticationMethod "Computer" -EncryptionLevel "High"

# Get DirectAccess status
Get-DirectAccessStatus
```

### VPN Configuration
```powershell
# Create VPN configuration
New-VPNConfiguration -VPNName "Corporate VPN" -VPNType "SSTP" -AuthenticationMethod "MS-CHAPv2" -EncryptionLevel "High" -IPAddressRange "192.168.100.0/24"

# Get VPN status
Get-VPNStatus
```

### Web Application Proxy Configuration
```powershell
# Publish SharePoint application
New-WAPApplication -Name "SharePoint" -ExternalUrl "https://sharepoint.contoso.com" -BackendServerUrl "https://sp.internal.contoso.com" -PreAuthenticationMethod "ADFS"

# Set SSL certificate
Set-WAPCertificate -CertificateThumbprint "1234567890ABCDEF"
```

### Network Policy Server Configuration
```powershell
# Create RADIUS client
New-NPSRADIUSClient -ClientName "VPN Server" -ClientAddress "192.168.1.100" -SharedSecret "Secret123"

# Create network policy
New-NPSNetworkPolicy -PolicyName "VPN Users" -PolicyType "Allow" -ProfileName "VPN"
```

## Monitoring Guide

### Start Continuous Monitoring
```powershell
# Start monitoring with alerts
Start-RemoteAccessMonitoring -MonitoringInterval 5 -AlertThreshold 2 -LogPath "C:\Logs\RemoteAccessMonitor.log"

# Start monitoring with email alerts
Start-RemoteAccessMonitoring -MonitoringInterval 5 -AlertThreshold 2 -EmailAlerts @("admin@contoso.com") -MonitorPerformance
```

### Generate Reports
```powershell
# Generate comprehensive report
Get-RemoteAccessReport -OutputPath "C:\Reports\RemoteAccess.html" -IncludePerformanceData -IncludeEventLogs -IncludeRecommendations

# Generate performance report
Test-RemoteAccessPerformance -TestDuration 120 -IncludeCounters @("RemoteAccess", "VPN", "NPS")
```

### Check Health Status
```powershell
# Get overall health
Test-RemoteAccessHealth

# Get monitoring status
Get-RemoteAccessMonitoringStatus
```

## Security Guide

### Security Status
```powershell
# Get security status
Get-RemoteAccessSecurityStatus

# Test compliance
Test-RemoteAccessCompliance -ComplianceStandard "NIST" -IncludeRecommendations
```

### Security Policies
```powershell
# Set security policies
Set-RemoteAccessSecurityPolicy -AuthenticationMethod "EAP-TLS" -EncryptionLevel "High" -AuditPolicy "EnableAll" -PasswordPolicy "Strong"
```

### Security Monitoring
```powershell
# Start security monitoring
Start-RemoteAccessSecurityMonitoring -MonitoringInterval 5 -AlertThreshold 1 -MonitorAuthentication -MonitorAuthorization

# Generate security report
Get-RemoteAccessSecurityReport -OutputPath "C:\Reports\Security.html" -IncludeComplianceData -IncludeSecurityEvents -IncludeRecommendations
```

## Troubleshooting Guide

### Service Issues
```powershell
# Check service status
Get-RemoteAccessServiceStatus

# Start services
Start-RemoteAccessServices

# Stop services
Stop-RemoteAccessServices
```

### Connectivity Issues
```powershell
# Test DirectAccess connectivity
Test-DirectAccessConnectivity -TestDuration 60

# Test VPN connectivity
Test-VPNConnectivity -TestType "Performance"

# Test NPS connectivity
Test-NPSConnectivity -TestDuration 60
```

### Performance Issues
```powershell
# Test performance
Test-RemoteAccessPerformance -TestDuration 120

# Get performance report
Get-RemoteAccessReport -IncludePerformanceData
```

### Health Issues
```powershell
# Test overall health
Test-RemoteAccessHealth

# Get detailed status
Get-RemoteAccessMonitoringStatus
```

## Best Practices

### Deployment
1. **Test in Lab Environment** - Always test deployments in a lab environment first
2. **Use Configuration Management** - Use configuration files for consistent deployments
3. **Document Changes** - Document all configuration changes
4. **Backup Before Changes** - Backup configurations before making changes

### Security
1. **Use Strong Authentication** - Implement multi-factor authentication
2. **Enable Encryption** - Use strong encryption protocols
3. **Regular Security Reviews** - Conduct regular security assessments
4. **Monitor Security Events** - Implement continuous security monitoring

### Monitoring
1. **Set Appropriate Thresholds** - Configure monitoring thresholds based on your environment
2. **Regular Health Checks** - Perform regular health checks
3. **Document Incidents** - Document all incidents and resolutions
4. **Review Logs Regularly** - Review logs regularly for issues

### Maintenance
1. **Regular Updates** - Keep the solution updated
2. **Performance Monitoring** - Monitor performance regularly
3. **Capacity Planning** - Plan for capacity growth
4. **Disaster Recovery** - Implement disaster recovery procedures

## Examples

### Complete Deployment Example
```powershell
# Complete deployment with monitoring
.\Scripts\Deploy-RemoteAccessServices.ps1 -DeploymentType "All" -StartServices -SetAutoStart -ConfirmDeployment

# Configure DirectAccess
New-DirectAccessConfiguration -ClientGroupName "DirectAccess Clients" -InternalInterface "Internal" -ExternalInterface "External"

# Configure VPN
New-VPNConfiguration -VPNName "Corporate VPN" -VPNType "SSTP" -AuthenticationMethod "MS-CHAPv2"

# Start monitoring
Start-RemoteAccessMonitoring -MonitoringInterval 5 -AlertThreshold 2

# Generate initial report
Get-RemoteAccessReport -OutputPath "C:\Reports\InitialReport.html" -IncludePerformanceData -IncludeRecommendations
```

### Security Configuration Example
```powershell
# Set security policies
Set-RemoteAccessSecurityPolicy -AuthenticationMethod "EAP-TLS" -EncryptionLevel "High" -AuditPolicy "EnableAll"

# Test compliance
Test-RemoteAccessCompliance -ComplianceStandard "All" -IncludeRecommendations

# Start security monitoring
Start-RemoteAccessSecurityMonitoring -MonitoringInterval 5 -MonitorAuthentication -MonitorAuthorization

# Generate security report
Get-RemoteAccessSecurityReport -OutputPath "C:\Reports\SecurityReport.html" -IncludeComplianceData -IncludeSecurityEvents
```

### Troubleshooting Example
```powershell
# Check overall health
$health = Test-RemoteAccessHealth
if ($health.OverallHealth -ne "Healthy") {
    Write-Warning "Health issues detected: $($health.Issues -join ', ')"
    
    # Check specific services
    Get-RemoteAccessServiceStatus
    
    # Test connectivity
    Test-DirectAccessConnectivity
    Test-VPNConnectivity
    
    # Generate diagnostic report
    Get-RemoteAccessReport -OutputPath "C:\Reports\DiagnosticReport.html" -IncludePerformanceData -IncludeEventLogs
}
```

## API Reference

### Core Functions
- `Test-RemoteAccessPrerequisites` - Test system prerequisites
- `Get-RemoteAccessServiceStatus` - Get service status
- `Test-RemoteAccessHealth` - Test overall health
- `Get-RemoteAccessFeatures` - Get installed features

### DirectAccess Functions
- `Install-DirectAccess` - Install DirectAccess
- `New-DirectAccessConfiguration` - Create configuration
- `Get-DirectAccessStatus` - Get status
- `Test-DirectAccessConnectivity` - Test connectivity
- `Remove-DirectAccessConfiguration` - Remove configuration

### VPN Functions
- `Install-VPNServer` - Install VPN server
- `New-VPNConfiguration` - Create configuration
- `Get-VPNStatus` - Get status
- `Test-VPNConnectivity` - Test connectivity
- `Remove-VPNConfiguration` - Remove configuration

### Web Application Proxy Functions
- `Install-WebApplicationProxy` - Install WAP
- `New-WAPApplication` - Publish application
- `Get-WAPStatus` - Get status
- `Test-WAPConnectivity` - Test connectivity
- `Set-WAPCertificate` - Set certificate
- `Remove-WAPApplication` - Remove application

### Network Policy Server Functions
- `Install-NPSServer` - Install NPS
- `New-NPSNetworkPolicy` - Create policy
- `New-NPSRADIUSClient` - Create client
- `Get-NPSStatus` - Get status
- `Test-NPSConnectivity` - Test connectivity
- `Remove-NPSConfiguration` - Remove configuration

### Monitoring Functions
- `Get-RemoteAccessMonitoringStatus` - Get monitoring status
- `Start-RemoteAccessMonitoring` - Start monitoring
- `Test-RemoteAccessPerformance` - Test performance
- `Get-RemoteAccessReport` - Generate report

### Security Functions
- `Get-RemoteAccessSecurityStatus` - Get security status
- `Set-RemoteAccessSecurityPolicy` - Set policies
- `Test-RemoteAccessCompliance` - Test compliance
- `Get-RemoteAccessSecurityReport` - Generate security report
- `Start-RemoteAccessSecurityMonitoring` - Start security monitoring

---

For more information, see the [Administrator Guide](Administrator-Guide.md) and [API Reference](API-Reference.md).
