# Network Policy and Access Services (NPAS) PowerShell Scripts

**Author:** Adrian Johnson (adrian207@gmail.com)

## Overview

This comprehensive PowerShell solution provides enterprise-grade management capabilities for Network Policy and Access Services (NPAS) on Windows Server. The solution includes deployment, configuration, security, monitoring, troubleshooting, and enterprise scenario management for all 30 NPAS use cases.

## Features

### 🔧 **Core Functionality**
- **Complete NPAS Deployment**: Automated installation and configuration
- **Policy Management**: Create, modify, and manage network policies
- **Client Management**: Configure RADIUS clients and authentication
- **Certificate Management**: Handle certificate-based authentication
- **VLAN Assignment**: Dynamic VLAN assignment based on user groups
- **Load Balancing**: Multi-server deployments with failover

### 🔒 **Security Features**
- **Multi-Factor Authentication**: Azure MFA, Duo, Okta integration
- **Certificate-Based Authentication**: EAP-TLS, PEAP-MS-CHAPv2
- **Conditional Access**: Risk-based and device compliance policies
- **Zero Trust Security**: Never trust, always verify model
- **Encryption**: AES-256, TLS-1.2, TLS-1.3 support
- **Auditing**: Comprehensive logging and compliance reporting

### 📊 **Monitoring & Alerting**
- **Real-Time Monitoring**: Health, performance, and security metrics
- **Comprehensive Alerting**: Email, SMS, webhook notifications
- **Performance Analytics**: Response time, throughput, error rates
- **Compliance Monitoring**: NIST, ISO-27001, SOX, HIPAA, PCI-DSS
- **Dashboard Integration**: Real-time status and metrics

### 🔍 **Troubleshooting & Diagnostics**
- **Automated Diagnostics**: Comprehensive health checks
- **Issue Resolution**: Automated repair and optimization
- **Event Log Analysis**: Security and system event analysis
- **Performance Analysis**: Bottleneck identification and optimization
- **Configuration Validation**: Policy and client validation

## Directory Structure

```
NPAS-Scripts/
├── Modules/
│   ├── NPAS-Core.psm1              # Core NPAS functionality
│   ├── NPAS-Security.psm1          # Security and compliance features
│   ├── NPAS-Monitoring.psm1        # Monitoring and alerting
│   └── NPAS-Troubleshooting.psm1   # Diagnostics and repair
├── Scripts/
│   ├── Deployment/
│   │   └── Deploy-NPASServer.ps1   # Main deployment script
│   ├── Configuration/
│   │   └── Configure-NPAS.ps1       # Configuration management
│   ├── Security/
│   │   └── Secure-NPAS.ps1          # Security implementation
│   ├── Monitoring/
│   │   └── Monitor-NPAS.ps1         # Monitoring and alerting
│   ├── Troubleshooting/
│   │   └── Troubleshoot-NPAS.ps1    # Troubleshooting tools
│   └── Enterprise-Scenarios/
│       └── Deploy-NPASScenarios.ps1 # Enterprise scenario deployment
├── Examples/
│   └── NPAS-Examples.ps1            # Usage examples and demonstrations
├── Tests/
│   └── Test-NPAS.ps1                # Comprehensive test suite
├── Documentation/
│   └── NPAS-Documentation.md        # Complete documentation
└── README.md                        # This file
```

## Quick Start

### Prerequisites
- Windows Server 2016 or later
- PowerShell 5.1 or later
- Administrator privileges
- Network Policy and Access Services role

### Installation

1. **Clone or download the NPAS-Scripts directory**
2. **Run the main deployment script**:
   ```powershell
   .\Scripts\Deployment\Deploy-NPASServer.ps1 -ServerName "NPAS-SERVER01" -InstallFeatures -ConfigureSecurity -ConfigureMonitoring
   ```

### Basic Usage

```powershell
# Import modules
Import-Module ".\Modules\NPAS-Core.psm1" -Force
Import-Module ".\Modules\NPAS-Security.psm1" -Force
Import-Module ".\Modules\NPAS-Monitoring.psm1" -Force
Import-Module ".\Modules\NPAS-Troubleshooting.psm1" -Force

# Install NPAS roles
Install-NPASRoles -ServerName "NPAS-SERVER01"

# Configure NPAS server
Configure-NPASServer -ServerName "NPAS-SERVER01" -LogPath "C:\NPAS\Logs"

# Create a policy
New-NPASPolicy -PolicyName "Wireless Access" -PolicyType "Access" -Conditions @("User-Groups", "Wireless-Users")

# Test connectivity
Test-NPASConnectivity -ServerName "NPAS-SERVER01"

# Get server status
Get-NPASStatus -ServerName "NPAS-SERVER01"
```

## Enterprise Scenarios Supported

### 🔐 **Authentication & Authorization**
1. **RADIUS Authentication for Network Devices** - Centralized authentication for switches, wireless controllers, VPN concentrators
2. **802.1X Wired and Wireless Authentication** - Enterprise network security baseline
3. **VPN Authentication and Authorization** - Policy-based remote access control
4. **Certificate-Based Network Authentication** - Passwordless, phishing-resistant access
5. **Cross-Forest Authentication** - Unified access control in multi-domain environments

### 🌐 **Network Access Control**
6. **Wi-Fi with Microsoft Entra ID** - Cloud-connected enterprise authentication
7. **Guest or Contractor VLAN Assignment** - Automatic network segmentation
8. **Conditional Network Access** - Contextual, rule-driven access decisions
9. **Wireless Authentication with Dynamic VLANs** - Identity-based network segmentation
10. **Integration with DHCP Enforcement** - Combined network access and IP allocation

### 🏥 **Health & Compliance**
11. **Network Access Protection (NAP)** - Health-based network admission
12. **Integration with Device Health Attestation** - Secure Boot, BitLocker, TPM validation
13. **Multi-Factor Authentication for VPNs** - Enhanced security for remote access
14. **Wi-Fi Authentication for BYOD** - Safe personal device enablement
15. **Compliance-Driven Access Control** - NIST, ISO 27001-aligned networks

### 🔄 **High Availability & Scalability**
16. **RADIUS Proxy and Multi-Site Redundancy** - Centralized authentication routing
17. **Load-Balanced RADIUS Infrastructure** - High throughput and redundancy
18. **Wired Port Authentication in Branch Offices** - Lightweight branch security
19. **PowerShell Policy Automation** - Infrastructure-as-code for network policy
20. **Role-Based Access for IT Staff** - Tiered admin access to network devices

### 🔗 **Integration & Federation**
21. **Integration with AD Groups and OU Filters** - Contextual policies using directory data
22. **Wireless Access in Educational Campuses** - Scalable student and faculty access
23. **Remote Desktop Gateway Integration** - RADIUS-based RDP session policies
24. **IoT Device Onboarding** - Secure headless device connection
25. **VPN Split-Tunnel Enforcement** - Policy-based routing control

### ☁️ **Hybrid Cloud & Modern Identity**
26. **Federated Authentication via ADFS or Azure AD** - Modern identity meets network edge
27. **Secure Guest Portal Integration** - Partner and customer access management
28. **Integration with Firewalls or NAC Appliances** - Cross-vendor interoperability
29. **TACACS+ Alternative for Windows Environments** - Unified credential auditing
30. **RADIUS Logging and Accounting** - Comprehensive audit trail and reporting

## Core Modules

### NPAS-Core.psm1
Core functionality including:
- `Install-NPASRoles` - Install NPAS roles and features
- `Configure-NPASServer` - Configure basic server settings
- `New-NPASPolicy` - Create network policies
- `Set-NPASPolicy` - Update existing policies
- `Remove-NPASPolicy` - Delete policies
- `Get-NPASPolicy` - Retrieve policy information
- `Test-NPASConnectivity` - Test server connectivity
- `Get-NPASStatus` - Get server status and statistics
- `Set-NPASLogging` - Configure logging settings
- `Get-NPASLogs` - Retrieve log information

### NPAS-Security.psm1
Security features including:
- `Set-NPASAuthentication` - Configure authentication methods
- `Set-NPASAuthorization` - Configure authorization policies
- `Set-NPASEncryption` - Configure encryption settings
- `Set-NPASAuditing` - Configure auditing and compliance
- `Set-NPASMFASettings` - Configure multi-factor authentication
- `Set-NPASCertificateSettings` - Configure certificate-based auth
- `Set-NPASGroupPolicies` - Configure group-based policies
- `Set-NPASConditionalAccess` - Configure conditional access
- `Set-NPASDeviceCompliance` - Configure device compliance
- `Set-NPASRiskAssessment` - Configure risk assessment
- `Set-NPASThreatProtection` - Configure threat protection
- `Set-NPASAccessControl` - Configure access control
- `Set-NPASSessionSecurity` - Configure session security
- `Set-NPASNetworkSecurity` - Configure network security
- `Get-NPASSecurityStatus` - Get security status
- `Test-NPASSecurityCompliance` - Test compliance
- `Get-NPASSecurityLogs` - Get security logs
- `Set-NPASSecurityAlerts` - Configure security alerts
- `Configure-NPASZeroTrust` - Configure Zero Trust model

### NPAS-Monitoring.psm1
Monitoring features including:
- `Get-NPASHealth` - Get server health status
- `Get-NPASPerformance` - Get performance metrics
- `Get-NPASStatistics` - Get statistical information
- `Set-NPASMonitoring` - Configure monitoring settings
- `Get-NPASAlerts` - Get current alerts
- `Set-NPASAlerting` - Configure alerting settings
- `Get-NPASMetrics` - Get performance metrics
- `Test-NPASConnectivity` - Test connectivity
- `Get-NPASLogs` - Get log information
- `Set-NPASLogging` - Configure logging

### NPAS-Troubleshooting.psm1
Troubleshooting features including:
- `Test-NPASDiagnostics` - Run comprehensive diagnostics
- `Repair-NPASIssues` - Automatically repair issues
- `Get-NPASEventLogs` - Analyze event logs
- `Analyze-NPASPerformance` - Analyze performance bottlenecks
- `Test-NPASConnectivity` - Test connectivity issues
- `Validate-NPASConfiguration` - Validate configuration
- `Get-NPASHealthCheck` - Perform health checks
- `Resolve-NPASConflicts` - Resolve configuration conflicts
- `Optimize-NPASPerformance` - Optimize performance
- `Backup-NPASConfiguration` - Backup configuration

## Configuration Examples

### Basic NPAS Server Setup
```powershell
# Install NPAS roles
Install-NPASRoles -ServerName "NPAS-SERVER01" -Features @("NPAS", "NPAS-Policy-Server")

# Configure basic settings
Configure-NPASServer -ServerName "NPAS-SERVER01" -LogPath "C:\NPAS\Logs" -AccountingEnabled

# Create wireless access policy
New-NPASPolicy -PolicyName "Wireless Access" -PolicyType "Access" -Conditions @("User-Groups", "Wireless-Users")
```

### Security Configuration
```powershell
# Configure authentication
Set-NPASAuthentication -ServerName "NPAS-SERVER01" -AuthenticationMethods @("EAP-TLS", "PEAP-MS-CHAPv2") -CertificateValidation

# Configure authorization
Set-NPASAuthorization -ServerName "NPAS-SERVER01" -AuthorizationMethod "RBAC" -GroupPolicies @("Network-Admins", "Wireless-Users")

# Configure encryption
Set-NPASEncryption -ServerName "NPAS-SERVER01" -EncryptionLevel "Strong" -EncryptionMethods @("AES-256", "TLS-1.2")

# Configure MFA
Set-NPASMFASettings -ServerName "NPAS-SERVER01" -MFAProvider "Azure-MFA" -MFAMethods @("SMS", "Phone", "Authenticator-App")
```

### Monitoring Configuration
```powershell
# Configure monitoring
Set-NPASMonitoring -ServerName "NPAS-SERVER01" -MonitoringLevel "Advanced" -AlertingEnabled

# Configure alerting
Set-NPASAlerting -ServerName "NPAS-SERVER01" -AlertTypes @("Authentication-Failure", "Performance-Warning") -NotificationMethods @("Email", "Webhook")

# Get health status
Get-NPASHealth -ServerName "NPAS-SERVER01"

# Get performance metrics
Get-NPASPerformance -ServerName "NPAS-SERVER01" -MetricType "All"
```

### Troubleshooting
```powershell
# Run diagnostics
Test-NPASDiagnostics -ServerName "NPAS-SERVER01" -DiagnosticType "All"

# Repair issues
Repair-NPASIssues -ServerName "NPAS-SERVER01" -RepairType "All" -Force

# Analyze performance
Analyze-NPASPerformance -ServerName "NPAS-SERVER01" -AnalysisPeriod "Last24Hours"

# Validate configuration
Validate-NPASConfiguration -ServerName "NPAS-SERVER01" -ValidationType "All"
```

## Enterprise Scenarios

### Scenario 1: RADIUS Authentication for Network Devices
```powershell
# Configure RADIUS authentication
Configure-NPASRadius -ServerName "NPAS-SERVER01"

# Add network device clients
$clients = @(
    @{ Name = "Switch-01"; IP = "192.168.1.10"; Secret = "Switch-Secret-01" },
    @{ Name = "Wireless-Controller"; IP = "192.168.1.20"; Secret = "Wireless-Secret-01" }
)

foreach ($client in $clients) {
    # Add client configuration
    Write-Host "Adding client: $($client.Name)"
}
```

### Scenario 2: 802.1X Wired and Wireless Authentication
```powershell
# Configure 802.1X authentication
Configure-NPAS8021X -ServerName "NPAS-SERVER01"

# Create 802.1X policy
New-NPASPolicy -PolicyName "802.1X Access" -PolicyType "Access" -Conditions @("User-Groups", "802.1X-Users") -Settings @{
    AuthenticationType = "EAP-TLS"
    CertificateValidation = $true
    VLANAssignment = "Dynamic"
}
```

### Scenario 3: VPN Authentication and Authorization
```powershell
# Configure VPN authentication
Configure-NPASVPN -ServerName "NPAS-SERVER01"

# Create VPN policy
New-NPASPolicy -PolicyName "VPN Access" -PolicyType "Access" -Conditions @("User-Groups", "VPN-Users") -Settings @{
    AuthenticationType = "MS-CHAPv2"
    SessionTimeout = 480
    IdleTimeout = 30
    SplitTunneling = $false
}
```

### Scenario 4: Wi-Fi with Microsoft Entra ID
```powershell
# Configure wireless authentication
Configure-NPASWireless -ServerName "NPAS-SERVER01"

# Configure Azure AD integration
Configure-NPASFederation -ServerName "NPAS-SERVER01"

# Create Azure AD policy
New-NPASPolicy -PolicyName "Azure AD Wi-Fi" -PolicyType "Access" -Conditions @("Azure-AD-Users") -Settings @{
    AuthenticationType = "EAP-TLS"
    FederationProvider = "Azure-AD"
    ConditionalAccess = $true
}
```

### Scenario 5: Certificate-Based Network Authentication
```powershell
# Configure certificate authentication
Configure-NPASCertificate -ServerName "NPAS-SERVER01"

# Configure certificate settings
Set-NPASCertificateSettings -ServerName "NPAS-SERVER01" -CertificateAuthority "AD-CS-SERVER01" -CertificateTemplates @("User-Certificate", "Machine-Certificate") -CertificateValidation

# Create certificate policy
New-NPASPolicy -PolicyName "Certificate Access" -PolicyType "Access" -Conditions @("Certificate-Users") -Settings @{
    AuthenticationType = "EAP-TLS"
    CertificateValidation = $true
    CRLChecking = $true
}
```

## Testing

Run the comprehensive test suite:

```powershell
# Run all tests
.\Tests\Test-NPAS.ps1

# Run specific test categories
.\Tests\Test-NPAS.ps1 -TestCategory "Core"
.\Tests\Test-NPAS.ps1 -TestCategory "Security"
.\Tests\Test-NPAS.ps1 -TestCategory "Monitoring"
.\Tests\Test-NPAS.ps1 -TestCategory "Troubleshooting"
```

## Documentation

- **Complete Documentation**: `Documentation\NPAS-Documentation.md`
- **Usage Examples**: `Examples\NPAS-Examples.ps1`
- **Test Suite**: `Tests\Test-NPAS.ps1`

## Requirements

- **Operating System**: Windows Server 2016 or later
- **PowerShell**: Version 5.1 or later
- **Privileges**: Administrator privileges required
- **Roles**: Network Policy and Access Services role
- **Features**: NPAS, NPAS-Policy-Server, NPAS-Health-Registration-Authority

## Support

For issues, questions, or contributions:
- Review the documentation in the `Documentation` folder
- Check the examples in the `Examples` folder
- Run the test suite to validate functionality
- Ensure all prerequisites are met

## License

This solution is provided as-is for educational and enterprise use. Ensure compliance with your organization's policies and Microsoft licensing requirements.

---

**Network Policy and Access Services (NPAS) PowerShell Scripts** - Enterprise-grade NPAS management for Windows Server environments.
