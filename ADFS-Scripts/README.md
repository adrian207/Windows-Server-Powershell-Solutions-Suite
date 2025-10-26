# ADFS PowerShell Scripts

> Recommendation: Use this ADFS automation toolkit to deploy, secure, and operate federation services with confidence and consistency.

**Author:** Adrian Johnson (adrian207@gmail.com)  
**Version:** 1.0.0  
**Last updated:** 2025-10-26

### Why it matters
- Simplify SSO: predictable federation for SaaS, partner orgs, and Office 365.
- Strengthen security: MFA, conditional access, and certificate management built-in.
- Move faster: scripted deployments and scenario templates for common patterns.

### How it works (high-level)
- Modular PowerShell modules for core ADFS, federation, security, and troubleshooting.
- Scenario scripts for SSO, OAuth, hybrid identity, and B2B federation.
- JSON-driven configurations and examples to standardize farm rollouts.

## Overview

This solution provides modular and portable PowerShell scripts for ADFS operations that can run on any Windows Server environment. It covers the complete ADFS lifecycle from deployment to troubleshooting.

## Features

### Core Modules

- **ADFS-Core.psm1** - Core ADFS operations including farm installation, relying party trusts, and claim rules
- **ADFS-Federation.psm1** - Federation capabilities including organization federation, Office 365 integration, and multi-forest scenarios
- **ADFS-Security.psm1** - Security features including MFA integration, certificate management, conditional access, and smartcard authentication
- **ADFS-Troubleshooting.psm1** - Troubleshooting capabilities including diagnostics, monitoring, and automated issue resolution

### Script Categories

- **Deployment** - Farm deployment and initial configuration
- **Configuration** - Ongoing configuration and management
- **Security** - Security hardening and compliance
- **Troubleshooting** - Diagnostics and issue resolution
- **Enterprise-Scenarios** - Advanced enterprise use cases

## Prerequisites

- Windows Server 2016 or later
- PowerShell 5.1 or later
- Administrator privileges
- Domain membership
- ADFS Windows features

## Quick Start

1. **Deploy ADFS Farm**
   ```powershell
   .\Scripts\Deployment\Deploy-ADFSFarm.ps1 -FederationServiceName "fs.company.com" -ServiceAccount "DOMAIN\adfs-service" -CertificateThumbprint "1234567890ABCDEF"
   ```

2. **Create Relying Party Trust**
   ```powershell
   Import-Module .\Modules\ADFS-Core.psm1
   New-ADFSRelyingPartyTrust -Name "Salesforce" -Identifier "https://salesforce.com" -MetadataUrl "https://salesforce.com/federationmetadata"
   ```

3. **Configure MFA Integration**
   ```powershell
   Import-Module .\Modules\ADFS-Security.psm1
   Set-ADFSMFAIntegration -MFAProvider "AzureMFA" -EnableConditionalMFA -EnablePerAppMFA
   ```

## Module Functions

### ADFS-Core Module

- `Install-ADFSFarm` - Install and configure ADFS farm
- `New-ADFSRelyingPartyTrust` - Create relying party trust
- `Set-ADFSClaimRule` - Configure claim rules
- `Get-ADFSStatus` - Get ADFS service status
- `Test-ADFSConnectivity` - Test ADFS connectivity

### ADFS-Federation Module

- `New-ADFSOrganizationFederation` - Create organization federation
- `Set-ADFSOffice365Federation` - Configure Office 365 federation
- `New-ADFSMultiForestFederation` - Create multi-forest federation
- `Set-ADFSB2BFederation` - Configure B2B federation
- `Get-ADFSFederationStatus` - Get federation status
- `Test-ADFSFederationConnectivity` - Test federation connectivity

### ADFS-Security Module

- `Set-ADFSMFAIntegration` - Configure MFA integration
- `Set-ADFSCertificateManagement` - Configure certificate management
- `Set-ADFSConditionalAccess` - Configure conditional access policies
- `Set-ADFSSmartcardAuthentication` - Configure smartcard authentication
- `Get-ADFSSecurityStatus` - Get security status
- `Test-ADFSSecurityConnectivity` - Test security functionality

### ADFS-Troubleshooting Module

- `Get-ADFSDiagnostics` - Perform comprehensive diagnostics
- `Test-ADFSConnectivity` - Test connectivity and functionality
- `Get-ADFSEventLogs` - Retrieve and analyze event logs
- `Repair-ADFSIssues` - Automatically repair common issues
- `Get-ADFSPerformanceMetrics` - Retrieve performance metrics
- `Get-ADFSTroubleshootingStatus` - Get troubleshooting status

## Enterprise Scenarios

The solution supports 30+ enterprise scenarios including:

1. **Single Sign-On (SSO) for External Web Applications**
2. **Federation Between Organizations**
3. **Office 365 / Microsoft 365 Federation**
4. **Multi-Factor Authentication Integration**
5. **Smartcard / Certificate-Based Authentication**
6. **Claims-Based Access Control**
7. **Single Sign-On for Legacy On-Prem Apps**
8. **ADFS + Web Application Proxy (WAP) Perimeter Access**
9. **OAuth2 / OpenID Connect Enablement**
10. **Custom Branding and Home Realm Discovery**
11. **Federation with Azure AD (Hybrid Identity)**
12. **B2B and Partner Federation**
13. **ADFS as OAuth Authorization Server for APIs**
14. **Conditional Access and Location-Based Rules**
15. **Integration with Citrix or VMware Horizon**
16. **Multi-Forest or Multi-Domain Federation**
17. **Service Provider Federation (SaaS Hub Model)**
18. **Consumer-Facing Web Portals**
19. **Integration with Microsoft Entra Conditional Access**
20. **Passwordless or Passkey Authentication Pilot**
21. **ADFS as an Identity Broker (Token Translation)**
22. **Relying Party Access Auditing**
23. **Smart Access via Device Registration (DRS)**
24. **Failover and Geo-Redundancy**
25. **Disaster Recovery Federation Service**
26. **Auditable Access for Compliance**
27. **Application Proxy Authentication**
28. **ADFS and Conditional MFA by Application**
29. **Migration Path to Entra ID (Azure AD)**
30. **Integration with Custom Line-of-Business Apps**

## Security Features

- **Multi-Factor Authentication (MFA)** - Support for Azure MFA, Duo, RSA, and custom providers
- **Certificate Management** - SSL, token signing, and encryption certificate management
- **Conditional Access** - Location-based, device-based, risk-based, and time-based access controls
- **Smartcard Authentication** - PKI integration and certificate-based authentication
- **Audit Logging** - Comprehensive audit logging and SIEM integration
- **Compliance** - Support for SOX, HIPAA, GDPR, PCI, and CCPA compliance

## Troubleshooting Features

- **Comprehensive Diagnostics** - Service status, configuration, and connectivity tests
- **Event Log Analysis** - Automated event log analysis with recommendations
- **Performance Monitoring** - Real-time performance metrics and trend analysis
- **Automated Repair** - Automatic detection and repair of common issues
- **Connectivity Testing** - Internal and external access testing
- **Certificate Validation** - Certificate health monitoring and validation

## Configuration Management

- **JSON Configuration** - Centralized configuration management
- **Template-Based Deployment** - Reusable deployment templates
- **Environment-Specific Configs** - Support for multiple environments
- **Version Control** - Git-based version control and change tracking

## Monitoring and Alerting

- **Performance Counters** - CPU, memory, disk, and network monitoring
- **Event Log Monitoring** - Automated event log monitoring and alerting
- **Certificate Monitoring** - Certificate expiration and health monitoring
- **Trust Monitoring** - Trust health and connectivity monitoring
- **SIEM Integration** - Integration with security information and event management systems

## Backup and Recovery

- **Configuration Backup** - Automated configuration backup before changes
- **Disaster Recovery** - Disaster recovery procedures and documentation
- **High Availability** - Support for high availability and failover scenarios
- **Geo-Redundancy** - Multi-site deployment and redundancy

## Examples

### Basic ADFS Farm Deployment

```powershell
# Deploy ADFS farm
Install-ADFSFarm -FederationServiceName "fs.company.com" -ServiceAccount "DOMAIN\adfs-service" -CertificateThumbprint "1234567890ABCDEF"

# Create relying party trust
New-ADFSRelyingPartyTrust -Name "Salesforce" -Identifier "https://salesforce.com" -MetadataUrl "https://salesforce.com/federationmetadata"

# Configure claim rules
Set-ADFSClaimRule -TrustName "Salesforce" -RuleName "Email Claim" -RuleType "PassThrough" -ClaimType "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
```

### Office 365 Federation

```powershell
# Configure Office 365 federation
Set-ADFSOffice365Federation -TenantDomain "company.onmicrosoft.com" -EnableHybridIdentity -EnablePasswordSync -EnableSeamlessSSO -EnableConditionalAccess

# Configure MFA integration
Set-ADFSMFAIntegration -MFAProvider "AzureMFA" -EnableConditionalMFA -EnablePerAppMFA -EnableLocationBasedMFA
```

### Organization Federation

```powershell
# Create organization federation
New-ADFSOrganizationFederation -PartnerOrganization "PartnerCorp" -PartnerDomain "partner.com" -PartnerMetadataUrl "https://fs.partner.com/federationmetadata/2007-06/federationmetadata.xml" -FederationProtocol "SAML" -EnableMutualTrust -EnableClaimsMapping
```

### Troubleshooting

```powershell
# Perform comprehensive diagnostics
Get-ADFSDiagnostics -IncludePerformanceCounters -IncludeEventLogs -IncludeCertificateValidation -IncludeTrustValidation

# Test connectivity
Test-ADFSConnectivity -TestInternalAccess -TestExternalAccess -TestTrustConnectivity -TestPerformance

# Get event logs
Get-ADFSEventLogs -LogSource "ADFS" -EventLevel "Error" -TimeRange "Last24Hours" -IncludeAnalysis

# Repair issues
Repair-ADFSIssues -RepairServiceIssues -RepairConfigurationIssues -RepairCertificateIssues -RepairTrustIssues -EnableBackup
```

## Best Practices

1. **Security**
   - Enable MFA for all external access
   - Use strong certificates with proper key sizes
   - Implement conditional access policies
   - Enable comprehensive audit logging

2. **Performance**
   - Monitor performance counters regularly
   - Implement proper load balancing
   - Use appropriate hardware sizing
   - Monitor certificate expiration

3. **Reliability**
   - Deploy multiple ADFS servers for high availability
   - Implement proper backup procedures
   - Test disaster recovery procedures
   - Monitor service health continuously

4. **Compliance**
   - Enable audit logging for compliance requirements
   - Implement data retention policies
   - Regular security assessments
   - Document all configurations

## Support

For issues, questions, or contributions, please refer to the project documentation or contact the development team.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Version History

- **v1.0.0** - Initial release with core ADFS functionality
  - Core ADFS operations
  - Federation capabilities
  - Security features
  - Troubleshooting tools
  - Enterprise scenarios support
