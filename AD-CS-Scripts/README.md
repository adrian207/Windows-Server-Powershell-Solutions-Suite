# Windows Active Directory Certificate Services (AD CS) Scripts

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Date:** December 2024

## Overview

This solution provides comprehensive PowerShell scripts for deploying, configuring, securing, monitoring, and troubleshooting Windows Active Directory Certificate Services (AD CS). The solution covers 35 enterprise scenarios ranging from basic PKI deployment to advanced hybrid cloud integrations.

## Table of Contents

1. [Features](#features)
2. [Scenarios Covered](#scenarios-covered)
3. [Solution Architecture](#solution-architecture)
4. [Prerequisites](#prerequisites)
5. [Installation](#installation)
6. [Usage](#usage)
7. [Modules](#modules)
8. [Scripts](#scripts)
9. [Examples](#examples)
10. [Testing](#testing)
11. [Configuration](#configuration)
12. [Security](#security)
13. [Monitoring](#monitoring)
14. [Troubleshooting](#troubleshooting)
15. [Enterprise Scenarios](#enterprise-scenarios)
16. [Best Practices](#best-practices)
17. [Support](#support)

## Features

### Core PKI Management
- **Enterprise Root and Subordinate CA Hierarchies** - Multi-tier PKI deployment
- **Smartcard and Virtual Smartcard Authentication** - Certificate-based logon
- **Machine and User Certificates via Autoenrollment** - Seamless certificate distribution
- **TLS/SSL Certificates for Internal Web Services** - Secure internal traffic
- **Code-Signing Certificates** - Application and driver signing

### Advanced Certificate Services
- **Email Encryption and Digital Signing (S/MIME)** - Secure messaging
- **VPN and Wi-Fi (EAP-TLS) Authentication** - Passwordless network access
- **Network Device Enrollment Service (NDES)** - Non-Windows device certificates
- **Simple Certificate Enrollment Protocol (SCEP)** - Mobile device provisioning
- **Domain Controller Authentication Certificates** - LDAPS and Kerberos PKINIT

### High Availability and Security
- **High Availability PKI** - Clustered and load-balanced CAs
- **Hardware Security Module (HSM) Backed Keys** - FIPS-certified hardware
- **BitLocker Recovery Key Protection** - Secure recovery workflows
- **Certificate Lifecycle Automation** - Infrastructure-as-Code
- **Cross-Forest Trust Certificates** - Cryptographic trust across forests

### Hybrid Cloud Integration
- **Azure Hybrid PKI** - AD CS + Key Vault integration
- **Hybrid Root of Trust** - On-prem and cloud CA integration
- **Integration with Host Guardian Service** - Shielded VM key release
- **Certificate-Based Authentication for APIs** - Mutual TLS for microservices

### Compliance and Governance
- **Compliance and Governance Reporting** - Audit trail and reporting
- **Revocation Auditing and SIEM Integration** - Real-time misuse detection
- **Template Security and Role Separation** - Least privilege enforcement
- **Key Archival and Recovery** - Secure key recovery workflows

## Scenarios Covered

### 1. Enterprise Root and Subordinate CA Hierarchies
**Scenario**: Standard multi-tier PKI deployment with offline root CA issuing to online subordinates.
**Why**: Separation of trust and operations; root stays cold and safe, subordinates handle daily issuance.

### 2. Smartcard and Virtual Smartcard Authentication
**Scenario**: Certificate-based logon replacing passwords with certificates mapped to user accounts in AD.
**Why**: Strong MFA rooted in hardware; essential for privileged accounts and compliance zones.

### 3. Machine and User Certificates via Autoenrollment
**Scenario**: Seamless certificate distribution via GPO triggers and AD CS autoenrollment.
**Why**: Zero-touch lifecycle management for thousands of devices.

### 4. TLS/SSL Certificates for Internal Web Services
**Scenario**: Secure internal traffic for IIS, LDAP over SSL, WinRM, and RDP.
**Why**: Encrypts east-west data flows, enables service authentication.

### 5. Code-Signing Certificates
**Scenario**: Sign PowerShell, drivers, or application binaries.
**Why**: Guarantees origin and integrity, protects against tampering.

### 6. Email Encryption and Digital Signing (S/MIME)
**Scenario**: Issue user certificates for Outlook or mobile mail.
**Why**: Confidential and authenticated messaging inside the enterprise.

### 7. VPN and Wi-Fi (EAP-TLS) Authentication
**Scenario**: NPS validates client certificates for network access.
**Why**: Passwordless network access; integrates cleanly with NPAS and Intune.

### 8. Network Device Enrollment Service (NDES)
**Scenario**: Non-Windows devices (routers, mobile, IoT) request certificates.
**Why**: Scales PKI beyond Windows domain membership.

### 9. Simple Certificate Enrollment Protocol (SCEP) via Intune
**Scenario**: Mobile and remote device certificate provisioning.
**Why**: Enables secure device identity in MDM and BYOD contexts.

### 10. Domain Controller Authentication Certificates
**Scenario**: LDAPS and Kerberos PKINIT support for domain controllers.
**Why**: Strengthens authentication and encryption for DC traffic.

### 11. Web Enrollment Services
**Scenario**: Manual or external certificate requests through a web portal.
**Why**: Enables issuance where autoenrollment isn't possible.

### 12. OCSP Responders and CRL Distribution Points
**Scenario**: Real-time certificate revocation checks.
**Why**: Keeps authentication decisions current and trustworthy.

### 13. High Availability PKI
**Scenario**: Clustered or load-balanced issuing CAs with DFS or shared storage.
**Why**: Zero downtime for critical issuance services.

### 14. Integration with Keyfactor/Venafi/EJBCA
**Scenario**: Centralized certificate governance and lifecycle management.
**Why**: Enterprise lifecycle tracking, policy enforcement, and reporting.

### 15. Hardware Security Module (HSM) Backed Keys
**Scenario**: Store CA private keys in FIPS-certified hardware.
**Why**: Prevents key exfiltration; mandatory for regulated industries.

### 16. BitLocker Recovery Key Protection
**Scenario**: Store recovery keys in AD DS protected by PKI.
**Why**: Secure recovery workflows with audit trail.

### 17. Workplace Join and Device Registration Certificates
**Scenario**: Issue device identity certificates for Entra hybrid join.
**Why**: Supports Conditional Access and DHA verification.

### 18. Certificate Lifecycle Automation via PowerShell
**Scenario**: Automated template creation, issuance, and renewal.
**Why**: Infrastructure-as-Code for PKI.

### 19. Cross-Forest Trust Certificates
**Scenario**: Secure Kerberos or ADFS federation between forests.
**Why**: Establishes cryptographic trust across identity boundaries.

### 20. RDP and WinRM Authentication
**Scenario**: Replace self-signed host certificates with CA-issued ones.
**Why**: Eliminates certificate warnings and MITM risk.

### 21. Secure Email Gateway Integration
**Scenario**: Use S/MIME certificates in boundary mail servers.
**Why**: End-to-end trust for external correspondence.

### 22. IoT/Embedded Device Identity
**Scenario**: Unique certificates per device for TLS and MQTT.
**Why**: Strong, scalable machine identity model.

### 23. Offline Enrollment for Air-Gapped Systems
**Scenario**: Export CSR from isolated system, sign offline.
**Why**: PKI for disconnected networks (defense, lab, manufacturing).

### 24. Template Security and Role Separation
**Scenario**: Delegate enrollment and approval rights.
**Why**: Enforces least privilege within CA operations.

### 25. CRL and AIA Publication Automation
**Scenario**: Scheduled publishing to web shares or HTTP endpoints.
**Why**: Keeps revocation infrastructure current and auditable.

### 26. Key Archival and Recovery
**Scenario**: Store encrypted copies of user keys in CA database.
**Why**: Enables recovery for lost certificates while maintaining confidentiality.

### 27. Integration with Windows Hello for Business
**Scenario**: Issue user and device certificates for key-based sign-in.
**Why**: Passwordless authentication with PKI assurance.

### 28. Azure Hybrid PKI (AD CS + Key Vault)
**Scenario**: Extend trust to cloud apps via Azure Key Vault or Managed HSM.
**Why**: Bridges on-prem PKI with SaaS ecosystems.

### 29. Time-Stamped Signing
**Scenario**: Pair with Windows Timestamping Service for long-term signature validity.
**Why**: Maintains trust after certificates expire.

### 30. Revocation Auditing and SIEM Integration
**Scenario**: Push CA and OCSP logs to Sentinel or Splunk.
**Why**: Real-time certificate misuse detection.

### 31. Certificate-Based Authentication for APIs or Containers
**Scenario**: Mutual TLS between microservices or container workloads.
**Why**: Identity and encryption at machine scale.

### 32. Hybrid Root of Trust
**Scenario**: Combine AD CS root with cloud CA subordinate.
**Why**: Consistent identity across on-prem and cloud workloads.

### 33. Compliance and Governance Reporting
**Scenario**: Export CA event logs, issuance counts, and expiration data.
**Why**: Proof of control for ISO 27001, PCI-DSS, or HIPAA audits.

### 34. Cross-Certification and Bridge CAs
**Scenario**: Interconnect independent PKI hierarchies.
**Why**: Enables federation without root substitution.

### 35. Integration with Host Guardian Service
**Scenario**: Shielded VM key release validation certificates.
**Why**: Cryptographic attestation chain between virtualization and PKI.

## Solution Architecture

The AD CS Scripts solution is built with a modular architecture:

```
AD-CS-Scripts/
├── Modules/                    # PowerShell modules
│   ├── ADCS-Core.psm1         # Core AD CS functions
│   ├── ADCS-Security.psm1     # Security functions
│   ├── ADCS-Monitoring.psm1  # Monitoring functions
│   └── ADCS-Troubleshooting.psm1 # Troubleshooting functions
├── Scripts/                   # Deployment and management scripts
│   ├── Deployment/            # Deployment scripts
│   ├── Configuration/        # Configuration scripts
│   ├── Security/             # Security scripts
│   ├── Monitoring/           # Monitoring scripts
│   ├── Troubleshooting/      # Troubleshooting scripts
│   └── Enterprise-Scenarios/ # Enterprise scenario scripts
├── Examples/                 # Example scripts
├── Tests/                    # Test scripts
├── Documentation/           # Documentation
└── Configuration/           # Configuration templates
```

## Prerequisites

### System Requirements
- **Operating System**: Windows Server 2016 or later
- **AD CS Feature**: Active Directory Certificate Services feature
- **PowerShell**: PowerShell 5.1 or later
- **Administrative Privileges**: Domain Administrator or Enterprise Administrator
- **Network Connectivity**: Network connectivity to domain controllers
- **Storage**: Sufficient storage for CA database and logs
- **Memory**: Minimum 4GB RAM (8GB recommended)
- **CPU**: 64-bit processor

### Software Requirements
- **Windows Server**: Windows Server 2016 or later
- **Active Directory**: Active Directory Domain Services
- **PowerShell**: PowerShell 5.1 or later
- **Windows Management Framework**: WMF 5.1 or later
- **.NET Framework**: .NET Framework 4.7 or later
- **Windows Update**: Latest updates installed

### Hardware Requirements
- **CPU**: 64-bit processor
- **Memory**: Minimum 4GB RAM (8GB recommended)
- **Storage**: Minimum 100GB free space
- **Network**: Network adapter
- **HSM**: Hardware Security Module (optional, for high security)

## Installation

### Installation Steps

1. **Download**: Download the solution files
2. **Extract**: Extract the files to a directory
3. **Prerequisites**: Install prerequisites
4. **Modules**: Import the modules
5. **Configuration**: Configure the solution
6. **Validation**: Validate the installation
7. **Testing**: Run the test suite
8. **Documentation**: Review the documentation

### Installation Commands

```powershell
# Import modules
Import-Module .\Modules\ADCS-Core.psm1
Import-Module .\Modules\ADCS-Security.psm1
Import-Module .\Modules\ADCS-Monitoring.psm1
Import-Module .\Modules\ADCS-Troubleshooting.psm1

# Run deployment
.\Scripts\Deployment\Deploy-ADCSServer.ps1 -ServerName "CA-SERVER01"

# Run tests
.\Tests\Test-ADCS.ps1 -TestType "All" -ServerName "CA-SERVER01"
```

## Usage

### Basic Usage

```powershell
# Deploy AD CS server
.\Scripts\Deployment\Deploy-ADCSServer.ps1 -ServerName "CA-SERVER01"

# Configure AD CS
.\Scripts\Configuration\Configure-ADCS.ps1 -ServerName "CA-SERVER01"

# Secure AD CS
.\Scripts\Security\Secure-ADCS.ps1 -ServerName "CA-SERVER01"

# Monitor AD CS
.\Scripts\Monitoring\Monitor-ADCS.ps1 -ServerName "CA-SERVER01"

# Troubleshoot AD CS
.\Scripts\Troubleshooting\Troubleshoot-ADCS.ps1 -ServerName "CA-SERVER01"
```

### Advanced Usage

```powershell
# Enterprise deployment
.\Scripts\Enterprise-Scenarios\Deploy-ADCSEnterpriseScenarios.ps1 -Scenario "EnterpriseRootCA" -ServerName "CA-SERVER01"

# Run examples
.\Examples\ADCS-Examples.ps1 -Scenario "SmartcardAuthentication" -ServerName "CA-SERVER01"

# Run tests
.\Tests\Test-ADCS.ps1 -TestType "Comprehensive" -ServerName "CA-SERVER01" -IncludePerformance -IncludeSecurity -IncludeMonitoring -IncludeTroubleshooting -GenerateReport
```

## Modules

### ADCS-Core.psm1
Core AD CS management functions:
- **CA Management**: Create, configure, and manage certificate authorities
- **Certificate Templates**: Manage certificate templates
- **Certificate Enrollment**: Handle certificate enrollment
- **Certificate Revocation**: Manage certificate revocation
- **OCSP Configuration**: Configure Online Certificate Status Protocol
- **CRL Management**: Manage Certificate Revocation Lists
- **Web Enrollment**: Configure web enrollment services
- **NDES Configuration**: Configure Network Device Enrollment Service

### ADCS-Security.psm1
Security management functions:
- **Security Baselines**: Apply security configurations
- **HSM Integration**: Hardware Security Module integration
- **Template Security**: Secure certificate templates
- **Role Separation**: Implement role-based access control
- **Audit Configuration**: Configure audit logging
- **Compliance**: Ensure compliance with standards
- **Key Management**: Secure key management
- **Certificate Policies**: Implement certificate policies

### ADCS-Monitoring.psm1
Monitoring functions:
- **Health Monitoring**: Monitor CA health
- **Performance Monitoring**: Track performance metrics
- **Event Monitoring**: Monitor event logs
- **Certificate Monitoring**: Monitor certificate lifecycle
- **Alerting**: Configure alerts and notifications
- **Reporting**: Generate monitoring reports
- **SIEM Integration**: Integrate with SIEM systems
- **Compliance Monitoring**: Monitor compliance status

### ADCS-Troubleshooting.psm1
Troubleshooting functions:
- **Health Diagnostics**: Comprehensive health checks
- **Event Analysis**: Analyze event logs
- **Performance Analysis**: Identify performance issues
- **Certificate Diagnostics**: Diagnose certificate issues
- **CA Diagnostics**: Diagnose CA issues
- **Network Diagnostics**: Diagnose network issues
- **Repair Operations**: Automated repair operations
- **Recovery Procedures**: Recovery procedures

## Scripts

### Deployment Scripts
- **Deploy-ADCSServer.ps1**: Main deployment script
- **Deploy-ADCSEnterpriseScenarios.ps1**: Enterprise scenarios

### Configuration Scripts
- **Configure-ADCS.ps1**: Configuration management
- **Configure-CertificateTemplates.ps1**: Template configuration
- **Configure-OCSP.ps1**: OCSP configuration
- **Configure-WebEnrollment.ps1**: Web enrollment configuration

### Security Scripts
- **Secure-ADCS.ps1**: Security configuration
- **Secure-CertificateTemplates.ps1**: Template security
- **Secure-HSM.ps1**: HSM configuration
- **Secure-RoleSeparation.ps1**: Role separation

### Monitoring Scripts
- **Monitor-ADCS.ps1**: Monitoring configuration
- **Monitor-CertificateLifecycle.ps1**: Certificate monitoring
- **Monitor-Performance.ps1**: Performance monitoring
- **Monitor-Compliance.ps1**: Compliance monitoring

### Troubleshooting Scripts
- **Troubleshoot-ADCS.ps1**: Troubleshooting and diagnostics
- **Troubleshoot-Certificates.ps1**: Certificate troubleshooting
- **Troubleshoot-CA.ps1**: CA troubleshooting
- **Troubleshoot-Enrollment.ps1**: Enrollment troubleshooting

## Examples

### ADCS-Examples.ps1
Comprehensive examples covering all 35 scenarios:
- **Enterprise Root CA**: Multi-tier PKI deployment
- **Smartcard Authentication**: Certificate-based logon
- **Autoenrollment**: Seamless certificate distribution
- **TLS/SSL Certificates**: Internal web services
- **Code-Signing**: Application signing
- **S/MIME**: Email encryption and signing
- **EAP-TLS**: VPN and Wi-Fi authentication
- **NDES**: Network device enrollment
- **SCEP**: Mobile device provisioning
- **DC Certificates**: Domain controller authentication
- **Web Enrollment**: Manual certificate requests
- **OCSP/CRL**: Revocation services
- **High Availability**: Clustered CAs
- **Third-Party Integration**: Keyfactor/Venafi/EJBCA
- **HSM**: Hardware security modules
- **BitLocker**: Recovery key protection
- **Device Registration**: Workplace join certificates
- **Lifecycle Automation**: PowerShell automation
- **Cross-Forest**: Trust certificates
- **RDP/WinRM**: Authentication certificates
- **Email Gateway**: S/MIME integration
- **IoT Devices**: Device identity certificates
- **Offline Enrollment**: Air-gapped systems
- **Template Security**: Role separation
- **CRL/AIA**: Publication automation
- **Key Archival**: Recovery workflows
- **Windows Hello**: Business integration
- **Azure Hybrid**: Key Vault integration
- **Time-Stamping**: Signature validity
- **SIEM Integration**: Audit logging
- **API Authentication**: Mutual TLS
- **Hybrid Root**: Cloud CA integration
- **Compliance**: Governance reporting
- **Cross-Certification**: Bridge CAs
- **HGS Integration**: Shielded VM certificates

## Testing

### Test-ADCS.ps1
Comprehensive test suite:
- **Module Testing**: Test all modules
- **Function Testing**: Test all functions
- **Scenario Testing**: Test all scenarios
- **Performance Testing**: Test performance
- **Security Testing**: Test security
- **Monitoring Testing**: Test monitoring
- **Troubleshooting Testing**: Test troubleshooting
- **Integration Testing**: Test integrations

## Configuration

### Configuration Templates
- **ADCS-Configuration-Template.json**: Main configuration
- **Security-Configuration-Template.json**: Security configuration
- **Monitoring-Configuration-Template.json**: Monitoring configuration
- **Troubleshooting-Configuration-Template.json**: Troubleshooting configuration

## Security

### Security Features
- **HSM Integration**: Hardware security modules
- **Template Security**: Secure certificate templates
- **Role Separation**: Role-based access control
- **Audit Logging**: Comprehensive audit trails
- **Compliance**: Regulatory compliance
- **Key Management**: Secure key management
- **Certificate Policies**: Policy enforcement
- **Access Control**: Granular access control

## Monitoring

### Monitoring Capabilities
- **Health Monitoring**: CA health monitoring
- **Performance Monitoring**: Performance metrics
- **Event Monitoring**: Event log monitoring
- **Certificate Monitoring**: Certificate lifecycle
- **Alerting**: Automated alerting
- **Reporting**: Comprehensive reporting
- **SIEM Integration**: Security information and event management
- **Compliance Monitoring**: Compliance tracking

## Troubleshooting

### Troubleshooting Capabilities
- **Health Diagnostics**: Comprehensive health checks
- **Event Analysis**: Event log analysis
- **Performance Analysis**: Performance analysis
- **Certificate Diagnostics**: Certificate troubleshooting
- **CA Diagnostics**: CA troubleshooting
- **Network Diagnostics**: Network troubleshooting
- **Repair Operations**: Automated repairs
- **Recovery Procedures**: Recovery procedures

## Enterprise Scenarios

### High Availability
- **Clustered CAs**: High availability clusters
- **Load Balancing**: Load-balanced CAs
- **Disaster Recovery**: Disaster recovery procedures
- **Backup and Restore**: Backup procedures

### Security
- **HSM Integration**: Hardware security modules
- **Template Security**: Secure templates
- **Role Separation**: Access control
- **Compliance**: Regulatory compliance

### Hybrid Cloud
- **Azure Integration**: Azure Key Vault
- **Cloud CA**: Cloud certificate authorities
- **Hybrid Identity**: Hybrid identity scenarios
- **SaaS Integration**: SaaS application integration

### Compliance
- **Audit Logging**: Comprehensive audit trails
- **Reporting**: Compliance reporting
- **Policy Enforcement**: Policy enforcement
- **Governance**: Governance procedures

## Best Practices

### Deployment Best Practices
- **Planning**: Plan the deployment carefully
- **Prerequisites**: Ensure all prerequisites are met
- **Testing**: Test in a lab environment first
- **Documentation**: Document the deployment
- **Validation**: Validate the deployment
- **Monitoring**: Monitor the deployment
- **Backup**: Backup before deployment
- **Rollback**: Plan rollback procedures

### Security Best Practices
- **Least Privilege**: Use least privilege principle
- **Defense in Depth**: Implement multiple security layers
- **Regular Updates**: Keep systems updated
- **Monitoring**: Monitor security continuously
- **Auditing**: Regular security audits
- **Incident Response**: Have incident response procedures
- **Training**: Security awareness training
- **Documentation**: Security documentation

### Monitoring Best Practices
- **Proactive Monitoring**: Monitor proactively
- **Comprehensive Coverage**: Monitor all components
- **Real-Time Alerts**: Real-time alerting
- **Historical Analysis**: Trend analysis
- **Capacity Planning**: Resource planning
- **Performance Optimization**: Performance tuning
- **Documentation**: Monitoring documentation
- **Training**: Monitoring training

## Support

### Support Information
- **Documentation**: Complete documentation
- **Examples**: Comprehensive examples
- **Tests**: Test suite
- **Troubleshooting**: Troubleshooting guide
- **Best Practices**: Best practices guide
- **Performance**: Performance guide
- **Security**: Security guide
- **Compliance**: Compliance guide

### Contact Information
- **Author**: Adrian Johnson
- **Email**: adrian207@gmail.com
- **Version**: 1.0.0
- **Date**: October 2025

---

*This solution provides comprehensive management capabilities for Windows Active Directory Certificate Services, covering all enterprise scenarios from basic PKI deployment to advanced hybrid cloud integrations.*
