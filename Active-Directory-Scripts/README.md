# Active Directory Scripts

## Overview

This solution provides comprehensive PowerShell scripts for Windows Active Directory management, covering all aspects of AD deployment, configuration, security, monitoring, and troubleshooting.

## Author

**Adrian Johnson**  
Email: adrian207@gmail.com  
Version: 1.0.0  
Date: October 2025

## Features

- Centralized Identity and Authentication
- Group Policy Management (GPO)
- Organizational Units (OUs) and Delegation
- Multi-Domain and Multi-Forest Architectures
- Trust Relationships
- Kerberos Delegation and Constrained Delegation
- Fine-Grained Password Policies
- Read-Only Domain Controllers (RODC)
- FSMO Role Management
- AD Integrated DNS
- Replication and Site Topology
- Certificate Mapping and PKINIT
- Service Accounts (gMSA and sMSA)
- Dynamic Access Control (DAC)
- Auditing and Security Monitoring
- Privileged Access Management (PAM)
- Group Nesting and Role-Based Access Control (RBAC)
- Schema Extension and Application Integration
- AD Federation and Single Sign-On (SSO)
- Backup and Disaster Recovery
- Time Synchronization via PDC Emulator
- Access Control Lists (ACLs) and Effective Permissions
- LDAP Query and Directory Applications
- Tiered Administration Model
- Privileged Access Workstations (PAW) Integration
- Group Policy Security Baselines
- Hybrid Join and Entra Integration
- Azure AD Kerberos for Cloud Resources
- Trust Hardening and SID Filtering
- AD Forest Recovery
- Schema Version Management and Migration
- Custom Attribute-Based Authentication
- Delegated Administration for Helpdesk
- Offline Domain Join and Provisioning
- Integration with Keyfactor, Venafi, and SCIM
- Kerberos Armoring and FAST
- LDAP over SSL (LDAPS)
- Dynamic Group Membership via LDAP Filters
- Integration with Device Health Attestation and NPS
- AD as Root of Trust for PKI and Federation

## Prerequisites

- Windows Server 2016 or later
- Active Directory Domain Services
- Administrative privileges
- Network connectivity
- Sufficient storage space
- Sufficient memory and CPU resources

## Installation

1. Download the Active Directory Scripts solution
2. Extract to desired location
3. Import required modules
4. Configure execution policy
5. Run deployment scripts

## Usage

```powershell
# Deploy Active Directory
.\Scripts\Deployment\Deploy-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com"

# Configure Active Directory
.\Scripts\Configuration\Configure-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -ConfigurationLevel "Standard"

# Secure Active Directory
.\Scripts\Security\Secure-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -SecurityLevel "Standard"

# Monitor Active Directory
.\Scripts\Monitoring\Monitor-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -MonitoringLevel "Standard"

# Troubleshoot Active Directory
.\Scripts\Troubleshooting\Troubleshoot-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -TroubleshootingLevel "Standard"
```

## Support

For support, please contact Adrian Johnson at adrian207@gmail.com
