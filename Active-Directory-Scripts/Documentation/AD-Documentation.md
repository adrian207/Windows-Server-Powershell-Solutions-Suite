# Active Directory Scripts Documentation

## Overview

This solution provides comprehensive PowerShell scripts for Windows Active Directory Domain Services management, covering all aspects of AD deployment, configuration, security, monitoring, and troubleshooting.

## Author

**Adrian Johnson**  
Email: adrian207@gmail.com  
Version: 1.0.0  
Date: October 2025

## Features

### Core Functionality

- **Centralized Identity and Authentication**: Users, computers, and services authenticate via Kerberos or NTLM. Passwords and tickets flow through secure domain controllers.
- **Group Policy Management (GPO)**: Configuration and security control at scale. Deploy password policies, scripts, registry changes, firewall rules, etc.
- **Organizational Units (OUs) and Delegation**: Logical structure for management and permissions. Segment by department, region, or function. Delegate admin rights granularly.
- **Multi-Domain and Multi-Forest Architectures**: Scale or isolation across global enterprises. Multiple domains under a forest for replication efficiency or legal separation.
- **Trust Relationships**: Authentication across boundaries. Forest, domain, or external trusts allow users in one AD to access another.

### Advanced Features

- **Kerberos Delegation and Constrained Delegation**: Allow services to act on behalf of users. Used by web apps, SQL, and ADFS for SSO.
- **Fine-Grained Password Policies**: Different security requirements by user type. Protects privileged accounts with stronger standards than general users.
- **Read-Only Domain Controllers (RODC)**: Secure AD presence in branch offices. Hosts read-only copies of the directory; caches passwords selectively.
- **FSMO Role Management**: Five special roles for forest and domain operations (Schema Master, RID, PDC Emulator, etc.).
- **AD Integrated DNS**: DNS zones stored within the directory. Simplifies replication and name resolution for domain services.

### Security Features

- **Replication and Site Topology**: Global synchronization of directory data. Sites and subnets control replication traffic and logon affinity.
- **Certificate Mapping and PKINIT**: Integrate with AD CS for certificate-based logon. Passwordless authentication with strong identity assurance.
- **Service Accounts (gMSA and sMSA)**: Managed credentials for services and applications. Automatic password rotation and permission scoping.
- **Dynamic Access Control (DAC)**: Attribute-based file and folder access control. Enforces policies like "Finance group + managed device + US region."
- **Auditing and Security Monitoring**: Track logons, directory changes, and policy application. Supports forensics, compliance, and insider threat detection.

### Enterprise Features

- **Privileged Access Management (PAM)**: Time-bound administrative roles. Leverages MIM or Entra Privileged Identity Management (PIM).
- **Group Nesting and Role-Based Access Control (RBAC)**: Structure groups by function, department, or system. Reduces complexity in ACL management.
- **Schema Extension and Application Integration**: Extend AD for apps like Exchange, SCCM, or custom attributes. Centralized identity schema for all enterprise systems.
- **AD Federation and Single Sign-On (SSO)**: Use ADFS or Entra ID to extend authentication to cloud apps. Unified identity between on-prem and SaaS ecosystems.
- **Backup and Disaster Recovery**: Use System State backups, Recycle Bin, and tombstone reanimation. Resilient recovery from corruption, deletion, or compromise.

### Monitoring and Troubleshooting

- **Time Synchronization via PDC Emulator**: Keep Kerberos and logs aligned. Prevents clock skew authentication failures and aids forensic accuracy.
- **Access Control Lists (ACLs) and Effective Permissions**: Control who can modify what in AD objects. Granular security and least privilege enforcement.
- **LDAP Query and Directory Applications**: Query AD for identity data (HR, IAM, SSO). Turns AD into a single authoritative source for user attributes.
- **Tiered Administration Model**: Separate Tier 0 (Domain Admins), Tier 1 (Servers), Tier 2 (Workstations). Limits lateral movement during attacks.
- **Privileged Access Workstations (PAW) Integration**: Dedicated hardened systems for admin work. Protects admin credentials from phishing and malware.

### Compliance and Governance

- **Group Policy Security Baselines**: Apply CIS, NIST, or Microsoft baselines via GPOs. Standardizes security posture across domains.
- **Hybrid Join and Entra Integration**: Sync AD identities to Entra ID via AAD Connect. Enables hybrid SSO and Conditional Access enforcement.
- **Azure AD Kerberos for Cloud Resources**: On-prem AD issues Kerberos tickets used by Azure Files or AVD. Bridges cloud resources with domain-based identity.
- **Trust Hardening and SID Filtering**: Secure cross-forest trusts to prevent SID spoofing. Prevents elevation of privilege via foreign domain SIDs.
- **AD Forest Recovery**: Complete rebuild using backups or Microsoft's forest recovery plan. Restores identity infrastructure after catastrophic compromise.

### Advanced Integration

- **Schema Version Management and Migration**: Update for new Windows Server versions or Exchange. Ensures compatibility and supports advanced directory features.
- **Custom Attribute-Based Authentication**: Extend AD for SCIM or claims-based identity. Enables modern IAM integrations beyond legacy fields.
- **Delegated Administration for Helpdesk**: Grant specific write rights (reset password, unlock account). Scales user support without overexposing privileges.
- **Offline Domain Join and Provisioning**: Pre-stage computers before network connection. Automates device enrollment in disconnected or secure environments.
- **Integration with Keyfactor, Venafi, and SCIM**: Tie AD attributes to certificate or lifecycle management. Unifies identity and PKI governance.

### Security Hardening

- **Kerberos Armoring and FAST**: Protect ticket exchanges from replay or interception. Hardens AD authentication against credential theft.
- **LDAP over SSL (LDAPS)**: Secure all directory communications. Encrypts credentials and queries end-to-end.
- **Dynamic Group Membership via LDAP Filters**: Automate group population based on attributes. Reduces manual group management and errors.
- **Integration with Device Health Attestation and NPS**: Enforce policy that ties user + device health to access rights. Brings AD identity into Zero Trust architecture.
- **AD as Root of Trust for PKI and Federation**: Anchor for AD CS, ADFS, and Kerberos ticketing. Provides the central authority of identity, trust, and encryption across Windows services.

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

### Basic Usage

```powershell
# Deploy Active Directory
.\Scripts\Deployment\Deploy-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -NetBIOSName "CONTOSO" -SafeModePassword "SecurePassword123!"

# Configure Active Directory
.\Scripts\Configuration\Configure-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -ConfigurationLevel "Standard"

# Secure Active Directory
.\Scripts\Security\Secure-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -SecurityLevel "Standard"

# Monitor Active Directory
.\Scripts\Monitoring\Monitor-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -MonitoringLevel "Standard"

# Troubleshoot Active Directory
.\Scripts\Troubleshooting\Troubleshoot-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -TroubleshootingLevel "Standard"
```

### Advanced Usage

```powershell
# Deploy with all enterprise scenarios
.\Scripts\Deployment\Deploy-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -NetBIOSName "CONTOSO" -SafeModePassword "SecurePassword123!" -DeploymentType "All" -DeploymentLevel "Comprehensive" -IncludeSecurity -IncludeMonitoring -IncludeCompliance -IncludeIntegration -IncludeCustom -CustomDeploymentScript "C:\Scripts\Custom-AD-Deployment.ps1" -OutputFormat "HTML" -OutputPath "C:\Reports\AD-Deployment-Results.html" -GenerateReport -ReportFormat "PDF" -ReportPath "C:\Reports\AD-Deployment-Report.pdf"

# Configure with comprehensive settings
.\Scripts\Configuration\Configure-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -ConfigurationLevel "Comprehensive" -IncludeSecurity -IncludeMonitoring -IncludeCompliance -IncludeIntegration -IncludeCustom -CustomConfigurationScript "C:\Scripts\Custom-AD-Configuration.ps1" -OutputFormat "HTML" -OutputPath "C:\Reports\AD-Configuration-Results.html" -GenerateReport -ReportFormat "PDF" -ReportPath "C:\Reports\AD-Configuration-Report.pdf"

# Secure with maximum settings
.\Scripts\Security\Secure-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -SecurityLevel "Maximum" -IncludePermissions -IncludeAudit -IncludeCompliance -IncludeBaselines -IncludeLogging -IncludeComplianceSettings -IncludeSecurityPolicies -IncludeAccessControl -IncludeEncryption -IncludeKeyProtection -IncludeCertificateLifecycle -IncludeCrossForestTrust -IncludeSmartcardSupport -IncludeWindowsHello -IncludeBitLockerIntegration -IncludeHSMIntegration -IncludeCustomSecurity -CustomSecurityScript "C:\Scripts\Custom-AD-Security.ps1" -OutputFormat "HTML" -OutputPath "C:\Reports\AD-Security-Results.html" -GenerateReport -ReportFormat "PDF" -ReportPath "C:\Reports\AD-Security-Report.pdf"

# Monitor with comprehensive alerting
.\Scripts\Monitoring\Monitor-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -MonitoringLevel "Comprehensive" -AlertLevel "High" -AlertTypes @("Email", "SMS", "Webhook") -SmtpServer "smtp.contoso.com" -SmtpPort 587 -SmtpUsername "alerts@contoso.com" -SmtpPassword "SecurePassword123" -Recipients @("admin@contoso.com", "ops@contoso.com") -WebhookUrl "https://webhook.contoso.com/alerts" -SmsProvider "Twilio" -SmsApiKey "your-api-key" -SmsApiSecret "your-api-secret" -SmsFromNumber "+1234567890" -SmsRecipients @("+1234567890", "+0987654321") -ReportType "Comprehensive" -DaysBack 7 -OutputFormat "HTML" -OutputPath "C:\Reports\AD-Monitoring-Report.html" -GenerateReport -ReportFormat "PDF" -ReportPath "C:\Reports\AD-Monitoring-Report.pdf"

# Troubleshoot with comprehensive analysis
.\Scripts\Troubleshooting\Troubleshoot-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -TroubleshootingLevel "Comprehensive" -TroubleshootingType "All" -IncludeRemediation -IncludePerformanceAnalysis -IncludeEventLogAnalysis -IncludeHealthChecks -IncludeSecurityAnalysis -IncludeComplianceCheck -IncludeReplicationCheck -IncludeFSMOCheck -IncludeDNSCheck -IncludeTimeSyncCheck -IncludeCustomTroubleshooting -CustomTroubleshootingScript "C:\Scripts\Custom-AD-Troubleshooting.ps1" -OutputFormat "HTML" -OutputPath "C:\Reports\AD-Troubleshooting-Results.html" -GenerateReport -ReportFormat "PDF" -ReportPath "C:\Reports\AD-Troubleshooting-Report.pdf"
```

### Enterprise Scenarios

```powershell
# Deploy all 40 enterprise scenarios
.\Scripts\Enterprise-Scenarios\Deploy-ADEnterpriseScenarios.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -NetBIOSName "CONTOSO" -SafeModePassword "SecurePassword123!" -ScenarioType "All" -IncludeSecurity -IncludeMonitoring -IncludeCompliance -IncludeIntegration -IncludeCustom -CustomScenarioScript "C:\Scripts\Custom-AD-Scenarios.ps1" -OutputFormat "HTML" -OutputPath "C:\Reports\AD-Enterprise-Scenarios-Results.html" -GenerateReport -ReportFormat "PDF" -ReportPath "C:\Reports\AD-Enterprise-Scenarios-Report.pdf"
```

## Modules

### AD-Core.psm1

Core PowerShell module for Windows Active Directory operations. Provides essential AD functionality including user management, group management, OU management, domain controller operations, and more.

**Functions:**
- `Get-ADHealthStatus`: Check AD health status
- `Get-ADUserManagement`: Retrieve user information
- `Get-ADGroupManagement`: Retrieve group information
- `Get-ADOUManagement`: Retrieve OU information
- `Set-ADPasswordPolicy`: Configure password policy
- `Set-ADGroupPolicy`: Configure group policy
- `Get-ADReplicationStatus`: Check replication status
- `Get-ADFSMORoles`: Retrieve FSMO roles
- `Set-ADTimeSync`: Configure time synchronization

### AD-Security.psm1

PowerShell module for Windows Active Directory security configurations. Provides security management capabilities including audit policies, access control, privileged access management, and security monitoring.

**Functions:**
- `Set-ADAuditPolicy`: Configure audit policy
- `Set-ADAccessControl`: Configure access control
- `Set-ADPrivilegedAccess`: Configure privileged access management
- `Set-ADSecurityBaseline`: Apply security baseline
- `Set-ADKerberosSecurity`: Configure Kerberos security
- `Set-ADLDAPSSecurity`: Configure LDAPS security
- `Set-ADTrustSecurity`: Configure trust security
- `Get-ADSecurityStatus`: Check security status

### AD-Monitoring.psm1

PowerShell module for Windows Active Directory monitoring and alerting. Provides comprehensive monitoring capabilities including health monitoring, performance monitoring, event monitoring, and alerting.

**Functions:**
- `Get-ADHealthMonitoring`: Monitor AD health
- `Get-ADPerformanceMonitoring`: Monitor AD performance
- `Get-ADEventMonitoring`: Monitor AD events
- `Set-ADAlerting`: Configure alerting
- `Get-ADMonitoringReport`: Generate monitoring report

### AD-Troubleshooting.psm1

PowerShell module for Windows Active Directory troubleshooting and diagnostics. Provides comprehensive troubleshooting capabilities including health checks, performance analysis, event log analysis, and automated remediation.

**Functions:**
- `Get-ADTroubleshootingStatus`: Perform AD troubleshooting
- `Get-ADHealthStatus`: Check AD health status
- `Get-ADPerformanceMetrics`: Collect performance metrics
- `Get-ADEventLogs`: Collect event logs
- `Get-ADComplianceStatus`: Check compliance status

## Scripts

### Deployment Scripts

- **Deploy-ActiveDirectory.ps1**: Main deployment script for Windows Active Directory Domain Services
- **Deploy-ADEnterpriseScenarios.ps1**: Enterprise scenarios deployment script for all 40 scenarios

### Configuration Scripts

- **Configure-ActiveDirectory.ps1**: Configuration script for Windows Active Directory Domain Services

### Security Scripts

- **Secure-ActiveDirectory.ps1**: Security script for Windows Active Directory Domain Services

### Monitoring Scripts

- **Monitor-ActiveDirectory.ps1**: Monitoring script for Windows Active Directory Domain Services

### Troubleshooting Scripts

- **Troubleshoot-ActiveDirectory.ps1**: Troubleshooting script for Windows Active Directory Domain Services

## Examples

### AD-Examples.ps1

Comprehensive examples for Windows Active Directory Domain Services. Demonstrates all 40 enterprise scenarios including centralized identity, group policy management, multi-domain architectures, trust relationships, and more.

**Examples:**
1. Centralized Identity and Authentication
2. Group Policy Management (GPO)
3. Organizational Units (OUs) and Delegation
4. Multi-Domain and Multi-Forest Architectures
5. Trust Relationships
6. Kerberos Delegation and Constrained Delegation
7. Fine-Grained Password Policies
8. Read-Only Domain Controllers (RODC)
9. FSMO Role Management
10. AD Integrated DNS
11. Replication and Site Topology
12. Certificate Mapping and PKINIT
13. Service Accounts (gMSA and sMSA)
14. Dynamic Access Control (DAC)
15. Auditing and Security Monitoring
16. Privileged Access Management (PAM)
17. Group Nesting and Role-Based Access Control (RBAC)
18. Schema Extension and Application Integration
19. AD Federation and Single Sign-On (SSO)
20. Backup and Disaster Recovery
21. Time Synchronization via PDC Emulator
22. Access Control Lists (ACLs) and Effective Permissions
23. LDAP Query and Directory Applications
24. Tiered Administration Model
25. Privileged Access Workstations (PAW) Integration
26. Group Policy Security Baselines
27. Hybrid Join and Entra Integration
28. Azure AD Kerberos for Cloud Resources
29. Trust Hardening and SID Filtering
30. AD Forest Recovery
31. Schema Version Management and Migration
32. Custom Attribute-Based Authentication
33. Delegated Administration for Helpdesk
34. Offline Domain Join and Provisioning
35. Integration with Keyfactor, Venafi, and SCIM
36. Kerberos Armoring and FAST
37. LDAP over SSL (LDAPS)
38. Dynamic Group Membership via LDAP Filters
39. Integration with Device Health Attestation and NPS
40. AD as Root of Trust for PKI and Federation

## Tests

### Test-ADScripts.ps1

Test script for Windows Active Directory Domain Services. Tests all modules, scripts, and functionality to ensure proper operation.

**Test Categories:**
- AD Core Module Tests
- AD Security Module Tests
- AD Monitoring Module Tests
- AD Troubleshooting Module Tests
- Deployment Script Tests
- Configuration Script Tests
- Security Script Tests
- Monitoring Script Tests
- Troubleshooting Script Tests
- Examples Tests
- Documentation Tests
- Configuration File Tests

## Configuration

### Configuration Templates

- **AD-Configuration-Template.json**: JSON template for main AD configurations
- **Security-Configuration-Template.json**: JSON template for AD security configurations
- **Monitoring-Configuration-Template.json**: JSON template for AD monitoring configurations
- **Troubleshooting-Configuration-Template.json**: JSON template for AD troubleshooting configurations

## Security Considerations

- Requires administrative privileges
- Configures secure AD settings
- Implements security baselines
- Enables security logging
- Configures security compliance settings
- Implements Zero Trust architecture
- Enables privileged access management
- Configures audit policies
- Implements access control
- Enables security monitoring

## Performance Impact

- Minimal impact during deployment
- Non-destructive operations
- Configurable deployment scope
- Resource-aware deployment
- Minimal impact during configuration
- Non-destructive operations
- Configurable configuration scope
- Resource-aware configuration
- Minimal impact during security configuration
- Non-destructive operations
- Configurable security scope
- Resource-aware security configuration
- Minimal impact during monitoring configuration
- Non-destructive operations
- Configurable monitoring scope
- Resource-aware monitoring configuration
- Minimal impact during troubleshooting
- Non-destructive operations
- Configurable troubleshooting scope
- Resource-aware troubleshooting

## Troubleshooting

### Common Issues

1. **Module Import Failures**: Ensure all required modules are in the correct path
2. **Permission Errors**: Run scripts with administrative privileges
3. **Network Connectivity**: Ensure network connectivity to domain controllers
4. **Storage Space**: Ensure sufficient storage space for operations
5. **Memory and CPU**: Ensure sufficient memory and CPU resources

### Error Handling

All scripts include comprehensive error handling with:
- Try-catch blocks
- Detailed error messages
- Error logging
- Graceful failure handling
- Recovery recommendations

### Logging

All scripts provide detailed logging with:
- Color-coded console output
- Timestamped log entries
- Severity levels (Info, Warning, Error, Success)
- Detailed operation tracking
- Progress indicators

## Support

For support, please contact Adrian Johnson at adrian207@gmail.com

## License

This solution is provided as-is for educational and demonstration purposes. Please ensure compliance with your organization's policies and Microsoft licensing requirements.

## Version History

- **Version 1.0.0** (October 2025): Initial release with all 40 enterprise scenarios
