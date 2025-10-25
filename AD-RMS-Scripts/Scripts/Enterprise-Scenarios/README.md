# AD RMS Enterprise Scenarios

**Author:** Adrian Johnson <adrian207@gmail.com>  
**Version:** 1.0.0  
**Date:** December 2024

## Overview

This directory contains comprehensive PowerShell scripts for deploying all 25 AD RMS enterprise scenarios. Each scenario is designed to be independently deployable and covers specific use cases for Active Directory Rights Management Services.

## 🎯 **25 Enterprise Scenarios**

### **Document Protection Scenarios**

1. **Confidential Document Protection** (`Deploy-ConfidentialDocumentProtection.ps1`)
   - Core purpose of RMS - Apply templates like "Confidential – Internal Use Only" or "Do Not Forward"
   - Encrypt Word, Excel, and PDF files so only authorized domain users can open them
   - Ensures persistent access control even if files leave the file share

2. **Policy-Based Protection Templates** (`Deploy-PolicyBasedProtection.ps1`)
   - Organization-wide classification system
   - Create RMS templates for departments (HR Confidential, Legal Review Only, etc.)
   - Templates auto-apply in Office or DLP solutions

3. **File Server Integration** (`Deploy-FileServerIntegration.ps1`)
   - File Server automatically protects content on save
   - FSRM file screen or classification rule applies RMS policy based on folder location
   - Seamless protection without user action

4. **Dynamic Data Classification** (`Deploy-DynamicDataClassification.ps1`)
   - Combine FSRM and RMS for automatic tagging
   - Detect keywords like "SSN," "Salary," or "Contract," then apply encryption and usage restrictions
   - Real-time data-loss prevention on-premises

5. **SharePoint RMS Protection** (`Deploy-SharePointRMSProtection.ps1`)
   - Secure documents in SharePoint libraries
   - RMS encrypts documents as users download them; decryption tied to their AD identity
   - Protects against exfiltration via local copies

6. **Printing Restrictions** (`Deploy-PrintingRestrictions.ps1`)
   - Prevent physical and digital leaks
   - RMS can disable printing, copy/paste, or screenshots in supported apps
   - Reduces accidental or malicious data exposure

7. **Document Expiry** (`Deploy-DocumentExpiry.ps1`)
   - Self-expiring data
   - RMS usage licenses include expiration date or revocation list
   - Time-bound access for contracts, bids, or tenders

### **Email Protection Scenarios**

8. **Email Protection** (`Deploy-EmailProtection.ps1`)
   - Encrypt and restrict forwarding, copying, or printing
   - Users choose "Do Not Forward" in Outlook; AD RMS issues usage licenses automatically
   - Works with Exchange transport rules to enforce policy

9. **Exchange DLP** (`Deploy-ExchangeDLP.ps1`)
   - Transport rule triggers RMS based on content detection
   - Example: messages containing credit-card numbers get "Confidential – Finance Only"
   - Removes user decision-making from the security chain

### **Collaboration Scenarios**

10. **Cross-Organization Collaboration** (`Deploy-CrossOrganizationCollaboration.ps1`)
    - Secure sharing with partners or subsidiaries
    - Use **Federated Trusts** between AD RMS clusters or Azure RMS
    - Partners authenticate through their own directory

11. **Project Data Rooms** (`Deploy-ProjectDataRooms.ps1`)
    - Temporary secure collaboration zones
    - Create RMS templates limited to project members; expire automatically after project closure
    - Ephemeral but enforceable data governance

12. **Vendor Exchange Portal** (`Deploy-VendorExchangePortal.ps1`)
    - Internal document drop-off/pick-up platform
    - Vendors authenticate via federated RMS or Azure AD B2B
    - Maintains end-to-end encryption and auditability

### **Cloud Integration Scenarios**

13. **Azure Information Protection** (`Deploy-AzureInformationProtection.ps1`)
    - Hybrid RMS → AIP migration
    - On-prem RMS handles LAN traffic; AIP cloud service extends classification to mobile and external users
    - Unified labeling and protection across on-prem and cloud

14. **Secure Cloud Gateways** (`Deploy-SecureCloudGateways.ps1`)
    - Protect files synced to OneDrive or SharePoint Online
    - Local RMS applies policy before sync; cloud respects encryption state
    - Prevents accidental data overexposure in hybrid storage

15. **Hybrid Identity Integration** (`Deploy-HybridIdentityIntegration.ps1`)
    - AD RMS + ADFS for single sign-on
    - Federates authentication for remote users; supports smartcards and MFA
    - Extends trusted access beyond the LAN securely

### **Compliance and Legal Scenarios**

16. **Legal Evidence Management** (`Deploy-LegalEvidenceManagement.ps1`)
    - Sensitive investigation documents
    - Only specific HR/legal groups granted "View Only" rights; auditing logs who opened each file
    - Preserves chain of custody for digital evidence

17. **Auditing Forensics** (`Deploy-AuditingForensics.ps1`)
    - Who opened what, when, and under which license
    - RMS logs tracked through Event Viewer or SIEM
    - Accountability and compliance verification

18. **Purview Integration** (`Deploy-PurviewIntegration.ps1`)
    - Unified classification + RMS protection labeling
    - RMS becomes the encryption backend for sensitivity labels
    - Centralized governance across SharePoint, Teams, Exchange, and endpoints

19. **Secure Backup** (`Deploy-SecureBackup.ps1`)
    - Keep encrypted copies in backup repositories
    - RMS-protected files stay encrypted in backup media but can be reopened by authorized users
    - Balances compliance retention with confidentiality

### **Mobile and BYOD Scenarios**

20. **BYOD Mobile Access** (`Deploy-BYODMobileAccess.ps1`)
    - Extend protection to unmanaged devices
    - RMS clients on iOS/Android enforce usage rights for mobile Office apps
    - Maintains policy compliance beyond corporate perimeter

### **Specialized Industry Scenarios**

21. **Research IP Protection** (`Deploy-ResearchIPProtection.ps1`)
    - R&D labs sharing prototypes or reports
    - RMS ensures only approved researchers can decrypt documents
    - Guards trade secrets even after leaks or insider exits

22. **IoT Industrial Data** (`Deploy-IoTIndustrialData.ps1`)
    - Protect engineering drawings distributed to contractors
    - RMS secures CAD and design files; offline use permitted for limited time
    - Prevents IP theft while enabling collaboration

### **Automation and Operations Scenarios**

23. **PowerShell Automation** (`Deploy-PowerShellAutomation.ps1`)
    - Bulk-protect or unprotect data sets
    - Use `Protect-RMSFile` and `Unprotect-RMSFile` cmdlets for automation
    - Supports DevSecOps workflows and mass policy enforcement

24. **Disaster Recovery RMS** (`Deploy-DisasterRecoveryRMS.ps1`)
    - Maintain continuity of license issuance
    - Deploy multiple RMS nodes behind load balancer with replicated configuration DB
    - Ensures users can still open protected files during outages

25. **Training Policy Awareness** (`Deploy-TrainingPolicyAwareness.ps1`)
    - Demonstrate protection in user training programs
    - Educate staff on document labels and their effects in real time
    - Human layer of security reinforcement

## 🚀 **Quick Start**

### **Prerequisites**

- Windows Server 2016 or later
- PowerShell 5.1 or later
- Administrator privileges
- AD RMS installed and configured
- Required PowerShell modules loaded

### **Basic Usage**

```powershell
# Deploy a single scenario
.\Deploy-ConfidentialDocumentProtection.ps1 -DeploymentName "Corporate-Document-Protection"

# Deploy with custom configuration
.\Deploy-EmailProtection.ps1 -DeploymentName "Enterprise-Email-Security" -TemplatePrefix "Legal" -EnableAuditing

# Test deployment without making changes
.\Deploy-SharePointRMSProtection.ps1 -DeploymentName "SharePoint-Security" -DryRun
```

### **Master Deployment Script**

```powershell
# Deploy any scenario using the master script
.\Deploy-ADRMSScenario.ps1 -Scenario "ConfidentialDocumentProtection" -DeploymentName "Corporate-Document-Protection"

# Deploy with configuration file
.\Deploy-ADRMSScenario.ps1 -Scenario "EmailProtection" -DeploymentName "Enterprise-Email-Security" -ConfigurationFile "Email-Config.json"

# Test deployment
.\Deploy-ADRMSScenario.ps1 -Scenario "SharePointRMSProtection" -DeploymentName "SharePoint-Security" -DryRun
```

## 📋 **Configuration**

### **JSON Configuration Template**

Use the `ADRMS-Enterprise-Config.json` file as a template for complex deployments:

```json
{
  "ADRMSEEnterpriseScenarios": {
    "Scenarios": {
      "ConfidentialDocumentProtection": {
        "Templates": [
          {
            "Name": "Confidential-Internal-Only",
            "Description": "Confidential documents for internal use only",
            "RightsGroup": "Viewer",
            "AllowPrint": false,
            "AllowCopy": false,
            "EnableAuditing": true
          }
        ]
      }
    }
  }
}
```

### **Common Parameters**

Most scripts support these common parameters:

- `-DeploymentName`: Name for the deployment
- `-TemplatePrefix`: Prefix for RMS templates
- `-EnableAuditing`: Enable audit logging
- `-DryRun`: Test mode without making changes

## 🔧 **Customization**

### **Template Customization**

Each scenario creates specific RMS templates. You can customize:

- **Rights Groups**: Viewer, Editor, Reviewer, Owner
- **Usage Rights**: Print, Copy, Forward, Offline Access
- **Expiration Dates**: Time-limited access
- **Auditing**: Comprehensive audit logging

### **Access Control**

Configure access controls for:

- **Security Groups**: Domain groups with access
- **User Accounts**: Individual user access
- **Computer Accounts**: Machine-based access
- **External Users**: Partner and vendor access

### **Integration Settings**

Each scenario supports integration with:

- **Exchange Server**: DLP rules and transport rules
- **SharePoint**: Document library protection
- **Azure AD**: Hybrid identity and conditional access
- **SIEM Systems**: Audit log integration

## 📊 **Monitoring and Reporting**

### **Audit Logging**

All scenarios support comprehensive audit logging:

- **Document Access**: Who accessed what documents
- **Template Usage**: Which templates were used
- **Rights Modifications**: Changes to usage rights
- **System Events**: RMS server events and errors

### **Performance Monitoring**

Monitor RMS performance with:

- **Template Performance**: Usage statistics
- **Protection Performance**: Success/failure rates
- **User Activity**: Access patterns and trends
- **System Health**: Server performance metrics

## 🛠️ **Troubleshooting**

### **Common Issues**

1. **Prerequisites Not Met**
   - Ensure Windows Server 2016+ and PowerShell 5.1+
   - Verify administrator privileges
   - Check AD RMS installation

2. **Template Creation Failures**
   - Verify RMS server connectivity
   - Check template naming conflicts
   - Ensure sufficient permissions

3. **Integration Issues**
   - Verify Exchange/SharePoint connectivity
   - Check service account permissions
   - Validate configuration settings

### **Logging and Diagnostics**

Enable detailed logging:

```powershell
# Enable verbose logging
$VerbosePreference = "Continue"

# Enable debug logging
$DebugPreference = "Continue"

# Run with detailed output
.\Deploy-ConfidentialDocumentProtection.ps1 -DeploymentName "Test" -Verbose
```

## 📚 **Documentation**

### **Additional Resources**

- **User Guide**: `..\..\Documentation\User-Guide.md`
- **Examples**: `..\..\Examples\README.md`
- **Tests**: `..\..\Tests\README.md`

### **Microsoft Documentation**

- [AD RMS Overview](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc771234(v=ws.10))
- [RMS Protection](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc771234(v=ws.10))
- [Exchange DLP](https://learn.microsoft.com/en-us/exchange/security-and-compliance/data-loss-prevention/dlp)

## 🤝 **Support**

For issues and questions:

1. Check the troubleshooting section above
2. Review the logs and error messages
3. Consult the Microsoft documentation
4. Test with `-DryRun` parameter first

## 📝 **Version History**

- **v1.0.0**: Initial release with all 25 enterprise scenarios
- Comprehensive AD RMS deployment capabilities
- Full integration with Exchange, SharePoint, and Azure
- Complete audit logging and compliance features

---

**Note**: These scripts are designed for enterprise environments and should be tested in a lab environment before production deployment.
