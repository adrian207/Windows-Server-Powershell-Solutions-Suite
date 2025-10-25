#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Secure NPAS

.DESCRIPTION
    This script provides comprehensive security implementation for Network Policy and Access Services (NPAS)
    including authentication configuration, authorization policies, encryption settings, compliance management,
    multi-factor authentication, certificate management, and Zero Trust security model implementation.

.PARAMETER ServerName
    Name of the NPAS server to secure

.PARAMETER SecurityLevel
    Security level to implement (Basic, Standard, High, Enterprise)

.PARAMETER ComplianceStandards
    Array of compliance standards to implement

.PARAMETER MFAProvider
    Multi-factor authentication provider to configure

.PARAMETER CertificateAuthority
    Certificate authority for certificate-based authentication

.PARAMETER ZeroTrust
    Enable Zero Trust security model

.EXAMPLE
    .\Secure-NPAS.ps1 -ServerName "NPAS-SERVER01" -SecurityLevel "Enterprise" -ComplianceStandards @("NIST", "ISO-27001") -MFAProvider "Azure-MFA" -ZeroTrust

.EXAMPLE
    .\Secure-NPAS.ps1 -ServerName "NPAS-SERVER01" -SecurityLevel "High" -CertificateAuthority "AD-CS-SERVER01"
#>

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerName,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Standard", "High", "Enterprise")]
    [string]$SecurityLevel = "Standard",

    [Parameter(Mandatory = $false)]
    [string[]]$ComplianceStandards = @("NIST"),

    [Parameter(Mandatory = $false)]
    [ValidateSet("Azure-MFA", "Duo", "Okta", "Google-Authenticator")]
    [string]$MFAProvider = "Azure-MFA",

    [Parameter(Mandatory = $false)]
    [string]$CertificateAuthority,

    [Parameter(Mandatory = $false)]
    [switch]$ZeroTrust
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Script configuration
$scriptConfig = @{
    ServerName = $ServerName
    SecurityLevel = $SecurityLevel
    ComplianceStandards = $ComplianceStandards
    MFAProvider = $MFAProvider
    CertificateAuthority = $CertificateAuthority
    ZeroTrust = $ZeroTrust
    LogPath = "C:\NPAS\Logs\Security"
    StartTime = Get-Date
}

# Create log directory
if (-not (Test-Path $scriptConfig.LogPath)) {
    New-Item -Path $scriptConfig.LogPath -ItemType Directory -Force
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Information"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    Write-Host $logMessage -ForegroundColor $(
        switch ($Level) {
            "Error" { "Red" }
            "Warning" { "Yellow" }
            "Success" { "Green" }
            default { "White" }
        }
    )
    
    $logMessage | Out-File -FilePath "$($scriptConfig.LogPath)\NPAS-Security.log" -Append -Encoding UTF8
}

try {
    Write-Log "Starting NPAS security implementation..." "Information"
    Write-Log "Server Name: $ServerName" "Information"
    Write-Log "Security Level: $SecurityLevel" "Information"
    Write-Log "Compliance Standards: $($ComplianceStandards -join ', ')" "Information"
    Write-Log "MFA Provider: $MFAProvider" "Information"
    Write-Log "Certificate Authority: $CertificateAuthority" "Information"
    Write-Log "Zero Trust: $ZeroTrust" "Information"

    # Import required modules
    Write-Log "Importing NPAS modules..." "Information"
    $modulePath = Join-Path $PSScriptRoot "..\..\Modules"
    
    if (Test-Path "$modulePath\NPAS-Security.psm1") {
        Import-Module "$modulePath\NPAS-Security.psm1" -Force
        Write-Log "NPAS-Security module imported successfully" "Success"
    } else {
        throw "NPAS-Security module not found at $modulePath\NPAS-Security.psm1"
    }

    if (Test-Path "$modulePath\NPAS-Core.psm1") {
        Import-Module "$modulePath\NPAS-Core.psm1" -Force
        Write-Log "NPAS-Core module imported successfully" "Success"
    } else {
        throw "NPAS-Core module not found at $modulePath\NPAS-Core.psm1"
    }

    # Security configuration based on security level
    $securityConfig = @{
        Basic = @{
            AuthenticationMethods = @("MS-CHAPv2", "PAP")
            EncryptionLevel = "Standard"
            EncryptionMethods = @("TLS-1.2")
            AuditLevel = "Basic"
            MFAMethods = @()
            CertificateValidation = $false
            SmartCardSupport = $false
            ConditionalAccess = $false
            RiskAssessment = $false
            ThreatProtection = $false
        }
        Standard = @{
            AuthenticationMethods = @("EAP-TLS", "PEAP-MS-CHAPv2", "MS-CHAPv2")
            EncryptionLevel = "Strong"
            EncryptionMethods = @("AES-256", "TLS-1.2")
            AuditLevel = "Standard"
            MFAMethods = @("SMS")
            CertificateValidation = $true
            SmartCardSupport = $true
            ConditionalAccess = $true
            RiskAssessment = $true
            ThreatProtection = $true
        }
        High = @{
            AuthenticationMethods = @("EAP-TLS", "PEAP-MS-CHAPv2")
            EncryptionLevel = "Strong"
            EncryptionMethods = @("AES-256", "TLS-1.2", "TLS-1.3")
            AuditLevel = "Comprehensive"
            MFAMethods = @("SMS", "Phone", "Authenticator-App")
            CertificateValidation = $true
            SmartCardSupport = $true
            ConditionalAccess = $true
            RiskAssessment = $true
            ThreatProtection = $true
        }
        Enterprise = @{
            AuthenticationMethods = @("EAP-TLS")
            EncryptionLevel = "Maximum"
            EncryptionMethods = @("AES-256", "TLS-1.3")
            AuditLevel = "Comprehensive"
            MFAMethods = @("SMS", "Phone", "Authenticator-App", "Hardware-Token")
            CertificateValidation = $true
            SmartCardSupport = $true
            ConditionalAccess = $true
            RiskAssessment = $true
            ThreatProtection = $true
        }
    }

    $currentConfig = $securityConfig[$SecurityLevel]
    Write-Log "Using security configuration for level: $SecurityLevel" "Information"

    # 1. Configure Authentication
    Write-Log "Configuring NPAS authentication..." "Information"
    $authResult = Set-NPASAuthentication -ServerName $ServerName -AuthenticationMethods $currentConfig.AuthenticationMethods -CertificateValidation $currentConfig.CertificateValidation -SmartCardSupport $currentConfig.SmartCardSupport
    
    if ($authResult.Success) {
        Write-Log "Authentication configured successfully" "Success"
        Write-Log "Authentication Methods: $($authResult.AuthenticationSettings.AuthenticationMethods -join ', ')" "Information"
        Write-Log "Certificate Validation: $($authResult.AuthenticationSettings.CertificateValidation)" "Information"
        Write-Log "Smart Card Support: $($authResult.AuthenticationSettings.SmartCardSupport)" "Information"
    } else {
        Write-Log "Failed to configure authentication: $($authResult.Error)" "Warning"
    }

    # 2. Configure Authorization
    Write-Log "Configuring NPAS authorization..." "Information"
    $authzResult = Set-NPASAuthorization -ServerName $ServerName -AuthorizationMethod "RBAC" -GroupPolicies @("Network-Admins", "Wireless-Users", "VPN-Users", "Guest-Users") -TimeRestrictions
    
    if ($authzResult.Success) {
        Write-Log "Authorization configured successfully" "Success"
        Write-Log "Authorization Method: $($authzResult.AuthorizationSettings.AuthorizationMethod)" "Information"
        Write-Log "Group Policies: $($authzResult.AuthorizationSettings.GroupPolicies.Count)" "Information"
        Write-Log "Time Restrictions: $($authzResult.AuthorizationSettings.TimeRestrictions)" "Information"
    } else {
        Write-Log "Failed to configure authorization: $($authzResult.Error)" "Warning"
    }

    # 3. Configure Encryption
    Write-Log "Configuring NPAS encryption..." "Information"
    $encryptResult = Set-NPASEncryption -ServerName $ServerName -EncryptionLevel $currentConfig.EncryptionLevel -EncryptionMethods $currentConfig.EncryptionMethods -KeyManagement
    
    if ($encryptResult.Success) {
        Write-Log "Encryption configured successfully" "Success"
        Write-Log "Encryption Level: $($encryptResult.EncryptionSettings.EncryptionLevel)" "Information"
        Write-Log "Encryption Methods: $($encryptResult.EncryptionSettings.EncryptionMethods -join ', ')" "Information"
        Write-Log "Key Management: $($encryptResult.EncryptionSettings.KeyManagement)" "Information"
    } else {
        Write-Log "Failed to configure encryption: $($encryptResult.Error)" "Warning"
    }

    # 4. Configure Auditing
    Write-Log "Configuring NPAS auditing..." "Information"
    $auditResult = Set-NPASAuditing -ServerName $ServerName -AuditLevel $currentConfig.AuditLevel -LogFormat "Database" -RetentionPeriod 90
    
    if ($auditResult.Success) {
        Write-Log "Auditing configured successfully" "Success"
        Write-Log "Audit Level: $($auditResult.AuditingSettings.AuditLevel)" "Information"
        Write-Log "Log Format: $($auditResult.AuditingSettings.LogFormat)" "Information"
        Write-Log "Retention Period: $($auditResult.AuditingSettings.RetentionPeriod) days" "Information"
    } else {
        Write-Log "Failed to configure auditing: $($auditResult.Error)" "Warning"
    }

    # 5. Configure Compliance
    Write-Log "Configuring NPAS compliance..." "Information"
    $complianceResult = Set-NPASCompliance -ServerName $ServerName -ComplianceStandards $ComplianceStandards -PolicyEnforcement -RiskAssessment
    
    if ($complianceResult.Success) {
        Write-Log "Compliance configured successfully" "Success"
        Write-Log "Compliance Standards: $($complianceResult.ComplianceSettings.ComplianceStandards -join ', ')" "Information"
        Write-Log "Policy Enforcement: $($complianceResult.ComplianceSettings.PolicyEnforcement)" "Information"
        Write-Log "Risk Assessment: $($complianceResult.ComplianceSettings.RiskAssessment)" "Information"
    } else {
        Write-Log "Failed to configure compliance: $($complianceResult.Error)" "Warning"
    }

    # 6. Configure Multi-Factor Authentication
    if ($currentConfig.MFAMethods.Count -gt 0) {
        Write-Log "Configuring multi-factor authentication..." "Information"
        $mfaResult = Set-NPASMFASettings -ServerName $ServerName -MFAProvider $MFAProvider -MFAMethods $currentConfig.MFAMethods -ConditionalAccess
        
        if ($mfaResult.Success) {
            Write-Log "MFA configured successfully" "Success"
            Write-Log "MFA Provider: $($mfaResult.MFASettings.MFAProvider)" "Information"
            Write-Log "MFA Methods: $($mfaResult.MFASettings.MFAMethods -join ', ')" "Information"
            Write-Log "Conditional Access: $($mfaResult.MFASettings.ConditionalAccess)" "Information"
        } else {
            Write-Log "Failed to configure MFA: $($mfaResult.Error)" "Warning"
        }
    }

    # 7. Configure Certificate Settings
    if ($CertificateAuthority) {
        Write-Log "Configuring certificate settings..." "Information"
        $certResult = Set-NPASCertificateSettings -ServerName $ServerName -CertificateAuthority $CertificateAuthority -CertificateTemplates @("User-Certificate", "Machine-Certificate") -CertificateValidation
        
        if ($certResult.Success) {
            Write-Log "Certificate settings configured successfully" "Success"
            Write-Log "Certificate Authority: $($certResult.CertificateSettings.CertificateAuthority)" "Information"
            Write-Log "Certificate Validation: $($certResult.CertificateSettings.CertificateValidation)" "Information"
            Write-Log "CRL Checking: $($certResult.CertificateSettings.CertificatePolicies.CertificateRevocation)" "Information"
        } else {
            Write-Log "Failed to configure certificate settings: $($certResult.Error)" "Warning"
        }
    }

    # 8. Configure Group Policies
    Write-Log "Configuring group policies..." "Information"
    $groupPolicyResult = Set-NPASGroupPolicies -ServerName $ServerName -GroupPolicies @("Network-Admins", "Wireless-Users", "VPN-Users", "Guest-Users") -PolicyTemplates @("High-Security", "Standard-Access", "Limited-Access")
    
    if ($groupPolicyResult.Success) {
        Write-Log "Group policies configured successfully" "Success"
        Write-Log "Group Policies: $($groupPolicyResult.GroupPolicySettings.GroupPolicies.Count)" "Information"
        Write-Log "Policy Templates: $($groupPolicyResult.GroupPolicySettings.PolicyTemplates.Count)" "Information"
    } else {
        Write-Log "Failed to configure group policies: $($groupPolicyResult.Error)" "Warning"
    }

    # 9. Configure Conditional Access
    if ($currentConfig.ConditionalAccess) {
        Write-Log "Configuring conditional access..." "Information"
        $conditionalResult = Set-NPASConditionalAccess -ServerName $ServerName -ConditionalPolicies @("High-Security", "Standard-Access", "Limited-Access") -RiskAssessment -DeviceCompliance
        
        if ($conditionalResult.Success) {
            Write-Log "Conditional access configured successfully" "Success"
            Write-Log "Conditional Policies: $($conditionalResult.ConditionalAccessSettings.ConditionalPolicies.Count)" "Information"
            Write-Log "Risk Assessment: $($conditionalResult.ConditionalAccessSettings.RiskAssessment)" "Information"
            Write-Log "Device Compliance: $($conditionalResult.ConditionalAccessSettings.DeviceCompliance)" "Information"
        } else {
            Write-Log "Failed to configure conditional access: $($conditionalResult.Error)" "Warning"
        }
    }

    # 10. Configure Device Compliance
    Write-Log "Configuring device compliance..." "Information"
    $deviceComplianceResult = Set-NPASDeviceCompliance -ServerName $ServerName -CompliancePolicies @("Antivirus", "Windows-Update", "Firewall", "BitLocker") -HealthValidation -Remediation
    
    if ($deviceComplianceResult.Success) {
        Write-Log "Device compliance configured successfully" "Success"
        Write-Log "Compliance Policies: $($deviceComplianceResult.DeviceComplianceSettings.CompliancePolicies -join ', ')" "Information"
        Write-Log "Health Validation: $($deviceComplianceResult.DeviceComplianceSettings.HealthValidation)" "Information"
        Write-Log "Remediation: $($deviceComplianceResult.DeviceComplianceSettings.Remediation)" "Information"
    } else {
        Write-Log "Failed to configure device compliance: $($deviceComplianceResult.Error)" "Warning"
    }

    # 11. Configure Risk Assessment
    if ($currentConfig.RiskAssessment) {
        Write-Log "Configuring risk assessment..." "Information"
        $riskResult = Set-NPASRiskAssessment -ServerName $ServerName -RiskFactors @("User-Behavior", "Device-Risk", "Network-Risk", "Location-Risk") -ThreatDetection -RiskMitigation
        
        if ($riskResult.Success) {
            Write-Log "Risk assessment configured successfully" "Success"
            Write-Log "Risk Factors: $($riskResult.RiskAssessmentSettings.RiskFactors -join ', ')" "Information"
            Write-Log "Threat Detection: $($riskResult.RiskAssessmentSettings.ThreatDetection)" "Information"
            Write-Log "Risk Mitigation: $($riskResult.RiskAssessmentSettings.RiskMitigation)" "Information"
        } else {
            Write-Log "Failed to configure risk assessment: $($riskResult.Error)" "Warning"
        }
    }

    # 12. Configure Threat Protection
    if ($currentConfig.ThreatProtection) {
        Write-Log "Configuring threat protection..." "Information"
        $threatResult = Set-NPASThreatProtection -ServerName $ServerName -ThreatProtectionLevel "Advanced" -SecurityMonitoring -IncidentResponse
        
        if ($threatResult.Success) {
            Write-Log "Threat protection configured successfully" "Success"
            Write-Log "Threat Protection Level: $($threatResult.ThreatProtectionSettings.ThreatProtectionLevel)" "Information"
            Write-Log "Security Monitoring: $($threatResult.ThreatProtectionSettings.SecurityMonitoring)" "Information"
            Write-Log "Incident Response: $($threatResult.ThreatProtectionSettings.IncidentResponse)" "Information"
        } else {
            Write-Log "Failed to configure threat protection: $($threatResult.Error)" "Warning"
        }
    }

    # 13. Configure Access Control
    Write-Log "Configuring access control..." "Information"
    $accessControlResult = Set-NPASAccessControl -ServerName $ServerName -AccessControlMethod "RBAC" -AccessPolicies @("Admin-Access", "User-Access", "Guest-Access") -TimeRestrictions -LocationRestrictions
    
    if ($accessControlResult.Success) {
        Write-Log "Access control configured successfully" "Success"
        Write-Log "Access Control Method: $($accessControlResult.AccessControlSettings.AccessControlMethod)" "Information"
        Write-Log "Access Policies: $($accessControlResult.AccessControlSettings.AccessPolicies.Count)" "Information"
        Write-Log "Time Restrictions: $($accessControlResult.AccessControlSettings.TimeRestrictions)" "Information"
        Write-Log "Location Restrictions: $($accessControlResult.AccessControlSettings.LocationRestrictions)" "Information"
    } else {
        Write-Log "Failed to configure access control: $($accessControlResult.Error)" "Warning"
    }

    # 14. Configure Session Security
    Write-Log "Configuring session security..." "Information"
    $sessionSecurityResult = Set-NPASSessionSecurity -ServerName $ServerName -SessionTimeout 480 -IdleTimeout 30 -SessionEncryption -SessionValidation
    
    if ($sessionSecurityResult.Success) {
        Write-Log "Session security configured successfully" "Success"
        Write-Log "Session Timeout: $($sessionSecurityResult.SessionSecuritySettings.SessionTimeout) minutes" "Information"
        Write-Log "Idle Timeout: $($sessionSecurityResult.SessionSecuritySettings.IdleTimeout) minutes" "Information"
        Write-Log "Session Encryption: $($sessionSecurityResult.SessionSecuritySettings.SessionEncryption)" "Information"
        Write-Log "Session Validation: $($sessionSecurityResult.SessionSecuritySettings.SessionValidation)" "Information"
    } else {
        Write-Log "Failed to configure session security: $($sessionSecurityResult.Error)" "Warning"
    }

    # 15. Configure Network Security
    Write-Log "Configuring network security..." "Information"
    $networkSecurityResult = Set-NPASNetworkSecurity -ServerName $ServerName -NetworkSegmentation -VLANIsolation -TrafficFiltering -IntrusionDetection
    
    if ($networkSecurityResult.Success) {
        Write-Log "Network security configured successfully" "Success"
        Write-Log "Network Segmentation: $($networkSecurityResult.NetworkSecuritySettings.NetworkSegmentation)" "Information"
        Write-Log "VLAN Isolation: $($networkSecurityResult.NetworkSecuritySettings.VLANIsolation)" "Information"
        Write-Log "Traffic Filtering: $($networkSecurityResult.NetworkSecuritySettings.TrafficFiltering)" "Information"
        Write-Log "Intrusion Detection: $($networkSecurityResult.NetworkSecuritySettings.IntrusionDetection)" "Information"
    } else {
        Write-Log "Failed to configure network security: $($networkSecurityResult.Error)" "Warning"
    }

    # 16. Configure Zero Trust (if enabled)
    if ($ZeroTrust) {
        Write-Log "Configuring Zero Trust security model..." "Information"
        $zeroTrustResult = Set-NPASZeroTrust -ServerName $ServerName -ZeroTrustPolicies @("Never-Trust", "Always-Verify", "Least-Privilege") -ContinuousVerification -LeastPrivilegeAccess -MicroSegmentation
        
        if ($zeroTrustResult.Success) {
            Write-Log "Zero Trust configured successfully" "Success"
            Write-Log "Zero Trust Policies: $($zeroTrustResult.ZeroTrustSettings.ZeroTrustPolicies -join ', ')" "Information"
            Write-Log "Continuous Verification: $($zeroTrustResult.ZeroTrustSettings.ContinuousVerification)" "Information"
            Write-Log "Least Privilege Access: $($zeroTrustResult.ZeroTrustSettings.LeastPrivilegeAccess)" "Information"
            Write-Log "Micro-Segmentation: $($zeroTrustResult.ZeroTrustSettings.MicroSegmentation)" "Information"
        } else {
            Write-Log "Failed to configure Zero Trust: $($zeroTrustResult.Error)" "Warning"
        }
    }

    # 17. Configure Security Alerts
    Write-Log "Configuring security alerts..." "Information"
    $securityAlertsResult = Set-NPASSecurityAlerts -ServerName $ServerName -AlertTypes @("Authentication-Failure", "Security-Violation", "Policy-Violation", "Threat-Detection") -NotificationMethods @("Email", "SMS", "Webhook") -AlertSeverity "High"
    
    if ($securityAlertsResult.Success) {
        Write-Log "Security alerts configured successfully" "Success"
        Write-Log "Alert Types: $($securityAlertsResult.SecurityAlertSettings.AlertTypes -join ', ')" "Information"
        Write-Log "Notification Methods: $($securityAlertsResult.SecurityAlertSettings.NotificationMethods -join ', ')" "Information"
        Write-Log "Alert Severity: $($securityAlertsResult.SecurityAlertSettings.AlertSeverity)" "Information"
    } else {
        Write-Log "Failed to configure security alerts: $($securityAlertsResult.Error)" "Warning"
    }

    # 18. Test Security Compliance
    Write-Log "Testing security compliance..." "Information"
    foreach ($standard in $ComplianceStandards) {
        $complianceTestResult = Test-NPASSecurityCompliance -ServerName $ServerName -ComplianceStandard $standard
        
        if ($complianceTestResult.Success) {
            Write-Log "Security compliance test for $standard completed successfully" "Success"
            Write-Log "Overall Compliance: $($complianceTestResult.ComplianceResults.OverallCompliance)" "Information"
            Write-Log "Compliance Score: $($complianceTestResult.ComplianceResults.ComplianceScore)" "Information"
            Write-Log "Passed Tests: $($complianceTestResult.ComplianceResults.PassedTests)" "Information"
        } else {
            Write-Log "Security compliance test for $standard failed: $($complianceTestResult.Error)" "Warning"
        }
    }

    # 19. Get Security Status
    Write-Log "Getting security status..." "Information"
    $securityStatusResult = Get-NPASSecurityStatus -ServerName $ServerName
    
    if ($securityStatusResult.Success) {
        Write-Log "Security status retrieved successfully" "Success"
        Write-Log "Security Score: $($securityStatusResult.SecurityStatus.SecurityScore)" "Information"
        Write-Log "Security Alerts: $($securityStatusResult.SecurityStatus.SecurityAlerts)" "Information"
        Write-Log "Compliance Violations: $($securityStatusResult.SecurityStatus.ComplianceViolations)" "Information"
        Write-Log "Threat Level: $($securityStatusResult.SecurityStatus.ThreatLevel)" "Information"
    } else {
        Write-Log "Failed to get security status: $($securityStatusResult.Error)" "Warning"
    }

    # 20. Get Security Logs
    Write-Log "Getting security logs..." "Information"
    $securityLogsResult = Get-NPASSecurityLogs -ServerName $ServerName -LogType "Security" -TimeRange "Last24Hours"
    
    if ($securityLogsResult.Success) {
        Write-Log "Security logs retrieved successfully" "Success"
        Write-Log "Log Type: $($securityLogsResult.LogType)" "Information"
        Write-Log "Time Range: $($securityLogsResult.TimeRange)" "Information"
        Write-Log "Log Entries: $($securityLogsResult.SecurityLogs.Count)" "Information"
    } else {
        Write-Log "Failed to get security logs: $($securityLogsResult.Error)" "Warning"
    }

    # Calculate security implementation duration
    $securityDuration = (Get-Date) - $scriptConfig.StartTime
    Write-Log "NPAS security implementation completed successfully!" "Success"
    Write-Log "Security Implementation Duration: $($securityDuration.TotalMinutes) minutes" "Information"
    Write-Log "Security Level: $SecurityLevel" "Information"
    Write-Log "Compliance Standards: $($ComplianceStandards -join ', ')" "Information"
    Write-Log "MFA Provider: $MFAProvider" "Information"
    Write-Log "Zero Trust: $ZeroTrust" "Information"

    # Display summary
    Write-Host "`n" -NoNewline
    Write-Host "=== NPAS SECURITY IMPLEMENTATION SUMMARY ===" -ForegroundColor Green
    Write-Host "Server Name: $ServerName" -ForegroundColor Cyan
    Write-Host "Security Level: $SecurityLevel" -ForegroundColor Cyan
    Write-Host "Implementation Duration: $($securityDuration.TotalMinutes) minutes" -ForegroundColor Cyan
    Write-Host "Compliance Standards: $($ComplianceStandards -join ', ')" -ForegroundColor Cyan
    Write-Host "MFA Provider: $MFAProvider" -ForegroundColor Cyan
    Write-Host "Certificate Authority: $CertificateAuthority" -ForegroundColor Cyan
    Write-Host "Zero Trust Enabled: $ZeroTrust" -ForegroundColor Cyan
    Write-Host "Log Path: $($scriptConfig.LogPath)" -ForegroundColor Cyan
    Write-Host "===========================================" -ForegroundColor Green

} catch {
    Write-Log "NPAS security implementation failed: $($_.Exception.Message)" "Error"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}
