#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Secure Active Directory

.DESCRIPTION
    Security script for Windows Active Directory Domain Services.
    Configures comprehensive security settings including audit policies,
    access control, privileged access management, and security monitoring.

.PARAMETER ServerName
    Name of the server to secure

.PARAMETER DomainName
    Name of the domain to secure

.PARAMETER SecurityLevel
    Level of security to apply

.PARAMETER IncludePermissions
    Include permission configurations

.PARAMETER IncludeAudit
    Include audit configurations

.PARAMETER IncludeCompliance
    Include compliance configurations

.PARAMETER IncludeBaselines
    Include security baselines

.PARAMETER IncludeLogging
    Include security logging

.PARAMETER IncludeComplianceSettings
    Include compliance settings

.PARAMETER IncludeSecurityPolicies
    Include security policies

.PARAMETER IncludeAccessControl
    Include access control configurations

.PARAMETER IncludeEncryption
    Include encryption configurations

.PARAMETER IncludeKeyProtection
    Include key protection configurations

.PARAMETER IncludeCertificateLifecycle
    Include certificate lifecycle configurations

.PARAMETER IncludeCrossForestTrust
    Include cross-forest trust configurations

.PARAMETER IncludeSmartcardSupport
    Include smartcard support configurations

.PARAMETER IncludeWindowsHello
    Include Windows Hello configurations

.PARAMETER IncludeBitLockerIntegration
    Include BitLocker integration configurations

.PARAMETER IncludeHSMIntegration
    Include HSM integration configurations

.PARAMETER IncludeCustomSecurity
    Include custom security configurations

.PARAMETER CustomSecurityScript
    Custom security script path

.PARAMETER OutputFormat
    Output format for security results

.PARAMETER OutputPath
    Output path for security results

.PARAMETER GenerateReport
    Generate security report

.PARAMETER ReportFormat
    Format for security report

.PARAMETER ReportPath
    Path for security report

.EXAMPLE
    .\Secure-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -SecurityLevel "Standard"

.EXAMPLE
    .\Secure-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -SecurityLevel "Comprehensive" -IncludePermissions -IncludeAudit -IncludeCompliance -IncludeBaselines -IncludeLogging -IncludeComplianceSettings -IncludeSecurityPolicies -IncludeAccessControl -IncludeEncryption -IncludeKeyProtection -IncludeCertificateLifecycle -IncludeCrossForestTrust -IncludeSmartcardSupport -IncludeWindowsHello -IncludeBitLockerIntegration -IncludeHSMIntegration -IncludeCustomSecurity -CustomSecurityScript "C:\Scripts\Custom-AD-Security.ps1" -OutputFormat "HTML" -OutputPath "C:\Reports\AD-Security-Results.html" -GenerateReport -ReportFormat "PDF" -ReportPath "C:\Reports\AD-Security-Report.pdf"

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ServerName,
    
    [Parameter(Mandatory = $true)]
    [string]$DomainName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Standard", "Comprehensive", "Maximum")]
    [string]$SecurityLevel = "Standard",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludePermissions,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAudit,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCompliance,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeBaselines,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeLogging,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeComplianceSettings,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSecurityPolicies,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAccessControl,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeEncryption,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeKeyProtection,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCertificateLifecycle,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCrossForestTrust,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSmartcardSupport,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeWindowsHello,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeBitLockerIntegration,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeHSMIntegration,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCustomSecurity,
    
    [Parameter(Mandatory = $false)]
    [string]$CustomSecurityScript,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("HTML", "PDF", "CSV", "JSON", "XML")]
    [string]$OutputFormat = "HTML",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateReport,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("HTML", "PDF", "CSV", "JSON", "XML")]
    [string]$ReportFormat = "PDF",
    
    [Parameter(Mandatory = $false)]
    [string]$ReportPath
)

# Import required modules
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $modulePath "..\..\Modules"

Import-Module "$modulesPath\AD-Core.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\AD-Security.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\AD-Monitoring.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\AD-Troubleshooting.psm1" -Force -ErrorAction Stop

# Logging function
function Write-SecurityLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] [AD-Security] $Message"
    
    switch ($Level) {
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
        "Info" { Write-Host $logMessage -ForegroundColor Cyan }
        default { Write-Host $logMessage -ForegroundColor White }
    }
}

# Error handling
$ErrorActionPreference = "Stop"

try {
    Write-SecurityLog "Starting Active Directory security configuration on $ServerName" "Info"
    Write-SecurityLog "Domain Name: $DomainName" "Info"
    Write-SecurityLog "Security Level: $SecurityLevel" "Info"
    
    # Security results
    $securityResults = @{
        ServerName = $ServerName
        DomainName = $DomainName
        SecurityLevel = $SecurityLevel
        Timestamp = Get-Date
        SecuritySteps = @()
        Issues = @()
        Recommendations = @()
        OverallResult = "Unknown"
    }
    
    # Configure security based on level
    switch ($SecurityLevel) {
        "Basic" {
            Write-SecurityLog "Applying basic Active Directory security..." "Info"
            
            # Step 1: Configure basic audit policy
            try {
                $auditPolicy = Set-ADAuditPolicy -ServerName $ServerName -AuditLevel "Basic"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Basic Audit Policy"
                    Status = "Completed"
                    Details = "Basic audit policy configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Basic audit policy configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Basic Audit Policy"
                    Status = "Failed"
                    Details = "Failed to configure basic audit policy: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure basic audit policy"
                $securityResults.Recommendations += "Check audit policy configuration parameters"
                Write-SecurityLog "Failed to configure basic audit policy: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Configure basic access control
            try {
                $accessControl = Set-ADAccessControl -ServerName $ServerName -AccessLevel "Basic"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Basic Access Control"
                    Status = "Completed"
                    Details = "Basic access control configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Basic access control configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Basic Access Control"
                    Status = "Failed"
                    Details = "Failed to configure basic access control: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure basic access control"
                $securityResults.Recommendations += "Check access control configuration parameters"
                Write-SecurityLog "Failed to configure basic access control: $($_.Exception.Message)" "Error"
            }
        }
        
        "Standard" {
            Write-SecurityLog "Applying standard Active Directory security..." "Info"
            
            # Step 1: Configure standard audit policy
            try {
                $auditPolicy = Set-ADAuditPolicy -ServerName $ServerName -AuditLevel "Standard"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Standard Audit Policy"
                    Status = "Completed"
                    Details = "Standard audit policy configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Standard audit policy configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Standard Audit Policy"
                    Status = "Failed"
                    Details = "Failed to configure standard audit policy: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure standard audit policy"
                $securityResults.Recommendations += "Check audit policy configuration parameters"
                Write-SecurityLog "Failed to configure standard audit policy: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Configure standard access control
            try {
                $accessControl = Set-ADAccessControl -ServerName $ServerName -AccessLevel "Standard"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Standard Access Control"
                    Status = "Completed"
                    Details = "Standard access control configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Standard access control configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Standard Access Control"
                    Status = "Failed"
                    Details = "Failed to configure standard access control: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure standard access control"
                $securityResults.Recommendations += "Check access control configuration parameters"
                Write-SecurityLog "Failed to configure standard access control: $($_.Exception.Message)" "Error"
            }
            
            # Step 3: Configure standard privileged access management
            try {
                $pam = Set-ADPrivilegedAccess -ServerName $ServerName -PAMLevel "Standard"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Standard Privileged Access Management"
                    Status = "Completed"
                    Details = "Standard privileged access management configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Standard privileged access management configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Standard Privileged Access Management"
                    Status = "Failed"
                    Details = "Failed to configure standard privileged access management: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure standard privileged access management"
                $securityResults.Recommendations += "Check privileged access management configuration parameters"
                Write-SecurityLog "Failed to configure standard privileged access management: $($_.Exception.Message)" "Error"
            }
            
            # Step 4: Configure standard security baseline
            try {
                $securityBaseline = Set-ADSecurityBaseline -ServerName $ServerName -BaselineType "CIS"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Standard Security Baseline"
                    Status = "Completed"
                    Details = "Standard security baseline configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Standard security baseline configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Standard Security Baseline"
                    Status = "Failed"
                    Details = "Failed to configure standard security baseline: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure standard security baseline"
                $securityResults.Recommendations += "Check security baseline configuration parameters"
                Write-SecurityLog "Failed to configure standard security baseline: $($_.Exception.Message)" "Error"
            }
        }
        
        "Comprehensive" {
            Write-SecurityLog "Applying comprehensive Active Directory security..." "Info"
            
            # Step 1: Configure comprehensive audit policy
            try {
                $auditPolicy = Set-ADAuditPolicy -ServerName $ServerName -AuditLevel "Comprehensive"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Comprehensive Audit Policy"
                    Status = "Completed"
                    Details = "Comprehensive audit policy configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Comprehensive audit policy configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Comprehensive Audit Policy"
                    Status = "Failed"
                    Details = "Failed to configure comprehensive audit policy: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure comprehensive audit policy"
                $securityResults.Recommendations += "Check audit policy configuration parameters"
                Write-SecurityLog "Failed to configure comprehensive audit policy: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Configure comprehensive access control
            try {
                $accessControl = Set-ADAccessControl -ServerName $ServerName -AccessLevel "Comprehensive"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Comprehensive Access Control"
                    Status = "Completed"
                    Details = "Comprehensive access control configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Comprehensive access control configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Comprehensive Access Control"
                    Status = "Failed"
                    Details = "Failed to configure comprehensive access control: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure comprehensive access control"
                $securityResults.Recommendations += "Check access control configuration parameters"
                Write-SecurityLog "Failed to configure comprehensive access control: $($_.Exception.Message)" "Error"
            }
            
            # Step 3: Configure comprehensive privileged access management
            try {
                $pam = Set-ADPrivilegedAccess -ServerName $ServerName -PAMLevel "Comprehensive"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Comprehensive Privileged Access Management"
                    Status = "Completed"
                    Details = "Comprehensive privileged access management configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Comprehensive privileged access management configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Comprehensive Privileged Access Management"
                    Status = "Failed"
                    Details = "Failed to configure comprehensive privileged access management: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure comprehensive privileged access management"
                $securityResults.Recommendations += "Check privileged access management configuration parameters"
                Write-SecurityLog "Failed to configure comprehensive privileged access management: $($_.Exception.Message)" "Error"
            }
            
            # Step 4: Configure comprehensive security baseline
            try {
                $securityBaseline = Set-ADSecurityBaseline -ServerName $ServerName -BaselineType "CIS"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Comprehensive Security Baseline"
                    Status = "Completed"
                    Details = "Comprehensive security baseline configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Comprehensive security baseline configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Comprehensive Security Baseline"
                    Status = "Failed"
                    Details = "Failed to configure comprehensive security baseline: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure comprehensive security baseline"
                $securityResults.Recommendations += "Check security baseline configuration parameters"
                Write-SecurityLog "Failed to configure comprehensive security baseline: $($_.Exception.Message)" "Error"
            }
            
            # Step 5: Configure comprehensive Kerberos security
            try {
                $kerberosSecurity = Set-ADKerberosSecurity -ServerName $ServerName -KerberosLevel "Comprehensive"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Comprehensive Kerberos Security"
                    Status = "Completed"
                    Details = "Comprehensive Kerberos security configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Comprehensive Kerberos security configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Comprehensive Kerberos Security"
                    Status = "Failed"
                    Details = "Failed to configure comprehensive Kerberos security: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure comprehensive Kerberos security"
                $securityResults.Recommendations += "Check Kerberos security configuration parameters"
                Write-SecurityLog "Failed to configure comprehensive Kerberos security: $($_.Exception.Message)" "Error"
            }
            
            # Step 6: Configure comprehensive LDAPS security
            try {
                $ldapsSecurity = Set-ADLDAPSSecurity -ServerName $ServerName -LDAPSLevel "Comprehensive"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Comprehensive LDAPS Security"
                    Status = "Completed"
                    Details = "Comprehensive LDAPS security configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Comprehensive LDAPS security configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Comprehensive LDAPS Security"
                    Status = "Failed"
                    Details = "Failed to configure comprehensive LDAPS security: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure comprehensive LDAPS security"
                $securityResults.Recommendations += "Check LDAPS security configuration parameters"
                Write-SecurityLog "Failed to configure comprehensive LDAPS security: $($_.Exception.Message)" "Error"
            }
            
            # Step 7: Configure comprehensive trust security
            try {
                $trustSecurity = Set-ADTrustSecurity -ServerName $ServerName -TrustLevel "Comprehensive"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Comprehensive Trust Security"
                    Status = "Completed"
                    Details = "Comprehensive trust security configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Comprehensive trust security configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Comprehensive Trust Security"
                    Status = "Failed"
                    Details = "Failed to configure comprehensive trust security: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure comprehensive trust security"
                $securityResults.Recommendations += "Check trust security configuration parameters"
                Write-SecurityLog "Failed to configure comprehensive trust security: $($_.Exception.Message)" "Error"
            }
        }
        
        "Maximum" {
            Write-SecurityLog "Applying maximum Active Directory security..." "Info"
            
            # Step 1: Configure maximum audit policy
            try {
                $auditPolicy = Set-ADAuditPolicy -ServerName $ServerName -AuditLevel "Maximum"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Maximum Audit Policy"
                    Status = "Completed"
                    Details = "Maximum audit policy configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Maximum audit policy configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Maximum Audit Policy"
                    Status = "Failed"
                    Details = "Failed to configure maximum audit policy: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure maximum audit policy"
                $securityResults.Recommendations += "Check audit policy configuration parameters"
                Write-SecurityLog "Failed to configure maximum audit policy: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Configure maximum access control
            try {
                $accessControl = Set-ADAccessControl -ServerName $ServerName -AccessLevel "Maximum"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Maximum Access Control"
                    Status = "Completed"
                    Details = "Maximum access control configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Maximum access control configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Maximum Access Control"
                    Status = "Failed"
                    Details = "Failed to configure maximum access control: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure maximum access control"
                $securityResults.Recommendations += "Check access control configuration parameters"
                Write-SecurityLog "Failed to configure maximum access control: $($_.Exception.Message)" "Error"
            }
            
            # Step 3: Configure maximum privileged access management
            try {
                $pam = Set-ADPrivilegedAccess -ServerName $ServerName -PAMLevel "Maximum"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Maximum Privileged Access Management"
                    Status = "Completed"
                    Details = "Maximum privileged access management configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Maximum privileged access management configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Maximum Privileged Access Management"
                    Status = "Failed"
                    Details = "Failed to configure maximum privileged access management: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure maximum privileged access management"
                $securityResults.Recommendations += "Check privileged access management configuration parameters"
                Write-SecurityLog "Failed to configure maximum privileged access management: $($_.Exception.Message)" "Error"
            }
            
            # Step 4: Configure maximum security baseline
            try {
                $securityBaseline = Set-ADSecurityBaseline -ServerName $ServerName -BaselineType "CIS"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Maximum Security Baseline"
                    Status = "Completed"
                    Details = "Maximum security baseline configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Maximum security baseline configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Maximum Security Baseline"
                    Status = "Failed"
                    Details = "Failed to configure maximum security baseline: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure maximum security baseline"
                $securityResults.Recommendations += "Check security baseline configuration parameters"
                Write-SecurityLog "Failed to configure maximum security baseline: $($_.Exception.Message)" "Error"
            }
            
            # Step 5: Configure maximum Kerberos security
            try {
                $kerberosSecurity = Set-ADKerberosSecurity -ServerName $ServerName -KerberosLevel "Maximum"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Maximum Kerberos Security"
                    Status = "Completed"
                    Details = "Maximum Kerberos security configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Maximum Kerberos security configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Maximum Kerberos Security"
                    Status = "Failed"
                    Details = "Failed to configure maximum Kerberos security: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure maximum Kerberos security"
                $securityResults.Recommendations += "Check Kerberos security configuration parameters"
                Write-SecurityLog "Failed to configure maximum Kerberos security: $($_.Exception.Message)" "Error"
            }
            
            # Step 6: Configure maximum LDAPS security
            try {
                $ldapsSecurity = Set-ADLDAPSSecurity -ServerName $ServerName -LDAPSLevel "Maximum"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Maximum LDAPS Security"
                    Status = "Completed"
                    Details = "Maximum LDAPS security configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Maximum LDAPS security configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Maximum LDAPS Security"
                    Status = "Failed"
                    Details = "Failed to configure maximum LDAPS security: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure maximum LDAPS security"
                $securityResults.Recommendations += "Check LDAPS security configuration parameters"
                Write-SecurityLog "Failed to configure maximum LDAPS security: $($_.Exception.Message)" "Error"
            }
            
            # Step 7: Configure maximum trust security
            try {
                $trustSecurity = Set-ADTrustSecurity -ServerName $ServerName -TrustLevel "Maximum"
                
                $securityResults.SecuritySteps += @{
                    Step = "Configure Maximum Trust Security"
                    Status = "Completed"
                    Details = "Maximum trust security configured successfully"
                    Severity = "Info"
                }
                Write-SecurityLog "Maximum trust security configured successfully" "Success"
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Maximum Trust Security"
                    Status = "Failed"
                    Details = "Failed to configure maximum trust security: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Failed to configure maximum trust security"
                $securityResults.Recommendations += "Check trust security configuration parameters"
                Write-SecurityLog "Failed to configure maximum trust security: $($_.Exception.Message)" "Error"
            }
            
            # Step 8: Configure custom security settings
            if ($IncludeCustomSecurity -and $CustomSecurityScript) {
                try {
                    if (Test-Path $CustomSecurityScript) {
                        & $CustomSecurityScript -ServerName $ServerName -DomainName $DomainName
                        
                        $securityResults.SecuritySteps += @{
                            Step = "Configure Custom Security Settings"
                            Status = "Completed"
                            Details = "Custom security settings configured successfully"
                            Severity = "Info"
                        }
                        Write-SecurityLog "Custom security settings configured successfully" "Success"
                    } else {
                        $securityResults.SecuritySteps += @{
                            Step = "Configure Custom Security Settings"
                            Status = "Skipped"
                            Details = "Custom security script not found"
                            Severity = "Warning"
                        }
                        Write-SecurityLog "Custom security script not found: $CustomSecurityScript" "Warning"
                    }
                }
                catch {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Custom Security Settings"
                        Status = "Failed"
                        Details = "Failed to configure custom security settings: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $securityResults.Issues += "Failed to configure custom security settings"
                    $securityResults.Recommendations += "Check custom security script"
                    Write-SecurityLog "Failed to configure custom security settings: $($_.Exception.Message)" "Error"
                }
            }
        }
        
        default {
            Write-SecurityLog "Unknown security level: $SecurityLevel" "Error"
            $securityResults.SecuritySteps += @{
                Step = "Security Level Validation"
                Status = "Failed"
                Details = "Unknown security level: $SecurityLevel"
                Severity = "Error"
            }
            $securityResults.Issues += "Unknown security level: $SecurityLevel"
            $securityResults.Recommendations += "Use a valid security level"
        }
    }
    
    # Determine overall result
    $failedSteps = $securityResults.SecuritySteps | Where-Object { $_.Status -eq "Failed" }
    if ($failedSteps.Count -eq 0) {
        $securityResults.OverallResult = "Success"
    } elseif ($failedSteps.Count -lt $securityResults.SecuritySteps.Count / 2) {
        $securityResults.OverallResult = "Partial Success"
    } else {
        $securityResults.OverallResult = "Failed"
    }
    
    # Summary
    Write-SecurityLog "=== SECURITY CONFIGURATION SUMMARY ===" "Info"
    Write-SecurityLog "Server Name: $ServerName" "Info"
    Write-SecurityLog "Domain Name: $DomainName" "Info"
    Write-SecurityLog "Security Level: $SecurityLevel" "Info"
    Write-SecurityLog "Overall Result: $($securityResults.OverallResult)" "Info"
    Write-SecurityLog "Security Steps: $($securityResults.SecuritySteps.Count)" "Info"
    Write-SecurityLog "Issues: $($securityResults.Issues.Count)" "Info"
    Write-SecurityLog "Recommendations: $($securityResults.Recommendations.Count)" "Info"
    
    if ($securityResults.Issues.Count -gt 0) {
        Write-SecurityLog "Issues:" "Warning"
        foreach ($issue in $securityResults.Issues) {
            Write-SecurityLog "  - $issue" "Warning"
        }
    }
    
    if ($securityResults.Recommendations.Count -gt 0) {
        Write-SecurityLog "Recommendations:" "Info"
        foreach ($recommendation in $securityResults.Recommendations) {
            Write-SecurityLog "  - $recommendation" "Info"
        }
    }
    
    Write-SecurityLog "Active Directory security configuration completed" "Success"
    
    return $securityResults
}
catch {
    Write-SecurityLog "Active Directory security configuration failed: $($_.Exception.Message)" "Error"
    Write-SecurityLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script configures comprehensive security for Windows Active Directory Domain Services
    including audit policies, access control, privileged access management, and security monitoring.
    
    Features:
    - Basic Security Configuration
    - Standard Security Configuration
    - Comprehensive Security Configuration
    - Maximum Security Configuration
    - Audit Policy Configuration
    - Access Control Configuration
    - Privileged Access Management
    - Security Baseline Configuration
    - Kerberos Security Configuration
    - LDAPS Security Configuration
    - Trust Security Configuration
    - Custom Security Configuration
    
    Prerequisites:
    - Windows Server 2016 or later
    - Active Directory Domain Services
    - Administrative privileges
    - Network connectivity
    - Sufficient storage space
    - Sufficient memory and CPU resources
    
    Dependencies:
    - AD-Core.psm1
    - AD-Security.psm1
    - AD-Monitoring.psm1
    - AD-Troubleshooting.psm1
    
    Usage Examples:
    .\Secure-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -SecurityLevel "Standard"
    .\Secure-ActiveDirectory.ps1 -ServerName "DC-SERVER01" -DomainName "contoso.com" -SecurityLevel "Comprehensive" -IncludePermissions -IncludeAudit -IncludeCompliance -IncludeBaselines -IncludeLogging -IncludeComplianceSettings -IncludeSecurityPolicies -IncludeAccessControl -IncludeEncryption -IncludeKeyProtection -IncludeCertificateLifecycle -IncludeCrossForestTrust -IncludeSmartcardSupport -IncludeWindowsHello -IncludeBitLockerIntegration -IncludeHSMIntegration -IncludeCustomSecurity -CustomSecurityScript "C:\Scripts\Custom-AD-Security.ps1" -OutputFormat "HTML" -OutputPath "C:\Reports\AD-Security-Results.html" -GenerateReport -ReportFormat "PDF" -ReportPath "C:\Reports\AD-Security-Report.pdf"
    
    Output:
    - Console logging with color-coded messages
    - Security configuration results summary
    - Detailed security configuration steps
    - Issues and recommendations
    - Comprehensive error handling
    
    Security Considerations:
    - Requires administrative privileges
    - Configures secure AD settings
    - Implements security baselines
    - Enables security logging
    - Configures security compliance settings
    
    Performance Impact:
    - Minimal impact during security configuration
    - Non-destructive operations
    - Configurable security scope
    - Resource-aware security configuration
#>
