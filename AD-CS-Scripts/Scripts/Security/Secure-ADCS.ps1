#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Secure AD CS

.DESCRIPTION
    Security configuration script for Windows Active Directory Certificate Services.
    Configures security baselines, HSM integration, template security, role separation,
    audit configuration, and compliance settings.

.PARAMETER ServerName
    Name of the server to secure

.PARAMETER SecurityLevel
    Level of security to apply

.PARAMETER HSMProvider
    HSM provider to use

.PARAMETER HSMProviderPath
    Path to HSM provider

.PARAMETER HSMProviderConfig
    HSM provider configuration

.PARAMETER HSMProviderKey
    HSM provider key

.PARAMETER HSMProviderCert
    HSM provider certificate

.PARAMETER HSMProviderPassword
    HSM provider password

.PARAMETER HSMProviderUser
    HSM provider user

.PARAMETER HSMProviderDomain
    HSM provider domain

.PARAMETER HSMProviderGroup
    HSM provider group

.PARAMETER HSMProviderRole
    HSM provider role

.PARAMETER HSMProviderPolicy
    HSM provider policy

.PARAMETER HSMProviderAudit
    HSM provider audit

.PARAMETER HSMProviderCompliance
    HSM provider compliance

.PARAMETER HSMProviderGovernance
    HSM provider governance

.PARAMETER HSMProviderMonitoring
    HSM provider monitoring

.PARAMETER HSMProviderTroubleshooting
    HSM provider troubleshooting

.PARAMETER HSMProviderReporting
    HSM provider reporting

.PARAMETER HSMProviderIntegration
    HSM provider integration

.PARAMETER HSMProviderManagement
    HSM provider management

.PARAMETER HSMProviderOperations
    HSM provider operations

.PARAMETER HSMProviderMaintenance
    HSM provider maintenance

.PARAMETER HSMProviderSupport
    HSM provider support

.PARAMETER HSMProviderDocumentation
    HSM provider documentation

.PARAMETER HSMProviderTraining
    HSM provider training

.PARAMETER HSMProviderBestPractices
    HSM provider best practices

.PARAMETER HSMProviderTroubleshootingGuide
    HSM provider troubleshooting guide

.PARAMETER HSMProviderPerformanceOptimization
    HSM provider performance optimization

.PARAMETER HSMProviderSecurityConsiderations
    HSM provider security considerations

.PARAMETER HSMProviderComplianceGovernance
    HSM provider compliance governance

.PARAMETER HSMProviderIntegration
    HSM provider integration

.PARAMETER HSMProviderSupport
    HSM provider support

.PARAMETER TemplateSecurityPolicy
    Template security policy

.PARAMETER TemplateSecurityLevel
    Template security level

.PARAMETER TemplateSecurityBaseline
    Template security baseline

.PARAMETER TemplateSecurityCompliance
    Template security compliance

.PARAMETER TemplateSecurityAudit
    Template security audit

.PARAMETER TemplateSecurityMonitoring
    Template security monitoring

.PARAMETER TemplateSecurityReporting
    Template security reporting

.PARAMETER TemplateSecurityIntegration
    Template security integration

.PARAMETER TemplateSecurityManagement
    Template security management

.PARAMETER TemplateSecurityOperations
    Template security operations

.PARAMETER TemplateSecurityMaintenance
    Template security maintenance

.PARAMETER TemplateSecuritySupport
    Template security support

.PARAMETER TemplateSecurityDocumentation
    Template security documentation

.PARAMETER TemplateSecurityTraining
    Template security training

.PARAMETER TemplateSecurityBestPractices
    Template security best practices

.PARAMETER TemplateSecurityTroubleshootingGuide
    Template security troubleshooting guide

.PARAMETER TemplateSecurityPerformanceOptimization
    Template security performance optimization

.PARAMETER TemplateSecuritySecurityConsiderations
    Template security security considerations

.PARAMETER TemplateSecurityComplianceGovernance
    Template security compliance governance

.PARAMETER TemplateSecurityIntegration
    Template security integration

.PARAMETER TemplateSecuritySupport
    Template security support

.PARAMETER RoleSeparationPolicy
    Role separation policy

.PARAMETER RoleSeparationLevel
    Role separation level

.PARAMETER RoleSeparationBaseline
    Role separation baseline

.PARAMETER RoleSeparationCompliance
    Role separation compliance

.PARAMETER RoleSeparationAudit
    Role separation audit

.PARAMETER RoleSeparationMonitoring
    Role separation monitoring

.PARAMETER RoleSeparationReporting
    Role separation reporting

.PARAMETER RoleSeparationIntegration
    Role separation integration

.PARAMETER RoleSeparationManagement
    Role separation management

.PARAMETER RoleSeparationOperations
    Role separation operations

.PARAMETER RoleSeparationMaintenance
    Role separation maintenance

.PARAMETER RoleSeparationSupport
    Role separation support

.PARAMETER RoleSeparationDocumentation
    Role separation documentation

.PARAMETER RoleSeparationTraining
    Role separation training

.PARAMETER RoleSeparationBestPractices
    Role separation best practices

.PARAMETER RoleSeparationTroubleshootingGuide
    Role separation troubleshooting guide

.PARAMETER RoleSeparationPerformanceOptimization
    Role separation performance optimization

.PARAMETER RoleSeparationSecurityConsiderations
    Role separation security considerations

.PARAMETER RoleSeparationComplianceGovernance
    Role separation compliance governance

.PARAMETER RoleSeparationIntegration
    Role separation integration

.PARAMETER RoleSeparationSupport
    Role separation support

.PARAMETER AuditPolicy
    Audit policy

.PARAMETER AuditLevel
    Audit level

.PARAMETER AuditBaseline
    Audit baseline

.PARAMETER AuditCompliance
    Audit compliance

.PARAMETER AuditMonitoring
    Audit monitoring

.PARAMETER AuditReporting
    Audit reporting

.PARAMETER AuditIntegration
    Audit integration

.PARAMETER AuditManagement
    Audit management

.PARAMETER AuditOperations
    Audit operations

.PARAMETER AuditMaintenance
    Audit maintenance

.PARAMETER AuditSupport
    Audit support

.PARAMETER AuditDocumentation
    Audit documentation

.PARAMETER AuditTraining
    Audit training

.PARAMETER AuditBestPractices
    Audit best practices

.PARAMETER AuditTroubleshootingGuide
    Audit troubleshooting guide

.PARAMETER AuditPerformanceOptimization
    Audit performance optimization

.PARAMETER AuditSecurityConsiderations
    Audit security considerations

.PARAMETER AuditComplianceGovernance
    Audit compliance governance

.PARAMETER AuditIntegration
    Audit integration

.PARAMETER AuditSupport
    Audit support

.PARAMETER CompliancePolicy
    Compliance policy

.PARAMETER ComplianceLevel
    Compliance level

.PARAMETER ComplianceBaseline
    Compliance baseline

.PARAMETER ComplianceAudit
    Compliance audit

.PARAMETER ComplianceMonitoring
    Compliance monitoring

.PARAMETER ComplianceReporting
    Compliance reporting

.PARAMETER ComplianceIntegration
    Compliance integration

.PARAMETER ComplianceManagement
    Compliance management

.PARAMETER ComplianceOperations
    Compliance operations

.PARAMETER ComplianceMaintenance
    Compliance maintenance

.PARAMETER ComplianceSupport
    Compliance support

.PARAMETER ComplianceDocumentation
    Compliance documentation

.PARAMETER ComplianceTraining
    Compliance training

.PARAMETER ComplianceBestPractices
    Compliance best practices

.PARAMETER ComplianceTroubleshootingGuide
    Compliance troubleshooting guide

.PARAMETER CompliancePerformanceOptimization
    Compliance performance optimization

.PARAMETER ComplianceSecurityConsiderations
    Compliance security considerations

.PARAMETER ComplianceComplianceGovernance
    Compliance compliance governance

.PARAMETER ComplianceIntegration
    Compliance integration

.PARAMETER ComplianceSupport
    Compliance support

.EXAMPLE
    .\Secure-ADCS.ps1 -ServerName "CA-SERVER01" -SecurityLevel "High"

.EXAMPLE
    .\Secure-ADCS.ps1 -ServerName "CA-SERVER01" -SecurityLevel "High" -HSMProvider "Thales" -HSMProviderPath "C:\HSM\Thales"

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ServerName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Standard", "High", "Maximum")]
    [string]$SecurityLevel = "Standard",
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProvider,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderPath,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderConfig,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderKey,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderCert,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderPassword,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderUser,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderDomain,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderGroup,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderRole,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderPolicy,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderAudit,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderCompliance,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderGovernance,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderMonitoring,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderTroubleshooting,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderReporting,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderIntegration,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderManagement,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderOperations,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderMaintenance,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderSupport,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderDocumentation,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderTraining,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderBestPractices,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderTroubleshootingGuide,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderPerformanceOptimization,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderSecurityConsiderations,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderComplianceGovernance,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderIntegration,
    
    [Parameter(Mandatory = $false)]
    [string]$HSMProviderSupport,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityPolicy,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityLevel,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityBaseline,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityCompliance,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityAudit,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityMonitoring,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityReporting,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityIntegration,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityManagement,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityOperations,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityMaintenance,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecuritySupport,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityDocumentation,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityTraining,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityBestPractices,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityTroubleshootingGuide,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityPerformanceOptimization,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecuritySecurityConsiderations,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityComplianceGovernance,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecurityIntegration,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplateSecuritySupport,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationPolicy,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationLevel,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationBaseline,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationCompliance,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationAudit,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationMonitoring,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationReporting,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationIntegration,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationManagement,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationOperations,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationMaintenance,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationSupport,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationDocumentation,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationTraining,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationBestPractices,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationTroubleshootingGuide,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationPerformanceOptimization,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationSecurityConsiderations,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationComplianceGovernance,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationIntegration,
    
    [Parameter(Mandatory = $false)]
    [string]$RoleSeparationSupport,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditPolicy,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditLevel,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditBaseline,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditCompliance,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditMonitoring,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditReporting,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditIntegration,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditManagement,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditOperations,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditMaintenance,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditSupport,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditDocumentation,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditTraining,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditBestPractices,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditTroubleshootingGuide,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditPerformanceOptimization,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditSecurityConsiderations,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditComplianceGovernance,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditIntegration,
    
    [Parameter(Mandatory = $false)]
    [string]$AuditSupport,
    
    [Parameter(Mandatory = $false)]
    [string]$CompliancePolicy,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceLevel,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceBaseline,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceAudit,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceMonitoring,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceReporting,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceIntegration,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceManagement,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceOperations,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceMaintenance,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceSupport,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceDocumentation,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceTraining,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceBestPractices,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceTroubleshootingGuide,
    
    [Parameter(Mandatory = $false)]
    [string]$CompliancePerformanceOptimization,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceSecurityConsiderations,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceComplianceGovernance,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceIntegration,
    
    [Parameter(Mandatory = $false)]
    [string]$ComplianceSupport
)

# Import required modules
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $modulePath "..\..\Modules"

Import-Module "$modulesPath\ADCS-Core.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Security.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Monitoring.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Troubleshooting.psm1" -Force -ErrorAction Stop

# Logging function
function Write-SecurityLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] [ADCS-Security] $Message"
    
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
    Write-SecurityLog "Starting AD CS security configuration on $ServerName" "Info"
    Write-SecurityLog "Security Level: $SecurityLevel" "Info"
    
    # Security results
    $securityResults = @{
        ServerName = $ServerName
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
            Write-SecurityLog "Applying basic security configuration..." "Info"
            
            # Step 1: Configure basic template security
            try {
                $templateSecurityResult = Set-TemplateSecurity -TemplateName "User" -TemplateSecurityPolicy "Basic" -TemplateSecurityLevel "Basic" -TemplateSecurityBaseline "Basic" -TemplateSecurityCompliance "Basic" -TemplateSecurityAudit "Basic" -TemplateSecurityMonitoring "Basic" -TemplateSecurityReporting "Basic" -TemplateSecurityIntegration "Basic" -TemplateSecurityManagement "Basic" -TemplateSecurityOperations "Basic" -TemplateSecurityMaintenance "Basic" -TemplateSecuritySupport "Basic" -TemplateSecurityDocumentation "Basic" -TemplateSecurityTraining "Basic" -TemplateSecurityBestPractices "Basic" -TemplateSecurityTroubleshootingGuide "Basic" -TemplateSecurityPerformanceOptimization "Basic" -TemplateSecuritySecurityConsiderations "Basic" -TemplateSecurityComplianceGovernance "Basic" -TemplateSecurityIntegration "Basic" -TemplateSecuritySupport "Basic"
                
                if ($templateSecurityResult) {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Template Security (Basic)"
                        Status = "Completed"
                        Details = "Template security configured with basic settings"
                        Severity = "Info"
                    }
                    Write-SecurityLog "Template security configured with basic settings" "Success"
                } else {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Template Security (Basic)"
                        Status = "Failed"
                        Details = "Failed to configure template security"
                        Severity = "Error"
                    }
                    $securityResults.Issues += "Failed to configure template security"
                    $securityResults.Recommendations += "Check template security configuration parameters"
                    Write-SecurityLog "Failed to configure template security" "Error"
                }
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Template Security (Basic)"
                    Status = "Failed"
                    Details = "Exception during template security configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Exception during template security configuration"
                $securityResults.Recommendations += "Check error logs and template security parameters"
                Write-SecurityLog "Exception during template security configuration: $($_.Exception.Message)" "Error"
            }
        }
        
        "Standard" {
            Write-SecurityLog "Applying standard security configuration..." "Info"
            
            # Step 1: Configure template security
            try {
                $templateSecurityResult = Set-TemplateSecurity -TemplateName "User" -TemplateSecurityPolicy "Standard" -TemplateSecurityLevel "Standard" -TemplateSecurityBaseline "CIS" -TemplateSecurityCompliance "Standard" -TemplateSecurityAudit "Standard" -TemplateSecurityMonitoring "Standard" -TemplateSecurityReporting "Standard" -TemplateSecurityIntegration "Standard" -TemplateSecurityManagement "Standard" -TemplateSecurityOperations "Standard" -TemplateSecurityMaintenance "Standard" -TemplateSecuritySupport "Standard" -TemplateSecurityDocumentation "Standard" -TemplateSecurityTraining "Standard" -TemplateSecurityBestPractices "Standard" -TemplateSecurityTroubleshootingGuide "Standard" -TemplateSecurityPerformanceOptimization "Standard" -TemplateSecuritySecurityConsiderations "Standard" -TemplateSecurityComplianceGovernance "Standard" -TemplateSecurityIntegration "Standard" -TemplateSecuritySupport "Standard"
                
                if ($templateSecurityResult) {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Template Security (Standard)"
                        Status = "Completed"
                        Details = "Template security configured with standard settings"
                        Severity = "Info"
                    }
                    Write-SecurityLog "Template security configured with standard settings" "Success"
                } else {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Template Security (Standard)"
                        Status = "Failed"
                        Details = "Failed to configure template security"
                        Severity = "Error"
                    }
                    $securityResults.Issues += "Failed to configure template security"
                    $securityResults.Recommendations += "Check template security configuration parameters"
                    Write-SecurityLog "Failed to configure template security" "Error"
                }
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Template Security (Standard)"
                    Status = "Failed"
                    Details = "Exception during template security configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Exception during template security configuration"
                $securityResults.Recommendations += "Check error logs and template security parameters"
                Write-SecurityLog "Exception during template security configuration: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Configure role separation
            try {
                $roleSeparationResult = Set-RoleSeparation -ServerName $ServerName -RoleSeparationPolicy "Standard" -RoleSeparationLevel "Standard" -RoleSeparationBaseline "CIS" -RoleSeparationCompliance "Standard" -RoleSeparationAudit "Standard" -RoleSeparationMonitoring "Standard" -RoleSeparationReporting "Standard" -RoleSeparationIntegration "Standard" -RoleSeparationManagement "Standard" -RoleSeparationOperations "Standard" -RoleSeparationMaintenance "Standard" -RoleSeparationSupport "Standard" -RoleSeparationDocumentation "Standard" -RoleSeparationTraining "Standard" -RoleSeparationBestPractices "Standard" -RoleSeparationTroubleshootingGuide "Standard" -RoleSeparationPerformanceOptimization "Standard" -RoleSeparationSecurityConsiderations "Standard" -RoleSeparationComplianceGovernance "Standard" -RoleSeparationIntegration "Standard" -RoleSeparationSupport "Standard"
                
                if ($roleSeparationResult) {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Role Separation (Standard)"
                        Status = "Completed"
                        Details = "Role separation configured with standard settings"
                        Severity = "Info"
                    }
                    Write-SecurityLog "Role separation configured with standard settings" "Success"
                } else {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Role Separation (Standard)"
                        Status = "Failed"
                        Details = "Failed to configure role separation"
                        Severity = "Error"
                    }
                    $securityResults.Issues += "Failed to configure role separation"
                    $securityResults.Recommendations += "Check role separation configuration parameters"
                    Write-SecurityLog "Failed to configure role separation" "Error"
                }
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Role Separation (Standard)"
                    Status = "Failed"
                    Details = "Exception during role separation configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Exception during role separation configuration"
                $securityResults.Recommendations += "Check error logs and role separation parameters"
                Write-SecurityLog "Exception during role separation configuration: $($_.Exception.Message)" "Error"
            }
        }
        
        "High" {
            Write-SecurityLog "Applying high security configuration..." "Info"
            
            # Step 1: Configure HSM integration
            if ($HSMProvider) {
                try {
                    $hsmResult = Install-HSMProvider -ServerName $ServerName -HSMProvider $HSMProvider -HSMProviderPath $HSMProviderPath -HSMProviderConfig $HSMProviderConfig -HSMProviderKey $HSMProviderKey -HSMProviderCert $HSMProviderCert -HSMProviderPassword $HSMProviderPassword -HSMProviderUser $HSMProviderUser -HSMProviderDomain $HSMProviderDomain -HSMProviderGroup $HSMProviderGroup -HSMProviderRole $HSMProviderRole -HSMProviderPolicy $HSMProviderPolicy -HSMProviderAudit $HSMProviderAudit -HSMProviderCompliance $HSMProviderCompliance -HSMProviderGovernance $HSMProviderGovernance -HSMProviderMonitoring $HSMProviderMonitoring -HSMProviderTroubleshooting $HSMProviderTroubleshooting -HSMProviderReporting $HSMProviderReporting -HSMProviderIntegration $HSMProviderIntegration -HSMProviderManagement $HSMProviderManagement -HSMProviderOperations $HSMProviderOperations -HSMProviderMaintenance $HSMProviderMaintenance -HSMProviderSupport $HSMProviderSupport -HSMProviderDocumentation $HSMProviderDocumentation -HSMProviderTraining $HSMProviderTraining -HSMProviderBestPractices $HSMProviderBestPractices -HSMProviderTroubleshootingGuide $HSMProviderTroubleshootingGuide -HSMProviderPerformanceOptimization $HSMProviderPerformanceOptimization -HSMProviderSecurityConsiderations $HSMProviderSecurityConsiderations -HSMProviderComplianceGovernance $HSMProviderComplianceGovernance -HSMProviderIntegration $HSMProviderIntegration -HSMProviderSupport $HSMProviderSupport
                    
                    if ($hsmResult) {
                        $securityResults.SecuritySteps += @{
                            Step = "Configure HSM Integration"
                            Status = "Completed"
                            Details = "HSM integration configured successfully"
                            Severity = "Info"
                        }
                        Write-SecurityLog "HSM integration configured successfully" "Success"
                    } else {
                        $securityResults.SecuritySteps += @{
                            Step = "Configure HSM Integration"
                            Status = "Failed"
                            Details = "Failed to configure HSM integration"
                            Severity = "Error"
                        }
                        $securityResults.Issues += "Failed to configure HSM integration"
                        $securityResults.Recommendations += "Check HSM configuration parameters"
                        Write-SecurityLog "Failed to configure HSM integration" "Error"
                    }
                }
                catch {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure HSM Integration"
                        Status = "Failed"
                        Details = "Exception during HSM configuration: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $securityResults.Issues += "Exception during HSM configuration"
                    $securityResults.Recommendations += "Check error logs and HSM parameters"
                    Write-SecurityLog "Exception during HSM configuration: $($_.Exception.Message)" "Error"
                }
            }
            
            # Step 2: Configure template security
            try {
                $templateSecurityResult = Set-TemplateSecurity -TemplateName "User" -TemplateSecurityPolicy "High" -TemplateSecurityLevel "High" -TemplateSecurityBaseline "CIS" -TemplateSecurityCompliance "High" -TemplateSecurityAudit "High" -TemplateSecurityMonitoring "High" -TemplateSecurityReporting "High" -TemplateSecurityIntegration "High" -TemplateSecurityManagement "High" -TemplateSecurityOperations "High" -TemplateSecurityMaintenance "High" -TemplateSecuritySupport "High" -TemplateSecurityDocumentation "High" -TemplateSecurityTraining "High" -TemplateSecurityBestPractices "High" -TemplateSecurityTroubleshootingGuide "High" -TemplateSecurityPerformanceOptimization "High" -TemplateSecuritySecurityConsiderations "High" -TemplateSecurityComplianceGovernance "High" -TemplateSecurityIntegration "High" -TemplateSecuritySupport "High"
                
                if ($templateSecurityResult) {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Template Security (High)"
                        Status = "Completed"
                        Details = "Template security configured with high settings"
                        Severity = "Info"
                    }
                    Write-SecurityLog "Template security configured with high settings" "Success"
                } else {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Template Security (High)"
                        Status = "Failed"
                        Details = "Failed to configure template security"
                        Severity = "Error"
                    }
                    $securityResults.Issues += "Failed to configure template security"
                    $securityResults.Recommendations += "Check template security configuration parameters"
                    Write-SecurityLog "Failed to configure template security" "Error"
                }
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Template Security (High)"
                    Status = "Failed"
                    Details = "Exception during template security configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Exception during template security configuration"
                $securityResults.Recommendations += "Check error logs and template security parameters"
                Write-SecurityLog "Exception during template security configuration: $($_.Exception.Message)" "Error"
            }
            
            # Step 3: Configure role separation
            try {
                $roleSeparationResult = Set-RoleSeparation -ServerName $ServerName -RoleSeparationPolicy "High" -RoleSeparationLevel "High" -RoleSeparationBaseline "CIS" -RoleSeparationCompliance "High" -RoleSeparationAudit "High" -RoleSeparationMonitoring "High" -RoleSeparationReporting "High" -RoleSeparationIntegration "High" -RoleSeparationManagement "High" -RoleSeparationOperations "High" -RoleSeparationMaintenance "High" -RoleSeparationSupport "High" -RoleSeparationDocumentation "High" -RoleSeparationTraining "High" -RoleSeparationBestPractices "High" -RoleSeparationTroubleshootingGuide "High" -RoleSeparationPerformanceOptimization "High" -RoleSeparationSecurityConsiderations "High" -RoleSeparationComplianceGovernance "High" -RoleSeparationIntegration "High" -RoleSeparationSupport "High"
                
                if ($roleSeparationResult) {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Role Separation (High)"
                        Status = "Completed"
                        Details = "Role separation configured with high settings"
                        Severity = "Info"
                    }
                    Write-SecurityLog "Role separation configured with high settings" "Success"
                } else {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Role Separation (High)"
                        Status = "Failed"
                        Details = "Failed to configure role separation"
                        Severity = "Error"
                    }
                    $securityResults.Issues += "Failed to configure role separation"
                    $securityResults.Recommendations += "Check role separation configuration parameters"
                    Write-SecurityLog "Failed to configure role separation" "Error"
                }
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Role Separation (High)"
                    Status = "Failed"
                    Details = "Exception during role separation configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Exception during role separation configuration"
                $securityResults.Recommendations += "Check error logs and role separation parameters"
                Write-SecurityLog "Exception during role separation configuration: $($_.Exception.Message)" "Error"
            }
            
            # Step 4: Configure audit
            try {
                $auditResult = Set-AuditConfiguration -ServerName $ServerName -AuditPolicy "High" -AuditLevel "High" -AuditBaseline "CIS" -AuditCompliance "High" -AuditMonitoring "High" -AuditReporting "High" -AuditIntegration "High" -AuditManagement "High" -AuditOperations "High" -AuditMaintenance "High" -AuditSupport "High" -AuditDocumentation "High" -AuditTraining "High" -AuditBestPractices "High" -AuditTroubleshootingGuide "High" -AuditPerformanceOptimization "High" -AuditSecurityConsiderations "High" -AuditComplianceGovernance "High" -AuditIntegration "High" -AuditSupport "High"
                
                if ($auditResult) {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Audit (High)"
                        Status = "Completed"
                        Details = "Audit configured with high settings"
                        Severity = "Info"
                    }
                    Write-SecurityLog "Audit configured with high settings" "Success"
                } else {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Audit (High)"
                        Status = "Failed"
                        Details = "Failed to configure audit"
                        Severity = "Error"
                    }
                    $securityResults.Issues += "Failed to configure audit"
                    $securityResults.Recommendations += "Check audit configuration parameters"
                    Write-SecurityLog "Failed to configure audit" "Error"
                }
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Audit (High)"
                    Status = "Failed"
                    Details = "Exception during audit configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Exception during audit configuration"
                $securityResults.Recommendations += "Check error logs and audit parameters"
                Write-SecurityLog "Exception during audit configuration: $($_.Exception.Message)" "Error"
            }
            
            # Step 5: Configure compliance
            try {
                $complianceResult = Set-ComplianceConfiguration -ServerName $ServerName -CompliancePolicy "CIS" -ComplianceLevel "High" -ComplianceBaseline "CIS" -ComplianceAudit "High" -ComplianceMonitoring "High" -ComplianceReporting "High" -ComplianceIntegration "High" -ComplianceManagement "High" -ComplianceOperations "High" -ComplianceMaintenance "High" -ComplianceSupport "High" -ComplianceDocumentation "High" -ComplianceTraining "High" -ComplianceBestPractices "High" -ComplianceTroubleshootingGuide "High" -CompliancePerformanceOptimization "High" -ComplianceSecurityConsiderations "High" -ComplianceComplianceGovernance "High" -ComplianceIntegration "High" -ComplianceSupport "High"
                
                if ($complianceResult) {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Compliance (High)"
                        Status = "Completed"
                        Details = "Compliance configured with high settings"
                        Severity = "Info"
                    }
                    Write-SecurityLog "Compliance configured with high settings" "Success"
                } else {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Compliance (High)"
                        Status = "Failed"
                        Details = "Failed to configure compliance"
                        Severity = "Error"
                    }
                    $securityResults.Issues += "Failed to configure compliance"
                    $securityResults.Recommendations += "Check compliance configuration parameters"
                    Write-SecurityLog "Failed to configure compliance" "Error"
                }
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Compliance (High)"
                    Status = "Failed"
                    Details = "Exception during compliance configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Exception during compliance configuration"
                $securityResults.Recommendations += "Check error logs and compliance parameters"
                Write-SecurityLog "Exception during compliance configuration: $($_.Exception.Message)" "Error"
            }
        }
        
        "Maximum" {
            Write-SecurityLog "Applying maximum security configuration..." "Info"
            
            # Step 1: Configure HSM integration
            if ($HSMProvider) {
                try {
                    $hsmResult = Install-HSMProvider -ServerName $ServerName -HSMProvider $HSMProvider -HSMProviderPath $HSMProviderPath -HSMProviderConfig $HSMProviderConfig -HSMProviderKey $HSMProviderKey -HSMProviderCert $HSMProviderCert -HSMProviderPassword $HSMProviderPassword -HSMProviderUser $HSMProviderUser -HSMProviderDomain $HSMProviderDomain -HSMProviderGroup $HSMProviderGroup -HSMProviderRole $HSMProviderRole -HSMProviderPolicy $HSMProviderPolicy -HSMProviderAudit $HSMProviderAudit -HSMProviderCompliance $HSMProviderCompliance -HSMProviderGovernance $HSMProviderGovernance -HSMProviderMonitoring $HSMProviderMonitoring -HSMProviderTroubleshooting $HSMProviderTroubleshooting -HSMProviderReporting $HSMProviderReporting -HSMProviderIntegration $HSMProviderIntegration -HSMProviderManagement $HSMProviderManagement -HSMProviderOperations $HSMProviderOperations -HSMProviderMaintenance $HSMProviderMaintenance -HSMProviderSupport $HSMProviderSupport -HSMProviderDocumentation $HSMProviderDocumentation -HSMProviderTraining $HSMProviderTraining -HSMProviderBestPractices $HSMProviderBestPractices -HSMProviderTroubleshootingGuide $HSMProviderTroubleshootingGuide -HSMProviderPerformanceOptimization $HSMProviderPerformanceOptimization -HSMProviderSecurityConsiderations $HSMProviderSecurityConsiderations -HSMProviderComplianceGovernance $HSMProviderComplianceGovernance -HSMProviderIntegration $HSMProviderIntegration -HSMProviderSupport $HSMProviderSupport
                    
                    if ($hsmResult) {
                        $securityResults.SecuritySteps += @{
                            Step = "Configure HSM Integration"
                            Status = "Completed"
                            Details = "HSM integration configured successfully"
                            Severity = "Info"
                        }
                        Write-SecurityLog "HSM integration configured successfully" "Success"
                    } else {
                        $securityResults.SecuritySteps += @{
                            Step = "Configure HSM Integration"
                            Status = "Failed"
                            Details = "Failed to configure HSM integration"
                            Severity = "Error"
                        }
                        $securityResults.Issues += "Failed to configure HSM integration"
                        $securityResults.Recommendations += "Check HSM configuration parameters"
                        Write-SecurityLog "Failed to configure HSM integration" "Error"
                    }
                }
                catch {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure HSM Integration"
                        Status = "Failed"
                        Details = "Exception during HSM configuration: $($_.Exception.Message)"
                        Severity = "Error"
                    }
                    $securityResults.Issues += "Exception during HSM configuration"
                    $securityResults.Recommendations += "Check error logs and HSM parameters"
                    Write-SecurityLog "Exception during HSM configuration: $($_.Exception.Message)" "Error"
                }
            }
            
            # Step 2: Configure template security
            try {
                $templateSecurityResult = Set-TemplateSecurity -TemplateName "User" -TemplateSecurityPolicy "Maximum" -TemplateSecurityLevel "Maximum" -TemplateSecurityBaseline "CIS" -TemplateSecurityCompliance "Maximum" -TemplateSecurityAudit "Maximum" -TemplateSecurityMonitoring "Maximum" -TemplateSecurityReporting "Maximum" -TemplateSecurityIntegration "Maximum" -TemplateSecurityManagement "Maximum" -TemplateSecurityOperations "Maximum" -TemplateSecurityMaintenance "Maximum" -TemplateSecuritySupport "Maximum" -TemplateSecurityDocumentation "Maximum" -TemplateSecurityTraining "Maximum" -TemplateSecurityBestPractices "Maximum" -TemplateSecurityTroubleshootingGuide "Maximum" -TemplateSecurityPerformanceOptimization "Maximum" -TemplateSecuritySecurityConsiderations "Maximum" -TemplateSecurityComplianceGovernance "Maximum" -TemplateSecurityIntegration "Maximum" -TemplateSecuritySupport "Maximum"
                
                if ($templateSecurityResult) {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Template Security (Maximum)"
                        Status = "Completed"
                        Details = "Template security configured with maximum settings"
                        Severity = "Info"
                    }
                    Write-SecurityLog "Template security configured with maximum settings" "Success"
                } else {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Template Security (Maximum)"
                        Status = "Failed"
                        Details = "Failed to configure template security"
                        Severity = "Error"
                    }
                    $securityResults.Issues += "Failed to configure template security"
                    $securityResults.Recommendations += "Check template security configuration parameters"
                    Write-SecurityLog "Failed to configure template security" "Error"
                }
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Template Security (Maximum)"
                    Status = "Failed"
                    Details = "Exception during template security configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Exception during template security configuration"
                $securityResults.Recommendations += "Check error logs and template security parameters"
                Write-SecurityLog "Exception during template security configuration: $($_.Exception.Message)" "Error"
            }
            
            # Step 3: Configure role separation
            try {
                $roleSeparationResult = Set-RoleSeparation -ServerName $ServerName -RoleSeparationPolicy "Maximum" -RoleSeparationLevel "Maximum" -RoleSeparationBaseline "CIS" -RoleSeparationCompliance "Maximum" -RoleSeparationAudit "Maximum" -RoleSeparationMonitoring "Maximum" -RoleSeparationReporting "Maximum" -RoleSeparationIntegration "Maximum" -RoleSeparationManagement "Maximum" -RoleSeparationOperations "Maximum" -RoleSeparationMaintenance "Maximum" -RoleSeparationSupport "Maximum" -RoleSeparationDocumentation "Maximum" -RoleSeparationTraining "Maximum" -RoleSeparationBestPractices "Maximum" -RoleSeparationTroubleshootingGuide "Maximum" -RoleSeparationPerformanceOptimization "Maximum" -RoleSeparationSecurityConsiderations "Maximum" -RoleSeparationComplianceGovernance "Maximum" -RoleSeparationIntegration "Maximum" -RoleSeparationSupport "Maximum"
                
                if ($roleSeparationResult) {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Role Separation (Maximum)"
                        Status = "Completed"
                        Details = "Role separation configured with maximum settings"
                        Severity = "Info"
                    }
                    Write-SecurityLog "Role separation configured with maximum settings" "Success"
                } else {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Role Separation (Maximum)"
                        Status = "Failed"
                        Details = "Failed to configure role separation"
                        Severity = "Error"
                    }
                    $securityResults.Issues += "Failed to configure role separation"
                    $securityResults.Recommendations += "Check role separation configuration parameters"
                    Write-SecurityLog "Failed to configure role separation" "Error"
                }
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Role Separation (Maximum)"
                    Status = "Failed"
                    Details = "Exception during role separation configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Exception during role separation configuration"
                $securityResults.Recommendations += "Check error logs and role separation parameters"
                Write-SecurityLog "Exception during role separation configuration: $($_.Exception.Message)" "Error"
            }
            
            # Step 4: Configure audit
            try {
                $auditResult = Set-AuditConfiguration -ServerName $ServerName -AuditPolicy "Maximum" -AuditLevel "Maximum" -AuditBaseline "CIS" -AuditCompliance "Maximum" -AuditMonitoring "Maximum" -AuditReporting "Maximum" -AuditIntegration "Maximum" -AuditManagement "Maximum" -AuditOperations "Maximum" -AuditMaintenance "Maximum" -AuditSupport "Maximum" -AuditDocumentation "Maximum" -AuditTraining "Maximum" -AuditBestPractices "Maximum" -AuditTroubleshootingGuide "Maximum" -AuditPerformanceOptimization "Maximum" -AuditSecurityConsiderations "Maximum" -AuditComplianceGovernance "Maximum" -AuditIntegration "Maximum" -AuditSupport "Maximum"
                
                if ($auditResult) {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Audit (Maximum)"
                        Status = "Completed"
                        Details = "Audit configured with maximum settings"
                        Severity = "Info"
                    }
                    Write-SecurityLog "Audit configured with maximum settings" "Success"
                } else {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Audit (Maximum)"
                        Status = "Failed"
                        Details = "Failed to configure audit"
                        Severity = "Error"
                    }
                    $securityResults.Issues += "Failed to configure audit"
                    $securityResults.Recommendations += "Check audit configuration parameters"
                    Write-SecurityLog "Failed to configure audit" "Error"
                }
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Audit (Maximum)"
                    Status = "Failed"
                    Details = "Exception during audit configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Exception during audit configuration"
                $securityResults.Recommendations += "Check error logs and audit parameters"
                Write-SecurityLog "Exception during audit configuration: $($_.Exception.Message)" "Error"
            }
            
            # Step 5: Configure compliance
            try {
                $complianceResult = Set-ComplianceConfiguration -ServerName $ServerName -CompliancePolicy "CIS" -ComplianceLevel "Maximum" -ComplianceBaseline "CIS" -ComplianceAudit "Maximum" -ComplianceMonitoring "Maximum" -ComplianceReporting "Maximum" -ComplianceIntegration "Maximum" -ComplianceManagement "Maximum" -ComplianceOperations "Maximum" -ComplianceMaintenance "Maximum" -ComplianceSupport "Maximum" -ComplianceDocumentation "Maximum" -ComplianceTraining "Maximum" -ComplianceBestPractices "Maximum" -ComplianceTroubleshootingGuide "Maximum" -CompliancePerformanceOptimization "Maximum" -ComplianceSecurityConsiderations "Maximum" -ComplianceComplianceGovernance "Maximum" -ComplianceIntegration "Maximum" -ComplianceSupport "Maximum"
                
                if ($complianceResult) {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Compliance (Maximum)"
                        Status = "Completed"
                        Details = "Compliance configured with maximum settings"
                        Severity = "Info"
                    }
                    Write-SecurityLog "Compliance configured with maximum settings" "Success"
                } else {
                    $securityResults.SecuritySteps += @{
                        Step = "Configure Compliance (Maximum)"
                        Status = "Failed"
                        Details = "Failed to configure compliance"
                        Severity = "Error"
                    }
                    $securityResults.Issues += "Failed to configure compliance"
                    $securityResults.Recommendations += "Check compliance configuration parameters"
                    Write-SecurityLog "Failed to configure compliance" "Error"
                }
            }
            catch {
                $securityResults.SecuritySteps += @{
                    Step = "Configure Compliance (Maximum)"
                    Status = "Failed"
                    Details = "Exception during compliance configuration: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $securityResults.Issues += "Exception during compliance configuration"
                $securityResults.Recommendations += "Check error logs and compliance parameters"
                Write-SecurityLog "Exception during compliance configuration: $($_.Exception.Message)" "Error"
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
    
    Write-SecurityLog "AD CS security configuration completed" "Success"
    
    return $securityResults
}
catch {
    Write-SecurityLog "AD CS security configuration failed: $($_.Exception.Message)" "Error"
    Write-SecurityLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script configures security for Windows Active Directory Certificate Services
    with various security levels including basic, standard, high, and maximum security.
    
    Features:
    - Basic Security Configuration
    - Standard Security Configuration
    - High Security Configuration
    - Maximum Security Configuration
    - HSM Integration
    - Template Security
    - Role Separation
    - Audit Configuration
    - Compliance Configuration
    
    Prerequisites:
    - Windows Server 2016 or later
    - Active Directory Domain Services
    - Administrative privileges
    - Network connectivity
    - Sufficient storage space
    - Sufficient memory and CPU resources
    
    Dependencies:
    - ADCS-Core.psm1
    - ADCS-Security.psm1
    - ADCS-Monitoring.psm1
    - ADCS-Troubleshooting.psm1
    
    Usage Examples:
    .\Secure-ADCS.ps1 -ServerName "CA-SERVER01" -SecurityLevel "Basic"
    .\Secure-ADCS.ps1 -ServerName "CA-SERVER01" -SecurityLevel "Standard"
    .\Secure-ADCS.ps1 -ServerName "CA-SERVER01" -SecurityLevel "High" -HSMProvider "Thales" -HSMProviderPath "C:\HSM\Thales"
    .\Secure-ADCS.ps1 -ServerName "CA-SERVER01" -SecurityLevel "Maximum" -HSMProvider "Thales" -HSMProviderPath "C:\HSM\Thales" -HSMProviderConfig "C:\HSM\Thales\config.xml" -HSMProviderKey "C:\HSM\Thales\key.pem" -HSMProviderCert "C:\HSM\Thales\cert.pem" -HSMProviderPassword "SecurePassword123" -HSMProviderUser "HSMUser" -HSMProviderDomain "CONTOSO" -HSMProviderGroup "HSMGroup" -HSMProviderRole "HSMRole" -HSMProviderPolicy "HSMPolicy" -HSMProviderAudit "Enabled" -HSMProviderCompliance "Enabled" -HSMProviderGovernance "Enabled" -HSMProviderMonitoring "Enabled" -HSMProviderTroubleshooting "Enabled" -HSMProviderReporting "Enabled" -HSMProviderIntegration "Enabled" -HSMProviderManagement "Enabled" -HSMProviderOperations "Enabled" -HSMProviderMaintenance "Enabled" -HSMProviderSupport "Enabled" -HSMProviderDocumentation "Enabled" -HSMProviderTraining "Enabled" -HSMProviderBestPractices "Enabled" -HSMProviderTroubleshootingGuide "Enabled" -HSMProviderPerformanceOptimization "Enabled" -HSMProviderSecurityConsiderations "Enabled" -HSMProviderComplianceGovernance "Enabled" -HSMProviderIntegration "Enabled" -HSMProviderSupport "Enabled"
    
    Output:
    - Console logging with color-coded messages
    - Security configuration results summary
    - Detailed security configuration steps
    - Issues and recommendations
    - Comprehensive error handling
    
    Security Considerations:
    - Requires administrative privileges
    - Configures secure CA settings
    - Implements security baselines
    - Enables audit logging
    - Configures compliance settings
    
    Performance Impact:
    - Minimal impact during security configuration
    - Non-destructive operations
    - Configurable security scope
    - Resource-aware security configuration
#>
