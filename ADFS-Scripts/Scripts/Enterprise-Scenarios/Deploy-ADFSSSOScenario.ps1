#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy ADFS Single Sign-On (SSO) Scenario

.DESCRIPTION
    This script deploys ADFS Single Sign-On scenario for external web applications
    including SaaS applications like Salesforce, ServiceNow, and Workday.

.PARAMETER Applications
    Array of applications to configure for SSO

.PARAMETER Environment
    Target environment (Development, Staging, Production)

.PARAMETER EnableMFA
    Enable MFA for SSO applications

.PARAMETER EnableConditionalAccess
    Enable conditional access policies

.PARAMETER EnableAuditing
    Enable comprehensive audit logging

.EXAMPLE
    .\Deploy-ADFSSSOScenario.ps1 -Applications @("Salesforce", "ServiceNow") -Environment "Production" -EnableMFA -EnableConditionalAccess

.EXAMPLE
    .\Deploy-ADFSSSOScenario.ps1 -Applications @("Workday") -Environment "Development" -EnableAuditing
#>

param(
    [Parameter(Mandatory = $true)]
    [string[]]$Applications,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Development", "Staging", "Production")]
    [string]$Environment = "Development",
    
    [switch]$EnableMFA,
    
    [switch]$EnableConditionalAccess,
    
    [switch]$EnableAuditing
)

# Import ADFS modules
try {
    Import-Module "..\..\Modules\ADFS-Core.psm1" -Force
    Import-Module "..\..\Modules\ADFS-Federation.psm1" -Force
    Import-Module "..\..\Modules\ADFS-Security.psm1" -Force
} catch {
    Write-Error "Failed to import ADFS modules: $($_.Exception.Message)"
    exit 1
}

# Script configuration
$scriptConfig = @{
    Applications = $Applications
    Environment = $Environment
    EnableMFA = $EnableMFA
    EnableConditionalAccess = $EnableConditionalAccess
    EnableAuditing = $EnableAuditing
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "ADFS Single Sign-On (SSO) Scenario Deployment" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Applications: $($Applications -join ', ')" -ForegroundColor Yellow
Write-Host "Environment: $Environment" -ForegroundColor Yellow
Write-Host "MFA Enabled: $EnableMFA" -ForegroundColor Yellow
Write-Host "Conditional Access: $EnableConditionalAccess" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Test prerequisites
Write-Host "Testing prerequisites..." -ForegroundColor Green
$prerequisites = Test-ADFSPrerequisites

if (-not $prerequisites.AdministratorPrivileges) {
    Write-Error "Administrator privileges are required for ADFS SSO deployment."
    exit 1
}

if (-not $prerequisites.ADFSInstalled) {
    Write-Error "ADFS must be installed to perform SSO deployment."
    exit 1
}

Write-Host "Prerequisites check passed!" -ForegroundColor Green

# Application configurations
$applicationConfigs = @{
    "Salesforce" = @{
        MetadataUrl = "https://login.salesforce.com/.well-known/openid_configuration"
        Identifier = "https://saml.salesforce.com"
        ClaimRules = @("Email", "Name", "Groups")
        EnableSSO = $true
        EnableClaims = $true
        EnableAuditing = $EnableAuditing
    }
    "ServiceNow" = @{
        MetadataUrl = "https://your-instance.service-now.com/sso/metadata"
        Identifier = "https://your-instance.service-now.com"
        ClaimRules = @("Email", "Name", "Groups")
        EnableSSO = $true
        EnableClaims = $true
        EnableAuditing = $EnableAuditing
    }
    "Workday" = @{
        MetadataUrl = "https://your-instance.workday.com/saml/metadata"
        Identifier = "https://your-instance.workday.com"
        ClaimRules = @("Email", "Name", "Groups")
        EnableSSO = $true
        EnableClaims = $true
        EnableAuditing = $EnableAuditing
    }
    "Office365" = @{
        MetadataUrl = "https://login.microsoftonline.com/your-tenant-id/federationmetadata/2007-06/federationmetadata.xml"
        Identifier = "https://login.microsoftonline.com/your-tenant-id/saml2"
        ClaimRules = @("Email", "Name", "Groups")
        EnableSSO = $true
        EnableClaims = $true
        EnableAuditing = $EnableAuditing
    }
}

# Deploy SSO for each application
$deploymentResults = @{}

foreach ($application in $Applications) {
    Write-Host "Deploying SSO for application: $application" -ForegroundColor Green
    
    if (-not $applicationConfigs.ContainsKey($application)) {
        Write-Warning "Configuration not found for application: $application. Using default configuration."
        $applicationConfigs[$application] = @{
            MetadataUrl = "https://$application.com/saml/metadata"
            Identifier = "https://$application.com"
            ClaimRules = @("Email", "Name", "Groups")
            EnableSSO = $true
            EnableClaims = $true
            EnableAuditing = $EnableAuditing
        }
    }
    
    $appConfig = $applicationConfigs[$application]
    
    # Create relying party trust
    Write-Host "Creating relying party trust for $application..." -ForegroundColor Yellow
    $trustResult = New-ADFSRelyingPartyTrust -Name $application -Identifier $appConfig.Identifier -MetadataUrl $appConfig.MetadataUrl -EnableSSO:$appConfig.EnableSSO -EnableClaims:$appConfig.EnableClaims -EnableAuditing:$appConfig.EnableAuditing
    
    if ($trustResult.Success) {
        Write-Host "Relying party trust created successfully for $application!" -ForegroundColor Green
        
        # Configure claim rules
        Write-Host "Configuring claim rules for $application..." -ForegroundColor Yellow
        foreach ($claimRule in $appConfig.ClaimRules) {
            $claimRuleResult = Set-ADFSClaimRule -TrustName $application -RuleName "$claimRule Claim" -RuleType "PassThrough" -ClaimType "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/$($claimRule.ToLower())" -EnableRule
            
            if ($claimRuleResult.Success) {
                Write-Host "Claim rule '${claimRule}' configured successfully for ${application}!" -ForegroundColor Green
            } else {
                Write-Warning "Failed to configure claim rule '${claimRule}' for ${application}: $($claimRuleResult.Error)"
            }
        }
        
        # Configure MFA if enabled
        if ($EnableMFA) {
            Write-Host "Configuring MFA for $application..." -ForegroundColor Yellow
            $mfaResult = Set-ADFSMFAIntegration -TrustName $application -MFAProvider "AzureMFA" -EnableConditionalMFA:$EnableConditionalAccess -EnablePerAppMFA -EnableLocationBasedMFA -EnableDeviceBasedMFA -EnableAuditing:$EnableAuditing
            
            if ($mfaResult.Success) {
                Write-Host "MFA configured successfully for ${application}!" -ForegroundColor Green
            } else {
                Write-Warning "Failed to configure MFA for ${application}: $($mfaResult.Error)"
            }
        }
        
        # Configure conditional access if enabled
        if ($EnableConditionalAccess) {
            Write-Host "Configuring conditional access for $application..." -ForegroundColor Yellow
            $conditionalAccessResult = Set-ADFSConditionalAccess -TrustName $application -EnableLocationBasedAccess -EnableDeviceBasedAccess -EnableRiskBasedAccess -EnableTimeBasedAccess -EnableGroupBasedAccess -EnableAuditing:$EnableAuditing
            
            if ($conditionalAccessResult.Success) {
                Write-Host "Conditional access configured successfully for ${application}!" -ForegroundColor Green
            } else {
                Write-Warning "Failed to configure conditional access for ${application}: $($conditionalAccessResult.Error)"
            }
        }
        
        $deploymentResults[$application] = @{
            Success = $true
            TrustCreated = $true
            ClaimRulesConfigured = $true
            MFAConfigured = $EnableMFA
            ConditionalAccessConfigured = $EnableConditionalAccess
        }
    } else {
        Write-Error "Failed to create relying party trust for ${application}: $($trustResult.Error)"
        $deploymentResults[$application] = @{
            Success = $false
            Error = $trustResult.Error
        }
    }
}

# Configure global SSO settings
Write-Host "Configuring global SSO settings..." -ForegroundColor Green
$globalSSOResult = Set-ADFSGlobalSSOSettings -EnableSSO -EnableClaims -EnableAuditing:$EnableAuditing -EnablePerformanceMonitoring -EnableErrorLogging

if ($globalSSOResult.Success) {
    Write-Host "Global SSO settings configured successfully!" -ForegroundColor Green
} else {
    Write-Warning "Failed to configure global SSO settings: $($globalSSOResult.Error)"
}

# Get final SSO status
Write-Host "Getting final SSO status..." -ForegroundColor Green
$ssoStatus = Get-ADFSSSOStatus

if ($ssoStatus.Success) {
    Write-Host "SSO Status:" -ForegroundColor Cyan
    Write-Host "  SSO Enabled: $($ssoStatus.SSOEnabled)" -ForegroundColor White
    Write-Host "  Applications Configured: $($ssoStatus.ApplicationsConfigured)" -ForegroundColor White
    Write-Host "  MFA Enabled: $($ssoStatus.MFAEnabled)" -ForegroundColor White
    Write-Host "  Conditional Access Enabled: $($ssoStatus.ConditionalAccessEnabled)" -ForegroundColor White
    Write-Host "  Auditing Enabled: $($ssoStatus.AuditingEnabled)" -ForegroundColor White
} else {
    Write-Warning "Failed to get SSO status: $($ssoStatus.Error)"
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "ADFS SSO Scenario Deployment Completed!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan

# Display deployment results
Write-Host "Deployment Results:" -ForegroundColor Yellow
foreach ($result in $deploymentResults.GetEnumerator()) {
    $appName = $result.Key
    $appResult = $result.Value
    
    if ($appResult.Success) {
        Write-Host "${appName}: SUCCESS" -ForegroundColor Green
        Write-Host "  Trust Created: $($appResult.TrustCreated)" -ForegroundColor White
        Write-Host "  Claim Rules Configured: $($appResult.ClaimRulesConfigured)" -ForegroundColor White
        Write-Host "  MFA Configured: $($appResult.MFAConfigured)" -ForegroundColor White
        Write-Host "  Conditional Access Configured: $($appResult.ConditionalAccessConfigured)" -ForegroundColor White
    } else {
        Write-Host "${appName}: FAILED - $($appResult.Error)" -ForegroundColor Red
    }
}

# Summary
Write-Host "SSO Deployment Summary:" -ForegroundColor Yellow
Write-Host "  Applications: $($Applications -join ', ')" -ForegroundColor White
Write-Host "  Environment: $Environment" -ForegroundColor White
Write-Host "  MFA Enabled: $EnableMFA" -ForegroundColor White
Write-Host "  Conditional Access: $EnableConditionalAccess" -ForegroundColor White
Write-Host "  Auditing Enabled: $EnableAuditing" -ForegroundColor White
Write-Host "  Completion Time: $(Get-Date)" -ForegroundColor White
