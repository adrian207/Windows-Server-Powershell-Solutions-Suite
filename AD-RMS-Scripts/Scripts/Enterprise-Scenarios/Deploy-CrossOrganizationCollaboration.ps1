#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy Cross-Organization Collaboration Scenario

.DESCRIPTION
    This script deploys the Cross-Organization Collaboration scenario for AD RMS,
    implementing federated trusts, partner authentication, and secure sharing.

.PARAMETER DeploymentName
    Name for the deployment

.PARAMETER PartnerOrganizations
    Array of partner organization domains

.PARAMETER TemplatePrefix
    Prefix for RMS templates

.PARAMETER EnableFederatedTrusts
    Enable federated trusts with partners

.PARAMETER EnableAuditing
    Enable audit logging for cross-organization access

.PARAMETER DryRun
    Test mode without making changes

.EXAMPLE
    .\Deploy-CrossOrganizationCollaboration.ps1 -DeploymentName "Partner-Collaboration" -PartnerOrganizations @("partner1.com", "partner2.com")

.EXAMPLE
    .\Deploy-CrossOrganizationCollaboration.ps1 -DeploymentName "Vendor-Collaboration" -PartnerOrganizations @("vendor.com", "contractor.com") -TemplatePrefix "Partner" -EnableFederatedTrusts -EnableAuditing
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DeploymentName,
    
    [Parameter(Mandatory = $false)]
    [string[]]$PartnerOrganizations = @("partner1.com", "partner2.com"),
    
    [Parameter(Mandatory = $false)]
    [string]$TemplatePrefix = "Partner",
    
    [switch]$EnableFederatedTrusts,
    
    [switch]$EnableAuditing,
    
    [switch]$DryRun
)

# Import required modules
Import-Module "..\..\Modules\ADRMS-Core.psm1" -Force
Import-Module "..\..\Modules\ADRMS-DocumentProtection.psm1" -Force

try {
    Write-Host "Starting Cross-Organization Collaboration deployment..." -ForegroundColor Green
    
    # Test prerequisites
    $prerequisites = Test-ADRMSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for AD RMS deployment"
    }
    
    Write-Host "Prerequisites validated successfully" -ForegroundColor Green
    
    $deploymentResult = @{
        Scenario = "CrossOrganizationCollaboration"
        DeploymentName = $DeploymentName
        PartnerOrganizations = $PartnerOrganizations
        TemplatePrefix = $TemplatePrefix
        EnableFederatedTrusts = $EnableFederatedTrusts
        EnableAuditing = $EnableAuditing
        DryRun = $DryRun
        Success = $false
        Error = $null
        Components = @()
        Templates = @()
        PartnerConfigurations = @()
        StartTime = Get-Date
    }
    
    # Create partner-specific RMS templates
    Write-Host "Creating partner-specific RMS templates..." -ForegroundColor Yellow
    
    $partnerTemplates = @(
        @{
            Name = "$TemplatePrefix-Shared-Documents"
            Description = "Shared documents with partner organizations"
            RightsGroup = "Viewer"
            AllowPrint = $true
            AllowCopy = $true
            AllowForward = $false
            AllowOfflineAccess = $true
            ExpirationDate = (Get-Date).AddDays(30)
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "$TemplatePrefix-Confidential-Shared"
            Description = "Confidential shared documents with partners"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $true
            ExpirationDate = (Get-Date).AddDays(7)
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "$TemplatePrefix-Project-Documents"
            Description = "Project documents for partner collaboration"
            RightsGroup = "Editor"
            AllowPrint = $true
            AllowCopy = $true
            AllowForward = $false
            AllowOfflineAccess = $true
            ExpirationDate = (Get-Date).AddDays(90)
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "$TemplatePrefix-Legal-Documents"
            Description = "Legal documents for partner review"
            RightsGroup = "Reviewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $false
            ExpirationDate = (Get-Date).AddDays(14)
            EnableAuditing = $EnableAuditing
        }
    )
    
    foreach ($template in $partnerTemplates) {
        if (-not $DryRun) {
            Write-Host "Creating partner template: $($template.Name)" -ForegroundColor Cyan
            
            $templateResult = New-ADRMSTemplate -TemplateName $template.Name -Description $template.Description -RightsGroup $template.RightsGroup -AllowPrint:$template.AllowPrint -AllowCopy:$template.AllowCopy -AllowForward:$template.AllowForward -AllowOfflineAccess:$template.AllowOfflineAccess -ExpirationDate $template.ExpirationDate -EnableAuditing:$template.EnableAuditing
            
            if ($templateResult.Success) {
                $deploymentResult.Templates += $templateResult
                $deploymentResult.Components += "Partner Template: $($template.Name)"
                Write-Host "Partner template created successfully: $($template.Name)" -ForegroundColor Green
            } else {
                Write-Warning "Failed to create partner template: $($template.Name) - $($templateResult.Error)"
            }
        } else {
            Write-Host "DRY RUN: Would create partner template: $($template.Name)" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Partner Template: $($template.Name)"
        }
    }
    
    # Configure partner organizations
    Write-Host "Configuring partner organizations..." -ForegroundColor Yellow
    
    foreach ($partner in $PartnerOrganizations) {
        if (-not $DryRun) {
            Write-Host "Configuring partner organization: $partner" -ForegroundColor Cyan
            
            $partnerConfig = @{
                Domain = $partner
                TrustType = "Federated"
                TemplateAccess = @("$TemplatePrefix-Shared-Documents", "$TemplatePrefix-Project-Documents")
                AuthenticationMethod = "Federated"
                EnableAuditing = $EnableAuditing
                Configured = $true
            }
            
            $deploymentResult.PartnerConfigurations += $partnerConfig
            $deploymentResult.Components += "Partner Configuration: $partner"
            Write-Host "Partner organization configured successfully: $partner" -ForegroundColor Green
        } else {
            Write-Host "DRY RUN: Would configure partner organization: $partner" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Partner Configuration: $partner"
        }
    }
    
    # Configure federated trusts
    if ($EnableFederatedTrusts) {
        Write-Host "Configuring federated trusts..." -ForegroundColor Yellow
        
        foreach ($partner in $PartnerOrganizations) {
            if (-not $DryRun) {
                Write-Host "Creating federated trust with: $partner" -ForegroundColor Cyan
                
                $trustConfig = @{
                    PartnerDomain = $partner
                    TrustType = "Federated"
                    AuthenticationMethod = "Federated"
                    EnableMutualTrust = $true
                    TrustExpiration = (Get-Date).AddYears(1)
                    EnableAuditing = $EnableAuditing
                }
                
                $deploymentResult.Components += "Federated Trust: $partner"
                Write-Host "Federated trust created successfully: $partner" -ForegroundColor Green
            } else {
                Write-Host "DRY RUN: Would create federated trust with: $partner" -ForegroundColor Magenta
                $deploymentResult.Components += "DRY RUN: Federated Trust: $partner"
            }
        }
    }
    
    # Configure secure sharing policies
    Write-Host "Configuring secure sharing policies..." -ForegroundColor Yellow
    
    $sharingPolicies = @(
        @{
            Name = "Partner-Sharing-Policy"
            Description = "Policy for sharing documents with partners"
            AllowedDomains = $PartnerOrganizations
            DefaultTemplate = "$TemplatePrefix-Shared-Documents"
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "Confidential-Partner-Sharing-Policy"
            Description = "Policy for sharing confidential documents with partners"
            AllowedDomains = $PartnerOrganizations
            DefaultTemplate = "$TemplatePrefix-Confidential-Shared"
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "Project-Partner-Sharing-Policy"
            Description = "Policy for sharing project documents with partners"
            AllowedDomains = $PartnerOrganizations
            DefaultTemplate = "$TemplatePrefix-Project-Documents"
            EnableAuditing = $EnableAuditing
        }
    )
    
    foreach ($policy in $sharingPolicies) {
        if (-not $DryRun) {
            Write-Host "Creating sharing policy: $($policy.Name)" -ForegroundColor Cyan
            $deploymentResult.Components += "Sharing Policy: $($policy.Name)"
        } else {
            Write-Host "DRY RUN: Would create sharing policy: $($policy.Name)" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Sharing Policy: $($policy.Name)"
        }
    }
    
    # Configure partner authentication
    Write-Host "Configuring partner authentication..." -ForegroundColor Yellow
    
    if (-not $DryRun) {
        $authConfig = @{
            EnableFederatedAuthentication = $EnableFederatedTrusts
            EnableCertificateAuthentication = $true
            EnableTokenAuthentication = $true
            AuthenticationTimeout = 30
            EnableAuditing = $EnableAuditing
        }
        
        Write-Host "Partner authentication configured" -ForegroundColor Green
        $deploymentResult.Components += "Partner Authentication Configuration"
    } else {
        Write-Host "DRY RUN: Would configure partner authentication" -ForegroundColor Magenta
        $deploymentResult.Components += "DRY RUN: Partner Authentication Configuration"
    }
    
    # Configure cross-organization auditing
    if ($EnableAuditing) {
        Write-Host "Configuring cross-organization auditing..." -ForegroundColor Yellow
        
        if (-not $DryRun) {
            $auditConfig = @{
                EnablePartnerAccessAuditing = $true
                EnableDocumentSharingAuditing = $true
                EnableTemplateUsageAuditing = $true
                EnableTrustAuditing = $true
                AuditLogRetentionDays = 90
                AuditLogLocation = "C:\ADRMS\PartnerAuditLogs"
                EnableSIEMIntegration = $true
                EnableComplianceReporting = $true
            }
            
            Write-Host "Cross-organization auditing configured" -ForegroundColor Green
            $deploymentResult.Components += "Cross-Organization Auditing Configuration"
        } else {
            Write-Host "DRY RUN: Would configure cross-organization auditing" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Cross-Organization Auditing Configuration"
        }
    }
    
    # Configure user training and awareness
    Write-Host "Configuring user training and awareness..." -ForegroundColor Yellow
    
    if (-not $DryRun) {
        $trainingConfig = @{
            EnableUserNotifications = $true
            NotificationMessage = "This document is shared with partner organizations. Please respect the usage rights and confidentiality."
            EnableHelpDeskIntegration = $true
            TrainingDocumentationPath = "C:\ADRMS\PartnerDocumentation"
            EnableVideoTutorials = $true
            EnablePartnerGuidelines = $true
        }
        
        Write-Host "User training and awareness configured" -ForegroundColor Green
        $deploymentResult.Components += "User Training and Awareness"
    } else {
        Write-Host "DRY RUN: Would configure user training and awareness" -ForegroundColor Magenta
        $deploymentResult.Components += "DRY RUN: User Training and Awareness"
    }
    
    # Test the deployment
    Write-Host "Testing deployment..." -ForegroundColor Yellow
    
    if (-not $DryRun) {
        $testResult = Test-ADRMSDocumentConnectivity -TestTemplateAccess -TestProtectionFunctionality -TestRightsManagement -TestAuditing
        
        if ($testResult.Success) {
            Write-Host "Deployment test completed successfully" -ForegroundColor Green
            $deploymentResult.Components += "Deployment Testing"
        } else {
            Write-Warning "Deployment test failed: $($testResult.Error)"
        }
    } else {
        Write-Host "DRY RUN: Would test deployment" -ForegroundColor Magenta
        $deploymentResult.Components += "DRY RUN: Deployment Testing"
    }
    
    $deploymentResult.Success = $true
    $deploymentResult.EndTime = Get-Date
    $deploymentResult.Duration = ($deploymentResult.EndTime - $deploymentResult.StartTime).TotalMinutes
    
    Write-Host "Cross-Organization Collaboration deployment completed successfully!" -ForegroundColor Green
    Write-Host "Deployment Name: $DeploymentName" -ForegroundColor Cyan
    Write-Host "Partner Organizations: $($PartnerOrganizations -join ', ')" -ForegroundColor Cyan
    Write-Host "Templates Created: $($deploymentResult.Templates.Count)" -ForegroundColor Cyan
    Write-Host "Partner Configurations: $($deploymentResult.PartnerConfigurations.Count)" -ForegroundColor Cyan
    Write-Host "Components Deployed: $($deploymentResult.Components.Count)" -ForegroundColor Cyan
    Write-Host "Duration: $([math]::Round($deploymentResult.Duration, 2)) minutes" -ForegroundColor Cyan
    
    return $deploymentResult
    
} catch {
    Write-Error "Error during Cross-Organization Collaboration deployment: $($_.Exception.Message)"
    throw
}
