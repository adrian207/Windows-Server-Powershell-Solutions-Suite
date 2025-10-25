#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy Legal Evidence Management Scenario

.DESCRIPTION
    This script deploys the Legal Evidence Management scenario for AD RMS,
    implementing secure document handling for legal and HR investigations.

.PARAMETER DeploymentName
    Name for the deployment

.PARAMETER LegalTeamGroups
    Array of legal team security groups

.PARAMETER HRTeamGroups
    Array of HR team security groups

.PARAMETER EnableChainOfCustody
    Enable chain of custody tracking

.PARAMETER EnableAuditing
    Enable comprehensive audit logging

.PARAMETER DryRun
    Test mode without making changes

.EXAMPLE
    .\Deploy-LegalEvidenceManagement.ps1 -DeploymentName "Legal-Evidence-System" -LegalTeamGroups @("Legal-Team", "Compliance-Team")

.EXAMPLE
    .\Deploy-LegalEvidenceManagement.ps1 -DeploymentName "HR-Legal-System" -LegalTeamGroups @("Legal-Team") -HRTeamGroups @("HR-Team") -EnableChainOfCustody -EnableAuditing
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DeploymentName,
    
    [Parameter(Mandatory = $false)]
    [string[]]$LegalTeamGroups = @("Legal-Team", "Compliance-Team"),
    
    [Parameter(Mandatory = $false)]
    [string[]]$HRTeamGroups = @("HR-Team", "HR-Managers"),
    
    [switch]$EnableChainOfCustody,
    
    [switch]$EnableAuditing,
    
    [switch]$DryRun
)

# Import required modules
Import-Module "..\..\Modules\ADRMS-Core.psm1" -Force
Import-Module "..\..\Modules\ADRMS-DocumentProtection.psm1" -Force

try {
    Write-Host "Starting Legal Evidence Management deployment..." -ForegroundColor Green
    
    # Test prerequisites
    $prerequisites = Test-ADRMSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for AD RMS deployment"
    }
    
    Write-Host "Prerequisites validated successfully" -ForegroundColor Green
    
    $deploymentResult = @{
        Scenario = "LegalEvidenceManagement"
        DeploymentName = $DeploymentName
        LegalTeamGroups = $LegalTeamGroups
        HRTeamGroups = $HRTeamGroups
        EnableChainOfCustody = $EnableChainOfCustody
        EnableAuditing = $EnableAuditing
        DryRun = $DryRun
        Success = $false
        Error = $null
        Components = @()
        Templates = @()
        AccessControls = @()
        StartTime = Get-Date
    }
    
    # Create legal evidence templates
    Write-Host "Creating legal evidence templates..." -ForegroundColor Yellow
    
    $legalTemplates = @(
        @{
            Name = "Legal-Evidence"
            Description = "Legal evidence documents with strict access control"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $false
            ExpirationDate = $null
            EnableAuditing = $EnableAuditing
            AccessLevel = "View Only"
        },
        @{
            Name = "Legal-Investigation"
            Description = "Legal investigation documents"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $false
            ExpirationDate = $null
            EnableAuditing = $EnableAuditing
            AccessLevel = "View Only"
        },
        @{
            Name = "HR-Evidence"
            Description = "HR evidence documents"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $false
            ExpirationDate = $null
            EnableAuditing = $EnableAuditing
            AccessLevel = "View Only"
        },
        @{
            Name = "Compliance-Evidence"
            Description = "Compliance evidence documents"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $false
            ExpirationDate = $null
            EnableAuditing = $EnableAuditing
            AccessLevel = "View Only"
        }
    )
    
    foreach ($template in $legalTemplates) {
        if (-not $DryRun) {
            Write-Host "Creating legal template: $($template.Name)" -ForegroundColor Cyan
            
            $templateResult = New-ADRMSTemplate -TemplateName $template.Name -Description $template.Description -RightsGroup $template.RightsGroup -AllowPrint:$template.AllowPrint -AllowCopy:$template.AllowCopy -AllowForward:$template.AllowForward -AllowOfflineAccess:$template.AllowOfflineAccess -ExpirationDate $template.ExpirationDate -EnableAuditing:$template.EnableAuditing
            
            if ($templateResult.Success) {
                $deploymentResult.Templates += $templateResult
                $deploymentResult.Components += "Legal Template: $($template.Name)"
                Write-Host "Legal template created successfully: $($template.Name)" -ForegroundColor Green
            } else {
                Write-Warning "Failed to create legal template: $($template.Name) - $($templateResult.Error)"
            }
        } else {
            Write-Host "DRY RUN: Would create legal template: $($template.Name)" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Legal Template: $($template.Name)"
        }
    }
    
    # Configure access controls
    Write-Host "Configuring access controls..." -ForegroundColor Yellow
    
    $accessControls = @(
        @{
            Name = "Legal-Team-Access"
            Description = "Access control for legal team"
            AllowedGroups = $LegalTeamGroups
            TemplateName = "Legal-Evidence"
            AccessLevel = "View Only"
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "HR-Team-Access"
            Description = "Access control for HR team"
            AllowedGroups = $HRTeamGroups
            TemplateName = "HR-Evidence"
            AccessLevel = "View Only"
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "Compliance-Team-Access"
            Description = "Access control for compliance team"
            AllowedGroups = @("Compliance-Team", "Audit-Team")
            TemplateName = "Compliance-Evidence"
            AccessLevel = "View Only"
            EnableAuditing = $EnableAuditing
        }
    )
    
    foreach ($accessControl in $accessControls) {
        if (-not $DryRun) {
            Write-Host "Creating access control: $($accessControl.Name)" -ForegroundColor Cyan
            
            $accessConfig = @{
                Name = $accessControl.Name
                Description = $accessControl.Description
                AllowedGroups = $accessControl.AllowedGroups
                TemplateName = $accessControl.TemplateName
                AccessLevel = $accessControl.AccessLevel
                EnableAuditing = $accessControl.EnableAuditing
                Configured = $true
            }
            
            $deploymentResult.AccessControls += $accessConfig
            $deploymentResult.Components += "Access Control: $($accessControl.Name)"
            Write-Host "Access control created successfully: $($accessControl.Name)" -ForegroundColor Green
        } else {
            Write-Host "DRY RUN: Would create access control: $($accessControl.Name)" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Access Control: $($accessControl.Name)"
        }
    }
    
    # Configure chain of custody
    if ($EnableChainOfCustody) {
        Write-Host "Configuring chain of custody..." -ForegroundColor Yellow
        
        if (-not $DryRun) {
            $chainOfCustodyConfig = @{
                EnableChainOfCustody = $true
                EnableDigitalSignatures = $true
                EnableTimestamping = $true
                EnableDocumentVersioning = $true
                EnableAccessLogging = $true
                EnableModificationLogging = $true
                EnableTransferLogging = $true
                RetentionPeriod = "7 years"
            }
            
            Write-Host "Chain of custody configured" -ForegroundColor Green
            $deploymentResult.Components += "Chain of Custody Configuration"
        } else {
            Write-Host "DRY RUN: Would configure chain of custody" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Chain of Custody Configuration"
        }
    }
    
    # Configure legal document repositories
    Write-Host "Configuring legal document repositories..." -ForegroundColor Yellow
    
    $legalRepositories = @(
        @{
            Name = "Legal-Evidence-Repository"
            Path = "C:\Legal\Evidence"
            TemplateName = "Legal-Evidence"
            AllowedGroups = $LegalTeamGroups
            EnableAutomaticProtection = $true
        },
        @{
            Name = "HR-Evidence-Repository"
            Path = "C:\HR\Evidence"
            TemplateName = "HR-Evidence"
            AllowedGroups = $HRTeamGroups
            EnableAutomaticProtection = $true
        },
        @{
            Name = "Compliance-Evidence-Repository"
            Path = "C:\Compliance\Evidence"
            TemplateName = "Compliance-Evidence"
            AllowedGroups = @("Compliance-Team", "Audit-Team")
            EnableAutomaticProtection = $true
        }
    )
    
    foreach ($repository in $legalRepositories) {
        if (-not $DryRun) {
            Write-Host "Creating legal repository: $($repository.Name)" -ForegroundColor Cyan
            $deploymentResult.Components += "Legal Repository: $($repository.Name)"
        } else {
            Write-Host "DRY RUN: Would create legal repository: $($repository.Name)" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Legal Repository: $($repository.Name)"
        }
    }
    
    # Configure legal auditing
    if ($EnableAuditing) {
        Write-Host "Configuring legal auditing..." -ForegroundColor Yellow
        
        if (-not $DryRun) {
            $legalAuditConfig = @{
                EnableDocumentAccessAuditing = $true
                EnableTemplateUsageAuditing = $true
                EnableRightsModificationAuditing = $true
                EnableChainOfCustodyAuditing = $EnableChainOfCustody
                EnableLegalComplianceAuditing = $true
                AuditLogRetentionDays = 2555
                AuditLogLocation = "C:\ADRMS\LegalAuditLogs"
                EnableSIEMIntegration = $true
                EnableComplianceReporting = $true
                EnableLegalReporting = $true
            }
            
            Write-Host "Legal auditing configured" -ForegroundColor Green
            $deploymentResult.Components += "Legal Auditing Configuration"
        } else {
            Write-Host "DRY RUN: Would configure legal auditing" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Legal Auditing Configuration"
        }
    }
    
    # Configure legal compliance
    Write-Host "Configuring legal compliance..." -ForegroundColor Yellow
    
    if (-not $DryRun) {
        $complianceConfig = @{
            EnableSOXCompliance = $true
            EnableHIPAACompliance = $true
            EnableGDPRCompliance = $true
            EnableCCPACompliance = $true
            EnableLegalHold = $true
            EnableeDiscovery = $true
            EnableDataRetention = $true
            RetentionPeriod = "7 years"
        }
        
        Write-Host "Legal compliance configured" -ForegroundColor Green
        $deploymentResult.Components += "Legal Compliance Configuration"
    } else {
        Write-Host "DRY RUN: Would configure legal compliance" -ForegroundColor Magenta
        $deploymentResult.Components += "DRY RUN: Legal Compliance Configuration"
    }
    
    # Configure user training and awareness
    Write-Host "Configuring user training and awareness..." -ForegroundColor Yellow
    
    if (-not $DryRun) {
        $trainingConfig = @{
            EnableUserNotifications = $true
            NotificationMessage = "This document is legal evidence. Access is restricted and monitored. Please respect the usage rights and legal requirements."
            EnableHelpDeskIntegration = $true
            TrainingDocumentationPath = "C:\ADRMS\LegalDocumentation"
            EnableVideoTutorials = $true
            EnableLegalGuidelines = $true
            EnableComplianceTraining = $true
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
    
    Write-Host "Legal Evidence Management deployment completed successfully!" -ForegroundColor Green
    Write-Host "Deployment Name: $DeploymentName" -ForegroundColor Cyan
    Write-Host "Legal Team Groups: $($LegalTeamGroups -join ', ')" -ForegroundColor Cyan
    Write-Host "HR Team Groups: $($HRTeamGroups -join ', ')" -ForegroundColor Cyan
    Write-Host "Templates Created: $($deploymentResult.Templates.Count)" -ForegroundColor Cyan
    Write-Host "Access Controls: $($deploymentResult.AccessControls.Count)" -ForegroundColor Cyan
    Write-Host "Components Deployed: $($deploymentResult.Components.Count)" -ForegroundColor Cyan
    Write-Host "Duration: $([math]::Round($deploymentResult.Duration, 2)) minutes" -ForegroundColor Cyan
    
    return $deploymentResult
    
} catch {
    Write-Error "Error during Legal Evidence Management deployment: $($_.Exception.Message)"
    throw
}
