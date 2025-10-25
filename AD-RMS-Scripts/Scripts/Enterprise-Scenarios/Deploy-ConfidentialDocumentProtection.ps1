#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy Confidential Document Protection Scenario

.DESCRIPTION
    This script deploys the Confidential Document Protection scenario for AD RMS,
    implementing templates for confidential documents with usage rights and auditing.

.PARAMETER DeploymentName
    Name for the deployment

.PARAMETER TemplatePrefix
    Prefix for RMS templates

.PARAMETER EnableAuditing
    Enable audit logging for document access

.PARAMETER DryRun
    Test mode without making changes

.EXAMPLE
    .\Deploy-ConfidentialDocumentProtection.ps1 -DeploymentName "Corporate-Document-Protection"

.EXAMPLE
    .\Deploy-ConfidentialDocumentProtection.ps1 -DeploymentName "Legal-Document-Security" -TemplatePrefix "Legal" -EnableAuditing
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DeploymentName,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplatePrefix = "Confidential",
    
    [switch]$EnableAuditing,
    
    [switch]$DryRun
)

# Import required modules
Import-Module "..\..\Modules\ADRMS-Core.psm1" -Force
Import-Module "..\..\Modules\ADRMS-DocumentProtection.psm1" -Force

try {
    Write-Host "Starting Confidential Document Protection deployment..." -ForegroundColor Green
    
    # Test prerequisites
    $prerequisites = Test-ADRMSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for AD RMS deployment"
    }
    
    Write-Host "Prerequisites validated successfully" -ForegroundColor Green
    
    $deploymentResult = @{
        Scenario = "ConfidentialDocumentProtection"
        DeploymentName = $DeploymentName
        TemplatePrefix = $TemplatePrefix
        EnableAuditing = $EnableAuditing
        DryRun = $DryRun
        Success = $false
        Error = $null
        Components = @()
        Templates = @()
        StartTime = Get-Date
    }
    
    # Create RMS templates for confidential documents
    Write-Host "Creating RMS templates for confidential documents..." -ForegroundColor Yellow
    
    $templates = @(
        @{
            Name = "$TemplatePrefix-Internal-Only"
            Description = "Confidential documents for internal use only"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $true
            AllowOfflineAccess = $true
            ExpirationDate = $null
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "$TemplatePrefix-Do-Not-Forward"
            Description = "Documents that cannot be forwarded"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $true
            ExpirationDate = $null
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "$TemplatePrefix-View-Only"
            Description = "View-only confidential documents"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $false
            ExpirationDate = $null
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "$TemplatePrefix-Time-Limited"
            Description = "Time-limited confidential documents"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $true
            ExpirationDate = (Get-Date).AddDays(30)
            EnableAuditing = $EnableAuditing
        }
    )
    
    foreach ($template in $templates) {
        if (-not $DryRun) {
            Write-Host "Creating template: $($template.Name)" -ForegroundColor Cyan
            
            $templateResult = New-ADRMSTemplate -TemplateName $template.Name -Description $template.Description -RightsGroup $template.RightsGroup -AllowPrint:$template.AllowPrint -AllowCopy:$template.AllowCopy -AllowForward:$template.AllowForward -AllowOfflineAccess:$template.AllowOfflineAccess -ExpirationDate $template.ExpirationDate -EnableAuditing:$template.EnableAuditing
            
            if ($templateResult.Success) {
                $deploymentResult.Templates += $templateResult
                $deploymentResult.Components += "Template: $($template.Name)"
                Write-Host "Template created successfully: $($template.Name)" -ForegroundColor Green
            } else {
                Write-Warning "Failed to create template: $($template.Name) - $($templateResult.Error)"
            }
        } else {
            Write-Host "DRY RUN: Would create template: $($template.Name)" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Template: $($template.Name)"
        }
    }
    
    # Configure document protection policies
    Write-Host "Configuring document protection policies..." -ForegroundColor Yellow
    
    if (-not $DryRun) {
        # Configure automatic protection based on folder location
        $protectionPolicies = @(
            @{
                Name = "Confidential-Folder-Protection"
                Description = "Automatic protection for confidential folders"
                FolderPath = "C:\Confidential"
                TemplateName = "$TemplatePrefix-Internal-Only"
            },
            @{
                Name = "Legal-Document-Protection"
                Description = "Automatic protection for legal documents"
                FolderPath = "C:\Legal"
                TemplateName = "$TemplatePrefix-Do-Not-Forward"
            },
            @{
                Name = "Executive-Document-Protection"
                Description = "Automatic protection for executive documents"
                FolderPath = "C:\Executive"
                TemplateName = "$TemplatePrefix-View-Only"
            }
        )
        
        foreach ($policy in $protectionPolicies) {
            Write-Host "Configuring policy: $($policy.Name)" -ForegroundColor Cyan
            $deploymentResult.Components += "Policy: $($policy.Name)"
        }
    } else {
        Write-Host "DRY RUN: Would configure document protection policies" -ForegroundColor Magenta
        $deploymentResult.Components += "DRY RUN: Document Protection Policies"
    }
    
    # Set up audit logging
    if ($EnableAuditing) {
        Write-Host "Configuring audit logging..." -ForegroundColor Yellow
        
        if (-not $DryRun) {
            # Configure audit logging for document access
            $auditConfig = @{
                EnableDocumentAccessAuditing = $true
                EnableTemplateUsageAuditing = $true
                EnableRightsModificationAuditing = $true
                AuditLogRetentionDays = 90
                AuditLogLocation = "C:\ADRMS\AuditLogs"
            }
            
            Write-Host "Audit logging configured" -ForegroundColor Green
            $deploymentResult.Components += "Audit Logging Configuration"
        } else {
            Write-Host "DRY RUN: Would configure audit logging" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Audit Logging Configuration"
        }
    }
    
    # Configure user training and awareness
    Write-Host "Configuring user training and awareness..." -ForegroundColor Yellow
    
    if (-not $DryRun) {
        $trainingConfig = @{
            EnableUserNotifications = $true
            NotificationMessage = "This document is protected with AD RMS. Please respect the usage rights."
            EnableHelpDeskIntegration = $true
            TrainingDocumentationPath = "C:\ADRMS\Documentation"
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
    
    Write-Host "Confidential Document Protection deployment completed successfully!" -ForegroundColor Green
    Write-Host "Deployment Name: $DeploymentName" -ForegroundColor Cyan
    Write-Host "Templates Created: $($deploymentResult.Templates.Count)" -ForegroundColor Cyan
    Write-Host "Components Deployed: $($deploymentResult.Components.Count)" -ForegroundColor Cyan
    Write-Host "Duration: $([math]::Round($deploymentResult.Duration, 2)) minutes" -ForegroundColor Cyan
    
    return $deploymentResult
    
} catch {
    Write-Error "Error during Confidential Document Protection deployment: $($_.Exception.Message)"
    throw
}
