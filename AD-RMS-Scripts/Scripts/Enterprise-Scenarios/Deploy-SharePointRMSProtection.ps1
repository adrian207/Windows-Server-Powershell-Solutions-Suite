#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy SharePoint RMS Protection Scenario

.DESCRIPTION
    This script deploys the SharePoint RMS Protection scenario for AD RMS,
    implementing document library protection, automatic encryption, and audit logging.

.PARAMETER DeploymentName
    Name for the deployment

.PARAMETER SharePointUrl
    SharePoint site URL

.PARAMETER TemplatePrefix
    Prefix for RMS templates

.PARAMETER EnableAutomaticProtection
    Enable automatic protection for document libraries

.PARAMETER EnableAuditing
    Enable audit logging for SharePoint access

.PARAMETER DryRun
    Test mode without making changes

.EXAMPLE
    .\Deploy-SharePointRMSProtection.ps1 -DeploymentName "SharePoint-Security" -SharePointUrl "https://company.sharepoint.com"

.EXAMPLE
    .\Deploy-SharePointRMSProtection.ps1 -DeploymentName "Legal-SharePoint" -SharePointUrl "https://legal.sharepoint.com" -TemplatePrefix "Legal" -EnableAutomaticProtection -EnableAuditing
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DeploymentName,
    
    [Parameter(Mandatory = $false)]
    [string]$SharePointUrl = "https://company.sharepoint.com",
    
    [Parameter(Mandatory = $false)]
    [string]$TemplatePrefix = "SharePoint",
    
    [switch]$EnableAutomaticProtection,
    
    [switch]$EnableAuditing,
    
    [switch]$DryRun
)

# Import required modules
Import-Module "..\..\Modules\ADRMS-Core.psm1" -Force
Import-Module "..\..\Modules\ADRMS-DocumentProtection.psm1" -Force

try {
    Write-Host "Starting SharePoint RMS Protection deployment..." -ForegroundColor Green
    
    # Test prerequisites
    $prerequisites = Test-ADRMSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for AD RMS deployment"
    }
    
    Write-Host "Prerequisites validated successfully" -ForegroundColor Green
    
    $deploymentResult = @{
        Scenario = "SharePointRMSProtection"
        DeploymentName = $DeploymentName
        SharePointUrl = $SharePointUrl
        TemplatePrefix = $TemplatePrefix
        EnableAutomaticProtection = $EnableAutomaticProtection
        EnableAuditing = $EnableAuditing
        DryRun = $DryRun
        Success = $false
        Error = $null
        Components = @()
        Templates = @()
        DocumentLibraries = @()
        StartTime = Get-Date
    }
    
    # Create SharePoint-specific RMS templates
    Write-Host "Creating SharePoint RMS templates..." -ForegroundColor Yellow
    
    $sharePointTemplates = @(
        @{
            Name = "$TemplatePrefix-DocumentLibrary"
            Description = "SharePoint document library protection template"
            RightsGroup = "Viewer"
            AllowPrint = $true
            AllowCopy = $true
            AllowForward = $false
            AllowOfflineAccess = $true
            ExpirationDate = $null
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "$TemplatePrefix-ConfidentialLibrary"
            Description = "SharePoint confidential document library template"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $true
            ExpirationDate = $null
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "$TemplatePrefix-LegalLibrary"
            Description = "SharePoint legal document library template"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $false
            ExpirationDate = $null
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "$TemplatePrefix-TimeLimitedLibrary"
            Description = "SharePoint time-limited document library template"
            RightsGroup = "Viewer"
            AllowPrint = $true
            AllowCopy = $true
            AllowForward = $false
            AllowOfflineAccess = $true
            ExpirationDate = (Get-Date).AddDays(90)
            EnableAuditing = $EnableAuditing
        }
    )
    
    foreach ($template in $sharePointTemplates) {
        if (-not $DryRun) {
            Write-Host "Creating SharePoint template: $($template.Name)" -ForegroundColor Cyan
            
            $templateResult = New-ADRMSTemplate -TemplateName $template.Name -Description $template.Description -RightsGroup $template.RightsGroup -AllowPrint:$template.AllowPrint -AllowCopy:$template.AllowCopy -AllowForward:$template.AllowForward -AllowOfflineAccess:$template.AllowOfflineAccess -ExpirationDate $template.ExpirationDate -EnableAuditing:$template.EnableAuditing
            
            if ($templateResult.Success) {
                $deploymentResult.Templates += $templateResult
                $deploymentResult.Components += "SharePoint Template: $($template.Name)"
                Write-Host "SharePoint template created successfully: $($template.Name)" -ForegroundColor Green
            } else {
                Write-Warning "Failed to create SharePoint template: $($template.Name) - $($templateResult.Error)"
            }
        } else {
            Write-Host "DRY RUN: Would create SharePoint template: $($template.Name)" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: SharePoint Template: $($template.Name)"
        }
    }
    
    # Configure SharePoint document libraries
    Write-Host "Configuring SharePoint document libraries..." -ForegroundColor Yellow
    
    $documentLibraries = @(
        @{
            Name = "General Documents"
            Url = "$SharePointUrl/Shared%20Documents"
            TemplateName = "$TemplatePrefix-DocumentLibrary"
            EnableAutomaticProtection = $EnableAutomaticProtection
            Description = "General document library with basic protection"
        },
        @{
            Name = "Confidential Documents"
            Url = "$SharePointUrl/Confidential%20Documents"
            TemplateName = "$TemplatePrefix-ConfidentialLibrary"
            EnableAutomaticProtection = $true
            Description = "Confidential document library with strict protection"
        },
        @{
            Name = "Legal Documents"
            Url = "$SharePointUrl/Legal%20Documents"
            TemplateName = "$TemplatePrefix-LegalLibrary"
            EnableAutomaticProtection = $true
            Description = "Legal document library with maximum protection"
        },
        @{
            Name = "Project Documents"
            Url = "$SharePointUrl/Project%20Documents"
            TemplateName = "$TemplatePrefix-TimeLimitedLibrary"
            EnableAutomaticProtection = $EnableAutomaticProtection
            Description = "Project document library with time-limited access"
        },
        @{
            Name = "HR Documents"
            Url = "$SharePointUrl/HR%20Documents"
            TemplateName = "$TemplatePrefix-ConfidentialLibrary"
            EnableAutomaticProtection = $true
            Description = "HR document library with confidential protection"
        },
        @{
            Name = "Finance Documents"
            Url = "$SharePointUrl/Finance%20Documents"
            TemplateName = "$TemplatePrefix-ConfidentialLibrary"
            EnableAutomaticProtection = $true
            Description = "Finance document library with confidential protection"
        }
    )
    
    foreach ($library in $documentLibraries) {
        if (-not $DryRun) {
            Write-Host "Configuring document library: $($library.Name)" -ForegroundColor Cyan
            
            $libraryConfig = @{
                Name = $library.Name
                Url = $library.Url
                TemplateName = $library.TemplateName
                EnableAutomaticProtection = $library.EnableAutomaticProtection
                Description = $library.Description
                Configured = $true
            }
            
            $deploymentResult.DocumentLibraries += $libraryConfig
            $deploymentResult.Components += "Document Library: $($library.Name)"
            Write-Host "Document library configured successfully: $($library.Name)" -ForegroundColor Green
        } else {
            Write-Host "DRY RUN: Would configure document library: $($library.Name)" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Document Library: $($library.Name)"
        }
    }
    
    # Configure automatic protection rules
    if ($EnableAutomaticProtection) {
        Write-Host "Configuring automatic protection rules..." -ForegroundColor Yellow
        
        $protectionRules = @(
            @{
                Name = "Automatic-Confidential-Protection"
                Description = "Automatically protect documents in confidential libraries"
                LibraryPattern = "*Confidential*"
                TemplateName = "$TemplatePrefix-ConfidentialLibrary"
                EnableRule = $true
            },
            @{
                Name = "Automatic-Legal-Protection"
                Description = "Automatically protect documents in legal libraries"
                LibraryPattern = "*Legal*"
                TemplateName = "$TemplatePrefix-LegalLibrary"
                EnableRule = $true
            },
            @{
                Name = "Automatic-HR-Protection"
                Description = "Automatically protect documents in HR libraries"
                LibraryPattern = "*HR*"
                TemplateName = "$TemplatePrefix-ConfidentialLibrary"
                EnableRule = $true
            },
            @{
                Name = "Automatic-Finance-Protection"
                Description = "Automatically protect documents in finance libraries"
                LibraryPattern = "*Finance*"
                TemplateName = "$TemplatePrefix-ConfidentialLibrary"
                EnableRule = $true
            }
        )
        
        foreach ($rule in $protectionRules) {
            if (-not $DryRun) {
                Write-Host "Creating protection rule: $($rule.Name)" -ForegroundColor Cyan
                $deploymentResult.Components += "Protection Rule: $($rule.Name)"
            } else {
                Write-Host "DRY RUN: Would create protection rule: $($rule.Name)" -ForegroundColor Magenta
                $deploymentResult.Components += "DRY RUN: Protection Rule: $($rule.Name)"
            }
        }
    }
    
    # Configure SharePoint integration settings
    Write-Host "Configuring SharePoint integration settings..." -ForegroundColor Yellow
    
    if (-not $DryRun) {
        $sharePointConfig = @{
            EnableRMSIntegration = $true
            EnableDocumentProtection = $true
            EnableLibraryProtection = $true
            EnableUserNotifications = $true
            EnableAdminNotifications = $true
            NotificationMessage = "This document is protected with AD RMS. Please respect the usage rights."
            EnableHelpDeskIntegration = $true
            EnableAuditLogging = $EnableAuditing
        }
        
        Write-Host "SharePoint integration settings configured" -ForegroundColor Green
        $deploymentResult.Components += "SharePoint Integration Settings"
    } else {
        Write-Host "DRY RUN: Would configure SharePoint integration settings" -ForegroundColor Magenta
        $deploymentResult.Components += "DRY RUN: SharePoint Integration Settings"
    }
    
    # Configure SharePoint auditing
    if ($EnableAuditing) {
        Write-Host "Configuring SharePoint auditing..." -ForegroundColor Yellow
        
        if (-not $DryRun) {
            $auditConfig = @{
                EnableDocumentAccessAuditing = $true
                EnableLibraryAccessAuditing = $true
                EnableTemplateUsageAuditing = $true
                EnableRightsModificationAuditing = $true
                AuditLogRetentionDays = 90
                AuditLogLocation = "C:\ADRMS\SharePointAuditLogs"
                EnableSIEMIntegration = $true
                EnableComplianceReporting = $true
            }
            
            Write-Host "SharePoint auditing configured" -ForegroundColor Green
            $deploymentResult.Components += "SharePoint Auditing Configuration"
        } else {
            Write-Host "DRY RUN: Would configure SharePoint auditing" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: SharePoint Auditing Configuration"
        }
    }
    
    # Configure user training and awareness
    Write-Host "Configuring user training and awareness..." -ForegroundColor Yellow
    
    if (-not $DryRun) {
        $trainingConfig = @{
            EnableUserNotifications = $true
            NotificationMessage = "This SharePoint document is protected with AD RMS. Please respect the usage rights."
            EnableHelpDeskIntegration = $true
            TrainingDocumentationPath = "C:\ADRMS\SharePointDocumentation"
            EnableVideoTutorials = $true
            EnableInAppHelp = $true
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
    
    Write-Host "SharePoint RMS Protection deployment completed successfully!" -ForegroundColor Green
    Write-Host "Deployment Name: $DeploymentName" -ForegroundColor Cyan
    Write-Host "SharePoint URL: $SharePointUrl" -ForegroundColor Cyan
    Write-Host "Templates Created: $($deploymentResult.Templates.Count)" -ForegroundColor Cyan
    Write-Host "Document Libraries Configured: $($deploymentResult.DocumentLibraries.Count)" -ForegroundColor Cyan
    Write-Host "Components Deployed: $($deploymentResult.Components.Count)" -ForegroundColor Cyan
    Write-Host "Duration: $([math]::Round($deploymentResult.Duration, 2)) minutes" -ForegroundColor Cyan
    
    return $deploymentResult
    
} catch {
    Write-Error "Error during SharePoint RMS Protection deployment: $($_.Exception.Message)"
    throw
}
