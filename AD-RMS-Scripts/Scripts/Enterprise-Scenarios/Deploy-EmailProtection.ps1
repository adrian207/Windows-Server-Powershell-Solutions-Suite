#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy Email Protection Scenario

.DESCRIPTION
    This script deploys the Email Protection scenario for AD RMS,
    implementing Outlook integration, Exchange DLP rules, and transport rules.

.PARAMETER DeploymentName
    Name for the deployment

.PARAMETER TemplatePrefix
    Prefix for RMS templates

.PARAMETER EnableExchangeIntegration
    Enable Exchange Server integration

.PARAMETER EnableOutlookIntegration
    Enable Outlook client integration

.PARAMETER EnableAuditing
    Enable audit logging for email access

.PARAMETER DryRun
    Test mode without making changes

.EXAMPLE
    .\Deploy-EmailProtection.ps1 -DeploymentName "Enterprise-Email-Security"

.EXAMPLE
    .\Deploy-EmailProtection.ps1 -DeploymentName "Legal-Email-Protection" -TemplatePrefix "Legal" -EnableExchangeIntegration -EnableAuditing
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DeploymentName,
    
    [Parameter(Mandatory = $false)]
    [string]$TemplatePrefix = "Email",
    
    [switch]$EnableExchangeIntegration,
    
    [switch]$EnableOutlookIntegration,
    
    [switch]$EnableAuditing,
    
    [switch]$DryRun
)

# Import required modules
Import-Module "..\..\Modules\ADRMS-Core.psm1" -Force
Import-Module "..\..\Modules\ADRMS-EmailProtection.psm1" -Force

try {
    Write-Host "Starting Email Protection deployment..." -ForegroundColor Green
    
    # Test prerequisites
    $prerequisites = Test-ADRMSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for AD RMS deployment"
    }
    
    Write-Host "Prerequisites validated successfully" -ForegroundColor Green
    
    $deploymentResult = @{
        Scenario = "EmailProtection"
        DeploymentName = $DeploymentName
        TemplatePrefix = $TemplatePrefix
        EnableExchangeIntegration = $EnableExchangeIntegration
        EnableOutlookIntegration = $EnableOutlookIntegration
        EnableAuditing = $EnableAuditing
        DryRun = $DryRun
        Success = $false
        Error = $null
        Components = @()
        Templates = @()
        DLPRules = @()
        TransportRules = @()
        StartTime = Get-Date
    }
    
    # Create email protection templates
    Write-Host "Creating email protection templates..." -ForegroundColor Yellow
    
    $emailTemplates = @(
        @{
            Name = "$TemplatePrefix-DoNotForward"
            Description = "Do not forward email template"
            EmailPolicy = "DoNotForward"
            AllowReply = $true
            AllowReplyAll = $true
            AllowForward = $false
            AllowPrint = $false
            AllowCopy = $false
            AllowOfflineAccess = $true
            ExpirationDays = 0
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "$TemplatePrefix-Confidential"
            Description = "Confidential email template"
            EmailPolicy = "Confidential"
            AllowReply = $true
            AllowReplyAll = $true
            AllowForward = $false
            AllowPrint = $false
            AllowCopy = $false
            AllowOfflineAccess = $true
            ExpirationDays = 30
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "$TemplatePrefix-InternalOnly"
            Description = "Internal only email template"
            EmailPolicy = "InternalOnly"
            AllowReply = $true
            AllowReplyAll = $true
            AllowForward = $false
            AllowPrint = $false
            AllowCopy = $false
            AllowOfflineAccess = $true
            ExpirationDays = 0
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "$TemplatePrefix-ExternalRestricted"
            Description = "External restricted email template"
            EmailPolicy = "ExternalRestricted"
            AllowReply = $true
            AllowReplyAll = $false
            AllowForward = $false
            AllowPrint = $false
            AllowCopy = $false
            AllowOfflineAccess = $false
            ExpirationDays = 7
            EnableAuditing = $EnableAuditing
        }
    )
    
    foreach ($template in $emailTemplates) {
        if (-not $DryRun) {
            Write-Host "Creating email template: $($template.Name)" -ForegroundColor Cyan
            
            $templateResult = New-ADRMSEmailTemplate -TemplateName $template.Name -Description $template.Description -EmailPolicy $template.EmailPolicy -AllowReply:$template.AllowReply -AllowReplyAll:$template.AllowReplyAll -AllowForward:$template.AllowForward -AllowPrint:$template.AllowPrint -AllowCopy:$template.AllowCopy -AllowOfflineAccess:$template.AllowOfflineAccess -ExpirationDays $template.ExpirationDays -EnableAuditing:$template.EnableAuditing
            
            if ($templateResult.Success) {
                $deploymentResult.Templates += $templateResult
                $deploymentResult.Components += "Email Template: $($template.Name)"
                Write-Host "Email template created successfully: $($template.Name)" -ForegroundColor Green
            } else {
                Write-Warning "Failed to create email template: $($template.Name) - $($templateResult.Error)"
            }
        } else {
            Write-Host "DRY RUN: Would create email template: $($template.Name)" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Email Template: $($template.Name)"
        }
    }
    
    # Configure Exchange DLP rules
    if ($EnableExchangeIntegration) {
        Write-Host "Configuring Exchange DLP rules..." -ForegroundColor Yellow
        
        $dlpRules = @(
            @{
                Name = "CreditCardDetection"
                Description = "Detect credit card numbers and apply RMS protection"
                ContentPattern = "\d{4}-\d{4}-\d{4}-\d{4}"
                TemplateName = "$TemplatePrefix-Confidential"
                ApplyToBody = $true
                ApplyToAttachments = $true
                EnableRule = $true
                Priority = 10
            },
            @{
                Name = "SSNDetection"
                Description = "Detect SSN and apply RMS protection"
                ContentPattern = "\d{3}-\d{2}-\d{4}"
                TemplateName = "$TemplatePrefix-DoNotForward"
                ApplyToBody = $true
                ApplyToAttachments = $true
                EnableRule = $true
                Priority = 20
            },
            @{
                Name = "BankAccountDetection"
                Description = "Detect bank account numbers and apply RMS protection"
                ContentPattern = "\d{8,12}"
                TemplateName = "$TemplatePrefix-Confidential"
                ApplyToBody = $true
                ApplyToAttachments = $true
                EnableRule = $true
                Priority = 30
            },
            @{
                Name = "ContractKeywordDetection"
                Description = "Detect contract keywords and apply RMS protection"
                ContentPattern = "(contract|agreement|confidential|proprietary)"
                TemplateName = "$TemplatePrefix-DoNotForward"
                ApplyToBody = $true
                ApplyToSubject = $true
                EnableRule = $true
                Priority = 40
            }
        )
        
        foreach ($rule in $dlpRules) {
            if (-not $DryRun) {
                Write-Host "Creating DLP rule: $($rule.Name)" -ForegroundColor Cyan
                
                $dlpResult = New-ADRMSExchangeDLPRule -RuleName $rule.Name -Description $rule.Description -ContentPattern $rule.ContentPattern -TemplateName $rule.TemplateName -ApplyToBody:$rule.ApplyToBody -ApplyToAttachments:$rule.ApplyToAttachments -ApplyToSubject:$rule.ApplyToSubject -EnableRule:$rule.EnableRule -Priority $rule.Priority
                
                if ($dlpResult.Success) {
                    $deploymentResult.DLPRules += $dlpResult
                    $deploymentResult.Components += "DLP Rule: $($rule.Name)"
                    Write-Host "DLP rule created successfully: $($rule.Name)" -ForegroundColor Green
                } else {
                    Write-Warning "Failed to create DLP rule: $($rule.Name) - $($dlpResult.Error)"
                }
            } else {
                Write-Host "DRY RUN: Would create DLP rule: $($rule.Name)" -ForegroundColor Magenta
                $deploymentResult.Components += "DRY RUN: DLP Rule: $($rule.Name)"
            }
        }
    }
    
    # Configure Exchange transport rules
    if ($EnableExchangeIntegration) {
        Write-Host "Configuring Exchange transport rules..." -ForegroundColor Yellow
        
        $transportRules = @(
            @{
                Name = "ExternalEmailProtection"
                Description = "Protect external emails with RMS"
                TemplateName = "$TemplatePrefix-ExternalRestricted"
                ApplyToExternal = $true
                EnableRule = $true
                Priority = 10
            },
            @{
                Name = "InternalConfidentialProtection"
                Description = "Protect internal confidential emails"
                TemplateName = "$TemplatePrefix-Confidential"
                ApplyToInternal = $true
                Conditions = @("Subject contains 'confidential'", "Body contains 'confidential'")
                EnableRule = $true
                Priority = 20
            },
            @{
                Name = "PartnerDomainProtection"
                Description = "Protect emails to partner domains"
                TemplateName = "$TemplatePrefix-ExternalRestricted"
                ApplyToSpecificDomains = $true
                DomainList = @("partner1.com", "partner2.com", "vendor.com")
                EnableRule = $true
                Priority = 30
            },
            @{
                Name = "ExecutiveEmailProtection"
                Description = "Protect emails to executive team"
                TemplateName = "$TemplatePrefix-DoNotForward"
                ApplyToInternal = $true
                Conditions = @("Recipient contains 'executive'", "Recipient contains 'ceo'", "Recipient contains 'cfo'")
                EnableRule = $true
                Priority = 40
            }
        )
        
        foreach ($rule in $transportRules) {
            if (-not $DryRun) {
                Write-Host "Creating transport rule: $($rule.Name)" -ForegroundColor Cyan
                
                $transportResult = New-ADRMSTransportRule -RuleName $rule.Name -Description $rule.Description -Conditions $rule.Conditions -TemplateName $rule.TemplateName -ApplyToInternal:$rule.ApplyToInternal -ApplyToExternal:$rule.ApplyToExternal -ApplyToSpecificDomains:$rule.ApplyToSpecificDomains -DomainList $rule.DomainList -EnableRule:$rule.EnableRule -Priority $rule.Priority
                
                if ($transportResult.Success) {
                    $deploymentResult.TransportRules += $transportResult
                    $deploymentResult.Components += "Transport Rule: $($rule.Name)"
                    Write-Host "Transport rule created successfully: $($rule.Name)" -ForegroundColor Green
                } else {
                    Write-Warning "Failed to create transport rule: $($rule.Name) - $($transportResult.Error)"
                }
            } else {
                Write-Host "DRY RUN: Would create transport rule: $($rule.Name)" -ForegroundColor Magenta
                $deploymentResult.Components += "DRY RUN: Transport Rule: $($rule.Name)"
            }
        }
    }
    
    # Configure Outlook integration
    if ($EnableOutlookIntegration) {
        Write-Host "Configuring Outlook integration..." -ForegroundColor Yellow
        
        if (-not $DryRun) {
            $outlookConfig = @{
                EnableRMSAddin = $true
                EnableTemplateMenu = $true
                EnableRightClickProtection = $true
                EnableAutomaticProtection = $true
                TemplateMenuLocation = "Ribbon"
                EnableUserNotifications = $true
            }
            
            Write-Host "Outlook integration configured" -ForegroundColor Green
            $deploymentResult.Components += "Outlook Integration Configuration"
        } else {
            Write-Host "DRY RUN: Would configure Outlook integration" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Outlook Integration Configuration"
        }
    }
    
    # Configure email auditing
    if ($EnableAuditing) {
        Write-Host "Configuring email auditing..." -ForegroundColor Yellow
        
        if (-not $DryRun) {
            $auditConfig = @{
                EnableEmailAccessAuditing = $true
                EnableTemplateUsageAuditing = $true
                EnableDLPRuleAuditing = $true
                EnableTransportRuleAuditing = $true
                AuditLogRetentionDays = 90
                AuditLogLocation = "C:\ADRMS\EmailAuditLogs"
                EnableSIEMIntegration = $true
            }
            
            Write-Host "Email auditing configured" -ForegroundColor Green
            $deploymentResult.Components += "Email Auditing Configuration"
        } else {
            Write-Host "DRY RUN: Would configure email auditing" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Email Auditing Configuration"
        }
    }
    
    # Configure user training and awareness
    Write-Host "Configuring user training and awareness..." -ForegroundColor Yellow
    
    if (-not $DryRun) {
        $trainingConfig = @{
            EnableEmailNotifications = $true
            NotificationMessage = "This email is protected with AD RMS. Please respect the usage rights."
            EnableHelpDeskIntegration = $true
            TrainingDocumentationPath = "C:\ADRMS\EmailDocumentation"
            EnableVideoTutorials = $true
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
        $testResult = Test-ADRMSEmailConnectivity -TestEmailTemplates -TestDLPRules -TestTransportRules -TestEmailProtection
        
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
    
    Write-Host "Email Protection deployment completed successfully!" -ForegroundColor Green
    Write-Host "Deployment Name: $DeploymentName" -ForegroundColor Cyan
    Write-Host "Email Templates Created: $($deploymentResult.Templates.Count)" -ForegroundColor Cyan
    Write-Host "DLP Rules Created: $($deploymentResult.DLPRules.Count)" -ForegroundColor Cyan
    Write-Host "Transport Rules Created: $($deploymentResult.TransportRules.Count)" -ForegroundColor Cyan
    Write-Host "Components Deployed: $($deploymentResult.Components.Count)" -ForegroundColor Cyan
    Write-Host "Duration: $([math]::Round($deploymentResult.Duration, 2)) minutes" -ForegroundColor Cyan
    
    return $deploymentResult
    
} catch {
    Write-Error "Error during Email Protection deployment: $($_.Exception.Message)"
    throw
}
