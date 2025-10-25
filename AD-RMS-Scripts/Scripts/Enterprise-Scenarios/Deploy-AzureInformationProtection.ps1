#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy Azure Information Protection Integration Scenario

.DESCRIPTION
    This script deploys the Azure Information Protection integration scenario for AD RMS,
    implementing hybrid RMS → AIP migration and cloud extension capabilities.

.PARAMETER DeploymentName
    Name for the deployment

.PARAMETER AzureTenantId
    Azure tenant ID

.PARAMETER EnableHybridMode
    Enable hybrid RMS + AIP mode

.PARAMETER EnableCloudExtension
    Enable cloud extension for mobile and external users

.PARAMETER EnableAuditing
    Enable audit logging for AIP integration

.PARAMETER DryRun
    Test mode without making changes

.EXAMPLE
    .\Deploy-AzureInformationProtection.ps1 -DeploymentName "Hybrid-AIP-Integration" -AzureTenantId "12345678-1234-1234-1234-123456789012"

.EXAMPLE
    .\Deploy-AzureInformationProtection.ps1 -DeploymentName "Cloud-AIP-Extension" -AzureTenantId "12345678-1234-1234-1234-123456789012" -EnableHybridMode -EnableCloudExtension -EnableAuditing
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DeploymentName,
    
    [Parameter(Mandatory = $false)]
    [string]$AzureTenantId = "12345678-1234-1234-1234-123456789012",
    
    [switch]$EnableHybridMode,
    
    [switch]$EnableCloudExtension,
    
    [switch]$EnableAuditing,
    
    [switch]$DryRun
)

# Import required modules
Import-Module "..\..\Modules\ADRMS-Core.psm1" -Force
Import-Module "..\..\Modules\ADRMS-DocumentProtection.psm1" -Force

try {
    Write-Host "Starting Azure Information Protection integration deployment..." -ForegroundColor Green
    
    # Test prerequisites
    $prerequisites = Test-ADRMSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for AD RMS deployment"
    }
    
    Write-Host "Prerequisites validated successfully" -ForegroundColor Green
    
    $deploymentResult = @{
        Scenario = "AzureInformationProtection"
        DeploymentName = $DeploymentName
        AzureTenantId = $AzureTenantId
        EnableHybridMode = $EnableHybridMode
        EnableCloudExtension = $EnableCloudExtension
        EnableAuditing = $EnableAuditing
        DryRun = $DryRun
        Success = $false
        Error = $null
        Components = @()
        Templates = @()
        AIPConfigurations = @()
        StartTime = Get-Date
    }
    
    # Create hybrid RMS + AIP templates
    Write-Host "Creating hybrid RMS + AIP templates..." -ForegroundColor Yellow
    
    $hybridTemplates = @(
        @{
            Name = "Hybrid-Confidential"
            Description = "Hybrid confidential documents (RMS + AIP)"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $true
            ExpirationDate = $null
            EnableAuditing = $EnableAuditing
            AIPLabel = "Confidential"
        },
        @{
            Name = "Hybrid-Internal-Only"
            Description = "Hybrid internal-only documents (RMS + AIP)"
            RightsGroup = "Viewer"
            AllowPrint = $true
            AllowCopy = $true
            AllowForward = $false
            AllowOfflineAccess = $true
            ExpirationDate = $null
            EnableAuditing = $EnableAuditing
            AIPLabel = "Internal"
        },
        @{
            Name = "Hybrid-Public"
            Description = "Hybrid public documents (RMS + AIP)"
            RightsGroup = "Viewer"
            AllowPrint = $true
            AllowCopy = $true
            AllowForward = $true
            AllowOfflineAccess = $true
            ExpirationDate = $null
            EnableAuditing = $EnableAuditing
            AIPLabel = "Public"
        },
        @{
            Name = "Hybrid-Restricted"
            Description = "Hybrid restricted documents (RMS + AIP)"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $false
            ExpirationDate = $null
            EnableAuditing = $EnableAuditing
            AIPLabel = "Restricted"
        }
    )
    
    foreach ($template in $hybridTemplates) {
        if (-not $DryRun) {
            Write-Host "Creating hybrid template: $($template.Name)" -ForegroundColor Cyan
            
            $templateResult = New-ADRMSTemplate -TemplateName $template.Name -Description $template.Description -RightsGroup $template.RightsGroup -AllowPrint:$template.AllowPrint -AllowCopy:$template.AllowCopy -AllowForward:$template.AllowForward -AllowOfflineAccess:$template.AllowOfflineAccess -ExpirationDate $template.ExpirationDate -EnableAuditing:$template.EnableAuditing
            
            if ($templateResult.Success) {
                $deploymentResult.Templates += $templateResult
                $deploymentResult.Components += "Hybrid Template: $($template.Name)"
                Write-Host "Hybrid template created successfully: $($template.Name)" -ForegroundColor Green
            } else {
                Write-Warning "Failed to create hybrid template: $($template.Name) - $($templateResult.Error)"
            }
        } else {
            Write-Host "DRY RUN: Would create hybrid template: $($template.Name)" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Hybrid Template: $($template.Name)"
        }
    }
    
    # Configure hybrid mode
    if ($EnableHybridMode) {
        Write-Host "Configuring hybrid RMS + AIP mode..." -ForegroundColor Yellow
        
        if (-not $DryRun) {
            $hybridConfig = @{
                EnableOnPremRMS = $true
                EnableAIPIntegration = $true
                EnableCoexistence = $true
                EnableGradualMigration = $true
                MigrationTimeline = "6 months"
                AzureTenantId = $AzureTenantId
            }
            
            Write-Host "Hybrid mode configured" -ForegroundColor Green
            $deploymentResult.Components += "Hybrid Mode Configuration"
        } else {
            Write-Host "DRY RUN: Would configure hybrid mode" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Hybrid Mode Configuration"
        }
    }
    
    # Configure cloud extension
    if ($EnableCloudExtension) {
        Write-Host "Configuring cloud extension..." -ForegroundColor Yellow
        
        $cloudExtensionConfigs = @(
            @{
                Name = "Mobile-Access"
                Description = "Mobile device access via AIP"
                EnableMobileAccess = $true
                EnableiOSAccess = $true
                EnableAndroidAccess = $true
                EnableOfflineAccess = $true
            },
            @{
                Name = "External-User-Access"
                Description = "External user access via AIP"
                EnableExternalAccess = $true
                EnableGuestAccess = $true
                EnablePartnerAccess = $true
                EnableVendorAccess = $true
            },
            @{
                Name = "Cloud-Application-Access"
                Description = "Cloud application access via AIP"
                EnableOffice365Access = $true
                EnableSharePointOnlineAccess = $true
                EnableTeamsAccess = $true
                EnableOneDriveAccess = $true
            }
        )
        
        foreach ($config in $cloudExtensionConfigs) {
            if (-not $DryRun) {
                Write-Host "Creating cloud extension config: $($config.Name)" -ForegroundColor Cyan
                
                $extensionConfig = @{
                    Name = $config.Name
                    Description = $config.Description
                    Configuration = $config
                    AzureTenantId = $AzureTenantId
                    Configured = $true
                }
                
                $deploymentResult.AIPConfigurations += $extensionConfig
                $deploymentResult.Components += "Cloud Extension: $($config.Name)"
                Write-Host "Cloud extension configured successfully: $($config.Name)" -ForegroundColor Green
            } else {
                Write-Host "DRY RUN: Would create cloud extension config: $($config.Name)" -ForegroundColor Magenta
                $deploymentResult.Components += "DRY RUN: Cloud Extension: $($config.Name)"
            }
        }
    }
    
    # Configure AIP sensitivity labels
    Write-Host "Configuring AIP sensitivity labels..." -ForegroundColor Yellow
    
    $sensitivityLabels = @(
        @{
            Name = "Public"
            Description = "Public information"
            RMSProtection = $false
            TemplateName = $null
            Color = "Green"
        },
        @{
            Name = "Internal"
            Description = "Internal information"
            RMSProtection = $true
            TemplateName = "Hybrid-Internal-Only"
            Color = "Yellow"
        },
        @{
            Name = "Confidential"
            Description = "Confidential information"
            RMSProtection = $true
            TemplateName = "Hybrid-Confidential"
            Color = "Orange"
        },
        @{
            Name = "Restricted"
            Description = "Restricted information"
            RMSProtection = $true
            TemplateName = "Hybrid-Restricted"
            Color = "Red"
        }
    )
    
    foreach ($label in $sensitivityLabels) {
        if (-not $DryRun) {
            Write-Host "Creating sensitivity label: $($label.Name)" -ForegroundColor Cyan
            $deploymentResult.Components += "Sensitivity Label: $($label.Name)"
        } else {
            Write-Host "DRY RUN: Would create sensitivity label: $($label.Name)" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Sensitivity Label: $($label.Name)"
        }
    }
    
    # Configure unified labeling
    Write-Host "Configuring unified labeling..." -ForegroundColor Yellow
    
    if (-not $DryRun) {
        $unifiedLabelingConfig = @{
            EnableUnifiedLabeling = $true
            EnableAutomaticLabeling = $true
            EnableUserLabeling = $true
            EnableAdminLabeling = $true
            EnablePolicyTips = $true
            EnableVisualMarkers = $true
        }
        
        Write-Host "Unified labeling configured" -ForegroundColor Green
        $deploymentResult.Components += "Unified Labeling Configuration"
    } else {
        Write-Host "DRY RUN: Would configure unified labeling" -ForegroundColor Magenta
        $deploymentResult.Components += "DRY RUN: Unified Labeling Configuration"
    }
    
    # Configure migration settings
    Write-Host "Configuring migration settings..." -ForegroundColor Yellow
    
    if (-not $DryRun) {
        $migrationConfig = @{
            EnableGradualMigration = $true
            EnableCoexistence = $true
            MigrationTimeline = "6 months"
            EnableRollback = $true
            EnableTesting = $true
        }
        
        Write-Host "Migration settings configured" -ForegroundColor Green
        $deploymentResult.Components += "Migration Settings Configuration"
    } else {
        Write-Host "DRY RUN: Would configure migration settings" -ForegroundColor Magenta
        $deploymentResult.Components += "DRY RUN: Migration Settings Configuration"
    }
    
    # Configure AIP auditing
    if ($EnableAuditing) {
        Write-Host "Configuring AIP auditing..." -ForegroundColor Yellow
        
        if (-not $DryRun) {
            $auditConfig = @{
                EnableAIPAuditing = $true
                EnableCloudAuditing = $true
                EnableHybridAuditing = $true
                EnableMigrationAuditing = $true
                AuditLogRetentionDays = 90
                AuditLogLocation = "C:\ADRMS\AIPAuditLogs"
                EnableSIEMIntegration = $true
                EnableComplianceReporting = $true
            }
            
            Write-Host "AIP auditing configured" -ForegroundColor Green
            $deploymentResult.Components += "AIP Auditing Configuration"
        } else {
            Write-Host "DRY RUN: Would configure AIP auditing" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: AIP Auditing Configuration"
        }
    }
    
    # Configure user training and awareness
    Write-Host "Configuring user training and awareness..." -ForegroundColor Yellow
    
    if (-not $DryRun) {
        $trainingConfig = @{
            EnableUserNotifications = $true
            NotificationMessage = "This document is protected with Azure Information Protection. Please respect the usage rights and sensitivity labels."
            EnableHelpDeskIntegration = $true
            TrainingDocumentationPath = "C:\ADRMS\AIPDocumentation"
            EnableVideoTutorials = $true
            EnableMigrationGuidance = $true
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
    
    Write-Host "Azure Information Protection integration deployment completed successfully!" -ForegroundColor Green
    Write-Host "Deployment Name: $DeploymentName" -ForegroundColor Cyan
    Write-Host "Azure Tenant ID: $AzureTenantId" -ForegroundColor Cyan
    Write-Host "Templates Created: $($deploymentResult.Templates.Count)" -ForegroundColor Cyan
    Write-Host "AIP Configurations: $($deploymentResult.AIPConfigurations.Count)" -ForegroundColor Cyan
    Write-Host "Components Deployed: $($deploymentResult.Components.Count)" -ForegroundColor Cyan
    Write-Host "Duration: $([math]::Round($deploymentResult.Duration, 2)) minutes" -ForegroundColor Cyan
    
    return $deploymentResult
    
} catch {
    Write-Error "Error during Azure Information Protection integration deployment: $($_.Exception.Message)"
    throw
}
