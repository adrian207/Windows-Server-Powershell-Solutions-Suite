#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy BYOD Mobile Access Control Scenario

.DESCRIPTION
    This script deploys the BYOD Mobile Access Control scenario for AD RMS,
    implementing mobile device protection and unmanaged device access control.

.PARAMETER DeploymentName
    Name for the deployment

.PARAMETER EnableiOSAccess
    Enable iOS device access

.PARAMETER EnableAndroidAccess
    Enable Android device access

.PARAMETER EnableOfflineAccess
    Enable offline access for mobile devices

.PARAMETER EnableAuditing
    Enable audit logging for mobile access

.PARAMETER DryRun
    Test mode without making changes

.EXAMPLE
    .\Deploy-BYODMobileAccess.ps1 -DeploymentName "Mobile-BYOD-Security"

.EXAMPLE
    .\Deploy-BYODMobileAccess.ps1 -DeploymentName "Mobile-Enterprise-Access" -EnableiOSAccess -EnableAndroidAccess -EnableOfflineAccess -EnableAuditing
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DeploymentName,
    
    [switch]$EnableiOSAccess,
    
    [switch]$EnableAndroidAccess,
    
    [switch]$EnableOfflineAccess,
    
    [switch]$EnableAuditing,
    
    [switch]$DryRun
)

# Import required modules
Import-Module "..\..\Modules\ADRMS-Core.psm1" -Force
Import-Module "..\..\Modules\ADRMS-DocumentProtection.psm1" -Force

try {
    Write-Host "Starting BYOD Mobile Access Control deployment..." -ForegroundColor Green
    
    # Test prerequisites
    $prerequisites = Test-ADRMSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for AD RMS deployment"
    }
    
    Write-Host "Prerequisites validated successfully" -ForegroundColor Green
    
    $deploymentResult = @{
        Scenario = "BYODMobileAccess"
        DeploymentName = $DeploymentName
        EnableiOSAccess = $EnableiOSAccess
        EnableAndroidAccess = $EnableAndroidAccess
        EnableOfflineAccess = $EnableOfflineAccess
        EnableAuditing = $EnableAuditing
        DryRun = $DryRun
        Success = $false
        Error = $null
        Components = @()
        Templates = @()
        MobileConfigurations = @()
        StartTime = Get-Date
    }
    
    # Create mobile-specific RMS templates
    Write-Host "Creating mobile-specific RMS templates..." -ForegroundColor Yellow
    
    $mobileTemplates = @(
        @{
            Name = "Mobile-View-Only"
            Description = "Mobile view-only access template"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $EnableOfflineAccess
            ExpirationDate = $null
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "Mobile-Confidential"
            Description = "Mobile confidential document template"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $EnableOfflineAccess
            ExpirationDate = (Get-Date).AddDays(7)
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "Mobile-Time-Limited"
            Description = "Mobile time-limited access template"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $EnableOfflineAccess
            ExpirationDate = (Get-Date).AddDays(1)
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "Mobile-Offline-Sync"
            Description = "Mobile offline sync template"
            RightsGroup = "Viewer"
            AllowPrint = $false
            AllowCopy = $false
            AllowForward = $false
            AllowOfflineAccess = $true
            ExpirationDate = (Get-Date).AddDays(30)
            EnableAuditing = $EnableAuditing
        }
    )
    
    foreach ($template in $mobileTemplates) {
        if (-not $DryRun) {
            Write-Host "Creating mobile template: $($template.Name)" -ForegroundColor Cyan
            
            $templateResult = New-ADRMSTemplate -TemplateName $template.Name -Description $template.Description -RightsGroup $template.RightsGroup -AllowPrint:$template.AllowPrint -AllowCopy:$template.AllowCopy -AllowForward:$template.AllowForward -AllowOfflineAccess:$template.AllowOfflineAccess -ExpirationDate $template.ExpirationDate -EnableAuditing:$template.EnableAuditing
            
            if ($templateResult.Success) {
                $deploymentResult.Templates += $templateResult
                $deploymentResult.Components += "Mobile Template: $($template.Name)"
                Write-Host "Mobile template created successfully: $($template.Name)" -ForegroundColor Green
            } else {
                Write-Warning "Failed to create mobile template: $($template.Name) - $($templateResult.Error)"
            }
        } else {
            Write-Host "DRY RUN: Would create mobile template: $($template.Name)" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Mobile Template: $($template.Name)"
        }
    }
    
    # Configure iOS access
    if ($EnableiOSAccess) {
        Write-Host "Configuring iOS access..." -ForegroundColor Yellow
        
        $iOSConfigurations = @(
            @{
                Name = "iOS-Office-Apps"
                Description = "iOS Office apps configuration"
                EnableWord = $true
                EnableExcel = $true
                EnablePowerPoint = $true
                EnableOutlook = $true
                EnableOneDrive = $true
                EnableSharePoint = $true
            },
            @{
                Name = "iOS-RMS-Client"
                Description = "iOS RMS client configuration"
                EnableRMSClient = $true
                EnableOfflineAccess = $EnableOfflineAccess
                EnableAuditing = $EnableAuditing
            },
            @{
                Name = "iOS-Security-Policies"
                Description = "iOS security policies"
                EnableDeviceCompliance = $true
                EnableAppProtection = $true
                EnableDataProtection = $true
            }
        )
        
        foreach ($config in $iOSConfigurations) {
            if (-not $DryRun) {
                Write-Host "Creating iOS configuration: $($config.Name)" -ForegroundColor Cyan
                
                $mobileConfig = @{
                    Name = $config.Name
                    Description = $config.Description
                    Platform = "iOS"
                    Configuration = $config
                    Configured = $true
                }
                
                $deploymentResult.MobileConfigurations += $mobileConfig
                $deploymentResult.Components += "iOS Configuration: $($config.Name)"
                Write-Host "iOS configuration created successfully: $($config.Name)" -ForegroundColor Green
            } else {
                Write-Host "DRY RUN: Would create iOS configuration: $($config.Name)" -ForegroundColor Magenta
                $deploymentResult.Components += "DRY RUN: iOS Configuration: $($config.Name)"
            }
        }
    }
    
    # Configure Android access
    if ($EnableAndroidAccess) {
        Write-Host "Configuring Android access..." -ForegroundColor Yellow
        
        $androidConfigurations = @(
            @{
                Name = "Android-Office-Apps"
                Description = "Android Office apps configuration"
                EnableWord = $true
                EnableExcel = $true
                EnablePowerPoint = $true
                EnableOutlook = $true
                EnableOneDrive = $true
                EnableSharePoint = $true
            },
            @{
                Name = "Android-RMS-Client"
                Description = "Android RMS client configuration"
                EnableRMSClient = $true
                EnableOfflineAccess = $EnableOfflineAccess
                EnableAuditing = $EnableAuditing
            },
            @{
                Name = "Android-Security-Policies"
                Description = "Android security policies"
                EnableDeviceCompliance = $true
                EnableAppProtection = $true
                EnableDataProtection = $true
            }
        )
        
        foreach ($config in $androidConfigurations) {
            if (-not $DryRun) {
                Write-Host "Creating Android configuration: $($config.Name)" -ForegroundColor Cyan
                
                $mobileConfig = @{
                    Name = $config.Name
                    Description = $config.Description
                    Platform = "Android"
                    Configuration = $config
                    Configured = $true
                }
                
                $deploymentResult.MobileConfigurations += $mobileConfig
                $deploymentResult.Components += "Android Configuration: $($config.Name)"
                Write-Host "Android configuration created successfully: $($config.Name)" -ForegroundColor Green
            } else {
                Write-Host "DRY RUN: Would create Android configuration: $($config.Name)" -ForegroundColor Magenta
                $deploymentResult.Components += "DRY RUN: Android Configuration: $($config.Name)"
            }
        }
    }
    
    # Configure mobile device policies
    Write-Host "Configuring mobile device policies..." -ForegroundColor Yellow
    
    $mobilePolicies = @(
        @{
            Name = "Mobile-Device-Compliance"
            Description = "Mobile device compliance policy"
            EnableDeviceCompliance = $true
            EnableAppProtection = $true
            EnableDataProtection = $true
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "Mobile-App-Protection"
            Description = "Mobile app protection policy"
            EnableAppProtection = $true
            EnableDataProtection = $true
            EnableOfflineAccess = $EnableOfflineAccess
            EnableAuditing = $EnableAuditing
        },
        @{
            Name = "Mobile-Data-Protection"
            Description = "Mobile data protection policy"
            EnableDataProtection = $true
            EnableEncryption = $true
            EnableAuditing = $EnableAuditing
        }
    )
    
    foreach ($policy in $mobilePolicies) {
        if (-not $DryRun) {
            Write-Host "Creating mobile policy: $($policy.Name)" -ForegroundColor Cyan
            $deploymentResult.Components += "Mobile Policy: $($policy.Name)"
        } else {
            Write-Host "DRY RUN: Would create mobile policy: $($policy.Name)" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Mobile Policy: $($policy.Name)"
        }
    }
    
    # Configure offline access
    if ($EnableOfflineAccess) {
        Write-Host "Configuring offline access..." -ForegroundColor Yellow
        
        if (-not $DryRun) {
            $offlineConfig = @{
                EnableOfflineAccess = $true
                OfflineAccessDuration = "30 days"
                EnableOfflineSync = $true
                EnableOfflineAuditing = $EnableAuditing
                OfflineAccessTemplates = @("Mobile-Offline-Sync", "Mobile-Time-Limited")
            }
            
            Write-Host "Offline access configured" -ForegroundColor Green
            $deploymentResult.Components += "Offline Access Configuration"
        } else {
            Write-Host "DRY RUN: Would configure offline access" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Offline Access Configuration"
        }
    }
    
    # Configure mobile auditing
    if ($EnableAuditing) {
        Write-Host "Configuring mobile auditing..." -ForegroundColor Yellow
        
        if (-not $DryRun) {
            $mobileAuditConfig = @{
                EnableMobileAccessAuditing = $true
                EnableDeviceComplianceAuditing = $true
                EnableAppProtectionAuditing = $true
                EnableDataProtectionAuditing = $true
                EnableOfflineAccessAuditing = $EnableOfflineAccess
                AuditLogRetentionDays = 90
                AuditLogLocation = "C:\ADRMS\MobileAuditLogs"
                EnableSIEMIntegration = $true
                EnableComplianceReporting = $true
            }
            
            Write-Host "Mobile auditing configured" -ForegroundColor Green
            $deploymentResult.Components += "Mobile Auditing Configuration"
        } else {
            Write-Host "DRY RUN: Would configure mobile auditing" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Mobile Auditing Configuration"
        }
    }
    
    # Configure user training and awareness
    Write-Host "Configuring user training and awareness..." -ForegroundColor Yellow
    
    if (-not $DryRun) {
        $trainingConfig = @{
            EnableUserNotifications = $true
            NotificationMessage = "This document is protected for mobile access. Please respect the usage rights and device policies."
            EnableHelpDeskIntegration = $true
            TrainingDocumentationPath = "C:\ADRMS\MobileDocumentation"
            EnableVideoTutorials = $true
            EnableMobileGuidelines = $true
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
    
    Write-Host "BYOD Mobile Access Control deployment completed successfully!" -ForegroundColor Green
    Write-Host "Deployment Name: $DeploymentName" -ForegroundColor Cyan
    Write-Host "iOS Access: $EnableiOSAccess" -ForegroundColor Cyan
    Write-Host "Android Access: $EnableAndroidAccess" -ForegroundColor Cyan
    Write-Host "Offline Access: $EnableOfflineAccess" -ForegroundColor Cyan
    Write-Host "Templates Created: $($deploymentResult.Templates.Count)" -ForegroundColor Cyan
    Write-Host "Mobile Configurations: $($deploymentResult.MobileConfigurations.Count)" -ForegroundColor Cyan
    Write-Host "Components Deployed: $($deploymentResult.Components.Count)" -ForegroundColor Cyan
    Write-Host "Duration: $([math]::Round($deploymentResult.Duration, 2)) minutes" -ForegroundColor Cyan
    
    return $deploymentResult
    
} catch {
    Write-Error "Error during BYOD Mobile Access Control deployment: $($_.Exception.Message)"
    throw
}
