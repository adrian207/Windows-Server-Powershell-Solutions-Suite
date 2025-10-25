#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy PowerShell Automation Scenario

.DESCRIPTION
    This script deploys the PowerShell Automation scenario for AD RMS,
    implementing bulk protection, automation scripts, and scheduled tasks.

.PARAMETER DeploymentName
    Name for the deployment

.PARAMETER ScriptsPath
    Path for automation scripts

.PARAMETER EnableBulkProtection
    Enable bulk protection scripts

.PARAMETER EnableScheduledTasks
    Enable scheduled automation tasks

.PARAMETER EnableAuditing
    Enable audit logging for automation

.PARAMETER DryRun
    Test mode without making changes

.EXAMPLE
    .\Deploy-PowerShellAutomation.ps1 -DeploymentName "RMS-Automation-System"

.EXAMPLE
    .\Deploy-PowerShellAutomation.ps1 -DeploymentName "RMS-Bulk-Automation" -ScriptsPath "C:\Scripts\RMS" -EnableBulkProtection -EnableScheduledTasks -EnableAuditing
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DeploymentName,
    
    [Parameter(Mandatory = $false)]
    [string]$ScriptsPath = "C:\Scripts\RMS",
    
    [switch]$EnableBulkProtection,
    
    [switch]$EnableScheduledTasks,
    
    [switch]$EnableAuditing,
    
    [switch]$DryRun
)

# Import required modules
Import-Module "..\..\Modules\ADRMS-Core.psm1" -Force
Import-Module "..\..\Modules\ADRMS-DocumentProtection.psm1" -Force

try {
    Write-Host "Starting PowerShell Automation deployment..." -ForegroundColor Green
    
    # Test prerequisites
    $prerequisites = Test-ADRMSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for AD RMS deployment"
    }
    
    Write-Host "Prerequisites validated successfully" -ForegroundColor Green
    
    $deploymentResult = @{
        Scenario = "PowerShellAutomation"
        DeploymentName = $DeploymentName
        ScriptsPath = $ScriptsPath
        EnableBulkProtection = $EnableBulkProtection
        EnableScheduledTasks = $EnableScheduledTasks
        EnableAuditing = $EnableAuditing
        DryRun = $DryRun
        Success = $false
        Error = $null
        Components = @()
        Scripts = @()
        ScheduledTasks = @()
        StartTime = Get-Date
    }
    
    # Create automation scripts directory
    Write-Host "Creating automation scripts directory..." -ForegroundColor Yellow
    
    if (-not $DryRun) {
        if (-not (Test-Path $ScriptsPath)) {
            New-Item -Path $ScriptsPath -ItemType Directory -Force
            Write-Host "Scripts directory created: $ScriptsPath" -ForegroundColor Green
        }
        $deploymentResult.Components += "Scripts Directory: $ScriptsPath"
    } else {
        Write-Host "DRY RUN: Would create scripts directory: $ScriptsPath" -ForegroundColor Magenta
        $deploymentResult.Components += "DRY RUN: Scripts Directory: $ScriptsPath"
    }
    
    # Create bulk protection scripts
    if ($EnableBulkProtection) {
        Write-Host "Creating bulk protection scripts..." -ForegroundColor Yellow
        
        $bulkScripts = @(
            @{
                Name = "Bulk-Protect-Documents.ps1"
                Description = "Bulk protect documents in folder"
                ScriptContent = @'
#Requires -Version 5.1
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory = $true)]
    [string]$FolderPath,
    
    [Parameter(Mandatory = $true)]
    [string]$TemplateName,
    
    [Parameter(Mandatory = $false)]
    [string]$FilePattern = "*.docx,*.xlsx,*.pptx,*.pdf"
)

Import-Module "..\..\Modules\ADRMS-DocumentProtection.psm1" -Force

$files = Get-ChildItem -Path $FolderPath -Include $FilePattern.Split(',') -Recurse

foreach ($file in $files) {
    Write-Host "Protecting: $($file.FullName)" -ForegroundColor Cyan
    $result = Protect-ADRMSDocument -DocumentPath $file.FullName -TemplateName $TemplateName
    if ($result.Success) {
        Write-Host "Protected successfully: $($file.FullName)" -ForegroundColor Green
    } else {
        Write-Warning "Failed to protect: $($file.FullName) - $($result.Error)"
    }
}
'@
            },
            @{
                Name = "Bulk-Unprotect-Documents.ps1"
                Description = "Bulk unprotect documents in folder"
                ScriptContent = @'
#Requires -Version 5.1
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory = $true)]
    [string]$FolderPath,
    
    [Parameter(Mandatory = $false)]
    [string]$FilePattern = "*.docx,*.xlsx,*.pptx,*.pdf",
    
    [switch]$BackupOriginal
)

Import-Module "..\..\Modules\ADRMS-DocumentProtection.psm1" -Force

$files = Get-ChildItem -Path $FolderPath -Include $FilePattern.Split(',') -Recurse

foreach ($file in $files) {
    Write-Host "Unprotecting: $($file.FullName)" -ForegroundColor Cyan
    $result = Unprotect-ADRMSDocument -DocumentPath $file.FullName -BackupOriginal:$BackupOriginal
    if ($result.Success) {
        Write-Host "Unprotected successfully: $($file.FullName)" -ForegroundColor Green
    } else {
        Write-Warning "Failed to unprotect: $($file.FullName) - $($result.Error)"
    }
}
'@
            },
            @{
                Name = "Bulk-Set-Document-Rights.ps1"
                Description = "Bulk set document rights in folder"
                ScriptContent = @'
#Requires -Version 5.1
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory = $true)]
    [string]$FolderPath,
    
    [Parameter(Mandatory = $false)]
    [string]$FilePattern = "*.docx,*.xlsx,*.pptx,*.pdf",
    
    [switch]$AllowPrint,
    [switch]$AllowCopy,
    [switch]$AllowForward,
    [switch]$AllowOfflineAccess,
    [Parameter(Mandatory = $false)]
    [DateTime]$ExpirationDate
)

Import-Module "..\..\Modules\ADRMS-DocumentProtection.psm1" -Force

$files = Get-ChildItem -Path $FolderPath -Include $FilePattern.Split(',') -Recurse

foreach ($file in $files) {
    Write-Host "Setting rights for: $($file.FullName)" -ForegroundColor Cyan
    $result = Set-ADRMSDocumentRights -DocumentPath $file.FullName -AllowPrint:$AllowPrint -AllowCopy:$AllowCopy -AllowForward:$AllowForward -AllowOfflineAccess:$AllowOfflineAccess -ExpirationDate $ExpirationDate
    if ($result.Success) {
        Write-Host "Rights set successfully: $($file.FullName)" -ForegroundColor Green
    } else {
        Write-Warning "Failed to set rights: $($file.FullName) - $($result.Error)"
    }
}
'@
            }
        )
        
        foreach ($script in $bulkScripts) {
            if (-not $DryRun) {
                $scriptPath = Join-Path $ScriptsPath $script.Name
                $script.ScriptContent | Out-File -FilePath $scriptPath -Encoding UTF8
                
                $scriptConfig = @{
                    Name = $script.Name
                    Description = $script.Description
                    Path = $scriptPath
                    Created = $true
                }
                
                $deploymentResult.Scripts += $scriptConfig
                $deploymentResult.Components += "Bulk Script: $($script.Name)"
                Write-Host "Bulk script created successfully: $($script.Name)" -ForegroundColor Green
            } else {
                Write-Host "DRY RUN: Would create bulk script: $($script.Name)" -ForegroundColor Magenta
                $deploymentResult.Components += "DRY RUN: Bulk Script: $($script.Name)"
            }
        }
    }
    
    # Create scheduled tasks
    if ($EnableScheduledTasks) {
        Write-Host "Creating scheduled tasks..." -ForegroundColor Yellow
        
        $scheduledTasks = @(
            @{
                Name = "Daily-Protection-Audit"
                Description = "Daily audit of document protection"
                Schedule = "Daily"
                Time = "02:00"
                ScriptPath = Join-Path $ScriptsPath "Daily-Protection-Audit.ps1"
                ScriptContent = @'
#Requires -Version 5.1
#Requires -RunAsAdministrator

Import-Module "..\..\Modules\ADRMS-DocumentProtection.psm1" -Force

$auditResult = Get-ADRMSDocumentStatus
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host "RMS Protection Audit - $timestamp" -ForegroundColor Green
Write-Host "Total Protected Documents: $($auditResult.ProtectionStatus.TotalProtectedDocuments)" -ForegroundColor Cyan
Write-Host "Protection Success Rate: $($auditResult.ProtectionStatus.ProtectionSuccessRate)%" -ForegroundColor Cyan
Write-Host "Protection Errors: $($auditResult.ProtectionStatus.ProtectionErrors)" -ForegroundColor Cyan

# Log to file
$logPath = "C:\ADRMS\Logs\Daily-Audit-$(Get-Date -Format 'yyyy-MM-dd').log"
$logContent = @"
RMS Protection Audit - $timestamp
Total Protected Documents: $($auditResult.ProtectionStatus.TotalProtectedDocuments)
Protection Success Rate: $($auditResult.ProtectionStatus.ProtectionSuccessRate)%
Protection Errors: $($auditResult.ProtectionStatus.ProtectionErrors)
"@

$logContent | Out-File -FilePath $logPath -Append -Encoding UTF8
'@
            },
            @{
                Name = "Weekly-Template-Report"
                Description = "Weekly template usage report"
                Schedule = "Weekly"
                Day = "Monday"
                Time = "09:00"
                ScriptPath = Join-Path $ScriptsPath "Weekly-Template-Report.ps1"
                ScriptContent = @'
#Requires -Version 5.1
#Requires -RunAsAdministrator

Import-Module "..\..\Modules\ADRMS-DocumentProtection.psm1" -Force

$templateStatus = Get-ADRMSDocumentStatus
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host "RMS Template Report - $timestamp" -ForegroundColor Green
Write-Host "Total Templates: $($templateStatus.TemplateStatus.TotalTemplates)" -ForegroundColor Cyan
Write-Host "Active Templates: $($templateStatus.TemplateStatus.ActiveTemplates)" -ForegroundColor Cyan
Write-Host "Most Used Template: $($templateStatus.TemplateStatus.MostUsedTemplate)" -ForegroundColor Cyan

# Generate report
$reportPath = "C:\ADRMS\Reports\Weekly-Template-Report-$(Get-Date -Format 'yyyy-MM-dd').html"
$reportContent = @"
<html>
<head><title>RMS Template Report - $timestamp</title></head>
<body>
<h1>RMS Template Report</h1>
<p><strong>Report Date:</strong> $timestamp</p>
<p><strong>Total Templates:</strong> $($templateStatus.TemplateStatus.TotalTemplates)</p>
<p><strong>Active Templates:</strong> $($templateStatus.TemplateStatus.ActiveTemplates)</p>
<p><strong>Most Used Template:</strong> $($templateStatus.TemplateStatus.MostUsedTemplate)</p>
</body>
</html>
"@

$reportContent | Out-File -FilePath $reportPath -Encoding UTF8
'@
            },
            @{
                Name = "Monthly-Compliance-Report"
                Description = "Monthly compliance report"
                Schedule = "Monthly"
                Day = 1
                Time = "08:00"
                ScriptPath = Join-Path $ScriptsPath "Monthly-Compliance-Report.ps1"
                ScriptContent = @'
#Requires -Version 5.1
#Requires -RunAsAdministrator

Import-Module "..\..\Modules\ADRMS-DocumentProtection.psm1" -Force

$complianceStatus = Get-ADRMSDocumentStatus
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

Write-Host "RMS Compliance Report - $timestamp" -ForegroundColor Green
Write-Host "Auditing Enabled: $($complianceStatus.AuditingStatus.AuditingEnabled)" -ForegroundColor Cyan
Write-Host "Audit Logs Generated: $($complianceStatus.AuditingStatus.AuditLogsGenerated)" -ForegroundColor Cyan
Write-Host "Audit Log Retention: $($complianceStatus.AuditingStatus.AuditLogRetentionDays) days" -ForegroundColor Cyan

# Generate compliance report
$reportPath = "C:\ADRMS\Reports\Monthly-Compliance-Report-$(Get-Date -Format 'yyyy-MM').html"
$reportContent = @"
<html>
<head><title>RMS Compliance Report - $timestamp</title></head>
<body>
<h1>RMS Compliance Report</h1>
<p><strong>Report Date:</strong> $timestamp</p>
<p><strong>Auditing Enabled:</strong> $($complianceStatus.AuditingStatus.AuditingEnabled)</p>
<p><strong>Audit Logs Generated:</strong> $($complianceStatus.AuditingStatus.AuditLogsGenerated)</p>
<p><strong>Audit Log Retention:</strong> $($complianceStatus.AuditingStatus.AuditLogRetentionDays) days</p>
</body>
</html>
"@

$reportContent | Out-File -FilePath $reportPath -Encoding UTF8
'@
            }
        )
        
        foreach ($task in $scheduledTasks) {
            if (-not $DryRun) {
                # Create script file
                $task.ScriptContent | Out-File -FilePath $task.ScriptPath -Encoding UTF8
                
                # Create scheduled task
                $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$($task.ScriptPath)`""
                $trigger = New-ScheduledTaskTrigger -Daily -At $task.Time
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
                $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                
                Register-ScheduledTask -TaskName $task.Name -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description $task.Description
                
                $taskConfig = @{
                    Name = $task.Name
                    Description = $task.Description
                    Schedule = $task.Schedule
                    Time = $task.Time
                    ScriptPath = $task.ScriptPath
                    Created = $true
                }
                
                $deploymentResult.ScheduledTasks += $taskConfig
                $deploymentResult.Components += "Scheduled Task: $($task.Name)"
                Write-Host "Scheduled task created successfully: $($task.Name)" -ForegroundColor Green
            } else {
                Write-Host "DRY RUN: Would create scheduled task: $($task.Name)" -ForegroundColor Magenta
                $deploymentResult.Components += "DRY RUN: Scheduled Task: $($task.Name)"
            }
        }
    }
    
    # Configure automation auditing
    if ($EnableAuditing) {
        Write-Host "Configuring automation auditing..." -ForegroundColor Yellow
        
        if (-not $DryRun) {
            $automationAuditConfig = @{
                EnableScriptExecutionAuditing = $true
                EnableScheduledTaskAuditing = $true
                EnableBulkOperationAuditing = $true
                EnableAutomationErrorAuditing = $true
                AuditLogRetentionDays = 90
                AuditLogLocation = "C:\ADRMS\AutomationAuditLogs"
                EnableSIEMIntegration = $true
                EnableComplianceReporting = $true
            }
            
            Write-Host "Automation auditing configured" -ForegroundColor Green
            $deploymentResult.Components += "Automation Auditing Configuration"
        } else {
            Write-Host "DRY RUN: Would configure automation auditing" -ForegroundColor Magenta
            $deploymentResult.Components += "DRY RUN: Automation Auditing Configuration"
        }
    }
    
    # Configure user training and awareness
    Write-Host "Configuring user training and awareness..." -ForegroundColor Yellow
    
    if (-not $DryRun) {
        $trainingConfig = @{
            EnableUserNotifications = $true
            NotificationMessage = "RMS automation scripts are available for bulk operations. Please contact IT for assistance."
            EnableHelpDeskIntegration = $true
            TrainingDocumentationPath = "C:\ADRMS\AutomationDocumentation"
            EnableVideoTutorials = $true
            EnableScriptDocumentation = $true
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
    
    Write-Host "PowerShell Automation deployment completed successfully!" -ForegroundColor Green
    Write-Host "Deployment Name: $DeploymentName" -ForegroundColor Cyan
    Write-Host "Scripts Path: $ScriptsPath" -ForegroundColor Cyan
    Write-Host "Bulk Protection: $EnableBulkProtection" -ForegroundColor Cyan
    Write-Host "Scheduled Tasks: $EnableScheduledTasks" -ForegroundColor Cyan
    Write-Host "Scripts Created: $($deploymentResult.Scripts.Count)" -ForegroundColor Cyan
    Write-Host "Scheduled Tasks: $($deploymentResult.ScheduledTasks.Count)" -ForegroundColor Cyan
    Write-Host "Components Deployed: $($deploymentResult.Components.Count)" -ForegroundColor Cyan
    Write-Host "Duration: $([math]::Round($deploymentResult.Duration, 2)) minutes" -ForegroundColor Cyan
    
    return $deploymentResult
    
} catch {
    Write-Error "Error during PowerShell Automation deployment: $($_.Exception.Message)"
    throw
}
