#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD RMS Health Check and Monitoring Script

.DESCRIPTION
    This script provides continuous health monitoring and alerting for AD RMS.
    It can run as a scheduled task or service to provide ongoing monitoring.

.PARAMETER Action
    The action to perform (Check, Monitor, Alert, Schedule)

.PARAMETER CheckInterval
    Interval between health checks in seconds (default: 300)

.PARAMETER AlertThreshold
    Number of consecutive failures before alerting (default: 3)

.PARAMETER EmailRecipients
    Email addresses to send alerts to

.PARAMETER LogPath
    Path to save monitoring logs

.PARAMETER CreateTask
    Create a scheduled task for continuous monitoring

.PARAMETER TaskName
    Name for the scheduled task

.PARAMETER TaskInterval
    Interval for the scheduled task in minutes (default: 5)

.EXAMPLE
    .\Monitor-ADRMSHealth.ps1 -Action Check

.EXAMPLE
    .\Monitor-ADRMSHealth.ps1 -Action Monitor -CheckInterval 60 -AlertThreshold 2

.EXAMPLE
    .\Monitor-ADRMSHealth.ps1 -Action Schedule -CreateTask -TaskName "AD RMS Health Monitor" -TaskInterval 10

.NOTES
    Author: AD RMS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Check", "Monitor", "Alert", "Schedule")]
    [string]$Action,
    
    [int]$CheckInterval = 300,
    
    [int]$AlertThreshold = 3,
    
    [string[]]$EmailRecipients,
    
    [string]$LogPath,
    
    [switch]$CreateTask,
    
    [string]$TaskName = "AD RMS Health Monitor",
    
    [int]$TaskInterval = 5
)

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "ADRMS-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "ADRMS-Configuration.psm1") -Force
    Import-Module (Join-Path $modulePath "ADRMS-Diagnostics.psm1") -Force
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Script variables
$script:HealthLog = @()
$script:StartTime = Get-Date
$script:FailureCount = 0
$script:LastAlertTime = $null

function Write-HealthLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:HealthLog += $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        "ALERT" { Write-Host $Message -ForegroundColor Red }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function Test-ADRMSHealthCheck {
    Write-HealthLog "Performing AD RMS health check..." "INFO"
    
    try {
        $healthCheck = Test-ADRMSHealth
        
        $healthStatus = @{
            Timestamp = Get-Date
            Overall = $healthCheck.Overall
            Services = $healthCheck.Services
            Configuration = $healthCheck.Configuration
            Connectivity = $healthCheck.Connectivity
            Performance = $healthCheck.Performance
            Logs = $healthCheck.Logs
            IsHealthy = $healthCheck.Overall -eq 'Healthy'
            Issues = @()
        }
        
        # Identify specific issues
        foreach ($service in $healthCheck.Services.GetEnumerator()) {
            if ($service.Value -ne 'Running') {
                $healthStatus.Issues += "Service $($service.Key) is not running"
            }
        }
        
        if ($healthCheck.Configuration.Overall -ne 'Fully Configured') {
            $healthStatus.Issues += "Configuration incomplete"
        }
        
        if ($healthCheck.Connectivity.Overall -ne 'All Accessible') {
            $healthStatus.Issues += "Connectivity issues detected"
        }
        
        if ($healthCheck.Logs.ErrorCount -gt 0) {
            $healthStatus.Issues += "Recent errors in logs"
        }
        
        if ($healthStatus.IsHealthy) {
            Write-HealthLog "Health check passed. Status: $($healthStatus.Overall)" "SUCCESS"
            $script:FailureCount = 0
        } else {
            $script:FailureCount++
            Write-HealthLog "Health check failed. Status: $($healthStatus.Overall). Failure count: $($script:FailureCount)" "WARNING"
        }
        
        return [PSCustomObject]$healthStatus
        
    } catch {
        Write-HealthLog "Error during health check: $($_.Exception.Message)" "ERROR"
        $script:FailureCount++
        return $null
    }
}

function Send-HealthAlert {
    param(
        [object]$HealthStatus,
        [string[]]$Recipients
    )
    
    if (-not $Recipients -or $Recipients.Count -eq 0) {
        Write-HealthLog "No email recipients configured for alerts" "WARNING"
        return $false
    }
    
    try {
        $subject = "AD RMS Health Alert - $($env:COMPUTERNAME)"
        $body = @"
AD RMS Health Alert

Computer: $($env:COMPUTERNAME)
Domain: $($env:USERDOMAIN)
Time: $($HealthStatus.Timestamp)
Overall Status: $($HealthStatus.Overall)

Issues Found:
$($HealthStatus.Issues -join "`n")

Services Status:
$($HealthStatus.Services | ConvertTo-Json -Compress)

Configuration Status:
$($HealthStatus.Configuration | ConvertTo-Json -Compress)

Connectivity Status:
$($HealthStatus.Connectivity | ConvertTo-Json -Compress)

Please investigate these issues immediately.

Generated by AD RMS Health Monitor
"@
        
        # Send email (requires SMTP configuration)
        Send-MailMessage -To $Recipients -Subject $subject -Body $body -SmtpServer "localhost" -From "ADRMS-Monitor@$($env:USERDOMAIN)"
        
        Write-HealthLog "Health alert sent to: $($Recipients -join ', ')" "ALERT"
        $script:LastAlertTime = Get-Date
        return $true
        
    } catch {
        Write-HealthLog "Failed to send health alert: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-HealthMonitoring {
    param(
        [int]$Interval,
        [int]$Threshold,
        [string[]]$Recipients
    )
    
    Write-HealthLog "Starting continuous health monitoring..." "INFO"
    Write-HealthLog "Check interval: $Interval seconds" "INFO"
    Write-HealthLog "Alert threshold: $Threshold failures" "INFO"
    
    try {
        while ($true) {
            $healthStatus = Test-ADRMSHealthCheck
            
            if ($healthStatus) {
                # Check if we need to send an alert
                if (-not $healthStatus.IsHealthy -and $script:FailureCount -ge $Threshold) {
                    $shouldAlert = $false
                    
                    if (-not $script:LastAlertTime) {
                        $shouldAlert = $true
                    } else {
                        $timeSinceLastAlert = (Get-Date) - $script:LastAlertTime
                        if ($timeSinceLastAlert.TotalMinutes -gt 30) {  # Don't alert more than once every 30 minutes
                            $shouldAlert = $true
                        }
                    }
                    
                    if ($shouldAlert) {
                        Send-HealthAlert -HealthStatus $healthStatus -Recipients $Recipients
                    }
                }
            }
            
            Write-HealthLog "Waiting $Interval seconds until next check..." "INFO"
            Start-Sleep -Seconds $Interval
        }
        
    } catch {
        Write-HealthLog "Error during monitoring: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function New-ScheduledTask {
    param(
        [string]$TaskName,
        [int]$IntervalMinutes,
        [string]$ScriptPath
    )
    
    Write-HealthLog "Creating scheduled task: $TaskName" "INFO"
    
    try {
        # Define the action
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$ScriptPath`" -Action Check"
        
        # Define the trigger (every X minutes)
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) -RepetitionDuration (New-TimeSpan -Days 365)
        
        # Define the principal (run as SYSTEM)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Define settings
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable
        
        # Create the task
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "AD RMS Health Monitoring Task"
        
        Write-HealthLog "Scheduled task created successfully: $TaskName" "SUCCESS"
        return $true
        
    } catch {
        Write-HealthLog "Failed to create scheduled task: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Save-HealthLog {
    param([string]$LogPath)
    
    if (-not $LogPath) {
        $LogPath = Join-Path $scriptPath "Health-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    }
    
    try {
        $script:HealthLog | Out-File -FilePath $LogPath -Encoding UTF8
        Write-HealthLog "Health log saved to: $LogPath" "INFO"
    } catch {
        Write-Warning "Failed to save health log: $($_.Exception.Message)"
    }
}

# Main health monitoring process
try {
    Write-HealthLog "Starting AD RMS health monitoring..." "INFO"
    Write-HealthLog "Action: $Action" "INFO"
    
    switch ($Action) {
        "Check" {
            $healthStatus = Test-ADRMSHealthCheck
            
            if ($healthStatus) {
                Write-Host "`n=== AD RMS Health Check Results ===" -ForegroundColor Cyan
                Write-Host "Overall Status: $($healthStatus.Overall)" -ForegroundColor White
                Write-Host "Is Healthy: $($healthStatus.IsHealthy)" -ForegroundColor White
                Write-Host "Issues Found: $($healthStatus.Issues.Count)" -ForegroundColor White
                
                if ($healthStatus.Issues.Count -gt 0) {
                    Write-Host "`nIssues:" -ForegroundColor Yellow
                    $healthStatus.Issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
                }
            }
        }
        
        "Monitor" {
            Start-HealthMonitoring -Interval $CheckInterval -Threshold $AlertThreshold -Recipients $EmailRecipients
        }
        
        "Alert" {
            $healthStatus = Test-ADRMSHealthCheck
            
            if ($healthStatus -and -not $healthStatus.IsHealthy) {
                Send-HealthAlert -HealthStatus $healthStatus -Recipients $EmailRecipients
            } else {
                Write-HealthLog "No alert needed - system is healthy" "INFO"
            }
        }
        
        "Schedule" {
            if ($CreateTask) {
                $scriptPath = $MyInvocation.MyCommand.Path
                New-ScheduledTask -TaskName $TaskName -IntervalMinutes $TaskInterval -ScriptPath $scriptPath
            } else {
                Write-HealthLog "Use -CreateTask parameter to create a scheduled task" "WARNING"
            }
        }
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-HealthLog "AD RMS health monitoring completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== AD RMS Health Monitoring Summary ===" -ForegroundColor Cyan
    Write-Host "Action: $Action" -ForegroundColor White
    Write-Host "Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    Write-Host "Failure Count: $($script:FailureCount)" -ForegroundColor White
    
    # Save health log
    Save-HealthLog -LogPath $LogPath
    
    Write-Host "`nHealth monitoring completed successfully!" -ForegroundColor Green
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-HealthLog "AD RMS health monitoring failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save health log
    Save-HealthLog -LogPath $LogPath
    
    Write-Host "`nHealth monitoring failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the health log for details." -ForegroundColor Yellow
    
    exit 1
}
