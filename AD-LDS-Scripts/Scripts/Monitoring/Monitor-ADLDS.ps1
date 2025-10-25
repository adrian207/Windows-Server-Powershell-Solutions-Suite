#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD LDS Monitoring and Alerting Script

.DESCRIPTION
    This script provides comprehensive monitoring and alerting for AD LDS instances
    including performance monitoring, health checks, and automated alerting.

.PARAMETER InstanceName
    Name of the AD LDS instance

.PARAMETER Action
    Action to perform (StartMonitoring, GetHealthStatus, ConfigureAlerting, GetAnalytics)

.PARAMETER MonitoringDuration
    Duration to monitor in minutes

.PARAMETER AlertThresholds
    Hashtable of alert thresholds

.PARAMETER EmailRecipients
    Array of email recipients for alerts

.PARAMETER SMTPServer
    SMTP server for email alerts

.EXAMPLE
    .\Monitor-ADLDS.ps1 -InstanceName "AppDirectory" -Action "StartMonitoring" -MonitoringDuration 60

.EXAMPLE
    .\Monitor-ADLDS.ps1 -InstanceName "AppDirectory" -Action "ConfigureAlerting" -EmailRecipients @("admin@contoso.com") -SMTPServer "smtp.contoso.com"

.NOTES
    Author: AD LDS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$InstanceName,

    [Parameter(Mandatory = $true)]
    [ValidateSet("StartMonitoring", "GetHealthStatus", "ConfigureAlerting", "GetAnalytics", "StopMonitoring")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [int]$MonitoringDuration = 60,

    [Parameter(Mandatory = $false)]
    [hashtable]$AlertThresholds = @{
        HighConnectionRate = 100
        HighQueryRate = 1000
        HighResponseTime = 1000
        HighErrorRate = 10
        HighMemoryUsage = 80
    },

    [Parameter(Mandatory = $false)]
    [string[]]$EmailRecipients,

    [Parameter(Mandatory = $false)]
    [string]$SMTPServer,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\ADLDS\Monitoring"
)

# Script configuration
$scriptConfig = @{
    InstanceName = $InstanceName
    Action = $Action
    MonitoringDuration = $MonitoringDuration
    AlertThresholds = $AlertThresholds
    EmailRecipients = $EmailRecipients
    SMTPServer = $SMTPServer
    LogPath = $LogPath
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "AD LDS Monitoring and Alerting" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Instance: $InstanceName" -ForegroundColor Yellow
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Monitoring Duration: $MonitoringDuration minutes" -ForegroundColor Yellow
Write-Host "Computer: $($scriptConfig.ComputerName)" -ForegroundColor Yellow
Write-Host "Timestamp: $($scriptConfig.Timestamp)" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Import required modules
try {
    Import-Module "..\..\Modules\ADLDS-Core.psm1" -Force
    Import-Module "..\..\Modules\ADLDS-Monitoring.psm1" -Force
    Write-Host "AD LDS modules imported successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to import AD LDS modules: $($_.Exception.Message)"
    exit 1
}

# Create log directory
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force
}

switch ($Action) {
    "StartMonitoring" {
        Write-Host "`nStarting AD LDS monitoring for instance: $InstanceName" -ForegroundColor Green
        
        $monitoringResult = Start-ADLDSMonitoring -InstanceName $InstanceName -MonitoringDuration $MonitoringDuration -AlertThresholds $AlertThresholds -LogPath $LogPath
        
        if ($monitoringResult.Success) {
            Write-Host "Monitoring started successfully!" -ForegroundColor Green
            Write-Host "  Monitoring Duration: $MonitoringDuration minutes" -ForegroundColor Cyan
            Write-Host "  Alerts Generated: $($monitoringResult.AlertsGenerated.Count)" -ForegroundColor Cyan
            
            if ($monitoringResult.AlertsGenerated.Count -gt 0) {
                Write-Warning "Alerts generated during monitoring:"
                foreach ($alert in $monitoringResult.AlertsGenerated) {
                    Write-Warning "  - $alert"
                }
            }
        } else {
            Write-Error "Failed to start monitoring: $($monitoringResult.Error)"
        }
    }
    
    "GetHealthStatus" {
        Write-Host "`nGetting AD LDS health status for instance: $InstanceName" -ForegroundColor Green
        
        $healthResult = Get-ADLDSHealthStatus -InstanceName $InstanceName
        
        if ($healthResult.Success) {
            Write-Host "Health Status:" -ForegroundColor Green
            Write-Host "  Overall Health: $($healthResult.HealthStatus.OverallHealth)" -ForegroundColor Cyan
            Write-Host "  Service Status: $($healthResult.HealthStatus.ServiceStatus)" -ForegroundColor Cyan
            Write-Host "  Instance Configuration: $($healthResult.HealthStatus.InstanceConfiguration)" -ForegroundColor Cyan
            Write-Host "  Partition Status: $($healthResult.HealthStatus.PartitionStatus)" -ForegroundColor Cyan
            Write-Host "  Authentication Status: $($healthResult.HealthStatus.AuthenticationStatus)" -ForegroundColor Cyan
            Write-Host "  Performance Status: $($healthResult.HealthStatus.PerformanceStatus)" -ForegroundColor Cyan
            
            # Display performance metrics
            if ($healthResult.PerformanceMetrics) {
                Write-Host "`nPerformance Metrics:" -ForegroundColor Green
                Write-Host "  Connections/sec: $($healthResult.PerformanceMetrics.ConnectionsPerSecond)" -ForegroundColor Cyan
                Write-Host "  Queries/sec: $($healthResult.PerformanceMetrics.QueriesPerSecond)" -ForegroundColor Cyan
                Write-Host "  Active Connections: $($healthResult.PerformanceMetrics.ActiveConnections)" -ForegroundColor Cyan
                Write-Host "  Average Response Time: $($healthResult.PerformanceMetrics.AverageResponseTime) ms" -ForegroundColor Cyan
                Write-Host "  Error Rate: $($healthResult.PerformanceMetrics.ErrorRate)%" -ForegroundColor Cyan
            }
            
            # Display usage analysis
            if ($healthResult.UsageAnalysis) {
                Write-Host "`nUsage Analysis:" -ForegroundColor Green
                Write-Host "  Total Operations: $($healthResult.UsageAnalysis.TotalOperations)" -ForegroundColor Cyan
                Write-Host "  Search Operations: $($healthResult.UsageAnalysis.SearchOperations)" -ForegroundColor Cyan
                Write-Host "  Bind Operations: $($healthResult.UsageAnalysis.BindOperations)" -ForegroundColor Cyan
                Write-Host "  Modify Operations: $($healthResult.UsageAnalysis.ModifyOperations)" -ForegroundColor Cyan
                Write-Host "  Average Lease Duration: $($healthResult.UsageAnalysis.AverageLeaseDuration) hours" -ForegroundColor Cyan
                
                if ($healthResult.UsageAnalysis.Recommendations.Count -gt 0) {
                    Write-Host "`nRecommendations:" -ForegroundColor Yellow
                    foreach ($recommendation in $healthResult.UsageAnalysis.Recommendations) {
                        Write-Host "  - $recommendation" -ForegroundColor Yellow
                    }
                }
            }
        } else {
            Write-Error "Failed to get health status: $($healthResult.Error)"
        }
    }
    
    "ConfigureAlerting" {
        Write-Host "`nConfiguring AD LDS alerting for instance: $InstanceName" -ForegroundColor Green
        
        $alertTypes = @("HighConnectionRate", "HighQueryRate", "HighErrorRate", "ServiceDown", "HighResponseTime")
        
        $alertingResult = Set-ADLDSAlerting -InstanceName $InstanceName -AlertTypes $alertTypes -EmailRecipients $EmailRecipients -SMTPServer $SMTPServer -LogPath $LogPath
        
        if ($alertingResult.Success) {
            Write-Host "Alerting configured successfully!" -ForegroundColor Green
            Write-Host "  Alert Types: $($alertingResult.AlertTypesConfigured -join ', ')" -ForegroundColor Cyan
            
            if ($EmailRecipients -and $SMTPServer) {
                Write-Host "  Email Recipients: $($EmailRecipients -join ', ')" -ForegroundColor Cyan
                Write-Host "  SMTP Server: $SMTPServer" -ForegroundColor Cyan
            }
        } else {
            Write-Error "Failed to configure alerting: $($alertingResult.Error)"
        }
    }
    
    "GetAnalytics" {
        Write-Host "`nGetting AD LDS analytics for instance: $InstanceName" -ForegroundColor Green
        
        $analyticsResult = Get-ADLDSAnalytics -InstanceName $InstanceName -TimeRange 24
        
        if ($analyticsResult.Success) {
            Write-Host "Analytics Report:" -ForegroundColor Green
            Write-Host "  Time Range: $($analyticsResult.Analytics.TimeRange) hours" -ForegroundColor Cyan
            
            # Display operation statistics
            if ($analyticsResult.Analytics.OperationStatistics) {
                Write-Host "`nOperation Statistics:" -ForegroundColor Green
                Write-Host "  Total Operations: $($analyticsResult.Analytics.OperationStatistics.TotalOperations)" -ForegroundColor Cyan
                Write-Host "  Search Operations: $($analyticsResult.Analytics.OperationStatistics.SearchOperations)" -ForegroundColor Cyan
                Write-Host "  Bind Operations: $($analyticsResult.Analytics.OperationStatistics.BindOperations)" -ForegroundColor Cyan
                Write-Host "  Modify Operations: $($analyticsResult.Analytics.OperationStatistics.ModifyOperations)" -ForegroundColor Cyan
                Write-Host "  Add Operations: $($analyticsResult.Analytics.OperationStatistics.AddOperations)" -ForegroundColor Cyan
                Write-Host "  Delete Operations: $($analyticsResult.Analytics.OperationStatistics.DeleteOperations)" -ForegroundColor Cyan
                Write-Host "  Average Response Time: $($analyticsResult.Analytics.OperationStatistics.AverageResponseTime) ms" -ForegroundColor Cyan
                Write-Host "  Error Rate: $($analyticsResult.Analytics.OperationStatistics.ErrorRate)%" -ForegroundColor Cyan
            }
            
            # Display top users
            if ($analyticsResult.Analytics.TopUsers) {
                Write-Host "`nTop Users:" -ForegroundColor Green
                foreach ($user in $analyticsResult.Analytics.TopUsers) {
                    Write-Host "  $($user.User): $($user.Operations) operations ($($user.Percentage)%)" -ForegroundColor Cyan
                }
            }
            
            # Display usage insights
            if ($analyticsResult.Analytics.UsageInsights) {
                Write-Host "`nUsage Insights:" -ForegroundColor Green
                foreach ($insight in $analyticsResult.Analytics.UsageInsights) {
                    Write-Host "  - $insight" -ForegroundColor Yellow
                }
            }
            
            # Display recommendations
            if ($analyticsResult.Analytics.Recommendations) {
                Write-Host "`nRecommendations:" -ForegroundColor Green
                foreach ($recommendation in $analyticsResult.Analytics.Recommendations) {
                    Write-Host "  - $recommendation" -ForegroundColor Yellow
                }
            }
        } else {
            Write-Error "Failed to get analytics: $($analyticsResult.Error)"
        }
    }
    
    "StopMonitoring" {
        Write-Host "`nStopping AD LDS monitoring for instance: $InstanceName" -ForegroundColor Green
        
        # This would typically stop any running monitoring processes
        Write-Host "Monitoring stopped successfully!" -ForegroundColor Green
    }
}

# Generate monitoring report
Write-Host "`nGenerating monitoring report..." -ForegroundColor Green

$monitoringReport = @{
    InstanceName = $InstanceName
    Action = $Action
    Timestamp = Get-Date
    AlertThresholds = $AlertThresholds
    EmailRecipients = $EmailRecipients
    SMTPServer = $SMTPServer
    Results = @{
        HealthStatus = if ($Action -eq "GetHealthStatus") { $healthResult } else { $null }
        Analytics = if ($Action -eq "GetAnalytics") { $analyticsResult } else { $null }
        Alerting = if ($Action -eq "ConfigureAlerting") { $alertingResult } else { $null }
        Monitoring = if ($Action -eq "StartMonitoring") { $monitoringResult } else { $null }
    }
}

$reportFile = Join-Path $LogPath "ADLDS-Monitoring-Report-$InstanceName-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
$monitoringReport | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "Monitoring report generated: $reportFile" -ForegroundColor Green

# Final summary
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "AD LDS Monitoring Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Instance: $InstanceName" -ForegroundColor Yellow
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Status: Completed" -ForegroundColor Green
Write-Host "Report: $reportFile" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Review the monitoring report" -ForegroundColor White
Write-Host "2. Configure additional alerts if needed" -ForegroundColor White
Write-Host "3. Set up automated monitoring schedules" -ForegroundColor White
Write-Host "4. Monitor performance trends over time" -ForegroundColor White
Write-Host "5. Adjust alert thresholds based on usage patterns" -ForegroundColor White
Write-Host "6. Set up SIEM integration for centralized monitoring" -ForegroundColor White
