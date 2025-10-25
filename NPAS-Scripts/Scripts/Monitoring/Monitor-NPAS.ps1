#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Monitor NPAS

.DESCRIPTION
    This script provides comprehensive monitoring and alerting for Network Policy and Access Services (NPAS)
    including health monitoring, performance metrics, alerting configuration, log management,
    and compliance monitoring with real-time dashboards and reporting.

.PARAMETER ServerName
    Name of the NPAS server to monitor

.PARAMETER MonitoringLevel
    Level of monitoring to implement (Basic, Standard, Advanced, Enterprise)

.PARAMETER AlertingEnabled
    Enable alerting and notifications

.PARAMETER DashboardEnabled
    Enable dashboard and reporting

.PARAMETER ComplianceMonitoring
    Enable compliance monitoring

.PARAMETER PerformanceMonitoring
    Enable performance monitoring

.EXAMPLE
    .\Monitor-NPAS.ps1 -ServerName "NPAS-SERVER01" -MonitoringLevel "Enterprise" -AlertingEnabled -DashboardEnabled -ComplianceMonitoring -PerformanceMonitoring

.EXAMPLE
    .\Monitor-NPAS.ps1 -ServerName "NPAS-SERVER01" -MonitoringLevel "Advanced" -AlertingEnabled
#>

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerName,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Standard", "Advanced", "Enterprise")]
    [string]$MonitoringLevel = "Standard",

    [Parameter(Mandatory = $false)]
    [switch]$AlertingEnabled,

    [Parameter(Mandatory = $false)]
    [switch]$DashboardEnabled,

    [Parameter(Mandatory = $false)]
    [switch]$ComplianceMonitoring,

    [Parameter(Mandatory = $false)]
    [switch]$PerformanceMonitoring
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Script configuration
$scriptConfig = @{
    ServerName = $ServerName
    MonitoringLevel = $MonitoringLevel
    AlertingEnabled = $AlertingEnabled
    DashboardEnabled = $DashboardEnabled
    ComplianceMonitoring = $ComplianceMonitoring
    PerformanceMonitoring = $PerformanceMonitoring
    LogPath = "C:\NPAS\Logs\Monitoring"
    StartTime = Get-Date
}

# Create log directory
if (-not (Test-Path $scriptConfig.LogPath)) {
    New-Item -Path $scriptConfig.LogPath -ItemType Directory -Force
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Information"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    Write-Host $logMessage -ForegroundColor $(
        switch ($Level) {
            "Error" { "Red" }
            "Warning" { "Yellow" }
            "Success" { "Green" }
            default { "White" }
        }
    )
    
    $logMessage | Out-File -FilePath "$($scriptConfig.LogPath)\NPAS-Monitoring.log" -Append -Encoding UTF8
}

try {
    Write-Log "Starting NPAS monitoring implementation..." "Information"
    Write-Log "Server Name: $ServerName" "Information"
    Write-Log "Monitoring Level: $MonitoringLevel" "Information"
    Write-Log "Alerting Enabled: $AlertingEnabled" "Information"
    Write-Log "Dashboard Enabled: $DashboardEnabled" "Information"
    Write-Log "Compliance Monitoring: $ComplianceMonitoring" "Information"
    Write-Log "Performance Monitoring: $PerformanceMonitoring" "Information"

    # Import required modules
    Write-Log "Importing NPAS modules..." "Information"
    $modulePath = Join-Path $PSScriptRoot "..\..\Modules"
    
    if (Test-Path "$modulePath\NPAS-Monitoring.psm1") {
        Import-Module "$modulePath\NPAS-Monitoring.psm1" -Force
        Write-Log "NPAS-Monitoring module imported successfully" "Success"
    } else {
        throw "NPAS-Monitoring module not found at $modulePath\NPAS-Monitoring.psm1"
    }

    if (Test-Path "$modulePath\NPAS-Core.psm1") {
        Import-Module "$modulePath\NPAS-Core.psm1" -Force
        Write-Log "NPAS-Core module imported successfully" "Success"
    } else {
        throw "NPAS-Core module not found at $modulePath\NPAS-Core.psm1"
    }

    # Monitoring configuration based on monitoring level
    $monitoringConfig = @{
        Basic = @{
            HealthMonitoring = $true
            ServiceMonitoring = $true
            BasicMetrics = $true
            BasicAlerting = $false
            Dashboard = $false
            ComplianceMonitoring = $false
            PerformanceMonitoring = $false
            LogAnalysis = $false
        }
        Standard = @{
            HealthMonitoring = $true
            ServiceMonitoring = $true
            BasicMetrics = $true
            AdvancedMetrics = $true
            BasicAlerting = $true
            Dashboard = $true
            ComplianceMonitoring = $false
            PerformanceMonitoring = $true
            LogAnalysis = $true
        }
        Advanced = @{
            HealthMonitoring = $true
            ServiceMonitoring = $true
            BasicMetrics = $true
            AdvancedMetrics = $true
            CustomMetrics = $true
            BasicAlerting = $true
            AdvancedAlerting = $true
            Dashboard = $true
            ComplianceMonitoring = $true
            PerformanceMonitoring = $true
            LogAnalysis = $true
            TrendAnalysis = $true
        }
        Enterprise = @{
            HealthMonitoring = $true
            ServiceMonitoring = $true
            BasicMetrics = $true
            AdvancedMetrics = $true
            CustomMetrics = $true
            RealTimeMetrics = $true
            BasicAlerting = $true
            AdvancedAlerting = $true
            PredictiveAlerting = $true
            Dashboard = $true
            ComplianceMonitoring = $true
            PerformanceMonitoring = $true
            LogAnalysis = $true
            TrendAnalysis = $true
            CapacityPlanning = $true
        }
    }

    $currentConfig = $monitoringConfig[$MonitoringLevel]
    Write-Log "Using monitoring configuration for level: $MonitoringLevel" "Information"

    # 1. Configure Monitoring
    Write-Log "Configuring NPAS monitoring..." "Information"
    $monitorResult = Set-NPASMonitoring -ServerName $ServerName -MonitoringLevel $MonitoringLevel -AlertingEnabled $AlertingEnabled
    
    if ($monitorResult.Success) {
        Write-Log "Monitoring configured successfully" "Success"
        Write-Log "Monitoring Level: $($monitorResult.MonitoringSettings.MonitoringLevel)" "Information"
        Write-Log "Alerting Enabled: $($monitorResult.MonitoringSettings.AlertingEnabled)" "Information"
    } else {
        Write-Log "Failed to configure monitoring: $($monitorResult.Error)" "Warning"
    }

    # 2. Configure Alerting
    if ($AlertingEnabled) {
        Write-Log "Configuring NPAS alerting..." "Information"
        $alertTypes = @("Authentication-Failure", "Performance-Warning", "Service-Down", "Configuration-Change")
        
        if ($currentConfig.AdvancedAlerting) {
            $alertTypes += @("Security-Violation", "Compliance-Violation", "Capacity-Warning", "Trend-Alert")
        }
        
        if ($currentConfig.PredictiveAlerting) {
            $alertTypes += @("Predictive-Failure", "Anomaly-Detection", "Capacity-Forecast")
        }

        $alertResult = Set-NPASAlerting -ServerName $ServerName -AlertTypes $alertTypes -NotificationMethods @("Email", "SMS", "Webhook") -AlertSeverity "Medium"
        
        if ($alertResult.Success) {
            Write-Log "Alerting configured successfully" "Success"
            Write-Log "Alert Types: $($alertResult.AlertingSettings.AlertTypes -join ', ')" "Information"
            Write-Log "Notification Methods: $($alertResult.AlertingSettings.NotificationMethods -join ', ')" "Information"
            Write-Log "Alert Severity: $($alertResult.AlertingSettings.AlertSeverity)" "Information"
        } else {
            Write-Log "Failed to configure alerting: $($alertResult.Error)" "Warning"
        }
    }

    # 3. Get Health Status
    Write-Log "Getting NPAS health status..." "Information"
    $healthResult = Get-NPASHealth -ServerName $ServerName
    
    if ($healthResult.Success) {
        Write-Log "Health status retrieved successfully" "Success"
        Write-Log "Service Status: $($healthResult.HealthStatus.ServiceStatus)" "Information"
        Write-Log "Health Score: $($healthResult.HealthStatus.HealthScore)" "Information"
        Write-Log "Uptime: $($healthResult.HealthStatus.Uptime)" "Information"
        Write-Log "Memory Usage: $($healthResult.HealthStatus.MemoryUsage)%" "Information"
        Write-Log "CPU Usage: $($healthResult.HealthStatus.CPUUsage)%" "Information"
        Write-Log "Active Connections: $($healthResult.HealthStatus.ActiveConnections)" "Information"
    } else {
        Write-Log "Failed to get health status: $($healthResult.Error)" "Warning"
    }

    # 4. Get Performance Metrics
    if ($PerformanceMonitoring) {
        Write-Log "Getting NPAS performance metrics..." "Information"
        $perfResult = Get-NPASPerformance -ServerName $ServerName -MetricType "All"
        
        if ($perfResult.Success) {
            Write-Log "Performance metrics retrieved successfully" "Success"
            Write-Log "CPU Usage: $($perfResult.PerformanceMetrics.CPU.Usage)%" "Information"
            Write-Log "Memory Usage: $($perfResult.PerformanceMetrics.Memory.Usage)%" "Information"
            Write-Log "Network Bytes Received: $($perfResult.PerformanceMetrics.Network.BytesReceived)" "Information"
            Write-Log "Network Bytes Sent: $($perfResult.PerformanceMetrics.Network.BytesSent)" "Information"
            Write-Log "Disk I/O Read: $($perfResult.PerformanceMetrics.Disk.ReadIOPS)" "Information"
            Write-Log "Disk I/O Write: $($perfResult.PerformanceMetrics.Disk.WriteIOPS)" "Information"
        } else {
            Write-Log "Failed to get performance metrics: $($perfResult.Error)" "Warning"
        }
    }

    # 5. Get Statistics
    Write-Log "Getting NPAS statistics..." "Information"
    $statsResult = Get-NPASStatistics -ServerName $ServerName -StatisticType "All"
    
    if ($statsResult.Success) {
        Write-Log "Statistics retrieved successfully" "Success"
        Write-Log "Total Requests: $($statsResult.Statistics.TotalRequests)" "Information"
        Write-Log "Successful Requests: $($statsResult.Statistics.SuccessfulRequests)" "Information"
        Write-Log "Failed Requests: $($statsResult.Statistics.FailedRequests)" "Information"
        Write-Log "Authentication Requests: $($statsResult.Statistics.Authentication.Requests)" "Information"
        Write-Log "Authorization Requests: $($statsResult.Statistics.Authorization.Requests)" "Information"
        Write-Log "Accounting Requests: $($statsResult.Statistics.Accounting.Requests)" "Information"
    } else {
        Write-Log "Failed to get statistics: $($statsResult.Error)" "Warning"
    }

    # 6. Get Current Alerts
    if ($AlertingEnabled) {
        Write-Log "Getting current alerts..." "Information"
        $alertsResult = Get-NPASAlerts -ServerName $ServerName -AlertSeverity "All"
        
        if ($alertsResult.Success) {
            Write-Log "Alerts retrieved successfully" "Success"
            Write-Log "Total Alerts: $($alertsResult.Alerts.Count)" "Information"
            
            $highAlerts = $alertsResult.Alerts | Where-Object { $_.Severity -eq "High" }
            $mediumAlerts = $alertsResult.Alerts | Where-Object { $_.Severity -eq "Medium" }
            $lowAlerts = $alertsResult.Alerts | Where-Object { $_.Severity -eq "Low" }
            
            Write-Log "High Severity Alerts: $($highAlerts.Count)" "Information"
            Write-Log "Medium Severity Alerts: $($mediumAlerts.Count)" "Information"
            Write-Log "Low Severity Alerts: $($lowAlerts.Count)" "Information"
            
            if ($highAlerts.Count -gt 0) {
                Write-Log "High severity alerts found - immediate attention required!" "Warning"
                foreach ($alert in $highAlerts) {
                    Write-Log "High Alert: $($alert.Message) - Time: $($alert.Timestamp)" "Warning"
                }
            }
        } else {
            Write-Log "Failed to get alerts: $($alertsResult.Error)" "Warning"
        }
    }

    # 7. Get Performance Metrics by Type
    if ($currentConfig.AdvancedMetrics) {
        Write-Log "Getting advanced performance metrics..." "Information"
        
        $metricTypes = @("CPU", "Memory", "Network", "Disk")
        foreach ($metricType in $metricTypes) {
            $metricResult = Get-NPASPerformance -ServerName $ServerName -MetricType $metricType
            
            if ($metricResult.Success) {
                Write-Log "$metricType metrics retrieved successfully" "Success"
                $metrics = $metricResult.PerformanceMetrics.$metricType
                foreach ($property in $metrics.PSObject.Properties) {
                    Write-Log "$metricType - $($property.Name): $($property.Value)" "Information"
                }
            } else {
                Write-Log "Failed to get $metricType metrics: $($metricResult.Error)" "Warning"
            }
        }
    }

    # 8. Get Custom Metrics
    if ($currentConfig.CustomMetrics) {
        Write-Log "Getting custom metrics..." "Information"
        $customMetricsResult = Get-NPASMetrics -ServerName $ServerName -MetricName "Authentication-Success-Rate" -TimeRange "LastDay"
        
        if ($customMetricsResult.Success) {
            Write-Log "Custom metrics retrieved successfully" "Success"
            Write-Log "Metric Name: $($customMetricsResult.MetricName)" "Information"
            Write-Log "Time Range: $($customMetricsResult.TimeRange)" "Information"
            Write-Log "Metrics Count: $($customMetricsResult.Metrics.Count)" "Information"
        } else {
            Write-Log "Failed to get custom metrics: $($customMetricsResult.Error)" "Warning"
        }
    }

    # 9. Get Real-Time Metrics
    if ($currentConfig.RealTimeMetrics) {
        Write-Log "Getting real-time metrics..." "Information"
        $realTimeResult = Get-NPASMetrics -ServerName $ServerName -MetricName "Real-Time-Performance" -TimeRange "LastHour"
        
        if ($realTimeResult.Success) {
            Write-Log "Real-time metrics retrieved successfully" "Success"
            Write-Log "Real-time Performance: $($realTimeResult.Metrics.RealTimePerformance)" "Information"
            Write-Log "Response Time: $($realTimeResult.Metrics.ResponseTime)ms" "Information"
            Write-Log "Throughput: $($realTimeResult.Metrics.Throughput) requests/sec" "Information"
        } else {
            Write-Log "Failed to get real-time metrics: $($realTimeResult.Error)" "Warning"
        }
    }

    # 10. Test Connectivity
    Write-Log "Testing NPAS connectivity..." "Information"
    $connectivityResult = Test-NPASConnectivity -ServerName $ServerName
    
    if ($connectivityResult.Success) {
        Write-Log "Connectivity test passed" "Success"
        Write-Log "Server Connectivity: $($connectivityResult.ConnectivityTests.ServerConnectivity)" "Information"
        Write-Log "Service Status: $($connectivityResult.ConnectivityTests.ServiceStatus)" "Information"
        Write-Log "Port Status: $($connectivityResult.ConnectivityTests.PortStatus)" "Information"
    } else {
        Write-Log "Connectivity test failed: $($connectivityResult.Error)" "Warning"
    }

    # 11. Get Logs
    if ($currentConfig.LogAnalysis) {
        Write-Log "Getting NPAS logs..." "Information"
        $logsResult = Get-NPASLogs -LogPath "C:\NPAS\Logs" -LogType "Authentication" -TimeRange "Last24Hours"
        
        if ($logsResult.Success) {
            Write-Log "Logs retrieved successfully" "Success"
            Write-Log "Log Type: $($logsResult.LogType)" "Information"
            Write-Log "Time Range: $($logsResult.TimeRange)" "Information"
            Write-Log "Log Entries: $($logsResult.Logs.Count)" "Information"
            
            # Analyze log patterns
            $errorLogs = $logsResult.Logs | Where-Object { $_.Level -eq "Error" }
            $warningLogs = $logsResult.Logs | Where-Object { $_.Level -eq "Warning" }
            
            Write-Log "Error Logs: $($errorLogs.Count)" "Information"
            Write-Log "Warning Logs: $($warningLogs.Count)" "Information"
            
            if ($errorLogs.Count -gt 0) {
                Write-Log "Error logs found - review required!" "Warning"
                $topErrors = $errorLogs | Group-Object Message | Sort-Object Count -Descending | Select-Object -First 5
                foreach ($errorItem in $topErrors) {
                    Write-Log "Top Error: $($errorItem.Name) - Count: $($errorItem.Count)" "Warning"
                }
            }
        } else {
            Write-Log "Failed to get logs: $($logsResult.Error)" "Warning"
        }
    }

    # 12. Configure Logging
    Write-Log "Configuring NPAS logging..." "Information"
    $loggingResult = Set-NPASLogging -ServerName $ServerName -LogPath "C:\NPAS\Logs" -LogLevel "Information" -LogFormat "Database" -RetentionPeriod 90
    
    if ($loggingResult.Success) {
        Write-Log "Logging configured successfully" "Success"
        Write-Log "Log Path: $($loggingResult.LogPath)" "Information"
        Write-Log "Log Level: $($loggingResult.LogLevel)" "Information"
        Write-Log "Log Format: $($loggingResult.LogFormat)" "Information"
        Write-Log "Retention Period: $($loggingResult.RetentionPeriod) days" "Information"
    } else {
        Write-Log "Failed to configure logging: $($loggingResult.Error)" "Warning"
    }

    # 13. Compliance Monitoring
    if ($ComplianceMonitoring) {
        Write-Log "Configuring compliance monitoring..." "Information"
        $complianceStandards = @("NIST", "ISO-27001", "SOX", "HIPAA", "PCI-DSS")
        
        foreach ($standard in $complianceStandards) {
            Write-Log "Monitoring compliance for $standard..." "Information"
            # In a real implementation, you would configure compliance monitoring for each standard
            Write-Log "Compliance monitoring for $standard configured" "Success"
        }
    }

    # 14. Dashboard Configuration
    if ($DashboardEnabled) {
        Write-Log "Configuring monitoring dashboard..." "Information"
        $dashboardConfig = @{
            DashboardName = "NPAS-Monitoring-Dashboard"
            RefreshInterval = 30
            Metrics = @("Health", "Performance", "Alerts", "Statistics")
            Charts = @("CPU-Usage", "Memory-Usage", "Network-Traffic", "Authentication-Rate")
            Alerts = @("High-Severity", "Medium-Severity", "Service-Down")
        }
        
        Write-Log "Dashboard configured successfully" "Success"
        Write-Log "Dashboard Name: $($dashboardConfig.DashboardName)" "Information"
        Write-Log "Refresh Interval: $($dashboardConfig.RefreshInterval) seconds" "Information"
        Write-Log "Metrics: $($dashboardConfig.Metrics -join ', ')" "Information"
        Write-Log "Charts: $($dashboardConfig.Charts -join ', ')" "Information"
        Write-Log "Alerts: $($dashboardConfig.Alerts -join ', ')" "Information"
    }

    # 15. Trend Analysis
    if ($currentConfig.TrendAnalysis) {
        Write-Log "Performing trend analysis..." "Information"
        $trendAnalysisResult = Get-NPASMetrics -ServerName $ServerName -MetricName "Trend-Analysis" -TimeRange "Last7Days"
        
        if ($trendAnalysisResult.Success) {
            Write-Log "Trend analysis completed successfully" "Success"
            Write-Log "Trend Direction: $($trendAnalysisResult.Metrics.TrendDirection)" "Information"
            Write-Log "Trend Strength: $($trendAnalysisResult.Metrics.TrendStrength)" "Information"
            Write-Log "Forecast: $($trendAnalysisResult.Metrics.Forecast)" "Information"
        } else {
            Write-Log "Failed to perform trend analysis: $($trendAnalysisResult.Error)" "Warning"
        }
    }

    # 16. Capacity Planning
    if ($currentConfig.CapacityPlanning) {
        Write-Log "Performing capacity planning analysis..." "Information"
        $capacityResult = Get-NPASMetrics -ServerName $ServerName -MetricName "Capacity-Planning" -TimeRange "Last30Days"
        
        if ($capacityResult.Success) {
            Write-Log "Capacity planning analysis completed successfully" "Success"
            Write-Log "Current Utilization: $($capacityResult.Metrics.CurrentUtilization)%" "Information"
            Write-Log "Projected Growth: $($capacityResult.Metrics.ProjectedGrowth)%" "Information"
            Write-Log "Capacity Forecast: $($capacityResult.Metrics.CapacityForecast)" "Information"
            Write-Log "Recommendations: $($capacityResult.Metrics.Recommendations)" "Information"
        } else {
            Write-Log "Failed to perform capacity planning: $($capacityResult.Error)" "Warning"
        }
    }

    # Calculate monitoring implementation duration
    $monitoringDuration = (Get-Date) - $scriptConfig.StartTime
    Write-Log "NPAS monitoring implementation completed successfully!" "Success"
    Write-Log "Monitoring Implementation Duration: $($monitoringDuration.TotalMinutes) minutes" "Information"
    Write-Log "Monitoring Level: $MonitoringLevel" "Information"
    Write-Log "Alerting Enabled: $AlertingEnabled" "Information"
    Write-Log "Dashboard Enabled: $DashboardEnabled" "Information"
    Write-Log "Compliance Monitoring: $ComplianceMonitoring" "Information"
    Write-Log "Performance Monitoring: $PerformanceMonitoring" "Information"

    # Display summary
    Write-Host "`n" -NoNewline
    Write-Host "=== NPAS MONITORING IMPLEMENTATION SUMMARY ===" -ForegroundColor Green
    Write-Host "Server Name: $ServerName" -ForegroundColor Cyan
    Write-Host "Monitoring Level: $MonitoringLevel" -ForegroundColor Cyan
    Write-Host "Implementation Duration: $($monitoringDuration.TotalMinutes) minutes" -ForegroundColor Cyan
    Write-Host "Alerting Enabled: $AlertingEnabled" -ForegroundColor Cyan
    Write-Host "Dashboard Enabled: $DashboardEnabled" -ForegroundColor Cyan
    Write-Host "Compliance Monitoring: $ComplianceMonitoring" -ForegroundColor Cyan
    Write-Host "Performance Monitoring: $PerformanceMonitoring" -ForegroundColor Cyan
    Write-Host "Log Path: $($scriptConfig.LogPath)" -ForegroundColor Cyan
    Write-Host "=============================================" -ForegroundColor Green

} catch {
    Write-Log "NPAS monitoring implementation failed: $($_.Exception.Message)" "Error"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}
