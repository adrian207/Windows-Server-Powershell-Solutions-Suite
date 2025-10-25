#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Monitor Host Guardian Service (HGS)

.DESCRIPTION
    Comprehensive monitoring and alerting script for HGS including:
    - Health monitoring and status checks
    - Performance metrics collection
    - Event log monitoring
    - Alert generation and notification
    - Capacity planning and reporting
    - Dashboard configuration

.PARAMETER HgsServer
    HGS server name

.PARAMETER MonitoringLevel
    Monitoring level (Basic, Enhanced, Advanced)

.PARAMETER AlertMethods
    Alert methods (Email, Webhook, SNMP, Slack, Teams)

.PARAMETER Recipients
    Alert recipients (email addresses, webhook URLs, etc.)

.PARAMETER LogRetention
    Log retention period (days)

.PARAMETER DashboardType
    Dashboard type (Web, PowerShell, Custom)

.PARAMETER RefreshInterval
    Dashboard refresh interval (seconds)

.PARAMETER CustomMetrics
    Custom metrics to monitor

.PARAMETER ContinuousMonitoring
    Enable continuous monitoring mode

.PARAMETER Force
    Force monitoring setup without confirmation

.EXAMPLE
    .\Monitor-HGS.ps1 -HgsServer "HGS01" -MonitoringLevel "Advanced" -AlertMethods @("Email", "Webhook") -Recipients @("admin@contoso.com")

.EXAMPLE
    .\Monitor-HGS.ps1 -HgsServer "HGS01" -MonitoringLevel "Enhanced" -ContinuousMonitoring -DashboardType "Web"

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$HgsServer = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Enhanced", "Advanced")]
    [string]$MonitoringLevel = "Enhanced",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Email", "Webhook", "SNMP", "Slack", "Teams")]
    [string[]]$AlertMethods = @("Email"),

    [Parameter(Mandatory = $false)]
    [string[]]$Recipients = @("admin@contoso.com"),

    [Parameter(Mandatory = $false)]
    [int]$LogRetention = 30,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Web", "PowerShell", "Custom")]
    [string]$DashboardType = "PowerShell",

    [Parameter(Mandatory = $false)]
    [int]$RefreshInterval = 30,

    [Parameter(Mandatory = $false)]
    [string[]]$CustomMetrics = @(),

    [Parameter(Mandatory = $false)]
    [switch]$ContinuousMonitoring,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# Import required modules
$ModulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module "$ModulePath\..\..\Modules\HGS-Core.psm1" -Force
Import-Module "$ModulePath\..\..\Modules\HGS-Monitoring.psm1" -Force

# Global variables
$script:MonitoringLog = @()
$script:MonitoringStartTime = Get-Date
$script:MonitoringConfig = @{}
$script:MonitoringRunning = $false

function Write-MonitoringLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = @{
        Timestamp = $timestamp
        Level = $Level
        Message = $Message
    }
    
    $script:MonitoringLog += $logEntry
    
    $color = switch ($Level) {
        "Info" { "White" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Success" { "Green" }
    }
    
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Set-HGSMonitoringConfiguration {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-MonitoringLog "Configuring HGS monitoring..." "Info"
    
    try {
        # Configure monitoring level
        Set-HGSMonitoring -MonitoringLevel $Config.MonitoringLevel -LogRetention $Config.LogRetention
        
        # Configure alerting
        if ($Config.AlertMethods.Count -gt 0) {
            Set-HGSAlerting -AlertMethods $Config.AlertMethods -Recipients $Config.Recipients
            Write-MonitoringLog "Alerting configured with methods: $($Config.AlertMethods -join ', ')" "Success"
        }
        
        # Configure logging
        Set-HGSLogging -LogLevel "Detailed" -LogRetention $Config.LogRetention -LogLocation "C:\Logs\HGS"
        
        # Configure dashboard
        Set-HGSDashboard -DashboardType $Config.DashboardType -RefreshInterval $Config.RefreshInterval -CustomMetrics $Config.CustomMetrics
        
        Write-MonitoringLog "Monitoring configuration completed" "Success"
        return $true
    }
    catch {
        Write-MonitoringLog "Failed to configure monitoring: $($_.Exception.Message)" "Error"
        throw
    }
}

function Start-HGSHealthMonitoring {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-MonitoringLog "Starting HGS health monitoring..." "Info"
    
    try {
        $script:MonitoringRunning = $true
        
        while ($script:MonitoringRunning) {
            # Get health status
            $healthStatus = Get-HGSHealthStatus -HgsServer $Config.HgsServer -IncludeDetails
            
            # Check for alerts
            $alerts = Get-HGSAlerts -HgsServer $Config.HgsServer -Severity "All" -TimeRange 1
            
            # Process alerts
            foreach ($alert in $alerts) {
                if ($alert.Severity -in @("Critical", "Warning")) {
                    Send-HGSAlert -Alert $alert -Methods $Config.AlertMethods -Recipients $Config.Recipients
                }
            }
            
            # Log health status
            Write-MonitoringLog "Health Status: $($healthStatus.OverallHealth)" "Info"
            
            if ($healthStatus.OverallHealth -ne "Healthy") {
                Write-MonitoringLog "Health issues detected: $($healthStatus.Issues.Count)" "Warning"
            }
            
            # Wait for next check
            Start-Sleep -Seconds $Config.RefreshInterval
        }
        
        return $true
    }
    catch {
        Write-MonitoringLog "Failed to start health monitoring: $($_.Exception.Message)" "Error"
        throw
    }
}

function Start-HGSPerformanceMonitoring {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-MonitoringLog "Starting HGS performance monitoring..." "Info"
    
    try {
        $script:MonitoringRunning = $true
        
        while ($script:MonitoringRunning) {
            # Get performance metrics
            $perfMetrics = Get-HGSPerformanceMetrics -HgsServer $Config.HgsServer -MetricType "All"
            
            # Check performance thresholds
            $thresholds = @{
                CPUUsage = 80
                MemoryUsage = 85
                DiskUsage = 90
                FailedAttestations = 5
                ResponseTime = 5000
            }
            
            # Check CPU usage
            if ($perfMetrics.CPU.ProcessorTime -gt $thresholds.CPUUsage) {
                $alert = @{
                    Severity = "Warning"
                    Message = "High CPU usage detected: $($perfMetrics.CPU.ProcessorTime)%"
                    TimeGenerated = Get-Date
                    Source = "Performance Monitor"
                }
                Send-HGSAlert -Alert $alert -Methods $Config.AlertMethods -Recipients $Config.Recipients
            }
            
            # Check memory usage
            if ($perfMetrics.Memory.UsedPercentage -gt $thresholds.MemoryUsage) {
                $alert = @{
                    Severity = "Warning"
                    Message = "High memory usage detected: $($perfMetrics.Memory.UsedPercentage)%"
                    TimeGenerated = Get-Date
                    Source = "Performance Monitor"
                }
                Send-HGSAlert -Alert $alert -Methods $Config.AlertMethods -Recipients $Config.Recipients
            }
            
            # Check disk usage
            if ($perfMetrics.Disk.FreeSpaceGB -lt 10) {
                $alert = @{
                    Severity = "Critical"
                    Message = "Low disk space detected: $($perfMetrics.Disk.FreeSpaceGB) GB free"
                    TimeGenerated = Get-Date
                    Source = "Performance Monitor"
                }
                Send-HGSAlert -Alert $alert -Methods $Config.AlertMethods -Recipients $Config.Recipients
            }
            
            # Log performance metrics
            Write-MonitoringLog "CPU: $($perfMetrics.CPU.ProcessorTime)%, Memory: $($perfMetrics.Memory.UsedPercentage)%, Disk: $($perfMetrics.Disk.FreeSpaceGB) GB free" "Info"
            
            # Wait for next check
            Start-Sleep -Seconds $Config.RefreshInterval
        }
        
        return $true
    }
    catch {
        Write-MonitoringLog "Failed to start performance monitoring: $($_.Exception.Message)" "Error"
        throw
    }
}

function Start-HGSEventMonitoring {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-MonitoringLog "Starting HGS event monitoring..." "Info"
    
    try {
        $script:MonitoringRunning = $true
        
        while ($script:MonitoringRunning) {
            # Get recent events
            $events = Get-HGSAuditLogs -HgsServer $Config.HgsServer -TimeRange 1 -LogType "All"
            
            # Process events
            foreach ($logEvent in $events) {
                if ($logEvent.Level -in @("Error", "Warning")) {
                    $alert = @{
                        Severity = if ($logEvent.Level -eq "Error") { "Critical" } else { "Warning" }
                        Message = "Event detected: $($logEvent.Message)"
                        TimeGenerated = $logEvent.TimeGenerated
                        Source = "Event Monitor"
                        EventId = $logEvent.Id
                    }
                    Send-HGSAlert -Alert $alert -Methods $Config.AlertMethods -Recipients $Config.Recipients
                }
            }
            
            # Log event count
            Write-MonitoringLog "Events processed: $($events.Count)" "Info"
            
            # Wait for next check
            Start-Sleep -Seconds $Config.RefreshInterval
        }
        
        return $true
    }
    catch {
        Write-MonitoringLog "Failed to start event monitoring: $($_.Exception.Message)" "Error"
        throw
    }
}

function Send-HGSAlert {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Alert,
        
        [Parameter(Mandatory = $true)]
        [string[]]$Methods,
        
        [Parameter(Mandatory = $true)]
        [string[]]$Recipients
    )
    
    try {
        $alertMessage = @{
            Timestamp = $Alert.TimeGenerated
            Severity = $Alert.Severity
            Message = $Alert.Message
            Source = $Alert.Source
            Server = $env:COMPUTERNAME
        }
        
        foreach ($method in $Methods) {
            switch ($method) {
                "Email" {
                    # Send email alert
                    $subject = "HGS Alert: $($Alert.Severity) - $($Alert.Message)"
                    $body = "HGS Alert Details:`n`nSeverity: $($Alert.Severity)`nMessage: $($Alert.Message)`nSource: $($Alert.Source)`nTime: $($Alert.TimeGenerated)`nServer: $($env:COMPUTERNAME)"
                    
                    foreach ($recipient in $Recipients) {
                        if ($recipient -match "@") {
                            Send-MailMessage -To $recipient -Subject $subject -Body $body -SmtpServer "smtp.contoso.com"
                            Write-MonitoringLog "Email alert sent to: $recipient" "Info"
                        }
                    }
                }
                "Webhook" {
                    # Send webhook alert
                    foreach ($recipient in $Recipients) {
                        if ($recipient -match "^https://") {
                            $webhookData = $alertMessage | ConvertTo-Json
                            Invoke-RestMethod -Uri $recipient -Method Post -Body $webhookData -ContentType "application/json"
                            Write-MonitoringLog "Webhook alert sent to: $recipient" "Info"
                        }
                    }
                }
                "SNMP" {
                    # Send SNMP alert
                    Write-MonitoringLog "SNMP alert: $($Alert.Message)" "Info"
                }
                "Slack" {
                    # Send Slack alert
                    foreach ($recipient in $Recipients) {
                        if ($recipient -match "^https://hooks.slack.com") {
                            $slackData = @{
                                text = "HGS Alert: $($Alert.Severity) - $($Alert.Message)"
                                channel = "#hgs-alerts"
                                username = "HGS Monitor"
                            } | ConvertTo-Json
                            
                            Invoke-RestMethod -Uri $recipient -Method Post -Body $slackData -ContentType "application/json"
                            Write-MonitoringLog "Slack alert sent to: $recipient" "Info"
                        }
                    }
                }
                "Teams" {
                    # Send Teams alert
                    foreach ($recipient in $Recipients) {
                        if ($recipient -match "^https://") {
                            $teamsData = @{
                                text = "HGS Alert: $($Alert.Severity) - $($Alert.Message)"
                            } | ConvertTo-Json
                            
                            Invoke-RestMethod -Uri $recipient -Method Post -Body $teamsData -ContentType "application/json"
                            Write-MonitoringLog "Teams alert sent to: $recipient" "Info"
                        }
                    }
                }
            }
        }
        
        return $true
    }
    catch {
        Write-MonitoringLog "Failed to send alert: $($_.Exception.Message)" "Error"
        return $false
    }
}

function Get-HGSCapacityPlanning {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-MonitoringLog "Generating capacity planning report..." "Info"
    
    try {
        $capacityInfo = Get-HGSCapacityPlanning -HgsServer $Config.HgsServer -PlanningHorizon 12
        
        # Generate capacity report
        $reportPath = "C:\HGS-Monitoring\Reports\Capacity-Planning-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        
        # Create report directory
        $reportDir = Split-Path $reportPath -Parent
        if (!(Test-Path $reportDir)) {
            New-Item -Path $reportDir -ItemType Directory -Force
        }
        
        $capacityReport = @{
            GeneratedAt = Get-Date
            ServerName = $Config.HgsServer
            CurrentCapacity = $capacityInfo.CurrentCapacity
            ProjectedCapacity = $capacityInfo.ProjectedCapacity
            Recommendations = $capacityInfo.Recommendations
        }
        
        $capacityReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8
        
        Write-MonitoringLog "Capacity planning report saved to: $reportPath" "Success"
        
        # Send capacity alerts if needed
        foreach ($recommendation in $capacityInfo.Recommendations) {
            $alert = @{
                Severity = "Warning"
                Message = "Capacity Planning: $recommendation"
                TimeGenerated = Get-Date
                Source = "Capacity Planning"
            }
            Send-HGSAlert -Alert $alert -Methods $Config.AlertMethods -Recipients $Config.Recipients
        }
        
        return $reportPath
    }
    catch {
        Write-MonitoringLog "Failed to generate capacity planning report: $($_.Exception.Message)" "Error"
        throw
    }
}

function Get-HGSMonitoringReport {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-MonitoringLog "Generating monitoring report..." "Info"
    
    try {
        $report = Get-HGSReport -HgsServer $Config.HgsServer -ReportType "Comprehensive" -OutputPath "C:\HGS-Monitoring\Reports\HGS-Monitoring-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        
        Write-MonitoringLog "Monitoring report generated: $($report.OutputPath)" "Success"
        return $report.OutputPath
    }
    catch {
        Write-MonitoringLog "Failed to generate monitoring report: $($_.Exception.Message)" "Error"
        throw
    }
}

function Stop-HGSMonitoring {
    Write-MonitoringLog "Stopping HGS monitoring..." "Info"
    
    try {
        $script:MonitoringRunning = $false
        Write-MonitoringLog "HGS monitoring stopped" "Success"
        return $true
    }
    catch {
        Write-MonitoringLog "Failed to stop monitoring: $($_.Exception.Message)" "Error"
        throw
    }
}

function Save-MonitoringReport {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-MonitoringLog "Saving monitoring report..." "Info"
    
    try {
        $reportPath = "C:\HGS-Monitoring\Reports\HGS-Monitoring-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        
        # Create report directory
        $reportDir = Split-Path $reportPath -Parent
        if (!(Test-Path $reportDir)) {
            New-Item -Path $reportDir -ItemType Directory -Force
        }
        
        $monitoringReport = @{
            MonitoringInfo = @{
                HgsServer = $Config.HgsServer
                StartTime = $script:MonitoringStartTime
                EndTime = Get-Date
                Duration = (Get-Date) - $script:MonitoringStartTime
                MonitoringLevel = $Config.MonitoringLevel
                AlertMethods = $Config.AlertMethods
                Recipients = $Config.Recipients
                Configuration = $Config
            }
            MonitoringLog = $script:MonitoringLog
            CurrentStatus = Get-HGSStatus -HgsServer $Config.HgsServer
            HealthStatus = Get-HGSHealthStatus -HgsServer $Config.HgsServer -IncludeDetails
            PerformanceMetrics = Get-HGSPerformanceMetrics -HgsServer $Config.HgsServer -MetricType "All"
            Alerts = Get-HGSAlerts -HgsServer $Config.HgsServer -Severity "All" -TimeRange 24
            Recommendations = @(
                "Monitor HGS services continuously",
                "Review alert thresholds regularly",
                "Update monitoring configuration as needed",
                "Test alerting mechanisms periodically",
                "Review capacity planning reports",
                "Maintain monitoring documentation",
                "Schedule regular monitoring reviews",
                "Update monitoring tools and scripts"
            )
        }
        
        $monitoringReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8
        
        Write-MonitoringLog "Monitoring report saved to: $reportPath" "Success"
        return $reportPath
    }
    catch {
        Write-MonitoringLog "Failed to save monitoring report: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Main monitoring logic
try {
    Write-MonitoringLog "Starting HGS monitoring setup..." "Info"
    Write-MonitoringLog "Server: $HgsServer" "Info"
    Write-MonitoringLog "Monitoring Level: $MonitoringLevel" "Info"
    Write-MonitoringLog "Alert Methods: $($AlertMethods -join ', ')" "Info"
    
    # Build monitoring configuration
    $script:MonitoringConfig = @{
        HgsServer = $HgsServer
        MonitoringLevel = $MonitoringLevel
        AlertMethods = $AlertMethods
        Recipients = $Recipients
        LogRetention = $LogRetention
        DashboardType = $DashboardType
        RefreshInterval = $RefreshInterval
        CustomMetrics = $CustomMetrics
        ContinuousMonitoring = $ContinuousMonitoring
    }
    
    # Confirm monitoring setup
    if (!$Force) {
        Write-Host "`nHGS Monitoring Setup:" -ForegroundColor Cyan
        Write-Host "Server Name: $($script:MonitoringConfig.HgsServer)" -ForegroundColor White
        Write-Host "Monitoring Level: $($script:MonitoringConfig.MonitoringLevel)" -ForegroundColor White
        Write-Host "Alert Methods: $($script:MonitoringConfig.AlertMethods -join ', ')" -ForegroundColor White
        Write-Host "Recipients: $($script:MonitoringConfig.Recipients -join ', ')" -ForegroundColor White
        Write-Host "Dashboard Type: $($script:MonitoringConfig.DashboardType)" -ForegroundColor White
        Write-Host "Refresh Interval: $($script:MonitoringConfig.RefreshInterval) seconds" -ForegroundColor White
        Write-Host "Continuous Monitoring: $($script:MonitoringConfig.ContinuousMonitoring)" -ForegroundColor White
        
        $confirmation = Read-Host "`nDo you want to proceed with HGS monitoring setup? (Y/N)"
        if ($confirmation -notmatch "^[Yy]") {
            Write-MonitoringLog "Monitoring setup cancelled by user" "Warning"
            exit 0
        }
    }
    
    # Execute monitoring setup steps
    Set-HGSMonitoringConfiguration -Config $script:MonitoringConfig
    
    # Generate initial reports
    $capacityReport = Get-HGSCapacityPlanning -Config $script:MonitoringConfig
    $monitoringReport = Get-HGSMonitoringReport -Config $script:MonitoringConfig
    
    # Start continuous monitoring if enabled
    if ($ContinuousMonitoring) {
        Write-MonitoringLog "Starting continuous monitoring..." "Info"
        
        # Start monitoring in background jobs
        $healthJob = Start-Job -ScriptBlock {
            param($Config)
            Import-Module "$using:ModulePath\..\..\Modules\HGS-Monitoring.psm1" -Force
            Start-HGSHealthMonitoring -Config $Config
        } -ArgumentList $script:MonitoringConfig
        
        $perfJob = Start-Job -ScriptBlock {
            param($Config)
            Import-Module "$using:ModulePath\..\..\Modules\HGS-Monitoring.psm1" -Force
            Start-HGSPerformanceMonitoring -Config $Config
        } -ArgumentList $script:MonitoringConfig
        
        $eventJob = Start-Job -ScriptBlock {
            param($Config)
            Import-Module "$using:ModulePath\..\..\Modules\HGS-Monitoring.psm1" -Force
            Start-HGSEventMonitoring -Config $Config
        } -ArgumentList $script:MonitoringConfig
        
        Write-MonitoringLog "Continuous monitoring started with $($healthJob.Id), $($perfJob.Id), $($eventJob.Id)" "Success"
        
        # Wait for user input to stop monitoring
        Write-Host "`nContinuous monitoring is running. Press Ctrl+C to stop." -ForegroundColor Yellow
        
        try {
            while ($true) {
                Start-Sleep -Seconds 10
                
                # Check job status
                if ($healthJob.State -eq "Failed") {
                    Write-MonitoringLog "Health monitoring job failed" "Error"
                }
                if ($perfJob.State -eq "Failed") {
                    Write-MonitoringLog "Performance monitoring job failed" "Error"
                }
                if ($eventJob.State -eq "Failed") {
                    Write-MonitoringLog "Event monitoring job failed" "Error"
                }
            }
        }
        catch {
            Write-MonitoringLog "Stopping continuous monitoring..." "Info"
            
            # Stop monitoring jobs
            Stop-Job $healthJob, $perfJob, $eventJob
            Remove-Job $healthJob, $perfJob, $eventJob
            
            Write-MonitoringLog "Continuous monitoring stopped" "Success"
        }
    }
    
    # Save monitoring report
    $reportPath = Save-MonitoringReport -Config $script:MonitoringConfig
    
    # Final status
    Write-MonitoringLog "HGS monitoring setup completed successfully!" "Success"
    Write-Host "`nMonitoring Setup Summary:" -ForegroundColor Green
    Write-Host "✓ Monitoring configuration completed" -ForegroundColor Green
    Write-Host "✓ Alerting configured" -ForegroundColor Green
    Write-Host "✓ Dashboard configured" -ForegroundColor Green
    Write-Host "✓ Capacity planning report generated" -ForegroundColor Green
    Write-Host "✓ Monitoring report generated" -ForegroundColor Green
    if ($ContinuousMonitoring) {
        Write-Host "✓ Continuous monitoring started" -ForegroundColor Green
    }
    Write-Host "`nMonitoring report saved to: $reportPath" -ForegroundColor Cyan
    Write-Host "Capacity planning report saved to: $capacityReport" -ForegroundColor Cyan
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Review the monitoring reports" -ForegroundColor White
    Write-Host "2. Test alerting mechanisms" -ForegroundColor White
    Write-Host "3. Configure monitoring dashboards" -ForegroundColor White
    Write-Host "4. Schedule regular monitoring reviews" -ForegroundColor White
    Write-Host "5. Update monitoring thresholds as needed" -ForegroundColor White
    Write-Host "6. Train staff on monitoring procedures" -ForegroundColor White
    Write-Host "7. Document monitoring processes" -ForegroundColor White
    
}
catch {
    Write-MonitoringLog "HGS monitoring setup failed: $($_.Exception.Message)" "Error"
    Write-Host "`nMonitoring setup failed. Please check the error messages above and resolve the issues." -ForegroundColor Red
    exit 1
}
