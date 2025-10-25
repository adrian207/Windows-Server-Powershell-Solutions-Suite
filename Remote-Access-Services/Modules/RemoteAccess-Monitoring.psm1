#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Remote Access Monitoring PowerShell Module

.DESCRIPTION
    This module provides comprehensive Remote Access monitoring capabilities
    including performance monitoring, health checks, diagnostics, and reporting.

.NOTES
    Author: Remote Access Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/windows-server/remote/remote-access/remote-access-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Get-RemoteAccessPerformanceCounters {
    <#
    .SYNOPSIS
        Gets Remote Access performance counters
    #>
    [CmdletBinding()]
    param()
    
    try {
        $performanceCounters = @{
            RemoteAccessCounters = @()
            VPNCounters = @()
            DirectAccessCounters = @()
            WAPCounters = @()
            NPSCounters = @()
        }
        
        # Get Remote Access performance counters
        $remoteAccessCounters = Get-Counter -Counter "\RemoteAccess(*)\*" -ErrorAction SilentlyContinue
        if ($remoteAccessCounters) {
            foreach ($counter in $remoteAccessCounters.CounterSamples) {
                $counterInfo = @{
                    Path = $counter.Path
                    InstanceName = $counter.InstanceName
                    CookedValue = $counter.CookedValue
                    RawValue = $counter.RawValue
                    Timestamp = $counter.Timestamp
                }
                $performanceCounters.RemoteAccessCounters += [PSCustomObject]$counterInfo
            }
        }
        
        # Get VPN performance counters
        $vpnCounters = Get-Counter -Counter "\RAS Port(*)\*" -ErrorAction SilentlyContinue
        if ($vpnCounters) {
            foreach ($counter in $vpnCounters.CounterSamples) {
                $counterInfo = @{
                    Path = $counter.Path
                    InstanceName = $counter.InstanceName
                    CookedValue = $counter.CookedValue
                    RawValue = $counter.RawValue
                    Timestamp = $counter.Timestamp
                }
                $performanceCounters.VPNCounters += [PSCustomObject]$counterInfo
            }
        }
        
        # Get NPS performance counters
        $npsCounters = Get-Counter -Counter "\Network Policy Server(*)\*" -ErrorAction SilentlyContinue
        if ($npsCounters) {
            foreach ($counter in $npsCounters.CounterSamples) {
                $counterInfo = @{
                    Path = $counter.Path
                    InstanceName = $counter.InstanceName
                    CookedValue = $counter.CookedValue
                    RawValue = $counter.RawValue
                    Timestamp = $counter.Timestamp
                }
                $performanceCounters.NPSCounters += [PSCustomObject]$counterInfo
            }
        }
        
        return $performanceCounters
        
    } catch {
        Write-Warning "Error getting Remote Access performance counters: $($_.Exception.Message)"
        return $null
    }
}

function Get-RemoteAccessEventLogs {
    <#
    .SYNOPSIS
        Gets Remote Access event logs
    #>
    [CmdletBinding()]
    param(
        [int]$MaxEvents = 100
    )
    
    try {
        $eventLogs = @{
            RemoteAccessEvents = @()
            VPNEvents = @()
            DirectAccessEvents = @()
            WAPEvents = @()
            NPSEvents = @()
        }
        
        # Get Remote Access events
        $remoteAccessEvents = Get-WinEvent -LogName "Microsoft-Windows-RemoteAccess/Operational" -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        foreach ($eventItem in $remoteAccessEvents) {
            $eventInfo = @{
                Id = $eventItem.Id
                Level = $eventItem.LevelDisplayName
                TimeCreated = $eventItem.TimeCreated
                Message = $eventItem.Message
                ProviderName = $eventItem.ProviderName
            }
            $eventLogs.RemoteAccessEvents += [PSCustomObject]$eventInfo
        }
        
        # Get VPN events
        $vpnEvents = Get-WinEvent -LogName "Microsoft-Windows-RasClient/Operational" -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        foreach ($eventItem in $vpnEvents) {
            $eventInfo = @{
                Id = $eventItem.Id
                Level = $eventItem.LevelDisplayName
                TimeCreated = $eventItem.TimeCreated
                Message = $eventItem.Message
                ProviderName = $eventItem.ProviderName
            }
            $eventLogs.VPNEvents += [PSCustomObject]$eventInfo
        }
        
        # Get NPS events
        $npsEvents = Get-WinEvent -LogName "Microsoft-Windows-NetworkPolicyServer/Operational" -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
        foreach ($eventItem in $npsEvents) {
            $eventInfo = @{
                Id = $eventItem.Id
                Level = $eventItem.LevelDisplayName
                TimeCreated = $eventItem.TimeCreated
                Message = $eventItem.Message
                ProviderName = $eventItem.ProviderName
            }
            $eventLogs.NPSEvents += [PSCustomObject]$eventInfo
        }
        
        return $eventLogs
        
    } catch {
        Write-Warning "Error getting Remote Access event logs: $($_.Exception.Message)"
        return $null
    }
}

#endregion

#region Public Functions

function Get-RemoteAccessMonitoringStatus {
    <#
    .SYNOPSIS
        Gets comprehensive Remote Access monitoring status
    
    .DESCRIPTION
        This function retrieves comprehensive Remote Access monitoring status information
        including service status, performance counters, event logs, and health status.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-RemoteAccessMonitoringStatus
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Getting Remote Access monitoring status..."
        
        $monitoringResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            ServiceStatus = $null
            PerformanceCounters = $null
            EventLogs = $null
            HealthStatus = "Unknown"
            Summary = @{}
        }
        
        # Get service status
        $monitoringResults.ServiceStatus = Get-RemoteAccessServiceStatus
        
        # Get performance counters
        $monitoringResults.PerformanceCounters = Get-RemoteAccessPerformanceCounters
        
        # Get event logs
        $monitoringResults.EventLogs = Get-RemoteAccessEventLogs
        
        # Determine health status
        $runningServices = ($monitoringResults.ServiceStatus.Services | Where-Object { $_.Status -eq "Running" }).Count
        $totalServices = $monitoringResults.ServiceStatus.Services.Count
        
        if ($runningServices -eq $totalServices) {
            $monitoringResults.HealthStatus = "Healthy"
        } elseif ($runningServices -gt 0) {
            $monitoringResults.HealthStatus = "Warning"
        } else {
            $monitoringResults.HealthStatus = "Critical"
        }
        
        # Generate summary
        $monitoringResults.Summary = @{
            TotalServices = $totalServices
            RunningServices = $runningServices
            StoppedServices = $totalServices - $runningServices
            PerformanceCountersAvailable = ($null -ne $monitoringResults.PerformanceCounters)
            EventLogsAvailable = ($null -ne $monitoringResults.EventLogs)
            HealthStatus = $monitoringResults.HealthStatus
        }
        
        Write-Verbose "Remote Access monitoring status retrieved successfully"
        return [PSCustomObject]$monitoringResults
        
    } catch {
        Write-Error "Error getting Remote Access monitoring status: $($_.Exception.Message)"
        return $null
    }
}

function Start-RemoteAccessMonitoring {
    <#
    .SYNOPSIS
        Starts continuous Remote Access monitoring
    
    .DESCRIPTION
        This function starts continuous monitoring of Remote Access services
        and alerts when issues are detected.
    
    .PARAMETER MonitoringInterval
        Monitoring interval in minutes (default: 5)
    
    .PARAMETER AlertThreshold
        Number of issues before alerting (default: 1)
    
    .PARAMETER LogPath
        Path to save monitoring logs
    
    .PARAMETER EmailAlerts
        Email addresses for alerts
    
    .PARAMETER MonitorPerformance
        Include performance monitoring
    
    .PARAMETER MonitorEvents
        Include event log monitoring
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Start-RemoteAccessMonitoring -MonitoringInterval 10
    
    .EXAMPLE
        Start-RemoteAccessMonitoring -MonitoringInterval 5 -AlertThreshold 2 -LogPath "C:\Logs\RemoteAccessMonitor.log" -MonitorPerformance
    #>
    [CmdletBinding()]
    param(
        [int]$MonitoringInterval = 5,
        
        [int]$AlertThreshold = 1,
        
        [string]$LogPath,
        
        [string[]]$EmailAlerts,
        
        [switch]$MonitorPerformance,
        
        [switch]$MonitorEvents
    )
    
    try {
        Write-Verbose "Starting Remote Access monitoring..."
        
        $monitoringResults = @{
            StartTime = Get-Date
            ComputerName = $env:COMPUTERNAME
            MonitoringInterval = $MonitoringInterval
            AlertThreshold = $AlertThreshold
            LogPath = $LogPath
            EmailAlerts = $EmailAlerts
            MonitorPerformance = $MonitorPerformance
            MonitorEvents = $MonitorEvents
            MonitoringActive = $true
            ChecksPerformed = 0
            AlertsGenerated = 0
            LastCheckTime = $null
            LastCheckResults = $null
        }
        
        Write-Verbose "Remote Access monitoring started"
        Write-Verbose "Monitoring interval: $MonitoringInterval minutes"
        Write-Verbose "Alert threshold: $AlertThreshold issues"
        
        # Start monitoring loop
        while ($monitoringResults.MonitoringActive) {
            try {
                $checkTime = Get-Date
                $monitoringResults.LastCheckTime = $checkTime
                $monitoringResults.ChecksPerformed++
                
                Write-Verbose "Performing Remote Access monitoring check #$($monitoringResults.ChecksPerformed)..."
                
                # Perform monitoring check
                $monitoringStatus = Get-RemoteAccessMonitoringStatus
                $monitoringResults.LastCheckResults = $monitoringStatus
                
                # Check for alerts
                $issues = 0
                $stoppedServices = ($monitoringStatus.ServiceStatus.Services | Where-Object { $_.Status -ne "Running" }).Count
                $issues += $stoppedServices
                
                if ($MonitorPerformance -and $null -eq $monitoringStatus.PerformanceCounters) {
                    $issues++
                }
                
                if ($MonitorEvents -and $null -eq $monitoringStatus.EventLogs) {
                    $issues++
                }
                
                if ($issues -ge $AlertThreshold) {
                    $monitoringResults.AlertsGenerated++
                    
                    $alertMessage = "REMOTE ACCESS ALERT: $issues issues detected"
                    Write-Warning $alertMessage
                    
                    # Log alert
                    if ($LogPath) {
                        $logEntry = "[$checkTime] ALERT: $alertMessage"
                        Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
                    }
                    
                    # Send email alert if configured
                    if ($EmailAlerts) {
                        try {
                            # Note: Email sending would require additional configuration
                            Write-Verbose "Email alert would be sent to: $($EmailAlerts -join ', ')"
                        } catch {
                            Write-Warning "Failed to send email alert: $($_.Exception.Message)"
                        }
                    }
                }
                
                # Log check results
                if ($LogPath) {
                    $logEntry = "[$checkTime] Check #$($monitoringResults.ChecksPerformed): $issues issues detected, Health: $($monitoringStatus.HealthStatus)"
                    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
                }
                
                Write-Verbose "Remote Access monitoring check completed. Issues: $issues, Health: $($monitoringStatus.HealthStatus)"
                
                # Wait for next check
                Start-Sleep -Seconds ($MonitoringInterval * 60)
                
            } catch {
                Write-Warning "Error during Remote Access monitoring: $($_.Exception.Message)"
                Start-Sleep -Seconds 60  # Wait 1 minute before retrying
            }
        }
        
        return [PSCustomObject]$monitoringResults
        
    } catch {
        Write-Error "Error starting Remote Access monitoring: $($_.Exception.Message)"
        return $null
    }
}

function Test-RemoteAccessPerformance {
    <#
    .SYNOPSIS
        Tests Remote Access performance
    
    .DESCRIPTION
        This function tests Remote Access performance by analyzing
        performance counters and identifying bottlenecks.
    
    .PARAMETER TestDuration
        Duration of the test in seconds (default: 60)
    
    .PARAMETER IncludeCounters
        Specific performance counters to include
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-RemoteAccessPerformance
    
    .EXAMPLE
        Test-RemoteAccessPerformance -TestDuration 120 -IncludeCounters @("RemoteAccess", "VPN", "NPS")
    #>
    [CmdletBinding()]
    param(
        [int]$TestDuration = 60,
        
        [string[]]$IncludeCounters
    )
    
    try {
        Write-Verbose "Testing Remote Access performance for $TestDuration seconds..."
        
        $performanceResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            TestDuration = $TestDuration
            IncludeCounters = $IncludeCounters
            PerformanceData = @()
            Analysis = @{}
            OverallPerformance = "Unknown"
        }
        
        try {
            # Define performance counters to monitor
            $counters = @(
                "\RemoteAccess(*)\*",
                "\RAS Port(*)\*",
                "\Network Policy Server(*)\*"
            )
            
            if ($IncludeCounters) {
                $counters = $IncludeCounters
            }
            
            # Collect performance data
            $startTime = Get-Date
            $endTime = $startTime.AddSeconds($TestDuration)
            
            while ((Get-Date) -lt $endTime) {
                $sampleTime = Get-Date
                $counterData = Get-Counter -Counter $counters -ErrorAction SilentlyContinue
                
                if ($counterData) {
                    $sampleData = @{
                        Timestamp = $sampleTime
                        Counters = @()
                    }
                    
                    foreach ($counter in $counterData.CounterSamples) {
                        $counterInfo = @{
                            Path = $counter.Path
                            InstanceName = $counter.InstanceName
                            CookedValue = $counter.CookedValue
                            RawValue = $counter.RawValue
                        }
                        $sampleData.Counters += [PSCustomObject]$counterInfo
                    }
                    
                    $performanceResult.PerformanceData += [PSCustomObject]$sampleData
                }
                
                Start-Sleep -Seconds 5  # Sample every 5 seconds
            }
            
            # Analyze performance data
            $analysis = @{
                TotalSamples = $performanceResult.PerformanceData.Count
                AverageResponseTime = 0
                PeakResponseTime = 0
                TotalConnections = 0
                ActiveConnections = 0
                Recommendations = @()
            }
            
            # Calculate averages and peaks
            $responseTimeValues = @()
            $connectionValues = @()
            
            foreach ($sample in $performanceResult.PerformanceData) {
                foreach ($counter in $sample.Counters) {
                    if ($counter.Path -like "*Response Time*") {
                        $responseTimeValues += $counter.CookedValue
                    }
                    if ($counter.Path -like "*Connections*") {
                        $connectionValues += $counter.CookedValue
                    }
                }
            }
            
            if ($responseTimeValues.Count -gt 0) {
                $analysis.AverageResponseTime = [math]::Round(($responseTimeValues | Measure-Object -Average).Average, 2)
                $analysis.PeakResponseTime = [math]::Round(($responseTimeValues | Measure-Object -Maximum).Maximum, 2)
            }
            
            if ($connectionValues.Count -gt 0) {
                $analysis.TotalConnections = [math]::Round(($connectionValues | Measure-Object -Sum).Sum, 0)
                $analysis.ActiveConnections = [math]::Round(($connectionValues | Measure-Object -Average).Average, 0)
            }
            
            # Generate recommendations
            if ($analysis.AverageResponseTime -gt 1000) {
                $analysis.Recommendations += "High response time detected. Consider optimizing network configuration."
            }
            
            if ($analysis.ActiveConnections -gt 100) {
                $analysis.Recommendations += "High number of active connections. Monitor for capacity issues."
            }
            
            if ($analysis.AverageResponseTime -lt 100) {
                $analysis.Recommendations += "Response time is within acceptable limits."
            }
            
            $performanceResult.Analysis = $analysis
            
            # Determine overall performance
            if ($analysis.AverageResponseTime -lt 500 -and $analysis.ActiveConnections -lt 50) {
                $performanceResult.OverallPerformance = "Excellent"
            } elseif ($analysis.AverageResponseTime -lt 1000 -and $analysis.ActiveConnections -lt 100) {
                $performanceResult.OverallPerformance = "Good"
            } elseif ($analysis.AverageResponseTime -lt 2000 -and $analysis.ActiveConnections -lt 200) {
                $performanceResult.OverallPerformance = "Fair"
            } else {
                $performanceResult.OverallPerformance = "Poor"
            }
            
        } catch {
            Write-Warning "Error during performance test: $($_.Exception.Message)"
        }
        
        Write-Verbose "Remote Access performance test completed. Overall performance: $($performanceResult.OverallPerformance)"
        return [PSCustomObject]$performanceResult
        
    } catch {
        Write-Error "Error testing Remote Access performance: $($_.Exception.Message)"
        return $null
    }
}

function Get-RemoteAccessReport {
    <#
    .SYNOPSIS
        Generates a comprehensive Remote Access report
    
    .DESCRIPTION
        This function creates a detailed report of Remote Access status,
        performance, and recommendations.
    
    .PARAMETER OutputPath
        Path to save the report
    
    .PARAMETER IncludePerformanceData
        Include performance analysis in the report
    
    .PARAMETER IncludeEventLogs
        Include event log analysis in the report
    
    .PARAMETER IncludeRecommendations
        Include recommendations in the report
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-RemoteAccessReport -OutputPath "C:\Reports\RemoteAccess.html"
    
    .EXAMPLE
        Get-RemoteAccessReport -OutputPath "C:\Reports\RemoteAccess.html" -IncludePerformanceData -IncludeEventLogs -IncludeRecommendations
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        
        [switch]$IncludePerformanceData,
        
        [switch]$IncludeEventLogs,
        
        [switch]$IncludeRecommendations
    )
    
    try {
        Write-Verbose "Generating Remote Access report..."
        
        $report = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            MonitoringStatus = Get-RemoteAccessMonitoringStatus
            PerformanceData = $null
            EventLogs = $null
            Recommendations = @()
        }
        
        # Include performance data if requested
        if ($IncludePerformanceData) {
            $report.PerformanceData = Test-RemoteAccessPerformance -TestDuration 30
        }
        
        # Include event logs if requested
        if ($IncludeEventLogs) {
            $report.EventLogs = Get-RemoteAccessEventLogs
        }
        
        # Generate recommendations
        if ($IncludeRecommendations) {
            if ($report.MonitoringStatus.HealthStatus -ne "Healthy") {
                $report.Recommendations += "Review and resolve identified health issues"
            }
            
            if ($report.PerformanceData -and $report.PerformanceData.OverallPerformance -eq "Poor") {
                $report.Recommendations += "Performance is poor. Consider optimizing configuration or adding resources"
            }
            
            $stoppedServices = $report.MonitoringStatus.Summary.StoppedServices
            if ($stoppedServices -gt 0) {
                $report.Recommendations += "Start stopped services: $stoppedServices services are not running"
            }
            
            if ($report.MonitoringStatus.Summary.TotalServices -eq 0) {
                $report.Recommendations += "Install Remote Access services"
            }
        }
        
        $reportObject = [PSCustomObject]$report
        
        if ($OutputPath) {
            # Convert to HTML report
            $htmlReport = $reportObject | ConvertTo-Html -Title "Remote Access Report" -Head @"
<style>
body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
.container { background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
h1 { color: #333; border-bottom: 2px solid #dc3545; padding-bottom: 10px; }
h2 { color: #dc3545; margin-top: 30px; }
h3 { color: #666; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; font-weight: bold; }
.healthy { color: #28a745; font-weight: bold; }
.warning { color: #ffc107; font-weight: bold; }
.critical { color: #dc3545; font-weight: bold; }
.recommendation { background-color: #d1ecf1; padding: 10px; margin: 5px 0; border-left: 4px solid #17a2b8; }
</style>
"@
            
            $htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Verbose "Remote Access report saved to: $OutputPath"
        }
        
        return $reportObject
        
    } catch {
        Write-Error "Error generating Remote Access report: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Get-RemoteAccessMonitoringStatus',
    'Start-RemoteAccessMonitoring',
    'Test-RemoteAccessPerformance',
    'Get-RemoteAccessReport'
)

# Module initialization
Write-Verbose "RemoteAccess-Monitoring module loaded successfully. Version: $ModuleVersion"
