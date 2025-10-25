#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    IIS Monitoring and Performance PowerShell Module

.DESCRIPTION
    This module provides comprehensive IIS monitoring and performance management
    capabilities including performance counters, log analysis, and health monitoring.

.NOTES
    Author: IIS Web Server PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/iis/get-started/introduction-to-iis
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Test-MonitoringPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for IIS monitoring operations
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        IISInstalled = $false
        WebAdministrationModule = $false
        AdministratorPrivileges = $false
        PerformanceCountersAvailable = $false
        EventLogsAccessible = $false
        LogFilesAccessible = $false
    }
    
    # Check if IIS is installed
    try {
        $iisFeature = Get-WindowsFeature -Name "IIS-WebServerRole" -ErrorAction SilentlyContinue
        $prerequisites.IISInstalled = ($iisFeature -and $iisFeature.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check IIS installation: $($_.Exception.Message)"
    }
    
    # Check WebAdministration module
    try {
        $module = Get-Module -ListAvailable -Name WebAdministration -ErrorAction SilentlyContinue
        $prerequisites.WebAdministrationModule = ($null -ne $module)
    } catch {
        Write-Warning "Could not check WebAdministration module: $($_.Exception.Message)"
    }
    
    # Check administrator privileges
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $prerequisites.AdministratorPrivileges = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Warning "Could not check administrator privileges: $($_.Exception.Message)"
    }
    
    # Check performance counters availability
    try {
        $perfCounters = Get-Counter -ListSet "*W3SVC*" -ErrorAction SilentlyContinue
        $prerequisites.PerformanceCountersAvailable = ($null -ne $perfCounters -and $perfCounters.Count -gt 0)
    } catch {
        Write-Warning "Could not check IIS performance counters: $($_.Exception.Message)"
    }
    
    # Check event logs accessibility
    try {
        $eventLogs = Get-WinEvent -ListLog "*W3SVC*" -ErrorAction SilentlyContinue
        $prerequisites.EventLogsAccessible = ($null -ne $eventLogs -and $eventLogs.Count -gt 0)
    } catch {
        Write-Warning "Could not check IIS event logs: $($_.Exception.Message)"
    }
    
    # Check log files accessibility
    try {
        $logPath = "C:\inetpub\logs\LogFiles"
        $prerequisites.LogFilesAccessible = (Test-Path $logPath)
    } catch {
        Write-Warning "Could not check IIS log files accessibility: $($_.Exception.Message)"
    }
    
    return $prerequisites
}

#endregion

#region Public Functions

function Get-IISMonitoringStatus {
    <#
    .SYNOPSIS
        Gets comprehensive IIS monitoring status information
    
    .DESCRIPTION
        This function retrieves comprehensive IIS monitoring status information
        including performance counters, event logs, and service status.
    
    .PARAMETER IncludePerformanceCounters
        Include performance counter data
    
    .PARAMETER IncludeEventLogs
        Include event log data
    
    .PARAMETER IncludeLogFiles
        Include log file analysis
    
    .PARAMETER MaxEvents
        Maximum number of events to retrieve
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-IISMonitoringStatus
    
    .EXAMPLE
        Get-IISMonitoringStatus -IncludePerformanceCounters -IncludeEventLogs -MaxEvents 100
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludePerformanceCounters,
        
        [switch]$IncludeEventLogs,
        
        [switch]$IncludeLogFiles,
        
        [int]$MaxEvents = 50
    )
    
    try {
        Write-Verbose "Getting IIS monitoring status information..."
        
        # Test prerequisites
        $prerequisites = Test-MonitoringPrerequisites
        
        $monitoringResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            IncludePerformanceCounters = $IncludePerformanceCounters
            IncludeEventLogs = $IncludeEventLogs
            IncludeLogFiles = $IncludeLogFiles
            MaxEvents = $MaxEvents
            Prerequisites = $prerequisites
            ServiceStatus = $null
            PerformanceCounters = $null
            EventLogs = $null
            LogFiles = $null
            HealthStatus = "Unknown"
            Summary = @{}
        }
        
        # Get service status
        $iisServices = @("W3SVC", "WAS", "IISADMIN")
        $serviceStatus = @{}
        $totalServices = $iisServices.Count
        $runningServices = 0
        
        foreach ($serviceName in $iisServices) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            $serviceStatus[$serviceName] = @{
                ServiceName = $serviceName
                Status = if ($service) { $service.Status } else { "Not Found" }
                StartType = if ($service) { $service.StartType } else { "Unknown" }
                DisplayName = if ($service) { $service.DisplayName } else { "Unknown" }
            }
            if ($service -and $service.Status -eq "Running") {
                $runningServices++
            }
        }
        
        $monitoringResults.ServiceStatus = $serviceStatus
        
        # Get performance counters
        if ($IncludePerformanceCounters) {
            try {
                $perfCounters = @{}
                
                # IIS performance counters
                $iisCounters = @(
                    "\Web Service(_Total)\Current Connections",
                    "\Web Service(_Total)\Total Connection Attempts",
                    "\Web Service(_Total)\Bytes Sent/sec",
                    "\Web Service(_Total)\Bytes Received/sec",
                    "\Web Service(_Total)\Requests/sec",
                    "\Web Service(_Total)\Requests Queued",
                    "\Web Service(_Total)\Current Anonymous Users",
                    "\Web Service(_Total)\Current NonAnonymous Users"
                )
                
                foreach ($counter in $iisCounters) {
                    try {
                        $perfData = Get-Counter -Counter $counter -ErrorAction SilentlyContinue
                        if ($perfData) {
                            $perfCounters[$counter] = $perfData.CounterSamples[0].CookedValue
                        }
                    } catch {
                        Write-Warning "Could not get performance counter $counter : $($_.Exception.Message)"
                    }
                }
                
                $monitoringResults.PerformanceCounters = $perfCounters
                
            } catch {
                Write-Warning "Failed to get performance counters: $($_.Exception.Message)"
            }
        }
        
        # Get event logs
        if ($IncludeEventLogs) {
            try {
                $eventLogs = @{
                    IISEvents = @()
                    SystemEvents = @()
                    ApplicationEvents = @()
                }
                
                # Get IIS events
                $iisEvents = Get-WinEvent -LogName "Microsoft-Windows-IIS-Configuration/Operational" -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
                foreach ($eventItem in $iisEvents) {
                    $eventInfo = @{
                        Id = $eventItem.Id
                        Level = $eventItem.LevelDisplayName
                        TimeCreated = $eventItem.TimeCreated
                        Message = $eventItem.Message
                        ProviderName = $eventItem.ProviderName
                    }
                    $eventLogs.IISEvents += [PSCustomObject]$eventInfo
                }
                
                # Get System events
                $systemEvents = Get-WinEvent -LogName "System" -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
                foreach ($eventItem in $systemEvents) {
                    $eventInfo = @{
                        Id = $eventItem.Id
                        Level = $eventItem.LevelDisplayName
                        TimeCreated = $eventItem.TimeCreated
                        Message = $eventItem.Message
                        ProviderName = $eventItem.ProviderName
                    }
                    $eventLogs.SystemEvents += [PSCustomObject]$eventInfo
                }
                
                # Get Application events
                $applicationEvents = Get-WinEvent -LogName "Application" -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
                foreach ($eventItem in $applicationEvents) {
                    $eventInfo = @{
                        Id = $eventItem.Id
                        Level = $eventItem.LevelDisplayName
                        TimeCreated = $eventItem.TimeCreated
                        Message = $eventItem.Message
                        ProviderName = $eventItem.ProviderName
                    }
                    $eventLogs.ApplicationEvents += [PSCustomObject]$eventInfo
                }
                
                $monitoringResults.EventLogs = $eventLogs
                
            } catch {
                Write-Warning "Failed to get event logs: $($_.Exception.Message)"
            }
        }
        
        # Get log files
        if ($IncludeLogFiles) {
            try {
                $logFiles = @{
                    LogDirectory = "C:\inetpub\logs\LogFiles"
                    LogFiles = @()
                    TotalLogFiles = 0
                    TotalLogSize = 0
                }
                
                $logPath = "C:\inetpub\logs\LogFiles"
                if (Test-Path $logPath) {
                    $files = Get-ChildItem -Path $logPath -Recurse -File -ErrorAction SilentlyContinue
                    foreach ($file in $files) {
                        $fileInfo = @{
                            Name = $file.Name
                            FullName = $file.FullName
                            Size = $file.Length
                            LastWriteTime = $file.LastWriteTime
                            Extension = $file.Extension
                        }
                        $logFiles.LogFiles += [PSCustomObject]$fileInfo
                        $logFiles.TotalLogSize += $file.Length
                    }
                    $logFiles.TotalLogFiles = $files.Count
                }
                
                $monitoringResults.LogFiles = $logFiles
                
            } catch {
                Write-Warning "Failed to get log files: $($_.Exception.Message)"
            }
        }
        
        # Determine health status
        if ($runningServices -eq $totalServices) {
            $monitoringResults.HealthStatus = "Healthy"
        } elseif ($runningServices -gt 0) {
            $monitoringResults.HealthStatus = "Degraded"
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
            LogFilesAvailable = ($null -ne $monitoringResults.LogFiles)
            HealthStatus = $monitoringResults.HealthStatus
        }
        
        Write-Verbose "IIS monitoring status information retrieved successfully"
        return [PSCustomObject]$monitoringResults
        
    } catch {
        Write-Error "Error getting IIS monitoring status: $($_.Exception.Message)"
        return $null
    }
}

function Start-IISMonitoring {
    <#
    .SYNOPSIS
        Starts continuous IIS monitoring
    
    .DESCRIPTION
        This function starts continuous IIS monitoring with specified
        intervals and alert thresholds.
    
    .PARAMETER MonitoringInterval
        Monitoring interval in seconds
    
    .PARAMETER AlertThresholds
        Alert thresholds for various metrics
    
    .PARAMETER LogFile
        Log file path for monitoring data
    
    .PARAMETER Duration
        Monitoring duration in minutes (0 = continuous)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Start-IISMonitoring
    
    .EXAMPLE
        Start-IISMonitoring -MonitoringInterval 30 -Duration 60 -LogFile "C:\Logs\IISMonitoring.log"
    #>
    [CmdletBinding()]
    param(
        [int]$MonitoringInterval = 60,
        
        [hashtable]$AlertThresholds = @{
            MaxConnections = 1000
            MaxRequestsPerSecond = 100
            MaxQueueLength = 50
            MaxCPUUsage = 80
            MaxMemoryUsage = 85
        },
        
        [string]$LogFile,
        
        [int]$Duration = 0
    )
    
    try {
        Write-Verbose "Starting IIS monitoring..."
        
        # Test prerequisites
        $prerequisites = Test-MonitoringPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to start IIS monitoring."
        }
        
        $monitoringResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            MonitoringInterval = $MonitoringInterval
            AlertThresholds = $AlertThresholds
            LogFile = $LogFile
            Duration = $Duration
            Success = $false
            Error = $null
            MonitoringData = @()
            Prerequisites = $prerequisites
        }
        
        try {
            $startTime = Get-Date
            $endTime = if ($Duration -gt 0) { $startTime.AddMinutes($Duration) } else { [DateTime]::MaxValue }
            $monitoringCount = 0
            
            Write-Verbose "IIS monitoring started. Interval: $MonitoringInterval seconds"
            
            while ((Get-Date) -lt $endTime) {
                $monitoringCount++
                $currentTime = Get-Date
                
                # Get current monitoring data
                $currentData = Get-IISMonitoringStatus -IncludePerformanceCounters -IncludeEventLogs -MaxEvents 10
                
                if ($currentData) {
                    $monitoringData = @{
                        Timestamp = $currentTime
                        MonitoringCount = $monitoringCount
                        HealthStatus = $currentData.HealthStatus
                        ServiceStatus = $currentData.ServiceStatus
                        PerformanceCounters = $currentData.PerformanceCounters
                        EventLogs = $currentData.EventLogs
                        Summary = $currentData.Summary
                    }
                    
                    $monitoringResult.MonitoringData += [PSCustomObject]$monitoringData
                    
                    # Log to file if specified
                    if ($LogFile) {
                        $logEntry = "$($currentTime): Monitoring Count $monitoringCount - Health: $($currentData.HealthStatus)"
                        Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
                    }
                    
                    # Check alert thresholds
                    if ($currentData.PerformanceCounters) {
                        $currentConnections = $currentData.PerformanceCounters["\Web Service(_Total)\Current Connections"]
                        if ($currentConnections -gt $AlertThresholds.MaxConnections) {
                            Write-Warning "ALERT: Current connections ($currentConnections) exceeds threshold ($($AlertThresholds.MaxConnections))"
                        }
                        
                        $requestsPerSecond = $currentData.PerformanceCounters["\Web Service(_Total)\Requests/sec"]
                        if ($requestsPerSecond -gt $AlertThresholds.MaxRequestsPerSecond) {
                            Write-Warning "ALERT: Requests per second ($requestsPerSecond) exceeds threshold ($($AlertThresholds.MaxRequestsPerSecond))"
                        }
                    }
                }
                
                # Wait for next monitoring cycle
                Start-Sleep -Seconds $MonitoringInterval
            }
            
            $monitoringResult.Success = $true
            Write-Verbose "IIS monitoring completed. Total monitoring cycles: $monitoringCount"
            
        } catch {
            $monitoringResult.Error = $_.Exception.Message
            Write-Warning "Failed to start IIS monitoring: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$monitoringResult
        
    } catch {
        Write-Error "Error starting IIS monitoring: $($_.Exception.Message)"
        return $null
    }
}

function Get-IISPerformanceReport {
    <#
    .SYNOPSIS
        Generates a comprehensive IIS performance report
    
    .DESCRIPTION
        This function generates a comprehensive IIS performance report
        including performance counters, trends, and recommendations.
    
    .PARAMETER ReportType
        Type of report to generate (Summary, Detailed, Trend, All)
    
    .PARAMETER TimeRange
        Time range for the report in hours
    
    .PARAMETER OutputFormat
        Output format (Console, HTML, CSV, JSON)
    
    .PARAMETER OutputPath
        Output file path
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-IISPerformanceReport
    
    .EXAMPLE
        Get-IISPerformanceReport -ReportType "Detailed" -OutputFormat "HTML" -OutputPath "C:\Reports\IISPerformance.html"
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("Summary", "Detailed", "Trend", "All")]
        [string]$ReportType = "Summary",
        
        [int]$TimeRange = 24,
        
        [ValidateSet("Console", "HTML", "CSV", "JSON")]
        [string]$OutputFormat = "Console",
        
        [string]$OutputPath
    )
    
    try {
        Write-Verbose "Generating IIS performance report..."
        
        # Test prerequisites
        $prerequisites = Test-MonitoringPrerequisites
        
        $reportResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            ReportType = $ReportType
            TimeRange = $TimeRange
            OutputFormat = $OutputFormat
            OutputPath = $OutputPath
            Prerequisites = $prerequisites
            ReportData = $null
            Success = $false
            Error = $null
        }
        
        try {
            # Get current monitoring data
            $monitoringData = Get-IISMonitoringStatus -IncludePerformanceCounters -IncludeEventLogs -MaxEvents 100
            
            if ($monitoringData) {
                $reportData = @{
                    ReportGenerated = Get-Date
                    ComputerName = $env:COMPUTERNAME
                    TimeRange = $TimeRange
                    ReportType = $ReportType
                    ServiceStatus = $monitoringData.ServiceStatus
                    PerformanceCounters = $monitoringData.PerformanceCounters
                    EventLogs = $monitoringData.EventLogs
                    HealthStatus = $monitoringData.HealthStatus
                    Summary = $monitoringData.Summary
                    Recommendations = @()
                }
                
                # Generate recommendations based on data
                if ($monitoringData.HealthStatus -eq "Critical") {
                    $reportData.Recommendations += "Critical: IIS services are not running properly. Check service status and restart if necessary."
                }
                
                if ($monitoringData.PerformanceCounters) {
                    $currentConnections = $monitoringData.PerformanceCounters["\Web Service(_Total)\Current Connections"]
                    if ($currentConnections -gt 500) {
                        $reportData.Recommendations += "High connection count detected. Consider load balancing or additional servers."
                    }
                    
                    $requestsPerSecond = $monitoringData.PerformanceCounters["\Web Service(_Total)\Requests/sec"]
                    if ($requestsPerSecond -gt 50) {
                        $reportData.Recommendations += "High request rate detected. Monitor server performance and consider optimization."
                    }
                }
                
                $reportResult.ReportData = $reportData
                $reportResult.Success = $true
                
                # Output report based on format
                if ($OutputFormat -eq "HTML" -and $OutputPath) {
                    # Generate HTML report
                    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>IIS Performance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .recommendation { background-color: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin: 10px 0; }
        .metric { background-color: #f8f9fa; padding: 10px; margin: 5px 0; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>IIS Performance Report</h1>
        <p>Generated: $($reportData.ReportGenerated)</p>
        <p>Computer: $($reportData.ComputerName)</p>
        <p>Health Status: $($reportData.HealthStatus)</p>
    </div>
    
    <div class="section">
        <h2>Service Status</h2>
        <p>Total Services: $($reportData.Summary.TotalServices)</p>
        <p>Running Services: $($reportData.Summary.RunningServices)</p>
        <p>Stopped Services: $($reportData.Summary.StoppedServices)</p>
    </div>
    
    <div class="section">
        <h2>Performance Metrics</h2>
        $(if ($reportData.PerformanceCounters) {
            $reportData.PerformanceCounters.GetEnumerator() | ForEach-Object { 
                "<div class='metric'><strong>$($_.Key)</strong>: $($_.Value)</div>"
            }
        } else {
            "<p>No performance counter data available.</p>"
        })
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        $(if ($reportData.Recommendations.Count -gt 0) {
            $reportData.Recommendations | ForEach-Object { "<div class='recommendation'>$_</div>" }
        } else {
            "<p>No specific recommendations at this time.</p>"
        })
    </div>
</body>
</html>
"@
                    Set-Content -Path $OutputPath -Value $htmlReport -ErrorAction Stop
                    Write-Verbose "HTML report saved to: $OutputPath"
                }
                
                Write-Verbose "IIS performance report generated successfully"
            }
            
        } catch {
            $reportResult.Error = $_.Exception.Message
            Write-Warning "Failed to generate IIS performance report: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$reportResult
        
    } catch {
        Write-Error "Error generating IIS performance report: $($_.Exception.Message)"
        return $null
    }
}

function Test-IISPerformance {
    <#
    .SYNOPSIS
        Tests IIS performance and identifies bottlenecks
    
    .DESCRIPTION
        This function tests IIS performance and identifies
        potential bottlenecks and optimization opportunities.
    
    .PARAMETER TestType
        Type of performance test to perform (Quick, Full, Load, All)
    
    .PARAMETER TestDuration
        Duration of the performance test in seconds
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-IISPerformance
    
    .EXAMPLE
        Test-IISPerformance -TestType "Full" -TestDuration 300
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("Quick", "Full", "Load", "All")]
        [string]$TestType = "Quick",
        
        [int]$TestDuration = 60
    )
    
    try {
        Write-Verbose "Testing IIS performance..."
        
        # Test prerequisites
        $prerequisites = Test-MonitoringPrerequisites
        if (-not $prerequisites.IISInstalled) {
            throw "IIS Web Server is not installed."
        }
        
        $performanceResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            TestType = $TestType
            TestDuration = $TestDuration
            Prerequisites = $prerequisites
            PerformanceMetrics = $null
            Bottlenecks = @()
            Recommendations = @()
            OverallPerformance = "Unknown"
        }
        
        try {
            # Get performance metrics
            $monitoringData = Get-IISMonitoringStatus -IncludePerformanceCounters -MaxEvents 10
            
            if ($monitoringData -and $monitoringData.PerformanceCounters) {
                $performanceResult.PerformanceMetrics = $monitoringData.PerformanceCounters
                
                # Analyze performance metrics
                $currentConnections = $monitoringData.PerformanceCounters["\Web Service(_Total)\Current Connections"]
                $requestsPerSecond = $monitoringData.PerformanceCounters["\Web Service(_Total)\Requests/sec"]
                $bytesPerSecond = $monitoringData.PerformanceCounters["\Web Service(_Total)\Bytes Sent/sec"]
                
                # Identify bottlenecks
                if ($currentConnections -gt 500) {
                    $performanceResult.Bottlenecks += "High connection count: $currentConnections"
                    $performanceResult.Recommendations += "Consider implementing connection limits or load balancing"
                }
                
                if ($requestsPerSecond -gt 100) {
                    $performanceResult.Bottlenecks += "High request rate: $requestsPerSecond requests/sec"
                    $performanceResult.Recommendations += "Monitor server resources and consider performance optimization"
                }
                
                if ($bytesPerSecond -gt 100000000) {  # 100MB/s
                    $performanceResult.Bottlenecks += "High data transfer rate: $bytesPerSecond bytes/sec"
                    $performanceResult.Recommendations += "Consider bandwidth optimization or content compression"
                }
                
                # Determine overall performance
                if ($performanceResult.Bottlenecks.Count -eq 0) {
                    $performanceResult.OverallPerformance = "Good"
                } elseif ($performanceResult.Bottlenecks.Count -le 2) {
                    $performanceResult.OverallPerformance = "Fair"
                } else {
                    $performanceResult.OverallPerformance = "Poor"
                }
                
            } else {
                $performanceResult.PerformanceMetrics = "No performance data available"
                $performanceResult.OverallPerformance = "Unknown"
            }
            
        } catch {
            $performanceResult.Error = $_.Exception.Message
            Write-Warning "Failed to test IIS performance: $($_.Exception.Message)"
        }
        
        Write-Verbose "IIS performance test completed. Overall performance: $($performanceResult.OverallPerformance)"
        return [PSCustomObject]$performanceResult
        
    } catch {
        Write-Error "Error testing IIS performance: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Get-IISMonitoringStatus',
    'Start-IISMonitoring',
    'Get-IISPerformanceReport',
    'Test-IISPerformance'
)

# Module initialization
Write-Verbose "IIS-Monitoring module loaded successfully. Version: $ModuleVersion"
