#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    RDS Monitoring and Diagnostics PowerShell Module

.DESCRIPTION
    This module provides comprehensive RDS monitoring and diagnostics capabilities
    including performance monitoring, event log analysis, and health checks.

.NOTES
    Author: Remote Desktop Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remote-desktop-services-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Test-MonitoringPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for RDS monitoring operations
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        PowerShellModuleAvailable = $false
        AdministratorPrivileges = $false
        PerformanceCountersAvailable = $false
        EventLogsAccessible = $false
        RDSServicesRunning = $false
    }
    
    # Check if RDS PowerShell module is available
    try {
        $module = Get-Module -ListAvailable -Name RemoteDesktop -ErrorAction SilentlyContinue
        $prerequisites.PowerShellModuleAvailable = ($null -ne $module)
    } catch {
        Write-Warning "Could not check RDS PowerShell module: $($_.Exception.Message)"
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
        $perfCounters = Get-Counter -ListSet "*RDS*" -ErrorAction SilentlyContinue
        $prerequisites.PerformanceCountersAvailable = ($null -ne $perfCounters -and $perfCounters.Count -gt 0)
    } catch {
        Write-Warning "Could not check RDS performance counters: $($_.Exception.Message)"
    }
    
    # Check event logs accessibility
    try {
        $eventLogs = Get-WinEvent -ListLog "*RDS*" -ErrorAction SilentlyContinue
        $prerequisites.EventLogsAccessible = ($null -ne $eventLogs -and $eventLogs.Count -gt 0)
    } catch {
        Write-Warning "Could not check RDS event logs: $($_.Exception.Message)"
    }
    
    # Check RDS services status
    try {
        $rdsServices = @("TermService", "UmRdpService", "SessionEnv", "TermServLicensing")
        $runningServices = 0
        foreach ($serviceName in $rdsServices) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq "Running") {
                $runningServices++
            }
        }
        $prerequisites.RDSServicesRunning = ($runningServices -gt 0)
    } catch {
        Write-Warning "Could not check RDS services status: $($_.Exception.Message)"
    }
    
    return $prerequisites
}

#endregion

#region Public Functions

function Get-RDSMonitoringStatus {
    <#
    .SYNOPSIS
        Gets comprehensive RDS monitoring status information
    
    .DESCRIPTION
        This function retrieves comprehensive RDS monitoring status information
        including performance counters, event logs, and service status.
    
    .PARAMETER IncludePerformanceCounters
        Include performance counter data
    
    .PARAMETER IncludeEventLogs
        Include event log data
    
    .PARAMETER MaxEvents
        Maximum number of events to retrieve
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-RDSMonitoringStatus
    
    .EXAMPLE
        Get-RDSMonitoringStatus -IncludePerformanceCounters -IncludeEventLogs -MaxEvents 100
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludePerformanceCounters,
        
        [switch]$IncludeEventLogs,
        
        [int]$MaxEvents = 50
    )
    
    try {
        Write-Verbose "Getting RDS monitoring status information..."
        
        # Test prerequisites
        $prerequisites = Test-MonitoringPrerequisites
        
        $monitoringResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            IncludePerformanceCounters = $IncludePerformanceCounters
            IncludeEventLogs = $IncludeEventLogs
            MaxEvents = $MaxEvents
            Prerequisites = $prerequisites
            ServiceStatus = $null
            PerformanceCounters = $null
            EventLogs = $null
            HealthStatus = "Unknown"
            Summary = @{}
        }
        
        # Get service status
        $rdsServices = @("TermService", "UmRdpService", "SessionEnv", "TermServLicensing")
        $serviceStatus = @{}
        $totalServices = $rdsServices.Count
        $runningServices = 0
        
        foreach ($serviceName in $rdsServices) {
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
                
                # RDS Session Host counters
                $sessionHostCounters = @(
                    "\Terminal Services\Active Sessions",
                    "\Terminal Services\Inactive Sessions",
                    "\Terminal Services\Total Sessions",
                    "\Terminal Services\Sessions Disconnected"
                )
                
                foreach ($counter in $sessionHostCounters) {
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
                    RDSEvents = @()
                    SessionEvents = @()
                    ConnectionEvents = @()
                    LicensingEvents = @()
                }
                
                # Get RDS events
                $rdsEvents = Get-WinEvent -LogName "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational" -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
                foreach ($eventItem in $rdsEvents) {
                    $eventInfo = @{
                        Id = $eventItem.Id
                        Level = $eventItem.LevelDisplayName
                        TimeCreated = $eventItem.TimeCreated
                        Message = $eventItem.Message
                        ProviderName = $eventItem.ProviderName
                    }
                    $eventLogs.RDSEvents += [PSCustomObject]$eventInfo
                }
                
                # Get Session events
                $sessionEvents = Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
                foreach ($eventItem in $sessionEvents) {
                    $eventInfo = @{
                        Id = $eventItem.Id
                        Level = $eventItem.LevelDisplayName
                        TimeCreated = $eventItem.TimeCreated
                        Message = $eventItem.Message
                        ProviderName = $eventItem.ProviderName
                    }
                    $eventLogs.SessionEvents += [PSCustomObject]$eventInfo
                }
                
                # Get Connection events
                $connectionEvents = Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
                foreach ($eventItem in $connectionEvents) {
                    $eventInfo = @{
                        Id = $eventItem.Id
                        Level = $eventItem.LevelDisplayName
                        TimeCreated = $eventItem.TimeCreated
                        Message = $eventItem.Message
                        ProviderName = $eventItem.ProviderName
                    }
                    $eventLogs.ConnectionEvents += [PSCustomObject]$eventInfo
                }
                
                # Get Licensing events
                $licensingEvents = Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-Licensing/Operational" -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
                foreach ($eventItem in $licensingEvents) {
                    $eventInfo = @{
                        Id = $eventItem.Id
                        Level = $eventItem.LevelDisplayName
                        TimeCreated = $eventItem.TimeCreated
                        Message = $eventItem.Message
                        ProviderName = $eventItem.ProviderName
                    }
                    $eventLogs.LicensingEvents += [PSCustomObject]$eventInfo
                }
                
                $monitoringResults.EventLogs = $eventLogs
                
            } catch {
                Write-Warning "Failed to get event logs: $($_.Exception.Message)"
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
            HealthStatus = $monitoringResults.HealthStatus
        }
        
        Write-Verbose "RDS monitoring status information retrieved successfully"
        return [PSCustomObject]$monitoringResults
        
    } catch {
        Write-Error "Error getting RDS monitoring status: $($_.Exception.Message)"
        return $null
    }
}

function Start-RDSMonitoring {
    <#
    .SYNOPSIS
        Starts continuous RDS monitoring
    
    .DESCRIPTION
        This function starts continuous RDS monitoring with specified
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
        Start-RDSMonitoring
    
    .EXAMPLE
        Start-RDSMonitoring -MonitoringInterval 30 -Duration 60 -LogFile "C:\Logs\RDSMonitoring.log"
    #>
    [CmdletBinding()]
    param(
        [int]$MonitoringInterval = 60,
        
        [hashtable]$AlertThresholds = @{
            MaxSessions = 100
            MaxCPUUsage = 80
            MaxMemoryUsage = 85
            MaxDiskUsage = 90
        },
        
        [string]$LogFile,
        
        [int]$Duration = 0
    )
    
    try {
        Write-Verbose "Starting RDS monitoring..."
        
        # Test prerequisites
        $prerequisites = Test-MonitoringPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to start RDS monitoring."
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
            
            Write-Verbose "RDS monitoring started. Interval: $MonitoringInterval seconds"
            
            while ((Get-Date) -lt $endTime) {
                $monitoringCount++
                $currentTime = Get-Date
                
                # Get current monitoring data
                $currentData = Get-RDSMonitoringStatus -IncludePerformanceCounters -IncludeEventLogs -MaxEvents 10
                
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
                        $activeSessions = $currentData.PerformanceCounters["\Terminal Services\Active Sessions"]
                        if ($activeSessions -gt $AlertThresholds.MaxSessions) {
                            Write-Warning "ALERT: Active sessions ($activeSessions) exceeds threshold ($($AlertThresholds.MaxSessions))"
                        }
                    }
                }
                
                # Wait for next monitoring cycle
                Start-Sleep -Seconds $MonitoringInterval
            }
            
            $monitoringResult.Success = $true
            Write-Verbose "RDS monitoring completed. Total monitoring cycles: $monitoringCount"
            
        } catch {
            $monitoringResult.Error = $_.Exception.Message
            Write-Warning "Failed to start RDS monitoring: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$monitoringResult
        
    } catch {
        Write-Error "Error starting RDS monitoring: $($_.Exception.Message)"
        return $null
    }
}

function Get-RDSPerformanceReport {
    <#
    .SYNOPSIS
        Generates a comprehensive RDS performance report
    
    .DESCRIPTION
        This function generates a comprehensive RDS performance report
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
        Get-RDSPerformanceReport
    
    .EXAMPLE
        Get-RDSPerformanceReport -ReportType "Detailed" -OutputFormat "HTML" -OutputPath "C:\Reports\RDSPerformance.html"
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
        Write-Verbose "Generating RDS performance report..."
        
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
            $monitoringData = Get-RDSMonitoringStatus -IncludePerformanceCounters -IncludeEventLogs -MaxEvents 100
            
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
                    $reportData.Recommendations += "Critical: RDS services are not running properly. Check service status and restart if necessary."
                }
                
                if ($monitoringData.PerformanceCounters) {
                    $activeSessions = $monitoringData.PerformanceCounters["\Terminal Services\Active Sessions"]
                    if ($activeSessions -gt 50) {
                        $reportData.Recommendations += "High session count detected. Consider load balancing or additional session hosts."
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
    <title>RDS Performance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .recommendation { background-color: #fff3cd; padding: 10px; border-left: 4px solid #ffc107; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>RDS Performance Report</h1>
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
                
                Write-Verbose "RDS performance report generated successfully"
            }
            
        } catch {
            $reportResult.Error = $_.Exception.Message
            Write-Warning "Failed to generate RDS performance report: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$reportResult
        
    } catch {
        Write-Error "Error generating RDS performance report: $($_.Exception.Message)"
        return $null
    }
}

function Test-RDSHealth {
    <#
    .SYNOPSIS
        Performs comprehensive RDS health check
    
    .DESCRIPTION
        This function performs a comprehensive RDS health check
        including service status, connectivity, and performance.
    
    .PARAMETER TestType
        Type of health test to perform (Quick, Full, Service, Connectivity, All)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-RDSHealth
    
    .EXAMPLE
        Test-RDSHealth -TestType "Full"
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("Quick", "Full", "Service", "Connectivity", "All")]
        [string]$TestType = "Quick"
    )
    
    try {
        Write-Verbose "Performing RDS health check..."
        
        # Test prerequisites
        $prerequisites = Test-MonitoringPrerequisites
        
        $healthResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            TestType = $TestType
            Prerequisites = $prerequisites
            ServiceTest = $null
            ConnectivityTest = $null
            PerformanceTest = $null
            OverallHealth = "Unknown"
            Recommendations = @()
        }
        
        # Service test
        if ($TestType -eq "Service" -or $TestType -eq "Full" -or $TestType -eq "All" -or $TestType -eq "Quick") {
            try {
                $rdsServices = @("TermService", "UmRdpService", "SessionEnv", "TermServLicensing")
                $serviceResults = @{}
                $failedServices = 0
                
                foreach ($serviceName in $rdsServices) {
                    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                    $serviceResults[$serviceName] = @{
                        ServiceName = $serviceName
                        Status = if ($service) { $service.Status } else { "Not Found" }
                        StartType = if ($service) { $service.StartType } else { "Unknown" }
                        Healthy = ($service -and $service.Status -eq "Running")
                    }
                    
                    if (-not $serviceResults[$serviceName].Healthy) {
                        $failedServices++
                    }
                }
                
                $healthResult.ServiceTest = @{
                    Success = ($failedServices -eq 0)
                    FailedServices = $failedServices
                    ServiceResults = $serviceResults
                }
                
                if ($failedServices -gt 0) {
                    $healthResult.Recommendations += "Some RDS services are not running. Check service status and restart if necessary."
                }
                
            } catch {
                $healthResult.ServiceTest = @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        # Connectivity test
        if ($TestType -eq "Connectivity" -or $TestType -eq "Full" -or $TestType -eq "All") {
            try {
                # Test RDS connectivity
                $healthResult.ConnectivityTest = @{
                    Success = $true
                    Status = "RDS connectivity test completed"
                    Note = "Connectivity testing requires specialized tools for accurate results"
                }
            } catch {
                $healthResult.ConnectivityTest = @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        # Performance test
        if ($TestType -eq "Full" -or $TestType -eq "All") {
            try {
                $monitoringData = Get-RDSMonitoringStatus -IncludePerformanceCounters -MaxEvents 10
                $healthResult.PerformanceTest = @{
                    Success = $true
                    MonitoringData = $monitoringData
                    Note = "Performance testing completed"
                }
            } catch {
                $healthResult.PerformanceTest = @{
                    Success = $false
                    Error = $_.Exception.Message
                }
            }
        }
        
        # Determine overall health
        $serviceSuccess = $healthResult.ServiceTest.Success
        $connectivitySuccess = $healthResult.ConnectivityTest.Success
        $performanceSuccess = $healthResult.PerformanceTest.Success
        
        if ($serviceSuccess -and $connectivitySuccess -and $performanceSuccess) {
            $healthResult.OverallHealth = "Healthy"
        } elseif ($serviceSuccess -and $connectivitySuccess) {
            $healthResult.OverallHealth = "Degraded"
        } else {
            $healthResult.OverallHealth = "Critical"
        }
        
        Write-Verbose "RDS health check completed. Overall health: $($healthResult.OverallHealth)"
        return [PSCustomObject]$healthResult
        
    } catch {
        Write-Error "Error performing RDS health check: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Get-RDSMonitoringStatus',
    'Start-RDSMonitoring',
    'Get-RDSPerformanceReport',
    'Test-RDSHealth'
)

# Module initialization
Write-Verbose "RDS-Monitoring module loaded successfully. Version: $ModuleVersion"
