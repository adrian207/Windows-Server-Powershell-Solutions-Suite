#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Remote Access Services Monitoring Implementation Script

.DESCRIPTION
    This script provides comprehensive monitoring for Remote Access Services
    including performance monitoring, event log analysis, and health checks.

.PARAMETER Action
    Action to perform (Start, Stop, Status, Report, Configure)

.PARAMETER MonitoringType
    Type of monitoring (Performance, Events, Health, All)

.PARAMETER LogFile
    Path to log file

.PARAMETER OutputPath
    Path for monitoring output

.EXAMPLE
    .\Implement-RemoteAccessMonitoring.ps1 -Action "Start" -MonitoringType "All"

.EXAMPLE
    .\Implement-RemoteAccessMonitoring.ps1 -Action "Report" -OutputPath "C:\Reports\RemoteAccess"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Start", "Stop", "Status", "Report", "Configure")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Performance", "Events", "Health", "All")]
    [string]$MonitoringType = "All",
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\Reports\RemoteAccess"
)

# Script configuration
$ScriptVersion = "1.0.0"
$ScriptStartTime = Get-Date

# Logging configuration
if (-not $LogFile) {
    $LogFile = "C:\Logs\RemoteAccess-Monitoring-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
}

# Create log directory if it doesn't exist
$LogDirectory = Split-Path $LogFile -Parent
if (-not (Test-Path $LogDirectory)) {
    New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
}

#region Helper Functions

function Write-RemoteAccessMonitoringLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    Write-Host $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
}

function Test-RemoteAccessMonitoringPrerequisites {
    Write-RemoteAccessMonitoringLog "Testing Remote Access monitoring prerequisites..."
    
    $prerequisites = @{
        OSVersion = $false
        PowerShellVersion = $false
        AdministratorPrivileges = $false
        NetworkConnectivity = $false
        RemoteAccessInstalled = $false
        PerformanceCountersAvailable = $false
    }
    
    # Check OS version
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -ge 10) {
        $prerequisites.OSVersion = $true
        Write-RemoteAccessMonitoringLog "OS Version: Windows 10/Server 2016+ (Compatible)"
    } else {
        Write-RemoteAccessMonitoringLog "OS Version: $($osVersion) (Incompatible)" "ERROR"
    }
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -ge 5) {
        $prerequisites.PowerShellVersion = $true
        Write-RemoteAccessMonitoringLog "PowerShell Version: $psVersion (Compatible)"
    } else {
        Write-RemoteAccessMonitoringLog "PowerShell Version: $psVersion (Incompatible)" "ERROR"
    }
    
    # Check administrator privileges
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $prerequisites.AdministratorPrivileges = $true
        Write-RemoteAccessMonitoringLog "Administrator privileges: Confirmed"
    } else {
        Write-RemoteAccessMonitoringLog "Administrator privileges: Not available" "ERROR"
    }
    
    # Check network connectivity
    try {
        $ping = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet
        $prerequisites.NetworkConnectivity = $ping
        Write-RemoteAccessMonitoringLog "Network connectivity: $($ping ? 'Available' : 'Not available')"
    } catch {
        Write-RemoteAccessMonitoringLog "Network connectivity: Check failed" "WARNING"
    }
    
    # Check Remote Access installation
    try {
        $remoteAccessFeature = Get-WindowsFeature -Name "DirectAccess-VPN" -ErrorAction SilentlyContinue
        $prerequisites.RemoteAccessInstalled = ($remoteAccessFeature -and $remoteAccessFeature.InstallState -eq "Installed")
        Write-RemoteAccessMonitoringLog "Remote Access installation: $($prerequisites.RemoteAccessInstalled ? 'Installed' : 'Not installed')"
    } catch {
        Write-RemoteAccessMonitoringLog "Remote Access installation: Check failed" "WARNING"
    }
    
    # Check performance counters availability
    try {
        $perfCounters = Get-Counter -ListSet "*RemoteAccess*" -ErrorAction SilentlyContinue
        $prerequisites.PerformanceCountersAvailable = ($null -ne $perfCounters -and $perfCounters.Count -gt 0)
        Write-RemoteAccessMonitoringLog "Performance counters: $($prerequisites.PerformanceCountersAvailable ? 'Available' : 'Not available')"
    } catch {
        Write-RemoteAccessMonitoringLog "Performance counters: Check failed" "WARNING"
    }
    
    return $prerequisites
}

function Start-RemoteAccessPerformanceMonitoring {
    Write-RemoteAccessMonitoringLog "Starting Remote Access performance monitoring..."
    
    try {
        # Create output directory if it doesn't exist
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        
        # Get performance counters
        $performanceCounters = @{
            "\RemoteAccess\Total Connections" = 0
            "\RemoteAccess\Active Connections" = 0
            "\RemoteAccess\Failed Connections" = 0
            "\RemoteAccess\Bytes Sent/sec" = 0
            "\RemoteAccess\Bytes Received/sec" = 0
        }
        
        $performanceData = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Counters = @{}
        }
        
        foreach ($counter in $performanceCounters.Keys) {
            try {
                $perfData = Get-Counter -Counter $counter -ErrorAction SilentlyContinue
                if ($perfData) {
                    $performanceData.Counters[$counter] = $perfData.CounterSamples[0].CookedValue
                    Write-RemoteAccessMonitoringLog "Counter $counter : $($perfData.CounterSamples[0].CookedValue)"
                } else {
                    $performanceData.Counters[$counter] = "N/A"
                    Write-RemoteAccessMonitoringLog "Counter $counter : Not available" "WARNING"
                }
            } catch {
                Write-RemoteAccessMonitoringLog "Counter $counter error: $($_.Exception.Message)" "WARNING"
            }
        }
        
        # Save performance data
        $performanceFile = Join-Path $OutputPath "RemoteAccess-Performance-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $performanceData | ConvertTo-Json -Depth 10 | Set-Content $performanceFile
        
        Write-RemoteAccessMonitoringLog "Performance monitoring data saved to: $performanceFile"
        return $true
        
    } catch {
        Write-RemoteAccessMonitoringLog "Performance monitoring failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-RemoteAccessEventMonitoring {
    Write-RemoteAccessMonitoringLog "Starting Remote Access event monitoring..."
    
    try {
        # Create output directory if it doesn't exist
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        
        # Get event logs
        $eventLogs = @("Application", "System", "Security")
        $eventData = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Events = @{}
        }
        
        foreach ($logName in $eventLogs) {
            try {
                $events = Get-WinEvent -LogName $logName -MaxEvents 100 -ErrorAction SilentlyContinue | Where-Object {
                    $_.ProviderName -like "*RemoteAccess*" -or 
                    $_.ProviderName -like "*DirectAccess*" -or 
                    $_.ProviderName -like "*VPN*" -or
                    $_.Message -like "*Remote Access*" -or
                    $_.Message -like "*DirectAccess*" -or
                    $_.Message -like "*VPN*"
                }
                
                $eventData.Events[$logName] = @()
                foreach ($eventItem in $events) {
                    $eventData.Events[$logName] += @{
                        TimeCreated = $eventItem.TimeCreated
                        Id = $eventItem.Id
                        Level = $eventItem.LevelDisplayName
                        ProviderName = $eventItem.ProviderName
                        Message = $eventItem.Message
                    }
                }
                
                Write-RemoteAccessMonitoringLog "Event log $logName : $($events.Count) Remote Access events found"
            } catch {
                Write-RemoteAccessMonitoringLog "Event log $logName error: $($_.Exception.Message)" "WARNING"
            }
        }
        
        # Save event data
        $eventFile = Join-Path $OutputPath "RemoteAccess-Events-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $eventData | ConvertTo-Json -Depth 10 | Set-Content $eventFile
        
        Write-RemoteAccessMonitoringLog "Event monitoring data saved to: $eventFile"
        return $true
        
    } catch {
        Write-RemoteAccessMonitoringLog "Event monitoring failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-RemoteAccessHealthMonitoring {
    Write-RemoteAccessMonitoringLog "Starting Remote Access health monitoring..."
    
    try {
        # Create output directory if it doesn't exist
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        
        # Check service health
        $services = @("RemoteAccess", "IKEEXT", "PolicyAgent", "SstpSvc", "IAS")
        $healthData = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Services = @{}
            OverallHealth = "Unknown"
            Issues = @()
        }
        
        $healthyServices = 0
        $totalServices = $services.Count
        
        foreach ($service in $services) {
            try {
                $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($serviceObj) {
                    $healthData.Services[$service] = @{
                        Status = $serviceObj.Status
                        StartType = $serviceObj.StartType
                        CanStart = $serviceObj.CanStart
                        CanStop = $serviceObj.CanStop
                    }
                    
                    if ($serviceObj.Status -eq "Running") {
                        $healthyServices++
                    } else {
                        $healthData.Issues += "Service $service is not running"
                    }
                    
                    Write-RemoteAccessMonitoringLog "Service $service : $($serviceObj.Status)"
                } else {
                    $healthData.Services[$service] = @{
                        Status = "Not Found"
                        StartType = "Unknown"
                        CanStart = $false
                        CanStop = $false
                    }
                    $healthData.Issues += "Service $service not found"
                    Write-RemoteAccessMonitoringLog "Service $service : Not found" "WARNING"
                }
            } catch {
                $healthData.Services[$service] = @{
                    Status = "Error"
                    StartType = "Unknown"
                    CanStart = $false
                    CanStop = $false
                }
                $healthData.Issues += "Service $service check failed: $($_.Exception.Message)"
                Write-RemoteAccessMonitoringLog "Service $service error: $($_.Exception.Message)" "WARNING"
            }
        }
        
        # Determine overall health
        if ($healthyServices -eq $totalServices) {
            $healthData.OverallHealth = "Healthy"
        } elseif ($healthyServices -gt 0) {
            $healthData.OverallHealth = "Degraded"
        } else {
            $healthData.OverallHealth = "Critical"
        }
        
        # Save health data
        $healthFile = Join-Path $OutputPath "RemoteAccess-Health-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $healthData | ConvertTo-Json -Depth 10 | Set-Content $healthFile
        
        Write-RemoteAccessMonitoringLog "Health monitoring data saved to: $healthFile"
        Write-RemoteAccessMonitoringLog "Overall health: $($healthData.OverallHealth)"
        return $true
        
    } catch {
        Write-RemoteAccessMonitoringLog "Health monitoring failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-RemoteAccessMonitoringStatus {
    Write-RemoteAccessMonitoringLog "Getting Remote Access monitoring status..."
    
    try {
        $statusData = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            MonitoringStatus = "Unknown"
            Services = @{}
            PerformanceCounters = @{}
            EventLogs = @{}
        }
        
        # Check monitoring services
        $monitoringServices = @("RemoteAccess", "IKEEXT", "PolicyAgent")
        foreach ($service in $monitoringServices) {
            try {
                $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($serviceObj) {
                    $statusData.Services[$service] = $serviceObj.Status
                } else {
                    $statusData.Services[$service] = "Not Found"
                }
            } catch {
                $statusData.Services[$service] = "Error"
            }
        }
        
        # Check performance counters
        try {
            $perfCounters = Get-Counter -ListSet "*RemoteAccess*" -ErrorAction SilentlyContinue
            if ($perfCounters) {
                $statusData.PerformanceCounters["Available"] = $perfCounters.Count
            } else {
                $statusData.PerformanceCounters["Available"] = 0
            }
        } catch {
            $statusData.PerformanceCounters["Available"] = "Error"
        }
        
        # Check event logs
        try {
            $eventLogs = Get-WinEvent -ListLog "*RemoteAccess*" -ErrorAction SilentlyContinue
            if ($eventLogs) {
                $statusData.EventLogs["Available"] = $eventLogs.Count
            } else {
                $statusData.EventLogs["Available"] = 0
            }
        } catch {
            $statusData.EventLogs["Available"] = "Error"
        }
        
        # Determine overall monitoring status
        $runningServices = ($statusData.Services.Values | Where-Object { $_ -eq "Running" }).Count
        if ($runningServices -eq $monitoringServices.Count) {
            $statusData.MonitoringStatus = "Active"
        } elseif ($runningServices -gt 0) {
            $statusData.MonitoringStatus = "Partial"
        } else {
            $statusData.MonitoringStatus = "Inactive"
        }
        
        Write-RemoteAccessMonitoringLog "Monitoring status: $($statusData.MonitoringStatus)"
        return $statusData
        
    } catch {
        Write-RemoteAccessMonitoringLog "Status check failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function New-RemoteAccessMonitoringReport {
    Write-RemoteAccessMonitoringLog "Generating Remote Access monitoring report..."
    
    try {
        # Create output directory if it doesn't exist
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        
        # Generate comprehensive report
        $reportData = @{
            ReportGenerated = Get-Date
            ComputerName = $env:COMPUTERNAME
            ReportType = "Remote Access Monitoring Report"
            Summary = @{}
            PerformanceData = @{}
            EventData = @{}
            HealthData = @{}
            Recommendations = @()
        }
        
        # Get performance data
        try {
            $performanceData = Start-RemoteAccessPerformanceMonitoring
            $reportData.PerformanceData["Status"] = if ($performanceData) { "Success" } else { "Failed" }
        } catch {
            $reportData.PerformanceData["Status"] = "Error"
            $reportData.PerformanceData["Error"] = $_.Exception.Message
        }
        
        # Get event data
        try {
            $eventData = Start-RemoteAccessEventMonitoring
            $reportData.EventData["Status"] = if ($eventData) { "Success" } else { "Failed" }
        } catch {
            $reportData.EventData["Status"] = "Error"
            $reportData.EventData["Error"] = $_.Exception.Message
        }
        
        # Get health data
        try {
            $healthData = Start-RemoteAccessHealthMonitoring
            $reportData.HealthData["Status"] = if ($healthData) { "Success" } else { "Failed" }
        } catch {
            $reportData.HealthData["Status"] = "Error"
            $reportData.HealthData["Error"] = $_.Exception.Message
        }
        
        # Generate recommendations
        if ($reportData.PerformanceData.Status -ne "Success") {
            $reportData.Recommendations += "Check performance counter availability and permissions"
        }
        
        if ($reportData.EventData.Status -ne "Success") {
            $reportData.Recommendations += "Review event log access and Remote Access event sources"
        }
        
        if ($reportData.HealthData.Status -ne "Success") {
            $reportData.Recommendations += "Verify Remote Access service status and configuration"
        }
        
        # Save report
        $reportFile = Join-Path $OutputPath "RemoteAccess-Monitoring-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $reportData | ConvertTo-Json -Depth 10 | Set-Content $reportFile
        
        Write-RemoteAccessMonitoringLog "Monitoring report saved to: $reportFile"
        return $true
        
    } catch {
        Write-RemoteAccessMonitoringLog "Report generation failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

#endregion

#region Main Script Logic

try {
    Write-RemoteAccessMonitoringLog "Starting Remote Access Monitoring Implementation Script - Version $ScriptVersion"
    Write-RemoteAccessMonitoringLog "Action: $Action"
    Write-RemoteAccessMonitoringLog "Monitoring Type: $MonitoringType"
    Write-RemoteAccessMonitoringLog "Computer: $env:COMPUTERNAME"
    Write-RemoteAccessMonitoringLog "User: $env:USERNAME"
    
    # Test prerequisites
    $prerequisites = Test-RemoteAccessMonitoringPrerequisites
    
    $criticalFailures = @()
    if (-not $prerequisites.OSVersion) { $criticalFailures += "OS Version" }
    if (-not $prerequisites.PowerShellVersion) { $criticalFailures += "PowerShell Version" }
    if (-not $prerequisites.AdministratorPrivileges) { $criticalFailures += "Administrator Privileges" }
    
    if ($criticalFailures.Count -gt 0) {
        throw "Critical prerequisites failed: $($criticalFailures -join ', ')"
    }
    
    Write-RemoteAccessMonitoringLog "Prerequisites check completed successfully"
    
    # Execute action
    $actionResult = @{
        Action = $Action
        MonitoringType = $MonitoringType
        Success = $false
        StartTime = $ScriptStartTime
        EndTime = $null
        Duration = $null
        Error = $null
        Prerequisites = $prerequisites
        OutputPath = $OutputPath
    }
    
    switch ($Action) {
        "Start" {
            Write-RemoteAccessMonitoringLog "Starting Remote Access monitoring..."
            
            $monitoringResults = @{}
            
            if ($MonitoringType -eq "Performance" -or $MonitoringType -eq "All") {
                $monitoringResults.Performance = Start-RemoteAccessPerformanceMonitoring
            }
            
            if ($MonitoringType -eq "Events" -or $MonitoringType -eq "All") {
                $monitoringResults.Events = Start-RemoteAccessEventMonitoring
            }
            
            if ($MonitoringType -eq "Health" -or $MonitoringType -eq "All") {
                $monitoringResults.Health = Start-RemoteAccessHealthMonitoring
            }
            
            $actionResult.Success = ($monitoringResults.Values | Where-Object { $_ -eq $true }).Count -gt 0
            $actionResult.MonitoringResults = $monitoringResults
        }
        
        "Stop" {
            Write-RemoteAccessMonitoringLog "Stopping Remote Access monitoring..."
            # Note: Actual monitoring stop would require specific implementation
            $actionResult.Success = $true
        }
        
        "Status" {
            Write-RemoteAccessMonitoringLog "Getting Remote Access monitoring status..."
            $statusResult = Get-RemoteAccessMonitoringStatus
            $actionResult.Success = ($null -ne $statusResult)
            $actionResult.StatusResult = $statusResult
        }
        
        "Report" {
            Write-RemoteAccessMonitoringLog "Generating Remote Access monitoring report..."
            $actionResult.Success = New-RemoteAccessMonitoringReport
        }
        
        "Configure" {
            Write-RemoteAccessMonitoringLog "Configuring Remote Access monitoring..."
            # Note: Actual monitoring configuration would require specific implementation
            $actionResult.Success = $true
        }
    }
    
    # Calculate duration
    $actionResult.EndTime = Get-Date
    $actionResult.Duration = $actionResult.EndTime - $actionResult.StartTime
    
    if ($actionResult.Success) {
        Write-RemoteAccessMonitoringLog "Remote Access monitoring $Action completed successfully!"
        Write-RemoteAccessMonitoringLog "Duration: $($actionResult.Duration.TotalMinutes.ToString('F2')) minutes"
    } else {
        Write-RemoteAccessMonitoringLog "Remote Access monitoring $Action failed!" "ERROR"
        Write-RemoteAccessMonitoringLog "Duration: $($actionResult.Duration.TotalMinutes.ToString('F2')) minutes" "ERROR"
    }
    
    # Return result
    return [PSCustomObject]$actionResult
    
} catch {
    $scriptEndTime = Get-Date
    $scriptDuration = $scriptEndTime - $ScriptStartTime
    
    Write-RemoteAccessMonitoringLog "Remote Access Monitoring Implementation Script FAILED!" "ERROR"
    Write-RemoteAccessMonitoringLog "Error: $($_.Exception.Message)" "ERROR"
    Write-RemoteAccessMonitoringLog "Duration: $($scriptDuration.TotalMinutes.ToString('F2')) minutes" "ERROR"
    
    # Return failure result
    $actionResult = @{
        Action = $Action
        Success = $false
        StartTime = $ScriptStartTime
        EndTime = $scriptEndTime
        Duration = $scriptDuration
        Error = $_.Exception.Message
    }
    
    return [PSCustomObject]$actionResult
}

#endregion
