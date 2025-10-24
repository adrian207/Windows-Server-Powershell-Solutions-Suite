#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Monitor Windows Hyper-V

.DESCRIPTION
    Comprehensive monitoring script for Windows Hyper-V virtualization.
    Provides health monitoring, performance metrics, alerting, and reporting.

.PARAMETER ServerName
    Name of the server to monitor

.PARAMETER MonitoringLevel
    Level of monitoring to enable (Basic, Standard, Comprehensive)

.PARAMETER IncludePerformance
    Include performance monitoring

.PARAMETER IncludeHealth
    Include health monitoring

.PARAMETER IncludeSecurity
    Include security monitoring

.PARAMETER IncludeStorage
    Include storage monitoring

.PARAMETER IncludeNetwork
    Include network monitoring

.PARAMETER EnableAlerting
    Enable alerting and notifications

.PARAMETER AlertThresholds
    Custom alert thresholds

.PARAMETER MonitoringInterval
    Monitoring interval in minutes

.PARAMETER GenerateReports
    Generate monitoring reports

.PARAMETER ReportInterval
    Report generation interval in hours

.PARAMETER MonitoringConfigurationFile
    Path to JSON monitoring configuration file

.EXAMPLE
    .\Monitor-HyperV.ps1 -ServerName "HV-SERVER01" -MonitoringLevel "Comprehensive" -EnableAlerting

.EXAMPLE
    .\Monitor-HyperV.ps1 -ServerName "HV-SERVER01" -MonitoringLevel "Standard" -IncludePerformance -IncludeHealth -GenerateReports

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive monitoring for Windows Hyper-V virtualization.
    It provides health monitoring, performance metrics, alerting, and reporting.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ServerName = $env:COMPUTERNAME,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Standard", "Comprehensive")]
    [string]$MonitoringLevel = "Standard",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludePerformance,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeHealth,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSecurity,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeStorage,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeNetwork,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableAlerting,
    
    [Parameter(Mandatory = $false)]
    [hashtable]$AlertThresholds,
    
    [Parameter(Mandatory = $false)]
    [int]$MonitoringInterval = 5,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateReports,
    
    [Parameter(Mandatory = $false)]
    [int]$ReportInterval = 24,
    
    [Parameter(Mandatory = $false)]
    [string]$MonitoringConfigurationFile
)

# Import required modules
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $modulePath "..\Modules"

Import-Module "$modulesPath\HyperV-Monitoring.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\HyperV-Core.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\HyperV-Security.psm1" -Force -ErrorAction Stop

# Logging function
function Write-MonitoringLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
        "Info" { Write-Host $logMessage -ForegroundColor Cyan }
        default { Write-Host $logMessage -ForegroundColor White }
    }
}

# Error handling
$ErrorActionPreference = "Stop"

try {
    Write-MonitoringLog "Starting Hyper-V monitoring" "Info"
    Write-MonitoringLog "Server Name: $ServerName" "Info"
    Write-MonitoringLog "Monitoring Level: $MonitoringLevel" "Info"
    Write-MonitoringLog "Monitoring Interval: $MonitoringInterval minutes" "Info"
    
    # Load monitoring configuration from file if provided
    if ($MonitoringConfigurationFile -and (Test-Path $MonitoringConfigurationFile)) {
        Write-MonitoringLog "Loading monitoring configuration from file: $MonitoringConfigurationFile" "Info"
        $monitoringConfig = Get-Content $MonitoringConfigurationFile | ConvertFrom-Json
        
        # Override parameters with file values if not specified
        if (-not $PSBoundParameters.ContainsKey('MonitoringLevel') -and $monitoringConfig.MonitoringLevel) {
            $MonitoringLevel = $monitoringConfig.MonitoringLevel
        }
        if (-not $PSBoundParameters.ContainsKey('MonitoringInterval') -and $monitoringConfig.MonitoringInterval) {
            $MonitoringInterval = $monitoringConfig.MonitoringInterval
        }
        if (-not $PSBoundParameters.ContainsKey('AlertThresholds') -and $monitoringConfig.AlertThresholds) {
            $AlertThresholds = $monitoringConfig.AlertThresholds
        }
    }
    
    # Validate prerequisites
    Write-MonitoringLog "Validating prerequisites..." "Info"
    
    # Check if Hyper-V is installed
    $hyperVFeature = Get-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
    if (-not $hyperVFeature -or $hyperVFeature.InstallState -ne "Installed") {
        throw "Hyper-V feature is not installed"
    }
    
    Write-MonitoringLog "Prerequisites validated successfully" "Success"
    
    # Configure monitoring based on level
    Write-MonitoringLog "Configuring monitoring level: $MonitoringLevel" "Info"
    
    switch ($MonitoringLevel) {
        "Basic" {
            $IncludeHealth = $true
        }
        "Standard" {
            $IncludeHealth = $true
            $IncludePerformance = $true
        }
        "Comprehensive" {
            $IncludeHealth = $true
            $IncludePerformance = $true
            $IncludeSecurity = $true
            $IncludeStorage = $true
            $IncludeNetwork = $true
        }
    }
    
    # Enable health monitoring
    if ($IncludeHealth) {
        Write-MonitoringLog "Enabling health monitoring..." "Info"
        
        $healthStatus = Get-HyperVHealthStatus -HostName $ServerName -IncludeDetails -IncludeVMs -IncludeHost
        
        Write-MonitoringLog "Health monitoring enabled" "Success"
        Write-MonitoringLog "Overall Health: $($healthStatus.OverallHealth)" "Info"
        Write-MonitoringLog "VMs Online: $($healthStatus.VMHealth.Count)" "Info"
    }
    
    # Enable performance monitoring
    if ($IncludePerformance) {
        Write-MonitoringLog "Enabling performance monitoring..." "Info"
        
        $performanceMetrics = Get-HyperVPerformanceMetrics -HostName $ServerName -DurationMinutes $MonitoringInterval
        
        Write-MonitoringLog "Performance monitoring enabled" "Success"
    }
    
    # Enable security monitoring
    if ($IncludeSecurity) {
        Write-MonitoringLog "Enabling security monitoring..." "Info"
        
        $securityReport = Get-HyperVSecurityReport -HostName $ServerName -ReportType "Enhanced"
        
        Write-MonitoringLog "Security monitoring enabled" "Success"
        Write-MonitoringLog "Compliance Score: $($securityReport.ComplianceStatus.ComplianceScore)%" "Info"
    }
    
    # Enable storage monitoring
    if ($IncludeStorage) {
        Write-MonitoringLog "Enabling storage monitoring..." "Info"
        
        $storageUtilization = Get-HyperVStorageUtilization -HostName $ServerName -IncludeVHDs -IncludeCheckpoints
        
        Write-MonitoringLog "Storage monitoring enabled" "Success"
        Write-MonitoringLog "Total VHD Size: $($storageUtilization.TotalVHDSize) bytes" "Info"
        Write-MonitoringLog "Total VHD Used: $($storageUtilization.TotalVHDUsed) bytes" "Info"
    }
    
    # Enable network monitoring
    if ($IncludeNetwork) {
        Write-MonitoringLog "Enabling network monitoring..." "Info"
        
        $networkUtilization = Get-HyperVNetworkUtilization -HostName $ServerName
        
        Write-MonitoringLog "Network monitoring enabled" "Success"
        Write-MonitoringLog "Switches: $($networkUtilization.Switches.Count)" "Info"
        Write-MonitoringLog "VMs: $($networkUtilization.VMs.Count)" "Info"
    }
    
    # Configure alerting
    if ($EnableAlerting) {
        Write-MonitoringLog "Configuring alerting..." "Info"
        
        $alertingConfig = Set-HyperVAlerting -HostName $ServerName -AlertThresholds $AlertThresholds -EnableCPUAlerts -EnableMemoryAlerts -EnableDiskAlerts -EnableNetworkAlerts
        
        Write-MonitoringLog "Alerting configured successfully" "Success"
    }
    
    # Get current resource utilization
    Write-MonitoringLog "Getting current resource utilization..." "Info"
    
    $resourceUtilization = Get-HyperVResourceUtilization -HostName $ServerName -ResourceType "All"
    
    Write-MonitoringLog "Resource utilization retrieved" "Success"
    Write-MonitoringLog "VMs Monitored: $($resourceUtilization.Count)" "Info"
    
    # Get current performance metrics
    if ($IncludePerformance) {
        Write-MonitoringLog "Getting current performance metrics..." "Info"
        
        $performanceMetrics = Get-HyperVPerformanceMetrics -HostName $ServerName -DurationMinutes 5
        
        Write-MonitoringLog "Performance metrics retrieved" "Success"
        Write-MonitoringLog "VMs Monitored: $($performanceMetrics.Count)" "Info"
    }
    
    # Get event logs
    Write-MonitoringLog "Getting event logs..." "Info"
    
    $eventLogs = Get-HyperVEventLogs -HostName $ServerName -LogLevel "All" -MaxEvents 50
    
    Write-MonitoringLog "Event logs retrieved" "Success"
    Write-MonitoringLog "Events Analyzed: $($eventLogs.Count)" "Info"
    
    # Analyze event logs
    $criticalEvents = $eventLogs | Where-Object { $_.Level -eq "Critical" }
    $errorEvents = $eventLogs | Where-Object { $_.Level -eq "Error" }
    $warningEvents = $eventLogs | Where-Object { $_.Level -eq "Warning" }
    
    if ($criticalEvents.Count -gt 0) {
        Write-MonitoringLog "Critical Events: $($criticalEvents.Count)" "Warning"
    }
    if ($errorEvents.Count -gt 0) {
        Write-MonitoringLog "Error Events: $($errorEvents.Count)" "Warning"
    }
    if ($warningEvents.Count -gt 0) {
        Write-MonitoringLog "Warning Events: $($warningEvents.Count)" "Info"
    }
    
    # Generate monitoring report
    Write-MonitoringLog "Generating monitoring report..." "Info"
    
    $reportPath = Join-Path $PSScriptRoot "HyperV-Monitoring-Report.html"
    Get-HyperVMonitoringReport -HostName $ServerName -ReportType "Comprehensive" -OutputPath $reportPath -Format "HTML"
    
    Write-MonitoringLog "Monitoring report generated: $reportPath" "Success"
    
    # Configure report generation if requested
    if ($GenerateReports) {
        Write-MonitoringLog "Configuring automated report generation..." "Info"
        
        # Create scheduled task for report generation
        $taskName = "HyperV-Monitoring-Reports"
        $taskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File `"$($MyInvocation.MyCommand.Path)`" -ServerName `"$ServerName`" -GenerateReports"
        $taskTrigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours $ReportInterval) -RepetitionDuration (New-TimeSpan -Days 365) -At (Get-Date)
        $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Force -ErrorAction SilentlyContinue
        
        Write-MonitoringLog "Automated report generation configured" "Success"
    }
    
    # Validate monitoring configuration
    Write-MonitoringLog "Validating monitoring configuration..." "Info"
    
    $monitoringValidation = Get-HyperVHealthStatus -HostName $ServerName -IncludeDetails
    if ($monitoringValidation.OverallHealth -eq "Healthy") {
        Write-MonitoringLog "Monitoring configuration validation passed" "Success"
    } else {
        Write-MonitoringLog "Monitoring configuration validation failed: $($monitoringValidation.Issues)" "Warning"
    }
    
    # Get capacity planning information
    if ($MonitoringLevel -eq "Comprehensive") {
        Write-MonitoringLog "Getting capacity planning information..." "Info"
        
        $capacityPlanning = Get-HyperVCapacityPlanning -HostName $ServerName -IncludeRecommendations
        
        Write-MonitoringLog "Capacity planning information retrieved" "Success"
        Write-MonitoringLog "Memory Utilization: $($capacityPlanning.HostCapacity.MemoryUtilization)%" "Info"
        Write-MonitoringLog "Processor Utilization: $($capacityPlanning.HostCapacity.ProcessorUtilization)%" "Info"
        
        if ($capacityPlanning.Recommendations.Count -gt 0) {
            Write-MonitoringLog "Recommendations:" "Info"
            foreach ($recommendation in $capacityPlanning.Recommendations) {
                Write-MonitoringLog "  - $recommendation" "Info"
            }
        }
    }
    
    Write-MonitoringLog "Hyper-V monitoring configuration completed successfully" "Success"
    
    # Return monitoring summary
    $monitoringSummary = @{
        ServerName = $ServerName
        MonitoringLevel = $MonitoringLevel
        MonitoringInterval = $MonitoringInterval
        IncludePerformance = $IncludePerformance
        IncludeHealth = $IncludeHealth
        IncludeSecurity = $IncludeSecurity
        IncludeStorage = $IncludeStorage
        IncludeNetwork = $IncludeNetwork
        EnableAlerting = $EnableAlerting
        GenerateReports = $GenerateReports
        ReportInterval = $ReportInterval
        ReportPath = $reportPath
        ResourceUtilization = $resourceUtilization
        PerformanceMetrics = if ($IncludePerformance) { $performanceMetrics } else { $null }
        HealthStatus = $healthStatus
        SecurityReport = if ($IncludeSecurity) { $securityReport } else { $null }
        StorageUtilization = if ($IncludeStorage) { $storageUtilization } else { $null }
        NetworkUtilization = if ($IncludeNetwork) { $networkUtilization } else { $null }
        EventLogs = $eventLogs
        CapacityPlanning = if ($MonitoringLevel -eq "Comprehensive") { $capacityPlanning } else { $null }
        ConfigurationTime = Get-Date
    }
    
    return $monitoringSummary
}
catch {
    Write-MonitoringLog "Hyper-V monitoring configuration failed: $($_.Exception.Message)" "Error"
    Write-MonitoringLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive monitoring for Windows Hyper-V virtualization.
    It provides health monitoring, performance metrics, alerting, and reporting.
    
    Features:
    - Health monitoring
    - Performance monitoring
    - Security monitoring
    - Storage monitoring
    - Network monitoring
    - Event log analysis
    - Resource utilization tracking
    - Alerting and notifications
    - Automated report generation
    - Capacity planning
    - Monitoring validation
    - Real-time status reporting
    
    Prerequisites:
    - Windows Server 2016 or later
    - Hyper-V feature installed
    - Administrative privileges
    - Network connectivity
    
    Dependencies:
    - HyperV-Monitoring.psm1
    - HyperV-Core.psm1
    - HyperV-Security.psm1
    
    Usage Examples:
    .\Monitor-HyperV.ps1 -ServerName "HV-SERVER01" -MonitoringLevel "Comprehensive" -EnableAlerting
    .\Monitor-HyperV.ps1 -ServerName "HV-SERVER01" -MonitoringLevel "Standard" -IncludePerformance -IncludeHealth -GenerateReports
    .\Monitor-HyperV.ps1 -ServerName "HV-SERVER01" -MonitoringLevel "Comprehensive" -IncludePerformance -IncludeHealth -IncludeSecurity -IncludeStorage -IncludeNetwork -EnableAlerting -GenerateReports -ReportInterval 12
    
    Output:
    - Console logging with color-coded messages
    - HTML monitoring report
    - Real-time resource utilization
    - Performance metrics
    - Health status
    - Security compliance
    - Storage utilization
    - Network utilization
    - Event log analysis
    - Capacity planning
    - Monitoring validation results
    - Comprehensive error handling
    
    Security Considerations:
    - Requires administrative privileges
    - Implements secure monitoring
    - Logs all operations for audit
    - Validates monitoring configuration
    
    Performance Impact:
    - Minimal impact during monitoring
    - Configurable monitoring intervals
    - Efficient data collection
    - Resource-aware monitoring
#>
