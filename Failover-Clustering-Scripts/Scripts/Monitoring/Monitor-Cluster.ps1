#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Monitor Windows Failover Cluster

.DESCRIPTION
    Comprehensive monitoring script for Windows Failover Clustering.
    Provides health monitoring, performance metrics, alerting, and reporting.

.PARAMETER ClusterName
    Name of the cluster to monitor

.PARAMETER MonitoringLevel
    Level of monitoring to enable (Basic, Standard, Comprehensive)

.PARAMETER IncludePerformance
    Include performance monitoring

.PARAMETER IncludeHealth
    Include health monitoring

.PARAMETER IncludeSecurity
    Include security monitoring

.PARAMETER IncludeConnectivity
    Include connectivity monitoring

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
    .\Monitor-Cluster.ps1 -ClusterName "PROD-CLUSTER" -MonitoringLevel "Comprehensive" -EnableAlerting

.EXAMPLE
    .\Monitor-Cluster.ps1 -ClusterName "HA-CLUSTER" -MonitoringLevel "Standard" -IncludePerformance -IncludeHealth -GenerateReports

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive monitoring for Windows Failover Clustering.
    It provides health monitoring, performance metrics, alerting, and reporting.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ClusterName,
    
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
    [switch]$IncludeConnectivity,
    
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

Import-Module "$modulesPath\Cluster-Monitoring.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\Cluster-Core.psm1" -Force -ErrorAction Stop

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
    Write-MonitoringLog "Starting cluster monitoring" "Info"
    Write-MonitoringLog "Cluster Name: $ClusterName" "Info"
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
    
    # Validate cluster exists
    Write-MonitoringLog "Validating cluster existence..." "Info"
    Get-Cluster -Name $ClusterName -ErrorAction Stop | Out-Null
    Write-MonitoringLog "Cluster validated successfully" "Success"
    
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
            $IncludeConnectivity = $true
        }
    }
    
    # Enable health monitoring
    if ($IncludeHealth) {
        Write-MonitoringLog "Enabling health monitoring..." "Info"
        Enable-ClusterHealthMonitoring -ClusterName $ClusterName -MonitoringInterval $MonitoringInterval
        Write-MonitoringLog "Health monitoring enabled" "Success"
    }
    
    # Enable performance monitoring
    if ($IncludePerformance) {
        Write-MonitoringLog "Enabling performance monitoring..." "Info"
        Enable-ClusterPerformanceMonitoring -ClusterName $ClusterName -MonitoringInterval $MonitoringInterval
        Write-MonitoringLog "Performance monitoring enabled" "Success"
    }
    
    # Enable security monitoring
    if ($IncludeSecurity) {
        Write-MonitoringLog "Enabling security monitoring..." "Info"
        Enable-ClusterSecurityMonitoring -ClusterName $ClusterName -MonitoringInterval $MonitoringInterval
        Write-MonitoringLog "Security monitoring enabled" "Success"
    }
    
    # Enable connectivity monitoring
    if ($IncludeConnectivity) {
        Write-MonitoringLog "Enabling connectivity monitoring..." "Info"
        Enable-ClusterConnectivityMonitoring -ClusterName $ClusterName -MonitoringInterval $MonitoringInterval
        Write-MonitoringLog "Connectivity monitoring enabled" "Success"
    }
    
    # Configure alerting
    if ($EnableAlerting) {
        Write-MonitoringLog "Configuring alerting..." "Info"
        Enable-ClusterAlerting -ClusterName $ClusterName -AlertThresholds $AlertThresholds
        Write-MonitoringLog "Alerting configured" "Success"
    }
    
    # Configure event log monitoring
    Write-MonitoringLog "Configuring event log monitoring..." "Info"
    Enable-ClusterEventLogMonitoring -ClusterName $ClusterName -LogLevel "Warning,Error" -MonitoringInterval $MonitoringInterval
    Write-MonitoringLog "Event log monitoring configured" "Success"
    
    # Configure resource monitoring
    Write-MonitoringLog "Configuring resource monitoring..." "Info"
    Enable-ClusterResourceMonitoring -ClusterName $ClusterName -MonitoringInterval $MonitoringInterval
    Write-MonitoringLog "Resource monitoring configured" "Success"
    
    # Configure network monitoring
    Write-MonitoringLog "Configuring network monitoring..." "Info"
    Enable-ClusterNetworkMonitoring -ClusterName $ClusterName -MonitoringInterval $MonitoringInterval
    Write-MonitoringLog "Network monitoring configured" "Success"
    
    # Configure storage monitoring
    Write-MonitoringLog "Configuring storage monitoring..." "Info"
    Enable-ClusterStorageMonitoring -ClusterName $ClusterName -MonitoringInterval $MonitoringInterval
    Write-MonitoringLog "Storage monitoring configured" "Success"
    
    # Configure quorum monitoring
    Write-MonitoringLog "Configuring quorum monitoring..." "Info"
    Enable-ClusterQuorumMonitoring -ClusterName $ClusterName -MonitoringInterval $MonitoringInterval
    Write-MonitoringLog "Quorum monitoring configured" "Success"
    
    # Configure backup monitoring
    Write-MonitoringLog "Configuring backup monitoring..." "Info"
    Enable-ClusterBackupMonitoring -ClusterName $ClusterName -MonitoringInterval $MonitoringInterval
    Write-MonitoringLog "Backup monitoring configured" "Success"
    
    # Configure disaster recovery monitoring
    Write-MonitoringLog "Configuring disaster recovery monitoring..." "Info"
    Enable-ClusterDisasterRecoveryMonitoring -ClusterName $ClusterName -MonitoringInterval $MonitoringInterval
    Write-MonitoringLog "Disaster recovery monitoring configured" "Success"
    
    # Configure compliance monitoring
    Write-MonitoringLog "Configuring compliance monitoring..." "Info"
    Enable-ClusterComplianceMonitoring -ClusterName $ClusterName -MonitoringInterval $MonitoringInterval
    Write-MonitoringLog "Compliance monitoring configured" "Success"
    
    # Configure SIEM integration
    Write-MonitoringLog "Configuring SIEM integration..." "Info"
    Enable-ClusterSIEMIntegration -ClusterName $ClusterName -SIEMType "Splunk" -MonitoringInterval $MonitoringInterval
    Write-MonitoringLog "SIEM integration configured" "Success"
    
    # Generate initial monitoring report
    Write-MonitoringLog "Generating initial monitoring report..." "Info"
    $reportPath = Join-Path $PSScriptRoot "Cluster-Monitoring-Report.html"
    Get-ClusterMonitoringReport -ClusterName $ClusterName -ReportType "Comprehensive" -OutputPath $reportPath -Format "HTML"
    Write-MonitoringLog "Initial monitoring report generated: $reportPath" "Success"
    
    # Configure report generation if requested
    if ($GenerateReports) {
        Write-MonitoringLog "Configuring automated report generation..." "Info"
        Enable-ClusterReportGeneration -ClusterName $ClusterName -ReportInterval $ReportInterval -ReportTypes @("Health", "Performance", "Security", "Compliance")
        Write-MonitoringLog "Automated report generation configured" "Success"
    }
    
    # Validate monitoring configuration
    Write-MonitoringLog "Validating monitoring configuration..." "Info"
    $monitoringValidation = Test-ClusterMonitoringConfiguration -ClusterName $ClusterName
    if ($monitoringValidation.IsValid) {
        Write-MonitoringLog "Monitoring configuration validation passed" "Success"
    } else {
        Write-MonitoringLog "Monitoring configuration validation failed: $($monitoringValidation.Issues)" "Warning"
    }
    
    # Get current cluster status
    Write-MonitoringLog "Getting current cluster status..." "Info"
    $clusterStatus = Get-ClusterHealthStatus -ClusterName $ClusterName -IncludeDetails -IncludeNodes -IncludeResources
    Write-MonitoringLog "Cluster Status: $($clusterStatus.OverallHealth)" "Info"
    Write-MonitoringLog "Nodes Online: $($clusterStatus.NodesOnline)/$($clusterStatus.TotalNodes)" "Info"
    Write-MonitoringLog "Resources Online: $($clusterStatus.ResourcesOnline)/$($clusterStatus.TotalResources)" "Info"
    
    # Get performance metrics
    if ($IncludePerformance) {
        Write-MonitoringLog "Getting current performance metrics..." "Info"
        $performanceMetrics = Get-ClusterPerformanceMetrics -ClusterName $ClusterName -MetricType "CPU,Memory,Network,Disk" -Duration "5Minutes"
        Write-MonitoringLog "Average CPU Usage: $($performanceMetrics.CPUUsage)%" "Info"
        Write-MonitoringLog "Average Memory Usage: $($performanceMetrics.MemoryUsage)%" "Info"
        Write-MonitoringLog "Average Network Usage: $($performanceMetrics.NetworkUsage)%" "Info"
        Write-MonitoringLog "Average Disk Usage: $($performanceMetrics.DiskUsage)%" "Info"
    }
    
    Write-MonitoringLog "Cluster monitoring configuration completed successfully" "Success"
    
    # Return monitoring summary
    $monitoringSummary = @{
        ClusterName = $ClusterName
        MonitoringLevel = $MonitoringLevel
        MonitoringInterval = $MonitoringInterval
        IncludePerformance = $IncludePerformance
        IncludeHealth = $IncludeHealth
        IncludeSecurity = $IncludeSecurity
        IncludeConnectivity = $IncludeConnectivity
        EnableAlerting = $EnableAlerting
        GenerateReports = $GenerateReports
        ReportInterval = $ReportInterval
        ReportPath = $reportPath
        ClusterStatus = $clusterStatus
        ConfigurationTime = Get-Date
    }
    
    return $monitoringSummary
}
catch {
    Write-MonitoringLog "Cluster monitoring configuration failed: $($_.Exception.Message)" "Error"
    Write-MonitoringLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive monitoring for Windows Failover Clustering.
    It provides health monitoring, performance metrics, alerting, and reporting.
    
    Features:
    - Health monitoring
    - Performance monitoring
    - Security monitoring
    - Connectivity monitoring
    - Event log monitoring
    - Resource monitoring
    - Network monitoring
    - Storage monitoring
    - Quorum monitoring
    - Backup monitoring
    - Disaster recovery monitoring
    - Compliance monitoring
    - SIEM integration
    - Alerting and notifications
    - Automated report generation
    - Monitoring validation
    - Real-time status reporting
    
    Prerequisites:
    - Windows Server 2016 or later
    - Failover Clustering feature installed
    - Administrative privileges
    - Network connectivity
    
    Dependencies:
    - Cluster-Monitoring.psm1
    - Cluster-Core.psm1
    
    Usage Examples:
    .\Monitor-Cluster.ps1 -ClusterName "PROD-CLUSTER" -MonitoringLevel "Comprehensive" -EnableAlerting
    .\Monitor-Cluster.ps1 -ClusterName "HA-CLUSTER" -MonitoringLevel "Standard" -IncludePerformance -IncludeHealth -GenerateReports
    .\Monitor-Cluster.ps1 -ClusterName "ENTERPRISE-CLUSTER" -MonitoringLevel "Comprehensive" -IncludePerformance -IncludeHealth -IncludeSecurity -IncludeConnectivity -EnableAlerting -GenerateReports -ReportInterval 12
    
    Output:
    - Console logging with color-coded messages
    - HTML monitoring report
    - Real-time cluster status
    - Performance metrics
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
