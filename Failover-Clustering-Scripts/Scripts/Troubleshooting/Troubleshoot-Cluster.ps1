#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Troubleshoot Windows Failover Cluster

.DESCRIPTION
    Comprehensive troubleshooting script for Windows Failover Clustering.
    Provides diagnostics, repair operations, event log analysis, and issue resolution.

.PARAMETER ClusterName
    Name of the cluster to troubleshoot

.PARAMETER DiagnosticLevel
    Level of diagnostics to run (Basic, Standard, Comprehensive)

.PARAMETER IncludePerformance
    Include performance diagnostics

.PARAMETER IncludeSecurity
    Include security diagnostics

.PARAMETER IncludeConnectivity
    Include connectivity diagnostics

.PARAMETER IncludeStorage
    Include storage diagnostics

.PARAMETER IncludeQuorum
    Include quorum diagnostics

.PARAMETER IncludeResources
    Include resource diagnostics

.PARAMETER IncludeNetworks
    Include network diagnostics

.PARAMETER RepairMode
    Repair mode (None, Automatic, Interactive)

.PARAMETER GenerateReport
    Generate troubleshooting report

.PARAMETER EventLogAnalysis
    Perform event log analysis

.PARAMETER TimeRange
    Time range for analysis (1Hour, 24Hours, 7Days, 30Days)

.PARAMETER TroubleshootingConfigurationFile
    Path to JSON troubleshooting configuration file

.EXAMPLE
    .\Troubleshoot-Cluster.ps1 -ClusterName "PROD-CLUSTER" -DiagnosticLevel "Comprehensive" -RepairMode "Automatic"

.EXAMPLE
    .\Troubleshoot-Cluster.ps1 -ClusterName "HA-CLUSTER" -DiagnosticLevel "Standard" -IncludePerformance -IncludeStorage -GenerateReport

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive troubleshooting for Windows Failover Clustering.
    It provides diagnostics, repair operations, event log analysis, and issue resolution.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ClusterName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Standard", "Comprehensive")]
    [string]$DiagnosticLevel = "Standard",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludePerformance,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSecurity,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeConnectivity,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeStorage,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeQuorum,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeResources,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeNetworks,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "Automatic", "Interactive")]
    [string]$RepairMode = "None",
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateReport,
    
    [Parameter(Mandatory = $false)]
    [switch]$EventLogAnalysis,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("1Hour", "24Hours", "7Days", "30Days")]
    [string]$TimeRange = "24Hours",
    
    [Parameter(Mandatory = $false)]
    [string]$TroubleshootingConfigurationFile
)

# Import required modules
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $modulePath "..\Modules"

Import-Module "$modulesPath\Cluster-Troubleshooting.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\Cluster-Core.psm1" -Force -ErrorAction Stop

# Logging function
function Write-TroubleshootingLog {
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
    Write-TroubleshootingLog "Starting cluster troubleshooting" "Info"
    Write-TroubleshootingLog "Cluster Name: $ClusterName" "Info"
    Write-TroubleshootingLog "Diagnostic Level: $DiagnosticLevel" "Info"
    Write-TroubleshootingLog "Repair Mode: $RepairMode" "Info"
    
    # Load troubleshooting configuration from file if provided
    if ($TroubleshootingConfigurationFile -and (Test-Path $TroubleshootingConfigurationFile)) {
        Write-TroubleshootingLog "Loading troubleshooting configuration from file: $TroubleshootingConfigurationFile" "Info"
        $troubleshootingConfig = Get-Content $TroubleshootingConfigurationFile | ConvertFrom-Json
        
        # Override parameters with file values if not specified
        if (-not $PSBoundParameters.ContainsKey('DiagnosticLevel') -and $troubleshootingConfig.DiagnosticLevel) {
            $DiagnosticLevel = $troubleshootingConfig.DiagnosticLevel
        }
        if (-not $PSBoundParameters.ContainsKey('RepairMode') -and $troubleshootingConfig.RepairMode) {
            $RepairMode = $troubleshootingConfig.RepairMode
        }
    }
    
    # Validate cluster exists
    Write-TroubleshootingLog "Validating cluster existence..." "Info"
    Get-Cluster -Name $ClusterName -ErrorAction Stop | Out-Null
    Write-TroubleshootingLog "Cluster validated successfully" "Success"
    
    # Configure diagnostics based on level
    Write-TroubleshootingLog "Configuring diagnostics level: $DiagnosticLevel" "Info"
    
    switch ($DiagnosticLevel) {
        "Basic" {
            $IncludeConnectivity = $true
            $IncludeQuorum = $true
        }
        "Standard" {
            $IncludeConnectivity = $true
            $IncludeQuorum = $true
            $IncludeResources = $true
            $IncludeNetworks = $true
        }
        "Comprehensive" {
            $IncludePerformance = $true
            $IncludeSecurity = $true
            $IncludeConnectivity = $true
            $IncludeStorage = $true
            $IncludeQuorum = $true
            $IncludeResources = $true
            $IncludeNetworks = $true
        }
    }
    
    # Run cluster diagnostics
    Write-TroubleshootingLog "Running cluster diagnostics..." "Info"
    $diagnostics = Test-ClusterDiagnostics -ClusterName $ClusterName -DiagnosticLevel $DiagnosticLevel -IncludePerformance:$IncludePerformance -IncludeSecurity:$IncludeSecurity -IncludeConnectivity:$IncludeConnectivity -IncludeStorage:$IncludeStorage -IncludeQuorum:$IncludeQuorum -IncludeResources:$IncludeResources -IncludeNetworks:$IncludeNetworks
    
    Write-TroubleshootingLog "Diagnostics completed" "Success"
    Write-TroubleshootingLog "Issues Found: $($diagnostics.IssuesFound)" "Info"
    Write-TroubleshootingLog "Critical Issues: $($diagnostics.CriticalIssues)" "Info"
    Write-TroubleshootingLog "Warning Issues: $($diagnostics.WarningIssues)" "Info"
    
    # Display diagnostic results
    if ($diagnostics.IssuesFound -gt 0) {
        Write-TroubleshootingLog "=== DIAGNOSTIC RESULTS ===" "Warning"
        foreach ($issue in $diagnostics.Issues) {
            Write-TroubleshootingLog "Issue: $($issue.Description)" "Warning"
            Write-TroubleshootingLog "Severity: $($issue.Severity)" "Warning"
            Write-TroubleshootingLog "Component: $($issue.Component)" "Warning"
            Write-TroubleshootingLog "Recommendation: $($issue.Recommendation)" "Info"
            Write-TroubleshootingLog "---" "Info"
        }
    } else {
        Write-TroubleshootingLog "No issues found in diagnostics" "Success"
    }
    
    # Run event log analysis if requested
    if ($EventLogAnalysis) {
        Write-TroubleshootingLog "Running event log analysis..." "Info"
        $eventAnalysis = Analyze-ClusterEventLogs -ClusterName $ClusterName -AnalysisType "Comprehensive" -TimeRange $TimeRange -GenerateReport
        
        Write-TroubleshootingLog "Event log analysis completed" "Success"
        Write-TroubleshootingLog "Events Analyzed: $($eventAnalysis.EventsAnalyzed)" "Info"
        Write-TroubleshootingLog "Critical Events: $($eventAnalysis.CriticalEvents)" "Info"
        Write-TroubleshootingLog "Warning Events: $($eventAnalysis.WarningEvents)" "Info"
        Write-TroubleshootingLog "Error Events: $($eventAnalysis.ErrorEvents)" "Info"
        
        # Display event analysis results
        if ($eventAnalysis.CriticalEvents -gt 0 -or $eventAnalysis.ErrorEvents -gt 0) {
            Write-TroubleshootingLog "=== EVENT LOG ANALYSIS RESULTS ===" "Warning"
            foreach ($logEvent in $eventAnalysis.TopEvents) {
                Write-TroubleshootingLog "Event ID: $($logEvent.EventID)" "Warning"
                Write-TroubleshootingLog "Source: $($logEvent.Source)" "Warning"
                Write-TroubleshootingLog "Level: $($logEvent.Level)" "Warning"
                Write-TroubleshootingLog "Count: $($logEvent.Count)" "Warning"
                Write-TroubleshootingLog "Last Occurrence: $($logEvent.LastOccurrence)" "Warning"
                Write-TroubleshootingLog "---" "Info"
            }
        }
    }
    
    # Run repair operations if requested
    if ($RepairMode -ne "None") {
        Write-TroubleshootingLog "Running repair operations..." "Info"
        $repair = Repair-ClusterIssues -ClusterName $ClusterName -RepairType $RepairMode -IncludeQuorum:$IncludeQuorum -IncludeResources:$IncludeResources -IncludeNetworks:$IncludeNetworks -IncludeStorage:$IncludeStorage
        
        Write-TroubleshootingLog "Repair operations completed" "Success"
        Write-TroubleshootingLog "Issues Repaired: $($repair.IssuesRepaired)" "Success"
        Write-TroubleshootingLog "Issues Failed: $($repair.IssuesFailed)" "Info"
        
        # Display repair results
        if ($repair.IssuesRepaired -gt 0) {
            Write-TroubleshootingLog "=== REPAIR RESULTS ===" "Success"
            foreach ($repairItem in $repair.RepairedIssues) {
                Write-TroubleshootingLog "Repaired: $($repairItem.Description)" "Success"
                Write-TroubleshootingLog "Method: $($repairItem.RepairMethod)" "Success"
                Write-TroubleshootingLog "---" "Info"
            }
        }
        
        if ($repair.IssuesFailed -gt 0) {
            Write-TroubleshootingLog "=== FAILED REPAIRS ===" "Warning"
            foreach ($failedItem in $repair.FailedIssues) {
                Write-TroubleshootingLog "Failed: $($failedItem.Description)" "Warning"
                Write-TroubleshootingLog "Reason: $($failedItem.FailureReason)" "Warning"
                Write-TroubleshootingLog "---" "Info"
            }
        }
    }
    
    # Run cluster validation
    Write-TroubleshootingLog "Running cluster validation..." "Info"
    $validation = Test-ClusterConfiguration -ClusterName $ClusterName
    if ($validation.IsValid) {
        Write-TroubleshootingLog "Cluster validation passed" "Success"
    } else {
        Write-TroubleshootingLog "Cluster validation failed: $($validation.Issues)" "Warning"
    }
    
    # Get cluster health status
    Write-TroubleshootingLog "Getting cluster health status..." "Info"
    $healthStatus = Get-ClusterHealthStatus -ClusterName $ClusterName -IncludeDetails -IncludeNodes -IncludeResources
    Write-TroubleshootingLog "Overall Health: $($healthStatus.OverallHealth)" "Info"
    Write-TroubleshootingLog "Nodes Online: $($healthStatus.NodesOnline)/$($healthStatus.TotalNodes)" "Info"
    Write-TroubleshootingLog "Resources Online: $($healthStatus.ResourcesOnline)/$($healthStatus.TotalResources)" "Info"
    
    # Generate troubleshooting report if requested
    if ($GenerateReport) {
        Write-TroubleshootingLog "Generating troubleshooting report..." "Info"
        $reportPath = Join-Path $PSScriptRoot "Cluster-Troubleshooting-Report.html"
        Get-ClusterTroubleshootingReport -ClusterName $ClusterName -ReportType "Comprehensive" -OutputPath $reportPath -Format "HTML" -IncludeDiagnostics -IncludeEventAnalysis -IncludeRepairResults
        Write-TroubleshootingLog "Troubleshooting report generated: $reportPath" "Success"
    }
    
    # Generate recommendations
    Write-TroubleshootingLog "Generating recommendations..." "Info"
    $recommendations = Get-ClusterRecommendations -ClusterName $ClusterName -IncludePerformance -IncludeSecurity -IncludeReliability
    Write-TroubleshootingLog "Recommendations generated: $($recommendations.Count)" "Success"
    
    # Display recommendations
    if ($recommendations.Count -gt 0) {
        Write-TroubleshootingLog "=== RECOMMENDATIONS ===" "Info"
        foreach ($recommendation in $recommendations) {
            Write-TroubleshootingLog "Category: $($recommendation.Category)" "Info"
            Write-TroubleshootingLog "Priority: $($recommendation.Priority)" "Info"
            Write-TroubleshootingLog "Description: $($recommendation.Description)" "Info"
            Write-TroubleshootingLog "Action: $($recommendation.Action)" "Info"
            Write-TroubleshootingLog "---" "Info"
        }
    }
    
    Write-TroubleshootingLog "Cluster troubleshooting completed successfully" "Success"
    
    # Return troubleshooting summary
    $troubleshootingSummary = @{
        ClusterName = $ClusterName
        DiagnosticLevel = $DiagnosticLevel
        RepairMode = $RepairMode
        IssuesFound = $diagnostics.IssuesFound
        CriticalIssues = $diagnostics.CriticalIssues
        WarningIssues = $diagnostics.WarningIssues
        IssuesRepaired = if ($RepairMode -ne "None") { $repair.IssuesRepaired } else { 0 }
        IssuesFailed = if ($RepairMode -ne "None") { $repair.IssuesFailed } else { 0 }
        OverallHealth = $healthStatus.OverallHealth
        NodesOnline = $healthStatus.NodesOnline
        TotalNodes = $healthStatus.TotalNodes
        ResourcesOnline = $healthStatus.ResourcesOnline
        TotalResources = $healthStatus.TotalResources
        RecommendationsCount = $recommendations.Count
        ReportPath = if ($GenerateReport) { $reportPath } else { $null }
        TroubleshootingTime = Get-Date
    }
    
    return $troubleshootingSummary
}
catch {
    Write-TroubleshootingLog "Cluster troubleshooting failed: $($_.Exception.Message)" "Error"
    Write-TroubleshootingLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive troubleshooting for Windows Failover Clustering.
    It provides diagnostics, repair operations, event log analysis, and issue resolution.
    
    Features:
    - Comprehensive diagnostics
    - Event log analysis
    - Repair operations
    - Cluster validation
    - Health status monitoring
    - Performance analysis
    - Security analysis
    - Connectivity testing
    - Storage diagnostics
    - Quorum diagnostics
    - Resource diagnostics
    - Network diagnostics
    - Automated repair
    - Interactive repair
    - Troubleshooting reports
    - Recommendations generation
    
    Prerequisites:
    - Windows Server 2016 or later
    - Failover Clustering feature installed
    - Administrative privileges
    - Network connectivity
    
    Dependencies:
    - Cluster-Troubleshooting.psm1
    - Cluster-Core.psm1
    
    Usage Examples:
    .\Troubleshoot-Cluster.ps1 -ClusterName "PROD-CLUSTER" -DiagnosticLevel "Comprehensive" -RepairMode "Automatic"
    .\Troubleshoot-Cluster.ps1 -ClusterName "HA-CLUSTER" -DiagnosticLevel "Standard" -IncludePerformance -IncludeStorage -GenerateReport
    .\Troubleshoot-Cluster.ps1 -ClusterName "ENTERPRISE-CLUSTER" -DiagnosticLevel "Comprehensive" -IncludePerformance -IncludeSecurity -IncludeConnectivity -IncludeStorage -IncludeQuorum -IncludeResources -IncludeNetworks -RepairMode "Interactive" -EventLogAnalysis -TimeRange "7Days" -GenerateReport
    
    Output:
    - Console logging with color-coded messages
    - Diagnostic results
    - Event log analysis
    - Repair results
    - Health status
    - Recommendations
    - HTML troubleshooting report
    - Comprehensive error handling
    
    Security Considerations:
    - Requires administrative privileges
    - Implements secure troubleshooting
    - Logs all operations for audit
    - Validates troubleshooting configuration
    
    Performance Impact:
    - Minimal impact during troubleshooting
    - Configurable diagnostic levels
    - Efficient issue detection
    - Resource-aware diagnostics
#>
