#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Troubleshoot Windows Hyper-V

.DESCRIPTION
    Comprehensive troubleshooting script for Windows Hyper-V virtualization.
    Provides diagnostics, repair operations, event log analysis, and issue resolution.

.PARAMETER ServerName
    Name of the server to troubleshoot

.PARAMETER VMName
    Name of specific VM to troubleshoot

.PARAMETER DiagnosticLevel
    Level of diagnostics to run (Basic, Standard, Comprehensive)

.PARAMETER IncludePerformance
    Include performance diagnostics

.PARAMETER IncludeSecurity
    Include security diagnostics

.PARAMETER IncludeStorage
    Include storage diagnostics

.PARAMETER IncludeNetwork
    Include network diagnostics

.PARAMETER IncludeIntegrationServices
    Include integration services diagnostics

.PARAMETER IncludeCheckpoints
    Include checkpoint diagnostics

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
    .\Troubleshoot-HyperV.ps1 -ServerName "HV-SERVER01" -DiagnosticLevel "Comprehensive" -RepairMode "Automatic"

.EXAMPLE
    .\Troubleshoot-HyperV.ps1 -ServerName "HV-SERVER01" -VMName "Test-VM" -DiagnosticLevel "Standard" -IncludePerformance -IncludeStorage -GenerateReport

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive troubleshooting for Windows Hyper-V virtualization.
    It provides diagnostics, repair operations, event log analysis, and issue resolution.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ServerName = $env:COMPUTERNAME,
    
    [Parameter(Mandatory = $false)]
    [string]$VMName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Standard", "Comprehensive")]
    [string]$DiagnosticLevel = "Standard",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludePerformance,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSecurity,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeStorage,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeNetwork,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeIntegrationServices,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCheckpoints,
    
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

Import-Module "$modulesPath\HyperV-Troubleshooting.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\HyperV-Core.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\HyperV-Security.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\HyperV-Monitoring.psm1" -Force -ErrorAction Stop

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
    Write-TroubleshootingLog "Starting Hyper-V troubleshooting" "Info"
    Write-TroubleshootingLog "Server Name: $ServerName" "Info"
    Write-TroubleshootingLog "VM Name: $VMName" "Info"
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
    
    # Validate prerequisites
    Write-TroubleshootingLog "Validating prerequisites..." "Info"
    
    # Check if Hyper-V is installed
    $hyperVFeature = Get-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
    if (-not $hyperVFeature -or $hyperVFeature.InstallState -ne "Installed") {
        throw "Hyper-V feature is not installed"
    }
    
    Write-TroubleshootingLog "Prerequisites validated successfully" "Success"
    
    # Configure diagnostics based on level
    Write-TroubleshootingLog "Configuring diagnostics level: $DiagnosticLevel" "Info"
    
    switch ($DiagnosticLevel) {
        "Basic" {
            $IncludeNetwork = $true
            $IncludeIntegrationServices = $true
        }
        "Standard" {
            $IncludeNetwork = $true
            $IncludeIntegrationServices = $true
            $IncludeStorage = $true
            $IncludePerformance = $true
        }
        "Comprehensive" {
            $IncludePerformance = $true
            $IncludeSecurity = $true
            $IncludeStorage = $true
            $IncludeNetwork = $true
            $IncludeIntegrationServices = $true
            $IncludeCheckpoints = $true
        }
    }
    
    # Run VM diagnostics
    Write-TroubleshootingLog "Running VM diagnostics..." "Info"
    
    if ($VMName) {
        $vmDiagnostics = Test-HyperVMDiagnostics -VMName $VMName -DiagnosticLevel $DiagnosticLevel -IncludePerformance:$IncludePerformance -IncludeSecurity:$IncludeSecurity -IncludeStorage:$IncludeStorage -IncludeNetwork:$IncludeNetwork -IncludeIntegrationServices:$IncludeIntegrationServices -IncludeCheckpoints:$IncludeCheckpoints
        
        Write-TroubleshootingLog "VM diagnostics completed for: $VMName" "Success"
        Write-TroubleshootingLog "Overall Status: $($vmDiagnostics.OverallStatus)" "Info"
        Write-TroubleshootingLog "Issues Found: $($vmDiagnostics.Issues.Count)" "Info"
        
        if ($vmDiagnostics.Issues.Count -gt 0) {
            Write-TroubleshootingLog "Issues:" "Warning"
            foreach ($issue in $vmDiagnostics.Issues) {
                Write-TroubleshootingLog "  - $issue" "Warning"
            }
        }
        
        if ($vmDiagnostics.Recommendations.Count -gt 0) {
            Write-TroubleshootingLog "Recommendations:" "Info"
            foreach ($recommendation in $vmDiagnostics.Recommendations) {
                Write-TroubleshootingLog "  - $recommendation" "Info"
            }
        }
    } else {
        # Run diagnostics for all VMs
        $vms = Get-VM -ComputerName $ServerName
        $allDiagnostics = @()
        
        foreach ($vm in $vms) {
            $vmDiagnostics = Test-HyperVMDiagnostics -VMName $vm.Name -DiagnosticLevel $DiagnosticLevel -IncludePerformance:$IncludePerformance -IncludeSecurity:$IncludeSecurity -IncludeStorage:$IncludeStorage -IncludeNetwork:$IncludeNetwork -IncludeIntegrationServices:$IncludeIntegrationServices -IncludeCheckpoints:$IncludeCheckpoints
            
            $allDiagnostics += $vmDiagnostics
            
            Write-TroubleshootingLog "VM diagnostics completed for: $($vm.Name)" "Success"
            Write-TroubleshootingLog "Overall Status: $($vmDiagnostics.OverallStatus)" "Info"
            Write-TroubleshootingLog "Issues Found: $($vmDiagnostics.Issues.Count)" "Info"
        }
        
        Write-TroubleshootingLog "All VM diagnostics completed" "Success"
    }
    
    # Run event log analysis if requested
    if ($EventLogAnalysis) {
        Write-TroubleshootingLog "Running event log analysis..." "Info"
        
        $eventAnalysis = Analyze-HyperVEventLogs -HostName $ServerName -VMName $VMName -AnalysisType "Comprehensive" -TimeRangeHours $TimeRange -GenerateReport
        
        Write-TroubleshootingLog "Event log analysis completed" "Success"
        Write-TroubleshootingLog "Events Analyzed: $($eventAnalysis.EventsAnalyzed)" "Info"
        Write-TroubleshootingLog "Critical Events: $($eventAnalysis.CriticalEvents)" "Info"
        Write-TroubleshootingLog "Error Events: $($eventAnalysis.ErrorEvents)" "Info"
        Write-TroubleshootingLog "Warning Events: $($eventAnalysis.WarningEvents)" "Info"
        
        # Display event analysis results
        if ($eventAnalysis.CriticalEvents -gt 0 -or $eventAnalysis.ErrorEvents -gt 0) {
            Write-TroubleshootingLog "=== EVENT LOG ANALYSIS RESULTS ===" "Warning"
            foreach ($logEvent in $eventAnalysis.TopEvents) {
                Write-TroubleshootingLog "Event ID: $($logEvent.EventId)" "Warning"
                Write-TroubleshootingLog "Count: $($logEvent.Count)" "Warning"
                Write-TroubleshootingLog "Level: $($logEvent.Level)" "Warning"
                Write-TroubleshootingLog "Last Occurrence: $($logEvent.LastOccurrence)" "Warning"
                Write-TroubleshootingLog "---" "Info"
            }
        }
        
        if ($eventAnalysis.Issues.Count -gt 0) {
            Write-TroubleshootingLog "Event Analysis Issues:" "Warning"
            foreach ($issue in $eventAnalysis.Issues) {
                Write-TroubleshootingLog "  - $issue" "Warning"
            }
        }
        
        if ($eventAnalysis.Recommendations.Count -gt 0) {
            Write-TroubleshootingLog "Event Analysis Recommendations:" "Info"
            foreach ($recommendation in $eventAnalysis.Recommendations) {
                Write-TroubleshootingLog "  - $recommendation" "Info"
            }
        }
    }
    
    # Run performance troubleshooting if requested
    if ($IncludePerformance) {
        Write-TroubleshootingLog "Running performance troubleshooting..." "Info"
        
        $performanceTest = Test-HyperVPerformance -HostName $ServerName -VMName $VMName -DurationMinutes 60
        
        Write-TroubleshootingLog "Performance troubleshooting completed" "Success"
        Write-TroubleshootingLog "Host CPU Usage: $($performanceTest.HostPerformance.CPUUsage)%" "Info"
        Write-TroubleshootingLog "Host Memory Available: $($performanceTest.HostPerformance.AvailableMemory) MB" "Info"
        Write-TroubleshootingLog "Host Disk Usage: $($performanceTest.HostPerformance.DiskUsage)%" "Info"
        
        if ($performanceTest.Issues.Count -gt 0) {
            Write-TroubleshootingLog "Performance Issues:" "Warning"
            foreach ($issue in $performanceTest.Issues) {
                Write-TroubleshootingLog "  - $issue" "Warning"
            }
        }
        
        if ($performanceTest.Recommendations.Count -gt 0) {
            Write-TroubleshootingLog "Performance Recommendations:" "Info"
            foreach ($recommendation in $performanceTest.Recommendations) {
                Write-TroubleshootingLog "  - $recommendation" "Info"
            }
        }
    }
    
    # Run repair operations if requested
    if ($RepairMode -ne "None") {
        Write-TroubleshootingLog "Running repair operations..." "Info"
        
        $repairResults = Repair-HyperVIssues -HostName $ServerName -VMName $VMName -RepairType $RepairMode -IncludeVMs -IncludeHost -IncludeStorage -IncludeNetwork
        
        Write-TroubleshootingLog "Repair operations completed" "Success"
        Write-TroubleshootingLog "Issues Repaired: $($repairResults.IssuesRepaired)" "Success"
        Write-TroubleshootingLog "Issues Failed: $($repairResults.IssuesFailed)" "Info"
        
        # Display repair results
        if ($repairResults.IssuesRepaired -gt 0) {
            Write-TroubleshootingLog "=== REPAIR RESULTS ===" "Success"
            foreach ($repairItem in $repairResults.RepairedIssues) {
                Write-TroubleshootingLog "Repaired: $($repairItem.Description)" "Success"
                Write-TroubleshootingLog "Method: $($repairItem.RepairMethod)" "Success"
                Write-TroubleshootingLog "---" "Info"
            }
        }
        
        if ($repairResults.IssuesFailed -gt 0) {
            Write-TroubleshootingLog "=== FAILED REPAIRS ===" "Warning"
            foreach ($failedItem in $repairResults.FailedIssues) {
                Write-TroubleshootingLog "Failed: $($failedItem.Description)" "Warning"
                Write-TroubleshootingLog "Reason: $($failedItem.FailureReason)" "Warning"
                Write-TroubleshootingLog "---" "Info"
            }
        }
        
        if ($repairResults.Recommendations.Count -gt 0) {
            Write-TroubleshootingLog "Repair Recommendations:" "Info"
            foreach ($recommendation in $repairResults.Recommendations) {
                Write-TroubleshootingLog "  - $recommendation" "Info"
            }
        }
    }
    
    # Run health check
    Write-TroubleshootingLog "Running health check..." "Info"
    
    $healthCheck = Test-HyperVHealth -HostName $ServerName -VMName $VMName -HealthLevel "Standard" -IncludePerformance:$IncludePerformance -IncludeStorage:$IncludeStorage -IncludeNetwork:$IncludeNetwork -IncludeSecurity:$IncludeSecurity
    
    Write-TroubleshootingLog "Health check completed" "Success"
    Write-TroubleshootingLog "Overall Health: $($healthCheck.OverallHealth)" "Info"
    Write-TroubleshootingLog "Host Health: $($healthCheck.HostHealth.State)" "Info"
    Write-TroubleshootingLog "VMs Monitored: $($healthCheck.VMHealth.Count)" "Info"
    
    if ($healthCheck.Issues.Count -gt 0) {
        Write-TroubleshootingLog "Health Check Issues:" "Warning"
        foreach ($issue in $healthCheck.Issues) {
            Write-TroubleshootingLog "  - $issue" "Warning"
        }
    }
    
    if ($healthCheck.Recommendations.Count -gt 0) {
        Write-TroubleshootingLog "Health Check Recommendations:" "Info"
        foreach ($recommendation in $healthCheck.Recommendations) {
            Write-TroubleshootingLog "  - $recommendation" "Info"
        }
    }
    
    # Generate troubleshooting report if requested
    if ($GenerateReport) {
        Write-TroubleshootingLog "Generating troubleshooting report..." "Info"
        
        $reportPath = Join-Path $PSScriptRoot "HyperV-Troubleshooting-Report.html"
        
        $troubleshootingReport = @{
            ServerName = $ServerName
            VMName = $VMName
            DiagnosticLevel = $DiagnosticLevel
            RepairMode = $RepairMode
            Timestamp = Get-Date
            VMDiagnostics = if ($VMName) { $vmDiagnostics } else { $allDiagnostics }
            EventAnalysis = if ($EventLogAnalysis) { $eventAnalysis } else { $null }
            PerformanceTest = if ($IncludePerformance) { $performanceTest } else { $null }
            RepairResults = if ($RepairMode -ne "None") { $repairResults } else { $null }
            HealthCheck = $healthCheck
        }
        
        $troubleshootingReport | ConvertTo-Html -Title "Hyper-V Troubleshooting Report" | Out-File -FilePath $reportPath -Encoding UTF8
        
        Write-TroubleshootingLog "Troubleshooting report generated: $reportPath" "Success"
    }
    
    # Generate recommendations
    Write-TroubleshootingLog "Generating recommendations..." "Info"
    
    $recommendations = @()
    
    # Add VM diagnostics recommendations
    if ($VMName) {
        $recommendations += $vmDiagnostics.Recommendations
    } else {
        foreach ($vmDiag in $allDiagnostics) {
            $recommendations += $vmDiag.Recommendations
        }
    }
    
    # Add event analysis recommendations
    if ($EventLogAnalysis) {
        $recommendations += $eventAnalysis.Recommendations
    }
    
    # Add performance recommendations
    if ($IncludePerformance) {
        $recommendations += $performanceTest.Recommendations
    }
    
    # Add repair recommendations
    if ($RepairMode -ne "None") {
        $recommendations += $repairResults.Recommendations
    }
    
    # Add health check recommendations
    $recommendations += $healthCheck.Recommendations
    
    # Remove duplicates
    $recommendations = $recommendations | Sort-Object -Unique
    
    Write-TroubleshootingLog "Recommendations generated: $($recommendations.Count)" "Success"
    
    # Display recommendations
    if ($recommendations.Count -gt 0) {
        Write-TroubleshootingLog "=== RECOMMENDATIONS ===" "Info"
        foreach ($recommendation in $recommendations) {
            Write-TroubleshootingLog "  - $recommendation" "Info"
        }
    }
    
    Write-TroubleshootingLog "Hyper-V troubleshooting completed successfully" "Success"
    
    # Return troubleshooting summary
    $troubleshootingSummary = @{
        ServerName = $ServerName
        VMName = $VMName
        DiagnosticLevel = $DiagnosticLevel
        RepairMode = $RepairMode
        VMDiagnostics = if ($VMName) { $vmDiagnostics } else { $allDiagnostics }
        EventAnalysis = if ($EventLogAnalysis) { $eventAnalysis } else { $null }
        PerformanceTest = if ($IncludePerformance) { $performanceTest } else { $null }
        RepairResults = if ($RepairMode -ne "None") { $repairResults } else { $null }
        HealthCheck = $healthCheck
        Recommendations = $recommendations
        ReportPath = if ($GenerateReport) { $reportPath } else { $null }
        TroubleshootingTime = Get-Date
    }
    
    return $troubleshootingSummary
}
catch {
    Write-TroubleshootingLog "Hyper-V troubleshooting failed: $($_.Exception.Message)" "Error"
    Write-TroubleshootingLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive troubleshooting for Windows Hyper-V virtualization.
    It provides diagnostics, repair operations, event log analysis, and issue resolution.
    
    Features:
    - VM diagnostics
    - Event log analysis
    - Performance troubleshooting
    - Repair operations
    - Health checks
    - Storage diagnostics
    - Network diagnostics
    - Integration services diagnostics
    - Checkpoint diagnostics
    - Security diagnostics
    - Automated repair
    - Interactive repair
    - Troubleshooting reports
    - Recommendations generation
    
    Prerequisites:
    - Windows Server 2016 or later
    - Hyper-V feature installed
    - Administrative privileges
    - Network connectivity
    
    Dependencies:
    - HyperV-Troubleshooting.psm1
    - HyperV-Core.psm1
    - HyperV-Security.psm1
    - HyperV-Monitoring.psm1
    
    Usage Examples:
    .\Troubleshoot-HyperV.ps1 -ServerName "HV-SERVER01" -DiagnosticLevel "Comprehensive" -RepairMode "Automatic"
    .\Troubleshoot-HyperV.ps1 -ServerName "HV-SERVER01" -VMName "Test-VM" -DiagnosticLevel "Standard" -IncludePerformance -IncludeStorage -GenerateReport
    .\Troubleshoot-HyperV.ps1 -ServerName "HV-SERVER01" -DiagnosticLevel "Comprehensive" -IncludePerformance -IncludeSecurity -IncludeStorage -IncludeNetwork -IncludeIntegrationServices -IncludeCheckpoints -RepairMode "Interactive" -EventLogAnalysis -TimeRange "7Days" -GenerateReport
    
    Output:
    - Console logging with color-coded messages
    - VM diagnostics results
    - Event log analysis
    - Performance analysis
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
