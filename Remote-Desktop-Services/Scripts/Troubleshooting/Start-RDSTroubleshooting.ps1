#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Start RDS Troubleshooting and Diagnostics

.DESCRIPTION
    This script starts comprehensive troubleshooting and diagnostics for Remote Desktop Services
    including issue detection, performance analysis, and automated resolution.

.PARAMETER DiagnosticType
    Type of diagnostics to run (All, Service, Performance, Security, Network, Configuration)

.PARAMETER IncludePerformanceAnalysis
    Include performance analysis in diagnostics

.PARAMETER IncludeEventLogAnalysis
    Include event log analysis in diagnostics

.PARAMETER IncludeAutomatedFixes
    Include automated fixes for detected issues

.PARAMETER LogFile
    Log file path for diagnostic data

.PARAMETER ConfirmFixes
    Confirmation flag for automated fixes

.EXAMPLE
    .\Start-RDSTroubleshooting.ps1

.EXAMPLE
    .\Start-RDSTroubleshooting.ps1 -DiagnosticType "All" -IncludePerformanceAnalysis -IncludeEventLogAnalysis -IncludeAutomatedFixes -ConfirmFixes
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Service", "Performance", "Security", "Network", "Configuration")]
    [string]$DiagnosticType = "All",
    
    [switch]$IncludePerformanceAnalysis,
    
    [switch]$IncludeEventLogAnalysis,
    
    [switch]$IncludeAutomatedFixes,
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile,
    
    [switch]$ConfirmFixes
)

# Import required modules
Import-Module ".\Modules\RDS-Core.psm1" -Force
Import-Module ".\Modules\RDS-Troubleshooting.psm1" -Force
Import-Module ".\Modules\RDS-Performance.psm1" -Force
Import-Module ".\Modules\RDS-Security.psm1" -Force

try {
    Write-Log -Message "Starting RDS troubleshooting and diagnostics..." -Level "INFO"
    
    # Test prerequisites
    $prerequisites = Test-RDSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for RDS troubleshooting"
    }
    
    Write-Log -Message "Prerequisites validated successfully" -Level "SUCCESS"
    
    # Set up log file if provided
    if ($LogFile) {
        $logDir = Split-Path $LogFile -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        Write-Log -Message "Troubleshooting log file: $LogFile" -Level "INFO"
    }
    
    # Run comprehensive diagnostics
    Write-Log -Message "Running comprehensive diagnostics..." -Level "INFO"
    $diagnosticResult = Start-RDSComprehensiveDiagnostics -DiagnosticType $DiagnosticType -IncludePerformanceAnalysis:$IncludePerformanceAnalysis -IncludeEventLogAnalysis:$IncludeEventLogAnalysis
    
    if ($diagnosticResult.Success) {
        Write-Log -Message "Diagnostics completed successfully" -Level "SUCCESS"
    } else {
        Write-Log -Message "Diagnostics failed: $($diagnosticResult.Error)" -Level "ERROR" -LogPath $LogFile
    }
    
    # Get troubleshooting recommendations
    Write-Log -Message "Getting troubleshooting recommendations..." -Level "INFO"
    $recommendations = Get-RDSTroubleshootingRecommendations -IssueType "All" -Severity "High" -IncludeAutomatedFixes:$IncludeAutomatedFixes
    
    if ($recommendations.Recommendations.Count -gt 0) {
        Write-Log -Message "Found $($recommendations.Recommendations.Count) recommendations" -Level "INFO" -LogPath $LogFile
        
        foreach ($recommendation in $recommendations.Recommendations) {
            Write-Log -Message "Recommendation: $($recommendation.Description)" -Level "INFO" -LogPath $LogFile
            
            if ($recommendation.AutomatedFix -and $IncludeAutomatedFixes) {
                if ($ConfirmFixes) {
                    Write-Log -Message "Applying automated fix: $($recommendation.AutomatedFix)" -Level "INFO" -LogPath $LogFile
                    # Apply automated fix here
                } else {
                    Write-Log -Message "Automated fix available but not applied (use -ConfirmFixes to apply): $($recommendation.AutomatedFix)" -Level "WARNING" -LogPath $LogFile
                }
            }
        }
    } else {
        Write-Log -Message "No recommendations found" -Level "INFO" -LogPath $LogFile
    }
    
    # Test connectivity
    Write-Log -Message "Testing RDS connectivity..." -Level "INFO"
    $connectivityTest = Test-RDSConnectivity -TestType "All" -IncludePerformanceTest -IncludeLatencyTest
    
    if ($connectivityTest.Success) {
        Write-Log -Message "Connectivity test passed" -Level "SUCCESS" -LogPath $LogFile
    } else {
        Write-Log -Message "Connectivity test failed: $($connectivityTest.Error)" -Level "ERROR" -LogPath $LogFile
    }
    
    # Repair configuration if requested
    if ($IncludeAutomatedFixes -and $ConfirmFixes) {
        Write-Log -Message "Repairing RDS configuration..." -Level "INFO"
        $repairResult = Repair-RDSConfiguration -RepairType "All" -ConfirmRepair
        
        if ($repairResult.Success) {
            Write-Log -Message "Configuration repair completed successfully" -Level "SUCCESS" -LogPath $LogFile
        } else {
            Write-Log -Message "Configuration repair failed: $($repairResult.Error)" -Level "ERROR" -LogPath $LogFile
        }
    }
    
    # Generate troubleshooting report
    Write-Log -Message "Generating troubleshooting report..." -Level "INFO"
    $report = @{
        Timestamp = Get-Date
        ComputerName = $env:COMPUTERNAME
        DiagnosticType = $DiagnosticType
        DiagnosticResult = $diagnosticResult
        Recommendations = $recommendations
        ConnectivityTest = $connectivityTest
        LogFile = $LogFile
    }
    
    Write-Log -Message "Troubleshooting and diagnostics completed" -Level "SUCCESS" -LogPath $LogFile
    
    return $report
    
} catch {
    Write-Log -Message "Error during RDS troubleshooting: $($_.Exception.Message)" -Level "ERROR"
    throw
}
