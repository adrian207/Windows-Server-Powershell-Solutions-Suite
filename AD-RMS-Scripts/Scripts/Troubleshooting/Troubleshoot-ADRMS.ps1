#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD RMS Troubleshooting and Diagnostic Script

.DESCRIPTION
    This script provides comprehensive troubleshooting and diagnostic capabilities
    for AD RMS including health checks, log analysis, and automated repair.

.PARAMETER Action
    The action to perform (Diagnose, Repair, Monitor, Analyze, Report)

.PARAMETER OutputPath
    Path to save diagnostic reports

.PARAMETER IncludeLogs
    Include recent log entries in analysis

.PARAMETER LogDays
    Number of days of logs to analyze (default: 7)

.PARAMETER RepairType
    Type of repair to perform (All, Services, Configuration, IIS)

.PARAMETER MonitorDuration
    Duration to monitor in seconds (default: 300)

.PARAMETER MonitorInterval
    Monitoring interval in seconds (default: 10)

.PARAMETER GenerateReport
    Generate detailed HTML report

.EXAMPLE
    .\Troubleshoot-ADRMS.ps1 -Action Diagnose

.EXAMPLE
    .\Troubleshoot-ADRMS.ps1 -Action Repair -RepairType "Services"

.EXAMPLE
    .\Troubleshoot-ADRMS.ps1 -Action Monitor -MonitorDuration 600 -MonitorInterval 15

.EXAMPLE
    .\Troubleshoot-ADRMS.ps1 -Action Report -OutputPath "C:\Reports\ADRMS-Report.html" -GenerateReport

.NOTES
    Author: AD RMS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Diagnose", "Repair", "Monitor", "Analyze", "Report")]
    [string]$Action,
    
    [string]$OutputPath,
    
    [switch]$IncludeLogs,
    
    [int]$LogDays = 7,
    
    [ValidateSet("All", "Services", "Configuration", "IIS")]
    [string]$RepairType = "All",
    
    [int]$MonitorDuration = 300,
    
    [int]$MonitorInterval = 10,
    
    [switch]$GenerateReport
)

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "ADRMS-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "ADRMS-Configuration.psm1") -Force
    Import-Module (Join-Path $modulePath "ADRMS-Diagnostics.psm1") -Force
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Script variables
$script:TroubleshootingLog = @()
$script:StartTime = Get-Date

function Write-TroubleshootingLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:TroubleshootingLog += $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function Start-ADRMSDiagnosis {
    Write-TroubleshootingLog "Starting comprehensive AD RMS diagnosis..." "INFO"
    
    try {
        $diagnosisResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            Prerequisites = @{}
            Configuration = @{}
            Services = @{}
            Connectivity = @{}
            Performance = @{}
            Logs = @{}
            Issues = @()
            Recommendations = @()
            Overall = 'Unknown'
        }
        
        # Check prerequisites
        Write-TroubleshootingLog "Checking prerequisites..." "INFO"
        $prerequisites = Test-ADRMSPrerequisites
        $diagnosisResults.Prerequisites = @{
            Passed = $prerequisites
            Details = "Prerequisites check completed"
        }
        
        # Check configuration
        Write-TroubleshootingLog "Checking configuration..." "INFO"
        $configStatus = Get-ADRMSConfigurationStatus
        $diagnosisResults.Configuration = $configStatus
        
        # Check services
        Write-TroubleshootingLog "Checking services..." "INFO"
        $services = @('MSDRMS', 'W3SVC', 'IISADMIN')
        foreach ($serviceName in $services) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                $diagnosisResults.Services[$serviceName] = @{
                    Status = $service.Status
                    StartType = $service.StartType
                    DisplayName = $service.DisplayName
                }
            } else {
                $diagnosisResults.Services[$serviceName] = @{
                    Status = 'Not Found'
                    StartType = 'Unknown'
                    DisplayName = 'Unknown'
                }
            }
        }
        
        # Check connectivity
        Write-TroubleshootingLog "Checking connectivity..." "INFO"
        $connectivity = Test-ADRMSConnectivity
        $diagnosisResults.Connectivity = $connectivity
        
        # Check performance
        Write-TroubleshootingLog "Checking performance..." "INFO"
        $performance = Get-ADRMSPerformanceCounters
        $diagnosisResults.Performance = $performance
        
        # Analyze logs if requested
        if ($IncludeLogs) {
            Write-TroubleshootingLog "Analyzing logs..." "INFO"
            $startTime = (Get-Date).AddDays(-$LogDays)
            $logEntries = Get-ADRMSLogEntries -StartTime $startTime
            
            $diagnosisResults.Logs = @{
                TotalEntries = $logEntries.Count
                ErrorEntries = ($logEntries | Where-Object { $_.LevelDisplayName -eq "Error" }).Count
                WarningEntries = ($logEntries | Where-Object { $_.LevelDisplayName -eq "Warning" }).Count
                RecentErrors = $logEntries | Where-Object { $_.LevelDisplayName -eq "Error" } | Select-Object -First 10 | ForEach-Object { $_.Message }
            }
        }
        
        # Identify issues
        if (-not $prerequisites) {
            $diagnosisResults.Issues += "Prerequisites check failed"
            $diagnosisResults.Recommendations += "Install required Windows features and verify system requirements"
        }
        
        $stoppedServices = $diagnosisResults.Services.GetEnumerator() | Where-Object { $_.Value.Status -ne 'Running' }
        if ($stoppedServices) {
            $diagnosisResults.Issues += "Services not running: $($stoppedServices.Key -join ', ')"
            $diagnosisResults.Recommendations += "Start stopped services"
        }
        
        if ($diagnosisResults.Configuration.ConfigurationStatus.Overall -ne 'Fully Configured') {
            $diagnosisResults.Issues += "Configuration incomplete"
            $diagnosisResults.Recommendations += "Complete AD RMS configuration"
        }
        
        if ($diagnosisResults.Connectivity.Overall -ne 'All Accessible') {
            $diagnosisResults.Issues += "Connectivity issues detected"
            $diagnosisResults.Recommendations += "Check network connectivity and firewall settings"
        }
        
        if ($IncludeLogs -and $diagnosisResults.Logs.ErrorEntries -gt 0) {
            $diagnosisResults.Issues += "Recent errors found in logs"
            $diagnosisResults.Recommendations += "Review error logs for specific issues"
        }
        
        # Determine overall health
        if ($diagnosisResults.Issues.Count -eq 0) {
            $diagnosisResults.Overall = 'Healthy'
        } elseif ($diagnosisResults.Issues.Count -le 2) {
            $diagnosisResults.Overall = 'Degraded'
        } else {
            $diagnosisResults.Overall = 'Unhealthy'
        }
        
        Write-TroubleshootingLog "Diagnosis completed. Overall status: $($diagnosisResults.Overall)" "SUCCESS"
        
        return [PSCustomObject]$diagnosisResults
        
    } catch {
        Write-TroubleshootingLog "Error during diagnosis: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Start-ADRMSRepair {
    param([string]$RepairType)
    
    Write-TroubleshootingLog "Starting AD RMS repair operation..." "INFO"
    
    try {
        $repairResults = Repair-ADRMSInstallation -RepairType $RepairType
        
        if ($repairResults) {
            Write-TroubleshootingLog "Repair operation completed: $($repairResults.Overall)" "SUCCESS"
        } else {
            Write-TroubleshootingLog "Repair operation failed" "ERROR"
        }
        
        return $repairResults
        
    } catch {
        Write-TroubleshootingLog "Error during repair: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Start-ADRMSMonitoring {
    param(
        [int]$Duration,
        [int]$Interval
    )
    
    Write-TroubleshootingLog "Starting AD RMS monitoring for $Duration seconds..." "INFO"
    
    try {
        Watch-ADRMSPerformance -Duration $Duration -Interval $Interval
        Write-TroubleshootingLog "Monitoring completed successfully" "SUCCESS"
        return $true
        
    } catch {
        Write-TroubleshootingLog "Error during monitoring: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-ADRMSAnalysis {
    param([int]$LogDays)
    
    Write-TroubleshootingLog "Starting AD RMS log analysis..." "INFO"
    
    try {
        $analysisResults = @{
            Timestamp = Get-Date
            LogPeriod = "$LogDays days"
            LogAnalysis = @{}
            PerformanceAnalysis = @{}
            ErrorPatterns = @{}
            Recommendations = @()
        }
        
        # Analyze logs
        $startTime = (Get-Date).AddDays(-$LogDays)
        $logEntries = Get-ADRMSLogEntries -StartTime $startTime
        
        $analysisResults.LogAnalysis = @{
            TotalEntries = $logEntries.Count
            ErrorCount = ($logEntries | Where-Object { $_.LevelDisplayName -eq "Error" }).Count
            WarningCount = ($logEntries | Where-Object { $_.LevelDisplayName -eq "Warning" }).Count
            InformationCount = ($logEntries | Where-Object { $_.LevelDisplayName -eq "Information" }).Count
            ErrorRate = if ($logEntries.Count -gt 0) { [math]::Round((($logEntries | Where-Object { $_.LevelDisplayName -eq "Error" }).Count / $logEntries.Count) * 100, 2) } else { 0 }
        }
        
        # Analyze error patterns
        $errorEntries = $logEntries | Where-Object { $_.LevelDisplayName -eq "Error" }
        $errorPatterns = $errorEntries | Group-Object -Property { $_.Message.Substring(0, [Math]::Min(50, $_.Message.Length)) }
        
        $analysisResults.ErrorPatterns = $errorPatterns | Select-Object -First 10 | ForEach-Object {
            @{
                Pattern = $_.Name
                Count = $_.Count
                Percentage = [math]::Round(($_.Count / $errorEntries.Count) * 100, 2)
            }
        }
        
        # Analyze performance
        $performance = Get-ADRMSPerformanceCounters
        $analysisResults.PerformanceAnalysis = $performance
        
        # Generate recommendations
        if ($analysisResults.LogAnalysis.ErrorRate -gt 10) {
            $analysisResults.Recommendations += "High error rate detected. Review error logs for patterns."
        }
        
        if ($analysisResults.LogAnalysis.ErrorCount -gt 100) {
            $analysisResults.Recommendations += "Large number of errors found. Consider system maintenance."
        }
        
        if ($analysisResults.ErrorPatterns.Count -gt 0) {
            $analysisResults.Recommendations += "Common error patterns identified. Address root causes."
        }
        
        Write-TroubleshootingLog "Analysis completed successfully" "SUCCESS"
        
        return [PSCustomObject]$analysisResults
        
    } catch {
        Write-TroubleshootingLog "Error during analysis: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function New-ADRMSReport {
    param(
        [object]$DiagnosisResults,
        [object]$AnalysisResults,
        [string]$OutputPath
    )
    
    Write-TroubleshootingLog "Generating AD RMS report..." "INFO"
    
    try {
        if (-not $OutputPath) {
            $OutputPath = Join-Path $scriptPath "ADRMS-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        }
        
        $report = @{
            Title = "AD RMS Diagnostic Report"
            Generated = Get-Date
            ComputerName = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            Diagnosis = $DiagnosisResults
            Analysis = $AnalysisResults
            Summary = @{
                OverallHealth = $DiagnosisResults.Overall
                IssuesFound = $DiagnosisResults.Issues.Count
                Recommendations = $DiagnosisResults.Recommendations.Count
            }
        }
        
        # Generate HTML report
        $htmlReport = $report | ConvertTo-Html -Title "AD RMS Diagnostic Report" -Head @"
<style>
body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
.container { background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
h1 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
h2 { color: #007acc; margin-top: 30px; }
h3 { color: #666; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; font-weight: bold; }
.status-healthy { color: #28a745; font-weight: bold; }
.status-degraded { color: #ffc107; font-weight: bold; }
.status-unhealthy { color: #dc3545; font-weight: bold; }
.issue { background-color: #fff3cd; padding: 10px; margin: 5px 0; border-left: 4px solid #ffc107; }
.recommendation { background-color: #d1ecf1; padding: 10px; margin: 5px 0; border-left: 4px solid #17a2b8; }
</style>
"@
        
        $htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8
        
        Write-TroubleshootingLog "Report generated successfully: $OutputPath" "SUCCESS"
        return $OutputPath
        
    } catch {
        Write-TroubleshootingLog "Error generating report: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Save-TroubleshootingLog {
    $logPath = Join-Path $scriptPath "Troubleshooting-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    try {
        $script:TroubleshootingLog | Out-File -FilePath $logPath -Encoding UTF8
        Write-TroubleshootingLog "Troubleshooting log saved to: $logPath" "INFO"
    } catch {
        Write-Warning "Failed to save troubleshooting log: $($_.Exception.Message)"
    }
}

# Main troubleshooting process
try {
    Write-TroubleshootingLog "Starting AD RMS troubleshooting..." "INFO"
    Write-TroubleshootingLog "Action: $Action" "INFO"
    
    $results = @{}
    
    switch ($Action) {
        "Diagnose" {
            $results.Diagnosis = Start-ADRMSDiagnosis
            if ($results.Diagnosis) {
                Write-Host "`n=== AD RMS Diagnosis Results ===" -ForegroundColor Cyan
                Write-Host "Overall Status: $($results.Diagnosis.Overall)" -ForegroundColor White
                Write-Host "Issues Found: $($results.Diagnosis.Issues.Count)" -ForegroundColor White
                Write-Host "Recommendations: $($results.Diagnosis.Recommendations.Count)" -ForegroundColor White
                
                if ($results.Diagnosis.Issues.Count -gt 0) {
                    Write-Host "`nIssues:" -ForegroundColor Yellow
                    $results.Diagnosis.Issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
                }
                
                if ($results.Diagnosis.Recommendations.Count -gt 0) {
                    Write-Host "`nRecommendations:" -ForegroundColor Yellow
                    $results.Diagnosis.Recommendations | ForEach-Object { Write-Host "  - $_" -ForegroundColor Green }
                }
            }
        }
        
        "Repair" {
            $results.Repair = Start-ADRMSRepair -RepairType $RepairType
            if ($results.Repair) {
                Write-Host "`n=== AD RMS Repair Results ===" -ForegroundColor Cyan
                Write-Host "Repair Status: $($results.Repair.Overall)" -ForegroundColor White
                Write-Host "Services Repaired: $($results.Repair.ServicesRepaired)" -ForegroundColor White
                Write-Host "Configuration Repaired: $($results.Repair.ConfigurationRepaired)" -ForegroundColor White
                Write-Host "IIS Repaired: $($results.Repair.IISRepaired)" -ForegroundColor White
            }
        }
        
        "Monitor" {
            $results.Monitoring = Start-ADRMSMonitoring -Duration $MonitorDuration -Interval $MonitorInterval
        }
        
        "Analyze" {
            $results.Analysis = Start-ADRMSAnalysis -LogDays $LogDays
            if ($results.Analysis) {
                Write-Host "`n=== AD RMS Analysis Results ===" -ForegroundColor Cyan
                Write-Host "Log Period: $($results.Analysis.LogPeriod)" -ForegroundColor White
                Write-Host "Total Entries: $($results.Analysis.LogAnalysis.TotalEntries)" -ForegroundColor White
                Write-Host "Error Count: $($results.Analysis.LogAnalysis.ErrorCount)" -ForegroundColor White
                Write-Host "Error Rate: $($results.Analysis.LogAnalysis.ErrorRate)%" -ForegroundColor White
                Write-Host "Recommendations: $($results.Analysis.Recommendations.Count)" -ForegroundColor White
            }
        }
        
        "Report" {
            $diagnosisResults = Start-ADRMSDiagnosis
            $analysisResults = Start-ADRMSAnalysis -LogDays $LogDays
            
            $reportPath = New-ADRMSReport -DiagnosisResults $diagnosisResults -AnalysisResults $analysisResults -OutputPath $OutputPath
            
            if ($reportPath) {
                Write-Host "`n=== AD RMS Report Generated ===" -ForegroundColor Cyan
                Write-Host "Report Path: $reportPath" -ForegroundColor White
                Write-Host "Report Type: HTML" -ForegroundColor White
            }
        }
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-TroubleshootingLog "AD RMS troubleshooting completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== AD RMS Troubleshooting Summary ===" -ForegroundColor Cyan
    Write-Host "Action: $Action" -ForegroundColor White
    Write-Host "Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    
    # Save troubleshooting log
    Save-TroubleshootingLog
    
    Write-Host "`nTroubleshooting completed successfully!" -ForegroundColor Green
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-TroubleshootingLog "AD RMS troubleshooting failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save troubleshooting log
    Save-TroubleshootingLog
    
    Write-Host "`nTroubleshooting failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the troubleshooting log for details." -ForegroundColor Yellow
    
    exit 1
}
