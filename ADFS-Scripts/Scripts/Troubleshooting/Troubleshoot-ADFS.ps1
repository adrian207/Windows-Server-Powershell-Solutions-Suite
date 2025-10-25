#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    ADFS Troubleshooting Automation Script

.DESCRIPTION
    This script provides comprehensive ADFS troubleshooting automation
    including diagnostics, monitoring, and automated repair.

.PARAMETER Action
    Action to perform (Diagnose, Monitor, Repair, AnalyzeLogs, TestConnectivity)

.PARAMETER DiagnosticLevel
    Level of diagnostics (Basic, Comprehensive, Deep)

.PARAMETER MonitorDuration
    Duration for monitoring in minutes

.PARAMETER LogPath
    Path to log files for analysis

.PARAMETER EnableAutoRepair
    Enable automatic repair of detected issues

.PARAMETER EnableSIEMIntegration
    Enable SIEM integration for monitoring

.PARAMETER AlertThreshold
    Threshold for alerting (Low, Medium, High)

.EXAMPLE
    .\Troubleshoot-ADFS.ps1 -Action "Diagnose" -DiagnosticLevel "Comprehensive"

.EXAMPLE
    .\Troubleshoot-ADFS.ps1 -Action "Monitor" -MonitorDuration 60 -EnableAutoRepair -EnableSIEMIntegration
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Diagnose", "Monitor", "Repair", "AnalyzeLogs", "TestConnectivity")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Comprehensive", "Deep")]
    [string]$DiagnosticLevel = "Comprehensive",
    
    [Parameter(Mandatory = $false)]
    [int]$MonitorDuration = 30,
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Windows\System32\winevt\Logs",
    
    [switch]$EnableAutoRepair,
    
    [switch]$EnableSIEMIntegration,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Low", "Medium", "High")]
    [string]$AlertThreshold = "Medium"
)

# Import ADFS modules
try {
    Import-Module "..\..\Modules\ADFS-Core.psm1" -Force
    Import-Module "..\..\Modules\ADFS-Troubleshooting.psm1" -Force
} catch {
    Write-Error "Failed to import ADFS modules: $($_.Exception.Message)"
    exit 1
}

# Script configuration
$scriptConfig = @{
    Action = $Action
    DiagnosticLevel = $DiagnosticLevel
    MonitorDuration = $MonitorDuration
    LogPath = $LogPath
    EnableAutoRepair = $EnableAutoRepair
    EnableSIEMIntegration = $EnableSIEMIntegration
    AlertThreshold = $AlertThreshold
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "ADFS Troubleshooting Automation" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Diagnostic Level: $DiagnosticLevel" -ForegroundColor Yellow
Write-Host "Monitor Duration: $MonitorDuration minutes" -ForegroundColor Yellow
Write-Host "Auto Repair: $EnableAutoRepair" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Test prerequisites
Write-Host "Testing prerequisites..." -ForegroundColor Green
$prerequisites = Test-ADFSPrerequisites

if (-not $prerequisites.AdministratorPrivileges) {
    Write-Error "Administrator privileges are required for ADFS troubleshooting operations."
    exit 1
}

if (-not $prerequisites.ADFSInstalled) {
    Write-Error "ADFS must be installed to perform troubleshooting operations."
    exit 1
}

Write-Host "Prerequisites check passed!" -ForegroundColor Green

# Perform requested action
switch ($Action) {
    "Diagnose" {
        Write-Host "Performing ADFS diagnostics..." -ForegroundColor Green
        
        $diagnosticResult = Invoke-ADFSDiagnostics -DiagnosticLevel $DiagnosticLevel -EnableAutoRepair:$EnableAutoRepair -EnableSIEMIntegration:$EnableSIEMIntegration
        
        if ($diagnosticResult.Success) {
            Write-Host "Diagnostics completed successfully!" -ForegroundColor Green
            
            # Display diagnostic results
            Write-Host "Diagnostic Results:" -ForegroundColor Cyan
            Write-Host "  Service Status: $($diagnosticResult.ServiceStatus)" -ForegroundColor White
            Write-Host "  Configuration Status: $($diagnosticResult.ConfigurationStatus)" -ForegroundColor White
            Write-Host "  Certificate Status: $($diagnosticResult.CertificateStatus)" -ForegroundColor White
            Write-Host "  Trust Status: $($diagnosticResult.TrustStatus)" -ForegroundColor White
            Write-Host "  Performance Status: $($diagnosticResult.PerformanceStatus)" -ForegroundColor White
            
            if ($diagnosticResult.IssuesFound -gt 0) {
                Write-Host "  Issues Found: $($diagnosticResult.IssuesFound)" -ForegroundColor Red
                Write-Host "  Issues Fixed: $($diagnosticResult.IssuesFixed)" -ForegroundColor Green
            }
        } else {
            Write-Error "Failed to perform diagnostics: $($diagnosticResult.Error)"
            exit 1
        }
    }
    
    "Monitor" {
        Write-Host "Starting ADFS monitoring for $MonitorDuration minutes..." -ForegroundColor Green
        
        $monitorResult = Start-ADFSMonitoring -Duration $MonitorDuration -EnableAutoRepair:$EnableAutoRepair -EnableSIEMIntegration:$EnableSIEMIntegration -AlertThreshold $AlertThreshold
        
        if ($monitorResult.Success) {
            Write-Host "Monitoring completed successfully!" -ForegroundColor Green
            
            # Display monitoring results
            Write-Host "Monitoring Results:" -ForegroundColor Cyan
            Write-Host "  Duration: $MonitorDuration minutes" -ForegroundColor White
            Write-Host "  Events Monitored: $($monitorResult.EventsMonitored)" -ForegroundColor White
            Write-Host "  Alerts Generated: $($monitorResult.AlertsGenerated)" -ForegroundColor White
            Write-Host "  Issues Detected: $($monitorResult.IssuesDetected)" -ForegroundColor White
            Write-Host "  Issues Fixed: $($monitorResult.IssuesFixed)" -ForegroundColor White
        } else {
            Write-Error "Failed to perform monitoring: $($monitorResult.Error)"
            exit 1
        }
    }
    
    "Repair" {
        Write-Host "Performing automated ADFS repair..." -ForegroundColor Green
        
        $repairResult = Invoke-ADFSRepair -EnableSIEMIntegration:$EnableSIEMIntegration -AlertThreshold $AlertThreshold
        
        if ($repairResult.Success) {
            Write-Host "Repair completed successfully!" -ForegroundColor Green
            
            # Display repair results
            Write-Host "Repair Results:" -ForegroundColor Cyan
            Write-Host "  Issues Detected: $($repairResult.IssuesDetected)" -ForegroundColor White
            Write-Host "  Issues Fixed: $($repairResult.IssuesFixed)" -ForegroundColor White
            Write-Host "  Issues Failed: $($repairResult.IssuesFailed)" -ForegroundColor White
            Write-Host "  Repair Time: $($repairResult.RepairTime)" -ForegroundColor White
        } else {
            Write-Error "Failed to perform repair: $($repairResult.Error)"
            exit 1
        }
    }
    
    "AnalyzeLogs" {
        Write-Host "Analyzing ADFS logs..." -ForegroundColor Green
        
        if (-not (Test-Path $LogPath)) {
            Write-Error "Log path does not exist: $LogPath"
            exit 1
        }
        
        $logAnalysisResult = Invoke-ADFSLogAnalysis -LogPath $LogPath -EnableSIEMIntegration:$EnableSIEMIntegration -AlertThreshold $AlertThreshold
        
        if ($logAnalysisResult.Success) {
            Write-Host "Log analysis completed successfully!" -ForegroundColor Green
            
            # Display log analysis results
            Write-Host "Log Analysis Results:" -ForegroundColor Cyan
            Write-Host "  Log Files Analyzed: $($logAnalysisResult.LogFilesAnalyzed)" -ForegroundColor White
            Write-Host "  Events Analyzed: $($logAnalysisResult.EventsAnalyzed)" -ForegroundColor White
            Write-Host "  Errors Found: $($logAnalysisResult.ErrorsFound)" -ForegroundColor White
            Write-Host "  Warnings Found: $($logAnalysisResult.WarningsFound)" -ForegroundColor White
            Write-Host "  Critical Issues: $($logAnalysisResult.CriticalIssues)" -ForegroundColor White
        } else {
            Write-Error "Failed to analyze logs: $($logAnalysisResult.Error)"
            exit 1
        }
    }
    
    "TestConnectivity" {
        Write-Host "Testing ADFS connectivity..." -ForegroundColor Green
        
        $connectivityResult = Test-ADFSConnectivity -EnableSIEMIntegration:$EnableSIEMIntegration -AlertThreshold $AlertThreshold
        
        if ($connectivityResult.Success) {
            Write-Host "Connectivity test completed successfully!" -ForegroundColor Green
            
            # Display connectivity results
            Write-Host "Connectivity Test Results:" -ForegroundColor Cyan
            Write-Host "  Service Connectivity: $($connectivityResult.ServiceConnectivity)" -ForegroundColor White
            Write-Host "  Certificate Connectivity: $($connectivityResult.CertificateConnectivity)" -ForegroundColor White
            Write-Host "  Trust Connectivity: $($connectivityResult.TrustConnectivity)" -ForegroundColor White
            Write-Host "  Performance Test: $($connectivityResult.PerformanceTest)" -ForegroundColor White
            Write-Host "  Overall Status: $($connectivityResult.OverallStatus)" -ForegroundColor White
        } else {
            Write-Error "Failed to test connectivity: $($connectivityResult.Error)"
            exit 1
        }
    }
}

# Get final troubleshooting status
Write-Host "Getting ADFS troubleshooting status..." -ForegroundColor Green
$troubleshootingStatus = Get-ADFSTroubleshootingStatus

if ($troubleshootingStatus.Success) {
    Write-Host "ADFS Troubleshooting Status:" -ForegroundColor Cyan
    Write-Host "  Service Status: $($troubleshootingStatus.ServiceStatus)" -ForegroundColor White
    Write-Host "  Configuration Status: $($troubleshootingStatus.ConfigurationStatus)" -ForegroundColor White
    Write-Host "  Certificate Status: $($troubleshootingStatus.CertificateStatus)" -ForegroundColor White
    Write-Host "  Trust Status: $($troubleshootingStatus.TrustStatus)" -ForegroundColor White
    Write-Host "  Performance Status: $($troubleshootingStatus.PerformanceStatus)" -ForegroundColor White
} else {
    Write-Warning "Failed to get ADFS troubleshooting status: $($troubleshootingStatus.Error)"
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "ADFS Troubleshooting Automation Completed!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan

# Summary
Write-Host "Troubleshooting Summary:" -ForegroundColor Yellow
Write-Host "  Action: $Action" -ForegroundColor White
Write-Host "  Diagnostic Level: $DiagnosticLevel" -ForegroundColor White
Write-Host "  Monitor Duration: $MonitorDuration minutes" -ForegroundColor White
Write-Host "  Auto Repair: $EnableAutoRepair" -ForegroundColor White
Write-Host "  SIEM Integration: $EnableSIEMIntegration" -ForegroundColor White
Write-Host "  Alert Threshold: $AlertThreshold" -ForegroundColor White
Write-Host "  Completion Time: $(Get-Date)" -ForegroundColor White
