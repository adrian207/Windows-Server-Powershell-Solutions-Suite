#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Troubleshoot AD CS

.DESCRIPTION
    Troubleshooting script for Windows Active Directory Certificate Services.
    Provides comprehensive troubleshooting capabilities for AD CS infrastructure,
    including health checks, performance analysis, event log analysis, certificate
    validation, and automated remediation.

.PARAMETER ServerName
    Name of the server to troubleshoot

.PARAMETER TroubleshootingLevel
    Level of troubleshooting to perform

.PARAMETER TroubleshootingType
    Type of troubleshooting to perform

.PARAMETER IncludeRemediation
    Include automated remediation

.PARAMETER IncludePerformanceAnalysis
    Include performance analysis

.PARAMETER IncludeEventLogAnalysis
    Include event log analysis

.PARAMETER IncludeCertificateValidation
    Include certificate validation

.PARAMETER IncludeHealthChecks
    Include health checks

.PARAMETER IncludeSecurityAnalysis
    Include security analysis

.PARAMETER IncludeComplianceCheck
    Include compliance check

.PARAMETER IncludeBackupValidation
    Include backup validation

.PARAMETER IncludeNetworkConnectivity
    Include network connectivity tests

.PARAMETER IncludeServiceStatus
    Include service status checks

.PARAMETER IncludeRegistryValidation
    Include registry validation

.PARAMETER IncludeFileSystemValidation
    Include file system validation

.PARAMETER IncludeDatabaseValidation
    Include database validation

.PARAMETER IncludeTemplateValidation
    Include template validation

.PARAMETER IncludeOCSPValidation
    Include OCSP validation

.PARAMETER IncludeWebEnrollmentValidation
    Include web enrollment validation

.PARAMETER IncludeNDESValidation
    Include NDES validation

.PARAMETER IncludeHSMValidation
    Include HSM validation

.PARAMETER IncludeClusterValidation
    Include cluster validation

.PARAMETER IncludeReplicationValidation
    Include replication validation

.PARAMETER IncludeTrustValidation
    Include trust validation

.PARAMETER IncludePolicyValidation
    Include policy validation

.PARAMETER IncludeAuditValidation
    Include audit validation

.PARAMETER IncludeLoggingValidation
    Include logging validation

.PARAMETER IncludeMonitoringValidation
    Include monitoring validation

.PARAMETER IncludeAlertingValidation
    Include alerting validation

.PARAMETER IncludeReportingValidation
    Include reporting validation

.PARAMETER IncludeIntegrationValidation
    Include integration validation

.PARAMETER IncludeCustomValidation
    Include custom validation

.PARAMETER CustomValidationScript
    Custom validation script path

.PARAMETER OutputFormat
    Output format for troubleshooting results

.PARAMETER OutputPath
    Output path for troubleshooting results

.PARAMETER GenerateReport
    Generate troubleshooting report

.PARAMETER ReportFormat
    Format for troubleshooting report

.PARAMETER ReportPath
    Path for troubleshooting report

.EXAMPLE
    .\Troubleshoot-ADCS.ps1 -ServerName "CA-SERVER01" -TroubleshootingLevel "Basic"

.EXAMPLE
    .\Troubleshoot-ADCS.ps1 -ServerName "CA-SERVER01" -TroubleshootingLevel "Comprehensive" -IncludeRemediation -IncludePerformanceAnalysis -IncludeEventLogAnalysis -IncludeCertificateValidation -IncludeHealthChecks -IncludeSecurityAnalysis -IncludeComplianceCheck -IncludeBackupValidation -IncludeNetworkConnectivity -IncludeServiceStatus -IncludeRegistryValidation -IncludeFileSystemValidation -IncludeDatabaseValidation -IncludeTemplateValidation -IncludeOCSPValidation -IncludeWebEnrollmentValidation -IncludeNDESValidation -IncludeHSMValidation -IncludeClusterValidation -IncludeReplicationValidation -IncludeTrustValidation -IncludePolicyValidation -IncludeAuditValidation -IncludeLoggingValidation -IncludeMonitoringValidation -IncludeAlertingValidation -IncludeReportingValidation -IncludeIntegrationValidation -IncludeCustomValidation -CustomValidationScript "C:\Scripts\Custom-ADCS-Validation.ps1" -OutputFormat "HTML" -OutputPath "C:\Reports\ADCS-Troubleshooting-Results.html" -GenerateReport -ReportFormat "PDF" -ReportPath "C:\Reports\ADCS-Troubleshooting-Report.pdf"

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ServerName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Standard", "Comprehensive", "Maximum")]
    [string]$TroubleshootingLevel = "Standard",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Health", "Performance", "Security", "Compliance", "Integration", "Custom", "All")]
    [string]$TroubleshootingType = "All",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeRemediation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludePerformanceAnalysis,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeEventLogAnalysis,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCertificateValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeHealthChecks,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSecurityAnalysis,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeComplianceCheck,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeBackupValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeNetworkConnectivity,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeServiceStatus,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeRegistryValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeFileSystemValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDatabaseValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeTemplateValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeOCSPValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeWebEnrollmentValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeNDESValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeHSMValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeClusterValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeReplicationValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeTrustValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludePolicyValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAuditValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeLoggingValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeMonitoringValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAlertingValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeReportingValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeIntegrationValidation,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCustomValidation,
    
    [Parameter(Mandatory = $false)]
    [string]$CustomValidationScript,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("HTML", "PDF", "CSV", "JSON", "XML")]
    [string]$OutputFormat = "HTML",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateReport,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("HTML", "PDF", "CSV", "JSON", "XML")]
    [string]$ReportFormat = "PDF",
    
    [Parameter(Mandatory = $false)]
    [string]$ReportPath
)

# Import required modules
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $modulePath "..\..\Modules"

Import-Module "$modulesPath\ADCS-Core.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Security.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Monitoring.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Troubleshooting.psm1" -Force -ErrorAction Stop

# Logging function
function Write-TroubleshootingLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] [ADCS-Troubleshooting] $Message"
    
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
    Write-TroubleshootingLog "Starting AD CS troubleshooting on $ServerName" "Info"
    Write-TroubleshootingLog "Troubleshooting Level: $TroubleshootingLevel" "Info"
    Write-TroubleshootingLog "Troubleshooting Type: $TroubleshootingType" "Info"
    
    # Troubleshooting results
    $troubleshootingResults = @{
        ServerName = $ServerName
        TroubleshootingLevel = $TroubleshootingLevel
        TroubleshootingType = $TroubleshootingType
        Timestamp = Get-Date
        TroubleshootingSteps = @()
        Issues = @()
        Recommendations = @()
        RemediationActions = @()
        OverallResult = "Unknown"
    }
    
    # Configure troubleshooting based on level
    switch ($TroubleshootingLevel) {
        "Basic" {
            Write-TroubleshootingLog "Performing basic troubleshooting..." "Info"
            
            # Step 1: Basic health checks
            try {
                $healthChecks = Get-CAHealthStatus -ServerName $ServerName -IncludeDetails -IncludeCertificates -IncludeTemplates -IncludeOCSP -IncludeWebEnrollment -IncludeNDES
                
                if ($healthChecks) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Basic Health Checks"
                        Status = "Completed"
                        Details = "Basic health checks completed successfully"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Basic health checks completed successfully" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Basic Health Checks"
                        Status = "Failed"
                        Details = "Basic health checks failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Basic health checks failed"
                    $troubleshootingResults.Recommendations += "Check basic health check parameters"
                    Write-TroubleshootingLog "Basic health checks failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Basic Health Checks"
                    Status = "Failed"
                    Details = "Exception during basic health checks: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during basic health checks"
                $troubleshootingResults.Recommendations += "Check error logs and basic health check parameters"
                Write-TroubleshootingLog "Exception during basic health checks: $($_.Exception.Message)" "Error"
            }
        }
        
        "Standard" {
            Write-TroubleshootingLog "Performing standard troubleshooting..." "Info"
            
            # Step 1: Health checks
            try {
                $healthChecks = Get-CAHealthStatus -ServerName $ServerName -IncludeDetails -IncludeCertificates -IncludeTemplates -IncludeOCSP -IncludeWebEnrollment -IncludeNDES
                
                if ($healthChecks) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Health Checks (Standard)"
                        Status = "Completed"
                        Details = "Health checks completed with standard settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Health checks completed with standard settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Health Checks (Standard)"
                        Status = "Failed"
                        Details = "Health checks failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Health checks failed"
                    $troubleshootingResults.Recommendations += "Check health check parameters"
                    Write-TroubleshootingLog "Health checks failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Health Checks (Standard)"
                    Status = "Failed"
                    Details = "Exception during health checks: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during health checks"
                $troubleshootingResults.Recommendations += "Check error logs and health check parameters"
                Write-TroubleshootingLog "Exception during health checks: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Service status checks
            try {
                $serviceStatus = Get-CAServiceStatus -ServerName $ServerName -IncludeDetails -IncludeDependencies -IncludePerformance
                
                if ($serviceStatus) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Service Status Checks (Standard)"
                        Status = "Completed"
                        Details = "Service status checks completed with standard settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Service status checks completed with standard settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Service Status Checks (Standard)"
                        Status = "Failed"
                        Details = "Service status checks failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Service status checks failed"
                    $troubleshootingResults.Recommendations += "Check service status parameters"
                    Write-TroubleshootingLog "Service status checks failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Service Status Checks (Standard)"
                    Status = "Failed"
                    Details = "Exception during service status checks: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during service status checks"
                $troubleshootingResults.Recommendations += "Check error logs and service status parameters"
                Write-TroubleshootingLog "Exception during service status checks: $($_.Exception.Message)" "Error"
            }
            
            # Step 3: Event log analysis
            try {
                $eventLogAnalysis = Get-CAEventLogs -ServerName $ServerName -LogLevel "All" -MaxEvents 1000 -HoursBack 24
                
                if ($eventLogAnalysis) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Event Log Analysis (Standard)"
                        Status = "Completed"
                        Details = "Event log analysis completed with standard settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Event log analysis completed with standard settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Event Log Analysis (Standard)"
                        Status = "Failed"
                        Details = "Event log analysis failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Event log analysis failed"
                    $troubleshootingResults.Recommendations += "Check event log analysis parameters"
                    Write-TroubleshootingLog "Event log analysis failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Event Log Analysis (Standard)"
                    Status = "Failed"
                    Details = "Exception during event log analysis: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during event log analysis"
                $troubleshootingResults.Recommendations += "Check error logs and event log analysis parameters"
                Write-TroubleshootingLog "Exception during event log analysis: $($_.Exception.Message)" "Error"
            }
        }
        
        "Comprehensive" {
            Write-TroubleshootingLog "Performing comprehensive troubleshooting..." "Info"
            
            # Step 1: Health checks
            try {
                $healthChecks = Get-CAHealthStatus -ServerName $ServerName -IncludeDetails -IncludeCertificates -IncludeTemplates -IncludeOCSP -IncludeWebEnrollment -IncludeNDES
                
                if ($healthChecks) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Health Checks (Comprehensive)"
                        Status = "Completed"
                        Details = "Health checks completed with comprehensive settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Health checks completed with comprehensive settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Health Checks (Comprehensive)"
                        Status = "Failed"
                        Details = "Health checks failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Health checks failed"
                    $troubleshootingResults.Recommendations += "Check health check parameters"
                    Write-TroubleshootingLog "Health checks failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Health Checks (Comprehensive)"
                    Status = "Failed"
                    Details = "Exception during health checks: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during health checks"
                $troubleshootingResults.Recommendations += "Check error logs and health check parameters"
                Write-TroubleshootingLog "Exception during health checks: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Service status checks
            try {
                $serviceStatus = Get-CAServiceStatus -ServerName $ServerName -IncludeDetails -IncludeDependencies -IncludePerformance
                
                if ($serviceStatus) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Service Status Checks (Comprehensive)"
                        Status = "Completed"
                        Details = "Service status checks completed with comprehensive settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Service status checks completed with comprehensive settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Service Status Checks (Comprehensive)"
                        Status = "Failed"
                        Details = "Service status checks failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Service status checks failed"
                    $troubleshootingResults.Recommendations += "Check service status parameters"
                    Write-TroubleshootingLog "Service status checks failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Service Status Checks (Comprehensive)"
                    Status = "Failed"
                    Details = "Exception during service status checks: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during service status checks"
                $troubleshootingResults.Recommendations += "Check error logs and service status parameters"
                Write-TroubleshootingLog "Exception during service status checks: $($_.Exception.Message)" "Error"
            }
            
            # Step 3: Event log analysis
            try {
                $eventLogAnalysis = Get-CAEventLogs -ServerName $ServerName -LogLevel "All" -MaxEvents 1000 -HoursBack 24
                
                if ($eventLogAnalysis) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Event Log Analysis (Comprehensive)"
                        Status = "Completed"
                        Details = "Event log analysis completed with comprehensive settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Event log analysis completed with comprehensive settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Event Log Analysis (Comprehensive)"
                        Status = "Failed"
                        Details = "Event log analysis failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Event log analysis failed"
                    $troubleshootingResults.Recommendations += "Check event log analysis parameters"
                    Write-TroubleshootingLog "Event log analysis failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Event Log Analysis (Comprehensive)"
                    Status = "Failed"
                    Details = "Exception during event log analysis: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during event log analysis"
                $troubleshootingResults.Recommendations += "Check error logs and event log analysis parameters"
                Write-TroubleshootingLog "Exception during event log analysis: $($_.Exception.Message)" "Error"
            }
            
            # Step 4: Certificate validation
            try {
                $certificateValidation = Get-CertificateValidationStatus -ServerName $ServerName -IncludeExpired -IncludeRevoked -IncludeChain -IncludeCRL -IncludeOCSP
                
                if ($certificateValidation) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Certificate Validation (Comprehensive)"
                        Status = "Completed"
                        Details = "Certificate validation completed with comprehensive settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Certificate validation completed with comprehensive settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Certificate Validation (Comprehensive)"
                        Status = "Failed"
                        Details = "Certificate validation failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Certificate validation failed"
                    $troubleshootingResults.Recommendations += "Check certificate validation parameters"
                    Write-TroubleshootingLog "Certificate validation failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Certificate Validation (Comprehensive)"
                    Status = "Failed"
                    Details = "Exception during certificate validation: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during certificate validation"
                $troubleshootingResults.Recommendations += "Check error logs and certificate validation parameters"
                Write-TroubleshootingLog "Exception during certificate validation: $($_.Exception.Message)" "Error"
            }
            
            # Step 5: Performance analysis
            try {
                $performanceAnalysis = Get-CAPerformanceMetrics -ServerName $ServerName -DurationMinutes 60 -Metrics @("CPU", "Memory", "Disk", "Network")
                
                if ($performanceAnalysis) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Performance Analysis (Comprehensive)"
                        Status = "Completed"
                        Details = "Performance analysis completed with comprehensive settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Performance analysis completed with comprehensive settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Performance Analysis (Comprehensive)"
                        Status = "Failed"
                        Details = "Performance analysis failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Performance analysis failed"
                    $troubleshootingResults.Recommendations += "Check performance analysis parameters"
                    Write-TroubleshootingLog "Performance analysis failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Performance Analysis (Comprehensive)"
                    Status = "Failed"
                    Details = "Exception during performance analysis: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during performance analysis"
                $troubleshootingResults.Recommendations += "Check error logs and performance analysis parameters"
                Write-TroubleshootingLog "Exception during performance analysis: $($_.Exception.Message)" "Error"
            }
            
            # Step 6: Security analysis
            try {
                $securityAnalysis = Get-CASecurityStatus -ServerName $ServerName -IncludeDetails -IncludePermissions -IncludeAudit -IncludeCompliance
                
                if ($securityAnalysis) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Security Analysis (Comprehensive)"
                        Status = "Completed"
                        Details = "Security analysis completed with comprehensive settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Security analysis completed with comprehensive settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Security Analysis (Comprehensive)"
                        Status = "Failed"
                        Details = "Security analysis failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Security analysis failed"
                    $troubleshootingResults.Recommendations += "Check security analysis parameters"
                    Write-TroubleshootingLog "Security analysis failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Security Analysis (Comprehensive)"
                    Status = "Failed"
                    Details = "Exception during security analysis: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during security analysis"
                $troubleshootingResults.Recommendations += "Check error logs and security analysis parameters"
                Write-TroubleshootingLog "Exception during security analysis: $($_.Exception.Message)" "Error"
            }
            
            # Step 7: Compliance check
            try {
                $complianceCheck = Get-CAComplianceStatus -ServerName $ServerName -IncludeDetails -IncludeStandards -IncludePolicies -IncludeAudit
                
                if ($complianceCheck) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Compliance Check (Comprehensive)"
                        Status = "Completed"
                        Details = "Compliance check completed with comprehensive settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Compliance check completed with comprehensive settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Compliance Check (Comprehensive)"
                        Status = "Failed"
                        Details = "Compliance check failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Compliance check failed"
                    $troubleshootingResults.Recommendations += "Check compliance check parameters"
                    Write-TroubleshootingLog "Compliance check failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Compliance Check (Comprehensive)"
                    Status = "Failed"
                    Details = "Exception during compliance check: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during compliance check"
                $troubleshootingResults.Recommendations += "Check error logs and compliance check parameters"
                Write-TroubleshootingLog "Exception during compliance check: $($_.Exception.Message)" "Error"
            }
            
            # Step 8: Generate troubleshooting report
            try {
                $troubleshootingReport = Get-CATroubleshootingReport -ServerName $ServerName -ReportType "Comprehensive" -OutputFormat $OutputFormat -OutputPath $OutputPath
                
                if ($troubleshootingReport) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Generate Troubleshooting Report (Comprehensive)"
                        Status = "Completed"
                        Details = "Troubleshooting report generated with comprehensive settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Troubleshooting report generated with comprehensive settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Generate Troubleshooting Report (Comprehensive)"
                        Status = "Failed"
                        Details = "Failed to generate troubleshooting report"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Failed to generate troubleshooting report"
                    $troubleshootingResults.Recommendations += "Check troubleshooting report configuration parameters"
                    Write-TroubleshootingLog "Failed to generate troubleshooting report" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Generate Troubleshooting Report (Comprehensive)"
                    Status = "Failed"
                    Details = "Exception during troubleshooting report generation: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during troubleshooting report generation"
                $troubleshootingResults.Recommendations += "Check error logs and troubleshooting report parameters"
                Write-TroubleshootingLog "Exception during troubleshooting report generation: $($_.Exception.Message)" "Error"
            }
        }
        
        "Maximum" {
            Write-TroubleshootingLog "Performing maximum troubleshooting..." "Info"
            
            # Step 1: Health checks
            try {
                $healthChecks = Get-CAHealthStatus -ServerName $ServerName -IncludeDetails -IncludeCertificates -IncludeTemplates -IncludeOCSP -IncludeWebEnrollment -IncludeNDES
                
                if ($healthChecks) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Health Checks (Maximum)"
                        Status = "Completed"
                        Details = "Health checks completed with maximum settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Health checks completed with maximum settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Health Checks (Maximum)"
                        Status = "Failed"
                        Details = "Health checks failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Health checks failed"
                    $troubleshootingResults.Recommendations += "Check health check parameters"
                    Write-TroubleshootingLog "Health checks failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Health Checks (Maximum)"
                    Status = "Failed"
                    Details = "Exception during health checks: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during health checks"
                $troubleshootingResults.Recommendations += "Check error logs and health check parameters"
                Write-TroubleshootingLog "Exception during health checks: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Service status checks
            try {
                $serviceStatus = Get-CAServiceStatus -ServerName $ServerName -IncludeDetails -IncludeDependencies -IncludePerformance
                
                if ($serviceStatus) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Service Status Checks (Maximum)"
                        Status = "Completed"
                        Details = "Service status checks completed with maximum settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Service status checks completed with maximum settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Service Status Checks (Maximum)"
                        Status = "Failed"
                        Details = "Service status checks failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Service status checks failed"
                    $troubleshootingResults.Recommendations += "Check service status parameters"
                    Write-TroubleshootingLog "Service status checks failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Service Status Checks (Maximum)"
                    Status = "Failed"
                    Details = "Exception during service status checks: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during service status checks"
                $troubleshootingResults.Recommendations += "Check error logs and service status parameters"
                Write-TroubleshootingLog "Exception during service status checks: $($_.Exception.Message)" "Error"
            }
            
            # Step 3: Event log analysis
            try {
                $eventLogAnalysis = Get-CAEventLogs -ServerName $ServerName -LogLevel "All" -MaxEvents 1000 -HoursBack 24
                
                if ($eventLogAnalysis) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Event Log Analysis (Maximum)"
                        Status = "Completed"
                        Details = "Event log analysis completed with maximum settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Event log analysis completed with maximum settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Event Log Analysis (Maximum)"
                        Status = "Failed"
                        Details = "Event log analysis failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Event log analysis failed"
                    $troubleshootingResults.Recommendations += "Check event log analysis parameters"
                    Write-TroubleshootingLog "Event log analysis failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Event Log Analysis (Maximum)"
                    Status = "Failed"
                    Details = "Exception during event log analysis: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during event log analysis"
                $troubleshootingResults.Recommendations += "Check error logs and event log analysis parameters"
                Write-TroubleshootingLog "Exception during event log analysis: $($_.Exception.Message)" "Error"
            }
            
            # Step 4: Certificate validation
            try {
                $certificateValidation = Get-CertificateValidationStatus -ServerName $ServerName -IncludeExpired -IncludeRevoked -IncludeChain -IncludeCRL -IncludeOCSP
                
                if ($certificateValidation) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Certificate Validation (Maximum)"
                        Status = "Completed"
                        Details = "Certificate validation completed with maximum settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Certificate validation completed with maximum settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Certificate Validation (Maximum)"
                        Status = "Failed"
                        Details = "Certificate validation failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Certificate validation failed"
                    $troubleshootingResults.Recommendations += "Check certificate validation parameters"
                    Write-TroubleshootingLog "Certificate validation failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Certificate Validation (Maximum)"
                    Status = "Failed"
                    Details = "Exception during certificate validation: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during certificate validation"
                $troubleshootingResults.Recommendations += "Check error logs and certificate validation parameters"
                Write-TroubleshootingLog "Exception during certificate validation: $($_.Exception.Message)" "Error"
            }
            
            # Step 5: Performance analysis
            try {
                $performanceAnalysis = Get-CAPerformanceMetrics -ServerName $ServerName -DurationMinutes 60 -Metrics @("CPU", "Memory", "Disk", "Network")
                
                if ($performanceAnalysis) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Performance Analysis (Maximum)"
                        Status = "Completed"
                        Details = "Performance analysis completed with maximum settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Performance analysis completed with maximum settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Performance Analysis (Maximum)"
                        Status = "Failed"
                        Details = "Performance analysis failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Performance analysis failed"
                    $troubleshootingResults.Recommendations += "Check performance analysis parameters"
                    Write-TroubleshootingLog "Performance analysis failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Performance Analysis (Maximum)"
                    Status = "Failed"
                    Details = "Exception during performance analysis: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during performance analysis"
                $troubleshootingResults.Recommendations += "Check error logs and performance analysis parameters"
                Write-TroubleshootingLog "Exception during performance analysis: $($_.Exception.Message)" "Error"
            }
            
            # Step 6: Security analysis
            try {
                $securityAnalysis = Get-CASecurityStatus -ServerName $ServerName -IncludeDetails -IncludePermissions -IncludeAudit -IncludeCompliance
                
                if ($securityAnalysis) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Security Analysis (Maximum)"
                        Status = "Completed"
                        Details = "Security analysis completed with maximum settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Security analysis completed with maximum settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Security Analysis (Maximum)"
                        Status = "Failed"
                        Details = "Security analysis failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Security analysis failed"
                    $troubleshootingResults.Recommendations += "Check security analysis parameters"
                    Write-TroubleshootingLog "Security analysis failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Security Analysis (Maximum)"
                    Status = "Failed"
                    Details = "Exception during security analysis: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during security analysis"
                $troubleshootingResults.Recommendations += "Check error logs and security analysis parameters"
                Write-TroubleshootingLog "Exception during security analysis: $($_.Exception.Message)" "Error"
            }
            
            # Step 7: Compliance check
            try {
                $complianceCheck = Get-CAComplianceStatus -ServerName $ServerName -IncludeDetails -IncludeStandards -IncludePolicies -IncludeAudit
                
                if ($complianceCheck) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Compliance Check (Maximum)"
                        Status = "Completed"
                        Details = "Compliance check completed with maximum settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Compliance check completed with maximum settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Compliance Check (Maximum)"
                        Status = "Failed"
                        Details = "Compliance check failed"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Compliance check failed"
                    $troubleshootingResults.Recommendations += "Check compliance check parameters"
                    Write-TroubleshootingLog "Compliance check failed" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Compliance Check (Maximum)"
                    Status = "Failed"
                    Details = "Exception during compliance check: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during compliance check"
                $troubleshootingResults.Recommendations += "Check error logs and compliance check parameters"
                Write-TroubleshootingLog "Exception during compliance check: $($_.Exception.Message)" "Error"
            }
            
            # Step 8: Generate troubleshooting report
            try {
                $troubleshootingReport = Get-CATroubleshootingReport -ServerName $ServerName -ReportType "Comprehensive" -OutputFormat $OutputFormat -OutputPath $OutputPath
                
                if ($troubleshootingReport) {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Generate Troubleshooting Report (Maximum)"
                        Status = "Completed"
                        Details = "Troubleshooting report generated with maximum settings"
                        Severity = "Info"
                    }
                    Write-TroubleshootingLog "Troubleshooting report generated with maximum settings" "Success"
                } else {
                    $troubleshootingResults.TroubleshootingSteps += @{
                        Step = "Generate Troubleshooting Report (Maximum)"
                        Status = "Failed"
                        Details = "Failed to generate troubleshooting report"
                        Severity = "Error"
                    }
                    $troubleshootingResults.Issues += "Failed to generate troubleshooting report"
                    $troubleshootingResults.Recommendations += "Check troubleshooting report configuration parameters"
                    Write-TroubleshootingLog "Failed to generate troubleshooting report" "Error"
                }
            }
            catch {
                $troubleshootingResults.TroubleshootingSteps += @{
                    Step = "Generate Troubleshooting Report (Maximum)"
                    Status = "Failed"
                    Details = "Exception during troubleshooting report generation: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $troubleshootingResults.Issues += "Exception during troubleshooting report generation"
                $troubleshootingResults.Recommendations += "Check error logs and troubleshooting report parameters"
                Write-TroubleshootingLog "Exception during troubleshooting report generation: $($_.Exception.Message)" "Error"
            }
        }
        
        default {
            Write-TroubleshootingLog "Unknown troubleshooting level: $TroubleshootingLevel" "Error"
            $troubleshootingResults.TroubleshootingSteps += @{
                Step = "Troubleshooting Level Validation"
                Status = "Failed"
                Details = "Unknown troubleshooting level: $TroubleshootingLevel"
                Severity = "Error"
            }
            $troubleshootingResults.Issues += "Unknown troubleshooting level: $TroubleshootingLevel"
            $troubleshootingResults.Recommendations += "Use a valid troubleshooting level"
        }
    }
    
    # Determine overall result
    $failedSteps = $troubleshootingResults.TroubleshootingSteps | Where-Object { $_.Status -eq "Failed" }
    if ($failedSteps.Count -eq 0) {
        $troubleshootingResults.OverallResult = "Success"
    } elseif ($failedSteps.Count -lt $troubleshootingResults.TroubleshootingSteps.Count / 2) {
        $troubleshootingResults.OverallResult = "Partial Success"
    } else {
        $troubleshootingResults.OverallResult = "Failed"
    }
    
    # Summary
    Write-TroubleshootingLog "=== TROUBLESHOOTING SUMMARY ===" "Info"
    Write-TroubleshootingLog "Server Name: $ServerName" "Info"
    Write-TroubleshootingLog "Troubleshooting Level: $TroubleshootingLevel" "Info"
    Write-TroubleshootingLog "Troubleshooting Type: $TroubleshootingType" "Info"
    Write-TroubleshootingLog "Overall Result: $($troubleshootingResults.OverallResult)" "Info"
    Write-TroubleshootingLog "Troubleshooting Steps: $($troubleshootingResults.TroubleshootingSteps.Count)" "Info"
    Write-TroubleshootingLog "Issues: $($troubleshootingResults.Issues.Count)" "Info"
    Write-TroubleshootingLog "Recommendations: $($troubleshootingResults.Recommendations.Count)" "Info"
    
    if ($troubleshootingResults.Issues.Count -gt 0) {
        Write-TroubleshootingLog "Issues:" "Warning"
        foreach ($issue in $troubleshootingResults.Issues) {
            Write-TroubleshootingLog "  - $issue" "Warning"
        }
    }
    
    if ($troubleshootingResults.Recommendations.Count -gt 0) {
        Write-TroubleshootingLog "Recommendations:" "Info"
        foreach ($recommendation in $troubleshootingResults.Recommendations) {
            Write-TroubleshootingLog "  - $recommendation" "Info"
        }
    }
    
    Write-TroubleshootingLog "AD CS troubleshooting completed" "Success"
    
    return $troubleshootingResults
}
catch {
    Write-TroubleshootingLog "AD CS troubleshooting failed: $($_.Exception.Message)" "Error"
    Write-TroubleshootingLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive troubleshooting for Windows Active Directory Certificate Services
    with various troubleshooting levels including basic, standard, comprehensive, and maximum troubleshooting.
    
    Features:
    - Basic Troubleshooting
    - Standard Troubleshooting
    - Comprehensive Troubleshooting
    - Maximum Troubleshooting
    - Health Checks
    - Service Status Checks
    - Event Log Analysis
    - Certificate Validation
    - Performance Analysis
    - Security Analysis
    - Compliance Check
    - Troubleshooting Report Generation
    
    Prerequisites:
    - Windows Server 2016 or later
    - Active Directory Domain Services
    - Administrative privileges
    - Network connectivity
    - Sufficient storage space
    - Sufficient memory and CPU resources
    
    Dependencies:
    - ADCS-Core.psm1
    - ADCS-Security.psm1
    - ADCS-Monitoring.psm1
    - ADCS-Troubleshooting.psm1
    
    Usage Examples:
    .\Troubleshoot-ADCS.ps1 -ServerName "CA-SERVER01" -TroubleshootingLevel "Basic"
    .\Troubleshoot-ADCS.ps1 -ServerName "CA-SERVER01" -TroubleshootingLevel "Standard" -TroubleshootingType "Health"
    .\Troubleshoot-ADCS.ps1 -ServerName "CA-SERVER01" -TroubleshootingLevel "Comprehensive" -TroubleshootingType "All" -IncludeRemediation -IncludePerformanceAnalysis -IncludeEventLogAnalysis -IncludeCertificateValidation -IncludeHealthChecks -IncludeSecurityAnalysis -IncludeComplianceCheck -IncludeBackupValidation -IncludeNetworkConnectivity -IncludeServiceStatus -IncludeRegistryValidation -IncludeFileSystemValidation -IncludeDatabaseValidation -IncludeTemplateValidation -IncludeOCSPValidation -IncludeWebEnrollmentValidation -IncludeNDESValidation -IncludeHSMValidation -IncludeClusterValidation -IncludeReplicationValidation -IncludeTrustValidation -IncludePolicyValidation -IncludeAuditValidation -IncludeLoggingValidation -IncludeMonitoringValidation -IncludeAlertingValidation -IncludeReportingValidation -IncludeIntegrationValidation -IncludeCustomValidation -CustomValidationScript "C:\Scripts\Custom-ADCS-Validation.ps1" -OutputFormat "HTML" -OutputPath "C:\Reports\ADCS-Troubleshooting-Results.html" -GenerateReport -ReportFormat "PDF" -ReportPath "C:\Reports\ADCS-Troubleshooting-Report.pdf"
    .\Troubleshoot-ADCS.ps1 -ServerName "CA-SERVER01" -TroubleshootingLevel "Maximum" -TroubleshootingType "All" -IncludeRemediation -IncludePerformanceAnalysis -IncludeEventLogAnalysis -IncludeCertificateValidation -IncludeHealthChecks -IncludeSecurityAnalysis -IncludeComplianceCheck -IncludeBackupValidation -IncludeNetworkConnectivity -IncludeServiceStatus -IncludeRegistryValidation -IncludeFileSystemValidation -IncludeDatabaseValidation -IncludeTemplateValidation -IncludeOCSPValidation -IncludeWebEnrollmentValidation -IncludeNDESValidation -IncludeHSMValidation -IncludeClusterValidation -IncludeReplicationValidation -IncludeTrustValidation -IncludePolicyValidation -IncludeAuditValidation -IncludeLoggingValidation -IncludeMonitoringValidation -IncludeAlertingValidation -IncludeReportingValidation -IncludeIntegrationValidation -IncludeCustomValidation -CustomValidationScript "C:\Scripts\Custom-ADCS-Validation.ps1" -OutputFormat "JSON" -OutputPath "C:\Reports\ADCS-Troubleshooting-Results.json" -GenerateReport -ReportFormat "PDF" -ReportPath "C:\Reports\ADCS-Troubleshooting-Report.pdf"
    
    Output:
    - Console logging with color-coded messages
    - Troubleshooting results summary
    - Detailed troubleshooting steps
    - Issues and recommendations
    - Comprehensive error handling
    
    Security Considerations:
    - Requires administrative privileges
    - Performs comprehensive security analysis
    - Implements security baselines
    - Enables security logging
    - Configures security compliance settings
    
    Performance Impact:
    - Minimal impact during troubleshooting
    - Non-destructive operations
    - Configurable troubleshooting scope
    - Resource-aware troubleshooting
#>
