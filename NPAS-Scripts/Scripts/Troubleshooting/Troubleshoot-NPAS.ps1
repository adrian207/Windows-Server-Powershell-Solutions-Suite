#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Troubleshoot NPAS

.DESCRIPTION
    This script provides comprehensive troubleshooting and diagnostics for Network Policy and Access Services (NPAS)
    including automated diagnostics, issue repair, event log analysis, performance analysis,
    configuration validation, health checks, and optimization recommendations.

.PARAMETER ServerName
    Name of the NPAS server to troubleshoot

.PARAMETER DiagnosticType
    Type of diagnostics to run (All, Service, Configuration, Connectivity, Performance, Security)

.PARAMETER RepairIssues
    Automatically repair common issues

.PARAMETER AnalyzePerformance
    Perform performance analysis

.PARAMETER ValidateConfiguration
    Validate NPAS configuration

.PARAMETER BackupConfiguration
    Backup configuration before making changes

.EXAMPLE
    .\Troubleshoot-NPAS.ps1 -ServerName "NPAS-SERVER01" -DiagnosticType "All" -RepairIssues -AnalyzePerformance -ValidateConfiguration -BackupConfiguration

.EXAMPLE
    .\Troubleshoot-NPAS.ps1 -ServerName "NPAS-SERVER01" -DiagnosticType "Service" -RepairIssues
#>

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerName,

    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Service", "Configuration", "Connectivity", "Performance", "Security")]
    [string]$DiagnosticType = "All",

    [Parameter(Mandatory = $false)]
    [switch]$RepairIssues,

    [Parameter(Mandatory = $false)]
    [switch]$AnalyzePerformance,

    [Parameter(Mandatory = $false)]
    [switch]$ValidateConfiguration,

    [Parameter(Mandatory = $false)]
    [switch]$BackupConfiguration
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Script configuration
$scriptConfig = @{
    ServerName = $ServerName
    DiagnosticType = $DiagnosticType
    RepairIssues = $RepairIssues
    AnalyzePerformance = $AnalyzePerformance
    ValidateConfiguration = $ValidateConfiguration
    BackupConfiguration = $BackupConfiguration
    LogPath = "C:\NPAS\Logs\Troubleshooting"
    StartTime = Get-Date
}

# Create log directory
if (-not (Test-Path $scriptConfig.LogPath)) {
    New-Item -Path $scriptConfig.LogPath -ItemType Directory -Force
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "Information"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    Write-Host $logMessage -ForegroundColor $(
        switch ($Level) {
            "Error" { "Red" }
            "Warning" { "Yellow" }
            "Success" { "Green" }
            default { "White" }
        }
    )
    
    $logMessage | Out-File -FilePath "$($scriptConfig.LogPath)\NPAS-Troubleshooting.log" -Append -Encoding UTF8
}

try {
    Write-Log "Starting NPAS troubleshooting..." "Information"
    Write-Log "Server Name: $ServerName" "Information"
    Write-Log "Diagnostic Type: $DiagnosticType" "Information"
    Write-Log "Repair Issues: $RepairIssues" "Information"
    Write-Log "Analyze Performance: $AnalyzePerformance" "Information"
    Write-Log "Validate Configuration: $ValidateConfiguration" "Information"
    Write-Log "Backup Configuration: $BackupConfiguration" "Information"

    # Import required modules
    Write-Log "Importing NPAS modules..." "Information"
    $modulePath = Join-Path $PSScriptRoot "..\..\Modules"
    
    if (Test-Path "$modulePath\NPAS-Troubleshooting.psm1") {
        Import-Module "$modulePath\NPAS-Troubleshooting.psm1" -Force
        Write-Log "NPAS-Troubleshooting module imported successfully" "Success"
    } else {
        throw "NPAS-Troubleshooting module not found at $modulePath\NPAS-Troubleshooting.psm1"
    }

    if (Test-Path "$modulePath\NPAS-Core.psm1") {
        Import-Module "$modulePath\NPAS-Core.psm1" -Force
        Write-Log "NPAS-Core module imported successfully" "Success"
    } else {
        throw "NPAS-Core module not found at $modulePath\NPAS-Core.psm1"
    }

    # Backup configuration if requested
    if ($BackupConfiguration) {
        Write-Log "Backing up NPAS configuration..." "Information"
        $backupResult = Backup-NPASConfiguration -ServerName $ServerName -BackupPath "C:\NPAS\Backup" -BackupType "Full"
        
        if ($backupResult.Success) {
            Write-Log "Configuration backup completed successfully" "Success"
            Write-Log "Backup Path: $($backupResult.BackupPath)" "Information"
            Write-Log "Backup Type: $($backupResult.BackupType)" "Information"
            Write-Log "Backup Size: $($backupResult.BackupSize) bytes" "Information"
        } else {
            Write-Log "Configuration backup failed: $($backupResult.Error)" "Warning"
        }
    }

    # 1. Run Comprehensive Diagnostics
    Write-Log "Running NPAS diagnostics..." "Information"
    $diagResult = Test-NPASDiagnostics -ServerName $ServerName -DiagnosticType $DiagnosticType
    
    if ($diagResult.Success) {
        Write-Log "Diagnostics completed successfully" "Success"
        Write-Log "Diagnostic Type: $($diagResult.DiagnosticType)" "Information"
        Write-Log "Issues Found: $($diagResult.IssuesFound.Count)" "Information"
        Write-Log "Recommendations: $($diagResult.Recommendations.Count)" "Information"
        
        # Display diagnostic results
        if ($diagResult.DiagnosticResults) {
            Write-Log "Diagnostic Results:" "Information"
            foreach ($result in $diagResult.DiagnosticResults.PSObject.Properties) {
                Write-Log "  $($result.Name): $($result.Value)" "Information"
            }
        }
        
        # Display issues found
        if ($diagResult.IssuesFound.Count -gt 0) {
            Write-Log "Issues Found:" "Warning"
            foreach ($issue in $diagResult.IssuesFound) {
                Write-Log "  - $($issue.Issue): $($issue.Description)" "Warning"
                Write-Log "    Severity: $($issue.Severity)" "Warning"
                Write-Log "    Recommendation: $($issue.Recommendation)" "Warning"
            }
        }
        
        # Display recommendations
        if ($diagResult.Recommendations.Count -gt 0) {
            Write-Log "Recommendations:" "Information"
            foreach ($recommendation in $diagResult.Recommendations) {
                Write-Log "  - $($recommendation.Recommendation)" "Information"
                Write-Log "    Priority: $($recommendation.Priority)" "Information"
            }
        }
    } else {
        Write-Log "Diagnostics failed: $($diagResult.Error)" "Warning"
    }

    # 2. Perform Health Check
    Write-Log "Performing NPAS health check..." "Information"
    $healthResult = Get-NPASHealthCheck -ServerName $ServerName -HealthCheckType "Comprehensive"
    
    if ($healthResult.Success) {
        Write-Log "Health check completed successfully" "Success"
        Write-Log "Health Score: $($healthResult.HealthScore)%" "Information"
        Write-Log "Issues Found: $($healthResult.IssuesFound.Count)" "Information"
        Write-Log "Recommendations: $($healthResult.Recommendations.Count)" "Information"
        
        # Display health status
        if ($healthResult.HealthScore -lt 80) {
            Write-Log "Health score is below 80% - attention required!" "Warning"
        } elseif ($healthResult.HealthScore -lt 90) {
            Write-Log "Health score is below 90% - monitoring recommended" "Warning"
        } else {
            Write-Log "Health score is good" "Success"
        }
        
        # Display health issues
        if ($healthResult.IssuesFound.Count -gt 0) {
            Write-Log "Health Issues:" "Warning"
            foreach ($issue in $healthResult.IssuesFound) {
                Write-Log "  - $($issue.Issue): $($issue.Description)" "Warning"
                Write-Log "    Impact: $($issue.Impact)" "Warning"
            }
        }
    } else {
        Write-Log "Health check failed: $($healthResult.Error)" "Warning"
    }

    # 3. Validate Configuration
    if ($ValidateConfiguration) {
        Write-Log "Validating NPAS configuration..." "Information"
        $validateResult = Test-NPASConfiguration -ServerName $ServerName -ValidationType "All"
        
        if ($validateResult.Success) {
            Write-Log "Configuration validation completed successfully" "Success"
            Write-Log "Validation Type: $($validateResult.ValidationType)" "Information"
            Write-Log "Issues Found: $($validateResult.IssuesFound.Count)" "Information"
            Write-Log "Recommendations: $($validateResult.Recommendations.Count)" "Information"
            
            # Display validation results
            if ($validateResult.ValidationResults) {
                Write-Log "Validation Results:" "Information"
                foreach ($result in $validateResult.ValidationResults.PSObject.Properties) {
                    Write-Log "  $($result.Name): $($result.Value)" "Information"
                }
            }
            
            # Display configuration issues
            if ($validateResult.IssuesFound.Count -gt 0) {
                Write-Log "Configuration Issues:" "Warning"
                foreach ($issue in $validateResult.IssuesFound) {
                    Write-Log "  - $($issue.Issue): $($issue.Description)" "Warning"
                    Write-Log "    Severity: $($issue.Severity)" "Warning"
                    Write-Log "    Fix: $($issue.Fix)" "Warning"
                }
            }
        } else {
            Write-Log "Configuration validation failed: $($validateResult.Error)" "Warning"
        }
    }

    # 4. Analyze Performance
    if ($AnalyzePerformance) {
        Write-Log "Analyzing NPAS performance..." "Information"
        $perfResult = Get-NPASPerformanceAnalysis -ServerName $ServerName -AnalysisPeriod "Last24Hours"
        
        if ($perfResult.Success) {
            Write-Log "Performance analysis completed successfully" "Success"
            Write-Log "Analysis Period: $($perfResult.AnalysisPeriod)" "Information"
            Write-Log "Average Response Time: $($perfResult.PerformanceAnalysis.AverageResponseTime)ms" "Information"
            Write-Log "Peak Response Time: $($perfResult.PerformanceAnalysis.PeakResponseTime)ms" "Information"
            Write-Log "Throughput: $($perfResult.PerformanceAnalysis.Throughput) requests/sec" "Information"
            Write-Log "Bottlenecks Found: $($perfResult.Bottlenecks.Count)" "Information"
            Write-Log "Recommendations: $($perfResult.Recommendations.Count)" "Information"
            
            # Display performance bottlenecks
            if ($perfResult.Bottlenecks.Count -gt 0) {
                Write-Log "Performance Bottlenecks:" "Warning"
                foreach ($bottleneck in $perfResult.Bottlenecks) {
                    Write-Log "  - $($bottleneck.Component): $($bottleneck.Description)" "Warning"
                    Write-Log "    Impact: $($bottleneck.Impact)" "Warning"
                    Write-Log "    Severity: $($bottleneck.Severity)" "Warning"
                }
            }
            
            # Display performance recommendations
            if ($perfResult.Recommendations.Count -gt 0) {
                Write-Log "Performance Recommendations:" "Information"
                foreach ($recommendation in $perfResult.Recommendations) {
                    Write-Log "  - $($recommendation.Recommendation)" "Information"
                    Write-Log "    Priority: $($recommendation.Priority)" "Information"
                    Write-Log "    Expected Improvement: $($recommendation.ExpectedImprovement)" "Information"
                }
            }
        } else {
            Write-Log "Performance analysis failed: $($perfResult.Error)" "Warning"
        }
    }

    # 5. Analyze Event Logs
    Write-Log "Analyzing NPAS event logs..." "Information"
    $eventLogsResult = Get-NPASEventLogs -ServerName $ServerName -LogSource "IAS" -TimeRange "Last24Hours"
    
    if ($eventLogsResult.Success) {
        Write-Log "Event log analysis completed successfully" "Success"
        Write-Log "Log Source: $($eventLogsResult.LogSource)" "Information"
        Write-Log "Time Range: $($eventLogsResult.TimeRange)" "Information"
        Write-Log "Event Logs: $($eventLogsResult.EventLogs.Count)" "Information"
        
        # Analyze log patterns
        $errorLogs = $eventLogsResult.EventLogs | Where-Object { $_.Level -eq "Error" }
        $warningLogs = $eventLogsResult.EventLogs | Where-Object { $_.Level -eq "Warning" }
        $infoLogs = $eventLogsResult.EventLogs | Where-Object { $_.Level -eq "Information" }
        
        Write-Log "Error Logs: $($errorLogs.Count)" "Information"
        Write-Log "Warning Logs: $($warningLogs.Count)" "Information"
        Write-Log "Information Logs: $($infoLogs.Count)" "Information"
        
        # Display top errors
        if ($errorLogs.Count -gt 0) {
            Write-Log "Top Errors:" "Warning"
            $topErrors = $errorLogs | Group-Object Message | Sort-Object Count -Descending | Select-Object -First 5
            foreach ($errorItem in $topErrors) {
                Write-Log "  - $($errorItem.Name): $($errorItem.Count) occurrences" "Warning"
            }
        }
        
        # Display top warnings
        if ($warningLogs.Count -gt 0) {
            Write-Log "Top Warnings:" "Warning"
            $topWarnings = $warningLogs | Group-Object Message | Sort-Object Count -Descending | Select-Object -First 5
            foreach ($warning in $topWarnings) {
                Write-Log "  - $($warning.Name): $($warning.Count) occurrences" "Warning"
            }
        }
    } else {
        Write-Log "Event log analysis failed: $($eventLogsResult.Error)" "Warning"
    }

    # 6. Test Connectivity
    Write-Log "Testing NPAS connectivity..." "Information"
    $connectivityResult = Test-NPASConnectivity -ServerName $ServerName
    
    if ($connectivityResult.Success) {
        Write-Log "Connectivity test completed successfully" "Success"
        Write-Log "Server Connectivity: $($connectivityResult.ConnectivityTests.ServerConnectivity)" "Information"
        Write-Log "Service Status: $($connectivityResult.ConnectivityTests.ServiceStatus)" "Information"
        Write-Log "Port Status: $($connectivityResult.ConnectivityTests.PortStatus)" "Information"
        Write-Log "Authentication Test: $($connectivityResult.ConnectivityTests.AuthenticationTest)" "Information"
        Write-Log "Authorization Test: $($connectivityResult.ConnectivityTests.AuthorizationTest)" "Information"
    } else {
        Write-Log "Connectivity test failed: $($connectivityResult.Error)" "Warning"
    }

    # 7. Resolve Configuration Conflicts
    Write-Log "Resolving NPAS configuration conflicts..." "Information"
    $conflictsResult = Resolve-NPASConflicts -ServerName $ServerName -ConflictType "All"
    
    if ($conflictsResult.Success) {
        Write-Log "Configuration conflicts resolution completed successfully" "Success"
        Write-Log "Conflict Type: $($conflictsResult.ConflictType)" "Information"
        Write-Log "Conflicts Found: $($conflictsResult.ConflictsFound.Count)" "Information"
        Write-Log "Conflicts Resolved: $($conflictsResult.ConflictsResolved.Count)" "Information"
        
        # Display conflicts found
        if ($conflictsResult.ConflictsFound.Count -gt 0) {
            Write-Log "Configuration Conflicts:" "Warning"
            foreach ($conflict in $conflictsResult.ConflictsFound) {
                Write-Log "  - $($conflict.Conflict): $($conflict.Description)" "Warning"
                Write-Log "    Severity: $($conflict.Severity)" "Warning"
                Write-Log "    Resolution: $($conflict.Resolution)" "Warning"
            }
        }
        
        # Display conflicts resolved
        if ($conflictsResult.ConflictsResolved.Count -gt 0) {
            Write-Log "Conflicts Resolved:" "Success"
            foreach ($resolved in $conflictsResult.ConflictsResolved) {
                Write-Log "  - $($resolved.Conflict): $($resolved.Resolution)" "Success"
            }
        }
    } else {
        Write-Log "Configuration conflicts resolution failed: $($conflictsResult.Error)" "Warning"
    }

    # 8. Repair Issues
    if ($RepairIssues) {
        Write-Log "Repairing NPAS issues..." "Information"
        $repairResult = Repair-NPASIssues -ServerName $ServerName -RepairType "All" -Force
        
        if ($repairResult.Success) {
            Write-Log "Issue repair completed successfully" "Success"
            Write-Log "Repair Type: $($repairResult.RepairType)" "Information"
            Write-Log "Repairs Performed: $($repairResult.RepairsPerformed.Count)" "Information"
            Write-Log "Issues Fixed: $($repairResult.IssuesFixed.Count)" "Information"
            
            # Display repairs performed
            if ($repairResult.RepairsPerformed.Count -gt 0) {
                Write-Log "Repairs Performed:" "Success"
                foreach ($repair in $repairResult.RepairsPerformed) {
                    Write-Log "  - $($repair.Repair): $($repair.Description)" "Success"
                    Write-Log "    Status: $($repair.Status)" "Success"
                }
            }
            
            # Display issues fixed
            if ($repairResult.IssuesFixed.Count -gt 0) {
                Write-Log "Issues Fixed:" "Success"
                foreach ($fixed in $repairResult.IssuesFixed) {
                    Write-Log "  - $($fixed.Issue): $($fixed.Fix)" "Success"
                }
            }
        } else {
            Write-Log "Issue repair failed: $($repairResult.Error)" "Warning"
        }
    }

    # 9. Optimize Performance
    Write-Log "Optimizing NPAS performance..." "Information"
    $optimizeResult = Optimize-NPASPerformance -ServerName $ServerName -OptimizationType "All"
    
    if ($optimizeResult.Success) {
        Write-Log "Performance optimization completed successfully" "Success"
        Write-Log "Optimization Type: $($optimizeResult.OptimizationType)" "Information"
        Write-Log "Optimizations Applied: $($optimizeResult.OptimizationsApplied.Count)" "Information"
        Write-Log "Performance Improvement: $($optimizeResult.PerformanceImprovement)%" "Information"
        
        # Display optimizations applied
        if ($optimizeResult.OptimizationsApplied.Count -gt 0) {
            Write-Log "Optimizations Applied:" "Success"
            foreach ($optimization in $optimizeResult.OptimizationsApplied) {
                Write-Log "  - $($optimization.Optimization): $($optimization.Description)" "Success"
                Write-Log "    Improvement: $($optimization.Improvement)%" "Success"
            }
        }
        
        # Display performance improvement
        if ($optimizeResult.PerformanceImprovement -gt 0) {
            Write-Log "Performance improved by $($optimizeResult.PerformanceImprovement)%" "Success"
        } else {
            Write-Log "No significant performance improvement detected" "Information"
        }
    } else {
        Write-Log "Performance optimization failed: $($optimizeResult.Error)" "Warning"
    }

    # 10. Generate Troubleshooting Report
    Write-Log "Generating troubleshooting report..." "Information"
    $reportPath = "$($scriptConfig.LogPath)\NPAS-Troubleshooting-Report-$(Get-Date -Format 'yyyy-MM-dd-HH-mm-ss').txt"
    
    $reportContent = @"
NPAS Troubleshooting Report
Generated: $(Get-Date)
Server: $ServerName
Diagnostic Type: $DiagnosticType

=== DIAGNOSTIC RESULTS ===
$($diagResult | ConvertTo-Json -Depth 3)

=== HEALTH CHECK RESULTS ===
$($healthResult | ConvertTo-Json -Depth 3)

=== CONFIGURATION VALIDATION RESULTS ===
$($validateResult | ConvertTo-Json -Depth 3)

=== PERFORMANCE ANALYSIS RESULTS ===
$($perfResult | ConvertTo-Json -Depth 3)

=== EVENT LOG ANALYSIS RESULTS ===
$($eventLogsResult | ConvertTo-Json -Depth 3)

=== CONNECTIVITY TEST RESULTS ===
$($connectivityResult | ConvertTo-Json -Depth 3)

=== CONFLICT RESOLUTION RESULTS ===
$($conflictsResult | ConvertTo-Json -Depth 3)

=== REPAIR RESULTS ===
$($repairResult | ConvertTo-Json -Depth 3)

=== OPTIMIZATION RESULTS ===
$($optimizeResult | ConvertTo-Json -Depth 3)
"@

    $reportContent | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Log "Troubleshooting report generated: $reportPath" "Success"

    # Calculate troubleshooting duration
    $troubleshootingDuration = (Get-Date) - $scriptConfig.StartTime
    Write-Log "NPAS troubleshooting completed successfully!" "Success"
    Write-Log "Troubleshooting Duration: $($troubleshootingDuration.TotalMinutes) minutes" "Information"
    Write-Log "Diagnostic Type: $DiagnosticType" "Information"
    Write-Log "Repair Issues: $RepairIssues" "Information"
    Write-Log "Analyze Performance: $AnalyzePerformance" "Information"
    Write-Log "Validate Configuration: $ValidateConfiguration" "Information"
    Write-Log "Backup Configuration: $BackupConfiguration" "Information"

    # Display summary
    Write-Host "`n" -NoNewline
    Write-Host "=== NPAS TROUBLESHOOTING SUMMARY ===" -ForegroundColor Green
    Write-Host "Server Name: $ServerName" -ForegroundColor Cyan
    Write-Host "Troubleshooting Duration: $($troubleshootingDuration.TotalMinutes) minutes" -ForegroundColor Cyan
    Write-Host "Diagnostic Type: $DiagnosticType" -ForegroundColor Cyan
    Write-Host "Repair Issues: $RepairIssues" -ForegroundColor Cyan
    Write-Host "Analyze Performance: $AnalyzePerformance" -ForegroundColor Cyan
    Write-Host "Validate Configuration: $ValidateConfiguration" -ForegroundColor Cyan
    Write-Host "Backup Configuration: $BackupConfiguration" -ForegroundColor Cyan
    Write-Host "Report Path: $reportPath" -ForegroundColor Cyan
    Write-Host "Log Path: $($scriptConfig.LogPath)" -ForegroundColor Cyan
    Write-Host "================================" -ForegroundColor Green

} catch {
    Write-Log "NPAS troubleshooting failed: $($_.Exception.Message)" "Error"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}
