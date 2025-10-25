#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Troubleshoot Host Guardian Service (HGS)

.DESCRIPTION
    Comprehensive troubleshooting script for HGS including:
    - Diagnostic tools and health checks
    - Event log analysis
    - Performance troubleshooting
    - Configuration validation
    - Repair and recovery operations
    - Automated issue resolution

.PARAMETER HgsServer
    HGS server name

.PARAMETER DiagnosticLevel
    Diagnostic level (Basic, Comprehensive, Deep)

.PARAMETER IncludePerformance
    Include performance diagnostics

.PARAMETER RepairType
    Type of repair to perform (All, Services, Configuration, Certificates, Network)

.PARAMETER AnalysisType
    Type of analysis to perform (Basic, Comprehensive, Deep)

.PARAMETER TimeRange
    Time range for analysis (days)

.PARAMETER TestType
    Type of configuration test (All, Basic, Security, Performance)

.PARAMETER IssueType
    Type of issue to get guidance for (All, Attestation, KeyProtection, Performance, Network, Certificate)

.PARAMETER Severity
    Issue severity level (Low, Medium, High, Critical)

.PARAMETER AutoRepair
    Enable automatic repair of common issues

.PARAMETER Force
    Force troubleshooting operations without confirmation

.EXAMPLE
    .\Troubleshoot-HGS.ps1 -HgsServer "HGS01" -DiagnosticLevel "Comprehensive" -IncludePerformance

.EXAMPLE
    .\Troubleshoot-HGS.ps1 -HgsServer "HGS01" -RepairType "All" -AutoRepair -Force

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$HgsServer = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Comprehensive", "Deep")]
    [string]$DiagnosticLevel = "Comprehensive",

    [Parameter(Mandatory = $false)]
    [switch]$IncludePerformance,

    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Services", "Configuration", "Certificates", "Network")]
    [string]$RepairType,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Comprehensive", "Deep")]
    [string]$AnalysisType = "Comprehensive",

    [Parameter(Mandatory = $false)]
    [int]$TimeRange = 7,

    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Basic", "Security", "Performance")]
    [string]$TestType = "All",

    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Attestation", "KeyProtection", "Performance", "Network", "Certificate")]
    [string]$IssueType = "All",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Low", "Medium", "High", "Critical")]
    [string]$Severity = "Medium",

    [Parameter(Mandatory = $false)]
    [switch]$AutoRepair,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# Import required modules
$ModulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module "$ModulePath\..\..\Modules\HGS-Core.psm1" -Force
Import-Module "$ModulePath\..\..\Modules\HGS-Monitoring.psm1" -Force
Import-Module "$ModulePath\..\..\Modules\HGS-Troubleshooting.psm1" -Force

# Global variables
$script:TroubleshootingLog = @()
$script:TroubleshootingStartTime = Get-Date
$script:TroubleshootingConfig = @{}

function Write-TroubleshootingLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = @{
        Timestamp = $timestamp
        Level = $Level
        Message = $Message
    }
    
    $script:TroubleshootingLog += $logEntry
    
    $color = switch ($Level) {
        "Info" { "White" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Success" { "Green" }
    }
    
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Start-HGSDiagnostics {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-TroubleshootingLog "Starting HGS diagnostics..." "Info"
    
    try {
        # Run comprehensive diagnostics
        $diagnostics = Test-HGSDiagnostics -HgsServer $Config.HgsServer -DiagnosticLevel $Config.DiagnosticLevel -IncludePerformance:$Config.IncludePerformance
        
        # Display diagnostic results
        Write-Host "`nHGS Diagnostic Results:" -ForegroundColor Cyan
        Write-Host "Overall Health: $($diagnostics.OverallHealth)" -ForegroundColor $(if ($diagnostics.OverallHealth -eq "Healthy") { "Green" } else { "Red" })
        Write-Host "Issues Found: $($diagnostics.Issues.Count)" -ForegroundColor $(if ($diagnostics.Issues.Count -eq 0) { "Green" } else { "Yellow" })
        Write-Host "Recommendations: $($diagnostics.Recommendations.Count)" -ForegroundColor "White"
        
        # Display issues
        if ($diagnostics.Issues.Count -gt 0) {
            Write-Host "`nIssues:" -ForegroundColor Yellow
            foreach ($issue in $diagnostics.Issues) {
                Write-Host "  - $issue" -ForegroundColor Yellow
            }
        }
        
        # Display recommendations
        if ($diagnostics.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            foreach ($recommendation in $diagnostics.Recommendations) {
                Write-Host "  - $recommendation" -ForegroundColor Cyan
            }
        }
        
        # Auto-repair if enabled
        if ($AutoRepair -and $diagnostics.Issues.Count -gt 0) {
            Write-TroubleshootingLog "Auto-repair enabled, attempting to fix issues..." "Info"
            $repairResult = Repair-HGSService -HgsServer $Config.HgsServer -RepairType "All" -Force
            if ($repairResult.Success) {
                Write-TroubleshootingLog "Auto-repair completed successfully" "Success"
            } else {
                Write-TroubleshootingLog "Auto-repair failed" "Error"
            }
        }
        
        Write-TroubleshootingLog "Diagnostics completed" "Success"
        return $diagnostics
    }
    catch {
        Write-TroubleshootingLog "Failed to run diagnostics: $($_.Exception.Message)" "Error"
        throw
    }
}

function Start-HGSEventAnalysis {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-TroubleshootingLog "Starting HGS event analysis..." "Info"
    
    try {
        # Analyze event logs
        $eventAnalysis = Get-HGSEventAnalysis -HgsServer $Config.HgsServer -TimeRange $Config.TimeRange -AnalysisType $Config.AnalysisType
        
        # Display analysis results
        Write-Host "`nHGS Event Analysis Results:" -ForegroundColor Cyan
        Write-Host "Total Events: $($eventAnalysis.EventSummary.TotalEvents)" -ForegroundColor White
        Write-Host "Errors: $($eventAnalysis.EventSummary.Errors)" -ForegroundColor Red
        Write-Host "Warnings: $($eventAnalysis.EventSummary.Warnings)" -ForegroundColor Yellow
        Write-Host "Information: $($eventAnalysis.EventSummary.Information)" -ForegroundColor Green
        
        # Display patterns
        if ($eventAnalysis.Patterns.Count -gt 0) {
            Write-Host "`nEvent Patterns:" -ForegroundColor Yellow
            foreach ($pattern in $eventAnalysis.Patterns) {
                Write-Host "  - Event ID $($pattern.EventId): $($pattern.Count) occurrences ($($pattern.Frequency) per day)" -ForegroundColor Yellow
            }
        }
        
        # Display issues
        if ($eventAnalysis.Issues.Count -gt 0) {
            Write-Host "`nIssues Detected:" -ForegroundColor Red
            foreach ($issue in $eventAnalysis.Issues) {
                Write-Host "  - $issue" -ForegroundColor Red
            }
        }
        
        # Display recommendations
        if ($eventAnalysis.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            foreach ($recommendation in $eventAnalysis.Recommendations) {
                Write-Host "  - $recommendation" -ForegroundColor Cyan
            }
        }
        
        Write-TroubleshootingLog "Event analysis completed" "Success"
        return $eventAnalysis
    }
    catch {
        Write-TroubleshootingLog "Failed to analyze events: $($_.Exception.Message)" "Error"
        throw
    }
}

function Start-HGSConfigurationTesting {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-TroubleshootingLog "Starting HGS configuration testing..." "Info"
    
    try {
        # Test configuration
        $configTest = Test-HGSConfiguration -HgsServer $Config.HgsServer -TestType $Config.TestType
        
        # Display test results
        Write-Host "`nHGS Configuration Test Results:" -ForegroundColor Cyan
        Write-Host "Overall Result: $($configTest.OverallResult)" -ForegroundColor $(if ($configTest.OverallResult -eq "Pass") { "Green" } else { "Red" })
        
        # Display test details
        foreach ($test in $configTest.Tests.GetEnumerator()) {
            Write-Host "`n$($test.Key):" -ForegroundColor White
            if ($test.Value.Result) {
                Write-Host "  Result: $($test.Value.Result)" -ForegroundColor $(if ($test.Value.Result -eq "Pass") { "Green" } else { "Red" })
            }
            if ($test.Value.Error) {
                Write-Host "  Error: $($test.Value.Error)" -ForegroundColor Red
            }
        }
        
        # Display issues
        if ($configTest.Issues.Count -gt 0) {
            Write-Host "`nConfiguration Issues:" -ForegroundColor Yellow
            foreach ($issue in $configTest.Issues) {
                Write-Host "  - $issue" -ForegroundColor Yellow
            }
        }
        
        Write-TroubleshootingLog "Configuration testing completed" "Success"
        return $configTest
    }
    catch {
        Write-TroubleshootingLog "Failed to test configuration: $($_.Exception.Message)" "Error"
        throw
    }
}

function Start-HGSRepairOperations {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-TroubleshootingLog "Starting HGS repair operations..." "Info"
    
    try {
        if ($Config.RepairType) {
            # Run repair operations
            $repairResult = Repair-HGSService -HgsServer $Config.HgsServer -RepairType $Config.RepairType -Force:$Config.Force
            
            # Display repair results
            Write-Host "`nHGS Repair Results:" -ForegroundColor Cyan
            Write-Host "Success: $($repairResult.Success)" -ForegroundColor $(if ($repairResult.Success) { "Green" } else { "Red" })
            
            # Display repair actions
            if ($repairResult.Actions.Count -gt 0) {
                Write-Host "`nRepair Actions:" -ForegroundColor White
                foreach ($action in $repairResult.Actions) {
                    Write-Host "  - $action" -ForegroundColor White
                }
            }
            
            Write-TroubleshootingLog "Repair operations completed" "Success"
            return $repairResult
        } else {
            Write-TroubleshootingLog "No repair type specified, skipping repair operations" "Info"
            return $null
        }
    }
    catch {
        Write-TroubleshootingLog "Failed to run repair operations: $($_.Exception.Message)" "Error"
        throw
    }
}

function Get-HGSTroubleshootingGuidance {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-TroubleshootingLog "Getting HGS troubleshooting guidance..." "Info"
    
    try {
        # Get troubleshooting guide
        $guide = Get-HGSTroubleshootingGuide -IssueType $Config.IssueType -Severity $Config.Severity
        
        # Display guidance
        Write-Host "`nHGS Troubleshooting Guidance:" -ForegroundColor Cyan
        Write-Host "Issue Type: $($guide.IssueType)" -ForegroundColor White
        Write-Host "Severity: $($guide.Severity)" -ForegroundColor White
        
        # Display steps
        if ($guide.Steps.Count -gt 0) {
            Write-Host "`nTroubleshooting Steps:" -ForegroundColor Yellow
            foreach ($stepGroup in $guide.Steps) {
                Write-Host "`n$($stepGroup.Category):" -ForegroundColor Cyan
                foreach ($step in $stepGroup.Steps) {
                    Write-Host "  - $step" -ForegroundColor White
                }
            }
        }
        
        # Display commands
        if ($guide.Commands.Count -gt 0) {
            Write-Host "`nUseful Commands:" -ForegroundColor Green
            foreach ($commandGroup in $guide.Commands) {
                Write-Host "`n$($commandGroup.Category):" -ForegroundColor Cyan
                foreach ($command in $commandGroup.Commands) {
                    Write-Host "  - $command" -ForegroundColor Green
                }
            }
        }
        
        # Display resources
        if ($guide.Resources.Count -gt 0) {
            Write-Host "`nAdditional Resources:" -ForegroundColor Blue
            foreach ($resource in $guide.Resources) {
                Write-Host "  - $resource" -ForegroundColor Blue
            }
        }
        
        Write-TroubleshootingLog "Troubleshooting guidance retrieved" "Success"
        return $guide
    }
    catch {
        Write-TroubleshootingLog "Failed to get troubleshooting guidance: $($_.Exception.Message)" "Error"
        throw
    }
}

function Start-HGSPerformanceTroubleshooting {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-TroubleshootingLog "Starting HGS performance troubleshooting..." "Info"
    
    try {
        # Get performance metrics
        $perfMetrics = Get-HGSPerformanceMetrics -HgsServer $Config.HgsServer -MetricType "All"
        
        # Display performance metrics
        Write-Host "`nHGS Performance Metrics:" -ForegroundColor Cyan
        Write-Host "CPU Usage: $($perfMetrics.CPU.ProcessorTime)%" -ForegroundColor $(if ($perfMetrics.CPU.ProcessorTime -gt 80) { "Red" } elseif ($perfMetrics.CPU.ProcessorTime -gt 60) { "Yellow" } else { "Green" })
        Write-Host "Memory Usage: $($perfMetrics.Memory.UsedPercentage)%" -ForegroundColor $(if ($perfMetrics.Memory.UsedPercentage -gt 85) { "Red" } elseif ($perfMetrics.Memory.UsedPercentage -gt 70) { "Yellow" } else { "Green" })
        Write-Host "Available Memory: $($perfMetrics.Memory.AvailableMB) MB" -ForegroundColor White
        Write-Host "Disk Queue Length: $($perfMetrics.Disk.QueueLength)" -ForegroundColor $(if ($perfMetrics.Disk.QueueLength -gt 5) { "Red" } elseif ($perfMetrics.Disk.QueueLength -gt 2) { "Yellow" } else { "Green" })
        Write-Host "Free Disk Space: $($perfMetrics.Disk.FreeSpaceGB) GB" -ForegroundColor $(if ($perfMetrics.Disk.FreeSpaceGB -lt 10) { "Red" } elseif ($perfMetrics.Disk.FreeSpaceGB -lt 50) { "Yellow" } else { "Green" })
        
        # Performance recommendations
        $recommendations = @()
        
        if ($perfMetrics.CPU.ProcessorTime -gt 80) {
            $recommendations += "High CPU usage detected. Consider CPU upgrade or load balancing."
        }
        
        if ($perfMetrics.Memory.UsedPercentage -gt 85) {
            $recommendations += "High memory usage detected. Consider memory upgrade or optimization."
        }
        
        if ($perfMetrics.Disk.QueueLength -gt 5) {
            $recommendations += "High disk queue length detected. Consider SSD upgrade or disk optimization."
        }
        
        if ($perfMetrics.Disk.FreeSpaceGB -lt 10) {
            $recommendations += "Low disk space detected. Consider disk expansion or cleanup."
        }
        
        if ($recommendations.Count -gt 0) {
            Write-Host "`nPerformance Recommendations:" -ForegroundColor Yellow
            foreach ($recommendation in $recommendations) {
                Write-Host "  - $recommendation" -ForegroundColor Yellow
            }
        }
        
        Write-TroubleshootingLog "Performance troubleshooting completed" "Success"
        return $perfMetrics
    }
    catch {
        Write-TroubleshootingLog "Failed to troubleshoot performance: $($_.Exception.Message)" "Error"
        throw
    }
}

function Save-TroubleshootingReport {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    
    Write-TroubleshootingLog "Saving troubleshooting report..." "Info"
    
    try {
        $reportPath = "C:\HGS-Troubleshooting\Reports\HGS-Troubleshooting-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        
        # Create report directory
        $reportDir = Split-Path $reportPath -Parent
        if (!(Test-Path $reportDir)) {
            New-Item -Path $reportDir -ItemType Directory -Force
        }
        
        $troubleshootingReport = @{
            TroubleshootingInfo = @{
                HgsServer = $Config.HgsServer
                StartTime = $script:TroubleshootingStartTime
                EndTime = Get-Date
                Duration = (Get-Date) - $script:TroubleshootingStartTime
                DiagnosticLevel = $Config.DiagnosticLevel
                AnalysisType = $Config.AnalysisType
                TestType = $Config.TestType
                IssueType = $Config.IssueType
                Severity = $Config.Severity
                Configuration = $Config
            }
            TroubleshootingLog = $script:TroubleshootingLog
            CurrentStatus = Get-HGSStatus -HgsServer $Config.HgsServer
            HealthStatus = Get-HGSHealthStatus -HgsServer $Config.HgsServer -IncludeDetails
            PerformanceMetrics = Get-HGSPerformanceMetrics -HgsServer $Config.HgsServer -MetricType "All"
            Alerts = Get-HGSAlerts -HgsServer $Config.HgsServer -Severity "All" -TimeRange 24
            Recommendations = @(
                "Regular health monitoring",
                "Proactive performance tuning",
                "Event log analysis",
                "Configuration validation",
                "Automated repair procedures",
                "Documentation of issues and solutions",
                "Staff training on troubleshooting procedures",
                "Regular troubleshooting reviews"
            )
        }
        
        $troubleshootingReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8
        
        Write-TroubleshootingLog "Troubleshooting report saved to: $reportPath" "Success"
        return $reportPath
    }
    catch {
        Write-TroubleshootingLog "Failed to save troubleshooting report: $($_.Exception.Message)" "Error"
        return $null
    }
}

# Main troubleshooting logic
try {
    Write-TroubleshootingLog "Starting HGS troubleshooting..." "Info"
    Write-TroubleshootingLog "Server: $HgsServer" "Info"
    Write-TroubleshootingLog "Diagnostic Level: $DiagnosticLevel" "Info"
    Write-TroubleshootingLog "Analysis Type: $AnalysisType" "Info"
    
    # Build troubleshooting configuration
    $script:TroubleshootingConfig = @{
        HgsServer = $HgsServer
        DiagnosticLevel = $DiagnosticLevel
        IncludePerformance = $IncludePerformance
        RepairType = $RepairType
        AnalysisType = $AnalysisType
        TimeRange = $TimeRange
        TestType = $TestType
        IssueType = $IssueType
        Severity = $Severity
        AutoRepair = $AutoRepair
        Force = $Force
    }
    
    # Confirm troubleshooting operations
    if (!$Force) {
        Write-Host "`nHGS Troubleshooting Operations:" -ForegroundColor Cyan
        Write-Host "Server Name: $($script:TroubleshootingConfig.HgsServer)" -ForegroundColor White
        Write-Host "Diagnostic Level: $($script:TroubleshootingConfig.DiagnosticLevel)" -ForegroundColor White
        Write-Host "Analysis Type: $($script:TroubleshootingConfig.AnalysisType)" -ForegroundColor White
        Write-Host "Test Type: $($script:TroubleshootingConfig.TestType)" -ForegroundColor White
        Write-Host "Issue Type: $($script:TroubleshootingConfig.IssueType)" -ForegroundColor White
        Write-Host "Severity: $($script:TroubleshootingConfig.Severity)" -ForegroundColor White
        Write-Host "Auto Repair: $($script:TroubleshootingConfig.AutoRepair)" -ForegroundColor White
        Write-Host "Repair Type: $($script:TroubleshootingConfig.RepairType)" -ForegroundColor White
        
        $confirmation = Read-Host "`nDo you want to proceed with HGS troubleshooting? (Y/N)"
        if ($confirmation -notmatch "^[Yy]") {
            Write-TroubleshootingLog "Troubleshooting cancelled by user" "Warning"
            exit 0
        }
    }
    
    # Execute troubleshooting steps
    $diagnostics = Start-HGSDiagnostics -Config $script:TroubleshootingConfig
    $eventAnalysis = Start-HGSEventAnalysis -Config $script:TroubleshootingConfig
    $configTest = Start-HGSConfigurationTesting -Config $script:TroubleshootingConfig
    $repairResult = Start-HGSRepairOperations -Config $script:TroubleshootingConfig
    $guidance = Get-HGSTroubleshootingGuidance -Config $script:TroubleshootingConfig
    Write-TroubleshootingLog "Troubleshooting guidance retrieved for $($guidance.IssueType) issues" "Info"
    
    if ($IncludePerformance) {
        $perfMetrics = Start-HGSPerformanceTroubleshooting -Config $script:TroubleshootingConfig
    }
    
    # Save troubleshooting report
    $reportPath = Save-TroubleshootingReport -Config $script:TroubleshootingConfig
    
    # Final status
    Write-TroubleshootingLog "HGS troubleshooting completed successfully!" "Success"
    Write-Host "`nTroubleshooting Summary:" -ForegroundColor Green
    Write-Host "✓ Diagnostics completed" -ForegroundColor Green
    Write-Host "✓ Event analysis completed" -ForegroundColor Green
    Write-Host "✓ Configuration testing completed" -ForegroundColor Green
    Write-Host "✓ Troubleshooting guidance provided" -ForegroundColor Green
    if ($IncludePerformance) {
        Write-Host "✓ Performance troubleshooting completed" -ForegroundColor Green
    }
    if ($RepairType) {
        Write-Host "✓ Repair operations completed" -ForegroundColor Green
    }
    Write-Host "✓ Troubleshooting report generated" -ForegroundColor Green
    Write-Host "`nTroubleshooting report saved to: $reportPath" -ForegroundColor Cyan
    
    # Display overall health status
    $overallHealth = $diagnostics.OverallHealth
    Write-Host "`nOverall HGS Health: $overallHealth" -ForegroundColor $(if ($overallHealth -eq "Healthy") { "Green" } else { "Red" })
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Review the troubleshooting report" -ForegroundColor White
    Write-Host "2. Address any identified issues" -ForegroundColor White
    Write-Host "3. Implement recommended solutions" -ForegroundColor White
    Write-Host "4. Monitor HGS services after repairs" -ForegroundColor White
    Write-Host "5. Document troubleshooting procedures" -ForegroundColor White
    Write-Host "6. Schedule regular health checks" -ForegroundColor White
    Write-Host "7. Train staff on troubleshooting procedures" -ForegroundColor White
    
}
catch {
    Write-TroubleshootingLog "HGS troubleshooting failed: $($_.Exception.Message)" "Error"
    Write-Host "`nTroubleshooting failed. Please check the error messages above and resolve the issues." -ForegroundColor Red
    exit 1
}
