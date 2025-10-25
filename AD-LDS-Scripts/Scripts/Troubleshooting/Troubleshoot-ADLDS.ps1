#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD LDS Troubleshooting and Diagnostics Script

.DESCRIPTION
    This script provides comprehensive troubleshooting and diagnostics for AD LDS instances
    including automated diagnostics, issue repair, and troubleshooting guidance.

.PARAMETER InstanceName
    Name of the AD LDS instance

.PARAMETER Action
    Action to perform (RunDiagnostics, RepairIssues, TestConfiguration, GetTroubleshootingGuide)

.PARAMETER DiagnosticLevel
    Level of diagnostics (Basic, Comprehensive, Deep)

.PARAMETER IncludeEventLogs
    Include event log analysis

.PARAMETER IncludeConnectivity
    Include connectivity tests

.PARAMETER IncludePerformance
    Include performance analysis

.PARAMETER RepairType
    Type of repair to perform (All, Service, Configuration, Partitions, Authentication, Permissions)

.PARAMETER EnableAutoRepair
    Enable automatic repair of common issues

.EXAMPLE
    .\Troubleshoot-ADLDS.ps1 -InstanceName "AppDirectory" -Action "RunDiagnostics" -DiagnosticLevel "Comprehensive"

.EXAMPLE
    .\Troubleshoot-ADLDS.ps1 -InstanceName "AppDirectory" -Action "RepairIssues" -RepairType "All" -EnableAutoRepair

.NOTES
    Author: AD LDS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$InstanceName,

    [Parameter(Mandatory = $true)]
    [ValidateSet("RunDiagnostics", "RepairIssues", "TestConfiguration", "GetTroubleshootingGuide")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Comprehensive", "Deep")]
    [string]$DiagnosticLevel = "Comprehensive",

    [Parameter(Mandatory = $false)]
    [switch]$IncludeEventLogs,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeConnectivity,

    [Parameter(Mandatory = $false)]
    [switch]$IncludePerformance,

    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Service", "Configuration", "Partitions", "Authentication", "Permissions")]
    [string]$RepairType = "All",

    [Parameter(Mandatory = $false)]
    [switch]$EnableAutoRepair,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\ADLDS\Troubleshooting"
)

# Script configuration
$scriptConfig = @{
    InstanceName = $InstanceName
    Action = $Action
    DiagnosticLevel = $DiagnosticLevel
    IncludeEventLogs = $IncludeEventLogs
    IncludeConnectivity = $IncludeConnectivity
    IncludePerformance = $IncludePerformance
    RepairType = $RepairType
    EnableAutoRepair = $EnableAutoRepair
    LogPath = $LogPath
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "AD LDS Troubleshooting and Diagnostics" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Instance: $InstanceName" -ForegroundColor Yellow
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Diagnostic Level: $DiagnosticLevel" -ForegroundColor Yellow
Write-Host "Include Event Logs: $IncludeEventLogs" -ForegroundColor Yellow
Write-Host "Include Connectivity: $IncludeConnectivity" -ForegroundColor Yellow
Write-Host "Include Performance: $IncludePerformance" -ForegroundColor Yellow
Write-Host "Repair Type: $RepairType" -ForegroundColor Yellow
Write-Host "Auto Repair: $EnableAutoRepair" -ForegroundColor Yellow
Write-Host "Computer: $($scriptConfig.ComputerName)" -ForegroundColor Yellow
Write-Host "Timestamp: $($scriptConfig.Timestamp)" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Import required modules
try {
    Import-Module "..\..\Modules\ADLDS-Core.psm1" -Force
    Import-Module "..\..\Modules\ADLDS-Troubleshooting.psm1" -Force
    Write-Host "AD LDS modules imported successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to import AD LDS modules: $($_.Exception.Message)"
    exit 1
}

# Create log directory
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force
}

switch ($Action) {
    "RunDiagnostics" {
        Write-Host "`nRunning AD LDS diagnostics for instance: $InstanceName" -ForegroundColor Green
        
        # Set diagnostic options based on level
        switch ($DiagnosticLevel) {
            "Basic" {
                $IncludeEventLogs = $false
                $IncludeConnectivity = $true
                $IncludePerformance = $false
            }
            "Comprehensive" {
                $IncludeEventLogs = $true
                $IncludeConnectivity = $true
                $IncludePerformance = $true
            }
            "Deep" {
                $IncludeEventLogs = $true
                $IncludeConnectivity = $true
                $IncludePerformance = $true
            }
        }
        
        $diagnosticsResult = Start-ADLDSDiagnostics -InstanceName $InstanceName -IncludeEventLogs:$IncludeEventLogs -IncludeConnectivity:$IncludeConnectivity -IncludePerformance:$IncludePerformance -LogPath $LogPath
        
        if ($diagnosticsResult.Success) {
            Write-Host "Diagnostics completed successfully!" -ForegroundColor Green
            
            # Display service health
            if ($diagnosticsResult.Diagnostics.ServiceHealth) {
                Write-Host "`nService Health:" -ForegroundColor Green
                Write-Host "  Service Running: $($diagnosticsResult.Diagnostics.ServiceHealth.ServiceRunning)" -ForegroundColor Cyan
                Write-Host "  Service Start Type: $($diagnosticsResult.Diagnostics.ServiceHealth.ServiceStartType)" -ForegroundColor Cyan
                Write-Host "  Instance Configuration: $($diagnosticsResult.Diagnostics.ServiceHealth.InstanceConfiguration)" -ForegroundColor Cyan
                Write-Host "  Partition Accessible: $($diagnosticsResult.Diagnostics.ServiceHealth.PartitionAccessible)" -ForegroundColor Cyan
                Write-Host "  Authentication Working: $($diagnosticsResult.Diagnostics.ServiceHealth.AuthenticationWorking)" -ForegroundColor Cyan
                
                if ($diagnosticsResult.Diagnostics.ServiceHealth.Issues.Count -gt 0) {
                    Write-Warning "Service Health Issues:"
                    foreach ($issue in $diagnosticsResult.Diagnostics.ServiceHealth.Issues) {
                        Write-Warning "  - $issue"
                    }
                }
            }
            
            # Display connectivity results
            if ($diagnosticsResult.Diagnostics.Connectivity) {
                Write-Host "`nConnectivity:" -ForegroundColor Green
                Write-Host "  Port Open: $($diagnosticsResult.Diagnostics.Connectivity.PortOpen)" -ForegroundColor Cyan
                Write-Host "  Service Listening: $($diagnosticsResult.Diagnostics.Connectivity.ServiceListening)" -ForegroundColor Cyan
                Write-Host "  LDAP Response: $($diagnosticsResult.Diagnostics.Connectivity.LDAPResponse)" -ForegroundColor Cyan
                
                if ($diagnosticsResult.Diagnostics.Connectivity.Issues.Count -gt 0) {
                    Write-Warning "Connectivity Issues:"
                    foreach ($issue in $diagnosticsResult.Diagnostics.Connectivity.Issues) {
                        Write-Warning "  - $issue"
                    }
                }
            }
            
            # Display issues found
            if ($diagnosticsResult.IssuesFound.Count -gt 0) {
                Write-Warning "`nIssues Found:"
                foreach ($issue in $diagnosticsResult.IssuesFound) {
                    Write-Warning "  - $issue"
                }
            }
            
            # Display recommendations
            if ($diagnosticsResult.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                foreach ($recommendation in $diagnosticsResult.Recommendations) {
                    Write-Host "  - $recommendation" -ForegroundColor Yellow
                }
            }
        } else {
            Write-Error "Failed to run diagnostics: $($diagnosticsResult.Error)"
        }
    }
    
    "RepairIssues" {
        Write-Host "`nRepairing AD LDS issues for instance: $InstanceName" -ForegroundColor Green
        
        $repairResult = Repair-ADLDSIssues -InstanceName $InstanceName -RepairType $RepairType -BackupPath "C:\ADLDS\Backup"
        
        if ($repairResult.Success) {
            Write-Host "Repair completed successfully!" -ForegroundColor Green
            Write-Host "  Repairs Performed: $($repairResult.RepairsPerformed.Count)" -ForegroundColor Cyan
            Write-Host "  Issues Fixed: $($repairResult.IssuesFixed.Count)" -ForegroundColor Cyan
            
            if ($repairResult.RepairsPerformed.Count -gt 0) {
                Write-Host "`nRepairs Performed:" -ForegroundColor Green
                foreach ($repair in $repairResult.RepairsPerformed) {
                    Write-Host "  - $repair" -ForegroundColor Cyan
                }
            }
            
            if ($repairResult.IssuesFixed.Count -gt 0) {
                Write-Host "`nIssues Fixed:" -ForegroundColor Green
                foreach ($issue in $repairResult.IssuesFixed) {
                    Write-Host "  - $issue" -ForegroundColor Cyan
                }
            }
        } else {
            Write-Error "Failed to repair issues: $($repairResult.Error)"
        }
    }
    
    "TestConfiguration" {
        Write-Host "`nTesting AD LDS configuration for instance: $InstanceName" -ForegroundColor Green
        
        $testResult = Test-ADLDSConfiguration -InstanceName $InstanceName
        
        if ($testResult.Success) {
            Write-Host "Configuration test completed!" -ForegroundColor Green
            Write-Host "  Configuration Valid: $($testResult.ConfigurationValid)" -ForegroundColor Cyan
            
            if ($testResult.IssuesFound.Count -gt 0) {
                Write-Warning "`nConfiguration Issues:"
                foreach ($issue in $testResult.IssuesFound) {
                    Write-Warning "  - $issue"
                }
            }
            
            if ($testResult.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                foreach ($recommendation in $testResult.Recommendations) {
                    Write-Host "  - $recommendation" -ForegroundColor Yellow
                }
            }
        } else {
            Write-Error "Failed to test configuration: $($testResult.Error)"
        }
    }
    
    "GetTroubleshootingGuide" {
        Write-Host "`nGetting AD LDS troubleshooting guide..." -ForegroundColor Green
        
        $guideResult = Get-ADLDSTroubleshootingGuide
        
        if ($guideResult.Success) {
            Write-Host "Troubleshooting Guide:" -ForegroundColor Green
            
            # Display common issues
            Write-Host "`nCommon Issues:" -ForegroundColor Green
            foreach ($issue in $guideResult.TroubleshootingGuide.CommonIssues.GetEnumerator()) {
                Write-Host "  $($issue.Key):" -ForegroundColor Cyan
                Write-Host "    Symptoms: $($issue.Value.Symptoms -join ', ')" -ForegroundColor White
                Write-Host "    Causes: $($issue.Value.Causes -join ', ')" -ForegroundColor White
                Write-Host "    Solutions: $($issue.Value.Solutions -join ', ')" -ForegroundColor White
            }
            
            # Display diagnostic steps
            Write-Host "`nDiagnostic Steps:" -ForegroundColor Green
            foreach ($step in $guideResult.TroubleshootingGuide.DiagnosticSteps) {
                Write-Host "  - $step" -ForegroundColor Cyan
            }
            
            # Display PowerShell commands
            Write-Host "`nPowerShell Commands:" -ForegroundColor Green
            foreach ($command in $guideResult.TroubleshootingGuide.PowerShellCommands.GetEnumerator()) {
                Write-Host "  $($command.Key): $($command.Value)" -ForegroundColor Cyan
            }
        } else {
            Write-Error "Failed to get troubleshooting guide: $($guideResult.Error)"
        }
    }
}

# Generate troubleshooting report
Write-Host "`nGenerating troubleshooting report..." -ForegroundColor Green

$troubleshootingReport = @{
    InstanceName = $InstanceName
    Action = $Action
    DiagnosticLevel = $DiagnosticLevel
    Timestamp = Get-Date
    Results = @{
        Diagnostics = if ($Action -eq "RunDiagnostics") { $diagnosticsResult } else { $null }
        Repair = if ($Action -eq "RepairIssues") { $repairResult } else { $null }
        ConfigurationTest = if ($Action -eq "TestConfiguration") { $testResult } else { $null }
        TroubleshootingGuide = if ($Action -eq "GetTroubleshootingGuide") { $guideResult } else { $null }
    }
}

$reportFile = Join-Path $LogPath "ADLDS-Troubleshooting-Report-$InstanceName-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
$troubleshootingReport | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "Troubleshooting report generated: $reportFile" -ForegroundColor Green

# Final summary
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "AD LDS Troubleshooting Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Instance: $InstanceName" -ForegroundColor Yellow
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Diagnostic Level: $DiagnosticLevel" -ForegroundColor Yellow
Write-Host "Status: Completed" -ForegroundColor Green
Write-Host "Report: $reportFile" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Review the troubleshooting report" -ForegroundColor White
Write-Host "2. Implement recommended fixes" -ForegroundColor White
Write-Host "3. Run diagnostics again to verify fixes" -ForegroundColor White
Write-Host "4. Monitor the instance for recurring issues" -ForegroundColor White
Write-Host "5. Document any custom solutions" -ForegroundColor White
Write-Host "6. Set up proactive monitoring to prevent issues" -ForegroundColor White
