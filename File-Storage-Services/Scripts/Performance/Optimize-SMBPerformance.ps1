#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    SMB Performance Tuning Script

.DESCRIPTION
    This script provides comprehensive SMB performance tuning capabilities based on
    Microsoft's official performance tuning guidelines for file servers.

.PARAMETER Action
    The action to perform (GetSettings, Optimize, TestCompliance, GenerateReport, OptimizeHighLatency, OptimizeEnterprise)

.PARAMETER OptimizationLevel
    Level of optimization (Basic, HighLatency, Enterprise, Custom)

.PARAMETER CustomSettings
    Custom settings hashtable for Custom optimization level

.PARAMETER OutputPath
    Path to save reports

.PARAMETER IncludeRecommendations
    Include optimization recommendations in reports

.PARAMETER RestartRequired
    Whether a restart is required for changes to take effect

.EXAMPLE
    .\Optimize-SMBPerformance.ps1 -Action GetSettings

.EXAMPLE
    .\Optimize-SMBPerformance.ps1 -Action Optimize -OptimizationLevel "HighLatency"

.EXAMPLE
    .\Optimize-SMBPerformance.ps1 -Action TestCompliance -OptimizationLevel "Enterprise"

.EXAMPLE
    .\Optimize-SMBPerformance.ps1 -Action GenerateReport -OutputPath "C:\Reports\SMB-Performance.html"

.EXAMPLE
    .\Optimize-SMBPerformance.ps1 -Action OptimizeHighLatency

.NOTES
    Author: File and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/role/file-server/
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("GetSettings", "Optimize", "TestCompliance", "GenerateReport", "OptimizeHighLatency", "OptimizeEnterprise")]
    [string]$Action,
    
    [ValidateSet("Basic", "HighLatency", "Enterprise", "Custom")]
    [string]$OptimizationLevel = "HighLatency",
    
    [hashtable]$CustomSettings,
    
    [string]$OutputPath,
    
    [switch]$IncludeRecommendations,
    
    [switch]$RestartRequired
)

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "FileStorage-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "SMB-Performance.psm1") -Force
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Script variables
$script:SMBLog = @()
$script:StartTime = Get-Date

function Write-SMBLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:SMBLog += $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function Get-SMBSettings {
    Write-SMBLog "Getting SMB performance settings..." "INFO"
    
    try {
        $settings = Get-SMBPerformanceSettings
        
        if ($settings) {
            Write-Host "`n=== SMB Performance Settings ===" -ForegroundColor Cyan
            Write-Host "Computer: $($settings.ComputerName)" -ForegroundColor White
            Write-Host "Timestamp: $($settings.Timestamp)" -ForegroundColor White
            
            Write-Host "`nRegistry Settings:" -ForegroundColor Yellow
            foreach ($setting in $settings.RegistrySettings.GetEnumerator()) {
                Write-Host "  $($setting.Key): $($setting.Value)" -ForegroundColor White
            }
            
            if ($settings.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                foreach ($recommendation in $settings.Recommendations) {
                    Write-Host "  - $recommendation" -ForegroundColor Green
                }
            }
            
            Write-SMBLog "SMB settings retrieved successfully" "SUCCESS"
        }
        
        return $settings
        
    } catch {
        Write-SMBLog "Error getting SMB settings: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Optimize-SMBSettings {
    param(
        [string]$Level,
        [hashtable]$Custom
    )
    
    Write-SMBLog "Optimizing SMB settings with level: $Level" "INFO"
    
    try {
        $optimizationResult = Set-SMBPerformanceOptimization -OptimizationLevel $Level -CustomSettings $Custom -RestartRequired:$RestartRequired
        
        if ($optimizationResult) {
            Write-Host "`n=== SMB Optimization Results ===" -ForegroundColor Cyan
            Write-Host "Optimization Level: $($optimizationResult.OptimizationLevel)" -ForegroundColor White
            Write-Host "Settings Applied: $($optimizationResult.SettingsApplied.Count)" -ForegroundColor White
            Write-Host "Errors: $($optimizationResult.Errors.Count)" -ForegroundColor White
            Write-Host "Restart Required: $($optimizationResult.RestartRequired)" -ForegroundColor White
            
            if ($optimizationResult.SettingsApplied.Count -gt 0) {
                Write-Host "`nApplied Settings:" -ForegroundColor Yellow
                foreach ($setting in $optimizationResult.SettingsApplied.GetEnumerator()) {
                    Write-Host "  $($setting.Key): $($setting.Value)" -ForegroundColor Green
                }
            }
            
            if ($optimizationResult.Errors.Count -gt 0) {
                Write-Host "`nErrors:" -ForegroundColor Yellow
                foreach ($errorItem in $optimizationResult.Errors) {
                    Write-Host "  $errorItem" -ForegroundColor Red
                }
            }
            
            if ($optimizationResult.RestartRequired) {
                Write-Host "`nRestart Required: Please restart the server for optimal performance" -ForegroundColor Yellow
            }
            
            Write-SMBLog "SMB optimization completed successfully" "SUCCESS"
        }
        
        return $optimizationResult
        
    } catch {
        Write-SMBLog "Error optimizing SMB settings: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Test-SMBCompliance {
    param([string]$Level)
    
    Write-SMBLog "Testing SMB compliance against $Level recommendations..." "INFO"
    
    try {
        $complianceResult = Test-SMBPerformanceSettings -OptimizationLevel $Level
        
        if ($complianceResult) {
            Write-Host "`n=== SMB Compliance Test Results ===" -ForegroundColor Cyan
            Write-Host "Optimization Level: $($complianceResult.OptimizationLevel)" -ForegroundColor White
            Write-Host "Computer: $($complianceResult.ComputerName)" -ForegroundColor White
            Write-Host "Timestamp: $($complianceResult.Timestamp)" -ForegroundColor White
            
            $compliantCount = ($complianceResult.Compliance.Values | Where-Object { $_ -eq "Compliant" }).Count
            $totalCount = $complianceResult.Compliance.Count
            
            Write-Host "`nCompliance Summary:" -ForegroundColor Yellow
            Write-Host "  Compliant: $compliantCount/$totalCount" -ForegroundColor Green
            Write-Host "  Non-Compliant: $($totalCount - $compliantCount)/$totalCount" -ForegroundColor Red
            
            Write-Host "`nCompliance Details:" -ForegroundColor Yellow
            foreach ($setting in $complianceResult.Compliance.GetEnumerator()) {
                $statusColor = if ($setting.Value -eq "Compliant") { "Green" } else { "Red" }
                Write-Host "  $($setting.Key): $($setting.Value)" -ForegroundColor $statusColor
            }
            
            if ($complianceResult.Issues.Count -gt 0) {
                Write-Host "`nIssues Found:" -ForegroundColor Yellow
                foreach ($issue in $complianceResult.Issues) {
                    Write-Host "  - $issue" -ForegroundColor Red
                }
            }
            
            if ($complianceResult.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                foreach ($recommendation in $complianceResult.Recommendations) {
                    Write-Host "  - $recommendation" -ForegroundColor Green
                }
            }
            
            Write-SMBLog "SMB compliance test completed successfully" "SUCCESS"
        }
        
        return $complianceResult
        
    } catch {
        Write-SMBLog "Error testing SMB compliance: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function New-SMBReport {
    param(
        [string]$Path,
        [switch]$IncludeRecs
    )
    
    Write-SMBLog "Generating SMB performance report..." "INFO"
    
    try {
        if (-not $Path) {
            $Path = Join-Path $scriptPath "SMB-Performance-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        }
        
        $report = Get-SMBPerformanceReport -OutputPath $Path -IncludeRecommendations:$IncludeRecs
        
        if ($report) {
            Write-Host "`n=== SMB Performance Report Generated ===" -ForegroundColor Cyan
            Write-Host "Report Path: $Path" -ForegroundColor White
            Write-Host "Report Type: HTML" -ForegroundColor White
            Write-Host "Computer: $($report.ComputerName)" -ForegroundColor White
            Write-Host "Timestamp: $($report.Timestamp)" -ForegroundColor White
            
            Write-Host "`nSummary:" -ForegroundColor Yellow
            Write-Host "  Total Settings: $($report.Summary.TotalSettings)" -ForegroundColor White
            Write-Host "  Basic Compliant: $($report.Summary.BasicCompliant)" -ForegroundColor White
            Write-Host "  High Latency Compliant: $($report.Summary.HighLatencyCompliant)" -ForegroundColor White
            Write-Host "  Enterprise Compliant: $($report.Summary.EnterpriseCompliant)" -ForegroundColor White
            
            Write-SMBLog "SMB performance report generated successfully" "SUCCESS"
        }
        
        return $report
        
    } catch {
        Write-SMBLog "Error generating SMB report: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Optimize-SMBHighLatency {
    Write-SMBLog "Optimizing SMB for high-latency networks..." "INFO"
    
    try {
        $result = Optimize-SMBForHighLatency
        
        if ($result) {
            Write-Host "`n=== High-Latency Optimization Results ===" -ForegroundColor Cyan
            Write-Host "Settings Applied: $($result.SettingsApplied.Count)" -ForegroundColor White
            Write-Host "Errors: $($result.Errors.Count)" -ForegroundColor White
            
            if ($result.SettingsApplied.Count -gt 0) {
                Write-Host "`nApplied Settings:" -ForegroundColor Yellow
                foreach ($setting in $result.SettingsApplied.GetEnumerator()) {
                    Write-Host "  $($setting.Key): $($setting.Value)" -ForegroundColor Green
                }
            }
            
            Write-SMBLog "High-latency optimization completed successfully" "SUCCESS"
        }
        
        return $result
        
    } catch {
        Write-SMBLog "Error optimizing SMB for high-latency: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Optimize-SMBEnterprise {
    Write-SMBLog "Optimizing SMB for enterprise environment..." "INFO"
    
    try {
        $result = Optimize-SMBForEnterprise
        
        if ($result) {
            Write-Host "`n=== Enterprise Optimization Results ===" -ForegroundColor Cyan
            Write-Host "Settings Applied: $($result.SettingsApplied.Count)" -ForegroundColor White
            Write-Host "Errors: $($result.Errors.Count)" -ForegroundColor White
            Write-Host "Restart Required: $($result.RestartRequired)" -ForegroundColor White
            
            if ($result.SettingsApplied.Count -gt 0) {
                Write-Host "`nApplied Settings:" -ForegroundColor Yellow
                foreach ($setting in $result.SettingsApplied.GetEnumerator()) {
                    Write-Host "  $($setting.Key): $($setting.Value)" -ForegroundColor Green
                }
            }
            
            if ($result.RestartRequired) {
                Write-Host "`nRestart Required: Please restart the server for optimal performance" -ForegroundColor Yellow
            }
            
            Write-SMBLog "Enterprise optimization completed successfully" "SUCCESS"
        }
        
        return $result
        
    } catch {
        Write-SMBLog "Error optimizing SMB for enterprise: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Save-SMBLog {
    $logPath = Join-Path $scriptPath "SMB-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    try {
        $script:SMBLog | Out-File -FilePath $logPath -Encoding UTF8
        Write-SMBLog "SMB log saved to: $logPath" "INFO"
    } catch {
        Write-Warning "Failed to save SMB log: $($_.Exception.Message)"
    }
}

# Main SMB performance tuning process
try {
    Write-SMBLog "Starting SMB performance tuning..." "INFO"
    Write-SMBLog "Action: $Action" "INFO"
    
    switch ($Action) {
        "GetSettings" {
            $settings = Get-SMBSettings
        }
        
        "Optimize" {
            $result = Optimize-SMBSettings -Level $OptimizationLevel -Custom $CustomSettings
        }
        
        "TestCompliance" {
            Test-SMBCompliance -Level $OptimizationLevel
        }
        
        "GenerateReport" {
            $report = New-SMBReport -Path $OutputPath -IncludeRecs:$IncludeRecommendations
        }
        
        "OptimizeHighLatency" {
            $result = Optimize-SMBHighLatency
        }
        
        "OptimizeEnterprise" {
            $result = Optimize-SMBEnterprise
        }
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-SMBLog "SMB performance tuning completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== SMB Performance Tuning Summary ===" -ForegroundColor Cyan
    Write-Host "Action: $Action" -ForegroundColor White
    Write-Host "Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    
    # Save SMB log
    Save-SMBLog
    
    Write-Host "`nSMB performance tuning completed successfully!" -ForegroundColor Green
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-SMBLog "SMB performance tuning failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save SMB log
    Save-SMBLog
    
    Write-Host "`nSMB performance tuning failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the SMB log for details." -ForegroundColor Yellow
    
    exit 1
}
