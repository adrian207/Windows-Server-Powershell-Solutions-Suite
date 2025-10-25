#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    SMB Performance Optimization Example Script

.DESCRIPTION
    This example script demonstrates how to optimize SMB performance settings
    based on Microsoft's official performance tuning guidelines for file servers.

.EXAMPLE
    .\Example-OptimizeSMBPerformance.ps1

.NOTES
    Author: File and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/role/file-server/
#>

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

Write-Host "=== SMB Performance Optimization Example ===" -ForegroundColor Cyan
Write-Host "This example demonstrates SMB performance optimization based on Microsoft guidelines" -ForegroundColor White

try {
    # Step 1: Get current SMB settings
    Write-Host "`nStep 1: Getting current SMB performance settings..." -ForegroundColor Yellow
    $currentSettings = Get-SMBPerformanceSettings
    if ($currentSettings) {
        Write-Host "Current settings retrieved successfully" -ForegroundColor Green
        Write-Host "Computer: $($currentSettings.ComputerName)" -ForegroundColor White
        Write-Host "Registry settings count: $($currentSettings.RegistrySettings.Count)" -ForegroundColor White
    } else {
        Write-Host "Failed to retrieve current settings" -ForegroundColor Red
        exit 1
    }
    
    # Step 2: Test compliance against different optimization levels
    Write-Host "`nStep 2: Testing compliance against optimization levels..." -ForegroundColor Yellow
    
    $basicCompliance = Test-SMBPerformanceSettings -OptimizationLevel "Basic"
    $highLatencyCompliance = Test-SMBPerformanceSettings -OptimizationLevel "HighLatency"
    $enterpriseCompliance = Test-SMBPerformanceSettings -OptimizationLevel "Enterprise"
    
    Write-Host "Compliance test results:" -ForegroundColor Green
    Write-Host "  Basic: $($basicCompliance.Compliance.Values | Where-Object { $_ -eq 'Compliant' }).Count/$($basicCompliance.Compliance.Count) compliant" -ForegroundColor White
    Write-Host "  High Latency: $($highLatencyCompliance.Compliance.Values | Where-Object { $_ -eq 'Compliant' }).Count/$($highLatencyCompliance.Compliance.Count) compliant" -ForegroundColor White
    Write-Host "  Enterprise: $($enterpriseCompliance.Compliance.Values | Where-Object { $_ -eq 'Compliant' }).Count/$($enterpriseCompliance.Compliance.Count) compliant" -ForegroundColor White
    
    # Step 3: Apply high-latency optimization (Microsoft recommended for branch offices)
    Write-Host "`nStep 3: Applying high-latency optimization..." -ForegroundColor Yellow
    $highLatencyResult = Optimize-SMBForHighLatency
    if ($highLatencyResult) {
        Write-Host "High-latency optimization applied successfully" -ForegroundColor Green
        Write-Host "Settings applied: $($highLatencyResult.SettingsApplied.Count)" -ForegroundColor White
        Write-Host "Errors: $($highLatencyResult.Errors.Count)" -ForegroundColor White
    } else {
        Write-Host "High-latency optimization failed" -ForegroundColor Red
    }
    
    # Step 4: Demonstrate enterprise optimization
    Write-Host "`nStep 4: Demonstrating enterprise optimization..." -ForegroundColor Yellow
    $enterpriseResult = Set-SMBPerformanceOptimization -OptimizationLevel "Enterprise"
    if ($enterpriseResult) {
        Write-Host "Enterprise optimization applied successfully" -ForegroundColor Green
        Write-Host "Settings applied: $($enterpriseResult.SettingsApplied.Count)" -ForegroundColor White
        Write-Host "Restart required: $($enterpriseResult.RestartRequired)" -ForegroundColor White
    } else {
        Write-Host "Enterprise optimization failed" -ForegroundColor Red
    }
    
    # Step 5: Generate comprehensive report
    Write-Host "`nStep 5: Generating comprehensive SMB performance report..." -ForegroundColor Yellow
    $reportPath = Join-Path $scriptPath "SMB-Performance-Example-Report.html"
    $report = Get-SMBPerformanceReport -OutputPath $reportPath -IncludeRecommendations
    if ($report) {
        Write-Host "Report generated successfully: $reportPath" -ForegroundColor Green
        Write-Host "Report summary:" -ForegroundColor White
        Write-Host "  Total settings: $($report.Summary.TotalSettings)" -ForegroundColor White
        Write-Host "  Basic compliant: $($report.Summary.BasicCompliant)" -ForegroundColor White
        Write-Host "  High latency compliant: $($report.Summary.HighLatencyCompliant)" -ForegroundColor White
        Write-Host "  Enterprise compliant: $($report.Summary.EnterpriseCompliant)" -ForegroundColor White
    } else {
        Write-Host "Report generation failed" -ForegroundColor Red
    }
    
    # Step 6: Demonstrate custom optimization
    Write-Host "`nStep 6: Demonstrating custom optimization..." -ForegroundColor Yellow
    $customSettings = @{
        DisableBandwidthThrottling = 1
        FileInfoCacheEntriesMax = 16384
        DirectoryCacheEntriesMax = 2048
        MaxCmds = 16384
    }
    
    $customResult = Set-SMBPerformanceOptimization -OptimizationLevel "Custom" -CustomSettings $customSettings
    if ($customResult) {
        Write-Host "Custom optimization applied successfully" -ForegroundColor Green
        Write-Host "Custom settings applied:" -ForegroundColor White
        foreach ($setting in $customResult.SettingsApplied.GetEnumerator()) {
            Write-Host "  $($setting.Key): $($setting.Value)" -ForegroundColor White
        }
    } else {
        Write-Host "Custom optimization failed" -ForegroundColor Red
    }
    
    # Step 7: Show Microsoft-recommended settings for different scenarios
    Write-Host "`nStep 7: Microsoft-recommended settings for different scenarios..." -ForegroundColor Yellow
    
    Write-Host "`nHigh-Latency Network Settings (Branch offices, cross-datacenter, mobile broadband):" -ForegroundColor Cyan
    Write-Host "  DisableBandwidthThrottling: 1 (default: 0)" -ForegroundColor White
    Write-Host "  FileInfoCacheEntriesMax: 32768 (default: 64)" -ForegroundColor White
    Write-Host "  DirectoryCacheEntriesMax: 4096 (default: 16)" -ForegroundColor White
    Write-Host "  FileNotFoundCacheEntriesMax: 32768 (default: 128)" -ForegroundColor White
    Write-Host "  MaxCmds: 32768 (default: 15)" -ForegroundColor White
    
    Write-Host "`nEnterprise Settings (High throughput, multiple interfaces):" -ForegroundColor Cyan
    Write-Host "  DisableBandwidthThrottling: 1" -ForegroundColor White
    Write-Host "  FileInfoCacheEntriesMax: 65536" -ForegroundColor White
    Write-Host "  DirectoryCacheEntriesMax: 4096" -ForegroundColor White
    Write-Host "  FileNotFoundCacheEntriesMax: 65536" -ForegroundColor White
    Write-Host "  MaxCmds: 32768" -ForegroundColor White
    Write-Host "  ConnectionCountPerNetworkInterface: 4" -ForegroundColor White
    Write-Host "  ConnectionCountPerRssNetworkInterface: 8" -ForegroundColor White
    Write-Host "  MaximumConnectionCountPerServer: 64" -ForegroundColor White
    
    Write-Host "`nSecurity Considerations:" -ForegroundColor Cyan
    Write-Host "  RequireSecuritySignature: 0 (default) - Set to 1 for enhanced security" -ForegroundColor White
    Write-Host "  Note: SMB signing increases CPU cost and network round trips" -ForegroundColor Yellow
    
    # Step 8: PowerShell cmdlet alternatives
    Write-Host "`nStep 8: PowerShell cmdlet alternatives..." -ForegroundColor Yellow
    Write-Host "Many SMB settings can also be configured using PowerShell cmdlets:" -ForegroundColor White
    Write-Host "  Set-SmbClientConfiguration -DisableBandwidthThrottling `$true" -ForegroundColor Green
    Write-Host "  Set-SmbServerConfiguration -RequireSecuritySignature `$true" -ForegroundColor Green
    Write-Host "  Set-SmbServerConfiguration -EncryptData `$true" -ForegroundColor Green
    
    Write-Host "`nSMB Performance Optimization Example completed successfully!" -ForegroundColor Green
    Write-Host "Check the generated report for detailed analysis: $reportPath" -ForegroundColor Yellow
    
} catch {
    Write-Host "`nSMB Performance Optimization Example failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
