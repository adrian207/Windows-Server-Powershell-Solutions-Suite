<#
.SYNOPSIS
    Test script for Performance-Monitoring module

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
#>

[CmdletBinding()]
param()

Write-Host "=== Testing Performance-Monitoring Module ===" -ForegroundColor Cyan
Write-Host ""

# Import Modules
try {
    # Import Logging-Core first (dependency)
    $loggingModulePath = Resolve-Path "Modules\Logging-Core.psm1"
    Import-Module $loggingModulePath -Force -ErrorAction SilentlyContinue
    
    # Import Performance-Monitoring
    $perfModulePath = Resolve-Path "Modules\Performance-Monitoring.psm1"
    Import-Module $perfModulePath -Force -ErrorAction Stop
    Write-Host "✅ Module imported successfully" -ForegroundColor Green
} catch {
    Write-Host "❌ Module import failed: $_" -ForegroundColor Red
    exit 1
}

# Test 1: Basic Performance Monitoring
Write-Host "`nTest 1: Basic Performance Monitoring" -ForegroundColor Yellow
try {
    $result = Start-PerformanceMonitor -ScriptBlock {
        Get-Process | Where-Object { $_.CPU -gt 10 } | Select-Object -First 5
    } -OperationName "GetHighCPUProcesses"
    
    Write-Host "  Execution Time: $($result.Metrics.ExecutionTime) ms" -ForegroundColor Gray
    Write-Host "  Memory Delta: $([math]::Round($result.Metrics.MemoryDelta/1MB, 2)) MB" -ForegroundColor Gray
    Write-Host "✅ Test 1 passed" -ForegroundColor Green
} catch {
    Write-Host "❌ Test 1 failed: $_" -ForegroundColor Red
}

# Test 2: Performance Summary
Write-Host "`nTest 2: Performance Summary" -ForegroundColor Yellow
try {
    # Create PSObject metrics for proper Measure-Object support
    $metrics = @(
        [PSCustomObject]@{ ExecutionTime = 100; MemoryDelta = 10MB }
        [PSCustomObject]@{ ExecutionTime = 150; MemoryDelta = 15MB }
        [PSCustomObject]@{ ExecutionTime = 120; MemoryDelta = 12MB }
    )
    
    $summary = Get-PerformanceSummary -Metrics $metrics
    Write-Host "  Average Time: $([math]::Round($summary.AverageExecutionTime, 2)) ms" -ForegroundColor Gray
    Write-Host "  Average Memory: $([math]::Round($summary.AverageMemoryMB, 2)) MB" -ForegroundColor Gray
    Write-Host "✅ Test 2 passed" -ForegroundColor Green
} catch {
    Write-Host "❌ Test 2 failed: $_" -ForegroundColor Red
}

# Test 3: Optimization Recommendations
Write-Host "`nTest 3: Optimization Recommendations" -ForegroundColor Yellow
try {
    $summary = @{
        AverageExecutionTime = 6000
        PeakMemoryMB = 600
        TotalMemoryMB = 1200
        MaxExecutionTime = 8000
        MinExecutionTime = 3000
    }
    
    $recommendations = Get-OptimizationRecommendations -Summary $summary
    Write-Host "  Recommendations: $($recommendations.Count)" -ForegroundColor Gray
    foreach ($rec in $recommendations) {
        Write-Host "    • $rec" -ForegroundColor Gray
    }
    Write-Host "✅ Test 3 passed" -ForegroundColor Green
} catch {
    Write-Host "❌ Test 3 failed: $_" -ForegroundColor Red
}

Write-Host "`n=== All Tests Complete ===" -ForegroundColor Green

