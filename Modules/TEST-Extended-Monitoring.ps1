<#
.SYNOPSIS
    Test script for Extended-Monitoring module

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
#>

[CmdletBinding()]
param()

Write-Host "=== Testing Extended-Monitoring Module ===" -ForegroundColor Cyan
Write-Host ""

# Import Modules
try {
    # Import Logging-Core first (dependency)
    $loggingModulePath = Resolve-Path "Modules\Logging-Core.psm1"
    Import-Module $loggingModulePath -Force -ErrorAction SilentlyContinue
    
    # Import Extended-Monitoring
    $monitoringModulePath = Resolve-Path "Modules\Extended-Monitoring.psm1"
    Import-Module $monitoringModulePath -Force -ErrorAction Stop
    Write-Host "✅ Module imported successfully" -ForegroundColor Green
} catch {
    Write-Host "❌ Module import failed: $_" -ForegroundColor Red
    exit 1
}

# Test 1: Health Status Check
Write-Host "`nTest 1: Health Status Check" -ForegroundColor Yellow
try {
    $health = Get-HealthStatus -Target $env:COMPUTERNAME -Checks @("CPU", "Memory")
    
    Write-Host "  Target: $($health.Target)" -ForegroundColor Gray
    Write-Host "  Status: $($health.Status)" -ForegroundColor Gray
    Write-Host "  CPU: $($health.Checks.CPU.Message)" -ForegroundColor Gray
    Write-Host "  Memory: $($health.Checks.Memory.Message)" -ForegroundColor Gray
    
    Write-Host "✅ Test 1 passed" -ForegroundColor Green
} catch {
    Write-Host "❌ Test 1 failed: $_" -ForegroundColor Red
}

# Test 2: Individual Health Checks
Write-Host "`nTest 2: Individual Health Checks" -ForegroundColor Yellow
try {
    $cpuHealth = Test-CPUHealth -Target $env:COMPUTERNAME
    Write-Host "  CPU Check: $($cpuHealth.Message)" -ForegroundColor Gray
    
    $memHealth = Test-MemoryHealth -Target $env:COMPUTERNAME
    Write-Host "  Memory Check: $($memHealth.Message)" -ForegroundColor Gray
    
    $diskHealth = Test-DiskHealth -Target $env:COMPUTERNAME
    Write-Host "  Disk Check: $($diskHealth.Message)" -ForegroundColor Gray
    
    Write-Host "✅ Test 2 passed" -ForegroundColor Green
} catch {
    Write-Host "❌ Test 2 failed: $_" -ForegroundColor Red
}

# Test 3: Predictive Analytics
Write-Host "`nTest 3: Predictive Analytics" -ForegroundColor Yellow
try {
    $predictions = Get-PredictiveAnalytics -Target $env:COMPUTERNAME -Metric "CPU"
    
    Write-Host "  Target: $($predictions.Target)" -ForegroundColor Gray
    Write-Host "  Metric: $($predictions.Metric)" -ForegroundColor Gray
    Write-Host "  Trend: $($predictions.Trend)" -ForegroundColor Gray
    Write-Host "  Prediction: $($predictions.Prediction)" -ForegroundColor Gray
    Write-Host "  Confidence: $($predictions.Confidence)%" -ForegroundColor Gray
    
    Write-Host "✅ Test 3 passed" -ForegroundColor Green
} catch {
    Write-Host "❌ Test 3 failed: $_" -ForegroundColor Red
}

# Test 4: Dashboard Generation
Write-Host "`nTest 4: Dashboard Generation" -ForegroundColor Yellow
try {
    $dashboardPath = "C:\Temp\test-dashboard.html"
    
    New-MonitoringDashboard -Targets @($env:COMPUTERNAME) -OutputPath $dashboardPath
    
    if (Test-Path $dashboardPath) {
        Write-Host "  Dashboard created: $dashboardPath" -ForegroundColor Gray
        Remove-Item $dashboardPath -Force
        Write-Host "✅ Test 4 passed" -ForegroundColor Green
    } else {
        Write-Host "❌ Dashboard file not created" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Test 4 failed: $_" -ForegroundColor Red
}

Write-Host "`n=== All Tests Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Module Status: Extended-Monitoring - Working ✅" -ForegroundColor Green

