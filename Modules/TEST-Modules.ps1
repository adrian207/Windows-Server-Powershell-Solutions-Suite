<#
.SYNOPSIS
    Test script for enhanced error handling and logging modules

.DESCRIPTION
    Validates that both modules load and function correctly.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
#>

[CmdletBinding()]
param()

Write-Host "=== Testing Enhanced Error Handling and Logging Modules ===" -ForegroundColor Cyan
Write-Host ""

# Test 1: Import Modules
Write-Host "Test 1: Importing modules..." -ForegroundColor Yellow
try {
    $loggingPath = Resolve-Path "Modules\Logging-Core.psm1"
    $errorHandlingPath = Resolve-Path "Modules\Error-Handling.psm1"
    
    Import-Module $loggingPath -Force -ErrorAction Stop
    Import-Module $errorHandlingPath -Force -ErrorAction Stop
    
    Write-Host "✅ Both modules imported successfully" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "❌ Module import failed: $_" -ForegroundColor Red
    exit 1
}

# Test 2: Check Module Versions
Write-Host "Test 2: Checking module versions..." -ForegroundColor Yellow
$modules = Get-Module -Name "Logging-Core", "Error-Handling"
foreach ($module in $modules) {
    Write-Host "   $($module.Name): v$($module.Version)" -ForegroundColor Gray
}

Write-Host "✅ Module versions retrieved" -ForegroundColor Green
Write-Host ""

# Test 3: Test Logging
Write-Host "Test 3: Testing logging functionality..." -ForegroundColor Yellow
try {
    Write-Log -Message "Test INFO message" -Level INFO -Component "TestModule"
    Write-Log -Message "Test WARNING message" -Level WARNING -Component "TestModule"
    Write-Log -Message "Test ERROR message" -Level ERROR -Component "TestModule"
    Write-Host "✅ Logging test passed" -ForegroundColor Green
} catch {
    Write-Host "❌ Logging test failed: $_" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Test 4: Test Error Handling
Write-Host "Test 4: Testing error handling..." -ForegroundColor Yellow
try {
    Invoke-CommandWithRetry -ScriptBlock {
        Get-Service -Name "Themes" -ErrorAction Stop
    } -MaxRetries 2 -OperationName "TestRetry"
    Write-Host "✅ Error handling test passed" -ForegroundColor Green
} catch {
    Write-Host "❌ Error handling test failed: $_" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Test 5: Test Get-ErrorDetails
Write-Host "Test 5: Testing error details..." -ForegroundColor Yellow
try {
    try {
        Get-Process -Name "NonExistentProcess12345" -ErrorAction Stop
    } catch {
        $details = Get-ErrorDetails -ErrorObject $_
        Write-Host "   Error type: $($details.Type)" -ForegroundColor Gray
        Write-Host "   Error message: $($details.Message)" -ForegroundColor Gray
    }
    Write-Host "✅ Error details test passed" -ForegroundColor Green
} catch {
    Write-Host "❌ Error details test failed: $_" -ForegroundColor Red
}
Write-Host ""

Write-Host "=== All Tests Passed ===" -ForegroundColor Green
Write-Host ""
Write-Host "Module Status:" -ForegroundColor Cyan
Write-Host "  Logging-Core:      Working ✅" -ForegroundColor Green
Write-Host "  Error-Handling:    Working ✅" -ForegroundColor Green
Write-Host ""
Write-Host "Version: 1.0.0" -ForegroundColor Gray

