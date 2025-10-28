#Requires -Version 5.1

<#
.SYNOPSIS
    LAPs Module Test Script

.DESCRIPTION
    Comprehensive test suite for LAPs modules.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

$ErrorActionPreference = "Stop"

# Test configuration
$TestConfig = @{
    TestName = "LAPs Module Tests"
    Modules = @("LAPs-Core", "LAPs-Security", "LAPs-Monitoring", "LAPs-Troubleshooting")
    TotalTests = 0
    PassedTests = 0
    FailedTests = 0
    StartTime = Get-Date
}

function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Message = ""
    )
    
    $TestConfig.TotalTests++
    
    if ($Passed) {
        $TestConfig.PassedTests++
        Write-Host "[PASS] $TestName" -ForegroundColor Green
        if ($Message) { Write-Host "      $Message" -ForegroundColor Gray }
    }
    else {
        $TestConfig.FailedTests++
        Write-Host "[FAIL] $TestName" -ForegroundColor Red
        if ($Message) { Write-Host "      $Message" -ForegroundColor Yellow }
    }
}

# Import modules
Write-Host "`nTesting LAPs Modules..." -ForegroundColor Cyan
Write-Host "=" * 50

try {
    Import-Module "$PSScriptRoot\..\Modules\LAPs-Core.psm1" -Force -ErrorAction Stop
    Write-TestResult -TestName "Import LAPs-Core" -Passed $true
}
catch {
    Write-TestResult -TestName "Import LAPs-Core" -Passed $false -Message $_.Exception.Message
}

try {
    Import-Module "$PSScriptRoot\..\Modules\LAPs-Security.psm1" -Force -ErrorAction Stop
    Write-TestResult -TestName "Import LAPs-Security" -Passed $true
}
catch {
    Write-TestResult -TestName "Import LAPs-Security" -Passed $false -Message $_.Exception.Message
}

try {
    Import-Module "$PSScriptRoot\..\Modules\LAPs-Monitoring.psm1" -Force -ErrorAction Stop
    Write-TestResult -TestName "Import LAPs-Monitoring" -Passed $true
}
catch {
    Write-TestResult -TestName "Import LAPs-Monitoring" -Passed $false -Message $_.Exception.Message
}

try {
    Import-Module "$PSScriptRoot\..\Modules\LAPs-Troubleshooting.psm1" -Force -ErrorAction Stop
    Write-TestResult -TestName "Import LAPs-Troubleshooting" -Passed $true
}
catch {
    Write-TestResult -TestName "Import LAPs-Troubleshooting" -Passed $false -Message $_.Exception.Message
}

# Test functions
Write-Host "`nTesting Functions:" -ForegroundColor Cyan

try {
    $result = Get-LAPsStatus -ComputerName @("TestComputer1", "TestComputer2")
    Write-TestResult -TestName "Get-LAPsStatus" -Passed ($null -ne $result) -Message "Retrieved status for multiple computers"
}
catch {
    Write-TestResult -TestName "Get-LAPsStatus" -Passed $false -Message $_.Exception.Message
}

try {
    $result = Get-LAPsPassword -ComputerName "TestComputer1"
    Write-TestResult -TestName "Get-LAPsPassword" -Passed ($null -ne $result) -Message "Retrieved password info"
}
catch {
    Write-TestResult -TestName "Get-LAPsPassword" -Passed $false -Message $_.Exception.Message
}

try {
    $result = Invoke-LAPsAudit
    Write-TestResult -TestName "Invoke-LAPsAudit" -Passed ($null -ne $result) -Message "Audit completed"
}
catch {
    Write-TestResult -TestName "Invoke-LAPsAudit" -Passed $false -Message $_.Exception.Message
}

try {
    $result = Get-LAPsStatistics
    Write-TestResult -TestName "Get-LAPsStatistics" -Passed ($null -ne $result) -Message "Retrieved statistics"
}
catch {
    Write-TestResult -TestName "Get-LAPsStatistics" -Passed $false -Message $_.Exception.Message
}

try {
    $result = Test-LAPsConnectivity -ComputerName "TestComputer1"
    Write-TestResult -TestName "Test-LAPsConnectivity" -Passed ($null -ne $result) -Message "Connectivity tested"
}
catch {
    Write-TestResult -TestName "Test-LAPsConnectivity" -Passed $false -Message $_.Exception.Message
}

try {
    $result = Get-LAPsComplianceStatus
    Write-TestResult -TestName "Get-LAPsComplianceStatus" -Passed ($null -ne $result) -Message "Compliance status retrieved"
}
catch {
    Write-TestResult -TestName "Get-LAPsComplianceStatus" -Passed $false -Message $_.Exception.Message
}

# Summary
$TestConfig.EndTime = Get-Date
$TestConfig.Duration = $TestConfig.EndTime - $TestConfig.StartTime

Write-Host "`n" + ("=" * 50) -ForegroundColor Cyan
Write-Host "Test Summary:" -ForegroundColor Cyan
Write-Host "  Total:    $($TestConfig.TotalTests)" -ForegroundColor White
Write-Host "  Passed:   $($TestConfig.PassedTests)" -ForegroundColor Green
Write-Host "  Failed:   $($TestConfig.FailedTests)" -ForegroundColor Red
Write-Host "  Duration: $($TestConfig.Duration.TotalSeconds) seconds" -ForegroundColor White

if ($TestConfig.FailedTests -eq 0) {
    Write-Host "`nAll tests PASSED!" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "`nSome tests FAILED!" -ForegroundColor Red
    exit 1
}
