#Requires -Version 5.1

<#
.SYNOPSIS
    Remote Access Services Test Runner

.DESCRIPTION
    This script runs comprehensive tests for the Remote Access Services PowerShell solution
    including unit tests, integration tests, and validation tests.

.PARAMETER TestType
    Type of tests to run (All, Unit, Integration, Performance, Validation)

.PARAMETER TestPath
    Path to test files

.PARAMETER OutputPath
    Path for test output

.PARAMETER Verbose
    Enable verbose output

.EXAMPLE
    .\Run-RemoteAccessTests.ps1

.EXAMPLE
    .\Run-RemoteAccessTests.ps1 -TestType "Unit" -Verbose
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Unit", "Integration", "Performance", "Validation")]
    [string]$TestType = "All",
    
    [Parameter(Mandatory = $false)]
    [string]$TestPath = ".\Tests",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\Logs\RemoteAccess-Tests",
    
    [switch]$Verbose
)

# Script configuration
$ScriptVersion = "1.0.0"
$TestStartTime = Get-Date

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Test configuration
$TestConfiguration = @{
    TestTimeout = 300  # 5 minutes
    TestRetries = 3
    TestLogPath = $OutputPath
    TestDataPath = "C:\TestData\RemoteAccess"
    TestResults = @()
}

#region Helper Functions

function Write-TestLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    if ($Verbose) {
        Write-Host $LogEntry
    }
    
    $LogFile = Join-Path $OutputPath "RemoteAccess-TestRunner.log"
    Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
}

function Test-PesterAvailability {
    try {
        Import-Module Pester -ErrorAction Stop
        Write-TestLog "Pester module loaded successfully"
        return $true
    } catch {
        Write-TestLog "Pester module not available: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Initialize-TestEnvironment {
    try {
        # Create test directories
        if (-not (Test-Path $TestConfiguration.TestLogPath)) {
            New-Item -Path $TestConfiguration.TestLogPath -ItemType Directory -Force | Out-Null
        }
        
        if (-not (Test-Path $TestConfiguration.TestDataPath)) {
            New-Item -Path $TestConfiguration.TestDataPath -ItemType Directory -Force | Out-Null
        }
        
        Write-TestLog "Test environment initialized successfully"
        return $true
    } catch {
        Write-TestLog "Failed to initialize test environment: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Invoke-TestSuite {
    param(
        [string]$TestName,
        [string]$TestFile,
        [string]$TestTag
    )
    
    try {
        Write-TestLog "Running test suite: $TestName"
        
        $testResult = Invoke-Pester -Path $TestFile -Tag $TestTag -PassThru -OutputFile (Join-Path $OutputPath "$TestName-Results.xml") -OutputFormat NUnitXml
        
        $testSuiteResult = @{
            TestName = $TestName
            TestFile = $TestFile
            TestTag = $TestTag
            TotalTests = $testResult.TotalCount
            PassedTests = $testResult.PassedCount
            FailedTests = $testResult.FailedCount
            SkippedTests = $testResult.SkippedCount
            TestDuration = $testResult.Duration
            Success = ($testResult.FailedCount -eq 0)
        }
        
        $TestConfiguration.TestResults += $testSuiteResult
        
        Write-TestLog "Test suite $TestName completed: $($testResult.PassedCount)/$($testResult.TotalCount) passed"
        
        return $testSuiteResult
        
    } catch {
        Write-TestLog "Test suite $TestName failed: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

#endregion

#region Main Test Execution

try {
    Write-TestLog "Starting Remote Access Services Test Runner - Version $ScriptVersion"
    Write-TestLog "Test Type: $TestType"
    Write-TestLog "Test Path: $TestPath"
    Write-TestLog "Output Path: $OutputPath"
    
    # Check Pester availability
    if (-not (Test-PesterAvailability)) {
        throw "Pester module is required but not available"
    }
    
    # Initialize test environment
    if (-not (Initialize-TestEnvironment)) {
        throw "Failed to initialize test environment"
    }
    
    # Run tests based on type
    switch ($TestType) {
        "All" {
            Write-TestLog "Running all test suites..."
            
            # Core module tests
            $coreTestFile = Join-Path $TestPath "RemoteAccess-Core.Tests.ps1"
            if (Test-Path $coreTestFile) {
                Invoke-TestSuite -TestName "Core" -TestFile $coreTestFile -TestTag "Core"
            }
            
            # DirectAccess tests
            $directAccessTestFile = Join-Path $TestPath "RemoteAccess-DirectAccess.Tests.ps1"
            if (Test-Path $directAccessTestFile) {
                Invoke-TestSuite -TestName "DirectAccess" -TestFile $directAccessTestFile -TestTag "DirectAccess"
            }
            
            # VPN tests
            $vpnTestFile = Join-Path $TestPath "RemoteAccess-VPN.Tests.ps1"
            if (Test-Path $vpnTestFile) {
                Invoke-TestSuite -TestName "VPN" -TestFile $vpnTestFile -TestTag "VPN"
            }
            
            # Web Application Proxy tests
            $wapTestFile = Join-Path $TestPath "RemoteAccess-WebApplicationProxy.Tests.ps1"
            if (Test-Path $wapTestFile) {
                Invoke-TestSuite -TestName "WebApplicationProxy" -TestFile $wapTestFile -TestTag "WebApplicationProxy"
            }
            
            # NPS tests
            $npsTestFile = Join-Path $TestPath "RemoteAccess-NPS.Tests.ps1"
            if (Test-Path $npsTestFile) {
                Invoke-TestSuite -TestName "NPS" -TestFile $npsTestFile -TestTag "NPS"
            }
            
            # Monitoring tests
            $monitoringTestFile = Join-Path $TestPath "RemoteAccess-Monitoring.Tests.ps1"
            if (Test-Path $monitoringTestFile) {
                Invoke-TestSuite -TestName "Monitoring" -TestFile $monitoringTestFile -TestTag "Monitoring"
            }
            
            # Security tests
            $securityTestFile = Join-Path $TestPath "RemoteAccess-Security.Tests.ps1"
            if (Test-Path $securityTestFile) {
                Invoke-TestSuite -TestName "Security" -TestFile $securityTestFile -TestTag "Security"
            }
            
            # Integration tests
            $integrationTestFile = Join-Path $TestPath "RemoteAccess-Integration.Tests.ps1"
            if (Test-Path $integrationTestFile) {
                Invoke-TestSuite -TestName "Integration" -TestFile $integrationTestFile -TestTag "Integration"
            }
            
            # Performance tests
            $performanceTestFile = Join-Path $TestPath "RemoteAccess-Performance.Tests.ps1"
            if (Test-Path $performanceTestFile) {
                Invoke-TestSuite -TestName "Performance" -TestFile $performanceTestFile -TestTag "Performance"
            }
        }
        
        "Unit" {
            Write-TestLog "Running unit tests..."
            
            $unitTestFiles = @(
                "RemoteAccess-Core.Tests.ps1",
                "RemoteAccess-DirectAccess.Tests.ps1",
                "RemoteAccess-VPN.Tests.ps1",
                "RemoteAccess-WebApplicationProxy.Tests.ps1",
                "RemoteAccess-NPS.Tests.ps1",
                "RemoteAccess-Monitoring.Tests.ps1",
                "RemoteAccess-Security.Tests.ps1"
            )
            
            foreach ($testFile in $unitTestFiles) {
                $fullPath = Join-Path $TestPath $testFile
                if (Test-Path $fullPath) {
                    $testName = $testFile -replace "\.Tests\.ps1$", ""
                    Invoke-TestSuite -TestName $testName -TestFile $fullPath -TestTag "Unit"
                }
            }
        }
        
        "Integration" {
            Write-TestLog "Running integration tests..."
            
            $integrationTestFile = Join-Path $TestPath "RemoteAccess-Integration.Tests.ps1"
            if (Test-Path $integrationTestFile) {
                Invoke-TestSuite -TestName "Integration" -TestFile $integrationTestFile -TestTag "Integration"
            }
        }
        
        "Performance" {
            Write-TestLog "Running performance tests..."
            
            $performanceTestFile = Join-Path $TestPath "RemoteAccess-Performance.Tests.ps1"
            if (Test-Path $performanceTestFile) {
                Invoke-TestSuite -TestName "Performance" -TestFile $performanceTestFile -TestTag "Performance"
            }
        }
        
        "Validation" {
            Write-TestLog "Running validation tests..."
            
            $validationTestFile = Join-Path $TestPath "RemoteAccess-Validation.Tests.ps1"
            if (Test-Path $validationTestFile) {
                Invoke-TestSuite -TestName "Validation" -TestFile $validationTestFile -TestTag "Validation"
            }
        }
    }
    
    # Generate test summary
    $testEndTime = Get-Date
    $testDuration = $testEndTime - $TestStartTime
    
    $totalTests = ($TestConfiguration.TestResults | Measure-Object -Property TotalTests -Sum).Sum
    $totalPassed = ($TestConfiguration.TestResults | Measure-Object -Property PassedTests -Sum).Sum
    $totalFailed = ($TestConfiguration.TestResults | Measure-Object -Property FailedTests -Sum).Sum
    $totalSkipped = ($TestConfiguration.TestResults | Measure-Object -Property SkippedTests -Sum).Sum
    
    $testSummary = @{
        TestType = $TestType
        StartTime = $TestStartTime
        EndTime = $testEndTime
        Duration = $testDuration
        TotalTests = $totalTests
        PassedTests = $totalPassed
        FailedTests = $totalFailed
        SkippedTests = $totalSkipped
        SuccessRate = if ($totalTests -gt 0) { [math]::Round(($totalPassed / $totalTests) * 100, 2) } else { 0 }
        TestResults = $TestConfiguration.TestResults
    }
    
    # Save test summary
    $summaryFile = Join-Path $OutputPath "RemoteAccess-TestSummary.json"
    $testSummary | ConvertTo-Json -Depth 10 | Set-Content $summaryFile
    
    # Display test summary
    Write-Host "`nRemote Access Services Test Runner Results:" -ForegroundColor Green
    Write-Host "Test Type: $TestType" -ForegroundColor White
    Write-Host "Total Tests: $totalTests" -ForegroundColor White
    Write-Host "Passed: $totalPassed" -ForegroundColor Green
    Write-Host "Failed: $totalFailed" -ForegroundColor Red
    Write-Host "Skipped: $totalSkipped" -ForegroundColor Yellow
    Write-Host "Success Rate: $($testSummary.SuccessRate)%" -ForegroundColor White
    Write-Host "Duration: $($testDuration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    Write-Host "Summary File: $summaryFile" -ForegroundColor White
    
    # Return test summary
    return [PSCustomObject]$testSummary
    
} catch {
    $testEndTime = Get-Date
    $testDuration = $testEndTime - $TestStartTime
    
    Write-TestLog "Remote Access Services Test Runner FAILED!" "ERROR"
    Write-TestLog "Error: $($_.Exception.Message)" "ERROR"
    Write-TestLog "Duration: $($testDuration.TotalMinutes.ToString('F2')) minutes" "ERROR"
    
    # Return failure result
    $testSummary = @{
        TestType = $TestType
        StartTime = $TestStartTime
        EndTime = $testEndTime
        Duration = $testDuration
        Success = $false
        Error = $_.Exception.Message
    }
    
    return [PSCustomObject]$testSummary
}

#endregion
