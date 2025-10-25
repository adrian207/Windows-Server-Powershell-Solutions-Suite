#Requires -Version 5.1

<#
.SYNOPSIS
    IIS Web Server Test Runner

.DESCRIPTION
    This script runs comprehensive tests for the IIS Web Server PowerShell solution
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
    .\Run-IISTests.ps1

.EXAMPLE
    .\Run-IISTests.ps1 -TestType "Unit" -Verbose
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Unit", "Integration", "Performance", "Validation")]
    [string]$TestType = "All",
    
    [Parameter(Mandatory = $false)]
    [string]$TestPath = ".\Tests",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\Logs\IIS-Tests",
    
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
    TestDataPath = "C:\TestData\IIS"
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
    
    $LogFile = Join-Path $OutputPath "IIS-TestRunner.log"
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
    Write-TestLog "Starting IIS Web Server Test Runner - Version $ScriptVersion"
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
            $coreTestFile = Join-Path $TestPath "IIS-Core.Tests.ps1"
            if (Test-Path $coreTestFile) {
                Invoke-TestSuite -TestName "Core" -TestFile $coreTestFile -TestTag "Core"
            }
            
            # Installation tests
            $installTestFile = Join-Path $TestPath "IIS-Installation.Tests.ps1"
            if (Test-Path $installTestFile) {
                Invoke-TestSuite -TestName "Installation" -TestFile $installTestFile -TestTag "Installation"
            }
            
            # Applications tests
            $appsTestFile = Join-Path $TestPath "IIS-Applications.Tests.ps1"
            if (Test-Path $appsTestFile) {
                Invoke-TestSuite -TestName "Applications" -TestFile $appsTestFile -TestTag "Applications"
            }
            
            # Security tests
            $securityTestFile = Join-Path $TestPath "IIS-Security.Tests.ps1"
            if (Test-Path $securityTestFile) {
                Invoke-TestSuite -TestName "Security" -TestFile $securityTestFile -TestTag "Security"
            }
            
            # Monitoring tests
            $monitoringTestFile = Join-Path $TestPath "IIS-Monitoring.Tests.ps1"
            if (Test-Path $monitoringTestFile) {
                Invoke-TestSuite -TestName "Monitoring" -TestFile $monitoringTestFile -TestTag "Monitoring"
            }
            
            # Backup tests
            $backupTestFile = Join-Path $TestPath "IIS-Backup.Tests.ps1"
            if (Test-Path $backupTestFile) {
                Invoke-TestSuite -TestName "Backup" -TestFile $backupTestFile -TestTag "Backup"
            }
            
            # Troubleshooting tests
            $troubleshootingTestFile = Join-Path $TestPath "IIS-Troubleshooting.Tests.ps1"
            if (Test-Path $troubleshootingTestFile) {
                Invoke-TestSuite -TestName "Troubleshooting" -TestFile $troubleshootingTestFile -TestTag "Troubleshooting"
            }
            
            # Integration tests
            $integrationTestFile = Join-Path $TestPath "IIS-Integration.Tests.ps1"
            if (Test-Path $integrationTestFile) {
                Invoke-TestSuite -TestName "Integration" -TestFile $integrationTestFile -TestTag "Integration"
            }
            
            # Performance tests
            $performanceTestFile = Join-Path $TestPath "IIS-Performance.Tests.ps1"
            if (Test-Path $performanceTestFile) {
                Invoke-TestSuite -TestName "Performance" -TestFile $performanceTestFile -TestTag "Performance"
            }
        }
        
        "Unit" {
            Write-TestLog "Running unit tests..."
            
            $unitTestFiles = @(
                "IIS-Core.Tests.ps1",
                "IIS-Installation.Tests.ps1",
                "IIS-Applications.Tests.ps1",
                "IIS-Security.Tests.ps1",
                "IIS-Monitoring.Tests.ps1",
                "IIS-Backup.Tests.ps1",
                "IIS-Troubleshooting.Tests.ps1"
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
            
            $integrationTestFile = Join-Path $TestPath "IIS-Integration.Tests.ps1"
            if (Test-Path $integrationTestFile) {
                Invoke-TestSuite -TestName "Integration" -TestFile $integrationTestFile -TestTag "Integration"
            }
        }
        
        "Performance" {
            Write-TestLog "Running performance tests..."
            
            $performanceTestFile = Join-Path $TestPath "IIS-Performance.Tests.ps1"
            if (Test-Path $performanceTestFile) {
                Invoke-TestSuite -TestName "Performance" -TestFile $performanceTestFile -TestTag "Performance"
            }
        }
        
        "Validation" {
            Write-TestLog "Running validation tests..."
            
            $validationTestFile = Join-Path $TestPath "IIS-Validation.Tests.ps1"
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
    $summaryFile = Join-Path $OutputPath "IIS-TestSummary.json"
    $testSummary | ConvertTo-Json -Depth 10 | Set-Content $summaryFile
    
    # Display test summary
    Write-Host "`nIIS Web Server Test Runner Results:" -ForegroundColor Green
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
    
    Write-TestLog "IIS Web Server Test Runner FAILED!" "ERROR"
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
