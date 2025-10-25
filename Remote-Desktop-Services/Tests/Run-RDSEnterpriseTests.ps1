#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    RDS Enterprise Test Runner

.DESCRIPTION
    This script provides a comprehensive test runner for all RDS enterprise scenarios,
    modules, and deployment scripts with detailed reporting and analysis.

.PARAMETER TestType
    Type of tests to run

.PARAMETER TestPath
    Path to test files

.PARAMETER OutputPath
    Path for test results

.PARAMETER IncludeIntegrationTests
    Include integration tests

.PARAMETER IncludePerformanceTests
    Include performance tests

.PARAMETER IncludeSecurityTests
    Include security tests

.PARAMETER TestTimeout
    Test timeout in seconds

.PARAMETER GenerateReport
    Generate detailed test report

.EXAMPLE
    .\Run-RDSEnterpriseTests.ps1 -TestType "All"

.EXAMPLE
    .\Run-RDSEnterpriseTests.ps1 -TestType "Modules" -IncludeIntegrationTests -GenerateReport

.EXAMPLE
    .\Run-RDSEnterpriseTests.ps1 -TestType "EnterpriseScripts" -OutputPath "C:\TestResults" -TestTimeout 600
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Modules", "EnterpriseScripts", "Integration", "Performance", "Security", "Documentation")]
    [string]$TestType = "All",
    
    [Parameter(Mandatory = $false)]
    [string]$TestPath = ".\Tests",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "C:\TestResults\RDS",
    
    [switch]$IncludeIntegrationTests,
    
    [switch]$IncludePerformanceTests,
    
    [switch]$IncludeSecurityTests,
    
    [Parameter(Mandatory = $false)]
    [int]$TestTimeout = 300,
    
    [switch]$GenerateReport
)

# Set up logging
$logFile = Join-Path $OutputPath "RDS-TestRunner.log"
$logDir = Split-Path $logFile -Parent
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

function Write-TestLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $logFile -Value $logEntry
}

try {
    Write-TestLog "Starting RDS Enterprise Test Runner"
    Write-TestLog "Test Type: $TestType"
    Write-TestLog "Test Path: $TestPath"
    Write-TestLog "Output Path: $OutputPath"
    
    # Check prerequisites
    if (-not (Get-Module -Name Pester -ListAvailable)) {
        Write-TestLog "Pester module not found. Please install Pester 5.0+ to run tests." "ERROR"
        throw "Pester module not found"
    }
    
    # Import Pester
    Import-Module Pester -Force
    Write-TestLog "Pester module imported successfully"
    
    # Test configuration
    $testConfig = @{
        TestType = $TestType
        TestPath = $TestPath
        OutputPath = $OutputPath
        IncludeIntegrationTests = $IncludeIntegrationTests
        IncludePerformanceTests = $IncludePerformanceTests
        IncludeSecurityTests = $IncludeSecurityTests
        TestTimeout = $TestTimeout
        GenerateReport = $GenerateReport
    }
    
    # Determine test files to run
    $testFiles = @()
    
    switch ($TestType) {
        "All" {
            $testFiles = Get-ChildItem -Path $TestPath -Filter "*.Tests.ps1" -Recurse
        }
        "Modules" {
            $testFiles = Get-ChildItem -Path $TestPath -Filter "*Module*.Tests.ps1" -Recurse
        }
        "EnterpriseScripts" {
            $testFiles = Get-ChildItem -Path $TestPath -Filter "*Enterprise*.Tests.ps1" -Recurse
        }
        "Integration" {
            $testFiles = Get-ChildItem -Path $TestPath -Filter "*Integration*.Tests.ps1" -Recurse
        }
        "Performance" {
            $testFiles = Get-ChildItem -Path $TestPath -Filter "*Performance*.Tests.ps1" -Recurse
        }
        "Security" {
            $testFiles = Get-ChildItem -Path $TestPath -Filter "*Security*.Tests.ps1" -Recurse
        }
        "Documentation" {
            $testFiles = Get-ChildItem -Path $TestPath -Filter "*Documentation*.Tests.ps1" -Recurse
        }
    }
    
    if ($testFiles.Count -eq 0) {
        Write-TestLog "No test files found for type: $TestType" "WARNING"
        $testFiles = @(Get-ChildItem -Path $TestPath -Filter "*.Tests.ps1" -Recurse | Select-Object -First 1)
    }
    
    Write-TestLog "Found $($testFiles.Count) test files to run"
    
    # Run tests
    $allTestResults = @()
    $totalTests = 0
    $totalPassed = 0
    $totalFailed = 0
    $totalSkipped = 0
    
    foreach ($testFile in $testFiles) {
        try {
            Write-TestLog "Running test file: $($testFile.Name)"
            
            $testResult = Invoke-Pester -Path $testFile.FullName -PassThru -Timeout $TestTimeout
            
            $allTestResults += $testResult
            
            $totalTests += $testResult.TotalCount
            $totalPassed += $testResult.PassedCount
            $totalFailed += $testResult.FailedCount
            $totalSkipped += $testResult.SkippedCount
            
            Write-TestLog "Test file $($testFile.Name) completed: $($testResult.PassedCount)/$($testResult.TotalCount) passed"
            
        } catch {
            Write-TestLog "Failed to run test file $($testFile.Name): $($_.Exception.Message)" "ERROR"
        }
    }
    
    # Generate comprehensive test report
    if ($GenerateReport) {
        Write-TestLog "Generating comprehensive test report"
        
        $reportPath = Join-Path $OutputPath "RDS-TestReport.html"
        $reportContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>RDS Enterprise Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #0078D4; color: white; padding: 20px; border-radius: 5px; }
        .summary { background-color: #f0f0f0; padding: 15px; margin: 20px 0; border-radius: 5px; }
        .test-results { margin: 20px 0; }
        .passed { color: green; font-weight: bold; }
        .failed { color: red; font-weight: bold; }
        .skipped { color: orange; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>RDS Enterprise Test Report</h1>
        <p>Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
    
    <div class="summary">
        <h2>Test Summary</h2>
        <p><strong>Total Tests:</strong> $totalTests</p>
        <p><strong>Passed:</strong> <span class="passed">$totalPassed</span></p>
        <p><strong>Failed:</strong> <span class="failed">$totalFailed</span></p>
        <p><strong>Skipped:</strong> <span class="skipped">$totalSkipped</span></p>
        <p><strong>Success Rate:</strong> $([math]::Round(($totalPassed / $totalTests) * 100, 2))%</p>
    </div>
    
    <div class="test-results">
        <h2>Detailed Test Results</h2>
        <table>
            <tr>
                <th>Test File</th>
                <th>Total</th>
                <th>Passed</th>
                <th>Failed</th>
                <th>Skipped</th>
                <th>Duration</th>
            </tr>
"@
        
        foreach ($result in $allTestResults) {
            $reportContent += @"
            <tr>
                <td>$($result.TestResult.Name)</td>
                <td>$($result.TotalCount)</td>
                <td class="passed">$($result.PassedCount)</td>
                <td class="failed">$($result.FailedCount)</td>
                <td class="skipped">$($result.SkippedCount)</td>
                <td>$($result.Duration)</td>
            </tr>
"@
        }
        
        $reportContent += @"
        </table>
    </div>
    
    <div class="test-results">
        <h2>Test Configuration</h2>
        <table>
            <tr><th>Configuration</th><th>Value</th></tr>
            <tr><td>Test Type</td><td>$($testConfig.TestType)</td></tr>
            <tr><td>Test Path</td><td>$($testConfig.TestPath)</td></tr>
            <tr><td>Output Path</td><td>$($testConfig.OutputPath)</td></tr>
            <tr><td>Include Integration Tests</td><td>$($testConfig.IncludeIntegrationTests)</td></tr>
            <tr><td>Include Performance Tests</td><td>$($testConfig.IncludePerformanceTests)</td></tr>
            <tr><td>Include Security Tests</td><td>$($testConfig.IncludeSecurityTests)</td></tr>
            <tr><td>Test Timeout</td><td>$($testConfig.TestTimeout) seconds</td></tr>
        </table>
    </div>
</body>
</html>
"@
        
        $reportContent | Out-File -FilePath $reportPath -Encoding UTF8
        Write-TestLog "Test report generated: $reportPath"
    }
    
    # Generate XML report for CI/CD integration
    $xmlReportPath = Join-Path $OutputPath "RDS-TestResults.xml"
    $xmlContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<test-results>
    <test-suite>
        <name>RDS Enterprise Tests</name>
        <total>$totalTests</total>
        <passed>$totalPassed</passed>
        <failed>$totalFailed</failed>
        <skipped>$totalSkipped</skipped>
        <duration>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</duration>
    </test-suite>
</test-results>
"@
    
    $xmlContent | Out-File -FilePath $xmlReportPath -Encoding UTF8
    Write-TestLog "XML report generated: $xmlReportPath"
    
    # Final summary
    Write-TestLog "=== RDS Enterprise Test Runner Summary ===" "INFO"
    Write-TestLog "Total Tests: $totalTests" "INFO"
    Write-TestLog "Passed: $totalPassed" "INFO"
    Write-TestLog "Failed: $totalFailed" "INFO"
    Write-TestLog "Skipped: $totalSkipped" "INFO"
    Write-TestLog "Success Rate: $([math]::Round(($totalPassed / $totalTests) * 100, 2))%" "INFO"
    Write-TestLog "Test files processed: $($testFiles.Count)" "INFO"
    Write-TestLog "Reports generated in: $OutputPath" "INFO"
    
    if ($totalFailed -gt 0) {
        Write-TestLog "Some tests failed. Please review the test results." "WARNING"
        exit 1
    } else {
        Write-TestLog "All tests passed successfully!" "SUCCESS"
        exit 0
    }
    
} catch {
    Write-TestLog "Test runner failed: $($_.Exception.Message)" "ERROR"
    Write-Error "RDS Enterprise Test Runner failed: $($_.Exception.Message)"
    exit 1
}
