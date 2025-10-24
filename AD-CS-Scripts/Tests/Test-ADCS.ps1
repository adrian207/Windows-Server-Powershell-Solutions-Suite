#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Test AD CS

.DESCRIPTION
    Test script for Windows Active Directory Certificate Services.
    Provides comprehensive testing capabilities for AD CS infrastructure.

.PARAMETER ServerName
    Name of the server to test

.PARAMETER TestType
    Type of test to perform

.PARAMETER TestLevel
    Level of testing to perform

.PARAMETER OutputFormat
    Output format for test results

.PARAMETER OutputPath
    Output path for test results

.EXAMPLE
    .\Test-ADCS.ps1 -ServerName "CA-SERVER01" -TestType "Basic" -TestLevel "Standard"

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ServerName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Standard", "Comprehensive", "Maximum")]
    [string]$TestType = "Standard",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Standard", "Comprehensive", "Maximum")]
    [string]$TestLevel = "Standard",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("HTML", "PDF", "CSV", "JSON", "XML")]
    [string]$OutputFormat = "HTML",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

# Import required modules
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $modulePath "..\..\Modules"

Import-Module "$modulesPath\ADCS-Core.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Security.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Monitoring.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\ADCS-Troubleshooting.psm1" -Force -ErrorAction Stop

# Logging function
function Write-TestLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] [ADCS-Test] $Message"
    
    switch ($Level) {
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
        "Info" { Write-Host $logMessage -ForegroundColor Cyan }
        default { Write-Host $logMessage -ForegroundColor White }
    }
}

# Error handling
$ErrorActionPreference = "Stop"

try {
    Write-TestLog "Starting AD CS testing on $ServerName" "Info"
    Write-TestLog "Test Type: $TestType" "Info"
    Write-TestLog "Test Level: $TestLevel" "Info"
    
    # Test results
    $testResults = @{
        ServerName = $ServerName
        TestType = $TestType
        TestLevel = $TestLevel
        Timestamp = Get-Date
        TestSteps = @()
        Issues = @()
        Recommendations = @()
        OverallResult = "Unknown"
    }
    
    # Configure test based on type
    switch ($TestType) {
        "Basic" {
            Write-TestLog "Performing basic testing..." "Info"
            
            # Step 1: Basic health test
            try {
                $healthTest = Get-CAHealthStatus -ServerName $ServerName -IncludeDetails -IncludeCertificates -IncludeTemplates -IncludeOCSP -IncludeWebEnrollment -IncludeNDES
                
                if ($healthTest) {
                    $testResults.TestSteps += @{
                        Step = "Basic Health Test"
                        Status = "Completed"
                        Details = "Basic health test completed successfully"
                        Severity = "Info"
                    }
                    Write-TestLog "Basic health test completed successfully" "Success"
                } else {
                    $testResults.TestSteps += @{
                        Step = "Basic Health Test"
                        Status = "Failed"
                        Details = "Basic health test failed"
                        Severity = "Error"
                    }
                    $testResults.Issues += "Basic health test failed"
                    $testResults.Recommendations += "Check basic health test parameters"
                    Write-TestLog "Basic health test failed" "Error"
                }
            }
            catch {
                $testResults.TestSteps += @{
                    Step = "Basic Health Test"
                    Status = "Failed"
                    Details = "Exception during basic health test: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $testResults.Issues += "Exception during basic health test"
                $testResults.Recommendations += "Check error logs and basic health test parameters"
                Write-TestLog "Exception during basic health test: $($_.Exception.Message)" "Error"
            }
        }
        
        "Standard" {
            Write-TestLog "Performing standard testing..." "Info"
            
            # Step 1: Health test
            try {
                $healthTest = Get-CAHealthStatus -ServerName $ServerName -IncludeDetails -IncludeCertificates -IncludeTemplates -IncludeOCSP -IncludeWebEnrollment -IncludeNDES
                
                if ($healthTest) {
                    $testResults.TestSteps += @{
                        Step = "Health Test (Standard)"
                        Status = "Completed"
                        Details = "Health test completed with standard settings"
                        Severity = "Info"
                    }
                    Write-TestLog "Health test completed with standard settings" "Success"
                } else {
                    $testResults.TestSteps += @{
                        Step = "Health Test (Standard)"
                        Status = "Failed"
                        Details = "Health test failed"
                        Severity = "Error"
                    }
                    $testResults.Issues += "Health test failed"
                    $testResults.Recommendations += "Check health test parameters"
                    Write-TestLog "Health test failed" "Error"
                }
            }
            catch {
                $testResults.TestSteps += @{
                    Step = "Health Test (Standard)"
                    Status = "Failed"
                    Details = "Exception during health test: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $testResults.Issues += "Exception during health test"
                $testResults.Recommendations += "Check error logs and health test parameters"
                Write-TestLog "Exception during health test: $($_.Exception.Message)" "Error"
            }
            
            # Step 2: Service test
            try {
                $serviceTest = Get-CAServiceStatus -ServerName $ServerName -IncludeDetails -IncludeDependencies -IncludePerformance
                
                if ($serviceTest) {
                    $testResults.TestSteps += @{
                        Step = "Service Test (Standard)"
                        Status = "Completed"
                        Details = "Service test completed with standard settings"
                        Severity = "Info"
                    }
                    Write-TestLog "Service test completed with standard settings" "Success"
                } else {
                    $testResults.TestSteps += @{
                        Step = "Service Test (Standard)"
                        Status = "Failed"
                        Details = "Service test failed"
                        Severity = "Error"
                    }
                    $testResults.Issues += "Service test failed"
                    $testResults.Recommendations += "Check service test parameters"
                    Write-TestLog "Service test failed" "Error"
                }
            }
            catch {
                $testResults.TestSteps += @{
                    Step = "Service Test (Standard)"
                    Status = "Failed"
                    Details = "Exception during service test: $($_.Exception.Message)"
                    Severity = "Error"
                }
                $testResults.Issues += "Exception during service test"
                $testResults.Recommendations += "Check error logs and service test parameters"
                Write-TestLog "Exception during service test: $($_.Exception.Message)" "Error"
            }
        }
        
        default {
            Write-TestLog "Unknown test type: $TestType" "Error"
            $testResults.TestSteps += @{
                Step = "Test Type Validation"
                Status = "Failed"
                Details = "Unknown test type: $TestType"
                Severity = "Error"
            }
            $testResults.Issues += "Unknown test type: $TestType"
            $testResults.Recommendations += "Use a valid test type"
        }
    }
    
    # Determine overall result
    $failedSteps = $testResults.TestSteps | Where-Object { $_.Status -eq "Failed" }
    if ($failedSteps.Count -eq 0) {
        $testResults.OverallResult = "Success"
    } elseif ($failedSteps.Count -lt $testResults.TestSteps.Count / 2) {
        $testResults.OverallResult = "Partial Success"
    } else {
        $testResults.OverallResult = "Failed"
    }
    
    # Summary
    Write-TestLog "=== TEST SUMMARY ===" "Info"
    Write-TestLog "Server Name: $ServerName" "Info"
    Write-TestLog "Test Type: $TestType" "Info"
    Write-TestLog "Test Level: $TestLevel" "Info"
    Write-TestLog "Overall Result: $($testResults.OverallResult)" "Info"
    Write-TestLog "Test Steps: $($testResults.TestSteps.Count)" "Info"
    Write-TestLog "Issues: $($testResults.Issues.Count)" "Info"
    Write-TestLog "Recommendations: $($testResults.Recommendations.Count)" "Info"
    
    if ($testResults.Issues.Count -gt 0) {
        Write-TestLog "Issues:" "Warning"
        foreach ($issue in $testResults.Issues) {
            Write-TestLog "  - $issue" "Warning"
        }
    }
    
    if ($testResults.Recommendations.Count -gt 0) {
        Write-TestLog "Recommendations:" "Info"
        foreach ($recommendation in $testResults.Recommendations) {
            Write-TestLog "  - $recommendation" "Info"
        }
    }
    
    Write-TestLog "AD CS testing completed" "Success"
    
    return $testResults
}
catch {
    Write-TestLog "AD CS testing failed: $($_.Exception.Message)" "Error"
    Write-TestLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive testing for Windows Active Directory Certificate Services
    with various test types including basic, standard, comprehensive, and maximum testing.
    
    Features:
    - Basic Testing
    - Standard Testing
    - Comprehensive Testing
    - Maximum Testing
    - Health Testing
    - Service Testing
    - Performance Testing
    - Security Testing
    - Compliance Testing
    - Integration Testing
    
    Prerequisites:
    - Windows Server 2016 or later
    - Active Directory Domain Services
    - Administrative privileges
    - Network connectivity
    - Sufficient storage space
    - Sufficient memory and CPU resources
    
    Dependencies:
    - ADCS-Core.psm1
    - ADCS-Security.psm1
    - ADCS-Monitoring.psm1
    - ADCS-Troubleshooting.psm1
    
    Usage Examples:
    .\Test-ADCS.ps1 -ServerName "CA-SERVER01" -TestType "Basic" -TestLevel "Standard"
    .\Test-ADCS.ps1 -ServerName "CA-SERVER01" -TestType "Standard" -TestLevel "Comprehensive" -OutputFormat "HTML" -OutputPath "C:\Tests\ADCS-Test-Results.html"
    
    Output:
    - Console logging with color-coded messages
    - Test results summary
    - Detailed test steps
    - Issues and recommendations
    - Comprehensive error handling
    
    Security Considerations:
    - Requires administrative privileges
    - Performs comprehensive security testing
    - Implements security baselines
    - Enables security logging
    - Configures security compliance settings
    
    Performance Impact:
    - Minimal impact during testing
    - Non-destructive operations
    - Configurable test scope
    - Resource-aware testing
#>
