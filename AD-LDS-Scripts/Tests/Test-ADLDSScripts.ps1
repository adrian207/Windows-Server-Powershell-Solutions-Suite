#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD LDS PowerShell Scripts Test Suite

.DESCRIPTION
    This script provides comprehensive testing for AD LDS PowerShell scripts
    including unit tests, integration tests, and validation tests.

.PARAMETER TestType
    Type of tests to run

.PARAMETER InstanceName
    Name of the test AD LDS instance

.PARAMETER TestPath
    Path for test results

.EXAMPLE
    .\Test-ADLDSScripts.ps1 -TestType "All" -InstanceName "TestInstance"

.EXAMPLE
    .\Test-ADLDSScripts.ps1 -TestType "Unit" -InstanceName "TestInstance"

.NOTES
    Author: AD LDS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("All", "Unit", "Integration", "Validation", "Performance", "Security")]
    [string]$TestType,

    [Parameter(Mandatory = $false)]
    [string]$InstanceName = "TestInstance",

    [Parameter(Mandatory = $false)]
    [string]$TestPath = "C:\ADLDS\Tests"
)

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "AD LDS PowerShell Scripts Test Suite" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Test Type: $TestType" -ForegroundColor Yellow
Write-Host "Instance: $InstanceName" -ForegroundColor Yellow
Write-Host "Test Path: $TestPath" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Import required modules
try {
    Import-Module "..\..\Modules\ADLDS-Core.psm1" -Force
    Import-Module "..\..\Modules\ADLDS-Security.psm1" -Force
    Import-Module "..\..\Modules\ADLDS-Monitoring.psm1" -Force
    Import-Module "..\..\Modules\ADLDS-Troubleshooting.psm1" -Force
    Write-Host "AD LDS modules imported successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to import AD LDS modules: $($_.Exception.Message)"
    exit 1
}

# Create test directory
if (-not (Test-Path $TestPath)) {
    New-Item -Path $TestPath -ItemType Directory -Force
}

# Test results tracking
$testResults = @{
    TotalTests = 0
    PassedTests = 0
    FailedTests = 0
    SkippedTests = 0
    TestDetails = @()
    StartTime = Get-Date
}

function Add-TestResult {
    param(
        [string]$TestName,
        [string]$Status,
        [string]$Message,
        [object]$Details = $null
    )
    
    $testResults.TotalTests++
    $testResults.$Status++
    
    $testResult = @{
        TestName = $TestName
        Status = $Status
        Message = $Message
        Details = $Details
        Timestamp = Get-Date
    }
    
    $testResults.TestDetails += $testResult
    
    $color = switch ($Status) {
        "PassedTests" { "Green" }
        "FailedTests" { "Red" }
        "SkippedTests" { "Yellow" }
    }
    
    Write-Host "  $Status`: $TestName - $Message" -ForegroundColor $color
}

# Unit Tests
function Test-ADLDSUnitTests {
    Write-Host "`n=== Running Unit Tests ===" -ForegroundColor Green
    
    # Test 1: Prerequisites Check
    Write-Host "`n1. Testing prerequisites check..." -ForegroundColor Yellow
    try {
        $prerequisites = Test-ADLDSPrerequisites
        if ($null -ne $prerequisites) {
            Add-TestResult -TestName "Prerequisites Check" -Status "PassedTests" -Message "Prerequisites check completed successfully" -Details $prerequisites
        } else {
            Add-TestResult -TestName "Prerequisites Check" -Status "FailedTests" -Message "Prerequisites check returned null"
        }
    } catch {
        Add-TestResult -TestName "Prerequisites Check" -Status "FailedTests" -Message "Prerequisites check failed: $($_.Exception.Message)"
    }
    
    # Test 2: Instance Status
    Write-Host "`n2. Testing instance status..." -ForegroundColor Yellow
    try {
        $status = Get-ADLDSInstanceStatus -InstanceName $InstanceName
        if ($null -ne $status) {
            Add-TestResult -TestName "Instance Status" -Status "PassedTests" -Message "Instance status retrieved successfully" -Details $status
        } else {
            Add-TestResult -TestName "Instance Status" -Status "FailedTests" -Message "Instance status returned null"
        }
    } catch {
        Add-TestResult -TestName "Instance Status" -Status "FailedTests" -Message "Instance status failed: $($_.Exception.Message)"
    }
    
    # Test 3: Statistics Collection
    Write-Host "`n3. Testing statistics collection..." -ForegroundColor Yellow
    try {
        $stats = Get-ADLDSStatistics -InstanceName $InstanceName
        if ($null -ne $stats) {
            Add-TestResult -TestName "Statistics Collection" -Status "PassedTests" -Message "Statistics collected successfully" -Details $stats
        } else {
            Add-TestResult -TestName "Statistics Collection" -Status "FailedTests" -Message "Statistics collection returned null"
        }
    } catch {
        Add-TestResult -TestName "Statistics Collection" -Status "FailedTests" -Message "Statistics collection failed: $($_.Exception.Message)"
    }
    
    # Test 4: Security Status
    Write-Host "`n4. Testing security status..." -ForegroundColor Yellow
    try {
        $securityStatus = Get-ADLDSSecurityStatus -InstanceName $InstanceName
        if ($null -ne $securityStatus) {
            Add-TestResult -TestName "Security Status" -Status "PassedTests" -Message "Security status retrieved successfully" -Details $securityStatus
        } else {
            Add-TestResult -TestName "Security Status" -Status "FailedTests" -Message "Security status returned null"
        }
    } catch {
        Add-TestResult -TestName "Security Status" -Status "FailedTests" -Message "Security status failed: $($_.Exception.Message)"
    }
    
    # Test 5: Health Status
    Write-Host "`n5. Testing health status..." -ForegroundColor Yellow
    try {
        $healthStatus = Get-ADLDSHealthStatus -InstanceName $InstanceName
        if ($null -ne $healthStatus) {
            Add-TestResult -TestName "Health Status" -Status "PassedTests" -Message "Health status retrieved successfully" -Details $healthStatus
        } else {
            Add-TestResult -TestName "Health Status" -Status "FailedTests" -Message "Health status returned null"
        }
    } catch {
        Add-TestResult -TestName "Health Status" -Status "FailedTests" -Message "Health status failed: $($_.Exception.Message)"
    }
}

# Integration Tests
function Test-ADLDSIntegrationTests {
    Write-Host "`n=== Running Integration Tests ===" -ForegroundColor Green
    
    # Test 1: Instance Creation
    Write-Host "`n1. Testing instance creation..." -ForegroundColor Yellow
    try {
        $instanceResult = New-ADLDSInstance -InstanceName $InstanceName -Port 399 -SSLPort 647
        if ($instanceResult.Success) {
            Add-TestResult -TestName "Instance Creation" -Status "PassedTests" -Message "Instance created successfully" -Details $instanceResult
        } else {
            Add-TestResult -TestName "Instance Creation" -Status "FailedTests" -Message "Instance creation failed: $($instanceResult.Error)"
        }
    } catch {
        Add-TestResult -TestName "Instance Creation" -Status "FailedTests" -Message "Instance creation failed: $($_.Exception.Message)"
    }
    
    # Test 2: Partition Creation
    Write-Host "`n2. Testing partition creation..." -ForegroundColor Yellow
    try {
        $partitionResult = New-ADLDSPartition -InstanceName $InstanceName -PartitionName "TestPartition" -PartitionDN "CN=TestPartition,DC=TestDir,DC=local"
        if ($partitionResult.Success) {
            Add-TestResult -TestName "Partition Creation" -Status "PassedTests" -Message "Partition created successfully" -Details $partitionResult
        } else {
            Add-TestResult -TestName "Partition Creation" -Status "FailedTests" -Message "Partition creation failed: $($partitionResult.Error)"
        }
    } catch {
        Add-TestResult -TestName "Partition Creation" -Status "FailedTests" -Message "Partition creation failed: $($_.Exception.Message)"
    }
    
    # Test 3: User Creation
    Write-Host "`n3. Testing user creation..." -ForegroundColor Yellow
    try {
        $userResult = Add-ADLDSUser -InstanceName $InstanceName -PartitionDN "CN=TestPartition,DC=TestDir,DC=local" -UserName "testuser" -UserDN "CN=testuser,CN=TestPartition,DC=TestDir,DC=local"
        if ($userResult.Success) {
            Add-TestResult -TestName "User Creation" -Status "PassedTests" -Message "User created successfully" -Details $userResult
        } else {
            Add-TestResult -TestName "User Creation" -Status "FailedTests" -Message "User creation failed: $($userResult.Error)"
        }
    } catch {
        Add-TestResult -TestName "User Creation" -Status "FailedTests" -Message "User creation failed: $($_.Exception.Message)"
    }
    
    # Test 4: Group Creation
    Write-Host "`n4. Testing group creation..." -ForegroundColor Yellow
    try {
        $groupResult = Add-ADLDSGroup -InstanceName $InstanceName -PartitionDN "CN=TestPartition,DC=TestDir,DC=local" -GroupName "testgroup" -GroupDN "CN=testgroup,CN=TestPartition,DC=TestDir,DC=local"
        if ($groupResult.Success) {
            Add-TestResult -TestName "Group Creation" -Status "PassedTests" -Message "Group created successfully" -Details $groupResult
        } else {
            Add-TestResult -TestName "Group Creation" -Status "FailedTests" -Message "Group creation failed: $($groupResult.Error)"
        }
    } catch {
        Add-TestResult -TestName "Group Creation" -Status "FailedTests" -Message "Group creation failed: $($_.Exception.Message)"
    }
    
    # Test 5: Schema Extension
    Write-Host "`n5. Testing schema extension..." -ForegroundColor Yellow
    try {
        $schemaResult = Set-ADLDSSchema -InstanceName $InstanceName -CustomAttributes @("testAttribute1", "testAttribute2") -CustomClasses @("testClass1", "testClass2")
        if ($schemaResult.Success) {
            Add-TestResult -TestName "Schema Extension" -Status "PassedTests" -Message "Schema extended successfully" -Details $schemaResult
        } else {
            Add-TestResult -TestName "Schema Extension" -Status "FailedTests" -Message "Schema extension failed: $($schemaResult.Error)"
        }
    } catch {
        Add-TestResult -TestName "Schema Extension" -Status "FailedTests" -Message "Schema extension failed: $($_.Exception.Message)"
    }
}

# Validation Tests
function Test-ADLDSValidationTests {
    Write-Host "`n=== Running Validation Tests ===" -ForegroundColor Green
    
    # Test 1: Configuration Validation
    Write-Host "`n1. Testing configuration validation..." -ForegroundColor Yellow
    try {
        $configTest = Test-ADLDSConfiguration -InstanceName $InstanceName
        if ($configTest.Success) {
            Add-TestResult -TestName "Configuration Validation" -Status "PassedTests" -Message "Configuration validation completed" -Details $configTest
        } else {
            Add-TestResult -TestName "Configuration Validation" -Status "FailedTests" -Message "Configuration validation failed: $($configTest.Error)"
        }
    } catch {
        Add-TestResult -TestName "Configuration Validation" -Status "FailedTests" -Message "Configuration validation failed: $($_.Exception.Message)"
    }
    
    # Test 2: Security Compliance
    Write-Host "`n2. Testing security compliance..." -ForegroundColor Yellow
    try {
        $complianceTest = Test-ADLDSSecurityCompliance -InstanceName $InstanceName -ComplianceStandard "SOX"
        if ($complianceTest.Success) {
            Add-TestResult -TestName "Security Compliance" -Status "PassedTests" -Message "Security compliance test completed" -Details $complianceTest
        } else {
            Add-TestResult -TestName "Security Compliance" -Status "FailedTests" -Message "Security compliance test failed: $($complianceTest.Error)"
        }
    } catch {
        Add-TestResult -TestName "Security Compliance" -Status "FailedTests" -Message "Security compliance test failed: $($_.Exception.Message)"
    }
    
    # Test 3: Diagnostics
    Write-Host "`n3. Testing diagnostics..." -ForegroundColor Yellow
    try {
        $diagnosticsTest = Start-ADLDSDiagnostics -InstanceName $InstanceName -IncludeEventLogs -IncludeConnectivity
        if ($diagnosticsTest.Success) {
            Add-TestResult -TestName "Diagnostics" -Status "PassedTests" -Message "Diagnostics completed successfully" -Details $diagnosticsTest
        } else {
            Add-TestResult -TestName "Diagnostics" -Status "FailedTests" -Message "Diagnostics failed: $($diagnosticsTest.Error)"
        }
    } catch {
        Add-TestResult -TestName "Diagnostics" -Status "FailedTests" -Message "Diagnostics failed: $($_.Exception.Message)"
    }
}

# Performance Tests
function Test-ADLDSPerformanceTests {
    Write-Host "`n=== Running Performance Tests ===" -ForegroundColor Green
    
    # Test 1: Performance Monitoring
    Write-Host "`n1. Testing performance monitoring..." -ForegroundColor Yellow
    try {
        $perfTest = Start-ADLDSMonitoring -InstanceName $InstanceName -MonitoringDuration 1 -LogPath $TestPath
        if ($perfTest.Success) {
            Add-TestResult -TestName "Performance Monitoring" -Status "PassedTests" -Message "Performance monitoring completed" -Details $perfTest
        } else {
            Add-TestResult -TestName "Performance Monitoring" -Status "FailedTests" -Message "Performance monitoring failed: $($perfTest.Error)"
        }
    } catch {
        Add-TestResult -TestName "Performance Monitoring" -Status "FailedTests" -Message "Performance monitoring failed: $($_.Exception.Message)"
    }
    
    # Test 2: Analytics
    Write-Host "`n2. Testing analytics..." -ForegroundColor Yellow
    try {
        $analyticsTest = Get-ADLDSAnalytics -InstanceName $InstanceName -TimeRange 1
        if ($analyticsTest.Success) {
            Add-TestResult -TestName "Analytics" -Status "PassedTests" -Message "Analytics retrieved successfully" -Details $analyticsTest
        } else {
            Add-TestResult -TestName "Analytics" -Status "FailedTests" -Message "Analytics failed: $($analyticsTest.Error)"
        }
    } catch {
        Add-TestResult -TestName "Analytics" -Status "FailedTests" -Message "Analytics failed: $($_.Exception.Message)"
    }
}

# Security Tests
function Test-ADLDSSecurityTests {
    Write-Host "`n=== Running Security Tests ===" -ForegroundColor Green
    
    # Test 1: Authentication Configuration
    Write-Host "`n1. Testing authentication configuration..." -ForegroundColor Yellow
    try {
        $authTest = Set-ADLDSAuthentication -InstanceName $InstanceName -AuthenticationType "Negotiate" -EnableSSL
        if ($authTest.Success) {
            Add-TestResult -TestName "Authentication Configuration" -Status "PassedTests" -Message "Authentication configured successfully" -Details $authTest
        } else {
            Add-TestResult -TestName "Authentication Configuration" -Status "FailedTests" -Message "Authentication configuration failed: $($authTest.Error)"
        }
    } catch {
        Add-TestResult -TestName "Authentication Configuration" -Status "FailedTests" -Message "Authentication configuration failed: $($_.Exception.Message)"
    }
    
    # Test 2: Security Policies
    Write-Host "`n2. Testing security policies..." -ForegroundColor Yellow
    try {
        $securityTest = Enable-ADLDSSecurityPolicies -InstanceName $InstanceName -EnableAuditLogging -EnablePasswordPolicy
        if ($securityTest.Success) {
            Add-TestResult -TestName "Security Policies" -Status "PassedTests" -Message "Security policies enabled successfully" -Details $securityTest
        } else {
            Add-TestResult -TestName "Security Policies" -Status "FailedTests" -Message "Security policies failed: $($securityTest.Error)"
        }
    } catch {
        Add-TestResult -TestName "Security Policies" -Status "FailedTests" -Message "Security policies failed: $($_.Exception.Message)"
    }
    
    # Test 3: Access Control
    Write-Host "`n3. Testing access control..." -ForegroundColor Yellow
    try {
        $aclTest = Set-ADLDSAccessControl -InstanceName $InstanceName -ObjectDN "CN=TestPartition,DC=TestDir,DC=local" -Principal "CN=Administrators" -Permission "Full Control"
        if ($aclTest.Success) {
            Add-TestResult -TestName "Access Control" -Status "PassedTests" -Message "Access control configured successfully" -Details $aclTest
        } else {
            Add-TestResult -TestName "Access Control" -Status "FailedTests" -Message "Access control failed: $($aclTest.Error)"
        }
    } catch {
        Add-TestResult -TestName "Access Control" -Status "FailedTests" -Message "Access control failed: $($_.Exception.Message)"
    }
}

# Run tests based on type
switch ($TestType) {
    "All" {
        Test-ADLDSUnitTests
        Test-ADLDSIntegrationTests
        Test-ADLDSValidationTests
        Test-ADLDSPerformanceTests
        Test-ADLDSSecurityTests
    }
    "Unit" {
        Test-ADLDSUnitTests
    }
    "Integration" {
        Test-ADLDSIntegrationTests
    }
    "Validation" {
        Test-ADLDSValidationTests
    }
    "Performance" {
        Test-ADLDSPerformanceTests
    }
    "Security" {
        Test-ADLDSSecurityTests
    }
}

# Calculate test results
$testResults.EndTime = Get-Date
$testResults.Duration = $testResults.EndTime - $testResults.StartTime
$testResults.SuccessRate = [math]::Round(($testResults.PassedTests / $testResults.TotalTests) * 100, 2)

# Generate test report
Write-Host "`n=== Test Results Summary ===" -ForegroundColor Green
Write-Host "Total Tests: $($testResults.TotalTests)" -ForegroundColor Cyan
Write-Host "Passed: $($testResults.PassedTests)" -ForegroundColor Green
Write-Host "Failed: $($testResults.FailedTests)" -ForegroundColor Red
Write-Host "Skipped: $($testResults.SkippedTests)" -ForegroundColor Yellow
Write-Host "Success Rate: $($testResults.SuccessRate)%" -ForegroundColor Cyan
Write-Host "Duration: $($testResults.Duration.TotalSeconds) seconds" -ForegroundColor Cyan

# Save detailed test report
$testReportFile = Join-Path $TestPath "ADLDS-Test-Report-$TestType-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
$testResults | ConvertTo-Json -Depth 5 | Out-File -FilePath $testReportFile -Encoding UTF8

Write-Host "`nDetailed test report saved: $testReportFile" -ForegroundColor Green

# Final summary
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "AD LDS Test Suite Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Test Type: $TestType" -ForegroundColor Yellow
Write-Host "Instance: $InstanceName" -ForegroundColor Yellow
Write-Host "Total Tests: $($testResults.TotalTests)" -ForegroundColor Yellow
Write-Host "Success Rate: $($testResults.SuccessRate)%" -ForegroundColor Yellow
Write-Host "Duration: $($testResults.Duration.TotalSeconds) seconds" -ForegroundColor Yellow
Write-Host "Report: $testReportFile" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

if ($testResults.SuccessRate -ge 90) {
    Write-Host "`n🎉 Test suite completed successfully!" -ForegroundColor Green
    Write-Host "All critical tests passed with a $($testResults.SuccessRate)% success rate." -ForegroundColor Green
} elseif ($testResults.SuccessRate -ge 70) {
    Write-Host "`n⚠️ Test suite completed with warnings." -ForegroundColor Yellow
    Write-Host "Some tests failed. Review the detailed report for issues." -ForegroundColor Yellow
} else {
    Write-Host "`n❌ Test suite completed with failures." -ForegroundColor Red
    Write-Host "Multiple tests failed. Review the detailed report and fix issues." -ForegroundColor Red
}

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Review the detailed test report" -ForegroundColor White
Write-Host "2. Fix any failed tests" -ForegroundColor White
Write-Host "3. Re-run tests to verify fixes" -ForegroundColor White
Write-Host "4. Update documentation based on test results" -ForegroundColor White
Write-Host "5. Set up automated testing in CI/CD pipeline" -ForegroundColor White
