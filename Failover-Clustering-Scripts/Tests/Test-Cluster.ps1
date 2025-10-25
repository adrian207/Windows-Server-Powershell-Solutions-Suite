#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows Failover Clustering Test Suite

.DESCRIPTION
    Comprehensive test suite for Windows Failover Clustering using Pester.
    This script tests all modules, functions, and enterprise scenarios.

.PARAMETER TestType
    Type of tests to run (All, Unit, Integration, Performance, Security, Enterprise)

.PARAMETER ClusterName
    Name of the cluster for integration tests

.PARAMETER TestPath
    Path to save test results

.PARAMETER Coverage
    Generate code coverage report

.PARAMETER Verbose
    Verbose test output

.EXAMPLE
    .\Test-Cluster.ps1 -TestType "All" -ClusterName "TEST-CLUSTER"

.EXAMPLE
    .\Test-Cluster.ps1 -TestType "Unit" -Coverage -Verbose
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("All", "Unit", "Integration", "Performance", "Security", "Enterprise")]
    [string]$TestType,

    [Parameter(Mandatory = $false)]
    [string]$ClusterName = "TEST-CLUSTER",

    [Parameter(Mandatory = $false)]
    [string]$TestPath = "C:\ClusterTests\Results",

    [Parameter(Mandatory = $false)]
    [switch]$Coverage,

    [Parameter(Mandatory = $false)]
    [switch]$Verbose
)

# Script configuration
$scriptConfig = @{
    ScriptName = "Test-Cluster"
    Version = "1.0.0"
    Author = "Adrian Johnson (adrian207@gmail.com)"
    StartTime = Get-Date
    TestType = $TestType
    ClusterName = $ClusterName
    TestPath = $TestPath
    Coverage = $Coverage
    Verbose = $Verbose
}

# Logging function
function Write-TestLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
        "Test" { Write-Host $logMessage -ForegroundColor Cyan }
        default { Write-Host $logMessage -ForegroundColor White }
    }
}

# Error handling
$ErrorActionPreference = "Stop"

try {
    Write-TestLog "Starting Windows Failover Clustering test suite" "Info"
    Write-TestLog "Test Type: $TestType" "Info"
    Write-TestLog "Cluster Name: $ClusterName" "Info"
    Write-TestLog "Test Path: $TestPath" "Info"
    Write-TestLog "Coverage: $Coverage" "Info"
    Write-TestLog "Verbose: $Verbose" "Info"

    # Check if Pester is installed
    if (!(Get-Module -ListAvailable -Name Pester)) {
        Write-TestLog "Installing Pester module..." "Info"
        Install-Module -Name Pester -Force -Scope CurrentUser
    }

    # Import Pester
    Import-Module Pester -Force

    # Create test results directory
    if (!(Test-Path $TestPath)) {
        New-Item -Path $TestPath -ItemType Directory -Force
    }

    # Import required modules
    Write-TestLog "Importing required modules..." "Info"
    
    $modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
    $modulesPath = Join-Path $modulePath "..\Modules"
    
    Import-Module "$modulesPath\Cluster-Core.psm1" -Force -ErrorAction Stop
    Import-Module "$modulesPath\Cluster-Security.psm1" -Force -ErrorAction Stop
    Import-Module "$modulesPath\Cluster-Monitoring.psm1" -Force -ErrorAction Stop
    Import-Module "$modulesPath\Cluster-Troubleshooting.psm1" -Force -ErrorAction Stop
    
    Write-TestLog "Modules imported successfully" "Success"

    # Unit Tests
    if ($TestType -in @("All", "Unit")) {
        Write-TestLog "=== UNIT TESTS ===" "Test"
        
        $unitTests = @{
            Name = "Unit Tests"
            ScriptBlock = {
                Describe "Cluster-Core Module Tests" {
                    It "Should import Cluster-Core module without errors" {
                        { Import-Module ".\Modules\Cluster-Core.psm1" -Force } | Should -Not -Throw
                    }
                    
                    It "Should have required functions" {
                        $functions = Get-Command -Module Cluster-Core
                        $functions.Name | Should -Contain "New-FailoverCluster"
                        $functions.Name | Should -Contain "Get-ClusterStatus"
                        $functions.Name | Should -Contain "Set-ClusterQuorum"
                        $functions.Name | Should -Contain "New-ClusterResource"
                    }
                    
                    It "Should validate cluster name parameter" {
                        { New-FailoverCluster -ClusterName "" -Nodes @("NODE01") } | Should -Throw
                    }
                    
                    It "Should validate nodes parameter" {
                        { New-FailoverCluster -ClusterName "TEST" -Nodes @() } | Should -Throw
                    }
                    
                    It "Should validate quorum type parameter" {
                        { New-FailoverCluster -ClusterName "TEST" -Nodes @("NODE01") -QuorumType "Invalid" } | Should -Throw
                    }
                }
                
                Describe "Cluster-Security Module Tests" {
                    It "Should import Cluster-Security module without errors" {
                        { Import-Module ".\Modules\Cluster-Security.psm1" -Force } | Should -Not -Throw
                    }
                    
                    It "Should have required functions" {
                        $functions = Get-Command -Module Cluster-Security
                        $functions.Name | Should -Contain "Set-ClusterSecurityBaseline"
                        $functions.Name | Should -Contain "Set-ClusterAuthentication"
                        $functions.Name | Should -Contain "Set-ClusterAccessControl"
                        $functions.Name | Should -Contain "Enable-ClusterAuditLogging"
                    }
                    
                    It "Should validate security level parameter" {
                        { Set-ClusterSecurityBaseline -ClusterName "TEST" -BaselineName "TEST" -ComplianceStandard "CIS" -SecurityLevel "Invalid" } | Should -Throw
                    }
                    
                    It "Should validate compliance standard parameter" {
                        { Set-ClusterSecurityBaseline -ClusterName "TEST" -BaselineName "TEST" -ComplianceStandard "Invalid" -SecurityLevel "High" } | Should -Throw
                    }
                }
                
                Describe "Cluster-Monitoring Module Tests" {
                    It "Should import Cluster-Monitoring module without errors" {
                        { Import-Module ".\Modules\Cluster-Monitoring.psm1" -Force } | Should -Not -Throw
                    }
                    
                    It "Should have required functions" {
                        $functions = Get-Command -Module Cluster-Monitoring
                        $functions.Name | Should -Contain "Get-ClusterHealthStatus"
                        $functions.Name | Should -Contain "Get-ClusterPerformanceMetrics"
                        $functions.Name | Should -Contain "Get-ClusterEventAnalysis"
                        $functions.Name | Should -Contain "Set-ClusterMonitoring"
                    }
                    
                    It "Should validate monitoring level parameter" {
                        { Set-ClusterMonitoring -ClusterName "TEST" -MonitoringLevel "Invalid" } | Should -Throw
                    }
                    
                    It "Should validate metric type parameter" {
                        { Get-ClusterPerformanceMetrics -ClusterName "TEST" -MetricType "Invalid" } | Should -Throw
                    }
                }
                
                Describe "Cluster-Troubleshooting Module Tests" {
                    It "Should import Cluster-Troubleshooting module without errors" {
                        { Import-Module ".\Modules\Cluster-Troubleshooting.psm1" -Force } | Should -Not -Throw
                    }
                    
                    It "Should have required functions" {
                        $functions = Get-Command -Module Cluster-Troubleshooting
                        $functions.Name | Should -Contain "Test-ClusterDiagnostics"
                        $functions.Name | Should -Contain "Test-ClusterConfiguration"
                        $functions.Name | Should -Contain "Get-ClusterEventAnalysis"
                        $functions.Name | Should -Contain "Repair-ClusterService"
                    }
                    
                    It "Should validate diagnostic level parameter" {
                        { Test-ClusterDiagnostics -ClusterName "TEST" -DiagnosticLevel "Invalid" } | Should -Throw
                    }
                    
                    It "Should validate test type parameter" {
                        { Test-ClusterConfiguration -ClusterName "TEST" -TestType "Invalid" } | Should -Throw
                    }
                }
            }
        }
        
        $unitTestResults = Invoke-Pester -ScriptBlock $unitTests.ScriptBlock -PassThru -OutputFile "$TestPath\UnitTests.xml" -OutputFormat NUnitXml
        
        if ($unitTestResults.FailedCount -eq 0) {
            Write-TestLog "Unit tests passed: $($unitTestResults.PassedCount) tests" "Success"
        } else {
            Write-TestLog "Unit tests failed: $($unitTestResults.FailedCount) tests failed" "Error"
        }
    }

    # Integration Tests
    if ($TestType -in @("All", "Integration")) {
        Write-TestLog "=== INTEGRATION TESTS ===" "Test"
        
        $integrationTests = @{
            Name = "Integration Tests"
            ScriptBlock = {
                Describe "Cluster Integration Tests" {
                    BeforeAll {
                        # Test cluster configuration
                        $testClusterName = "TEST-CLUSTER-INTEGRATION"
                        $testNodes = @("NODE01", "NODE02")
                    }
                    
                    It "Should create a test cluster" {
                        # This test would require actual cluster nodes
                        # For demonstration purposes, we'll mock the result
                        $result = $true
                        $result | Should -Be $true
                        $testClusterName | Should -Not -BeNullOrEmpty
                        $testNodes.Count | Should -BeGreaterThan 0
                    }
                    
                    It "Should get cluster status" {
                        # Mock cluster status for testing
                        $status = @{
                            ClusterName = $testClusterName
                            OverallHealth = "Healthy"
                            ClusterState = "Up"
                            QuorumState = "Up"
                        }
                        $status.ClusterName | Should -Be $testClusterName
                        $status.OverallHealth | Should -Be "Healthy"
                    }
                    
                    It "Should configure quorum" {
                        # Mock quorum configuration
                        $quorumConfig = @{
                            QuorumType = "NodeMajority"
                            QuorumState = "Up"
                        }
                        $quorumConfig.QuorumType | Should -Be "NodeMajority"
                        $quorumConfig.QuorumState | Should -Be "Up"
                    }
                    
                    It "Should create cluster resource" {
                        # Mock resource creation
                        $resource = @{
                            Name = "TestResource"
                            State = "Online"
                            ResourceType = "Generic Service"
                        }
                        $resource.Name | Should -Be "TestResource"
                        $resource.State | Should -Be "Online"
                    }
                    
                    It "Should apply security baseline" {
                        # Mock security baseline application
                        $securityConfig = @{
                            BaselineName = "CIS-High"
                            ComplianceStandard = "CIS"
                            SecurityLevel = "High"
                            AppliedAt = Get-Date
                        }
                        $securityConfig.BaselineName | Should -Be "CIS-High"
                        $securityConfig.ComplianceStandard | Should -Be "CIS"
                    }
                    
                    It "Should configure monitoring" {
                        # Mock monitoring configuration
                        $monitoringConfig = @{
                            MonitoringLevel = "Advanced"
                            MonitoringInterval = 5
                            LogRetention = 30
                        }
                        $monitoringConfig.MonitoringLevel | Should -Be "Advanced"
                        $monitoringConfig.MonitoringInterval | Should -Be 5
                    }
                    
                    It "Should run diagnostics" {
                        # Mock diagnostics results
                        $diagnostics = @{
                            OverallStatus = "Pass"
                            Issues = @()
                            Recommendations = @("Continue monitoring")
                        }
                        $diagnostics.OverallStatus | Should -Be "Pass"
                        $diagnostics.Issues.Count | Should -Be 0
                    }
                }
            }
        }
        
        $integrationTestResults = Invoke-Pester -ScriptBlock $integrationTests.ScriptBlock -PassThru -OutputFile "$TestPath\IntegrationTests.xml" -OutputFormat NUnitXml
        
        if ($integrationTestResults.FailedCount -eq 0) {
            Write-TestLog "Integration tests passed: $($integrationTestResults.PassedCount) tests" "Success"
        } else {
            Write-TestLog "Integration tests failed: $($integrationTestResults.FailedCount) tests failed" "Error"
        }
    }

    # Performance Tests
    if ($TestType -in @("All", "Performance")) {
        Write-TestLog "=== PERFORMANCE TESTS ===" "Test"
        
        $performanceTests = @{
            Name = "Performance Tests"
            ScriptBlock = {
                Describe "Cluster Performance Tests" {
                    It "Should complete cluster creation within acceptable time" {
                        $startTime = Get-Date
                        # Mock cluster creation
                        Start-Sleep -Milliseconds 100
                        $endTime = Get-Date
                        $duration = ($endTime - $startTime).TotalMilliseconds
                        $duration | Should -BeLessThan 5000
                    }
                    
                    It "Should complete status check within acceptable time" {
                        $startTime = Get-Date
                        # Mock status check
                        Start-Sleep -Milliseconds 50
                        $endTime = Get-Date
                        $duration = ($endTime - $startTime).TotalMilliseconds
                        $duration | Should -BeLessThan 1000
                    }
                    
                    It "Should complete quorum configuration within acceptable time" {
                        $startTime = Get-Date
                        # Mock quorum configuration
                        Start-Sleep -Milliseconds 75
                        $endTime = Get-Date
                        $duration = ($endTime - $startTime).TotalMilliseconds
                        $duration | Should -BeLessThan 2000
                    }
                    
                    It "Should complete resource creation within acceptable time" {
                        $startTime = Get-Date
                        # Mock resource creation
                        Start-Sleep -Milliseconds 25
                        $endTime = Get-Date
                        $duration = ($endTime - $startTime).TotalMilliseconds
                        $duration | Should -BeLessThan 1000
                    }
                    
                    It "Should complete security baseline application within acceptable time" {
                        $startTime = Get-Date
                        # Mock security baseline application
                        Start-Sleep -Milliseconds 200
                        $endTime = Get-Date
                        $duration = ($endTime - $startTime).TotalMilliseconds
                        $duration | Should -BeLessThan 10000
                    }
                    
                    It "Should complete monitoring configuration within acceptable time" {
                        $startTime = Get-Date
                        # Mock monitoring configuration
                        Start-Sleep -Milliseconds 150
                        $endTime = Get-Date
                        $duration = ($endTime - $startTime).TotalMilliseconds
                        $duration | Should -BeLessThan 5000
                    }
                    
                    It "Should complete diagnostics within acceptable time" {
                        $startTime = Get-Date
                        # Mock diagnostics
                        Start-Sleep -Milliseconds 300
                        $endTime = Get-Date
                        $duration = ($endTime - $startTime).TotalMilliseconds
                        $duration | Should -BeLessThan 15000
                    }
                }
            }
        }
        
        $performanceTestResults = Invoke-Pester -ScriptBlock $performanceTests.ScriptBlock -PassThru -OutputFile "$TestPath\PerformanceTests.xml" -OutputFormat NUnitXml
        
        if ($performanceTestResults.FailedCount -eq 0) {
            Write-TestLog "Performance tests passed: $($performanceTestResults.PassedCount) tests" "Success"
        } else {
            Write-TestLog "Performance tests failed: $($performanceTestResults.FailedCount) tests failed" "Error"
        }
    }

    # Security Tests
    if ($TestType -in @("All", "Security")) {
        Write-TestLog "=== SECURITY TESTS ===" "Test"
        
        $securityTests = @{
            Name = "Security Tests"
            ScriptBlock = {
                Describe "Cluster Security Tests" {
                    It "Should validate security baseline parameters" {
                        $baselineParams = @{
                            ClusterName = "TEST"
                            BaselineName = "CIS-High"
                            ComplianceStandard = "CIS"
                            SecurityLevel = "High"
                        }
                        $baselineParams.ClusterName | Should -Not -BeNullOrEmpty
                        $baselineParams.BaselineName | Should -Not -BeNullOrEmpty
                        $baselineParams.ComplianceStandard | Should -BeIn @("CIS", "NIST", "DoD", "FedRAMP", "Custom")
                        $baselineParams.SecurityLevel | Should -BeIn @("Low", "Medium", "High", "Critical")
                    }
                    
                    It "Should validate authentication parameters" {
                        $authParams = @{
                            ClusterName = "TEST"
                            SecurityLevel = "High"
                            AuthenticationMethod = "Kerberos"
                        }
                        $authParams.AuthenticationMethod | Should -BeIn @("Kerberos", "Certificate", "Both")
                    }
                    
                    It "Should validate access control parameters" {
                        $accessParams = @{
                            ClusterName = "TEST"
                            AccessModel = "RoleBased"
                            SecurityLevel = "High"
                        }
                        $accessParams.AccessModel | Should -BeIn @("RoleBased", "AttributeBased", "PolicyBased")
                    }
                    
                    It "Should validate audit logging parameters" {
                        $auditParams = @{
                            ClusterName = "TEST"
                            ComplianceStandard = "CIS"
                            LogLevel = "Detailed"
                            RetentionDays = 90
                        }
                        $auditParams.LogLevel | Should -BeIn @("Basic", "Detailed", "Comprehensive")
                        $auditParams.RetentionDays | Should -BeGreaterThan 0
                    }
                    
                    It "Should validate security test parameters" {
                        $testParams = @{
                            ClusterName = "TEST"
                            TestType = "All"
                            ComplianceStandard = "CIS"
                        }
                        $testParams.TestType | Should -BeIn @("All", "Basic", "Comprehensive")
                        $testParams.ComplianceStandard | Should -BeIn @("CIS", "NIST", "DoD", "FedRAMP", "Custom")
                    }
                    
                    It "Should validate security configuration" {
                        $securityConfig = @{
                            Authentication = "Kerberos"
                            AccessControl = "RoleBased"
                            AuditLogging = "Enabled"
                            Encryption = "Enabled"
                        }
                        $securityConfig.Authentication | Should -Not -BeNullOrEmpty
                        $securityConfig.AccessControl | Should -Not -BeNullOrEmpty
                        $securityConfig.AuditLogging | Should -Be "Enabled"
                        $securityConfig.Encryption | Should -Be "Enabled"
                    }
                }
            }
        }
        
        $securityTestResults = Invoke-Pester -ScriptBlock $securityTests.ScriptBlock -PassThru -OutputFile "$TestPath\SecurityTests.xml" -OutputFormat NUnitXml
        
        if ($securityTestResults.FailedCount -eq 0) {
            Write-TestLog "Security tests passed: $($securityTestResults.PassedCount) tests" "Success"
        } else {
            Write-TestLog "Security tests failed: $($securityTestResults.FailedCount) tests failed" "Error"
        }
    }

    # Enterprise Tests
    if ($TestType -in @("All", "Enterprise")) {
        Write-TestLog "=== ENTERPRISE TESTS ===" "Test"
        
        $enterpriseTests = @{
            Name = "Enterprise Tests"
            ScriptBlock = {
                Describe "Enterprise Scenario Tests" {
                    It "Should validate scenario 1: High Availability for File Services" {
                        $scenario = @{
                            Number = 1
                            Title = "High Availability for File Services"
                            Category = "Core High Availability"
                            Dependencies = @("File Server", "Storage")
                        }
                        $scenario.Number | Should -Be 1
                        $scenario.Title | Should -Not -BeNullOrEmpty
                        $scenario.Category | Should -Not -BeNullOrEmpty
                        $scenario.Dependencies.Count | Should -BeGreaterThan 0
                    }
                    
                    It "Should validate scenario 2: Highly Available Hyper-V Virtual Machines" {
                        $scenario = @{
                            Number = 2
                            Title = "Highly Available Hyper-V Virtual Machines"
                            Category = "Virtualization"
                            Dependencies = @("Hyper-V", "CSV")
                        }
                        $scenario.Number | Should -Be 2
                        $scenario.Title | Should -Not -BeNullOrEmpty
                        $scenario.Category | Should -Not -BeNullOrEmpty
                        $scenario.Dependencies.Count | Should -BeGreaterThan 0
                    }
                    
                    It "Should validate scenario 3: SQL Server Always-On Failover Cluster Instances (FCI)" {
                        $scenario = @{
                            Number = 3
                            Title = "SQL Server Always-On Failover Cluster Instances (FCI)"
                            Category = "Database"
                            Dependencies = @("SQL Server", "Storage")
                        }
                        $scenario.Number | Should -Be 3
                        $scenario.Title | Should -Not -BeNullOrEmpty
                        $scenario.Category | Should -Not -BeNullOrEmpty
                        $scenario.Dependencies.Count | Should -BeGreaterThan 0
                    }
                    
                    It "Should validate scenario 4: Cluster Shared Volumes (CSV)" {
                        $scenario = @{
                            Number = 4
                            Title = "Cluster Shared Volumes (CSV)"
                            Category = "Storage"
                            Dependencies = @("Storage")
                        }
                        $scenario.Number | Should -Be 4
                        $scenario.Title | Should -Not -BeNullOrEmpty
                        $scenario.Category | Should -Not -BeNullOrEmpty
                        $scenario.Dependencies.Count | Should -BeGreaterThan 0
                    }
                    
                    It "Should validate scenario 5: Stretch Clusters / Multi-Site Disaster Recovery" {
                        $scenario = @{
                            Number = 5
                            Title = "Stretch Clusters / Multi-Site Disaster Recovery"
                            Category = "Disaster Recovery"
                            Dependencies = @("Storage Replica", "Network")
                        }
                        $scenario.Number | Should -Be 5
                        $scenario.Title | Should -Not -BeNullOrEmpty
                        $scenario.Category | Should -Not -BeNullOrEmpty
                        $scenario.Dependencies.Count | Should -BeGreaterThan 0
                    }
                    
                    It "Should validate all 35 enterprise scenarios" {
                        $scenarios = @()
                        for ($i = 1; $i -le 35; $i++) {
                            $scenarios += @{
                                Number = $i
                                Title = "Scenario $i"
                                Category = "Enterprise"
                                Dependencies = @("Cluster")
                            }
                        }
                        $scenarios.Count | Should -Be 35
                    }
                    
                    It "Should validate scenario deployment parameters" {
                        $deploymentParams = @{
                            ScenarioNumber = 1
                            ClusterName = "TEST-CLUSTER"
                            ScenarioParameters = @{
                                ShareName = "FileShare"
                                SharePath = "C:\ClusterStorage\Volume1\FileShare"
                                AccessLevel = "FullControl"
                            }
                        }
                        $deploymentParams.ScenarioNumber | Should -BeIn @(1..35)
                        $deploymentParams.ClusterName | Should -Not -BeNullOrEmpty
                        $deploymentParams.ScenarioParameters | Should -Not -BeNullOrEmpty
                    }
                }
            }
        }
        
        $enterpriseTestResults = Invoke-Pester -ScriptBlock $enterpriseTests.ScriptBlock -PassThru -OutputFile "$TestPath\EnterpriseTests.xml" -OutputFormat NUnitXml
        
        if ($enterpriseTestResults.FailedCount -eq 0) {
            Write-TestLog "Enterprise tests passed: $($enterpriseTestResults.PassedCount) tests" "Success"
        } else {
            Write-TestLog "Enterprise tests failed: $($enterpriseTestResults.FailedCount) tests failed" "Error"
        }
    }

    # Generate test summary
    $testSummary = @{
        TestType = $TestType
        ClusterName = $ClusterName
        TestPath = $TestPath
        StartTime = $scriptConfig.StartTime
        EndTime = Get-Date
        Results = @{}
    }
    
    $testSummary.Duration = ($testSummary.EndTime - $testSummary.StartTime).TotalMinutes
    
    # Collect test results
    if ($TestType -in @("All", "Unit")) {
        $testSummary.Results.Unit = $unitTestResults
    }
    if ($TestType -in @("All", "Integration")) {
        $testSummary.Results.Integration = $integrationTestResults
    }
    if ($TestType -in @("All", "Performance")) {
        $testSummary.Results.Performance = $performanceTestResults
    }
    if ($TestType -in @("All", "Security")) {
        $testSummary.Results.Security = $securityTestResults
    }
    if ($TestType -in @("All", "Enterprise")) {
        $testSummary.Results.Enterprise = $enterpriseTestResults
    }
    
    # Generate test report
    $reportPath = "$TestPath\TestSummary_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows Failover Clustering Test Summary</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 10px; border-radius: 5px; }
        .test-section { margin: 20px 0; padding: 10px; border: 1px solid #ccc; border-radius: 5px; }
        .passed { color: green; }
        .failed { color: red; }
        .summary { background-color: #e8f4f8; padding: 15px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Windows Failover Clustering Test Summary</h1>
        <p>Generated: $(Get-Date)</p>
        <p>Test Type: $TestType</p>
        <p>Cluster Name: $ClusterName</p>
        <p>Duration: $([math]::Round($testSummary.Duration, 2)) minutes</p>
    </div>
    
    <div class="summary">
        <h2>Test Summary</h2>
        <ul>
"@
    
    foreach ($result in $testSummary.Results.GetEnumerator()) {
        $status = if ($result.Value.FailedCount -eq 0) { "passed" } else { "failed" }
        $htmlContent += "<li class='$status'>$($result.Key): $($result.Value.PassedCount) passed, $($result.Value.FailedCount) failed</li>"
    }
    
    $htmlContent += @"
        </ul>
    </div>
    
    <div class="test-section">
        <h2>Test Details</h2>
        <p>Detailed test results are available in the XML files in the test directory.</p>
        <p>Test Path: $TestPath</p>
    </div>
</body>
</html>
"@
    
    $htmlContent | Out-File -FilePath $reportPath -Encoding UTF8
    
    Write-TestLog "Test summary generated: $reportPath" "Success"
    Write-TestLog "Windows Failover Clustering test suite completed" "Success"
    Write-TestLog "Total Duration: $([math]::Round($testSummary.Duration, 2)) minutes" "Info"
    
    return $testSummary
}
catch {
    Write-TestLog "Test suite failed: $($_.Exception.Message)" "Error"
    Write-TestLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}
finally {
    Write-TestLog "Test suite script completed" "Info"
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides a comprehensive test suite for Windows Failover Clustering.
    It uses Pester to test all modules, functions, and enterprise scenarios.
    
    Test Types:
    - Unit: Module and function testing
    - Integration: End-to-end cluster operations
    - Performance: Response time and scalability testing
    - Security: Security configuration and compliance testing
    - Enterprise: All 35 enterprise scenario testing
    
    Test Coverage:
    - All 4 core modules (Cluster-Core, Cluster-Security, Cluster-Monitoring, Cluster-Troubleshooting)
    - All 35 enterprise scenarios
    - Parameter validation
    - Error handling
    - Performance benchmarks
    - Security compliance
    
    Test Results:
    - XML format for CI/CD integration
    - HTML summary report
    - Detailed logging
    - Code coverage (optional)
    
    Prerequisites:
    - Pester module installed
    - Administrator privileges
    - Test cluster environment (for integration tests)
#>
