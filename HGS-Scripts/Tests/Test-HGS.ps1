#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Comprehensive Test Suite for HGS PowerShell Solution

.DESCRIPTION
    Comprehensive test suite for HGS using Pester including:
    - Module loading tests
    - Function availability tests
    - Parameter validation tests
    - Integration tests
    - Performance tests
    - Security tests
    - Enterprise scenario tests

.PARAMETER TestType
    Type of tests to run (All, Unit, Integration, Performance, Security, Enterprise)

.PARAMETER HgsServer
    HGS server name for testing

.PARAMETER TestPath
    Path to save test results

.PARAMETER Coverage
    Generate code coverage report

.PARAMETER Verbose
    Enable verbose test output

.PARAMETER Force
    Run tests without confirmation

.EXAMPLE
    .\Test-HGS.ps1 -TestType "All" -HgsServer "HGS01"

.EXAMPLE
    .\Test-HGS.ps1 -TestType "Unit" -Coverage -Verbose

.EXAMPLE
    .\Test-HGS.ps1 -TestType "Integration" -HgsServer "HGS01" -TestPath "C:\TestResults"

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Pester, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Unit", "Integration", "Performance", "Security", "Enterprise")]
    [string]$TestType = "All",

    [Parameter(Mandatory = $false)]
    [string]$HgsServer = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [string]$TestPath = "C:\HGS-Tests\Results",

    [Parameter(Mandatory = $false)]
    [switch]$Coverage,

    [Parameter(Mandatory = $false)]
    [switch]$Verbose,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# Import Pester module
if (!(Get-Module -Name Pester -ListAvailable)) {
    Write-Warning "Pester module not found. Installing Pester..."
    Install-Module -Name Pester -Force -Scope CurrentUser
}

Import-Module Pester -Force

# Import HGS modules
$ModulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module "$ModulePath\..\Modules\HGS-Core.psm1" -Force
Import-Module "$ModulePath\..\Modules\HGS-Security.psm1" -Force
Import-Module "$ModulePath\..\Modules\HGS-Monitoring.psm1" -Force
Import-Module "$ModulePath\..\Modules\HGS-Troubleshooting.psm1" -Force

# Global variables
$script:TestLog = @()
$script:TestStartTime = Get-Date
$script:TestConfig = @{}

function Write-TestLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = @{
        Timestamp = $timestamp
        Level = $Level
        Message = $Message
    }
    
    $script:TestLog += $logEntry
    
    $color = switch ($Level) {
        "Info" { "White" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Success" { "Green" }
    }
    
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

# Unit Tests
Describe "HGS Core Module Tests" -Tag "Unit" {
    
    Context "Module Loading" {
        It "Should load HGS-Core module without errors" {
            { Import-Module "$ModulePath\..\Modules\HGS-Core.psm1" -Force } | Should -Not -Throw
        }
        
        It "Should load HGS-Security module without errors" {
            { Import-Module "$ModulePath\..\Modules\HGS-Security.psm1" -Force } | Should -Not -Throw
        }
        
        It "Should load HGS-Monitoring module without errors" {
            { Import-Module "$ModulePath\..\Modules\HGS-Monitoring.psm1" -Force } | Should -Not -Throw
        }
        
        It "Should load HGS-Troubleshooting module without errors" {
            { Import-Module "$ModulePath\..\Modules\HGS-Troubleshooting.psm1" -Force } | Should -Not -Throw
        }
    }
    
    Context "Function Availability" {
        It "Should have Get-HGSStatus function" {
            Get-Command -Name "Get-HGSStatus" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Add-HGSHost function" {
            Get-Command -Name "Add-HGSHost" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Set-HGSAttestationMode function" {
            Get-Command -Name "Set-HGSAttestationMode" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Get-HGSHealthStatus function" {
            Get-Command -Name "Get-HGSHealthStatus" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Test-HGSConfiguration function" {
            Get-Command -Name "Test-HGSConfiguration" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Parameter Validation" {
        It "Should validate HgsServer parameter" {
            { Get-HGSStatus -HgsServer "InvalidServer" } | Should -Not -Throw
        }
        
        It "Should validate SecurityLevel parameter" {
            { Set-HGSSecurityBaseline -BaselineName "Test" -ComplianceStandard "Custom" -SecurityLevel "Invalid" } | Should -Throw
        }
        
        It "Should validate AttestationMode parameter" {
            { Set-HGSAttestationMode -Mode "Invalid" } | Should -Throw
        }
    }
}

Describe "HGS Security Module Tests" -Tag "Unit" {
    
    Context "Security Functions" {
        It "Should have Set-HGSSecurityBaseline function" {
            Get-Command -Name "Set-HGSSecurityBaseline" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Set-HGSZeroTrust function" {
            Get-Command -Name "Set-HGSZeroTrust" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Set-HGSMultiTenantSecurity function" {
            Get-Command -Name "Set-HGSMultiTenantSecurity" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Set-HGSTrustBoundary function" {
            Get-Command -Name "Set-HGSTrustBoundary" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Security Parameter Validation" {
        It "Should validate ComplianceStandard parameter" {
            { Set-HGSSecurityBaseline -BaselineName "Test" -ComplianceStandard "Invalid" -SecurityLevel "High" } | Should -Throw
        }
        
        It "Should validate TrustModel parameter" {
            { Set-HGSZeroTrust -TrustModel "Invalid" -VerificationLevel "Continuous" -PolicyEnforcement "Strict" } | Should -Throw
        }
    }
}

Describe "HGS Monitoring Module Tests" -Tag "Unit" {
    
    Context "Monitoring Functions" {
        It "Should have Get-HGSPerformanceMetrics function" {
            Get-Command -Name "Get-HGSPerformanceMetrics" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Get-HGSEventAnalysis function" {
            Get-Command -Name "Get-HGSEventAnalysis" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Get-HGSCapacityPlanning function" {
            Get-Command -Name "Get-HGSCapacityPlanning" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Set-HGSAlerting function" {
            Get-Command -Name "Set-HGSAlerting" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Monitoring Parameter Validation" {
        It "Should validate MonitoringLevel parameter" {
            { Set-HGSMonitoring -MonitoringLevel "Invalid" -LogRetention 30 } | Should -Throw
        }
        
        It "Should validate MetricType parameter" {
            { Get-HGSPerformanceMetrics -HgsServer $HgsServer -MetricType "Invalid" } | Should -Throw
        }
    }
}

Describe "HGS Troubleshooting Module Tests" -Tag "Unit" {
    
    Context "Troubleshooting Functions" {
        It "Should have Test-HGSDiagnostics function" {
            Get-Command -Name "Test-HGSDiagnostics" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Repair-HGSService function" {
            Get-Command -Name "Repair-HGSService" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Get-HGSTroubleshootingGuide function" {
            Get-Command -Name "Get-HGSTroubleshootingGuide" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Troubleshooting Parameter Validation" {
        It "Should validate DiagnosticLevel parameter" {
            { Test-HGSDiagnostics -HgsServer $HgsServer -DiagnosticLevel "Invalid" } | Should -Throw
        }
        
        It "Should validate RepairType parameter" {
            { Repair-HGSService -HgsServer $HgsServer -RepairType "Invalid" } | Should -Throw
        }
    }
}

# Integration Tests
Describe "HGS Integration Tests" -Tag "Integration" {
    
    Context "HGS Server Integration" {
        It "Should connect to HGS server" {
            $result = Get-HGSStatus -HgsServer $HgsServer
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should get HGS health status" {
            $result = Get-HGSHealthStatus -HgsServer $HgsServer -IncludeDetails
            $result | Should -Not -BeNullOrEmpty
            $result.OverallHealth | Should -BeIn @("Healthy", "Warning", "Critical")
        }
        
        It "Should get HGS performance metrics" {
            $result = Get-HGSPerformanceMetrics -HgsServer $HgsServer -MetricType "All"
            $result | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Configuration Integration" {
        It "Should test HGS configuration" {
            $result = Test-HGSConfiguration -HgsServer $HgsServer -TestType "Basic"
            $result | Should -Not -BeNullOrEmpty
            $result.OverallResult | Should -BeIn @("Pass", "Fail", "Warning")
        }
        
        It "Should run HGS diagnostics" {
            $result = Test-HGSDiagnostics -HgsServer $HgsServer -DiagnosticLevel "Basic"
            $result | Should -Not -BeNullOrEmpty
        }
    }
}

# Performance Tests
Describe "HGS Performance Tests" -Tag "Performance" {
    
    Context "Performance Metrics" {
        It "Should get performance metrics within acceptable time" {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $result = Get-HGSPerformanceMetrics -HgsServer $HgsServer -MetricType "All"
            $stopwatch.Stop()
            
            $result | Should -Not -BeNullOrEmpty
            $stopwatch.ElapsedMilliseconds | Should -BeLessThan 5000
        }
        
        It "Should get health status within acceptable time" {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $result = Get-HGSHealthStatus -HgsServer $HgsServer -IncludeDetails
            $stopwatch.Stop()
            
            $result | Should -Not -BeNullOrEmpty
            $stopwatch.ElapsedMilliseconds | Should -BeLessThan 3000
        }
    }
    
    Context "Memory Usage" {
        It "Should not consume excessive memory" {
            $memoryBefore = [GC]::GetTotalMemory($false)
            
            # Run multiple operations
            for ($i = 1; $i -le 10; $i++) {
                Get-HGSStatus -HgsServer $HgsServer | Out-Null
            }
            
            $memoryAfter = [GC]::GetTotalMemory($false)
            $memoryIncrease = $memoryAfter - $memoryBefore
            
            $memoryIncrease | Should -BeLessThan 50MB
        }
    }
}

# Security Tests
Describe "HGS Security Tests" -Tag "Security" {
    
    Context "Security Functions" {
        It "Should apply security baseline" {
            { Set-HGSSecurityBaseline -BaselineName "TestBaseline" -ComplianceStandard "Custom" -SecurityLevel "High" } | Should -Not -Throw
        }
        
        It "Should configure Zero Trust" {
            { Set-HGSZeroTrust -TrustModel "NeverTrust" -VerificationLevel "Continuous" -PolicyEnforcement "Strict" } | Should -Not -Throw
        }
        
        It "Should configure multi-tenant security" {
            { Set-HGSMultiTenantSecurity -TenantName "TestTenant" -IsolationLevel "High" -ResourceQuotas @{VMs=5; Storage="500GB"} } | Should -Not -Throw
        }
    }
    
    Context "Security Validation" {
        It "Should validate security parameters" {
            { Set-HGSSecurityBaseline -BaselineName "Test" -ComplianceStandard "Invalid" -SecurityLevel "High" } | Should -Throw
        }
        
        It "Should require valid security levels" {
            { Set-HGSSecurityBaseline -BaselineName "Test" -ComplianceStandard "Custom" -SecurityLevel "Invalid" } | Should -Throw
        }
    }
}

# Enterprise Scenario Tests
Describe "HGS Enterprise Scenario Tests" -Tag "Enterprise" {
    
    Context "Enterprise Scenarios" {
        It "Should deploy Shielded VMs scenario" {
            { Set-HGSShieldedVMs -VMProtectionLevel "Maximum" -EncryptionEnabled -AttestationRequired } | Should -Not -Throw
        }
        
        It "Should configure cluster attestation" {
            { Set-HGSClusterAttestation -ClusterName "TestCluster" -ClusterNodes @("HV01", "HV02") -HgsServer $HgsServer } | Should -Not -Throw
        }
        
        It "Should configure disaster recovery" {
            { Set-HGSDisasterRecovery -PrimaryHgsServer $HgsServer -SecondaryHgsServer "HGS02" -ReplicationMode "Active-Passive" } | Should -Not -Throw
        }
        
        It "Should configure hybrid cloud" {
            { Set-HGSHybridCloud -AzureStackEndpoint "https://azurestack.local" -OnPremisesHgsServer $HgsServer -TrustMode "Federated" } | Should -Not -Throw
        }
    }
    
    Context "Advanced Security Scenarios" {
        It "Should configure rogue host detection" {
            { Set-HGSRogueHostDetection -DetectionThreshold 2 -RevocationAction "Immediate" -HgsServer $HgsServer } | Should -Not -Throw
        }
        
        It "Should configure forensic integrity" {
            { Set-HGSForensicIntegrity -BaselinePath "C:\HGS-Baselines" -VerificationInterval "Hourly" -HgsServer $HgsServer } | Should -Not -Throw
        }
        
        It "Should configure PAW hosting" {
            { Set-HGSPAWHosting -PAWTemplatePath "C:\Templates\PAW.vhdx" -SecurityPolicy "Maximum" -HgsServer $HgsServer } | Should -Not -Throw
        }
    }
}

# Error Handling Tests
Describe "HGS Error Handling Tests" -Tag "ErrorHandling" {
    
    Context "Error Scenarios" {
        It "Should handle invalid server gracefully" {
            { Get-HGSStatus -HgsServer "NonExistentServer" } | Should -Not -Throw
        }
        
        It "Should handle invalid parameters gracefully" {
            { Set-HGSAttestationMode -Mode "InvalidMode" } | Should -Throw
        }
        
        It "Should provide meaningful error messages" {
            try {
                Set-HGSAttestationMode -Mode "InvalidMode"
            }
            catch {
                $_.Exception.Message | Should -Not -BeNullOrEmpty
            }
        }
    }
}

# Main test execution
try {
    Write-TestLog "Starting HGS comprehensive test suite..." "Info"
    Write-TestLog "Server: $HgsServer" "Info"
    Write-TestLog "Test Type: $TestType" "Info"
    Write-TestLog "Test Path: $TestPath" "Info"
    
    # Build test configuration
    $script:TestConfig = @{
        HgsServer = $HgsServer
        TestType = $TestType
        TestPath = $TestPath
        Coverage = $Coverage
        Verbose = $Verbose
    }
    
    # Create test results directory
    if (!(Test-Path $TestPath)) {
        New-Item -Path $TestPath -ItemType Directory -Force
    }
    
    # Confirm test execution
    if (!$Force) {
        Write-Host "`nHGS Comprehensive Test Suite:" -ForegroundColor Cyan
        Write-Host "Server Name: $($script:TestConfig.HgsServer)" -ForegroundColor White
        Write-Host "Test Type: $($script:TestConfig.TestType)" -ForegroundColor White
        Write-Host "Test Path: $($script:TestConfig.TestPath)" -ForegroundColor White
        Write-Host "Coverage: $($script:TestConfig.Coverage)" -ForegroundColor White
        Write-Host "Verbose: $($script:TestConfig.Verbose)" -ForegroundColor White
        
        $confirmation = Read-Host "`nDo you want to proceed with HGS test suite? (Y/N)"
        if ($confirmation -notmatch "^[Yy]") {
            Write-TestLog "Test suite cancelled by user" "Warning"
            exit 0
        }
    }
    
    # Configure Pester
    $pesterConfig = New-PesterConfiguration
    $pesterConfig.Output.Verbosity = if ($Verbose) { "Detailed" } else { "Normal" }
    $pesterConfig.Run.Path = $PSScriptRoot
    $pesterConfig.Run.Exit = $false
    
    # Set test tags based on test type
    switch ($TestType) {
        "Unit" { $pesterConfig.Filter.Tag = "Unit" }
        "Integration" { $pesterConfig.Filter.Tag = "Integration" }
        "Performance" { $pesterConfig.Filter.Tag = "Performance" }
        "Security" { $pesterConfig.Filter.Tag = "Security" }
        "Enterprise" { $pesterConfig.Filter.Tag = "Enterprise" }
        "All" { $pesterConfig.Filter.Tag = @("Unit", "Integration", "Performance", "Security", "Enterprise", "ErrorHandling") }
    }
    
    # Configure code coverage if requested
    if ($Coverage) {
        $pesterConfig.CodeCoverage.Enabled = $true
        $pesterConfig.CodeCoverage.Path = @(
            "$ModulePath\..\Modules\HGS-Core.psm1",
            "$ModulePath\..\Modules\HGS-Security.psm1",
            "$ModulePath\..\Modules\HGS-Monitoring.psm1",
            "$ModulePath\..\Modules\HGS-Troubleshooting.psm1"
        )
        $pesterConfig.CodeCoverage.OutputFormat = "CoverageGutters"
        $pesterConfig.CodeCoverage.OutputPath = "$TestPath\Coverage.xml"
    }
    
    # Set output paths
    $pesterConfig.TestResult.Enabled = $true
    $pesterConfig.TestResult.OutputFormat = "NUnitXml"
    $pesterConfig.TestResult.OutputPath = "$TestPath\TestResults.xml"
    
    # Run tests
    Write-TestLog "Running Pester tests..." "Info"
    $testResults = Invoke-Pester -Configuration $pesterConfig
    
    # Generate test report
    $testReport = @{
        TestInfo = @{
            HgsServer = $HgsServer
            StartTime = $script:TestStartTime
            EndTime = Get-Date
            Duration = (Get-Date) - $script:TestStartTime
            TestType = $TestType
            Configuration = $script:TestConfig
        }
        TestResults = @{
            TotalTests = $testResults.TotalCount
            PassedTests = $testResults.PassedCount
            FailedTests = $testResults.FailedCount
            SkippedTests = $testResults.SkippedCount
            NotRunTests = $testResults.NotRunCount
            Duration = $testResults.Duration
        }
        TestLog = $script:TestLog
        Recommendations = @(
            "Review failed tests and fix issues",
            "Run tests regularly during development",
            "Add more test cases for edge scenarios",
            "Monitor test performance and optimize",
            "Update tests when functionality changes",
            "Document test procedures and requirements",
            "Train team on testing best practices",
            "Integrate tests into CI/CD pipeline"
        )
    }
    
    # Save test report
    $reportPath = "$TestPath\HGS-Test-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $testReport | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportPath -Encoding UTF8
    
    # Final status
    Write-TestLog "HGS test suite completed!" "Success"
    Write-Host "`nTest Results Summary:" -ForegroundColor Green
    Write-Host "Total Tests: $($testResults.TotalCount)" -ForegroundColor White
    Write-Host "Passed: $($testResults.PassedCount)" -ForegroundColor Green
    Write-Host "Failed: $($testResults.FailedCount)" -ForegroundColor Red
    Write-Host "Skipped: $($testResults.SkippedCount)" -ForegroundColor Yellow
    Write-Host "Not Run: $($testResults.NotRunCount)" -ForegroundColor Gray
    Write-Host "Duration: $($testResults.Duration)" -ForegroundColor White
    Write-Host "`nTest report saved to: $reportPath" -ForegroundColor Cyan
    
    if ($testResults.FailedCount -eq 0) {
        Write-Host "`n🎉 All tests passed successfully!" -ForegroundColor Green
    } else {
        Write-Host "`n⚠️ Some tests failed. Please review the test results." -ForegroundColor Yellow
    }
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Review the test report" -ForegroundColor White
    Write-Host "2. Fix any failed tests" -ForegroundColor White
    Write-Host "3. Add more test cases as needed" -ForegroundColor White
    Write-Host "4. Integrate tests into CI/CD pipeline" -ForegroundColor White
    Write-Host "5. Schedule regular test execution" -ForegroundColor White
    Write-Host "6. Monitor test performance" -ForegroundColor White
    Write-Host "7. Update tests when functionality changes" -ForegroundColor White
    
    # Exit with appropriate code
    if ($testResults.FailedCount -gt 0) {
        exit 1
    } else {
        exit 0
    }
    
}
catch {
    Write-TestLog "HGS test suite failed: $($_.Exception.Message)" "Error"
    Write-Host "`nTest suite failed. Please check the error messages above and resolve the issues." -ForegroundColor Red
    exit 1
}
