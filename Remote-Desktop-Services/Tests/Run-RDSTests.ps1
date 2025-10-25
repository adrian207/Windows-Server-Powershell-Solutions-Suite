#Requires -Version 5.1
#Requires -Modules Pester

<#
.SYNOPSIS
    RDS Test Suite Runner

.DESCRIPTION
    Comprehensive test runner for all RDS PowerShell modules and scripts.

.PARAMETER TestType
    Type of tests to run (Unit, Integration, All)

.PARAMETER ModuleName
    Specific module to test (optional)

.PARAMETER OutputFormat
    Output format for test results (NUnitXml, JUnitXml, CoverageGutters)

.PARAMETER OutputPath
    Path for test output files

.PARAMETER CoveragePath
    Path for coverage reports

.PARAMETER Verbose
    Enable verbose output

.EXAMPLE
    .\Run-RDSTests.ps1 -TestType "All" -OutputFormat "NUnitXml" -OutputPath "C:\TestResults"

.EXAMPLE
    .\Run-RDSTests.ps1 -TestType "Unit" -ModuleName "RDS-Core" -Verbose
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Unit", "Integration", "All")]
    [string]$TestType = "All",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("RDS-Core", "RDS-SessionHost", "RDS-ConnectionBroker", "RDS-Gateway", "RDS-WebAccess", "RDS-Licensing", "RDS-Monitoring", "RDS-Security", "RDS-Deployment")]
    [string]$ModuleName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("NUnitXml", "JUnitXml", "CoverageGutters")]
    [string]$OutputFormat = "NUnitXml",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\TestResults",
    
    [Parameter(Mandatory = $false)]
    [string]$CoveragePath = ".\Coverage",
    
    [Parameter(Mandatory = $false)]
    [switch]$Verbose
)

# Script metadata
$ScriptVersion = "1.0.0"

# Test configuration
$TestConfiguration = @{
    TestTimeout = 300
    TestDataPath = ".\TestData"
    LogPath = ".\TestLogs"
    OutputPath = $OutputPath
    CoveragePath = $CoveragePath
    Verbose = $Verbose
}

# Ensure test directories exist
$directories = @($TestConfiguration.TestDataPath, $TestConfiguration.LogPath, $TestConfiguration.OutputPath, $TestConfiguration.CoveragePath)
foreach ($directory in $directories) {
    if (-not (Test-Path $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
        Write-Verbose "Created directory: $directory"
    }
}

# Test file mappings
$TestFiles = @{
    "RDS-Core" = ".\Tests\RDS-Core.Tests.ps1"
    "RDS-SessionHost" = ".\Tests\RDS-SessionHost.Tests.ps1"
    "RDS-ConnectionBroker" = ".\Tests\RDS-ConnectionBroker.Tests.ps1"
    "RDS-Gateway" = ".\Tests\RDS-Gateway.Tests.ps1"
    "RDS-WebAccess" = ".\Tests\RDS-WebAccess.Tests.ps1"
    "RDS-Licensing" = ".\Tests\RDS-Licensing.Tests.ps1"
    "RDS-Monitoring" = ".\Tests\RDS-Monitoring.Tests.ps1"
    "RDS-Security" = ".\Tests\RDS-Security.Tests.ps1"
    "RDS-Deployment" = ".\Tests\RDS-Deployment.Tests.ps1"
}

# Module file mappings
$ModuleFiles = @{
    "RDS-Core" = ".\Modules\RDS-Core.psm1"
    "RDS-SessionHost" = ".\Modules\RDS-SessionHost.psm1"
    "RDS-ConnectionBroker" = ".\Modules\RDS-ConnectionBroker.psm1"
    "RDS-Gateway" = ".\Modules\RDS-Gateway.psm1"
    "RDS-WebAccess" = ".\Modules\RDS-WebAccess.psm1"
    "RDS-Licensing" = ".\Modules\RDS-Licensing.psm1"
    "RDS-Monitoring" = ".\Modules\RDS-Monitoring.psm1"
    "RDS-Security" = ".\Modules\RDS-Security.psm1"
}

#region Helper Functions

function Write-TestLog {
    <#
    .SYNOPSIS
        Writes test log messages
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Info" { Write-Host $logMessage -ForegroundColor White }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
    }
    
    # Log to file
    $logFile = "$($TestConfiguration.LogPath)\TestRunner.log"
    try {
        Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Failed to write to log file: $($_.Exception.Message)"
    }
}

function Test-TestPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for running tests
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        PesterAvailable = $false
        PowerShellVersion = $false
        AdministratorPrivileges = $false
        TestFilesExist = $false
        ModuleFilesExist = $false
    }
    
    # Check Pester module
    try {
        $pesterModule = Get-Module -ListAvailable -Name Pester -ErrorAction SilentlyContinue
        $prerequisites.PesterAvailable = ($null -ne $pesterModule)
    } catch {
        Write-TestLog "Could not check Pester module: $($_.Exception.Message)" "Error"
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        $prerequisites.PowerShellVersion = $true
    } else {
        Write-TestLog "PowerShell version 5.0 or higher is required" "Error"
    }
    
    # Check administrator privileges
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $prerequisites.AdministratorPrivileges = $true
    } else {
        Write-TestLog "Administrator privileges are required for some tests" "Warning"
    }
    
    # Check test files
    $testFilesExist = $true
    foreach ($testFile in $TestFiles.Values) {
        if (-not (Test-Path $testFile)) {
            $testFilesExist = $false
            Write-TestLog "Test file not found: $testFile" "Warning"
        }
    }
    $prerequisites.TestFilesExist = $testFilesExist
    
    # Check module files
    $moduleFilesExist = $true
    foreach ($moduleFile in $ModuleFiles.Values) {
        if (-not (Test-Path $moduleFile)) {
            $moduleFilesExist = $false
            Write-TestLog "Module file not found: $moduleFile" "Warning"
        }
    }
    $prerequisites.ModuleFilesExist = $moduleFilesExist
    
    return $prerequisites
}

function Invoke-ModuleTests {
    <#
    .SYNOPSIS
        Runs tests for a specific module
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory = $false)]
        [string]$TestType = "All"
    )
    
    try {
        Write-TestLog "Running tests for module: $ModuleName" "Info"
        
        $testFile = $TestFiles[$ModuleName]
        if (-not $testFile -or -not (Test-Path $testFile)) {
            Write-TestLog "Test file not found for module: $ModuleName" "Error"
            return $null
        }
        
        $moduleFile = $ModuleFiles[$ModuleName]
        if (-not $moduleFile -or -not (Test-Path $moduleFile)) {
            Write-TestLog "Module file not found: $ModuleName" "Error"
            return $null
        }
        
        # Prepare test parameters
        $testParams = @{
            Path = $testFile
            PassThru = $true
        }
        
        # Add output format if specified
        if ($OutputFormat) {
            $testParams.OutputFormat = $OutputFormat
            $testParams.OutputFile = "$($TestConfiguration.OutputPath)\$ModuleName-TestResults.xml"
        }
        
        # Add coverage if specified
        if ($TestType -eq "Unit" -or $TestType -eq "All") {
            $testParams.CodeCoverage = $moduleFile
            $testParams.CodeCoverageOutputFile = "$($TestConfiguration.CoveragePath)\$ModuleName-Coverage.xml"
        }
        
        # Run tests
        $testResult = Invoke-Pester @testParams
        
        if ($testResult) {
            Write-TestLog "Tests completed for $ModuleName - Passed: $($testResult.PassedCount), Failed: $($testResult.FailedCount)" "Success"
        } else {
            Write-TestLog "Tests failed for $ModuleName" "Error"
        }
        
        return $testResult
        
    } catch {
        Write-TestLog "Error running tests for $ModuleName : $($_.Exception.Message)" "Error"
        return $null
    }
}

function Invoke-AllTests {
    <#
    .SYNOPSIS
        Runs all available tests
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$TestType = "All"
    )
    
    try {
        Write-TestLog "Running all tests..." "Info"
        
        $allTestResults = @{}
        $totalPassed = 0
        $totalFailed = 0
        $totalSkipped = 0
        
        foreach ($moduleName in $TestFiles.Keys) {
            $testResult = Invoke-ModuleTests -ModuleName $moduleName -TestType $TestType
            
            if ($testResult) {
                $allTestResults[$moduleName] = $testResult
                $totalPassed += $testResult.PassedCount
                $totalFailed += $testResult.FailedCount
                $totalSkipped += $testResult.SkippedCount
            }
        }
        
        # Generate summary
        $summary = @{
            TotalModules = $allTestResults.Count
            TotalPassed = $totalPassed
            TotalFailed = $totalFailed
            TotalSkipped = $totalSkipped
            TestResults = $allTestResults
        }
        
        Write-TestLog "All tests completed - Total Passed: $totalPassed, Total Failed: $totalFailed, Total Skipped: $totalSkipped" "Success"
        
        return $summary
        
    } catch {
        Write-TestLog "Error running all tests: $($_.Exception.Message)" "Error"
        return $null
    }
}

#endregion

#region Main Script Execution

try {
    Write-TestLog "RDS Test Suite Runner Started" "Info"
    Write-TestLog "Script Version: $ScriptVersion" "Info"
    Write-TestLog "Test Type: $TestType" "Info"
    Write-TestLog "Module Name: $ModuleName" "Info"
    Write-TestLog "Output Format: $OutputFormat" "Info"
    Write-TestLog "Output Path: $OutputPath" "Info"
    
    # Test prerequisites
    Write-TestLog "Testing prerequisites..." "Info"
    $prerequisites = Test-TestPrerequisites
    
    if (-not $prerequisites.PesterAvailable) {
        Write-TestLog "Pester module is required to run tests" "Error"
        exit 1
    }
    
    if (-not $prerequisites.PowerShellVersion) {
        Write-TestLog "PowerShell version 5.0 or higher is required" "Error"
        exit 1
    }
    
    if (-not $prerequisites.TestFilesExist) {
        Write-TestLog "Some test files are missing" "Warning"
    }
    
    if (-not $prerequisites.ModuleFilesExist) {
        Write-TestLog "Some module files are missing" "Warning"
    }
    
    Write-TestLog "Prerequisites check completed" "Success"
    
    # Run tests based on parameters
    if ($ModuleName) {
        # Run tests for specific module
        Write-TestLog "Running tests for specific module: $ModuleName" "Info"
        $testResult = Invoke-ModuleTests -ModuleName $ModuleName -TestType $TestType
        
        if ($testResult) {
            Write-TestLog "Module tests completed successfully" "Success"
            $exitCode = if ($testResult.FailedCount -eq 0) { 0 } else { 1 }
        } else {
            Write-TestLog "Module tests failed" "Error"
            $exitCode = 1
        }
    } else {
        # Run all tests
        Write-TestLog "Running all tests..." "Info"
        $testSummary = Invoke-AllTests -TestType $TestType
        
        if ($testSummary) {
            Write-TestLog "All tests completed successfully" "Success"
            $exitCode = if ($testSummary.TotalFailed -eq 0) { 0 } else { 1 }
        } else {
            Write-TestLog "All tests failed" "Error"
            $exitCode = 1
        }
    }
    
    Write-TestLog "RDS Test Suite Runner Completed" "Success"
    exit $exitCode
    
} catch {
    Write-TestLog "Test runner execution failed: $($_.Exception.Message)" "Error"
    exit 1
}

#endregion
