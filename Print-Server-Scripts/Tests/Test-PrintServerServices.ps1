#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Print Server PowerShell Scripts Test Suite

.DESCRIPTION
    This test suite validates the functionality of the Print Server PowerShell scripts
    using Pester testing framework.

.EXAMPLE
    .\Test-PrintServerServices.ps1

.NOTES
    Author: Print Server PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges, Pester module
#>

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "PrintServer-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "PrintServer-Management.psm1") -Force
    Import-Module (Join-Path $modulePath "PrintServer-Troubleshooting.psm1") -Force
    Import-Module Pester -ErrorAction Stop
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Test configuration
$TestConfiguration = @{
    TestPrinters = @("TestPrinter1", "TestPrinter2", "TestPrinter3")
    TestDrivers = @("Generic / Text Only")
    TestBackupPath = "C:\TestBackups"
    TestReportPath = "C:\TestReports"
    TestLogPath = "C:\TestLogs"
}

# Setup test environment
function Initialize-TestEnvironment {
    Write-Host "Initializing test environment..." -ForegroundColor Yellow
    
    # Create test directories
    $testDirs = @(
        $TestConfiguration.TestBackupPath,
        $TestConfiguration.TestReportPath,
        $TestConfiguration.TestLogPath
    )
    
    foreach ($dir in $testDirs) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
    }
    
    Write-Host "Test environment initialized" -ForegroundColor Green
}

# Cleanup test environment
function Cleanup-TestEnvironment {
    Write-Host "Cleaning up test environment..." -ForegroundColor Yellow
    
    # Remove test printers
    foreach ($printerName in $TestConfiguration.TestPrinters) {
        try {
            $printer = Get-Printer -Name $printerName -ErrorAction SilentlyContinue
            if ($printer) {
                Remove-Printer -Name $printerName -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # Ignore errors during cleanup
        }
    }
    
    # Remove test directories
    $testDirs = @(
        $TestConfiguration.TestBackupPath,
        $TestConfiguration.TestReportPath,
        $TestConfiguration.TestLogPath
    )
    
    foreach ($dir in $testDirs) {
        if (Test-Path $dir) {
            Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Host "Test environment cleaned up" -ForegroundColor Green
}

# Test suite
Describe "Print Server PowerShell Scripts" {
    
    BeforeAll {
        Initialize-TestEnvironment
    }
    
    AfterAll {
        Cleanup-TestEnvironment
    }
    
    Context "PrintServer-Core Module Tests" {
        
        It "Should import PrintServer-Core module successfully" {
            { Import-Module (Join-Path $modulePath "PrintServer-Core.psm1") -Force } | Should -Not -Throw
        }
        
        It "Should have Test-IsAdministrator function" {
            { Test-IsAdministrator } | Should -Not -Throw
        }
        
        It "Should return boolean from Test-IsAdministrator" {
            $result = Test-IsAdministrator
            $result | Should -BeOfType [System.Boolean]
        }
        
        It "Should have Get-OperatingSystemVersion function" {
            { Get-OperatingSystemVersion } | Should -Not -Throw
        }
        
        It "Should return Version object from Get-OperatingSystemVersion" {
            $result = Get-OperatingSystemVersion
            $result | Should -BeOfType [System.Version]
        }
        
        It "Should have Write-Log function" {
            { Write-Log -Message "Test message" } | Should -Not -Throw
        }
        
        It "Should have Test-PrintServerPrerequisites function" {
            { Test-PrintServerPrerequisites } | Should -Not -Throw
        }
        
        It "Should return boolean from Test-PrintServerPrerequisites" {
            $result = Test-PrintServerPrerequisites
            $result | Should -BeOfType [System.Boolean]
        }
        
        It "Should have Install-PrintServerPrerequisites function" {
            { Install-PrintServerPrerequisites } | Should -Not -Throw
        }
        
        It "Should have Get-PrintServerStatus function" {
            { Get-PrintServerStatus } | Should -Not -Throw
        }
        
        It "Should return object from Get-PrintServerStatus" {
            $result = Get-PrintServerStatus
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Start-PrintServerServices function" {
            { Start-PrintServerServices } | Should -Not -Throw
        }
        
        It "Should have Stop-PrintServerServices function" {
            { Stop-PrintServerServices } | Should -Not -Throw
        }
        
        It "Should have Test-PrintServerHealth function" {
            { Test-PrintServerHealth } | Should -Not -Throw
        }
        
        It "Should return object from Test-PrintServerHealth" {
            $result = Test-PrintServerHealth
            $result | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "PrintServer-Management Module Tests" {
        
        It "Should import PrintServer-Management module successfully" {
            { Import-Module (Join-Path $modulePath "PrintServer-Management.psm1") -Force } | Should -Not -Throw
        }
        
        It "Should have New-PrintServerPrinter function" {
            { New-PrintServerPrinter -PrinterName "TestPrinter" -DriverName "Generic / Text Only" -PortName "LPT1:" } | Should -Not -Throw
        }
        
        It "Should create printer successfully" {
            $printerName = "TestPrinter1"
            $driverName = "Generic / Text Only"
            $portName = "LPT1:"
            
            { New-PrintServerPrinter -PrinterName $printerName -DriverName $driverName -PortName $portName -Description "Test Printer" } | Should -Not -Throw
            
            $printer = Get-Printer -Name $printerName -ErrorAction SilentlyContinue
            $printer | Should -Not -BeNullOrEmpty
            $printer.Name | Should -Be $printerName
            $printer.DriverName | Should -Be $driverName
            $printer.PortName | Should -Be $portName
        }
        
        It "Should have Remove-PrintServerPrinter function" {
            { Remove-PrintServerPrinter -PrinterName "TestPrinter" -Force } | Should -Not -Throw
        }
        
        It "Should remove printer successfully" {
            $printerName = "TestPrinter2"
            $driverName = "Generic / Text Only"
            $portName = "LPT1:"
            
            # Create printer first
            New-PrintServerPrinter -PrinterName $printerName -DriverName $driverName -PortName $portName -Description "Test Printer"
            
            # Remove printer
            { Remove-PrintServerPrinter -PrinterName $printerName -Force } | Should -Not -Throw
            
            $printer = Get-Printer -Name $printerName -ErrorAction SilentlyContinue
            $printer | Should -BeNullOrEmpty
        }
        
        It "Should have Install-PrintServerDriver function" {
            { Install-PrintServerDriver -DriverName "Generic / Text Only" -FromWindowsUpdate } | Should -Not -Throw
        }
        
        It "Should have Remove-PrintServerDriver function" {
            { Remove-PrintServerDriver -DriverName "Generic / Text Only" -Force } | Should -Not -Throw
        }
        
        It "Should have Get-PrintServerReport function" {
            { Get-PrintServerReport } | Should -Not -Throw
        }
        
        It "Should return object from Get-PrintServerReport" {
            $result = Get-PrintServerReport
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Set-PrintServerConfiguration function" {
            { Set-PrintServerConfiguration -EnableWebManagement } | Should -Not -Throw
        }
    }
    
    Context "PrintServer-Troubleshooting Module Tests" {
        
        It "Should import PrintServer-Troubleshooting module successfully" {
            { Import-Module (Join-Path $modulePath "PrintServer-Troubleshooting.psm1") -Force } | Should -Not -Throw
        }
        
        It "Should have Test-PrintServerHealth function" {
            { Test-PrintServerHealth } | Should -Not -Throw
        }
        
        It "Should return object from Test-PrintServerHealth" {
            $result = Test-PrintServerHealth
            $result | Should -Not -BeNullOrEmpty
            $result.Overall | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Get-PrintServerDiagnosticReport function" {
            { Get-PrintServerDiagnosticReport } | Should -Not -Throw
        }
        
        It "Should return object from Get-PrintServerDiagnosticReport" {
            $result = Get-PrintServerDiagnosticReport
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Repair-PrintServerInstallation function" {
            { Repair-PrintServerInstallation -RepairType "Services" } | Should -Not -Throw
        }
        
        It "Should return object from Repair-PrintServerInstallation" {
            $result = Repair-PrintServerInstallation -RepairType "Services"
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Watch-PrintServerPerformance function" {
            { Watch-PrintServerPerformance -Duration 5 -Interval 1 } | Should -Not -Throw
        }
        
        It "Should have Test-PrinterAccess function" {
            { Test-PrinterAccess -PrinterName "TestPrinter" } | Should -Not -Throw
        }
        
        It "Should return object from Test-PrinterAccess" {
            $result = Test-PrinterAccess -PrinterName "TestPrinter"
            $result | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Script Functionality Tests" {
        
        It "Should have Install-PrintServer script" {
            $scriptPath = Join-Path $scriptPath "..\..\Scripts\PrintServer\Install-PrintServer.ps1"
            Test-Path $scriptPath | Should -Be $true
        }
        
        It "Should have Manage-Printers script" {
            $scriptPath = Join-Path $scriptPath "..\..\Scripts\PrinterManagement\Manage-Printers.ps1"
            Test-Path $scriptPath | Should -Be $true
        }
        
        It "Should have Manage-PrintQueues script" {
            $scriptPath = Join-Path $scriptPath "..\..\Scripts\PrintQueue\Manage-PrintQueues.ps1"
            Test-Path $scriptPath | Should -Be $true
        }
        
        It "Should have Troubleshoot-PrintServer script" {
            $scriptPath = Join-Path $scriptPath "..\..\Scripts\Troubleshooting\Troubleshoot-PrintServer.ps1"
            Test-Path $scriptPath | Should -Be $true
        }
        
        It "Should have Backup-PrintServer script" {
            $scriptPath = Join-Path $scriptPath "..\..\Scripts\Backup\Backup-PrintServer.ps1"
            Test-Path $scriptPath | Should -Be $true
        }
    }
    
    Context "Integration Tests" {
        
        It "Should create and manage printers end-to-end" {
            $printerName = "IntegrationTestPrinter"
            $driverName = "Generic / Text Only"
            $portName = "LPT1:"
            
            # Create printer
            { New-PrintServerPrinter -PrinterName $printerName -DriverName $driverName -PortName $portName -Description "Integration Test Printer" } | Should -Not -Throw
            
            # Verify printer exists
            $printer = Get-Printer -Name $printerName -ErrorAction SilentlyContinue
            $printer | Should -Not -BeNullOrEmpty
            
            # Test printer access
            $accessTest = Test-PrinterAccess -PrinterName $printerName
            $accessTest | Should -Not -BeNullOrEmpty
            
            # Remove printer
            { Remove-PrintServerPrinter -PrinterName $printerName -Force } | Should -Not -Throw
            
            # Verify printer removed
            $printer = Get-Printer -Name $printerName -ErrorAction SilentlyContinue
            $printer | Should -BeNullOrEmpty
        }
        
        It "Should perform health check and generate report" {
            # Perform health check
            $healthCheck = Test-PrintServerHealth
            $healthCheck | Should -Not -BeNullOrEmpty
            $healthCheck.Overall | Should -Not -BeNullOrEmpty
            
            # Generate diagnostic report
            $reportPath = Join-Path $TestConfiguration.TestReportPath "Test-Diagnostic-Report.html"
            $report = Get-PrintServerDiagnosticReport -OutputPath $reportPath
            $report | Should -Not -BeNullOrEmpty
            
            # Verify report file exists
            Test-Path $reportPath | Should -Be $true
        }
        
        It "Should create and verify print server report" {
            # Create a test printer
            $printerName = "ReportTestPrinter"
            $driverName = "Generic / Text Only"
            $portName = "LPT1:"
            New-PrintServerPrinter -PrinterName $printerName -DriverName $driverName -PortName $portName -Description "Report Test Printer"
            
            # Generate print server report
            $reportPath = Join-Path $TestConfiguration.TestReportPath "Test-PrintServer-Report.html"
            $report = Get-PrintServerReport -OutputPath $reportPath -IncludePrintJobs
            $report | Should -Not -BeNullOrEmpty
            
            # Verify report file exists
            Test-Path $reportPath | Should -Be $true
            
            # Cleanup
            Remove-PrintServerPrinter -PrinterName $printerName -Force
        }
    }
    
    Context "Error Handling Tests" {
        
        It "Should handle invalid printer names gracefully" {
            { New-PrintServerPrinter -PrinterName "" -DriverName "Generic / Text Only" -PortName "LPT1:" } | Should -Throw
        }
        
        It "Should handle invalid driver names gracefully" {
            { New-PrintServerPrinter -PrinterName "InvalidDriverPrinter" -DriverName "NonExistentDriver" -PortName "LPT1:" } | Should -Throw
        }
        
        It "Should handle non-existent printer removal gracefully" {
            { Remove-PrintServerPrinter -PrinterName "NonExistentPrinter" -Force } | Should -Not -Throw
        }
        
        It "Should handle invalid repair types gracefully" {
            { Repair-PrintServerInstallation -RepairType "Invalid" } | Should -Throw
        }
    }
}

# Run the tests
Write-Host "`n=== Running Print Server Test Suite ===" -ForegroundColor Cyan
Write-Host "Test Configuration:" -ForegroundColor White
Write-Host "  Test Printers: $($TestConfiguration.TestPrinters -join ', ')" -ForegroundColor White
Write-Host "  Test Drivers: $($TestConfiguration.TestDrivers -join ', ')" -ForegroundColor White
Write-Host "  Backup Path: $($TestConfiguration.TestBackupPath)" -ForegroundColor White
Write-Host "  Report Path: $($TestConfiguration.TestReportPath)" -ForegroundColor White
Write-Host "  Log Path: $($TestConfiguration.TestLogPath)" -ForegroundColor White

try {
    $testResults = Invoke-Pester -Script $MyInvocation.MyCommand.Path -PassThru
    
    Write-Host "`n=== Test Results Summary ===" -ForegroundColor Cyan
    Write-Host "Total Tests: $($testResults.TotalCount)" -ForegroundColor White
    Write-Host "Passed: $($testResults.PassedCount)" -ForegroundColor Green
    Write-Host "Failed: $($testResults.FailedCount)" -ForegroundColor Red
    Write-Host "Skipped: $($testResults.SkippedCount)" -ForegroundColor Yellow
    Write-Host "Duration: $($testResults.Duration)" -ForegroundColor White
    
    if ($testResults.FailedCount -eq 0) {
        Write-Host "`nAll tests passed successfully!" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "`nSome tests failed. Please review the output above." -ForegroundColor Red
        exit 1
    }
    
} catch {
    Write-Host "`nTest execution failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
