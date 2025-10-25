#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    File and Storage Services PowerShell Scripts Test Suite

.DESCRIPTION
    This test suite validates the functionality of the File and Storage Services
    PowerShell scripts using Pester testing framework.

.EXAMPLE
    .\Test-FileStorageServices.ps1

.NOTES
    Author: File and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges, Pester module
#>

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "FileStorage-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "FileStorage-Management.psm1") -Force
    Import-Module (Join-Path $modulePath "FileStorage-Troubleshooting.psm1") -Force
    Import-Module Pester -ErrorAction Stop
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Test configuration
$TestConfiguration = @{
    TestShares = @("TestShare1", "TestShare2", "TestShare3")
    TestPaths = @("C:\TestShares\Share1", "C:\TestShares\Share2", "C:\TestShares\Share3")
    TestBackupPath = "C:\TestBackups"
    TestReportPath = "C:\TestReports"
    TestLogPath = "C:\TestLogs"
}

# Setup test environment
function Initialize-TestEnvironment {
    Write-Host "Initializing test environment..." -ForegroundColor Yellow
    
    # Create test directories
    $testDirs = @(
        "C:\TestShares\Share1",
        "C:\TestShares\Share2", 
        "C:\TestShares\Share3",
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
    
    # Remove test shares
    foreach ($shareName in $TestConfiguration.TestShares) {
        try {
            $share = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
            if ($share) {
                Remove-SmbShare -Name $shareName -Force -ErrorAction SilentlyContinue
            }
        } catch {
            # Ignore errors during cleanup
        }
    }
    
    # Remove test directories
    $testDirs = @(
        "C:\TestShares",
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
Describe "File and Storage Services PowerShell Scripts" {
    
    BeforeAll {
        Initialize-TestEnvironment
    }
    
    AfterAll {
        Cleanup-TestEnvironment
    }
    
    Context "FileStorage-Core Module Tests" {
        
        It "Should import FileStorage-Core module successfully" {
            { Import-Module (Join-Path $modulePath "FileStorage-Core.psm1") -Force } | Should -Not -Throw
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
        
        It "Should have Test-FileStoragePrerequisites function" {
            { Test-FileStoragePrerequisites } | Should -Not -Throw
        }
        
        It "Should return boolean from Test-FileStoragePrerequisites" {
            $result = Test-FileStoragePrerequisites
            $result | Should -BeOfType [System.Boolean]
        }
        
        It "Should have Install-FileStoragePrerequisites function" {
            { Install-FileStoragePrerequisites } | Should -Not -Throw
        }
        
        It "Should have Get-FileServerStatus function" {
            { Get-FileServerStatus } | Should -Not -Throw
        }
        
        It "Should return object from Get-FileServerStatus" {
            $result = Get-FileServerStatus
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Start-FileServerServices function" {
            { Start-FileServerServices } | Should -Not -Throw
        }
        
        It "Should have Stop-FileServerServices function" {
            { Stop-FileServerServices } | Should -Not -Throw
        }
        
        It "Should have Get-StorageInformation function" {
            { Get-StorageInformation } | Should -Not -Throw
        }
        
        It "Should return object from Get-StorageInformation" {
            $result = Get-StorageInformation
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Test-FileServerHealth function" {
            { Test-FileServerHealth } | Should -Not -Throw
        }
        
        It "Should return object from Test-FileServerHealth" {
            $result = Test-FileServerHealth
            $result | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "FileStorage-Management Module Tests" {
        
        It "Should import FileStorage-Management module successfully" {
            { Import-Module (Join-Path $modulePath "FileStorage-Management.psm1") -Force } | Should -Not -Throw
        }
        
        It "Should have New-FileShare function" {
            { New-FileShare -ShareName "TestShare" -Path "C:\TestShares\TestShare" } | Should -Not -Throw
        }
        
        It "Should create file share successfully" {
            $shareName = "TestShare1"
            $sharePath = "C:\TestShares\Share1"
            
            { New-FileShare -ShareName $shareName -Path $sharePath -Description "Test Share" -FullAccess @("Administrators") } | Should -Not -Throw
            
            $share = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
            $share | Should -Not -BeNullOrEmpty
            $share.Name | Should -Be $shareName
            $share.Path | Should -Be $sharePath
        }
        
        It "Should have Remove-FileShare function" {
            { Remove-FileShare -ShareName "TestShare" -Force } | Should -Not -Throw
        }
        
        It "Should remove file share successfully" {
            $shareName = "TestShare2"
            $sharePath = "C:\TestShares\Share2"
            
            # Create share first
            New-FileShare -ShareName $shareName -Path $sharePath -Description "Test Share" -FullAccess @("Administrators")
            
            # Remove share
            { Remove-FileShare -ShareName $shareName -Force } | Should -Not -Throw
            
            $share = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
            $share | Should -BeNullOrEmpty
        }
        
        It "Should have Get-FileShareReport function" {
            { Get-FileShareReport } | Should -Not -Throw
        }
        
        It "Should return object from Get-FileShareReport" {
            $result = Get-FileShareReport
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Set-FileServerConfiguration function" {
            { Set-FileServerConfiguration -EnableSMB3 } | Should -Not -Throw
        }
        
        It "Should have Enable-FSRM function" {
            { Enable-FSRM -EnableQuotas } | Should -Not -Throw
        }
    }
    
    Context "FileStorage-Troubleshooting Module Tests" {
        
        It "Should import FileStorage-Troubleshooting module successfully" {
            { Import-Module (Join-Path $modulePath "FileStorage-Troubleshooting.psm1") -Force } | Should -Not -Throw
        }
        
        It "Should have Test-FileServerHealth function" {
            { Test-FileServerHealth } | Should -Not -Throw
        }
        
        It "Should return object from Test-FileServerHealth" {
            $result = Test-FileServerHealth
            $result | Should -Not -BeNullOrEmpty
            $result.Overall | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Get-FileServerDiagnosticReport function" {
            { Get-FileServerDiagnosticReport } | Should -Not -Throw
        }
        
        It "Should return object from Get-FileServerDiagnosticReport" {
            $result = Get-FileServerDiagnosticReport
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Repair-FileServerInstallation function" {
            { Repair-FileServerInstallation -RepairType "Services" } | Should -Not -Throw
        }
        
        It "Should return object from Repair-FileServerInstallation" {
            $result = Repair-FileServerInstallation -RepairType "Services"
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should have Watch-FileServerPerformance function" {
            { Watch-FileServerPerformance -Duration 5 -Interval 1 } | Should -Not -Throw
        }
        
        It "Should have Test-FileShareAccess function" {
            { Test-FileShareAccess -ShareName "TestShare" } | Should -Not -Throw
        }
        
        It "Should return object from Test-FileShareAccess" {
            $result = Test-FileShareAccess -ShareName "TestShare"
            $result | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Script Functionality Tests" {
        
        It "Should have Install-FileServer script" {
            $scriptPath = Join-Path $scriptPath "..\..\Scripts\FileServer\Install-FileServer.ps1"
            Test-Path $scriptPath | Should -Be $true
        }
        
        It "Should have Manage-FileShares script" {
            $scriptPath = Join-Path $scriptPath "..\..\Scripts\FileServer\Manage-FileShares.ps1"
            Test-Path $scriptPath | Should -Be $true
        }
        
        It "Should have Troubleshoot-FileServer script" {
            $scriptPath = Join-Path $scriptPath "..\..\Scripts\Troubleshooting\Troubleshoot-FileServer.ps1"
            Test-Path $scriptPath | Should -Be $true
        }
        
        It "Should have Manage-Storage script" {
            $scriptPath = Join-Path $scriptPath "..\..\Scripts\Storage\Manage-Storage.ps1"
            Test-Path $scriptPath | Should -Be $true
        }
        
        It "Should have Backup-FileServer script" {
            $scriptPath = Join-Path $scriptPath "..\..\Scripts\Backup\Backup-FileServer.ps1"
            Test-Path $scriptPath | Should -Be $true
        }
        
        It "Should have Monitor-FileServerPerformance script" {
            $scriptPath = Join-Path $scriptPath "..\..\Scripts\Performance\Monitor-FileServerPerformance.ps1"
            Test-Path $scriptPath | Should -Be $true
        }
    }
    
    Context "Integration Tests" {
        
        It "Should create and manage file shares end-to-end" {
            $shareName = "IntegrationTestShare"
            $sharePath = "C:\TestShares\IntegrationTest"
            
            # Create share
            { New-FileShare -ShareName $shareName -Path $sharePath -Description "Integration Test Share" -FullAccess @("Administrators") } | Should -Not -Throw
            
            # Verify share exists
            $share = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
            $share | Should -Not -BeNullOrEmpty
            
            # Test share access
            $accessTest = Test-FileShareAccess -ShareName $shareName
            $accessTest | Should -Not -BeNullOrEmpty
            
            # Remove share
            { Remove-FileShare -ShareName $shareName -Force } | Should -Not -Throw
            
            # Verify share removed
            $share = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
            $share | Should -BeNullOrEmpty
        }
        
        It "Should perform health check and generate report" {
            # Perform health check
            $healthCheck = Test-FileServerHealth
            $healthCheck | Should -Not -BeNullOrEmpty
            $healthCheck.Overall | Should -Not -BeNullOrEmpty
            
            # Generate diagnostic report
            $reportPath = Join-Path $TestConfiguration.TestReportPath "Test-Diagnostic-Report.html"
            $report = Get-FileServerDiagnosticReport -OutputPath $reportPath
            $report | Should -Not -BeNullOrEmpty
            
            # Verify report file exists
            Test-Path $reportPath | Should -Be $true
        }
        
        It "Should create and verify file share report" {
            # Create a test share
            $shareName = "ReportTestShare"
            $sharePath = "C:\TestShares\ReportTest"
            New-FileShare -ShareName $shareName -Path $sharePath -Description "Report Test Share" -FullAccess @("Administrators")
            
            # Generate share report
            $reportPath = Join-Path $TestConfiguration.TestReportPath "Test-Share-Report.html"
            $report = Get-FileShareReport -OutputPath $reportPath -IncludePermissions
            $report | Should -Not -BeNullOrEmpty
            
            # Verify report file exists
            Test-Path $reportPath | Should -Be $true
            
            # Cleanup
            Remove-FileShare -ShareName $shareName -Force
        }
    }
    
    Context "Error Handling Tests" {
        
        It "Should handle invalid share names gracefully" {
            { New-FileShare -ShareName "" -Path "C:\TestShares\Invalid" } | Should -Throw
        }
        
        It "Should handle invalid paths gracefully" {
            { New-FileShare -ShareName "InvalidPathShare" -Path "Z:\NonExistent\Path" } | Should -Throw
        }
        
        It "Should handle non-existent share removal gracefully" {
            { Remove-FileShare -ShareName "NonExistentShare" -Force } | Should -Not -Throw
        }
        
        It "Should handle invalid repair types gracefully" {
            { Repair-FileServerInstallation -RepairType "Invalid" } | Should -Throw
        }
    }
}

# Run the tests
Write-Host "`n=== Running File and Storage Services Test Suite ===" -ForegroundColor Cyan
Write-Host "Test Configuration:" -ForegroundColor White
Write-Host "  Test Shares: $($TestConfiguration.TestShares -join ', ')" -ForegroundColor White
Write-Host "  Test Paths: $($TestConfiguration.TestPaths -join ', ')" -ForegroundColor White
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
