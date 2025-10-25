#Requires -Version 5.1
#Requires -Modules Pester

<#
.SYNOPSIS
    RDS Core Module Tests

.DESCRIPTION
    Comprehensive Pester tests for the RDS Core module functionality.

.NOTES
    Author: Remote Desktop Services PowerShell Scripts
    Version: 1.0.0
    Requires: Pester 5.0+, PowerShell 5.1+, Administrator privileges
#>

# Test configuration
$TestConfiguration = @{
    TestTimeout = 300
    TestDataPath = ".\TestData"
    LogPath = ".\TestLogs"
}

# Ensure test directories exist
if (-not (Test-Path $TestConfiguration.TestDataPath)) {
    New-Item -Path $TestConfiguration.TestDataPath -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path $TestConfiguration.LogPath)) {
    New-Item -Path $TestConfiguration.LogPath -ItemType Directory -Force | Out-Null
}

# Import the module under test
$ModulePath = ".\Modules\RDS-Core.psm1"
if (Test-Path $ModulePath) {
    Import-Module $ModulePath -Force
} else {
    throw "RDS-Core module not found at $ModulePath"
}

Describe "RDS Core Module Tests" -Tag "RDS-Core" {
    
    Context "Module Import and Basic Functionality" {
        
        It "Should import the module without errors" {
            { Import-Module $ModulePath -Force } | Should -Not -Throw
        }
        
        It "Should have the expected exported functions" {
            $expectedFunctions = @(
                'Test-RDSPrerequisites',
                'Get-OperatingSystemVersion',
                'Write-RDSLog',
                'Get-RDSServiceStatus',
                'Test-RDSHealth',
                'Get-RDSFeatures',
                'Get-RDSSessions'
            )
            
            $exportedFunctions = (Get-Module -Name "RDS-Core").ExportedFunctions.Keys
            
            foreach ($function in $expectedFunctions) {
                $exportedFunctions | Should -Contain $function
            }
        }
        
        It "Should have the correct module version" {
            $module = Get-Module -Name "RDS-Core"
            $module.Version | Should -Be "1.0.0"
        }
    }
    
    Context "Prerequisites Testing" {
        
        It "Should test RDS prerequisites without errors" {
            { Test-RDSPrerequisites } | Should -Not -Throw
        }
        
        It "Should return a hashtable with expected properties" {
            $prerequisites = Test-RDSPrerequisites
            
            $prerequisites | Should -BeOfType [hashtable]
            $prerequisites.Keys | Should -Contain "PowerShellModuleAvailable"
            $prerequisites.Keys | Should -Contain "AdministratorPrivileges"
            $prerequisites.Keys | Should -Contain "WindowsVersion"
            $prerequisites.Keys | Should -Contain "RDSServicesRunning"
        }
        
        It "Should correctly identify administrator privileges" {
            $prerequisites = Test-RDSPrerequisites
            
            # This test assumes the test is running with administrator privileges
            $prerequisites.AdministratorPrivileges | Should -Be $true
        }
        
        It "Should correctly identify PowerShell version" {
            $prerequisites = Test-RDSPrerequisites
            
            $prerequisites.PowerShellVersion | Should -Be $true
        }
    }
    
    Context "Operating System Version" {
        
        It "Should get operating system version without errors" {
            { Get-OperatingSystemVersion } | Should -Not -Throw
        }
        
        It "Should return version information" {
            $osVersion = Get-OperatingSystemVersion
            
            $osVersion | Should -Not -BeNullOrEmpty
            $osVersion | Should -BeOfType [string]
        }
    }
    
    Context "Logging Functionality" {
        
        It "Should write log messages without errors" {
            { Write-RDSLog -Message "Test log message" -Level "Info" } | Should -Not -Throw
        }
        
        It "Should handle different log levels" {
            $logLevels = @("Info", "Warning", "Error", "Success")
            
            foreach ($level in $logLevels) {
                { Write-RDSLog -Message "Test message for $level" -Level $level } | Should -Not -Throw
            }
        }
        
        It "Should handle log file parameter" {
            $testLogFile = "$($TestConfiguration.LogPath)\TestLog.log"
            
            { Write-RDSLog -Message "Test log message" -Level "Info" -LogFile $testLogFile } | Should -Not -Throw
            
            if (Test-Path $testLogFile) {
                $logContent = Get-Content $testLogFile
                $logContent | Should -Not -BeNullOrEmpty
            }
        }
    }
    
    Context "Service Status" {
        
        It "Should get RDS service status without errors" {
            { Get-RDSServiceStatus } | Should -Not -Throw
        }
        
        It "Should return service status information" {
            $serviceStatus = Get-RDSServiceStatus
            
            $serviceStatus | Should -Not -BeNullOrEmpty
            $serviceStatus | Should -BeOfType [PSCustomObject]
            $serviceStatus.PSObject.Properties.Name | Should -Contain "Timestamp"
            $serviceStatus.PSObject.Properties.Name | Should -Contain "ComputerName"
        }
    }
    
    Context "Health Testing" {
        
        It "Should test RDS health without errors" {
            { Test-RDSHealth } | Should -Not -Throw
        }
        
        It "Should return health status information" {
            $healthTest = Test-RDSHealth
            
            $healthTest | Should -Not -BeNullOrEmpty
            $healthTest | Should -BeOfType [PSCustomObject]
            $healthTest.PSObject.Properties.Name | Should -Contain "OverallHealth"
        }
        
        It "Should handle different test types" {
            $testTypes = @("Quick", "Full", "Service", "Connectivity", "All")
            
            foreach ($testType in $testTypes) {
                { Test-RDSHealth -TestType $testType } | Should -Not -Throw
            }
        }
    }
    
    Context "Features and Sessions" {
        
        It "Should get RDS features without errors" {
            { Get-RDSFeatures } | Should -Not -Throw
        }
        
        It "Should get RDS sessions without errors" {
            { Get-RDSSessions } | Should -Not -Throw
        }
        
        It "Should return features information" {
            $features = Get-RDSFeatures
            
            $features | Should -Not -BeNullOrEmpty
            $features | Should -BeOfType [PSCustomObject]
        }
        
        It "Should return sessions information" {
            $sessions = Get-RDSSessions
            
            $sessions | Should -Not -BeNullOrEmpty
            $sessions | Should -BeOfType [PSCustomObject]
        }
    }
    
    Context "Error Handling" {
        
        It "Should handle invalid parameters gracefully" {
            { Test-RDSHealth -TestType "InvalidType" } | Should -Not -Throw
        }
        
        It "Should handle missing parameters gracefully" {
            { Write-RDSLog -Message $null -Level "Info" } | Should -Not -Throw
        }
    }
    
    Context "Performance" {
        
        It "Should complete prerequisite testing within reasonable time" {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            Test-RDSPrerequisites | Out-Null
            $stopwatch.Stop()
            
            $stopwatch.ElapsedMilliseconds | Should -BeLessThan 5000
        }
        
        It "Should complete health testing within reasonable time" {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            Test-RDSHealth -TestType "Quick" | Out-Null
            $stopwatch.Stop()
            
            $stopwatch.ElapsedMilliseconds | Should -BeLessThan 10000
        }
    }
}

# Cleanup
AfterAll {
    # Clean up test files
    $testLogFile = "$($TestConfiguration.LogPath)\TestLog.log"
    if (Test-Path $testLogFile) {
        Remove-Item $testLogFile -Force
    }
}
