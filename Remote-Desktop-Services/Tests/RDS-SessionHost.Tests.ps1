#Requires -Version 5.1
#Requires -Modules Pester

<#
.SYNOPSIS
    RDS Session Host Module Tests

.DESCRIPTION
    Comprehensive Pester tests for the RDS Session Host module functionality.

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
$ModulePath = ".\Modules\RDS-SessionHost.psm1"
if (Test-Path $ModulePath) {
    Import-Module $ModulePath -Force
} else {
    throw "RDS-SessionHost module not found at $ModulePath"
}

Describe "RDS Session Host Module Tests" -Tag "RDS-SessionHost" {
    
    Context "Module Import and Basic Functionality" {
        
        It "Should import the module without errors" {
            { Import-Module $ModulePath -Force } | Should -Not -Throw
        }
        
        It "Should have the expected exported functions" {
            $expectedFunctions = @(
                'Install-RDSSessionHost',
                'New-RDSSessionHostConfiguration',
                'Get-RDSSessionHostStatus',
                'Test-RDSSessionHostConnectivity',
                'Optimize-RDSSessionHostPerformance',
                'Remove-RDSSessionHostConfiguration'
            )
            
            $exportedFunctions = (Get-Module -Name "RDS-SessionHost").ExportedFunctions.Keys
            
            foreach ($function in $expectedFunctions) {
                $exportedFunctions | Should -Contain $function
            }
        }
        
        It "Should have the correct module version" {
            $module = Get-Module -Name "RDS-SessionHost"
            $module.Version | Should -Be "1.0.0"
        }
    }
    
    Context "Session Host Installation" {
        
        It "Should handle installation function without errors" {
            { Install-RDSSessionHost -StartService -SetAutoStart } | Should -Not -Throw
        }
        
        It "Should return installation result object" {
            $installResult = Install-RDSSessionHost -StartService -SetAutoStart
            
            $installResult | Should -Not -BeNullOrEmpty
            $installResult | Should -BeOfType [PSCustomObject]
            $installResult.PSObject.Properties.Name | Should -Contain "Success"
            $installResult.PSObject.Properties.Name | Should -Contain "Timestamp"
            $installResult.PSObject.Properties.Name | Should -Contain "ComputerName"
        }
        
        It "Should handle different installation parameters" {
            $installResult = Install-RDSSessionHost -StartService -SetAutoStart -IncludeManagementTools
            
            $installResult | Should -Not -BeNullOrEmpty
            $installResult.IncludeManagementTools | Should -Be $true
        }
    }
    
    Context "Session Host Configuration" {
        
        It "Should create session host configuration without errors" {
            { New-RDSSessionHostConfiguration -CollectionName "Test Collection" -MaxConnections 10 } | Should -Not -Throw
        }
        
        It "Should return configuration result object" {
            $configResult = New-RDSSessionHostConfiguration -CollectionName "Test Collection" -MaxConnections 10
            
            $configResult | Should -Not -BeNullOrEmpty
            $configResult | Should -BeOfType [PSCustomObject]
            $configResult.PSObject.Properties.Name | Should -Contain "Success"
            $configResult.PSObject.Properties.Name | Should -Contain "CollectionName"
            $configResult.PSObject.Properties.Name | Should -Contain "MaxConnections"
        }
        
        It "Should handle different configuration parameters" {
            $configResult = New-RDSSessionHostConfiguration -CollectionName "Test Collection" -MaxConnections 10 -IdleTimeout 30 -DisconnectTimeout 60
            
            $configResult | Should -Not -BeNullOrEmpty
            $configResult.IdleTimeout | Should -Be 30
            $configResult.DisconnectTimeout | Should -Be 60
        }
        
        It "Should validate collection name parameter" {
            { New-RDSSessionHostConfiguration -CollectionName $null -MaxConnections 10 } | Should -Not -Throw
        }
    }
    
    Context "Session Host Status" {
        
        It "Should get session host status without errors" {
            { Get-RDSSessionHostStatus } | Should -Not -Throw
        }
        
        It "Should return status information" {
            $status = Get-RDSSessionHostStatus
            
            $status | Should -Not -BeNullOrEmpty
            $status | Should -BeOfType [PSCustomObject]
            $status.PSObject.Properties.Name | Should -Contain "HealthStatus"
            $status.PSObject.Properties.Name | Should -Contain "ServiceStatus"
        }
        
        It "Should include service status information" {
            $status = Get-RDSSessionHostStatus
            
            $status.ServiceStatus | Should -Not -BeNullOrEmpty
            $status.ServiceStatus | Should -BeOfType [hashtable]
        }
    }
    
    Context "Connectivity Testing" {
        
        It "Should test session host connectivity without errors" {
            { Test-RDSSessionHostConnectivity } | Should -Not -Throw
        }
        
        It "Should return connectivity test result" {
            $connectivityTest = Test-RDSSessionHostConnectivity
            
            $connectivityTest | Should -Not -BeNullOrEmpty
            $connectivityTest | Should -BeOfType [PSCustomObject]
            $connectivityTest.PSObject.Properties.Name | Should -Contain "Success"
            $connectivityTest.PSObject.Properties.Name | Should -Contain "TestDuration"
        }
        
        It "Should handle different test durations" {
            $connectivityTest = Test-RDSSessionHostConnectivity -TestDuration 30
            
            $connectivityTest | Should -Not -BeNullOrEmpty
            $connectivityTest.TestDuration | Should -Be 30
        }
        
        It "Should handle different test types" {
            $testTypes = @("Basic", "Performance", "All")
            
            foreach ($testType in $testTypes) {
                { Test-RDSSessionHostConnectivity -TestType $testType } | Should -Not -Throw
            }
        }
    }
    
    Context "Performance Optimization" {
        
        It "Should optimize session host performance without errors" {
            { Optimize-RDSSessionHostPerformance } | Should -Not -Throw
        }
        
        It "Should return optimization result" {
            $optimizationResult = Optimize-RDSSessionHostPerformance
            
            $optimizationResult | Should -Not -BeNullOrEmpty
            $optimizationResult | Should -BeOfType [PSCustomObject]
            $optimizationResult.PSObject.Properties.Name | Should -Contain "Success"
            $optimizationResult.PSObject.Properties.Name | Should -Contain "OptimizationsApplied"
        }
        
        It "Should handle different optimization parameters" {
            $optimizationResult = Optimize-RDSSessionHostPerformance -EnableHardwareAcceleration -OptimizeMemory -EnableCompression
            
            $optimizationResult | Should -Not -BeNullOrEmpty
            $optimizationResult.EnableHardwareAcceleration | Should -Be $true
            $optimizationResult.OptimizeMemory | Should -Be $true
            $optimizationResult.EnableCompression | Should -Be $true
        }
    }
    
    Context "Configuration Removal" {
        
        It "Should remove session host configuration without errors" {
            { Remove-RDSSessionHostConfiguration -ConfirmRemoval } | Should -Not -Throw
        }
        
        It "Should require confirmation parameter" {
            { Remove-RDSSessionHostConfiguration } | Should -Throw
        }
        
        It "Should return removal result" {
            $removalResult = Remove-RDSSessionHostConfiguration -ConfirmRemoval
            
            $removalResult | Should -Not -BeNullOrEmpty
            $removalResult | Should -BeOfType [PSCustomObject]
            $removalResult.PSObject.Properties.Name | Should -Contain "Success"
        }
    }
    
    Context "Error Handling" {
        
        It "Should handle invalid parameters gracefully" {
            { Test-RDSSessionHostConnectivity -TestType "InvalidType" } | Should -Not -Throw
        }
        
        It "Should handle missing parameters gracefully" {
            { New-RDSSessionHostConfiguration -CollectionName $null -MaxConnections 0 } | Should -Not -Throw
        }
        
        It "Should handle negative values gracefully" {
            { New-RDSSessionHostConfiguration -CollectionName "Test" -MaxConnections -1 } | Should -Not -Throw
        }
    }
    
    Context "Performance" {
        
        It "Should complete status check within reasonable time" {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            Get-RDSSessionHostStatus | Out-Null
            $stopwatch.Stop()
            
            $stopwatch.ElapsedMilliseconds | Should -BeLessThan 5000
        }
        
        It "Should complete connectivity test within reasonable time" {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            Test-RDSSessionHostConnectivity -TestDuration 10 | Out-Null
            $stopwatch.Stop()
            
            $stopwatch.ElapsedMilliseconds | Should -BeLessThan 15000
        }
    }
    
    Context "Integration Tests" {
        
        It "Should work with RDS Core module" {
            # Import RDS Core module
            $coreModulePath = ".\Modules\RDS-Core.psm1"
            if (Test-Path $coreModulePath) {
                Import-Module $coreModulePath -Force
                
                # Test integration
                $prerequisites = Test-RDSPrerequisites
                $sessionHostStatus = Get-RDSSessionHostStatus
                
                $prerequisites | Should -Not -BeNullOrEmpty
                $sessionHostStatus | Should -Not -BeNullOrEmpty
            }
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
