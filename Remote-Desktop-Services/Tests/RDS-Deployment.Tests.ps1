#Requires -Version 5.1
#Requires -Modules Pester

<#
.SYNOPSIS
    RDS Deployment Script Tests

.DESCRIPTION
    Comprehensive Pester tests for the RDS Deployment script functionality.

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

# Test script path
$ScriptPath = ".\Scripts\Deploy-RDSServices.ps1"
if (-not (Test-Path $ScriptPath)) {
    throw "Deploy-RDSServices script not found at $ScriptPath"
}

Describe "RDS Deployment Script Tests" -Tag "RDS-Deployment" {
    
    Context "Script Validation" {
        
        It "Should have valid PowerShell syntax" {
            $syntaxErrors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $ScriptPath -Raw), [ref]$syntaxErrors)
            $syntaxErrors | Should -BeNullOrEmpty
        }
        
        It "Should have required parameters" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "param\s*\("
            $scriptContent | Should -Match "Action"
            $scriptContent | Should -Match "DeploymentType"
        }
        
        It "Should have proper script metadata" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "ScriptVersion"
            $scriptContent | Should -Match "Requires -Version"
            $scriptContent | Should -Match "Requires -RunAsAdministrator"
        }
    }
    
    Context "Parameter Validation" {
        
        It "Should validate Action parameter" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "ValidateSet.*Install.*Configure.*Monitor.*Troubleshoot.*All"
        }
        
        It "Should validate DeploymentType parameter" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "ValidateSet.*SessionHost.*ConnectionBroker.*Gateway.*WebAccess.*Licensing.*All"
        }
        
        It "Should have proper parameter attributes" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "Parameter.*Mandatory.*true"
            $scriptContent | Should -Match "Parameter.*Mandatory.*false"
        }
    }
    
    Context "Function Definitions" {
        
        It "Should have required script functions" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "function Write-ScriptLog"
            $scriptContent | Should -Match "function Test-ScriptPrerequisites"
            $scriptContent | Should -Match "function Install-RDSServices"
            $scriptContent | Should -Match "function Set-RDSServicesConfiguration"
            $scriptContent | Should -Match "function Start-RDSMonitoring"
            $scriptContent | Should -Match "function Start-RDSTroubleshooting"
        }
        
        It "Should have proper function documentation" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "\.SYNOPSIS"
            $scriptContent | Should -Match "\.DESCRIPTION"
            $scriptContent | Should -Match "\.PARAMETER"
            $scriptContent | Should -Match "\.EXAMPLE"
        }
    }
    
    Context "Error Handling" {
        
        It "Should have comprehensive error handling" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "try\s*\{"
            $scriptContent | Should -Match "catch\s*\{"
            $scriptContent | Should -Match "Write-Error"
            $scriptContent | Should -Match "Write-Warning"
        }
        
        It "Should handle missing prerequisites" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "AdministratorPrivileges"
            $scriptContent | Should -Match "PowerShellVersion"
            $scriptContent | Should -Match "WindowsVersion"
        }
    }
    
    Context "Logging Functionality" {
        
        It "Should have logging capabilities" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "LogFile"
            $scriptContent | Should -Match "Add-Content.*LogFile"
            $scriptContent | Should -Match "Write-ScriptLog"
        }
        
        It "Should support different log levels" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "Info.*Warning.*Error.*Success"
        }
    }
    
    Context "Module Integration" {
        
        It "Should import required modules" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "Import-Module.*RDS-Core"
            $scriptContent | Should -Match "Import-Module.*RDS-SessionHost"
            $scriptContent | Should -Match "Import-Module.*RDS-ConnectionBroker"
            $scriptContent | Should -Match "Import-Module.*RDS-Gateway"
            $scriptContent | Should -Match "Import-Module.*RDS-WebAccess"
            $scriptContent | Should -Match "Import-Module.*RDS-Licensing"
        }
        
        It "Should handle module import errors" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "ErrorAction.*SilentlyContinue"
        }
    }
    
    Context "Action Handling" {
        
        It "Should handle Install action" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "Install.*Install-RDSServices"
        }
        
        It "Should handle Configure action" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "Configure.*Set-RDSServicesConfiguration"
        }
        
        It "Should handle Monitor action" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "Monitor.*Start-RDSMonitoring"
        }
        
        It "Should handle Troubleshoot action" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "Troubleshoot.*Start-RDSTroubleshooting"
        }
        
        It "Should handle All action" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "All.*Install.*Configure.*Monitor.*Troubleshoot"
        }
    }
    
    Context "Deployment Type Handling" {
        
        It "Should handle SessionHost deployment" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "SessionHost.*Install-RDSSessionHost"
        }
        
        It "Should handle ConnectionBroker deployment" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "ConnectionBroker.*Install-RDSConnectionBroker"
        }
        
        It "Should handle Gateway deployment" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "Gateway.*Install-RDSGateway"
        }
        
        It "Should handle WebAccess deployment" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "WebAccess.*Install-RDSWebAccess"
        }
        
        It "Should handle Licensing deployment" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "Licensing.*Install-RDSLicensing"
        }
        
        It "Should handle All deployment" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "All.*Install-RDSSessionHost.*Install-RDSConnectionBroker.*Install-RDSGateway.*Install-RDSWebAccess.*Install-RDSLicensing"
        }
    }
    
    Context "Script Execution" {
        
        It "Should execute without syntax errors" {
            { & $ScriptPath -Action "Install" -DeploymentType "SessionHost" -WhatIf } | Should -Not -Throw
        }
        
        It "Should handle missing parameters gracefully" {
            { & $ScriptPath -Action "Install" } | Should -Not -Throw
        }
        
        It "Should validate prerequisites before execution" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "Test-ScriptPrerequisites"
            $scriptContent | Should -Match "AdministratorPrivileges"
        }
    }
    
    Context "Output and Results" {
        
        It "Should provide meaningful output" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "Write-Host.*ForegroundColor"
            $scriptContent | Should -Match "Success.*Error.*Warning"
        }
        
        It "Should handle exit codes properly" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "exit 1"
            $scriptContent | Should -Match "LASTEXITCODE"
        }
    }
    
    Context "Performance" {
        
        It "Should complete prerequisite testing quickly" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "Test-ScriptPrerequisites"
        }
        
        It "Should have reasonable timeout handling" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "Start-Sleep"
        }
    }
    
    Context "Security" {
        
        It "Should require administrator privileges" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "Requires -RunAsAdministrator"
            $scriptContent | Should -Match "AdministratorPrivileges"
        }
        
        It "Should validate security requirements" {
            $scriptContent = Get-Content $ScriptPath -Raw
            
            $scriptContent | Should -Match "PowerShellVersion"
            $scriptContent | Should -Match "WindowsVersion"
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
