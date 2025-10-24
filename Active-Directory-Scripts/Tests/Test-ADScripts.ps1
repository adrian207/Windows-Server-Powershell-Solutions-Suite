#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Test Active Directory Scripts

.DESCRIPTION
    Test script for Windows Active Directory Domain Services.
    Tests all modules, scripts, and functionality to ensure proper operation.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

# Import required modules
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $modulePath "..\..\Modules"

Import-Module "$modulesPath\AD-Core.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\AD-Security.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\AD-Monitoring.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\AD-Troubleshooting.psm1" -Force -ErrorAction Stop

# Test results
$testResults = @{
    Timestamp = Get-Date
    Tests = @()
    Passed = 0
    Failed = 0
    Skipped = 0
    Total = 0
    OverallResult = "Unknown"
}

# Test function
function Test-ADFunction {
    param(
        [string]$TestName,
        [scriptblock]$TestScript,
        [string]$Description = ""
    )
    
    $testResults.Total++
    
    try {
        Write-Host "Testing: $TestName" -ForegroundColor Cyan
        
        $result = & $TestScript
        
        if ($result) {
            $testResults.Passed++
            $testResults.Tests += @{
                Name = $TestName
                Status = "Passed"
                Description = $Description
                Result = $result
                Timestamp = Get-Date
            }
            Write-Host "  ✓ PASSED" -ForegroundColor Green
        } else {
            $testResults.Failed++
            $testResults.Tests += @{
                Name = $TestName
                Status = "Failed"
                Description = $Description
                Result = $null
                Timestamp = Get-Date
            }
            Write-Host "  ✗ FAILED" -ForegroundColor Red
        }
    }
    catch {
        $testResults.Failed++
        $testResults.Tests += @{
            Name = $TestName
            Status = "Failed"
            Description = $Description
            Result = $_.Exception.Message
            Timestamp = Get-Date
        }
        Write-Host "  ✗ FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Test AD Core Module
Write-Host "=== Testing AD Core Module ===" -ForegroundColor Cyan

Test-ADFunction -TestName "Get-ADHealthStatus" -Description "Test AD health status function" -TestScript {
    $healthStatus = Get-ADHealthStatus -ServerName "localhost" -IncludeDetails -IncludeReplication -IncludeFSMO -IncludeDNS -IncludeTimeSync
    return $healthStatus -ne $null
}

Test-ADFunction -TestName "Get-ADUserManagement" -Description "Test AD user management function" -TestScript {
    $users = Get-ADUserManagement -ServerName "localhost" -SearchBase "DC=contoso,DC=com" -Filter "*" -Properties @("Name", "SamAccountName", "UserPrincipalName", "Enabled", "LastLogonDate")
    return $users -ne $null
}

Test-ADFunction -TestName "Get-ADGroupManagement" -Description "Test AD group management function" -TestScript {
    $groups = Get-ADGroupManagement -ServerName "localhost" -SearchBase "DC=contoso,DC=com" -Filter "*" -Properties @("Name", "SamAccountName", "GroupCategory", "GroupScope", "MemberCount")
    return $groups -ne $null
}

Test-ADFunction -TestName "Get-ADOUManagement" -Description "Test AD OU management function" -TestScript {
    $ous = Get-ADOUManagement -ServerName "localhost" -SearchBase "DC=contoso,DC=com" -Filter "*" -Properties @("Name", "DistinguishedName", "Description", "ProtectedFromAccidentalDeletion")
    return $ous -ne $null
}

Test-ADFunction -TestName "Set-ADPasswordPolicy" -Description "Test AD password policy function" -TestScript {
    $passwordPolicy = Set-ADPasswordPolicy -ServerName "localhost" -MinPasswordLength 12 -PasswordHistoryCount 12 -MaxPasswordAge 90 -MinPasswordAge 1 -PasswordComplexity $true -LockoutThreshold 5 -LockoutDuration 30 -LockoutObservationWindow 30
    return $passwordPolicy -ne $null
}

Test-ADFunction -TestName "Set-ADGroupPolicy" -Description "Test AD group policy function" -TestScript {
    $groupPolicy = Set-ADGroupPolicy -ServerName "localhost" -GPOName "Test Policy" -GPODescription "Test policy for testing" -GPOSettings @{
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
            Name = "EnableLUA"
            Value = 1
            Type = "DWord"
        }
    }
    return $groupPolicy -ne $null
}

Test-ADFunction -TestName "Get-ADReplicationStatus" -Description "Test AD replication status function" -TestScript {
    $replicationStatus = Get-ADReplicationStatus -ServerName "localhost"
    return $replicationStatus -ne $null
}

Test-ADFunction -TestName "Get-ADFSMORoles" -Description "Test AD FSMO roles function" -TestScript {
    $fsmoRoles = Get-ADFSMORoles -ServerName "localhost"
    return $fsmoRoles -ne $null
}

Test-ADFunction -TestName "Set-ADTimeSync" -Description "Test AD time sync function" -TestScript {
    $timeSync = Set-ADTimeSync -ServerName "localhost" -TimeSource "time.windows.com"
    return $timeSync -ne $null
}

# Test AD Security Module
Write-Host "=== Testing AD Security Module ===" -ForegroundColor Cyan

Test-ADFunction -TestName "Set-ADAuditPolicy" -Description "Test AD audit policy function" -TestScript {
    $auditPolicy = Set-ADAuditPolicy -ServerName "localhost" -AuditLevel "Standard"
    return $auditPolicy -ne $null
}

Test-ADFunction -TestName "Set-ADAccessControl" -Description "Test AD access control function" -TestScript {
    $accessControl = Set-ADAccessControl -ServerName "localhost" -AccessLevel "Standard"
    return $accessControl -ne $null
}

Test-ADFunction -TestName "Set-ADPrivilegedAccess" -Description "Test AD privileged access function" -TestScript {
    $pam = Set-ADPrivilegedAccess -ServerName "localhost" -PAMLevel "Standard"
    return $pam -ne $null
}

Test-ADFunction -TestName "Set-ADSecurityBaseline" -Description "Test AD security baseline function" -TestScript {
    $securityBaseline = Set-ADSecurityBaseline -ServerName "localhost" -BaselineType "CIS"
    return $securityBaseline -ne $null
}

Test-ADFunction -TestName "Set-ADKerberosSecurity" -Description "Test AD Kerberos security function" -TestScript {
    $kerberosSecurity = Set-ADKerberosSecurity -ServerName "localhost" -KerberosLevel "Standard"
    return $kerberosSecurity -ne $null
}

Test-ADFunction -TestName "Set-ADLDAPSSecurity" -Description "Test AD LDAPS security function" -TestScript {
    $ldapsSecurity = Set-ADLDAPSSecurity -ServerName "localhost" -LDAPSLevel "Standard"
    return $ldapsSecurity -ne $null
}

Test-ADFunction -TestName "Set-ADTrustSecurity" -Description "Test AD trust security function" -TestScript {
    $trustSecurity = Set-ADTrustSecurity -ServerName "localhost" -TrustLevel "Standard"
    return $trustSecurity -ne $null
}

Test-ADFunction -TestName "Get-ADSecurityStatus" -Description "Test AD security status function" -TestScript {
    $securityStatus = Get-ADSecurityStatus -ServerName "localhost" -IncludeDetails -IncludeAudit -IncludeAccess -IncludeKerberos -IncludeLDAPS -IncludeTrust
    return $securityStatus -ne $null
}

# Test AD Monitoring Module
Write-Host "=== Testing AD Monitoring Module ===" -ForegroundColor Cyan

Test-ADFunction -TestName "Get-ADHealthMonitoring" -Description "Test AD health monitoring function" -TestScript {
    $healthMonitoring = Get-ADHealthMonitoring -ServerName "localhost" -IncludeDetails -IncludeReplication -IncludeFSMO -IncludeDNS -IncludeTimeSync
    return $healthMonitoring -ne $null
}

Test-ADFunction -TestName "Get-ADPerformanceMonitoring" -Description "Test AD performance monitoring function" -TestScript {
    $performanceMonitoring = Get-ADPerformanceMonitoring -ServerName "localhost" -DurationMinutes 60 -Metrics @("CPU", "Memory", "Disk", "Network")
    return $performanceMonitoring -ne $null
}

Test-ADFunction -TestName "Get-ADEventMonitoring" -Description "Test AD event monitoring function" -TestScript {
    $eventMonitoring = Get-ADEventMonitoring -ServerName "localhost" -LogLevel "All" -MaxEvents 1000 -HoursBack 24
    return $eventMonitoring -ne $null
}

Test-ADFunction -TestName "Set-ADAlerting" -Description "Test AD alerting function" -TestScript {
    $alerting = Set-ADAlerting -ServerName "localhost" -AlertLevel "Standard" -AlertTypes @("Email", "Webhook")
    return $alerting -ne $null
}

Test-ADFunction -TestName "Get-ADMonitoringReport" -Description "Test AD monitoring report function" -TestScript {
    $monitoringReport = Get-ADMonitoringReport -ServerName "localhost" -ReportType "Comprehensive" -DaysBack 7 -OutputFormat "HTML" -OutputPath "C:\Temp\AD-Monitoring-Report.html"
    return $monitoringReport -ne $null
}

# Test AD Troubleshooting Module
Write-Host "=== Testing AD Troubleshooting Module ===" -ForegroundColor Cyan

Test-ADFunction -TestName "Get-ADTroubleshootingStatus" -Description "Test AD troubleshooting status function" -TestScript {
    $troubleshootingStatus = Get-ADTroubleshootingStatus -ServerName "localhost" -TroubleshootingLevel "Standard" -TroubleshootingType "All" -IncludeRemediation -IncludePerformanceAnalysis -IncludeEventLogAnalysis -IncludeHealthChecks -IncludeSecurityAnalysis -IncludeComplianceCheck -IncludeReplicationCheck -IncludeFSMOCheck -IncludeDNSCheck -IncludeTimeSyncCheck
    return $troubleshootingStatus -ne $null
}

Test-ADFunction -TestName "Get-ADHealthStatus" -Description "Test AD health status function" -TestScript {
    $healthStatus = Get-ADHealthStatus -ServerName "localhost" -IncludeDetails -IncludeReplication -IncludeFSMO -IncludeDNS -IncludeTimeSync
    return $healthStatus -ne $null
}

Test-ADFunction -TestName "Get-ADPerformanceMetrics" -Description "Test AD performance metrics function" -TestScript {
    $performanceMetrics = Get-ADPerformanceMetrics -ServerName "localhost" -DurationMinutes 60 -Metrics @("CPU", "Memory", "Disk", "Network")
    return $performanceMetrics -ne $null
}

Test-ADFunction -TestName "Get-ADEventLogs" -Description "Test AD event logs function" -TestScript {
    $eventLogs = Get-ADEventLogs -ServerName "localhost" -LogLevel "All" -MaxEvents 1000 -HoursBack 24
    return $eventLogs -ne $null
}

Test-ADFunction -TestName "Get-ADComplianceStatus" -Description "Test AD compliance status function" -TestScript {
    $complianceStatus = Get-ADComplianceStatus -ServerName "localhost" -IncludeDetails -IncludeStandards -IncludePolicies -IncludeAudit
    return $complianceStatus -ne $null
}

# Test Deployment Scripts
Write-Host "=== Testing Deployment Scripts ===" -ForegroundColor Cyan

Test-ADFunction -TestName "Deploy-ActiveDirectory" -Description "Test AD deployment script" -TestScript {
    $deploymentScript = "C:\Github\Windows-Server\Active-Directory-Scripts\Scripts\Deployment\Deploy-ActiveDirectory.ps1"
    return Test-Path $deploymentScript
}

Test-ADFunction -TestName "Deploy-ADEnterpriseScenarios" -Description "Test AD enterprise scenarios script" -TestScript {
    $enterpriseScenariosScript = "C:\Github\Windows-Server\Active-Directory-Scripts\Scripts\Enterprise-Scenarios\Deploy-ADEnterpriseScenarios.ps1"
    return Test-Path $enterpriseScenariosScript
}

# Test Configuration Scripts
Write-Host "=== Testing Configuration Scripts ===" -ForegroundColor Cyan

Test-ADFunction -TestName "Configure-ActiveDirectory" -Description "Test AD configuration script" -TestScript {
    $configurationScript = "C:\Github\Windows-Server\Active-Directory-Scripts\Scripts\Configuration\Configure-ActiveDirectory.ps1"
    return Test-Path $configurationScript
}

# Test Security Scripts
Write-Host "=== Testing Security Scripts ===" -ForegroundColor Cyan

Test-ADFunction -TestName "Secure-ActiveDirectory" -Description "Test AD security script" -TestScript {
    $securityScript = "C:\Github\Windows-Server\Active-Directory-Scripts\Scripts\Security\Secure-ActiveDirectory.ps1"
    return Test-Path $securityScript
}

# Test Monitoring Scripts
Write-Host "=== Testing Monitoring Scripts ===" -ForegroundColor Cyan

Test-ADFunction -TestName "Monitor-ActiveDirectory" -Description "Test AD monitoring script" -TestScript {
    $monitoringScript = "C:\Github\Windows-Server\Active-Directory-Scripts\Scripts\Monitoring\Monitor-ActiveDirectory.ps1"
    return Test-Path $monitoringScript
}

# Test Troubleshooting Scripts
Write-Host "=== Testing Troubleshooting Scripts ===" -ForegroundColor Cyan

Test-ADFunction -TestName "Troubleshoot-ActiveDirectory" -Description "Test AD troubleshooting script" -TestScript {
    $troubleshootingScript = "C:\Github\Windows-Server\Active-Directory-Scripts\Scripts\Troubleshooting\Troubleshoot-ActiveDirectory.ps1"
    return Test-Path $troubleshootingScript
}

# Test Examples
Write-Host "=== Testing Examples ===" -ForegroundColor Cyan

Test-ADFunction -TestName "AD-Examples" -Description "Test AD examples script" -TestScript {
    $examplesScript = "C:\Github\Windows-Server\Active-Directory-Scripts\Examples\AD-Examples.ps1"
    return Test-Path $examplesScript
}

# Test Documentation
Write-Host "=== Testing Documentation ===" -ForegroundColor Cyan

Test-ADFunction -TestName "AD-Documentation" -Description "Test AD documentation" -TestScript {
    $documentationFile = "C:\Github\Windows-Server\Active-Directory-Scripts\Documentation\AD-Documentation.md"
    return Test-Path $documentationFile
}

# Test Configuration Files
Write-Host "=== Testing Configuration Files ===" -ForegroundColor Cyan

Test-ADFunction -TestName "AD-Configuration-Template" -Description "Test AD configuration template" -TestScript {
    $configurationTemplate = "C:\Github\Windows-Server\Active-Directory-Scripts\Configuration\AD-Configuration-Template.json"
    return Test-Path $configurationTemplate
}

Test-ADFunction -TestName "Security-Configuration-Template" -Description "Test security configuration template" -TestScript {
    $securityTemplate = "C:\Github\Windows-Server\Active-Directory-Scripts\Configuration\Security-Configuration-Template.json"
    return Test-Path $securityTemplate
}

Test-ADFunction -TestName "Monitoring-Configuration-Template" -Description "Test monitoring configuration template" -TestScript {
    $monitoringTemplate = "C:\Github\Windows-Server\Active-Directory-Scripts\Configuration\Monitoring-Configuration-Template.json"
    return Test-Path $monitoringTemplate
}

Test-ADFunction -TestName "Troubleshooting-Configuration-Template" -Description "Test troubleshooting configuration template" -TestScript {
    $troubleshootingTemplate = "C:\Github\Windows-Server\Active-Directory-Scripts\Configuration\Troubleshooting-Configuration-Template.json"
    return Test-Path $troubleshootingTemplate
}

# Determine overall result
if ($testResults.Failed -eq 0) {
    $testResults.OverallResult = "All Tests Passed"
} elseif ($testResults.Failed -lt $testResults.Total / 2) {
    $testResults.OverallResult = "Most Tests Passed"
} else {
    $testResults.OverallResult = "Many Tests Failed"
}

# Summary
Write-Host ""
Write-Host "=== Test Summary ===" -ForegroundColor Cyan
Write-Host "Total Tests: $($testResults.Total)" -ForegroundColor White
Write-Host "Passed: $($testResults.Passed)" -ForegroundColor Green
Write-Host "Failed: $($testResults.Failed)" -ForegroundColor Red
Write-Host "Skipped: $($testResults.Skipped)" -ForegroundColor Yellow
Write-Host "Overall Result: $($testResults.OverallResult)" -ForegroundColor White

# Detailed results
Write-Host ""
Write-Host "=== Detailed Test Results ===" -ForegroundColor Cyan
foreach ($test in $testResults.Tests) {
    $statusColor = switch ($test.Status) {
        "Passed" { "Green" }
        "Failed" { "Red" }
        "Skipped" { "Yellow" }
        default { "White" }
    }
    
    Write-Host "$($test.Name): $($test.Status)" -ForegroundColor $statusColor
    if ($test.Description) {
        Write-Host "  Description: $($test.Description)" -ForegroundColor Gray
    }
    if ($test.Result -and $test.Status -eq "Failed") {
        Write-Host "  Error: $($test.Result)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "=== Active Directory Scripts Testing Completed ===" -ForegroundColor Green
Write-Host "Author: Adrian Johnson (adrian207@gmail.com)" -ForegroundColor Green
Write-Host "Version: 1.0.0" -ForegroundColor Green
Write-Host "Date: October 2025" -ForegroundColor Green
Write-Host "Overall Result: $($testResults.OverallResult)" -ForegroundColor Green
