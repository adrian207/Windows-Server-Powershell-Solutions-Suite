#Requires -Version 5.1

<#
.SYNOPSIS
    LAPs Module Examples

.DESCRIPTION
    Comprehensive examples demonstrating LAPs usage scenarios.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

# Import modules
Import-Module "$PSScriptRoot\..\Modules\LAPs-Core.psm1" -Force
Import-Module "$PSScriptRoot\..\Modules\LAPs-Security.psm1" -Force
Import-Module "$PSScriptRoot\..\Modules\LAPs-Monitoring.psm1" -Force
Import-Module "$PSScriptRoot\..\Modules\LAPs-Troubleshooting.psm1" -Force

Write-Host "LAPs Module Examples" -ForegroundColor Cyan
Write-Host ("=" * 50)

# Example 1: Get LAPs status for multiple computers
Write-Host "`nExample 1: Get LAPs Status" -ForegroundColor Yellow
$status = Get-LAPsStatus -ComputerName @("SERVER01", "SERVER02", "SERVER03")
$status | Format-Table -AutoSize

# Example 2: Retrieve local administrator password
Write-Host "`nExample 2: Retrieve Local Administrator Password" -ForegroundColor Yellow
$password = Get-LAPsPassword -ComputerName "SERVER01"
Write-Host "Computer: $($password.ComputerName)" -ForegroundColor Green
Write-Host "Password: $($password.Password)" -ForegroundColor Green
Write-Host "Age: $($password.PasswordAge.Days) days" -ForegroundColor Green

# Example 3: Configure LAPs Group Policy
Write-Host "`nExample 3: Configure LAPs Group Policy" -ForegroundColor Yellow
$policy = Set-LAPsGroupPolicy -PolicyName "Production LAPs Policy" -PasswordAgeInDays 30 -PasswordLength 14 -EnableAuditing
$policy | Format-List

# Example 4: Perform LAPs audit
Write-Host "`nExample 4: Perform LAPs Audit" -ForegroundColor Yellow
$audit = Invoke-LAPsAudit -ExportReport
Write-Host "Total Computers: $($audit.TotalComputers)" -ForegroundColor Green
Write-Host "LAPs Enabled: $($audit.LAPsEnabled)" -ForegroundColor Green
Write-Host "Compliant: $($audit.Compliant)" -ForegroundColor Green

# Example 5: Get monitoring statistics
Write-Host "`nExample 5: Get Monitoring Statistics" -ForegroundColor Yellow
$stats = Get-LAPsStatistics
$stats | Format-List

# Example 6: Test connectivity
Write-Host "`nExample 6: Test Connectivity" -ForegroundColor Yellow
$connectivity = Test-LAPsConnectivity -ComputerName "SERVER01"
Write-Host "Connected: $($connectivity.Connected)" -ForegroundColor Green
Write-Host "Latency: $($connectivity.Latency)ms" -ForegroundColor Green

# Example 7: Get compliance status
Write-Host "`nExample 7: Get Compliance Status" -ForegroundColor Yellow
$compliance = Get-LAPsComplianceStatus
Write-Host "Compliance Rate: $($compliance.ComplianceRate)%" -ForegroundColor Green

Write-Host "`nExamples completed successfully!" -ForegroundColor Green