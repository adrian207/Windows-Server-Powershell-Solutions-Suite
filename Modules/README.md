<#
.SYNOPSIS
    Examples demonstrating the Logging-Core module

.DESCRIPTION
    This script provides practical examples of using the enhanced logging
    functionality in the Windows Server PowerShell Solutions Suite.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Last Updated: December 2024
#>

[CmdletBinding()]
param()

# Import the logging module
Import-Module .\Modules\Logging-Core.psm1 -Force

Write-Host "=== Logging Module Examples ===" -ForegroundColor Cyan
Write-Host ""

# Example 1: Basic Logging
Write-Host "Example 1: Basic Logging" -ForegroundColor Yellow
Write-Log -Message "Application started" -Level INFO -Component "Application"
Write-Log -Message "User logged in successfully" -Level INFO -Component "Authentication"
Write-Log -Message "File processed successfully" -Level DEBUG -Component "FileProcessing"
Write-Host ""

# Example 2: Logging with Exceptions
Write-Host "Example 2: Logging with Exceptions" -ForegroundColor Yellow
try {
    Get-Process -Name "NonExistentProcess123" -ErrorAction Stop
} catch {
    Write-Log -Message "Failed to retrieve process" -Level ERROR -Component "ProcessManagement" -Exception $_
}
Write-Host ""

# Example 3: Logging with Structured Data
Write-Host "Example 3: Logging with Structured Data" -ForegroundColor Yellow
$userData = @{
    UserName = "john.doe"
    Department = "IT"
    Role = "Administrator"
}
Write-Log -Message "User data retrieved" -Level INFO -Component "UserManagement" -Data $userData
Write-Host ""

# Example 4: Configure Log Targets
Write-Host "Example 4: Configure Log Targets" -ForegroundColor Yellow
Set-LogTarget -Target Console -Enabled $true
Set-LogTarget -Target File -Enabled $true
Set-LogTarget -Target EventLog -Enabled $true
Write-Log -Message "Log targets configured" -Level INFO -Component "Logging"
Write-Host ""

# Example 5: Custom Log Path
Write-Host "Example 5: Custom Log Path" -ForegroundColor Yellow
$customPath = "C:\Temp\MyLogs"
Set-LogTarget -Target File -Enabled $true -LogPath $customPath
Write-Log -Message "Using custom log path: $customPath" -Level INFO -Component "Logging"
Write-Host ""

# Example 6: Initialize Log Rotation
Write-Host "Example 6: Initialize Log Rotation" -ForegroundColor Yellow
Initialize-LogRotation -MaxFileSizeMB 50 -RetentionDays 14
Write-Host ""

# Example 7: Different Log Levels
Write-Host "Example 7: Different Log Levels" -ForegroundColor Yellow
Write-Log -Message "Debug information" -Level DEBUG -Component "Debug"
Write-Log -Message "Information message" -Level INFO -Component "Info"
Write-Log -Message "Warning condition" -Level WARNING -Component "Warning"
Write-Log -Message "Error occurred" -Level ERROR -Component "Error"
Write-Log -Message "Critical failure" -Level CRITICAL -Component "Critical"
Write-Host ""

Write-Host "=== Examples Complete ===" -ForegroundColor Green

