<#
.SYNOPSIS
    Examples demonstrating the Error-Handling module

.DESCRIPTION
    This script provides practical examples of using the enhanced error handling
    functionality in the Windows Server PowerShell Solutions Suite.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Last Updated: December 2024
#>

[CmdletBinding()]
param()

# Import both modules
Import-Module .\Modules\Logging-Core.psm1 -Force
Import-Module .\Modules\Error-Handling.psm1 -Force

Write-Host "=== Error Handling Module Examples ===" -ForegroundColor Cyan
Write-Host ""

# Example 1: Simple Retry Logic
Write-Host "Example 1: Simple Retry Logic" -ForegroundColor Yellow
Invoke-CommandWithRetry -ScriptBlock {
    Get-Service -Name "Themes" -ErrorAction Stop
} -MaxRetries 3 -RetryInterval 2 -OperationName "Get Service"
Write-Host ""

# Example 2: Retry with Exponential Backoff
Write-Host "Example 2: Retry with Exponential Backoff" -ForegroundColor Yellow
Invoke-CommandWithRetry -ScriptBlock {
    Test-Path "C:\NonExistentFolder" -ErrorAction Stop
} -MaxRetries 3 -RetryInterval 1 -BackoffMultiplier 1.5 -OperationName "Test Path"
Write-Host ""

# Example 3: Try-Catch-Finally
Write-Host "Example 3: Try-Catch-Finally" -ForegroundColor Yellow
$filesCreated = 0
Invoke-TryCatchFinally -Try {
    $filesCreated++
    New-Item -Path "C:\Temp\TestFile$filesCreated.txt" -ItemType File -Force | Out-Null
    New-Item -Path "C:\Temp\TestFile$($filesCreated+1).txt" -ItemType File -Force | Out-Null
    Write-Log -Message "Files created successfully" -Level INFO -Component "FileCreation"
} -Catch {
    Write-Log -Message "Some files failed to create" -Level WARNING -Component "FileCreation" -Exception $_
} -Finally {
    Write-Log -Message "Attempted to create files: $filesCreated" -Level INFO -Component "FileCreation"
}
Write-Host ""

# Example 4: Get Error Details
Write-Host "Example 4: Get Error Details" -ForegroundColor Yellow
try {
    Get-Process -Name "NonExistentProcess" -ErrorAction Stop
} catch {
    $errorDetails = Get-ErrorDetails -ErrorObject $_
    Write-Log -Message "Error details captured" -Level INFO -Component "ErrorHandling" -Data $errorDetails
}
Write-Host ""

# Example 5: Send Error Report
Write-Host "Example 5: Send Error Report" -ForegroundColor Yellow
try {
    Get-Item -Path "C:\NonExistentPath\File.txt" -ErrorAction Stop
} catch {
    $errorDetails = Get-ErrorDetails -ErrorObject $_
    Send-ErrorReport -ErrorDetails $errorDetails -Severity ERROR -Component "FileAccess"
}
Write-Host ""

# Example 6: Graceful Degradation
Write-Host "Example 6: Graceful Degradation" -ForegroundColor Yellow
$fallbackActions = @{
    'FileNotFoundException' = {
        Write-Log -Message "Using default configuration file" -Level WARNING -Component "Config"
        Copy-Item "C:\Default\config.xml" "C:\App\config.xml"
    }
    'UnauthorizedAccessException' = {
        Write-Log -Message "Requesting elevation" -Level WARNING -Component "Security"
        # Request elevation logic here
    }
}
Enable-GracefulDegradation -FallbackActions $fallbackActions

# Simulate an error and test fallback
Write-Host "   (Simulating file not found error...)" -ForegroundColor Gray
Invoke-FallbackAction -ErrorType "FileNotFoundException"
Write-Host ""

# Example 7: Complex Error Handling
Write-Host "Example 7: Complex Error Handling" -ForegroundColor Yellow
Invoke-CommandWithRetry -ScriptBlock {
    $result = Invoke-WebRequest -Uri "https://httpstat.us/200" -UseBasicParsing -TimeoutSec 5
    Write-Log -Message "Web request successful: $($result.StatusCode)" -Level INFO -Component "WebRequest"
    return $result
} -MaxRetries 5 -RetryInterval 3 -OperationName "Web Request" -ErrorAction Stop
Write-Host ""

Write-Host "=== Examples Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Check the logs in: $env:ProgramData\WindowsServerSolutions\Logs" -ForegroundColor Cyan

