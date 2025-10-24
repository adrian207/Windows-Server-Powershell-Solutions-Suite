#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Print Queue Management Script

.DESCRIPTION
    This script provides comprehensive print queue management capabilities including
    monitoring print jobs, managing print queues, and controlling print operations.

.PARAMETER Action
    The action to perform (GetQueues, GetJobs, PauseQueue, ResumeQueue, ClearQueue, RestartQueue, PauseJob, ResumeJob, CancelJob, GetQueueStatus)

.PARAMETER PrinterName
    The name of the printer

.PARAMETER JobId
    The ID of the print job

.PARAMETER JobName
    The name of the print job

.PARAMETER UserName
    The name of the user

.PARAMETER JobStatus
    The status of the print job

.PARAMETER SubmittedAfter
    Get jobs submitted after this date

.PARAMETER SubmittedBefore
    Get jobs submitted before this date

.PARAMETER OutputPath
    Path to save reports

.PARAMETER GenerateReport
    Generate detailed print queue report

.PARAMETER MonitorDuration
    Duration to monitor print queues in seconds

.PARAMETER MonitorInterval
    Monitoring interval in seconds

.EXAMPLE
    .\Manage-PrintQueues.ps1 -Action GetQueues

.EXAMPLE
    .\Manage-PrintQueues.ps1 -Action GetJobs -PrinterName "Office Printer"

.EXAMPLE
    .\Manage-PrintQueues.ps1 -Action PauseQueue -PrinterName "Office Printer"

.EXAMPLE
    .\Manage-PrintQueues.ps1 -Action CancelJob -PrinterName "Office Printer" -JobId 123

.NOTES
    Author: Print Server PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("GetQueues", "GetJobs", "PauseQueue", "ResumeQueue", "ClearQueue", "RestartQueue", "PauseJob", "ResumeJob", "CancelJob", "GetQueueStatus", "Monitor", "Report")]
    [string]$Action,
    
    [string]$PrinterName,
    
    [int]$JobId,
    
    [string]$JobName,
    
    [string]$UserName,
    
    [string]$JobStatus,
    
    [DateTime]$SubmittedAfter,
    
    [DateTime]$SubmittedBefore,
    
    [string]$OutputPath,
    
    [switch]$GenerateReport,
    
    [int]$MonitorDuration = 300,
    
    [int]$MonitorInterval = 10
)

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "PrintServer-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "PrintServer-Management.psm1") -Force
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Script variables
$script:QueueLog = @()
$script:StartTime = Get-Date

function Write-QueueLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:QueueLog += $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function Get-PrintQueues {
    Write-QueueLog "Getting print queues..." "INFO"
    
    try {
        $printers = Get-Printer
        
        Write-Host "`n=== Print Queues ===" -ForegroundColor Cyan
        Write-Host "Total Printers: $($printers.Count)" -ForegroundColor White
        
        if ($printers.Count -gt 0) {
            $printers | Format-Table Name, DriverName, PortName, Location, Shared, Published, PrinterStatus -AutoSize
        } else {
            Write-Host "No printers found" -ForegroundColor Yellow
        }
        
        Write-QueueLog "Print queues retrieved successfully" "SUCCESS"
        return $printers
        
    } catch {
        Write-QueueLog "Error getting print queues: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-PrintJobs {
    Write-QueueLog "Getting print jobs..." "INFO"
    
    try {
        $printJobs = @()
        
        if ($PrinterName) {
            $printJobs = Get-PrintJob -PrinterName $PrinterName -ErrorAction SilentlyContinue
        } else {
            $printJobs = Get-PrintJob -ErrorAction SilentlyContinue
        }
        
        # Filter by additional criteria
        if ($UserName) {
            $printJobs = $printJobs | Where-Object { $_.SubmittedBy -like "*$UserName*" }
        }
        
        if ($JobStatus) {
            $printJobs = $printJobs | Where-Object { $_.JobStatus -like "*$JobStatus*" }
        }
        
        if ($SubmittedAfter) {
            $printJobs = $printJobs | Where-Object { $_.SubmittedTime -gt $SubmittedAfter }
        }
        
        if ($SubmittedBefore) {
            $printJobs = $printJobs | Where-Object { $_.SubmittedTime -lt $SubmittedBefore }
        }
        
        Write-Host "`n=== Print Jobs ===" -ForegroundColor Cyan
        Write-Host "Total Jobs: $($printJobs.Count)" -ForegroundColor White
        
        if ($printJobs.Count -gt 0) {
            $printJobs | Format-Table PrinterName, JobName, JobStatus, SubmittedBy, SubmittedTime, PagesPrinted, TotalPages -AutoSize
        } else {
            Write-Host "No print jobs found" -ForegroundColor Yellow
        }
        
        Write-QueueLog "Print jobs retrieved successfully" "SUCCESS"
        return $printJobs
        
    } catch {
        Write-QueueLog "Error getting print jobs: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Set-PrintQueuePause {
    Write-QueueLog "Pausing print queue: $PrinterName" "INFO"
    
    try {
        if (-not $PrinterName) {
            throw "PrinterName is required for PauseQueue action"
        }
        
        # Check if printer exists
        $printer = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
        if (-not $printer) {
            throw "Printer '$PrinterName' does not exist"
        }
        
        # Pause the print queue
        Set-Printer -Name $PrinterName -PrinterState "Paused"
        
        Write-QueueLog "Print queue paused successfully: $PrinterName" "SUCCESS"
        return $true
        
    } catch {
        Write-QueueLog "Error pausing print queue: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-PrintQueueResume {
    Write-QueueLog "Resuming print queue: $PrinterName" "INFO"
    
    try {
        if (-not $PrinterName) {
            throw "PrinterName is required for ResumeQueue action"
        }
        
        # Check if printer exists
        $printer = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
        if (-not $printer) {
            throw "Printer '$PrinterName' does not exist"
        }
        
        # Resume the print queue
        Set-Printer -Name $PrinterName -PrinterState "Normal"
        
        Write-QueueLog "Print queue resumed successfully: $PrinterName" "SUCCESS"
        return $true
        
    } catch {
        Write-QueueLog "Error resuming print queue: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Clear-PrintQueue {
    Write-QueueLog "Clearing print queue: $PrinterName" "INFO"
    
    try {
        if (-not $PrinterName) {
            throw "PrinterName is required for ClearQueue action"
        }
        
        # Check if printer exists
        $printer = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
        if (-not $printer) {
            throw "Printer '$PrinterName' does not exist"
        }
        
        # Get all print jobs for the printer
        $printJobs = Get-PrintJob -PrinterName $PrinterName -ErrorAction SilentlyContinue
        
        # Cancel all print jobs
        foreach ($printJob in $printJobs) {
            try {
                Remove-PrintJob -PrinterName $PrinterName -JobId $printJob.JobId -Force
            } catch {
                Write-Warning "Could not cancel job $($printJob.JobId): $($_.Exception.Message)"
            }
        }
        
        Write-QueueLog "Print queue cleared successfully: $PrinterName" "SUCCESS"
        return $true
        
    } catch {
        Write-QueueLog "Error clearing print queue: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Restart-PrintQueue {
    Write-QueueLog "Restarting print queue: $PrinterName" "INFO"
    
    try {
        if (-not $PrinterName) {
            throw "PrinterName is required for RestartQueue action"
        }
        
        # Check if printer exists
        $printer = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
        if (-not $printer) {
            throw "Printer '$PrinterName' does not exist"
        }
        
        # Restart the print queue by stopping and starting the spooler service
        Restart-Service -Name Spooler -Force
        Start-Sleep -Seconds 5
        
        Write-QueueLog "Print queue restarted successfully: $PrinterName" "SUCCESS"
        return $true
        
    } catch {
        Write-QueueLog "Error restarting print queue: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-PrintJobPause {
    Write-QueueLog "Pausing print job: $JobId" "INFO"
    
    try {
        if (-not $PrinterName -or -not $JobId) {
            throw "PrinterName and JobId are required for PauseJob action"
        }
        
        # Check if print job exists
        $printJob = Get-PrintJob -PrinterName $PrinterName -JobId $JobId -ErrorAction SilentlyContinue
        if (-not $printJob) {
            throw "Print job $JobId not found for printer $PrinterName"
        }
        
        # Pause the print job
        Set-PrintJob -PrinterName $PrinterName -JobId $JobId -JobStatus "Paused"
        
        Write-QueueLog "Print job paused successfully: $JobId" "SUCCESS"
        return $true
        
    } catch {
        Write-QueueLog "Error pausing print job: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-PrintJobResume {
    Write-QueueLog "Resuming print job: $JobId" "INFO"
    
    try {
        if (-not $PrinterName -or -not $JobId) {
            throw "PrinterName and JobId are required for ResumeJob action"
        }
        
        # Check if print job exists
        $printJob = Get-PrintJob -PrinterName $PrinterName -JobId $JobId -ErrorAction SilentlyContinue
        if (-not $printJob) {
            throw "Print job $JobId not found for printer $PrinterName"
        }
        
        # Resume the print job
        Set-PrintJob -PrinterName $PrinterName -JobId $JobId -JobStatus "Printing"
        
        Write-QueueLog "Print job resumed successfully: $JobId" "SUCCESS"
        return $true
        
    } catch {
        Write-QueueLog "Error resuming print job: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-PrintJob {
    Write-QueueLog "Canceling print job: $JobId" "INFO"
    
    try {
        if (-not $PrinterName -or -not $JobId) {
            throw "PrinterName and JobId are required for CancelJob action"
        }
        
        # Check if print job exists
        $printJob = Get-PrintJob -PrinterName $PrinterName -JobId $JobId -ErrorAction SilentlyContinue
        if (-not $printJob) {
            throw "Print job $JobId not found for printer $PrinterName"
        }
        
        # Cancel the print job
        Remove-PrintJob -PrinterName $PrinterName -JobId $JobId -Force
        
        Write-QueueLog "Print job canceled successfully: $JobId" "SUCCESS"
        return $true
        
    } catch {
        Write-QueueLog "Error canceling print job: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-PrintQueueStatus {
    Write-QueueLog "Getting print queue status..." "INFO"
    
    try {
        $printers = Get-Printer
        $queueStatus = @()
        
        foreach ($printer in $printers) {
            $printerInfo = @{
                Name = $printer.Name
                DriverName = $printer.DriverName
                PortName = $printer.PortName
                Location = $printer.Location
                Shared = $printer.Shared
                Published = $printer.Published
                PrinterStatus = $printer.PrinterStatus
                JobCount = 0
                ActiveJobs = 0
                PausedJobs = 0
                ErrorJobs = 0
            }
            
            # Get print job information
            try {
                $printJobs = Get-PrintJob -PrinterName $printer.Name -ErrorAction SilentlyContinue
                $printerInfo.JobCount = $printJobs.Count
                $printerInfo.ActiveJobs = ($printJobs | Where-Object { $_.JobStatus -eq "Printing" }).Count
                $printerInfo.PausedJobs = ($printJobs | Where-Object { $_.JobStatus -eq "Paused" }).Count
                $printerInfo.ErrorJobs = ($printJobs | Where-Object { $_.JobStatus -eq "Error" }).Count
            } catch {
                Write-Warning "Could not retrieve job information for printer: $($printer.Name)"
            }
            
            $queueStatus += $printerInfo
        }
        
        Write-Host "`n=== Print Queue Status ===" -ForegroundColor Cyan
        $queueStatus | Format-Table Name, PrinterStatus, JobCount, ActiveJobs, PausedJobs, ErrorJobs -AutoSize
        
        Write-QueueLog "Print queue status retrieved successfully" "SUCCESS"
        return $queueStatus
        
    } catch {
        Write-QueueLog "Error getting print queue status: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Start-PrintQueueMonitoring {
    Write-QueueLog "Starting print queue monitoring..." "INFO"
    
    try {
        $startTime = Get-Date
        $endTime = $startTime.AddSeconds($MonitorDuration)
        $sampleCount = 0
        
        while ((Get-Date) -lt $endTime) {
            $sampleCount++
            $timestamp = Get-Date
            
            Write-QueueLog "Collecting print queue sample $sampleCount..." "INFO"
            
            # Get current print queue status
            $queueStatus = Get-PrintQueueStatus
            
            # Display current status
            Write-Host "`n=== Print Queue Monitoring Sample $sampleCount ===" -ForegroundColor Cyan
            Write-Host "Time: $($timestamp.ToString('HH:mm:ss'))" -ForegroundColor White
            
            if ($queueStatus) {
                $totalJobs = ($queueStatus | Measure-Object -Property JobCount -Sum).Sum
                $activeJobs = ($queueStatus | Measure-Object -Property ActiveJobs -Sum).Sum
                $pausedJobs = ($queueStatus | Measure-Object -Property PausedJobs -Sum).Sum
                $errorJobs = ($queueStatus | Measure-Object -Property ErrorJobs -Sum).Sum
                
                Write-Host "Total Jobs: $totalJobs" -ForegroundColor Yellow
                Write-Host "Active Jobs: $activeJobs" -ForegroundColor Green
                Write-Host "Paused Jobs: $pausedJobs" -ForegroundColor Yellow
                Write-Host "Error Jobs: $errorJobs" -ForegroundColor Red
            }
            
            # Check if we should continue monitoring
            if ((Get-Date).AddSeconds($MonitorInterval) -lt $endTime) {
                Start-Sleep -Seconds $MonitorInterval
            }
        }
        
        Write-QueueLog "Print queue monitoring completed. Collected $sampleCount samples." "SUCCESS"
        return $sampleCount
        
    } catch {
        Write-QueueLog "Error during print queue monitoring: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function New-PrintQueueReport {
    Write-QueueLog "Generating print queue report..." "INFO"
    
    try {
        if (-not $OutputPath) {
            $OutputPath = Join-Path $scriptPath "PrintQueue-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        }
        
        $report = Get-PrintServerReport -OutputPath $OutputPath -IncludePrintJobs -IncludeDrivers
        
        if ($report) {
            Write-Host "`n=== Print Queue Report Generated ===" -ForegroundColor Cyan
            Write-Host "Report Path: $OutputPath" -ForegroundColor White
            Write-Host "Report Type: HTML" -ForegroundColor White
            Write-Host "Total Printers: $($report.Summary.TotalPrinters)" -ForegroundColor White
            Write-Host "Total Print Jobs: $($report.Summary.TotalPrintJobs)" -ForegroundColor White
            Write-Host "Active Print Jobs: $($report.Summary.ActivePrintJobs)" -ForegroundColor White
        }
        
        Write-QueueLog "Print queue report generated successfully" "SUCCESS"
        return $report
        
    } catch {
        Write-QueueLog "Error generating print queue report: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Save-QueueLog {
    $logPath = Join-Path $scriptPath "Queue-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    try {
        $script:QueueLog | Out-File -FilePath $logPath -Encoding UTF8
        Write-QueueLog "Queue log saved to: $logPath" "INFO"
    } catch {
        Write-Warning "Failed to save queue log: $($_.Exception.Message)"
    }
}

# Main print queue management process
try {
    Write-QueueLog "Starting print queue management..." "INFO"
    Write-QueueLog "Action: $Action" "INFO"
    
    switch ($Action) {
        "GetQueues" {
            $printers = Get-PrintQueues
            if ($GenerateReport) {
                $report = New-PrintQueueReport
            }
        }
        
        "GetJobs" {
            $printJobs = Get-PrintJobs
            if ($GenerateReport) {
                $report = New-PrintQueueReport
            }
        }
        
        "PauseQueue" {
            $result = Set-PrintQueuePause
            if ($result) {
                Write-Host "`nPrint queue paused successfully: $PrinterName" -ForegroundColor Green
            } else {
                Write-Host "`nFailed to pause print queue: $PrinterName" -ForegroundColor Red
            }
        }
        
        "ResumeQueue" {
            $result = Set-PrintQueueResume
            if ($result) {
                Write-Host "`nPrint queue resumed successfully: $PrinterName" -ForegroundColor Green
            } else {
                Write-Host "`nFailed to resume print queue: $PrinterName" -ForegroundColor Red
            }
        }
        
        "ClearQueue" {
            $result = Clear-PrintQueue
            if ($result) {
                Write-Host "`nPrint queue cleared successfully: $PrinterName" -ForegroundColor Green
            } else {
                Write-Host "`nFailed to clear print queue: $PrinterName" -ForegroundColor Red
            }
        }
        
        "RestartQueue" {
            $result = Restart-PrintQueue
            if ($result) {
                Write-Host "`nPrint queue restarted successfully: $PrinterName" -ForegroundColor Green
            } else {
                Write-Host "`nFailed to restart print queue: $PrinterName" -ForegroundColor Red
            }
        }
        
        "PauseJob" {
            $result = Set-PrintJobPause
            if ($result) {
                Write-Host "`nPrint job paused successfully: $JobId" -ForegroundColor Green
            } else {
                Write-Host "`nFailed to pause print job: $JobId" -ForegroundColor Red
            }
        }
        
        "ResumeJob" {
            $result = Set-PrintJobResume
            if ($result) {
                Write-Host "`nPrint job resumed successfully: $JobId" -ForegroundColor Green
            } else {
                Write-Host "`nFailed to resume print job: $JobId" -ForegroundColor Red
            }
        }
        
        "CancelJob" {
            $result = Remove-PrintJob
            if ($result) {
                Write-Host "`nPrint job canceled successfully: $JobId" -ForegroundColor Green
            } else {
                Write-Host "`nFailed to cancel print job: $JobId" -ForegroundColor Red
            }
        }
        
        "GetQueueStatus" {
            $queueStatus = Get-PrintQueueStatus
            if ($GenerateReport) {
                $report = New-PrintQueueReport
            }
        }
        
        "Monitor" {
            $sampleCount = Start-PrintQueueMonitoring
            Write-Host "`nPrint queue monitoring completed. Collected $sampleCount samples." -ForegroundColor Green
        }
        
        "Report" {
            $report = New-PrintQueueReport
        }
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-QueueLog "Print queue management completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== Print Queue Management Summary ===" -ForegroundColor Cyan
    Write-Host "Action: $Action" -ForegroundColor White
    Write-Host "Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    
    # Save queue log
    Save-QueueLog
    
    Write-Host "`nPrint queue management completed successfully!" -ForegroundColor Green
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-QueueLog "Print queue management failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save queue log
    Save-QueueLog
    
    Write-Host "`nPrint queue management failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the queue log for details." -ForegroundColor Yellow
    
    exit 1
}
