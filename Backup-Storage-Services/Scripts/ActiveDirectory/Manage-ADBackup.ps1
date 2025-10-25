#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Active Directory Backup and Restore Management Script

.DESCRIPTION
    This script provides comprehensive Active Directory backup and restore capabilities
    including system state backup, AD database backup, and disaster recovery procedures.

.PARAMETER Action
    The action to perform (CreateBackup, RestoreBackup, GetStatus, GetHistory, TestIntegrity, RemoveOldBackups)

.PARAMETER BackupPath
    Path where backups will be stored or restored from

.PARAMETER BackupName
    Name for the backup (default: AD-SystemState-YYYYMMDD-HHMMSS)

.PARAMETER BackupTime
    Specific backup time to restore from

.PARAMETER IncludeSystemDrive
    Include the system drive in the backup

.PARAMETER CompressionEnabled
    Enable compression for the backup

.PARAMETER RetentionDays
    Number of days to retain backups (default: 30)

.PARAMETER ConfirmRestore
    Confirmation flag for restore operations

.PARAMETER OutputPath
    Path to save backup reports

.EXAMPLE
    .\Manage-ADBackup.ps1 -Action CreateBackup -BackupPath "D:\AD-Backups"

.EXAMPLE
    .\Manage-ADBackup.ps1 -Action CreateBackup -BackupPath "D:\AD-Backups" -IncludeSystemDrive -CompressionEnabled

.EXAMPLE
    .\Manage-ADBackup.ps1 -Action GetStatus

.EXAMPLE
    .\Manage-ADBackup.ps1 -Action GetHistory -BackupPath "D:\AD-Backups" -Days 7

.EXAMPLE
    .\Manage-ADBackup.ps1 -Action TestIntegrity -BackupPath "D:\AD-Backups"

.EXAMPLE
    .\Manage-ADBackup.ps1 -Action RestoreBackup -BackupPath "D:\AD-Backups" -BackupTime "2024-01-15 14:30:00" -ConfirmRestore

.EXAMPLE
    .\Manage-ADBackup.ps1 -Action RemoveOldBackups -BackupPath "D:\AD-Backups" -RetentionDays 14 -ConfirmRemoval

.NOTES
    Author: Backup and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/backup-and-storage-overview
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("CreateBackup", "RestoreBackup", "GetStatus", "GetHistory", "TestIntegrity", "RemoveOldBackups")]
    [string]$Action,
    
    [string]$BackupPath,
    
    [string]$BackupName,
    
    [datetime]$BackupTime,
    
    [switch]$IncludeSystemDrive,
    
    [switch]$CompressionEnabled,
    
    [int]$RetentionDays = 30,
    
    [switch]$ConfirmRestore,
    
    [switch]$ConfirmRemoval,
    
    [string]$OutputPath
)

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "BackupStorage-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "BackupStorage-ADBackup.psm1") -Force
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Script variables
$script:ADBackupLog = @()
$script:StartTime = Get-Date

function Write-ADBackupLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:ADBackupLog += $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function New-ADBackup {
    Write-ADBackupLog "Creating Active Directory backup..." "INFO"
    
    try {
        $backupResult = Start-ADSystemStateBackup -BackupPath $BackupPath -BackupName $BackupName -IncludeSystemDrive:$IncludeSystemDrive -CompressionEnabled:$CompressionEnabled
        
        if ($backupResult.Success) {
            Write-Host "`n=== Active Directory Backup Created ===" -ForegroundColor Cyan
            Write-Host "Backup Name: $($backupResult.BackupName)" -ForegroundColor White
            Write-Host "Backup Path: $($backupResult.BackupPath)" -ForegroundColor White
            Write-Host "Job ID: $($backupResult.JobId)" -ForegroundColor White
            Write-Host "Start Time: $($backupResult.StartTime)" -ForegroundColor White
            
            if ($backupResult.Prerequisites) {
                Write-Host "`nPrerequisites Check:" -ForegroundColor Yellow
                Write-Host "  Domain Controller: $($backupResult.Prerequisites.IsDomainController)" -ForegroundColor White
                Write-Host "  Windows Backup Installed: $($backupResult.Prerequisites.WindowsBackupInstalled)" -ForegroundColor White
                Write-Host "  Sufficient Space: $($backupResult.Prerequisites.SufficientSpace)" -ForegroundColor White
                Write-Host "  Backup Path Writable: $($backupResult.Prerequisites.BackupPathWritable)" -ForegroundColor White
            }
            
            Write-ADBackupLog "Active Directory backup created successfully" "SUCCESS"
        } else {
            Write-Host "`n=== Active Directory Backup Failed ===" -ForegroundColor Red
            Write-Host "Error: $($backupResult.Error)" -ForegroundColor Red
            Write-ADBackupLog "Active Directory backup failed: $($backupResult.Error)" "ERROR"
        }
        
        return $backupResult
        
    } catch {
        Write-ADBackupLog "Error creating Active Directory backup: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Restore-ADBackup {
    Write-ADBackupLog "Restoring Active Directory from backup..." "INFO"
    
    try {
        if (-not $ConfirmRestore) {
            Write-Host "`n=== RESTORE OPERATION REQUIRES CONFIRMATION ===" -ForegroundColor Red
            Write-Host "This operation will overwrite the current Active Directory database." -ForegroundColor Yellow
            Write-Host "Please add -ConfirmRestore parameter to proceed." -ForegroundColor Yellow
            Write-ADBackupLog "Restore operation cancelled - confirmation required" "WARNING"
            return $null
        }
        
        $restoreResult = Restore-ADSystemState -BackupPath $BackupPath -BackupTime $BackupTime -ConfirmRestore
        
        if ($restoreResult.Success) {
            Write-Host "`n=== Active Directory Restore Initiated ===" -ForegroundColor Cyan
            Write-Host "Backup Time: $($restoreResult.BackupTime)" -ForegroundColor White
            Write-Host "Backup Path: $($restoreResult.BackupPath)" -ForegroundColor White
            Write-Host "Target Path: $($restoreResult.TargetPath)" -ForegroundColor White
            Write-Host "Job ID: $($restoreResult.JobId)" -ForegroundColor White
            Write-Host "Start Time: $($restoreResult.StartTime)" -ForegroundColor White
            Write-Host "`nWARNING: System restart will be required after restore completion" -ForegroundColor Yellow
            
            Write-ADBackupLog "Active Directory restore initiated successfully" "SUCCESS"
        } else {
            Write-Host "`n=== Active Directory Restore Failed ===" -ForegroundColor Red
            Write-Host "Error: $($restoreResult.Error)" -ForegroundColor Red
            Write-ADBackupLog "Active Directory restore failed: $($restoreResult.Error)" "ERROR"
        }
        
        return $restoreResult
        
    } catch {
        Write-ADBackupLog "Error restoring Active Directory backup: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-ADBackupStatus {
    Write-ADBackupLog "Getting Active Directory backup status..." "INFO"
    
    try {
        $status = Get-ADBackupStatus
        
        if ($status) {
            Write-Host "`n=== Active Directory Backup Status ===" -ForegroundColor Cyan
            Write-Host "Computer: $($status.ComputerName)" -ForegroundColor White
            Write-Host "Timestamp: $($status.Timestamp)" -ForegroundColor White
            Write-Host "Total Jobs: $($status.TotalJobs)" -ForegroundColor White
            Write-Host "Running Jobs: $($status.RunningJobs)" -ForegroundColor White
            Write-Host "Completed Jobs: $($status.CompletedJobs)" -ForegroundColor White
            Write-Host "Failed Jobs: $($status.FailedJobs)" -ForegroundColor White
            
            if ($status.Jobs.Count -gt 0) {
                Write-Host "`nRecent Jobs:" -ForegroundColor Yellow
                foreach ($job in $status.Jobs | Select-Object -First 5) {
                    $statusColor = switch ($job.JobState) {
                        "Completed" { "Green" }
                        "Running" { "Yellow" }
                        "Failed" { "Red" }
                        default { "White" }
                    }
                    Write-Host "  Job ID: $($job.JobId) | State: $($job.JobState) | Start: $($job.StartTime)" -ForegroundColor $statusColor
                }
            }
            
            Write-ADBackupLog "Active Directory backup status retrieved successfully" "SUCCESS"
        }
        
        return $status
        
    } catch {
        Write-ADBackupLog "Error getting Active Directory backup status: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-ADBackupHistory {
    Write-ADBackupLog "Getting Active Directory backup history..." "INFO"
    
    try {
        $history = Get-ADBackupHistory -BackupPath $BackupPath -Days $RetentionDays
        
        if ($history) {
            Write-Host "`n=== Active Directory Backup History ===" -ForegroundColor Cyan
            Write-Host "Computer: $($history.ComputerName)" -ForegroundColor White
            Write-Host "Backup Path: $($history.BackupPath)" -ForegroundColor White
            Write-Host "Days: $($history.Days)" -ForegroundColor White
            Write-Host "Total Backups: $($history.TotalBackups)" -ForegroundColor White
            Write-Host "Oldest Backup: $($history.OldestBackup)" -ForegroundColor White
            Write-Host "Newest Backup: $($history.NewestBackup)" -ForegroundColor White
            
            if ($history.Backups.Count -gt 0) {
                Write-Host "`nBackup Details:" -ForegroundColor Yellow
                foreach ($backup in $history.Backups | Select-Object -First 10) {
                    Write-Host "  Time: $($backup.BackupTime) | Size: $($backup.BackupSize) | Days Old: $($backup.DaysOld)" -ForegroundColor White
                }
            }
            
            Write-ADBackupLog "Active Directory backup history retrieved successfully" "SUCCESS"
        }
        
        return $history
        
    } catch {
        Write-ADBackupLog "Error getting Active Directory backup history: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Test-ADBackupIntegrity {
    Write-ADBackupLog "Testing Active Directory backup integrity..." "INFO"
    
    try {
        $integrity = Test-ADBackupIntegrity -BackupPath $BackupPath -BackupTime $BackupTime
        
        if ($integrity) {
            Write-Host "`n=== Active Directory Backup Integrity Test ===" -ForegroundColor Cyan
            Write-Host "Computer: $($integrity.ComputerName)" -ForegroundColor White
            Write-Host "Backup Path: $($integrity.BackupPath)" -ForegroundColor White
            Write-Host "Total Tested: $($integrity.TotalTested)" -ForegroundColor White
            Write-Host "Valid Backups: $($integrity.ValidBackups)" -ForegroundColor Green
            Write-Host "Invalid Backups: $($integrity.InvalidBackups)" -ForegroundColor Red
            
            if ($integrity.TestedBackups.Count -gt 0) {
                Write-Host "`nIntegrity Test Results:" -ForegroundColor Yellow
                foreach ($test in $integrity.TestedBackups) {
                    $statusColor = if ($test.IsValid) { "Green" } else { "Red" }
                    $status = if ($test.IsValid) { "Valid" } else { "Invalid" }
                    Write-Host "  Backup: $($test.BackupTime) | Status: $status" -ForegroundColor $statusColor
                    if ($test.ErrorMessage) {
                        Write-Host "    Error: $($test.ErrorMessage)" -ForegroundColor Red
                    }
                }
            }
            
            Write-ADBackupLog "Active Directory backup integrity test completed" "SUCCESS"
        }
        
        return $integrity
        
    } catch {
        Write-ADBackupLog "Error testing Active Directory backup integrity: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Remove-OldADBackups {
    Write-ADBackupLog "Removing old Active Directory backups..." "INFO"
    
    try {
        if (-not $ConfirmRemoval) {
            Write-Host "`n=== REMOVAL OPERATION REQUIRES CONFIRMATION ===" -ForegroundColor Red
            Write-Host "This operation will permanently delete old backups." -ForegroundColor Yellow
            Write-Host "Please add -ConfirmRemoval parameter to proceed." -ForegroundColor Yellow
            Write-ADBackupLog "Removal operation cancelled - confirmation required" "WARNING"
            return $null
        }
        
        $removeResult = Remove-OldADBackups -BackupPath $BackupPath -RetentionDays $RetentionDays -ConfirmRemoval
        
        if ($removeResult.Success) {
            Write-Host "`n=== Old Active Directory Backups Removed ===" -ForegroundColor Cyan
            Write-Host "Backup Path: $($removeResult.BackupPath)" -ForegroundColor White
            Write-Host "Retention Days: $($removeResult.RetentionDays)" -ForegroundColor White
            Write-Host "Cutoff Date: $($removeResult.CutoffDate)" -ForegroundColor White
            Write-Host "Total Removed: $($removeResult.TotalRemoved)" -ForegroundColor White
            Write-Host "Space Freed: $($removeResult.SpaceFreedGB) GB" -ForegroundColor Green
            
            if ($removeResult.RemovedBackups.Count -gt 0) {
                Write-Host "`nRemoved Backups:" -ForegroundColor Yellow
                foreach ($backup in $removeResult.RemovedBackups) {
                    Write-Host "  Time: $($backup.BackupTime) | Size: $($backup.BackupSize)" -ForegroundColor White
                }
            }
            
            Write-ADBackupLog "Old Active Directory backups removed successfully" "SUCCESS"
        } else {
            Write-Host "`n=== Backup Removal Failed ===" -ForegroundColor Red
            Write-Host "Error: $($removeResult.Error)" -ForegroundColor Red
            Write-ADBackupLog "Backup removal failed: $($removeResult.Error)" "ERROR"
        }
        
        return $removeResult
        
    } catch {
        Write-ADBackupLog "Error removing old Active Directory backups: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Save-ADBackupLog {
    $logPath = Join-Path $scriptPath "AD-Backup-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    try {
        $script:ADBackupLog | Out-File -FilePath $logPath -Encoding UTF8
        Write-ADBackupLog "AD backup log saved to: $logPath" "INFO"
    } catch {
        Write-Warning "Failed to save AD backup log: $($_.Exception.Message)"
    }
}

# Main Active Directory backup management process
try {
    Write-ADBackupLog "Starting Active Directory backup management..." "INFO"
    Write-ADBackupLog "Action: $Action" "INFO"
    
    switch ($Action) {
        "CreateBackup" {
            New-ADBackup
        }
        
        "RestoreBackup" {
            Restore-ADBackup
        }
        
        "GetStatus" {
            Get-ADBackupStatus
        }
        
        "GetHistory" {
            Get-ADBackupHistory
        }
        
        "TestIntegrity" {
            Test-ADBackupIntegrity
        }
        
        "RemoveOldBackups" {
            Remove-OldADBackups
        }
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-ADBackupLog "Active Directory backup management completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== Active Directory Backup Management Summary ===" -ForegroundColor Cyan
    Write-Host "Action: $Action" -ForegroundColor White
    Write-Host "Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    
    # Save AD backup log
    Save-ADBackupLog
    
    Write-Host "`nActive Directory backup management completed successfully!" -ForegroundColor Green
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-ADBackupLog "Active Directory backup management failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save AD backup log
    Save-ADBackupLog
    
    Write-Host "`nActive Directory backup management failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the AD backup log for details." -ForegroundColor Yellow
    
    exit 1
}
