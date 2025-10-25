#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    File Server Backup and Disaster Recovery Script

.DESCRIPTION
    This script provides comprehensive backup and disaster recovery capabilities
    for Windows File and Storage Services including configuration backup,
    file-level backup, shadow copy management, and disaster recovery procedures.

.PARAMETER Action
    The action to perform (BackupConfig, BackupFiles, RestoreConfig, RestoreFiles, CreateShadowCopy, ManageShadowCopies, DisasterRecovery)

.PARAMETER BackupPath
    Path to save backups

.PARAMETER RestorePath
    Path to restore from

.PARAMETER SourcePath
    Source path for file backup

.PARAMETER DestinationPath
    Destination path for file backup

.PARAMETER DriveLetter
    Drive letter for shadow copy operations

.PARAMETER ShadowCopyType
    Type of shadow copy (Manual, Scheduled)

.PARAMETER RetentionDays
    Number of days to retain shadow copies

.PARAMETER IncludeShares
    Include file share configurations in backup

.PARAMETER IncludePermissions
    Include NTFS permissions in backup

.PARAMETER CompressionLevel
    Compression level for backups (None, Fast, Optimal)

.PARAMETER VerifyBackup
    Verify backup integrity after creation

.PARAMETER ScheduleBackup
    Create scheduled backup task

.PARAMETER TaskName
    Name for the scheduled task

.PARAMETER ScheduleType
    Schedule type (Daily, Weekly, Monthly)

.EXAMPLE
    .\Backup-FileServer.ps1 -Action BackupConfig -BackupPath "C:\Backups\FileServer-Config.xml" -IncludeShares -IncludePermissions

.EXAMPLE
    .\Backup-FileServer.ps1 -Action BackupFiles -SourcePath "C:\Shares" -DestinationPath "D:\Backups\Files" -CompressionLevel "Optimal"

.EXAMPLE
    .\Backup-FileServer.ps1 -Action CreateShadowCopy -DriveLetter "C" -ShadowCopyType "Manual"

.EXAMPLE
    .\Backup-FileServer.ps1 -Action DisasterRecovery -BackupPath "C:\Backups\FileServer-Config.xml"

.NOTES
    Author: File and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("BackupConfig", "BackupFiles", "RestoreConfig", "RestoreFiles", "CreateShadowCopy", "ManageShadowCopies", "DisasterRecovery")]
    [string]$Action,
    
    [string]$BackupPath,
    
    [string]$RestorePath,
    
    [string]$SourcePath,
    
    [string]$DestinationPath,
    
    [string]$DriveLetter,
    
    [ValidateSet("Manual", "Scheduled")]
    [string]$ShadowCopyType = "Manual",
    
    [int]$RetentionDays = 7,
    
    [switch]$IncludeShares,
    
    [switch]$IncludePermissions,
    
    [ValidateSet("None", "Fast", "Optimal")]
    [string]$CompressionLevel = "Optimal",
    
    [switch]$VerifyBackup,
    
    [switch]$ScheduleBackup,
    
    [string]$TaskName = "File Server Backup",
    
    [ValidateSet("Daily", "Weekly", "Monthly")]
    [string]$ScheduleType = "Daily"
)

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "FileStorage-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "FileStorage-Management.psm1") -Force
    Import-Module (Join-Path $modulePath "FileStorage-Troubleshooting.psm1") -Force
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Script variables
$script:BackupLog = @()
$script:StartTime = Get-Date

function Write-BackupLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:BackupLog += $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function New-ConfigurationBackup {
    param(
        [string]$BackupPath,
        [switch]$IncludeShares,
        [switch]$IncludePermissions
    )
    
    Write-BackupLog "Creating file server configuration backup..." "INFO"
    
    try {
        if (-not $BackupPath) {
            $BackupPath = Join-Path $scriptPath "FileServer-Config-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"
        }
        
        $backup = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            Configuration = @{}
            Shares = @()
            Services = @{}
            Registry = @{}
        }
        
        # Backup file server configuration
        $config = Get-FileServerConfiguration
        $backup.Configuration = $config
        
        # Backup services
        $services = @('LanmanServer', 'LanmanWorkstation', 'Browser', 'FsrmSvc')
        foreach ($serviceName in $services) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                $backup.Services[$serviceName] = @{
                    Status = $service.Status
                    StartType = $service.StartType
                    DisplayName = $service.DisplayName
                }
            }
        }
        
        # Backup shares if requested
        if ($IncludeShares) {
            $shares = Get-SmbShare | Where-Object { $_.ShareType -eq 'FileSystemDirectory' }
            foreach ($share in $shares) {
                $shareInfo = @{
                    Name = $share.Name
                    Path = $share.Path
                    Description = $share.Description
                    FolderEnumerationMode = $share.FolderEnumerationMode
                    CachingMode = $share.CachingMode
                    Permissions = @()
                }
                
                # Get share permissions
                try {
                    $permissions = Get-SmbShareAccess -Name $share.Name
                    $shareInfo.Permissions = $permissions | Select-Object AccountName, AccessRight, AccessType
                } catch {
                    Write-Warning "Could not retrieve permissions for share: $($share.Name)"
                }
                
                $backup.Shares += $shareInfo
            }
        }
        
        # Backup registry configuration
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\MSDRMS",
            "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer",
            "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation"
        )
        
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                try {
                    $regData = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                    if ($regData) {
                        $backup.Registry[$regPath] = $regData
                    }
                } catch {
                    Write-Warning "Could not backup registry path: $regPath"
                }
            }
        }
        
        # Save backup
        $backup | Export-Clixml -Path $BackupPath -Force
        
        Write-BackupLog "Configuration backup saved to: $BackupPath" "SUCCESS"
        return $BackupPath
        
    } catch {
        Write-BackupLog "Failed to create configuration backup: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Restore-ConfigurationBackup {
    param([string]$RestorePath)
    
    Write-BackupLog "Restoring file server configuration from backup..." "INFO"
    
    try {
        if (-not (Test-Path $RestorePath)) {
            throw "Backup file not found: $RestorePath"
        }
        
        # Load backup
        $backup = Import-Clixml -Path $RestorePath
        
        Write-BackupLog "Restoring configuration from: $($backup.Timestamp)" "INFO"
        
        # Restore services
        foreach ($serviceName in $backup.Services.Keys) {
            $serviceInfo = $backup.Services[$serviceName]
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            
            if ($service) {
                # Set service startup type
                Set-Service -Name $serviceName -StartupType $serviceInfo.StartType
                
                # Start service if it was running
                if ($serviceInfo.Status -eq 'Running' -and $service.Status -ne 'Running') {
                    Start-Service -Name $serviceName
                }
                
                Write-BackupLog "Restored service: $serviceName" "SUCCESS"
            }
        }
        
        # Restore shares
        foreach ($shareInfo in $backup.Shares) {
            try {
                # Check if share already exists
                $existingShare = Get-SmbShare -Name $shareInfo.Name -ErrorAction SilentlyContinue
                
                if (-not $existingShare) {
                    # Ensure the path exists
                    if (-not (Test-Path $shareInfo.Path)) {
                        New-Item -Path $shareInfo.Path -ItemType Directory -Force | Out-Null
                    }
                    
                    # Create the share
                    $shareParams = @{
                        Name = $shareInfo.Name
                        Path = $shareInfo.Path
                        Description = $shareInfo.Description
                    }
                    
                    if ($shareInfo.FolderEnumerationMode -eq 'AccessBased') {
                        $shareParams.AccessBasedEnumeration = $true
                    }
                    
                    New-SmbShare @shareParams
                    
                    # Set caching mode
                    if ($shareInfo.CachingMode) {
                        Set-SmbShare -Name $shareInfo.Name -CachingMode $shareInfo.CachingMode
                    }
                    
                    # Restore permissions
                    foreach ($permission in $shareInfo.Permissions) {
                        try {
                            Grant-SmbShareAccess -Name $shareInfo.Name -AccountName $permission.AccountName -AccessRight $permission.AccessRight -AccessType $permission.AccessType -Force
                        } catch {
                            Write-Warning "Could not restore permission for $($permission.AccountName) on share $($shareInfo.Name)"
                        }
                    }
                    
                    Write-BackupLog "Restored share: $($shareInfo.Name)" "SUCCESS"
                } else {
                    Write-BackupLog "Share already exists, skipping: $($shareInfo.Name)" "WARNING"
                }
            } catch {
                Write-Warning "Failed to restore share $($shareInfo.Name): $($_.Exception.Message)"
            }
        }
        
        Write-BackupLog "Configuration restore completed successfully" "SUCCESS"
        return $true
        
    } catch {
        Write-BackupLog "Failed to restore configuration backup: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function New-FileBackup {
    param(
        [string]$SourcePath,
        [string]$DestinationPath,
        [string]$CompressionLevel,
        [switch]$IncludePermissions,
        [switch]$VerifyBackup
    )
    
    Write-BackupLog "Creating file backup..." "INFO"
    
    try {
        if (-not (Test-Path $SourcePath)) {
            throw "Source path does not exist: $SourcePath"
        }
        
        # Ensure destination directory exists
        if (-not (Test-Path $DestinationPath)) {
            New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null
        }
        
        # Create backup using Robocopy
        $robocopyArgs = @(
            "`"$SourcePath`"",
            "`"$DestinationPath`"",
            "/E", "/COPY:DAT"
        )
        
        if ($IncludePermissions) {
            $robocopyArgs += "/COPY:DATSOU"
        }
        
        if ($CompressionLevel -eq "Fast") {
            $robocopyArgs += "/COMPRESS"
        }
        
        $robocopyArgs += "/R:3", "/W:10", "/LOG:`"$DestinationPath\Backup.log`""
        
        Write-BackupLog "Starting file backup with Robocopy..." "INFO"
        $robocopyProcess = Start-Process -FilePath "robocopy.exe" -ArgumentList $robocopyArgs -Wait -PassThru -NoNewWindow
        
        if ($robocopyProcess.ExitCode -le 7) {
            Write-BackupLog "File backup completed successfully" "SUCCESS"
            
            # Verify backup if requested
            if ($VerifyBackup) {
                Write-BackupLog "Verifying backup integrity..." "INFO"
                $verificationResult = Test-Path $DestinationPath
                if ($verificationResult) {
                    Write-BackupLog "Backup verification passed" "SUCCESS"
                } else {
                    Write-BackupLog "Backup verification failed" "ERROR"
                }
            }
            
            return $true
        } else {
            throw "Robocopy failed with exit code: $($robocopyProcess.ExitCode)"
        }
        
    } catch {
        Write-BackupLog "Failed to create file backup: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Restore-FileBackup {
    param(
        [string]$SourcePath,
        [string]$DestinationPath,
        [switch]$IncludePermissions
    )
    
    Write-BackupLog "Restoring file backup..." "INFO"
    
    try {
        if (-not (Test-Path $SourcePath)) {
            throw "Source backup path does not exist: $SourcePath"
        }
        
        # Ensure destination directory exists
        if (-not (Test-Path $DestinationPath)) {
            New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null
        }
        
        # Restore using Robocopy
        $robocopyArgs = @(
            "`"$SourcePath`"",
            "`"$DestinationPath`"",
            "/E", "/COPY:DAT"
        )
        
        if ($IncludePermissions) {
            $robocopyArgs += "/COPY:DATSOU"
        }
        
        $robocopyArgs += "/R:3", "/W:10", "/LOG:`"$DestinationPath\Restore.log`""
        
        Write-BackupLog "Starting file restore with Robocopy..." "INFO"
        $robocopyProcess = Start-Process -FilePath "robocopy.exe" -ArgumentList $robocopyArgs -Wait -PassThru -NoNewWindow
        
        if ($robocopyProcess.ExitCode -le 7) {
            Write-BackupLog "File restore completed successfully" "SUCCESS"
            return $true
        } else {
            throw "Robocopy restore failed with exit code: $($robocopyProcess.ExitCode)"
        }
        
    } catch {
        Write-BackupLog "Failed to restore file backup: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function New-ShadowCopy {
    param(
        [string]$DriveLetter,
        [string]$ShadowCopyType
    )
    
    Write-BackupLog "Creating shadow copy for drive: $DriveLetter" "INFO"
    
    try {
        # Check if Volume Shadow Copy Service is running
        $vssService = Get-Service -Name VSS -ErrorAction SilentlyContinue
        if ($vssService -and $vssService.Status -ne 'Running') {
            Start-Service -Name VSS
        }
        
        # Create shadow copy
        $shadowCopy = New-VolumeShadowCopy -Drive $DriveLetter -Description "Backup Script - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        
        Write-BackupLog "Shadow copy created successfully: $($shadowCopy.ShadowCopyId)" "SUCCESS"
        return $shadowCopy
        
    } catch {
        Write-BackupLog "Failed to create shadow copy: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Set-ShadowCopies {
    param(
        [string]$DriveLetter,
        [int]$RetentionDays
    )
    
    Write-BackupLog "Managing shadow copies for drive: $DriveLetter" "INFO"
    
    try {
        # Get existing shadow copies
        $shadowCopies = Get-VolumeShadowCopy -Drive $DriveLetter
        
        Write-BackupLog "Found $($shadowCopies.Count) existing shadow copies" "INFO"
        
        # Remove old shadow copies
        $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
        $oldShadowCopies = $shadowCopies | Where-Object { $_.CreationTime -lt $cutoffDate }
        
        foreach ($oldShadowCopy in $oldShadowCopies) {
            try {
                Remove-VolumeShadowCopy -ShadowCopyId $oldShadowCopy.ShadowCopyId -Confirm:$false
                Write-BackupLog "Removed old shadow copy: $($oldShadowCopy.ShadowCopyId)" "SUCCESS"
            } catch {
                Write-Warning "Could not remove shadow copy: $($oldShadowCopy.ShadowCopyId)"
            }
        }
        
        # Create new shadow copy
        $newShadowCopy = New-ShadowCopy -DriveLetter $DriveLetter -ShadowCopyType "Manual"
        
        Write-BackupLog "Shadow copy management completed" "SUCCESS"
        return $newShadowCopy
        
    } catch {
        Write-BackupLog "Failed to manage shadow copies: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Start-DisasterRecovery {
    param([string]$BackupPath)
    
    Write-BackupLog "Starting disaster recovery procedure..." "INFO"
    
    try {
        $recoveryResults = @{
            StepsCompleted = @()
            Issues = @()
            Recommendations = @()
            Overall = 'Unknown'
        }
        
        # Step 1: Verify backup exists
        if (-not (Test-Path $BackupPath)) {
            throw "Backup file not found: $BackupPath"
        }
        
        $recoveryResults.StepsCompleted += "Backup file verified"
        Write-BackupLog "Backup file verified: $BackupPath" "SUCCESS"
        
        # Step 2: Check system health
        $healthCheck = Test-FileServerHealth
        if ($healthCheck.Overall -ne 'Healthy') {
            $recoveryResults.Issues += "System health issues detected: $($healthCheck.Overall)"
            $recoveryResults.Recommendations += "Address system health issues before proceeding"
        }
        
        $recoveryResults.StepsCompleted += "System health checked"
        
        # Step 3: Stop file server services
        try {
            Stop-FileServerServices
            $recoveryResults.StepsCompleted += "File server services stopped"
            Write-BackupLog "File server services stopped" "SUCCESS"
        } catch {
            $recoveryResults.Issues += "Could not stop file server services"
        }
        
        # Step 4: Restore configuration
        try {
            Restore-ConfigurationBackup -RestorePath $BackupPath
            $recoveryResults.StepsCompleted += "Configuration restored"
            Write-BackupLog "Configuration restored successfully" "SUCCESS"
        } catch {
            $recoveryResults.Issues += "Configuration restore failed"
        }
        
        # Step 5: Start file server services
        try {
            Start-FileServerServices
            $recoveryResults.StepsCompleted += "File server services started"
            Write-BackupLog "File server services started" "SUCCESS"
        } catch {
            $recoveryResults.Issues += "Could not start file server services"
        }
        
        # Step 6: Verify recovery
        try {
            Start-Sleep -Seconds 10
            $postRecoveryHealth = Test-FileServerHealth
            $recoveryResults.StepsCompleted += "Recovery verification completed"
            
            if ($postRecoveryHealth.Overall -eq 'Healthy') {
                $recoveryResults.Overall = 'Successful'
                Write-BackupLog "Disaster recovery completed successfully" "SUCCESS"
            } else {
                $recoveryResults.Overall = 'Partial'
                $recoveryResults.Issues += "System not fully healthy after recovery"
                $recoveryResults.Recommendations += "Manual intervention may be required"
            }
        } catch {
            $recoveryResults.Issues += "Recovery verification failed"
        }
        
        return [PSCustomObject]$recoveryResults
        
    } catch {
        Write-BackupLog "Disaster recovery failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function New-ScheduledBackupTask {
    param(
        [string]$TaskName,
        [string]$ScheduleType,
        [string]$BackupPath
    )
    
    Write-BackupLog "Creating scheduled backup task..." "INFO"
    
    try {
        # Define the action
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" -Action BackupConfig -BackupPath `"$BackupPath`" -IncludeShares -IncludePermissions"
        
        # Define the trigger based on schedule type
        switch ($ScheduleType) {
            "Daily" {
                $trigger = New-ScheduledTaskTrigger -Daily -At "02:00"
            }
            "Weekly" {
                $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "02:00"
            }
            "Monthly" {
                $trigger = New-ScheduledTaskTrigger -Monthly -DaysOfMonth 1 -At "02:00"
            }
        }
        
        # Define the principal
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Define settings
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        # Create the task
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "File Server Configuration Backup Task"
        
        Write-BackupLog "Scheduled backup task created: $TaskName" "SUCCESS"
        return $true
        
    } catch {
        Write-BackupLog "Failed to create scheduled backup task: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Save-BackupLog {
    $logPath = Join-Path $scriptPath "Backup-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    try {
        $script:BackupLog | Out-File -FilePath $logPath -Encoding UTF8
        Write-BackupLog "Backup log saved to: $logPath" "INFO"
    } catch {
        Write-Warning "Failed to save backup log: $($_.Exception.Message)"
    }
}

# Main backup and recovery process
try {
    Write-BackupLog "Starting file server backup and recovery..." "INFO"
    Write-BackupLog "Action: $Action" "INFO"
    
    switch ($Action) {
        "BackupConfig" {
            $backupPath = New-ConfigurationBackup -BackupPath $BackupPath -IncludeShares:$IncludeShares -IncludePermissions:$IncludePermissions
            
            if ($ScheduleBackup) {
                New-ScheduledBackupTask -TaskName $TaskName -ScheduleType $ScheduleType -BackupPath $backupPath
            }
            
            Write-Host "`nConfiguration backup created: $backupPath" -ForegroundColor Green
        }
        
        "BackupFiles" {
            if (-not $SourcePath -or -not $DestinationPath) {
                throw "SourcePath and DestinationPath parameters are required for BackupFiles action"
            }
            
            New-FileBackup -SourcePath $SourcePath -DestinationPath $DestinationPath -CompressionLevel $CompressionLevel -IncludePermissions:$IncludePermissions -VerifyBackup:$VerifyBackup
            
            Write-Host "`nFile backup completed successfully" -ForegroundColor Green
        }
        
        "RestoreConfig" {
            if (-not $RestorePath) {
                throw "RestorePath parameter is required for RestoreConfig action"
            }
            
            Restore-ConfigurationBackup -RestorePath $RestorePath
            
            Write-Host "`nConfiguration restore completed successfully" -ForegroundColor Green
        }
        
        "RestoreFiles" {
            if (-not $SourcePath -or -not $DestinationPath) {
                throw "SourcePath and DestinationPath parameters are required for RestoreFiles action"
            }
            
            Restore-FileBackup -SourcePath $SourcePath -DestinationPath $DestinationPath -IncludePermissions:$IncludePermissions
            
            Write-Host "`nFile restore completed successfully" -ForegroundColor Green
        }
        
        "CreateShadowCopy" {
            if (-not $DriveLetter) {
                throw "DriveLetter parameter is required for CreateShadowCopy action"
            }
            
            $shadowCopy = New-ShadowCopy -DriveLetter $DriveLetter -ShadowCopyType $ShadowCopyType
            
            Write-Host "`nShadow copy created: $($shadowCopy.ShadowCopyId)" -ForegroundColor Green
        }
        
        "ManageShadowCopies" {
            if (-not $DriveLetter) {
                throw "DriveLetter parameter is required for ManageShadowCopies action"
            }
            
            $shadowCopy = Set-ShadowCopies -DriveLetter $DriveLetter -RetentionDays $RetentionDays
            
            Write-Host "`nShadow copy management completed" -ForegroundColor Green
        }
        
        "DisasterRecovery" {
            if (-not $BackupPath) {
                throw "BackupPath parameter is required for DisasterRecovery action"
            }
            
            $recoveryResults = Start-DisasterRecovery -BackupPath $BackupPath
            
            Write-Host "`n=== Disaster Recovery Results ===" -ForegroundColor Cyan
            Write-Host "Overall Status: $($recoveryResults.Overall)" -ForegroundColor White
            Write-Host "Steps Completed: $($recoveryResults.StepsCompleted.Count)" -ForegroundColor White
            Write-Host "Issues Found: $($recoveryResults.Issues.Count)" -ForegroundColor White
            Write-Host "Recommendations: $($recoveryResults.Recommendations.Count)" -ForegroundColor White
            
            if ($recoveryResults.Issues.Count -gt 0) {
                Write-Host "`nIssues:" -ForegroundColor Yellow
                $recoveryResults.Issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
            }
            
            if ($recoveryResults.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                $recoveryResults.Recommendations | ForEach-Object { Write-Host "  - $_" -ForegroundColor Green }
            }
        }
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-BackupLog "File server backup and recovery completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== File Server Backup and Recovery Summary ===" -ForegroundColor Cyan
    Write-Host "Action: $Action" -ForegroundColor White
    Write-Host "Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    
    # Save backup log
    Save-BackupLog
    
    Write-Host "`nBackup and recovery completed successfully!" -ForegroundColor Green
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-BackupLog "File server backup and recovery failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save backup log
    Save-BackupLog
    
    Write-Host "`nBackup and recovery failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the backup log for details." -ForegroundColor Yellow
    
    exit 1
}
