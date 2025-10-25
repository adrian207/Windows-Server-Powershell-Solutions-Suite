#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Active Directory Backup and Restore PowerShell Module

.DESCRIPTION
    This module provides comprehensive Active Directory backup and restore capabilities
    including system state backup, AD database backup, and disaster recovery procedures.

.NOTES
    Author: Backup and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/backup-and-storage-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Get-ADBackupPath {
    <#
    .SYNOPSIS
        Gets the default backup path for Active Directory backups
    #>
    [CmdletBinding()]
    param()
    
    $backupPath = "C:\AD-Backups"
    if (-not (Test-Path $backupPath)) {
        try {
            New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
        } catch {
            Write-Warning "Failed to create backup directory: $($_.Exception.Message)"
            return $null
        }
    }
    return $backupPath
}

function Test-ADBackupPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for Active Directory backup operations
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        IsDomainController = $false
        WindowsBackupInstalled = $false
        SufficientSpace = $false
        BackupPathWritable = $false
    }
    
    # Check if this is a domain controller
    try {
        $domainRole = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole
        $prerequisites.IsDomainController = ($domainRole -eq 4 -or $domainRole -eq 5) # Primary or Backup DC
    } catch {
        Write-Warning "Could not determine domain controller status: $($_.Exception.Message)"
    }
    
    # Check Windows Server Backup installation
    try {
        $backupFeature = Get-WindowsFeature -Name "Windows-Server-Backup"
        $prerequisites.WindowsBackupInstalled = ($backupFeature.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check Windows Server Backup installation: $($_.Exception.Message)"
    }
    
    # Check available disk space
    try {
        $backupPath = Get-ADBackupPath
        if ($backupPath) {
            $drive = Split-Path $backupPath -Qualifier
            $disk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$drive'"
            $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            $prerequisites.SufficientSpace = ($freeSpaceGB -gt 10) # At least 10GB free
            $prerequisites.FreeSpaceGB = $freeSpaceGB
        }
    } catch {
        Write-Warning "Could not check disk space: $($_.Exception.Message)"
    }
    
    # Check if backup path is writable
    try {
        $backupPath = Get-ADBackupPath
        if ($backupPath) {
            $testFile = Join-Path $backupPath "test-write.tmp"
            "test" | Out-File -FilePath $testFile -ErrorAction Stop
            Remove-Item $testFile -ErrorAction SilentlyContinue
            $prerequisites.BackupPathWritable = $true
        }
    } catch {
        Write-Warning "Backup path is not writable: $($_.Exception.Message)"
    }
    
    return $prerequisites
}

#endregion

#region Public Functions

function Start-ADSystemStateBackup {
    <#
    .SYNOPSIS
        Creates a system state backup of Active Directory
    
    .DESCRIPTION
        This function creates a comprehensive system state backup including
        Active Directory database, SYSVOL, registry, and other critical components.
    
    .PARAMETER BackupPath
        Path where the backup will be stored
    
    .PARAMETER BackupName
        Name for the backup (default: AD-SystemState-YYYYMMDD-HHMMSS)
    
    .PARAMETER IncludeSystemDrive
        Include the system drive in the backup
    
    .PARAMETER CompressionEnabled
        Enable compression for the backup
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Start-ADSystemStateBackup -BackupPath "D:\AD-Backups"
    
    .EXAMPLE
        Start-ADSystemStateBackup -BackupPath "D:\AD-Backups" -IncludeSystemDrive -CompressionEnabled
    #>
    [CmdletBinding()]
    param(
        [string]$BackupPath,
        
        [string]$BackupName,
        
        [switch]$IncludeSystemDrive,
        
        [switch]$CompressionEnabled
    )
    
    try {
        Write-Verbose "Starting Active Directory system state backup..."
        
        # Set default values
        if (-not $BackupPath) {
            $BackupPath = Get-ADBackupPath
        }
        
        if (-not $BackupName) {
            $BackupName = "AD-SystemState-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        }
        
        # Test prerequisites
        $prerequisites = Test-ADBackupPrerequisites
        if (-not $prerequisites.IsDomainController) {
            throw "This computer is not a domain controller. System state backup is only available on domain controllers."
        }
        
        if (-not $prerequisites.WindowsBackupInstalled) {
            throw "Windows Server Backup is not installed. Please install it first."
        }
        
        if (-not $prerequisites.SufficientSpace) {
            throw "Insufficient disk space. Available: $($prerequisites.FreeSpaceGB)GB. Required: 10GB minimum."
        }
        
        if (-not $prerequisites.BackupPathWritable) {
            throw "Backup path is not writable: $BackupPath"
        }
        
        # Create backup policy
        $backupPolicy = New-WBPolicy
        
        # Add system state to backup
        $systemState = Get-WBSystemState
        Add-WBSystemState -Policy $backupPolicy
        
        # Add system drive if requested
        if ($IncludeSystemDrive) {
            $systemDrive = Get-WBVolume | Where-Object { $_.SystemVolume -eq $true }
            if ($systemDrive) {
                Add-WBVolume -Policy $backupPolicy -Volume $systemDrive
            }
        }
        
        # Set backup target
        $backupTarget = New-WBBackupTarget -VolumePath $BackupPath
        Add-WBBackupTarget -Policy $backupPolicy -Target $backupTarget
        
        # Set backup schedule (immediate)
        $backupSchedule = New-WBSchedule -Start (Get-Date)
        Set-WBSchedule -Policy $backupPolicy -Schedule $backupSchedule
        
        # Set compression if enabled
        if ($CompressionEnabled) {
            Set-WBVssBackupOptions -Policy $backupPolicy -VssCopyBackup
        }
        
        # Start backup
        Write-Verbose "Starting backup: $BackupName"
        $backupJob = Start-WBBackup -Policy $backupPolicy -Async
        
        $result = @{
            Success = $true
            BackupName = $BackupName
            BackupPath = $BackupPath
            JobId = $backupJob.JobId
            StartTime = Get-Date
            Policy = $backupPolicy
            Prerequisites = $prerequisites
        }
        
        Write-Verbose "Active Directory system state backup started successfully"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error starting Active Directory system state backup: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
            BackupName = $BackupName
            BackupPath = $BackupPath
        }
    }
}

function Get-ADBackupStatus {
    <#
    .SYNOPSIS
        Gets the status of Active Directory backup jobs
    
    .DESCRIPTION
        Retrieves the current status of Windows Server Backup jobs,
        including progress and completion status.
    
    .PARAMETER JobId
        Specific job ID to check (optional)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-ADBackupStatus
    
    .EXAMPLE
        Get-ADBackupStatus -JobId "12345"
    #>
    [CmdletBinding()]
    param(
        [string]$JobId
    )
    
    try {
        Write-Verbose "Getting Active Directory backup status..."
        
        $backupJobs = @()
        
        if ($JobId) {
            $jobs = Get-WBJob -JobId $JobId -ErrorAction SilentlyContinue
        } else {
            $jobs = Get-WBJob -ErrorAction SilentlyContinue
        }
        
        foreach ($job in $jobs) {
            $jobInfo = @{
                JobId = $job.JobId
                JobState = $job.JobState
                StartTime = $job.StartTime
                EndTime = $job.EndTime
                Duration = if ($job.EndTime) { $job.EndTime - $job.StartTime } else { (Get-Date) - $job.StartTime }
                Progress = $job.Progress
                ErrorCode = $job.ErrorCode
                ErrorDescription = $job.ErrorDescription
                BackupTarget = $job.BackupTarget
                BackupTime = $job.BackupTime
            }
            
            $backupJobs += [PSCustomObject]$jobInfo
        }
        
        $result = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Jobs = $backupJobs
            TotalJobs = $backupJobs.Count
            RunningJobs = ($backupJobs | Where-Object { $_.JobState -eq "Running" }).Count
            CompletedJobs = ($backupJobs | Where-Object { $_.JobState -eq "Completed" }).Count
            FailedJobs = ($backupJobs | Where-Object { $_.JobState -eq "Failed" }).Count
        }
        
        Write-Verbose "Active Directory backup status retrieved successfully"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error getting Active Directory backup status: $($_.Exception.Message)"
        return $null
    }
}

function Restore-ADSystemState {
    <#
    .SYNOPSIS
        Restores Active Directory from a system state backup
    
    .DESCRIPTION
        This function restores Active Directory from a previous system state backup.
        This is a critical operation that should be performed with extreme caution.
    
    .PARAMETER BackupPath
        Path to the backup to restore from
    
    .PARAMETER BackupTime
        Specific backup time to restore from
    
    .PARAMETER TargetPath
        Target path for restoration
    
    .PARAMETER ConfirmRestore
        Confirmation flag - must be set to true to proceed
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Restore-ADSystemState -BackupPath "D:\AD-Backups" -BackupTime "2024-01-15 14:30:00" -ConfirmRestore
    
    .NOTES
        WARNING: This operation will overwrite the current Active Directory database.
        Ensure you have a current backup before proceeding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath,
        
        [Parameter(Mandatory = $true)]
        [datetime]$BackupTime,
        
        [string]$TargetPath,
        
        [switch]$ConfirmRestore
    )
    
    if (-not $ConfirmRestore) {
        throw "You must specify -ConfirmRestore to proceed with this destructive operation."
    }
    
    try {
        Write-Verbose "Starting Active Directory system state restore..."
        
        # Get available backups
        $backups = Get-WBBackupSet -BackupTarget $BackupPath -ErrorAction Stop
        
        # Find the specific backup
        $targetBackup = $backups | Where-Object { 
            $_.BackupTime -eq $BackupTime 
        }
        
        if (-not $targetBackup) {
            throw "Backup not found for the specified time: $BackupTime"
        }
        
        # Set target path
        if (-not $TargetPath) {
            $TargetPath = "C:\"
        }
        
        # Create restore policy
        $restorePolicy = New-WBPolicy
        
        # Add system state to restore
        $systemState = Get-WBSystemState
        Add-WBSystemState -Policy $restorePolicy -SystemState $systemState
        
        # Set restore target
        $restoreTarget = New-WBRestoreTarget -TargetPath $TargetPath
        Add-WBRestoreTarget -Policy $restorePolicy -Target $restoreTarget
        
        # Start restore
        Write-Verbose "Starting restore from backup: $BackupTime"
        $restoreJob = Start-WBRestore -Policy $restorePolicy -BackupSet $targetBackup -Async
        
        $result = @{
            Success = $true
            BackupTime = $BackupTime
            BackupPath = $BackupPath
            TargetPath = $TargetPath
            JobId = $restoreJob.JobId
            StartTime = Get-Date
            Warning = "System restart will be required after restore completion"
        }
        
        Write-Verbose "Active Directory system state restore started successfully"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error starting Active Directory system state restore: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
            BackupTime = $BackupTime
            BackupPath = $BackupPath
        }
    }
}

function Get-ADBackupHistory {
    <#
    .SYNOPSIS
        Gets the history of Active Directory backups
    
    .DESCRIPTION
        Retrieves a list of all available Active Directory backups
        with their details and status.
    
    .PARAMETER BackupPath
        Path to check for backups
    
    .PARAMETER Days
        Number of days to look back (default: 30)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-ADBackupHistory
    
    .EXAMPLE
        Get-ADBackupHistory -BackupPath "D:\AD-Backups" -Days 7
    #>
    [CmdletBinding()]
    param(
        [string]$BackupPath,
        
        [int]$Days = 30
    )
    
    try {
        Write-Verbose "Getting Active Directory backup history..."
        
        if (-not $BackupPath) {
            $BackupPath = Get-ADBackupPath
        }
        
        $cutoffDate = (Get-Date).AddDays(-$Days)
        
        # Get backup sets
        $backupSets = Get-WBBackupSet -BackupTarget $BackupPath -ErrorAction SilentlyContinue
        
        $backupHistory = @()
        
        foreach ($backupSet in $backupSets) {
            if ($backupSet.BackupTime -ge $cutoffDate) {
                $backupInfo = @{
                    BackupTime = $backupSet.BackupTime
                    BackupPath = $BackupPath
                    BackupSize = $backupSet.BackupSize
                    BackupTarget = $backupSet.BackupTarget
                    BackupType = $backupSet.BackupType
                    DaysOld = [math]::Round(((Get-Date) - $backupSet.BackupTime).TotalDays, 1)
                }
                
                $backupHistory += [PSCustomObject]$backupInfo
            }
        }
        
        # Sort by backup time (newest first)
        $backupHistory = $backupHistory | Sort-Object BackupTime -Descending
        
        $result = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            BackupPath = $BackupPath
            Days = $Days
            Backups = $backupHistory
            TotalBackups = $backupHistory.Count
            OldestBackup = if ($backupHistory.Count -gt 0) { $backupHistory[-1].BackupTime } else { $null }
            NewestBackup = if ($backupHistory.Count -gt 0) { $backupHistory[0].BackupTime } else { $null }
        }
        
        Write-Verbose "Active Directory backup history retrieved successfully"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error getting Active Directory backup history: $($_.Exception.Message)"
        return $null
    }
}

function Remove-OldADBackups {
    <#
    .SYNOPSIS
        Removes old Active Directory backups to free up space
    
    .DESCRIPTION
        This function removes Active Directory backups older than the specified
        retention period to manage disk space.
    
    .PARAMETER BackupPath
        Path where backups are stored
    
    .PARAMETER RetentionDays
        Number of days to retain backups (default: 30)
    
    .PARAMETER ConfirmRemoval
        Confirmation flag - must be set to true to proceed
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Remove-OldADBackups -BackupPath "D:\AD-Backups" -RetentionDays 14 -ConfirmRemoval
    
    .NOTES
        WARNING: This operation will permanently delete old backups.
        Ensure you have verified the retention policy before proceeding.
    #>
    [CmdletBinding()]
    param(
        [string]$BackupPath,
        
        [int]$RetentionDays = 30,
        
        [switch]$ConfirmRemoval
    )
    
    if (-not $ConfirmRemoval) {
        throw "You must specify -ConfirmRemoval to proceed with this destructive operation."
    }
    
    try {
        Write-Verbose "Removing old Active Directory backups..."
        
        if (-not $BackupPath) {
            $BackupPath = Get-ADBackupPath
        }
        
        $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
        
        # Get backup sets
        $backupSets = Get-WBBackupSet -BackupTarget $BackupPath -ErrorAction SilentlyContinue
        
        $removedBackups = @()
        $totalSpaceFreed = 0
        
        foreach ($backupSet in $backupSets) {
            if ($backupSet.BackupTime -lt $cutoffDate) {
                try {
                    # Remove the backup
                    Remove-WBBackupSet -BackupSet $backupSet -Force
                    
                    $removedBackups += @{
                        BackupTime = $backupSet.BackupTime
                        BackupSize = $backupSet.BackupSize
                    }
                    
                    $totalSpaceFreed += $backupSet.BackupSize
                    
                    Write-Verbose "Removed backup from: $($backupSet.BackupTime)"
                } catch {
                    Write-Warning "Failed to remove backup from $($backupSet.BackupTime): $($_.Exception.Message)"
                }
            }
        }
        
        $result = @{
            Success = $true
            BackupPath = $BackupPath
            RetentionDays = $RetentionDays
            CutoffDate = $cutoffDate
            RemovedBackups = $removedBackups
            TotalRemoved = $removedBackups.Count
            SpaceFreedGB = [math]::Round($totalSpaceFreed / 1GB, 2)
        }
        
        Write-Verbose "Old Active Directory backups removal completed successfully"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error removing old Active Directory backups: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
            BackupPath = $BackupPath
            RetentionDays = $RetentionDays
        }
    }
}

function Test-ADBackupIntegrity {
    <#
    .SYNOPSIS
        Tests the integrity of Active Directory backups
    
    .DESCRIPTION
        This function performs integrity checks on Active Directory backups
        to ensure they are valid and can be used for restoration.
    
    .PARAMETER BackupPath
        Path where backups are stored
    
    .PARAMETER BackupTime
        Specific backup time to test (optional)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-ADBackupIntegrity
    
    .EXAMPLE
        Test-ADBackupIntegrity -BackupPath "D:\AD-Backups" -BackupTime "2024-01-15 14:30:00"
    #>
    [CmdletBinding()]
    param(
        [string]$BackupPath,
        
        [datetime]$BackupTime
    )
    
    try {
        Write-Verbose "Testing Active Directory backup integrity..."
        
        if (-not $BackupPath) {
            $BackupPath = Get-ADBackupPath
        }
        
        # Get backup sets
        $backupSets = Get-WBBackupSet -BackupTarget $BackupPath -ErrorAction SilentlyContinue
        
        if ($BackupTime) {
            $backupSets = $backupSets | Where-Object { $_.BackupTime -eq $BackupTime }
        }
        
        $integrityResults = @()
        
        foreach ($backupSet in $backupSets) {
            $integrityCheck = @{
                BackupTime = $backupSet.BackupTime
                BackupPath = $BackupPath
                IsValid = $false
                ErrorMessage = $null
                TestTime = Get-Date
            }
            
            try {
                # Test backup integrity
                $testResult = Test-WBBackupSet -BackupSet $backupSet -ErrorAction Stop
                $integrityCheck.IsValid = $true
            } catch {
                $integrityCheck.ErrorMessage = $_.Exception.Message
            }
            
            $integrityResults += [PSCustomObject]$integrityCheck
        }
        
        $result = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            BackupPath = $BackupPath
            TestedBackups = $integrityResults
            TotalTested = $integrityResults.Count
            ValidBackups = ($integrityResults | Where-Object { $_.IsValid }).Count
            InvalidBackups = ($integrityResults | Where-Object { -not $_.IsValid }).Count
        }
        
        Write-Verbose "Active Directory backup integrity testing completed"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error testing Active Directory backup integrity: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Start-ADSystemStateBackup',
    'Get-ADBackupStatus',
    'Restore-ADSystemState',
    'Get-ADBackupHistory',
    'Remove-OldADBackups',
    'Test-ADBackupIntegrity'
)

# Module initialization
Write-Verbose "BackupStorage-ADBackup module loaded successfully. Version: $ModuleVersion"
