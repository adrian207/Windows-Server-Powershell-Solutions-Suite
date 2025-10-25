#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deduplication Management PowerShell Module

.DESCRIPTION
    This module provides comprehensive deduplication management capabilities
    including deduplication configuration, monitoring, and optimization.

.NOTES
    Author: Backup and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/backup-and-storage-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Test-DeduplicationPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for deduplication operations
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        DeduplicationInstalled = $false
        PowerShellModuleAvailable = $false
        AdministratorPrivileges = $false
    }
    
    # Check if deduplication feature is installed
    try {
        $feature = Get-WindowsFeature -Name "FS-Data-Deduplication" -ErrorAction SilentlyContinue
        $prerequisites.DeduplicationInstalled = ($feature -and $feature.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check deduplication installation: $($_.Exception.Message)"
    }
    
    # Check if deduplication PowerShell module is available
    try {
        $module = Get-Module -ListAvailable -Name Deduplication -ErrorAction SilentlyContinue
        $prerequisites.PowerShellModuleAvailable = ($null -ne $module)
    } catch {
        Write-Warning "Could not check deduplication PowerShell module: $($_.Exception.Message)"
    }
    
    # Check administrator privileges
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $prerequisites.AdministratorPrivileges = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Warning "Could not check administrator privileges: $($_.Exception.Message)"
    }
    
    return $prerequisites
}

#endregion

#region Public Functions

function Enable-Deduplication {
    <#
    .SYNOPSIS
        Enables deduplication on specified volumes
    
    .DESCRIPTION
        This function enables deduplication on the specified volumes with
        configurable settings for optimization and scheduling.
    
    .PARAMETER VolumePaths
        Array of volume paths to enable deduplication on
    
    .PARAMETER OptimizationType
        Type of optimization (GeneralPurpose, HyperV, VDI, Backup)
    
    .PARAMETER MinimumFileAgeDays
        Minimum file age in days before deduplication (default: 3)
    
    .PARAMETER MinimumFileSizeKB
        Minimum file size in KB for deduplication (default: 32)
    
    .PARAMETER ExcludeFileExtensions
        File extensions to exclude from deduplication
    
    .PARAMETER ExcludeFolders
        Folders to exclude from deduplication
    
    .PARAMETER ScheduleOptimization
        Schedule for optimization (Daily, Weekly, Manual)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Enable-Deduplication -VolumePaths @("D:") -OptimizationType "GeneralPurpose"
    
    .EXAMPLE
        Enable-Deduplication -VolumePaths @("E:") -OptimizationType "HyperV" -MinimumFileAgeDays 7
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$VolumePaths,
        
        [ValidateSet("GeneralPurpose", "HyperV", "VDI", "Backup")]
        [string]$OptimizationType = "GeneralPurpose",
        
        [int]$MinimumFileAgeDays = 3,
        
        [int]$MinimumFileSizeKB = 32,
        
        [string[]]$ExcludeFileExtensions,
        
        [string[]]$ExcludeFolders,
        
        [ValidateSet("Daily", "Weekly", "Manual")]
        [string]$ScheduleOptimization = "Daily"
    )
    
    try {
        Write-Verbose "Enabling deduplication on volumes: $($VolumePaths -join ', ')"
        
        # Test prerequisites
        $prerequisites = Test-DeduplicationPrerequisites
        if (-not $prerequisites.DeduplicationInstalled) {
            throw "Data Deduplication feature is not installed. Please install it first."
        }
        
        if (-not $prerequisites.PowerShellModuleAvailable) {
            throw "Deduplication PowerShell module is not available."
        }
        
        $enableResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            VolumePaths = $VolumePaths
            OptimizationType = $OptimizationType
            VolumeResults = @()
            Prerequisites = $prerequisites
        }
        
        foreach ($volumePath in $VolumePaths) {
            Write-Verbose "Enabling deduplication on volume: $volumePath"
            
            $volumeResult = @{
                VolumePath = $volumePath
                Success = $false
                Error = $null
                Configuration = $null
            }
            
            try {
                # Enable deduplication
                Enable-DedupVolume -Volume $volumePath -ErrorAction Stop
                
                # Set deduplication configuration
                $configParams = @{
                    Volume = $volumePath
                    OptimizationType = $OptimizationType
                    MinimumFileAgeDays = $MinimumFileAgeDays
                    MinimumFileSizeKB = $MinimumFileSizeKB
                }
                
                Set-DedupVolume @configParams -ErrorAction Stop
                
                # Set exclusions if specified
                if ($ExcludeFileExtensions) {
                    Set-DedupVolume -Volume $volumePath -ExcludeFileType $ExcludeFileExtensions -ErrorAction SilentlyContinue
                }
                
                if ($ExcludeFolders) {
                    Set-DedupVolume -Volume $volumePath -ExcludeFolder $ExcludeFolders -ErrorAction SilentlyContinue
                }
                
                # Configure optimization schedule
                if ($ScheduleOptimization -ne "Manual") {
                    $scheduleDays = if ($ScheduleOptimization -eq "Daily") { @(0,1,2,3,4,5,6) } else { @(0) } # Daily or Sunday
                    Set-DedupSchedule -Name "Optimization" -Volume $volumePath -Days $scheduleDays -ErrorAction SilentlyContinue
                }
                
                # Get configuration
                $volumeResult.Configuration = Get-DedupVolume -Volume $volumePath -ErrorAction SilentlyContinue
                $volumeResult.Success = $true
                
                Write-Verbose "Deduplication enabled successfully on volume: $volumePath"
                
            } catch {
                $volumeResult.Error = $_.Exception.Message
                Write-Warning "Failed to enable deduplication on volume $volumePath`: $($_.Exception.Message)"
            }
            
            $enableResults.VolumeResults += [PSCustomObject]$volumeResult
        }
        
        Write-Verbose "Deduplication enablement completed"
        return [PSCustomObject]$enableResults
        
    } catch {
        Write-Error "Error enabling deduplication: $($_.Exception.Message)"
        return $null
    }
}

function Disable-Deduplication {
    <#
    .SYNOPSIS
        Disables deduplication on specified volumes
    
    .DESCRIPTION
        This function disables deduplication on the specified volumes.
        This process may take time as files need to be unoptimized.
    
    .PARAMETER VolumePaths
        Array of volume paths to disable deduplication on
    
    .PARAMETER ConfirmDisable
        Confirmation flag - must be set to true to proceed
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Disable-Deduplication -VolumePaths @("D:") -ConfirmDisable
    
    .NOTES
        WARNING: Disabling deduplication will unoptimize files and may require significant time and space.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$VolumePaths,
        
        [switch]$ConfirmDisable
    )
    
    if (-not $ConfirmDisable) {
        throw "You must specify -ConfirmDisable to proceed with this operation."
    }
    
    try {
        Write-Verbose "Disabling deduplication on volumes: $($VolumePaths -join ', ')"
        
        $disableResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            VolumePaths = $VolumePaths
            VolumeResults = @()
        }
        
        foreach ($volumePath in $VolumePaths) {
            Write-Verbose "Disabling deduplication on volume: $volumePath"
            
            $volumeResult = @{
                VolumePath = $volumePath
                Success = $false
                Error = $null
                UnoptimizationJob = $null
            }
            
            try {
                # Disable deduplication
                Disable-DedupVolume -Volume $volumePath -ErrorAction Stop
                
                # Start unoptimization job
                $unoptimizationJob = Start-DedupUnoptimization -Volume $volumePath -ErrorAction SilentlyContinue
                $volumeResult.UnoptimizationJob = $unoptimizationJob
                
                $volumeResult.Success = $true
                Write-Verbose "Deduplication disabled successfully on volume: $volumePath"
                
            } catch {
                $volumeResult.Error = $_.Exception.Message
                Write-Warning "Failed to disable deduplication on volume $volumePath`: $($_.Exception.Message)"
            }
            
            $disableResults.VolumeResults += [PSCustomObject]$volumeResult
        }
        
        Write-Verbose "Deduplication disablement completed"
        return [PSCustomObject]$disableResults
        
    } catch {
        Write-Error "Error disabling deduplication: $($_.Exception.Message)"
        return $null
    }
}

function Get-DeduplicationStatus {
    <#
    .SYNOPSIS
        Gets deduplication status for specified volumes
    
    .DESCRIPTION
        This function retrieves comprehensive deduplication status information
        including savings, optimization status, and configuration details.
    
    .PARAMETER VolumePaths
        Array of volume paths to get status for (optional, defaults to all deduplicated volumes)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-DeduplicationStatus
    
    .EXAMPLE
        Get-DeduplicationStatus -VolumePaths @("D:", "E:")
    #>
    [CmdletBinding()]
    param(
        [string[]]$VolumePaths
    )
    
    try {
        Write-Verbose "Getting deduplication status..."
        
        # Test prerequisites
        $prerequisites = Test-DeduplicationPrerequisites
        if (-not $prerequisites.DeduplicationInstalled) {
            throw "Data Deduplication feature is not installed."
        }
        
        $statusResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            VolumePaths = $VolumePaths
            VolumeStatus = @()
            Summary = @{}
            Prerequisites = $prerequisites
        }
        
        # Get volumes to check
        if (-not $VolumePaths) {
            $VolumePaths = Get-DedupVolume -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Volume
        }
        
        foreach ($volumePath in $VolumePaths) {
            try {
                $volumeStatus = Get-DedupVolume -Volume $volumePath -ErrorAction Stop
                
                $statusInfo = @{
                    VolumePath = $volumePath
                    Enabled = $volumeStatus.Enabled
                    OptimizationType = $volumeStatus.OptimizationType
                    UsageType = $volumeStatus.UsageType
                    DataReduction = $volumeStatus.DataReduction
                    SavingsRate = $volumeStatus.SavingsRate
                    OptimizedFilesCount = $volumeStatus.OptimizedFilesCount
                    OptimizedFilesSize = $volumeStatus.OptimizedFilesSize
                    InPolicyFilesCount = $volumeStatus.InPolicyFilesCount
                    InPolicyFilesSize = $volumeStatus.InPolicyFilesSize
                    UnoptimizedSize = $volumeStatus.UnoptimizedSize
                    SavedSpace = $volumeStatus.SavedSpace
                    DeduplicationRate = $volumeStatus.DeduplicationRate
                    CompressionRate = $volumeStatus.CompressionRate
                    LastOptimizationTime = $volumeStatus.LastOptimizationTime
                    LastGarbageCollectionTime = $volumeStatus.LastGarbageCollectionTime
                    LastScrubbingTime = $volumeStatus.LastScrubbingTime
                }
                
                $statusResults.VolumeStatus += [PSCustomObject]$statusInfo
                
            } catch {
                Write-Warning "Could not get deduplication status for volume $volumePath`: $($_.Exception.Message)"
            }
        }
        
        # Generate summary
        $enabledVolumes = ($statusResults.VolumeStatus | Where-Object { $_.Enabled }).Count
        $totalSavedSpace = ($statusResults.VolumeStatus | Measure-Object -Property SavedSpace -Sum).Sum
        $averageSavingsRate = if ($statusResults.VolumeStatus.Count -gt 0) { 
            ($statusResults.VolumeStatus | Measure-Object -Property SavingsRate -Average).Average 
        } else { 0 }
        
        $statusResults.Summary = @{
            TotalVolumes = $statusResults.VolumeStatus.Count
            EnabledVolumes = $enabledVolumes
            DisabledVolumes = $statusResults.VolumeStatus.Count - $enabledVolumes
            TotalSavedSpace = $totalSavedSpace
            AverageSavingsRate = [math]::Round($averageSavingsRate, 2)
        }
        
        Write-Verbose "Deduplication status retrieved successfully"
        return [PSCustomObject]$statusResults
        
    } catch {
        Write-Error "Error getting deduplication status: $($_.Exception.Message)"
        return $null
    }
}

function Start-DeduplicationOptimization {
    <#
    .SYNOPSIS
        Starts deduplication optimization on specified volumes
    
    .DESCRIPTION
        This function starts the deduplication optimization process on
        the specified volumes to optimize files and save space.
    
    .PARAMETER VolumePaths
        Array of volume paths to optimize
    
    .PARAMETER OptimizationType
        Type of optimization to perform (Optimization, GarbageCollection, Scrubbing, Unoptimization)
    
    .PARAMETER Priority
        Priority level for the optimization job (Low, Normal, High)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Start-DeduplicationOptimization -VolumePaths @("D:") -OptimizationType "Optimization"
    
    .EXAMPLE
        Start-DeduplicationOptimization -VolumePaths @("D:", "E:") -OptimizationType "GarbageCollection" -Priority "High"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$VolumePaths,
        
        [ValidateSet("Optimization", "GarbageCollection", "Scrubbing", "Unoptimization")]
        [string]$OptimizationType = "Optimization",
        
        [ValidateSet("Low", "Normal", "High")]
        [string]$Priority = "Normal"
    )
    
    try {
        Write-Verbose "Starting deduplication optimization: $OptimizationType on volumes: $($VolumePaths -join ', ')"
        
        $optimizationResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            VolumePaths = $VolumePaths
            OptimizationType = $OptimizationType
            Priority = $Priority
            VolumeResults = @()
        }
        
        foreach ($volumePath in $VolumePaths) {
            Write-Verbose "Starting $OptimizationType on volume: $volumePath"
            
            $volumeResult = @{
                VolumePath = $volumePath
                Success = $false
                JobId = $null
                Error = $null
            }
            
            try {
                # Start optimization based on type
                switch ($OptimizationType) {
                    "Optimization" {
                        $job = Start-DedupOptimization -Volume $volumePath -Priority $Priority -ErrorAction Stop
                    }
                    "GarbageCollection" {
                        $job = Start-DedupGarbageCollection -Volume $volumePath -Priority $Priority -ErrorAction Stop
                    }
                    "Scrubbing" {
                        $job = Start-DedupScrubbing -Volume $volumePath -Priority $Priority -ErrorAction Stop
                    }
                    "Unoptimization" {
                        $job = Start-DedupUnoptimization -Volume $volumePath -Priority $Priority -ErrorAction Stop
                    }
                }
                
                $volumeResult.JobId = $job.JobId
                $volumeResult.Success = $true
                
                Write-Verbose "$OptimizationType started successfully on volume: $volumePath (Job ID: $($job.JobId))"
                
            } catch {
                $volumeResult.Error = $_.Exception.Message
                Write-Warning "Failed to start $OptimizationType on volume $volumePath`: $($_.Exception.Message)"
            }
            
            $optimizationResults.VolumeResults += [PSCustomObject]$volumeResult
        }
        
        Write-Verbose "Deduplication optimization started"
        return [PSCustomObject]$optimizationResults
        
    } catch {
        Write-Error "Error starting deduplication optimization: $($_.Exception.Message)"
        return $null
    }
}

function Get-DeduplicationJobs {
    <#
    .SYNOPSIS
        Gets deduplication job status
    
    .DESCRIPTION
        This function retrieves the status of deduplication jobs
        including optimization, garbage collection, and scrubbing jobs.
    
    .PARAMETER JobId
        Specific job ID to get status for (optional)
    
    .PARAMETER VolumePath
        Volume path to get jobs for (optional)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-DeduplicationJobs
    
    .EXAMPLE
        Get-DeduplicationJobs -JobId "12345"
    
    .EXAMPLE
        Get-DeduplicationJobs -VolumePath "D:"
    #>
    [CmdletBinding()]
    param(
        [string]$JobId,
        
        [string]$VolumePath
    )
    
    try {
        Write-Verbose "Getting deduplication job status..."
        
        $jobResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            JobId = $JobId
            VolumePath = $VolumePath
            Jobs = @()
            Summary = @{}
        }
        
        # Get deduplication jobs
        $jobs = Get-DedupJob -ErrorAction SilentlyContinue
        
        if ($JobId) {
            $jobs = $jobs | Where-Object { $_.JobId -eq $JobId }
        }
        
        if ($VolumePath) {
            $jobs = $jobs | Where-Object { $_.Volume -eq $VolumePath }
        }
        
        foreach ($job in $jobs) {
            $jobInfo = @{
                JobId = $job.JobId
                Volume = $job.Volume
                Type = $job.Type
                Status = $job.Status
                Progress = $job.Progress
                StartTime = $job.StartTime
                EndTime = $job.EndTime
                Duration = if ($job.EndTime) { $job.EndTime - $job.StartTime } else { (Get-Date) - $job.StartTime }
                Priority = $job.Priority
                ErrorMessage = $job.ErrorMessage
            }
            
            $jobResults.Jobs += [PSCustomObject]$jobInfo
        }
        
        # Generate summary
        $runningJobs = ($jobResults.Jobs | Where-Object { $_.Status -eq "Running" }).Count
        $completedJobs = ($jobResults.Jobs | Where-Object { $_.Status -eq "Completed" }).Count
        $failedJobs = ($jobResults.Jobs | Where-Object { $_.Status -eq "Failed" }).Count
        
        $jobResults.Summary = @{
            TotalJobs = $jobResults.Jobs.Count
            RunningJobs = $runningJobs
            CompletedJobs = $completedJobs
            FailedJobs = $failedJobs
        }
        
        Write-Verbose "Deduplication job status retrieved successfully"
        return [PSCustomObject]$jobResults
        
    } catch {
        Write-Error "Error getting deduplication job status: $($_.Exception.Message)"
        return $null
    }
}

function Set-DeduplicationSchedule {
    <#
    .SYNOPSIS
        Sets deduplication schedule for specified volumes
    
    .DESCRIPTION
        This function configures the deduplication schedule for
        optimization, garbage collection, and scrubbing operations.
    
    .PARAMETER VolumePaths
        Array of volume paths to configure schedule for
    
    .PARAMETER ScheduleType
        Type of schedule (Optimization, GarbageCollection, Scrubbing)
    
    .PARAMETER Days
        Days of the week to run (0=Sunday, 1=Monday, etc.)
    
    .PARAMETER StartTime
        Start time for the schedule (HH:MM format)
    
    .PARAMETER Duration
        Duration in hours for the schedule
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Set-DeduplicationSchedule -VolumePaths @("D:") -ScheduleType "Optimization" -Days @(0,1,2,3,4,5,6) -StartTime "02:00"
    
    .EXAMPLE
        Set-DeduplicationSchedule -VolumePaths @("D:", "E:") -ScheduleType "GarbageCollection" -Days @(0) -StartTime "03:00" -Duration 4
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$VolumePaths,
        
        [ValidateSet("Optimization", "GarbageCollection", "Scrubbing")]
        [string]$ScheduleType,
        
        [Parameter(Mandatory = $true)]
        [int[]]$Days,
        
        [string]$StartTime = "02:00",
        
        [int]$Duration = 2
    )
    
    try {
        Write-Verbose "Setting deduplication schedule: $ScheduleType for volumes: $($VolumePaths -join ', ')"
        
        $scheduleResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            VolumePaths = $VolumePaths
            ScheduleType = $ScheduleType
            Days = $Days
            StartTime = $StartTime
            Duration = $Duration
            VolumeResults = @()
        }
        
        foreach ($volumePath in $VolumePaths) {
            Write-Verbose "Setting $ScheduleType schedule on volume: $volumePath"
            
            $volumeResult = @{
                VolumePath = $volumePath
                Success = $false
                Error = $null
            }
            
            try {
                # Set deduplication schedule
                Set-DedupSchedule -Name $ScheduleType -Volume $volumePath -Days $Days -Start $StartTime -Duration $Duration -ErrorAction Stop
                
                $volumeResult.Success = $true
                Write-Verbose "$ScheduleType schedule set successfully on volume: $volumePath"
                
            } catch {
                $volumeResult.Error = $_.Exception.Message
                Write-Warning "Failed to set $ScheduleType schedule on volume $volumePath`: $($_.Exception.Message)"
            }
            
            $scheduleResults.VolumeResults += [PSCustomObject]$volumeResult
        }
        
        Write-Verbose "Deduplication schedule configuration completed"
        return [PSCustomObject]$scheduleResults
        
    } catch {
        Write-Error "Error setting deduplication schedule: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Enable-Deduplication',
    'Disable-Deduplication',
    'Get-DeduplicationStatus',
    'Start-DeduplicationOptimization',
    'Get-DeduplicationJobs',
    'Set-DeduplicationSchedule'
)

# Module initialization
Write-Verbose "BackupStorage-Deduplication module loaded successfully. Version: $ModuleVersion"
