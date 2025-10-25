#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Storage Management Script

.DESCRIPTION
    This script provides comprehensive storage management capabilities including
    disk management, storage pools, volumes, deduplication, and storage tiering.

.PARAMETER Action
    The action to perform (CreatePool, CreateVolume, ManageDeduplication, Monitor, Report, Optimize)

.PARAMETER PoolName
    Name of the storage pool

.PARAMETER VolumeName
    Name of the volume

.PARAMETER VolumeSize
    Size of the volume (e.g., "1TB", "500GB")

.PARAMETER ResiliencySetting
    Resiliency setting (Simple, Mirror, Parity)

.PARAMETER PhysicalDisks
    Array of physical disk objects or friendly names

.PARAMETER DriveLetter
    Drive letter for the volume

.PARAMETER FileSystem
    File system type (NTFS, ReFS)

.PARAMETER EnableDeduplication
    Enable deduplication on the volume

.PARAMETER EnableTiering
    Enable storage tiering

.PARAMETER OutputPath
    Path to save reports

.PARAMETER IncludePerformance
    Include performance data in reports

.EXAMPLE
    .\Manage-Storage.ps1 -Action CreatePool -PoolName "DataPool" -PhysicalDisks (Get-PhysicalDisk | Where-Object { $_.CanPool -eq $true })

.EXAMPLE
    .\Manage-Storage.ps1 -Action CreateVolume -PoolName "DataPool" -VolumeName "DataVolume" -VolumeSize "1TB" -ResiliencySetting "Mirror" -DriveLetter "D"

.EXAMPLE
    .\Manage-Storage.ps1 -Action ManageDeduplication -DriveLetter "D" -EnableDeduplication

.EXAMPLE
    .\Manage-Storage.ps1 -Action Monitor -OutputPath "C:\Reports\Storage-Monitor.html"

.NOTES
    Author: File and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("CreatePool", "CreateVolume", "ManageDeduplication", "Monitor", "Report", "Optimize")]
    [string]$Action,
    
    [string]$PoolName,
    
    [string]$VolumeName,
    
    [string]$VolumeSize,
    
    [ValidateSet("Simple", "Mirror", "Parity")]
    [string]$ResiliencySetting = "Simple",
    
    [object[]]$PhysicalDisks,
    
    [string]$DriveLetter,
    
    [ValidateSet("NTFS", "ReFS")]
    [string]$FileSystem = "NTFS",
    
    [switch]$EnableDeduplication,
    
    [switch]$EnableTiering,
    
    [string]$OutputPath,
    
    [switch]$IncludePerformance
)

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "FileStorage-Core.psm1") -Force
    Import-Module Storage -ErrorAction Stop
    Import-Module Deduplication -ErrorAction SilentlyContinue
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Script variables
$script:StorageLog = @()
$script:StartTime = Get-Date

function Write-StorageLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:StorageLog += $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function New-StoragePoolConfiguration {
    param(
        [string]$PoolName,
        [object[]]$PhysicalDisks
    )
    
    Write-StorageLog "Creating storage pool: $PoolName" "INFO"
    
    try {
        # Check if pool already exists
        $existingPool = Get-StoragePool -FriendlyName $PoolName -ErrorAction SilentlyContinue
        if ($existingPool) {
            Write-StorageLog "Storage pool already exists: $PoolName" "WARNING"
            return $existingPool
        }
        
        # Validate physical disks
        if (-not $PhysicalDisks -or $PhysicalDisks.Count -eq 0) {
            $PhysicalDisks = Get-PhysicalDisk | Where-Object { $_.CanPool -eq $true }
        }
        
        if ($PhysicalDisks.Count -eq 0) {
            throw "No suitable physical disks found for storage pool creation"
        }
        
        Write-StorageLog "Using $($PhysicalDisks.Count) physical disks for pool creation" "INFO"
        
        # Create storage pool
        New-StoragePool -FriendlyName $PoolName -StorageSubSystemFriendlyName "Windows Storage*" -PhysicalDisks $PhysicalDisks
        
        Write-StorageLog "Storage pool created successfully: $PoolName" "SUCCESS"
        return Get-StoragePool -FriendlyName $PoolName
        
    } catch {
        Write-StorageLog "Failed to create storage pool: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function New-StorageVolumeConfiguration {
    param(
        [string]$PoolName,
        [string]$VolumeName,
        [string]$VolumeSize,
        [string]$ResiliencySetting,
        [string]$DriveLetter,
        [string]$FileSystem
    )
    
    Write-StorageLog "Creating storage volume: $VolumeName" "INFO"
    
    try {
        # Check if volume already exists
        $existingVolume = Get-VirtualDisk -FriendlyName $VolumeName -ErrorAction SilentlyContinue
        if ($existingVolume) {
            Write-StorageLog "Storage volume already exists: $VolumeName" "WARNING"
            return $existingVolume
        }
        
        # Get storage pool
        Get-StoragePool -FriendlyName $PoolName -ErrorAction Stop | Out-Null
        
        # Create virtual disk
        $virtualDisk = New-VirtualDisk -StoragePoolFriendlyName $PoolName -FriendlyName $VolumeName -Size $VolumeSize -ResiliencySettingName $ResiliencySetting
        
        Write-StorageLog "Virtual disk created: $VolumeName" "SUCCESS"
        
        # Initialize and format the disk
        $disk = $virtualDisk | Get-Disk
        $disk | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter $DriveLetter -UseMaximumSize | Format-Volume -FileSystem $FileSystem -NewFileSystemLabel $VolumeName -Confirm:$false
        
        Write-StorageLog "Volume formatted and assigned drive letter: $DriveLetter" "SUCCESS"
        
        return $virtualDisk
        
    } catch {
        Write-StorageLog "Failed to create storage volume: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Set-DeduplicationConfiguration {
    param(
        [string]$DriveLetter,
        [switch]$EnableDeduplication
    )
    
    Write-StorageLog "Configuring deduplication for drive: $DriveLetter" "INFO"
    
    try {
        # Check if deduplication feature is installed
        $dedupFeature = Get-WindowsFeature -Name FS-Deduplication
        if ($dedupFeature.InstallState -ne 'Installed') {
            Write-StorageLog "Installing deduplication feature..." "INFO"
            Install-WindowsFeature -Name FS-Deduplication -IncludeManagementTools
        }
        
        if ($EnableDeduplication) {
            # Enable deduplication
            Enable-DedupVolume -Volume $DriveLetter -DataAccessEnabled
            
            # Set deduplication settings
            Set-DedupVolume -Volume $DriveLetter -MinimumFileAgeDays 3 -MinimumFileSizeKB 32
            
            Write-StorageLog "Deduplication enabled for drive: $DriveLetter" "SUCCESS"
        } else {
            # Disable deduplication
            Disable-DedupVolume -Volume $DriveLetter
            
            Write-StorageLog "Deduplication disabled for drive: $DriveLetter" "SUCCESS"
        }
        
    } catch {
        Write-StorageLog "Failed to configure deduplication: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-StorageMonitoringData {
    param([switch]$IncludePerformance)
    
    Write-StorageLog "Gathering storage monitoring data..." "INFO"
    
    try {
        $monitoringData = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            PhysicalDisks = @()
            StoragePools = @()
            VirtualDisks = @()
            Volumes = @()
            Performance = @{}
        }
        
        # Get physical disks
        $disks = Get-PhysicalDisk
        foreach ($disk in $disks) {
            $diskInfo = @{
                FriendlyName = $disk.FriendlyName
                Size = $disk.Size
                OperationalStatus = $disk.OperationalStatus
                HealthStatus = $disk.HealthStatus
                BusType = $disk.BusType
                MediaType = $disk.MediaType
                CanPool = $disk.CanPool
            }
            $monitoringData.PhysicalDisks += $diskInfo
        }
        
        # Get storage pools
        $pools = Get-StoragePool -ErrorAction SilentlyContinue
        foreach ($pool in $pools) {
            $poolInfo = @{
                FriendlyName = $pool.FriendlyName
                Size = $pool.Size
                AllocatedSize = $pool.AllocatedSize
                OperationalStatus = $pool.OperationalStatus
                HealthStatus = $pool.HealthStatus
                PhysicalDisks = (Get-PhysicalDisk -StoragePool $pool).Count
            }
            $monitoringData.StoragePools += $poolInfo
        }
        
        # Get virtual disks
        $virtualDisks = Get-VirtualDisk -ErrorAction SilentlyContinue
        foreach ($vdisk in $virtualDisks) {
            $vdiskInfo = @{
                FriendlyName = $vdisk.FriendlyName
                Size = $vdisk.Size
                AllocatedSize = $vdisk.AllocatedSize
                OperationalStatus = $vdisk.OperationalStatus
                HealthStatus = $vdisk.HealthStatus
                ResiliencySettingName = $vdisk.ResiliencySettingName
                StoragePool = $vdisk.StoragePoolFriendlyName
            }
            $monitoringData.VirtualDisks += $vdiskInfo
        }
        
        # Get volumes
        $volumes = Get-Volume
        foreach ($volume in $volumes) {
            $volumeInfo = @{
                DriveLetter = $volume.DriveLetter
                FileSystemLabel = $volume.FileSystemLabel
                Size = $volume.Size
                SizeRemaining = $volume.SizeRemaining
                HealthStatus = $volume.HealthStatus
                FileSystem = $volume.FileSystem
                DeduplicationEnabled = $false
            }
            
            # Check deduplication status
            try {
                $dedupStatus = Get-DedupVolume -Volume $volume.DriveLetter -ErrorAction SilentlyContinue
                if ($dedupStatus) {
                    $volumeInfo.DeduplicationEnabled = $true
                    $volumeInfo.DeduplicationSavings = $dedupStatus.SavedSpace
                }
            } catch {
                # Deduplication not available or not enabled
            }
            
            $monitoringData.Volumes += $volumeInfo
        }
        
        # Get performance data if requested
        if ($IncludePerformance) {
            $performanceCounters = @(
                "\PhysicalDisk(_Total)\Disk Reads/sec",
                "\PhysicalDisk(_Total)\Disk Writes/sec",
                "\PhysicalDisk(_Total)\Avg. Disk Queue Length",
                "\PhysicalDisk(_Total)\% Disk Time"
            )
            
            foreach ($counter in $performanceCounters) {
                try {
                    $perfData = Get-Counter -Counter $counter -SampleInterval 1 -MaxSamples 1 -ErrorAction Stop
                    $monitoringData.Performance[$counter] = $perfData.CounterSamples[0].CookedValue
                } catch {
                    $monitoringData.Performance[$counter] = "Not Available"
                }
            }
        }
        
        return [PSCustomObject]$monitoringData
        
    } catch {
        Write-StorageLog "Error gathering storage monitoring data: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function New-StorageReport {
    param(
        [object]$MonitoringData,
        [string]$OutputPath
    )
    
    Write-StorageLog "Generating storage report..." "INFO"
    
    try {
        if (-not $OutputPath) {
            $OutputPath = Join-Path $scriptPath "Storage-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        }
        
        $report = @{
            Title = "Storage Management Report"
            Generated = Get-Date
            ComputerName = $env:COMPUTERNAME
            MonitoringData = $MonitoringData
            Summary = @{
                TotalDisks = $MonitoringData.PhysicalDisks.Count
                TotalPools = $MonitoringData.StoragePools.Count
                TotalVolumes = $MonitoringData.Volumes.Count
                TotalCapacity = ($MonitoringData.PhysicalDisks | Measure-Object -Property Size -Sum).Sum
                UsedCapacity = ($MonitoringData.Volumes | Measure-Object -Property Size -Sum).Sum
                AvailableCapacity = ($MonitoringData.Volumes | Measure-Object -Property SizeRemaining -Sum).Sum
            }
        }
        
        # Generate HTML report
        $htmlReport = $report | ConvertTo-Html -Title "Storage Management Report" -Head @"
<style>
body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
.container { background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
h1 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
h2 { color: #007acc; margin-top: 30px; }
h3 { color: #666; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; font-weight: bold; }
.status-healthy { color: #28a745; font-weight: bold; }
.status-warning { color: #ffc107; font-weight: bold; }
.status-error { color: #dc3545; font-weight: bold; }
</style>
"@
        
        $htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8
        
        Write-StorageLog "Storage report saved to: $OutputPath" "SUCCESS"
        return $OutputPath
        
    } catch {
        Write-StorageLog "Error generating storage report: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Optimize-StorageConfiguration {
    Write-StorageLog "Optimizing storage configuration..." "INFO"
    
    try {
        $optimizationResults = @{
            OptimizationsApplied = @()
            Recommendations = @()
            Issues = @()
        }
        
        # Check for offline disks
        $offlineDisks = Get-PhysicalDisk | Where-Object { $_.OperationalStatus -ne 'Online' }
        if ($offlineDisks) {
            $optimizationResults.Issues += "Offline disks detected: $($offlineDisks.FriendlyName -join ', ')"
            $optimizationResults.Recommendations += "Bring offline disks online or replace failed disks"
        }
        
        # Check for unhealthy storage pools
        $unhealthyPools = Get-StoragePool -ErrorAction SilentlyContinue | Where-Object { $_.HealthStatus -ne 'Healthy' }
        if ($unhealthyPools) {
            $optimizationResults.Issues += "Unhealthy storage pools detected: $($unhealthyPools.FriendlyName -join ', ')"
            $optimizationResults.Recommendations += "Check storage pool health and consider rebuilding"
        }
        
        # Check for low disk space
        $lowSpaceVolumes = Get-Volume | Where-Object { $_.SizeRemaining -lt ($_.Size * 0.1) }
        if ($lowSpaceVolumes) {
            $optimizationResults.Issues += "Low disk space detected on volumes: $($lowSpaceVolumes.DriveLetter -join ', ')"
            $optimizationResults.Recommendations += "Free up disk space or expand volumes"
        }
        
        # Check for volumes without deduplication that could benefit
        $largeVolumes = Get-Volume | Where-Object { $_.Size -gt 100GB -and $_.DriveLetter }
        foreach ($volume in $largeVolumes) {
            try {
                $dedupStatus = Get-DedupVolume -Volume $volume.DriveLetter -ErrorAction SilentlyContinue
                if (-not $dedupStatus) {
                    $optimizationResults.Recommendations += "Consider enabling deduplication on volume $($volume.DriveLetter)"
                }
            } catch {
                # Deduplication not available
            }
        }
        
        # Check for unused storage pools
        $unusedPools = Get-StoragePool -ErrorAction SilentlyContinue | Where-Object { $null -eq (Get-VirtualDisk -StoragePool $_) }
        if ($unusedPools) {
            $optimizationResults.Recommendations += "Consider removing unused storage pools: $($unusedPools.FriendlyName -join ', ')"
        }
        
        Write-StorageLog "Storage optimization analysis completed" "SUCCESS"
        
        return [PSCustomObject]$optimizationResults
        
    } catch {
        Write-StorageLog "Error during storage optimization: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Save-StorageLog {
    $logPath = Join-Path $scriptPath "Storage-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    try {
        $script:StorageLog | Out-File -FilePath $logPath -Encoding UTF8
        Write-StorageLog "Storage log saved to: $logPath" "INFO"
    } catch {
        Write-Warning "Failed to save storage log: $($_.Exception.Message)"
    }
}

# Main storage management process
try {
    Write-StorageLog "Starting storage management..." "INFO"
    Write-StorageLog "Action: $Action" "INFO"
    
    switch ($Action) {
        "CreatePool" {
            if (-not $PoolName) {
                throw "PoolName parameter is required for CreatePool action"
            }
            
            $pool = New-StoragePoolConfiguration -PoolName $PoolName -PhysicalDisks $PhysicalDisks
            Write-Host "`nStorage pool created successfully: $PoolName" -ForegroundColor Green
        }
        
        "CreateVolume" {
            if (-not $PoolName -or -not $VolumeName -or -not $VolumeSize -or -not $DriveLetter) {
                throw "PoolName, VolumeName, VolumeSize, and DriveLetter parameters are required for CreateVolume action"
            }
            
            $volume = New-StorageVolumeConfiguration -PoolName $PoolName -VolumeName $VolumeName -VolumeSize $VolumeSize -ResiliencySetting $ResiliencySetting -DriveLetter $DriveLetter -FileSystem $FileSystem
            Write-Host "`nStorage volume created successfully: $VolumeName" -ForegroundColor Green
        }
        
        "ManageDeduplication" {
            if (-not $DriveLetter) {
                throw "DriveLetter parameter is required for ManageDeduplication action"
            }
            
            Set-DeduplicationConfiguration -DriveLetter $DriveLetter -EnableDeduplication:$EnableDeduplication
            Write-Host "`nDeduplication configuration completed for drive: $DriveLetter" -ForegroundColor Green
        }
        
        "Monitor" {
            $monitoringData = Get-StorageMonitoringData -IncludePerformance:$IncludePerformance
            
            Write-Host "`n=== Storage Monitoring Results ===" -ForegroundColor Cyan
            Write-Host "Physical Disks: $($monitoringData.PhysicalDisks.Count)" -ForegroundColor White
            Write-Host "Storage Pools: $($monitoringData.StoragePools.Count)" -ForegroundColor White
            Write-Host "Virtual Disks: $($monitoringData.VirtualDisks.Count)" -ForegroundColor White
            Write-Host "Volumes: $($monitoringData.Volumes.Count)" -ForegroundColor White
            
            if ($OutputPath) {
                $reportPath = New-StorageReport -MonitoringData $monitoringData -OutputPath $OutputPath
                Write-Host "`nStorage report generated: $reportPath" -ForegroundColor Green
            }
        }
        
        "Report" {
            $monitoringData = Get-StorageMonitoringData -IncludePerformance:$IncludePerformance
            $reportPath = New-StorageReport -MonitoringData $monitoringData -OutputPath $OutputPath
            
            if ($reportPath) {
                Write-Host "`n=== Storage Report Generated ===" -ForegroundColor Cyan
                Write-Host "Report Path: $reportPath" -ForegroundColor White
                Write-Host "Report Type: HTML" -ForegroundColor White
            }
        }
        
        "Optimize" {
            $optimizationResults = Optimize-StorageConfiguration
            
            Write-Host "`n=== Storage Optimization Results ===" -ForegroundColor Cyan
            Write-Host "Issues Found: $($optimizationResults.Issues.Count)" -ForegroundColor White
            Write-Host "Recommendations: $($optimizationResults.Recommendations.Count)" -ForegroundColor White
            
            if ($optimizationResults.Issues.Count -gt 0) {
                Write-Host "`nIssues:" -ForegroundColor Yellow
                $optimizationResults.Issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
            }
            
            if ($optimizationResults.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                $optimizationResults.Recommendations | ForEach-Object { Write-Host "  - $_" -ForegroundColor Green }
            }
        }
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-StorageLog "Storage management completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== Storage Management Summary ===" -ForegroundColor Cyan
    Write-Host "Action: $Action" -ForegroundColor White
    Write-Host "Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    
    # Save storage log
    Save-StorageLog
    
    Write-Host "`nStorage management completed successfully!" -ForegroundColor Green
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-StorageLog "Storage management failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save storage log
    Save-StorageLog
    
    Write-Host "`nStorage management failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the storage log for details." -ForegroundColor Yellow
    
    exit 1
}
