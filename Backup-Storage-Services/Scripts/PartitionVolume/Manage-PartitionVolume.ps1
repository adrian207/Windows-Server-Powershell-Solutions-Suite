#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Partition and Volume Management Script

.DESCRIPTION
    This script provides comprehensive partition and volume management including
    creation, deletion, resizing, formatting, and health monitoring.

.PARAMETER Action
    Action to perform (CreatePartition, DeletePartition, ResizePartition, FormatVolume, MonitorHealth)

.PARAMETER DiskNumber
    Disk number for operations

.PARAMETER PartitionSize
    Size of partition in GB

.PARAMETER DriveLetter
    Drive letter for volume operations

.PARAMETER FileSystem
    File system type (NTFS, ReFS, FAT32)

.PARAMETER LogPath
    Path for operation logs

.EXAMPLE
    .\Manage-PartitionVolume.ps1 -Action "CreatePartition" -DiskNumber 1 -PartitionSize 100 -DriveLetter "E"

.EXAMPLE
    .\Manage-PartitionVolume.ps1 -Action "FormatVolume" -DriveLetter "E" -FileSystem "NTFS"

.NOTES
    Author: Backup Storage PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("CreatePartition", "DeletePartition", "ResizePartition", "FormatVolume", "MonitorHealth", "ListDisks", "ListVolumes")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [int]$DiskNumber = 1,

    [Parameter(Mandatory = $false)]
    [int]$PartitionSize = 100,

    [Parameter(Mandatory = $false)]
    [string]$DriveLetter = "E",

    [Parameter(Mandatory = $false)]
    [ValidateSet("NTFS", "ReFS", "FAT32", "exFAT")]
    [string]$FileSystem = "NTFS",

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\BackupStorage\PartitionVolume",

    [Parameter(Mandatory = $false)]
    [string]$VolumeLabel,

    [Parameter(Mandatory = $false)]
    [switch]$QuickFormat,

    [Parameter(Mandatory = $false)]
    [switch]$Compress,

    [Parameter(Mandatory = $false)]
    [int]$AllocationUnitSize = 4096
)

# Script configuration
$scriptConfig = @{
    Action = $Action
    DiskNumber = $DiskNumber
    PartitionSize = $PartitionSize
    DriveLetter = $DriveLetter
    FileSystem = $FileSystem
    LogPath = $LogPath
    VolumeLabel = $VolumeLabel
    QuickFormat = $QuickFormat
    Compress = $Compress
    AllocationUnitSize = $AllocationUnitSize
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Partition and Volume Management" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Disk Number: $DiskNumber" -ForegroundColor Yellow
Write-Host "Partition Size: $PartitionSize GB" -ForegroundColor Yellow
Write-Host "Drive Letter: $DriveLetter" -ForegroundColor Yellow
Write-Host "File System: $FileSystem" -ForegroundColor Yellow
Write-Host "Volume Label: $VolumeLabel" -ForegroundColor Yellow
Write-Host "Quick Format: $QuickFormat" -ForegroundColor Yellow
Write-Host "Compress: $Compress" -ForegroundColor Yellow
Write-Host "Allocation Unit Size: $AllocationUnitSize bytes" -ForegroundColor Yellow
Write-Host "Computer: $($scriptConfig.ComputerName)" -ForegroundColor Yellow
Write-Host "Timestamp: $($scriptConfig.Timestamp)" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Import required modules
try {
    Import-Module "..\..\Modules\BackupStorage-Core.psm1" -Force
    Import-Module "..\..\Modules\BackupStorage-PartitionVolume.psm1" -Force
    Write-Host "Backup Storage modules imported successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to import Backup Storage modules: $($_.Exception.Message)"
    exit 1
}

# Create log directory
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force
}

switch ($Action) {
    "CreatePartition" {
        Write-Host "`nCreating partition on disk $DiskNumber..." -ForegroundColor Green
        
        $createResult = @{
            Success = $false
            DiskNumber = $DiskNumber
            PartitionSize = $PartitionSize
            DriveLetter = $DriveLetter
            PartitionCreated = $false
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Creating partition..." -ForegroundColor Yellow
            
            # Check if disk exists
            $disk = Get-Disk -Number $DiskNumber -ErrorAction SilentlyContinue
            if (-not $disk) {
                throw "Disk $DiskNumber not found"
            }
            
            Write-Host "Disk Information:" -ForegroundColor Cyan
            Write-Host "  Size: $([math]::Round($disk.Size / 1GB, 2)) GB" -ForegroundColor White
            Write-Host "  Partition Style: $($disk.PartitionStyle)" -ForegroundColor White
            Write-Host "  Status: $($disk.HealthStatus)" -ForegroundColor White
            
            # Create partition
            Write-Host "Creating partition with size: $PartitionSize GB" -ForegroundColor Cyan
            $partition = New-Partition -DiskNumber $DiskNumber -Size ($PartitionSize * 1GB) -AssignDriveLetter:$false
            Write-Host "✓ Partition created successfully!" -ForegroundColor Green
            
            # Assign drive letter
            if ($DriveLetter) {
                Write-Host "Assigning drive letter: $DriveLetter" -ForegroundColor Cyan
                Set-Partition -DiskNumber $DiskNumber -PartitionNumber $partition.PartitionNumber -NewDriveLetter $DriveLetter
                Write-Host "✓ Drive letter assigned!" -ForegroundColor Green
            }
            
            $createResult.PartitionCreated = $true
            $createResult.EndTime = Get-Date
            $createResult.Duration = $createResult.EndTime - $createResult.StartTime
            $createResult.Success = $true
            
            Write-Host "✓ Partition creation completed!" -ForegroundColor Green
            Write-Host "  Disk Number: $DiskNumber" -ForegroundColor Cyan
            Write-Host "  Partition Size: $PartitionSize GB" -ForegroundColor Cyan
            Write-Host "  Drive Letter: $DriveLetter" -ForegroundColor Cyan
            
        } catch {
            $createResult.Error = $_.Exception.Message
            Write-Error "Partition creation failed: $($_.Exception.Message)"
        }
        
        # Save create result
        $resultFile = Join-Path $LogPath "PartitionCreate-Disk$DiskNumber-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $createResult | ConvertTo-Json -Depth 3 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "Partition creation completed!" -ForegroundColor Green
    }
    
    "DeletePartition" {
        Write-Host "`nDeleting partition on disk $DiskNumber..." -ForegroundColor Green
        
        $deleteResult = @{
            Success = $false
            DiskNumber = $DiskNumber
            DriveLetter = $DriveLetter
            PartitionDeleted = $false
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Deleting partition..." -ForegroundColor Yellow
            
            # Find partition by drive letter
            if ($DriveLetter) {
                $partition = Get-Partition -DriveLetter $DriveLetter -ErrorAction SilentlyContinue
                if (-not $partition) {
                    throw "Partition with drive letter $DriveLetter not found"
                }
                
                Write-Host "Found partition:" -ForegroundColor Cyan
                Write-Host "  Drive Letter: $DriveLetter" -ForegroundColor White
                Write-Host "  Size: $([math]::Round($partition.Size / 1GB, 2)) GB" -ForegroundColor White
                Write-Host "  Type: $($partition.Type)" -ForegroundColor White
                
                # Delete partition
                Write-Host "Deleting partition..." -ForegroundColor Cyan
                Remove-Partition -DriveLetter $DriveLetter -Confirm:$false
                Write-Host "✓ Partition deleted successfully!" -ForegroundColor Green
            } else {
                throw "Drive letter is required for partition deletion"
            }
            
            $deleteResult.PartitionDeleted = $true
            $deleteResult.EndTime = Get-Date
            $deleteResult.Duration = $deleteResult.EndTime - $deleteResult.StartTime
            $deleteResult.Success = $true
            
        } catch {
            $deleteResult.Error = $_.Exception.Message
            Write-Error "Partition deletion failed: $($_.Exception.Message)"
        }
        
        # Save delete result
        $resultFile = Join-Path $LogPath "PartitionDelete-$DriveLetter-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $deleteResult | ConvertTo-Json -Depth 3 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "Partition deletion completed!" -ForegroundColor Green
    }
    
    "ResizePartition" {
        Write-Host "`nResizing partition on drive $DriveLetter..." -ForegroundColor Green
        
        $resizeResult = @{
            Success = $false
            DriveLetter = $DriveLetter
            NewSize = $PartitionSize
            ResizeCompleted = $false
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Resizing partition..." -ForegroundColor Yellow
            
            # Get current partition information
            $partition = Get-Partition -DriveLetter $DriveLetter -ErrorAction SilentlyContinue
            if (-not $partition) {
                throw "Partition with drive letter $DriveLetter not found"
            }
            
            $currentSize = [math]::Round($partition.Size / 1GB, 2)
            Write-Host "Current partition size: $currentSize GB" -ForegroundColor Cyan
            Write-Host "New partition size: $PartitionSize GB" -ForegroundColor Cyan
            
            # Resize partition
            Write-Host "Resizing partition..." -ForegroundColor Cyan
            Resize-Partition -DriveLetter $DriveLetter -Size ($PartitionSize * 1GB)
            Write-Host "✓ Partition resized successfully!" -ForegroundColor Green
            
            $resizeResult.ResizeCompleted = $true
            $resizeResult.EndTime = Get-Date
            $resizeResult.Duration = $resizeResult.EndTime - $resizeResult.StartTime
            $resizeResult.Success = $true
            
        } catch {
            $resizeResult.Error = $_.Exception.Message
            Write-Error "Partition resize failed: $($_.Exception.Message)"
        }
        
        # Save resize result
        $resultFile = Join-Path $LogPath "PartitionResize-$DriveLetter-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $resizeResult | ConvertTo-Json -Depth 3 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "Partition resize completed!" -ForegroundColor Green
    }
    
    "FormatVolume" {
        Write-Host "`nFormatting volume on drive $DriveLetter..." -ForegroundColor Green
        
        $formatResult = @{
            Success = $false
            DriveLetter = $DriveLetter
            FileSystem = $FileSystem
            VolumeLabel = $VolumeLabel
            QuickFormat = $QuickFormat
            Compress = $Compress
            AllocationUnitSize = $AllocationUnitSize
            FormatCompleted = $false
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Formatting volume..." -ForegroundColor Yellow
            
            # Get volume information
            $volume = Get-Volume -DriveLetter $DriveLetter -ErrorAction SilentlyContinue
            if (-not $volume) {
                throw "Volume with drive letter $DriveLetter not found"
            }
            
            Write-Host "Volume Information:" -ForegroundColor Cyan
            Write-Host "  Drive Letter: $DriveLetter" -ForegroundColor White
            Write-Host "  Current File System: $($volume.FileSystem)" -ForegroundColor White
            Write-Host "  Size: $([math]::Round($volume.Size / 1GB, 2)) GB" -ForegroundColor White
            Write-Host "  Free Space: $([math]::Round($volume.SizeRemaining / 1GB, 2)) GB" -ForegroundColor White
            
            # Format volume
            Write-Host "Formatting volume with $FileSystem file system..." -ForegroundColor Cyan
            $formatParams = @{
                DriveLetter = $DriveLetter
                FileSystem = $FileSystem
                NewFileSystemLabel = if ($VolumeLabel) { $VolumeLabel } else { "New Volume" }
                AllocationUnitSize = $AllocationUnitSize
                Confirm = $false
            }
            
            if ($QuickFormat) {
                $formatParams.Add("QuickFormat", $true)
            }
            
            if ($Compress) {
                $formatParams.Add("Compress", $true)
            }
            
            Format-Volume @formatParams
            Write-Host "✓ Volume formatted successfully!" -ForegroundColor Green
            
            $formatResult.FormatCompleted = $true
            $formatResult.EndTime = Get-Date
            $formatResult.Duration = $formatResult.EndTime - $formatResult.StartTime
            $formatResult.Success = $true
            
            Write-Host "✓ Volume formatting completed!" -ForegroundColor Green
            Write-Host "  Drive Letter: $DriveLetter" -ForegroundColor Cyan
            Write-Host "  File System: $FileSystem" -ForegroundColor Cyan
            Write-Host "  Volume Label: $($formatParams.NewFileSystemLabel)" -ForegroundColor Cyan
            Write-Host "  Quick Format: $QuickFormat" -ForegroundColor Cyan
            Write-Host "  Compress: $Compress" -ForegroundColor Cyan
            
        } catch {
            $formatResult.Error = $_.Exception.Message
            Write-Error "Volume formatting failed: $($_.Exception.Message)"
        }
        
        # Save format result
        $resultFile = Join-Path $LogPath "VolumeFormat-$DriveLetter-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $formatResult | ConvertTo-Json -Depth 3 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "Volume formatting completed!" -ForegroundColor Green
    }
    
    "MonitorHealth" {
        Write-Host "`nMonitoring partition and volume health..." -ForegroundColor Green
        
        $monitorResult = @{
            Success = $false
            HealthData = @{
                Disks = @()
                Volumes = @()
                OverallHealth = "Unknown"
                IssuesFound = @()
            }
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Collecting health information..." -ForegroundColor Yellow
            
            # Get disk health information
            Write-Host "Checking disk health..." -ForegroundColor Cyan
            $disks = Get-Disk | Select-Object Number, Size, HealthStatus, OperationalStatus, PartitionStyle
            foreach ($disk in $disks) {
                $diskInfo = @{
                    DiskNumber = $disk.Number
                    Size = [math]::Round($disk.Size / 1GB, 2)
                    HealthStatus = $disk.HealthStatus
                    OperationalStatus = $disk.OperationalStatus
                    PartitionStyle = $disk.PartitionStyle
                }
                $monitorResult.HealthData.Disks += $diskInfo
            }
            
            # Get volume health information
            Write-Host "Checking volume health..." -ForegroundColor Cyan
            $volumes = Get-Volume | Where-Object { $_.DriveLetter } | Select-Object DriveLetter, Size, SizeRemaining, HealthStatus, OperationalStatus, FileSystem
            foreach ($volume in $volumes) {
                $volumeInfo = @{
                    DriveLetter = $volume.DriveLetter
                    Size = [math]::Round($volume.Size / 1GB, 2)
                    FreeSpace = [math]::Round($volume.SizeRemaining / 1GB, 2)
                    UsedSpace = [math]::Round(($volume.Size - $volume.SizeRemaining) / 1GB, 2)
                    UsagePercent = [math]::Round((($volume.Size - $volume.SizeRemaining) / $volume.Size) * 100, 2)
                    HealthStatus = $volume.HealthStatus
                    OperationalStatus = $volume.OperationalStatus
                    FileSystem = $volume.FileSystem
                }
                $monitorResult.HealthData.Volumes += $volumeInfo
            }
            
            # Analyze health status
            $unhealthyDisks = $monitorResult.HealthData.Disks | Where-Object { $_.HealthStatus -ne "Healthy" }
            $unhealthyVolumes = $monitorResult.HealthData.Volumes | Where-Object { $_.HealthStatus -ne "Healthy" }
            $lowSpaceVolumes = $monitorResult.HealthData.Volumes | Where-Object { $_.UsagePercent -gt 90 }
            
            if ($unhealthyDisks.Count -eq 0 -and $unhealthyVolumes.Count -eq 0 -and $lowSpaceVolumes.Count -eq 0) {
                $monitorResult.HealthData.OverallHealth = "Healthy"
            } elseif ($unhealthyDisks.Count -gt 0 -or $unhealthyVolumes.Count -gt 0) {
                $monitorResult.HealthData.OverallHealth = "Critical"
            } else {
                $monitorResult.HealthData.OverallHealth = "Warning"
            }
            
            # Generate issues
            foreach ($disk in $unhealthyDisks) {
                $monitorResult.HealthData.IssuesFound += "Disk $($disk.DiskNumber): $($disk.HealthStatus)"
            }
            foreach ($volume in $unhealthyVolumes) {
                $monitorResult.HealthData.IssuesFound += "Volume $($volume.DriveLetter): $($volume.HealthStatus)"
            }
            foreach ($volume in $lowSpaceVolumes) {
                $monitorResult.HealthData.IssuesFound += "Volume $($volume.DriveLetter): Low disk space ($($volume.UsagePercent)%)"
            }
            
            $monitorResult.EndTime = Get-Date
            $monitorResult.Duration = $monitorResult.EndTime - $monitorResult.StartTime
            $monitorResult.Success = $true
            
            Write-Host "Partition and Volume Health Status:" -ForegroundColor Green
            Write-Host "  Overall Health: $($monitorResult.HealthData.OverallHealth)" -ForegroundColor Cyan
            Write-Host "  Disks Checked: $($monitorResult.HealthData.Disks.Count)" -ForegroundColor Cyan
            Write-Host "  Volumes Checked: $($monitorResult.HealthData.Volumes.Count)" -ForegroundColor Cyan
            Write-Host "  Issues Found: $($monitorResult.HealthData.IssuesFound.Count)" -ForegroundColor Cyan
            
            if ($monitorResult.HealthData.IssuesFound.Count -gt 0) {
                Write-Host "`nIssues Found:" -ForegroundColor Red
                foreach ($issue in $monitorResult.HealthData.IssuesFound) {
                    Write-Host "  • $issue" -ForegroundColor Red
                }
            }
            
        } catch {
            $monitorResult.Error = $_.Exception.Message
            Write-Error "Health monitoring failed: $($_.Exception.Message)"
        }
        
        # Save monitor result
        $resultFile = Join-Path $LogPath "PartitionVolumeHealth-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $monitorResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "Partition and volume health monitoring completed!" -ForegroundColor Green
    }
    
    "ListDisks" {
        Write-Host "`nListing all disks..." -ForegroundColor Green
        
        try {
            Write-Host "Available Disks:" -ForegroundColor Yellow
            $disks = Get-Disk | Select-Object Number, Size, HealthStatus, OperationalStatus, PartitionStyle, BusType
            
            foreach ($disk in $disks) {
                Write-Host "`nDisk $($disk.Number):" -ForegroundColor Cyan
                Write-Host "  Size: $([math]::Round($disk.Size / 1GB, 2)) GB" -ForegroundColor White
                Write-Host "  Health: $($disk.HealthStatus)" -ForegroundColor White
                Write-Host "  Status: $($disk.OperationalStatus)" -ForegroundColor White
                Write-Host "  Partition Style: $($disk.PartitionStyle)" -ForegroundColor White
                Write-Host "  Bus Type: $($disk.BusType)" -ForegroundColor White
            }
            
        } catch {
            Write-Error "Failed to list disks: $($_.Exception.Message)"
        }
        
        Write-Host "Disk listing completed!" -ForegroundColor Green
    }
    
    "ListVolumes" {
        Write-Host "`nListing all volumes..." -ForegroundColor Green
        
        try {
            Write-Host "Available Volumes:" -ForegroundColor Yellow
            $volumes = Get-Volume | Where-Object { $_.DriveLetter } | Select-Object DriveLetter, Size, SizeRemaining, HealthStatus, OperationalStatus, FileSystem, FileSystemLabel
            
            foreach ($volume in $volumes) {
                $usedSpace = [math]::Round(($volume.Size - $volume.SizeRemaining) / 1GB, 2)
                $usagePercent = [math]::Round(($usedSpace / ($volume.Size / 1GB)) * 100, 2)
                
                Write-Host "`nVolume $($volume.DriveLetter):" -ForegroundColor Cyan
                Write-Host "  Size: $([math]::Round($volume.Size / 1GB, 2)) GB" -ForegroundColor White
                Write-Host "  Used: $usedSpace GB ($usagePercent%)" -ForegroundColor White
                Write-Host "  Free: $([math]::Round($volume.SizeRemaining / 1GB, 2)) GB" -ForegroundColor White
                Write-Host "  Health: $($volume.HealthStatus)" -ForegroundColor White
                Write-Host "  Status: $($volume.OperationalStatus)" -ForegroundColor White
                Write-Host "  File System: $($volume.FileSystem)" -ForegroundColor White
                Write-Host "  Label: $($volume.FileSystemLabel)" -ForegroundColor White
            }
            
        } catch {
            Write-Error "Failed to list volumes: $($_.Exception.Message)"
        }
        
        Write-Host "Volume listing completed!" -ForegroundColor Green
    }
}

# Generate operation report
Write-Host "`nGenerating operation report..." -ForegroundColor Green

$operationReport = @{
    Action = $Action
    DiskNumber = $DiskNumber
    PartitionSize = $PartitionSize
    DriveLetter = $DriveLetter
    FileSystem = $FileSystem
    VolumeLabel = $VolumeLabel
    QuickFormat = $QuickFormat
    Compress = $Compress
    AllocationUnitSize = $AllocationUnitSize
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
    Status = "Completed"
}

$reportFile = Join-Path $LogPath "PartitionVolumeOperation-Report-$Action-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
$operationReport | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "Operation report generated: $reportFile" -ForegroundColor Green

# Final summary
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "Partition and Volume Management Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Disk Number: $DiskNumber" -ForegroundColor Yellow
Write-Host "Partition Size: $PartitionSize GB" -ForegroundColor Yellow
Write-Host "Drive Letter: $DriveLetter" -ForegroundColor Yellow
Write-Host "File System: $FileSystem" -ForegroundColor Yellow
Write-Host "Volume Label: $VolumeLabel" -ForegroundColor Yellow
Write-Host "Quick Format: $QuickFormat" -ForegroundColor Yellow
Write-Host "Compress: $Compress" -ForegroundColor Yellow
Write-Host "Allocation Unit Size: $AllocationUnitSize bytes" -ForegroundColor Yellow
Write-Host "Status: Completed" -ForegroundColor Green
Write-Host "Report: $reportFile" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

Write-Host "`n🎉 Partition and volume management completed successfully!" -ForegroundColor Green
Write-Host "The partition and volume operations have been completed." -ForegroundColor Green

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Review the operation report" -ForegroundColor White
Write-Host "2. Verify partition and volume operations" -ForegroundColor White
Write-Host "3. Monitor disk and volume health" -ForegroundColor White
Write-Host "4. Set up regular health checks" -ForegroundColor White
Write-Host "5. Document partition and volume configuration" -ForegroundColor White
Write-Host "6. Plan for future storage needs" -ForegroundColor White
