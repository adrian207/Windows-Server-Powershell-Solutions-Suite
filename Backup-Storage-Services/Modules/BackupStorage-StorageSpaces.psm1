#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Storage Spaces Management PowerShell Module

.DESCRIPTION
    This module provides comprehensive Storage Spaces management capabilities
    including storage pools, virtual disks, and volumes management.

.NOTES
    Author: Backup and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/backup-and-storage-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Test-StorageSpacesPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for Storage Spaces operations
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        StorageSpacesInstalled = $false
        PhysicalDisksAvailable = $false
        AdministratorPrivileges = $false
    }
    
    # Check if Storage Spaces feature is installed
    try {
        $feature = Get-WindowsFeature -Name "Storage-Services" -ErrorAction SilentlyContinue
        $prerequisites.StorageSpacesInstalled = ($feature -and $feature.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check Storage Spaces installation: $($_.Exception.Message)"
    }
    
    # Check for available physical disks
    try {
        $physicalDisks = Get-PhysicalDisk -CanPool $true -ErrorAction SilentlyContinue
        $prerequisites.PhysicalDisksAvailable = ($physicalDisks.Count -gt 0)
        $prerequisites.AvailableDiskCount = $physicalDisks.Count
    } catch {
        Write-Warning "Could not check physical disks: $($_.Exception.Message)"
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

function New-StoragePool {
    <#
    .SYNOPSIS
        Creates a new Storage Pool
    
    .DESCRIPTION
        This function creates a new Storage Pool using available physical disks.
        Storage pools provide a way to group physical disks for virtual disk creation.
    
    .PARAMETER FriendlyName
        Friendly name for the storage pool
    
    .PARAMETER PhysicalDisks
        Array of physical disk objects to include in the pool
    
    .PARAMETER AutoAllocate
        Automatically allocate all available disks
    
    .PARAMETER ResiliencySettingName
        Default resiliency setting (Simple, Mirror, Parity)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-StoragePool -FriendlyName "ProductionPool" -AutoAllocate
    
    .EXAMPLE
        New-StoragePool -FriendlyName "TestPool" -PhysicalDisks (Get-PhysicalDisk -CanPool $true)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FriendlyName,
        
        [array]$PhysicalDisks,
        
        [switch]$AutoAllocate,
        
        [ValidateSet("Simple", "Mirror", "Parity")]
        [string]$ResiliencySettingName = "Simple"
    )
    
    try {
        Write-Verbose "Creating Storage Pool: $FriendlyName"
        
        # Test prerequisites
        $prerequisites = Test-StorageSpacesPrerequisites
        if (-not $prerequisites.StorageSpacesInstalled) {
            throw "Storage Spaces feature is not installed. Please install it first."
        }
        
        if (-not $prerequisites.PhysicalDisksAvailable) {
            throw "No physical disks available for pooling. Please ensure disks are available and not in use."
        }
        
        # Get physical disks
        if ($AutoAllocate) {
            $PhysicalDisks = Get-PhysicalDisk -CanPool $true
        } elseif (-not $PhysicalDisks) {
            $PhysicalDisks = Get-PhysicalDisk -CanPool $true
        }
        
        if ($PhysicalDisks.Count -eq 0) {
            throw "No physical disks available for the storage pool."
        }
        
        # Create storage pool
        $storagePool = New-StoragePool -FriendlyName $FriendlyName -StorageSubSystemFriendlyName "Windows Storage*" -PhysicalDisks $PhysicalDisks
        
        # Set default resiliency setting
        Set-StoragePool -FriendlyName $FriendlyName -ResiliencySettingNameDefault $ResiliencySettingName
        
        $result = @{
            Success = $true
            FriendlyName = $FriendlyName
            StoragePool = $storagePool
            PhysicalDisks = $PhysicalDisks
            ResiliencySettingName = $ResiliencySettingName
            CreationTime = Get-Date
            Prerequisites = $prerequisites
        }
        
        Write-Verbose "Storage Pool created successfully: $FriendlyName"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error creating Storage Pool: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
            FriendlyName = $FriendlyName
            PhysicalDisks = $PhysicalDisks
        }
    }
}

function New-VirtualDisk {
    <#
    .SYNOPSIS
        Creates a new Virtual Disk in a Storage Pool
    
    .DESCRIPTION
        This function creates a new Virtual Disk within an existing Storage Pool
        with specified resiliency and size settings.
    
    .PARAMETER StoragePoolName
        Name of the storage pool to create the virtual disk in
    
    .PARAMETER FriendlyName
        Friendly name for the virtual disk
    
    .PARAMETER Size
        Size of the virtual disk (e.g., "100GB", "1TB")
    
    .PARAMETER ResiliencySettingName
        Resiliency setting (Simple, Mirror, Parity)
    
    .PARAMETER ProvisioningType
        Provisioning type (Thin, Fixed)
    
    .PARAMETER NumberOfColumns
        Number of columns for the virtual disk
    
    .PARAMETER Interleave
        Interleave size in bytes
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-VirtualDisk -StoragePoolName "ProductionPool" -FriendlyName "DataDisk" -Size "500GB" -ResiliencySettingName "Mirror"
    
    .EXAMPLE
        New-VirtualDisk -StoragePoolName "TestPool" -FriendlyName "TestDisk" -Size "100GB" -ResiliencySettingName "Simple" -ProvisioningType "Thin"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$StoragePoolName,
        
        [Parameter(Mandatory = $true)]
        [string]$FriendlyName,
        
        [Parameter(Mandatory = $true)]
        [string]$Size,
        
        [ValidateSet("Simple", "Mirror", "Parity")]
        [string]$ResiliencySettingName = "Simple",
        
        [ValidateSet("Thin", "Fixed")]
        [string]$ProvisioningType = "Thin",
        
        [int]$NumberOfColumns,
        
        [int]$Interleave
    )
    
    try {
        Write-Verbose "Creating Virtual Disk: $FriendlyName in Storage Pool: $StoragePoolName"
        
        # Get storage pool
        $storagePool = Get-StoragePool -FriendlyName $StoragePoolName -ErrorAction Stop
        
        # Get resiliency setting
        Get-ResiliencySetting -FriendlyName $ResiliencySettingName -ErrorAction Stop | Out-Null
        
        # Create virtual disk parameters
        $virtualDiskParams = @{
            FriendlyName = $FriendlyName
            StoragePool = $storagePool
            ResiliencySettingName = $ResiliencySettingName
            Size = $Size
            ProvisioningType = $ProvisioningType
        }
        
        # Add optional parameters
        if ($NumberOfColumns) {
            $virtualDiskParams.NumberOfColumns = $NumberOfColumns
        }
        
        if ($Interleave) {
            $virtualDiskParams.Interleave = $Interleave
        }
        
        # Create virtual disk
        $virtualDisk = New-VirtualDisk @virtualDiskParams
        
        $result = @{
            Success = $true
            FriendlyName = $FriendlyName
            StoragePoolName = $StoragePoolName
            VirtualDisk = $virtualDisk
            Size = $Size
            ResiliencySettingName = $ResiliencySettingName
            ProvisioningType = $ProvisioningType
            CreationTime = Get-Date
        }
        
        Write-Verbose "Virtual Disk created successfully: $FriendlyName"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error creating Virtual Disk: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
            FriendlyName = $FriendlyName
            StoragePoolName = $StoragePoolName
            Size = $Size
        }
    }
}

function New-StorageVolume {
    <#
    .SYNOPSIS
        Creates a new Storage Volume from a Virtual Disk
    
    .DESCRIPTION
        This function creates a new Storage Volume from an existing Virtual Disk
        and optionally formats and assigns a drive letter.
    
    .PARAMETER VirtualDiskName
        Name of the virtual disk to create volume from
    
    .PARAMETER FriendlyName
        Friendly name for the volume
    
    .PARAMETER DriveLetter
        Drive letter to assign (optional)
    
    .PARAMETER FileSystem
        File system to format with (NTFS, ReFS)
    
    .PARAMETER AllocationUnitSize
        Allocation unit size in bytes
    
    .PARAMETER FormatVolume
        Format the volume after creation
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-StorageVolume -VirtualDiskName "DataDisk" -FriendlyName "DataVolume" -DriveLetter "D" -FormatVolume
    
    .EXAMPLE
        New-StorageVolume -VirtualDiskName "TestDisk" -FriendlyName "TestVolume" -FileSystem "ReFS"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VirtualDiskName,
        
        [Parameter(Mandatory = $true)]
        [string]$FriendlyName,
        
        [string]$DriveLetter,
        
        [ValidateSet("NTFS", "ReFS")]
        [string]$FileSystem = "NTFS",
        
        [int]$AllocationUnitSize = 4096,
        
        [switch]$FormatVolume
    )
    
    try {
        Write-Verbose "Creating Storage Volume: $FriendlyName from Virtual Disk: $VirtualDiskName"
        
        # Get virtual disk
        $virtualDisk = Get-VirtualDisk -FriendlyName $VirtualDiskName -ErrorAction Stop
        
        # Initialize virtual disk if needed
        if ($virtualDisk.OperationalStatus -eq "Offline") {
            Initialize-Disk -VirtualDisk $virtualDisk -PartitionStyle GPT -ErrorAction Stop
        }
        
        # Create partition
        $partition = New-Partition -VirtualDisk $virtualDisk -UseMaximumSize -AssignDriveLetter:$([bool]$DriveLetter)
        
        # Assign drive letter if specified
        if ($DriveLetter -and $partition.DriveLetter -ne $DriveLetter) {
            Set-Partition -DiskNumber $partition.DiskNumber -PartitionNumber $partition.PartitionNumber -NewDriveLetter $DriveLetter
        }
        
        $volume = $null
        if ($FormatVolume) {
            # Format the volume
            $volume = Format-Volume -Partition $partition -FileSystem $FileSystem -NewFileSystemLabel $FriendlyName -AllocationUnitSize $AllocationUnitSize -Confirm:$false
        } else {
            # Get the volume without formatting
            $volume = Get-Volume -Partition $partition
        }
        
        $result = @{
            Success = $true
            FriendlyName = $FriendlyName
            VirtualDiskName = $VirtualDiskName
            Volume = $volume
            Partition = $partition
            DriveLetter = $DriveLetter
            FileSystem = $FileSystem
            AllocationUnitSize = $AllocationUnitSize
            FormatVolume = $FormatVolume
            CreationTime = Get-Date
        }
        
        Write-Verbose "Storage Volume created successfully: $FriendlyName"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error creating Storage Volume: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
            FriendlyName = $FriendlyName
            VirtualDiskName = $VirtualDiskName
            DriveLetter = $DriveLetter
        }
    }
}

function Get-StorageSpacesInfo {
    <#
    .SYNOPSIS
        Gets comprehensive Storage Spaces information
    
    .DESCRIPTION
        This function retrieves comprehensive information about Storage Spaces
        including pools, virtual disks, volumes, and physical disks.
    
    .PARAMETER StoragePoolName
        Specific storage pool name to get information for
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-StorageSpacesInfo
    
    .EXAMPLE
        Get-StorageSpacesInfo -StoragePoolName "ProductionPool"
    #>
    [CmdletBinding()]
    param(
        [string]$StoragePoolName
    )
    
    try {
        Write-Verbose "Getting Storage Spaces information..."
        
        $storageInfo = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            StoragePools = @()
            VirtualDisks = @()
            Volumes = @()
            PhysicalDisks = @()
            Summary = @{}
        }
        
        # Get storage pools
        if ($StoragePoolName) {
            $storagePools = Get-StoragePool -FriendlyName $StoragePoolName -ErrorAction SilentlyContinue
        } else {
            $storagePools = Get-StoragePool -ErrorAction SilentlyContinue
        }
        
        foreach ($pool in $storagePools) {
            $poolInfo = @{
                FriendlyName = $pool.FriendlyName
                HealthStatus = $pool.HealthStatus
                OperationalStatus = $pool.OperationalStatus
                Size = $pool.Size
                AllocatedSize = $pool.AllocatedSize
                FreeSpace = $pool.FreeSpace
                Usage = [math]::Round(($pool.AllocatedSize / $pool.Size) * 100, 2)
                ResiliencySettingNameDefault = $pool.ResiliencySettingNameDefault
                PhysicalDisks = @()
                VirtualDisks = @()
            }
            
            # Get physical disks in pool
            $poolPhysicalDisks = Get-PhysicalDisk -StoragePool $pool -ErrorAction SilentlyContinue
            foreach ($disk in $poolPhysicalDisks) {
                $poolInfo.PhysicalDisks += @{
                    FriendlyName = $disk.FriendlyName
                    Size = $disk.Size
                    HealthStatus = $disk.HealthStatus
                    OperationalStatus = $disk.OperationalStatus
                    Usage = $disk.Usage
                }
            }
            
            # Get virtual disks in pool
            $poolVirtualDisks = Get-VirtualDisk -StoragePool $pool -ErrorAction SilentlyContinue
            foreach ($vdisk in $poolVirtualDisks) {
                $poolInfo.VirtualDisks += @{
                    FriendlyName = $vdisk.FriendlyName
                    Size = $vdisk.Size
                    AllocatedSize = $vdisk.AllocatedSize
                    HealthStatus = $vdisk.HealthStatus
                    OperationalStatus = $vdisk.OperationalStatus
                    ResiliencySettingName = $vdisk.ResiliencySettingName
                    ProvisioningType = $vdisk.ProvisioningType
                }
            }
            
            $storageInfo.StoragePools += [PSCustomObject]$poolInfo
        }
        
        # Get all virtual disks
        $virtualDisks = Get-VirtualDisk -ErrorAction SilentlyContinue
        foreach ($vdisk in $virtualDisks) {
            $vdiskInfo = @{
                FriendlyName = $vdisk.FriendlyName
                Size = $vdisk.Size
                AllocatedSize = $vdisk.AllocatedSize
                HealthStatus = $vdisk.HealthStatus
                OperationalStatus = $vdisk.OperationalStatus
                ResiliencySettingName = $vdisk.ResiliencySettingName
                ProvisioningType = $vdisk.ProvisioningType
                StoragePool = $vdisk.StoragePoolFriendlyName
            }
            
            $storageInfo.VirtualDisks += [PSCustomObject]$vdiskInfo
        }
        
        # Get volumes from virtual disks
        $volumes = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq "Fixed" }
        foreach ($volume in $volumes) {
            $volumeInfo = @{
                FriendlyName = $volume.FriendlyName
                DriveLetter = $volume.DriveLetter
                Size = $volume.Size
                SizeRemaining = $volume.SizeRemaining
                FileSystem = $volume.FileSystem
                HealthStatus = $volume.HealthStatus
                OperationalStatus = $volume.OperationalStatus
            }
            
            $storageInfo.Volumes += [PSCustomObject]$volumeInfo
        }
        
        # Get physical disks
        $physicalDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
        foreach ($disk in $physicalDisks) {
            $diskInfo = @{
                FriendlyName = $disk.FriendlyName
                Size = $disk.Size
                HealthStatus = $disk.HealthStatus
                OperationalStatus = $disk.OperationalStatus
                Usage = $disk.Usage
                CanPool = $disk.CanPool
                BusType = $disk.BusType
                MediaType = $disk.MediaType
            }
            
            $storageInfo.PhysicalDisks += [PSCustomObject]$diskInfo
        }
        
        # Generate summary
        $storageInfo.Summary = @{
            TotalStoragePools = $storageInfo.StoragePools.Count
            TotalVirtualDisks = $storageInfo.VirtualDisks.Count
            TotalVolumes = $storageInfo.Volumes.Count
            TotalPhysicalDisks = $storageInfo.PhysicalDisks.Count
            AvailablePhysicalDisks = ($storageInfo.PhysicalDisks | Where-Object { $_.CanPool }).Count
            UnhealthyDisks = ($storageInfo.PhysicalDisks | Where-Object { $_.HealthStatus -ne "Healthy" }).Count
            TotalPoolSize = ($storageInfo.StoragePools | Measure-Object -Property Size -Sum).Sum
            TotalPoolAllocated = ($storageInfo.StoragePools | Measure-Object -Property AllocatedSize -Sum).Sum
        }
        
        Write-Verbose "Storage Spaces information retrieved successfully"
        return [PSCustomObject]$storageInfo
        
    } catch {
        Write-Error "Error getting Storage Spaces information: $($_.Exception.Message)"
        return $null
    }
}

function Remove-StoragePool {
    <#
    .SYNOPSIS
        Removes a Storage Pool and all associated resources
    
    .DESCRIPTION
        This function removes a Storage Pool and all associated virtual disks and volumes.
        This is a destructive operation that will result in data loss.
    
    .PARAMETER FriendlyName
        Name of the storage pool to remove
    
    .PARAMETER ConfirmRemoval
        Confirmation flag - must be set to true to proceed
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Remove-StoragePool -FriendlyName "TestPool" -ConfirmRemoval
    
    .NOTES
        WARNING: This operation will permanently delete all data in the storage pool.
        Ensure you have backed up all important data before proceeding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FriendlyName,
        
        [switch]$ConfirmRemoval
    )
    
    if (-not $ConfirmRemoval) {
        throw "You must specify -ConfirmRemoval to proceed with this destructive operation."
    }
    
    try {
        Write-Verbose "Removing Storage Pool: $FriendlyName"
        
        # Get storage pool
        $storagePool = Get-StoragePool -FriendlyName $FriendlyName -ErrorAction Stop
        
        # Get virtual disks in pool
        $virtualDisks = Get-VirtualDisk -StoragePool $storagePool -ErrorAction SilentlyContinue
        
        # Get volumes from virtual disks
        $volumes = @()
        foreach ($vdisk in $virtualDisks) {
            $vdiskVolumes = Get-Volume -ErrorAction SilentlyContinue | Where-Object { 
                $_.Path -like "*$($vdisk.FriendlyName)*" 
            }
            $volumes += $vdiskVolumes
        }
        
        # Remove volumes
        foreach ($volume in $volumes) {
            try {
                Remove-Partition -DriveLetter $volume.DriveLetter -Confirm:$false -ErrorAction Stop
                Write-Verbose "Removed volume: $($volume.FriendlyName)"
            } catch {
                Write-Warning "Failed to remove volume $($volume.FriendlyName): $($_.Exception.Message)"
            }
        }
        
        # Remove virtual disks
        foreach ($vdisk in $virtualDisks) {
            try {
                Remove-VirtualDisk -FriendlyName $vdisk.FriendlyName -Confirm:$false -ErrorAction Stop
                Write-Verbose "Removed virtual disk: $($vdisk.FriendlyName)"
            } catch {
                Write-Warning "Failed to remove virtual disk $($vdisk.FriendlyName): $($_.Exception.Message)"
            }
        }
        
        # Remove storage pool
        Remove-StoragePool -FriendlyName $FriendlyName -Confirm:$false -ErrorAction Stop
        
        $result = @{
            Success = $true
            FriendlyName = $FriendlyName
            RemovedVolumes = $volumes.Count
            RemovedVirtualDisks = $virtualDisks.Count
            RemovalTime = Get-Date
        }
        
        Write-Verbose "Storage Pool removed successfully: $FriendlyName"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error removing Storage Pool: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
            FriendlyName = $FriendlyName
        }
    }
}

function Optimize-StoragePool {
    <#
    .SYNOPSIS
        Optimizes a Storage Pool for better performance
    
    .DESCRIPTION
        This function optimizes a Storage Pool by performing maintenance tasks
        such as rebalancing and health checks.
    
    .PARAMETER FriendlyName
        Name of the storage pool to optimize
    
    .PARAMETER Rebalance
        Perform rebalancing operation
    
    .PARAMETER HealthCheck
        Perform health check on all disks
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Optimize-StoragePool -FriendlyName "ProductionPool" -Rebalance -HealthCheck
    
    .EXAMPLE
        Optimize-StoragePool -FriendlyName "TestPool" -HealthCheck
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FriendlyName,
        
        [switch]$Rebalance,
        
        [switch]$HealthCheck
    )
    
    try {
        Write-Verbose "Optimizing Storage Pool: $FriendlyName"
        
        # Get storage pool
        $storagePool = Get-StoragePool -FriendlyName $FriendlyName -ErrorAction Stop
        
        $optimizationResults = @{
            FriendlyName = $FriendlyName
            RebalanceResult = $null
            HealthCheckResult = $null
            OptimizationTime = Get-Date
        }
        
        # Perform rebalancing if requested
        if ($Rebalance) {
            try {
                $rebalanceJob = Start-StorageJob -StoragePool $storagePool -Operation "Rebalance" -ErrorAction Stop
                $optimizationResults.RebalanceResult = @{
                    Success = $true
                    JobId = $rebalanceJob.JobId
                    Status = "Started"
                }
                Write-Verbose "Rebalancing started for storage pool: $FriendlyName"
            } catch {
                $optimizationResults.RebalanceResult = @{
                    Success = $false
                    Error = $_.Exception.Message
                }
                Write-Warning "Failed to start rebalancing: $($_.Exception.Message)"
            }
        }
        
        # Perform health check if requested
        if ($HealthCheck) {
            try {
                $physicalDisks = Get-PhysicalDisk -StoragePool $storagePool -ErrorAction SilentlyContinue
                $unhealthyDisks = $physicalDisks | Where-Object { $_.HealthStatus -ne "Healthy" }
                
                $optimizationResults.HealthCheckResult = @{
                    TotalDisks = $physicalDisks.Count
                    UnhealthyDisks = $unhealthyDisks.Count
                    UnhealthyDiskNames = $unhealthyDisks.FriendlyName
                    HealthStatus = if ($unhealthyDisks.Count -eq 0) { "Healthy" } else { "Unhealthy" }
                }
                
                Write-Verbose "Health check completed for storage pool: $FriendlyName"
            } catch {
                $optimizationResults.HealthCheckResult = @{
                    Success = $false
                    Error = $_.Exception.Message
                }
                Write-Warning "Failed to perform health check: $($_.Exception.Message)"
            }
        }
        
        Write-Verbose "Storage Pool optimization completed: $FriendlyName"
        return [PSCustomObject]$optimizationResults
        
    } catch {
        Write-Error "Error optimizing Storage Pool: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
            FriendlyName = $FriendlyName
        }
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'New-StoragePool',
    'New-VirtualDisk',
    'New-StorageVolume',
    'Get-StorageSpacesInfo',
    'Remove-StoragePool',
    'Optimize-StoragePool'
)

# Module initialization
Write-Verbose "BackupStorage-StorageSpaces module loaded successfully. Version: $ModuleVersion"
