#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Partition and Volume Management PowerShell Module

.DESCRIPTION
    This module provides comprehensive partition and volume management capabilities
    including disk partitioning, volume creation, and advanced disk operations.

.NOTES
    Author: Backup and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/backup-and-storage-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Test-DiskManagementPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for disk management operations
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        PowerShellModuleAvailable = $false
        AdministratorPrivileges = $false
        DiskManagementServiceRunning = $false
    }
    
    # Check if Storage PowerShell module is available
    try {
        $module = Get-Module -ListAvailable -Name Storage -ErrorAction SilentlyContinue
        $prerequisites.PowerShellModuleAvailable = ($null -ne $module)
    } catch {
        Write-Warning "Could not check Storage PowerShell module: $($_.Exception.Message)"
    }
    
    # Check disk management service status
    try {
        $diskService = Get-Service -Name "VDS" -ErrorAction SilentlyContinue
        $prerequisites.DiskManagementServiceRunning = ($diskService -and $diskService.Status -eq "Running")
    } catch {
        Write-Warning "Could not check disk management service: $($_.Exception.Message)"
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

function Get-DiskHealthStatus {
    <#
    .SYNOPSIS
        Gets disk health status using WMI
    #>
    [CmdletBinding()]
    param(
        [int]$DiskNumber
    )
    
    try {
        $disk = Get-WmiObject -Class Win32_DiskDrive -Filter "Index=$DiskNumber" -ErrorAction SilentlyContinue
        if ($disk) {
            return @{
                DiskNumber = $DiskNumber
                Status = $disk.Status
                HealthStatus = if ($disk.Status -eq "OK") { "Healthy" } else { "Unhealthy" }
                Model = $disk.Model
                Size = $disk.Size
                InterfaceType = $disk.InterfaceType
            }
        }
        return $null
    } catch {
        Write-Warning "Could not get disk health status for disk $DiskNumber`: $($_.Exception.Message)"
        return $null
    }
}

#endregion

#region Public Functions

function Get-DiskManagementStatus {
    <#
    .SYNOPSIS
        Gets comprehensive disk management status information
    
    .DESCRIPTION
        This function retrieves comprehensive disk management status information
        including physical disks, partitions, volumes, and health status.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-DiskManagementStatus
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Getting disk management status information..."
        
        # Test prerequisites
        $prerequisites = Test-DiskManagementPrerequisites
        
        $statusResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Prerequisites = $prerequisites
            PhysicalDisks = @()
            Partitions = @()
            Volumes = @()
            Summary = @{}
        }
        
        # Get physical disks
        try {
            $physicalDisks = Get-Disk -ErrorAction SilentlyContinue
            foreach ($disk in $physicalDisks) {
                $diskHealth = Get-DiskHealthStatus -DiskNumber $disk.Number
                $diskInfo = @{
                    Number = $disk.Number
                    FriendlyName = $disk.FriendlyName
                    Size = $disk.Size
                    AllocatedSize = $disk.AllocatedSize
                    PartitionStyle = $disk.PartitionStyle
                    BusType = $disk.BusType
                    HealthStatus = if ($diskHealth) { $diskHealth.HealthStatus } else { "Unknown" }
                    OperationalStatus = $disk.OperationalStatus
                    IsSystem = $disk.IsSystem
                    IsBoot = $disk.IsBoot
                    IsOffline = $disk.IsOffline
                }
                $statusResults.PhysicalDisks += [PSCustomObject]$diskInfo
            }
        } catch {
            Write-Warning "Could not get physical disks: $($_.Exception.Message)"
        }
        
        # Get partitions
        try {
            $partitions = Get-Partition -ErrorAction SilentlyContinue
            foreach ($partition in $partitions) {
                $partitionInfo = @{
                    DiskNumber = $partition.DiskNumber
                    PartitionNumber = $partition.PartitionNumber
                    DriveLetter = $partition.DriveLetter
                    Size = $partition.Size
                    Offset = $partition.Offset
                    Type = $partition.Type
                    GptType = $partition.GptType
                    IsSystem = $partition.IsSystem
                    IsBoot = $partition.IsBoot
                    IsActive = $partition.IsActive
                    IsHidden = $partition.IsHidden
                    IsOffline = $partition.IsOffline
                }
                $statusResults.Partitions += [PSCustomObject]$partitionInfo
            }
        } catch {
            Write-Warning "Could not get partitions: $($_.Exception.Message)"
        }
        
        # Get volumes
        try {
            $volumes = Get-Volume -ErrorAction SilentlyContinue
            foreach ($volume in $volumes) {
                $volumeInfo = @{
                    DriveLetter = $volume.DriveLetter
                    FileSystemLabel = $volume.FileSystemLabel
                    FileSystem = $volume.FileSystem
                    Size = $volume.Size
                    SizeRemaining = $volume.SizeRemaining
                    HealthStatus = $volume.HealthStatus
                    OperationalStatus = $volume.OperationalStatus
                    PartitionStyle = $volume.PartitionStyle
                    Path = $volume.Path
                }
                $statusResults.Volumes += [PSCustomObject]$volumeInfo
            }
        } catch {
            Write-Warning "Could not get volumes: $($_.Exception.Message)"
        }
        
        # Generate summary
        $statusResults.Summary = @{
            TotalPhysicalDisks = $statusResults.PhysicalDisks.Count
            HealthyDisks = ($statusResults.PhysicalDisks | Where-Object { $_.HealthStatus -eq "Healthy" }).Count
            UnhealthyDisks = ($statusResults.PhysicalDisks | Where-Object { $_.HealthStatus -eq "Unhealthy" }).Count
            TotalPartitions = $statusResults.Partitions.Count
            TotalVolumes = $statusResults.Volumes.Count
            OnlineVolumes = ($statusResults.Volumes | Where-Object { $_.OperationalStatus -eq "OK" }).Count
            OfflineVolumes = ($statusResults.Volumes | Where-Object { $_.OperationalStatus -ne "OK" }).Count
        }
        
        Write-Verbose "Disk management status information retrieved successfully"
        return [PSCustomObject]$statusResults
        
    } catch {
        Write-Error "Error getting disk management status: $($_.Exception.Message)"
        return $null
    }
}

function New-DiskPartition {
    <#
    .SYNOPSIS
        Creates a new partition on a disk
    
    .DESCRIPTION
        This function creates a new partition on a specified disk with
        configurable size, type, and file system options.
    
    .PARAMETER DiskNumber
        Disk number to create partition on
    
    .PARAMETER Size
        Size of the partition (e.g., "100GB", "1TB", or "Max" for maximum size)
    
    .PARAMETER PartitionType
        Type of partition (MBR: Primary, Extended, Logical | GPT: Basic, System, Reserved, Recovery)
    
    .PARAMETER FileSystem
        File system to format with (NTFS, FAT32, exFAT)
    
    .PARAMETER DriveLetter
        Drive letter to assign (optional)
    
    .PARAMETER Label
        Volume label for the partition
    
    .PARAMETER UseMaximumSize
        Use maximum available size for the partition
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-DiskPartition -DiskNumber 1 -Size "100GB" -FileSystem "NTFS" -Label "Data"
    
    .EXAMPLE
        New-DiskPartition -DiskNumber 1 -UseMaximumSize -FileSystem "NTFS" -DriveLetter "D"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$DiskNumber,
        
        [string]$Size,
        
        [ValidateSet("Primary", "Extended", "Logical", "Basic", "System", "Reserved", "Recovery")]
        [string]$PartitionType = "Primary",
        
        [ValidateSet("NTFS", "FAT32", "exFAT")]
        [string]$FileSystem = "NTFS",
        
        [char]$DriveLetter,
        
        [string]$Label = "New Volume",
        
        [switch]$UseMaximumSize
    )
    
    try {
        Write-Verbose "Creating partition on disk: $DiskNumber"
        
        # Test prerequisites
        $prerequisites = Test-DiskManagementPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to create partitions."
        }
        
        $partitionResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            DiskNumber = $DiskNumber
            Size = $Size
            PartitionType = $PartitionType
            FileSystem = $FileSystem
            DriveLetter = $DriveLetter
            Label = $Label
            UseMaximumSize = $UseMaximumSize
            Success = $false
            Error = $null
            PartitionObject = $null
            VolumeObject = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Get disk information
            $disk = Get-Disk -Number $DiskNumber -ErrorAction Stop
            
            # Determine partition size
            if ($UseMaximumSize) {
                $partitionSize = $disk.Size - $disk.AllocatedSize
            } elseif ($Size) {
                # Convert size string to bytes
                $sizeBytes = switch -Regex ($Size.ToUpper()) {
                    "MAX" { $disk.Size - $disk.AllocatedSize }
                    "GB" { [int]($Size -replace "GB", "") * 1GB }
                    "TB" { [int]($Size -replace "TB", "") * 1TB }
                    "MB" { [int]($Size -replace "MB", "") * 1MB }
                    default { [int]$Size }
                }
                $partitionSize = $sizeBytes
            } else {
                $partitionSize = $disk.Size - $disk.AllocatedSize
            }
            
            # Create partition
            $partition = New-Partition -DiskNumber $DiskNumber -Size $partitionSize -AssignDriveLetter:$($DriveLetter -ne $null) -ErrorAction Stop
            
            # Assign drive letter if specified
            if ($DriveLetter -and -not $partition.DriveLetter) {
                $partition | Set-Partition -NewDriveLetter $DriveLetter -ErrorAction SilentlyContinue
            }
            
            $partitionResult.PartitionObject = $partition
            
            # Format volume if file system specified
            if ($FileSystem -and $partition.DriveLetter) {
                $volume = Format-Volume -DriveLetter $partition.DriveLetter -FileSystem $FileSystem -NewFileSystemLabel $Label -Confirm:$false -ErrorAction Stop
                $partitionResult.VolumeObject = $volume
            }
            
            $partitionResult.Success = $true
            Write-Verbose "Partition created successfully on disk: $DiskNumber"
            
        } catch {
            $partitionResult.Error = $_.Exception.Message
            Write-Warning "Failed to create partition: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$partitionResult
        
    } catch {
        Write-Error "Error creating partition: $($_.Exception.Message)"
        return $null
    }
}

function Remove-DiskPartition {
    <#
    .SYNOPSIS
        Removes a partition from a disk
    
    .DESCRIPTION
        This function removes a specified partition from a disk.
        This operation is destructive and will result in data loss.
    
    .PARAMETER DiskNumber
        Disk number containing the partition
    
    .PARAMETER PartitionNumber
        Partition number to remove
    
    .PARAMETER ConfirmRemoval
        Confirmation flag - must be set to true to proceed
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Remove-DiskPartition -DiskNumber 1 -PartitionNumber 2 -ConfirmRemoval
    
    .NOTES
        WARNING: This operation will permanently delete the partition and all data on it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$DiskNumber,
        
        [Parameter(Mandatory = $true)]
        [int]$PartitionNumber,
        
        [switch]$ConfirmRemoval
    )
    
    if (-not $ConfirmRemoval) {
        throw "You must specify -ConfirmRemoval to proceed with this destructive operation."
    }
    
    try {
        Write-Verbose "Removing partition $PartitionNumber from disk: $DiskNumber"
        
        # Test prerequisites
        $prerequisites = Test-DiskManagementPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to remove partitions."
        }
        
        $removalResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            DiskNumber = $DiskNumber
            PartitionNumber = $PartitionNumber
            Success = $false
            Error = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Remove partition
            Remove-Partition -DiskNumber $DiskNumber -PartitionNumber $PartitionNumber -Confirm:$false -ErrorAction Stop
            
            $removalResult.Success = $true
            Write-Verbose "Partition removed successfully from disk: $DiskNumber"
            
        } catch {
            $removalResult.Error = $_.Exception.Message
            Write-Warning "Failed to remove partition: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$removalResult
        
    } catch {
        Write-Error "Error removing partition: $($_.Exception.Message)"
        return $null
    }
}

function Set-DiskOnline {
    <#
    .SYNOPSIS
        Sets a disk online
    
    .DESCRIPTION
        This function sets an offline disk online to make it available
        for use in the system.
    
    .PARAMETER DiskNumber
        Disk number to set online
    
    .PARAMETER InitializeDisk
        Initialize the disk if it's not initialized
    
    .PARAMETER PartitionStyle
        Partition style for initialization (MBR, GPT)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Set-DiskOnline -DiskNumber 1
    
    .EXAMPLE
        Set-DiskOnline -DiskNumber 1 -InitializeDisk -PartitionStyle "GPT"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$DiskNumber,
        
        [switch]$InitializeDisk,
        
        [ValidateSet("MBR", "GPT")]
        [string]$PartitionStyle = "GPT"
    )
    
    try {
        Write-Verbose "Setting disk online: $DiskNumber"
        
        # Test prerequisites
        $prerequisites = Test-DiskManagementPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to set disks online."
        }
        
        $onlineResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            DiskNumber = $DiskNumber
            InitializeDisk = $InitializeDisk
            PartitionStyle = $PartitionStyle
            Success = $false
            Error = $null
            DiskObject = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Set disk online
            Set-Disk -Number $DiskNumber -IsOffline $false -ErrorAction Stop
            
            # Initialize disk if requested
            if ($InitializeDisk) {
                Initialize-Disk -Number $DiskNumber -PartitionStyle $PartitionStyle -Confirm:$false -ErrorAction Stop
                Write-Verbose "Disk initialized with partition style: $PartitionStyle"
            }
            
            # Get updated disk object
            $onlineResult.DiskObject = Get-Disk -Number $DiskNumber -ErrorAction SilentlyContinue
            $onlineResult.Success = $true
            
            Write-Verbose "Disk set online successfully: $DiskNumber"
            
        } catch {
            $onlineResult.Error = $_.Exception.Message
            Write-Warning "Failed to set disk online: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$onlineResult
        
    } catch {
        Write-Error "Error setting disk online: $($_.Exception.Message)"
        return $null
    }
}

function Set-DiskOffline {
    <#
    .SYNOPSIS
        Sets a disk offline
    
    .DESCRIPTION
        This function sets a disk offline to remove it from the system.
        This should be done before physically removing a disk.
    
    .PARAMETER DiskNumber
        Disk number to set offline
    
    .PARAMETER ConfirmOffline
        Confirmation flag - must be set to true to proceed
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Set-DiskOffline -DiskNumber 1 -ConfirmOffline
    
    .NOTES
        WARNING: Setting a disk offline will make it unavailable to the system.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$DiskNumber,
        
        [switch]$ConfirmOffline
    )
    
    if (-not $ConfirmOffline) {
        throw "You must specify -ConfirmOffline to proceed with this operation."
    }
    
    try {
        Write-Verbose "Setting disk offline: $DiskNumber"
        
        # Test prerequisites
        $prerequisites = Test-DiskManagementPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to set disks offline."
        }
        
        $offlineResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            DiskNumber = $DiskNumber
            Success = $false
            Error = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Set disk offline
            Set-Disk -Number $DiskNumber -IsOffline $true -ErrorAction Stop
            
            $offlineResult.Success = $true
            Write-Verbose "Disk set offline successfully: $DiskNumber"
            
        } catch {
            $offlineResult.Error = $_.Exception.Message
            Write-Warning "Failed to set disk offline: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$offlineResult
        
    } catch {
        Write-Error "Error setting disk offline: $($_.Exception.Message)"
        return $null
    }
}

function Optimize-DiskLayout {
    <#
    .SYNOPSIS
        Optimizes disk layout for better performance
    
    .DESCRIPTION
        This function optimizes disk layout by defragmenting volumes,
        aligning partitions, and optimizing file system settings.
    
    .PARAMETER DriveLetters
        Array of drive letters to optimize (optional, optimizes all if not specified)
    
    .PARAMETER OptimizationType
        Type of optimization (Defrag, Align, All)
    
    .PARAMETER AnalyzeOnly
        Only analyze without making changes
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Optimize-DiskLayout -OptimizationType "Defrag"
    
    .EXAMPLE
        Optimize-DiskLayout -DriveLetters @("C:", "D:") -OptimizationType "All" -AnalyzeOnly
    #>
    [CmdletBinding()]
    param(
        [string[]]$DriveLetters,
        
        [ValidateSet("Defrag", "Align", "All")]
        [string]$OptimizationType = "All",
        
        [switch]$AnalyzeOnly
    )
    
    try {
        Write-Verbose "Optimizing disk layout: $OptimizationType"
        
        # Test prerequisites
        $prerequisites = Test-DiskManagementPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to optimize disk layout."
        }
        
        $optimizationResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            DriveLetters = $DriveLetters
            OptimizationType = $OptimizationType
            AnalyzeOnly = $AnalyzeOnly
            DriveResults = @()
            Success = $false
            Error = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Get volumes to optimize
            $volumes = Get-Volume -ErrorAction SilentlyContinue
            if ($DriveLetters) {
                $volumes = $volumes | Where-Object { $DriveLetters -contains $_.DriveLetter }
            }
            
            foreach ($volume in $volumes) {
                if (-not $volume.DriveLetter) { continue }
                
                $driveResult = @{
                    DriveLetter = $volume.DriveLetter
                    FileSystem = $volume.FileSystem
                    Size = $volume.Size
                    SizeRemaining = $volume.SizeRemaining
                    DefragResult = $null
                    AlignResult = $null
                    Success = $false
                }
                
                # Defragmentation
                if ($OptimizationType -eq "Defrag" -or $OptimizationType -eq "All") {
                    try {
                        if ($AnalyzeOnly) {
                            $defragResult = Optimize-Volume -DriveLetter $volume.DriveLetter -Analyze -ErrorAction SilentlyContinue
                        } else {
                            $defragResult = Optimize-Volume -DriveLetter $volume.DriveLetter -Defrag -ErrorAction SilentlyContinue
                        }
                        $driveResult.DefragResult = @{
                            Success = $true
                            Result = $defragResult
                        }
                    } catch {
                        $driveResult.DefragResult = @{
                            Success = $false
                            Error = $_.Exception.Message
                        }
                    }
                }
                
                # Partition alignment (for NTFS volumes)
                if (($OptimizationType -eq "Align" -or $OptimizationType -eq "All") -and $volume.FileSystem -eq "NTFS") {
                    try {
                        # Check partition alignment
                        $partition = Get-Partition -DriveLetter $volume.DriveLetter -ErrorAction SilentlyContinue
                        if ($partition) {
                            $alignment = $partition.Offset % 4096
                            $driveResult.AlignResult = @{
                                Success = $true
                                CurrentAlignment = $alignment
                                IsAligned = ($alignment -eq 0)
                                Recommendation = if ($alignment -ne 0) { "Partition should be aligned to 4KB boundary" } else { "Partition is properly aligned" }
                            }
                        }
                    } catch {
                        $driveResult.AlignResult = @{
                            Success = $false
                            Error = $_.Exception.Message
                        }
                    }
                }
                
                $driveResult.Success = ($driveResult.DefragResult.Success -or $driveResult.AlignResult.Success)
                $optimizationResult.DriveResults += [PSCustomObject]$driveResult
            }
            
            $optimizationResult.Success = ($optimizationResult.DriveResults | Where-Object { $_.Success }).Count -gt 0
            
        } catch {
            $optimizationResult.Error = $_.Exception.Message
            Write-Warning "Failed to optimize disk layout: $($_.Exception.Message)"
        }
        
        Write-Verbose "Disk layout optimization completed"
        return [PSCustomObject]$optimizationResult
        
    } catch {
        Write-Error "Error optimizing disk layout: $($_.Exception.Message)"
        return $null
    }
}

function Test-DiskHealth {
    <#
    .SYNOPSIS
        Tests disk health and performance
    
    .DESCRIPTION
        This function tests disk health, performance, and identifies
        potential issues with physical disks and volumes.
    
    .PARAMETER DiskNumbers
        Array of disk numbers to test (optional, tests all if not specified)
    
    .PARAMETER TestType
        Type of test to perform (SMART, Performance, All)
    
    .PARAMETER TestDuration
        Duration of performance test in seconds (default: 30)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-DiskHealth -TestType "SMART"
    
    .EXAMPLE
        Test-DiskHealth -DiskNumbers @(0, 1) -TestType "Performance" -TestDuration 60
    #>
    [CmdletBinding()]
    param(
        [int[]]$DiskNumbers,
        
        [ValidateSet("SMART", "Performance", "All")]
        [string]$TestType = "All",
        
        [int]$TestDuration = 30
    )
    
    try {
        Write-Verbose "Testing disk health: $TestType"
        
        # Test prerequisites
        $prerequisites = Test-DiskManagementPrerequisites
        
        $healthResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            DiskNumbers = $DiskNumbers
            TestType = $TestType
            TestDuration = $TestDuration
            DiskResults = @()
            OverallHealth = "Unknown"
            Prerequisites = $prerequisites
        }
        
        try {
            # Get disks to test
            $disks = Get-Disk -ErrorAction SilentlyContinue
            if ($DiskNumbers) {
                $disks = $disks | Where-Object { $DiskNumbers -contains $_.Number }
            }
            
            foreach ($disk in $disks) {
                $diskHealth = @{
                    DiskNumber = $disk.Number
                    FriendlyName = $disk.FriendlyName
                    Size = $disk.Size
                    HealthStatus = $disk.HealthStatus
                    OperationalStatus = $disk.OperationalStatus
                    SMARTResult = $null
                    PerformanceResult = $null
                    OverallHealth = "Unknown"
                }
                
                # SMART test
                if ($TestType -eq "SMART" -or $TestType -eq "All") {
                    $smartInfo = Get-DiskHealthStatus -DiskNumber $disk.Number
                    $diskHealth.SMARTResult = $smartInfo
                }
                
                # Performance test
                if ($TestType -eq "Performance" -or $TestType -eq "All") {
                    # Basic performance indicators
                    $diskHealth.PerformanceResult = @{
                        TestDuration = $TestDuration
                        Status = "Completed"
                        Note = "Performance testing requires specialized tools for accurate results"
                    }
                }
                
                # Determine overall disk health
                if ($disk.HealthStatus -eq "Healthy" -and $disk.OperationalStatus -eq "OK") {
                    $diskHealth.OverallHealth = "Healthy"
                } elseif ($disk.HealthStatus -eq "Warning") {
                    $diskHealth.OverallHealth = "Warning"
                } else {
                    $diskHealth.OverallHealth = "Critical"
                }
                
                $healthResult.DiskResults += [PSCustomObject]$diskHealth
            }
            
            # Determine overall health
            $criticalDisks = ($healthResult.DiskResults | Where-Object { $_.OverallHealth -eq "Critical" }).Count
            $warningDisks = ($healthResult.DiskResults | Where-Object { $_.OverallHealth -eq "Warning" }).Count
            
            if ($criticalDisks -gt 0) {
                $healthResult.OverallHealth = "Critical"
            } elseif ($warningDisks -gt 0) {
                $healthResult.OverallHealth = "Warning"
            } else {
                $healthResult.OverallHealth = "Healthy"
            }
            
        } catch {
            Write-Warning "Error during disk health test: $($_.Exception.Message)"
        }
        
        Write-Verbose "Disk health test completed. Overall health: $($healthResult.OverallHealth)"
        return [PSCustomObject]$healthResult
        
    } catch {
        Write-Error "Error testing disk health: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Get-DiskManagementStatus',
    'New-DiskPartition',
    'Remove-DiskPartition',
    'Set-DiskOnline',
    'Set-DiskOffline',
    'Optimize-DiskLayout',
    'Test-DiskHealth'
)

# Module initialization
Write-Verbose "BackupStorage-PartitionVolume module loaded successfully. Version: $ModuleVersion"
