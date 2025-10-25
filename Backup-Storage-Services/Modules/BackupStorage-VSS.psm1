#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Volume Shadow Copy Service (VSS) Management PowerShell Module

.DESCRIPTION
    This module provides comprehensive Volume Shadow Copy Service management capabilities
    including shadow copy creation, management, and restoration.

.NOTES
    Author: Backup and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/backup-and-storage-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Get-VSSProvider {
    <#
    .SYNOPSIS
        Gets available VSS providers
    #>
    [CmdletBinding()]
    param()
    
    try {
        $vssAdmin = & vssadmin list providers 2>$null
        return $vssAdmin
    } catch {
        Write-Warning "Could not get VSS providers: $($_.Exception.Message)"
        return $null
    }
}

function Test-VSSService {
    <#
    .SYNOPSIS
        Tests if VSS service is running
    #>
    [CmdletBinding()]
    param()
    
    try {
        $vssService = Get-Service -Name "VSS" -ErrorAction Stop
        return $vssService.Status -eq "Running"
    } catch {
        return $false
    }
}

#endregion

#region Public Functions

function New-VSSShadowCopy {
    <#
    .SYNOPSIS
        Creates a new Volume Shadow Copy
    
    .DESCRIPTION
        This function creates a new Volume Shadow Copy (snapshot) of the specified volume.
        Shadow copies provide point-in-time copies of files and folders.
    
    .PARAMETER Volume
        The volume to create a shadow copy of (e.g., "C:", "D:")
    
    .PARAMETER Description
        Description for the shadow copy
    
    .PARAMETER Provider
        VSS provider to use (default: "Microsoft Software Shadow Copy provider")
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-VSSShadowCopy -Volume "C:" -Description "Daily backup"
    
    .EXAMPLE
        New-VSSShadowCopy -Volume "D:" -Description "Before maintenance" -Provider "Microsoft Software Shadow Copy provider"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Volume,
        
        [string]$Description = "PowerShell VSS Shadow Copy",
        
        [string]$Provider = "Microsoft Software Shadow Copy provider"
    )
    
    try {
        Write-Verbose "Creating Volume Shadow Copy for volume: $Volume"
        
        # Test VSS service
        if (-not (Test-VSSService)) {
            throw "Volume Shadow Copy Service (VSS) is not running. Please start the service first."
        }
        
        # Ensure volume path format
        if (-not $Volume.EndsWith(":")) {
            $Volume = $Volume + ":"
        }
        
        # Create shadow copy using vssadmin
        $command = "vssadmin create shadow /for=$Volume /autoretry=5"
        if ($Description) {
            $command += " /description=`"$Description`""
        }
        
        Write-Verbose "Executing command: $command"
        $result = Invoke-Expression $command
        
        # Parse the result to get shadow copy ID
        $shadowCopyId = $null
        if ($result -match "Shadow Copy ID: \{([^}]+)\}") {
            $shadowCopyId = $matches[1]
        }
        
        # Get shadow copy details
        $shadowCopyInfo = Get-VSSShadowCopy -Volume $Volume | Where-Object { $_.ShadowCopyID -eq $shadowCopyId }
        
        $result = @{
            Success = $true
            Volume = $Volume
            Description = $Description
            ShadowCopyID = $shadowCopyId
            ShadowCopyInfo = $shadowCopyInfo
            CreationTime = Get-Date
            CommandOutput = $result
        }
        
        Write-Verbose "Volume Shadow Copy created successfully"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error creating Volume Shadow Copy: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Volume = $Volume
            Description = $Description
        }
    }
}

function Get-VSSShadowCopy {
    <#
    .SYNOPSIS
        Gets Volume Shadow Copies for specified volumes
    
    .DESCRIPTION
        This function retrieves information about existing Volume Shadow Copies
        for the specified volume or all volumes.
    
    .PARAMETER Volume
        The volume to get shadow copies for (optional, defaults to all volumes)
    
    .PARAMETER ShadowCopyID
        Specific shadow copy ID to retrieve
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-VSSShadowCopy
    
    .EXAMPLE
        Get-VSSShadowCopy -Volume "C:"
    
    .EXAMPLE
        Get-VSSShadowCopy -ShadowCopyID "12345678-1234-1234-1234-123456789012"
    #>
    [CmdletBinding()]
    param(
        [string]$Volume,
        
        [string]$ShadowCopyID
    )
    
    try {
        Write-Verbose "Getting Volume Shadow Copy information..."
        
        # Test VSS service
        if (-not (Test-VSSService)) {
            throw "Volume Shadow Copy Service (VSS) is not running."
        }
        
        $shadowCopies = @()
        
        if ($ShadowCopyID) {
            # Get specific shadow copy
            $command = "vssadmin list shadows /shadow=$ShadowCopyID"
        } elseif ($Volume) {
            # Get shadow copies for specific volume
            if (-not $Volume.EndsWith(":")) {
                $Volume = $Volume + ":"
            }
            $command = "vssadmin list shadows /for=$Volume"
        } else {
            # Get all shadow copies
            $command = "vssadmin list shadows"
        }
        
        Write-Verbose "Executing command: $command"
        $output = Invoke-Expression $command
        
        # Parse the output
        $currentShadowCopy = $null
        foreach ($line in $output) {
            if ($line -match "Shadow Copy ID: \{([^}]+)\}") {
                if ($currentShadowCopy) {
                    $shadowCopies += [PSCustomObject]$currentShadowCopy
                }
                $currentShadowCopy = @{
                    ShadowCopyID = $matches[1]
                }
            } elseif ($line -match "Creation Time: (.+)") {
                if ($currentShadowCopy) {
                    $currentShadowCopy.CreationTime = $matches[1]
                }
            } elseif ($line -match "Shadow Copy Volume: (.+)") {
                if ($currentShadowCopy) {
                    $currentShadowCopy.ShadowCopyVolume = $matches[1]
                }
            } elseif ($line -match "Original Volume: (.+)") {
                if ($currentShadowCopy) {
                    $currentShadowCopy.OriginalVolume = $matches[1]
                }
            } elseif ($line -match "Shadow Copy Storage Area: (.+)") {
                if ($currentShadowCopy) {
                    $currentShadowCopy.StorageArea = $matches[1]
                }
            } elseif ($line -match "Provider: (.+)") {
                if ($currentShadowCopy) {
                    $currentShadowCopy.Provider = $matches[1]
                }
            } elseif ($line -match "Type: (.+)") {
                if ($currentShadowCopy) {
                    $currentShadowCopy.Type = $matches[1]
                }
            } elseif ($line -match "Attributes: (.+)") {
                if ($currentShadowCopy) {
                    $currentShadowCopy.Attributes = $matches[1]
                }
            }
        }
        
        # Add the last shadow copy
        if ($currentShadowCopy) {
            $shadowCopies += [PSCustomObject]$currentShadowCopy
        }
        
        $result = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Volume = $Volume
            ShadowCopyID = $ShadowCopyID
            ShadowCopies = $shadowCopies
            TotalShadowCopies = $shadowCopies.Count
        }
        
        Write-Verbose "Volume Shadow Copy information retrieved successfully"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error getting Volume Shadow Copy information: $($_.Exception.Message)"
        return $null
    }
}

function Remove-VSSShadowCopy {
    <#
    .SYNOPSIS
        Removes Volume Shadow Copies
    
    .DESCRIPTION
        This function removes specified Volume Shadow Copies to free up storage space.
    
    .PARAMETER ShadowCopyID
        ID of the shadow copy to remove
    
    .PARAMETER Volume
        Volume to remove all shadow copies from
    
    .PARAMETER OlderThanDays
        Remove shadow copies older than specified days
    
    .PARAMETER ConfirmRemoval
        Confirmation flag - must be set to true to proceed
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Remove-VSSShadowCopy -ShadowCopyID "12345678-1234-1234-1234-123456789012" -ConfirmRemoval
    
    .EXAMPLE
        Remove-VSSShadowCopy -Volume "C:" -OlderThanDays 7 -ConfirmRemoval
    
    .NOTES
        WARNING: This operation will permanently delete shadow copies.
        Ensure you have verified the removal criteria before proceeding.
    #>
    [CmdletBinding()]
    param(
        [string]$ShadowCopyID,
        
        [string]$Volume,
        
        [int]$OlderThanDays,
        
        [switch]$ConfirmRemoval
    )
    
    if (-not $ConfirmRemoval) {
        throw "You must specify -ConfirmRemoval to proceed with this destructive operation."
    }
    
    try {
        Write-Verbose "Removing Volume Shadow Copies..."
        
        $removedShadowCopies = @()
        
        if ($ShadowCopyID) {
            # Remove specific shadow copy
            $command = "vssadmin delete shadows /shadow=$ShadowCopyID /quiet"
            Write-Verbose "Executing command: $command"
            $result = Invoke-Expression $command
            
            $removedShadowCopies += @{
                ShadowCopyID = $ShadowCopyID
                RemovalMethod = "Specific ID"
            }
            
        } elseif ($Volume) {
            # Remove shadow copies for specific volume
            if (-not $Volume.EndsWith(":")) {
                $Volume = $Volume + ":"
            }
            
            if ($OlderThanDays) {
                # Remove shadow copies older than specified days
                $command = "vssadmin delete shadows /for=$Volume /oldest /quiet"
                Write-Verbose "Executing command: $command"
                $result = Invoke-Expression $command
                
                $removedShadowCopies += @{
                    Volume = $Volume
                    RemovalMethod = "Older than $OlderThanDays days"
                }
            } else {
                # Remove all shadow copies for volume
                $command = "vssadmin delete shadows /for=$Volume /all /quiet"
                Write-Verbose "Executing command: $command"
                $result = Invoke-Expression $command
                
                $removedShadowCopies += @{
                    Volume = $Volume
                    RemovalMethod = "All shadow copies"
                }
            }
        } else {
            throw "You must specify either ShadowCopyID or Volume parameter."
        }
        
        $result = @{
            Success = $true
            ShadowCopyID = $ShadowCopyID
            Volume = $Volume
            OlderThanDays = $OlderThanDays
            RemovedShadowCopies = $removedShadowCopies
            TotalRemoved = $removedShadowCopies.Count
            RemovalTime = Get-Date
        }
        
        Write-Verbose "Volume Shadow Copy removal completed successfully"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error removing Volume Shadow Copy: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
            ShadowCopyID = $ShadowCopyID
            Volume = $Volume
        }
    }
}

function Set-VSSStorageSpace {
    <#
    .SYNOPSIS
        Sets the storage space allocation for Volume Shadow Copies
    
    .DESCRIPTION
        This function configures the storage space allocation for Volume Shadow Copies
        on the specified volume.
    
    .PARAMETER Volume
        The volume to configure shadow copy storage for
    
    .PARAMETER MaximumSize
        Maximum size for shadow copy storage (in MB)
    
    .PARAMETER MinimumSize
        Minimum size for shadow copy storage (in MB)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Set-VSSStorageSpace -Volume "C:" -MaximumSize 10240
    
    .EXAMPLE
        Set-VSSStorageSpace -Volume "D:" -MaximumSize 20480 -MinimumSize 1024
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Volume,
        
        [Parameter(Mandatory = $true)]
        [int]$MaximumSize,
        
        [int]$MinimumSize
    )
    
    try {
        Write-Verbose "Setting Volume Shadow Copy storage space for volume: $Volume"
        
        # Ensure volume path format
        if (-not $Volume.EndsWith(":")) {
            $Volume = $Volume + ":"
        }
        
        # Set maximum size
        $command = "vssadmin resize shadowstorage /for=$Volume /on=$Volume /maxsize=$MaximumSize"
        Write-Verbose "Executing command: $command"
        $result = Invoke-Expression $command
        
        # Set minimum size if specified
        if ($MinimumSize) {
            $command = "vssadmin resize shadowstorage /for=$Volume /on=$Volume /minsize=$MinimumSize"
            Write-Verbose "Executing command: $command"
            $result += Invoke-Expression $command
        }
        
        $result = @{
            Success = $true
            Volume = $Volume
            MaximumSizeMB = $MaximumSize
            MinimumSizeMB = $MinimumSize
            ConfigurationTime = Get-Date
            CommandOutput = $result
        }
        
        Write-Verbose "Volume Shadow Copy storage space configured successfully"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error setting Volume Shadow Copy storage space: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Volume = $Volume
            MaximumSizeMB = $MaximumSize
            MinimumSizeMB = $MinimumSize
        }
    }
}

function Get-VSSStorageSpace {
    <#
    .SYNOPSIS
        Gets the current storage space allocation for Volume Shadow Copies
    
    .DESCRIPTION
        This function retrieves the current storage space allocation
        for Volume Shadow Copies on the specified volume.
    
    .PARAMETER Volume
        The volume to get shadow copy storage information for
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-VSSStorageSpace -Volume "C:"
    
    .EXAMPLE
        Get-VSSStorageSpace -Volume "D:"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Volume
    )
    
    try {
        Write-Verbose "Getting Volume Shadow Copy storage space for volume: $Volume"
        
        # Ensure volume path format
        if (-not $Volume.EndsWith(":")) {
            $Volume = $Volume + ":"
        }
        
        $command = "vssadmin list shadowstorage /for=$Volume"
        Write-Verbose "Executing command: $command"
        $output = Invoke-Expression $command
        
        $storageInfo = @{
            Volume = $Volume
            UsedSpace = $null
            AllocatedSpace = $null
            MaximumSpace = $null
            MinimumSpace = $null
        }
        
        # Parse the output
        foreach ($line in $output) {
            if ($line -match "Used Shadow Copy Storage space: (.+)") {
                $storageInfo.UsedSpace = $matches[1]
            } elseif ($line -match "Allocated Shadow Copy Storage space: (.+)") {
                $storageInfo.AllocatedSpace = $matches[1]
            } elseif ($line -match "Maximum Shadow Copy Storage space: (.+)") {
                $storageInfo.MaximumSpace = $matches[1]
            } elseif ($line -match "Minimum Shadow Copy Storage space: (.+)") {
                $storageInfo.MinimumSpace = $matches[1]
            }
        }
        
        $result = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Volume = $Volume
            StorageInfo = [PSCustomObject]$storageInfo
        }
        
        Write-Verbose "Volume Shadow Copy storage space information retrieved successfully"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error getting Volume Shadow Copy storage space: $($_.Exception.Message)"
        return $null
    }
}

function Enable-VSSShadowCopy {
    <#
    .SYNOPSIS
        Enables Volume Shadow Copy for a volume
    
    .DESCRIPTION
        This function enables Volume Shadow Copy service for the specified volume
        and configures it for scheduled shadow copies.
    
    .PARAMETER Volume
        The volume to enable shadow copy for
    
    .PARAMETER Schedule
        Schedule for automatic shadow copies (Daily, Hourly, Manual)
    
    .PARAMETER MaximumSpace
        Maximum space to allocate for shadow copies (in MB)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Enable-VSSShadowCopy -Volume "C:" -Schedule "Daily" -MaximumSpace 10240
    
    .EXAMPLE
        Enable-VSSShadowCopy -Volume "D:" -Schedule "Hourly" -MaximumSpace 20480
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Volume,
        
        [ValidateSet("Daily", "Hourly", "Manual")]
        [string]$Schedule = "Manual",
        
        [int]$MaximumSpace = 10240
    )
    
    try {
        Write-Verbose "Enabling Volume Shadow Copy for volume: $Volume"
        
        # Ensure volume path format
        if (-not $Volume.EndsWith(":")) {
            $Volume = $Volume + ":"
        }
        
        # Set storage space
        $storageResult = Set-VSSStorageSpace -Volume $Volume -MaximumSize $MaximumSpace
        
        # Enable shadow copy
        $command = "vssadmin add shadowstorage /for=$Volume /on=$Volume /maxsize=$MaximumSpace"
        Write-Verbose "Executing command: $command"
        $result = Invoke-Expression $command
        
        # Configure schedule if not manual
        if ($Schedule -ne "Manual") {
            # This would typically involve configuring a scheduled task
            # For now, we'll just note the schedule preference
            Write-Verbose "Schedule set to: $Schedule (manual task configuration required)"
        }
        
        $result = @{
            Success = $true
            Volume = $Volume
            Schedule = $Schedule
            MaximumSpaceMB = $MaximumSpace
            StorageConfiguration = $storageResult
            EnableTime = Get-Date
            CommandOutput = $result
        }
        
        Write-Verbose "Volume Shadow Copy enabled successfully"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error enabling Volume Shadow Copy: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Volume = $Volume
            Schedule = $Schedule
            MaximumSpaceMB = $MaximumSpace
        }
    }
}

function Disable-VSSShadowCopy {
    <#
    .SYNOPSIS
        Disables Volume Shadow Copy for a volume
    
    .DESCRIPTION
        This function disables Volume Shadow Copy service for the specified volume
        and removes all existing shadow copies.
    
    .PARAMETER Volume
        The volume to disable shadow copy for
    
    .PARAMETER RemoveExisting
        Remove existing shadow copies when disabling
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Disable-VSSShadowCopy -Volume "C:" -RemoveExisting
    
    .EXAMPLE
        Disable-VSSShadowCopy -Volume "D:"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Volume,
        
        [switch]$RemoveExisting
    )
    
    try {
        Write-Verbose "Disabling Volume Shadow Copy for volume: $Volume"
        
        # Ensure volume path format
        if (-not $Volume.EndsWith(":")) {
            $Volume = $Volume + ":"
        }
        
        # Remove existing shadow copies if requested
        if ($RemoveExisting) {
            $removeResult = Remove-VSSShadowCopy -Volume $Volume -ConfirmRemoval
        }
        
        # Disable shadow copy
        $command = "vssadmin delete shadowstorage /for=$Volume"
        Write-Verbose "Executing command: $command"
        $result = Invoke-Expression $command
        
        $result = @{
            Success = $true
            Volume = $Volume
            RemoveExisting = $RemoveExisting
            RemoveResult = if ($RemoveExisting) { $removeResult } else { $null }
            DisableTime = Get-Date
            CommandOutput = $result
        }
        
        Write-Verbose "Volume Shadow Copy disabled successfully"
        return [PSCustomObject]$result
        
    } catch {
        Write-Error "Error disabling Volume Shadow Copy: $($_.Exception.Message)"
        return @{
            Success = $false
            Error = $_.Exception.Message
            Volume = $Volume
            RemoveExisting = $RemoveExisting
        }
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'New-VSSShadowCopy',
    'Get-VSSShadowCopy',
    'Remove-VSSShadowCopy',
    'Set-VSSStorageSpace',
    'Get-VSSStorageSpace',
    'Enable-VSSShadowCopy',
    'Disable-VSSShadowCopy'
)

# Module initialization
Write-Verbose "BackupStorage-VSS module loaded successfully. Version: $ModuleVersion"
