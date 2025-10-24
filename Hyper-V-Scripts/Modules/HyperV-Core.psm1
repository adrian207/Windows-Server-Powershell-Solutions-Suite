#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Hyper-V Core Management Module

.DESCRIPTION
    Core functions for Windows Hyper-V virtualization management.
    Provides comprehensive VM management, live migration, checkpoint operations,
    resource allocation, and integration services management.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This module provides core Hyper-V management capabilities including:
    - VM creation and management
    - Live migration operations
    - Checkpoint management
    - Resource allocation
    - Integration services
    - PowerShell Direct operations
    - Dynamic memory management
    - Storage operations
    - Network configuration
    - Performance optimization
#>

# Module metadata
$ModuleName = "HyperV-Core"
$ModuleVersion = "1.0.0"

# Import required modules
Import-Module Hyper-V -ErrorAction Stop

# Core VM Management Functions

function New-HyperVMachine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$Memory = "2GB",
        
        [Parameter(Mandatory = $false)]
        [int]$ProcessorCount = 2,
        
        [Parameter(Mandatory = $false)]
        [string]$VHDPath,
        
        [Parameter(Mandatory = $false)]
        [string]$SwitchName = "Default Switch",
        
        [Parameter(Mandatory = $false)]
        [string]$Generation = "2",
        
        [Parameter(Mandatory = $false)]
        [string]$Path = "C:\VMs",
        
        [Parameter(Mandatory = $false)]
        [switch]$StartVM,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableDynamicMemory,
        
        [Parameter(Mandatory = $false)]
        [string]$MemoryMinimum = "512MB",
        
        [Parameter(Mandatory = $false)]
        [string]$MemoryMaximum = "4GB"
    )
    
    try {
        Write-Verbose "Creating Hyper-V machine: $Name"
        
        # Create VM
        $vm = New-VM -Name $Name -MemoryStartupBytes $Memory -Generation $Generation -Path $Path -SwitchName $SwitchName
        
        # Configure processors
        Set-VM -VM $vm -ProcessorCount $ProcessorCount
        
        # Configure dynamic memory if enabled
        if ($EnableDynamicMemory) {
            Set-VMMemory -VM $vm -DynamicMemoryEnabled $true -MinimumBytes $MemoryMinimum -MaximumBytes $MemoryMaximum
        }
        
        # Create VHD if path provided
        if ($VHDPath) {
            $vhd = New-VHD -Path $VHDPath -SizeBytes 40GB -Dynamic
            Add-VMHardDiskDrive -VM $vm -Path $vhd.Path
        }
        
        # Start VM if requested
        if ($StartVM) {
            Start-VM -VM $vm
        }
        
        Write-Verbose "Hyper-V machine created successfully: $Name"
        return $vm
    }
    catch {
        Write-Error "Failed to create Hyper-V machine: $($_.Exception.Message)"
        throw
    }
}

function Set-HyperVMachine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [string]$Memory,
        
        [Parameter(Mandatory = $false)]
        [int]$ProcessorCount,
        
        [Parameter(Mandatory = $false)]
        [string]$SwitchName,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableDynamicMemory,
        
        [Parameter(Mandatory = $false)]
        [string]$MemoryMinimum,
        
        [Parameter(Mandatory = $false)]
        [string]$MemoryMaximum,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableSecureBoot,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableTPM
    )
    
    try {
        Write-Verbose "Configuring Hyper-V machine: $VMName"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        
        # Configure memory
        if ($Memory) {
            Set-VMMemory -VM $vm -StartupBytes $Memory
        }
        
        # Configure processors
        if ($ProcessorCount) {
            Set-VM -VM $vm -ProcessorCount $ProcessorCount
        }
        
        # Configure dynamic memory
        if ($EnableDynamicMemory) {
            Set-VMMemory -VM $vm -DynamicMemoryEnabled $true
            if ($MemoryMinimum) { Set-VMMemory -VM $vm -MinimumBytes $MemoryMinimum }
            if ($MemoryMaximum) { Set-VMMemory -VM $vm -MaximumBytes $MemoryMaximum }
        }
        
        # Configure network
        if ($SwitchName) {
            $networkAdapter = Get-VMNetworkAdapter -VM $vm
            Set-VMNetworkAdapter -VMNetworkAdapter $networkAdapter -SwitchName $SwitchName
        }
        
        # Configure secure boot
        if ($EnableSecureBoot) {
            Set-VMFirmware -VM $vm -EnableSecureBoot
        }
        
        # Configure TPM
        if ($EnableTPM) {
            Set-VMSecurity -VM $vm -TpmEnabled
        }
        
        Write-Verbose "Hyper-V machine configured successfully: $VMName"
        return $vm
    }
    catch {
        Write-Error "Failed to configure Hyper-V machine: $($_.Exception.Message)"
        throw
    }
}

function Remove-HyperVMachine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [switch]$RemoveVHDs
    )
    
    try {
        Write-Verbose "Removing Hyper-V machine: $VMName"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        
        # Stop VM if running
        if ($vm.State -eq "Running") {
            Stop-VM -VM $vm -Force:$Force
        }
        
        # Remove VM
        Remove-VM -VM $vm -Force:$Force
        
        # Remove VHDs if requested
        if ($RemoveVHDs) {
            $vhdPaths = Get-VMHardDiskDrive -VM $vm | Select-Object -ExpandProperty Path
            foreach ($vhdPath in $vhdPaths) {
                Remove-Item -Path $vhdPath -Force:$Force
            }
        }
        
        Write-Verbose "Hyper-V machine removed successfully: $VMName"
    }
    catch {
        Write-Error "Failed to remove Hyper-V machine: $($_.Exception.Message)"
        throw
    }
}

# Live Migration Functions

function Move-HyperVMachine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $true)]
        [string]$DestinationHost,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Live", "Storage", "Quick")]
        [string]$MigrationType = "Live",
        
        [Parameter(Mandatory = $false)]
        [string]$DestinationPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$Compress,
        
        [Parameter(Mandatory = $false)]
        [switch]$RetainVhdCopiesOnSource
    )
    
    try {
        Write-Verbose "Migrating Hyper-V machine: $VMName to $DestinationHost"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        
        switch ($MigrationType) {
            "Live" {
                Move-VM -VM $vm -DestinationHost $DestinationHost -Compress:$Compress
            }
            "Storage" {
                Move-VM -VM $vm -DestinationHost $DestinationHost -DestinationStoragePath $DestinationPath -RetainVhdCopiesOnSource:$RetainVhdCopiesOnSource
            }
            "Quick" {
                Move-VM -VM $vm -DestinationHost $DestinationHost -Compress:$Compress
            }
        }
        
        Write-Verbose "Hyper-V machine migrated successfully: $VMName"
    }
    catch {
        Write-Error "Failed to migrate Hyper-V machine: $($_.Exception.Message)"
        throw
    }
}

function Test-HyperVMigration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $true)]
        [string]$DestinationHost,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Live", "Storage", "Quick")]
        [string]$MigrationType = "Live"
    )
    
    try {
        Write-Verbose "Testing migration compatibility: $VMName to $DestinationHost"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        
        switch ($MigrationType) {
            "Live" {
                $result = Test-VMReplication -VM $vm -ReplicaServerName $DestinationHost
            }
            "Storage" {
                $result = Test-VMReplication -VM $vm -ReplicaServerName $DestinationHost -ReplicaServerPort 80
            }
            "Quick" {
                $result = Test-VMReplication -VM $vm -ReplicaServerName $DestinationHost
            }
        }
        
        Write-Verbose "Migration compatibility test completed: $VMName"
        return $result
    }
    catch {
        Write-Error "Failed to test migration compatibility: $($_.Exception.Message)"
        throw
    }
}

# Checkpoint Management Functions

function New-HyperVCheckpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $true)]
        [string]$CheckpointName,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Standard", "Production")]
        [string]$CheckpointType = "Standard",
        
        [Parameter(Mandatory = $false)]
        [string]$Description
    )
    
    try {
        Write-Verbose "Creating checkpoint: $CheckpointName for VM: $VMName"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        
        if ($CheckpointType -eq "Production") {
            $checkpoint = Checkpoint-VM -VM $vm -SnapshotName $CheckpointName -Description $Description
        } else {
            $checkpoint = Checkpoint-VM -VM $vm -SnapshotName $CheckpointName -Description $Description
        }
        
        Write-Verbose "Checkpoint created successfully: $CheckpointName"
        return $checkpoint
    }
    catch {
        Write-Error "Failed to create checkpoint: $($_.Exception.Message)"
        throw
    }
}

function Restore-HyperVCheckpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $true)]
        [string]$CheckpointName,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    try {
        Write-Verbose "Restoring checkpoint: $CheckpointName for VM: $VMName"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        $checkpoint = Get-VMSnapshot -VM $vm -Name $CheckpointName -ErrorAction Stop
        
        Restore-VMSnapshot -VMSnapshot $checkpoint -Confirm:$(-not $Force)
        
        Write-Verbose "Checkpoint restored successfully: $CheckpointName"
    }
    catch {
        Write-Error "Failed to restore checkpoint: $($_.Exception.Message)"
        throw
    }
}

function Remove-HyperVCheckpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $true)]
        [string]$CheckpointName,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    try {
        Write-Verbose "Removing checkpoint: $CheckpointName for VM: $VMName"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        $checkpoint = Get-VMSnapshot -VM $vm -Name $CheckpointName -ErrorAction Stop
        
        Remove-VMSnapshot -VMSnapshot $checkpoint -Force:$Force
        
        Write-Verbose "Checkpoint removed successfully: $CheckpointName"
    }
    catch {
        Write-Error "Failed to remove checkpoint: $($_.Exception.Message)"
        throw
    }
}

# Resource Management Functions

function Set-HyperVResourceAllocation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [int]$CPUReservation,
        
        [Parameter(Mandatory = $false)]
        [int]$CPULimit,
        
        [Parameter(Mandatory = $false)]
        [int]$CPUShares,
        
        [Parameter(Mandatory = $false)]
        [int]$MemoryReservation,
        
        [Parameter(Mandatory = $false)]
        [int]$MemoryLimit,
        
        [Parameter(Mandatory = $false)]
        [int]$MemoryShares
    )
    
    try {
        Write-Verbose "Setting resource allocation for VM: $VMName"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        
        # Configure CPU resources
        if ($CPUReservation -or $CPULimit -or $CPUShares) {
            Set-VMProcessor -VM $vm -Reservation $CPUReservation -Limit $CPULimit -Weight $CPUShares
        }
        
        # Configure memory resources
        if ($MemoryReservation -or $MemoryLimit -or $MemoryShares) {
            Set-VMMemory -VM $vm -Reservation $MemoryReservation -Limit $MemoryLimit -Weight $MemoryShares
        }
        
        Write-Verbose "Resource allocation set successfully for VM: $VMName"
    }
    catch {
        Write-Error "Failed to set resource allocation: $($_.Exception.Message)"
        throw
    }
}

function Get-HyperVResourceUtilization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [string]$HostName,
        
        [Parameter(Mandatory = $false)]
        [int]$DurationMinutes = 60
    )
    
    try {
        Write-Verbose "Getting resource utilization"
        
        if ($VMName) {
            $vm = Get-VM -Name $VMName -ErrorAction Stop
            $metrics = Get-VM -VM $vm | Get-VMResourcePool | Get-VMResourcePoolMeter
        } elseif ($HostName) {
            $host = Get-VMHost -ComputerName $HostName -ErrorAction Stop
            $metrics = Get-VMHost -VMHost $host | Get-VMResourcePool | Get-VMResourcePoolMeter
        } else {
            $metrics = Get-VMResourcePool | Get-VMResourcePoolMeter
        }
        
        Write-Verbose "Resource utilization retrieved successfully"
        return $metrics
    }
    catch {
        Write-Error "Failed to get resource utilization: $($_.Exception.Message)"
        throw
    }
}

# Integration Services Functions

function Set-HyperVIntegrationServices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableTimeSynchronization,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableHeartbeat,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableKeyValuePairExchange,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableShutdown,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableVSS,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableGuestServiceInterface
    )
    
    try {
        Write-Verbose "Configuring integration services for VM: $VMName"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        
        # Configure integration services
        if ($EnableTimeSynchronization) {
            Enable-VMIntegrationService -VM $vm -Name "Time Synchronization"
        }
        if ($EnableHeartbeat) {
            Enable-VMIntegrationService -VM $vm -Name "Heartbeat"
        }
        if ($EnableKeyValuePairExchange) {
            Enable-VMIntegrationService -VM $vm -Name "Key-Value Pair Exchange"
        }
        if ($EnableShutdown) {
            Enable-VMIntegrationService -VM $vm -Name "Shutdown"
        }
        if ($EnableVSS) {
            Enable-VMIntegrationService -VM $vm -Name "Volume Shadow Copy Requestor"
        }
        if ($EnableGuestServiceInterface) {
            Enable-VMIntegrationService -VM $vm -Name "Guest Service Interface"
        }
        
        Write-Verbose "Integration services configured successfully for VM: $VMName"
    }
    catch {
        Write-Error "Failed to configure integration services: $($_.Exception.Message)"
        throw
    }
}

# PowerShell Direct Functions

function Invoke-HyperVPowerShellDirect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $true)]
        [string]$ScriptBlock,
        
        [Parameter(Mandatory = $false)]
        [string]$Credential,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Parameters
    )
    
    try {
        Write-Verbose "Executing PowerShell Direct on VM: $VMName"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        
        if ($Credential) {
            $result = Invoke-Command -VM $vm -ScriptBlock $ScriptBlock -Credential $Credential -ArgumentList $Parameters
        } else {
            $result = Invoke-Command -VM $vm -ScriptBlock $ScriptBlock -ArgumentList $Parameters
        }
        
        Write-Verbose "PowerShell Direct executed successfully on VM: $VMName"
        return $result
    }
    catch {
        Write-Error "Failed to execute PowerShell Direct: $($_.Exception.Message)"
        throw
    }
}

# Storage Management Functions

function New-HyperVVHD {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [string]$Size,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Fixed", "Dynamic", "Differencing")]
        [string]$Type = "Dynamic",
        
        [Parameter(Mandatory = $false)]
        [string]$ParentPath,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("VHD", "VHDX")]
        [string]$Format = "VHDX"
    )
    
    try {
        Write-Verbose "Creating VHD: $Path"
        
        switch ($Type) {
            "Fixed" {
                $vhd = New-VHD -Path $Path -SizeBytes $Size -Fixed
            }
            "Dynamic" {
                $vhd = New-VHD -Path $Path -SizeBytes $Size -Dynamic
            }
            "Differencing" {
                if (-not $ParentPath) {
                    throw "ParentPath is required for differencing VHDs"
                }
                $vhd = New-VHD -Path $Path -ParentPath $ParentPath -Differencing
            }
        }
        
        Write-Verbose "VHD created successfully: $Path"
        return $vhd
    }
    catch {
        Write-Error "Failed to create VHD: $($_.Exception.Message)"
        throw
    }
}

function Optimize-HyperVStorage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [string]$HostName,
        
        [Parameter(Mandatory = $false)]
        [switch]$CompactVHDs,
        
        [Parameter(Mandatory = $false)]
        [switch]$MergeCheckpoints,
        
        [Parameter(Mandatory = $false)]
        [switch]$DefragmentVHDs
    )
    
    try {
        Write-Verbose "Optimizing Hyper-V storage"
        
        if ($VMName) {
            $vm = Get-VM -Name $VMName -ErrorAction Stop
            $vhdPaths = Get-VMHardDiskDrive -VM $vm | Select-Object -ExpandProperty Path
        } elseif ($HostName) {
            $host = Get-VMHost -ComputerName $HostName -ErrorAction Stop
            $vhdPaths = Get-VM -VMHost $host | Get-VMHardDiskDrive | Select-Object -ExpandProperty Path
        } else {
            $vhdPaths = Get-VM | Get-VMHardDiskDrive | Select-Object -ExpandProperty Path
        }
        
        foreach ($vhdPath in $vhdPaths) {
            if ($CompactVHDs) {
                Optimize-VHD -Path $vhdPath -Mode Full
            }
            if ($DefragmentVHDs) {
                Optimize-VHD -Path $vhdPath -Mode Retrim
            }
        }
        
        if ($MergeCheckpoints) {
            $vms = if ($VMName) { @(Get-VM -Name $VMName) } elseif ($HostName) { Get-VM -VMHost (Get-VMHost -ComputerName $HostName) } else { Get-VM }
            foreach ($vm in $vms) {
                $checkpoints = Get-VMSnapshot -VM $vm
                foreach ($checkpoint in $checkpoints) {
                    Merge-VHD -Path $checkpoint.HardDrives[0].Path
                }
            }
        }
        
        Write-Verbose "Hyper-V storage optimization completed"
    }
    catch {
        Write-Error "Failed to optimize Hyper-V storage: $($_.Exception.Message)"
        throw
    }
}

# Network Management Functions

function New-HyperVSwitch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("External", "Internal", "Private")]
        [string]$Type = "Internal",
        
        [Parameter(Mandatory = $false)]
        [string]$NetAdapterName,
        
        [Parameter(Mandatory = $false)]
        [switch]$AllowManagementOS,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableSR_IOV
    )
    
    try {
        Write-Verbose "Creating Hyper-V switch: $Name"
        
        switch ($Type) {
            "External" {
                $switch = New-VMSwitch -Name $Name -NetAdapterName $NetAdapterName -AllowManagementOS:$AllowManagementOS -EnableSR_IOV:$EnableSR_IOV
            }
            "Internal" {
                $switch = New-VMSwitch -Name $Name -SwitchType Internal
            }
            "Private" {
                $switch = New-VMSwitch -Name $Name -SwitchType Private
            }
        }
        
        Write-Verbose "Hyper-V switch created successfully: $Name"
        return $switch
    }
    catch {
        Write-Error "Failed to create Hyper-V switch: $($_.Exception.Message)"
        throw
    }
}

function Set-HyperVNetworkAdapter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [string]$SwitchName,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableSR_IOV,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableVMQ,
        
        [Parameter(Mandatory = $false)]
        [int]$BandwidthReservation,
        
        [Parameter(Mandatory = $false)]
        [int]$BandwidthLimit
    )
    
    try {
        Write-Verbose "Configuring network adapter for VM: $VMName"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        $networkAdapter = Get-VMNetworkAdapter -VM $vm
        
        if ($SwitchName) {
            Set-VMNetworkAdapter -VMNetworkAdapter $networkAdapter -SwitchName $SwitchName
        }
        if ($EnableSR_IOV) {
            Set-VMNetworkAdapter -VMNetworkAdapter $networkAdapter -IovWeight 1
        }
        if ($EnableVMQ) {
            Set-VMNetworkAdapter -VMNetworkAdapter $networkAdapter -VmqWeight 1
        }
        if ($BandwidthReservation) {
            Set-VMNetworkAdapter -VMNetworkAdapter $networkAdapter -MinimumBandwidthAbsolute $BandwidthReservation
        }
        if ($BandwidthLimit) {
            Set-VMNetworkAdapter -VMNetworkAdapter $networkAdapter -MaximumBandwidth $BandwidthLimit
        }
        
        Write-Verbose "Network adapter configured successfully for VM: $VMName"
    }
    catch {
        Write-Error "Failed to configure network adapter: $($_.Exception.Message)"
        throw
    }
}

# Export functions
Export-ModuleMember -Function @(
    'New-HyperVMachine',
    'Set-HyperVMachine',
    'Remove-HyperVMachine',
    'Move-HyperVMachine',
    'Test-HyperVMigration',
    'New-HyperVCheckpoint',
    'Restore-HyperVCheckpoint',
    'Remove-HyperVCheckpoint',
    'Set-HyperVResourceAllocation',
    'Get-HyperVResourceUtilization',
    'Set-HyperVIntegrationServices',
    'Invoke-HyperVPowerShellDirect',
    'New-HyperVVHD',
    'Optimize-HyperVStorage',
    'New-HyperVSwitch',
    'Set-HyperVNetworkAdapter'
)
