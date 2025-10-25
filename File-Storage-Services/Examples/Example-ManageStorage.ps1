#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Storage Management Example Script

.DESCRIPTION
    This example script demonstrates how to manage Windows Storage including
    storage pools, virtual disks, volumes, and deduplication.

.EXAMPLE
    .\Example-ManageStorage.ps1

.NOTES
    Author: File and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "FileStorage-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "FileStorage-Management.psm1") -Force
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

Write-Host "=== Storage Management Example ===" -ForegroundColor Cyan
Write-Host "This example demonstrates storage pool and volume management" -ForegroundColor White

try {
    # Step 1: Get available physical disks
    Write-Host "`nStep 1: Checking available physical disks..." -ForegroundColor Yellow
    $physicalDisks = Get-PhysicalDisk | Where-Object { $_.CanPool -eq $true }
    
    if ($physicalDisks.Count -eq 0) {
        Write-Host "No suitable physical disks found for storage pool creation" -ForegroundColor Red
        Write-Host "This example requires at least one physical disk that can be pooled" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "Found $($physicalDisks.Count) physical disks suitable for pooling" -ForegroundColor Green
    foreach ($disk in $physicalDisks) {
        Write-Host "  - $($disk.FriendlyName): $([math]::Round($disk.Size / 1GB, 2)) GB" -ForegroundColor White
    }
    
    # Step 2: Create storage pool
    Write-Host "`nStep 2: Creating storage pool..." -ForegroundColor Yellow
    $poolName = "ExamplePool"
    
    try {
        $pool = New-StoragePool -FriendlyName $poolName -StorageSubSystemFriendlyName "Windows Storage*" -PhysicalDisks $physicalDisks
        Write-Host "Storage pool '$poolName' created successfully" -ForegroundColor Green
    } catch {
        Write-Host "Storage pool '$poolName' may already exist or creation failed" -ForegroundColor Yellow
        $pool = Get-StoragePool -FriendlyName $poolName -ErrorAction SilentlyContinue
        if (-not $pool) {
            Write-Host "Could not create or find storage pool" -ForegroundColor Red
            exit 1
        }
    }
    
    # Step 3: Create virtual disk
    Write-Host "`nStep 3: Creating virtual disk..." -ForegroundColor Yellow
    $virtualDiskName = "ExampleVirtualDisk"
    $virtualDiskSize = "10GB"
    $resiliencySetting = "Simple"
    
    try {
        $virtualDisk = New-VirtualDisk -StoragePoolFriendlyName $poolName -FriendlyName $virtualDiskName -Size $virtualDiskSize -ResiliencySettingName $resiliencySetting
        Write-Host "Virtual disk '$virtualDiskName' created successfully" -ForegroundColor Green
    } catch {
        Write-Host "Virtual disk '$virtualDiskName' may already exist or creation failed" -ForegroundColor Yellow
        $virtualDisk = Get-VirtualDisk -FriendlyName $virtualDiskName -ErrorAction SilentlyContinue
        if (-not $virtualDisk) {
            Write-Host "Could not create or find virtual disk" -ForegroundColor Red
            exit 1
        }
    }
    
    # Step 4: Initialize and format the disk
    Write-Host "`nStep 4: Initializing and formatting the disk..." -ForegroundColor Yellow
    $disk = $virtualDisk | Get-Disk
    $driveLetter = "E"
    
    if ($disk.PartitionStyle -eq "RAW") {
        $disk | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter $driveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel $virtualDiskName -Confirm:$false
        Write-Host "Disk initialized and formatted with drive letter $driveLetter" -ForegroundColor Green
    } else {
        Write-Host "Disk already initialized" -ForegroundColor Yellow
    }
    
    # Step 5: Enable deduplication (if available)
    Write-Host "`nStep 5: Checking deduplication availability..." -ForegroundColor Yellow
    $dedupFeature = Get-WindowsFeature -Name FS-Deduplication
    if ($dedupFeature.InstallState -eq 'Installed') {
        try {
            Enable-DedupVolume -Volume $driveLetter -DataAccessEnabled
            Write-Host "Deduplication enabled on drive $driveLetter" -ForegroundColor Green
        } catch {
            Write-Host "Could not enable deduplication: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "Deduplication feature not installed" -ForegroundColor Yellow
    }
    
    # Step 6: Create a test share on the new volume
    Write-Host "`nStep 6: Creating test share on new volume..." -ForegroundColor Yellow
    $testSharePath = "$driveLetter`:\TestShare"
    $testShareName = "TestShare"
    
    try {
        New-FileShare -ShareName $testShareName -Path $testSharePath -Description "Test Share on Storage Pool" -FullAccess @("Administrators") -ReadAccess @("Users")
        Write-Host "Test share '$testShareName' created successfully" -ForegroundColor Green
    } catch {
        Write-Host "Could not create test share: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Step 7: Get storage information
    Write-Host "`nStep 7: Getting storage information..." -ForegroundColor Yellow
    $storageInfo = Get-StorageInformation
    
    # Display summary
    Write-Host "`n=== Storage Management Summary ===" -ForegroundColor Cyan
    Write-Host "Storage Pool: $poolName" -ForegroundColor White
    Write-Host "Virtual Disk: $virtualDiskName" -ForegroundColor White
    Write-Host "Drive Letter: $driveLetter" -ForegroundColor White
    Write-Host "Resiliency Setting: $resiliencySetting" -ForegroundColor White
    Write-Host "Test Share: $testShareName" -ForegroundColor White
    
    if ($storageInfo) {
        Write-Host "`nStorage Information:" -ForegroundColor Yellow
        Write-Host "  Total Disks: $($storageInfo.PhysicalDisks.Count)" -ForegroundColor White
        Write-Host "  Total Volumes: $($storageInfo.Volumes.Count)" -ForegroundColor White
        Write-Host "  Total Capacity: $([math]::Round($storageInfo.TotalCapacity / 1GB, 2)) GB" -ForegroundColor White
        Write-Host "  Available Capacity: $([math]::Round($storageInfo.AvailableCapacity / 1GB, 2)) GB" -ForegroundColor White
    }
    
    Write-Host "`nStorage management example completed successfully!" -ForegroundColor Green
    
} catch {
    Write-Host "`nStorage management example failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
