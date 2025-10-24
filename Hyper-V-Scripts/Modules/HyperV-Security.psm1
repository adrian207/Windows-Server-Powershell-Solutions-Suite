#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Hyper-V Security Management Module

.DESCRIPTION
    Security and compliance functions for Windows Hyper-V virtualization.
    Provides shielded VM configuration, BitLocker integration, Host Guardian Service
    integration, VM encryption, security baselines, and compliance reporting.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This module provides Hyper-V security capabilities including:
    - Shielded VM configuration
    - BitLocker integration
    - Host Guardian Service integration
    - VM encryption
    - Security baselines
    - Compliance reporting
    - Access control
    - Audit logging
    - Network security
    - Storage security
#>

# Module metadata
$ModuleName = "HyperV-Security"
$ModuleVersion = "1.0.0"

# Import required modules
Import-Module Hyper-V -ErrorAction Stop
Import-Module BitLocker -ErrorAction Stop

# Shielded VM Functions

function New-ShieldedVM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $true)]
        [string]$TemplateDiskPath,
        
        [Parameter(Mandatory = $false)]
        [string]$Memory = "2GB",
        
        [Parameter(Mandatory = $false)]
        [int]$ProcessorCount = 2,
        
        [Parameter(Mandatory = $false)]
        [string]$SwitchName = "Default Switch",
        
        [Parameter(Mandatory = $false)]
        [string]$Path = "C:\VMs",
        
        [Parameter(Mandatory = $false)]
        [string]$KeyProtector,
        
        [Parameter(Mandatory = $false)]
        [string]$GuardianService,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableSecureBoot,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableTPM
    )
    
    try {
        Write-Verbose "Creating shielded VM: $VMName"
        
        # Create VM
        $vm = New-VM -Name $VMName -MemoryStartupBytes $Memory -Generation 2 -Path $Path -SwitchName $SwitchName
        
        # Configure as shielded VM
        Set-VMSecurity -VM $vm -Shielded $true
        
        # Configure secure boot
        if ($EnableSecureBoot) {
            Set-VMFirmware -VM $vm -EnableSecureBoot
        }
        
        # Configure TPM
        if ($EnableTPM) {
            Set-VMSecurity -VM $vm -TpmEnabled
        }
        
        # Create shielded disk from template
        $shieldedDisk = New-VHD -Path "$Path\$VMName.vhdx" -ParentPath $TemplateDiskPath -Differencing
        Add-VMHardDiskDrive -VM $vm -Path $shieldedDisk.Path
        
        # Configure key protector if provided
        if ($KeyProtector) {
            Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
        }
        
        # Configure guardian service if provided
        if ($GuardianService) {
            Set-VMKeyProtector -VM $vm -Guardian $GuardianService
        }
        
        Write-Verbose "Shielded VM created successfully: $VMName"
        return $vm
    }
    catch {
        Write-Error "Failed to create shielded VM: $($_.Exception.Message)"
        throw
    }
}

function Set-VMShieldedConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableShieldedVM,
        
        [Parameter(Mandatory = $false)]
        [switch]$DisableShieldedVM,
        
        [Parameter(Mandatory = $false)]
        [string]$KeyProtector,
        
        [Parameter(Mandatory = $false)]
        [string]$GuardianService,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableSecureBoot,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableTPM
    )
    
    try {
        Write-Verbose "Configuring shielded VM settings for: $VMName"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        
        # Configure shielded VM
        if ($EnableShieldedVM) {
            Set-VMSecurity -VM $vm -Shielded $true
        }
        if ($DisableShieldedVM) {
            Set-VMSecurity -VM $vm -Shielded $false
        }
        
        # Configure secure boot
        if ($EnableSecureBoot) {
            Set-VMFirmware -VM $vm -EnableSecureBoot
        }
        
        # Configure TPM
        if ($EnableTPM) {
            Set-VMSecurity -VM $vm -TpmEnabled
        }
        
        # Configure key protector
        if ($KeyProtector) {
            Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
        }
        
        # Configure guardian service
        if ($GuardianService) {
            Set-VMKeyProtector -VM $vm -Guardian $GuardianService
        }
        
        Write-Verbose "Shielded VM configuration updated successfully: $VMName"
    }
    catch {
        Write-Error "Failed to configure shielded VM: $($_.Exception.Message)"
        throw
    }
}

# BitLocker Integration Functions

function Enable-VMBitLocker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("TPM", "Password", "RecoveryKey", "StartupKey")]
        [string]$ProtectorType = "TPM",
        
        [Parameter(Mandatory = $false)]
        [string]$Password,
        
        [Parameter(Mandatory = $false)]
        [string]$RecoveryKeyPath,
        
        [Parameter(Mandatory = $false)]
        [string]$StartupKeyPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$UsedSpaceOnly
    )
    
    try {
        Write-Verbose "Enabling BitLocker for VM: $VMName"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        
        # Get VM hard drives
        $hardDrives = Get-VMHardDiskDrive -VM $vm
        foreach ($hardDrive in $hardDrives) {
            $driveLetter = $hardDrive.Path.Substring(0, 1)
            
            # Enable BitLocker based on protector type
            switch ($ProtectorType) {
                "TPM" {
                    Enable-BitLocker -MountPoint $driveLetter -TpmProtector -UsedSpaceOnly:$UsedSpaceOnly
                }
                "Password" {
                    if (-not $Password) {
                        throw "Password is required for password protector"
                    }
                    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
                    Enable-BitLocker -MountPoint $driveLetter -PasswordProtector -Password $securePassword -UsedSpaceOnly:$UsedSpaceOnly
                }
                "RecoveryKey" {
                    if (-not $RecoveryKeyPath) {
                        throw "RecoveryKeyPath is required for recovery key protector"
                    }
                    Enable-BitLocker -MountPoint $driveLetter -RecoveryKeyProtector -RecoveryKeyPath $RecoveryKeyPath -UsedSpaceOnly:$UsedSpaceOnly
                }
                "StartupKey" {
                    if (-not $StartupKeyPath) {
                        throw "StartupKeyPath is required for startup key protector"
                    }
                    Enable-BitLocker -MountPoint $driveLetter -StartupKeyProtector -StartupKeyPath $StartupKeyPath -UsedSpaceOnly:$UsedSpaceOnly
                }
            }
        }
        
        Write-Verbose "BitLocker enabled successfully for VM: $VMName"
    }
    catch {
        Write-Error "Failed to enable BitLocker: $($_.Exception.Message)"
        throw
    }
}

function Get-VMBitLockerStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName
    )
    
    try {
        Write-Verbose "Getting BitLocker status for VM: $VMName"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        $hardDrives = Get-VMHardDiskDrive -VM $vm
        $bitLockerStatus = @()
        
        foreach ($hardDrive in $hardDrives) {
            $driveLetter = $hardDrive.Path.Substring(0, 1)
            $status = Get-BitLockerVolume -MountPoint $driveLetter
            $bitLockerStatus += $status
        }
        
        Write-Verbose "BitLocker status retrieved successfully for VM: $VMName"
        return $bitLockerStatus
    }
    catch {
        Write-Error "Failed to get BitLocker status: $($_.Exception.Message)"
        throw
    }
}

# Host Guardian Service Functions

function Register-VMWithHGS {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $true)]
        [string]$HGSClusterName,
        
        [Parameter(Mandatory = $false)]
        [string]$AttestationServer,
        
        [Parameter(Mandatory = $false)]
        [string]$KeyProtectionServer,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("TPM", "Admin")]
        [string]$AttestationMode = "TPM"
    )
    
    try {
        Write-Verbose "Registering VM with HGS: $VMName"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        
        # Configure HGS attestation
        if ($AttestationServer) {
            Set-VMHost -ComputerName $env:COMPUTERNAME -AttestationServer $AttestationServer
        }
        
        # Configure key protection server
        if ($KeyProtectionServer) {
            Set-VMHost -ComputerName $env:COMPUTERNAME -KeyProtectionServer $KeyProtectionServer
        }
        
        # Configure attestation mode
        Set-VMHost -ComputerName $env:COMPUTERNAME -AttestationMode $AttestationMode
        
        Write-Verbose "VM registered with HGS successfully: $VMName"
    }
    catch {
        Write-Error "Failed to register VM with HGS: $($_.Exception.Message)"
        throw
    }
}

function Test-VMHGSAttestation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME
    )
    
    try {
        Write-Verbose "Testing HGS attestation for host: $HostName"
        
        $host = Get-VMHost -ComputerName $HostName -ErrorAction Stop
        $attestationResult = Test-VMHostAttestation -VMHost $host
        
        Write-Verbose "HGS attestation test completed for host: $HostName"
        return $attestationResult
    }
    catch {
        Write-Error "Failed to test HGS attestation: $($_.Exception.Message)"
        throw
    }
}

# VM Encryption Functions

function Enable-VMEncryption {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [string]$EncryptionKey,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("AES128", "AES256")]
        [string]$EncryptionAlgorithm = "AES256",
        
        [Parameter(Mandatory = $false)]
        [switch]$EncryptMemory,
        
        [Parameter(Mandatory = $false)]
        [switch]$EncryptStorage
    )
    
    try {
        Write-Verbose "Enabling encryption for VM: $VMName"
        
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        
        # Configure VM encryption
        if ($EncryptMemory) {
            Set-VMSecurity -VM $vm -EncryptStateAndVmMigrationTraffic
        }
        
        if ($EncryptStorage) {
            $hardDrives = Get-VMHardDiskDrive -VM $vm
            foreach ($hardDrive in $hardDrives) {
                # Enable BitLocker for storage encryption
                $driveLetter = $hardDrive.Path.Substring(0, 1)
                Enable-BitLocker -MountPoint $driveLetter -TpmProtector
            }
        }
        
        Write-Verbose "VM encryption enabled successfully: $VMName"
    }
    catch {
        Write-Error "Failed to enable VM encryption: $($_.Exception.Message)"
        throw
    }
}

# Security Baseline Functions

function Set-HyperVSecurityBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Basic", "Enhanced", "High")]
        [string]$SecurityLevel = "Enhanced",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("CIS", "NIST", "SOX", "HIPAA", "PCI-DSS")]
        [string]$ComplianceStandard = "CIS",
        
        [Parameter(Mandatory = $false)]
        [string]$BaselineName,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeVMs,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeHost
    )
    
    try {
        Write-Verbose "Applying security baseline: $SecurityLevel for host: $HostName"
        
        $host = Get-VMHost -ComputerName $HostName -ErrorAction Stop
        
        # Apply host-level security settings
        if ($IncludeHost) {
            # Configure host security settings
            Set-VMHost -VMHost $host -EnableEnhancedSessionMode $true
            Set-VMHost -VMHost $host -VirtualMachinePath "C:\VMs"
            Set-VMHost -VMHost $host -VirtualHardDiskPath "C:\VHDs"
            
            # Configure firewall rules
            Enable-NetFirewallRule -DisplayGroup "Hyper-V"
            
            # Configure Windows Defender exclusions
            Add-MpPreference -ExclusionPath "C:\VMs"
            Add-MpPreference -ExclusionPath "C:\VHDs"
        }
        
        # Apply VM-level security settings
        if ($IncludeVMs) {
            $vms = Get-VM -VMHost $host
            foreach ($vm in $vms) {
                # Configure VM security settings
                Set-VMSecurity -VM $vm -TpmEnabled
                Set-VMFirmware -VM $vm -EnableSecureBoot
                
                # Configure integration services
                Enable-VMIntegrationService -VM $vm -Name "Time Synchronization"
                Enable-VMIntegrationService -VM $vm -Name "Heartbeat"
                Enable-VMIntegrationService -VM $vm -Name "Key-Value Pair Exchange"
                Enable-VMIntegrationService -VM $vm -Name "Shutdown"
                Enable-VMIntegrationService -VM $vm -Name "Volume Shadow Copy Requestor"
            }
        }
        
        Write-Verbose "Security baseline applied successfully: $SecurityLevel"
    }
    catch {
        Write-Error "Failed to apply security baseline: $($_.Exception.Message)"
        throw
    }
}

# Access Control Functions

function Set-HyperVAccessControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [string]$UserOrGroup,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("FullControl", "Read", "Write", "Execute")]
        [string]$Permission,
        
        [Parameter(Mandatory = $false)]
        [switch]$RemoveAccess
    )
    
    try {
        Write-Verbose "Configuring access control for Hyper-V"
        
        if ($VMName) {
            $vm = Get-VM -Name $VMName -ErrorAction Stop
            $aclPath = $vm.Path
        } else {
            $host = Get-VMHost -ComputerName $HostName -ErrorAction Stop
            $aclPath = "C:\VMs"
        }
        
        # Get current ACL
        $acl = Get-Acl -Path $aclPath
        
        if ($RemoveAccess) {
            # Remove access
            $acl.RemoveAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($UserOrGroup, $Permission, "ContainerInherit,ObjectInherit", "None", "Allow")))
        } else {
            # Add access
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($UserOrGroup, $Permission, "ContainerInherit,ObjectInherit", "None", "Allow")
            $acl.SetAccessRule($accessRule)
        }
        
        # Apply ACL
        Set-Acl -Path $aclPath -AclObject $acl
        
        Write-Verbose "Access control configured successfully"
    }
    catch {
        Write-Error "Failed to configure access control: $($_.Exception.Message)"
        throw
    }
}

# Audit Logging Functions

function Enable-HyperVAuditLogging {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Basic", "Enhanced", "Comprehensive")]
        [string]$AuditLevel = "Enhanced",
        
        [Parameter(Mandatory = $false)]
        [string]$LogPath = "C:\HyperVLogs",
        
        [Parameter(Mandatory = $false)]
        [int]$LogRetentionDays = 30,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeSecurityEvents,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeConfigurationChanges,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeVMOperations
    )
    
    try {
        Write-Verbose "Enabling audit logging for Hyper-V"
        
        # Create log directory
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force
        }
        
        # Configure Windows Event Log
        $eventLogs = @("Microsoft-Windows-Hyper-V-VMMS-Admin", "Microsoft-Windows-Hyper-V-VMMS-Operational")
        foreach ($eventLog in $eventLogs) {
            wevtutil sl $eventLog /ms:10485760 /rt:false /ab:true
        }
        
        # Configure PowerShell logging
        if ($AuditLevel -eq "Comprehensive") {
            Enable-PSTranscript -Path $LogPath -IncludeInvocationHeader
        }
        
        Write-Verbose "Audit logging enabled successfully"
    }
    catch {
        Write-Error "Failed to enable audit logging: $($_.Exception.Message)"
        throw
    }
}

# Network Security Functions

function Set-HyperVNetworkSecurity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [string]$SwitchName,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnablePortMirroring,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableVLAN,
        
        [Parameter(Mandatory = $false)]
        [int]$VLANID,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableMACAddressSpoofing,
        
        [Parameter(Mandatory = $false)]
        [switch]$EnableDHCPGuard
    )
    
    try {
        Write-Verbose "Configuring network security for Hyper-V"
        
        if ($SwitchName) {
            $switch = Get-VMSwitch -Name $SwitchName -ErrorAction Stop
            
            # Configure port mirroring
            if ($EnablePortMirroring) {
                Set-VMSwitch -VMSwitch $switch -EnableIov $true
            }
            
            # Configure VLAN
            if ($EnableVLAN -and $VLANID) {
                $networkAdapters = Get-VMNetworkAdapter -VMSwitch $switch
                foreach ($networkAdapter in $networkAdapters) {
                    Set-VMNetworkAdapterVlan -VMNetworkAdapter $networkAdapter -Access -VlanId $VLANID
                }
            }
        }
        
        # Configure VM network adapter security
        $vms = Get-VM -VMHost (Get-VMHost -ComputerName $HostName)
        foreach ($vm in $vms) {
            $networkAdapters = Get-VMNetworkAdapter -VM $vm
            foreach ($networkAdapter in $networkAdapters) {
                # Configure MAC address spoofing
                if ($EnableMACAddressSpoofing) {
                    Set-VMNetworkAdapter -VMNetworkAdapter $networkAdapter -MacAddressSpoofing On
                }
                
                # Configure DHCP guard
                if ($EnableDHCPGuard) {
                    Set-VMNetworkAdapter -VMNetworkAdapter $networkAdapter -DhcpGuard On
                }
            }
        }
        
        Write-Verbose "Network security configured successfully"
    }
    catch {
        Write-Error "Failed to configure network security: $($_.Exception.Message)"
        throw
    }
}

# Compliance Reporting Functions

function Get-HyperVSecurityReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$HostName = $env:COMPUTERNAME,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Basic", "Enhanced", "Comprehensive")]
        [string]$ReportType = "Enhanced",
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("HTML", "XML", "JSON")]
        [string]$Format = "HTML"
    )
    
    try {
        Write-Verbose "Generating Hyper-V security report"
        
        $host = Get-VMHost -ComputerName $HostName -ErrorAction Stop
        $report = @{
            HostName = $HostName
            ReportDate = Get-Date
            ReportType = $ReportType
            HostInfo = @{
                Name = $host.Name
                Version = $host.Version
                LogicalProcessorCount = $host.LogicalProcessorCount
                TotalMemory = $host.TotalMemory
            }
            VMs = @()
            SecuritySettings = @{}
            ComplianceStatus = @{}
        }
        
        # Get VM information
        $vms = Get-VM -VMHost $host
        foreach ($vm in $vms) {
            $vmInfo = @{
                Name = $vm.Name
                State = $vm.State
                Generation = $vm.Generation
                MemoryAssigned = $vm.MemoryAssigned
                ProcessorCount = $vm.ProcessorCount
                IsShielded = $vm.IsShielded
                HasSecureBoot = $vm.HasSecureBoot
                HasTPM = $vm.HasTPM
            }
            $report.VMs += $vmInfo
        }
        
        # Get security settings
        $report.SecuritySettings = @{
            EnhancedSessionMode = $host.EnableEnhancedSessionMode
            VirtualMachinePath = $host.VirtualMachinePath
            VirtualHardDiskPath = $host.VirtualHardDiskPath
        }
        
        # Generate compliance status
        $report.ComplianceStatus = @{
            ShieldedVMs = ($vms | Where-Object { $_.IsShielded }).Count
            SecureBootEnabled = ($vms | Where-Object { $_.HasSecureBoot }).Count
            TPMEnabled = ($vms | Where-Object { $_.HasTPM }).Count
            TotalVMs = $vms.Count
        }
        
        # Output report
        if ($OutputPath) {
            switch ($Format) {
                "HTML" {
                    $htmlReport = $report | ConvertTo-Html -Title "Hyper-V Security Report"
                    $htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8
                }
                "XML" {
                    $report | Export-Clixml -Path $OutputPath
                }
                "JSON" {
                    $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
                }
            }
        }
        
        Write-Verbose "Hyper-V security report generated successfully"
        return $report
    }
    catch {
        Write-Error "Failed to generate security report: $($_.Exception.Message)"
        throw
    }
}

# Export functions
Export-ModuleMember -Function @(
    'New-ShieldedVM',
    'Set-VMShieldedConfiguration',
    'Enable-VMBitLocker',
    'Get-VMBitLockerStatus',
    'Register-VMWithHGS',
    'Test-VMHGSAttestation',
    'Enable-VMEncryption',
    'Set-HyperVSecurityBaseline',
    'Set-HyperVAccessControl',
    'Enable-HyperVAuditLogging',
    'Set-HyperVNetworkSecurity',
    'Get-HyperVSecurityReport'
)
