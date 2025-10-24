#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Hyper-V Examples Script

.DESCRIPTION
    Comprehensive examples script demonstrating all 35 Hyper-V enterprise scenarios.
    Provides practical examples for server virtualization, VDI, clustering, live migration,
    replica, shielded VMs, nested virtualization, and all advanced scenarios.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive examples for all 35 Hyper-V enterprise scenarios.
    It demonstrates practical implementations for server virtualization, VDI, clustering,
    live migration, replica, shielded VMs, nested virtualization, and all advanced scenarios.
#>

# Import required modules
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $modulePath "..\Modules"

Import-Module "$modulesPath\HyperV-Core.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\HyperV-Security.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\HyperV-Monitoring.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\HyperV-Troubleshooting.psm1" -Force -ErrorAction Stop

# Logging function
function Write-ExampleLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Error" { Write-Host $logMessage -ForegroundColor Red }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
        "Info" { Write-Host $logMessage -ForegroundColor Cyan }
        default { Write-Host $logMessage -ForegroundColor White }
    }
}

# Error handling
$ErrorActionPreference = "Stop"

try {
    Write-ExampleLog "Starting Hyper-V examples demonstration" "Info"
    
    # Define all 35 scenarios with examples
    $scenarioExamples = @{
        1 = @{
            Title = "Server Virtualization (Core Scenario)"
            Description = "Consolidate multiple workloads on a single physical server"
            Code = "New-HyperVMachine -Name 'Web-Server' -Memory '2GB' -ProcessorCount 2 -VHDPath 'C:\VHDs\Web-Server.vhdx' -SwitchName 'Default Switch' -Path 'C:\VMs'"
        }
        2 = @{
            Title = "Test and Development Environments"
            Description = "Sandbox new builds, OS versions, or software releases"
            Code = "New-HyperVMachine -Name 'Test-VM' -Memory '1GB' -ProcessorCount 1 -Path 'C:\VMs'`nNew-HyperVCheckpoint -VMName 'Test-VM' -CheckpointName 'Base-Image' -CheckpointType 'Standard'"
        }
        3 = @{
            Title = "Virtual Desktop Infrastructure (VDI)"
            Description = "Host user desktops as virtual machines on a Hyper-V cluster"
            Code = "New-HyperVMachine -Name 'VDI-Pool-01' -Memory '4GB' -ProcessorCount 2 -VHDPath 'C:\VHDs\VDI-Pool-01.vhdx' -SwitchName 'Default Switch' -Path 'C:\VMs'"
        }
        4 = @{
            Title = "Failover Clustering with Hyper-V"
            Description = "Enable high availability for virtual machines"
            Code = "New-HyperVMachine -Name 'Cluster-VM' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`n# Configure clustering using Failover Clustering scripts"
        }
        5 = @{
            Title = "Live Migration"
            Description = "Move running VMs between hosts without downtime"
            Code = "Move-HyperVMachine -VMName 'Test-VM' -DestinationHost 'HV-SERVER02' -MigrationType 'Live'"
        }
        6 = @{
            Title = "Storage Live Migration"
            Description = "Move a VM's storage while it's running"
            Code = "Move-HyperVMachine -VMName 'Test-VM' -DestinationHost 'HV-SERVER02' -MigrationType 'Storage' -DestinationPath 'C:\VMs'"
        }
        7 = @{
            Title = "Replica and Disaster Recovery"
            Description = "Asynchronous VM replication between primary and secondary sites"
            Code = "Set-VMReplicationServer -ReplicationEnabled $true -AllowedAuthenticationType Kerberos`nEnable-VMReplication -VM 'Test-VM' -ReplicaServerName 'HV-SERVER02' -ReplicationFrequency 300"
        }
        8 = @{
            Title = "Shielded Virtual Machines"
            Description = "Protect VMs from host or fabric administrators"
            Code = "New-ShieldedVM -VMName 'Shielded-VM' -TemplateDiskPath 'C:\Templates\ShieldedTemplate.vhdx' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'"
        }
        9 = @{
            Title = "Nested Virtualization"
            Description = "Run Hyper-V inside a VM"
            Code = "New-HyperVMachine -Name 'Nested-VM' -Memory '4GB' -ProcessorCount 2 -Path 'C:\VMs'`nSet-VMProcessor -VM 'Nested-VM' -ExposeVirtualizationExtensions $true"
        }
        10 = @{
            Title = "Disaster Recovery with Storage Replica and Hyper-V"
            Description = "Combine VM replication with synchronous storage replication"
            Code = "New-HyperVMachine -Name 'DR-VM' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`n# Configure Storage Replica using Storage Replica scripts"
        }
        11 = @{
            Title = "Hyper-Converged Infrastructure (HCI)"
            Description = "Pair Hyper-V with Storage Spaces Direct and Failover Clustering"
            Code = "Enable-StorageSpacesDirect -CacheMode WriteBack`n# Configure Failover Clustering using Failover Clustering scripts"
        }
        12 = @{
            Title = "Hyper-V Network Virtualization"
            Description = "Abstract network topology from physical layout"
            Code = "New-HyperVSwitch -Name 'NV-Switch' -Type 'Internal'`n# Configure network virtualization using Network Virtualization scripts"
        }
        13 = @{
            Title = "Production Checkpoints"
            Description = "Application-consistent snapshots using VSS writers"
            Code = "New-HyperVMachine -Name 'Checkpoint-VM' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`nNew-HyperVCheckpoint -VMName 'Checkpoint-VM' -CheckpointName 'Production-Checkpoint' -CheckpointType 'Production'"
        }
        14 = @{
            Title = "Hyper-V Replica Broker"
            Description = "Central management for replication in clustered environments"
            Code = "Set-VMReplicationServer -ReplicationEnabled $true -AllowedAuthenticationType Kerberos`n# Configure replica broker in clustered environment"
        }
        15 = @{
            Title = "Dynamic Memory Management"
            Description = "Adjust VM memory allocation on the fly"
            Code = "New-HyperVMachine -Name 'Dynamic-VM' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs' -EnableDynamicMemory -MemoryMinimum '512MB' -MemoryMaximum '4GB'"
        }
        16 = @{
            Title = "Integration Services for Linux Guests"
            Description = "Seamless management and performance parity for Linux VMs"
            Code = "New-HyperVMachine -Name 'Linux-VM' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`nSet-HyperVIntegrationServices -VMName 'Linux-VM' -EnableTimeSynchronization -EnableHeartbeat -EnableKeyValuePairExchange -EnableShutdown -EnableVSS"
        }
        17 = @{
            Title = "PowerShell Direct"
            Description = "Manage guest OS from host without network connectivity"
            Code = "Invoke-HyperVPowerShellDirect -VMName 'Test-VM' -ScriptBlock { Get-ComputerInfo } -Credential (Get-Credential)"
        }
        18 = @{
            Title = "Enhanced Session Mode"
            Description = "Redirect USB devices, clipboard, and audio between host and VM"
            Code = "Set-VMHost -EnableEnhancedSessionMode $true`n# Connect to VM using enhanced session mode"
        }
        19 = @{
            Title = "Differencing Disks"
            Description = "Save space by basing multiple VMs on one parent image"
            Code = "New-HyperVVHD -Path 'C:\VHDs\Parent.vhdx' -Size '40GB' -Type 'Dynamic'`nNew-HyperVVHD -Path 'C:\VHDs\Differencing1.vhdx' -Size '40GB' -Type 'Differencing' -ParentPath 'C:\VHDs\Parent.vhdx'"
        }
        20 = @{
            Title = "VM Templates and Golden Images"
            Description = "Standardize base builds across environments"
            Code = "New-HyperVMachine -Name 'Windows-Template' -Memory '2GB' -ProcessorCount 2 -VHDPath 'C:\VHDs\Windows-Template.vhdx' -Path 'C:\Templates'`nNew-HyperVMachine -Name 'Linux-Template' -Memory '2GB' -ProcessorCount 2 -VHDPath 'C:\VHDs\Linux-Template.vhdx' -Path 'C:\Templates'"
        }
        21 = @{
            Title = "Checkpoint-Based Patch Rollback"
            Description = "Patch, test, and revert instantly"
            Code = "New-HyperVMachine -Name 'Rollback-VM' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`nNew-HyperVCheckpoint -VMName 'Rollback-VM' -CheckpointName 'Pre-Patch' -CheckpointType 'Production'`n# Apply patches`n# If issues occur: Restore-HyperVCheckpoint -VMName 'Rollback-VM' -CheckpointName 'Pre-Patch'"
        }
        22 = @{
            Title = "Hyper-V Replica for Edge Sites"
            Description = "Replicate workloads from branch office to central site"
            Code = "New-HyperVMachine -Name 'Edge-VM' -Memory '1GB' -ProcessorCount 1 -Path 'C:\VMs'`n# Configure replica to central site"
        }
        23 = @{
            Title = "GPU-Passthrough and RemoteFX vGPU"
            Description = "Accelerate VMs requiring 3D or compute workloads"
            Code = "New-HyperVMachine -Name 'GPU-VM' -Memory '4GB' -ProcessorCount 4 -Path 'C:\VMs'`nSet-VMHost -EnableGPU $true"
        }
        24 = @{
            Title = "Windows Sandbox / Container Integration"
            Description = "Lightweight isolation for apps and tests"
            Code = "Install-WindowsFeature -Name 'Containers' -IncludeManagementTools`n# Configure Windows containers"
        }
        25 = @{
            Title = "Host Resource Protection"
            Description = "Prevent noisy neighbor VMs from starving others"
            Code = "New-HyperVMachine -Name 'Protected-VM-01' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`nSet-HyperVResourceAllocation -VMName 'Protected-VM-01' -CPUReservation 50 -CPULimit 80 -MemoryReservation 1024 -MemoryLimit 2048"
        }
        26 = @{
            Title = "Nested Lab Environments"
            Description = "Full multi-node AD, ADFS, Keyfactor, or PKI labs on one host"
            Code = "New-HyperVMachine -Name 'DC-01' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`nNew-HyperVMachine -Name 'DC-02' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`nNew-HyperVMachine -Name 'ADFS-01' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`nNew-HyperVMachine -Name 'PKI-01' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'"
        }
        27 = @{
            Title = "Hot-Add Hardware"
            Description = "Add NICs or storage to running VMs"
            Code = "New-HyperVMachine -Name 'HotAdd-VM' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`n# Add hardware while VM is running"
        }
        28 = @{
            Title = "Shared Nothing Live Migration"
            Description = "Migrate VMs between hosts without shared storage"
            Code = "New-HyperVMachine -Name 'SharedNothing-VM' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`n# Configure shared nothing migration"
        }
        29 = @{
            Title = "Cluster-Aware Hyper-V Management"
            Description = "Integrate Hyper-V roles with SCVMM, Azure Arc, or PowerCLI"
            Code = "New-HyperVMachine -Name 'Cluster-Managed-VM-01' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`nNew-HyperVMachine -Name 'Cluster-Managed-VM-02' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`n# Configure cluster-aware management"
        }
        30 = @{
            Title = "Virtual Machine Resource Metering"
            Description = "Track resource usage for chargeback or showback"
            Code = "New-HyperVMachine -Name 'Metered-VM-01' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`nNew-HyperVMachine -Name 'Metered-VM-02' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`n# Configure resource metering"
        }
        31 = @{
            Title = "Hyper-V and Azure Hybrid Integration"
            Description = "Extend workloads to Azure using Azure Migrate or Arc-enabled servers"
            Code = "New-HyperVMachine -Name 'Azure-Hybrid-VM-01' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`nNew-HyperVMachine -Name 'Azure-Hybrid-VM-02' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`n# Configure Azure hybrid integration"
        }
        32 = @{
            Title = "Replica Encryption and Secure Transport"
            Description = "Protect replication traffic using HTTPS/TLS"
            Code = "Set-VMReplicationServer -ReplicationEnabled $true -AllowedAuthenticationType Kerberos -CertificateThumbprint 'EncryptionCert'`n# Configure replica encryption"
        }
        33 = @{
            Title = "Cluster Sets (Windows Server 2019+)"
            Description = "Manage multiple failover clusters as a single fabric"
            Code = "New-HyperVMachine -Name 'ClusterSet-VM-01' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`nNew-HyperVMachine -Name 'ClusterSet-VM-02' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`n# Configure cluster sets"
        }
        34 = @{
            Title = "Checkpoint Chains for Development Pipelines"
            Description = "Automate snapshot stages in CI/CD"
            Code = "New-HyperVMachine -Name 'Chain-VM' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'`nNew-HyperVCheckpoint -VMName 'Chain-VM' -CheckpointName 'Checkpoint-1' -CheckpointType 'Standard'`nNew-HyperVCheckpoint -VMName 'Chain-VM' -CheckpointName 'Checkpoint-2' -CheckpointType 'Standard'`nNew-HyperVCheckpoint -VMName 'Chain-VM' -CheckpointName 'Checkpoint-3' -CheckpointType 'Standard'"
        }
        35 = @{
            Title = "Hyper-V for Application Sandboxing"
            Description = "Isolate high-risk software, malware analysis, or R&D code"
            Code = "New-HyperVMachine -Name 'Sandbox-VM-01' -Memory '1GB' -ProcessorCount 1 -Path 'C:\VMs'`nNew-HyperVMachine -Name 'Sandbox-VM-02' -Memory '1GB' -ProcessorCount 1 -Path 'C:\VMs'`nNew-HyperVMachine -Name 'Sandbox-VM-03' -Memory '1GB' -ProcessorCount 1 -Path 'C:\VMs'"
        }
    }
    
    Write-ExampleLog "=== HYPER-V ENTERPRISE SCENARIOS EXAMPLES ===" "Info"
    
    # Display all scenarios with examples
    foreach ($scenarioNumber in 1..35) {
        $scenario = $scenarioExamples[$scenarioNumber]
        if ($scenario) {
            Write-ExampleLog "Scenario $scenarioNumber`: $($scenario.Title)" "Info"
            Write-ExampleLog "Description: $($scenario.Description)" "Info"
            Write-ExampleLog "Example Code:" "Info"
            Write-ExampleLog $scenario.Code "Info"
            Write-ExampleLog "---" "Info"
        }
    }
    
    # Demonstrate core functions
    Write-ExampleLog "=== CORE FUNCTION EXAMPLES ===" "Info"
    
    # VM Management Examples
    Write-ExampleLog "VM Management Examples:" "Info"
    Write-ExampleLog "Create VM: New-HyperVMachine -Name 'Test-VM' -Memory '2GB' -ProcessorCount 2 -VHDPath 'C:\VHDs\Test-VM.vhdx' -SwitchName 'Default Switch' -Path 'C:\VMs'" "Info"
    Write-ExampleLog "Configure VM: Set-HyperVMachine -VMName 'Test-VM' -Memory '4GB' -ProcessorCount 4 -EnableDynamicMemory -MemoryMinimum '1GB' -MemoryMaximum '8GB'" "Info"
    Write-ExampleLog "Remove VM: Remove-HyperVMachine -VMName 'Test-VM' -Force -RemoveVHDs" "Info"
    
    # Live Migration Examples
    Write-ExampleLog "Live Migration Examples:" "Info"
    Write-ExampleLog "Live Migration: Move-HyperVMachine -VMName 'Test-VM' -DestinationHost 'HV-SERVER02' -MigrationType 'Live'" "Info"
    Write-ExampleLog "Storage Migration: Move-HyperVMachine -VMName 'Test-VM' -DestinationHost 'HV-SERVER02' -MigrationType 'Storage' -DestinationPath 'C:\VMs'" "Info"
    Write-ExampleLog "Test Migration: Test-HyperVMigration -VMName 'Test-VM' -DestinationHost 'HV-SERVER02' -MigrationType 'Live'" "Info"
    
    # Checkpoint Examples
    Write-ExampleLog "Checkpoint Examples:" "Info"
    Write-ExampleLog "Create Checkpoint: New-HyperVCheckpoint -VMName 'Test-VM' -CheckpointName 'Before-Update' -CheckpointType 'Production'" "Info"
    Write-ExampleLog "Restore Checkpoint: Restore-HyperVCheckpoint -VMName 'Test-VM' -CheckpointName 'Before-Update' -Force" "Info"
    Write-ExampleLog "Remove Checkpoint: Remove-HyperVCheckpoint -VMName 'Test-VM' -CheckpointName 'Before-Update' -Force" "Info"
    
    # Resource Management Examples
    Write-ExampleLog "Resource Management Examples:" "Info"
    Write-ExampleLog "Set Resource Allocation: Set-HyperVResourceAllocation -VMName 'Test-VM' -CPUReservation 50 -CPULimit 80 -MemoryReservation 1024 -MemoryLimit 2048" "Info"
    Write-ExampleLog "Get Resource Utilization: Get-HyperVResourceUtilization -VMName 'Test-VM' -ResourceType 'All'" "Info"
    
    # Integration Services Examples
    Write-ExampleLog "Integration Services Examples:" "Info"
    Write-ExampleLog "Configure Integration Services: Set-HyperVIntegrationServices -VMName 'Test-VM' -EnableTimeSynchronization -EnableHeartbeat -EnableKeyValuePairExchange -EnableShutdown -EnableVSS -EnableGuestServiceInterface" "Info"
    
    # PowerShell Direct Examples
    Write-ExampleLog "PowerShell Direct Examples:" "Info"
    Write-ExampleLog "Execute PowerShell Direct: Invoke-HyperVPowerShellDirect -VMName 'Test-VM' -ScriptBlock { Get-ComputerInfo } -Credential (Get-Credential)" "Info"
    
    # Storage Examples
    Write-ExampleLog "Storage Examples:" "Info"
    Write-ExampleLog "Create VHD: New-HyperVVHD -Path 'C:\VHDs\Test-VM.vhdx' -Size '40GB' -Type 'Dynamic'" "Info"
    Write-ExampleLog "Create Differencing VHD: New-HyperVVHD -Path 'C:\VHDs\Differencing.vhdx' -Size '40GB' -Type 'Differencing' -ParentPath 'C:\VHDs\Parent.vhdx'" "Info"
    Write-ExampleLog "Optimize Storage: Optimize-HyperVStorage -VMName 'Test-VM' -CompactVHDs -DefragmentVHDs" "Info"
    
    # Network Examples
    Write-ExampleLog "Network Examples:" "Info"
    Write-ExampleLog "Create Switch: New-HyperVSwitch -Name 'Test-Switch' -Type 'Internal'" "Info"
    Write-ExampleLog "Configure Network Adapter: Set-HyperVNetworkAdapter -VMName 'Test-VM' -SwitchName 'Test-Switch' -EnableSR_IOV -EnableVMQ" "Info"
    
    # Security Examples
    Write-ExampleLog "Security Examples:" "Info"
    Write-ExampleLog "Create Shielded VM: New-ShieldedVM -VMName 'Shielded-VM' -TemplateDiskPath 'C:\Templates\ShieldedTemplate.vhdx' -Memory '2GB' -ProcessorCount 2 -Path 'C:\VMs'" "Info"
    Write-ExampleLog "Enable BitLocker: Enable-VMBitLocker -VMName 'Test-VM' -ProtectorType 'TPM'" "Info"
    Write-ExampleLog "Configure Security Baseline: Set-HyperVSecurityBaseline -HostName 'HV-SERVER01' -SecurityLevel 'High' -ComplianceStandard 'CIS' -IncludeHost -IncludeVMs" "Info"
    
    # Monitoring Examples
    Write-ExampleLog "Monitoring Examples:" "Info"
    Write-ExampleLog "Get Health Status: Get-HyperVHealthStatus -HostName 'HV-SERVER01' -IncludeDetails -IncludeVMs -IncludeHost" "Info"
    Write-ExampleLog "Get Performance Metrics: Get-HyperVPerformanceMetrics -HostName 'HV-SERVER01' -DurationMinutes 60" "Info"
    Write-ExampleLog "Get Event Logs: Get-HyperVEventLogs -HostName 'HV-SERVER01' -LogLevel 'All' -MaxEvents 100" "Info"
    Write-ExampleLog "Get Storage Utilization: Get-HyperVStorageUtilization -HostName 'HV-SERVER01' -IncludeVHDs -IncludeCheckpoints" "Info"
    Write-ExampleLog "Get Network Utilization: Get-HyperVNetworkUtilization -HostName 'HV-SERVER01'" "Info"
    Write-ExampleLog "Set Alerting: Set-HyperVAlerting -HostName 'HV-SERVER01' -EnableCPUAlerts -EnableMemoryAlerts -EnableDiskAlerts -EnableNetworkAlerts" "Info"
    Write-ExampleLog "Get Capacity Planning: Get-HyperVCapacityPlanning -HostName 'HV-SERVER01' -IncludeRecommendations" "Info"
    Write-ExampleLog "Get Monitoring Report: Get-HyperVMonitoringReport -HostName 'HV-SERVER01' -ReportType 'Comprehensive' -OutputPath 'C:\Reports\Monitoring-Report.html' -Format 'HTML'" "Info"
    
    # Troubleshooting Examples
    Write-ExampleLog "Troubleshooting Examples:" "Info"
    Write-ExampleLog "Test VM Diagnostics: Test-HyperVMDiagnostics -VMName 'Test-VM' -DiagnosticLevel 'Comprehensive' -IncludePerformance -IncludeSecurity -IncludeStorage -IncludeNetwork -IncludeIntegrationServices -IncludeCheckpoints" "Info"
    Write-ExampleLog "Analyze Event Logs: Analyze-HyperVEventLogs -HostName 'HV-SERVER01' -VMName 'Test-VM' -AnalysisType 'Comprehensive' -TimeRangeHours 24 -GenerateReport" "Info"
    Write-ExampleLog "Test Performance: Test-HyperVPerformance -HostName 'HV-SERVER01' -VMName 'Test-VM' -DurationMinutes 60 -IncludeCPU -IncludeMemory -IncludeNetwork -IncludeDisk" "Info"
    Write-ExampleLog "Test Migration: Test-HyperVMigration -VMName 'Test-VM' -DestinationHost 'HV-SERVER02' -MigrationType 'Live'" "Info"
    Write-ExampleLog "Repair Issues: Repair-HyperVIssues -HostName 'HV-SERVER01' -VMName 'Test-VM' -RepairType 'Automatic' -IncludeVMs -IncludeHost -IncludeStorage -IncludeNetwork" "Info"
    Write-ExampleLog "Test Health: Test-HyperVHealth -HostName 'HV-SERVER01' -VMName 'Test-VM' -HealthLevel 'Standard' -IncludePerformance -IncludeStorage -IncludeNetwork -IncludeSecurity" "Info"
    
    # Advanced Examples
    Write-ExampleLog "Advanced Examples:" "Info"
    Write-ExampleLog "Nested Virtualization: Set-VMProcessor -VM 'Nested-VM' -ExposeVirtualizationExtensions $true" "Info"
    Write-ExampleLog "GPU Passthrough: Set-VMHost -EnableGPU $true" "Info"
    Write-ExampleLog "Container Integration: Install-WindowsFeature -Name 'Containers' -IncludeManagementTools" "Info"
    Write-ExampleLog "Network Virtualization: New-HyperVSwitch -Name 'NV-Switch' -Type 'Internal'" "Info"
    Write-ExampleLog "Storage Spaces Direct: Enable-StorageSpacesDirect -CacheMode WriteBack" "Info"
    Write-ExampleLog "Hyper-V Replica: Set-VMReplicationServer -ReplicationEnabled $true -AllowedAuthenticationType Kerberos" "Info"
    Write-ExampleLog "Host Guardian Service: Register-VMWithHGS -VMName 'Test-VM' -HGSClusterName 'HGS-CLUSTER' -AttestationMode 'TPM'" "Info"
    
    Write-ExampleLog "Hyper-V examples demonstration completed successfully" "Success"
}
catch {
    Write-ExampleLog "Hyper-V examples demonstration failed: $($_.Exception.Message)" "Error"
    Write-ExampleLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive examples for all 35 Hyper-V enterprise scenarios.
    It demonstrates practical implementations for server virtualization, VDI, clustering,
    live migration, replica, shielded VMs, nested virtualization, and all advanced scenarios.
    
    Features:
    - All 35 enterprise scenarios with examples
    - Core function demonstrations
    - VM management examples
    - Live migration examples
    - Checkpoint examples
    - Resource management examples
    - Integration services examples
    - PowerShell Direct examples
    - Storage examples
    - Network examples
    - Security examples
    - Monitoring examples
    - Troubleshooting examples
    - Advanced examples
    
    Prerequisites:
    - Windows Server 2016 or later
    - Hyper-V feature installed
    - Administrative privileges
    - Network connectivity
    
    Dependencies:
    - HyperV-Core.psm1
    - HyperV-Security.psm1
    - HyperV-Monitoring.psm1
    - HyperV-Troubleshooting.psm1
    
    Usage Examples:
    .\HyperV-Examples.ps1
    
    Output:
    - Console logging with color-coded messages
    - All 35 scenario examples
    - Core function examples
    - Advanced examples
    - Comprehensive error handling
    
    Security Considerations:
    - Requires administrative privileges
    - Demonstrates secure configurations
    - Logs all operations for audit
    
    Performance Impact:
    - Minimal impact during demonstration
    - Non-destructive operations
    - Educational examples only
#>
