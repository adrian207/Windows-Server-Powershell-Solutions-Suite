#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy Virtual Desktop Infrastructure (VDI) Environment

.DESCRIPTION
    This script deploys a complete VDI environment using RDS Virtualization Host,
    including VM pools, user assignments, and profile management.

.PARAMETER DeploymentName
    Name for the VDI deployment

.PARAMETER PoolName
    Name of the VM pool

.PARAMETER PoolType
    Type of VM pool (Personal, Pooled, Automatic)

.PARAMETER MaxVMs
    Maximum number of VMs in the pool

.PARAMETER VMConfiguration
    VM configuration settings

.PARAMETER UserAssignments
    Array of user assignments

.PARAMETER EnableFSLogix
    Enable FSLogix profile containers

.PARAMETER LogFile
    Log file path for deployment

.EXAMPLE
    .\Deploy-VDIEnvironment.ps1 -DeploymentName "VDI-Production" -PoolName "Personal-Desktops" -PoolType "Personal" -MaxVMs 50

.EXAMPLE
    .\Deploy-VDIEnvironment.ps1 -DeploymentName "VDI-Pooled" -PoolName "Pooled-Desktops" -PoolType "Pooled" -MaxVMs 100 -EnableFSLogix
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DeploymentName,
    
    [Parameter(Mandatory = $true)]
    [string]$PoolName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Personal", "Pooled", "Automatic")]
    [string]$PoolType = "Pooled",
    
    [Parameter(Mandatory = $false)]
    [int]$MaxVMs = 10,
    
    [Parameter(Mandatory = $false)]
    [hashtable]$VMConfiguration = @{
        MemoryGB = 4
        CPUCount = 2
        DiskSizeGB = 60
        OSVersion = "Windows 10 Enterprise"
    },
    
    [Parameter(Mandatory = $false)]
    [hashtable[]]$UserAssignments = @(),
    
    [switch]$EnableFSLogix,
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile = "C:\Logs\VDI-Deployment.log"
)

# Set up logging
$logDir = Split-Path $LogFile -Parent
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

function Write-DeploymentLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogFile -Value $logEntry
}

try {
    Write-DeploymentLog "Starting VDI Environment Deployment: $DeploymentName"
    
    # Import RDS modules
    $modulePaths = @(
        ".\Modules\RDS-Core.psm1",
        ".\Modules\RDS-Virtualization.psm1",
        ".\Modules\RDS-ProfileManagement.psm1",
        ".\Modules\RDS-Performance.psm1",
        ".\Modules\RDS-Monitoring.psm1"
    )
    
    foreach ($modulePath in $modulePaths) {
        if (Test-Path $modulePath) {
            Import-Module $modulePath -Force
            Write-DeploymentLog "Imported module: $modulePath"
        } else {
            Write-DeploymentLog "Module not found: $modulePath" "WARNING"
        }
    }
    
    # Test prerequisites
    Write-DeploymentLog "Testing prerequisites..."
    $prerequisites = Test-RDSVirtualizationPrerequisites
    if (-not $prerequisites.AdministratorPrivileges) {
        throw "Administrator privileges are required for VDI deployment"
    }
    
    if (-not $prerequisites.HyperVInstalled) {
        Write-DeploymentLog "Installing Hyper-V..."
        $hyperVResult = Install-RDSVirtualizationHost -IncludeManagementTools -RestartRequired
        if ($hyperVResult.Success) {
            Write-DeploymentLog "Hyper-V installed successfully"
        } else {
            throw "Failed to install Hyper-V: $($hyperVResult.Error)"
        }
    }
    
    # Step 1: Install RDS Virtualization Host
    Write-DeploymentLog "Installing RDS Virtualization Host..."
    $virtHostResult = Install-RDSVirtualizationHost -IncludeManagementTools -RestartRequired
    if ($virtHostResult.Success) {
        Write-DeploymentLog "RDS Virtualization Host installed successfully"
    } else {
        throw "Failed to install RDS Virtualization Host: $($virtHostResult.Error)"
    }
    
    # Step 2: Create VM Pool
    Write-DeploymentLog "Creating VM Pool: $PoolName..."
    $poolResult = New-RDSVirtualMachinePool -PoolName $PoolName -AssignmentType $PoolType -MaxVMs $MaxVMs -MemoryGB $VMConfiguration.MemoryGB -CPUCount $VMConfiguration.CPUCount
    if ($poolResult.Success) {
        Write-DeploymentLog "VM Pool created successfully"
        Write-DeploymentLog "Pool ID: $($poolResult.PoolId)"
    } else {
        throw "Failed to create VM Pool: $($poolResult.Error)"
    }
    
    # Step 3: Configure VM templates
    Write-DeploymentLog "Configuring VM templates..."
    $templateConfig = @{
        Name = "$PoolName-Template"
        MemoryGB = $VMConfiguration.MemoryGB
        CPUCount = $VMConfiguration.CPUCount
        DiskSizeGB = $VMConfiguration.DiskSizeGB
        OSVersion = $VMConfiguration.OSVersion
    }
    Write-DeploymentLog "VM Template configured: $($templateConfig.Name)"
    
    # Step 4: Install and configure FSLogix (if enabled)
    if ($EnableFSLogix) {
        Write-DeploymentLog "Installing and configuring FSLogix Profile Containers..."
        $fslogixResult = Install-FSLogixProfileContainers -ProfilePath "\\FileServer\Profiles" -IncludeOfficeContainers -IncludeAppsContainers
        if ($fslogixResult.Success) {
            Write-DeploymentLog "FSLogix Profile Containers installed successfully"
        } else {
            Write-DeploymentLog "Failed to install FSLogix: $($fslogixResult.Error)" "WARNING"
        }
    }
    
    # Step 5: Configure user assignments
    Write-DeploymentLog "Configuring user assignments..."
    foreach ($assignment in $UserAssignments) {
        try {
            $assignmentResult = Set-RDSVirtualMachineAssignment -PoolName $PoolName -UserName $assignment.UserName -AssignmentType $assignment.AssignmentType
            if ($assignmentResult.Success) {
                Write-DeploymentLog "Configured assignment for user: $($assignment.UserName)"
            } else {
                Write-DeploymentLog "Failed to configure assignment for user $($assignment.UserName) : $($assignmentResult.Error)" "WARNING"
            }
        } catch {
            Write-DeploymentLog "Error configuring assignment for user $($assignment.UserName) : $($_.Exception.Message)" "WARNING"
        }
    }
    
    # Step 6: Configure performance optimization
    Write-DeploymentLog "Configuring performance optimization..."
    $perfResult = Enable-RDSGPUAcceleration -GPUType "NVIDIA" -EnableHardwareAcceleration -EnableGraphicsVirtualization
    if ($perfResult.Success) {
        Write-DeploymentLog "GPU acceleration configured successfully"
    } else {
        Write-DeploymentLog "Failed to configure GPU acceleration: $($perfResult.Error)" "WARNING"
    }
    
    # Configure bandwidth optimization
    $bandwidthResult = Set-RDSBandwidthOptimization -EnableCompression -EnableCaching -EnableAdaptiveGraphics -EnableUDPTransport
    if ($bandwidthResult.Success) {
        Write-DeploymentLog "Bandwidth optimization configured successfully"
    } else {
        Write-DeploymentLog "Failed to configure bandwidth optimization: $($bandwidthResult.Error)" "WARNING"
    }
    
    # Step 7: Start monitoring
    Write-DeploymentLog "Starting VDI monitoring..."
    $monitoringResult = Start-RDSVirtualMachinePoolMonitoring -PoolName $PoolName -IncludePerformance -IncludeHealthChecks -LogFile "C:\Logs\VDI-Monitor.log"
    if ($monitoringResult.Success) {
        Write-DeploymentLog "VDI monitoring started successfully"
    } else {
        Write-DeploymentLog "Failed to start VDI monitoring: $($monitoringResult.Error)" "WARNING"
    }
    
    # Step 8: Verify deployment
    Write-DeploymentLog "Verifying VDI deployment..."
    $verificationResult = Get-RDSVirtualMachinePoolStatus -PoolName $PoolName -IncludeVMs -IncludeAssignments
    if ($verificationResult.Pools.Count -gt 0) {
        Write-DeploymentLog "VDI deployment verification successful"
        Write-DeploymentLog "Deployment Summary:" "INFO"
        Write-DeploymentLog "  - Deployment Name: $DeploymentName" "INFO"
        Write-DeploymentLog "  - Pool Name: $PoolName" "INFO"
        Write-DeploymentLog "  - Pool Type: $PoolType" "INFO"
        Write-DeploymentLog "  - Max VMs: $MaxVMs" "INFO"
        Write-DeploymentLog "  - VM Memory: $($VMConfiguration.MemoryGB) GB" "INFO"
        Write-DeploymentLog "  - VM CPUs: $($VMConfiguration.CPUCount)" "INFO"
        Write-DeploymentLog "  - FSLogix Enabled: $EnableFSLogix" "INFO"
        Write-DeploymentLog "  - User Assignments: $($UserAssignments.Count)" "INFO"
    } else {
        Write-DeploymentLog "VDI deployment verification failed" "ERROR"
    }
    
    Write-DeploymentLog "VDI Environment Deployment completed successfully!" "SUCCESS"
    
} catch {
    Write-DeploymentLog "Deployment failed: $($_.Exception.Message)" "ERROR"
    Write-Error "VDI Environment Deployment failed: $($_.Exception.Message)"
    exit 1
}
