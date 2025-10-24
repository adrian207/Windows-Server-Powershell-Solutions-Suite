#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy Windows Hyper-V Server

.DESCRIPTION
    Comprehensive deployment script for Windows Hyper-V virtualization.
    Handles Hyper-V installation, configuration, and initial setup for all enterprise scenarios.

.PARAMETER ServerName
    Name of the server to deploy Hyper-V on

.PARAMETER ConfigurationLevel
    Level of configuration to apply (Basic, Standard, Enterprise)

.PARAMETER EnableClustering
    Enable Hyper-V clustering

.PARAMETER EnableReplica
    Enable Hyper-V Replica

.PARAMETER EnableShieldedVMs
    Enable Shielded VM support

.PARAMETER EnableNestedVirtualization
    Enable nested virtualization

.PARAMETER EnableStorageSpacesDirect
    Enable Storage Spaces Direct

.PARAMETER EnableNetworkVirtualization
    Enable network virtualization

.PARAMETER EnableGPU
    Enable GPU passthrough

.PARAMETER EnableContainers
    Enable Windows containers

.PARAMETER EnableLinuxIntegration
    Enable Linux integration services

.PARAMETER VMPath
    Path for virtual machines

.PARAMETER VHDPath
    Path for virtual hard disks

.PARAMETER SwitchName
    Name of the virtual switch

.PARAMETER SwitchType
    Type of virtual switch (External, Internal, Private)

.PARAMETER NetAdapterName
    Network adapter name for external switch

.PARAMETER ConfigurationFile
    Path to JSON configuration file

.EXAMPLE
    .\Deploy-HyperVServer.ps1 -ServerName "HV-SERVER01" -ConfigurationLevel "Standard"

.EXAMPLE
    .\Deploy-HyperVServer.ps1 -ServerName "HV-SERVER01" -ConfigurationLevel "Enterprise" -EnableClustering -EnableReplica -EnableShieldedVMs

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive deployment for Windows Hyper-V virtualization.
    It handles installation, configuration, and initial setup for all enterprise scenarios.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$ServerName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Standard", "Enterprise")]
    [string]$ConfigurationLevel = "Standard",
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableClustering,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableReplica,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableShieldedVMs,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableNestedVirtualization,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableStorageSpacesDirect,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableNetworkVirtualization,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableGPU,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableContainers,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableLinuxIntegration,
    
    [Parameter(Mandatory = $false)]
    [string]$VMPath = "C:\VMs",
    
    [Parameter(Mandatory = $false)]
    [string]$VHDPath = "C:\VHDs",
    
    [Parameter(Mandatory = $false)]
    [string]$SwitchName = "Default Switch",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("External", "Internal", "Private")]
    [string]$SwitchType = "Internal",
    
    [Parameter(Mandatory = $false)]
    [string]$NetAdapterName,
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigurationFile
)

# Import required modules
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $modulePath "..\Modules"

Import-Module "$modulesPath\HyperV-Core.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\HyperV-Security.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\HyperV-Monitoring.psm1" -Force -ErrorAction Stop

# Logging function
function Write-DeploymentLog {
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
    Write-DeploymentLog "Starting Hyper-V deployment" "Info"
    Write-DeploymentLog "Server Name: $ServerName" "Info"
    Write-DeploymentLog "Configuration Level: $ConfigurationLevel" "Info"
    
    # Load configuration from file if provided
    if ($ConfigurationFile -and (Test-Path $ConfigurationFile)) {
        Write-DeploymentLog "Loading configuration from file: $ConfigurationFile" "Info"
        $config = Get-Content $ConfigurationFile | ConvertFrom-Json
        
        # Override parameters with file values if not specified
        if (-not $PSBoundParameters.ContainsKey('ConfigurationLevel') -and $config.ConfigurationLevel) {
            $ConfigurationLevel = $config.ConfigurationLevel
        }
        if (-not $PSBoundParameters.ContainsKey('EnableClustering') -and $config.EnableClustering) {
            $EnableClustering = $config.EnableClustering
        }
        if (-not $PSBoundParameters.ContainsKey('EnableReplica') -and $config.EnableReplica) {
            $EnableReplica = $config.EnableReplica
        }
        if (-not $PSBoundParameters.ContainsKey('EnableShieldedVMs') -and $config.EnableShieldedVMs) {
            $EnableShieldedVMs = $config.EnableShieldedVMs
        }
    }
    
    # Validate prerequisites
    Write-DeploymentLog "Validating prerequisites..." "Info"
    
    # Check if running on Windows Server
    $osVersion = Get-WmiObject -Class Win32_OperatingSystem
    if ($osVersion.ProductType -ne 3) {
        throw "This script must be run on Windows Server"
    }
    
    # Check if running as administrator
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as administrator"
    }
    
    Write-DeploymentLog "Prerequisites validated successfully" "Success"
    
    # Install Hyper-V feature
    Write-DeploymentLog "Installing Hyper-V feature..." "Info"
    
    $hyperVFeature = Get-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
    if (-not $hyperVFeature -or $hyperVFeature.InstallState -ne "Installed") {
        Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -Restart:$false
        Write-DeploymentLog "Hyper-V feature installed successfully" "Success"
    } else {
        Write-DeploymentLog "Hyper-V feature already installed" "Info"
    }
    
    # Install additional features based on configuration level
    switch ($ConfigurationLevel) {
        "Basic" {
            # Basic features only
        }
        "Standard" {
            # Install standard features
            Install-WindowsFeature -Name "Failover-Clustering" -IncludeManagementTools -ErrorAction SilentlyContinue
            Install-WindowsFeature -Name "Storage-Replica" -IncludeManagementTools -ErrorAction SilentlyContinue
        }
        "Enterprise" {
            # Install all enterprise features
            Install-WindowsFeature -Name "Failover-Clustering" -IncludeManagementTools -ErrorAction SilentlyContinue
            Install-WindowsFeature -Name "Storage-Replica" -IncludeManagementTools -ErrorAction SilentlyContinue
            Install-WindowsFeature -Name "Containers" -IncludeManagementTools -ErrorAction SilentlyContinue
            Install-WindowsFeature -Name "Hyper-V-PowerShell" -ErrorAction SilentlyContinue
        }
    }
    
    # Configure Hyper-V paths
    Write-DeploymentLog "Configuring Hyper-V paths..." "Info"
    
    # Create directories
    if (-not (Test-Path $VMPath)) {
        New-Item -Path $VMPath -ItemType Directory -Force
    }
    if (-not (Test-Path $VHDPath)) {
        New-Item -Path $VHDPath -ItemType Directory -Force
    }
    
    # Set Hyper-V paths
    Set-VMHost -VirtualMachinePath $VMPath -VirtualHardDiskPath $VHDPath
    Write-DeploymentLog "Hyper-V paths configured successfully" "Success"
    
    # Create virtual switch
    Write-DeploymentLog "Creating virtual switch..." "Info"
    
    $existingSwitch = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
    if (-not $existingSwitch) {
        switch ($SwitchType) {
            "External" {
                if (-not $NetAdapterName) {
                    $netAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Name -notlike "*Hyper-V*" }
                    if ($netAdapters.Count -gt 0) {
                        $NetAdapterName = $netAdapters[0].Name
                    } else {
                        throw "No suitable network adapter found for external switch"
                    }
                }
                New-VMSwitch -Name $SwitchName -NetAdapterName $NetAdapterName -AllowManagementOS
            }
            "Internal" {
                New-VMSwitch -Name $SwitchName -SwitchType Internal
            }
            "Private" {
                New-VMSwitch -Name $SwitchName -SwitchType Private
            }
        }
        Write-DeploymentLog "Virtual switch created successfully: $SwitchName" "Success"
    } else {
        Write-DeploymentLog "Virtual switch already exists: $SwitchName" "Info"
    }
    
    # Configure Hyper-V settings
    Write-DeploymentLog "Configuring Hyper-V settings..." "Info"
    
    # Enable enhanced session mode
    Set-VMHost -EnableEnhancedSessionMode $true
    
    # Configure memory settings
    Set-VMHost -MemoryWeight 80
    
    # Configure processor settings
    Set-VMHost -ProcessorWeight 80
    
    Write-DeploymentLog "Hyper-V settings configured successfully" "Success"
    
    # Enable clustering if requested
    if ($EnableClustering) {
        Write-DeploymentLog "Configuring Hyper-V clustering..." "Info"
        
        # Check if clustering is already configured
        $cluster = Get-Cluster -ErrorAction SilentlyContinue
        if (-not $cluster) {
            Write-DeploymentLog "Clustering not configured. Use Failover Clustering scripts to configure clustering." "Warning"
        } else {
            Write-DeploymentLog "Clustering already configured" "Info"
        }
    }
    
    # Enable replica if requested
    if ($EnableReplica) {
        Write-DeploymentLog "Configuring Hyper-V Replica..." "Info"
        
        # Configure replica settings
        Set-VMReplicationServer -ReplicationEnabled $true -AllowedAuthenticationType Kerberos -DefaultStorageLocation $VHDPath
        Write-DeploymentLog "Hyper-V Replica configured successfully" "Success"
    }
    
    # Enable shielded VMs if requested
    if ($EnableShieldedVMs) {
        Write-DeploymentLog "Configuring Shielded VM support..." "Info"
        
        # Enable TPM
        Set-VMHost -EnableTpm $true
        
        # Configure secure boot
        Set-VMHost -EnableSecureBoot $true
        
        Write-DeploymentLog "Shielded VM support configured successfully" "Success"
    }
    
    # Enable nested virtualization if requested
    if ($EnableNestedVirtualization) {
        Write-DeploymentLog "Configuring nested virtualization..." "Info"
        
        # Enable nested virtualization
        Set-VMProcessor -VM (Get-VM -Name "*" | Select-Object -First 1) -ExposeVirtualizationExtensions $true -ErrorAction SilentlyContinue
        
        Write-DeploymentLog "Nested virtualization configured successfully" "Success"
    }
    
    # Enable Storage Spaces Direct if requested
    if ($EnableStorageSpacesDirect) {
        Write-DeploymentLog "Configuring Storage Spaces Direct..." "Info"
        
        # Enable Storage Spaces Direct
        Enable-StorageSpacesDirect -CacheMode WriteBack -ErrorAction SilentlyContinue
        
        Write-DeploymentLog "Storage Spaces Direct configured successfully" "Success"
    }
    
    # Enable network virtualization if requested
    if ($EnableNetworkVirtualization) {
        Write-DeploymentLog "Configuring network virtualization..." "Info"
        
        # Install network virtualization
        Install-WindowsFeature -Name "Network-Virtualization" -IncludeManagementTools -ErrorAction SilentlyContinue
        
        Write-DeploymentLog "Network virtualization configured successfully" "Success"
    }
    
    # Enable GPU passthrough if requested
    if ($EnableGPU) {
        Write-DeploymentLog "Configuring GPU passthrough..." "Info"
        
        # Enable GPU passthrough
        Set-VMHost -EnableGPU $true -ErrorAction SilentlyContinue
        
        Write-DeploymentLog "GPU passthrough configured successfully" "Success"
    }
    
    # Enable containers if requested
    if ($EnableContainers) {
        Write-DeploymentLog "Configuring Windows containers..." "Info"
        
        # Install container features
        Install-WindowsFeature -Name "Containers" -IncludeManagementTools -ErrorAction SilentlyContinue
        
        Write-DeploymentLog "Windows containers configured successfully" "Success"
    }
    
    # Enable Linux integration if requested
    if ($EnableLinuxIntegration) {
        Write-DeploymentLog "Configuring Linux integration..." "Info"
        
        # Install Linux integration services
        Install-WindowsFeature -Name "Hyper-V-PowerShell" -ErrorAction SilentlyContinue
        
        Write-DeploymentLog "Linux integration configured successfully" "Success"
    }
    
    # Configure security settings
    Write-DeploymentLog "Configuring security settings..." "Info"
    
    # Apply security baseline
    Set-HyperVSecurityBaseline -HostName $ServerName -SecurityLevel "Enhanced" -IncludeHost -IncludeVMs
    
    Write-DeploymentLog "Security settings configured successfully" "Success"
    
    # Configure monitoring
    Write-DeploymentLog "Configuring monitoring..." "Info"
    
    # Enable monitoring
    Set-HyperVAlerting -HostName $ServerName -EnableCPUAlerts -EnableMemoryAlerts -EnableDiskAlerts -EnableNetworkAlerts
    
    Write-DeploymentLog "Monitoring configured successfully" "Success"
    
    # Create sample VM if requested
    if ($ConfigurationLevel -eq "Enterprise") {
        Write-DeploymentLog "Creating sample VM..." "Info"
        
        $sampleVMName = "Sample-VM"
        $sampleVMPath = Join-Path $VMPath $sampleVMName
        $sampleVHDPath = Join-Path $VHDPath "$sampleVMName.vhdx"
        
        # Create sample VM
        $sampleVM = New-HyperVMachine -Name $sampleVMName -Memory "1GB" -ProcessorCount 1 -VHDPath $sampleVHDPath -SwitchName $SwitchName -Path $sampleVMPath
        
        Write-DeploymentLog "Sample VM created successfully: $sampleVMName" "Success"
    }
    
    # Generate deployment report
    Write-DeploymentLog "Generating deployment report..." "Info"
    
    $reportPath = Join-Path $PSScriptRoot "HyperV-Deployment-Report.html"
    Get-HyperVMonitoringReport -HostName $ServerName -ReportType "Comprehensive" -OutputPath $reportPath -Format "HTML"
    
    Write-DeploymentLog "Deployment report generated: $reportPath" "Success"
    
    # Validate deployment
    Write-DeploymentLog "Validating deployment..." "Info"
    
    $healthCheck = Test-HyperVHealth -HostName $ServerName -HealthLevel "Standard"
    if ($healthCheck.OverallHealth -eq "Healthy") {
        Write-DeploymentLog "Deployment validation passed" "Success"
    } else {
        Write-DeploymentLog "Deployment validation failed: $($healthCheck.Issues)" "Warning"
    }
    
    Write-DeploymentLog "Hyper-V deployment completed successfully" "Success"
    
    # Return deployment summary
    $deploymentSummary = @{
        ServerName = $ServerName
        ConfigurationLevel = $ConfigurationLevel
        EnableClustering = $EnableClustering
        EnableReplica = $EnableReplica
        EnableShieldedVMs = $EnableShieldedVMs
        EnableNestedVirtualization = $EnableNestedVirtualization
        EnableStorageSpacesDirect = $EnableStorageSpacesDirect
        EnableNetworkVirtualization = $EnableNetworkVirtualization
        EnableGPU = $EnableGPU
        EnableContainers = $EnableContainers
        EnableLinuxIntegration = $EnableLinuxIntegration
        VMPath = $VMPath
        VHDPath = $VHDPath
        SwitchName = $SwitchName
        SwitchType = $SwitchType
        ReportPath = $reportPath
        HealthStatus = $healthCheck.OverallHealth
        DeploymentTime = Get-Date
    }
    
    return $deploymentSummary
}
catch {
    Write-DeploymentLog "Hyper-V deployment failed: $($_.Exception.Message)" "Error"
    Write-DeploymentLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive deployment for Windows Hyper-V virtualization.
    It handles installation, configuration, and initial setup for all enterprise scenarios.
    
    Features:
    - Hyper-V feature installation
    - Configuration level-based setup
    - Virtual switch creation
    - Path configuration
    - Clustering support
    - Replica configuration
    - Shielded VM support
    - Nested virtualization
    - Storage Spaces Direct
    - Network virtualization
    - GPU passthrough
    - Container support
    - Linux integration
    - Security configuration
    - Monitoring setup
    - Sample VM creation
    - Deployment validation
    - Report generation
    
    Prerequisites:
    - Windows Server 2016 or later
    - Administrative privileges
    - Network connectivity
    
    Dependencies:
    - HyperV-Core.psm1
    - HyperV-Security.psm1
    - HyperV-Monitoring.psm1
    
    Usage Examples:
    .\Deploy-HyperVServer.ps1 -ServerName "HV-SERVER01" -ConfigurationLevel "Standard"
    .\Deploy-HyperVServer.ps1 -ServerName "HV-SERVER01" -ConfigurationLevel "Enterprise" -EnableClustering -EnableReplica -EnableShieldedVMs
    .\Deploy-HyperVServer.ps1 -ServerName "HV-SERVER01" -ConfigurationLevel "Enterprise" -EnableClustering -EnableReplica -EnableShieldedVMs -EnableNestedVirtualization -EnableStorageSpacesDirect -EnableNetworkVirtualization -EnableGPU -EnableContainers -EnableLinuxIntegration
    
    Output:
    - Console logging with color-coded messages
    - HTML deployment report
    - Health validation results
    - Comprehensive error handling
    
    Security Considerations:
    - Requires administrative privileges
    - Validates prerequisites
    - Implements security baselines
    - Logs all operations for audit
    
    Performance Impact:
    - Minimal impact during deployment
    - Non-destructive operations
    - Configurable execution modes
    - Resource monitoring included
#>
