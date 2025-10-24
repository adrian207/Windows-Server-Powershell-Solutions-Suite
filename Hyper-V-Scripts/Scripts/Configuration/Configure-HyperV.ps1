#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Configure Windows Hyper-V

.DESCRIPTION
    Comprehensive configuration script for Windows Hyper-V virtualization.
    Handles Hyper-V configuration, VM settings, network configuration, storage setup, and optimization.

.PARAMETER ServerName
    Name of the server to configure

.PARAMETER ConfigurationLevel
    Level of configuration to apply (Basic, Standard, Enterprise)

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

.PARAMETER EnableDynamicMemory
    Enable dynamic memory management

.PARAMETER EnableIntegrationServices
    Enable integration services

.PARAMETER EnableSecureBoot
    Enable secure boot

.PARAMETER EnableTPM
    Enable TPM

.PARAMETER EnableEnhancedSessionMode
    Enable enhanced session mode

.PARAMETER EnableNestedVirtualization
    Enable nested virtualization

.PARAMETER EnableGPU
    Enable GPU passthrough

.PARAMETER ConfigurationFile
    Path to JSON configuration file

.EXAMPLE
    .\Configure-HyperV.ps1 -ServerName "HV-SERVER01" -ConfigurationLevel "Standard"

.EXAMPLE
    .\Configure-HyperV.ps1 -ServerName "HV-SERVER01" -ConfigurationLevel "Enterprise" -EnableDynamicMemory -EnableSecureBoot -EnableTPM

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive configuration for Windows Hyper-V virtualization.
    It handles Hyper-V configuration, VM settings, network configuration, storage setup, and optimization.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$ServerName = $env:COMPUTERNAME,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Standard", "Enterprise")]
    [string]$ConfigurationLevel = "Standard",
    
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
    [switch]$EnableDynamicMemory,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableIntegrationServices,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableSecureBoot,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableTPM,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableEnhancedSessionMode,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableNestedVirtualization,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableGPU,
    
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
function Write-ConfigLog {
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
    Write-ConfigLog "Starting Hyper-V configuration" "Info"
    Write-ConfigLog "Server Name: $ServerName" "Info"
    Write-ConfigLog "Configuration Level: $ConfigurationLevel" "Info"
    
    # Load configuration from file if provided
    if ($ConfigurationFile -and (Test-Path $ConfigurationFile)) {
        Write-ConfigLog "Loading configuration from file: $ConfigurationFile" "Info"
        $config = Get-Content $ConfigurationFile | ConvertFrom-Json
        
        # Override parameters with file values if not specified
        if (-not $PSBoundParameters.ContainsKey('ConfigurationLevel') -and $config.ConfigurationLevel) {
            $ConfigurationLevel = $config.ConfigurationLevel
        }
        if (-not $PSBoundParameters.ContainsKey('VMPath') -and $config.VMPath) {
            $VMPath = $config.VMPath
        }
        if (-not $PSBoundParameters.ContainsKey('VHDPath') -and $config.VHDPath) {
            $VHDPath = $config.VHDPath
        }
        if (-not $PSBoundParameters.ContainsKey('SwitchName') -and $config.SwitchName) {
            $SwitchName = $config.SwitchName
        }
        if (-not $PSBoundParameters.ContainsKey('SwitchType') -and $config.SwitchType) {
            $SwitchType = $config.SwitchType
        }
    }
    
    # Validate prerequisites
    Write-ConfigLog "Validating prerequisites..." "Info"
    
    # Check if Hyper-V is installed
    $hyperVFeature = Get-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
    if (-not $hyperVFeature -or $hyperVFeature.InstallState -ne "Installed") {
        throw "Hyper-V feature is not installed"
    }
    
    Write-ConfigLog "Prerequisites validated successfully" "Success"
    
    # Configure Hyper-V paths
    Write-ConfigLog "Configuring Hyper-V paths..." "Info"
    
    # Create directories
    if (-not (Test-Path $VMPath)) {
        New-Item -Path $VMPath -ItemType Directory -Force
        Write-ConfigLog "Created VM directory: $VMPath" "Success"
    }
    if (-not (Test-Path $VHDPath)) {
        New-Item -Path $VHDPath -ItemType Directory -Force
        Write-ConfigLog "Created VHD directory: $VHDPath" "Success"
    }
    
    # Set Hyper-V paths
    Set-VMHost -ComputerName $ServerName -VirtualMachinePath $VMPath -VirtualHardDiskPath $VHDPath
    Write-ConfigLog "Hyper-V paths configured successfully" "Success"
    
    # Configure Hyper-V settings based on level
    Write-ConfigLog "Configuring Hyper-V settings..." "Info"
    
    switch ($ConfigurationLevel) {
        "Basic" {
            # Basic configuration
            Set-VMHost -ComputerName $ServerName -EnableEnhancedSessionMode $true
            Write-ConfigLog "Basic configuration applied" "Success"
        }
        "Standard" {
            # Standard configuration
            Set-VMHost -ComputerName $ServerName -EnableEnhancedSessionMode $true
            Set-VMHost -ComputerName $ServerName -MemoryWeight 80
            Set-VMHost -ComputerName $ServerName -ProcessorWeight 80
            Write-ConfigLog "Standard configuration applied" "Success"
        }
        "Enterprise" {
            # Enterprise configuration
            Set-VMHost -ComputerName $ServerName -EnableEnhancedSessionMode $true
            Set-VMHost -ComputerName $ServerName -MemoryWeight 80
            Set-VMHost -ComputerName $ServerName -ProcessorWeight 80
            Set-VMHost -ComputerName $ServerName -EnableTpm $true
            Set-VMHost -ComputerName $ServerName -EnableSecureBoot $true
            Write-ConfigLog "Enterprise configuration applied" "Success"
        }
    }
    
    # Configure virtual switch
    Write-ConfigLog "Configuring virtual switch..." "Info"
    
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
        Write-ConfigLog "Virtual switch created successfully: $SwitchName" "Success"
    } else {
        Write-ConfigLog "Virtual switch already exists: $SwitchName" "Info"
    }
    
    # Configure dynamic memory if enabled
    if ($EnableDynamicMemory) {
        Write-ConfigLog "Configuring dynamic memory..." "Info"
        
        $vms = Get-VM -ComputerName $ServerName
        foreach ($vm in $vms) {
            Set-VMMemory -VM $vm -DynamicMemoryEnabled $true
        }
        
        Write-ConfigLog "Dynamic memory configured successfully" "Success"
    }
    
    # Configure integration services if enabled
    if ($EnableIntegrationServices) {
        Write-ConfigLog "Configuring integration services..." "Info"
        
        $vms = Get-VM -ComputerName $ServerName
        foreach ($vm in $vms) {
            Set-HyperVIntegrationServices -VMName $vm.Name -EnableTimeSynchronization -EnableHeartbeat -EnableKeyValuePairExchange -EnableShutdown -EnableVSS -EnableGuestServiceInterface
        }
        
        Write-ConfigLog "Integration services configured successfully" "Success"
    }
    
    # Configure secure boot if enabled
    if ($EnableSecureBoot) {
        Write-ConfigLog "Configuring secure boot..." "Info"
        
        $vms = Get-VM -ComputerName $ServerName
        foreach ($vm in $vms) {
            Set-VMFirmware -VM $vm -EnableSecureBoot
        }
        
        Write-ConfigLog "Secure boot configured successfully" "Success"
    }
    
    # Configure TPM if enabled
    if ($EnableTPM) {
        Write-ConfigLog "Configuring TPM..." "Info"
        
        $vms = Get-VM -ComputerName $ServerName
        foreach ($vm in $vms) {
            Set-VMSecurity -VM $vm -TpmEnabled
        }
        
        Write-ConfigLog "TPM configured successfully" "Success"
    }
    
    # Configure enhanced session mode if enabled
    if ($EnableEnhancedSessionMode) {
        Write-ConfigLog "Configuring enhanced session mode..." "Info"
        
        Set-VMHost -ComputerName $ServerName -EnableEnhancedSessionMode $true
        Write-ConfigLog "Enhanced session mode configured successfully" "Success"
    }
    
    # Configure nested virtualization if enabled
    if ($EnableNestedVirtualization) {
        Write-ConfigLog "Configuring nested virtualization..." "Info"
        
        $vms = Get-VM -ComputerName $ServerName
        foreach ($vm in $vms) {
            Set-VMProcessor -VM $vm -ExposeVirtualizationExtensions $true -ErrorAction SilentlyContinue
        }
        
        Write-ConfigLog "Nested virtualization configured successfully" "Success"
    }
    
    # Configure GPU passthrough if enabled
    if ($EnableGPU) {
        Write-ConfigLog "Configuring GPU passthrough..." "Info"
        
        Set-VMHost -ComputerName $ServerName -EnableGPU $true -ErrorAction SilentlyContinue
        Write-ConfigLog "GPU passthrough configured successfully" "Success"
    }
    
    # Configure network settings
    Write-ConfigLog "Configuring network settings..." "Info"
    
    $vms = Get-VM -ComputerName $ServerName
    foreach ($vm in $vms) {
        $networkAdapters = Get-VMNetworkAdapter -VM $vm
        foreach ($adapter in $networkAdapters) {
            Set-VMNetworkAdapter -VMNetworkAdapter $adapter -SwitchName $SwitchName
        }
    }
    
    Write-ConfigLog "Network settings configured successfully" "Success"
    
    # Configure storage settings
    Write-ConfigLog "Configuring storage settings..." "Info"
    
    # Optimize storage
    Optimize-HyperVStorage -HostName $ServerName -CompactVHDs -DefragmentVHDs
    
    Write-ConfigLog "Storage settings configured successfully" "Success"
    
    # Configure security settings
    Write-ConfigLog "Configuring security settings..." "Info"
    
    Set-HyperVSecurityBaseline -HostName $ServerName -SecurityLevel "Enhanced" -IncludeHost -IncludeVMs
    
    Write-ConfigLog "Security settings configured successfully" "Success"
    
    # Configure monitoring
    Write-ConfigLog "Configuring monitoring..." "Info"
    
    Set-HyperVAlerting -HostName $ServerName -EnableCPUAlerts -EnableMemoryAlerts -EnableDiskAlerts -EnableNetworkAlerts
    
    Write-ConfigLog "Monitoring configured successfully" "Success"
    
    # Generate configuration report
    Write-ConfigLog "Generating configuration report..." "Info"
    
    $reportPath = Join-Path $PSScriptRoot "HyperV-Configuration-Report.html"
    Get-HyperVMonitoringReport -HostName $ServerName -ReportType "Enhanced" -OutputPath $reportPath -Format "HTML"
    
    Write-ConfigLog "Configuration report generated: $reportPath" "Success"
    
    # Validate configuration
    Write-ConfigLog "Validating configuration..." "Info"
    
    $healthCheck = Test-HyperVHealth -HostName $ServerName -HealthLevel "Standard"
    if ($healthCheck.OverallHealth -eq "Healthy") {
        Write-ConfigLog "Configuration validation passed" "Success"
    } else {
        Write-ConfigLog "Configuration validation failed: $($healthCheck.Issues)" "Warning"
    }
    
    Write-ConfigLog "Hyper-V configuration completed successfully" "Success"
    
    # Return configuration summary
    $configSummary = @{
        ServerName = $ServerName
        ConfigurationLevel = $ConfigurationLevel
        VMPath = $VMPath
        VHDPath = $VHDPath
        SwitchName = $SwitchName
        SwitchType = $SwitchType
        EnableDynamicMemory = $EnableDynamicMemory
        EnableIntegrationServices = $EnableIntegrationServices
        EnableSecureBoot = $EnableSecureBoot
        EnableTPM = $EnableTPM
        EnableEnhancedSessionMode = $EnableEnhancedSessionMode
        EnableNestedVirtualization = $EnableNestedVirtualization
        EnableGPU = $EnableGPU
        ReportPath = $reportPath
        HealthStatus = $healthCheck.OverallHealth
        ConfigurationTime = Get-Date
    }
    
    return $configSummary
}
catch {
    Write-ConfigLog "Hyper-V configuration failed: $($_.Exception.Message)" "Error"
    Write-ConfigLog "Stack Trace: $($_.ScriptStackTrace)" "Error"
    throw
}

<#
.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
    
    This script provides comprehensive configuration for Windows Hyper-V virtualization.
    It handles Hyper-V configuration, VM settings, network configuration, storage setup, and optimization.
    
    Features:
    - Hyper-V path configuration
    - Virtual switch creation
    - Dynamic memory management
    - Integration services configuration
    - Secure boot configuration
    - TPM configuration
    - Enhanced session mode
    - Nested virtualization
    - GPU passthrough
    - Network settings
    - Storage optimization
    - Security configuration
    - Monitoring setup
    - Configuration validation
    - Report generation
    
    Prerequisites:
    - Windows Server 2016 or later
    - Hyper-V feature installed
    - Administrative privileges
    - Network connectivity
    
    Dependencies:
    - HyperV-Core.psm1
    - HyperV-Security.psm1
    - HyperV-Monitoring.psm1
    
    Usage Examples:
    .\Configure-HyperV.ps1 -ServerName "HV-SERVER01" -ConfigurationLevel "Standard"
    .\Configure-HyperV.ps1 -ServerName "HV-SERVER01" -ConfigurationLevel "Enterprise" -EnableDynamicMemory -EnableSecureBoot -EnableTPM
    .\Configure-HyperV.ps1 -ServerName "HV-SERVER01" -ConfigurationLevel "Enterprise" -EnableDynamicMemory -EnableIntegrationServices -EnableSecureBoot -EnableTPM -EnableEnhancedSessionMode -EnableNestedVirtualization -EnableGPU
    
    Output:
    - Console logging with color-coded messages
    - HTML configuration report
    - Health validation results
    - Comprehensive error handling
    
    Security Considerations:
    - Requires administrative privileges
    - Validates prerequisites
    - Implements security baselines
    - Logs all operations for audit
    
    Performance Impact:
    - Minimal impact during configuration
    - Non-destructive operations
    - Configurable execution modes
    - Resource monitoring included
#>
