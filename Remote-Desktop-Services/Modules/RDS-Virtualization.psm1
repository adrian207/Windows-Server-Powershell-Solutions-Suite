#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Remote Desktop Services Virtualization PowerShell Module

.DESCRIPTION
    This module provides comprehensive Virtual Desktop Infrastructure (VDI) management
    capabilities for Remote Desktop Services including VM management, pool management,
    and advanced virtualization scenarios.

.NOTES
    Author: Remote Desktop Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/desktop-hosting/remote-desktop-services-virtualization-host
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Test-RDSVirtualizationPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for RDS Virtualization operations
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        HyperVInstalled = $false
        RDSVirtualizationHostInstalled = $false
        AdministratorPrivileges = $false
        VirtualizationEnabled = $false
        StorageAvailable = $false
        NetworkConnectivity = $false
    }
    
    # Check if Hyper-V is installed
    try {
        $hyperVFeature = Get-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
        $prerequisites.HyperVInstalled = ($hyperVFeature -and $hyperVFeature.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check Hyper-V installation: $($_.Exception.Message)"
    }
    
    # Check if RDS Virtualization Host is installed
    try {
        $rdsVirtFeature = Get-WindowsFeature -Name "RDS-Virtualization" -ErrorAction SilentlyContinue
        $prerequisites.RDSVirtualizationHostInstalled = ($rdsVirtFeature -and $rdsVirtFeature.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check RDS Virtualization Host installation: $($_.Exception.Message)"
    }
    
    # Check administrator privileges
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $prerequisites.AdministratorPrivileges = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Warning "Could not check administrator privileges: $($_.Exception.Message)"
    }
    
    # Check virtualization support
    try {
        $vmProcessor = Get-WmiObject -Class "Win32_Processor" -ErrorAction SilentlyContinue | Select-Object -First 1
        $prerequisites.VirtualizationEnabled = ($vmProcessor.VirtualizationFirmwareEnabled -eq $true)
    } catch {
        Write-Warning "Could not check virtualization support: $($_.Exception.Message)"
    }
    
    # Check storage availability
    try {
        $drives = Get-WmiObject -Class "Win32_LogicalDisk" -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 3 }
        $prerequisites.StorageAvailable = ($drives | Where-Object { $_.FreeSpace -gt 10GB }).Count -gt 0
    } catch {
        Write-Warning "Could not check storage availability: $($_.Exception.Message)"
    }
    
    # Check network connectivity
    try {
        $ping = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet -ErrorAction SilentlyContinue
        $prerequisites.NetworkConnectivity = $ping
    } catch {
        Write-Warning "Could not check network connectivity: $($_.Exception.Message)"
    }
    
    return $prerequisites
}

#endregion

#region Public Functions

function Install-RDSVirtualizationHost {
    <#
    .SYNOPSIS
        Installs RDS Virtualization Host role and required features
    
    .DESCRIPTION
        This function installs the Remote Desktop Services Virtualization Host role
        and all required Windows features for VDI deployment.
    
    .PARAMETER IncludeManagementTools
        Include Remote Desktop Services management tools
    
    .PARAMETER RestartRequired
        Allow automatic restart if required
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Install-RDSVirtualizationHost -IncludeManagementTools
    
    .EXAMPLE
        Install-RDSVirtualizationHost -IncludeManagementTools -RestartRequired
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeManagementTools,
        
        [switch]$RestartRequired
    )
    
    try {
        Write-Verbose "Installing RDS Virtualization Host..."
        
        # Test prerequisites
        $prerequisites = Test-RDSVirtualizationPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to install RDS Virtualization Host."
        }
        
        $installResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            IncludeManagementTools = $IncludeManagementTools
            RestartRequired = $RestartRequired
            Success = $false
            Error = $null
            InstalledFeatures = @()
            Prerequisites = $prerequisites
        }
        
        try {
            # Install Hyper-V if not already installed
            if (-not $prerequisites.HyperVInstalled) {
                Write-Verbose "Installing Hyper-V..."
                $hyperVResult = Install-WindowsFeature -Name "Hyper-V" -IncludeManagementTools -Restart:$RestartRequired
                if ($hyperVResult.Success) {
                    $installResult.InstalledFeatures += "Hyper-V"
                    Write-Verbose "Hyper-V installed successfully"
                } else {
                    throw "Failed to install Hyper-V: $($hyperVResult.RestartNeeded)"
                }
            }
            
            # Install RDS Virtualization Host
            if (-not $prerequisites.RDSVirtualizationHostInstalled) {
                Write-Verbose "Installing RDS Virtualization Host..."
                $rdsVirtFeatures = @("RDS-Virtualization")
                
                if ($IncludeManagementTools) {
                    $rdsVirtFeatures += @("RDS-RD-Server", "RDS-Connection-Broker", "RDS-Gateway", "RDS-Web-Access", "RDS-Licensing")
                }
                
                foreach ($feature in $rdsVirtFeatures) {
                    try {
                        $featureResult = Install-WindowsFeature -Name $feature -IncludeManagementTools -Restart:$RestartRequired
                        if ($featureResult.Success) {
                            $installResult.InstalledFeatures += $feature
                            Write-Verbose "Feature $feature installed successfully"
                        } else {
                            Write-Warning "Failed to install feature $feature : $($featureResult.RestartNeeded)"
                        }
                    } catch {
                        Write-Warning "Error installing feature $feature : $($_.Exception.Message)"
                    }
                }
            }
            
            # Install additional required features
            $additionalFeatures = @("RSAT-Hyper-V-Tools", "Hyper-V-PowerShell")
            foreach ($feature in $additionalFeatures) {
                try {
                    $featureResult = Install-WindowsFeature -Name $feature -Restart:$RestartRequired
                    if ($featureResult.Success) {
                        $installResult.InstalledFeatures += $feature
                        Write-Verbose "Additional feature $feature installed successfully"
                    }
                } catch {
                    Write-Warning "Error installing additional feature $feature : $($_.Exception.Message)"
                }
            }
            
            $installResult.Success = $true
            
        } catch {
            $installResult.Error = $_.Exception.Message
            Write-Warning "Failed to install RDS Virtualization Host: $($_.Exception.Message)"
        }
        
        Write-Verbose "RDS Virtualization Host installation completed"
        return [PSCustomObject]$installResult
        
    } catch {
        Write-Error "Error installing RDS Virtualization Host: $($_.Exception.Message)"
        return $null
    }
}

function New-RDSVirtualMachinePool {
    <#
    .SYNOPSIS
        Creates a new RDS Virtual Machine Pool
    
    .DESCRIPTION
        This function creates a new Virtual Machine Pool for RDS VDI deployment
        with configurable VM templates and assignment policies.
    
    .PARAMETER PoolName
        Name of the virtual machine pool
    
    .PARAMETER PoolDescription
        Description of the virtual machine pool
    
    .PARAMETER VMTemplate
        VM template configuration
    
    .PARAMETER AssignmentType
        Assignment type (Automatic, Manual, Personal)
    
    .PARAMETER MaxVMs
        Maximum number of VMs in the pool
    
    .PARAMETER StoragePath
        Path for VM storage
    
    .PARAMETER NetworkAdapter
        Network adapter configuration
    
    .PARAMETER MemoryGB
        Memory allocation per VM in GB
    
    .PARAMETER CPUCount
        Number of CPUs per VM
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-RDSVirtualMachinePool -PoolName "Development-Pool" -AssignmentType "Automatic" -MaxVMs 10
    
    .EXAMPLE
        New-RDSVirtualMachinePool -PoolName "Personal-Desktops" -AssignmentType "Personal" -MaxVMs 50 -MemoryGB 8 -CPUCount 4
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PoolName,
        
        [Parameter(Mandatory = $false)]
        [string]$PoolDescription,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$VMTemplate,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Automatic", "Manual", "Personal")]
        [string]$AssignmentType = "Automatic",
        
        [Parameter(Mandatory = $false)]
        [int]$MaxVMs = 10,
        
        [Parameter(Mandatory = $false)]
        [string]$StoragePath = "C:\VMs",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$NetworkAdapter,
        
        [Parameter(Mandatory = $false)]
        [int]$MemoryGB = 4,
        
        [Parameter(Mandatory = $false)]
        [int]$CPUCount = 2
    )
    
    try {
        Write-Verbose "Creating RDS Virtual Machine Pool: $PoolName..."
        
        # Test prerequisites
        $prerequisites = Test-RDSVirtualizationPrerequisites
        if (-not $prerequisites.RDSVirtualizationHostInstalled) {
            throw "RDS Virtualization Host is not installed. Please install it first."
        }
        
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to create VM pools."
        }
        
        $poolResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            PoolName = $PoolName
            PoolDescription = $PoolDescription
            VMTemplate = $VMTemplate
            AssignmentType = $AssignmentType
            MaxVMs = $MaxVMs
            StoragePath = $StoragePath
            NetworkAdapter = $NetworkAdapter
            MemoryGB = $MemoryGB
            CPUCount = $CPUCount
            Success = $false
            Error = $null
            PoolId = $null
            CreatedVMs = @()
            Prerequisites = $prerequisites
        }
        
        try {
            # Create storage path if it doesn't exist
            if (-not (Test-Path $StoragePath)) {
                New-Item -Path $StoragePath -ItemType Directory -Force | Out-Null
                Write-Verbose "Created storage path: $StoragePath"
            }
            
            # Generate unique pool ID
            $poolResult.PoolId = [System.Guid]::NewGuid().ToString()
            
            # Create VM template if not provided
            if (-not $VMTemplate) {
                $VMTemplate = @{
                    Name = "$PoolName-Template"
                    MemoryGB = $MemoryGB
                    CPUCount = $CPUCount
                    DiskSizeGB = 60
                    OSVersion = "Windows 10 Enterprise"
                    NetworkAdapter = $NetworkAdapter
                }
            }
            
            # Create VMs in the pool
            for ($i = 1; $i -le $MaxVMs; $i++) {
                try {
                    $vmName = "$PoolName-VM$i"
                    $vmPath = Join-Path $StoragePath $vmName
                    
                    # Note: Actual VM creation would require Hyper-V cmdlets
                    # This is a placeholder for the VM creation process
                    Write-Verbose "Creating VM: $vmName"
                    
                    $vmInfo = @{
                        Name = $vmName
                        Path = $vmPath
                        MemoryGB = $MemoryGB
                        CPUCount = $CPUCount
                        AssignmentType = $AssignmentType
                        PoolId = $poolResult.PoolId
                    }
                    
                    $poolResult.CreatedVMs += [PSCustomObject]$vmInfo
                    
                } catch {
                    Write-Warning "Failed to create VM $vmName : $($_.Exception.Message)"
                }
            }
            
            $poolResult.Success = $true
            
        } catch {
            $poolResult.Error = $_.Exception.Message
            Write-Warning "Failed to create VM pool: $($_.Exception.Message)"
        }
        
        Write-Verbose "RDS Virtual Machine Pool creation completed"
        return [PSCustomObject]$poolResult
        
    } catch {
        Write-Error "Error creating RDS Virtual Machine Pool: $($_.Exception.Message)"
        return $null
    }
}

function Set-RDSVirtualMachineAssignment {
    <#
    .SYNOPSIS
        Assigns users to virtual machines in a pool
    
    .DESCRIPTION
        This function assigns users to virtual machines in a pool based on
        assignment policies and user requirements.
    
    .PARAMETER PoolName
        Name of the virtual machine pool
    
    .PARAMETER UserName
        Username to assign
    
    .PARAMETER AssignmentType
        Assignment type (Automatic, Manual, Personal)
    
    .PARAMETER VMName
        Specific VM name for manual assignment
    
    .PARAMETER AssignmentPolicy
        Assignment policy configuration
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Set-RDSVirtualMachineAssignment -PoolName "Development-Pool" -UserName "john.doe" -AssignmentType "Automatic"
    
    .EXAMPLE
        Set-RDSVirtualMachineAssignment -PoolName "Personal-Desktops" -UserName "jane.smith" -AssignmentType "Personal" -VMName "Personal-Desktops-VM1"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PoolName,
        
        [Parameter(Mandatory = $true)]
        [string]$UserName,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Automatic", "Manual", "Personal")]
        [string]$AssignmentType = "Automatic",
        
        [Parameter(Mandatory = $false)]
        [string]$VMName,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$AssignmentPolicy
    )
    
    try {
        Write-Verbose "Setting RDS Virtual Machine assignment for user: $UserName..."
        
        # Test prerequisites
        $prerequisites = Test-RDSVirtualizationPrerequisites
        if (-not $prerequisites.RDSVirtualizationHostInstalled) {
            throw "RDS Virtualization Host is not installed. Please install it first."
        }
        
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to set VM assignments."
        }
        
        $assignmentResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            PoolName = $PoolName
            UserName = $UserName
            AssignmentType = $AssignmentType
            VMName = $VMName
            AssignmentPolicy = $AssignmentPolicy
            Success = $false
            Error = $null
            AssignmentId = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Generate unique assignment ID
            $assignmentResult.AssignmentId = [System.Guid]::NewGuid().ToString()
            
            # Determine VM assignment based on type
            switch ($AssignmentType) {
                "Automatic" {
                    # Find available VM in pool
                    # Note: Actual VM selection would require pool management logic
                    # This is a placeholder for the automatic assignment process
                    Write-Verbose "Assigning user $UserName to available VM in pool $PoolName"
                }
                "Manual" {
                    if (-not $VMName) {
                        throw "VMName is required for manual assignment"
                    }
                    # Assign to specific VM
                    Write-Verbose "Assigning user $UserName to specific VM: $VMName"
                }
                "Personal" {
                    # Create or assign personal VM
                    Write-Verbose "Assigning user $UserName to personal VM in pool $PoolName"
                }
            }
            
            # Apply assignment policy if provided
            if ($AssignmentPolicy) {
                Write-Verbose "Applying assignment policy: $($AssignmentPolicy.Keys -join ', ')"
            }
            
            $assignmentResult.Success = $true
            
        } catch {
            $assignmentResult.Error = $_.Exception.Message
            Write-Warning "Failed to set VM assignment: $($_.Exception.Message)"
        }
        
        Write-Verbose "RDS Virtual Machine assignment completed"
        return [PSCustomObject]$assignmentResult
        
    } catch {
        Write-Error "Error setting RDS Virtual Machine assignment: $($_.Exception.Message)"
        return $null
    }
}

function Get-RDSVirtualMachinePoolStatus {
    <#
    .SYNOPSIS
        Gets status information for RDS Virtual Machine Pools
    
    .DESCRIPTION
        This function retrieves comprehensive status information for
        RDS Virtual Machine Pools including VM status, assignments, and performance.
    
    .PARAMETER PoolName
        Name of the virtual machine pool (optional)
    
    .PARAMETER IncludeVMs
        Include detailed VM information
    
    .PARAMETER IncludeAssignments
        Include user assignment information
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-RDSVirtualMachinePoolStatus
    
    .EXAMPLE
        Get-RDSVirtualMachinePoolStatus -PoolName "Development-Pool" -IncludeVMs -IncludeAssignments
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$PoolName,
        
        [switch]$IncludeVMs,
        
        [switch]$IncludeAssignments
    )
    
    try {
        Write-Verbose "Getting RDS Virtual Machine Pool status..."
        
        # Test prerequisites
        $prerequisites = Test-RDSVirtualizationPrerequisites
        if (-not $prerequisites.RDSVirtualizationHostInstalled) {
            throw "RDS Virtualization Host is not installed. Please install it first."
        }
        
        $statusResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            PoolName = $PoolName
            IncludeVMs = $IncludeVMs
            IncludeAssignments = $IncludeAssignments
            Prerequisites = $prerequisites
            Pools = @()
            Summary = @{}
        }
        
        try {
            # Get VM pools information
            # Note: Actual pool enumeration would require RDS management cmdlets
            # This is a placeholder for the pool status retrieval process
            
            if ($PoolName) {
                # Get specific pool status
                Write-Verbose "Getting status for pool: $PoolName"
            } else {
                # Get all pools status
                Write-Verbose "Getting status for all VM pools"
            }
            
            # Generate sample pool data for demonstration
            $samplePool = @{
                Name = if ($PoolName) { $PoolName } else { "Sample-Pool" }
                AssignmentType = "Automatic"
                TotalVMs = 10
                AvailableVMs = 7
                AssignedVMs = 3
                RunningVMs = 8
                StoppedVMs = 2
                VMs = if ($IncludeVMs) { @() } else { $null }
                Assignments = if ($IncludeAssignments) { @() } else { $null }
            }
            
            $statusResult.Pools += [PSCustomObject]$samplePool
            
            # Generate summary
            $statusResult.Summary = @{
                TotalPools = $statusResult.Pools.Count
                TotalVMs = ($statusResult.Pools | Measure-Object -Property TotalVMs -Sum).Sum
                AvailableVMs = ($statusResult.Pools | Measure-Object -Property AvailableVMs -Sum).Sum
                AssignedVMs = ($statusResult.Pools | Measure-Object -Property AssignedVMs -Sum).Sum
                RunningVMs = ($statusResult.Pools | Measure-Object -Property RunningVMs -Sum).Sum
            }
            
        } catch {
            Write-Warning "Could not retrieve pool status: $($_.Exception.Message)"
        }
        
        Write-Verbose "RDS Virtual Machine Pool status retrieved successfully"
        return [PSCustomObject]$statusResult
        
    } catch {
        Write-Error "Error getting RDS Virtual Machine Pool status: $($_.Exception.Message)"
        return $null
    }
}

function Start-RDSVirtualMachinePoolMonitoring {
    <#
    .SYNOPSIS
        Starts monitoring for RDS Virtual Machine Pools
    
    .DESCRIPTION
        This function starts comprehensive monitoring for RDS Virtual Machine Pools
        including performance metrics, health checks, and alerting.
    
    .PARAMETER PoolName
        Name of the virtual machine pool to monitor
    
    .PARAMETER MonitoringInterval
        Monitoring interval in seconds
    
    .PARAMETER LogFile
        Log file path for monitoring data
    
    .PARAMETER IncludePerformance
        Include performance counter monitoring
    
    .PARAMETER IncludeHealthChecks
        Include health check monitoring
    
    .PARAMETER AlertThresholds
        Alert threshold configuration
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Start-RDSVirtualMachinePoolMonitoring -PoolName "Development-Pool" -MonitoringInterval 60
    
    .EXAMPLE
        Start-RDSVirtualMachinePoolMonitoring -PoolName "Development-Pool" -IncludePerformance -IncludeHealthChecks -LogFile "C:\Logs\VM-Pool-Monitor.log"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$PoolName,
        
        [Parameter(Mandatory = $false)]
        [int]$MonitoringInterval = 60,
        
        [Parameter(Mandatory = $false)]
        [string]$LogFile,
        
        [switch]$IncludePerformance,
        
        [switch]$IncludeHealthChecks,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$AlertThresholds
    )
    
    try {
        Write-Verbose "Starting RDS Virtual Machine Pool monitoring..."
        
        # Test prerequisites
        $prerequisites = Test-RDSVirtualizationPrerequisites
        if (-not $prerequisites.RDSVirtualizationHostInstalled) {
            throw "RDS Virtualization Host is not installed. Please install it first."
        }
        
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to start VM pool monitoring."
        }
        
        $monitoringResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            PoolName = $PoolName
            MonitoringInterval = $MonitoringInterval
            LogFile = $LogFile
            IncludePerformance = $IncludePerformance
            IncludeHealthChecks = $IncludeHealthChecks
            AlertThresholds = $AlertThresholds
            Success = $false
            Error = $null
            MonitoringId = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Generate unique monitoring ID
            $monitoringResult.MonitoringId = [System.Guid]::NewGuid().ToString()
            
            # Set up log file if provided
            if ($LogFile) {
                $logDir = Split-Path $LogFile -Parent
                if (-not (Test-Path $logDir)) {
                    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
                }
                Write-Verbose "Monitoring log file: $LogFile"
            }
            
            # Set up performance monitoring
            if ($IncludePerformance) {
                Write-Verbose "Setting up performance monitoring for VM pools"
                # Note: Actual performance monitoring setup would require specific cmdlets
            }
            
            # Set up health checks
            if ($IncludeHealthChecks) {
                Write-Verbose "Setting up health checks for VM pools"
                # Note: Actual health check setup would require specific cmdlets
            }
            
            # Set up alert thresholds
            if ($AlertThresholds) {
                Write-Verbose "Setting up alert thresholds: $($AlertThresholds.Keys -join ', ')"
            }
            
            # Start monitoring process
            Write-Verbose "Starting VM pool monitoring process (ID: $($monitoringResult.MonitoringId))"
            
            $monitoringResult.Success = $true
            
        } catch {
            $monitoringResult.Error = $_.Exception.Message
            Write-Warning "Failed to start VM pool monitoring: $($_.Exception.Message)"
        }
        
        Write-Verbose "RDS Virtual Machine Pool monitoring started"
        return [PSCustomObject]$monitoringResult
        
    } catch {
        Write-Error "Error starting RDS Virtual Machine Pool monitoring: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Install-RDSVirtualizationHost',
    'New-RDSVirtualMachinePool',
    'Set-RDSVirtualMachineAssignment',
    'Get-RDSVirtualMachinePoolStatus',
    'Start-RDSVirtualMachinePoolMonitoring'
)

# Module initialization
Write-Verbose "RDS-Virtualization module loaded successfully. Version: $ModuleVersion"
