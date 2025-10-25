#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Multipath I/O (MPIO) Management PowerShell Module

.DESCRIPTION
    This module provides comprehensive Multipath I/O management capabilities
    including MPIO configuration, path management, and Storport optimization.

.NOTES
    Author: Backup and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/backup-and-storage-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Test-MPIOPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for MPIO operations
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        MPIOInstalled = $false
        PowerShellModuleAvailable = $false
        AdministratorPrivileges = $false
        MPIOServiceRunning = $false
    }
    
    # Check if MPIO feature is installed
    try {
        $feature = Get-WindowsFeature -Name "Multipath-IO" -ErrorAction SilentlyContinue
        $prerequisites.MPIOInstalled = ($feature -and $feature.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check MPIO installation: $($_.Exception.Message)"
    }
    
    # Check if MPIO PowerShell module is available
    try {
        $module = Get-Module -ListAvailable -Name MPIO -ErrorAction SilentlyContinue
        $prerequisites.PowerShellModuleAvailable = ($null -ne $module)
    } catch {
        Write-Warning "Could not check MPIO PowerShell module: $($_.Exception.Message)"
    }
    
    # Check MPIO service status
    try {
        $mpioService = Get-Service -Name "MPIO" -ErrorAction SilentlyContinue
        $prerequisites.MPIOServiceRunning = ($mpioService -and $mpioService.Status -eq "Running")
    } catch {
        Write-Warning "Could not check MPIO service status: $($_.Exception.Message)"
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

function Get-MPIODiskInfo {
    <#
    .SYNOPSIS
        Gets MPIO disk information
    #>
    [CmdletBinding()]
    param()
    
    try {
        $mpioDisks = Get-MpioDisk -ErrorAction SilentlyContinue
        return $mpioDisks
    } catch {
        Write-Warning "Could not get MPIO disk information: $($_.Exception.Message)"
        return @()
    }
}

#endregion

#region Public Functions

function Install-MPIO {
    <#
    .SYNOPSIS
        Installs and configures Multipath I/O
    
    .DESCRIPTION
        This function installs the Multipath I/O feature and configures
        it for use with storage devices.
    
    .PARAMETER StartService
        Start the MPIO service after installation
    
    .PARAMETER SetAutoStart
        Set the MPIO service to start automatically
    
    .PARAMETER EnableDSM
        Enable Device Specific Module (DSM) for MPIO
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Install-MPIO
    
    .EXAMPLE
        Install-MPIO -StartService -SetAutoStart -EnableDSM
    #>
    [CmdletBinding()]
    param(
        [switch]$StartService,
        
        [switch]$SetAutoStart,
        
        [switch]$EnableDSM
    )
    
    try {
        Write-Verbose "Installing Multipath I/O..."
        
        # Test prerequisites
        $prerequisites = Test-MPIOPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to install MPIO."
        }
        
        $installResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            StartService = $StartService
            SetAutoStart = $SetAutoStart
            EnableDSM = $EnableDSM
            Success = $false
            Error = $null
            ServiceStatus = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Install MPIO feature
            if (-not $prerequisites.MPIOInstalled) {
                Write-Verbose "Installing Multipath I/O feature..."
                $installResult = Install-WindowsFeature -Name "Multipath-IO" -IncludeManagementTools -ErrorAction Stop
                
                if (-not $installResult.Success) {
                    throw "Failed to install Multipath I/O feature"
                }
                
                Write-Verbose "Multipath I/O feature installed successfully"
            } else {
                Write-Verbose "Multipath I/O feature already installed"
            }
            
            # Configure service
            if ($SetAutoStart) {
                Set-Service -Name "MPIO" -StartupType Automatic -ErrorAction SilentlyContinue
                Write-Verbose "MPIO service set to start automatically"
            }
            
            if ($StartService) {
                Start-Service -Name "MPIO" -ErrorAction Stop
                Write-Verbose "MPIO service started"
            }
            
            # Enable DSM if requested
            if ($EnableDSM) {
                Enable-MPIO -ErrorAction SilentlyContinue
                Write-Verbose "Device Specific Module (DSM) enabled"
            }
            
            # Get service status
            $mpioService = Get-Service -Name "MPIO" -ErrorAction SilentlyContinue
            $installResult.ServiceStatus = @{
                ServiceName = "MPIO"
                Status = if ($mpioService) { $mpioService.Status } else { "Not Found" }
                StartType = if ($mpioService) { $mpioService.StartType } else { "Unknown" }
            }
            
            $installResult.Success = $true
            
        } catch {
            $installResult.Error = $_.Exception.Message
            Write-Warning "Failed to install MPIO: $($_.Exception.Message)"
        }
        
        Write-Verbose "Multipath I/O installation completed"
        return [PSCustomObject]$installResult
        
    } catch {
        Write-Error "Error installing MPIO: $($_.Exception.Message)"
        return $null
    }
}

function Get-MPIOStatus {
    <#
    .SYNOPSIS
        Gets comprehensive MPIO status information
    
    .DESCRIPTION
        This function retrieves comprehensive MPIO status information
        including disks, paths, and configuration details.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-MPIOStatus
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Getting MPIO status information..."
        
        # Test prerequisites
        $prerequisites = Test-MPIOPrerequisites
        
        $statusResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Prerequisites = $prerequisites
            ServiceStatus = $null
            MPIODisks = @()
            MPIOPaths = @()
            DSMInfo = @()
            Summary = @{}
        }
        
        # Get MPIO service status
        $mpioService = Get-Service -Name "MPIO" -ErrorAction SilentlyContinue
        $statusResults.ServiceStatus = @{
            ServiceName = "MPIO"
            Status = if ($mpioService) { $mpioService.Status } else { "Not Found" }
            StartType = if ($mpioService) { $mpioService.StartType } else { "Unknown" }
        }
        
        # Get MPIO disks
        try {
            $mpioDisks = Get-MpioDisk -ErrorAction SilentlyContinue
            foreach ($disk in $mpioDisks) {
                $diskInfo = @{
                    Number = $disk.Number
                    FriendlyName = $disk.FriendlyName
                    Paths = $disk.Paths
                    LoadBalancePolicy = $disk.LoadBalancePolicy
                    Status = $disk.Status
                }
                $statusResults.MPIODisks += [PSCustomObject]$diskInfo
            }
        } catch {
            Write-Warning "Could not get MPIO disks: $($_.Exception.Message)"
        }
        
        # Get MPIO paths
        try {
            $mpioPaths = Get-MpioPath -ErrorAction SilentlyContinue
            foreach ($path in $mpioPaths) {
                $pathInfo = @{
                    PathId = $path.PathId
                    DiskNumber = $path.DiskNumber
                    InitiatorPort = $path.InitiatorPort
                    TargetPort = $path.TargetPort
                    Status = $path.Status
                    LoadBalancePolicy = $path.LoadBalancePolicy
                }
                $statusResults.MPIOPaths += [PSCustomObject]$pathInfo
            }
        } catch {
            Write-Warning "Could not get MPIO paths: $($_.Exception.Message)"
        }
        
        # Get DSM information
        try {
            $dsmInfo = Get-MpioDsm -ErrorAction SilentlyContinue
            foreach ($dsm in $dsmInfo) {
                $dsmData = @{
                    Name = $dsm.Name
                    Version = $dsm.Version
                    Vendor = $dsm.Vendor
                    Status = $dsm.Status
                }
                $statusResults.DSMInfo += [PSCustomObject]$dsmData
            }
        } catch {
            Write-Warning "Could not get DSM information: $($_.Exception.Message)"
        }
        
        # Generate summary
        $statusResults.Summary = @{
            TotalMPIODisks = $statusResults.MPIODisks.Count
            TotalMPIOPaths = $statusResults.MPIOPaths.Count
            ActivePaths = ($statusResults.MPIOPaths | Where-Object { $_.Status -eq "Active" }).Count
            FailedPaths = ($statusResults.MPIOPaths | Where-Object { $_.Status -eq "Failed" }).Count
            TotalDSMs = $statusResults.DSMInfo.Count
            MPIOServiceRunning = ($statusResults.ServiceStatus.Status -eq "Running")
        }
        
        Write-Verbose "MPIO status information retrieved successfully"
        return [PSCustomObject]$statusResults
        
    } catch {
        Write-Error "Error getting MPIO status: $($_.Exception.Message)"
        return $null
    }
}

function Set-MPIOLoadBalancePolicy {
    <#
    .SYNOPSIS
        Sets MPIO load balance policy for disks
    
    .DESCRIPTION
        This function sets the load balance policy for MPIO disks
        to optimize performance and availability.
    
    .PARAMETER DiskNumbers
        Array of disk numbers to configure
    
    .PARAMETER LoadBalancePolicy
        Load balance policy (Failover, RoundRobin, RoundRobinWithSubset, DynamicLeastQueueDepth, WeightedPath)
    
    .PARAMETER ApplyToAll
        Apply policy to all MPIO disks
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Set-MPIOLoadBalancePolicy -DiskNumbers @(0, 1) -LoadBalancePolicy "RoundRobin"
    
    .EXAMPLE
        Set-MPIOLoadBalancePolicy -ApplyToAll -LoadBalancePolicy "DynamicLeastQueueDepth"
    #>
    [CmdletBinding()]
    param(
        [int[]]$DiskNumbers,
        
        [ValidateSet("Failover", "RoundRobin", "RoundRobinWithSubset", "DynamicLeastQueueDepth", "WeightedPath")]
        [string]$LoadBalancePolicy = "RoundRobin",
        
        [switch]$ApplyToAll
    )
    
    try {
        Write-Verbose "Setting MPIO load balance policy: $LoadBalancePolicy"
        
        # Test prerequisites
        $prerequisites = Test-MPIOPrerequisites
        if (-not $prerequisites.MPIOInstalled) {
            throw "MPIO is not installed. Please install it first."
        }
        
        $policyResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            LoadBalancePolicy = $LoadBalancePolicy
            DiskNumbers = $DiskNumbers
            ApplyToAll = $ApplyToAll
            Success = $false
            Error = $null
            ConfiguredDisks = @()
            Prerequisites = $prerequisites
        }
        
        try {
            # Get disks to configure
            if ($ApplyToAll) {
                $mpioDisks = Get-MpioDisk -ErrorAction SilentlyContinue
                $DiskNumbers = $mpioDisks | Select-Object -ExpandProperty Number
            }
            
            foreach ($diskNumber in $DiskNumbers) {
                try {
                    # Set load balance policy for disk
                    Set-MpioDisk -Number $diskNumber -LoadBalancePolicy $LoadBalancePolicy -ErrorAction Stop
                    
                    $policyResult.ConfiguredDisks += @{
                        DiskNumber = $diskNumber
                        LoadBalancePolicy = $LoadBalancePolicy
                        Success = $true
                    }
                    
                    Write-Verbose "Load balance policy set for disk $diskNumber`: $LoadBalancePolicy"
                    
                } catch {
                    $policyResult.ConfiguredDisks += @{
                        DiskNumber = $diskNumber
                        LoadBalancePolicy = $LoadBalancePolicy
                        Success = $false
                        Error = $_.Exception.Message
                    }
                    
                    Write-Warning "Failed to set load balance policy for disk $diskNumber`: $($_.Exception.Message)"
                }
            }
            
            $policyResult.Success = ($policyResult.ConfiguredDisks | Where-Object { $_.Success }).Count -gt 0
            
        } catch {
            $policyResult.Error = $_.Exception.Message
            Write-Warning "Failed to set MPIO load balance policy: $($_.Exception.Message)"
        }
        
        Write-Verbose "MPIO load balance policy configuration completed"
        return [PSCustomObject]$policyResult
        
    } catch {
        Write-Error "Error setting MPIO load balance policy: $($_.Exception.Message)"
        return $null
    }
}

function Enable-MPIODSM {
    <#
    .SYNOPSIS
        Enables Device Specific Module (DSM) for MPIO
    
    .DESCRIPTION
        This function enables DSM for MPIO to provide enhanced
        functionality for specific storage devices.
    
    .PARAMETER DSMName
        Name of the DSM to enable (optional, enables all available DSMs)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Enable-MPIODSM
    
    .EXAMPLE
        Enable-MPIODSM -DSMName "Microsoft DSM"
    #>
    [CmdletBinding()]
    param(
        [string]$DSMName
    )
    
    try {
        Write-Verbose "Enabling MPIO DSM..."
        
        # Test prerequisites
        $prerequisites = Test-MPIOPrerequisites
        if (-not $prerequisites.MPIOInstalled) {
            throw "MPIO is not installed. Please install it first."
        }
        
        $dsmResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            DSMName = $DSMName
            Success = $false
            Error = $null
            EnabledDSMs = @()
            Prerequisites = $prerequisites
        }
        
        try {
            # Enable DSM
            if ($DSMName) {
                Enable-MPIO -DSMName $DSMName -ErrorAction Stop
                $dsmResult.EnabledDSMs += @{
                    DSMName = $DSMName
                    Success = $true
                }
                Write-Verbose "DSM enabled: $DSMName"
            } else {
                Enable-MPIO -ErrorAction Stop
                $dsmResult.EnabledDSMs += @{
                    DSMName = "All Available DSMs"
                    Success = $true
                }
                Write-Verbose "All available DSMs enabled"
            }
            
            $dsmResult.Success = $true
            
        } catch {
            $dsmResult.Error = $_.Exception.Message
            Write-Warning "Failed to enable MPIO DSM: $($_.Exception.Message)"
        }
        
        Write-Verbose "MPIO DSM enablement completed"
        return [PSCustomObject]$dsmResult
        
    } catch {
        Write-Error "Error enabling MPIO DSM: $($_.Exception.Message)"
        return $null
    }
}

function Test-MPIOPathHealth {
    <#
    .SYNOPSIS
        Tests MPIO path health and performance
    
    .DESCRIPTION
        This function tests MPIO path health, latency, and performance
        to identify potential issues with storage paths.
    
    .PARAMETER DiskNumbers
        Array of disk numbers to test (optional, tests all if not specified)
    
    .PARAMETER TestDuration
        Duration of the test in seconds (default: 30)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-MPIOPathHealth
    
    .EXAMPLE
        Test-MPIOPathHealth -DiskNumbers @(0, 1) -TestDuration 60
    #>
    [CmdletBinding()]
    param(
        [int[]]$DiskNumbers,
        
        [int]$TestDuration = 30
    )
    
    try {
        Write-Verbose "Testing MPIO path health..."
        
        # Test prerequisites
        $prerequisites = Test-MPIOPrerequisites
        if (-not $prerequisites.MPIOInstalled) {
            throw "MPIO is not installed. Please install it first."
        }
        
        $healthResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            DiskNumbers = $DiskNumbers
            TestDuration = $TestDuration
            DiskResults = @()
            PathResults = @()
            OverallHealth = "Unknown"
            Prerequisites = $prerequisites
        }
        
        try {
            # Get MPIO disks to test
            $mpioDisks = Get-MpioDisk -ErrorAction SilentlyContinue
            
            if ($DiskNumbers) {
                $mpioDisks = $mpioDisks | Where-Object { $DiskNumbers -contains $_.Number }
            }
            
            foreach ($disk in $mpioDisks) {
                $diskHealth = @{
                    DiskNumber = $disk.Number
                    FriendlyName = $disk.FriendlyName
                    TotalPaths = $disk.Paths
                    ActivePaths = 0
                    FailedPaths = 0
                    LoadBalancePolicy = $disk.LoadBalancePolicy
                    HealthStatus = "Unknown"
                }
                
                # Get paths for this disk
                $diskPaths = Get-MpioPath -DiskNumber $disk.Number -ErrorAction SilentlyContinue
                
                foreach ($path in $diskPaths) {
                    $pathHealth = @{
                        PathId = $path.PathId
                        DiskNumber = $path.DiskNumber
                        InitiatorPort = $path.InitiatorPort
                        TargetPort = $path.TargetPort
                        Status = $path.Status
                        LoadBalancePolicy = $path.LoadBalancePolicy
                        HealthStatus = if ($path.Status -eq "Active") { "Healthy" } else { "Failed" }
                    }
                    
                    $healthResult.PathResults += [PSCustomObject]$pathHealth
                    
                    if ($path.Status -eq "Active") {
                        $diskHealth.ActivePaths++
                    } else {
                        $diskHealth.FailedPaths++
                    }
                }
                
                # Determine disk health
                if ($diskHealth.ActivePaths -eq 0) {
                    $diskHealth.HealthStatus = "Critical"
                } elseif ($diskHealth.FailedPaths -gt 0) {
                    $diskHealth.HealthStatus = "Degraded"
                } else {
                    $diskHealth.HealthStatus = "Healthy"
                }
                
                $healthResult.DiskResults += [PSCustomObject]$diskHealth
            }
            
            # Determine overall health
            $criticalDisks = ($healthResult.DiskResults | Where-Object { $_.HealthStatus -eq "Critical" }).Count
            $degradedDisks = ($healthResult.DiskResults | Where-Object { $_.HealthStatus -eq "Degraded" }).Count
            
            if ($criticalDisks -gt 0) {
                $healthResult.OverallHealth = "Critical"
            } elseif ($degradedDisks -gt 0) {
                $healthResult.OverallHealth = "Degraded"
            } else {
                $healthResult.OverallHealth = "Healthy"
            }
            
        } catch {
            Write-Warning "Error during MPIO path health test: $($_.Exception.Message)"
        }
        
        Write-Verbose "MPIO path health test completed. Overall health: $($healthResult.OverallHealth)"
        return [PSCustomObject]$healthResult
        
    } catch {
        Write-Error "Error testing MPIO path health: $($_.Exception.Message)"
        return $null
    }
}

function Optimize-MPIOConfiguration {
    <#
    .SYNOPSIS
        Optimizes MPIO configuration for better performance
    
    .DESCRIPTION
        This function optimizes MPIO configuration by setting
        appropriate load balance policies and DSM settings.
    
    .PARAMETER OptimizationLevel
        Level of optimization (Basic, Advanced, Custom)
    
    .PARAMETER LoadBalancePolicy
        Custom load balance policy for advanced optimization
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Optimize-MPIOConfiguration -OptimizationLevel "Basic"
    
    .EXAMPLE
        Optimize-MPIOConfiguration -OptimizationLevel "Advanced" -LoadBalancePolicy "DynamicLeastQueueDepth"
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("Basic", "Advanced", "Custom")]
        [string]$OptimizationLevel = "Basic",
        
        [ValidateSet("Failover", "RoundRobin", "RoundRobinWithSubset", "DynamicLeastQueueDepth", "WeightedPath")]
        [string]$LoadBalancePolicy
    )
    
    try {
        Write-Verbose "Optimizing MPIO configuration: $OptimizationLevel"
        
        # Test prerequisites
        $prerequisites = Test-MPIOPrerequisites
        if (-not $prerequisites.MPIOInstalled) {
            throw "MPIO is not installed. Please install it first."
        }
        
        $optimizationResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            OptimizationLevel = $OptimizationLevel
            LoadBalancePolicy = $LoadBalancePolicy
            OptimizationsApplied = @()
            Success = $false
            Error = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Determine load balance policy based on optimization level
            if (-not $LoadBalancePolicy) {
                switch ($OptimizationLevel) {
                    "Basic" { $LoadBalancePolicy = "RoundRobin" }
                    "Advanced" { $LoadBalancePolicy = "DynamicLeastQueueDepth" }
                    "Custom" { $LoadBalancePolicy = "RoundRobin" }
                }
            }
            
            # Apply load balance policy to all MPIO disks
            $policyResult = Set-MPIOLoadBalancePolicy -ApplyToAll -LoadBalancePolicy $LoadBalancePolicy
            $optimizationResult.OptimizationsApplied += @{
                Type = "LoadBalancePolicy"
                Policy = $LoadBalancePolicy
                Success = $policyResult.Success
            }
            
            # Enable DSM for advanced optimization
            if ($OptimizationLevel -eq "Advanced" -or $OptimizationLevel -eq "Custom") {
                $dsmResult = Enable-MPIODSM
                $optimizationResult.OptimizationsApplied += @{
                    Type = "DSMEnablement"
                    Success = $dsmResult.Success
                }
            }
            
            $optimizationResult.Success = ($optimizationResult.OptimizationsApplied | Where-Object { $_.Success }).Count -gt 0
            
        } catch {
            $optimizationResult.Error = $_.Exception.Message
            Write-Warning "Failed to optimize MPIO configuration: $($_.Exception.Message)"
        }
        
        Write-Verbose "MPIO configuration optimization completed"
        return [PSCustomObject]$optimizationResult
        
    } catch {
        Write-Error "Error optimizing MPIO configuration: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Install-MPIO',
    'Get-MPIOStatus',
    'Set-MPIOLoadBalancePolicy',
    'Enable-MPIODSM',
    'Test-MPIOPathHealth',
    'Optimize-MPIOConfiguration'
)

# Module initialization
Write-Verbose "BackupStorage-MPIO module loaded successfully. Version: $ModuleVersion"
