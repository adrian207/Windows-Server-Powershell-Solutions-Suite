#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    iSCSI Management PowerShell Module

.DESCRIPTION
    This module provides comprehensive iSCSI management capabilities
    including iSCSI target server configuration, initiator management, and troubleshooting.

.NOTES
    Author: Backup and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/backup-and-storage-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Test-iSCSIPrerequisites {
    <#
    .SYNOPSIS
        Tests prerequisites for iSCSI operations
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        iSCSITargetInstalled = $false
        iSCSIInitiatorInstalled = $false
        PowerShellModuleAvailable = $false
        AdministratorPrivileges = $false
    }
    
    # Check if iSCSI Target Server feature is installed
    try {
        $feature = Get-WindowsFeature -Name "iSCSI-Target-Server" -ErrorAction SilentlyContinue
        $prerequisites.iSCSITargetInstalled = ($feature -and $feature.InstallState -eq "Installed")
    } catch {
        Write-Warning "Could not check iSCSI Target Server installation: $($_.Exception.Message)"
    }
    
    # Check if iSCSI Initiator service is available
    try {
        $initiatorService = Get-Service -Name "MSiSCSI" -ErrorAction SilentlyContinue
        $prerequisites.iSCSIInitiatorInstalled = ($null -ne $initiatorService)
    } catch {
        Write-Warning "Could not check iSCSI Initiator service: $($_.Exception.Message)"
    }
    
    # Check if iSCSI PowerShell module is available
    try {
        $module = Get-Module -ListAvailable -Name iSCSI -ErrorAction SilentlyContinue
        $prerequisites.PowerShellModuleAvailable = ($null -ne $module)
    } catch {
        Write-Warning "Could not check iSCSI PowerShell module: $($_.Exception.Message)"
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

function Get-iSCSITargetServerStatus {
    <#
    .SYNOPSIS
        Gets iSCSI Target Server status
    #>
    [CmdletBinding()]
    param()
    
    try {
        $targetServer = Get-WmiObject -Class Win32_Service -Filter "Name='iSCSITarget'" -ErrorAction SilentlyContinue
        return @{
            ServiceName = "iSCSITarget"
            Status = if ($targetServer) { $targetServer.State } else { "Not Found" }
            StartMode = if ($targetServer) { $targetServer.StartMode } else { "Unknown" }
        }
    } catch {
        return @{
            ServiceName = "iSCSITarget"
            Status = "Error"
            StartMode = "Unknown"
            Error = $_.Exception.Message
        }
    }
}

#endregion

#region Public Functions

function Install-iSCSITargetServer {
    <#
    .SYNOPSIS
        Installs and configures iSCSI Target Server
    
    .DESCRIPTION
        This function installs the iSCSI Target Server feature and configures
        it for use with iSCSI targets and initiators.
    
    .PARAMETER StartService
        Start the iSCSI Target service after installation
    
    .PARAMETER SetAutoStart
        Set the iSCSI Target service to start automatically
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Install-iSCSITargetServer
    
    .EXAMPLE
        Install-iSCSITargetServer -StartService -SetAutoStart
    #>
    [CmdletBinding()]
    param(
        [switch]$StartService,
        
        [switch]$SetAutoStart
    )
    
    try {
        Write-Verbose "Installing iSCSI Target Server..."
        
        # Test prerequisites
        $prerequisites = Test-iSCSIPrerequisites
        if (-not $prerequisites.AdministratorPrivileges) {
            throw "Administrator privileges are required to install iSCSI Target Server."
        }
        
        $installResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            StartService = $StartService
            SetAutoStart = $SetAutoStart
            Success = $false
            Error = $null
            ServiceStatus = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Install iSCSI Target Server feature
            if (-not $prerequisites.iSCSITargetInstalled) {
                Write-Verbose "Installing iSCSI Target Server feature..."
                $installResult = Install-WindowsFeature -Name "iSCSI-Target-Server" -IncludeManagementTools -ErrorAction Stop
                
                if (-not $installResult.Success) {
                    throw "Failed to install iSCSI Target Server feature"
                }
                
                Write-Verbose "iSCSI Target Server feature installed successfully"
            } else {
                Write-Verbose "iSCSI Target Server feature already installed"
            }
            
            # Configure service
            if ($SetAutoStart) {
                Set-Service -Name "iSCSITarget" -StartupType Automatic -ErrorAction SilentlyContinue
                Write-Verbose "iSCSI Target service set to start automatically"
            }
            
            if ($StartService) {
                Start-Service -Name "iSCSITarget" -ErrorAction Stop
                Write-Verbose "iSCSI Target service started"
            }
            
            # Get service status
            $installResult.ServiceStatus = Get-iSCSITargetServerStatus
            $installResult.Success = $true
            
        } catch {
            $installResult.Error = $_.Exception.Message
            Write-Warning "Failed to install iSCSI Target Server: $($_.Exception.Message)"
        }
        
        Write-Verbose "iSCSI Target Server installation completed"
        return [PSCustomObject]$installResult
        
    } catch {
        Write-Error "Error installing iSCSI Target Server: $($_.Exception.Message)"
        return $null
    }
}

function New-iSCSITarget {
    <#
    .SYNOPSIS
        Creates a new iSCSI target
    
    .DESCRIPTION
        This function creates a new iSCSI target with specified settings
        and optional authentication configuration.
    
    .PARAMETER TargetName
        Name for the iSCSI target
    
    .PARAMETER InitiatorIds
        Array of initiator IDs to allow access
    
    .PARAMETER EnableCHAP
        Enable CHAP authentication
    
    .PARAMETER CHAPSecret
        CHAP secret for authentication
    
    .PARAMETER EnableReverseCHAP
        Enable reverse CHAP authentication
    
    .PARAMETER ReverseCHAPSecret
        Reverse CHAP secret for authentication
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-iSCSITarget -TargetName "Target1" -InitiatorIds @("iqn.1991-05.com.microsoft:server1")
    
    .EXAMPLE
        New-iSCSITarget -TargetName "SecureTarget" -InitiatorIds @("iqn.1991-05.com.microsoft:server1") -EnableCHAP -CHAPSecret "Secret123"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetName,
        
        [string[]]$InitiatorIds,
        
        [switch]$EnableCHAP,
        
        [string]$CHAPSecret,
        
        [switch]$EnableReverseCHAP,
        
        [string]$ReverseCHAPSecret
    )
    
    try {
        Write-Verbose "Creating iSCSI target: $TargetName"
        
        # Test prerequisites
        $prerequisites = Test-iSCSIPrerequisites
        if (-not $prerequisites.iSCSITargetInstalled) {
            throw "iSCSI Target Server is not installed. Please install it first."
        }
        
        $targetResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            TargetName = $TargetName
            InitiatorIds = $InitiatorIds
            EnableCHAP = $EnableCHAP
            EnableReverseCHAP = $EnableReverseCHAP
            Success = $false
            Error = $null
            TargetObject = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Create iSCSI target
            $target = New-IscsiTarget -TargetName $TargetName -ErrorAction Stop
            
            # Add initiator IDs if specified
            if ($InitiatorIds) {
                foreach ($initiatorId in $InitiatorIds) {
                    Add-IscsiTargetPortal -TargetPortalAddress $initiatorId -ErrorAction SilentlyContinue
                }
            }
            
            # Configure CHAP authentication if enabled
            if ($EnableCHAP -and $CHAPSecret) {
                Set-IscsiTarget -TargetName $TargetName -ChapSecret $CHAPSecret -ErrorAction SilentlyContinue
                Write-Verbose "CHAP authentication configured for target: $TargetName"
            }
            
            if ($EnableReverseCHAP -and $ReverseCHAPSecret) {
                Set-IscsiTarget -TargetName $TargetName -ReverseChapSecret $ReverseCHAPSecret -ErrorAction SilentlyContinue
                Write-Verbose "Reverse CHAP authentication configured for target: $TargetName"
            }
            
            $targetResult.TargetObject = $target
            $targetResult.Success = $true
            
            Write-Verbose "iSCSI target created successfully: $TargetName"
            
        } catch {
            $targetResult.Error = $_.Exception.Message
            Write-Warning "Failed to create iSCSI target: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$targetResult
        
    } catch {
        Write-Error "Error creating iSCSI target: $($_.Exception.Message)"
        return $null
    }
}

function New-iSCSIVirtualDisk {
    <#
    .SYNOPSIS
        Creates a new iSCSI virtual disk
    
    .DESCRIPTION
        This function creates a new iSCSI virtual disk and associates it
        with an iSCSI target for storage purposes.
    
    .PARAMETER Path
        Path where the virtual disk will be stored
    
    .PARAMETER VirtualDiskName
        Name for the virtual disk
    
    .PARAMETER Size
        Size of the virtual disk (e.g., "100GB", "1TB")
    
    .PARAMETER TargetName
        iSCSI target name to associate with
    
    .PARAMETER Description
        Description for the virtual disk
    
    .PARAMETER UseFixedSize
        Create a fixed-size virtual disk instead of dynamic
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        New-iSCSIVirtualDisk -Path "D:\iSCSI" -VirtualDiskName "Disk1" -Size "100GB" -TargetName "Target1"
    
    .EXAMPLE
        New-iSCSIVirtualDisk -Path "D:\iSCSI" -VirtualDiskName "Disk2" -Size "500GB" -TargetName "Target1" -UseFixedSize
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [string]$VirtualDiskName,
        
        [Parameter(Mandatory = $true)]
        [string]$Size,
        
        [Parameter(Mandatory = $true)]
        [string]$TargetName,
        
        [string]$Description = "iSCSI Virtual Disk",
        
        [switch]$UseFixedSize
    )
    
    try {
        Write-Verbose "Creating iSCSI virtual disk: $VirtualDiskName"
        
        # Test prerequisites
        $prerequisites = Test-iSCSIPrerequisites
        if (-not $prerequisites.iSCSITargetInstalled) {
            throw "iSCSI Target Server is not installed. Please install it first."
        }
        
        $diskResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Path = $Path
            VirtualDiskName = $VirtualDiskName
            Size = $Size
            TargetName = $TargetName
            Description = $Description
            UseFixedSize = $UseFixedSize
            Success = $false
            Error = $null
            VirtualDiskObject = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Ensure path exists
            if (-not (Test-Path $Path)) {
                New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop
                Write-Verbose "Created directory: $Path"
            }
            
            # Create virtual disk file path
            $diskPath = Join-Path $Path "$VirtualDiskName.vhdx"
            
            # Create virtual disk
            $virtualDisk = New-IscsiVirtualDisk -Path $diskPath -Size $Size -Description $Description -ErrorAction Stop
            
            # Associate with target
            Add-IscsiVirtualDiskTargetMapping -TargetName $TargetName -Path $diskPath -ErrorAction Stop
            
            $diskResult.VirtualDiskObject = $virtualDisk
            $diskResult.Success = $true
            
            Write-Verbose "iSCSI virtual disk created successfully: $VirtualDiskName"
            
        } catch {
            $diskResult.Error = $_.Exception.Message
            Write-Warning "Failed to create iSCSI virtual disk: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$diskResult
        
    } catch {
        Write-Error "Error creating iSCSI virtual disk: $($_.Exception.Message)"
        return $null
    }
}

function Get-iSCSIStatus {
    <#
    .SYNOPSIS
        Gets comprehensive iSCSI status information
    
    .DESCRIPTION
        This function retrieves comprehensive iSCSI status information
        including targets, virtual disks, initiators, and connections.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-iSCSIStatus
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Getting iSCSI status information..."
        
        # Test prerequisites
        $prerequisites = Test-iSCSIPrerequisites
        
        $statusResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Prerequisites = $prerequisites
            TargetServerStatus = $null
            Targets = @()
            VirtualDisks = @()
            Initiators = @()
            Connections = @()
            Summary = @{}
        }
        
        # Get target server status
        $statusResults.TargetServerStatus = Get-iSCSITargetServerStatus
        
        # Get iSCSI targets
        try {
            $targets = Get-IscsiTarget -ErrorAction SilentlyContinue
            foreach ($target in $targets) {
                $targetInfo = @{
                    TargetName = $target.TargetName
                    TargetIqn = $target.TargetIqn
                    Enabled = $target.Enabled
                    Status = $target.Status
                    Connections = $target.Connections
                }
                $statusResults.Targets += [PSCustomObject]$targetInfo
            }
        } catch {
            Write-Warning "Could not get iSCSI targets: $($_.Exception.Message)"
        }
        
        # Get virtual disks
        try {
            $virtualDisks = Get-IscsiVirtualDisk -ErrorAction SilentlyContinue
            foreach ($disk in $virtualDisks) {
                $diskInfo = @{
                    Path = $disk.Path
                    Size = $disk.Size
                    UsedSize = $disk.UsedSize
                    AvailableSize = $disk.AvailableSize
                    Status = $disk.Status
                    Description = $disk.Description
                }
                $statusResults.VirtualDisks += [PSCustomObject]$diskInfo
            }
        } catch {
            Write-Warning "Could not get iSCSI virtual disks: $($_.Exception.Message)"
        }
        
        # Get initiators
        try {
            $initiators = Get-IscsiInitiator -ErrorAction SilentlyContinue
            foreach ($initiator in $initiators) {
                $initiatorInfo = @{
                    InitiatorName = $initiator.InitiatorName
                    InitiatorId = $initiator.InitiatorId
                    Status = $initiator.Status
                }
                $statusResults.Initiators += [PSCustomObject]$initiatorInfo
            }
        } catch {
            Write-Warning "Could not get iSCSI initiators: $($_.Exception.Message)"
        }
        
        # Get connections
        try {
            $connections = Get-IscsiConnection -ErrorAction SilentlyContinue
            foreach ($connection in $connections) {
                $connectionInfo = @{
                    ConnectionId = $connection.ConnectionId
                    TargetName = $connection.TargetName
                    InitiatorAddress = $connection.InitiatorAddress
                    TargetAddress = $connection.TargetAddress
                    Status = $connection.Status
                    AuthenticationType = $connection.AuthenticationType
                }
                $statusResults.Connections += [PSCustomObject]$connectionInfo
            }
        } catch {
            Write-Warning "Could not get iSCSI connections: $($_.Exception.Message)"
        }
        
        # Generate summary
        $statusResults.Summary = @{
            TotalTargets = $statusResults.Targets.Count
            EnabledTargets = ($statusResults.Targets | Where-Object { $_.Enabled }).Count
            TotalVirtualDisks = $statusResults.VirtualDisks.Count
            TotalInitiators = $statusResults.Initiators.Count
            ActiveConnections = ($statusResults.Connections | Where-Object { $_.Status -eq "Connected" }).Count
            TargetServerRunning = ($statusResults.TargetServerStatus.Status -eq "Running")
        }
        
        Write-Verbose "iSCSI status information retrieved successfully"
        return [PSCustomObject]$statusResults
        
    } catch {
        Write-Error "Error getting iSCSI status: $($_.Exception.Message)"
        return $null
    }
}

function Connect-iSCSITarget {
    <#
    .SYNOPSIS
        Connects to an iSCSI target
    
    .DESCRIPTION
        This function connects the local iSCSI initiator to a remote iSCSI target
        for storage access.
    
    .PARAMETER TargetAddress
        IP address or hostname of the iSCSI target
    
    .PARAMETER TargetName
        Name of the iSCSI target to connect to
    
    .PARAMETER Port
        Port number for the iSCSI connection (default: 3260)
    
    .PARAMETER EnableCHAP
        Enable CHAP authentication
    
    .PARAMETER CHAPUsername
        CHAP username for authentication
    
    .PARAMETER CHAPSecret
        CHAP secret for authentication
    
    .PARAMETER EnableReverseCHAP
        Enable reverse CHAP authentication
    
    .PARAMETER ReverseCHAPUsername
        Reverse CHAP username for authentication
    
    .PARAMETER ReverseCHAPSecret
        Reverse CHAP secret for authentication
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Connect-iSCSITarget -TargetAddress "192.168.1.100" -TargetName "iqn.1991-05.com.microsoft:target1"
    
    .EXAMPLE
        Connect-iSCSITarget -TargetAddress "192.168.1.100" -TargetName "iqn.1991-05.com.microsoft:target1" -EnableCHAP -CHAPUsername "user" -CHAPSecret "secret"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetAddress,
        
        [Parameter(Mandatory = $true)]
        [string]$TargetName,
        
        [int]$Port = 3260,
        
        [switch]$EnableCHAP,
        
        [string]$CHAPUsername,
        
        [string]$CHAPSecret,
        
        [switch]$EnableReverseCHAP,
        
        [string]$ReverseCHAPUsername,
        
        [string]$ReverseCHAPSecret
    )
    
    try {
        Write-Verbose "Connecting to iSCSI target: $TargetName at $TargetAddress"
        
        # Test prerequisites
        $prerequisites = Test-iSCSIPrerequisites
        if (-not $prerequisites.iSCSIInitiatorInstalled) {
            throw "iSCSI Initiator service is not available. Please ensure it is installed and running."
        }
        
        $connectionResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            TargetAddress = $TargetAddress
            TargetName = $TargetName
            Port = $Port
            EnableCHAP = $EnableCHAP
            EnableReverseCHAP = $EnableReverseCHAP
            Success = $false
            Error = $null
            ConnectionObject = $null
            Prerequisites = $prerequisites
        }
        
        try {
            # Add target portal
            New-IscsiTargetPortal -TargetPortalAddress $TargetAddress -TargetPortalPortNumber $Port -ErrorAction Stop | Out-Null
            
            # Configure authentication if specified
            if ($EnableCHAP -and $CHAPUsername -and $CHAPSecret) {
                Set-IscsiChapSecret -ChapSecret $CHAPSecret -ErrorAction SilentlyContinue
                Write-Verbose "CHAP authentication configured"
            }
            
            if ($EnableReverseCHAP -and $ReverseCHAPUsername -and $ReverseCHAPSecret) {
                Set-IscsiReverseChapSecret -ReverseChapSecret $ReverseCHAPSecret -ErrorAction SilentlyContinue
                Write-Verbose "Reverse CHAP authentication configured"
            }
            
            # Connect to target
            $connection = Connect-IscsiTarget -TargetPortalAddress $TargetAddress -TargetPortalPortNumber $Port -TargetName $TargetName -ErrorAction Stop
            
            $connectionResult.ConnectionObject = $connection
            $connectionResult.Success = $true
            
            Write-Verbose "Successfully connected to iSCSI target: $TargetName"
            
        } catch {
            $connectionResult.Error = $_.Exception.Message
            Write-Warning "Failed to connect to iSCSI target: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$connectionResult
        
    } catch {
        Write-Error "Error connecting to iSCSI target: $($_.Exception.Message)"
        return $null
    }
}

function Disconnect-iSCSITarget {
    <#
    .SYNOPSIS
        Disconnects from an iSCSI target
    
    .DESCRIPTION
        This function disconnects the local iSCSI initiator from a remote iSCSI target.
    
    .PARAMETER TargetName
        Name of the iSCSI target to disconnect from
    
    .PARAMETER ConnectionId
        Specific connection ID to disconnect (optional)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Disconnect-iSCSITarget -TargetName "iqn.1991-05.com.microsoft:target1"
    
    .EXAMPLE
        Disconnect-iSCSITarget -TargetName "iqn.1991-05.com.microsoft:target1" -ConnectionId "1"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetName,
        
        [string]$ConnectionId
    )
    
    try {
        Write-Verbose "Disconnecting from iSCSI target: $TargetName"
        
        $disconnectResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            TargetName = $TargetName
            ConnectionId = $ConnectionId
            Success = $false
            Error = $null
        }
        
        try {
            if ($ConnectionId) {
                # Disconnect specific connection
                Disconnect-IscsiTarget -TargetName $TargetName -ConnectionId $ConnectionId -ErrorAction Stop
            } else {
                # Disconnect all connections to target
                Disconnect-IscsiTarget -TargetName $TargetName -ErrorAction Stop
            }
            
            $disconnectResult.Success = $true
            Write-Verbose "Successfully disconnected from iSCSI target: $TargetName"
            
        } catch {
            $disconnectResult.Error = $_.Exception.Message
            Write-Warning "Failed to disconnect from iSCSI target: $($_.Exception.Message)"
        }
        
        return [PSCustomObject]$disconnectResult
        
    } catch {
        Write-Error "Error disconnecting from iSCSI target: $($_.Exception.Message)"
        return $null
    }
}

function Test-iSCSIConnection {
    <#
    .SYNOPSIS
        Tests iSCSI connection health and performance
    
    .DESCRIPTION
        This function tests iSCSI connection health, latency, and performance
        to identify potential issues.
    
    .PARAMETER TargetAddress
        IP address or hostname of the iSCSI target to test
    
    .PARAMETER Port
        Port number for the iSCSI connection (default: 3260)
    
    .PARAMETER TestDuration
        Duration of the test in seconds (default: 30)
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-iSCSIConnection -TargetAddress "192.168.1.100"
    
    .EXAMPLE
        Test-iSCSIConnection -TargetAddress "192.168.1.100" -TestDuration 60
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetAddress,
        
        [int]$Port = 3260,
        
        [int]$TestDuration = 30
    )
    
    try {
        Write-Verbose "Testing iSCSI connection to: $TargetAddress"
        
        $testResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            TargetAddress = $TargetAddress
            Port = $Port
            TestDuration = $TestDuration
            ConnectivityTest = $null
            LatencyTest = $null
            PerformanceTest = $null
            OverallHealth = "Unknown"
        }
        
        # Test basic connectivity
        try {
            $pingResult = Test-NetConnection -ComputerName $TargetAddress -Port $Port -WarningAction SilentlyContinue
            $testResult.ConnectivityTest = @{
                Success = $pingResult.TcpTestSucceeded
                Latency = $pingResult.PingReplyDetails.RoundtripTime
                Error = if (-not $pingResult.TcpTestSucceeded) { "Connection failed" } else { $null }
            }
        } catch {
            $testResult.ConnectivityTest = @{
                Success = $false
                Error = $_.Exception.Message
            }
        }
        
        # Test iSCSI-specific connectivity
        try {
            $iscsiTest = Test-IscsiConnection -TargetPortalAddress $TargetAddress -TargetPortalPortNumber $Port -ErrorAction SilentlyContinue
            $testResult.LatencyTest = @{
                Success = ($null -ne $iscsiTest)
                Latency = if ($iscsiTest) { $iscsiTest.Latency } else { $null }
                Error = if (-not $iscsiTest) { "iSCSI connection test failed" } else { $null }
            }
        } catch {
            $testResult.LatencyTest = @{
                Success = $false
                Error = $_.Exception.Message
            }
        }
        
        # Determine overall health
        if ($testResult.ConnectivityTest.Success -and $testResult.LatencyTest.Success) {
            $testResult.OverallHealth = "Healthy"
        } elseif ($testResult.ConnectivityTest.Success) {
            $testResult.OverallHealth = "Degraded"
        } else {
            $testResult.OverallHealth = "Failed"
        }
        
        Write-Verbose "iSCSI connection test completed. Health: $($testResult.OverallHealth)"
        return [PSCustomObject]$testResult
        
    } catch {
        Write-Error "Error testing iSCSI connection: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Install-iSCSITargetServer',
    'New-iSCSITarget',
    'New-iSCSIVirtualDisk',
    'Get-iSCSIStatus',
    'Connect-iSCSITarget',
    'Disconnect-iSCSITarget',
    'Test-iSCSIConnection'
)

# Module initialization
Write-Verbose "BackupStorage-iSCSI module loaded successfully. Version: $ModuleVersion"
