#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Core File and Storage Services PowerShell Module

.DESCRIPTION
    This module provides core functions for Windows File and Storage Services operations
    including file server management, storage operations, and basic diagnostics.

.NOTES
    Author: File and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Module metadata
$ModuleVersion = "1.0.0"

# Import required modules
try {
    Import-Module FileServer -ErrorAction SilentlyContinue
    Import-Module Storage -ErrorAction SilentlyContinue
    Import-Module Deduplication -ErrorAction SilentlyContinue
    Import-Module SmbShare -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Some optional modules not available. Some functions may not work properly."
}

#region Private Functions

function Test-FileStoragePrerequisites {
    <#
    .SYNOPSIS
        Tests if the system meets File and Storage Services prerequisites
    
    .DESCRIPTION
        Checks Windows version, PowerShell version, required features, and permissions
    
    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        WindowsVersion = $false
        PowerShellVersion = $false
        RequiredFeatures = $false
        Permissions = $false
    }
    
    try {
        # Check Windows version (Server 2016+)
        $osVersion = [System.Environment]::OSVersion.Version
        if ($osVersion.Major -ge 10) {
            $prerequisites.WindowsVersion = $true
            Write-Verbose "Windows version check passed: $($osVersion.ToString())"
        } else {
            Write-Warning "Windows Server 2016 or later required. Current: $($osVersion.ToString())"
        }
        
        # Check PowerShell version (5.1+)
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            $prerequisites.PowerShellVersion = $true
            Write-Verbose "PowerShell version check passed: $($PSVersionTable.PSVersion.ToString())"
        } else {
            Write-Warning "PowerShell 5.1 or later required. Current: $($PSVersionTable.PSVersion.ToString())"
        }
        
        # Check required Windows features
        $requiredFeatures = @('FileAndStorage-Services', 'FS-FileServer', 'FS-SMB1', 'FS-SMB2')
        $installedFeatures = Get-WindowsFeature | Where-Object { $_.InstallState -eq 'Installed' }
        
        $missingFeatures = @()
        foreach ($feature in $requiredFeatures) {
            if ($installedFeatures.Name -notcontains $feature) {
                $missingFeatures += $feature
            }
        }
        
        if ($missingFeatures.Count -eq 0) {
            $prerequisites.RequiredFeatures = $true
            Write-Verbose "Required Windows features check passed"
        } else {
            Write-Warning "Missing required Windows features: $($missingFeatures -join ', ')"
        }
        
        # Check permissions (run as administrator)
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if ($isAdmin) {
            $prerequisites.Permissions = $true
            Write-Verbose "Administrator permissions check passed"
        } else {
            Write-Warning "Administrator privileges required"
        }
        
        # Return overall result
        $allPassed = $prerequisites.Values -notcontains $false
        return $allPassed
        
    } catch {
        Write-Error "Error checking prerequisites: $($_.Exception.Message)"
        return $false
    }
}

function Get-FileServerConfiguration {
    <#
    .SYNOPSIS
        Retrieves current file server configuration
    
    .DESCRIPTION
        Gets the current file server configuration including shares, services, and settings
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    try {
        $config = @{}
        
        # Check if File Server role is installed
        $fileServerFeature = Get-WindowsFeature -Name FS-FileServer
        $config.FileServerInstalled = $fileServerFeature.InstallState -eq 'Installed'
        
        if ($config.FileServerInstalled) {
            # Get file server services
            $services = @('LanmanServer', 'LanmanWorkstation', 'Browser')
            $config.Services = @{}
            
            foreach ($serviceName in $services) {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service) {
                    $config.Services[$serviceName] = $service.Status
                } else {
                    $config.Services[$serviceName] = 'Not Found'
                }
            }
            
            # Get SMB shares
            try {
                $config.Shares = Get-SmbShare -ErrorAction SilentlyContinue
            } catch {
                $config.Shares = @()
            }
            
            # Get SMB server configuration
            try {
                $config.SmbServerConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
            } catch {
                $config.SmbServerConfig = $null
            }
        }
        
        return [PSCustomObject]$config
        
    } catch {
        Write-Error "Error retrieving file server configuration: $($_.Exception.Message)"
        return $null
    }
}

function Test-FileServerHealth {
    <#
    .SYNOPSIS
        Performs basic health checks on file server
    
    .DESCRIPTION
        Checks service status, share accessibility, and basic connectivity
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    $health = @{
        Overall = 'Unknown'
        Services = @{}
        Shares = @{}
        Connectivity = @{}
        Timestamp = Get-Date
    }
    
    try {
        # Check file server services
        $services = @('LanmanServer', 'LanmanWorkstation')
        foreach ($serviceName in $services) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                $health.Services[$serviceName] = $service.Status
            } else {
                $health.Services[$serviceName] = 'Not Found'
            }
        }
        
        # Check SMB shares
        try {
            $shares = Get-SmbShare -ErrorAction SilentlyContinue
            $health.Shares.TotalShares = $shares.Count
            $health.Shares.ActiveShares = ($shares | Where-Object { $_.ShareState -eq 'Online' }).Count
        } catch {
            $health.Shares.TotalShares = 0
            $health.Shares.ActiveShares = 0
        }
        
        # Basic connectivity test
        try {
            $testPath = "\\$($env:COMPUTERNAME)\C$"
            $testResult = Test-Path $testPath -ErrorAction Stop
            $health.Connectivity.LocalShare = if ($testResult) { 'Accessible' } else { 'Not Accessible' }
        } catch {
            $health.Connectivity.LocalShare = 'Not Accessible'
        }
        
        # Determine overall health
        $allServicesRunning = ($health.Services.Values -eq 'Running').Count -eq $health.Services.Count
        $sharesAccessible = $health.Connectivity.LocalShare -eq 'Accessible'
        
        if ($allServicesRunning -and $sharesAccessible) {
            $health.Overall = 'Healthy'
        } elseif ($allServicesRunning) {
            $health.Overall = 'Degraded'
        } else {
            $health.Overall = 'Unhealthy'
        }
        
        return [PSCustomObject]$health
        
    } catch {
        Write-Error "Error performing health check: $($_.Exception.Message)"
        $health.Overall = 'Error'
        return [PSCustomObject]$health
    }
}

#endregion

#region Public Functions

function Install-FileStoragePrerequisites {
    <#
    .SYNOPSIS
        Installs required Windows features for File and Storage Services
    
    .DESCRIPTION
        Installs File and Storage Services, SMB features, and other required components
    
    .PARAMETER RestartRequired
        Specifies whether to restart the computer if required
    
    .EXAMPLE
        Install-FileStoragePrerequisites
    
    .EXAMPLE
        Install-FileStoragePrerequisites -RestartRequired $true
    #>
    [CmdletBinding()]
    param(
        [switch]$RestartRequired
    )
    
    try {
        Write-Host "Installing File and Storage Services prerequisites..." -ForegroundColor Green
        
        # Define required features
        $features = @(
            'FileAndStorage-Services',
            'FS-FileServer',
            'FS-SMB1',
            'FS-SMB2',
            'FS-Resource-Manager',
            'FS-DFS-Namespace',
            'FS-DFS-Replication',
            'FS-NFS-Service',
            'FS-iSCSITarget-Server',
            'FS-iSCSITarget-Server-Tools',
            'FS-Storage-Replica',
            'FS-Deduplication'
        )
        
        $restartNeeded = $false
        
        foreach ($feature in $features) {
            $featureInfo = Get-WindowsFeature -Name $feature
            if ($featureInfo.InstallState -ne 'Installed') {
                Write-Host "Installing feature: $feature" -ForegroundColor Yellow
                $result = Install-WindowsFeature -Name $feature -IncludeManagementTools
                
                if ($result.RestartNeeded) {
                    $restartNeeded = $true
                }
                
                if ($result.Success) {
                    Write-Host "Successfully installed: $feature" -ForegroundColor Green
                } else {
                    Write-Warning "Failed to install: $feature"
                }
            } else {
                Write-Host "Feature already installed: $feature" -ForegroundColor Cyan
            }
        }
        
        if ($restartNeeded -and $RestartRequired) {
            Write-Host "Restart required. Restarting computer..." -ForegroundColor Yellow
            Restart-Computer -Force
        } elseif ($restartNeeded) {
            Write-Warning "A restart is required to complete the installation."
        }
        
        Write-Host "Prerequisites installation completed." -ForegroundColor Green
        
    } catch {
        Write-Error "Error installing prerequisites: $($_.Exception.Message)"
        throw
    }
}

function Get-FileServerStatus {
    <#
    .SYNOPSIS
        Gets comprehensive file server status information
    
    .DESCRIPTION
        Returns detailed status information including configuration, health, and services
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Gathering file server status information..." -ForegroundColor Green
        
        $status = @{
            Prerequisites = Test-FileStoragePrerequisites
            Configuration = Get-FileServerConfiguration
            Health = Test-FileServerHealth
            Timestamp = Get-Date
        }
        
        return [PSCustomObject]$status
        
    } catch {
        Write-Error "Error getting file server status: $($_.Exception.Message)"
        throw
    }
}

function Start-FileServerServices {
    <#
    .SYNOPSIS
        Starts file server related services
    
    .DESCRIPTION
        Starts file server and dependent services
    
    .EXAMPLE
        Start-FileServerServices
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Starting file server services..." -ForegroundColor Green
        
        $services = @('LanmanServer', 'LanmanWorkstation', 'Browser')
        
        foreach ($serviceName in $services) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                if ($service.Status -ne 'Running') {
                    Write-Host "Starting service: $serviceName" -ForegroundColor Yellow
                    Start-Service -Name $serviceName
                    Write-Host "Service started: $serviceName" -ForegroundColor Green
                } else {
                    Write-Host "Service already running: $serviceName" -ForegroundColor Cyan
                }
            } else {
                Write-Warning "Service not found: $serviceName"
            }
        }
        
    } catch {
        Write-Error "Error starting file server services: $($_.Exception.Message)"
        throw
    }
}

function Stop-FileServerServices {
    <#
    .SYNOPSIS
        Stops file server related services
    
    .DESCRIPTION
        Stops file server and dependent services
    
    .EXAMPLE
        Stop-FileServerServices
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Stopping file server services..." -ForegroundColor Green
        
        $services = @('Browser', 'LanmanWorkstation', 'LanmanServer')
        
        foreach ($serviceName in $services) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq 'Running') {
                Write-Host "Stopping service: $serviceName" -ForegroundColor Yellow
                Stop-Service -Name $serviceName -Force
                Write-Host "Service stopped: $serviceName" -ForegroundColor Green
            } else {
                Write-Host "Service not running or not found: $serviceName" -ForegroundColor Cyan
            }
        }
        
    } catch {
        Write-Error "Error stopping file server services: $($_.Exception.Message)"
        throw
    }
}

function Get-StorageInformation {
    <#
    .SYNOPSIS
        Gets comprehensive storage information
    
    .DESCRIPTION
        Retrieves disk, volume, and storage pool information
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Gathering storage information..." -ForegroundColor Green
        
        $storageInfo = @{
            Disks = Get-Disk
            Volumes = Get-Volume
            StoragePools = @()
            Timestamp = Get-Date
        }
        
        # Get storage pools if available
        try {
            $storageInfo.StoragePools = Get-StoragePool -ErrorAction SilentlyContinue
        } catch {
            Write-Verbose "Storage pools not available or accessible"
        }
        
        return [PSCustomObject]$storageInfo
        
    } catch {
        Write-Error "Error getting storage information: $($_.Exception.Message)"
        throw
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Install-FileStoragePrerequisites',
    'Get-FileServerStatus',
    'Start-FileServerServices',
    'Stop-FileServerServices',
    'Get-StorageInformation'
)

# Module initialization
Write-Verbose "FileStorage-Core module loaded successfully. Version: $ModuleVersion"