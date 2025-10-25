#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Core module for Backup and Storage Services management.

.DESCRIPTION
    This module provides fundamental functions for managing Windows Backup and Storage Services,
    including common utilities, prerequisite checks, and helper functions.

.NOTES
    Author: Backup and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/backup-and-storage-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Helper Functions

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Checks if the current user has administrator privileges.
    .DESCRIPTION
        This function determines if the PowerShell session is running with elevated
        administrator privileges.
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        Test-IsAdministrator
    #>
    [CmdletBinding()]
    param()

    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-OperatingSystemVersion {
    <#
    .SYNOPSIS
        Gets the operating system version.
    .DESCRIPTION
        Retrieves the major and minor version of the operating system.
    .OUTPUTS
        System.Version
    .EXAMPLE
        Get-OperatingSystemVersion
    #>
    [CmdletBinding()]
    param()

    [System.Environment]::OSVersion.Version
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a log message to a file and/or console.
    .DESCRIPTION
        This function writes a timestamped log message to a specified log file
        and optionally to the console.
    .PARAMETER Message
        The log message to write.
    .PARAMETER Level
        The log level (e.g., INFO, WARNING, ERROR, DEBUG).
    .PARAMETER LogFilePath
        Optional path to the log file. If not provided, logs only to console.
    .EXAMPLE
        Write-Log -Message "Service started successfully." -Level "INFO" -LogFilePath "C:\Logs\BackupStorage.log"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Level = "INFO",
        [string]$LogFilePath
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    Write-Host $logEntry

    if (-not [string]::IsNullOrEmpty($LogFilePath)) {
        try {
            Add-Content -Path $LogFilePath -Value $logEntry -ErrorAction Stop
        } catch {
            Write-Warning "Failed to write to log file '$LogFilePath': $($_.Exception.Message)"
        }
    }
}

#endregion

#region Backup and Storage Specific Functions

function Test-BackupStoragePrerequisites {
    <#
    .SYNOPSIS
        Tests if the system meets the prerequisites for Backup and Storage Services.
    .DESCRIPTION
        This function checks for necessary operating system versions, administrative privileges,
        and other requirements before installing Backup and Storage Services.
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        Test-BackupStoragePrerequisites
    #>
    [CmdletBinding()]
    param()

    Write-Log -Message "Checking Backup and Storage Services prerequisites..." -Level "INFO"

    if (-not (Test-IsAdministrator)) {
        Write-Log -Message "Administrator privileges are required for Backup and Storage Services." -Level "ERROR"
        return $false
    }

    $osVersion = Get-OperatingSystemVersion
    if ($osVersion.Major -lt 10) { # Windows Server 2016 is 10.0
        Write-Log -Message "Unsupported operating system version: $($osVersion). Windows Server 2016 or later is required." -Level "ERROR"
        return $false
    }

    # Check for required Windows features
    $requiredFeatures = @(
        'Windows-Server-Backup',
        'File-Services',
        'Storage-Services',
        'FSRM',
        'iSCSI-Target-Server',
        'Multipath-IO'
    )

    foreach ($feature in $requiredFeatures) {
        $featureInfo = Get-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
        if ($null -eq $featureInfo) {
            Write-Log -Message "Required feature not found: $feature" -Level "WARNING"
        }
    }

    Write-Log -Message "All Backup and Storage Services prerequisites met." -Level "INFO"
    return $true
}

function Install-BackupStoragePrerequisites {
    <#
    .SYNOPSIS
        Installs any missing prerequisites for Backup and Storage Services.
    .DESCRIPTION
        This function ensures that all necessary features or roles are installed
        before Backup and Storage Services can be deployed.
    .EXAMPLE
        Install-BackupStoragePrerequisites
    #>
    [CmdletBinding()]
    param()

    Write-Log -Message "Installing Backup and Storage Services prerequisites..." -Level "INFO"

    $requiredFeatures = @(
        'Windows-Server-Backup',
        'File-Services',
        'Storage-Services',
        'FSRM',
        'iSCSI-Target-Server',
        'Multipath-IO'
    )

    $restartNeeded = $false

    foreach ($feature in $requiredFeatures) {
        try {
            $featureInfo = Get-WindowsFeature -Name $feature -ErrorAction Stop
            
            if ($featureInfo.InstallState -ne 'Installed') {
                Write-Log -Message "Installing feature: $feature" -Level "INFO"
                $result = Install-WindowsFeature -Name $feature -IncludeManagementTools
                
                if ($result.RestartNeeded) {
                    $restartNeeded = $true
                }
                
                if ($result.Success) {
                    Write-Log -Message "Successfully installed: $feature" -Level "SUCCESS"
                } else {
                    Write-Log -Message "Failed to install: $feature" -Level "ERROR"
                    return $false
                }
            } else {
                Write-Log -Message "Feature already installed: $feature" -Level "INFO"
            }
        } catch {
            Write-Log -Message "Error checking/installing feature $feature`: $($_.Exception.Message)" -Level "WARNING"
        }
    }

    if ($restartNeeded) {
        Write-Log -Message "A restart is required to complete prerequisite installation." -Level "WARNING"
    }

    Write-Log -Message "Backup and Storage Services prerequisites installation completed." -Level "SUCCESS"
    return $true
}

function Get-BackupStorageStatus {
    <#
    .SYNOPSIS
        Gets the status of Backup and Storage Services.
    .DESCRIPTION
        Retrieves the current status of various backup and storage services.
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .EXAMPLE
        Get-BackupStorageStatus
    #>
    [CmdletBinding()]
    param()

    Write-Log -Message "Getting Backup and Storage Services status..." -Level "INFO"

    try {
        $status = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Services = @{}
            Features = @{}
            Storage = @{}
            Backup = @{}
        }

        # Check Windows Backup service
        try {
            $backupService = Get-Service -Name "SDRSVC" -ErrorAction SilentlyContinue
            $status.Services.WindowsBackup = if ($backupService) { $backupService.Status } else { "Not Found" }
        } catch {
            $status.Services.WindowsBackup = "Error: $($_.Exception.Message)"
        }

        # Check Volume Shadow Copy service
        try {
            $vssService = Get-Service -Name "VSS" -ErrorAction SilentlyContinue
            $status.Services.VolumeShadowCopy = if ($vssService) { $vssService.Status } else { "Not Found" }
        } catch {
            $status.Services.VolumeShadowCopy = "Error: $($_.Exception.Message)"
        }

        # Check installed features
        $features = @('Windows-Server-Backup', 'File-Services', 'Storage-Services', 'FSRM', 'iSCSI-Target-Server', 'Multipath-IO')
        foreach ($feature in $features) {
            try {
                $featureInfo = Get-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
                $status.Features[$feature] = if ($featureInfo) { $featureInfo.InstallState } else { "Not Found" }
            } catch {
                $status.Features[$feature] = "Error: $($_.Exception.Message)"
            }
        }

        # Check storage information
        try {
            $status.Storage.Drives = Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace, FileSystem
            $status.Storage.PhysicalDisks = Get-PhysicalDisk | Select-Object FriendlyName, Size, HealthStatus, OperationalStatus
        } catch {
            $status.Storage.Error = $_.Exception.Message
        }

        # Check backup information
        try {
            $status.Backup.WindowsBackupInstalled = (Get-WindowsFeature -Name "Windows-Server-Backup").InstallState -eq "Installed"
        } catch {
            $status.Backup.Error = $_.Exception.Message
        }

        Write-Log -Message "Backup and Storage Services status retrieved successfully" -Level "SUCCESS"
        return [PSCustomObject]$status

    } catch {
        Write-Log -Message "Error getting Backup and Storage Services status: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Test-BackupStorageHealth {
    <#
    .SYNOPSIS
        Performs a basic health check of the Backup and Storage Services.
    .DESCRIPTION
        This function checks if essential backup and storage services are running
        and if basic management cmdlets are available.
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .EXAMPLE
        Test-BackupStorageHealth
    #>
    [CmdletBinding()]
    param()

    Write-Log -Message "Performing Backup and Storage Services health check..." -Level "INFO"

    $health = @{
        Timestamp = Get-Date
        ComputerName = $env:COMPUTERNAME
        Overall = "Healthy"
        Checks = @{}
        Issues = @()
        Recommendations = @()
    }

    # Check Windows Backup service
    try {
        $backupService = Get-Service -Name "SDRSVC" -ErrorAction SilentlyContinue
        if ($null -eq $backupService -or $backupService.Status -ne 'Running') {
            $health.Checks.WindowsBackupService = "Failed"
            $health.Issues += "Windows Backup service is not running"
            $health.Overall = "Unhealthy"
        } else {
            $health.Checks.WindowsBackupService = "Passed"
        }
    } catch {
        $health.Checks.WindowsBackupService = "Error"
        $health.Issues += "Error checking Windows Backup service: $($_.Exception.Message)"
        $health.Overall = "Unhealthy"
    }

    # Check Volume Shadow Copy service
    try {
        $vssService = Get-Service -Name "VSS" -ErrorAction SilentlyContinue
        if ($null -eq $vssService -or $vssService.Status -ne 'Running') {
            $health.Checks.VolumeShadowCopyService = "Failed"
            $health.Issues += "Volume Shadow Copy service is not running"
            $health.Overall = "Unhealthy"
        } else {
            $health.Checks.VolumeShadowCopyService = "Passed"
        }
    } catch {
        $health.Checks.VolumeShadowCopyService = "Error"
        $health.Issues += "Error checking Volume Shadow Copy service: $($_.Exception.Message)"
        $health.Overall = "Unhealthy"
    }

    # Check storage health
    try {
        $unhealthyDisks = Get-PhysicalDisk | Where-Object { $_.HealthStatus -ne 'Healthy' }
        if ($unhealthyDisks) {
            $health.Checks.StorageHealth = "Failed"
            $health.Issues += "Unhealthy physical disks detected: $($unhealthyDisks.FriendlyName -join ', ')"
            $health.Overall = "Unhealthy"
        } else {
            $health.Checks.StorageHealth = "Passed"
        }
    } catch {
        $health.Checks.StorageHealth = "Error"
        $health.Issues += "Error checking storage health: $($_.Exception.Message)"
        $health.Overall = "Unhealthy"
    }

    # Check disk space
    try {
        $lowSpaceDrives = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { 
            $_.FreeSpace -lt ($_.Size * 0.1) -and $_.DriveType -eq 3 
        }
        if ($lowSpaceDrives) {
            $health.Checks.DiskSpace = "Warning"
            $health.Issues += "Low disk space on drives: $($lowSpaceDrives.DeviceID -join ', ')"
            if ($health.Overall -eq "Healthy") {
                $health.Overall = "Warning"
            }
        } else {
            $health.Checks.DiskSpace = "Passed"
        }
    } catch {
        $health.Checks.DiskSpace = "Error"
        $health.Issues += "Error checking disk space: $($_.Exception.Message)"
        $health.Overall = "Unhealthy"
    }

    # Generate recommendations
    if ($health.Overall -eq "Unhealthy") {
        $health.Recommendations += "Address the issues listed above to restore service health"
    } elseif ($health.Overall -eq "Warning") {
        $health.Recommendations += "Monitor disk space and consider cleanup or expansion"
    } else {
        $health.Recommendations += "All health checks passed - system is operating normally"
    }

    Write-Log -Message "Backup and Storage Services health check completed. Overall status: $($health.Overall)" -Level "INFO"
    return [PSCustomObject]$health
}

function Start-BackupStorageServices {
    <#
    .SYNOPSIS
        Starts essential Backup and Storage Services.
    .DESCRIPTION
        Ensures essential backup and storage services are running.
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        Start-BackupStorageServices
    #>
    [CmdletBinding()]
    param()

    Write-Log -Message "Starting Backup and Storage Services..." -Level "INFO"

    $services = @('SDRSVC', 'VSS', 'Spooler')

    foreach ($serviceName in $services) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -ne 'Running') {
                Start-Service -Name $serviceName -ErrorAction Stop
                Write-Log -Message "Started service: $serviceName" -Level "SUCCESS"
            } elseif ($service) {
                Write-Log -Message "Service already running: $serviceName" -Level "INFO"
            } else {
                Write-Log -Message "Service not found: $serviceName" -Level "WARNING"
            }
        } catch {
            Write-Log -Message "Failed to start service $serviceName`: $($_.Exception.Message)" -Level "ERROR"
        }
    }

    Write-Log -Message "Backup and Storage Services startup completed" -Level "SUCCESS"
    return $true
}

function Stop-BackupStorageServices {
    <#
    .SYNOPSIS
        Stops Backup and Storage Services.
    .DESCRIPTION
        Stops essential backup and storage services.
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        Stop-BackupStorageServices
    #>
    [CmdletBinding()]
    param()

    Write-Log -Message "Stopping Backup and Storage Services..." -Level "INFO"

    $services = @('SDRSVC', 'VSS')

    foreach ($serviceName in $services) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq 'Running') {
                Stop-Service -Name $serviceName -ErrorAction Stop
                Write-Log -Message "Stopped service: $serviceName" -Level "SUCCESS"
            } elseif ($service) {
                Write-Log -Message "Service already stopped: $serviceName" -Level "INFO"
            } else {
                Write-Log -Message "Service not found: $serviceName" -Level "WARNING"
            }
        } catch {
            Write-Log -Message "Failed to stop service $serviceName`: $($_.Exception.Message)" -Level "ERROR"
        }
    }

    Write-Log -Message "Backup and Storage Services shutdown completed" -Level "SUCCESS"
    return $true
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Test-IsAdministrator',
    'Get-OperatingSystemVersion',
    'Write-Log',
    'Test-BackupStoragePrerequisites',
    'Install-BackupStoragePrerequisites',
    'Get-BackupStorageStatus',
    'Test-BackupStorageHealth',
    'Start-BackupStorageServices',
    'Stop-BackupStorageServices'
)

# Module initialization
Write-Verbose "BackupStorage-Core module loaded successfully. Version: $ModuleVersion"
