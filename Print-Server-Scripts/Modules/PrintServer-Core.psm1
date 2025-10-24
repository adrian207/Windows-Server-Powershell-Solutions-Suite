#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Print Server Core PowerShell Module

.DESCRIPTION
    This module provides fundamental functions for managing Windows Print Server services,
    including common utilities, prerequisite checks, and helper functions.

.NOTES
    Author: Print Server PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
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
        Write-Log -Message "Print server started successfully." -Level "INFO" -LogFilePath "C:\Logs\PrintServer.log"
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

#region Print Server Core Functions

function Test-PrintServerPrerequisites {
    <#
    .SYNOPSIS
        Tests if the system meets the prerequisites for Print Server.
    
    .DESCRIPTION
        This function checks if the system meets the minimum requirements for
        installing and running Print Server services.
    
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        Test-PrintServerPrerequisites
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Checking Print Server prerequisites..."
        
        # Check if running as administrator
        if (-not (Test-IsAdministrator)) {
            Write-Warning "Script must be run as Administrator"
            return $false
        }
        
        # Check Windows version
        $osVersion = Get-OperatingSystemVersion
        if ($osVersion.Major -lt 10) {
            Write-Warning "Windows Server 2016 or later is required"
            return $false
        }
        
        # Check if Print Server feature is available
        $printServerFeature = Get-WindowsFeature -Name Print-Server -ErrorAction SilentlyContinue
        if (-not $printServerFeature) {
            Write-Warning "Print Server feature not available on this system"
            return $false
        }
        
        Write-Verbose "Prerequisites check passed"
        return $true
        
    } catch {
        Write-Error "Error checking prerequisites: $($_.Exception.Message)"
        return $false
    }
}

function Install-PrintServerPrerequisites {
    <#
    .SYNOPSIS
        Installs the Print Server role and required features.
    
    .DESCRIPTION
        This function installs the Print Server role and any required Windows features.
    
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        Install-PrintServerPrerequisites
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Installing Print Server prerequisites..."
        
        # Install Print Server feature
        $printServerFeature = Get-WindowsFeature -Name Print-Server
        if ($printServerFeature.InstallState -ne 'Installed') {
            Write-Verbose "Installing Print Server feature..."
            Install-WindowsFeature -Name Print-Server -IncludeManagementTools
        }
        
        # Install Print Services role
        $printServicesRole = Get-WindowsFeature -Name Print-Services
        if ($printServicesRole.InstallState -ne 'Installed') {
            Write-Verbose "Installing Print Services role..."
            Install-WindowsFeature -Name Print-Services -IncludeManagementTools
        }
        
        Write-Verbose "Print Server prerequisites installed successfully"
        return $true
        
    } catch {
        Write-Error "Error installing prerequisites: $($_.Exception.Message)"
        return $false
    }
}

function Get-PrintServerStatus {
    <#
    .SYNOPSIS
        Gets the current status of the Print Server.
    
    .DESCRIPTION
        This function retrieves comprehensive status information about the Print Server
        including service status, installed printers, and configuration.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .EXAMPLE
        Get-PrintServerStatus
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Getting Print Server status..."
        
        $status = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            PrintServerInstalled = $false
            SpoolerServiceStatus = $null
            PrintServerFeatures = @{}
            InstalledPrinters = @()
            PrintDrivers = @()
            PrintQueues = @()
            Configuration = @{}
        }
        
        # Check if Print Server is installed
        $printServerFeature = Get-WindowsFeature -Name Print-Server -ErrorAction SilentlyContinue
        if ($printServerFeature -and $printServerFeature.InstallState -eq 'Installed') {
            $status.PrintServerInstalled = $true
        }
        
        # Check Spooler service status
        $spoolerService = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        if ($spoolerService) {
            $status.SpoolerServiceStatus = $spoolerService.Status
        }
        
        # Get installed printers
        try {
            $printers = Get-Printer -ErrorAction SilentlyContinue
            $status.InstalledPrinters = $printers | Select-Object Name, DriverName, PortName, Location, Shared, Published
        } catch {
            Write-Warning "Could not retrieve printer information: $($_.Exception.Message)"
        }
        
        # Get print drivers
        try {
            $drivers = Get-PrinterDriver -ErrorAction SilentlyContinue
            $status.PrintDrivers = $drivers | Select-Object Name, DriverVersion, InfPath
        } catch {
            Write-Warning "Could not retrieve driver information: $($_.Exception.Message)"
        }
        
        # Get print queues
        try {
            $queues = Get-PrintJob -ErrorAction SilentlyContinue
            $status.PrintQueues = $queues | Select-Object PrinterName, JobName, JobStatus, SubmittedTime
        } catch {
            Write-Warning "Could not retrieve print queue information: $($_.Exception.Message)"
        }
        
        # Get Print Server configuration
        try {
            $status.Configuration = @{
                WebManagementEnabled = $false
                BranchOfficeDirectPrintingEnabled = $false
                PrintDriverIsolationEnabled = $false
            }
            
            # Check Web Management
            $webManagementFeature = Get-WindowsFeature -Name Print-Services-Web -ErrorAction SilentlyContinue
            if ($webManagementFeature -and $webManagementFeature.InstallState -eq 'Installed') {
                $status.Configuration.WebManagementEnabled = $true
            }
            
            # Check Branch Office Direct Printing
            $branchOfficeFeature = Get-WindowsFeature -Name Print-Services-BranchOffice -ErrorAction SilentlyContinue
            if ($branchOfficeFeature -and $branchOfficeFeature.InstallState -eq 'Installed') {
                $status.Configuration.BranchOfficeDirectPrintingEnabled = $true
            }
            
        } catch {
            Write-Warning "Could not retrieve configuration information: $($_.Exception.Message)"
        }
        
        Write-Verbose "Print Server status retrieved successfully"
        return [PSCustomObject]$status
        
    } catch {
        Write-Error "Error getting Print Server status: $($_.Exception.Message)"
        return $null
    }
}

function Start-PrintServerServices {
    <#
    .SYNOPSIS
        Starts the Print Server services.
    
    .DESCRIPTION
        This function starts the Print Server services including the Spooler service.
    
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        Start-PrintServerServices
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Starting Print Server services..."
        
        # Start Spooler service
        $spoolerService = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        if ($spoolerService -and $spoolerService.Status -ne 'Running') {
            Start-Service -Name Spooler
            Write-Verbose "Spooler service started"
        }
        
        Write-Verbose "Print Server services started successfully"
        return $true
        
    } catch {
        Write-Error "Error starting Print Server services: $($_.Exception.Message)"
        return $false
    }
}

function Stop-PrintServerServices {
    <#
    .SYNOPSIS
        Stops the Print Server services.
    
    .DESCRIPTION
        This function stops the Print Server services including the Spooler service.
    
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        Stop-PrintServerServices
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Stopping Print Server services..."
        
        # Stop Spooler service
        $spoolerService = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        if ($spoolerService -and $spoolerService.Status -eq 'Running') {
            Stop-Service -Name Spooler
            Write-Verbose "Spooler service stopped"
        }
        
        Write-Verbose "Print Server services stopped successfully"
        return $true
        
    } catch {
        Write-Error "Error stopping Print Server services: $($_.Exception.Message)"
        return $false
    }
}

function Test-PrintServerHealth {
    <#
    .SYNOPSIS
        Tests the health of the Print Server.
    
    .DESCRIPTION
        This function performs comprehensive health checks on the Print Server
        including service status, printer availability, and configuration.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .EXAMPLE
        Test-PrintServerHealth
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Testing Print Server health..."
        
        $health = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Overall = 'Unknown'
            Services = @{}
            Printers = @{}
            Issues = @()
            Recommendations = @()
        }
        
        # Check service health
        $spoolerService = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        if ($spoolerService) {
            $health.Services.Spooler = $spoolerService.Status
            if ($spoolerService.Status -ne 'Running') {
                $health.Issues += "Spooler service is not running"
                $health.Recommendations += "Start the Spooler service"
            }
        } else {
            $health.Issues += "Spooler service not found"
            $health.Recommendations += "Install Print Server role"
        }
        
        # Check printer health
        try {
            $printers = Get-Printer -ErrorAction SilentlyContinue
            $health.Printers.TotalCount = $printers.Count
            $health.Printers.OnlineCount = ($printers | Where-Object { $_.PrinterStatus -eq 'Normal' }).Count
            $health.Printers.OfflineCount = ($printers | Where-Object { $_.PrinterStatus -eq 'Offline' }).Count
            
            if ($health.Printers.OfflineCount -gt 0) {
                $health.Issues += "$($health.Printers.OfflineCount) printers are offline"
                $health.Recommendations += "Check printer connectivity and drivers"
            }
        } catch {
            $health.Issues += "Could not retrieve printer information"
            $health.Recommendations += "Check Print Server installation"
        }
        
        # Determine overall health
        if ($health.Issues.Count -eq 0) {
            $health.Overall = 'Healthy'
        } elseif ($health.Issues.Count -le 2) {
            $health.Overall = 'Degraded'
        } else {
            $health.Overall = 'Unhealthy'
        }
        
        Write-Verbose "Print Server health check completed: $($health.Overall)"
        return [PSCustomObject]$health
        
    } catch {
        Write-Error "Error testing Print Server health: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Test-IsAdministrator',
    'Get-OperatingSystemVersion',
    'Write-Log',
    'Test-PrintServerPrerequisites',
    'Install-PrintServerPrerequisites',
    'Get-PrintServerStatus',
    'Start-PrintServerServices',
    'Stop-PrintServerServices',
    'Test-PrintServerHealth'
)

# Module initialization
Write-Verbose "PrintServer-Core module loaded successfully. Version: $ModuleVersion"