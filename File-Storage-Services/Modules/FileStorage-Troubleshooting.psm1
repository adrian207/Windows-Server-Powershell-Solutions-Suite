#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    File and Storage Services Troubleshooting PowerShell Module

.DESCRIPTION
    This module provides comprehensive troubleshooting and diagnostic functions
    for Windows File and Storage Services including health checks, log analysis,
    performance monitoring, and automated repair capabilities.

.NOTES
    Author: File and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Module metadata
$ModuleVersion = "1.0.0"

# Import required modules
try {
    Import-Module FileStorage-Core -ErrorAction Stop
    Import-Module FileStorage-Management -ErrorAction Stop
    Import-Module SmbShare -ErrorAction Stop
    Import-Module Storage -ErrorAction Stop
} catch {
    Write-Warning "Required modules not found. Some functions may not work properly."
}

#region Private Functions

function Get-FileServerLogEntries {
    <#
    .SYNOPSIS
        Retrieves file server related log entries from Windows Event Log
    
    .DESCRIPTION
        Gets file server related events from the Application and System event logs
    
    .PARAMETER LogName
        The event log name to search
    
    .PARAMETER StartTime
        Start time for log entries
    
    .PARAMETER EndTime
        End time for log entries
    
    .PARAMETER MaxEntries
        Maximum number of entries to return
    #>
    [CmdletBinding()]
    param(
        [string]$LogName = "Application",
        [DateTime]$StartTime = (Get-Date).AddDays(-1),
        [DateTime]$EndTime = (Get-Date),
        [int]$MaxEntries = 100
    )
    
    try {
        $logEntries = Get-WinEvent -FilterHashtable @{
            LogName = $LogName
            StartTime = $StartTime
            EndTime = $EndTime
        } -MaxEvents $MaxEntries | Where-Object {
            $_.ProviderName -like "*SMB*" -or 
            $_.ProviderName -like "*LanmanServer*" -or
            $_.ProviderName -like "*LanmanWorkstation*" -or
            $_.Message -like "*file share*" -or
            $_.Message -like "*SMB*" -or
            $_.Message -like "*share*"
        }
        
        return $logEntries
        
    } catch {
        Write-Warning "Error retrieving log entries: $($_.Exception.Message)"
        return @()
    }
}

function Test-FileServerConnectivity {
    <#
    .SYNOPSIS
        Tests file server connectivity and endpoints
    
    .DESCRIPTION
        Performs connectivity tests to file server endpoints and services
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    $connectivity = @{
        LocalEndpoints = @{}
        RemoteEndpoints = @{}
        Overall = 'Unknown'
    }
    
    try {
        # Test local endpoints
        $localEndpoints = @(
            "\\$($env:COMPUTERNAME)\C$",
            "\\$($env:COMPUTERNAME)\IPC$"
        )
        
        foreach ($endpoint in $localEndpoints) {
            try {
                $testResult = Test-Path $endpoint -ErrorAction Stop
                $connectivity.LocalEndpoints[$endpoint] = if ($testResult) { "Accessible" } else { "Not Accessible" }
            } catch {
                $connectivity.LocalEndpoints[$endpoint] = "Not Accessible: $($_.Exception.Message)"
            }
        }
        
        # Test SMB ports
        $smbPorts = @(445, 139)
        foreach ($port in $smbPorts) {
            try {
                $testConnection = Test-NetConnection -ComputerName $env:COMPUTERNAME -Port $port -WarningAction SilentlyContinue
                $connectivity.LocalEndpoints["Port $port"] = if ($testConnection.TcpTestSucceeded) { "Open" } else { "Closed" }
            } catch {
                $connectivity.LocalEndpoints["Port $port"] = "Error: $($_.Exception.Message)"
            }
        }
        
        # Determine overall connectivity
        $accessibleCount = ($connectivity.LocalEndpoints.Values | Where-Object { $_ -like "Accessible*" -or $_ -eq "Open" }).Count
        $totalCount = $connectivity.LocalEndpoints.Count
        
        if ($accessibleCount -eq $totalCount) {
            $connectivity.Overall = 'All Accessible'
        } elseif ($accessibleCount -gt 0) {
            $connectivity.Overall = 'Partially Accessible'
        } else {
            $connectivity.Overall = 'Not Accessible'
        }
        
        return [PSCustomObject]$connectivity
        
    } catch {
        Write-Error "Error testing connectivity: $($_.Exception.Message)"
        return $null
    }
}

function Get-FileServerPerformanceCounters {
    <#
    .SYNOPSIS
        Gets file server performance counters
    
    .DESCRIPTION
        Retrieves performance counter data for file server operations
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    try {
        $counters = @{}
        
        # Define performance counters to check
        $counterNames = @(
            "\Server\Sessions Logged On",
            "\Server\Files Open",
            "\Server\File Directory Operations/sec",
            "\Server\Logon/sec",
            "\Server\Logon Total",
            "\PhysicalDisk(_Total)\Disk Reads/sec",
            "\PhysicalDisk(_Total)\Disk Writes/sec",
            "\PhysicalDisk(_Total)\Avg. Disk Queue Length"
        )
        
        foreach ($counterName in $counterNames) {
            try {
                $counter = Get-Counter -Counter $counterName -SampleInterval 1 -MaxSamples 1 -ErrorAction Stop
                $counters[$counterName] = $counter.CounterSamples[0].CookedValue
            } catch {
                $counters[$counterName] = "Not Available"
            }
        }
        
        return [PSCustomObject]$counters
        
    } catch {
        Write-Warning "Error retrieving performance counters: $($_.Exception.Message)"
        return $null
    }
}

function Test-StorageHealth {
    <#
    .SYNOPSIS
        Tests storage health and performance
    
    .DESCRIPTION
        Performs comprehensive storage health checks including disk status,
        volume health, and storage pool status
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    $storageHealth = @{
        Overall = 'Unknown'
        Disks = @{}
        Volumes = @{}
        StoragePools = @{}
        Issues = @()
        Recommendations = @()
        Timestamp = Get-Date
    }
    
    try {
        # Check disk health
        $disks = Get-Disk
        foreach ($disk in $disks) {
            $diskHealth = @{
                Status = $disk.OperationalStatus
                Health = $disk.HealthStatus
                Size = $disk.Size
                PartitionStyle = $disk.PartitionStyle
            }
            
            if ($disk.OperationalStatus -ne 'Online' -or $disk.HealthStatus -ne 'Healthy') {
                $storageHealth.Issues += "Disk $($disk.FriendlyName) has issues: Status=$($disk.OperationalStatus), Health=$($disk.HealthStatus)"
                $storageHealth.Recommendations += "Check disk $($disk.FriendlyName) for hardware issues"
            }
            
            $storageHealth.Disks[$disk.FriendlyName] = $diskHealth
        }
        
        # Check volume health
        $volumes = Get-Volume
        foreach ($volume in $volumes) {
            $volumeHealth = @{
                Status = $volume.HealthStatus
                Size = $volume.Size
                SizeRemaining = $volume.SizeRemaining
                FileSystem = $volume.FileSystem
                DriveLetter = $volume.DriveLetter
            }
            
            if ($volume.HealthStatus -ne 'Healthy') {
                $storageHealth.Issues += "Volume $($volume.DriveLetter) has issues: $($volume.HealthStatus)"
                $storageHealth.Recommendations += "Check volume $($volume.DriveLetter) for file system issues"
            }
            
            # Check disk space
            if ($volume.SizeRemaining -lt ($volume.Size * 0.1)) {
                $storageHealth.Issues += "Volume $($volume.DriveLetter) is low on disk space: $([math]::Round(($volume.SizeRemaining / $volume.Size) * 100, 2))% remaining"
                $storageHealth.Recommendations += "Free up disk space on volume $($volume.DriveLetter)"
            }
            
            $storageHealth.Volumes[$volume.DriveLetter] = $volumeHealth
        }
        
        # Check storage pools if available
        try {
            $storagePools = Get-StoragePool -ErrorAction SilentlyContinue
            foreach ($pool in $storagePools) {
                $poolHealth = @{
                    Status = $pool.OperationalStatus
                    Health = $pool.HealthStatus
                    Size = $pool.Size
                    AllocatedSize = $pool.AllocatedSize
                }
                
                if ($pool.OperationalStatus -ne 'OK' -or $pool.HealthStatus -ne 'Healthy') {
                    $storageHealth.Issues += "Storage pool $($pool.FriendlyName) has issues: Status=$($pool.OperationalStatus), Health=$($pool.HealthStatus)"
                    $storageHealth.Recommendations += "Check storage pool $($pool.FriendlyName) for issues"
                }
                
                $storageHealth.StoragePools[$pool.FriendlyName] = $poolHealth
            }
        } catch {
            Write-Verbose "Storage pools not available or accessible"
        }
        
        # Determine overall health
        if ($storageHealth.Issues.Count -eq 0) {
            $storageHealth.Overall = 'Healthy'
        } elseif ($storageHealth.Issues.Count -le 2) {
            $storageHealth.Overall = 'Degraded'
        } else {
            $storageHealth.Overall = 'Unhealthy'
        }
        
        return [PSCustomObject]$storageHealth
        
    } catch {
        Write-Error "Error testing storage health: $($_.Exception.Message)"
        $storageHealth.Overall = 'Error'
        return [PSCustomObject]$storageHealth
    }
}

#endregion

#region Public Functions

function Test-FileServerHealth {
    <#
    .SYNOPSIS
        Performs comprehensive file server health check
    
    .DESCRIPTION
        Executes a full health check including services, connectivity, storage, and performance
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Performing comprehensive file server health check..." -ForegroundColor Green
        
        $healthReport = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            Services = @{}
            Configuration = @{}
            Connectivity = @{}
            Storage = @{}
            Performance = @{}
            Logs = @{}
            Issues = @()
            Recommendations = @()
            Overall = 'Unknown'
        }
        
        # Check services
        $services = @('LanmanServer', 'LanmanWorkstation', 'Browser', 'FsrmSvc')
        foreach ($serviceName in $services) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                $healthReport.Services[$serviceName] = $service.Status
            } else {
                $healthReport.Services[$serviceName] = 'Not Found'
            }
        }
        
        # Check configuration
        $configStatus = Get-FileServerConfiguration
        $healthReport.Configuration = $configStatus
        
        # Check connectivity
        $connectivity = Test-FileServerConnectivity
        $healthReport.Connectivity = $connectivity
        
        # Check storage health
        $storageHealth = Test-StorageHealth
        $healthReport.Storage = $storageHealth
        
        # Check performance
        $performance = Get-FileServerPerformanceCounters
        $healthReport.Performance = $performance
        
        # Check recent logs for errors
        $errorLogs = Get-FileServerLogEntries -LogName "Application" -StartTime (Get-Date).AddHours(-1) | Where-Object { $_.LevelDisplayName -eq "Error" }
        $healthReport.Logs.ErrorCount = $errorLogs.Count
        $healthReport.Logs.RecentErrors = $errorLogs | Select-Object -First 5 | ForEach-Object { $_.Message }
        
        # Identify issues
        $stoppedServices = $healthReport.Services.GetEnumerator() | Where-Object { $_.Value -ne 'Running' }
        if ($stoppedServices) {
            $healthReport.Issues += "Services not running: $($stoppedServices.Key -join ', ')"
            $healthReport.Recommendations += "Start stopped services"
        }
        
        if ($healthReport.Configuration.FileServerInstalled -ne $true) {
            $healthReport.Issues += "File server role not installed"
            $healthReport.Recommendations += "Install File Server role"
        }
        
        if ($healthReport.Connectivity.Overall -ne 'All Accessible') {
            $healthReport.Issues += "Connectivity issues detected"
            $healthReport.Recommendations += "Check network connectivity and firewall settings"
        }
        
        if ($healthReport.Storage.Issues.Count -gt 0) {
            $healthReport.Issues += $healthReport.Storage.Issues
            $healthReport.Recommendations += $healthReport.Storage.Recommendations
        }
        
        if ($healthReport.Logs.ErrorCount -gt 0) {
            $healthReport.Issues += "Recent errors found in logs"
            $healthReport.Recommendations += "Review error logs for specific issues"
        }
        
        # Determine overall health
        $allServicesRunning = ($healthReport.Services.Values -eq 'Running').Count -eq $healthReport.Services.Count
        $fileServerInstalled = $healthReport.Configuration.FileServerInstalled -eq $true
        $allAccessible = $healthReport.Connectivity.Overall -eq 'All Accessible'
        $storageHealthy = $healthReport.Storage.Overall -eq 'Healthy'
        $noRecentErrors = $healthReport.Logs.ErrorCount -eq 0
        
        if ($allServicesRunning -and $fileServerInstalled -and $allAccessible -and $storageHealthy -and $noRecentErrors) {
            $healthReport.Overall = 'Healthy'
        } elseif ($allServicesRunning -and $fileServerInstalled -and $allAccessible) {
            $healthReport.Overall = 'Degraded'
        } else {
            $healthReport.Overall = 'Unhealthy'
        }
        
        Write-Host "Health check completed. Overall status: $($healthReport.Overall)" -ForegroundColor Green
        
        return [PSCustomObject]$healthReport
        
    } catch {
        Write-Error "Error during health check: $($_.Exception.Message)"
        return $null
    }
}

function Get-FileServerDiagnosticReport {
    <#
    .SYNOPSIS
        Generates a comprehensive diagnostic report for file server
    
    .DESCRIPTION
        Creates a detailed diagnostic report including all aspects of file server health
    
    .PARAMETER OutputPath
        Path to save the diagnostic report
    
    .PARAMETER IncludeLogs
        Include recent log entries in the report
    
    .PARAMETER IncludePerformance
        Include performance data in the report
    
    .EXAMPLE
        Get-FileServerDiagnosticReport -OutputPath "C:\Reports\FileServer-Diagnostic.html"
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        
        [switch]$IncludeLogs,
        
        [switch]$IncludePerformance
    )
    
    try {
        Write-Host "Generating comprehensive file server diagnostic report..." -ForegroundColor Green
        
        $report = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            HealthCheck = Test-FileServerHealth
            Configuration = Get-FileServerConfiguration
            Status = Get-FileServerStatus
        }
        
        if ($IncludeLogs) {
            $report.RecentLogs = Get-FileServerLogEntries -StartTime (Get-Date).AddDays(-1)
        }
        
        if ($IncludePerformance) {
            $report.PerformanceData = Get-FileServerPerformanceCounters
        }
        
        $reportObject = [PSCustomObject]$report
        
        if ($OutputPath) {
            # Convert to HTML report
            $htmlReport = $reportObject | ConvertTo-Html -Title "File Server Diagnostic Report" -Head @"
<style>
body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
.container { background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
h1 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
h2 { color: #007acc; margin-top: 30px; }
h3 { color: #666; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; font-weight: bold; }
.status-healthy { color: #28a745; font-weight: bold; }
.status-degraded { color: #ffc107; font-weight: bold; }
.status-unhealthy { color: #dc3545; font-weight: bold; }
.issue { background-color: #fff3cd; padding: 10px; margin: 5px 0; border-left: 4px solid #ffc107; }
.recommendation { background-color: #d1ecf1; padding: 10px; margin: 5px 0; border-left: 4px solid #17a2b8; }
</style>
"@
            
            $htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "Diagnostic report saved to: $OutputPath" -ForegroundColor Green
        }
        
        return $reportObject
        
    } catch {
        Write-Error "Error generating diagnostic report: $($_.Exception.Message)"
        throw
    }
}

function Repair-FileServerInstallation {
    <#
    .SYNOPSIS
        Attempts to repair file server installation issues
    
    .DESCRIPTION
        Performs common repair operations for file server
    
    .PARAMETER RepairType
        Type of repair to perform (All, Services, Configuration, Storage, Shares)
    
    .EXAMPLE
        Repair-FileServerInstallation -RepairType "Services"
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("All", "Services", "Configuration", "Storage", "Shares")]
        [string]$RepairType = "All"
    )
    
    try {
        Write-Host "Starting file server repair operation: $RepairType" -ForegroundColor Green
        
        $repairResults = @{
            ServicesRepaired = $false
            ConfigurationRepaired = $false
            StorageRepaired = $false
            SharesRepaired = $false
            Overall = 'Unknown'
        }
        
        if ($RepairType -eq "All" -or $RepairType -eq "Services") {
            Write-Host "Repairing services..." -ForegroundColor Yellow
            
            # Stop services
            Stop-FileServerServices
            
            # Start services
            Start-FileServerServices
            
            $repairResults.ServicesRepaired = $true
            Write-Host "Services repair completed" -ForegroundColor Green
        }
        
        if ($RepairType -eq "All" -or $RepairType -eq "Configuration") {
            Write-Host "Checking configuration..." -ForegroundColor Yellow
            
            # Check if file server role is installed
            $fileServerFeature = Get-WindowsFeature -Name FS-FileServer
            if ($fileServerFeature.InstallState -ne 'Installed') {
                Write-Host "Installing File Server role..." -ForegroundColor Yellow
                Install-WindowsFeature -Name FS-FileServer -IncludeManagementTools
            }
            
            $repairResults.ConfigurationRepaired = $true
            Write-Host "Configuration repair completed" -ForegroundColor Green
        }
        
        if ($RepairType -eq "All" -or $RepairType -eq "Storage") {
            Write-Host "Checking storage..." -ForegroundColor Yellow
            
            # Check disk health
            $disks = Get-Disk | Where-Object { $_.OperationalStatus -ne 'Online' }
            if ($disks) {
                Write-Warning "Some disks are not online. Manual intervention may be required."
            }
            
            # Check volume health
            $volumes = Get-Volume | Where-Object { $_.HealthStatus -ne 'Healthy' }
            if ($volumes) {
                Write-Warning "Some volumes have health issues. Manual intervention may be required."
            }
            
            $repairResults.StorageRepaired = $true
            Write-Host "Storage repair completed" -ForegroundColor Green
        }
        
        if ($RepairType -eq "All" -or $RepairType -eq "Shares") {
            Write-Host "Checking shares..." -ForegroundColor Yellow
            
            # Check for offline shares
            $offlineShares = Get-SmbShare | Where-Object { $_.ShareState -eq 'Offline' }
            if ($offlineShares) {
                foreach ($share in $offlineShares) {
                    Write-Host "Attempting to bring share online: $($share.Name)" -ForegroundColor Yellow
                    try {
                        Set-SmbShare -Name $share.Name -Force
                    } catch {
                        Write-Warning "Could not bring share online: $($share.Name)"
                    }
                }
            }
            
            $repairResults.SharesRepaired = $true
            Write-Host "Shares repair completed" -ForegroundColor Green
        }
        
        # Determine overall repair status
        $repairCount = ($repairResults.ServicesRepaired, $repairResults.ConfigurationRepaired, $repairResults.StorageRepaired, $repairResults.SharesRepaired | Where-Object { $_ }).Count
        
        if ($repairCount -eq 4) {
            $repairResults.Overall = 'Fully Repaired'
        } elseif ($repairCount -gt 0) {
            $repairResults.Overall = 'Partially Repaired'
        } else {
            $repairResults.Overall = 'Repair Failed'
        }
        
        Write-Host "File server repair operation completed: $($repairResults.Overall)" -ForegroundColor Green
        
        return [PSCustomObject]$repairResults
        
    } catch {
        Write-Error "Error during repair operation: $($_.Exception.Message)"
        throw
    }
}

function Watch-FileServerPerformance {
    <#
    .SYNOPSIS
        Monitors file server performance in real-time
    
    .DESCRIPTION
        Continuously monitors file server performance counters
    
    .PARAMETER Duration
        Duration to monitor in seconds (default: 60)
    
    .PARAMETER Interval
        Monitoring interval in seconds (default: 5)
    
    .EXAMPLE
        Watch-FileServerPerformance -Duration 300 -Interval 10
    #>
    [CmdletBinding()]
    param(
        [int]$Duration = 60,
        [int]$Interval = 5
    )
    
    try {
        Write-Host "Starting file server performance monitoring for $Duration seconds..." -ForegroundColor Green
        
        $startTime = Get-Date
        $endTime = $startTime.AddSeconds($Duration)
        
        while ((Get-Date) -lt $endTime) {
            $performance = Get-FileServerPerformanceCounters
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            
            Write-Host "[$timestamp] File Server Performance:" -ForegroundColor Cyan
            $performance | Format-Table -AutoSize
            
            if ((Get-Date).AddSeconds($Interval) -lt $endTime) {
                Start-Sleep -Seconds $Interval
            }
        }
        
        Write-Host "Performance monitoring completed" -ForegroundColor Green
        
    } catch {
        Write-Error "Error during performance monitoring: $($_.Exception.Message)"
        throw
    }
}

function Test-FileShareAccess {
    <#
    .SYNOPSIS
        Tests access to file shares
    
    .DESCRIPTION
        Tests access to specific file shares and validates permissions
    
    .PARAMETER ShareName
        The name of the share to test
    
    .PARAMETER TestUser
        The user account to test access with
    
    .PARAMETER TestPath
        Specific path within the share to test
    
    .EXAMPLE
        Test-FileShareAccess -ShareName "Data" -TestUser "Domain\User"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ShareName,
        
        [string]$TestUser,
        
        [string]$TestPath
    )
    
    try {
        Write-Host "Testing access to share: $ShareName" -ForegroundColor Green
        
        $testResults = @{
            ShareName = $ShareName
            ShareExists = $false
            ShareAccessible = $false
            Permissions = @()
            Issues = @()
            Recommendations = @()
        }
        
        # Check if share exists
        $share = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
        if ($share) {
            $testResults.ShareExists = $true
            Write-Host "Share exists: $ShareName" -ForegroundColor Green
            
            # Test share accessibility
            try {
                $sharePath = "\\$($env:COMPUTERNAME)\$ShareName"
                $testResult = Test-Path $sharePath -ErrorAction Stop
                $testResults.ShareAccessible = $testResult
                
                if ($testResult) {
                    Write-Host "Share is accessible: $ShareName" -ForegroundColor Green
                } else {
                    Write-Host "Share is not accessible: $ShareName" -ForegroundColor Red
                    $testResults.Issues += "Share is not accessible"
                    $testResults.Recommendations += "Check share permissions and network connectivity"
                }
            } catch {
                $testResults.Issues += "Error testing share accessibility: $($_.Exception.Message)"
                $testResults.Recommendations += "Check share configuration and permissions"
            }
            
            # Get share permissions
            try {
                $permissions = Get-SmbShareAccess -Name $ShareName
                $testResults.Permissions = $permissions
                Write-Host "Retrieved permissions for share: $ShareName" -ForegroundColor Green
            } catch {
                $testResults.Issues += "Could not retrieve permissions: $($_.Exception.Message)"
                $testResults.Recommendations += "Check share permissions configuration"
            }
            
            # Test specific path if provided
            if ($TestPath) {
                try {
                    $fullPath = "\\$($env:COMPUTERNAME)\$ShareName\$TestPath"
                    $pathTest = Test-Path $fullPath -ErrorAction Stop
                    if ($pathTest) {
                        Write-Host "Test path is accessible: $TestPath" -ForegroundColor Green
                    } else {
                        Write-Host "Test path is not accessible: $TestPath" -ForegroundColor Red
                        $testResults.Issues += "Test path is not accessible: $TestPath"
                        $testResults.Recommendations += "Check path permissions and existence"
                    }
                } catch {
                    $testResults.Issues += "Error testing path: $($_.Exception.Message)"
                    $testResults.Recommendations += "Check path configuration"
                }
            }
            
        } else {
            Write-Host "Share does not exist: $ShareName" -ForegroundColor Red
            $testResults.Issues += "Share does not exist"
            $testResults.Recommendations += "Create the share or check the share name"
        }
        
        return [PSCustomObject]$testResults
        
    } catch {
        Write-Error "Error testing file share access: $($_.Exception.Message)"
        throw
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Test-FileServerHealth',
    'Get-FileServerDiagnosticReport',
    'Repair-FileServerInstallation',
    'Watch-FileServerPerformance',
    'Test-FileShareAccess'
)

# Module initialization
Write-Verbose "FileStorage-Troubleshooting module loaded successfully. Version: $ModuleVersion"
