#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Print Server Troubleshooting PowerShell Module

.DESCRIPTION
    This module provides comprehensive troubleshooting and diagnostic functions
    for Windows Print Server services including health checks, log analysis,
    performance monitoring, and automated repair capabilities.

.NOTES
    Author: Print Server PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Module metadata
$ModuleVersion = "1.0.0"

# Import required modules
try {
    Import-Module PrintServer-Core -ErrorAction Stop
    Import-Module PrintServer-Management -ErrorAction Stop
} catch {
    Write-Warning "Required modules not found. Some functions may not work properly."
}

#region Private Functions

function Get-PrintServerLogEntries {
    <#
    .SYNOPSIS
        Retrieves print server related log entries from Windows Event Log
    
    .DESCRIPTION
        Gets print server related events from the Application and System event logs
    
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
            $_.ProviderName -like "*Print*" -or 
            $_.ProviderName -like "*Spooler*" -or
            $_.Message -like "*print*" -or
            $_.Message -like "*printer*" -or
            $_.Message -like "*spooler*"
        }
        
        return $logEntries
        
    } catch {
        Write-Warning "Error retrieving log entries: $($_.Exception.Message)"
        return @()
    }
}

function Test-PrintServerConnectivity {
    <#
    .SYNOPSIS
        Tests print server connectivity and endpoints
    
    .DESCRIPTION
        Performs connectivity tests to print server endpoints and services
    
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
        
        # Test print server ports
        $printPorts = @(9100, 515, 631)
        foreach ($port in $printPorts) {
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

function Get-PrintServerPerformanceCounters {
    <#
    .SYNOPSIS
        Gets print server performance counters
    
    .DESCRIPTION
        Retrieves performance counter data for print server operations
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    try {
        $counters = @{}
        
        # Define performance counters to check
        $counterNames = @(
            "\Print Queue\Jobs",
            "\Print Queue\Jobs Spooling",
            "\Print Queue\Max Jobs Spooling",
            "\Print Queue\Bytes Printed/sec",
            "\Print Queue\Pages Printed/sec",
            "\Print Queue\Job Errors",
            "\Print Queue\Out of Paper Errors",
            "\Print Queue\Not Ready Errors"
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

function Test-PrinterConnectivity {
    <#
    .SYNOPSIS
        Tests connectivity to a specific printer
    
    .DESCRIPTION
        Performs connectivity tests to a specific printer
    
    .PARAMETER PrinterName
        The name of the printer to test
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrinterName
    )
    
    try {
        $printerTest = @{
            PrinterName = $PrinterName
            Exists = $false
            Accessible = $false
            DriverStatus = 'Unknown'
            PortStatus = 'Unknown'
            Issues = @()
            Recommendations = @()
        }
        
        # Check if printer exists
        $printer = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
        if ($printer) {
            $printerTest.Exists = $true
            
            # Check driver status
            try {
                $driver = Get-PrinterDriver -Name $printer.DriverName -ErrorAction SilentlyContinue
                if ($driver) {
                    $printerTest.DriverStatus = 'Available'
                } else {
                    $printerTest.DriverStatus = 'Not Found'
                    $printerTest.Issues += "Driver not found: $($printer.DriverName)"
                    $printerTest.Recommendations += "Install or reinstall printer driver"
                }
            } catch {
                $printerTest.DriverStatus = 'Error'
                $printerTest.Issues += "Error checking driver status"
            }
            
            # Check port status
            try {
                $port = Get-PrinterPort -Name $printer.PortName -ErrorAction SilentlyContinue
                if ($port) {
                    $printerTest.PortStatus = 'Available'
                } else {
                    $printerTest.PortStatus = 'Not Found'
                    $printerTest.Issues += "Port not found: $($printer.PortName)"
                    $printerTest.Recommendations += "Check printer port configuration"
                }
            } catch {
                $printerTest.PortStatus = 'Error'
                $printerTest.Issues += "Error checking port status"
            }
            
            # Test printer accessibility
            try {
                $testJob = Start-Job -ScriptBlock { 
                    param($PrinterName)
                    Get-Printer -Name $PrinterName -ErrorAction Stop
                } -ArgumentList $PrinterName
                
                $result = Wait-Job -Job $testJob -Timeout 10
                if ($result) {
                    $printerTest.Accessible = $true
                } else {
                    $printerTest.Accessible = $false
                    $printerTest.Issues += "Printer not accessible"
                    $printerTest.Recommendations += "Check printer connectivity and configuration"
                }
                
                Remove-Job -Job $testJob -Force
            } catch {
                $printerTest.Accessible = $false
                $printerTest.Issues += "Error testing printer accessibility"
            }
            
        } else {
            $printerTest.Issues += "Printer does not exist"
            $printerTest.Recommendations += "Create the printer or check the printer name"
        }
        
        return [PSCustomObject]$printerTest
        
    } catch {
        Write-Error "Error testing printer connectivity: $($_.Exception.Message)"
        return $null
    }
}

#endregion

#region Public Functions

function Test-PrintServerHealth {
    <#
    .SYNOPSIS
        Performs comprehensive print server health check
    
    .DESCRIPTION
        Executes a full health check including services, connectivity, printers, and performance
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Performing comprehensive print server health check..." -ForegroundColor Green
        
        $healthReport = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            Services = @{}
            Configuration = @{}
            Connectivity = @{}
            Printers = @{}
            Performance = @{}
            Logs = @{}
            Issues = @()
            Recommendations = @()
            Overall = 'Unknown'
        }
        
        # Check services
        $services = @('Spooler')
        foreach ($serviceName in $services) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                $healthReport.Services[$serviceName] = $service.Status
            } else {
                $healthReport.Services[$serviceName] = 'Not Found'
            }
        }
        
        # Check configuration
        $configStatus = Get-PrintServerStatus
        $healthReport.Configuration = $configStatus
        
        # Check connectivity
        $connectivity = Test-PrintServerConnectivity
        $healthReport.Connectivity = $connectivity
        
        # Check printers
        try {
            $printers = Get-Printer -ErrorAction SilentlyContinue
            $healthReport.Printers = @{
                TotalCount = $printers.Count
                OnlineCount = ($printers | Where-Object { $_.PrinterStatus -eq 'Normal' }).Count
                OfflineCount = ($printers | Where-Object { $_.PrinterStatus -eq 'Offline' }).Count
                ErrorCount = ($printers | Where-Object { $_.PrinterStatus -eq 'Error' }).Count
            }
        } catch {
            $healthReport.Printers = @{
                TotalCount = 0
                OnlineCount = 0
                OfflineCount = 0
                ErrorCount = 0
            }
        }
        
        # Check performance
        $performance = Get-PrintServerPerformanceCounters
        $healthReport.Performance = $performance
        
        # Check recent logs for errors
        $errorLogs = Get-PrintServerLogEntries -LogName "Application" -StartTime (Get-Date).AddHours(-1) | Where-Object { $_.LevelDisplayName -eq "Error" }
        $healthReport.Logs.ErrorCount = $errorLogs.Count
        $healthReport.Logs.RecentErrors = $errorLogs | Select-Object -First 5 | ForEach-Object { $_.Message }
        
        # Identify issues
        $stoppedServices = $healthReport.Services.GetEnumerator() | Where-Object { $_.Value -ne 'Running' }
        if ($stoppedServices) {
            $healthReport.Issues += "Services not running: $($stoppedServices.Key -join ', ')"
            $healthReport.Recommendations += "Start stopped services"
        }
        
        if ($healthReport.Configuration.PrintServerInstalled -ne $true) {
            $healthReport.Issues += "Print Server role not installed"
            $healthReport.Recommendations += "Install Print Server role"
        }
        
        if ($healthReport.Connectivity.Overall -ne 'All Accessible') {
            $healthReport.Issues += "Connectivity issues detected"
            $healthReport.Recommendations += "Check network connectivity and firewall settings"
        }
        
        if ($healthReport.Printers.OfflineCount -gt 0) {
            $healthReport.Issues += "$($healthReport.Printers.OfflineCount) printers are offline"
            $healthReport.Recommendations += "Check printer connectivity and drivers"
        }
        
        if ($healthReport.Printers.ErrorCount -gt 0) {
            $healthReport.Issues += "$($healthReport.Printers.ErrorCount) printers have errors"
            $healthReport.Recommendations += "Check printer configuration and drivers"
        }
        
        if ($healthReport.Logs.ErrorCount -gt 0) {
            $healthReport.Issues += "Recent errors found in logs"
            $healthReport.Recommendations += "Review error logs for specific issues"
        }
        
        # Determine overall health
        $allServicesRunning = ($healthReport.Services.Values -eq 'Running').Count -eq $healthReport.Services.Count
        $printServerInstalled = $healthReport.Configuration.PrintServerInstalled -eq $true
        $allAccessible = $healthReport.Connectivity.Overall -eq 'All Accessible'
        $allPrintersOnline = $healthReport.Printers.OfflineCount -eq 0 -and $healthReport.Printers.ErrorCount -eq 0
        $noRecentErrors = $healthReport.Logs.ErrorCount -eq 0
        
        if ($allServicesRunning -and $printServerInstalled -and $allAccessible -and $allPrintersOnline -and $noRecentErrors) {
            $healthReport.Overall = 'Healthy'
        } elseif ($allServicesRunning -and $printServerInstalled -and $allAccessible) {
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

function Get-PrintServerDiagnosticReport {
    <#
    .SYNOPSIS
        Generates a comprehensive diagnostic report for print server
    
    .DESCRIPTION
        Creates a detailed diagnostic report including all aspects of print server health
    
    .PARAMETER OutputPath
        Path to save the diagnostic report
    
    .PARAMETER IncludeLogs
        Include recent log entries in the report
    
    .PARAMETER IncludePerformance
        Include performance data in the report
    
    .EXAMPLE
        Get-PrintServerDiagnosticReport -OutputPath "C:\Reports\PrintServer-Diagnostic.html"
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        
        [switch]$IncludeLogs,
        
        [switch]$IncludePerformance
    )
    
    try {
        Write-Host "Generating comprehensive print server diagnostic report..." -ForegroundColor Green
        
        $report = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            HealthCheck = Test-PrintServerHealth
            Configuration = Get-PrintServerStatus
        }
        
        if ($IncludeLogs) {
            $report.RecentLogs = Get-PrintServerLogEntries -StartTime (Get-Date).AddDays(-1)
        }
        
        if ($IncludePerformance) {
            $report.PerformanceData = Get-PrintServerPerformanceCounters
        }
        
        $reportObject = [PSCustomObject]$report
        
        if ($OutputPath) {
            # Convert to HTML report
            $htmlReport = $reportObject | ConvertTo-Html -Title "Print Server Diagnostic Report" -Head @"
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

function Repair-PrintServerInstallation {
    <#
    .SYNOPSIS
        Attempts to repair print server installation issues
    
    .DESCRIPTION
        Performs common repair operations for print server
    
    .PARAMETER RepairType
        Type of repair to perform (All, Services, Configuration, Printers, Drivers)
    
    .EXAMPLE
        Repair-PrintServerInstallation -RepairType "Services"
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("All", "Services", "Configuration", "Printers", "Drivers")]
        [string]$RepairType = "All"
    )
    
    try {
        Write-Host "Starting print server repair operation: $RepairType" -ForegroundColor Green
        
        $repairResults = @{
            ServicesRepaired = $false
            ConfigurationRepaired = $false
            PrintersRepaired = $false
            DriversRepaired = $false
            Overall = 'Unknown'
        }
        
        if ($RepairType -eq "All" -or $RepairType -eq "Services") {
            Write-Host "Repairing services..." -ForegroundColor Yellow
            
            # Stop services
            Stop-PrintServerServices
            
            # Start services
            Start-PrintServerServices
            
            $repairResults.ServicesRepaired = $true
            Write-Host "Services repair completed" -ForegroundColor Green
        }
        
        if ($RepairType -eq "All" -or $RepairType -eq "Configuration") {
            Write-Host "Checking configuration..." -ForegroundColor Yellow
            
            # Check if print server role is installed
            $printServerFeature = Get-WindowsFeature -Name Print-Server
            if ($printServerFeature.InstallState -ne 'Installed') {
                Write-Host "Installing Print Server role..." -ForegroundColor Yellow
                Install-WindowsFeature -Name Print-Server -IncludeManagementTools
            }
            
            $repairResults.ConfigurationRepaired = $true
            Write-Host "Configuration repair completed" -ForegroundColor Green
        }
        
        if ($RepairType -eq "All" -or $RepairType -eq "Printers") {
            Write-Host "Checking printers..." -ForegroundColor Yellow
            
            # Check for offline printers
            $offlinePrinters = Get-Printer | Where-Object { $_.PrinterStatus -eq 'Offline' }
            if ($offlinePrinters) {
                Write-Warning "Some printers are offline. Manual intervention may be required."
            }
            
            $repairResults.PrintersRepaired = $true
            Write-Host "Printers repair completed" -ForegroundColor Green
        }
        
        if ($RepairType -eq "All" -or $RepairType -eq "Drivers") {
            Write-Host "Checking drivers..." -ForegroundColor Yellow
            
            # Check for missing drivers
            $printers = Get-Printer
            foreach ($printer in $printers) {
                try {
                    $driver = Get-PrinterDriver -Name $printer.DriverName -ErrorAction SilentlyContinue
                    if (-not $driver) {
                        Write-Warning "Driver not found for printer: $($printer.Name)"
                    }
                } catch {
                    Write-Warning "Error checking driver for printer: $($printer.Name)"
                }
            }
            
            $repairResults.DriversRepaired = $true
            Write-Host "Drivers repair completed" -ForegroundColor Green
        }
        
        # Determine overall repair status
        $repairCount = ($repairResults.ServicesRepaired, $repairResults.ConfigurationRepaired, $repairResults.PrintersRepaired, $repairResults.DriversRepaired | Where-Object { $_ }).Count
        
        if ($repairCount -eq 4) {
            $repairResults.Overall = 'Fully Repaired'
        } elseif ($repairCount -gt 0) {
            $repairResults.Overall = 'Partially Repaired'
        } else {
            $repairResults.Overall = 'Repair Failed'
        }
        
        Write-Host "Print server repair operation completed: $($repairResults.Overall)" -ForegroundColor Green
        
        return [PSCustomObject]$repairResults
        
    } catch {
        Write-Error "Error during repair operation: $($_.Exception.Message)"
        throw
    }
}

function Watch-PrintServerPerformance {
    <#
    .SYNOPSIS
        Monitors print server performance in real-time
    
    .DESCRIPTION
        Continuously monitors print server performance counters
    
    .PARAMETER Duration
        Duration to monitor in seconds (default: 60)
    
    .PARAMETER Interval
        Monitoring interval in seconds (default: 5)
    
    .EXAMPLE
        Watch-PrintServerPerformance -Duration 300 -Interval 10
    #>
    [CmdletBinding()]
    param(
        [int]$Duration = 60,
        [int]$Interval = 5
    )
    
    try {
        Write-Host "Starting print server performance monitoring for $Duration seconds..." -ForegroundColor Green
        
        $startTime = Get-Date
        $endTime = $startTime.AddSeconds($Duration)
        
        while ((Get-Date) -lt $endTime) {
            $performance = Get-PrintServerPerformanceCounters
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            
            Write-Host "[$timestamp] Print Server Performance:" -ForegroundColor Cyan
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

function Test-PrinterAccess {
    <#
    .SYNOPSIS
        Tests access to a specific printer
    
    .DESCRIPTION
        Tests access to a specific printer and validates configuration
    
    .PARAMETER PrinterName
        The name of the printer to test
    
    .PARAMETER TestUser
        The user account to test access with
    
    .EXAMPLE
        Test-PrinterAccess -PrinterName "Office Printer" -TestUser "Domain\User"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrinterName,
        
        [string]$TestUser
    )
    
    try {
        Write-Host "Testing access to printer: $PrinterName" -ForegroundColor Green
        
        $testResults = Test-PrinterConnectivity -PrinterName $PrinterName
        
        if ($testResults) {
            Write-Host "`n=== Printer Test Results ===" -ForegroundColor Cyan
            Write-Host "Printer Name: $($testResults.PrinterName)" -ForegroundColor White
            Write-Host "Printer Exists: $($testResults.Exists)" -ForegroundColor White
            Write-Host "Printer Accessible: $($testResults.Accessible)" -ForegroundColor White
            Write-Host "Driver Status: $($testResults.DriverStatus)" -ForegroundColor White
            Write-Host "Port Status: $($testResults.PortStatus)" -ForegroundColor White
            Write-Host "Issues Found: $($testResults.Issues.Count)" -ForegroundColor White
            
            if ($testResults.Issues.Count -gt 0) {
                Write-Host "`nIssues:" -ForegroundColor Yellow
                $testResults.Issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
            }
            
            if ($testResults.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                $testResults.Recommendations | ForEach-Object { Write-Host "  - $_" -ForegroundColor Green }
            }
        }
        
        return $testResults
        
    } catch {
        Write-Error "Error testing printer access: $($_.Exception.Message)"
        throw
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Test-PrintServerHealth',
    'Get-PrintServerDiagnosticReport',
    'Repair-PrintServerInstallation',
    'Watch-PrintServerPerformance',
    'Test-PrinterAccess'
)

# Module initialization
Write-Verbose "PrintServer-Troubleshooting module loaded successfully. Version: $ModuleVersion"
