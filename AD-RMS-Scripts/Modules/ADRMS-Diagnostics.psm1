#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Active Directory Rights Management Services Diagnostics Module

.DESCRIPTION
    This module provides comprehensive diagnostic and troubleshooting functions
    for AD RMS including health checks, log analysis, and performance monitoring.

.NOTES
    Author: AD RMS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

# Module metadata
$ModuleVersion = "1.0.0"

# Import required modules
try {
    Import-Module ADRMS-Core -ErrorAction Stop
    Import-Module ADRMS-Configuration -ErrorAction Stop
} catch {
    Write-Warning "Required modules not found. Some functions may not work properly."
}

#region Private Functions

function Get-ADRMSLogEntries {
    <#
    .SYNOPSIS
        Retrieves AD RMS log entries from Windows Event Log
    
    .DESCRIPTION
        Gets AD RMS related events from the Application and System event logs
    
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
            $_.ProviderName -like "*RMS*" -or 
            $_.Message -like "*RMS*" -or
            $_.Message -like "*Rights Management*"
        }
        
        return $logEntries
        
    } catch {
        Write-Warning "Error retrieving log entries: $($_.Exception.Message)"
        return @()
    }
}

function Test-ADRMSConnectivity {
    <#
    .SYNOPSIS
        Tests AD RMS connectivity and endpoints
    
    .DESCRIPTION
        Performs connectivity tests to AD RMS endpoints
    
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
            "http://localhost/_wmcs/licensing",
            "http://localhost/_wmcs/certification",
            "http://localhost/_wmcs/admin"
        )
        
        foreach ($endpoint in $localEndpoints) {
            try {
                $response = Invoke-WebRequest -Uri $endpoint -TimeoutSec 10 -ErrorAction Stop
                $connectivity.LocalEndpoints[$endpoint] = "Accessible ($($response.StatusCode))"
            } catch {
                $connectivity.LocalEndpoints[$endpoint] = "Not Accessible: $($_.Exception.Message)"
            }
        }
        
        # Test remote endpoints (if configured)
        $config = Get-ADRMSConfiguration
        if ($config.ClusterUrl) {
            $remoteEndpoints = @(
                "$($config.ClusterUrl)/licensing",
                "$($config.ClusterUrl)/certification",
                "$($config.ClusterUrl)/admin"
            )
            
            foreach ($endpoint in $remoteEndpoints) {
                try {
                    $response = Invoke-WebRequest -Uri $endpoint -TimeoutSec 10 -ErrorAction Stop
                    $connectivity.RemoteEndpoints[$endpoint] = "Accessible ($($response.StatusCode))"
                } catch {
                    $connectivity.RemoteEndpoints[$endpoint] = "Not Accessible: $($_.Exception.Message)"
                }
            }
        }
        
        # Determine overall connectivity
        $accessibleCount = ($connectivity.LocalEndpoints.Values | Where-Object { $_ -like "Accessible*" }).Count
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

function Get-ADRMSPerformanceCounters {
    <#
    .SYNOPSIS
        Gets AD RMS performance counters
    
    .DESCRIPTION
        Retrieves performance counter data for AD RMS
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    try {
        $counters = @{}
        
        # Define performance counters to check
        $counterNames = @(
            "\Process(MSDRMS)\% Processor Time",
            "\Process(MSDRMS)\Working Set",
            "\Process(MSDRMS)\Handle Count",
            "\Web Service(_Total)\Current Connections",
            "\Web Service(_Total)\Total Method Requests/sec"
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

#endregion

#region Public Functions

function Test-ADRMSHealth {
    <#
    .SYNOPSIS
        Performs comprehensive AD RMS health check
    
    .DESCRIPTION
        Executes a full health check including services, connectivity, and configuration
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Performing comprehensive AD RMS health check..." -ForegroundColor Green
        
        $healthReport = @{
            Timestamp = Get-Date
            Services = @{}
            Configuration = @{}
            Connectivity = @{}
            Performance = @{}
            Logs = @{}
            Overall = 'Unknown'
            Recommendations = @()
        }
        
        # Check services
        $services = @('MSDRMS', 'W3SVC', 'IISADMIN')
        foreach ($serviceName in $services) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                $healthReport.Services[$serviceName] = $service.Status
            } else {
                $healthReport.Services[$serviceName] = 'Not Found'
            }
        }
        
        # Check configuration
        $configStatus = Test-ADRMSConfiguration
        $healthReport.Configuration = $configStatus
        
        # Check connectivity
        $connectivity = Test-ADRMSConnectivity
        $healthReport.Connectivity = $connectivity
        
        # Check performance
        $performance = Get-ADRMSPerformanceCounters
        $healthReport.Performance = $performance
        
        # Check recent logs for errors
        $errorLogs = Get-ADRMSLogEntries -LogName "Application" -StartTime (Get-Date).AddHours(-1) | Where-Object { $_.LevelDisplayName -eq "Error" }
        $healthReport.Logs.ErrorCount = $errorLogs.Count
        $healthReport.Logs.RecentErrors = $errorLogs | Select-Object -First 5 | ForEach-Object { $_.Message }
        
        # Generate recommendations
        if ($healthReport.Services.MSDRMS -ne 'Running') {
            $healthReport.Recommendations += "Start the MSDRMS service"
        }
        
        if ($healthReport.Configuration.Overall -ne 'Fully Configured') {
            $healthReport.Recommendations += "Complete AD RMS configuration"
        }
        
        if ($healthReport.Connectivity.Overall -ne 'All Accessible') {
            $healthReport.Recommendations += "Check network connectivity and firewall settings"
        }
        
        if ($healthReport.Logs.ErrorCount -gt 0) {
            $healthReport.Recommendations += "Review recent error logs for issues"
        }
        
        # Determine overall health
        $allServicesRunning = ($healthReport.Services.Values -eq 'Running').Count -eq $healthReport.Services.Count
        $fullyConfigured = $healthReport.Configuration.Overall -eq 'Fully Configured'
        $allAccessible = $healthReport.Connectivity.Overall -eq 'All Accessible'
        $noRecentErrors = $healthReport.Logs.ErrorCount -eq 0
        
        if ($allServicesRunning -and $fullyConfigured -and $allAccessible -and $noRecentErrors) {
            $healthReport.Overall = 'Healthy'
        } elseif ($allServicesRunning -and $fullyConfigured) {
            $healthReport.Overall = 'Degraded'
        } else {
            $healthReport.Overall = 'Unhealthy'
        }
        
        return [PSCustomObject]$healthReport
        
    } catch {
        Write-Error "Error performing health check: $($_.Exception.Message)"
        throw
    }
}

function Get-ADRMSDiagnosticReport {
    <#
    .SYNOPSIS
        Generates a comprehensive diagnostic report for AD RMS
    
    .DESCRIPTION
        Creates a detailed diagnostic report including all aspects of AD RMS
    
    .PARAMETER OutputPath
        Path to save the diagnostic report
    
    .PARAMETER IncludeLogs
        Include recent log entries in the report
    
    .EXAMPLE
        Get-ADRMSDiagnosticReport -OutputPath "C:\Reports\ADRMS-Diagnostic.html"
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        [switch]$IncludeLogs
    )
    
    try {
        Write-Host "Generating comprehensive AD RMS diagnostic report..." -ForegroundColor Green
        
        $report = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            Domain = $env:USERDOMAIN
            HealthCheck = Test-ADRMSHealth
            Configuration = Get-ADRMSConfigurationStatus
            Status = Get-ADRMSStatus
        }
        
        if ($IncludeLogs) {
            $report.RecentLogs = Get-ADRMSLogEntries -StartTime (Get-Date).AddDays(-1)
        }
        
        $reportObject = [PSCustomObject]$report
        
        if ($OutputPath) {
            # Convert to HTML report
            $htmlReport = $reportObject | ConvertTo-Html -Title "AD RMS Diagnostic Report" -Head "<style>body{font-family:Arial;margin:20px;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ddd;padding:8px;text-align:left;}th{background-color:#f2f2f2;}</style>"
            $htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "Diagnostic report saved to: $OutputPath" -ForegroundColor Green
        }
        
        return $reportObject
        
    } catch {
        Write-Error "Error generating diagnostic report: $($_.Exception.Message)"
        throw
    }
}

function Repair-ADRMSInstallation {
    <#
    .SYNOPSIS
        Attempts to repair AD RMS installation issues
    
    .DESCRIPTION
        Performs common repair operations for AD RMS
    
    .PARAMETER RepairType
        Type of repair to perform (All, Services, Configuration, IIS)
    
    .EXAMPLE
        Repair-ADRMSInstallation -RepairType "Services"
    #>
    [CmdletBinding()]
    param(
        [ValidateSet("All", "Services", "Configuration", "IIS")]
        [string]$RepairType = "All"
    )
    
    try {
        Write-Host "Starting AD RMS repair operation: $RepairType" -ForegroundColor Green
        
        $repairResults = @{
            ServicesRepaired = $false
            ConfigurationRepaired = $false
            IISRepaired = $false
            Overall = 'Unknown'
        }
        
        if ($RepairType -eq "All" -or $RepairType -eq "Services") {
            Write-Host "Repairing services..." -ForegroundColor Yellow
            
            # Stop services
            Stop-ADRMSServices
            
            # Start services
            Start-ADRMSServices
            
            $repairResults.ServicesRepaired = $true
            Write-Host "Services repair completed" -ForegroundColor Green
        }
        
        if ($RepairType -eq "All" -or $RepairType -eq "Configuration") {
            Write-Host "Checking configuration..." -ForegroundColor Yellow
            
            $configStatus = Test-ADRMSConfiguration
            if ($configStatus.Overall -ne 'Fully Configured') {
                Write-Warning "Configuration issues detected. Manual intervention may be required."
            } else {
                $repairResults.ConfigurationRepaired = $true
                Write-Host "Configuration check completed" -ForegroundColor Green
            }
        }
        
        if ($RepairType -eq "All" -or $RepairType -eq "IIS") {
            Write-Host "Repairing IIS configuration..." -ForegroundColor Yellow
            
            try {
                Import-Module WebAdministration -ErrorAction Stop
                
                # Reset IIS
                iisreset /stop
                Start-Sleep -Seconds 5
                iisreset /start
                
                $repairResults.IISRepaired = $true
                Write-Host "IIS repair completed" -ForegroundColor Green
            } catch {
                Write-Warning "IIS repair failed: $($_.Exception.Message)"
            }
        }
        
        # Determine overall repair status
        $repairCount = ($repairResults.ServicesRepaired, $repairResults.ConfigurationRepaired, $repairResults.IISRepaired | Where-Object { $_ }).Count
        
        if ($repairCount -eq 3) {
            $repairResults.Overall = 'Fully Repaired'
        } elseif ($repairCount -gt 0) {
            $repairResults.Overall = 'Partially Repaired'
        } else {
            $repairResults.Overall = 'Repair Failed'
        }
        
        Write-Host "AD RMS repair operation completed: $($repairResults.Overall)" -ForegroundColor Green
        
        return [PSCustomObject]$repairResults
        
    } catch {
        Write-Error "Error during repair operation: $($_.Exception.Message)"
        throw
    }
}

function Watch-ADRMSPerformance {
    <#
    .SYNOPSIS
        Monitors AD RMS performance in real-time
    
    .DESCRIPTION
        Continuously monitors AD RMS performance counters
    
    .PARAMETER Duration
        Duration to monitor in seconds (default: 60)
    
    .PARAMETER Interval
        Monitoring interval in seconds (default: 5)
    
    .EXAMPLE
        Watch-ADRMSPerformance -Duration 300 -Interval 10
    #>
    [CmdletBinding()]
    param(
        [int]$Duration = 60,
        [int]$Interval = 5
    )
    
    try {
        Write-Host "Starting AD RMS performance monitoring for $Duration seconds..." -ForegroundColor Green
        
        $startTime = Get-Date
        $endTime = $startTime.AddSeconds($Duration)
        
        while ((Get-Date) -lt $endTime) {
            $performance = Get-ADRMSPerformanceCounters
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            
            Write-Host "[$timestamp] AD RMS Performance:" -ForegroundColor Cyan
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

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Test-ADRMSHealth',
    'Get-ADRMSDiagnosticReport',
    'Repair-ADRMSInstallation',
    'Watch-ADRMSPerformance'
)

# Module initialization
Write-Verbose "ADRMS-Diagnostics module loaded successfully. Version: $ModuleVersion"
