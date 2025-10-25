#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Storage Hardware Monitoring PowerShell Module

.DESCRIPTION
    This module provides comprehensive storage hardware monitoring capabilities
    including disk health monitoring, performance tracking, and hardware diagnostics.

.NOTES
    Author: Backup and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
    Based on: https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/backup-and-storage-overview
#>

# Module metadata
$ModuleVersion = "1.0.0"

#region Private Functions

function Get-StorageHardwareInfo {
    <#
    .SYNOPSIS
        Gets comprehensive storage hardware information
    #>
    [CmdletBinding()]
    param()
    
    try {
        $hardwareInfo = @{
            PhysicalDisks = @()
            StorageControllers = @()
            StoragePools = @()
            VirtualDisks = @()
        }
        
        # Get physical disk information
        $physicalDisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
        foreach ($disk in $physicalDisks) {
            $diskInfo = @{
                FriendlyName = $disk.FriendlyName
                DeviceId = $disk.DeviceId
                Size = $disk.Size
                MediaType = $disk.MediaType
                BusType = $disk.BusType
                HealthStatus = $disk.HealthStatus
                OperationalStatus = $disk.OperationalStatus
                Usage = $disk.Usage
                SerialNumber = $disk.SerialNumber
                FirmwareVersion = $disk.FirmwareVersion
                Temperature = $disk.Temperature
                SpindleSpeed = $disk.SpindleSpeed
            }
            $hardwareInfo.PhysicalDisks += [PSCustomObject]$diskInfo
        }
        
        # Get storage controller information
        $controllers = Get-StorageController -ErrorAction SilentlyContinue
        foreach ($controller in $controllers) {
            $controllerInfo = @{
                FriendlyName = $controller.FriendlyName
                DeviceId = $controller.DeviceId
                Manufacturer = $controller.Manufacturer
                Model = $controller.Model
                FirmwareVersion = $controller.FirmwareVersion
                DriverVersion = $controller.DriverVersion
                HealthStatus = $controller.HealthStatus
                OperationalStatus = $controller.OperationalStatus
            }
            $hardwareInfo.StorageControllers += [PSCustomObject]$controllerInfo
        }
        
        # Get storage pool information
        $storagePools = Get-StoragePool -ErrorAction SilentlyContinue
        foreach ($pool in $storagePools) {
            $poolInfo = @{
                FriendlyName = $pool.FriendlyName
                ObjectId = $pool.ObjectId
                Size = $pool.Size
                AllocatedSize = $pool.AllocatedSize
                HealthStatus = $pool.HealthStatus
                OperationalStatus = $pool.OperationalStatus
                IsPrimordial = $pool.IsPrimordial
            }
            $hardwareInfo.StoragePools += [PSCustomObject]$poolInfo
        }
        
        # Get virtual disk information
        $virtualDisks = Get-VirtualDisk -ErrorAction SilentlyContinue
        foreach ($vdisk in $virtualDisks) {
            $vdiskInfo = @{
                FriendlyName = $vdisk.FriendlyName
                ObjectId = $vdisk.ObjectId
                Size = $vdisk.Size
                AllocatedSize = $vdisk.AllocatedSize
                HealthStatus = $vdisk.HealthStatus
                OperationalStatus = $vdisk.OperationalStatus
                ResiliencySettingName = $vdisk.ResiliencySettingName
                NumberOfColumns = $vdisk.NumberOfColumns
                NumberOfDataCopies = $vdisk.NumberOfDataCopies
            }
            $hardwareInfo.VirtualDisks += [PSCustomObject]$vdiskInfo
        }
        
        return $hardwareInfo
        
    } catch {
        Write-Warning "Error getting storage hardware information: $($_.Exception.Message)"
        return $null
    }
}

function Get-StoragePerformanceCounters {
    <#
    .SYNOPSIS
        Gets storage performance counters
    #>
    [CmdletBinding()]
    param()
    
    try {
        $performanceCounters = @{
            PhysicalDiskCounters = @()
            LogicalDiskCounters = @()
            StorageSpacesCounters = @()
        }
        
        # Get physical disk performance counters
        $physicalDiskCounters = Get-Counter -Counter "\PhysicalDisk(*)\*" -ErrorAction SilentlyContinue
        if ($physicalDiskCounters) {
            foreach ($counter in $physicalDiskCounters.CounterSamples) {
                $counterInfo = @{
                    Path = $counter.Path
                    InstanceName = $counter.InstanceName
                    CookedValue = $counter.CookedValue
                    RawValue = $counter.RawValue
                    Timestamp = $counter.Timestamp
                }
                $performanceCounters.PhysicalDiskCounters += [PSCustomObject]$counterInfo
            }
        }
        
        # Get logical disk performance counters
        $logicalDiskCounters = Get-Counter -Counter "\LogicalDisk(*)\*" -ErrorAction SilentlyContinue
        if ($logicalDiskCounters) {
            foreach ($counter in $logicalDiskCounters.CounterSamples) {
                $counterInfo = @{
                    Path = $counter.Path
                    InstanceName = $counter.InstanceName
                    CookedValue = $counter.CookedValue
                    RawValue = $counter.RawValue
                    Timestamp = $counter.Timestamp
                }
                $performanceCounters.LogicalDiskCounters += [PSCustomObject]$counterInfo
            }
        }
        
        return $performanceCounters
        
    } catch {
        Write-Warning "Error getting storage performance counters: $($_.Exception.Message)"
        return $null
    }
}

#endregion

#region Public Functions

function Get-StorageHardwareStatus {
    <#
    .SYNOPSIS
        Gets comprehensive storage hardware status
    
    .DESCRIPTION
        This function retrieves comprehensive storage hardware status information
        including physical disks, controllers, storage pools, and virtual disks.
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-StorageHardwareStatus
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Getting storage hardware status..."
        
        $statusResults = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            HardwareInfo = $null
            PerformanceCounters = $null
            Summary = @{}
        }
        
        # Get hardware information
        $statusResults.HardwareInfo = Get-StorageHardwareInfo
        
        # Get performance counters
        $statusResults.PerformanceCounters = Get-StoragePerformanceCounters
        
        # Generate summary
        if ($statusResults.HardwareInfo) {
            $statusResults.Summary = @{
                TotalPhysicalDisks = $statusResults.HardwareInfo.PhysicalDisks.Count
                HealthyPhysicalDisks = ($statusResults.HardwareInfo.PhysicalDisks | Where-Object { $_.HealthStatus -eq "Healthy" }).Count
                UnhealthyPhysicalDisks = ($statusResults.HardwareInfo.PhysicalDisks | Where-Object { $_.HealthStatus -ne "Healthy" }).Count
                TotalStorageControllers = $statusResults.HardwareInfo.StorageControllers.Count
                HealthyStorageControllers = ($statusResults.HardwareInfo.StorageControllers | Where-Object { $_.HealthStatus -eq "Healthy" }).Count
                TotalStoragePools = $statusResults.HardwareInfo.StoragePools.Count
                TotalVirtualDisks = $statusResults.HardwareInfo.VirtualDisks.Count
                HealthyVirtualDisks = ($statusResults.HardwareInfo.VirtualDisks | Where-Object { $_.HealthStatus -eq "Healthy" }).Count
                OverallHealth = if ($statusResults.Summary.UnhealthyPhysicalDisks -eq 0) { "Healthy" } elseif ($statusResults.Summary.UnhealthyPhysicalDisks -lt 3) { "Warning" } else { "Critical" }
            }
        }
        
        Write-Verbose "Storage hardware status retrieved successfully"
        return [PSCustomObject]$statusResults
        
    } catch {
        Write-Error "Error getting storage hardware status: $($_.Exception.Message)"
        return $null
    }
}

function Watch-StorageHardwareHealth {
    <#
    .SYNOPSIS
        Monitors storage hardware health continuously
    
    .DESCRIPTION
        This function starts continuous monitoring of storage hardware health
        and alerts when issues are detected.
    
    .PARAMETER MonitoringInterval
        Monitoring interval in minutes (default: 5)
    
    .PARAMETER AlertThreshold
        Number of unhealthy components before alerting (default: 1)
    
    .PARAMETER LogPath
        Path to save monitoring logs
    
    .PARAMETER EmailAlerts
        Email addresses for alerts
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Monitor-StorageHardwareHealth -MonitoringInterval 10
    
    .EXAMPLE
        Monitor-StorageHardwareHealth -MonitoringInterval 5 -AlertThreshold 2 -LogPath "C:\Logs\StorageHealth.log"
    #>
    [CmdletBinding()]
    param(
        [int]$MonitoringInterval = 5,
        
        [int]$AlertThreshold = 1,
        
        [string]$LogPath,
        
        [string[]]$EmailAlerts
    )
    
    try {
        Write-Verbose "Starting storage hardware health monitoring..."
        
        $monitoringResults = @{
            StartTime = Get-Date
            ComputerName = $env:COMPUTERNAME
            MonitoringInterval = $MonitoringInterval
            AlertThreshold = $AlertThreshold
            LogPath = $LogPath
            EmailAlerts = $EmailAlerts
            MonitoringActive = $true
            ChecksPerformed = 0
            AlertsGenerated = 0
            LastCheckTime = $null
            LastCheckResults = $null
        }
        
        Write-Verbose "Storage hardware health monitoring started"
        Write-Verbose "Monitoring interval: $MonitoringInterval minutes"
        Write-Verbose "Alert threshold: $AlertThreshold unhealthy components"
        
        # Start monitoring loop
        while ($monitoringResults.MonitoringActive) {
            try {
                $checkTime = Get-Date
                $monitoringResults.LastCheckTime = $checkTime
                $monitoringResults.ChecksPerformed++
                
                Write-Verbose "Performing storage hardware health check #$($monitoringResults.ChecksPerformed)..."
                
                # Perform health check
                $healthStatus = Get-StorageHardwareStatus
                $monitoringResults.LastCheckResults = $healthStatus
                
                # Check for alerts
                $unhealthyComponents = 0
                if ($healthStatus.HardwareInfo) {
                    $unhealthyComponents += $healthStatus.Summary.UnhealthyPhysicalDisks
                    $unhealthyComponents += ($healthStatus.Summary.TotalStorageControllers - $healthStatus.Summary.HealthyStorageControllers)
                    $unhealthyComponents += ($healthStatus.Summary.TotalVirtualDisks - $healthStatus.Summary.HealthyVirtualDisks)
                }
                
                if ($unhealthyComponents -ge $AlertThreshold) {
                    $monitoringResults.AlertsGenerated++
                    
                    $alertMessage = "STORAGE HARDWARE ALERT: $unhealthyComponents unhealthy components detected"
                    Write-Warning $alertMessage
                    
                    # Log alert
                    if ($LogPath) {
                        $logEntry = "[$checkTime] ALERT: $alertMessage"
                        Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
                    }
                    
                    # Send email alert if configured
                    if ($EmailAlerts) {
                        try {
                            # Note: Email sending would require additional configuration
                            Write-Verbose "Email alert would be sent to: $($EmailAlerts -join ', ')"
                        } catch {
                            Write-Warning "Failed to send email alert: $($_.Exception.Message)"
                        }
                    }
                }
                
                # Log check results
                if ($LogPath) {
                    $logEntry = "[$checkTime] Check #$($monitoringResults.ChecksPerformed): $unhealthyComponents unhealthy components detected"
                    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
                }
                
                Write-Verbose "Storage hardware health check completed. Unhealthy components: $unhealthyComponents"
                
                # Wait for next check
                Start-Sleep -Seconds ($MonitoringInterval * 60)
                
            } catch {
                Write-Warning "Error during storage hardware health monitoring: $($_.Exception.Message)"
                Start-Sleep -Seconds 60  # Wait 1 minute before retrying
            }
        }
        
        return [PSCustomObject]$monitoringResults
        
    } catch {
        Write-Error "Error starting storage hardware health monitoring: $($_.Exception.Message)"
        return $null
    }
}

function Test-StorageHardwarePerformance {
    <#
    .SYNOPSIS
        Tests storage hardware performance
    
    .DESCRIPTION
        This function tests storage hardware performance by analyzing
        performance counters and identifying bottlenecks.
    
    .PARAMETER TestDuration
        Duration of the test in seconds (default: 60)
    
    .PARAMETER IncludeCounters
        Specific performance counters to include
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Test-StorageHardwarePerformance
    
    .EXAMPLE
        Test-StorageHardwarePerformance -TestDuration 120 -IncludeCounters @("Disk Read/sec", "Disk Write/sec")
    #>
    [CmdletBinding()]
    param(
        [int]$TestDuration = 60,
        
        [string[]]$IncludeCounters
    )
    
    try {
        Write-Verbose "Testing storage hardware performance for $TestDuration seconds..."
        
        $performanceResult = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            TestDuration = $TestDuration
            IncludeCounters = $IncludeCounters
            PerformanceData = @()
            Analysis = @{}
            OverallPerformance = "Unknown"
        }
        
        try {
            # Define performance counters to monitor
            $counters = @(
                "\PhysicalDisk(*)\Disk Read Bytes/sec",
                "\PhysicalDisk(*)\Disk Write Bytes/sec",
                "\PhysicalDisk(*)\Disk Reads/sec",
                "\PhysicalDisk(*)\Disk Writes/sec",
                "\PhysicalDisk(*)\% Disk Time",
                "\PhysicalDisk(*)\Avg. Disk Queue Length",
                "\LogicalDisk(*)\Disk Read Bytes/sec",
                "\LogicalDisk(*)\Disk Write Bytes/sec",
                "\LogicalDisk(*)\% Disk Time"
            )
            
            if ($IncludeCounters) {
                $counters = $IncludeCounters
            }
            
            # Collect performance data
            $startTime = Get-Date
            $endTime = $startTime.AddSeconds($TestDuration)
            
            while ((Get-Date) -lt $endTime) {
                $sampleTime = Get-Date
                $counterData = Get-Counter -Counter $counters -ErrorAction SilentlyContinue
                
                if ($counterData) {
                    $sampleData = @{
                        Timestamp = $sampleTime
                        Counters = @()
                    }
                    
                    foreach ($counter in $counterData.CounterSamples) {
                        $counterInfo = @{
                            Path = $counter.Path
                            InstanceName = $counter.InstanceName
                            CookedValue = $counter.CookedValue
                            RawValue = $counter.RawValue
                        }
                        $sampleData.Counters += [PSCustomObject]$counterInfo
                    }
                    
                    $performanceResult.PerformanceData += [PSCustomObject]$sampleData
                }
                
                Start-Sleep -Seconds 5  # Sample every 5 seconds
            }
            
            # Analyze performance data
            $analysis = @{
                TotalSamples = $performanceResult.PerformanceData.Count
                AverageDiskTime = 0
                PeakDiskTime = 0
                AverageQueueLength = 0
                PeakQueueLength = 0
                TotalReadBytes = 0
                TotalWriteBytes = 0
                Recommendations = @()
            }
            
            # Calculate averages and peaks
            $diskTimeValues = @()
            $queueLengthValues = @()
            
            foreach ($sample in $performanceResult.PerformanceData) {
                foreach ($counter in $sample.Counters) {
                    if ($counter.Path -like "*% Disk Time*") {
                        $diskTimeValues += $counter.CookedValue
                    }
                    if ($counter.Path -like "*Queue Length*") {
                        $queueLengthValues += $counter.CookedValue
                    }
                }
            }
            
            if ($diskTimeValues.Count -gt 0) {
                $analysis.AverageDiskTime = [math]::Round(($diskTimeValues | Measure-Object -Average).Average, 2)
                $analysis.PeakDiskTime = [math]::Round(($diskTimeValues | Measure-Object -Maximum).Maximum, 2)
            }
            
            if ($queueLengthValues.Count -gt 0) {
                $analysis.AverageQueueLength = [math]::Round(($queueLengthValues | Measure-Object -Average).Average, 2)
                $analysis.PeakQueueLength = [math]::Round(($queueLengthValues | Measure-Object -Maximum).Maximum, 2)
            }
            
            # Generate recommendations
            if ($analysis.AverageDiskTime -gt 80) {
                $analysis.Recommendations += "High disk utilization detected. Consider adding more storage or optimizing I/O patterns."
            }
            
            if ($analysis.AverageQueueLength -gt 2) {
                $analysis.Recommendations += "High disk queue length detected. Consider using faster storage or optimizing applications."
            }
            
            if ($analysis.AverageDiskTime -lt 20) {
                $analysis.Recommendations += "Low disk utilization. Storage performance appears adequate."
            }
            
            $performanceResult.Analysis = $analysis
            
            # Determine overall performance
            if ($analysis.AverageDiskTime -lt 50 -and $analysis.AverageQueueLength -lt 1) {
                $performanceResult.OverallPerformance = "Excellent"
            } elseif ($analysis.AverageDiskTime -lt 80 -and $analysis.AverageQueueLength -lt 2) {
                $performanceResult.OverallPerformance = "Good"
            } elseif ($analysis.AverageDiskTime -lt 95 -and $analysis.AverageQueueLength -lt 4) {
                $performanceResult.OverallPerformance = "Fair"
            } else {
                $performanceResult.OverallPerformance = "Poor"
            }
            
        } catch {
            Write-Warning "Error during performance test: $($_.Exception.Message)"
        }
        
        Write-Verbose "Storage hardware performance test completed. Overall performance: $($performanceResult.OverallPerformance)"
        return [PSCustomObject]$performanceResult
        
    } catch {
        Write-Error "Error testing storage hardware performance: $($_.Exception.Message)"
        return $null
    }
}

function Get-StorageHardwareReport {
    <#
    .SYNOPSIS
        Generates a comprehensive storage hardware report
    
    .DESCRIPTION
        This function creates a detailed report of storage hardware status,
        performance, and recommendations.
    
    .PARAMETER OutputPath
        Path to save the report
    
    .PARAMETER IncludePerformanceData
        Include performance analysis in the report
    
    .PARAMETER IncludeRecommendations
        Include recommendations in the report
    
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    
    .EXAMPLE
        Get-StorageHardwareReport -OutputPath "C:\Reports\StorageHardware.html"
    
    .EXAMPLE
        Get-StorageHardwareReport -OutputPath "C:\Reports\StorageHardware.html" -IncludePerformanceData -IncludeRecommendations
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath,
        
        [switch]$IncludePerformanceData,
        
        [switch]$IncludeRecommendations
    )
    
    try {
        Write-Verbose "Generating storage hardware report..."
        
        $report = @{
            Timestamp = Get-Date
            ComputerName = $env:COMPUTERNAME
            HardwareStatus = Get-StorageHardwareStatus
            PerformanceData = $null
            Recommendations = @()
        }
        
        # Include performance data if requested
        if ($IncludePerformanceData) {
            $report.PerformanceData = Test-StorageHardwarePerformance -TestDuration 30
        }
        
        # Generate recommendations
        if ($IncludeRecommendations) {
            if ($report.HardwareStatus.Summary.UnhealthyPhysicalDisks -gt 0) {
                $report.Recommendations += "Replace unhealthy physical disks: $($report.HardwareStatus.Summary.UnhealthyPhysicalDisks) disks need attention"
            }
            
            if ($report.HardwareStatus.Summary.TotalPhysicalDisks -lt 2) {
                $report.Recommendations += "Consider adding redundant storage for better availability"
            }
            
            if ($report.PerformanceData -and $report.PerformanceData.OverallPerformance -eq "Poor") {
                $report.Recommendations += "Storage performance is poor. Consider upgrading to faster storage or optimizing I/O patterns"
            }
            
            if ($report.HardwareStatus.Summary.TotalStoragePools -eq 0) {
                $report.Recommendations += "Consider implementing Storage Spaces for better storage management"
            }
        }
        
        $reportObject = [PSCustomObject]$report
        
        if ($OutputPath) {
            # Convert to HTML report
            $htmlReport = $reportObject | ConvertTo-Html -Title "Storage Hardware Report" -Head @"
<style>
body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
.container { background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
h1 { color: #333; border-bottom: 2px solid #dc3545; padding-bottom: 10px; }
h2 { color: #dc3545; margin-top: 30px; }
h3 { color: #666; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; font-weight: bold; }
.healthy { color: #28a745; font-weight: bold; }
.warning { color: #ffc107; font-weight: bold; }
.critical { color: #dc3545; font-weight: bold; }
.recommendation { background-color: #d1ecf1; padding: 10px; margin: 5px 0; border-left: 4px solid #17a2b8; }
</style>
"@
            
            $htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Verbose "Storage hardware report saved to: $OutputPath"
        }
        
        return $reportObject
        
    } catch {
        Write-Error "Error generating storage hardware report: $($_.Exception.Message)"
        return $null
    }
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Get-StorageHardwareStatus',
    'Watch-StorageHardwareHealth',
    'Test-StorageHardwarePerformance',
    'Get-StorageHardwareReport'
)

# Module initialization
Write-Verbose "BackupStorage-HardwareMonitoring module loaded successfully. Version: $ModuleVersion"
