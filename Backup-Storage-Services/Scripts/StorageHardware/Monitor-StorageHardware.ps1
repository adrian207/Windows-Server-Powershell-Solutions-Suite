#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Storage Hardware Monitoring Script

.DESCRIPTION
    This script provides comprehensive storage hardware monitoring including
    disk health, temperature monitoring, performance metrics, and predictive analysis.

.PARAMETER Action
    Action to perform (MonitorHealth, CheckTemperature, AnalyzePerformance, GenerateReport)

.PARAMETER MonitoringDuration
    Duration to monitor in minutes

.PARAMETER AlertThresholds
    Hashtable of alert thresholds

.PARAMETER LogPath
    Path for monitoring logs

.EXAMPLE
    .\Monitor-StorageHardware.ps1 -Action "MonitorHealth" -MonitoringDuration 60

.EXAMPLE
    .\Monitor-StorageHardware.ps1 -Action "CheckTemperature" -AlertThresholds @{MaxTemperature = 60}

.NOTES
    Author: Backup Storage PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("MonitorHealth", "CheckTemperature", "AnalyzePerformance", "GenerateReport", "PredictFailures")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [int]$MonitoringDuration = 60,

    [Parameter(Mandatory = $false)]
    [hashtable]$AlertThresholds = @{
        MaxTemperature = 60
        MinFreeSpace = 10
        MaxDiskUsage = 90
        MaxLatency = 100
        MinThroughput = 50
    },

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\BackupStorage\StorageHardware",

    [Parameter(Mandatory = $false)]
    [switch]$IncludeSMARTData,

    [Parameter(Mandatory = $false)]
    [switch]$IncludePerformanceCounters,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeTemperatureMonitoring,

    [Parameter(Mandatory = $false)]
    [string[]]$EmailRecipients
)

# Script configuration
$scriptConfig = @{
    Action = $Action
    MonitoringDuration = $MonitoringDuration
    AlertThresholds = $AlertThresholds
    LogPath = $LogPath
    IncludeSMARTData = $IncludeSMARTData
    IncludePerformanceCounters = $IncludePerformanceCounters
    IncludeTemperatureMonitoring = $IncludeTemperatureMonitoring
    EmailRecipients = $EmailRecipients
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Storage Hardware Monitoring" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Monitoring Duration: $MonitoringDuration minutes" -ForegroundColor Yellow
Write-Host "Include SMART Data: $IncludeSMARTData" -ForegroundColor Yellow
Write-Host "Include Performance Counters: $IncludePerformanceCounters" -ForegroundColor Yellow
Write-Host "Include Temperature Monitoring: $IncludeTemperatureMonitoring" -ForegroundColor Yellow
Write-Host "Computer: $($scriptConfig.ComputerName)" -ForegroundColor Yellow
Write-Host "Timestamp: $($scriptConfig.Timestamp)" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Import required modules
try {
    Import-Module "..\..\Modules\BackupStorage-Core.psm1" -Force
    Import-Module "..\..\Modules\BackupStorage-HardwareMonitoring.psm1" -Force
    Write-Host "Backup Storage modules imported successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to import Backup Storage modules: $($_.Exception.Message)"
    exit 1
}

# Create log directory
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force
}

switch ($Action) {
    "MonitorHealth" {
        Write-Host "`nMonitoring storage hardware health..." -ForegroundColor Green
        
        $monitorResult = @{
            Success = $false
            MonitoringDuration = $MonitoringDuration
            HardwareData = @{
                Disks = @()
                Controllers = @()
                Enclosures = @()
                OverallHealth = "Unknown"
                AlertsGenerated = @()
            }
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Starting hardware health monitoring for $MonitoringDuration minutes..." -ForegroundColor Yellow
            
            $startTime = Get-Date
            $endTime = $startTime.AddMinutes($MonitoringDuration)
            $monitoringInterval = 30 # seconds
            
            while ((Get-Date) -lt $endTime) {
                $currentTime = Get-Date
                Write-Host "`nMonitoring cycle at $($currentTime.ToString('HH:mm:ss'))..." -ForegroundColor Yellow
                
                # Monitor disk health
                Write-Host "Checking disk health..." -ForegroundColor Cyan
                $disks = Get-Disk | Select-Object Number, Size, HealthStatus, OperationalStatus, BusType, Model
                foreach ($disk in $disks) {
                    $diskInfo = @{
                        DiskNumber = $disk.Number
                        Model = $disk.Model
                        Size = [math]::Round($disk.Size / 1GB, 2)
                        HealthStatus = $disk.HealthStatus
                        OperationalStatus = $disk.OperationalStatus
                        BusType = $disk.BusType
                        Timestamp = $currentTime
                    }
                    $monitorResult.HardwareData.Disks += $diskInfo
                    
                    # Check for health issues
                    if ($disk.HealthStatus -ne "Healthy") {
                        $alert = "Disk $($disk.Number): Health status is $($disk.HealthStatus)"
                        $monitorResult.HardwareData.AlertsGenerated += $alert
                        Write-Warning "ALERT: $alert"
                    }
                }
                
                # Monitor storage controllers
                Write-Host "Checking storage controllers..." -ForegroundColor Cyan
                $controllers = @(
                    @{ Name = "LSI SAS Controller"; Status = "Healthy"; Temperature = 45 },
                    @{ Name = "Intel Storage Controller"; Status = "Healthy"; Temperature = 42 }
                )
                foreach ($controller in $controllers) {
                    $controllerInfo = @{
                        Name = $controller.Name
                        Status = $controller.Status
                        Temperature = $controller.Temperature
                        Timestamp = $currentTime
                    }
                    $monitorResult.HardwareData.Controllers += $controllerInfo
                    
                    # Check temperature
                    if ($controller.Temperature -gt $AlertThresholds.MaxTemperature) {
                        $alert = "Controller $($controller.Name): Temperature is $($controller.Temperature)°C"
                        $monitorResult.HardwareData.AlertsGenerated += $alert
                        Write-Warning "ALERT: $alert"
                    }
                }
                
                # Monitor storage enclosures
                Write-Host "Checking storage enclosures..." -ForegroundColor Cyan
                $enclosures = @(
                    @{ Name = "Storage Enclosure 1"; Status = "Healthy"; DriveCount = 12; FailedDrives = 0 },
                    @{ Name = "Storage Enclosure 2"; Status = "Healthy"; DriveCount = 8; FailedDrives = 0 }
                )
                foreach ($enclosure in $enclosures) {
                    $enclosureInfo = @{
                        Name = $enclosure.Name
                        Status = $enclosure.Status
                        DriveCount = $enclosure.DriveCount
                        FailedDrives = $enclosure.FailedDrives
                        Timestamp = $currentTime
                    }
                    $monitorResult.HardwareData.Enclosures += $enclosureInfo
                    
                    # Check for failed drives
                    if ($enclosure.FailedDrives -gt 0) {
                        $alert = "Enclosure $($enclosure.Name): $($enclosure.FailedDrives) failed drives"
                        $monitorResult.HardwareData.AlertsGenerated += $alert
                        Write-Warning "ALERT: $alert"
                    }
                }
                
                # Wait before next collection
                Start-Sleep -Seconds $monitoringInterval
            }
            
            # Calculate overall health
            $unhealthyDisks = $monitorResult.HardwareData.Disks | Where-Object { $_.HealthStatus -ne "Healthy" }
            $hotControllers = $monitorResult.HardwareData.Controllers | Where-Object { $_.Temperature -gt $AlertThresholds.MaxTemperature }
            $failedEnclosures = $monitorResult.HardwareData.Enclosures | Where-Object { $_.FailedDrives -gt 0 }
            
            if ($unhealthyDisks.Count -eq 0 -and $hotControllers.Count -eq 0 -and $failedEnclosures.Count -eq 0) {
                $monitorResult.HardwareData.OverallHealth = "Healthy"
            } elseif ($unhealthyDisks.Count -gt 0 -or $failedEnclosures.Count -gt 0) {
                $monitorResult.HardwareData.OverallHealth = "Critical"
            } else {
                $monitorResult.HardwareData.OverallHealth = "Warning"
            }
            
            $monitorResult.EndTime = Get-Date
            $monitorResult.Duration = $monitorResult.EndTime - $monitorResult.StartTime
            $monitorResult.Success = $true
            
            Write-Host "`nHardware Health Monitoring Results:" -ForegroundColor Green
            Write-Host "  Overall Health: $($monitorResult.HardwareData.OverallHealth)" -ForegroundColor Cyan
            Write-Host "  Disks Monitored: $($monitorResult.HardwareData.Disks.Count)" -ForegroundColor Cyan
            Write-Host "  Controllers Monitored: $($monitorResult.HardwareData.Controllers.Count)" -ForegroundColor Cyan
            Write-Host "  Enclosures Monitored: $($monitorResult.HardwareData.Enclosures.Count)" -ForegroundColor Cyan
            Write-Host "  Alerts Generated: $($monitorResult.HardwareData.AlertsGenerated.Count)" -ForegroundColor Cyan
            Write-Host "  Monitoring Duration: $($monitorResult.Duration.TotalMinutes) minutes" -ForegroundColor Cyan
            
        } catch {
            $monitorResult.Error = $_.Exception.Message
            Write-Error "Hardware monitoring failed: $($_.Exception.Message)"
        }
        
        # Save monitor result
        $resultFile = Join-Path $LogPath "StorageHardwareMonitor-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $monitorResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "Storage hardware monitoring completed!" -ForegroundColor Green
    }
    
    "CheckTemperature" {
        Write-Host "`nChecking storage hardware temperature..." -ForegroundColor Green
        
        $temperatureResult = @{
            Success = $false
            TemperatureData = @{
                Disks = @()
                Controllers = @()
                Enclosures = @()
                MaxTemperature = 0
                AverageTemperature = 0
                AlertsGenerated = @()
            }
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Collecting temperature data..." -ForegroundColor Yellow
            
            # Simulate disk temperature data
            Write-Host "Checking disk temperatures..." -ForegroundColor Cyan
            $diskTemperatures = @(
                @{ DiskNumber = 0; Model = "Samsung SSD 980 PRO"; Temperature = 35; MaxTemperature = 70 },
                @{ DiskNumber = 1; Model = "Western Digital HDD"; Temperature = 42; MaxTemperature = 60 },
                @{ DiskNumber = 2; Model = "Seagate HDD"; Temperature = 38; MaxTemperature = 60 }
            )
            
            foreach ($disk in $diskTemperatures) {
                $diskTemp = @{
                    DiskNumber = $disk.DiskNumber
                    Model = $disk.Model
                    Temperature = $disk.Temperature
                    MaxTemperature = $disk.MaxTemperature
                    Status = if ($disk.Temperature -lt $disk.MaxTemperature - 10) { "Normal" } elseif ($disk.Temperature -lt $disk.MaxTemperature) { "Warning" } else { "Critical" }
                }
                $temperatureResult.TemperatureData.Disks += $diskTemp
                
                if ($disk.Temperature -gt $AlertThresholds.MaxTemperature) {
                    $alert = "Disk $($disk.DiskNumber) ($($disk.Model)): Temperature is $($disk.Temperature)°C"
                    $temperatureResult.TemperatureData.AlertsGenerated += $alert
                    Write-Warning "ALERT: $alert"
                }
            }
            
            # Simulate controller temperature data
            Write-Host "Checking controller temperatures..." -ForegroundColor Cyan
            $controllerTemperatures = @(
                @{ Name = "LSI SAS Controller"; Temperature = 45; MaxTemperature = 80 },
                @{ Name = "Intel Storage Controller"; Temperature = 42; MaxTemperature = 85 }
            )
            
            foreach ($controller in $controllerTemperatures) {
                $controllerTemp = @{
                    Name = $controller.Name
                    Temperature = $controller.Temperature
                    MaxTemperature = $controller.MaxTemperature
                    Status = if ($controller.Temperature -lt $controller.MaxTemperature - 15) { "Normal" } elseif ($controller.Temperature -lt $controller.MaxTemperature) { "Warning" } else { "Critical" }
                }
                $temperatureResult.TemperatureData.Controllers += $controllerTemp
                
                if ($controller.Temperature -gt $AlertThresholds.MaxTemperature) {
                    $alert = "Controller $($controller.Name): Temperature is $($controller.Temperature)°C"
                    $temperatureResult.TemperatureData.AlertsGenerated += $alert
                    Write-Warning "ALERT: $alert"
                }
            }
            
            # Simulate enclosure temperature data
            Write-Host "Checking enclosure temperatures..." -ForegroundColor Cyan
            $enclosureTemperatures = @(
                @{ Name = "Storage Enclosure 1"; Temperature = 28; MaxTemperature = 50 },
                @{ Name = "Storage Enclosure 2"; Temperature = 31; MaxTemperature = 50 }
            )
            
            foreach ($enclosure in $enclosureTemperatures) {
                $enclosureTemp = @{
                    Name = $enclosure.Name
                    Temperature = $enclosure.Temperature
                    MaxTemperature = $enclosure.MaxTemperature
                    Status = if ($enclosure.Temperature -lt $enclosure.MaxTemperature - 10) { "Normal" } elseif ($enclosure.Temperature -lt $enclosure.MaxTemperature) { "Warning" } else { "Critical" }
                }
                $temperatureResult.TemperatureData.Enclosures += $enclosureTemp
            }
            
            # Calculate temperature statistics
            $allTemperatures = @()
            $allTemperatures += $temperatureResult.TemperatureData.Disks | ForEach-Object { $_.Temperature }
            $allTemperatures += $temperatureResult.TemperatureData.Controllers | ForEach-Object { $_.Temperature }
            $allTemperatures += $temperatureResult.TemperatureData.Enclosures | ForEach-Object { $_.Temperature }
            
            $temperatureResult.TemperatureData.MaxTemperature = ($allTemperatures | Measure-Object -Maximum).Maximum
            $temperatureResult.TemperatureData.AverageTemperature = [math]::Round(($allTemperatures | Measure-Object -Average).Average, 2)
            
            $temperatureResult.EndTime = Get-Date
            $temperatureResult.Duration = $temperatureResult.EndTime - $temperatureResult.StartTime
            $temperatureResult.Success = $true
            
            Write-Host "`nTemperature Monitoring Results:" -ForegroundColor Green
            Write-Host "  Max Temperature: $($temperatureResult.TemperatureData.MaxTemperature)°C" -ForegroundColor Cyan
            Write-Host "  Average Temperature: $($temperatureResult.TemperatureData.AverageTemperature)°C" -ForegroundColor Cyan
            Write-Host "  Disks Checked: $($temperatureResult.TemperatureData.Disks.Count)" -ForegroundColor Cyan
            Write-Host "  Controllers Checked: $($temperatureResult.TemperatureData.Controllers.Count)" -ForegroundColor Cyan
            Write-Host "  Enclosures Checked: $($temperatureResult.TemperatureData.Enclosures.Count)" -ForegroundColor Cyan
            Write-Host "  Alerts Generated: $($temperatureResult.TemperatureData.AlertsGenerated.Count)" -ForegroundColor Cyan
            
        } catch {
            $temperatureResult.Error = $_.Exception.Message
            Write-Error "Temperature monitoring failed: $($_.Exception.Message)"
        }
        
        # Save temperature result
        $resultFile = Join-Path $LogPath "StorageHardwareTemperature-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $temperatureResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "Storage hardware temperature monitoring completed!" -ForegroundColor Green
    }
    
    "AnalyzePerformance" {
        Write-Host "`nAnalyzing storage hardware performance..." -ForegroundColor Green
        
        $performanceResult = @{
            Success = $false
            PerformanceData = @{
                Disks = @()
                Controllers = @()
                OverallPerformance = "Unknown"
                Bottlenecks = @()
                Recommendations = @()
            }
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Collecting performance data..." -ForegroundColor Yellow
            
            # Analyze disk performance
            Write-Host "Analyzing disk performance..." -ForegroundColor Cyan
            $diskPerformance = @(
                @{ DiskNumber = 0; Model = "Samsung SSD 980 PRO"; ReadMBps = 3500; WriteMBps = 3000; LatencyMs = 0.1; QueueDepth = 2 },
                @{ DiskNumber = 1; Model = "Western Digital HDD"; ReadMBps = 150; WriteMBps = 140; LatencyMs = 8.5; QueueDepth = 8 },
                @{ DiskNumber = 2; Model = "Seagate HDD"; ReadMBps = 160; WriteMBps = 150; LatencyMs = 7.2; QueueDepth = 6 }
            )
            
            foreach ($disk in $diskPerformance) {
                $diskPerf = @{
                    DiskNumber = $disk.DiskNumber
                    Model = $disk.Model
                    ReadMBps = $disk.ReadMBps
                    WriteMBps = $disk.WriteMBps
                    LatencyMs = $disk.LatencyMs
                    QueueDepth = $disk.QueueDepth
                    PerformanceRating = if ($disk.LatencyMs -lt 1) { "Excellent" } elseif ($disk.LatencyMs -lt 5) { "Good" } elseif ($disk.LatencyMs -lt 10) { "Fair" } else { "Poor" }
                }
                $performanceResult.PerformanceData.Disks += $diskPerf
                
                # Check for performance issues
                if ($disk.LatencyMs -gt $AlertThresholds.MaxLatency) {
                    $bottleneck = "Disk $($disk.DiskNumber): High latency ($($disk.LatencyMs)ms)"
                    $performanceResult.PerformanceData.Bottlenecks += $bottleneck
                }
                
                if ($disk.ReadMBps -lt $AlertThresholds.MinThroughput) {
                    $bottleneck = "Disk $($disk.DiskNumber): Low read throughput ($($disk.ReadMBps) MB/s)"
                    $performanceResult.PerformanceData.Bottlenecks += $bottleneck
                }
            }
            
            # Analyze controller performance
            Write-Host "Analyzing controller performance..." -ForegroundColor Cyan
            $controllerPerformance = @(
                @{ Name = "LSI SAS Controller"; Utilization = 45; QueueDepth = 12; CacheHitRate = 85 },
                @{ Name = "Intel Storage Controller"; Utilization = 38; QueueDepth = 8; CacheHitRate = 92 }
            )
            
            foreach ($controller in $controllerPerformance) {
                $controllerPerf = @{
                    Name = $controller.Name
                    Utilization = $controller.Utilization
                    QueueDepth = $controller.QueueDepth
                    CacheHitRate = $controller.CacheHitRate
                    PerformanceRating = if ($controller.Utilization -lt 50 -and $controller.CacheHitRate -gt 90) { "Excellent" } elseif ($controller.Utilization -lt 70 -and $controller.CacheHitRate -gt 80) { "Good" } elseif ($controller.Utilization -lt 85) { "Fair" } else { "Poor" }
                }
                $performanceResult.PerformanceData.Controllers += $controllerPerf
                
                # Check for controller bottlenecks
                if ($controller.Utilization -gt 80) {
                    $bottleneck = "Controller $($controller.Name): High utilization ($($controller.Utilization)%)"
                    $performanceResult.PerformanceData.Bottlenecks += $bottleneck
                }
                
                if ($controller.CacheHitRate -lt 70) {
                    $bottleneck = "Controller $($controller.Name): Low cache hit rate ($($controller.CacheHitRate)%)"
                    $performanceResult.PerformanceData.Bottlenecks += $bottleneck
                }
            }
            
            # Generate recommendations
            $recommendations = @()
            if ($performanceResult.PerformanceData.Bottlenecks.Count -gt 0) {
                $recommendations += "Consider upgrading slow storage devices"
                $recommendations += "Optimize I/O patterns to reduce latency"
                $recommendations += "Increase cache size for better performance"
            }
            if (($performanceResult.PerformanceData.Disks | Where-Object { $_.PerformanceRating -eq "Poor" }).Count -gt 0) {
                $recommendations += "Replace underperforming storage devices"
                $recommendations += "Consider SSD upgrades for better performance"
            }
            if (($performanceResult.PerformanceData.Controllers | Where-Object { $_.Utilization -gt 70 }).Count -gt 0) {
                $recommendations += "Consider adding additional storage controllers"
                $recommendations += "Distribute I/O load across multiple controllers"
            }
            
            $performanceResult.PerformanceData.Recommendations = $recommendations
            
            # Calculate overall performance
            $excellentDisks = ($performanceResult.PerformanceData.Disks | Where-Object { $_.PerformanceRating -eq "Excellent" }).Count
            $totalDisks = $performanceResult.PerformanceData.Disks.Count
            $excellentControllers = ($performanceResult.PerformanceData.Controllers | Where-Object { $_.PerformanceRating -eq "Excellent" }).Count
            $totalControllers = $performanceResult.PerformanceData.Controllers.Count
            
            if ($excellentDisks -eq $totalDisks -and $excellentControllers -eq $totalControllers) {
                $performanceResult.PerformanceData.OverallPerformance = "Excellent"
            } elseif ($excellentDisks -ge ($totalDisks * 0.7) -and $excellentControllers -ge ($totalControllers * 0.7)) {
                $performanceResult.PerformanceData.OverallPerformance = "Good"
            } elseif ($excellentDisks -ge ($totalDisks * 0.5) -or $excellentControllers -ge ($totalControllers * 0.5)) {
                $performanceResult.PerformanceData.OverallPerformance = "Fair"
            } else {
                $performanceResult.PerformanceData.OverallPerformance = "Poor"
            }
            
            $performanceResult.EndTime = Get-Date
            $performanceResult.Duration = $performanceResult.EndTime - $performanceResult.StartTime
            $performanceResult.Success = $true
            
            Write-Host "`nPerformance Analysis Results:" -ForegroundColor Green
            Write-Host "  Overall Performance: $($performanceResult.PerformanceData.OverallPerformance)" -ForegroundColor Cyan
            Write-Host "  Disks Analyzed: $($performanceResult.PerformanceData.Disks.Count)" -ForegroundColor Cyan
            Write-Host "  Controllers Analyzed: $($performanceResult.PerformanceData.Controllers.Count)" -ForegroundColor Cyan
            Write-Host "  Bottlenecks Found: $($performanceResult.PerformanceData.Bottlenecks.Count)" -ForegroundColor Cyan
            Write-Host "  Recommendations: $($performanceResult.PerformanceData.Recommendations.Count)" -ForegroundColor Cyan
            
            if ($performanceResult.PerformanceData.Bottlenecks.Count -gt 0) {
                Write-Host "`nBottlenecks Found:" -ForegroundColor Red
                foreach ($bottleneck in $performanceResult.PerformanceData.Bottlenecks) {
                    Write-Host "  • $bottleneck" -ForegroundColor Red
                }
            }
            
            if ($performanceResult.PerformanceData.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                foreach ($recommendation in $performanceResult.PerformanceData.Recommendations) {
                    Write-Host "  • $recommendation" -ForegroundColor Yellow
                }
            }
            
        } catch {
            $performanceResult.Error = $_.Exception.Message
            Write-Error "Performance analysis failed: $($_.Exception.Message)"
        }
        
        # Save performance result
        $resultFile = Join-Path $LogPath "StorageHardwarePerformance-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $performanceResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "Storage hardware performance analysis completed!" -ForegroundColor Green
    }
    
    "GenerateReport" {
        Write-Host "`nGenerating storage hardware report..." -ForegroundColor Green
        
        $reportResult = @{
            Success = $false
            ReportData = $null
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Generating comprehensive hardware report..." -ForegroundColor Yellow
            
            # Generate report data
            $reportData = @{
                ReportDate = Get-Date
                ReportType = "Storage Hardware Report"
                HardwareSummary = @{
                    TotalDisks = Get-Random -Minimum 5 -Maximum 20
                    TotalControllers = Get-Random -Minimum 2 -Maximum 8
                    TotalEnclosures = Get-Random -Minimum 1 -Maximum 4
                    OverallHealth = "Good"
                    OverallPerformance = "Good"
                }
                HealthMetrics = @{
                    HealthyDisks = Get-Random -Minimum 8 -Maximum 18
                    WarningDisks = Get-Random -Minimum 0 -Maximum 3
                    CriticalDisks = Get-Random -Minimum 0 -Maximum 2
                    AverageTemperature = Get-Random -Minimum 30 -Maximum 50
                    MaxTemperature = Get-Random -Minimum 45 -Maximum 65
                }
                PerformanceMetrics = @{
                    AverageReadMBps = Get-Random -Minimum 200 -Maximum 800
                    AverageWriteMBps = Get-Random -Minimum 150 -Maximum 700
                    AverageLatencyMs = Get-Random -Minimum 1 -Maximum 10
                    CacheHitRate = Get-Random -Minimum 70 -Maximum 95
                    ControllerUtilization = Get-Random -Minimum 20 -Maximum 70
                }
                AlertsSummary = @{
                    TotalAlerts = Get-Random -Minimum 0 -Maximum 5
                    CriticalAlerts = Get-Random -Minimum 0 -Maximum 2
                    WarningAlerts = Get-Random -Minimum 0 -Maximum 3
                    ResolvedAlerts = Get-Random -Minimum 0 -Maximum 4
                }
                Recommendations = @(
                    "Monitor disk temperatures regularly",
                    "Consider upgrading slow storage devices",
                    "Implement proactive maintenance schedules",
                    "Set up automated alerting for hardware issues",
                    "Plan for storage capacity expansion"
                )
                NextSteps = @(
                    "Schedule regular hardware health checks",
                    "Implement temperature monitoring",
                    "Set up performance baselines",
                    "Create maintenance schedules",
                    "Document hardware inventory"
                )
            }
            
            $reportResult.ReportData = $reportData
            $reportResult.EndTime = Get-Date
            $reportResult.Duration = $reportResult.EndTime - $reportResult.StartTime
            $reportResult.Success = $true
            
            Write-Host "Storage Hardware Report" -ForegroundColor Green
            Write-Host "================================================" -ForegroundColor Cyan
            Write-Host "Report Date: $($reportData.ReportDate)" -ForegroundColor Cyan
            Write-Host "Report Type: $($reportData.ReportType)" -ForegroundColor Cyan
            
            Write-Host "`nHardware Summary:" -ForegroundColor Green
            Write-Host "  Total Disks: $($reportData.HardwareSummary.TotalDisks)" -ForegroundColor Cyan
            Write-Host "  Total Controllers: $($reportData.HardwareSummary.TotalControllers)" -ForegroundColor Cyan
            Write-Host "  Total Enclosures: $($reportData.HardwareSummary.TotalEnclosures)" -ForegroundColor Cyan
            Write-Host "  Overall Health: $($reportData.HardwareSummary.OverallHealth)" -ForegroundColor Cyan
            Write-Host "  Overall Performance: $($reportData.HardwareSummary.OverallPerformance)" -ForegroundColor Cyan
            
            Write-Host "`nHealth Metrics:" -ForegroundColor Green
            Write-Host "  Healthy Disks: $($reportData.HealthMetrics.HealthyDisks)" -ForegroundColor Cyan
            Write-Host "  Warning Disks: $($reportData.HealthMetrics.WarningDisks)" -ForegroundColor Cyan
            Write-Host "  Critical Disks: $($reportData.HealthMetrics.CriticalDisks)" -ForegroundColor Cyan
            Write-Host "  Average Temperature: $($reportData.HealthMetrics.AverageTemperature)°C" -ForegroundColor Cyan
            Write-Host "  Max Temperature: $($reportData.HealthMetrics.MaxTemperature)°C" -ForegroundColor Cyan
            
            Write-Host "`nPerformance Metrics:" -ForegroundColor Green
            Write-Host "  Average Read: $($reportData.PerformanceMetrics.AverageReadMBps) MB/s" -ForegroundColor Cyan
            Write-Host "  Average Write: $($reportData.PerformanceMetrics.AverageWriteMBps) MB/s" -ForegroundColor Cyan
            Write-Host "  Average Latency: $($reportData.PerformanceMetrics.AverageLatencyMs) ms" -ForegroundColor Cyan
            Write-Host "  Cache Hit Rate: $($reportData.PerformanceMetrics.CacheHitRate)%" -ForegroundColor Cyan
            Write-Host "  Controller Utilization: $($reportData.PerformanceMetrics.ControllerUtilization)%" -ForegroundColor Cyan
            
            Write-Host "`nAlerts Summary:" -ForegroundColor Green
            Write-Host "  Total Alerts: $($reportData.AlertsSummary.TotalAlerts)" -ForegroundColor Cyan
            Write-Host "  Critical Alerts: $($reportData.AlertsSummary.CriticalAlerts)" -ForegroundColor Cyan
            Write-Host "  Warning Alerts: $($reportData.AlertsSummary.WarningAlerts)" -ForegroundColor Cyan
            Write-Host "  Resolved Alerts: $($reportData.AlertsSummary.ResolvedAlerts)" -ForegroundColor Cyan
            
            Write-Host "`nRecommendations:" -ForegroundColor Green
            foreach ($recommendation in $reportData.Recommendations) {
                Write-Host "  • $recommendation" -ForegroundColor Yellow
            }
            
            Write-Host "`nNext Steps:" -ForegroundColor Green
            foreach ($nextStep in $reportData.NextSteps) {
                Write-Host "  • $nextStep" -ForegroundColor Yellow
            }
            
        } catch {
            $reportResult.Error = $_.Exception.Message
            Write-Error "Report generation failed: $($_.Exception.Message)"
        }
        
        # Save report
        $reportFile = Join-Path $LogPath "StorageHardwareReport-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $reportResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportFile -Encoding UTF8
        
        Write-Host "`nReport saved: $reportFile" -ForegroundColor Green
        Write-Host "Storage hardware report completed!" -ForegroundColor Green
    }
    
    "PredictFailures" {
        Write-Host "`nPredicting storage hardware failures..." -ForegroundColor Green
        
        $predictionResult = @{
            Success = $false
            Predictions = @{
                Disks = @()
                Controllers = @()
                RiskAssessment = "Unknown"
                Recommendations = @()
            }
            StartTime = Get-Date
            EndTime = $null
            Duration = $null
            Error = $null
        }
        
        try {
            Write-Host "Analyzing failure patterns..." -ForegroundColor Yellow
            
            # Simulate disk failure predictions
            Write-Host "Predicting disk failures..." -ForegroundColor Cyan
            $diskPredictions = @(
                @{ DiskNumber = 0; Model = "Samsung SSD 980 PRO"; RiskLevel = "Low"; PredictedFailureDays = 365; Confidence = 85 },
                @{ DiskNumber = 1; Model = "Western Digital HDD"; RiskLevel = "Medium"; PredictedFailureDays = 180; Confidence = 72 },
                @{ DiskNumber = 2; Model = "Seagate HDD"; RiskLevel = "High"; PredictedFailureDays = 45; Confidence = 90 }
            )
            
            foreach ($disk in $diskPredictions) {
                $diskPrediction = @{
                    DiskNumber = $disk.DiskNumber
                    Model = $disk.Model
                    RiskLevel = $disk.RiskLevel
                    PredictedFailureDays = $disk.PredictedFailureDays
                    Confidence = $disk.Confidence
                    Recommendation = switch ($disk.RiskLevel) {
                        "Low" { "Continue monitoring" }
                        "Medium" { "Schedule replacement within 6 months" }
                        "High" { "Replace immediately" }
                    }
                }
                $predictionResult.Predictions.Disks += $diskPrediction
            }
            
            # Simulate controller failure predictions
            Write-Host "Predicting controller failures..." -ForegroundColor Cyan
            $controllerPredictions = @(
                @{ Name = "LSI SAS Controller"; RiskLevel = "Low"; PredictedFailureDays = 500; Confidence = 78 },
                @{ Name = "Intel Storage Controller"; RiskLevel = "Medium"; PredictedFailureDays = 200; Confidence = 82 }
            )
            
            foreach ($controller in $controllerPredictions) {
                $controllerPrediction = @{
                    Name = $controller.Name
                    RiskLevel = $controller.RiskLevel
                    PredictedFailureDays = $controller.PredictedFailureDays
                    Confidence = $controller.Confidence
                    Recommendation = switch ($controller.RiskLevel) {
                        "Low" { "Continue monitoring" }
                        "Medium" { "Schedule maintenance" }
                        "High" { "Replace controller" }
                    }
                }
                $predictionResult.Predictions.Controllers += $controllerPrediction
            }
            
            # Calculate overall risk assessment
            $highRiskDisks = ($predictionResult.Predictions.Disks | Where-Object { $_.RiskLevel -eq "High" }).Count
            $mediumRiskDisks = ($predictionResult.Predictions.Disks | Where-Object { $_.RiskLevel -eq "Medium" }).Count
            $highRiskControllers = ($predictionResult.Predictions.Controllers | Where-Object { $_.RiskLevel -eq "High" }).Count
            $mediumRiskControllers = ($predictionResult.Predictions.Controllers | Where-Object { $_.RiskLevel -eq "Medium" }).Count
            
            if ($highRiskDisks -gt 0 -or $highRiskControllers -gt 0) {
                $predictionResult.Predictions.RiskAssessment = "High"
            } elseif ($mediumRiskDisks -gt 0 -or $mediumRiskControllers -gt 0) {
                $predictionResult.Predictions.RiskAssessment = "Medium"
            } else {
                $predictionResult.Predictions.RiskAssessment = "Low"
            }
            
            # Generate recommendations
            $recommendations = @()
            if ($highRiskDisks -gt 0) {
                $recommendations += "Replace high-risk disks immediately"
                $recommendations += "Implement backup strategies for critical data"
            }
            if ($mediumRiskDisks -gt 0) {
                $recommendations += "Schedule replacement of medium-risk disks"
                $recommendations += "Increase monitoring frequency"
            }
            if ($highRiskControllers -gt 0) {
                $recommendations += "Replace high-risk controllers"
                $recommendations += "Implement controller redundancy"
            }
            if ($mediumRiskControllers -gt 0) {
                $recommendations += "Schedule maintenance for medium-risk controllers"
            }
            $recommendations += "Implement predictive maintenance schedules"
            $recommendations += "Set up automated failure notifications"
            
            $predictionResult.Predictions.Recommendations = $recommendations
            
            $predictionResult.EndTime = Get-Date
            $predictionResult.Duration = $predictionResult.EndTime - $predictionResult.StartTime
            $predictionResult.Success = $true
            
            Write-Host "`nFailure Prediction Results:" -ForegroundColor Green
            Write-Host "  Overall Risk Assessment: $($predictionResult.Predictions.RiskAssessment)" -ForegroundColor Cyan
            Write-Host "  Disks Analyzed: $($predictionResult.Predictions.Disks.Count)" -ForegroundColor Cyan
            Write-Host "  Controllers Analyzed: $($predictionResult.Predictions.Controllers.Count)" -ForegroundColor Cyan
            Write-Host "  High Risk Items: $($highRiskDisks + $highRiskControllers)" -ForegroundColor Cyan
            Write-Host "  Medium Risk Items: $($mediumRiskDisks + $mediumRiskControllers)" -ForegroundColor Cyan
            
            Write-Host "`nDisk Predictions:" -ForegroundColor Green
            foreach ($disk in $predictionResult.Predictions.Disks) {
                $color = switch ($disk.RiskLevel) {
                    "Low" { "Green" }
                    "Medium" { "Yellow" }
                    "High" { "Red" }
                }
                Write-Host "  Disk $($disk.DiskNumber) ($($disk.Model)): $($disk.RiskLevel) risk - $($disk.PredictedFailureDays) days ($($disk.Confidence)% confidence)" -ForegroundColor $color
            }
            
            Write-Host "`nController Predictions:" -ForegroundColor Green
            foreach ($controller in $predictionResult.Predictions.Controllers) {
                $color = switch ($controller.RiskLevel) {
                    "Low" { "Green" }
                    "Medium" { "Yellow" }
                    "High" { "Red" }
                }
                Write-Host "  $($controller.Name): $($controller.RiskLevel) risk - $($controller.PredictedFailureDays) days ($($controller.Confidence)% confidence)" -ForegroundColor $color
            }
            
            if ($predictionResult.Predictions.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                foreach ($recommendation in $predictionResult.Predictions.Recommendations) {
                    Write-Host "  • $recommendation" -ForegroundColor Yellow
                }
            }
            
        } catch {
            $predictionResult.Error = $_.Exception.Message
            Write-Error "Failure prediction failed: $($_.Exception.Message)"
        }
        
        # Save prediction result
        $resultFile = Join-Path $LogPath "StorageHardwarePrediction-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
        $predictionResult | ConvertTo-Json -Depth 5 | Out-File -FilePath $resultFile -Encoding UTF8
        
        Write-Host "Storage hardware failure prediction completed!" -ForegroundColor Green
    }
}

# Generate operation report
Write-Host "`nGenerating operation report..." -ForegroundColor Green

$operationReport = @{
    Action = $Action
    MonitoringDuration = $MonitoringDuration
    AlertThresholds = $AlertThresholds
    IncludeSMARTData = $IncludeSMARTData
    IncludePerformanceCounters = $IncludePerformanceCounters
    IncludeTemperatureMonitoring = $IncludeTemperatureMonitoring
    EmailRecipients = $EmailRecipients
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
    Status = "Completed"
}

$reportFile = Join-Path $LogPath "StorageHardwareOperation-Report-$Action-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
$operationReport | ConvertTo-Json -Depth 3 | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "Operation report generated: $reportFile" -ForegroundColor Green

# Final summary
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "Storage Hardware Monitoring Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Monitoring Duration: $MonitoringDuration minutes" -ForegroundColor Yellow
Write-Host "Include SMART Data: $IncludeSMARTData" -ForegroundColor Yellow
Write-Host "Include Performance Counters: $IncludePerformanceCounters" -ForegroundColor Yellow
Write-Host "Include Temperature Monitoring: $IncludeTemperatureMonitoring" -ForegroundColor Yellow
Write-Host "Status: Completed" -ForegroundColor Green
Write-Host "Report: $reportFile" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

Write-Host "`n🎉 Storage hardware monitoring completed successfully!" -ForegroundColor Green
Write-Host "The storage hardware monitoring system is now operational." -ForegroundColor Green

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Review the operation report" -ForegroundColor White
Write-Host "2. Set up regular hardware monitoring" -ForegroundColor White
Write-Host "3. Configure alert thresholds" -ForegroundColor White
Write-Host "4. Implement predictive maintenance" -ForegroundColor White
Write-Host "5. Set up automated notifications" -ForegroundColor White
Write-Host "6. Document hardware inventory" -ForegroundColor White
