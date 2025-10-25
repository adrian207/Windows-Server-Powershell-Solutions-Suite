#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    File Server Performance Monitoring Script

.DESCRIPTION
    This script provides comprehensive performance monitoring capabilities
    for Windows File and Storage Services including real-time monitoring,
    performance analysis, bottleneck identification, and optimization recommendations.

.PARAMETER Action
    The action to perform (Monitor, Analyze, Report, Optimize, Alert)

.PARAMETER MonitorDuration
    Duration to monitor in seconds (default: 300)

.PARAMETER MonitorInterval
    Monitoring interval in seconds (default: 10)

.PARAMETER OutputPath
    Path to save performance reports

.PARAMETER IncludeNetwork
    Include network performance metrics

.PARAMETER IncludeStorage
    Include storage performance metrics

.PARAMETER IncludeCPU
    Include CPU performance metrics

.PARAMETER IncludeMemory
    Include memory performance metrics

.PARAMETER ThresholdCPU
    CPU usage threshold for alerts (default: 80)

.PARAMETER ThresholdMemory
    Memory usage threshold for alerts (default: 85)

.PARAMETER ThresholdDisk
    Disk usage threshold for alerts (default: 90)

.PARAMETER ThresholdNetwork
    Network usage threshold for alerts (default: 80)

.PARAMETER AlertEmail
    Email address for performance alerts

.PARAMETER GenerateReport
    Generate detailed performance report

.EXAMPLE
    .\Monitor-FileServerPerformance.ps1 -Action Monitor -MonitorDuration 600 -MonitorInterval 15

.EXAMPLE
    .\Monitor-FileServerPerformance.ps1 -Action Analyze -OutputPath "C:\Reports\Performance-Analysis.html"

.EXAMPLE
    .\Monitor-FileServerPerformance.ps1 -Action Alert -ThresholdCPU 75 -ThresholdMemory 80 -AlertEmail "admin@company.com"

.NOTES
    Author: File and Storage Services PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Monitor", "Analyze", "Report", "Optimize", "Alert")]
    [string]$Action,
    
    [int]$MonitorDuration = 300,
    
    [int]$MonitorInterval = 10,
    
    [string]$OutputPath,
    
    [switch]$IncludeNetwork,
    
    [switch]$IncludeStorage,
    
    [switch]$IncludeCPU,
    
    [switch]$IncludeMemory,
    
    [int]$ThresholdCPU = 80,
    
    [int]$ThresholdMemory = 85,
    
    [int]$ThresholdDisk = 90,
    
    [int]$ThresholdNetwork = 80,
    
    [string]$AlertEmail,
    
    [switch]$GenerateReport
)

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "FileStorage-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "FileStorage-Management.psm1") -Force
    Import-Module (Join-Path $modulePath "FileStorage-Troubleshooting.psm1") -Force
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Script variables
$script:PerformanceLog = @()
$script:StartTime = Get-Date
$script:PerformanceData = @()

function Write-PerformanceLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:PerformanceLog += $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function Get-PerformanceCounters {
    param(
        [switch]$IncludeNetwork,
        [switch]$IncludeStorage,
        [switch]$IncludeCPU,
        [switch]$IncludeMemory
    )
    
    try {
        $counters = @{}
        
        # Base file server counters
        $baseCounters = @(
            "\Server\Sessions Logged On",
            "\Server\Files Open",
            "\Server\File Directory Operations/sec",
            "\Server\Logon/sec",
            "\Server\Logon Total",
            "\Server\Sessions Total",
            "\Server\Sessions Active",
            "\Server\Sessions Disconnected"
        )
        
        # CPU counters
        if ($IncludeCPU) {
            $baseCounters += @(
                "\Processor(_Total)\% Processor Time",
                "\Processor(_Total)\% User Time",
                "\Processor(_Total)\% Privileged Time",
                "\System\Processor Queue Length"
            )
        }
        
        # Memory counters
        if ($IncludeMemory) {
            $baseCounters += @(
                "\Memory\Available MBytes",
                "\Memory\% Committed Bytes In Use",
                "\Memory\Pool Paged Bytes",
                "\Memory\Pool Nonpaged Bytes",
                "\Memory\Cache Bytes"
            )
        }
        
        # Storage counters
        if ($IncludeStorage) {
            $baseCounters += @(
                "\PhysicalDisk(_Total)\Disk Reads/sec",
                "\PhysicalDisk(_Total)\Disk Writes/sec",
                "\PhysicalDisk(_Total)\Avg. Disk Queue Length",
                "\PhysicalDisk(_Total)\% Disk Time",
                "\PhysicalDisk(_Total)\Avg. Disk Read Queue Length",
                "\PhysicalDisk(_Total)\Avg. Disk Write Queue Length"
            )
        }
        
        # Network counters
        if ($IncludeNetwork) {
            $baseCounters += @(
                "\Network Interface(*)\Bytes Total/sec",
                "\Network Interface(*)\Bytes Received/sec",
                "\Network Interface(*)\Bytes Sent/sec",
                "\Network Interface(*)\Packets/sec",
                "\Network Interface(*)\Packets Received/sec",
                "\Network Interface(*)\Packets Sent/sec"
            )
        }
        
        # Collect counter data
        foreach ($counter in $baseCounters) {
            try {
                $counterData = Get-Counter -Counter $counter -SampleInterval 1 -MaxSamples 1 -ErrorAction Stop
                $counters[$counter] = $counterData.CounterSamples[0].CookedValue
            } catch {
                $counters[$counter] = "Not Available"
            }
        }
        
        return [PSCustomObject]$counters
        
    } catch {
        Write-PerformanceLog "Error collecting performance counters: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Start-PerformanceMonitoring {
    param(
        [int]$Duration,
        [int]$Interval
    )
    
    Write-PerformanceLog "Starting performance monitoring for $Duration seconds..." "INFO"
    
    try {
        $startTime = Get-Date
        $endTime = $startTime.AddSeconds($Duration)
        $sampleCount = 0
        
        while ((Get-Date) -lt $endTime) {
            $sampleCount++
            $timestamp = Get-Date
            
            Write-PerformanceLog "Collecting performance sample $sampleCount..." "INFO"
            
            $performanceSample = @{
                Timestamp = $timestamp
                SampleNumber = $sampleCount
                Counters = Get-PerformanceCounters -IncludeNetwork:$IncludeNetwork -IncludeStorage:$IncludeStorage -IncludeCPU:$IncludeCPU -IncludeMemory:$IncludeMemory
            }
            
            $script:PerformanceData += $performanceSample
            
            # Display current performance
            Write-Host "`n=== Performance Sample $sampleCount ===" -ForegroundColor Cyan
            Write-Host "Time: $($timestamp.ToString('HH:mm:ss'))" -ForegroundColor White
            
            if ($performanceSample.Counters) {
                # Display key metrics
                $keyMetrics = @(
                    "\Server\Sessions Logged On",
                    "\Server\Files Open",
                    "\Server\File Directory Operations/sec"
                )
                
                foreach ($metric in $keyMetrics) {
                    if ($performanceSample.Counters.$metric -ne "Not Available") {
                        Write-Host "$metric`: $($performanceSample.Counters.$metric)" -ForegroundColor Yellow
                    }
                }
                
                if ($IncludeCPU -and $performanceSample.Counters."\Processor(_Total)\% Processor Time" -ne "Not Available") {
                    Write-Host "CPU Usage: $($performanceSample.Counters.'\Processor(_Total)\% Processor Time')%" -ForegroundColor Yellow
                }
                
                if ($IncludeMemory -and $performanceSample.Counters."\Memory\Available MBytes" -ne "Not Available") {
                    Write-Host "Available Memory: $($performanceSample.Counters.'\Memory\Available MBytes') MB" -ForegroundColor Yellow
                }
            }
            
            # Check if we should continue monitoring
            if ((Get-Date).AddSeconds($Interval) -lt $endTime) {
                Start-Sleep -Seconds $Interval
            }
        }
        
        Write-PerformanceLog "Performance monitoring completed. Collected $sampleCount samples." "SUCCESS"
        return $sampleCount
        
    } catch {
        Write-PerformanceLog "Error during performance monitoring: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-PerformanceAnalysis {
    param([object[]]$PerformanceData)
    
    Write-PerformanceLog "Analyzing performance data..." "INFO"
    
    try {
        $analysis = @{
            Timestamp = Get-Date
            SampleCount = $PerformanceData.Count
            Analysis = @{}
            Bottlenecks = @()
            Recommendations = @()
            Alerts = @()
        }
        
        if ($PerformanceData.Count -eq 0) {
            Write-PerformanceLog "No performance data to analyze" "WARNING"
            return [PSCustomObject]$analysis
        }
        
        # Analyze CPU performance
        $cpuSamples = $PerformanceData | Where-Object { $_.Counters."\Processor(_Total)\% Processor Time" -ne "Not Available" }
        if ($cpuSamples.Count -gt 0) {
            $cpuValues = $cpuSamples | ForEach-Object { $_.Counters."\Processor(_Total)\% Processor Time" }
            $analysis.Analysis.CPU = @{
                Average = [math]::Round(($cpuValues | Measure-Object -Average).Average, 2)
                Maximum = [math]::Round(($cpuValues | Measure-Object -Maximum).Maximum, 2)
                Minimum = [math]::Round(($cpuValues | Measure-Object -Minimum).Minimum, 2)
                Samples = $cpuSamples.Count
            }
            
            if ($analysis.Analysis.CPU.Average -gt $ThresholdCPU) {
                $analysis.Bottlenecks += "High CPU usage detected: $($analysis.Analysis.CPU.Average)%"
                $analysis.Recommendations += "Consider CPU optimization or hardware upgrade"
                $analysis.Alerts += "CPU usage exceeded threshold: $($analysis.Analysis.CPU.Average)% > $ThresholdCPU%"
            }
        }
        
        # Analyze memory performance
        $memorySamples = $PerformanceData | Where-Object { $_.Counters."\Memory\Available MBytes" -ne "Not Available" }
        if ($memorySamples.Count -gt 0) {
            $memoryValues = $memorySamples | ForEach-Object { $_.Counters."\Memory\Available MBytes" }
            $analysis.Analysis.Memory = @{
                AverageAvailable = [math]::Round(($memoryValues | Measure-Object -Average).Average, 2)
                MinimumAvailable = [math]::Round(($memoryValues | Measure-Object -Minimum).Minimum, 2)
                Samples = $memorySamples.Count
            }
            
            # Calculate memory usage percentage (assuming total memory)
            $totalMemory = (Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1MB
            $memoryUsagePercent = [math]::Round((($totalMemory - $analysis.Analysis.Memory.AverageAvailable) / $totalMemory) * 100, 2)
            
            if ($memoryUsagePercent -gt $ThresholdMemory) {
                $analysis.Bottlenecks += "High memory usage detected: $memoryUsagePercent%"
                $analysis.Recommendations += "Consider memory optimization or hardware upgrade"
                $analysis.Alerts += "Memory usage exceeded threshold: $memoryUsagePercent% > $ThresholdMemory%"
            }
        }
        
        # Analyze disk performance
        $diskSamples = $PerformanceData | Where-Object { $_.Counters."\PhysicalDisk(_Total)\% Disk Time" -ne "Not Available" }
        if ($diskSamples.Count -gt 0) {
            $diskValues = $diskSamples | ForEach-Object { $_.Counters."\PhysicalDisk(_Total)\% Disk Time" }
            $analysis.Analysis.Disk = @{
                Average = [math]::Round(($diskValues | Measure-Object -Average).Average, 2)
                Maximum = [math]::Round(($diskValues | Measure-Object -Maximum).Maximum, 2)
                Samples = $diskSamples.Count
            }
            
            if ($analysis.Analysis.Disk.Average -gt $ThresholdDisk) {
                $analysis.Bottlenecks += "High disk usage detected: $($analysis.Analysis.Disk.Average)%"
                $analysis.Recommendations += "Consider disk optimization or storage upgrade"
                $analysis.Alerts += "Disk usage exceeded threshold: $($analysis.Analysis.Disk.Average)% > $ThresholdDisk%"
            }
        }
        
        # Analyze file server performance
        $fileServerSamples = $PerformanceData | Where-Object { $_.Counters."\Server\File Directory Operations/sec" -ne "Not Available" }
        if ($fileServerSamples.Count -gt 0) {
            $fileServerValues = $fileServerSamples | ForEach-Object { $_.Counters."\Server\File Directory Operations/sec" }
            $analysis.Analysis.FileServer = @{
                AverageOperations = [math]::Round(($fileServerValues | Measure-Object -Average).Average, 2)
                MaximumOperations = [math]::Round(($fileServerValues | Measure-Object -Maximum).Maximum, 2)
                Samples = $fileServerSamples.Count
            }
        }
        
        # Analyze network performance
        $networkSamples = $PerformanceData | Where-Object { $_.Counters."\Network Interface(*)\Bytes Total/sec" -ne "Not Available" }
        if ($networkSamples.Count -gt 0) {
            $networkValues = $networkSamples | ForEach-Object { $_.Counters."\Network Interface(*)\Bytes Total/sec" }
            $analysis.Analysis.Network = @{
                AverageBytes = [math]::Round(($networkValues | Measure-Object -Average).Average, 2)
                MaximumBytes = [math]::Round(($networkValues | Measure-Object -Maximum).Maximum, 2)
                Samples = $networkSamples.Count
            }
        }
        
        Write-PerformanceLog "Performance analysis completed" "SUCCESS"
        return [PSCustomObject]$analysis
        
    } catch {
        Write-PerformanceLog "Error during performance analysis: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function New-PerformanceReport {
    param(
        [object]$Analysis,
        [object[]]$PerformanceData,
        [string]$OutputPath
    )
    
    Write-PerformanceLog "Generating performance report..." "INFO"
    
    try {
        if (-not $OutputPath) {
            $OutputPath = Join-Path $scriptPath "Performance-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        }
        
        $report = @{
            Title = "File Server Performance Report"
            Generated = Get-Date
            ComputerName = $env:COMPUTERNAME
            Analysis = $Analysis
            PerformanceData = $PerformanceData
            Summary = @{
                SampleCount = $Analysis.SampleCount
                BottlenecksFound = $Analysis.Bottlenecks.Count
                Recommendations = $Analysis.Recommendations.Count
                Alerts = $Analysis.Alerts.Count
            }
        }
        
        # Generate HTML report
        $htmlReport = $report | ConvertTo-Html -Title "File Server Performance Report" -Head @"
<style>
body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
.container { background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
h1 { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
h2 { color: #007acc; margin-top: 30px; }
h3 { color: #666; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; font-weight: bold; }
.alert { background-color: #f8d7da; padding: 10px; margin: 5px 0; border-left: 4px solid #dc3545; }
.recommendation { background-color: #d1ecf1; padding: 10px; margin: 5px 0; border-left: 4px solid #17a2b8; }
.bottleneck { background-color: #fff3cd; padding: 10px; margin: 5px 0; border-left: 4px solid #ffc107; }
</style>
"@
        
        $htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8
        
        Write-PerformanceLog "Performance report saved to: $OutputPath" "SUCCESS"
        return $OutputPath
        
    } catch {
        Write-PerformanceLog "Error generating performance report: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Optimize-PerformanceConfiguration {
    param([object]$Analysis)
    
    Write-PerformanceLog "Optimizing performance configuration..." "INFO"
    
    try {
        $optimizationResults = @{
            OptimizationsApplied = @()
            Recommendations = @()
            Issues = @()
        }
        
        # CPU optimization
        if ($Analysis.Analysis.CPU -and $Analysis.Analysis.CPU.Average -gt 70) {
            $optimizationResults.Recommendations += "Consider enabling CPU power management optimization"
            $optimizationResults.Recommendations += "Review and optimize running services"
            $optimizationResults.Recommendations += "Consider hardware upgrade for CPU-intensive workloads"
        }
        
        # Memory optimization
        if ($Analysis.Analysis.Memory -and $Analysis.Analysis.Memory.AverageAvailable -lt 1000) {
            $optimizationResults.Recommendations += "Consider increasing system memory"
            $optimizationResults.Recommendations += "Review memory usage by applications"
            $optimizationResults.Recommendations += "Consider enabling memory compression"
        }
        
        # Disk optimization
        if ($Analysis.Analysis.Disk -and $Analysis.Analysis.Disk.Average -gt 70) {
            $optimizationResults.Recommendations += "Consider disk defragmentation"
            $optimizationResults.Recommendations += "Review disk I/O patterns"
            $optimizationResults.Recommendations += "Consider SSD upgrade for better performance"
        }
        
        # File server optimization
        if ($Analysis.Analysis.FileServer -and $Analysis.Analysis.FileServer.AverageOperations -gt 1000) {
            $optimizationResults.Recommendations += "Consider increasing file server cache size"
            $optimizationResults.Recommendations += "Review file sharing protocols and settings"
            $optimizationResults.Recommendations += "Consider load balancing for high-traffic scenarios"
        }
        
        # Network optimization
        if ($Analysis.Analysis.Network -and $Analysis.Analysis.Network.AverageBytes -gt 100000000) {
            $optimizationResults.Recommendations += "Consider network bandwidth upgrade"
            $optimizationResults.Recommendations += "Review network adapter settings"
            $optimizationResults.Recommendations += "Consider network load balancing"
        }
        
        Write-PerformanceLog "Performance optimization analysis completed" "SUCCESS"
        return [PSCustomObject]$optimizationResults
        
    } catch {
        Write-PerformanceLog "Error during performance optimization: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Send-PerformanceAlert {
    param(
        [object]$Analysis,
        [string]$AlertEmail
    )
    
    Write-PerformanceLog "Sending performance alerts..." "INFO"
    
    try {
        if ($Analysis.Alerts.Count -eq 0) {
            Write-PerformanceLog "No alerts to send" "INFO"
            return $true
        }
        
        if (-not $AlertEmail) {
            Write-PerformanceLog "No email address provided for alerts" "WARNING"
            return $false
        }
        
        # Create alert message
        $alertSubject = "File Server Performance Alert - $($env:COMPUTERNAME)"
        $alertBody = @"
File Server Performance Alert

Computer: $($env:COMPUTERNAME)
Time: $(Get-Date)

Alerts:
$($Analysis.Alerts -join "`n")

Bottlenecks:
$($Analysis.Bottlenecks -join "`n")

Recommendations:
$($Analysis.Recommendations -join "`n")

Please review the performance data and take appropriate action.
"@
        
        # Send email alert
        try {
            Send-MailMessage -To $AlertEmail -Subject $alertSubject -Body $alertBody -SmtpServer "localhost" -ErrorAction Stop
            Write-PerformanceLog "Performance alert sent to: $AlertEmail" "SUCCESS"
            return $true
        } catch {
            Write-PerformanceLog "Failed to send email alert: $($_.Exception.Message)" "WARNING"
            return $false
        }
        
    } catch {
        Write-PerformanceLog "Error sending performance alerts: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Save-PerformanceLog {
    $logPath = Join-Path $scriptPath "Performance-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    try {
        $script:PerformanceLog | Out-File -FilePath $logPath -Encoding UTF8
        Write-PerformanceLog "Performance log saved to: $logPath" "INFO"
    } catch {
        Write-Warning "Failed to save performance log: $($_.Exception.Message)"
    }
}

# Main performance monitoring process
try {
    Write-PerformanceLog "Starting file server performance monitoring..." "INFO"
    Write-PerformanceLog "Action: $Action" "INFO"
    
    switch ($Action) {
        "Monitor" {
            $sampleCount = Start-PerformanceMonitoring -Duration $MonitorDuration -Interval $MonitorInterval
            
            Write-Host "`n=== Performance Monitoring Results ===" -ForegroundColor Cyan
            Write-Host "Samples Collected: $sampleCount" -ForegroundColor White
            Write-Host "Duration: $MonitorDuration seconds" -ForegroundColor White
            Write-Host "Interval: $MonitorInterval seconds" -ForegroundColor White
        }
        
        "Analyze" {
            if ($script:PerformanceData.Count -eq 0) {
                Write-PerformanceLog "No performance data available for analysis. Run Monitor action first." "WARNING"
                exit 1
            }
            
            $analysis = Get-PerformanceAnalysis -PerformanceData $script:PerformanceData
            
            Write-Host "`n=== Performance Analysis Results ===" -ForegroundColor Cyan
            Write-Host "Samples Analyzed: $($analysis.SampleCount)" -ForegroundColor White
            Write-Host "Bottlenecks Found: $($analysis.Bottlenecks.Count)" -ForegroundColor White
            Write-Host "Recommendations: $($analysis.Recommendations.Count)" -ForegroundColor White
            Write-Host "Alerts: $($analysis.Alerts.Count)" -ForegroundColor White
            
            if ($analysis.Bottlenecks.Count -gt 0) {
                Write-Host "`nBottlenecks:" -ForegroundColor Yellow
                $analysis.Bottlenecks | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
            }
            
            if ($analysis.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                $analysis.Recommendations | ForEach-Object { Write-Host "  - $_" -ForegroundColor Green }
            }
            
            if ($analysis.Alerts.Count -gt 0) {
                Write-Host "`nAlerts:" -ForegroundColor Yellow
                $analysis.Alerts | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
            }
        }
        
        "Report" {
            if ($script:PerformanceData.Count -eq 0) {
                Write-PerformanceLog "No performance data available for report. Run Monitor action first." "WARNING"
                exit 1
            }
            
            $analysis = Get-PerformanceAnalysis -PerformanceData $script:PerformanceData
            $reportPath = New-PerformanceReport -Analysis $analysis -PerformanceData $script:PerformanceData -OutputPath $OutputPath
            
            if ($reportPath) {
                Write-Host "`n=== Performance Report Generated ===" -ForegroundColor Cyan
                Write-Host "Report Path: $reportPath" -ForegroundColor White
                Write-Host "Report Type: HTML" -ForegroundColor White
            }
        }
        
        "Optimize" {
            if ($script:PerformanceData.Count -eq 0) {
                Write-PerformanceLog "No performance data available for optimization. Run Monitor action first." "WARNING"
                exit 1
            }
            
            $analysis = Get-PerformanceAnalysis -PerformanceData $script:PerformanceData
            $optimizationResults = Optimize-PerformanceConfiguration -Analysis $analysis
            
            Write-Host "`n=== Performance Optimization Results ===" -ForegroundColor Cyan
            Write-Host "Optimizations Applied: $($optimizationResults.OptimizationsApplied.Count)" -ForegroundColor White
            Write-Host "Recommendations: $($optimizationResults.Recommendations.Count)" -ForegroundColor White
            Write-Host "Issues: $($optimizationResults.Issues.Count)" -ForegroundColor White
            
            if ($optimizationResults.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                $optimizationResults.Recommendations | ForEach-Object { Write-Host "  - $_" -ForegroundColor Green }
            }
        }
        
        "Alert" {
            if ($script:PerformanceData.Count -eq 0) {
                Write-PerformanceLog "No performance data available for alerts. Run Monitor action first." "WARNING"
                exit 1
            }
            
            $analysis = Get-PerformanceAnalysis -PerformanceData $script:PerformanceData
            $alertSent = Send-PerformanceAlert -Analysis $analysis -AlertEmail $AlertEmail
            
            if ($alertSent) {
                Write-Host "`nPerformance alerts sent successfully" -ForegroundColor Green
            } else {
                Write-Host "`nPerformance alerts could not be sent" -ForegroundColor Yellow
            }
        }
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-PerformanceLog "File server performance monitoring completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== File Server Performance Monitoring Summary ===" -ForegroundColor Cyan
    Write-Host "Action: $Action" -ForegroundColor White
    Write-Host "Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    
    # Save performance log
    Save-PerformanceLog
    
    Write-Host "`nPerformance monitoring completed successfully!" -ForegroundColor Green
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-PerformanceLog "File server performance monitoring failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save performance log
    Save-PerformanceLog
    
    Write-Host "`nPerformance monitoring failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the performance log for details." -ForegroundColor Yellow
    
    exit 1
}
