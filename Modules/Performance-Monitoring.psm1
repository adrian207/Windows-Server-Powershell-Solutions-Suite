<#
.SYNOPSIS
    Performance monitoring and optimization module for Windows Server PowerShell Solutions Suite

.DESCRIPTION
    Provides comprehensive performance monitoring, profiling, optimization recommendations,
    and resource usage tracking for PowerShell scripts and Windows Server operations.

.PARAMETER None

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Last Updated: December 2024
    
    Features:
    - Script execution profiling
    - Memory usage tracking
    - CPU performance monitoring
    - Disk I/O metrics
    - Network performance tracking
    - Automatic optimization recommendations
    - Performance baselines and trending
#>

[CmdletBinding()]
param()

# Module Variables
$script:ModuleVersion = '1.0.0'
$script:PerformanceMetrics = @{}
$script:Baselines = @{}

# Import Logging Module
$loggingModule = Get-Module -Name "Logging-Core" -ListAvailable
if ($loggingModule) {
    Import-Module Logging-Core -Force -ErrorAction SilentlyContinue
}

#region Public Functions

function Start-PerformanceMonitor {
    <#
    .SYNOPSIS
        Starts performance monitoring for a script block
    
    .DESCRIPTION
        Wraps a script block in performance monitoring, tracking execution time,
        memory usage, and resource consumption.
    
    .PARAMETER ScriptBlock
        The script block to monitor
    
    .PARAMETER OperationName
        Name of the operation for logging
    
    .PARAMETER Detailed
        Collect detailed performance metrics
    
    .EXAMPLE
        Start-PerformanceMonitor -ScriptBlock { Get-Process } -OperationName "GetProcesses"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,
        
        [Parameter(Mandatory = $false)]
        [string]$OperationName = "ScriptExecution",
        
        [Parameter(Mandatory = $false)]
        [switch]$Detailed
    )
    
    $metrics = @{
        StartTime = Get-Date
        InitialMemory = (Get-Process -Id $PID).WorkingSet64
        InitialCPU = (Get-Counter "\Process(powershell*)\% Processor Time").CounterSamples[0].CookedValue
    }
    
    try {
        $result = Invoke-Command -ScriptBlock $ScriptBlock -ErrorAction Stop
        
        $metrics.EndTime = Get-Date
        $metrics.FinalMemory = (Get-Process -Id $PID).WorkingSet64
        $metrics.FinalCPU = (Get-Counter "\Process(powershell*)\% Processor Time").CounterSamples[0].CookedValue
        $metrics.ExecutionTime = ($metrics.EndTime - $metrics.StartTime).TotalMilliseconds
        $metrics.MemoryDelta = $metrics.FinalMemory - $metrics.InitialMemory
        $metrics.CPUDelta = $metrics.FinalCPU - $metrics.InitialCPU
        $metrics.Success = $true
        
        if ($Detailed) {
            $metrics.DiskIO = Get-DiskIOMetrics
            $metrics.NetworkIO = Get-NetworkMetrics
        }
        
        $script:PerformanceMetrics[$OperationName] = $metrics
        
        Write-Log -Message "Performance metrics captured for: $OperationName" -Level INFO -Component "PerformanceMonitor" -Data $metrics
        
        return @{
            Result = $result
            Metrics = $metrics
        }
        
    } catch {
        $metrics.Error = $_.Exception.Message
        $metrics.Success = $false
        $script:PerformanceMetrics[$OperationName] = $metrics
        
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Message "Performance monitoring failed for: $OperationName" -Level ERROR -Component "PerformanceMonitor" -Exception $_ -Data $metrics
        }
        
        throw
    }
}

function Measure-ScriptPerformance {
    <#
    .SYNOPSIS
        Measures performance of a PowerShell script
    
    .DESCRIPTION
        Comprehensive performance measurement including execution time, memory,
        and resource usage with optimization recommendations.
    
    .PARAMETER ScriptPath
        Path to the PowerShell script to measure
    
    .PARAMETER Iterations
        Number of iterations to run for averaging
    
    .EXAMPLE
        Measure-ScriptPerformance -ScriptPath "C:\Scripts\MyScript.ps1" -Iterations 5
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        
        [Parameter(Mandatory = $false)]
        [int]$Iterations = 1
    )
    
    if (-not (Test-Path $ScriptPath)) {
        throw "Script file not found: $ScriptPath"
    }
    
    $allMetrics = @()
    $scriptContent = Get-Content $ScriptPath -Raw
    
    Write-Host "Measuring script performance: $ScriptPath" -ForegroundColor Cyan
    Write-Host "Iterations: $Iterations" -ForegroundColor Gray
    
    for ($i = 1; $i -le $Iterations; $i++) {
        Write-Host "  Iteration $i/$Iterations..." -ForegroundColor Gray
        
        $metrics = Start-PerformanceMonitor -ScriptBlock {
            & $ScriptPath
        } -OperationName "ScriptIteration_$i"
        
        $allMetrics += $metrics.Metrics
        
        Start-Sleep -Milliseconds 100
    }
    
    $summary = Get-PerformanceSummary -Metrics $allMetrics
    $recommendations = Get-OptimizationRecommendations -Summary $summary
    
    Write-Host "`nPerformance Summary:" -ForegroundColor Cyan
    Write-Host "  Average Execution Time: $([math]::Round($summary.AverageExecutionTime, 2)) ms" -ForegroundColor White
    Write-Host "  Average Memory Usage: $([math]::Round($summary.AverageMemoryMB, 2)) MB" -ForegroundColor White
    Write-Host "  Memory Peak: $([math]::Round($summary.PeakMemoryMB, 2)) MB" -ForegroundColor White
    
    if ($recommendations.Count -gt 0) {
        Write-Host "`nOptimization Recommendations:" -ForegroundColor Yellow
        foreach ($rec in $recommendations) {
            Write-Host "  • $rec" -ForegroundColor Yellow
        }
    }
    
    return @{
        Summary = $summary
        Recommendations = $recommendations
        Metrics = $allMetrics
    }
}

function Get-PerformanceSummary {
    <#
    .SYNOPSIS
        Calculates performance summary from metrics
    
    .DESCRIPTION
        Aggregates performance metrics and calculates averages, peaks, and trends
    
    .PARAMETER Metrics
        Array of performance metrics
    
    .EXAMPLE
        Get-PerformanceSummary -Metrics $performanceMetrics
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Metrics
    )
    
    $summary = @{
        Count = $Metrics.Count
        AverageExecutionTime = ($Metrics | Measure-Object -Property ExecutionTime -Average).Average
        MaxExecutionTime = ($Metrics | Measure-Object -Property ExecutionTime -Maximum).Maximum
        MinExecutionTime = ($Metrics | Measure-Object -Property ExecutionTime -Minimum).Minimum
        AverageMemoryMB = (($Metrics | Measure-Object -Property MemoryDelta -Average).Average / 1MB)
        PeakMemoryMB = ((($Metrics | Measure-Object -Property MemoryDelta -Maximum).Maximum) / 1MB)
        TotalMemoryMB = ((($Metrics | ForEach-Object { $_.MemoryDelta } | Measure-Object -Sum).Sum) / 1MB)
    }
    
    return $summary
}

function Get-OptimizationRecommendations {
    <#
    .SYNOPSIS
        Generates optimization recommendations based on performance metrics
    
    .DESCRIPTION
        Analyzes performance metrics and suggests optimizations
    
    .PARAMETER Summary
        Performance summary object
    
    .EXAMPLE
        Get-OptimizationRecommendations -Summary $performanceSummary
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Summary
    )
    
    $recommendations = @()
    
    # Check execution time
    if ($Summary.AverageExecutionTime -gt 5000) {
        $recommendations += "Execution time exceeds 5 seconds - Consider using parallel processing or optimization"
    }
    
    # Check memory usage
    if ($Summary.PeakMemoryMB -gt 500) {
        $recommendations += "High memory usage ($([math]::Round($Summary.PeakMemoryMB, 2)) MB) - Consider streaming or batching data"
    }
    
    # Check for potential issues
    if ($Summary.MaxExecutionTime / $Summary.MinExecutionTime -gt 2) {
        $recommendations += "Execution time variance detected - Performance may be inconsistent"
    }
    
    if ($Summary.TotalMemoryMB -gt 1000) {
        $recommendations += "Total memory consumption high ($([math]::Round($Summary.TotalMemoryMB, 2)) MB) - Check for memory leaks"
    }
    
    return $recommendations
}

function Set-PerformanceBaseline {
    <#
    .SYNOPSIS
        Sets a performance baseline for comparison
    
    .DESCRIPTION
        Establishes a performance baseline to compare future measurements against
    
    .PARAMETER OperationName
        Name of the operation
    
    .PARAMETER Baseline
        Baseline metrics to store
    
    .EXAMPLE
        Set-PerformanceBaseline -OperationName "GetProcesses" -Baseline $metrics
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OperationName,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Baseline
    )
    
    $script:Baselines[$OperationName] = $Baseline
    
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Message "Performance baseline set for: $OperationName" -Level INFO -Component "PerformanceMonitor"
    }
}

function Compare-Performance {
    <#
    .SYNOPSIS
        Compares current metrics against baseline
    
    .DESCRIPTION
        Analyzes current performance against stored baseline and reports deviations
    
    .PARAMETER OperationName
        Name of the operation to compare
    
    .PARAMETER CurrentMetrics
        Current performance metrics
    
    .EXAMPLE
        Compare-Performance -OperationName "GetProcesses" -CurrentMetrics $currentMetrics
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OperationName,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$CurrentMetrics
    )
    
    if (-not $script:Baselines.ContainsKey($OperationName)) {
        Write-Warning "No baseline found for operation: $OperationName"
        return
    }
    
    $baseline = $script:Baselines[$OperationName]
    
    $comparison = @{
        OperationName = $OperationName
        BaselineTime = $baseline.ExecutionTime
        CurrentTime = $CurrentMetrics.ExecutionTime
        TimeDelta = $CurrentMetrics.ExecutionTime - $baseline.ExecutionTime
        TimeDeltaPercent = (($CurrentMetrics.ExecutionTime - $baseline.ExecutionTime) / $baseline.ExecutionTime) * 100
        BaselineMemory = $baseline.MemoryDelta
        CurrentMemory = $CurrentMetrics.MemoryDelta
        MemoryDelta = $CurrentMetrics.MemoryDelta - $baseline.MemoryDelta
    }
    
    if ($comparison.TimeDeltaPercent -gt 20) {
        $level = "WARNING"
        $status = "Performance degraded by $([math]::Round($comparison.TimeDeltaPercent, 2))%"
    } elseif ($comparison.TimeDeltaPercent -lt -20) {
        $level = "INFO"
        $status = "Performance improved by $([math]::Round([math]::Abs($comparison.TimeDeltaPercent), 2))%"
    } else {
        $level = "INFO"
        $status = "Performance within baseline range"
    }
    
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Message $status -Level $level -Component "PerformanceMonitor" -Data $comparison
    }
    
    return $comparison
}

function Get-DiskIOMetrics {
    <#
    .SYNOPSIS
        Gets disk I/O metrics for the current process
    
    .DESCRIPTION
        Collects disk read/write statistics
    
    .PARAMETER None
    
    .EXAMPLE
        Get-DiskIOMetrics
    #>
    [CmdletBinding()]
    param()
    
    try {
        $diskRead = (Get-Counter "\Process(powershell*)\IO Data Read Bytes/sec" -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue
        $diskWrite = (Get-Counter "\Process(powershell*)\IO Data Write Bytes/sec" -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue
        
        return @{
            ReadBytesPerSec = [long]$diskRead
            WriteBytesPerSec = [long]$diskWrite
        }
    } catch {
        return @{
            ReadBytesPerSec = 0
            WriteBytesPerSec = 0
        }
    }
}

function Get-NetworkMetrics {
    <#
    .SYNOPSIS
        Gets network I/O metrics
    
    .DESCRIPTION
        Collects network interface statistics
    
    .PARAMETER None
    
    .EXAMPLE
        Get-NetworkMetrics
    #>
    [CmdletBinding()]
    param()
    
    try {
        $networkInterface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
        
        if ($networkInterface) {
            $stats = Get-NetAdapterStatistics -Name $networkInterface.Name
            
            return @{
                InterfaceName = $networkInterface.Name
                BytesSent = $stats.SentBytes
                BytesReceived = $stats.ReceivedBytes
            }
        }
    } catch {}
    
    return @{
        InterfaceName = "Unknown"
        BytesSent = 0
        BytesReceived = 0
    }
}

function Export-PerformanceReport {
    <#
    .SYNOPSIS
        Exports performance metrics to a report
    
    .DESCRIPTION
        Generates a comprehensive performance report with all collected metrics
    
    .PARAMETER OutputPath
        Path to save the report
    
    .PARAMETER Format
        Report format: JSON, CSV, or HTML
    
    .EXAMPLE
        Export-PerformanceReport -OutputPath "C:\Reports\performance.json" -Format JSON
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON', 'CSV', 'HTML')]
        [string]$Format = 'JSON'
    )
    
    $report = @{
        Timestamp = Get-Date
        Host = $env:COMPUTERNAME
        Metrics = $script:PerformanceMetrics
        Baselines = $script:Baselines
    }
    
    switch ($Format) {
        'JSON' {
            $report | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
        }
        'CSV' {
            $csvData = $script:PerformanceMetrics.Values | Select-Object OperationName, ExecutionTime, MemoryDelta, CPUDelta, Success
            $csvData | Export-Csv -Path $OutputPath -NoTypeInformation
        }
        'HTML' {
            # Generate HTML report
            $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Performance Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Performance Report</h1>
    <p>Generated: $(Get-Date)</p>
    <p>Host: $env:COMPUTERNAME</p>
    <h2>Metrics</h2>
    <table>
        <tr>
            <th>Operation</th>
            <th>Execution Time (ms)</th>
            <th>Memory Delta (MB)</th>
            <th>Success</th>
        </tr>
"@
            foreach ($key in $script:PerformanceMetrics.Keys) {
                $metrics = $script:PerformanceMetrics[$key]
                $html += "<tr><td>$key</td><td>$($metrics.ExecutionTime)</td><td>$([math]::Round($metrics.MemoryDelta/1MB, 2))</td><td>$($metrics.Success)</td></tr>`n"
            }
            $html += "</table></body></html>"
            $html | Out-File -FilePath $OutputPath -Encoding UTF8
        }
    }
    
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Message "Performance report exported to: $OutputPath" -Level INFO -Component "PerformanceMonitor"
    }
}

#endregion Public Functions

# Export Functions
Export-ModuleMember -Function Start-PerformanceMonitor, Measure-ScriptPerformance, Get-PerformanceSummary, Get-OptimizationRecommendations, Set-PerformanceBaseline, Compare-Performance, Export-PerformanceReport

# Module Metadata
$script:ModuleInfo = @{
    Name = 'Performance-Monitoring'
    Version = $script:ModuleVersion
    Author = 'Adrian Johnson (adrian207@gmail.com)'
    Description = 'Performance monitoring and optimization module for Windows Server PowerShell Solutions Suite'
}

