#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Monitor RDS Connection Broker

.DESCRIPTION
    This script monitors the Remote Desktop Services Connection Broker
    including service status, load balancing, failover status, and performance metrics.

.PARAMETER MonitoringInterval
    Monitoring interval in seconds

.PARAMETER LogFile
    Log file path for monitoring data

.PARAMETER IncludePerformanceMetrics
    Include performance metrics in monitoring

.PARAMETER IncludeFailoverStatus
    Include failover status in monitoring

.PARAMETER AlertThreshold
    Alert threshold for performance metrics

.EXAMPLE
    .\Monitor-ConnectionBroker.ps1

.EXAMPLE
    .\Monitor-ConnectionBroker.ps1 -MonitoringInterval 60 -LogFile "C:\Logs\ConnectionBroker.log" -IncludePerformanceMetrics
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$MonitoringInterval = 30,
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile,
    
    [switch]$IncludePerformanceMetrics,
    
    [switch]$IncludeFailoverStatus,
    
    [Parameter(Mandatory = $false)]
    [int]$AlertThreshold = 80
)

# Import required modules
Import-Module ".\Modules\RDS-Core.psm1" -Force
Import-Module ".\Modules\RDS-ConnectionBroker.psm1" -Force
Import-Module ".\Modules\RDS-Monitoring.psm1" -Force

try {
    Write-Log -Message "Starting RDS Connection Broker monitoring..." -Level "INFO"
    
    # Test prerequisites
    $prerequisites = Test-RDSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for RDS Connection Broker monitoring"
    }
    
    Write-Log -Message "Prerequisites validated successfully" -Level "SUCCESS"
    
    # Set up log file if provided
    if ($LogFile) {
        $logDir = Split-Path $LogFile -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        Write-Log -Message "Monitoring log file: $LogFile" -Level "INFO"
    }
    
    # Start monitoring loop
    Write-Log -Message "Starting monitoring loop with interval: $MonitoringInterval seconds" -Level "INFO"
    
    do {
        try {
            $monitoringData = @{
                Timestamp = Get-Date
                ComputerName = $env:COMPUTERNAME
                MonitoringInterval = $MonitoringInterval
                LogFile = $LogFile
                IncludePerformanceMetrics = $IncludePerformanceMetrics
                IncludeFailoverStatus = $IncludeFailoverStatus
                AlertThreshold = $AlertThreshold
            }
            
            # Get Connection Broker status
            $brokerStatus = Get-RDSConnectionBrokerStatus
            $monitoringData.ConnectionBrokerStatus = $brokerStatus
            
            # Get performance metrics if requested
            if ($IncludePerformanceMetrics) {
                $perfMetrics = Get-RDSConnectionBrokerPerformanceMetrics
                $monitoringData.PerformanceMetrics = $perfMetrics
                
                # Check for alerts
                if ($perfMetrics.CPUUtilization -gt $AlertThreshold) {
                    Write-Log -Message "ALERT: High CPU utilization: $($perfMetrics.CPUUtilization)%" -Level "WARNING" -LogPath $LogFile
                }
                
                if ($perfMetrics.MemoryUsage -gt $AlertThreshold) {
                    Write-Log -Message "ALERT: High memory usage: $($perfMetrics.MemoryUsage)%" -Level "WARNING" -LogPath $LogFile
                }
            }
            
            # Get failover status if requested
            if ($IncludeFailoverStatus) {
                $failoverStatus = Get-RDSFailoverStatus
                $monitoringData.FailoverStatus = $failoverStatus
                
                if ($failoverStatus.FailoverActive) {
                    Write-Log -Message "ALERT: Failover is active" -Level "WARNING" -LogPath $LogFile
                }
            }
            
            # Log monitoring data
            Write-Log -Message "Connection Broker monitoring cycle completed" -Level "INFO" -LogPath $LogFile
            
            # Wait for next monitoring cycle
            Start-Sleep -Seconds $MonitoringInterval
            
        } catch {
            Write-Log -Message "Error during monitoring cycle: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogFile
            Start-Sleep -Seconds $MonitoringInterval
        }
        
    } while ($true)
    
} catch {
    Write-Log -Message "Error during Connection Broker monitoring: $($_.Exception.Message)" -Level "ERROR"
    throw
}
