#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Start Comprehensive RDS Monitoring

.DESCRIPTION
    This script starts comprehensive monitoring of all Remote Desktop Services components
    including performance metrics, service status, and health monitoring.

.PARAMETER MonitoringInterval
    Monitoring interval in seconds

.PARAMETER LogFile
    Log file path for monitoring data

.PARAMETER IncludePerformanceMetrics
    Include performance metrics in monitoring

.PARAMETER IncludeServiceStatus
    Include service status monitoring

.PARAMETER IncludeHealthMonitoring
    Include health monitoring

.PARAMETER IncludeSecurityMonitoring
    Include security monitoring

.PARAMETER AlertThreshold
    Alert threshold for performance metrics

.EXAMPLE
    .\Start-RDSMonitoring.ps1

.EXAMPLE
    .\Start-RDSMonitoring.ps1 -MonitoringInterval 60 -LogFile "C:\Logs\RDS-Monitoring.log" -IncludePerformanceMetrics -IncludeServiceStatus
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$MonitoringInterval = 30,
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile,
    
    [switch]$IncludePerformanceMetrics,
    
    [switch]$IncludeServiceStatus,
    
    [switch]$IncludeHealthMonitoring,
    
    [switch]$IncludeSecurityMonitoring,
    
    [Parameter(Mandatory = $false)]
    [int]$AlertThreshold = 80
)

# Import required modules
Import-Module ".\Modules\RDS-Core.psm1" -Force
Import-Module ".\Modules\RDS-Monitoring.psm1" -Force
Import-Module ".\Modules\RDS-Performance.psm1" -Force
Import-Module ".\Modules\RDS-Security.psm1" -Force

try {
    Write-Log -Message "Starting comprehensive RDS monitoring..." -Level "INFO"
    
    # Test prerequisites
    $prerequisites = Test-RDSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for RDS monitoring"
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
                IncludeServiceStatus = $IncludeServiceStatus
                IncludeHealthMonitoring = $IncludeHealthMonitoring
                IncludeSecurityMonitoring = $IncludeSecurityMonitoring
                AlertThreshold = $AlertThreshold
            }
            
            # Monitor service status if requested
            if ($IncludeServiceStatus) {
                Write-Verbose "Monitoring service status..."
                $serviceStatus = Get-RDSServiceStatus
                $monitoringData.ServiceStatus = $serviceStatus
                
                # Check for service issues
                $stoppedServices = $serviceStatus.Services | Where-Object { $_.Status -ne "Running" }
                if ($stoppedServices) {
                    foreach ($service in $stoppedServices) {
                        Write-Log -Message "ALERT: Service $($service.Name) is not running (Status: $($service.Status))" -Level "WARNING" -LogPath $LogFile
                    }
                }
            }
            
            # Monitor performance metrics if requested
            if ($IncludePerformanceMetrics) {
                Write-Verbose "Monitoring performance metrics..."
                $perfMetrics = Get-RDSPerformanceCounters -CounterType "All" -IncludeGraphics -IncludePerformance
                $monitoringData.PerformanceMetrics = $perfMetrics
                
                # Check for performance alerts
                if ($perfMetrics.CPUUtilization -gt $AlertThreshold) {
                    Write-Log -Message "ALERT: High CPU utilization: $($perfMetrics.CPUUtilization)%" -Level "WARNING" -LogPath $LogFile
                }
                
                if ($perfMetrics.MemoryUsage -gt $AlertThreshold) {
                    Write-Log -Message "ALERT: High memory usage: $($perfMetrics.MemoryUsage)%" -Level "WARNING" -LogPath $LogFile
                }
            }
            
            # Monitor health if requested
            if ($IncludeHealthMonitoring) {
                Write-Verbose "Monitoring health status..."
                $healthStatus = Test-RDSHealth
                $monitoringData.HealthStatus = $healthStatus
                
                if ($healthStatus.HealthStatus -ne "Healthy") {
                    Write-Log -Message "ALERT: RDS health status: $($healthStatus.HealthStatus)" -Level "WARNING" -LogPath $LogFile
                    foreach ($issue in $healthStatus.Issues) {
                        Write-Log -Message "Health Issue: $issue" -Level "WARNING" -LogPath $LogFile
                    }
                }
            }
            
            # Monitor security if requested
            if ($IncludeSecurityMonitoring) {
                Write-Verbose "Monitoring security status..."
                $securityStatus = Get-RDSSecurityStatus
                $monitoringData.SecurityStatus = $securityStatus
                
                if (-not $securityStatus.ComplianceStatus.Compliant) {
                    Write-Log -Message "ALERT: Security compliance issues detected" -Level "WARNING" -LogPath $LogFile
                }
            }
            
            # Log monitoring data
            Write-Log -Message "RDS monitoring cycle completed" -Level "INFO" -LogPath $LogFile
            
            # Wait for next monitoring cycle
            Start-Sleep -Seconds $MonitoringInterval
            
        } catch {
            Write-Log -Message "Error during monitoring cycle: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogFile
            Start-Sleep -Seconds $MonitoringInterval
        }
        
    } while ($true)
    
} catch {
    Write-Log -Message "Error during RDS monitoring: $($_.Exception.Message)" -Level "ERROR"
    throw
}
