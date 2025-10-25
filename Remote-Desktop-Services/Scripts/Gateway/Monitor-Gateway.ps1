#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Monitor RDS Gateway

.DESCRIPTION
    This script monitors the Remote Desktop Services Gateway
    including service status, SSL configuration, authentication, and performance metrics.

.PARAMETER MonitoringInterval
    Monitoring interval in seconds

.PARAMETER LogFile
    Log file path for monitoring data

.PARAMETER IncludePerformanceMetrics
    Include performance metrics in monitoring

.PARAMETER IncludeSSLCertificateStatus
    Include SSL certificate status in monitoring

.PARAMETER IncludeAuthenticationStatus
    Include authentication status in monitoring

.PARAMETER AlertThreshold
    Alert threshold for performance metrics

.EXAMPLE
    .\Monitor-Gateway.ps1

.EXAMPLE
    .\Monitor-Gateway.ps1 -MonitoringInterval 60 -LogFile "C:\Logs\Gateway.log" -IncludePerformanceMetrics -IncludeSSLCertificateStatus
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$MonitoringInterval = 30,
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile,
    
    [switch]$IncludePerformanceMetrics,
    
    [switch]$IncludeSSLCertificateStatus,
    
    [switch]$IncludeAuthenticationStatus,
    
    [Parameter(Mandatory = $false)]
    [int]$AlertThreshold = 80
)

# Import required modules
Import-Module ".\Modules\RDS-Core.psm1" -Force
Import-Module ".\Modules\RDS-Gateway.psm1" -Force
Import-Module ".\Modules\RDS-Monitoring.psm1" -Force

try {
    Write-Log -Message "Starting RDS Gateway monitoring..." -Level "INFO"
    
    # Test prerequisites
    $prerequisites = Test-RDSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for RDS Gateway monitoring"
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
                IncludeSSLCertificateStatus = $IncludeSSLCertificateStatus
                IncludeAuthenticationStatus = $IncludeAuthenticationStatus
                AlertThreshold = $AlertThreshold
            }
            
            # Get Gateway status
            $gatewayStatus = Get-RDSGatewayStatus
            $monitoringData.GatewayStatus = $gatewayStatus
            
            # Get performance metrics if requested
            if ($IncludePerformanceMetrics) {
                $perfMetrics = Get-RDSGatewayPerformanceMetrics
                $monitoringData.PerformanceMetrics = $perfMetrics
                
                # Check for alerts
                if ($perfMetrics.CPUUtilization -gt $AlertThreshold) {
                    Write-Log -Message "ALERT: High CPU utilization: $($perfMetrics.CPUUtilization)%" -Level "WARNING" -LogPath $LogFile
                }
                
                if ($perfMetrics.MemoryUsage -gt $AlertThreshold) {
                    Write-Log -Message "ALERT: High memory usage: $($perfMetrics.MemoryUsage)%" -Level "WARNING" -LogPath $LogFile
                }
            }
            
            # Get SSL certificate status if requested
            if ($IncludeSSLCertificateStatus) {
                $sslStatus = Get-RDSGatewaySSLCertificateStatus
                $monitoringData.SSLCertificateStatus = $sslStatus
                
                if (-not $sslStatus.CertificateValid) {
                    Write-Log -Message "ALERT: SSL certificate is invalid or expired" -Level "WARNING" -LogPath $LogFile
                }
            }
            
            # Get authentication status if requested
            if ($IncludeAuthenticationStatus) {
                $authStatus = Get-RDSGatewayAuthenticationStatus
                $monitoringData.AuthenticationStatus = $authStatus
                
                if ($authStatus.AuthenticationFailures -gt 10) {
                    Write-Log -Message "ALERT: High number of authentication failures: $($authStatus.AuthenticationFailures)" -Level "WARNING" -LogPath $LogFile
                }
            }
            
            # Log monitoring data
            Write-Log -Message "Gateway monitoring cycle completed" -Level "INFO" -LogPath $LogFile
            
            # Wait for next monitoring cycle
            Start-Sleep -Seconds $MonitoringInterval
            
        } catch {
            Write-Log -Message "Error during monitoring cycle: $($_.Exception.Message)" -Level "ERROR" -LogPath $LogFile
            Start-Sleep -Seconds $MonitoringInterval
        }
        
    } while ($true)
    
} catch {
    Write-Log -Message "Error during Gateway monitoring: $($_.Exception.Message)" -Level "ERROR"
    throw
}
