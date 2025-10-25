#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Configure RDS Connection Broker High Availability

.DESCRIPTION
    This script configures high availability for the Remote Desktop Services Connection Broker
    including failover configuration, load balancing, and health monitoring.

.PARAMETER PrimaryServer
    Primary Connection Broker server name

.PARAMETER SecondaryServer
    Secondary Connection Broker server name

.PARAMETER EnableFailover
    Enable automatic failover

.PARAMETER EnableLoadBalancing
    Enable load balancing

.PARAMETER LoadBalancingMethod
    Load balancing method (RoundRobin, Weighted, LeastConnections)

.PARAMETER HealthCheckInterval
    Health check interval in seconds

.EXAMPLE
    .\Configure-HighAvailability.ps1 -PrimaryServer "RDS-CB-01" -SecondaryServer "RDS-CB-02"

.EXAMPLE
    .\Configure-HighAvailability.ps1 -PrimaryServer "RDS-CB-01" -SecondaryServer "RDS-CB-02" -EnableFailover -EnableLoadBalancing -LoadBalancingMethod "RoundRobin"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PrimaryServer,
    
    [Parameter(Mandatory = $true)]
    [string]$SecondaryServer,
    
    [switch]$EnableFailover,
    
    [switch]$EnableLoadBalancing,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("RoundRobin", "Weighted", "LeastConnections")]
    [string]$LoadBalancingMethod = "RoundRobin",
    
    [Parameter(Mandatory = $false)]
    [int]$HealthCheckInterval = 30
)

# Import required modules
Import-Module ".\Modules\RDS-Core.psm1" -Force
Import-Module ".\Modules\RDS-ConnectionBroker.psm1" -Force

try {
    Write-Log -Message "Starting RDS Connection Broker high availability configuration..." -Level "INFO"
    
    # Test prerequisites
    $prerequisites = Test-RDSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for RDS Connection Broker high availability configuration"
    }
    
    Write-Log -Message "Prerequisites validated successfully" -Level "SUCCESS"
    
    # Configure high availability
    Write-Log -Message "Configuring high availability between $PrimaryServer and $SecondaryServer..." -Level "INFO"
    $haResult = New-RDSHighAvailabilityConfiguration -PrimaryServer $PrimaryServer -SecondaryServer $SecondaryServer -EnableFailover:$EnableFailover -EnableLoadBalancing:$EnableLoadBalancing -LoadBalancingMethod $LoadBalancingMethod
    
    if ($haResult.Success) {
        Write-Log -Message "High availability configuration completed successfully" -Level "SUCCESS"
    } else {
        throw "Failed to configure high availability: $($haResult.Error)"
    }
    
    # Configure health monitoring
    Write-Log -Message "Configuring health monitoring with interval: $HealthCheckInterval seconds..." -Level "INFO"
    $healthResult = Set-RDSHealthMonitoring -HealthCheckInterval $HealthCheckInterval -EnableAutomaticFailover:$EnableFailover
    
    if ($healthResult.Success) {
        Write-Log -Message "Health monitoring configured successfully" -Level "SUCCESS"
    } else {
        Write-Log -Message "Health monitoring configuration failed: $($healthResult.Error)" -Level "WARNING"
    }
    
    # Test failover configuration
    if ($EnableFailover) {
        Write-Log -Message "Testing failover configuration..." -Level "INFO"
        $failoverTest = Test-RDSFailoverConfiguration -PrimaryServer $PrimaryServer -SecondaryServer $SecondaryServer
        
        if ($failoverTest.Success) {
            Write-Log -Message "Failover configuration test passed" -Level "SUCCESS"
        } else {
            Write-Log -Message "Failover configuration test failed: $($failoverTest.Error)" -Level "WARNING"
        }
    }
    
    # Test load balancing if enabled
    if ($EnableLoadBalancing) {
        Write-Log -Message "Testing load balancing configuration..." -Level "INFO"
        $lbTest = Test-RDSLoadBalancingConfiguration -LoadBalancingMethod $LoadBalancingMethod
        
        if ($lbTest.Success) {
            Write-Log -Message "Load balancing configuration test passed" -Level "SUCCESS"
        } else {
            Write-Log -Message "Load balancing configuration test failed: $($lbTest.Error)" -Level "WARNING"
        }
    }
    
    # Get final status
    $status = Get-RDSConnectionBrokerStatus
    Write-Log -Message "High availability configuration completed" -Level "SUCCESS"
    Write-Log -Message "Primary Server: $PrimaryServer" -Level "INFO"
    Write-Log -Message "Secondary Server: $SecondaryServer" -Level "INFO"
    Write-Log -Message "Failover Enabled: $EnableFailover" -Level "INFO"
    Write-Log -Message "Load Balancing Enabled: $EnableLoadBalancing" -Level "INFO"
    Write-Log -Message "Load Balancing Method: $LoadBalancingMethod" -Level "INFO"
    
    return $status
    
} catch {
    Write-Log -Message "Error during high availability configuration: $($_.Exception.Message)" -Level "ERROR"
    throw
}
