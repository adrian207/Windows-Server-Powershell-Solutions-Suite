#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Install and Configure RDS Connection Broker

.DESCRIPTION
    This script installs and configures the Remote Desktop Services Connection Broker
    including high availability setup, load balancing, and failover configuration.

.PARAMETER ConnectionBrokerName
    Name for the Connection Broker server

.PARAMETER EnableHighAvailability
    Enable high availability configuration

.PARAMETER SecondaryBroker
    Secondary Connection Broker server for HA

.PARAMETER LoadBalancingMethod
    Load balancing method (RoundRobin, Weighted, LeastConnections)

.PARAMETER EnableSessionPersistence
    Enable session persistence across servers

.EXAMPLE
    .\Install-ConnectionBroker.ps1 -ConnectionBrokerName "RDS-CB-01"

.EXAMPLE
    .\Install-ConnectionBroker.ps1 -ConnectionBrokerName "RDS-CB-01" -EnableHighAvailability -SecondaryBroker "RDS-CB-02" -LoadBalancingMethod "RoundRobin"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ConnectionBrokerName,
    
    [switch]$EnableHighAvailability,
    
    [Parameter(Mandatory = $false)]
    [string]$SecondaryBroker,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("RoundRobin", "Weighted", "LeastConnections")]
    [string]$LoadBalancingMethod = "RoundRobin",
    
    [switch]$EnableSessionPersistence
)

# Import required modules
Import-Module ".\Modules\RDS-Core.psm1" -Force
Import-Module ".\Modules\RDS-ConnectionBroker.psm1" -Force

try {
    Write-Log -Message "Starting RDS Connection Broker installation and configuration..." -Level "INFO"
    
    # Test prerequisites
    $prerequisites = Test-RDSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for RDS Connection Broker installation"
    }
    
    Write-Log -Message "Prerequisites validated successfully" -Level "SUCCESS"
    
    # Install Connection Broker
    Write-Log -Message "Installing RDS Connection Broker..." -Level "INFO"
    $installResult = Install-RDSConnectionBroker -StartService -SetAutoStart
    
    if ($installResult.Success) {
        Write-Log -Message "RDS Connection Broker installed successfully" -Level "SUCCESS"
    } else {
        throw "Failed to install RDS Connection Broker: $($installResult.Error)"
    }
    
    # Configure Connection Broker
    Write-Log -Message "Configuring RDS Connection Broker..." -Level "INFO"
    $configResult = New-RDSConnectionBrokerConfiguration -ConnectionBrokerName $ConnectionBrokerName -EnableLoadBalancing -LoadBalancingMethod $LoadBalancingMethod
    
    if ($configResult.Success) {
        Write-Log -Message "RDS Connection Broker configured successfully" -Level "SUCCESS"
    } else {
        throw "Failed to configure RDS Connection Broker: $($configResult.Error)"
    }
    
    # Configure High Availability if requested
    if ($EnableHighAvailability) {
        if (-not $SecondaryBroker) {
            throw "Secondary Broker server name is required for high availability configuration"
        }
        
        Write-Log -Message "Configuring high availability with secondary broker: $SecondaryBroker" -Level "INFO"
        $haResult = New-RDSHighAvailabilityConfiguration -PrimaryServer $ConnectionBrokerName -SecondaryServer $SecondaryBroker -EnableFailover -EnableLoadBalancing
        
        if ($haResult.Success) {
            Write-Log -Message "High availability configuration completed successfully" -Level "SUCCESS"
        } else {
            Write-Log -Message "High availability configuration failed: $($haResult.Error)" -Level "WARNING"
        }
    }
    
    # Configure session persistence if requested
    if ($EnableSessionPersistence) {
        Write-Log -Message "Configuring session persistence..." -Level "INFO"
        $persistenceResult = Set-RDSSessionPersistence -EnablePersistence -PersistenceMethod "Database"
        
        if ($persistenceResult.Success) {
            Write-Log -Message "Session persistence configured successfully" -Level "SUCCESS"
        } else {
            Write-Log -Message "Session persistence configuration failed: $($persistenceResult.Error)" -Level "WARNING"
        }
    }
    
    # Test Connection Broker functionality
    Write-Log -Message "Testing Connection Broker functionality..." -Level "INFO"
    $testResult = Test-RDSConnectionBrokerConfiguration
    
    if ($testResult.Success) {
        Write-Log -Message "Connection Broker functionality test passed" -Level "SUCCESS"
    } else {
        Write-Log -Message "Connection Broker functionality test failed: $($testResult.Error)" -Level "WARNING"
    }
    
    # Get final status
    $status = Get-RDSConnectionBrokerStatus
    Write-Log -Message "Connection Broker installation and configuration completed" -Level "SUCCESS"
    Write-Log -Message "Connection Broker Name: $ConnectionBrokerName" -Level "INFO"
    Write-Log -Message "High Availability: $EnableHighAvailability" -Level "INFO"
    Write-Log -Message "Load Balancing: $LoadBalancingMethod" -Level "INFO"
    Write-Log -Message "Session Persistence: $EnableSessionPersistence" -Level "INFO"
    
    return $status
    
} catch {
    Write-Log -Message "Error during Connection Broker installation: $($_.Exception.Message)" -Level "ERROR"
    throw
}
