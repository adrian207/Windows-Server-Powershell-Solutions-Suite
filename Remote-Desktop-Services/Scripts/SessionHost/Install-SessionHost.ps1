#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Install and Configure RDS Session Host

.DESCRIPTION
    This script installs and configures the Remote Desktop Services Session Host
    including session collection configuration, user access, and performance settings.

.PARAMETER SessionHostName
    Name for the Session Host server

.PARAMETER CollectionName
    Name for the session collection

.PARAMETER MaxConnections
    Maximum number of concurrent connections

.PARAMETER UserGroups
    Array of user groups with access

.PARAMETER EnableSessionLimit
    Enable session limits

.PARAMETER IdleTimeout
    Idle timeout in minutes

.EXAMPLE
    .\Install-SessionHost.ps1 -SessionHostName "RDS-SH-01" -CollectionName "Production Sessions"

.EXAMPLE
    .\Install-SessionHost.ps1 -SessionHostName "RDS-SH-01" -CollectionName "Production Sessions" -MaxConnections 50 -UserGroups @("Domain Users") -EnableSessionLimit -IdleTimeout 60
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SessionHostName,
    
    [Parameter(Mandatory = $false)]
    [string]$CollectionName = "Default Collection",
    
    [Parameter(Mandatory = $false)]
    [int]$MaxConnections = 50,
    
    [Parameter(Mandatory = $false)]
    [string[]]$UserGroups = @("Domain Users"),
    
    [switch]$EnableSessionLimit,
    
    [Parameter(Mandatory = $false)]
    [int]$IdleTimeout = 60
)

# Import required modules
Import-Module ".\Modules\RDS-Core.psm1" -Force
Import-Module ".\Modules\RDS-SessionHost.psm1" -Force

try {
    Write-Log -Message "Starting RDS Session Host installation and configuration..." -Level "INFO"
    
    # Test prerequisites
    $prerequisites = Test-RDSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for RDS Session Host installation"
    }
    
    Write-Log -Message "Prerequisites validated successfully" -Level "SUCCESS"
    
    # Install Session Host
    Write-Log -Message "Installing RDS Session Host..." -Level "INFO"
    $installResult = Install-RDSSessionHost -StartService -SetAutoStart
    
    if ($installResult.Success) {
        Write-Log -Message "RDS Session Host installed successfully" -Level "SUCCESS"
    } else {
        throw "Failed to install RDS Session Host: $($installResult.Error)"
    }
    
    # Configure Session Host
    Write-Log -Message "Configuring RDS Session Host..." -Level "INFO"
    $configResult = New-RDSSessionHostConfiguration -CollectionName $CollectionName -MaxConnections $MaxConnections -UserGroups $UserGroups
    
    if ($configResult.Success) {
        Write-Log -Message "RDS Session Host configured successfully" -Level "SUCCESS"
    } else {
        throw "Failed to configure RDS Session Host: $($configResult.Error)"
    }
    
    # Configure session limits if requested
    if ($EnableSessionLimit) {
        Write-Log -Message "Configuring session limits..." -Level "INFO"
        $limitResult = Set-RDSSessionLimit -MaxSessions $MaxConnections -IdleTimeout $IdleTimeout
        
        if ($limitResult.Success) {
            Write-Log -Message "Session limits configured successfully" -Level "SUCCESS"
        } else {
            Write-Log -Message "Session limits configuration failed: $($limitResult.Error)" -Level "WARNING"
        }
    }
    
    # Test Session Host connectivity
    Write-Log -Message "Testing Session Host connectivity..." -Level "INFO"
    $testResult = Test-RDSSessionHostConnectivity -TestDuration 60
    
    if ($testResult.Success) {
        Write-Log -Message "Session Host connectivity test passed" -Level "SUCCESS"
    } else {
        Write-Log -Message "Session Host connectivity test failed: $($testResult.Error)" -Level "WARNING"
    }
    
    # Get final status
    $status = Get-RDSSessionHostStatus
    Write-Log -Message "Session Host installation and configuration completed" -Level "SUCCESS"
    Write-Log -Message "Session Host Name: $SessionHostName" -Level "INFO"
    Write-Log -Message "Collection Name: $CollectionName" -Level "INFO"
    Write-Log -Message "Max Connections: $MaxConnections" -Level "INFO"
    Write-Log -Message "User Groups: $($UserGroups -join ', ')" -Level "INFO"
    Write-Log -Message "Session Limits Enabled: $EnableSessionLimit" -Level "INFO"
    
    return $status
    
} catch {
    Write-Log -Message "Error during Session Host installation: $($_.Exception.Message)" -Level "ERROR"
    throw
}
