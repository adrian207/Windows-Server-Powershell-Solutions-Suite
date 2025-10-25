#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Install and Configure RDS Licensing Server

.DESCRIPTION
    This script installs and configures the Remote Desktop Services Licensing server
    including license mode configuration, activation settings, and CAL management.

.PARAMETER LicensingServerName
    Name for the Licensing server

.PARAMETER LicenseMode
    License mode (PerUser, PerDevice)

.PARAMETER EnableActivation
    Enable license activation

.PARAMETER ActivationMethod
    Activation method (Automatic, Manual)

.PARAMETER LicenseServer
    License server address for activation

.EXAMPLE
    .\Install-Licensing.ps1 -LicensingServerName "RDS-Licensing"

.EXAMPLE
    .\Install-Licensing.ps1 -LicensingServerName "RDS-Licensing" -LicenseMode "PerUser" -EnableActivation -ActivationMethod "Automatic"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$LicensingServerName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("PerUser", "PerDevice")]
    [string]$LicenseMode = "PerUser",
    
    [switch]$EnableActivation,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Automatic", "Manual")]
    [string]$ActivationMethod = "Automatic",
    
    [Parameter(Mandatory = $false)]
    [string]$LicenseServer
)

# Import required modules
Import-Module ".\Modules\RDS-Core.psm1" -Force
Import-Module ".\Modules\RDS-Licensing.psm1" -Force

try {
    Write-Log -Message "Starting RDS Licensing server installation and configuration..." -Level "INFO"
    
    # Test prerequisites
    $prerequisites = Test-RDSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for RDS Licensing server installation"
    }
    
    Write-Log -Message "Prerequisites validated successfully" -Level "SUCCESS"
    
    # Install Licensing server
    Write-Log -Message "Installing RDS Licensing server..." -Level "INFO"
    $installResult = Install-RDSLicensing -IncludeManagementTools
    
    if ($installResult.Success) {
        Write-Log -Message "RDS Licensing server installed successfully" -Level "SUCCESS"
    } else {
        throw "Failed to install RDS Licensing server: $($installResult.Error)"
    }
    
    # Configure Licensing server
    Write-Log -Message "Configuring RDS Licensing server..." -Level "INFO"
    $configResult = New-RDSLicensingConfiguration -LicensingServerName $LicensingServerName -LicenseMode $LicenseMode -EnableActivation:$EnableActivation -ActivationMethod $ActivationMethod -LicenseServer $LicenseServer
    
    if ($configResult.Success) {
        Write-Log -Message "RDS Licensing server configured successfully" -Level "SUCCESS"
    } else {
        throw "Failed to configure RDS Licensing server: $($configResult.Error)"
    }
    
    # Configure Licensing settings
    Write-Log -Message "Configuring Licensing settings..." -Level "INFO"
    $settingsResult = Set-RDSLicensingSettings -LicenseMode $LicenseMode -EnableActivation:$EnableActivation -ActivationMethod $ActivationMethod -LicenseServer $LicenseServer -EnableAuditing
    
    if ($settingsResult.Success) {
        Write-Log -Message "Licensing settings configured successfully" -Level "SUCCESS"
    } else {
        Write-Log -Message "Licensing settings configuration failed: $($settingsResult.Error)" -Level "WARNING"
    }
    
    # Test Licensing connectivity
    Write-Log -Message "Testing Licensing connectivity..." -Level "INFO"
    $testResult = Test-RDSLicensingConnectivity -TestServiceAvailability -TestLicenseServerConnectivity -TestActivationStatus
    
    if ($testResult.Success) {
        Write-Log -Message "Licensing connectivity test passed" -Level "SUCCESS"
    } else {
        Write-Log -Message "Licensing connectivity test failed: $($testResult.Error)" -Level "WARNING"
    }
    
    # Get final status
    $status = Get-RDSLicensingStatus
    Write-Log -Message "Licensing server installation and configuration completed" -Level "SUCCESS"
    Write-Log -Message "Licensing Server Name: $LicensingServerName" -Level "INFO"
    Write-Log -Message "License Mode: $LicenseMode" -Level "INFO"
    Write-Log -Message "Activation Enabled: $EnableActivation" -Level "INFO"
    Write-Log -Message "Activation Method: $ActivationMethod" -Level "INFO"
    
    return $status
    
} catch {
    Write-Log -Message "Error during Licensing server installation: $($_.Exception.Message)" -Level "ERROR"
    throw
}
