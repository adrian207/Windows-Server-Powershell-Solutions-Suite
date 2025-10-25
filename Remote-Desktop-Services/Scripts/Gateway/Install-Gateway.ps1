#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Install and Configure RDS Gateway

.DESCRIPTION
    This script installs and configures the Remote Desktop Services Gateway
    including SSL certificates, authentication policies, and security settings.

.PARAMETER GatewayName
    Name for the Gateway server

.PARAMETER CertificateThumbprint
    SSL certificate thumbprint

.PARAMETER AuthenticationMethod
    Authentication method (Password, SmartCard, Both)

.PARAMETER EnableSSL
    Enable SSL/TLS encryption

.PARAMETER RequireClientCertificates
    Require client certificates

.PARAMETER EnableMFA
    Enable multi-factor authentication

.EXAMPLE
    .\Install-Gateway.ps1 -GatewayName "Corporate Gateway"

.EXAMPLE
    .\Install-Gateway.ps1 -GatewayName "Secure Gateway" -CertificateThumbprint "1234567890ABCDEF" -AuthenticationMethod "SmartCard" -EnableSSL -RequireClientCertificates
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$GatewayName,
    
    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Password", "SmartCard", "Both")]
    [string]$AuthenticationMethod = "Password",
    
    [switch]$EnableSSL,
    
    [switch]$RequireClientCertificates,
    
    [switch]$EnableMFA
)

# Import required modules
Import-Module ".\Modules\RDS-Core.psm1" -Force
Import-Module ".\Modules\RDS-Gateway.psm1" -Force

try {
    Write-Log -Message "Starting RDS Gateway installation and configuration..." -Level "INFO"
    
    # Test prerequisites
    $prerequisites = Test-RDSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for RDS Gateway installation"
    }
    
    Write-Log -Message "Prerequisites validated successfully" -Level "SUCCESS"
    
    # Install Gateway
    Write-Log -Message "Installing RDS Gateway..." -Level "INFO"
    $installResult = Install-RDSGateway -IncludeManagementTools
    
    if ($installResult.Success) {
        Write-Log -Message "RDS Gateway installed successfully" -Level "SUCCESS"
    } else {
        throw "Failed to install RDS Gateway: $($installResult.Error)"
    }
    
    # Configure Gateway
    Write-Log -Message "Configuring RDS Gateway..." -Level "INFO"
    $configResult = New-RDSGatewayConfiguration -GatewayName $GatewayName -CertificateThumbprint $CertificateThumbprint -AuthenticationMethod $AuthenticationMethod -EnableSSL:$EnableSSL -RequireClientCertificates:$RequireClientCertificates -EnableMFA:$EnableMFA
    
    if ($configResult.Success) {
        Write-Log -Message "RDS Gateway configured successfully" -Level "SUCCESS"
    } else {
        throw "Failed to configure RDS Gateway: $($configResult.Error)"
    }
    
    # Configure Gateway settings
    Write-Log -Message "Configuring Gateway settings..." -Level "INFO"
    $settingsResult = Set-RDSGatewaySettings -EnableSSL:$EnableSSL -RequireClientCertificates:$RequireClientCertificates -EnableMFA:$EnableMFA -AuthenticationMethod $AuthenticationMethod -CertificateThumbprint $CertificateThumbprint
    
    if ($settingsResult.Success) {
        Write-Log -Message "Gateway settings configured successfully" -Level "SUCCESS"
    } else {
        Write-Log -Message "Gateway settings configuration failed: $($settingsResult.Error)" -Level "WARNING"
    }
    
    # Test Gateway connectivity
    Write-Log -Message "Testing Gateway connectivity..." -Level "INFO"
    $testResult = Test-RDSGatewayConnectivity -TestSSL:$EnableSSL -TestAuthentication -TestServiceAvailability
    
    if ($testResult.Success) {
        Write-Log -Message "Gateway connectivity test passed" -Level "SUCCESS"
    } else {
        Write-Log -Message "Gateway connectivity test failed: $($testResult.Error)" -Level "WARNING"
    }
    
    # Get final status
    $status = Get-RDSGatewayStatus
    Write-Log -Message "Gateway installation and configuration completed" -Level "SUCCESS"
    Write-Log -Message "Gateway Name: $GatewayName" -Level "INFO"
    Write-Log -Message "Authentication Method: $AuthenticationMethod" -Level "INFO"
    Write-Log -Message "SSL Enabled: $EnableSSL" -Level "INFO"
    Write-Log -Message "Client Certificates Required: $RequireClientCertificates" -Level "INFO"
    Write-Log -Message "MFA Enabled: $EnableMFA" -Level "INFO"
    
    return $status
    
} catch {
    Write-Log -Message "Error during Gateway installation: $($_.Exception.Message)" -Level "ERROR"
    throw
}
