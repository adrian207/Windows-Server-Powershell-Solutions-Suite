#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Configure RDS Gateway Settings

.DESCRIPTION
    This script configures various RDS Gateway settings including
    SSL configuration, authentication policies, and security settings.

.PARAMETER EnableSSL
    Enable SSL/TLS encryption

.PARAMETER RequireClientCertificates
    Require client certificates

.PARAMETER EnableMFA
    Enable multi-factor authentication

.PARAMETER AuthenticationMethod
    Authentication method (Password, SmartCard, Both)

.PARAMETER CertificateThumbprint
    SSL certificate thumbprint

.PARAMETER EnableAuditLogging
    Enable comprehensive audit logging

.EXAMPLE
    .\Configure-Gateway.ps1 -EnableSSL -RequireClientCertificates

.EXAMPLE
    .\Configure-Gateway.ps1 -EnableSSL -EnableMFA -AuthenticationMethod "SmartCard" -CertificateThumbprint "1234567890ABCDEF"
#>

[CmdletBinding()]
param(
    [switch]$EnableSSL,
    
    [switch]$RequireClientCertificates,
    
    [switch]$EnableMFA,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Password", "SmartCard", "Both")]
    [string]$AuthenticationMethod = "Password",
    
    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint,
    
    [switch]$EnableAuditLogging
)

# Import required modules
Import-Module ".\Modules\RDS-Core.psm1" -Force
Import-Module ".\Modules\RDS-Gateway.psm1" -Force

try {
    Write-Log -Message "Starting RDS Gateway configuration..." -Level "INFO"
    
    # Test prerequisites
    $prerequisites = Test-RDSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for RDS Gateway configuration"
    }
    
    Write-Log -Message "Prerequisites validated successfully" -Level "SUCCESS"
    
    # Configure Gateway settings
    Write-Log -Message "Configuring Gateway settings..." -Level "INFO"
    $settingsResult = Set-RDSGatewaySettings -EnableSSL:$EnableSSL -RequireClientCertificates:$RequireClientCertificates -EnableMFA:$EnableMFA -AuthenticationMethod $AuthenticationMethod -CertificateThumbprint $CertificateThumbprint -EnableAuditLogging:$EnableAuditLogging
    
    if ($settingsResult.Success) {
        Write-Log -Message "Gateway settings configured successfully" -Level "SUCCESS"
    } else {
        throw "Failed to configure Gateway settings: $($settingsResult.Error)"
    }
    
    # Configure authentication policy
    Write-Log -Message "Configuring authentication policy..." -Level "INFO"
    $policyResult = Set-RDSGatewayAuthenticationPolicy -PolicyName "Default Policy" -UserGroups @("Domain Users") -EnableConditionalAccess:$EnableMFA
    
    if ($policyResult.Success) {
        Write-Log -Message "Authentication policy configured successfully" -Level "SUCCESS"
    } else {
        Write-Log -Message "Authentication policy configuration failed: $($policyResult.Error)" -Level "WARNING"
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
    Write-Log -Message "Gateway configuration completed" -Level "SUCCESS"
    Write-Log -Message "SSL Enabled: $EnableSSL" -Level "INFO"
    Write-Log -Message "Client Certificates Required: $RequireClientCertificates" -Level "INFO"
    Write-Log -Message "MFA Enabled: $EnableMFA" -Level "INFO"
    Write-Log -Message "Authentication Method: $AuthenticationMethod" -Level "INFO"
    Write-Log -Message "Audit Logging Enabled: $EnableAuditLogging" -Level "INFO"
    
    return $status
    
} catch {
    Write-Log -Message "Error during Gateway configuration: $($_.Exception.Message)" -Level "ERROR"
    throw
}
