#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Install and Configure RDS Web Access

.DESCRIPTION
    This script installs and configures the Remote Desktop Services Web Access
    including portal customization, application publishing, and user access control.

.PARAMETER WebAccessName
    Name for the Web Access portal

.PARAMETER PortalURL
    URL for the Web Access portal

.PARAMETER AuthenticationMethod
    Authentication method (NTLM, Forms, Both)

.PARAMETER EnableSSO
    Enable single sign-on

.PARAMETER CustomizePortal
    Enable portal customization

.PARAMETER EnableSSL
    Enable SSL/TLS encryption

.EXAMPLE
    .\Install-WebAccess.ps1 -WebAccessName "Corporate Portal"

.EXAMPLE
    .\Install-WebAccess.ps1 -WebAccessName "Corporate Portal" -PortalURL "https://rds.company.com" -AuthenticationMethod "Forms" -EnableSSO -CustomizePortal
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$WebAccessName,
    
    [Parameter(Mandatory = $false)]
    [string]$PortalURL,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("NTLM", "Forms", "Both")]
    [string]$AuthenticationMethod = "NTLM",
    
    [switch]$EnableSSO,
    
    [switch]$CustomizePortal,
    
    [switch]$EnableSSL
)

# Import required modules
Import-Module ".\Modules\RDS-Core.psm1" -Force
Import-Module ".\Modules\RDS-WebAccess.psm1" -Force

try {
    Write-Log -Message "Starting RDS Web Access installation and configuration..." -Level "INFO"
    
    # Test prerequisites
    $prerequisites = Test-RDSPrerequisites
    if (-not $prerequisites) {
        throw "Prerequisites not met for RDS Web Access installation"
    }
    
    Write-Log -Message "Prerequisites validated successfully" -Level "SUCCESS"
    
    # Install Web Access
    Write-Log -Message "Installing RDS Web Access..." -Level "INFO"
    $installResult = Install-RDSWebAccess -IncludeManagementTools
    
    if ($installResult.Success) {
        Write-Log -Message "RDS Web Access installed successfully" -Level "SUCCESS"
    } else {
        throw "Failed to install RDS Web Access: $($installResult.Error)"
    }
    
    # Configure Web Access
    Write-Log -Message "Configuring RDS Web Access..." -Level "INFO"
    $configResult = New-RDSWebAccessConfiguration -WebAccessName $WebAccessName -PortalURL $PortalURL -AuthenticationMethod $AuthenticationMethod -EnableSSO:$EnableSSO -CustomizePortal:$CustomizePortal -EnableSSL:$EnableSSL
    
    if ($configResult.Success) {
        Write-Log -Message "RDS Web Access configured successfully" -Level "SUCCESS"
    } else {
        throw "Failed to configure RDS Web Access: $($configResult.Error)"
    }
    
    # Configure Web Access settings
    Write-Log -Message "Configuring Web Access settings..." -Level "INFO"
    $settingsResult = Set-RDSWebAccessSettings -EnableSSO:$EnableSSO -CustomizePortal:$CustomizePortal -EnableSSL:$EnableSSL -AuthenticationMethod $AuthenticationMethod
    
    if ($settingsResult.Success) {
        Write-Log -Message "Web Access settings configured successfully" -Level "SUCCESS"
    } else {
        Write-Log -Message "Web Access settings configuration failed: $($settingsResult.Error)" -Level "WARNING"
    }
    
    # Test Web Access connectivity
    Write-Log -Message "Testing Web Access connectivity..." -Level "INFO"
    $testResult = Test-RDSWebAccessConnectivity -TestHTTP -TestHTTPS:$EnableSSL -TestAuthentication -TestPortalFunctionality
    
    if ($testResult.Success) {
        Write-Log -Message "Web Access connectivity test passed" -Level "SUCCESS"
    } else {
        Write-Log -Message "Web Access connectivity test failed: $($testResult.Error)" -Level "WARNING"
    }
    
    # Get final status
    $status = Get-RDSWebAccessStatus
    Write-Log -Message "Web Access installation and configuration completed" -Level "SUCCESS"
    Write-Log -Message "Web Access Name: $WebAccessName" -Level "INFO"
    Write-Log -Message "Portal URL: $PortalURL" -Level "INFO"
    Write-Log -Message "Authentication Method: $AuthenticationMethod" -Level "INFO"
    Write-Log -Message "SSO Enabled: $EnableSSO" -Level "INFO"
    Write-Log -Message "Portal Customized: $CustomizePortal" -Level "INFO"
    Write-Log -Message "SSL Enabled: $EnableSSL" -Level "INFO"
    
    return $status
    
} catch {
    Write-Log -Message "Error during Web Access installation: $($_.Exception.Message)" -Level "ERROR"
    throw
}
