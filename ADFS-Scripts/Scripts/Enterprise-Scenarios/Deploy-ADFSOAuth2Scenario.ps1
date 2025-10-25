#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy ADFS OAuth2 and OpenID Connect Scenario

.DESCRIPTION
    This script deploys ADFS OAuth2 and OpenID Connect scenario
    for modern web applications and API authentication.

.PARAMETER Environment
    Target environment (Development, Staging, Production)

.PARAMETER EnableOAuth2
    Enable OAuth2 support

.PARAMETER EnableOpenIDConnect
    Enable OpenID Connect support

.PARAMETER EnableJWT
    Enable JWT token support

.PARAMETER EnableAuditing
    Enable comprehensive audit logging

.EXAMPLE
    .\Deploy-ADFSOAuth2Scenario.ps1 -Environment "Production" -EnableOAuth2 -EnableOpenIDConnect -EnableJWT

.EXAMPLE
    .\Deploy-ADFSOAuth2Scenario.ps1 -Environment "Development" -EnableAuditing
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Development", "Staging", "Production")]
    [string]$Environment = "Development",
    
    [switch]$EnableOAuth2,
    
    [switch]$EnableOpenIDConnect,
    
    [switch]$EnableJWT,
    
    [switch]$EnableAuditing
)

# Import ADFS modules
try {
    Import-Module "..\..\Modules\ADFS-Core.psm1" -Force
    Import-Module "..\..\Modules\ADFS-Security.psm1" -Force
} catch {
    Write-Error "Failed to import ADFS modules: $($_.Exception.Message)"
    exit 1
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "ADFS OAuth2 and OpenID Connect Scenario Deployment" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Environment: $Environment" -ForegroundColor Yellow
Write-Host "OAuth2 Enabled: $EnableOAuth2" -ForegroundColor Yellow
Write-Host "OpenID Connect Enabled: $EnableOpenIDConnect" -ForegroundColor Yellow
Write-Host "JWT Enabled: $EnableJWT" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Test prerequisites
Write-Host "Testing prerequisites..." -ForegroundColor Green
$prerequisites = Test-ADFSPrerequisites

if (-not $prerequisites.AdministratorPrivileges) {
    Write-Error "Administrator privileges are required for ADFS OAuth2 deployment."
    exit 1
}

if (-not $prerequisites.ADFSInstalled) {
    Write-Error "ADFS must be installed to perform OAuth2 deployment."
    exit 1
}

Write-Host "Prerequisites check passed!" -ForegroundColor Green

# Configure OAuth2
if ($EnableOAuth2) {
    Write-Host "Configuring OAuth2..." -ForegroundColor Green
    
    $oauth2Result = Set-ADFSOAuth2Configuration -EnableOAuth2 -EnableAuditing:$EnableAuditing
    
    if ($oauth2Result.Success) {
        Write-Host "OAuth2 configured successfully!" -ForegroundColor Green
    } else {
        Write-Warning "Failed to configure OAuth2: $($oauth2Result.Error)"
    }
}

# Configure OpenID Connect
if ($EnableOpenIDConnect) {
    Write-Host "Configuring OpenID Connect..." -ForegroundColor Green
    
    $oidcResult = Set-ADFSOpenIDConnectConfiguration -EnableOpenIDConnect -EnableAuditing:$EnableAuditing
    
    if ($oidcResult.Success) {
        Write-Host "OpenID Connect configured successfully!" -ForegroundColor Green
    } else {
        Write-Warning "Failed to configure OpenID Connect: $($oidcResult.Error)"
    }
}

# Configure JWT
if ($EnableJWT) {
    Write-Host "Configuring JWT..." -ForegroundColor Green
    
    $jwtResult = Set-ADFSJWTConfiguration -EnableJWT -EnableAuditing:$EnableAuditing
    
    if ($jwtResult.Success) {
        Write-Host "JWT configured successfully!" -ForegroundColor Green
    } else {
        Write-Warning "Failed to configure JWT: $($jwtResult.Error)"
    }
}

# Get final OAuth2 status
Write-Host "Getting final OAuth2 status..." -ForegroundColor Green
$oauth2Status = Get-ADFSOAuth2Status

if ($oauth2Status.Success) {
    Write-Host "OAuth2 Status:" -ForegroundColor Cyan
    Write-Host "  OAuth2 Enabled: $($oauth2Status.OAuth2Enabled)" -ForegroundColor White
    Write-Host "  OpenID Connect Enabled: $($oauth2Status.OpenIDConnectEnabled)" -ForegroundColor White
    Write-Host "  JWT Enabled: $($oauth2Status.JWTEnabled)" -ForegroundColor White
    Write-Host "  Auditing Enabled: $($oauth2Status.AuditingEnabled)" -ForegroundColor White
} else {
    Write-Warning "Failed to get OAuth2 status: $($oauth2Status.Error)"
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "ADFS OAuth2 Scenario Deployment Completed!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan

# Summary
Write-Host "OAuth2 Deployment Summary:" -ForegroundColor Yellow
Write-Host "  Environment: $Environment" -ForegroundColor White
Write-Host "  OAuth2 Enabled: $EnableOAuth2" -ForegroundColor White
Write-Host "  OpenID Connect Enabled: $EnableOpenIDConnect" -ForegroundColor White
Write-Host "  JWT Enabled: $EnableJWT" -ForegroundColor White
Write-Host "  Auditing Enabled: $EnableAuditing" -ForegroundColor White
Write-Host "  Completion Time: $(Get-Date)" -ForegroundColor White
