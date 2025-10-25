#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploy ADFS Web Application Proxy (WAP) Scenario

.DESCRIPTION
    This script deploys ADFS Web Application Proxy scenario
    for secure external access to internal applications.

.PARAMETER Environment
    Target environment (Development, Staging, Production)

.PARAMETER EnableWebApplicationProxy
    Enable Web Application Proxy

.PARAMETER EnablePreAuthentication
    Enable pre-authentication

.PARAMETER EnableAuditing
    Enable comprehensive audit logging

.EXAMPLE
    .\Deploy-ADFSWAPScenario.ps1 -Environment "Production" -EnableWebApplicationProxy -EnablePreAuthentication

.EXAMPLE
    .\Deploy-ADFSWAPScenario.ps1 -Environment "Development" -EnableAuditing
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Development", "Staging", "Production")]
    [string]$Environment = "Development",
    
    [switch]$EnableWebApplicationProxy,
    
    [switch]$EnablePreAuthentication,
    
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
Write-Host "ADFS Web Application Proxy (WAP) Scenario Deployment" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Environment: $Environment" -ForegroundColor Yellow
Write-Host "Web Application Proxy Enabled: $EnableWebApplicationProxy" -ForegroundColor Yellow
Write-Host "Pre-Authentication Enabled: $EnablePreAuthentication" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Test prerequisites
Write-Host "Testing prerequisites..." -ForegroundColor Green
$prerequisites = Test-ADFSPrerequisites

if (-not $prerequisites.AdministratorPrivileges) {
    Write-Error "Administrator privileges are required for ADFS WAP deployment."
    exit 1
}

if (-not $prerequisites.ADFSInstalled) {
    Write-Error "ADFS must be installed to perform WAP deployment."
    exit 1
}

Write-Host "Prerequisites check passed!" -ForegroundColor Green

# Configure Web Application Proxy
if ($EnableWebApplicationProxy) {
    Write-Host "Configuring Web Application Proxy..." -ForegroundColor Green
    
    $wapResult = Set-ADFSWebApplicationProxy -EnableWAP -EnableAuditing:$EnableAuditing
    
    if ($wapResult.Success) {
        Write-Host "Web Application Proxy configured successfully!" -ForegroundColor Green
    } else {
        Write-Warning "Failed to configure Web Application Proxy: $($wapResult.Error)"
    }
}

# Configure Pre-Authentication
if ($EnablePreAuthentication) {
    Write-Host "Configuring Pre-Authentication..." -ForegroundColor Green
    
    $preAuthResult = Set-ADFSPreAuthentication -EnablePreAuthentication -EnableAuditing:$EnableAuditing
    
    if ($preAuthResult.Success) {
        Write-Host "Pre-Authentication configured successfully!" -ForegroundColor Green
    } else {
        Write-Warning "Failed to configure Pre-Authentication: $($preAuthResult.Error)"
    }
}

# Get final WAP status
Write-Host "Getting final WAP status..." -ForegroundColor Green
$wapStatus = Get-ADFSWAPStatus

if ($wapStatus.Success) {
    Write-Host "WAP Status:" -ForegroundColor Cyan
    Write-Host "  Web Application Proxy Enabled: $($wapStatus.WAPEnabled)" -ForegroundColor White
    Write-Host "  Pre-Authentication Enabled: $($wapStatus.PreAuthenticationEnabled)" -ForegroundColor White
    Write-Host "  Auditing Enabled: $($wapStatus.AuditingEnabled)" -ForegroundColor White
} else {
    Write-Warning "Failed to get WAP status: $($wapStatus.Error)"
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "ADFS WAP Scenario Deployment Completed!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan

# Summary
Write-Host "WAP Deployment Summary:" -ForegroundColor Yellow
Write-Host "  Environment: $Environment" -ForegroundColor White
Write-Host "  Web Application Proxy Enabled: $EnableWebApplicationProxy" -ForegroundColor White
Write-Host "  Pre-Authentication Enabled: $EnablePreAuthentication" -ForegroundColor White
Write-Host "  Auditing Enabled: $EnableAuditing" -ForegroundColor White
Write-Host "  Completion Time: $(Get-Date)" -ForegroundColor White
