#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    ADFS Farm Deployment Script

.DESCRIPTION
    This script deploys a complete ADFS farm with all necessary components
    including federation service, proxy, and Web Application Proxy.

.PARAMETER FederationServiceName
    Name for the federation service (e.g., fs.company.com)

.PARAMETER ServiceAccount
    Service account for ADFS (e.g., DOMAIN\adfs-service)

.PARAMETER CertificateThumbprint
    Thumbprint of the SSL certificate for ADFS

.PARAMETER DatabaseConnectionString
    Connection string for ADFS configuration database

.PARAMETER EnableProxy
    Enable ADFS proxy functionality

.PARAMETER EnableWAP
    Enable Web Application Proxy

.PARAMETER EnableAuditing
    Enable audit logging

.PARAMETER DryRun
    Perform a dry run without making changes

.EXAMPLE
    .\Deploy-ADFSFarm.ps1 -FederationServiceName "fs.company.com" -ServiceAccount "DOMAIN\adfs-service" -CertificateThumbprint "1234567890ABCDEF"

.EXAMPLE
    .\Deploy-ADFSFarm.ps1 -FederationServiceName "fs.company.com" -ServiceAccount "DOMAIN\adfs-service" -CertificateThumbprint "1234567890ABCDEF" -EnableProxy -EnableWAP -EnableAuditing
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$FederationServiceName,
    
    [Parameter(Mandatory = $true)]
    [string]$ServiceAccount,
    
    [Parameter(Mandatory = $true)]
    [string]$CertificateThumbprint,
    
    [Parameter(Mandatory = $false)]
    [string]$DatabaseConnectionString,
    
    [switch]$EnableProxy,
    
    [switch]$EnableWAP,
    
    [switch]$EnableAuditing,
    
    [switch]$DryRun
)

# Import ADFS modules
try {
    Import-Module "..\Modules\ADFS-Core.psm1" -Force
    Import-Module "..\Modules\ADFS-Federation.psm1" -Force
    Import-Module "..\Modules\ADFS-Security.psm1" -Force
    Import-Module "..\Modules\ADFS-Troubleshooting.psm1" -Force
} catch {
    Write-Error "Failed to import ADFS modules: $($_.Exception.Message)"
    exit 1
}

# Script configuration
$ScriptConfig = @{
    FederationServiceName = $FederationServiceName
    ServiceAccount = $ServiceAccount
    CertificateThumbprint = $CertificateThumbprint
    DatabaseConnectionString = $DatabaseConnectionString
    EnableProxy = $EnableProxy
    EnableWAP = $EnableWAP
    EnableAuditing = $EnableAuditing
    DryRun = $DryRun
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "ADFS Farm Deployment Script" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Federation Service Name: $FederationServiceName" -ForegroundColor Yellow
Write-Host "Service Account: $ServiceAccount" -ForegroundColor Yellow
Write-Host "Certificate Thumbprint: $CertificateThumbprint" -ForegroundColor Yellow
Write-Host "Enable Proxy: $EnableProxy" -ForegroundColor Yellow
Write-Host "Enable WAP: $EnableWAP" -ForegroundColor Yellow
Write-Host "Enable Auditing: $EnableAuditing" -ForegroundColor Yellow
Write-Host "Dry Run: $DryRun" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Test prerequisites
Write-Host "Testing prerequisites..." -ForegroundColor Green
$prerequisites = Test-ADFSPrerequisites

if (-not $prerequisites.AdministratorPrivileges) {
    Write-Error "Administrator privileges are required to deploy ADFS farm."
    exit 1
}

if (-not $prerequisites.WindowsVersion) {
    Write-Error "Windows Server 2016 or later is required."
    exit 1
}

if (-not $prerequisites.PowerShellVersion) {
    Write-Error "PowerShell 5.0 or later is required."
    exit 1
}

if (-not $prerequisites.DomainMember) {
    Write-Error "Server must be a domain member to deploy ADFS farm."
    exit 1
}

Write-Host "Prerequisites check passed!" -ForegroundColor Green

# Deploy ADFS farm
Write-Host "Deploying ADFS farm..." -ForegroundColor Green
$farmResult = Install-ADFSFarm -FederationServiceName $FederationServiceName -ServiceAccount $ServiceAccount -CertificateThumbprint $CertificateThumbprint -DatabaseConnectionString $DatabaseConnectionString -EnableProxy:$EnableProxy -EnableWAP:$EnableWAP -EnableAuditing:$EnableAuditing

if ($farmResult.Success) {
    Write-Host "ADFS farm deployed successfully!" -ForegroundColor Green
} else {
    Write-Error "Failed to deploy ADFS farm: $($farmResult.Error)"
    exit 1
}

# Configure MFA integration
Write-Host "Configuring MFA integration..." -ForegroundColor Green
$mfaResult = Set-ADFSMFAIntegration -MFAProvider "AzureMFA" -EnableConditionalMFA -EnablePerAppMFA -EnableLocationBasedMFA -EnableDeviceBasedMFA -EnableAuditing:$EnableAuditing

if ($mfaResult.Success) {
    Write-Host "MFA integration configured successfully!" -ForegroundColor Green
} else {
    Write-Warning "Failed to configure MFA integration: $($mfaResult.Error)"
}

# Configure certificate management
Write-Host "Configuring certificate management..." -ForegroundColor Green
$certResult = Set-ADFSCertificateManagement -SSLCertificateThumbprint $CertificateThumbprint -TokenSigningCertificateThumbprint $CertificateThumbprint -EnableAutoRenewal -EnableCertificateMonitoring -EnableAuditing:$EnableAuditing

if ($certResult.Success) {
    Write-Host "Certificate management configured successfully!" -ForegroundColor Green
} else {
    Write-Warning "Failed to configure certificate management: $($certResult.Error)"
}

# Configure conditional access
Write-Host "Configuring conditional access policies..." -ForegroundColor Green
$conditionalAccessResult = Set-ADFSConditionalAccess -EnableLocationBasedAccess -EnableDeviceBasedAccess -EnableRiskBasedAccess -EnableTimeBasedAccess -EnableGroupBasedAccess -EnableAuditing:$EnableAuditing

if ($conditionalAccessResult.Success) {
    Write-Host "Conditional access policies configured successfully!" -ForegroundColor Green
} else {
    Write-Warning "Failed to configure conditional access policies: $($conditionalAccessResult.Error)"
}

# Configure smartcard authentication
Write-Host "Configuring smartcard authentication..." -ForegroundColor Green
$smartcardResult = Set-ADFSSmartcardAuthentication -EnableSmartcardAuth -CertificateAuthority "CA.company.com" -EnableCertificateValidation -EnableCertificateRevocation -EnableAuditing:$EnableAuditing

if ($smartcardResult.Success) {
    Write-Host "Smartcard authentication configured successfully!" -ForegroundColor Green
} else {
    Write-Warning "Failed to configure smartcard authentication: $($smartcardResult.Error)"
}

# Get final status
Write-Host "Getting final ADFS status..." -ForegroundColor Green
$statusResult = Get-ADFSStatus

if ($statusResult.Success) {
    Write-Host "ADFS Status:" -ForegroundColor Cyan
    Write-Host "  Service Status: $($statusResult.ServiceStatus.ADFSServiceRunning)" -ForegroundColor White
    Write-Host "  Farm Status: $($statusResult.FarmStatus.FarmConfigured)" -ForegroundColor White
    Write-Host "  Trust Status: $($statusResult.TrustStatus.TotalRelyingPartyTrusts) trusts configured" -ForegroundColor White
} else {
    Write-Warning "Failed to get ADFS status: $($statusResult.Error)"
}

# Test connectivity
Write-Host "Testing ADFS connectivity..." -ForegroundColor Green
$connectivityResult = Test-ADFSConnectivity -TestServiceConnectivity -TestTrustFunctionality -TestClaimProcessing -TestSSO

if ($connectivityResult.Success) {
    Write-Host "ADFS connectivity tests passed!" -ForegroundColor Green
} else {
    Write-Warning "ADFS connectivity tests failed: $($connectivityResult.Error)"
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "ADFS Farm Deployment Completed!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan

# Summary
Write-Host "Deployment Summary:" -ForegroundColor Yellow
Write-Host "  Federation Service: $FederationServiceName" -ForegroundColor White
Write-Host "  Service Account: $ServiceAccount" -ForegroundColor White
Write-Host "  Certificate: $CertificateThumbprint" -ForegroundColor White
Write-Host "  Proxy Enabled: $EnableProxy" -ForegroundColor White
Write-Host "  WAP Enabled: $EnableWAP" -ForegroundColor White
Write-Host "  Auditing Enabled: $EnableAuditing" -ForegroundColor White
Write-Host "  Deployment Time: $(Get-Date)" -ForegroundColor White

Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Configure relying party trusts for applications" -ForegroundColor White
Write-Host "  2. Set up claims rules for applications" -ForegroundColor White
Write-Host "  3. Configure Office 365 federation if needed" -ForegroundColor White
Write-Host "  4. Test single sign-on functionality" -ForegroundColor White
Write-Host "  5. Set up monitoring and alerting" -ForegroundColor White
