#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD LDS Security Hardening Script

.DESCRIPTION
    This script provides comprehensive security hardening for AD LDS instances
    including authentication configuration, access control, and compliance testing.

.PARAMETER InstanceName
    Name of the AD LDS instance

.PARAMETER SecurityLevel
    Security level (Basic, Enhanced, Maximum)

.PARAMETER ComplianceStandard
    Compliance standard to implement (SOX, HIPAA, PCI-DSS, ISO27001)

.PARAMETER EnableAuditLogging
    Enable comprehensive audit logging

.PARAMETER EnableCredentialVault
    Enable credential vault functionality

.EXAMPLE
    .\Secure-ADLDS.ps1 -InstanceName "AppDirectory" -SecurityLevel "Enhanced" -ComplianceStandard "SOX" -EnableAuditLogging

.NOTES
    Author: AD LDS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$InstanceName,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Enhanced", "Maximum")]
    [string]$SecurityLevel = "Enhanced",

    [Parameter(Mandatory = $false)]
    [ValidateSet("SOX", "HIPAA", "PCI-DSS", "ISO27001")]
    [string]$ComplianceStandard = "SOX",

    [Parameter(Mandatory = $false)]
    [switch]$EnableAuditLogging,

    [Parameter(Mandatory = $false)]
    [switch]$EnableCredentialVault,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\ADLDS\Security"
)

# Script configuration
$scriptConfig = @{
    InstanceName = $InstanceName
    SecurityLevel = $SecurityLevel
    ComplianceStandard = $ComplianceStandard
    EnableAuditLogging = $EnableAuditLogging
    EnableCredentialVault = $EnableCredentialVault
    LogPath = $LogPath
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "AD LDS Security Hardening" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Instance: $InstanceName" -ForegroundColor Yellow
Write-Host "Security Level: $SecurityLevel" -ForegroundColor Yellow
Write-Host "Compliance Standard: $ComplianceStandard" -ForegroundColor Yellow
Write-Host "Audit Logging: $EnableAuditLogging" -ForegroundColor Yellow
Write-Host "Credential Vault: $EnableCredentialVault" -ForegroundColor Yellow
Write-Host "Computer: $($scriptConfig.ComputerName)" -ForegroundColor Yellow
Write-Host "Timestamp: $($scriptConfig.Timestamp)" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Import required modules
try {
    Import-Module "..\..\Modules\ADLDS-Core.psm1" -Force
    Import-Module "..\..\Modules\ADLDS-Security.psm1" -Force
    Write-Host "AD LDS modules imported successfully!" -ForegroundColor Green
} catch {
    Write-Error "Failed to import AD LDS modules: $($_.Exception.Message)"
    exit 1
}

# Create log directory
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force
}

# Step 1: Configure Authentication
Write-Host "`nStep 1: Configuring Authentication..." -ForegroundColor Green

$authType = switch ($SecurityLevel) {
    "Basic" { "Simple" }
    "Enhanced" { "Negotiate" }
    "Maximum" { "Kerberos" }
}

$authResult = Set-ADLDSAuthentication -InstanceName $InstanceName -AuthenticationType $authType -EnableSSL -RequireStrongAuthentication:($SecurityLevel -eq "Maximum")

if ($authResult.Success) {
    Write-Host "Authentication configured successfully!" -ForegroundColor Green
    Write-Host "  Authentication Type: $($authResult.AuthenticationType)" -ForegroundColor Cyan
    Write-Host "  SSL Enabled: $($authResult.SSLEnabled)" -ForegroundColor Cyan
} else {
    Write-Error "Failed to configure authentication: $($authResult.Error)"
}

# Step 2: Configure Access Control
Write-Host "`nStep 2: Configuring Access Control..." -ForegroundColor Green

# Configure access control based on security level
$accessControls = @()

switch ($SecurityLevel) {
    "Basic" {
        $accessControls = @(
            @{ ObjectDN = "CN=DefaultPartition,DC=AppDir,DC=local"; Principal = "CN=Administrators"; Permission = "Full Control" }
        )
    }
    "Enhanced" {
        $accessControls = @(
            @{ ObjectDN = "CN=DefaultPartition,DC=AppDir,DC=local"; Principal = "CN=Administrators"; Permission = "Full Control" },
            @{ ObjectDN = "CN=DefaultPartition,DC=AppDir,DC=local"; Principal = "CN=ServiceAccounts"; Permission = "Read" }
        )
    }
    "Maximum" {
        $accessControls = @(
            @{ ObjectDN = "CN=DefaultPartition,DC=AppDir,DC=local"; Principal = "CN=Administrators"; Permission = "Full Control" },
            @{ ObjectDN = "CN=DefaultPartition,DC=AppDir,DC=local"; Principal = "CN=ServiceAccounts"; Permission = "Read" },
            @{ ObjectDN = "CN=DefaultPartition,DC=AppDir,DC=local"; Principal = "CN=ApplicationUsers"; Permission = "Read" }
        )
    }
}

foreach ($accessControl in $accessControls) {
    $aclResult = Set-ADLDSAccessControl -InstanceName $InstanceName -ObjectDN $accessControl.ObjectDN -Principal $accessControl.Principal -Permission $accessControl.Permission
    
    if ($aclResult.Success) {
        Write-Host "Access control configured for $($accessControl.Principal)" -ForegroundColor Green
    } else {
        Write-Warning "Failed to configure access control for $($accessControl.Principal): $($aclResult.Error)"
    }
}

# Step 3: Enable Security Policies
Write-Host "`nStep 3: Enabling Security Policies..." -ForegroundColor Green

$securityPolicies = @{
    EnableAuditLogging = $EnableAuditLogging
    EnablePasswordPolicy = $true
    EnableAccountLockout = $SecurityLevel -ne "Basic"
    EnableSSLRequired = $SecurityLevel -eq "Maximum"
    EnableStrongAuthentication = $SecurityLevel -eq "Maximum"
}

$securityResult = Enable-ADLDSSecurityPolicies -InstanceName $InstanceName @securityPolicies

if ($securityResult.Success) {
    Write-Host "Security policies enabled successfully!" -ForegroundColor Green
    Write-Host "  Policies enabled: $($securityResult.PoliciesEnabled -join ', ')" -ForegroundColor Cyan
} else {
    Write-Error "Failed to enable security policies: $($securityResult.Error)"
}

# Step 4: Configure Credential Vault
if ($EnableCredentialVault) {
    Write-Host "`nStep 4: Configuring Credential Vault..." -ForegroundColor Green
    
    $vaultResult = Set-ADLDSCredentialVault -InstanceName $InstanceName -VaultName "SecureCredentials" -AccessGroups @("CN=Administrators", "CN=ServiceAccounts")
    
    if ($vaultResult.Success) {
        Write-Host "Credential vault configured successfully!" -ForegroundColor Green
    } else {
        Write-Warning "Failed to configure credential vault: $($vaultResult.Error)"
    }
}

# Step 5: Test Security Compliance
Write-Host "`nStep 5: Testing Security Compliance..." -ForegroundColor Green

$complianceResult = Test-ADLDSSecurityCompliance -InstanceName $InstanceName -ComplianceStandard $ComplianceStandard

if ($complianceResult.Success) {
    Write-Host "Security compliance test completed!" -ForegroundColor Green
    Write-Host "  Overall Compliance: $($complianceResult.ComplianceStatus.OverallCompliance)" -ForegroundColor Cyan
    
    if ($complianceResult.IssuesFound.Count -gt 0) {
        Write-Warning "Compliance issues found:"
        foreach ($issue in $complianceResult.IssuesFound) {
            Write-Warning "  - $issue"
        }
    }
    
    if ($complianceResult.Recommendations.Count -gt 0) {
        Write-Host "Recommendations:" -ForegroundColor Yellow
        foreach ($recommendation in $complianceResult.Recommendations) {
            Write-Host "  - $recommendation" -ForegroundColor Yellow
        }
    }
} else {
    Write-Error "Failed to test security compliance: $($complianceResult.Error)"
}

# Step 6: Get Security Status
Write-Host "`nStep 6: Getting Security Status..." -ForegroundColor Green

$securityStatus = Get-ADLDSSecurityStatus -InstanceName $InstanceName

if ($securityStatus.Success) {
    Write-Host "Security Status:" -ForegroundColor Green
    Write-Host "  Authentication Type: $($securityStatus.SecurityStatus.AuthenticationType)" -ForegroundColor Cyan
    Write-Host "  SSL Enabled: $($securityStatus.SecurityStatus.SSLEnabled)" -ForegroundColor Cyan
    Write-Host "  Audit Logging: $($securityStatus.SecurityStatus.AuditLoggingEnabled)" -ForegroundColor Cyan
    Write-Host "  Password Policy: $($securityStatus.SecurityStatus.PasswordPolicyEnabled)" -ForegroundColor Cyan
    Write-Host "  Account Lockout: $($securityStatus.SecurityStatus.AccountLockoutEnabled)" -ForegroundColor Cyan
    Write-Host "  Strong Authentication: $($securityStatus.SecurityStatus.StrongAuthenticationRequired)" -ForegroundColor Cyan
} else {
    Write-Warning "Could not get security status: $($securityStatus.Error)"
}

# Step 7: Generate Security Report
Write-Host "`nStep 7: Generating Security Report..." -ForegroundColor Green

$securityReport = @{
    InstanceName = $InstanceName
    SecurityLevel = $SecurityLevel
    ComplianceStandard = $ComplianceStandard
    Timestamp = Get-Date
    SecurityStatus = $securityStatus.SecurityStatus
    ComplianceStatus = $complianceResult.ComplianceStatus
    PoliciesEnabled = $securityResult.PoliciesEnabled
    Recommendations = $complianceResult.Recommendations
}

$reportFile = Join-Path $LogPath "ADLDS-Security-Report-$InstanceName-$(Get-Date -Format 'yyyy-MM-dd-HH-mm').json"
$securityReport | ConvertTo-Json -Depth 5 | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host "Security report generated: $reportFile" -ForegroundColor Green

# Final summary
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "AD LDS Security Hardening Summary" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Instance: $InstanceName" -ForegroundColor Yellow
Write-Host "Security Level: $SecurityLevel" -ForegroundColor Yellow
Write-Host "Compliance Standard: $ComplianceStandard" -ForegroundColor Yellow
Write-Host "Audit Logging: $EnableAuditLogging" -ForegroundColor Yellow
Write-Host "Credential Vault: $EnableCredentialVault" -ForegroundColor Yellow
Write-Host "Overall Compliance: $($complianceResult.ComplianceStatus.OverallCompliance)" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

if ($complianceResult.ComplianceStatus.OverallCompliance -eq "Compliant") {
    Write-Host "`n🎉 AD LDS security hardening completed successfully!" -ForegroundColor Green
    Write-Host "The AD LDS instance meets $ComplianceStandard compliance requirements." -ForegroundColor Green
} else {
    Write-Host "`n⚠️ AD LDS security hardening completed with warnings." -ForegroundColor Yellow
    Write-Host "Please review the recommendations above to achieve full compliance." -ForegroundColor Yellow
}

Write-Host "`nNext Steps:" -ForegroundColor Cyan
Write-Host "1. Review the security report" -ForegroundColor White
Write-Host "2. Implement any remaining recommendations" -ForegroundColor White
Write-Host "3. Schedule regular security audits" -ForegroundColor White
Write-Host "4. Monitor security events and logs" -ForegroundColor White
Write-Host "5. Update security policies as needed" -ForegroundColor White
Write-Host "6. Train administrators on security procedures" -ForegroundColor White
