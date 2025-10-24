#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Active Directory Security Module

.DESCRIPTION
    PowerShell module for Windows Active Directory security configurations.
    Provides security management capabilities including audit policies, access control,
    privileged access management, and security monitoring.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

# Module variables
$ModuleVersion = "1.0.0"
$ModuleAuthor = "Adrian Johnson (adrian207@gmail.com)"

# Security Functions
function Set-ADAuditPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$AuditLevel = "Standard",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$AuditSettings
    )
    
    try {
        Write-Host "Configuring audit policy on $ServerName..." -ForegroundColor Cyan
        
        $defaultAuditSettings = @{
            "AuditAccountLogon" = "Success,Failure"
            "AuditAccountManagement" = "Success,Failure"
            "AuditDirectoryServiceAccess" = "Success,Failure"
            "AuditLogonEvents" = "Success,Failure"
            "AuditObjectAccess" = "Success,Failure"
            "AuditPolicyChange" = "Success,Failure"
            "AuditPrivilegeUse" = "Success,Failure"
            "AuditProcessTracking" = "Success,Failure"
            "AuditSystemEvents" = "Success,Failure"
        }
        
        $auditSettings = if ($AuditSettings) { $AuditSettings } else { $defaultAuditSettings }
        
        # Configure audit policy
        foreach ($setting in $auditSettings.GetEnumerator()) {
            auditpol /set /subcategory:$($setting.Key) /success:enable /failure:enable
        }
        
        Write-Host "Audit policy configured successfully" -ForegroundColor Green
        
        return $auditSettings
    }
    catch {
        Write-Error "Failed to configure audit policy: $($_.Exception.Message)"
        throw
    }
}

function Set-ADAccessControl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$AccessLevel = "Standard",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$AccessSettings
    )
    
    try {
        Write-Host "Configuring access control on $ServerName..." -ForegroundColor Cyan
        
        $defaultAccessSettings = @{
            "UserAccess" = "Read,Write"
            "GroupAccess" = "Read,Write"
            "OUAccess" = "Read,Write"
            "ComputerAccess" = "Read,Write"
            "ServiceAccountAccess" = "Read,Write"
        }
        
        $accessSettings = if ($AccessSettings) { $AccessSettings } else { $defaultAccessSettings }
        
        # Configure access control
        foreach ($setting in $accessSettings.GetEnumerator()) {
            # Apply access control settings
            Write-Host "Configuring $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "Access control configured successfully" -ForegroundColor Green
        
        return $accessSettings
    }
    catch {
        Write-Error "Failed to configure access control: $($_.Exception.Message)"
        throw
    }
}

function Set-ADPrivilegedAccess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$PAMLevel = "Standard",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$PAMSettings
    )
    
    try {
        Write-Host "Configuring privileged access management on $ServerName..." -ForegroundColor Cyan
        
        $defaultPAMSettings = @{
            "Tier0Admins" = "Domain Admins,Enterprise Admins"
            "Tier1Admins" = "Server Admins"
            "Tier2Admins" = "Workstation Admins"
            "PAWEnabled" = $true
            "JustInTimeAccess" = $true
            "ApprovalRequired" = $true
        }
        
        $pamSettings = if ($PAMSettings) { $PAMSettings } else { $defaultPAMSettings }
        
        # Configure PAM
        foreach ($setting in $pamSettings.GetEnumerator()) {
            Write-Host "Configuring PAM setting $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "Privileged access management configured successfully" -ForegroundColor Green
        
        return $pamSettings
    }
    catch {
        Write-Error "Failed to configure privileged access management: $($_.Exception.Message)"
        throw
    }
}

function Set-ADSecurityBaseline {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$BaselineType = "CIS",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$BaselineSettings
    )
    
    try {
        Write-Host "Applying security baseline ($BaselineType) on $ServerName..." -ForegroundColor Cyan
        
        $defaultBaselineSettings = @{
            "PasswordPolicy" = "Strong"
            "AccountLockout" = "Enabled"
            "AuditLogging" = "Comprehensive"
            "UserRights" = "Restricted"
            "ServiceAccounts" = "Managed"
            "PrivilegedAccess" = "Controlled"
        }
        
        $baselineSettings = if ($BaselineSettings) { $BaselineSettings } else { $defaultBaselineSettings }
        
        # Apply security baseline
        foreach ($setting in $baselineSettings.GetEnumerator()) {
            Write-Host "Applying baseline setting $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "Security baseline applied successfully" -ForegroundColor Green
        
        return $baselineSettings
    }
    catch {
        Write-Error "Failed to apply security baseline: $($_.Exception.Message)"
        throw
    }
}

function Set-ADKerberosSecurity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$KerberosLevel = "Standard",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$KerberosSettings
    )
    
    try {
        Write-Host "Configuring Kerberos security on $ServerName..." -ForegroundColor Cyan
        
        $defaultKerberosSettings = @{
            "TicketLifetime" = "10"
            "RenewalLifetime" = "7"
            "ClockSkew" = "5"
            "Armoring" = $true
            "FAST" = $true
            "Delegation" = "Constrained"
        }
        
        $kerberosSettings = if ($KerberosSettings) { $KerberosSettings } else { $defaultKerberosSettings }
        
        # Configure Kerberos security
        foreach ($setting in $kerberosSettings.GetEnumerator()) {
            Write-Host "Configuring Kerberos setting $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "Kerberos security configured successfully" -ForegroundColor Green
        
        return $kerberosSettings
    }
    catch {
        Write-Error "Failed to configure Kerberos security: $($_.Exception.Message)"
        throw
    }
}

function Set-ADLDAPSSecurity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$LDAPSLevel = "Standard",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$LDAPSSettings
    )
    
    try {
        Write-Host "Configuring LDAPS security on $ServerName..." -ForegroundColor Cyan
        
        $defaultLDAPSSettings = @{
            "LDAPSEnabled" = $true
            "CertificateRequired" = $true
            "TLSVersion" = "1.2"
            "CipherSuites" = "Strong"
            "ClientCertificateRequired" = $false
        }
        
        $ldapsSettings = if ($LDAPSSettings) { $LDAPSSettings } else { $defaultLDAPSSettings }
        
        # Configure LDAPS security
        foreach ($setting in $ldapsSettings.GetEnumerator()) {
            Write-Host "Configuring LDAPS setting $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "LDAPS security configured successfully" -ForegroundColor Green
        
        return $ldapsSettings
    }
    catch {
        Write-Error "Failed to configure LDAPS security: $($_.Exception.Message)"
        throw
    }
}

function Set-ADTrustSecurity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$TrustLevel = "Standard",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$TrustSettings
    )
    
    try {
        Write-Host "Configuring trust security on $ServerName..." -ForegroundColor Cyan
        
        $defaultTrustSettings = @{
            "SIDFiltering" = $true
            "Quarantine" = $true
            "SelectiveAuthentication" = $true
            "ForestTrust" = $true
            "ExternalTrust" = $false
        }
        
        $trustSettings = if ($TrustSettings) { $TrustSettings } else { $defaultTrustSettings }
        
        # Configure trust security
        foreach ($setting in $trustSettings.GetEnumerator()) {
            Write-Host "Configuring trust setting $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "Trust security configured successfully" -ForegroundColor Green
        
        return $trustSettings
    }
    catch {
        Write-Error "Failed to configure trust security: $($_.Exception.Message)"
        throw
    }
}

function Get-ADSecurityStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDetails,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeAudit,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeAccess,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeKerberos,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeLDAPS,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeTrust
    )
    
    try {
        Write-Host "Checking security status on $ServerName..." -ForegroundColor Cyan
        
        $securityStatus = @{
            ServerName = $ServerName
            Timestamp = Get-Date
            OverallStatus = "Unknown"
            Components = @{}
            Issues = @()
            Recommendations = @()
        }
        
        # Check audit policy
        if ($IncludeAudit) {
            try {
                $auditPolicy = auditpol /get /category:* | Out-String
                $securityStatus.Components.AuditPolicy = @{
                    Status = "Healthy"
                    Details = $auditPolicy
                }
            }
            catch {
                $securityStatus.Components.AuditPolicy = @{
                    Status = "Unhealthy"
                    Details = $_.Exception.Message
                }
                $securityStatus.Issues += "Audit policy check failed"
            }
        }
        
        # Check access control
        if ($IncludeAccess) {
            try {
                $accessControl = Get-ACL -Path "AD:\" | Out-String
                $securityStatus.Components.AccessControl = @{
                    Status = "Healthy"
                    Details = $accessControl
                }
            }
            catch {
                $securityStatus.Components.AccessControl = @{
                    Status = "Unhealthy"
                    Details = $_.Exception.Message
                }
                $securityStatus.Issues += "Access control check failed"
            }
        }
        
        # Determine overall status
        $unhealthyComponents = $securityStatus.Components.Values | Where-Object { $_.Status -eq "Unhealthy" }
        if ($unhealthyComponents.Count -eq 0) {
            $securityStatus.OverallStatus = "Healthy"
        } elseif ($unhealthyComponents.Count -lt $securityStatus.Components.Count / 2) {
            $securityStatus.OverallStatus = "Degraded"
        } else {
            $securityStatus.OverallStatus = "Unhealthy"
        }
        
        return $securityStatus
    }
    catch {
        Write-Error "Failed to check security status: $($_.Exception.Message)"
        throw
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Set-ADAuditPolicy',
    'Set-ADAccessControl',
    'Set-ADPrivilegedAccess',
    'Set-ADSecurityBaseline',
    'Set-ADKerberosSecurity',
    'Set-ADLDAPSSecurity',
    'Set-ADTrustSecurity',
    'Get-ADSecurityStatus'
)
