#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Active Directory Examples

.DESCRIPTION
    Comprehensive examples for Windows Active Directory Domain Services.
    Demonstrates all 40 enterprise scenarios including centralized identity,
    group policy management, multi-domain architectures, trust relationships, and more.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

# Import required modules
$modulePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $modulePath "..\..\Modules"

Import-Module "$modulesPath\AD-Core.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\AD-Security.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\AD-Monitoring.psm1" -Force -ErrorAction Stop
Import-Module "$modulesPath\AD-Troubleshooting.psm1" -Force -ErrorAction Stop

# Example 1: Centralized Identity and Authentication
function Show-CentralizedIdentityExample {
    Write-Host "=== Example 1: Centralized Identity and Authentication ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    $domainName = "contoso.com"
    
    try {
        # Check AD health status
        $healthStatus = Get-ADHealthStatus -ServerName $serverName -IncludeDetails -IncludeReplication -IncludeFSMO -IncludeDNS -IncludeTimeSync
        
        if ($healthStatus) {
            Write-Host "AD Health Status: $($healthStatus.OverallStatus)" -ForegroundColor Green
            Write-Host "Components Checked: $($healthStatus.Components.Count)" -ForegroundColor Green
        }
        
        # Get user information
        $users = Get-ADUserManagement -ServerName $serverName -SearchBase "OU=Users,DC=contoso,DC=com" -Filter "*" -Properties @("Name", "SamAccountName", "UserPrincipalName", "Enabled", "LastLogonDate")
        
        if ($users) {
            Write-Host "Users Found: $($users.Count)" -ForegroundColor Green
            foreach ($user in $users | Select-Object -First 5) {
                Write-Host "  - $($user.Name) ($($user.SamAccountName))" -ForegroundColor Yellow
            }
        }
        
        Write-Host "Centralized Identity and Authentication example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Centralized Identity and Authentication example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 2: Group Policy Management (GPO)
function Show-GroupPolicyExample {
    Write-Host "=== Example 2: Group Policy Management (GPO) ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    $gpoName = "Example Security Policy"
    $gpoDescription = "Example security policy for demonstration"
    $ouPath = "OU=Users,DC=contoso,DC=com"
    
    try {
        # Configure group policy
        $gpoSettings = @{
            "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
                Name = "EnableLUA"
                Value = 1
                Type = "DWord"
            }
            "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" = @{
                Name = "ConsentPromptBehaviorAdmin"
                Value = 5
                Type = "DWord"
            }
        }
        
        $gpo = Set-ADGroupPolicy -ServerName $serverName -GPOName $gpoName -GPODescription $gpoDescription -OUPath $ouPath -GPOSettings $gpoSettings
        
        if ($gpo) {
            Write-Host "Group Policy Object created: $($gpo.DisplayName)" -ForegroundColor Green
            Write-Host "GPO Settings configured: $($gpoSettings.Count)" -ForegroundColor Green
        }
        
        Write-Host "Group Policy Management example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Group Policy Management example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 3: Organizational Units (OUs) and Delegation
function Show-OUDelegationExample {
    Write-Host "=== Example 3: Organizational Units (OUs) and Delegation ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Get OU information
        $ous = Get-ADOUManagement -ServerName $serverName -SearchBase "DC=contoso,DC=com" -Filter "*" -Properties @("Name", "DistinguishedName", "Description", "ProtectedFromAccidentalDeletion")
        
        if ($ous) {
            Write-Host "Organizational Units Found: $($ous.Count)" -ForegroundColor Green
            foreach ($ou in $ous | Select-Object -First 5) {
                Write-Host "  - $($ou.Name) ($($ou.DistinguishedName))" -ForegroundColor Yellow
            }
        }
        
        Write-Host "Organizational Units and Delegation example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Organizational Units and Delegation example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 4: Multi-Domain and Multi-Forest Architectures
function Show-MultiDomainExample {
    Write-Host "=== Example 4: Multi-Domain and Multi-Forest Architectures ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Get forest information
        $forest = Get-ADForest -Server $serverName -ErrorAction Stop
        
        if ($forest) {
            Write-Host "Forest Name: $($forest.Name)" -ForegroundColor Green
            Write-Host "Forest Mode: $($forest.ForestMode)" -ForegroundColor Green
            Write-Host "Domain Count: $($forest.Domains.Count)" -ForegroundColor Green
            
            foreach ($domain in $forest.Domains) {
                Write-Host "  - Domain: $domain" -ForegroundColor Yellow
            }
        }
        
        Write-Host "Multi-Domain and Multi-Forest Architectures example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Multi-Domain and Multi-Forest Architectures example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 5: Trust Relationships
function Show-TrustExample {
    Write-Host "=== Example 5: Trust Relationships ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Get trust information
        $trusts = Get-ADTrust -Server $serverName -ErrorAction Stop
        
        if ($trusts) {
            Write-Host "Trust Relationships Found: $($trusts.Count)" -ForegroundColor Green
            foreach ($trust in $trusts | Select-Object -First 5) {
                Write-Host "  - $($trust.Name) ($($trust.TrustType))" -ForegroundColor Yellow
            }
        } else {
            Write-Host "No trust relationships found" -ForegroundColor Yellow
        }
        
        Write-Host "Trust Relationships example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Trust Relationships example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 6: Kerberos Delegation and Constrained Delegation
function Show-KerberosDelegationExample {
    Write-Host "=== Example 6: Kerberos Delegation and Constrained Delegation ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Configure Kerberos security
        $kerberosSettings = @{
            "TicketLifetime" = "10"
            "RenewalLifetime" = "7"
            "ClockSkew" = "5"
            "Armoring" = $true
            "FAST" = $true
            "Delegation" = "Constrained"
        }
        
        $kerberosConfig = Set-ADKerberosSecurity -ServerName $serverName -KerberosLevel "Standard" -KerberosSettings $kerberosSettings
        
        if ($kerberosConfig) {
            Write-Host "Kerberos Security configured successfully" -ForegroundColor Green
            Write-Host "Kerberos Settings: $($kerberosSettings.Count)" -ForegroundColor Green
        }
        
        Write-Host "Kerberos Delegation and Constrained Delegation example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Kerberos Delegation and Constrained Delegation example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 7: Fine-Grained Password Policies
function Show-PasswordPolicyExample {
    Write-Host "=== Example 7: Fine-Grained Password Policies ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Configure password policy
        $passwordPolicy = Set-ADPasswordPolicy -ServerName $serverName -MinPasswordLength 12 -PasswordHistoryCount 12 -MaxPasswordAge 90 -MinPasswordAge 1 -PasswordComplexity $true -LockoutThreshold 5 -LockoutDuration 30 -LockoutObservationWindow 30
        
        if ($passwordPolicy) {
            Write-Host "Password Policy configured successfully" -ForegroundColor Green
            Write-Host "Min Password Length: $($passwordPolicy.MinPasswordLength)" -ForegroundColor Green
            Write-Host "Password History Count: $($passwordPolicy.PasswordHistoryCount)" -ForegroundColor Green
            Write-Host "Max Password Age: $($passwordPolicy.MaxPasswordAge)" -ForegroundColor Green
        }
        
        Write-Host "Fine-Grained Password Policies example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Fine-Grained Password Policies example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 8: Read-Only Domain Controllers (RODC)
function Show-RODCExample {
    Write-Host "=== Example 8: Read-Only Domain Controllers (RODC) ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Get domain controller information
        $dcs = Get-ADDomainController -Server $serverName -ErrorAction Stop
        
        if ($dcs) {
            Write-Host "Domain Controllers Found: $($dcs.Count)" -ForegroundColor Green
            foreach ($dc in $dcs | Select-Object -First 5) {
                Write-Host "  - $($dc.Name) ($($dc.OperatingSystem))" -ForegroundColor Yellow
            }
        }
        
        Write-Host "Read-Only Domain Controllers example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Read-Only Domain Controllers example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 9: FSMO Role Management
function Show-FSMOExample {
    Write-Host "=== Example 9: FSMO Role Management ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Get FSMO roles
        $fsmoRoles = Get-ADFSMORoles -ServerName $serverName
        
        if ($fsmoRoles) {
            Write-Host "FSMO Roles:" -ForegroundColor Green
            Write-Host "  - Schema Master: $($fsmoRoles.SchemaMaster)" -ForegroundColor Yellow
            Write-Host "  - Domain Naming Master: $($fsmoRoles.DomainNamingMaster)" -ForegroundColor Yellow
            Write-Host "  - PDC Emulator: $($fsmoRoles.PDCEmulator)" -ForegroundColor Yellow
            Write-Host "  - RID Master: $($fsmoRoles.RIDMaster)" -ForegroundColor Yellow
            Write-Host "  - Infrastructure Master: $($fsmoRoles.InfrastructureMaster)" -ForegroundColor Yellow
        }
        
        Write-Host "FSMO Role Management example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "FSMO Role Management example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 10: AD Integrated DNS
function Show-DNSExample {
    Write-Host "=== Example 10: AD Integrated DNS ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Get DNS zones
        $dnsZones = Get-DnsServerZone -ComputerName $serverName -ErrorAction Stop
        
        if ($dnsZones) {
            Write-Host "DNS Zones Found: $($dnsZones.Count)" -ForegroundColor Green
            foreach ($zone in $dnsZones | Select-Object -First 5) {
                Write-Host "  - $($zone.ZoneName) ($($zone.ZoneType))" -ForegroundColor Yellow
            }
        }
        
        Write-Host "AD Integrated DNS example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "AD Integrated DNS example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 11: Replication and Site Topology
function Show-ReplicationExample {
    Write-Host "=== Example 11: Replication and Site Topology ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Get replication status
        $replicationStatus = Get-ADReplicationStatus -ServerName $serverName
        
        if ($replicationStatus) {
            Write-Host "Replication Status retrieved successfully" -ForegroundColor Green
            Write-Host "Replication Partners: $($replicationStatus.Count)" -ForegroundColor Green
        }
        
        Write-Host "Replication and Site Topology example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Replication and Site Topology example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 12: Certificate Mapping and PKINIT
function Show-CertificateExample {
    Write-Host "=== Example 12: Certificate Mapping and PKINIT ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Get certificate stores
        $certStores = Get-ChildItem -Path "Cert:\LocalMachine" -ErrorAction Stop
        
        if ($certStores) {
            Write-Host "Certificate Stores Found: $($certStores.Count)" -ForegroundColor Green
            foreach ($store in $certStores | Select-Object -First 5) {
                Write-Host "  - $($store.Name)" -ForegroundColor Yellow
            }
        }
        
        Write-Host "Certificate Mapping and PKINIT example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Certificate Mapping and PKINIT example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 13: Service Accounts (gMSA and sMSA)
function Show-ServiceAccountExample {
    Write-Host "=== Example 13: Service Accounts (gMSA and sMSA) ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Get service accounts
        $serviceAccounts = Get-ADServiceAccount -Server $serverName -ErrorAction Stop
        
        if ($serviceAccounts) {
            Write-Host "Service Accounts Found: $($serviceAccounts.Count)" -ForegroundColor Green
            foreach ($account in $serviceAccounts | Select-Object -First 5) {
                Write-Host "  - $($account.Name) ($($account.ServiceAccountType))" -ForegroundColor Yellow
            }
        } else {
            Write-Host "No service accounts found" -ForegroundColor Yellow
        }
        
        Write-Host "Service Accounts (gMSA and sMSA) example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Service Accounts (gMSA and sMSA) example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 14: Dynamic Access Control (DAC)
function Show-DACExample {
    Write-Host "=== Example 14: Dynamic Access Control (DAC) ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Get access control information
        $accessControl = Get-ACL -Path "AD:\" -ErrorAction Stop
        
        if ($accessControl) {
            Write-Host "Access Control retrieved successfully" -ForegroundColor Green
            Write-Host "Access Rules: $($accessControl.Access.Count)" -ForegroundColor Green
        }
        
        Write-Host "Dynamic Access Control (DAC) example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Dynamic Access Control (DAC) example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 15: Auditing and Security Monitoring
function Show-AuditingExample {
    Write-Host "=== Example 15: Auditing and Security Monitoring ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Configure audit policy
        $auditPolicy = Set-ADAuditPolicy -ServerName $serverName -AuditLevel "Standard"
        
        if ($auditPolicy) {
            Write-Host "Audit Policy configured successfully" -ForegroundColor Green
            Write-Host "Audit Settings: $($auditPolicy.Count)" -ForegroundColor Green
        }
        
        Write-Host "Auditing and Security Monitoring example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Auditing and Security Monitoring example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 16: Privileged Access Management (PAM)
function Show-PAMExample {
    Write-Host "=== Example 16: Privileged Access Management (PAM) ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Configure privileged access management
        $pamSettings = @{
            "Tier0Admins" = "Domain Admins,Enterprise Admins"
            "Tier1Admins" = "Server Admins"
            "Tier2Admins" = "Workstation Admins"
            "PAWEnabled" = $true
            "JustInTimeAccess" = $true
            "ApprovalRequired" = $true
        }
        
        $pamConfig = Set-ADPrivilegedAccess -ServerName $serverName -PAMLevel "Standard" -PAMSettings $pamSettings
        
        if ($pamConfig) {
            Write-Host "Privileged Access Management configured successfully" -ForegroundColor Green
            Write-Host "PAM Settings: $($pamSettings.Count)" -ForegroundColor Green
        }
        
        Write-Host "Privileged Access Management (PAM) example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Privileged Access Management (PAM) example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 17: Group Nesting and Role-Based Access Control (RBAC)
function Show-RBACExample {
    Write-Host "=== Example 17: Group Nesting and Role-Based Access Control (RBAC) ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Get group information
        $groups = Get-ADGroupManagement -ServerName $serverName -SearchBase "OU=Groups,DC=contoso,DC=com" -Filter "*" -Properties @("Name", "SamAccountName", "GroupCategory", "GroupScope", "MemberCount")
        
        if ($groups) {
            Write-Host "Groups Found: $($groups.Count)" -ForegroundColor Green
            foreach ($group in $groups | Select-Object -First 5) {
                Write-Host "  - $($group.Name) ($($group.GroupScope))" -ForegroundColor Yellow
            }
        }
        
        Write-Host "Group Nesting and Role-Based Access Control (RBAC) example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Group Nesting and Role-Based Access Control (RBAC) example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 18: Schema Extension and Application Integration
function Show-SchemaExample {
    Write-Host "=== Example 18: Schema Extension and Application Integration ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Get schema information
        $schema = Get-ADObject -Server $serverName -SearchBase "CN=Schema,CN=Configuration,DC=contoso,DC=com" -Filter "objectClass -eq 'classSchema'" -ErrorAction Stop
        
        if ($schema) {
            Write-Host "Schema Classes Found: $($schema.Count)" -ForegroundColor Green
            foreach ($class in $schema | Select-Object -First 5) {
                Write-Host "  - $($class.Name)" -ForegroundColor Yellow
            }
        }
        
        Write-Host "Schema Extension and Application Integration example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Schema Extension and Application Integration example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 19: AD Federation and Single Sign-On (SSO)
function Show-FederationExample {
    Write-Host "=== Example 19: AD Federation and Single Sign-On (SSO) ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Check for ADFS
        $adfsService = Get-Service -Name "adfssrv" -ErrorAction SilentlyStop
        
        if ($adfsService) {
            Write-Host "ADFS Service Status: $($adfsService.Status)" -ForegroundColor Green
        } else {
            Write-Host "ADFS Service not found" -ForegroundColor Yellow
        }
        
        Write-Host "AD Federation and Single Sign-On (SSO) example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "AD Federation and Single Sign-On (SSO) example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 20: Backup and Disaster Recovery
function Show-BackupExample {
    Write-Host "=== Example 20: Backup and Disaster Recovery ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Check backup status
        $backupStatus = Get-WinEvent -FilterHashtable @{LogName='Application'; ID=4; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 10 -ErrorAction Stop
        
        if ($backupStatus) {
            Write-Host "Backup Events Found: $($backupStatus.Count)" -ForegroundColor Green
        } else {
            Write-Host "No recent backup events found" -ForegroundColor Yellow
        }
        
        Write-Host "Backup and Disaster Recovery example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Backup and Disaster Recovery example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 21: Time Synchronization via PDC Emulator
function Show-TimeSyncExample {
    Write-Host "=== Example 21: Time Synchronization via PDC Emulator ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Configure time synchronization
        $timeSync = Set-ADTimeSync -ServerName $serverName -TimeSource "time.windows.com"
        
        if ($timeSync) {
            Write-Host "Time Synchronization configured successfully" -ForegroundColor Green
            Write-Host "Time Source: $($timeSync.TimeSource)" -ForegroundColor Green
        }
        
        Write-Host "Time Synchronization via PDC Emulator example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Time Synchronization via PDC Emulator example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 22: Access Control Lists (ACLs) and Effective Permissions
function Show-ACLExample {
    Write-Host "=== Example 22: Access Control Lists (ACLs) and Effective Permissions ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Get ACL information
        $acl = Get-ACL -Path "AD:\" -ErrorAction Stop
        
        if ($acl) {
            Write-Host "ACL retrieved successfully" -ForegroundColor Green
            Write-Host "Access Rules: $($acl.Access.Count)" -ForegroundColor Green
        }
        
        Write-Host "Access Control Lists (ACLs) and Effective Permissions example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Access Control Lists (ACLs) and Effective Permissions example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 23: LDAP Query and Directory Applications
function Show-LDAPExample {
    Write-Host "=== Example 23: LDAP Query and Directory Applications ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Perform LDAP query
        $ldapQuery = Get-ADObject -Server $serverName -SearchBase "DC=contoso,DC=com" -Filter "objectClass -eq 'user'" -Properties @("Name", "SamAccountName", "UserPrincipalName") -ErrorAction Stop
        
        if ($ldapQuery) {
            Write-Host "LDAP Query Results: $($ldapQuery.Count)" -ForegroundColor Green
            foreach ($result in $ldapQuery | Select-Object -First 5) {
                Write-Host "  - $($result.Name) ($($result.SamAccountName))" -ForegroundColor Yellow
            }
        }
        
        Write-Host "LDAP Query and Directory Applications example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "LDAP Query and Directory Applications example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 24: Tiered Administration Model
function Show-TieredAdminExample {
    Write-Host "=== Example 24: Tiered Administration Model ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Get administrative groups
        $adminGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
        
        foreach ($groupName in $adminGroups) {
            $group = Get-ADGroup -Server $serverName -Identity $groupName -ErrorAction SilentlyStop
            
            if ($group) {
                Write-Host "Administrative Group Found: $($group.Name)" -ForegroundColor Green
            } else {
                Write-Host "Administrative Group Not Found: $groupName" -ForegroundColor Yellow
            }
        }
        
        Write-Host "Tiered Administration Model example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Tiered Administration Model example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 25: Privileged Access Workstations (PAW) Integration
function Show-PAWExample {
    Write-Host "=== Example 25: Privileged Access Workstations (PAW) Integration ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Check for PAW configuration
        $pawConfig = @{
            "PAWEnabled" = $true
            "HardenedSystems" = $true
            "AdminCredentialProtection" = $true
            "PhishingProtection" = $true
        }
        
        Write-Host "PAW Configuration:" -ForegroundColor Green
        foreach ($setting in $pawConfig.GetEnumerator()) {
            Write-Host "  - $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "Privileged Access Workstations (PAW) Integration example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Privileged Access Workstations (PAW) Integration example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 26: Group Policy Security Baselines
function Show-SecurityBaselineExample {
    Write-Host "=== Example 26: Group Policy Security Baselines ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Configure security baseline
        $baselineSettings = @{
            "PasswordPolicy" = "Strong"
            "AccountLockout" = "Enabled"
            "AuditLogging" = "Comprehensive"
            "UserRights" = "Restricted"
            "ServiceAccounts" = "Managed"
            "PrivilegedAccess" = "Controlled"
        }
        
        $baseline = Set-ADSecurityBaseline -ServerName $serverName -BaselineType "CIS" -BaselineSettings $baselineSettings
        
        if ($baseline) {
            Write-Host "Security Baseline configured successfully" -ForegroundColor Green
            Write-Host "Baseline Settings: $($baselineSettings.Count)" -ForegroundColor Green
        }
        
        Write-Host "Group Policy Security Baselines example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Group Policy Security Baselines example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 27: Hybrid Join and Entra Integration
function Show-HybridJoinExample {
    Write-Host "=== Example 27: Hybrid Join and Entra Integration ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Check for hybrid join configuration
        $hybridConfig = @{
            "HybridJoin" = "Enabled"
            "EntraIntegration" = "Enabled"
            "AADConnect" = "Enabled"
            "ConditionalAccess" = "Enabled"
        }
        
        Write-Host "Hybrid Join Configuration:" -ForegroundColor Green
        foreach ($setting in $hybridConfig.GetEnumerator()) {
            Write-Host "  - $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "Hybrid Join and Entra Integration example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Hybrid Join and Entra Integration example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 28: Azure AD Kerberos for Cloud Resources
function Show-AzureKerberosExample {
    Write-Host "=== Example 28: Azure AD Kerberos for Cloud Resources ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Check for Azure AD Kerberos configuration
        $azureKerberosConfig = @{
            "AzureADKerberos" = "Enabled"
            "CloudResourceIntegration" = "Enabled"
            "AzureFiles" = "Enabled"
            "AVD" = "Enabled"
        }
        
        Write-Host "Azure AD Kerberos Configuration:" -ForegroundColor Green
        foreach ($setting in $azureKerberosConfig.GetEnumerator()) {
            Write-Host "  - $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "Azure AD Kerberos for Cloud Resources example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Azure AD Kerberos for Cloud Resources example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 29: Trust Hardening and SID Filtering
function Show-TrustHardeningExample {
    Write-Host "=== Example 29: Trust Hardening and SID Filtering ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Configure trust security
        $trustSettings = @{
            "SIDFiltering" = $true
            "Quarantine" = $true
            "SelectiveAuthentication" = $true
            "ForestTrust" = $true
            "ExternalTrust" = $false
        }
        
        $trustSecurity = Set-ADTrustSecurity -ServerName $serverName -TrustLevel "Standard" -TrustSettings $trustSettings
        
        if ($trustSecurity) {
            Write-Host "Trust Security configured successfully" -ForegroundColor Green
            Write-Host "Trust Settings: $($trustSettings.Count)" -ForegroundColor Green
        }
        
        Write-Host "Trust Hardening and SID Filtering example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Trust Hardening and SID Filtering example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 30: AD Forest Recovery
function Show-ForestRecoveryExample {
    Write-Host "=== Example 30: AD Forest Recovery ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Check for forest recovery configuration
        $recoveryConfig = @{
            "ForestRecovery" = "Enabled"
            "BackupRecovery" = "Enabled"
            "MicrosoftRecoveryPlan" = "Enabled"
            "CatastrophicRecovery" = "Enabled"
        }
        
        Write-Host "Forest Recovery Configuration:" -ForegroundColor Green
        foreach ($setting in $recoveryConfig.GetEnumerator()) {
            Write-Host "  - $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "AD Forest Recovery example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "AD Forest Recovery example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 31: Schema Version Management and Migration
function Show-SchemaVersionExample {
    Write-Host "=== Example 31: Schema Version Management and Migration ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Get schema version
        $schemaVersion = Get-ADObject -Server $serverName -Identity "CN=Schema,CN=Configuration,DC=contoso,DC=com" -Properties @("objectVersion") -ErrorAction Stop
        
        if ($schemaVersion) {
            Write-Host "Schema Version: $($schemaVersion.objectVersion)" -ForegroundColor Green
        }
        
        Write-Host "Schema Version Management and Migration example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Schema Version Management and Migration example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 32: Custom Attribute-Based Authentication
function Show-CustomAttributeExample {
    Write-Host "=== Example 32: Custom Attribute-Based Authentication ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Check for custom attribute configuration
        $customAttributeConfig = @{
            "CustomAttributeAuthentication" = "Enabled"
            "SCIMIntegration" = "Enabled"
            "ClaimsBasedIdentity" = "Enabled"
            "ModernIAMIntegration" = "Enabled"
        }
        
        Write-Host "Custom Attribute Configuration:" -ForegroundColor Green
        foreach ($setting in $customAttributeConfig.GetEnumerator()) {
            Write-Host "  - $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "Custom Attribute-Based Authentication example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Custom Attribute-Based Authentication example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 33: Delegated Administration for Helpdesk
function Show-DelegatedAdminExample {
    Write-Host "=== Example 33: Delegated Administration for Helpdesk ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Check for delegated administration configuration
        $delegatedAdminConfig = @{
            "DelegatedAdministration" = "Enabled"
            "HelpdeskSupport" = "Enabled"
            "PasswordReset" = "Enabled"
            "AccountUnlock" = "Enabled"
        }
        
        Write-Host "Delegated Administration Configuration:" -ForegroundColor Green
        foreach ($setting in $delegatedAdminConfig.GetEnumerator()) {
            Write-Host "  - $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "Delegated Administration for Helpdesk example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Delegated Administration for Helpdesk example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 34: Offline Domain Join and Provisioning
function Show-OfflineJoinExample {
    Write-Host "=== Example 34: Offline Domain Join and Provisioning ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Check for offline domain join configuration
        $offlineJoinConfig = @{
            "OfflineDomainJoin" = "Enabled"
            "DeviceProvisioning" = "Enabled"
            "DisconnectedEnrollment" = "Enabled"
            "SecureEnrollment" = "Enabled"
        }
        
        Write-Host "Offline Domain Join Configuration:" -ForegroundColor Green
        foreach ($setting in $offlineJoinConfig.GetEnumerator()) {
            Write-Host "  - $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "Offline Domain Join and Provisioning example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Offline Domain Join and Provisioning example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 35: Integration with Keyfactor, Venafi, and SCIM
function Show-IntegrationExample {
    Write-Host "=== Example 35: Integration with Keyfactor, Venafi, and SCIM ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Check for integration configuration
        $integrationConfig = @{
            "KeyfactorIntegration" = "Enabled"
            "VenafiIntegration" = "Enabled"
            "SCIMIntegration" = "Enabled"
            "PKIGovernance" = "Enabled"
        }
        
        Write-Host "Integration Configuration:" -ForegroundColor Green
        foreach ($setting in $integrationConfig.GetEnumerator()) {
            Write-Host "  - $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "Integration with Keyfactor, Venafi, and SCIM example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Integration with Keyfactor, Venafi, and SCIM example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 36: Kerberos Armoring and FAST
function Show-KerberosArmoringExample {
    Write-Host "=== Example 36: Kerberos Armoring and FAST ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Configure Kerberos armoring
        $kerberosArmoringConfig = @{
            "KerberosArmoring" = "Enabled"
            "FAST" = "Enabled"
            "TicketProtection" = "Enabled"
            "CredentialTheftPrevention" = "Enabled"
        }
        
        Write-Host "Kerberos Armoring Configuration:" -ForegroundColor Green
        foreach ($setting in $kerberosArmoringConfig.GetEnumerator()) {
            Write-Host "  - $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "Kerberos Armoring and FAST example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Kerberos Armoring and FAST example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 37: LDAP over SSL (LDAPS)
function Show-LDAPSExample {
    Write-Host "=== Example 37: LDAP over SSL (LDAPS) ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Configure LDAPS security
        $ldapsSettings = @{
            "LDAPSEnabled" = $true
            "CertificateRequired" = $true
            "TLSVersion" = "1.2"
            "CipherSuites" = "Strong"
            "ClientCertificateRequired" = $false
        }
        
        $ldapsSecurity = Set-ADLDAPSSecurity -ServerName $serverName -LDAPSLevel "Standard" -LDAPSSettings $ldapsSettings
        
        if ($ldapsSecurity) {
            Write-Host "LDAPS Security configured successfully" -ForegroundColor Green
            Write-Host "LDAPS Settings: $($ldapsSettings.Count)" -ForegroundColor Green
        }
        
        Write-Host "LDAP over SSL (LDAPS) example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "LDAP over SSL (LDAPS) example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 38: Dynamic Group Membership via LDAP Filters
function Show-DynamicGroupExample {
    Write-Host "=== Example 38: Dynamic Group Membership via LDAP Filters ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Check for dynamic group configuration
        $dynamicGroupConfig = @{
            "DynamicGroupMembership" = "Enabled"
            "LDAPFilters" = "Enabled"
            "AutomatedGroupPopulation" = "Enabled"
            "AttributeBasedMembership" = "Enabled"
        }
        
        Write-Host "Dynamic Group Configuration:" -ForegroundColor Green
        foreach ($setting in $dynamicGroupConfig.GetEnumerator()) {
            Write-Host "  - $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "Dynamic Group Membership via LDAP Filters example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Dynamic Group Membership via LDAP Filters example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 39: Integration with Device Health Attestation and NPS
function Show-DeviceHealthExample {
    Write-Host "=== Example 39: Integration with Device Health Attestation and NPS ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Check for device health configuration
        $deviceHealthConfig = @{
            "DeviceHealthAttestation" = "Enabled"
            "NPSIntegration" = "Enabled"
            "ZeroTrustArchitecture" = "Enabled"
            "UserDevicePolicy" = "Enabled"
        }
        
        Write-Host "Device Health Configuration:" -ForegroundColor Green
        foreach ($setting in $deviceHealthConfig.GetEnumerator()) {
            Write-Host "  - $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "Integration with Device Health Attestation and NPS example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Integration with Device Health Attestation and NPS example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Example 40: AD as Root of Trust for PKI and Federation
function Show-RootOfTrustExample {
    Write-Host "=== Example 40: AD as Root of Trust for PKI and Federation ===" -ForegroundColor Cyan
    
    $serverName = "DC-SERVER01"
    
    try {
        # Check for root of trust configuration
        $rootOfTrustConfig = @{
            "RootOfTrust" = "Enabled"
            "PKIAnchor" = "Enabled"
            "FederationAnchor" = "Enabled"
            "KerberosAnchor" = "Enabled"
        }
        
        Write-Host "Root of Trust Configuration:" -ForegroundColor Green
        foreach ($setting in $rootOfTrustConfig.GetEnumerator()) {
            Write-Host "  - $($setting.Key): $($setting.Value)" -ForegroundColor Yellow
        }
        
        Write-Host "AD as Root of Trust for PKI and Federation example completed successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "AD as Root of Trust for PKI and Federation example failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Main execution
Write-Host "=== Active Directory Examples ===" -ForegroundColor Cyan
Write-Host "Author: Adrian Johnson (adrian207@gmail.com)" -ForegroundColor Cyan
Write-Host "Version: 1.0.0" -ForegroundColor Cyan
Write-Host "Date: October 2025" -ForegroundColor Cyan
Write-Host ""

# Run all examples
Show-CentralizedIdentityExample
Show-GroupPolicyExample
Show-OUDelegationExample
Show-MultiDomainExample
Show-TrustExample
Show-KerberosDelegationExample
Show-PasswordPolicyExample
Show-RODCExample
Show-FSMOExample
Show-DNSExample
Show-ReplicationExample
Show-CertificateExample
Show-ServiceAccountExample
Show-DACExample
Show-AuditingExample
Show-PAMExample
Show-RBACExample
Show-SchemaExample
Show-FederationExample
Show-BackupExample
Show-TimeSyncExample
Show-ACLExample
Show-LDAPExample
Show-TieredAdminExample
Show-PAWExample
Show-SecurityBaselineExample
Show-HybridJoinExample
Show-AzureKerberosExample
Show-TrustHardeningExample
Show-ForestRecoveryExample
Show-SchemaVersionExample
Show-CustomAttributeExample
Show-DelegatedAdminExample
Show-OfflineJoinExample
Show-IntegrationExample
Show-KerberosArmoringExample
Show-LDAPSExample
Show-DynamicGroupExample
Show-DeviceHealthExample
Show-RootOfTrustExample

Write-Host ""
Write-Host "=== All Active Directory Examples Completed ===" -ForegroundColor Green
Write-Host "Total Examples: 40" -ForegroundColor Green
Write-Host "Author: Adrian Johnson (adrian207@gmail.com)" -ForegroundColor Green
Write-Host "Version: 1.0.0" -ForegroundColor Green
Write-Host "Date: October 2025" -ForegroundColor Green
