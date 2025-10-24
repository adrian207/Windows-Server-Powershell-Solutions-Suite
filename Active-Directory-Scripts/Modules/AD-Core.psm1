#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Active Directory Core Module

.DESCRIPTION
    Core PowerShell module for Windows Active Directory operations.
    Provides essential AD functionality including user management, group management,
    OU management, domain controller operations, and more.

.NOTES
    Author: Adrian Johnson (adrian207@gmail.com)
    Version: 1.0.0
    Date: October 2025
#>

# Module variables
$ModuleVersion = "1.0.0"
$ModuleAuthor = "Adrian Johnson (adrian207@gmail.com)"

# Core AD Functions
function Get-ADHealthStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDetails,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeReplication,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeFSMO,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeDNS,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeTimeSync
    )
    
    try {
        Write-Host "Checking AD health status on $ServerName..." -ForegroundColor Cyan
        
        $healthStatus = @{
            ServerName = $ServerName
            Timestamp = Get-Date
            OverallStatus = "Unknown"
            Components = @{}
            Issues = @()
            Recommendations = @()
        }
        
        # Check domain controller status
        try {
            $dcStatus = Get-ADDomainController -Server $ServerName -ErrorAction Stop
            $healthStatus.Components.DomainController = @{
                Status = "Healthy"
                Details = $dcStatus
            }
        }
        catch {
            $healthStatus.Components.DomainController = @{
                Status = "Unhealthy"
                Details = $_.Exception.Message
            }
            $healthStatus.Issues += "Domain controller check failed"
        }
        
        # Check replication if requested
        if ($IncludeReplication) {
            try {
                $replicationStatus = Get-ADReplicationPartnerMetadata -Target $ServerName -ErrorAction Stop
                $healthStatus.Components.Replication = @{
                    Status = "Healthy"
                    Details = $replicationStatus
                }
            }
            catch {
                $healthStatus.Components.Replication = @{
                    Status = "Unhealthy"
                    Details = $_.Exception.Message
                }
                $healthStatus.Issues += "Replication check failed"
            }
        }
        
        # Check FSMO roles if requested
        if ($IncludeFSMO) {
            try {
                $fsmoRoles = Get-ADForest -Server $ServerName | Select-Object SchemaMaster, DomainNamingMaster
                $fsmoRoles | ForEach-Object {
                    $fsmoRoles += Get-ADDomain -Server $ServerName | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster
                }
                $healthStatus.Components.FSMO = @{
                    Status = "Healthy"
                    Details = $fsmoRoles
                }
            }
            catch {
                $healthStatus.Components.FSMO = @{
                    Status = "Unhealthy"
                    Details = $_.Exception.Message
                }
                $healthStatus.Issues += "FSMO roles check failed"
            }
        }
        
        # Determine overall status
        $unhealthyComponents = $healthStatus.Components.Values | Where-Object { $_.Status -eq "Unhealthy" }
        if ($unhealthyComponents.Count -eq 0) {
            $healthStatus.OverallStatus = "Healthy"
        } elseif ($unhealthyComponents.Count -lt $healthStatus.Components.Count / 2) {
            $healthStatus.OverallStatus = "Degraded"
        } else {
            $healthStatus.OverallStatus = "Unhealthy"
        }
        
        return $healthStatus
    }
    catch {
        Write-Error "Failed to check AD health status: $($_.Exception.Message)"
        throw
    }
}

function Get-ADUserManagement {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$SearchBase,
        
        [Parameter(Mandatory = $false)]
        [string]$Filter = "*",
        
        [Parameter(Mandatory = $false)]
        [string[]]$Properties = @("Name", "SamAccountName", "UserPrincipalName", "Enabled", "LastLogonDate")
    )
    
    try {
        Write-Host "Retrieving user information from $ServerName..." -ForegroundColor Cyan
        
        $users = Get-ADUser -Server $ServerName -SearchBase $SearchBase -Filter $Filter -Properties $Properties -ErrorAction Stop
        
        return $users
    }
    catch {
        Write-Error "Failed to retrieve user information: $($_.Exception.Message)"
        throw
    }
}

function Get-ADGroupManagement {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$SearchBase,
        
        [Parameter(Mandatory = $false)]
        [string]$Filter = "*",
        
        [Parameter(Mandatory = $false)]
        [string[]]$Properties = @("Name", "SamAccountName", "GroupCategory", "GroupScope", "MemberCount")
    )
    
    try {
        Write-Host "Retrieving group information from $ServerName..." -ForegroundColor Cyan
        
        $groups = Get-ADGroup -Server $ServerName -SearchBase $SearchBase -Filter $Filter -Properties $Properties -ErrorAction Stop
        
        return $groups
    }
    catch {
        Write-Error "Failed to retrieve group information: $($_.Exception.Message)"
        throw
    }
}

function Get-ADOUManagement {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$SearchBase,
        
        [Parameter(Mandatory = $false)]
        [string]$Filter = "*",
        
        [Parameter(Mandatory = $false)]
        [string[]]$Properties = @("Name", "DistinguishedName", "Description", "ProtectedFromAccidentalDeletion")
    )
    
    try {
        Write-Host "Retrieving OU information from $ServerName..." -ForegroundColor Cyan
        
        $ous = Get-ADOrganizationalUnit -Server $ServerName -SearchBase $SearchBase -Filter $Filter -Properties $Properties -ErrorAction Stop
        
        return $ous
    }
    catch {
        Write-Error "Failed to retrieve OU information: $($_.Exception.Message)"
        throw
    }
}

function Set-ADPasswordPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [int]$MinPasswordLength = 12,
        
        [Parameter(Mandatory = $false)]
        [int]$PasswordHistoryCount = 12,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxPasswordAge = 90,
        
        [Parameter(Mandatory = $false)]
        [int]$MinPasswordAge = 1,
        
        [Parameter(Mandatory = $false)]
        [bool]$PasswordComplexity = $true,
        
        [Parameter(Mandatory = $false)]
        [int]$LockoutThreshold = 5,
        
        [Parameter(Mandatory = $false)]
        [int]$LockoutDuration = 30,
        
        [Parameter(Mandatory = $false)]
        [int]$LockoutObservationWindow = 30
    )
    
    try {
        Write-Host "Configuring password policy on $ServerName..." -ForegroundColor Cyan
        
        $domain = Get-ADDomain -Server $ServerName -ErrorAction Stop
        $dc = Get-ADDomainController -Server $ServerName -ErrorAction Stop
        
        # Configure password policy
        $passwordPolicy = @{
            MinPasswordLength = $MinPasswordLength
            PasswordHistoryCount = $PasswordHistoryCount
            MaxPasswordAge = (New-TimeSpan -Days $MaxPasswordAge)
            MinPasswordAge = (New-TimeSpan -Days $MinPasswordAge)
            PasswordComplexity = $PasswordComplexity
            LockoutThreshold = $LockoutThreshold
            LockoutDuration = (New-TimeSpan -Minutes $LockoutDuration)
            LockoutObservationWindow = (New-TimeSpan -Minutes $LockoutObservationWindow)
        }
        
        # Apply password policy
        Set-ADDefaultDomainPasswordPolicy -Server $ServerName -Identity $domain.DistinguishedName @passwordPolicy -ErrorAction Stop
        
        Write-Host "Password policy configured successfully" -ForegroundColor Green
        
        return $passwordPolicy
    }
    catch {
        Write-Error "Failed to configure password policy: $($_.Exception.Message)"
        throw
    }
}

function Set-ADGroupPolicy {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $true)]
        [string]$GPOName,
        
        [Parameter(Mandatory = $false)]
        [string]$GPODescription,
        
        [Parameter(Mandatory = $false)]
        [string]$OUPath,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$GPOSettings
    )
    
    try {
        Write-Host "Configuring Group Policy Object: $GPOName on $ServerName..." -ForegroundColor Cyan
        
        # Create or update GPO
        $gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
        if (-not $gpo) {
            $gpo = New-GPO -Name $GPOName -Comment $GPODescription -ErrorAction Stop
        }
        
        # Configure GPO settings if provided
        if ($GPOSettings) {
            foreach ($setting in $GPOSettings.GetEnumerator()) {
                Set-GPRegistryValue -Name $GPOName -Key $setting.Key -ValueName $setting.Value.Name -Value $setting.Value.Value -Type $setting.Value.Type -ErrorAction Stop
            }
        }
        
        # Link GPO to OU if specified
        if ($OUPath) {
            New-GPLink -Name $GPOName -Target $OUPath -ErrorAction Stop
        }
        
        Write-Host "Group Policy Object configured successfully" -ForegroundColor Green
        
        return $gpo
    }
    catch {
        Write-Error "Failed to configure Group Policy Object: $($_.Exception.Message)"
        throw
    }
}

function Get-ADReplicationStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName
    )
    
    try {
        Write-Host "Checking replication status on $ServerName..." -ForegroundColor Cyan
        
        $replicationStatus = Get-ADReplicationPartnerMetadata -Target $ServerName -ErrorAction Stop
        
        return $replicationStatus
    }
    catch {
        Write-Error "Failed to check replication status: $($_.Exception.Message)"
        throw
    }
}

function Get-ADFSMORoles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName
    )
    
    try {
        Write-Host "Retrieving FSMO roles from $ServerName..." -ForegroundColor Cyan
        
        $forest = Get-ADForest -Server $ServerName -ErrorAction Stop
        $domain = Get-ADDomain -Server $ServerName -ErrorAction Stop
        
        $fsmoRoles = @{
            SchemaMaster = $forest.SchemaMaster
            DomainNamingMaster = $forest.DomainNamingMaster
            PDCEmulator = $domain.PDCEmulator
            RIDMaster = $domain.RIDMaster
            InfrastructureMaster = $domain.InfrastructureMaster
        }
        
        return $fsmoRoles
    }
    catch {
        Write-Error "Failed to retrieve FSMO roles: $($_.Exception.Message)"
        throw
    }
}

function Set-ADTimeSync {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerName,
        
        [Parameter(Mandatory = $false)]
        [string]$TimeSource = "time.windows.com"
    )
    
    try {
        Write-Host "Configuring time synchronization on $ServerName..." -ForegroundColor Cyan
        
        # Configure NTP client
        w32tm /config /manualpeerlist:$TimeSource /syncfromflags:manual /reliable:yes /update
        
        # Restart time service
        Restart-Service -Name "w32time" -Force -ErrorAction Stop
        
        # Resync time
        w32tm /resync /force
        
        Write-Host "Time synchronization configured successfully" -ForegroundColor Green
        
        return @{
            TimeSource = $TimeSource
            Status = "Configured"
        }
    }
    catch {
        Write-Error "Failed to configure time synchronization: $($_.Exception.Message)"
        throw
    }
}

# Export functions
Export-ModuleMember -Function @(
    'Get-ADHealthStatus',
    'Get-ADUserManagement',
    'Get-ADGroupManagement',
    'Get-ADOUManagement',
    'Set-ADPasswordPolicy',
    'Set-ADGroupPolicy',
    'Get-ADReplicationStatus',
    'Get-ADFSMORoles',
    'Set-ADTimeSync'
)
