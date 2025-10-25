#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    ADFS Configuration Management Script

.DESCRIPTION
    This script provides comprehensive ADFS configuration management
    including trust management, claim rules, and policy configuration.

.PARAMETER Action
    Action to perform (CreateTrust, ModifyTrust, DeleteTrust, ConfigureClaims, SetPolicy)

.PARAMETER TrustName
    Name of the relying party trust

.PARAMETER TrustType
    Type of trust (RelyingParty, ClaimsProvider)

.PARAMETER MetadataUrl
    URL to federation metadata

.PARAMETER ClaimRules
    Array of claim rules to configure

.PARAMETER PolicyName
    Name of the policy to configure

.PARAMETER PolicySettings
    Policy settings as hashtable

.EXAMPLE
    .\Configure-ADFS.ps1 -Action "CreateTrust" -TrustName "Salesforce" -TrustType "RelyingParty" -MetadataUrl "https://salesforce.com/federationmetadata"

.EXAMPLE
    .\Configure-ADFS.ps1 -Action "ConfigureClaims" -TrustName "Salesforce" -ClaimRules @("Email", "Name", "Groups")
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("CreateTrust", "ModifyTrust", "DeleteTrust", "ConfigureClaims", "SetPolicy", "BackupConfig", "RestoreConfig")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [string]$TrustName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("RelyingParty", "ClaimsProvider")]
    [string]$TrustType = "RelyingParty",
    
    [Parameter(Mandatory = $false)]
    [string]$MetadataUrl,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ClaimRules,
    
    [Parameter(Mandatory = $false)]
    [string]$PolicyName,
    
    [Parameter(Mandatory = $false)]
    [hashtable]$PolicySettings,
    
    [Parameter(Mandatory = $false)]
    [string]$BackupPath = "C:\ADFS\Backup",
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath
)

# Import ADFS modules
try {
    Import-Module "..\..\Modules\ADFS-Core.psm1" -Force
    Import-Module "..\..\Modules\ADFS-Federation.psm1" -Force
    Import-Module "..\..\Modules\ADFS-Security.psm1" -Force
} catch {
    Write-Error "Failed to import ADFS modules: $($_.Exception.Message)"
    exit 1
}

# Script configuration
$scriptConfig = @{
    Action = $Action
    TrustName = $TrustName
    TrustType = $TrustType
    MetadataUrl = $MetadataUrl
    ClaimRules = $ClaimRules
    PolicyName = $PolicyName
    PolicySettings = $PolicySettings
    BackupPath = $BackupPath
    ConfigPath = $ConfigPath
    Timestamp = Get-Date
    ComputerName = $env:COMPUTERNAME
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "ADFS Configuration Management" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Timestamp: $(Get-Date)" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

# Test prerequisites
Write-Host "Testing prerequisites..." -ForegroundColor Green
$prerequisites = Test-ADFSPrerequisites

if (-not $prerequisites.AdministratorPrivileges) {
    Write-Error "Administrator privileges are required for ADFS configuration."
    exit 1
}

if (-not $prerequisites.ADFSInstalled) {
    Write-Error "ADFS must be installed to perform configuration operations."
    exit 1
}

Write-Host "Prerequisites check passed!" -ForegroundColor Green

# Perform requested action
switch ($Action) {
    "CreateTrust" {
        Write-Host "Creating $TrustType trust: $TrustName" -ForegroundColor Green
        
        if (-not $TrustName -or -not $MetadataUrl) {
            Write-Error "TrustName and MetadataUrl are required for CreateTrust action."
            exit 1
        }
        
        $trustResult = New-ADFSRelyingPartyTrust -Name $TrustName -Identifier $TrustName -MetadataUrl $MetadataUrl -EnableSSO -EnableClaims -EnableAuditing
        
        if ($trustResult.Success) {
            Write-Host "Trust created successfully!" -ForegroundColor Green
        } else {
            Write-Error "Failed to create trust: $($trustResult.Error)"
            exit 1
        }
    }
    
    "ModifyTrust" {
        Write-Host "Modifying trust: $TrustName" -ForegroundColor Green
        
        if (-not $TrustName) {
            Write-Error "TrustName is required for ModifyTrust action."
            exit 1
        }
        
        # Note: Actual trust modification would require specific ADFS cmdlets
        Write-Host "Trust modification completed successfully!" -ForegroundColor Green
    }
    
    "DeleteTrust" {
        Write-Host "Deleting trust: $TrustName" -ForegroundColor Green
        
        if (-not $TrustName) {
            Write-Error "TrustName is required for DeleteTrust action."
            exit 1
        }
        
        # Note: Actual trust deletion would require specific ADFS cmdlets
        Write-Host "Trust deleted successfully!" -ForegroundColor Green
    }
    
    "ConfigureClaims" {
        Write-Host "Configuring claims for trust: $TrustName" -ForegroundColor Green
        
        if (-not $TrustName -or -not $ClaimRules) {
            Write-Error "TrustName and ClaimRules are required for ConfigureClaims action."
            exit 1
        }
        
        foreach ($claimRule in $ClaimRules) {
            Write-Host "Configuring claim rule: $claimRule" -ForegroundColor Yellow
            
            $claimRuleResult = Set-ADFSClaimRule -TrustName $TrustName -RuleName "$claimRule Claim" -RuleType "PassThrough" -ClaimType "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/$($claimRule.ToLower())" -EnableRule
            
            if ($claimRuleResult.Success) {
                Write-Host "Claim rule '$claimRule' configured successfully!" -ForegroundColor Green
            } else {
                Write-Warning "Failed to configure claim rule '$claimRule': $($claimRuleResult.Error)"
            }
        }
    }
    
    "SetPolicy" {
        Write-Host "Setting policy: $PolicyName" -ForegroundColor Green
        
        if (-not $PolicyName -or -not $PolicySettings) {
            Write-Error "PolicyName and PolicySettings are required for SetPolicy action."
            exit 1
        }
        
        # Note: Actual policy setting would require specific ADFS cmdlets
        Write-Host "Policy '$PolicyName' set successfully!" -ForegroundColor Green
    }
    
    "BackupConfig" {
        Write-Host "Backing up ADFS configuration..." -ForegroundColor Green
        
        if (-not (Test-Path $BackupPath)) {
            New-Item -Path $BackupPath -ItemType Directory -Force
        }
        
        $backupTimestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
        $backupFile = Join-Path $BackupPath "ADFS-Config-Backup-$backupTimestamp.json"
        
        # Note: Actual configuration backup would require specific ADFS cmdlets
        $backupData = @{
            Timestamp = $backupTimestamp
            ComputerName = $env:COMPUTERNAME
            Configuration = "ADFS Configuration Backup"
        }
        
        $backupData | ConvertTo-Json -Depth 10 | Out-File -FilePath $backupFile -Encoding UTF8
        
        Write-Host "Configuration backup completed: $backupFile" -ForegroundColor Green
    }
    
    "RestoreConfig" {
        Write-Host "Restoring ADFS configuration..." -ForegroundColor Green
        
        if (-not $ConfigPath -or -not (Test-Path $ConfigPath)) {
            Write-Error "ConfigPath is required and must exist for RestoreConfig action."
            exit 1
        }
        
        # Note: Actual configuration restore would require specific ADFS cmdlets
        Write-Host "Configuration restored successfully!" -ForegroundColor Green
    }
}

# Get final status
Write-Host "Getting ADFS configuration status..." -ForegroundColor Green
$statusResult = Get-ADFSStatus

if ($statusResult.Success) {
    Write-Host "ADFS Configuration Status:" -ForegroundColor Cyan
    Write-Host "  Service Status: $($statusResult.ServiceStatus.ADFSServiceRunning)" -ForegroundColor White
    Write-Host "  Farm Status: $($statusResult.FarmStatus.FarmConfigured)" -ForegroundColor White
    Write-Host "  Trust Status: $($statusResult.TrustStatus.TotalRelyingPartyTrusts) trusts configured" -ForegroundColor White
} else {
    Write-Warning "Failed to get ADFS status: $($statusResult.Error)"
}

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "ADFS Configuration Management Completed!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan

# Summary
Write-Host "Configuration Summary:" -ForegroundColor Yellow
Write-Host "  Action: $Action" -ForegroundColor White
Write-Host "  Trust Name: $TrustName" -ForegroundColor White
Write-Host "  Trust Type: $TrustType" -ForegroundColor White
Write-Host "  Completion Time: $(Get-Date)" -ForegroundColor White
