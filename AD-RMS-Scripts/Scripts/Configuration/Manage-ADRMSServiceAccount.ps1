#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD RMS Service Account Management Script

.DESCRIPTION
    This script provides comprehensive service account management for AD RMS including
    account creation, configuration, and security settings.

.PARAMETER Action
    The action to perform (Create, Configure, Update, Validate, Reset)

.PARAMETER ServiceAccount
    The service account name

.PARAMETER ServiceAccountPassword
    The password for the service account

.PARAMETER DomainName
    The domain name (required for account creation)

.PARAMETER AccountDescription
    Description for the service account

.PARAMETER PasswordNeverExpires
    Set password to never expire

.PARAMETER AccountDisabled
    Create the account in disabled state

.PARAMETER AddToGroups
    Array of groups to add the account to

.EXAMPLE
    .\Manage-ADRMSServiceAccount.ps1 -Action Create -ServiceAccount "RMS_Service" -ServiceAccountPassword $securePassword -DomainName "contoso.com"

.EXAMPLE
    .\Manage-ADRMSServiceAccount.ps1 -Action Configure -ServiceAccount "RMS_Service" -ServiceAccountPassword $securePassword

.EXAMPLE
    .\Manage-ADRMSServiceAccount.ps1 -Action Validate -ServiceAccount "RMS_Service"

.NOTES
    Author: AD RMS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Create", "Configure", "Update", "Validate", "Reset")]
    [string]$Action,
    
    [Parameter(Mandatory = $true)]
    [string]$ServiceAccount,
    
    [SecureString]$ServiceAccountPassword,
    
    [string]$DomainName,
    
    [string]$AccountDescription = "AD RMS Service Account",
    
    [switch]$PasswordNeverExpires,
    
    [switch]$AccountDisabled,
    
    [string[]]$AddToGroups = @("Domain Users")
)

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "ADRMS-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "ADRMS-Configuration.psm1") -Force
    Import-Module (Join-Path $modulePath "ADRMS-Diagnostics.psm1") -Force
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Script variables
$script:ServiceAccountLog = @()
$script:StartTime = Get-Date

function Write-ServiceAccountLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:ServiceAccountLog += $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function New-ADRMSServiceAccount {
    param(
        [string]$ServiceAccount,
        [SecureString]$ServiceAccountPassword,
        [string]$DomainName,
        [string]$AccountDescription,
        [bool]$PasswordNeverExpires,
        [bool]$AccountDisabled,
        [string[]]$AddToGroups
    )
    
    Write-ServiceAccountLog "Creating AD RMS service account..." "INFO"
    
    try {
        # Check if account already exists
        $existingAccount = Get-LocalUser -Name $ServiceAccount -ErrorAction SilentlyContinue
        if ($existingAccount) {
            Write-ServiceAccountLog "Service account already exists: $ServiceAccount" "WARNING"
            return $true
        }
        
        # Create the service account
        $accountParams = @{
            Name = $ServiceAccount
            Description = $AccountDescription
            PasswordNeverExpires = $PasswordNeverExpires
            Disabled = $AccountDisabled
        }
        
        if ($ServiceAccountPassword) {
            $accountParams.Password = $ServiceAccountPassword
        }
        
        New-LocalUser @accountParams
        
        Write-ServiceAccountLog "Service account created: $ServiceAccount" "SUCCESS"
        
        # Add to groups
        foreach ($groupName in $AddToGroups) {
            try {
                Add-LocalGroupMember -Group $groupName -Member $ServiceAccount -ErrorAction Stop
                Write-ServiceAccountLog "Added $ServiceAccount to group: $groupName" "SUCCESS"
            } catch {
                Write-ServiceAccountLog "Failed to add $ServiceAccount to group $groupName: $($_.Exception.Message)" "WARNING"
            }
        }
        
        return $true
        
    } catch {
        Write-ServiceAccountLog "Failed to create service account: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-ADRMSServiceAccountConfiguration {
    param(
        [string]$ServiceAccount,
        [SecureString]$ServiceAccountPassword
    )
    
    Write-ServiceAccountLog "Configuring AD RMS service account..." "INFO"
    
    try {
        # Configure service account in AD RMS
        if ($ServiceAccountPassword) {
            Set-ADRMSServiceAccount -ServiceAccount $ServiceAccount -ServiceAccountPassword $ServiceAccountPassword
        } else {
            # Get current password from registry if available
            $serviceAccountReg = "HKLM:\SOFTWARE\Microsoft\MSDRMS\ServiceAccount"
            if (Test-Path $serviceAccountReg) {
                $currentPassword = Get-ItemProperty -Path $serviceAccountReg -Name "ServiceAccountPassword" -ErrorAction SilentlyContinue
                if ($currentPassword.ServiceAccountPassword) {
                    $securePassword = ConvertTo-SecureString $currentPassword.ServiceAccountPassword -AsPlainText -Force
                    Set-ADRMSServiceAccount -ServiceAccount $ServiceAccount -ServiceAccountPassword $securePassword
                }
            }
        }
        
        Write-ServiceAccountLog "AD RMS service account configuration completed." "SUCCESS"
        return $true
        
    } catch {
        Write-ServiceAccountLog "Failed to configure service account: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-ServiceAccountValidation {
    param([string]$ServiceAccount)
    
    Write-ServiceAccountLog "Validating service account..." "INFO"
    
    try {
        $validationResults = @{
            AccountExists = $false
            AccountEnabled = $false
            PasswordSet = $false
            InRequiredGroups = $false
            ADRMSConfigured = $false
            Overall = 'Unknown'
        }
        
        # Check if account exists
        $account = Get-LocalUser -Name $ServiceAccount -ErrorAction SilentlyContinue
        if ($account) {
            $validationResults.AccountExists = $true
            $validationResults.AccountEnabled = -not $account.Disabled
            $validationResults.PasswordSet = $account.PasswordRequired
        }
        
        # Check group membership
        $requiredGroups = @("Domain Users", "IIS_IUSRS")
        $groupMembership = @()
        
        foreach ($groupName in $requiredGroups) {
            try {
                $group = Get-LocalGroupMember -Group $groupName -Member $ServiceAccount -ErrorAction SilentlyContinue
                if ($group) {
                    $groupMembership += $groupName
                }
            } catch {
                # Group or member not found
            }
        }
        
        $validationResults.InRequiredGroups = $groupMembership.Count -gt 0
        
        # Check AD RMS configuration
        $serviceAccountReg = "HKLM:\SOFTWARE\Microsoft\MSDRMS\ServiceAccount"
        if (Test-Path $serviceAccountReg) {
            $configuredAccount = Get-ItemProperty -Path $serviceAccountReg -Name "ServiceAccount" -ErrorAction SilentlyContinue
            $validationResults.ADRMSConfigured = $configuredAccount.ServiceAccount -eq $ServiceAccount
        }
        
        # Determine overall validation status
        $validCount = ($validationResults.AccountExists, $validationResults.AccountEnabled, $validationResults.PasswordSet, $validationResults.ADRMSConfigured | Where-Object { $_ }).Count
        
        if ($validCount -eq 4) {
            $validationResults.Overall = 'Valid'
        } elseif ($validCount -gt 2) {
            $validationResults.Overall = 'Partially Valid'
        } else {
            $validationResults.Overall = 'Invalid'
        }
        
        return [PSCustomObject]$validationResults
        
    } catch {
        Write-ServiceAccountLog "Error validating service account: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Reset-ServiceAccountConfiguration {
    param([string]$ServiceAccount)
    
    Write-ServiceAccountLog "Resetting service account configuration..." "WARNING"
    
    try {
        # Remove AD RMS service account configuration
        $serviceAccountReg = "HKLM:\SOFTWARE\Microsoft\MSDRMS\ServiceAccount"
        if (Test-Path $serviceAccountReg) {
            Remove-Item -Path $serviceAccountReg -Recurse -Force
            Write-ServiceAccountLog "Removed AD RMS service account configuration." "SUCCESS"
        }
        
        # Optionally disable the account
        $account = Get-LocalUser -Name $ServiceAccount -ErrorAction SilentlyContinue
        if ($account) {
            Disable-LocalUser -Name $ServiceAccount
            Write-ServiceAccountLog "Disabled service account: $ServiceAccount" "SUCCESS"
        }
        
        return $true
        
    } catch {
        Write-ServiceAccountLog "Failed to reset service account configuration: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Save-ServiceAccountLog {
    $logPath = Join-Path $scriptPath "ServiceAccount-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    try {
        $script:ServiceAccountLog | Out-File -FilePath $logPath -Encoding UTF8
        Write-ServiceAccountLog "Service account log saved to: $logPath" "INFO"
    } catch {
        Write-Warning "Failed to save service account log: $($_.Exception.Message)"
    }
}

# Main service account management process
try {
    Write-ServiceAccountLog "Starting AD RMS service account management..." "INFO"
    Write-ServiceAccountLog "Action: $Action" "INFO"
    Write-ServiceAccountLog "Service Account: $ServiceAccount" "INFO"
    
    switch ($Action) {
        "Create" {
            if (-not $DomainName) {
                throw "DomainName parameter is required for Create action"
            }
            
            if (-not $ServiceAccountPassword) {
                throw "ServiceAccountPassword parameter is required for Create action"
            }
            
            if (-not (New-ADRMSServiceAccount -ServiceAccount $ServiceAccount -ServiceAccountPassword $ServiceAccountPassword -DomainName $DomainName -AccountDescription $AccountDescription -PasswordNeverExpires $PasswordNeverExpires -AccountDisabled $AccountDisabled -AddToGroups $AddToGroups)) {
                throw "Service account creation failed"
            }
        }
        
        "Configure" {
            if (-not (Set-ADRMSServiceAccountConfiguration -ServiceAccount $ServiceAccount -ServiceAccountPassword $ServiceAccountPassword)) {
                throw "Service account configuration failed"
            }
        }
        
        "Update" {
            if (-not $ServiceAccountPassword) {
                throw "ServiceAccountPassword parameter is required for Update action"
            }
            
            if (-not (Set-ADRMSServiceAccountConfiguration -ServiceAccount $ServiceAccount -ServiceAccountPassword $ServiceAccountPassword)) {
                throw "Service account update failed"
            }
        }
        
        "Validate" {
            $validationResults = Test-ServiceAccountValidation -ServiceAccount $ServiceAccount
            if (-not $validationResults) {
                throw "Service account validation failed"
            }
            
            Write-Host "`n=== Service Account Validation Results ===" -ForegroundColor Cyan
            Write-Host "Account Exists: $($validationResults.AccountExists)" -ForegroundColor White
            Write-Host "Account Enabled: $($validationResults.AccountEnabled)" -ForegroundColor White
            Write-Host "Password Set: $($validationResults.PasswordSet)" -ForegroundColor White
            Write-Host "In Required Groups: $($validationResults.InRequiredGroups)" -ForegroundColor White
            Write-Host "AD RMS Configured: $($validationResults.ADRMSConfigured)" -ForegroundColor White
            Write-Host "Overall Status: $($validationResults.Overall)" -ForegroundColor White
        }
        
        "Reset" {
            if (-not (Reset-ServiceAccountConfiguration -ServiceAccount $ServiceAccount)) {
                throw "Service account reset failed"
            }
        }
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-ServiceAccountLog "AD RMS service account management completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== AD RMS Service Account Management Summary ===" -ForegroundColor Cyan
    Write-Host "Action: $Action" -ForegroundColor White
    Write-Host "Service Account: $ServiceAccount" -ForegroundColor White
    Write-Host "Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    
    # Save service account log
    Save-ServiceAccountLog
    
    Write-Host "`nService account management completed successfully!" -ForegroundColor Green
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-ServiceAccountLog "AD RMS service account management failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save service account log
    Save-ServiceAccountLog
    
    Write-Host "`nService account management failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the service account log for details." -ForegroundColor Yellow
    
    exit 1
}
