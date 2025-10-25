#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    AD RMS Installation and Implementation Script

.DESCRIPTION
    This script provides a comprehensive AD RMS installation and implementation process.
    It handles prerequisites, installation, configuration, and initial setup.

.PARAMETER DomainName
    The domain name for the AD RMS cluster

.PARAMETER ServiceAccount
    The service account for AD RMS (default: RMS_Service)

.PARAMETER ServiceAccountPassword
    The password for the service account

.PARAMETER DatabaseServer
    The database server (default: localhost)

.PARAMETER DatabaseName
    The database name (default: DRMS)

.PARAMETER ClusterUrl
    The cluster URL (optional, will be generated if not provided)

.PARAMETER SkipPrerequisites
    Skip prerequisite installation

.PARAMETER SkipConfiguration
    Skip initial configuration

.PARAMETER RestartRequired
    Allow automatic restart if required

.EXAMPLE
    .\Install-ADRMS.ps1 -DomainName "contoso.com" -ServiceAccountPassword $securePassword

.EXAMPLE
    .\Install-ADRMS.ps1 -DomainName "contoso.com" -ServiceAccount "RMS_SVC" -ServiceAccountPassword $securePassword -DatabaseServer "SQL01" -DatabaseName "RMS_DB"

.NOTES
    Author: AD RMS PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DomainName,
    
    [string]$ServiceAccount = "RMS_Service",
    
    [Parameter(Mandatory = $true)]
    [SecureString]$ServiceAccountPassword,
    
    [string]$DatabaseServer = "localhost",
    
    [string]$DatabaseName = "DRMS",
    
    [string]$ClusterUrl,
    
    [switch]$SkipPrerequisites,
    
    [switch]$SkipConfiguration,
    
    [switch]$RestartRequired
)

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\Modules"

try {
    Import-Module (Join-Path $modulePath "ADRMS-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "ADRMS-Configuration.psm1") -Force
    Import-Module (Join-Path $modulePath "ADRMS-Diagnostics.psm1") -Force
} catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Script variables
$script:InstallationLog = @()
$script:StartTime = Get-Date

function Write-InstallationLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:InstallationLog += $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        default { Write-Host $Message -ForegroundColor White }
    }
}

function Test-InstallationPrerequisites {
    Write-InstallationLog "Testing installation prerequisites..." "INFO"
    
    $prerequisites = Test-ADRMSPrerequisites
    
    if (-not $prerequisites) {
        Write-InstallationLog "Prerequisites check failed. Please resolve issues before continuing." "ERROR"
        return $false
    }
    
    Write-InstallationLog "Prerequisites check passed." "SUCCESS"
    return $true
}

function Install-Prerequisites {
    if ($SkipPrerequisites) {
        Write-InstallationLog "Skipping prerequisite installation as requested." "INFO"
        return $true
    }
    
    Write-InstallationLog "Installing AD RMS prerequisites..." "INFO"
    
    try {
        Install-ADRMSPrerequisites -RestartRequired:$RestartRequired
        Write-InstallationLog "Prerequisites installed successfully." "SUCCESS"
        return $true
    } catch {
        Write-InstallationLog "Failed to install prerequisites: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Install-ADRMSFeature {
    Write-InstallationLog "Installing AD RMS Windows feature..." "INFO"
    
    try {
        $adrmsFeature = Get-WindowsFeature -Name ADRMS
        
        if ($adrmsFeature.InstallState -eq 'Installed') {
            Write-InstallationLog "AD RMS feature is already installed." "INFO"
            return $true
        }
        
        Write-InstallationLog "Installing AD RMS feature..." "INFO"
        $result = Install-WindowsFeature -Name ADRMS -IncludeManagementTools
        
        if ($result.Success) {
            Write-InstallationLog "AD RMS feature installed successfully." "SUCCESS"
            return $true
        } else {
            Write-InstallationLog "Failed to install AD RMS feature." "ERROR"
            return $false
        }
    } catch {
        Write-InstallationLog "Error installing AD RMS feature: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Configure-ADRMS {
    if ($SkipConfiguration) {
        Write-InstallationLog "Skipping AD RMS configuration as requested." "INFO"
        return $true
    }
    
    Write-InstallationLog "Configuring AD RMS..." "INFO"
    
    try {
        # Generate cluster URL if not provided
        if (-not $ClusterUrl) {
            $computerName = $env:COMPUTERNAME
            $ClusterUrl = "https://$computerName.$DomainName/_wmcs"
        }
        
        # Initialize AD RMS configuration
        Initialize-ADRMSConfiguration -DomainName $DomainName -DatabaseServer $DatabaseServer -ServiceAccount $ServiceAccount -ServiceAccountPassword $ServiceAccountPassword
        
        Write-InstallationLog "AD RMS configuration completed successfully." "SUCCESS"
        return $true
    } catch {
        Write-InstallationLog "Failed to configure AD RMS: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-ADRMSServices {
    Write-InstallationLog "Starting AD RMS services..." "INFO"
    
    try {
        Start-ADRMSServices
        Write-InstallationLog "AD RMS services started successfully." "SUCCESS"
        return $true
    } catch {
        Write-InstallationLog "Failed to start AD RMS services: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-Installation {
    Write-InstallationLog "Testing AD RMS installation..." "INFO"
    
    try {
        Start-Sleep -Seconds 10  # Allow services to fully start
        
        $status = Get-ADRMSStatus
        $health = Test-ADRMSHealth
        
        if ($status.Configuration.Installed -and $health.Overall -eq 'Healthy') {
            Write-InstallationLog "AD RMS installation test passed." "SUCCESS"
            return $true
        } else {
            Write-InstallationLog "AD RMS installation test failed. Status: $($status.Configuration.Installed), Health: $($health.Overall)" "WARNING"
            return $false
        }
    } catch {
        Write-InstallationLog "Error testing installation: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Save-InstallationLog {
    $logPath = Join-Path $scriptPath "Installation-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    try {
        $script:InstallationLog | Out-File -FilePath $logPath -Encoding UTF8
        Write-InstallationLog "Installation log saved to: $logPath" "INFO"
    } catch {
        Write-Warning "Failed to save installation log: $($_.Exception.Message)"
    }
}

# Main installation process
try {
    Write-InstallationLog "Starting AD RMS installation process..." "INFO"
    Write-InstallationLog "Domain: $DomainName" "INFO"
    Write-InstallationLog "Service Account: $ServiceAccount" "INFO"
    Write-InstallationLog "Database Server: $DatabaseServer" "INFO"
    Write-InstallationLog "Database Name: $DatabaseName" "INFO"
    
    # Step 1: Test prerequisites
    if (-not (Test-InstallationPrerequisites)) {
        throw "Prerequisites check failed"
    }
    
    # Step 2: Install prerequisites
    if (-not (Install-Prerequisites)) {
        throw "Prerequisite installation failed"
    }
    
    # Step 3: Install AD RMS feature
    if (-not (Install-ADRMSFeature)) {
        throw "AD RMS feature installation failed"
    }
    
    # Step 4: Configure AD RMS
    if (-not (Configure-ADRMS)) {
        throw "AD RMS configuration failed"
    }
    
    # Step 5: Start services
    if (-not (Start-ADRMSServices)) {
        throw "Failed to start AD RMS services"
    }
    
    # Step 6: Test installation
    if (-not (Test-Installation)) {
        Write-InstallationLog "Installation completed but tests failed. Manual verification may be required." "WARNING"
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-InstallationLog "AD RMS installation completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== AD RMS Installation Summary ===" -ForegroundColor Cyan
    Write-Host "Domain: $DomainName" -ForegroundColor White
    Write-Host "Service Account: $ServiceAccount" -ForegroundColor White
    Write-Host "Database Server: $DatabaseServer" -ForegroundColor White
    Write-Host "Database Name: $DatabaseName" -ForegroundColor White
    Write-Host "Installation Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    
    # Save installation log
    Save-InstallationLog
    
    Write-Host "`nInstallation completed successfully!" -ForegroundColor Green
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-InstallationLog "AD RMS installation failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save installation log
    Save-InstallationLog
    
    Write-Host "`nInstallation failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the installation log for details." -ForegroundColor Yellow
    
    exit 1
}
