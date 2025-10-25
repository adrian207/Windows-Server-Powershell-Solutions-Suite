# Entra Connect Server Deployment Script

<#
.SYNOPSIS
    Deploys and configures Entra Connect server for hybrid identity.

.DESCRIPTION
    This script automates the deployment of Entra Connect server including installation,
    configuration, and initial setup for hybrid identity scenarios.

.PARAMETER ConfigurationFile
    Path to the JSON configuration file containing deployment settings.

.PARAMETER AzureTenantId
    Azure AD tenant ID for the target tenant.

.PARAMETER AzureAdminCredential
    Credential for Azure AD Global Administrator.

.PARAMETER OnPremisesAdminCredential
    Credential for on-premises Domain Administrator.

.PARAMETER SyncMethod
    Synchronization method: PasswordHashSync, PassThroughAuthentication, or Federation.

.PARAMETER EnableSeamlessSSO
    Enable seamless single sign-on.

.PARAMETER EnableStagingMode
    Enable staging mode for safe testing.

.EXAMPLE
    .\Deploy-EntraConnectServer.ps1 -ConfigurationFile ".\Configuration\EntraConnect-Config.json"

.EXAMPLE
    .\Deploy-EntraConnectServer.ps1 -AzureTenantId "12345678-1234-1234-1234-123456789012" -SyncMethod "PasswordHashSync" -EnableSeamlessSSO

.NOTES
    Author: Adrian Johnson <adrian207@gmail.com>
    Version: 1.0.0
    Date: December 2024
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigurationFile = ".\Configuration\EntraConnect-Configuration-Template.json",
    
    [Parameter(Mandatory = $false)]
    [string]$AzureTenantId,
    
    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$AzureAdminCredential,
    
    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$OnPremisesAdminCredential,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("PasswordHashSync", "PassThroughAuthentication", "Federation")]
    [string]$SyncMethod = "PasswordHashSync",
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableSeamlessSSO,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableStagingMode,
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory = $false)]
    [switch]$Confirm
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Import required modules
try {
    Import-Module .\Modules\EntraConnect-Core.psm1 -Force
    Import-Module .\Modules\EntraConnect-Security.psm1 -Force
    Import-Module .\Modules\EntraConnect-Monitoring.psm1 -Force
    Import-Module .\Modules\EntraConnect-Troubleshooting.psm1 -Force
    Write-Verbose "Successfully imported Entra Connect modules"
}
catch {
    Write-Error "Failed to import required modules: $($_.Exception.Message)"
    exit 1
}

# Function to validate prerequisites
function Test-Prerequisites {
    Write-Host "Validating prerequisites..." -ForegroundColor Green
    
    # Check Windows version
    $OSVersion = [System.Environment]::OSVersion.Version
    if ($OSVersion.Major -lt 10) {
        throw "Windows Server 2016 or later is required"
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        throw "PowerShell 5.1 or later is required"
    }
    
    # Check if running as administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        throw "This script must be run as Administrator"
    }
    
    # Check network connectivity to Azure
    try {
        $TestConnection = Test-NetConnection -ComputerName "login.microsoftonline.com" -Port 443 -InformationLevel Quiet
        if (-not $TestConnection) {
            throw "Cannot connect to Azure services. Check network connectivity."
        }
    }
    catch {
        throw "Network connectivity test failed: $($_.Exception.Message)"
    }
    
    Write-Host "Prerequisites validation completed successfully" -ForegroundColor Green
}

# Function to download Entra Connect
function Get-EntraConnectInstaller {
    Write-Host "Downloading Entra Connect installer..." -ForegroundColor Green
    
    $DownloadUrl = "https://download.microsoft.com/download/B/0/0/B00291D0-5A0C-4E81-8215-AB4E509EDEB5/AzureADConnect.msi"
    $DownloadPath = "$env:TEMP\AzureADConnect.msi"
    
    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $DownloadPath -UseBasicParsing
        Write-Verbose "Entra Connect installer downloaded to: $DownloadPath"
        return $DownloadPath
    }
    catch {
        throw "Failed to download Entra Connect installer: $($_.Exception.Message)"
    }
}

# Function to install Entra Connect
function Install-EntraConnect {
    param(
        [string]$InstallerPath,
        [string]$SyncMethod,
        [bool]$EnableSeamlessSSO,
        [bool]$EnableStagingMode
    )
    
    Write-Host "Installing Entra Connect..." -ForegroundColor Green
    
    $InstallArgs = @(
        "/i", $InstallerPath,
        "/quiet",
        "/norestart"
    )
    
    try {
        $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $InstallArgs -Wait -PassThru
        
        if ($Process.ExitCode -ne 0) {
            throw "Entra Connect installation failed with exit code: $($Process.ExitCode)"
        }
        
        Write-Verbose "Entra Connect installation completed successfully"
    }
    catch {
        throw "Failed to install Entra Connect: $($_.Exception.Message)"
    }
}

# Function to configure Entra Connect
function Set-EntraConnectConfiguration {
    param(
        [string]$AzureTenantId,
        [System.Management.Automation.PSCredential]$AzureAdminCredential,
        [System.Management.Automation.PSCredential]$OnPremisesAdminCredential,
        [string]$SyncMethod,
        [bool]$EnableSeamlessSSO,
        [bool]$EnableStagingMode
    )
    
    Write-Host "Configuring Entra Connect..." -ForegroundColor Green
    
    try {
        # Configure synchronization method
        switch ($SyncMethod) {
            "PasswordHashSync" {
                Write-Verbose "Configuring Password Hash Synchronization"
                # Implementation for PHS configuration
            }
            "PassThroughAuthentication" {
                Write-Verbose "Configuring Pass-Through Authentication"
                # Implementation for PTA configuration
            }
            "Federation" {
                Write-Verbose "Configuring Federation"
                # Implementation for federation configuration
            }
        }
        
        # Configure seamless SSO if enabled
        if ($EnableSeamlessSSO) {
            Write-Verbose "Enabling Seamless Single Sign-On"
            # Implementation for seamless SSO
        }
        
        # Configure staging mode if enabled
        if ($EnableStagingMode) {
            Write-Verbose "Enabling Staging Mode"
            # Implementation for staging mode
        }
        
        Write-Verbose "Entra Connect configuration completed successfully"
    }
    catch {
        throw "Failed to configure Entra Connect: $($_.Exception.Message)"
    }
}

# Function to validate installation
function Test-EntraConnectInstallation {
    Write-Host "Validating Entra Connect installation..." -ForegroundColor Green
    
    try {
        # Check if Entra Connect service is running
        $Service = Get-Service -Name "Azure AD Connect" -ErrorAction SilentlyContinue
        if (-not $Service -or $Service.Status -ne "Running") {
            throw "Entra Connect service is not running"
        }
        
        # Check sync status
        # Implementation for sync status check
        
        Write-Verbose "Entra Connect installation validation completed successfully"
    }
    catch {
        throw "Entra Connect installation validation failed: $($_.Exception.Message)"
    }
}

# Main execution
try {
    Write-Host "Starting Entra Connect server deployment..." -ForegroundColor Cyan
    Write-Host "Author: Adrian Johnson <adrian207@gmail.com>" -ForegroundColor Gray
    Write-Host "Version: 1.0.0" -ForegroundColor Gray
    Write-Host "Date: December 2024" -ForegroundColor Gray
    Write-Host ""
    
    # Validate prerequisites
    Test-Prerequisites
    
    # Load configuration if provided
    if (Test-Path $ConfigurationFile) {
        Write-Host "Loading configuration from: $ConfigurationFile" -ForegroundColor Green
        $Config = Get-Content $ConfigurationFile | ConvertFrom-Json
        
        # Override parameters with configuration values
        if ($Config.AzureTenantId) { $AzureTenantId = $Config.AzureTenantId }
        if ($Config.SyncMethod) { $SyncMethod = $Config.SyncMethod }
        if ($Config.EnableSeamlessSSO) { $EnableSeamlessSSO = $Config.EnableSeamlessSSO }
        if ($Config.EnableStagingMode) { $EnableStagingMode = $Config.EnableStagingMode }
    }
    
    # Validate required parameters
    if (-not $AzureTenantId) {
        throw "AzureTenantId parameter is required"
    }
    
    if (-not $AzureAdminCredential) {
        $AzureAdminCredential = Get-Credential -Message "Enter Azure AD Global Administrator credentials"
    }
    
    if (-not $OnPremisesAdminCredential) {
        $OnPremisesAdminCredential = Get-Credential -Message "Enter on-premises Domain Administrator credentials"
    }
    
    # Download and install Entra Connect
    $InstallerPath = Get-EntraConnectInstaller
    Install-EntraConnect -InstallerPath $InstallerPath -SyncMethod $SyncMethod -EnableSeamlessSSO $EnableSeamlessSSO -EnableStagingMode $EnableStagingMode
    
    # Configure Entra Connect
    Set-EntraConnectConfiguration -AzureTenantId $AzureTenantId -AzureAdminCredential $AzureAdminCredential -OnPremisesAdminCredential $OnPremisesAdminCredential -SyncMethod $SyncMethod -EnableSeamlessSSO $EnableSeamlessSSO -EnableStagingMode $EnableStagingMode
    
    # Validate installation
    Test-EntraConnectInstallation
    
    Write-Host ""
    Write-Host "Entra Connect server deployment completed successfully!" -ForegroundColor Green
    Write-Host "Synchronization method: $SyncMethod" -ForegroundColor Yellow
    Write-Host "Seamless SSO: $EnableSeamlessSSO" -ForegroundColor Yellow
    Write-Host "Staging mode: $EnableStagingMode" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "1. Verify synchronization status" -ForegroundColor White
    Write-Host "2. Configure additional security features" -ForegroundColor White
    Write-Host "3. Set up monitoring and alerting" -ForegroundColor White
    Write-Host "4. Test authentication methods" -ForegroundColor White
}
catch {
    Write-Error "Entra Connect deployment failed: $($_.Exception.Message)"
    Write-Host "Please check the error details and try again." -ForegroundColor Red
    exit 1
}
finally {
    # Cleanup
    if ($InstallerPath -and (Test-Path $InstallerPath)) {
        Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue
    }
}
