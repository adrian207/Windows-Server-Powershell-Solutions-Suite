#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Print Server Installation Script

.DESCRIPTION
    This script installs and configures Windows Print Server services including
    the Print Server role, required features, and basic configuration.

.PARAMETER EnableWebManagement
    Enable Print Server Web Management

.PARAMETER EnableBranchOfficeDirectPrinting
    Enable Branch Office Direct Printing

.PARAMETER EnablePrintDriverIsolation
    Enable Print Driver Isolation

.PARAMETER EnablePrinterPooling
    Enable Printer Pooling

.PARAMETER EnablePrintJobLogging
    Enable Print Job Logging

.PARAMETER RestartSpooler
    Restart the Print Spooler service after installation

.PARAMETER LogFilePath
    Path to the log file

.EXAMPLE
    .\Install-PrintServer.ps1

.EXAMPLE
    .\Install-PrintServer.ps1 -EnableWebManagement -EnableBranchOfficeDirectPrinting

.EXAMPLE
    .\Install-PrintServer.ps1 -EnableWebManagement -EnableBranchOfficeDirectPrinting -EnablePrintDriverIsolation -RestartSpooler

.NOTES
    Author: Print Server PowerShell Scripts
    Version: 1.0.0
    Requires: Windows Server 2016+, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [switch]$EnableWebManagement,
    
    [switch]$EnableBranchOfficeDirectPrinting,
    
    [switch]$EnablePrintDriverIsolation,
    
    [switch]$EnablePrinterPooling,
    
    [switch]$EnablePrintJobLogging,
    
    [switch]$RestartSpooler,
    
    [string]$LogFilePath
)

# Import required modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulePath = Join-Path $scriptPath "..\..\Modules"

try {
    Import-Module (Join-Path $modulePath "PrintServer-Core.psm1") -Force
    Import-Module (Join-Path $modulePath "PrintServer-Management.psm1") -Force
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

function Test-PrintServerInstallation {
    Write-InstallationLog "Testing Print Server installation..." "INFO"
    
    try {
        $prerequisites = Test-PrintServerPrerequisites
        if (-not $prerequisites) {
            Write-InstallationLog "Prerequisites check failed" "ERROR"
            return $false
        }
        
        Write-InstallationLog "Prerequisites check passed" "SUCCESS"
        return $true
        
    } catch {
        Write-InstallationLog "Error during prerequisites check: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Install-PrintServerRole {
    Write-InstallationLog "Installing Print Server role..." "INFO"
    
    try {
        $installResult = Install-PrintServerPrerequisites
        if (-not $installResult) {
            Write-InstallationLog "Print Server role installation failed" "ERROR"
            return $false
        }
        
        Write-InstallationLog "Print Server role installed successfully" "SUCCESS"
        return $true
        
    } catch {
        Write-InstallationLog "Error installing Print Server role: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-PrintServerServices {
    Write-InstallationLog "Starting Print Server services..." "INFO"
    
    try {
        $startResult = Start-PrintServerServices
        if (-not $startResult) {
            Write-InstallationLog "Failed to start Print Server services" "ERROR"
            return $false
        }
        
        Write-InstallationLog "Print Server services started successfully" "SUCCESS"
        return $true
        
    } catch {
        Write-InstallationLog "Error starting Print Server services: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Set-PrintServerConfiguration {
    Write-InstallationLog "Configuring Print Server..." "INFO"
    
    try {
        Set-PrintServerConfiguration -EnableWebManagement:$EnableWebManagement -EnableBranchOfficeDirectPrinting:$EnableBranchOfficeDirectPrinting -EnablePrintDriverIsolation:$EnablePrintDriverIsolation -EnablePrinterPooling:$EnablePrinterPooling -EnablePrintJobLogging:$EnablePrintJobLogging
        
        Write-InstallationLog "Print Server configuration completed" "SUCCESS"
        return $true
        
    } catch {
        Write-InstallationLog "Error configuring Print Server: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Restart-PrintSpoolerService {
    Write-InstallationLog "Restarting Print Spooler service..." "INFO"
    
    try {
        Restart-Service -Name Spooler -Force
        Start-Sleep -Seconds 5
        
        $spoolerService = Get-Service -Name Spooler
        if ($spoolerService.Status -eq 'Running') {
            Write-InstallationLog "Print Spooler service restarted successfully" "SUCCESS"
            return $true
        } else {
            Write-InstallationLog "Print Spooler service failed to start" "ERROR"
            return $false
        }
        
    } catch {
        Write-InstallationLog "Error restarting Print Spooler service: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-PrintServerInstallationStatus {
    Write-InstallationLog "Getting Print Server installation status..." "INFO"
    
    try {
        $status = Get-PrintServerStatus
        if ($status) {
            Write-InstallationLog "Print Server status retrieved successfully" "SUCCESS"
            return $status
        } else {
            Write-InstallationLog "Failed to retrieve Print Server status" "ERROR"
            return $null
        }
        
    } catch {
        Write-InstallationLog "Error getting Print Server status: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Save-InstallationLog {
    if (-not $LogFilePath) {
        $LogFilePath = Join-Path $scriptPath "PrintServer-Installation-Log-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    }
    
    try {
        $script:InstallationLog | Out-File -FilePath $LogFilePath -Encoding UTF8
        Write-InstallationLog "Installation log saved to: $LogFilePath" "INFO"
    } catch {
        Write-Warning "Failed to save installation log: $($_.Exception.Message)"
    }
}

# Main installation process
try {
    Write-InstallationLog "Starting Print Server installation..." "INFO"
    Write-InstallationLog "Computer: $($env:COMPUTERNAME)" "INFO"
    Write-InstallationLog "Domain: $($env:USERDOMAIN)" "INFO"
    Write-InstallationLog "User: $($env:USERNAME)" "INFO"
    
    # Step 1: Test prerequisites
    Write-Host "`n=== Step 1: Testing Prerequisites ===" -ForegroundColor Cyan
    if (-not (Test-PrintServerInstallation)) {
        Write-InstallationLog "Prerequisites test failed. Installation aborted." "ERROR"
        exit 1
    }
    
    # Step 2: Install Print Server role
    Write-Host "`n=== Step 2: Installing Print Server Role ===" -ForegroundColor Cyan
    if (-not (Install-PrintServerRole)) {
        Write-InstallationLog "Print Server role installation failed. Installation aborted." "ERROR"
        exit 1
    }
    
    # Step 3: Start Print Server services
    Write-Host "`n=== Step 3: Starting Print Server Services ===" -ForegroundColor Cyan
    if (-not (Start-PrintServerServices)) {
        Write-InstallationLog "Failed to start Print Server services. Installation aborted." "ERROR"
        exit 1
    }
    
    # Step 4: Configure Print Server
    Write-Host "`n=== Step 4: Configuring Print Server ===" -ForegroundColor Cyan
    if (-not (Set-PrintServerConfiguration)) {
        Write-InstallationLog "Print Server configuration failed. Installation aborted." "ERROR"
        exit 1
    }
    
    # Step 5: Restart Spooler service if requested
    if ($RestartSpooler) {
        Write-Host "`n=== Step 5: Restarting Print Spooler Service ===" -ForegroundColor Cyan
        if (-not (Restart-PrintSpoolerService)) {
            Write-InstallationLog "Failed to restart Print Spooler service" "WARNING"
        }
    }
    
    # Step 6: Get installation status
    Write-Host "`n=== Step 6: Getting Installation Status ===" -ForegroundColor Cyan
    $status = Get-PrintServerInstallationStatus
    if ($status) {
        Write-Host "`n=== Print Server Installation Status ===" -ForegroundColor Cyan
        Write-Host "Computer Name: $($status.ComputerName)" -ForegroundColor White
        Write-Host "Print Server Installed: $($status.PrintServerInstalled)" -ForegroundColor White
        Write-Host "Spooler Service Status: $($status.SpoolerServiceStatus)" -ForegroundColor White
        Write-Host "Installed Printers: $($status.InstalledPrinters.Count)" -ForegroundColor White
        Write-Host "Installed Drivers: $($status.PrintDrivers.Count)" -ForegroundColor White
        Write-Host "Web Management Enabled: $($status.Configuration.WebManagementEnabled)" -ForegroundColor White
        Write-Host "Branch Office Direct Printing Enabled: $($status.Configuration.BranchOfficeDirectPrintingEnabled)" -ForegroundColor White
        Write-Host "Print Driver Isolation Enabled: $($status.Configuration.PrintDriverIsolationEnabled)" -ForegroundColor White
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-InstallationLog "Print Server installation completed successfully in $($duration.TotalMinutes.ToString('F2')) minutes." "SUCCESS"
    
    # Display final status
    Write-Host "`n=== Print Server Installation Summary ===" -ForegroundColor Cyan
    Write-Host "Installation Status: SUCCESS" -ForegroundColor Green
    Write-Host "Duration: $($duration.TotalMinutes.ToString('F2')) minutes" -ForegroundColor White
    Write-Host "Features Enabled:" -ForegroundColor White
    if ($EnableWebManagement) { Write-Host "  - Web Management" -ForegroundColor Green }
    if ($EnableBranchOfficeDirectPrinting) { Write-Host "  - Branch Office Direct Printing" -ForegroundColor Green }
    if ($EnablePrintDriverIsolation) { Write-Host "  - Print Driver Isolation" -ForegroundColor Green }
    if ($EnablePrinterPooling) { Write-Host "  - Printer Pooling" -ForegroundColor Green }
    if ($EnablePrintJobLogging) { Write-Host "  - Print Job Logging" -ForegroundColor Green }
    
    # Save installation log
    Save-InstallationLog
    
    Write-Host "`nPrint Server installation completed successfully!" -ForegroundColor Green
    Write-Host "You can now add printers and configure print services." -ForegroundColor Yellow
    
} catch {
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-InstallationLog "Print Server installation failed after $($duration.TotalMinutes.ToString('F2')) minutes: $($_.Exception.Message)" "ERROR"
    
    # Save installation log
    Save-InstallationLog
    
    Write-Host "`nPrint Server installation failed!" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Check the installation log for details." -ForegroundColor Yellow
    
    exit 1
}
